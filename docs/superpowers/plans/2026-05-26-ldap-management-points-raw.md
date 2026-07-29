# `ldap_management_points_raw` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename `ldap_mp_site_classifications` → `ldap_management_points_raw`, extend the yield to carry `mp_hostname` and `fsp_hostnames`, wire it into live collection, and implement the preproc transforms + lookup method that populate `Computer.SCCMSiteSystemRoles`.

**Architecture:** The collector parses `mSSMSCapabilities` XML once per entry via a standalone `_parse_mp_capabilities()` helper, calls `ctx.register_target()` for the MP and every FSP host, then yields a single flat row with all derived fields. Three preproc transforms fan that raw table into `site_types`, `computer_mp_roles`, `computer_fsp_roles`, and a unified `computer_site_system_roles` table using plain DuckDB SQL (no XML at preproc time). `SCCMLookup.computer_site_system_roles()` queries the unified table at convert time, matching by hostname.

**Tech Stack:** Python `xml.etree.ElementTree`, DuckDB SQL (`UNNEST`, `SPLIT_PART`), `@lru_cache`, pytest, DLT `@app.resource`, `raw_table_asset`.

---

### Task 1: Add `_parse_mp_capabilities` helper (test-first)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/ldap.py`
- Create: `sccm/sccm/tests/test_ldap_management_points_raw.py`

The existing XML parsing logic inside `ldap_mp_site_classifications` is embedded in the loop body and has two bugs: `site_type: Optional[str] = "Secondary Site" | None` is invalid Python (bitwise-OR on a string instance), and site type strings (`"Primary"`, `"CAS"`, `"Secondary"`) don't match PS1 conventions. This task extracts the logic into a testable helper with the correct strings.

- [ ] **Step 1: Write the failing tests**

Create `sccm/sccm/tests/test_ldap_management_points_raw.py`:

```python
import pytest
from openhound_sccm.collectors.ldap import _parse_mp_capabilities


PRIMARY_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
</ClientOperationalSettings>"""

CAS_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
</ClientOperationalSettings>"""

SECONDARY_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
</ClientOperationalSettings>"""

FSP_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
  <RootSiteCode>CAS</RootSiteCode>
  <FSP>
    <FSPServer>fsp1.contoso.com</FSPServer>
    <FSPServer>fsp2.contoso.com</FSPServer>
  </FSP>
</ClientOperationalSettings>"""

STANDALONE_PRIMARY_XML = """<ClientOperationalSettings>
  <CCM CommandLine="SMSSITECODE=PS1" />
</ClientOperationalSettings>"""


def test_primary_site_with_cas_parent():
    # commandLineSiteCode == mp_site_code → Primary; root != mp → parent = root
    result = _parse_mp_capabilities(PRIMARY_XML, "PS1")
    assert result["site_type"] == "Primary Site"
    assert result["parent_site_code"] == "CAS"
    assert result["command_line_site_code"] == "PS1"
    assert result["root_site_code"] == "CAS"


def test_cas_site():
    # rootSiteCode == mp_site_code AND commandLine != mp → CAS
    result = _parse_mp_capabilities(CAS_XML, "CAS")
    assert result["site_type"] == "Central Administration Site"
    assert result["parent_site_code"] == "None"


def test_secondary_site():
    # neither condition → Secondary; parent = root_site_code
    result = _parse_mp_capabilities(SECONDARY_XML, "SEC")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "CAS"


def test_primary_standalone_no_root():
    # Primary with no hierarchy: commandLine == mp, no root → parent = "None"
    result = _parse_mp_capabilities(STANDALONE_PRIMARY_XML, "PS1")
    assert result["site_type"] == "Primary Site"
    assert result["parent_site_code"] == "None"


def test_fsp_hostnames_extracted():
    result = _parse_mp_capabilities(FSP_XML, "PS1")
    assert result["fsp_hostnames"] == ["fsp1.contoso.com", "fsp2.contoso.com"]


def test_empty_fsp_list_when_no_fsp_element():
    result = _parse_mp_capabilities(PRIMARY_XML, "PS1")
    assert result["fsp_hostnames"] == []


def test_malformed_xml_returns_safe_defaults():
    result = _parse_mp_capabilities("<<not xml>>", "PS1")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "Undetermined"
    assert result["fsp_hostnames"] == []


def test_empty_string_returns_safe_defaults():
    result = _parse_mp_capabilities("", "PS1")
    assert result["site_type"] == "Secondary Site"
    assert result["parent_site_code"] == "Undetermined"
    assert result["fsp_hostnames"] == []
```

- [ ] **Step 2: Run tests to confirm they fail**

```
cd sccm/sccm && uv run pytest tests/test_ldap_management_points_raw.py -v
```

Expected: `ImportError` — `_parse_mp_capabilities` does not exist yet.

- [ ] **Step 3: Add `_parse_mp_capabilities` to `collectors/ldap.py`**

Add this function above the `_SITE_ATTRS` constant (before any `@app.resource` decorator):

```python
import xml.etree.ElementTree as ET
```

Add this import at the top of `collectors/ldap.py` alongside the existing imports. Then add the helper function:

```python
def _parse_mp_capabilities(capabilities_str: str, mp_site_code: str) -> dict:
    """Parse mSSMSCapabilities XML into structured fields.

    Returns a dict with keys: site_type, parent_site_code,
    command_line_site_code, root_site_code, fsp_hostnames.
    Returns safe defaults on parse failure or empty input.
    """
    # Default assumption — overwritten below if XML parses successfully
    result: dict = {
        "site_type": "Secondary Site",
        "parent_site_code": "Undetermined",
        "command_line_site_code": None,
        "root_site_code": None,
        "fsp_hostnames": [],
    }
    if not capabilities_str:
        return result
    try:
        # Clean unescaped ampersands before parsing
        clean = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", str(capabilities_str))
        root = ET.fromstring(clean)

        # Extract CommandLine site code
        # ClientOperationalSettings.CCM.CommandLine contains "SMSSITECODE=XYZ"
        ccm = root.find(".//CCM")
        if ccm is not None:
            cmd = ccm.get("CommandLine", "") or ""
            if not cmd:
                cl_elem = ccm.find("CommandLine")
                cmd = (cl_elem.text or "") if cl_elem is not None else (ccm.text or "")
            m = re.search(r"SMSSITECODE=([A-Z0-9]{3})", cmd, re.IGNORECASE)
            if m:
                result["command_line_site_code"] = m.group(1).upper()

        # Extract root site code — identifies the hierarchy root
        rs = root.find("RootSiteCode") or root.find(".//RootSiteCode")
        if rs is not None and rs.text:
            result["root_site_code"] = rs.text.strip().upper()

        # Extract fallback status point hostnames
        # Each FSPServer node names a host serving as an FSP for this site
        fsp_elem = root.find("FSP") or root.find(".//FSP")
        if fsp_elem is not None:
            result["fsp_hostnames"] = [
                s.text.strip()
                for s in fsp_elem.findall("FSPServer")
                if s.text and s.text.strip()
            ]

        # Determine site type from the relationship between this MP's site code,
        # the CommandLine site code, and the root site code
        mp_code = mp_site_code.upper() if mp_site_code else ""
        cmd_code = result["command_line_site_code"]
        root_code = result["root_site_code"]

        # Check if this MP's CommandLine site code matches the site we're analyzing
        if cmd_code and cmd_code == mp_code:
            # Primary Site: an MP exists whose CommandLine.SMSSITECODE equals
            # this site's code
            result["site_type"] = "Primary Site"
            # A different root site code indicates this Primary reports to a CAS
            result["parent_site_code"] = root_code if (root_code and root_code != mp_code) else "None"
        elif root_code and root_code == mp_code and cmd_code != mp_code:
            # Central Administration Site: an MP exists whose RootSiteCode equals
            # this site's code but CommandLine.SMSSITECODE points elsewhere
            result["site_type"] = "Central Administration Site"
            result["parent_site_code"] = "None"
        else:
            # Neither condition met — Secondary Site; parent is the root if known,
            # otherwise fall back to the CommandLine site code
            result["site_type"] = "Secondary Site"
            if root_code and root_code != mp_code:
                result["parent_site_code"] = root_code
            elif cmd_code and cmd_code != mp_code:
                result["parent_site_code"] = cmd_code

    except Exception as ex:
        logger.debug("mSSMSCapabilities parse failed for %s: %s", mp_site_code, ex)
    return result
```

- [ ] **Step 4: Run tests to confirm they pass**

```
cd sccm/sccm && uv run pytest tests/test_ldap_management_points_raw.py -v
```

Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```
git add sccm/sccm/src/openhound_sccm/collectors/ldap.py sccm/sccm/tests/test_ldap_management_points_raw.py
git commit -m "feat(ldap): add _parse_mp_capabilities helper with site type and FSP extraction"
```

---

### Task 2: Rename resource and extend yield

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/ldap.py`

Replace the entire `ldap_mp_site_classifications` function with `ldap_management_points_raw`. The new version:
- Uses `_parse_mp_capabilities()` from Task 1
- Calls `ctx.register_target()` for every FSP hostname
- Yields the full flat row including `mp_hostname` and `fsp_hostnames`

- [ ] **Step 1: Replace `ldap_mp_site_classifications` with `ldap_management_points_raw`**

Remove the entire existing `ldap_mp_site_classifications` function (lines 80–180 in the current file) and replace it with:

```python
@app.resource(name="ldap_management_points_raw", parallelized=False, columns=raw_table_asset("ldap_management_points_raw"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_management_points_raw(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Management points, FSP hosts, and site classification from mSSMSManagementPoint.

    One row per mSSMSManagementPoint entry. Registers both the MP hostname and
    any FSP hostnames parsed from mSSMSCapabilities as collection targets.
    Preproc transforms derive site_types, computer_mp_roles, computer_fsp_roles,
    and computer_site_system_roles from this table.
    """
    logger.info("Collecting mSSMSManagementPoint objects in System Management container...")
    mp_count = 0

    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSManagementPoint)",
            base=ctx.system_management_dn,
            attributes=["mSSMSSiteCode", "mSSMSCapabilities", "mSSMSMPName"],
        ):
            mp_hostname = entry.get("mSSMSMPName")
            mp_site_code = (entry.get("mSSMSSiteCode") or "").strip()
            mp_code_upper = mp_site_code.upper() if mp_site_code else None

            # Register the management point as a collection target so its
            # per-host resources run in subsequent passes
            if mp_hostname:
                if not mp_site_code:
                    logger.warning("mSSMSManagementPoint missing site code: %s", mp_hostname)
                mp_target = ctx.register_target(
                    mp_hostname,
                    site_code=mp_code_upper,
                    source="LDAP-mSSMSManagementPoint",
                )
                if mp_target and mp_target.is_new:
                    logger.info("Found management point: %s (site: %s)", mp_hostname, mp_site_code)

            # Parse capabilities to determine site relationships and extract
            # FSP hostnames from the capabilities XML
            parsed = _parse_mp_capabilities(entry.get("mSSMSCapabilities") or "", mp_site_code)

            # Register each fallback status point as a collection target;
            # FSP hostnames come from FSPServer nodes inside the capabilities XML
            for fsp_hostname in parsed["fsp_hostnames"]:
                fsp_target = ctx.register_target(
                    fsp_hostname,
                    site_code=mp_code_upper,
                    source="LDAP-mSSMSManagementPoint",
                )
                if fsp_target and fsp_target.is_new:
                    logger.info("Found fallback status point: %s (site: %s)", fsp_hostname, mp_site_code)

            mp_count += 1
            # One flat row per entry; preproc transforms fan this into
            # site_types, computer_mp_roles, and computer_fsp_roles tables
            yield {
                "mp_hostname": mp_hostname,
                "site_code": mp_site_code,
                "site_type": parsed["site_type"],
                "parent_site_code": parsed["parent_site_code"],
                "command_line_site_code": parsed["command_line_site_code"],
                "root_site_code": parsed["root_site_code"],
                "fsp_hostnames": parsed["fsp_hostnames"],
            }
    except Exception as ex:
        logger.warning("ldap_management_points_raw resource failed: %s", ex)

    logger.info("Found %d mSSMSManagementPoint objects", mp_count)
```

- [ ] **Step 2: Run conformance tests to confirm the new resource registers correctly**

```
cd sccm/sccm && uv run pytest tests/test_extension_methods.py -v
```

Expected: all conformance tests PASS. If `test_extension_resources_use_models` fails, it means `raw_table_asset("ldap_management_points_raw")` isn't resolving — check that the decorator and factory name match exactly.

- [ ] **Step 3: Commit**

```
git add sccm/sccm/src/openhound_sccm/collectors/ldap.py
git commit -m "feat(ldap): rename ldap_mp_site_classifications to ldap_management_points_raw, add mp_hostname and fsp_hostnames"
```

---

### Task 3: Wire into source + update preproc table list

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/source.py`
- Modify: `sccm/sccm/src/openhound_sccm/main.py`

`ldap_mp_site_classifications` was never returned from `source()` — this is the first time the resource will actually run during collection.

- [ ] **Step 1: Update `source.py` import and return tuple**

In `sccm/sccm/src/openhound_sccm/source.py`, change:

```python
from .collectors.ldap import (
    ldap_sites,
)
```

to:

```python
from .collectors.ldap import (
    ldap_management_points_raw,
    ldap_sites,
)
```

And change the return at the bottom of `source()`:

```python
    return (
        ldap_sites(ctx),
    )
```

to:

```python
    return (
        ldap_sites(ctx),
        ldap_management_points_raw(ctx),
    )
```

- [ ] **Step 2: Rename table in `main.py` preproc list**

In `sccm/sccm/src/openhound_sccm/main.py` at line 607, change:

```python
        "ldap_mp_site_classifications",
```

to:

```python
        "ldap_management_points_raw",
```

- [ ] **Step 3: Run all tests**

```
cd sccm/sccm && uv run pytest tests/ -v
```

Expected: all tests PASS.

- [ ] **Step 4: Commit**

```
git add sccm/sccm/src/openhound_sccm/source.py sccm/sccm/src/openhound_sccm/main.py
git commit -m "feat(source): wire ldap_management_points_raw into collection and preproc table list"
```

---

### Task 4: Implement preproc transforms (test-first)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py`
- Create: `sccm/sccm/tests/test_transforms_computer_roles.py`

Adds four transforms: `site_types`, `computer_mp_roles`, `computer_fsp_roles`, `computer_site_system_roles`. All degrade gracefully when the source table is absent.

- [ ] **Step 1: Write failing transform tests**

Create `sccm/sccm/tests/test_transforms_computer_roles.py`:

```python
import duckdb
import pytest
from openhound_sccm.transforms import transforms

SCHEMA = "sccm"


@pytest.fixture
def con():
    conn = duckdb.connect(":memory:")
    conn.execute(f"CREATE SCHEMA {SCHEMA}")
    yield conn
    conn.close()


@pytest.fixture
def con_with_raw(con):
    con.execute(f"""
        CREATE TABLE {SCHEMA}.ldap_management_points_raw (
            mp_hostname VARCHAR,
            site_code VARCHAR,
            site_type VARCHAR,
            parent_site_code VARCHAR,
            command_line_site_code VARCHAR,
            root_site_code VARCHAR,
            fsp_hostnames VARCHAR[]
        )
    """)
    con.execute(f"""
        INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES
        ('mp.contoso.com', 'PS1', 'Primary Site', 'CAS', 'PS1', 'CAS', ['fsp1.contoso.com', 'fsp2.contoso.com']),
        ('cas-mp.contoso.com', 'CAS', 'Central Administration Site', 'None', 'PS1', 'CAS', []),
        (NULL, 'SEC', 'Secondary Site', 'PS1', NULL, 'PS1', [])
    """)
    return con


def test_site_types_built(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT site_code, site_type, parent_site_code FROM {SCHEMA}.site_types ORDER BY site_code"
    ).fetchall()
    assert ("CAS", "Central Administration Site", "None") in rows
    assert ("PS1", "Primary Site", "CAS") in rows
    assert ("SEC", "Secondary Site", "PS1") in rows


def test_computer_mp_roles_built(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT hostname, role FROM {SCHEMA}.computer_mp_roles"
    ).fetchall()
    assert ("mp.contoso.com", "SMS Management Point@PS1") in rows
    assert ("cas-mp.contoso.com", "SMS Management Point@CAS") in rows


def test_computer_mp_roles_excludes_null_hostname(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT hostname FROM {SCHEMA}.computer_mp_roles WHERE hostname IS NULL"
    ).fetchall()
    assert rows == []


def test_computer_fsp_roles_unnested(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT hostname, role FROM {SCHEMA}.computer_fsp_roles ORDER BY hostname"
    ).fetchall()
    assert ("fsp1.contoso.com", "SMS Fallback Status Point@PS1") in rows
    assert ("fsp2.contoso.com", "SMS Fallback Status Point@PS1") in rows
    assert len(rows) == 2  # CAS row had empty fsp_hostnames


def test_computer_site_system_roles_union(con_with_raw):
    transforms(con_with_raw)
    rows = con_with_raw.execute(
        f"SELECT hostname, role FROM {SCHEMA}.computer_site_system_roles ORDER BY hostname"
    ).fetchall()
    hostnames = [r[0] for r in rows]
    assert "mp.contoso.com" in hostnames
    assert "fsp1.contoso.com" in hostnames
    assert "fsp2.contoso.com" in hostnames
    assert "cas-mp.contoso.com" in hostnames


def test_graceful_degradation_no_raw_table(con):
    # transforms() must not crash when ldap_management_points_raw is absent
    transforms(con)
    # empty placeholder tables should exist
    for table in ("site_types", "computer_site_system_roles"):
        count = con.execute(
            f"SELECT COUNT(*) FROM information_schema.tables "
            f"WHERE table_schema = '{SCHEMA}' AND table_name = '{table}'"
        ).fetchone()[0]
        assert count == 1, f"Expected placeholder table {table} to exist"
```

- [ ] **Step 2: Run tests to confirm they fail**

```
cd sccm/sccm && uv run pytest tests/test_transforms_computer_roles.py -v
```

Expected: failures — `site_types`, `computer_mp_roles`, etc. don't exist in the transforms output yet.

- [ ] **Step 3: Add empty schema entries and build functions to `transforms.py`**

In `transforms.py`, extend `_EMPTY_SCHEMAS`:

```python
_EMPTY_SCHEMAS: dict[str, str] = {
    "site_types": "(site_code VARCHAR, site_type VARCHAR, parent_site_code VARCHAR)",
    "hierarchies": "(root_code VARCHAR, member_code VARCHAR)",
    "computer_mp_roles": "(hostname VARCHAR, role VARCHAR, site_code VARCHAR)",
    "computer_fsp_roles": "(hostname VARCHAR, role VARCHAR, site_code VARCHAR)",
    "computer_site_system_roles": "(hostname VARCHAR, role VARCHAR, site_code VARCHAR)",
}
```

Then add these four build functions after `_build_computer_sccm_infra`:

```python
def _build_site_types(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    if not _table_exists(con, schema, "ldap_management_points_raw"):
        _ensure_empty(con, schema, "site_types")
        return
    _safe_exec(
        con,
        f"""CREATE OR REPLACE TABLE {schema}.site_types AS
            SELECT site_code, site_type, parent_site_code
            FROM {schema}.ldap_management_points_raw
            WHERE site_code IS NOT NULL""",
        "site_types",
    )


def _build_computer_mp_roles(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    if not _table_exists(con, schema, "ldap_management_points_raw"):
        _ensure_empty(con, schema, "computer_mp_roles")
        return
    _safe_exec(
        con,
        f"""CREATE OR REPLACE TABLE {schema}.computer_mp_roles AS
            SELECT
                mp_hostname AS hostname,
                'SMS Management Point@' || site_code AS role,
                site_code
            FROM {schema}.ldap_management_points_raw
            WHERE mp_hostname IS NOT NULL AND site_code IS NOT NULL""",
        "computer_mp_roles",
    )


def _build_computer_fsp_roles(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    if not _table_exists(con, schema, "ldap_management_points_raw"):
        _ensure_empty(con, schema, "computer_fsp_roles")
        return
    _safe_exec(
        con,
        f"""CREATE OR REPLACE TABLE {schema}.computer_fsp_roles AS
            SELECT
                UNNEST(fsp_hostnames) AS hostname,
                'SMS Fallback Status Point@' || site_code AS role,
                site_code
            FROM {schema}.ldap_management_points_raw
            WHERE fsp_hostnames IS NOT NULL AND LEN(fsp_hostnames) > 0""",
        "computer_fsp_roles",
    )


def _build_computer_site_system_roles(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    parts: list[str] = []
    for table in ("computer_mp_roles", "computer_fsp_roles"):
        if _table_exists(con, schema, table):
            parts.append(
                f"SELECT hostname, role, site_code FROM {schema}.{table}"
            )
    if not parts:
        _ensure_empty(con, schema, "computer_site_system_roles")
        return
    _safe_exec(
        con,
        f"CREATE OR REPLACE TABLE {schema}.computer_site_system_roles AS "
        + " UNION ALL ".join(parts),
        "computer_site_system_roles",
    )
```

- [ ] **Step 4: Call the new build functions from `transforms()`**

Replace the body of `transforms()`:

```python
def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Apply all preprocessing transformations to the DuckDB lookup database."""
    _build_site_types(con, schema)
    _build_computer_mp_roles(con, schema)
    _build_computer_fsp_roles(con, schema)
    _build_computer_site_system_roles(con, schema)
    _build_computer_sccm_infra(con, schema)
```

Note: `create_joined_tables` was an example placeholder — remove the call and the function itself.

- [ ] **Step 5: Run tests to confirm they pass**

```
cd sccm/sccm && uv run pytest tests/test_transforms_computer_roles.py -v
```

Expected: all 7 tests PASS.

- [ ] **Step 6: Run full test suite**

```
cd sccm/sccm && uv run pytest tests/ -v
```

Expected: all tests PASS.

- [ ] **Step 7: Commit**

```
git add sccm/sccm/src/openhound_sccm/transforms.py sccm/sccm/tests/test_transforms_computer_roles.py
git commit -m "feat(transforms): implement site_types, computer_mp_roles, fsp_roles, and computer_site_system_roles transforms"
```

---

### Task 5: Implement `computer_site_system_roles` lookup (test-first)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/lookup.py`
- Create: `sccm/sccm/tests/test_lookup_computer_site_system_roles.py`

`Computer.as_node` at line 99 calls `self._lookup.computer_site_system_roles(self.object_sid, self.dns_host_name)` but the method doesn't exist. This task adds it.

- [ ] **Step 1: Write the failing test**

Create `sccm/sccm/tests/test_lookup_computer_site_system_roles.py`:

```python
import duckdb
import pytest
from openhound_sccm.lookup import SCCMLookup

SCHEMA = "sccm"


@pytest.fixture
def lookup():
    conn = duckdb.connect(":memory:")
    conn.execute(f"CREATE SCHEMA {SCHEMA}")
    conn.execute(f"""
        CREATE TABLE {SCHEMA}.computer_site_system_roles (
            hostname VARCHAR,
            role VARCHAR,
            site_code VARCHAR
        )
    """)
    conn.execute(f"""
        INSERT INTO {SCHEMA}.computer_site_system_roles VALUES
        ('mp.contoso.com',  'SMS Management Point@PS1',      'PS1'),
        ('fsp.contoso.com', 'SMS Fallback Status Point@PS1', 'PS1'),
        ('mp.contoso.com',  'SMS Management Point@CAS',      'CAS')
    """)
    yield SCCMLookup(conn)
    conn.close()


def test_roles_by_fqdn(lookup):
    roles = lookup.computer_site_system_roles(None, "mp.contoso.com")
    assert "SMS Management Point@PS1" in roles
    assert "SMS Management Point@CAS" in roles


def test_roles_by_short_hostname(lookup):
    # 'mp' matches SPLIT_PART('mp.contoso.com', '.', 1)
    roles = lookup.computer_site_system_roles(None, "mp")
    assert "SMS Management Point@PS1" in roles


def test_fsp_roles_returned(lookup):
    roles = lookup.computer_site_system_roles(None, "fsp.contoso.com")
    assert "SMS Fallback Status Point@PS1" in roles


def test_no_roles_returns_empty_tuple(lookup):
    roles = lookup.computer_site_system_roles(None, "unknown.contoso.com")
    assert roles == ()


def test_none_hostname_returns_empty_tuple(lookup):
    roles = lookup.computer_site_system_roles(None, None)
    assert roles == ()


def test_returns_tuple_not_list(lookup):
    roles = lookup.computer_site_system_roles(None, "mp.contoso.com")
    assert isinstance(roles, tuple)


def test_missing_table_returns_empty_tuple():
    conn = duckdb.connect(":memory:")
    conn.execute(f"CREATE SCHEMA {SCHEMA}")
    lk = SCCMLookup(conn)
    # No computer_site_system_roles table — must not raise
    roles = lk.computer_site_system_roles(None, "mp.contoso.com")
    assert roles == ()
    conn.close()
```

- [ ] **Step 2: Run test to confirm it fails**

```
cd sccm/sccm && uv run pytest tests/test_lookup_computer_site_system_roles.py -v
```

Expected: `AttributeError: 'SCCMLookup' object has no attribute 'computer_site_system_roles'`

- [ ] **Step 3: Implement `computer_site_system_roles` in `lookup.py`**

Add to `SCCMLookup` after `sites_in_hierarchy`:

```python
    @lru_cache
    def computer_site_system_roles(
        self,
        object_sid: str | None,
        dns_host_name: str | None,
    ) -> tuple[str, ...]:
        """Return SCCMSiteSystemRoles for the computer matching dns_host_name.

        Matches by full FQDN or short hostname against the hostname column
        in sccm.computer_site_system_roles (populated by preproc transforms).
        object_sid is accepted for cache-key uniqueness but hostname matching
        is used since the roles table is hostname-keyed.
        """
        if not dns_host_name:
            return ()
        hostname_lower = dns_host_name.lower()
        short = hostname_lower.split(".")[0]
        rows = self._find_all_objects(
            f"""SELECT DISTINCT role
                FROM {self.schema}.computer_site_system_roles
                WHERE LOWER(hostname) = ?
                   OR LOWER(SPLIT_PART(hostname, '.', 1)) = ?""",
            [hostname_lower, short],
        )
        return tuple(r[0] for r in rows if r and r[0])
```

- [ ] **Step 4: Run test to confirm it passes**

```
cd sccm/sccm && uv run pytest tests/test_lookup_computer_site_system_roles.py -v
```

Expected: all 7 tests PASS.

- [ ] **Step 5: Run full test suite**

```
cd sccm/sccm && uv run pytest tests/ -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```
git add sccm/sccm/src/openhound_sccm/lookup.py sccm/sccm/tests/test_lookup_computer_site_system_roles.py
git commit -m "feat(lookup): implement computer_site_system_roles resolving SCCMSiteSystemRoles at convert time"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered by |
|---|---|
| Rename resource to `ldap_management_points_raw` | Task 2 |
| Add `mp_hostname` to yield | Task 2 |
| Add `fsp_hostnames` to yield | Task 2 |
| `ctx.register_target()` for FSPs | Task 2 |
| XML parsing stays in collector (not preproc) | Task 1 helper, Task 2 |
| `site_type` strings match PS1 conventions | Task 1 (`"Primary Site"`, `"Central Administration Site"`, `"Secondary Site"`) |
| Wire into `source.py` return | Task 3 |
| Rename in `main.py` base tables | Task 3 |
| `sccm.site_types` transform | Task 4 |
| `sccm.computer_mp_roles` transform | Task 4 |
| `sccm.computer_fsp_roles` transform (UNNEST) | Task 4 |
| `sccm.computer_site_system_roles` UNION transform | Task 4 |
| Graceful degradation when raw table absent | Task 4 (`_table_exists` guards) |
| `SCCMLookup.computer_site_system_roles()` | Task 5 |
| Match by FQDN and short hostname | Task 5 |
| `@lru_cache` with `(object_sid, dns_host_name)` key | Task 5 |

**No placeholders:** All steps contain complete code.

**Type consistency:** `_parse_mp_capabilities` returns `dict` with keys `site_type`, `parent_site_code`, `command_line_site_code`, `root_site_code`, `fsp_hostnames`. Task 2 accesses `parsed["site_type"]` etc. — consistent. `computer_site_system_roles()` returns `tuple[str, ...]` — `Computer.as_node` assigns to `sccm_site_system_roles` and then `list(roles) if roles else None` — consistent (a tuple is truthy when non-empty and iterable).
