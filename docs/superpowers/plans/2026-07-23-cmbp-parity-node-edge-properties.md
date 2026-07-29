# CMBP-parity node/edge properties — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the CMBP-parity property gaps found via `--compare-to-zip`: populate AD-object properties on Computer/User/Group nodes (Phase A / ope-c141) and emit the missing SCCM properties — `SCCM_ClientDevice` telemetry, `SCCM_Site.siteSystemRoles`, `SCCM_IsMappedTo.SCCMInfra` (Phase B / ope-fb99).

**Architecture:** Phase A reuses the existing `ctx.resolve_principal` LDAP resolver (adds 2 attributes, persists its result cache to a new raw table, derives + plumbs fields in preproc/convert). Phase B is preproc derivation (`siteSystemRoles`), a one-line edge-property add (`SCCMInfra`), and source-grounded collection plumbing (`SCCM_ClientDevice` extras). Spec: `docs/superpowers/specs/2026-07-23-cmbp-parity-node-edge-properties-design.md`.

**Tech Stack:** Python 3.13+, dlt, DuckDB (preproc SQL in `transforms.py`), ldap3, pytest.

## Global Constraints

- **No git commits.** No-commit harness: each task ends at a *green checkpoint* (tests pass); the human commits. Never `git add`/`git commit`.
- **CMBP-exact casing** for new *output* property names (`Domain`, `Enabled`, `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`, `CN`, `siteSystemRoles`, `SCCMInfra`, and the `SCCM_ClientDevice` extras). DuckDB columns + model input fields stay snake_case; the graph.py `*Properties` field name IS the output key.
- **Existing camelCase AD props (`dNSHostName`, `samAccountName`, `userPrincipalName`) are NOT renamed** (casing variants ruled fine).
- **Null → pruned:** never fabricate a property; leave null so convert's `_without_null_properties` drops it.
- **Phase A reaches only principals already resolved via `resolve_principal`** — no new LDAP pass over the offline `principal_by_name` set. Partial parity is accepted and expected.
- **No schema-file changes** (`schema_SCCM.json`/`schema_MSSQL.json`) — properties aren't registered kinds.
- **Only modify `sccm/sccm/`** (and, where the plan says so, the shared `openhound-collector-common` — but this plan touches only SCCM code). Read `sccm/sccm/ARCHITECTURE.md` before the collection-touching tasks.
- **Test venv (from repo root `c:\Users\domainadmin\Desktop\OpenHound`):** `./sccm/sccm/.venv/Scripts/python.exe -m pytest <path> -v`. SCCM test files use the `*_test.py` suffix.

---

## File Structure

- `sccm/sccm/src/openhound_sccm/clients/ad.py` — extend `_ATTR_MAP` + resolver attr lists (Phase A).
- `sccm/sccm/src/openhound_sccm/context.py` — resolver attr lists; accumulate resolved principals for persistence (Phase A).
- `sccm/sccm/src/openhound_sccm/source.py` — register the `ldap_resolved_principals` resource (Phase A).
- `sccm/sccm/src/openhound_sccm/main.py` — add `ldap_resolved_principals` to `_preproc_table_map()` (Phase A).
- `sccm/sccm/src/openhound_sccm/transforms.py` — preproc: derive/join AD props onto `node_computer/user/group`; derive `node_site.siteSystemRoles`; add `SCCMInfra` to `_edge_is_mapped_to`; plumb `SCCM_ClientDevice` extras.
- `sccm/sccm/src/openhound_sccm/graph.py` — add CMBP-cased fields to `ComputerProperties`/`UserProperties`/`GroupProperties`/`SCCMSiteProperties`/`SCCMClientDeviceProperties`.
- `sccm/sccm/src/openhound_sccm/collectors/*` — `SCCM_ClientDevice` extras collection (Phase B, task-scoped after source investigation).
- Tests: `sccm/sccm/tests/*_test.py`. Docs: `README.md`, `ARCHITECTURE.md`.

---

## Phase A — AD node properties (ope-c141)

### Task A1: Fetch `userAccountControl` + `servicePrincipalName` in the resolver

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/clients/ad.py` (`_ATTR_MAP` ~line 71-75)
- Modify: `sccm/sccm/src/openhound_sccm/context.py` (`_ldap_resolve` attrs ~259-262, `_ldap_resolve_dn` attrs ~229-232)
- Test: `sccm/sccm/tests/ad_resolver_attrs_test.py`

**Interfaces:**
- Produces: resolved `ad_object` dicts now carry keys `user_account_control` and `service_principal_name` (snake_case, per `_ATTR_MAP`).

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/ad_resolver_attrs_test.py
from openhound_sccm.clients.ad import ADClient

def test_attr_map_has_uac_and_spn():
    # The shared AD client maps LDAP attribute names -> snake_case dict keys.
    m = ADClient._ATTR_MAP
    assert m.get("useraccountcontrol") == "user_account_control"
    assert m.get("serviceprincipalname") == "service_principal_name"

def test_resolver_requests_uac_and_spn():
    import openhound_sccm.context as ctx_mod
    src = ctx_mod.__file__
    text = open(src, encoding="utf-8").read()
    # Both resolver searches must request the two new attributes.
    assert text.count('"userAccountControl"') >= 2
    assert text.count('"servicePrincipalName"') >= 2
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/ad_resolver_attrs_test.py -v`
Expected: FAIL (keys/attrs absent).

- [ ] **Step 3: Implement**

In `clients/ad.py` `_ATTR_MAP`, add two entries alongside the existing ones:
```python
        "useraccountcontrol": "user_account_control",
        "serviceprincipalname": "service_principal_name",
```
In `context.py`, add `"userAccountControl", "servicePrincipalName"` to BOTH attr lists (`_ldap_resolve_dn` ~229 and `_ldap_resolve` ~259):
```python
        attrs = [
            "sAMAccountName", "objectSid", "dNSHostName", "cn",
            "distinguishedName", "objectClass", "userPrincipalName", "name",
            "userAccountControl", "servicePrincipalName",
        ]
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/ad_resolver_attrs_test.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Green checkpoint** (no commit).

---

### Task A2: Persist resolved principals to a raw `ldap_resolved_principals` table

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/context.py` (accumulate resolved objects)
- Modify: `sccm/sccm/src/openhound_sccm/source.py` (new resource)
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (`_preproc_table_map`)
- Test: `sccm/sccm/tests/ldap_resolved_principals_test.py`

**Interfaces:**
- Produces: raw table `ldap_resolved_principals`, one row per uniquely-resolved principal, columns `{sid, object_class, user_account_control, service_principal_name, cn, dns_host_name, sam_account_name, user_principal_name, distinguished_name, domain}`.

> **INVESTIGATION-FIRST (do this before coding — it determines the mechanism, and guessing here would be a placeholder):** Read `sccm/sccm/ARCHITECTURE.md` §"per-host phased pipeline"/streaming and `sccm/sccm/src/openhound_sccm/source.py` (the `source()` body + `_EMIT_RESOURCES`/`build_emit_resources`/`_drain_stream` region, ~lines 100-320) and `phased_pipeline/streams.py`. Decide the persistence mechanism between: **(a)** accumulate each successful new resolution into a `ctx.resolved_principals: dict[sid -> row]` (populated inside `resolve_principal` on cache-miss→hit) and add a plain `@app.resource(name="ldap_resolved_principals")` that yields `ctx.resolved_principals.values()` — **declared/ordered so it runs after discovery AND the per-host phases** (verify ordering; if a plain resource cannot be guaranteed to run last, use mechanism (b)); **(b)** push each resolved row onto the StreamBridge under table `ldap_resolved_principals` (same mechanism the per-host `yield "table", row` uses) and add an emit resource that drains it. Record the chosen mechanism + why in the report. Whichever is chosen, the Step-1 test below (raw table non-empty after a collect-shaped run) is the gate.

- [ ] **Step 1: Write the failing test** (mechanism-agnostic — asserts the accumulator + row shape)

```python
# sccm/sccm/tests/ldap_resolved_principals_test.py
from openhound_sccm.context import SourceContext

def test_resolve_principal_accumulates_row(monkeypatch):
    ctx = SourceContext.__new__(SourceContext)   # bypass full init
    ctx.ad_resolution_cache = {}
    ctx.discovered_domains = set()
    ctx.resolved_principals = {}
    # Stub the LDAP layer to return one AD object with the new attrs.
    obj = {"object_sid": "S-1-5-21-1-2-3-1104", "object_class": ["top", "person", "user"],
           "user_account_control": 512, "service_principal_name": [],
           "cn": "Bob", "dns_host_name": None, "sam_account_name": "bob",
           "user_principal_name": "bob@corp.local", "distinguished_name": "CN=Bob,DC=corp,DC=local"}
    monkeypatch.setattr(ctx, "_build_domains_to_try", lambda hint: ["corp.local"])
    monkeypatch.setattr(ctx, "_ldap_resolve", lambda name, domain: obj)
    got = ctx.resolve_principal("corp.local\\bob")
    assert got is obj
    # The successful resolution was recorded for persistence, keyed by SID.
    assert "S-1-5-21-1-2-3-1104" in ctx.resolved_principals
    row = ctx.resolved_principals["S-1-5-21-1-2-3-1104"]
    assert row["user_account_control"] == 512 and row["sam_account_name"] == "bob"
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/ldap_resolved_principals_test.py -v`
Expected: FAIL (`resolved_principals` attr / recording absent).

- [ ] **Step 3: Implement the accumulator + resource + preproc-map entry**

In `context.py`: add field `resolved_principals: dict[str, dict] = field(default_factory=dict)`. In `resolve_principal`, on any path that returns a non-None `result`, record it before returning (dedupe by the object's SID key — the ad_object's SID field; confirm the exact key from `clients/ad.py` `_entry_to_dict`, likely `object_sid`):
```python
        if result is not None:
            sid = result.get("object_sid")
            if sid and sid not in self.resolved_principals:
                self.resolved_principals[sid] = {
                    "sid": sid,
                    "object_class": result.get("object_class"),
                    "user_account_control": result.get("user_account_control"),
                    "service_principal_name": result.get("service_principal_name"),
                    "cn": result.get("cn"),
                    "dns_host_name": result.get("dns_host_name"),
                    "sam_account_name": result.get("sam_account_name"),
                    "user_principal_name": result.get("user_principal_name"),
                    "distinguished_name": result.get("distinguished_name"),
                    "domain": result.get("domain"),
                }
```
(Apply at the DN-resolve return, the per-domain hit return, AND the `_ldap_resolve_dn` return — every non-None result path.)
Add the resource in `source.py` per the chosen mechanism (Investigation-first). Add `"ldap_resolved_principals"` to `_preproc_table_map()` base_tables list in `main.py`.

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/ldap_resolved_principals_test.py -v`
Expected: PASS. Also add/verify a test that `"ldap_resolved_principals"` is in `_preproc_table_map()`.

- [ ] **Step 5: Green checkpoint** (no commit). Report the chosen persistence mechanism.

---

### Task A3: Preproc — derive AD props + join onto AD node tables

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (new `_ad_props` lookup + join in `_node_computer`/`_node_user`/`_node_group`)
- Test: `sccm/sccm/tests/ad_props_derive_test.py`

**Interfaces:**
- Consumes: raw `ldap_resolved_principals` (Task A2).
- Produces: `node_computer`/`node_user`/`node_group` carry columns `enabled`, `type`, `is_domain_principal`, `object_class`, `service_principal_name`, `cn`, `domain` (null where SID unresolved).

- [ ] **Step 1: Write the failing test** (unit-test the derivation SQL over a synthetic table)

```python
# sccm/sccm/tests/ad_props_derive_test.py
import duckdb
from openhound_sccm.transforms import _derive_ad_props  # new helper (Step 3)

def test_enabled_and_type_derivation():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.ldap_resolved_principals (sid VARCHAR, object_class VARCHAR[], "
                "user_account_control BIGINT, service_principal_name VARCHAR[], cn VARCHAR, "
                "dns_host_name VARCHAR, sam_account_name VARCHAR, user_principal_name VARCHAR, "
                "distinguished_name VARCHAR, domain VARCHAR)")
    con.execute("INSERT INTO sccm.ldap_resolved_principals VALUES "
                "('S-1-1', ['top','user'], 512, [], 'Bob', NULL, 'bob', 'bob@c', 'CN=Bob', 'corp.local'),"
                "('S-1-2', ['top','computer'], 4098, ['HOST/x'], 'PC1', 'pc1.c', 'PC1$', NULL, 'CN=PC1', 'corp.local')")
    _derive_ad_props(con, "sccm")   # creates sccm.ad_props
    rows = {r[0]: r for r in con.execute(
        "SELECT sid, enabled, type, is_domain_principal FROM sccm.ad_props ORDER BY sid").fetchall()}
    assert rows['S-1-1'][1] is True and rows['S-1-1'][2] == 'User'      # uac 512 -> enabled
    assert rows['S-1-2'][1] is False and rows['S-1-2'][2] == 'Computer' # uac 4098 has bit 2 -> disabled
    assert rows['S-1-1'][3] is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/ad_props_derive_test.py -v`
Expected: FAIL (`_derive_ad_props` undefined).

- [ ] **Step 3: Implement `_derive_ad_props` + wire the join**

Add to `transforms.py`:
```python
def _derive_ad_props(con, schema: str) -> None:
    """Build sccm.ad_props (sid -> CMBP-parity AD attributes) from ldap_resolved_principals.

    Enabled = userAccountControl bit 2 (ACCOUNTDISABLE) clear; Type = last objectClass
    element title-cased; IsDomainPrincipal = True for every resolved principal.
    """
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.ad_props AS
        SELECT
            sid,
            CASE WHEN user_account_control IS NULL THEN NULL
                 ELSE (user_account_control & 2) = 0 END       AS enabled,
            CASE WHEN object_class IS NULL OR len(object_class) = 0 THEN NULL
                 ELSE upper(substr(object_class[-1],1,1)) || lower(substr(object_class[-1],2)) END AS type,
            TRUE                                                AS is_domain_principal,
            object_class,
            service_principal_name,
            cn,
            domain
        FROM {schema}.ldap_resolved_principals
    """)
```
Call `_derive_ad_props(con, schema)` in the preproc pipeline before the AD node builders, and in each of `_node_computer`/`_node_user`/`_node_group`, LEFT JOIN `ad_props` on the node's SID, selecting `enabled, type, is_domain_principal, object_class, service_principal_name, cn, domain` into the node table (guard with `_ensure_columns`/coalesce per the existing dlt-coalesce pattern so an absent `ad_props`/all-NULL column doesn't drop the source — see the [[SCCM dlt coalesce gotchas]] pattern already used throughout `transforms.py`).

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/ad_props_derive_test.py -v`
Expected: PASS.

- [ ] **Step 5: Green checkpoint** (no commit).

---

### Task A4: Graph fields + convert emit (Computer/User/Group)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/graph.py` (`ComputerProperties`, `UserProperties`, `GroupProperties`)
- Modify: the AD node models if they construct the property dataclass explicitly (`models/computer.py`, `models/user.py`, `models/group.py`) — pass the new columns through.
- Test: `sccm/sccm/tests/ad_node_props_emit_test.py`

**Interfaces:**
- Consumes: node table columns from Task A3.
- Produces: emitted Computer/User/Group nodes carry `Domain`, `Enabled`, `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`, `CN` (CMBP casing); null pruned.

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/ad_node_props_emit_test.py
from openhound_sccm.graph import ComputerProperties, UserProperties, GroupProperties

def test_ad_props_fields_exist_with_cmbp_casing():
    for cls in (ComputerProperties, UserProperties, GroupProperties):
        names = cls.__dataclass_fields__
        for f in ("Domain", "Enabled", "IsDomainPrincipal", "Type", "objectClass", "servicePrincipalName", "CN"):
            assert f in names, f"{cls.__name__} missing {f}"
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/ad_node_props_emit_test.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Add to each of `ComputerProperties`/`UserProperties`/`GroupProperties` (kw_only fields, documented in the `Attributes` docstring):
```python
    Domain: str | None = field(default=None, kw_only=True)
    Enabled: bool | None = field(default=None, kw_only=True)
    IsDomainPrincipal: bool | None = field(default=None, kw_only=True)
    Type: str | None = field(default=None, kw_only=True)
    objectClass: list[str] | None = field(default=None, kw_only=True)
    servicePrincipalName: list[str] | None = field(default=None, kw_only=True)
    CN: str | None = field(default=None, kw_only=True)
```
Thread the values from the node-table columns in the models' `as_node`/`to_node` (map snake_case column → CMBP-cased field). Follow the existing per-model pattern for reading node-table columns.

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/ad_node_props_emit_test.py -v`
Expected: PASS. Also run the existing AD-node model tests (`computer_test.py`, `user_test.py`, `ad_test.py`) to confirm no regression.

- [ ] **Step 5: Green checkpoint** (no commit).

---

## Phase B — SCCM node/edge properties (ope-fb99)

### Task B1: `SCCM_Site.siteSystemRoles` (preproc derivation, no new collection)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (`_node_site`)
- Modify: `sccm/sccm/src/openhound_sccm/graph.py` (`SCCMSiteProperties`)
- Test: `sccm/sccm/tests/site_system_roles_test.py`

**Interfaces:**
- Consumes: `node_computer.SCCMSiteSystemRoles` (existing, `"<role>@<site>"` entries).
- Produces: `SCCMSiteProperties.siteSystemRoles: list[str]` = `"<dnsHostName>: <role>@<site>"` for each site-system computer whose role suffix matches the site (CMBP ps1:1851-1897).

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/site_system_roles_test.py
import duckdb
from openhound_sccm.transforms import _derive_site_system_roles  # new helper

def test_site_system_roles_aggregation():
    con = duckdb.connect(); con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.node_site (id VARCHAR)")
    con.execute("INSERT INTO sccm.node_site VALUES ('PS1')")
    con.execute("CREATE TABLE sccm.node_computer (dns_host_name VARCHAR, sccm_site_system_roles VARCHAR[])")
    con.execute("INSERT INTO sccm.node_computer VALUES "
                "('ps1-mp.corp.local', ['SMS Management Point@PS1']),"
                "('other.corp.local', ['SMS Site System@CAS'])")
    out = _derive_site_system_roles(con, "sccm")   # returns {site_id: [entries]}
    assert out['PS1'] == ['ps1-mp.corp.local: SMS Management Point@PS1']
```

- [ ] **Step 2: Run to verify it fails** → `_derive_site_system_roles` undefined.

- [ ] **Step 3: Implement** a helper that, per `node_site.id`, collects `dns_host_name || ': ' || role` for each `node_computer` whose `sccm_site_system_roles` entry ends `@<site.id>`; store the aggregated list into a `site_system_roles` column on `node_site`. Add `siteSystemRoles: list[str] = field(default_factory=list, kw_only=True)` to `SCCMSiteProperties` (documented) and thread it in `models/sccm_site.py`.

- [ ] **Step 4: Run to verify it passes** (+ run `sccm_site` existing tests for no regression).

- [ ] **Step 5: Green checkpoint** (no commit).

---

### Task B2: `SCCM_IsMappedTo.SCCMInfra = true`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (`_edge_is_mapped_to`)
- Modify: `sccm/sccm/src/openhound_sccm/models/graph_edge.py` if edge props are typed there / or the edge property bag
- Test: `sccm/sccm/tests/edge_is_mapped_to_sccminfra_test.py`

**Interfaces:**
- Produces: every `SCCM_IsMappedTo` edge row carries property `SCCMInfra = true`.

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/edge_is_mapped_to_sccminfra_test.py
# (Pattern: mirror an existing edge test that runs _edge_is_mapped_to over a synthetic
# graph_edges + asserts the emitted edge's properties. Read graph_edges_coercion_cols_test.py
# for the harness shape.) Assert the SCCM_IsMappedTo row has SCCMInfra truthy.
```

- [ ] **Step 2-4:** Add `SCCMInfra` to the `SCCM_IsMappedTo` insert in `_edge_is_mapped_to` (a literal `true`), threaded through the edge property emission (SCCMRelayEdgeProperties/SCCMEdgeProperties don't carry it today — add an `SCCMInfra: bool | None` to the base `SCCMEdgeProperties` OR set it via the graph_edges column path used for coercion props; follow whichever mechanism `graph_edge.py` uses to attach per-edge properties). Run the test → PASS.

- [ ] **Step 5: Green checkpoint** (no commit).

---

### Task B3: `SCCM_ClientDevice` telemetry extras

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/*` (source of each field — determined in Step 0), `transforms.py` (`_node_client_device`), `graph.py` (`SCCMClientDeviceProperties`)
- Test: `sccm/sccm/tests/client_device_extras_test.py`

**Interfaces:**
- Produces: `SCCM_ClientDevice` nodes carry `currentManagementPoint`, `currentManagementPointSID`, `previousSMSID`, `previousSMSIDChangeDate`, `userName`, `userDomainName`, `lastReportedMPServerSID` where the source provides them (null pruned otherwise).

- [ ] **Step 0 — INVESTIGATION-FIRST (required; produces the source map, not a guess):** For EACH property, read the exact CMBP source and confirm the OpenHound raw table that carries (or must carry) it, citing lines:
  - `currentManagementPoint`/`currentManagementPointSID`/`previousSMSID`/`previousSMSIDChangeDate` — CMBP ps1:3907-4016 read them from **local WMI `root\CCM SMS_Authority`** on the collector host (Local phase). Map to OpenHound's Local collector raw table (`local_wmi_sms_authority` / `local_wmi_ccm_client`); check whether those already carry the fields (grep the raw JSONL under `sccm/sccm/output/sccm/local_wmi_*`).
  - `userName`/`userDomainName`/`lastReportedMPServerSID` — find CMBP's assignment (grep for the SMS_R_System / device-resource field, e.g. `LastLogonUserName`/`LastLogonUserDomain`/`UserName`); check `sccm/sccm/output/sccm/adminservice_r_system` / `adminservice_client_devices` raw rows for the field. Some already exist on `SCCMClientDeviceProperties` (e.g. `currentLogonUser`) — reuse, don't duplicate.
  Write the resulting `property -> {cmbp_line, source_table, raw_field}` table into the task report. THEN implement only what's genuinely uncollected; the rest is preproc plumbing.

- [ ] **Step 1: Write the failing test** — synthetic raw rows (per the Step-0 map) → assert `_node_client_device` emits the extras onto the node row.

- [ ] **Step 2-4:** Extend the relevant collector(s) to carry any uncollected field (matching the local-WMI/AdminService source), plumb through `_node_client_device`, add the fields to `SCCMClientDeviceProperties` (CMBP casing, documented). Run the test → PASS. Run existing `sccm_client_device` tests for no regression.

- [ ] **Step 5: Green checkpoint** (no commit).

---

### Task C1: Docs + live re-validation

**Files:** `sccm/sccm/README.md`, `sccm/sccm/ARCHITECTURE.md`.

- [ ] **Step 1:** README Node Reference — add the new Computer/User/Group AD props, `SCCM_Site.siteSystemRoles`, and the `SCCM_ClientDevice` extras; Edge Reference — note `SCCM_IsMappedTo.SCCMInfra`.
- [ ] **Step 2:** ARCHITECTURE.md — new subsection (capturing AD-object attributes from the resolution cache via `ldap_resolved_principals`; note it's resolved-principals-only = partial parity by design) + a changelog row. No schema-file changes.
- [ ] **Step 3 — live re-validation:** regenerate the graph (reprocess the cached bucket per `[[sccm-live-parity-recheck]]`: `preprocess` over `output`, then `convert`), then `compare_to_zip` vs the CMBP baseline zip. Confirm the previously-`only_in_b` AD props now match for resolved principals and the Phase-B SCCM props match; document the expected residual (offline-resolved principals still bare — by design). Write a short `sccm/tests/live-comparison/parity_props_check/SUMMARY.md`; gitignore bulky artifacts.
- [ ] **Step 4: Green checkpoint** — run the full new-test set + a broad SCCM regression sweep.

---

## Self-Review

**Spec coverage:** Phase A collect (A1 attrs, A2 persist) → preproc (A3 derive/join) → graph (A4) ✓; Phase B siteSystemRoles (B1) ✓, IsMappedTo.SCCMInfra (B2) ✓, ClientDevice extras (B3) ✓; docs + live re-validation (C1) ✓. Scope "resolved-principals-only" reflected in A3/C1 ✓. CMBP-casing in A4/B1/B2/B3 ✓. No schema changes ✓.

**Placeholder scan:** Two tasks (A2 persistence mechanism, B3 field sourcing) are deliberately **investigation-first with a concrete deliverable + gating test**, because the persistence mechanism depends on unread StreamBridge internals and the ClientDevice field sources need cached-row confirmation — fabricating either would be a false-complete placeholder. Every other step carries complete code + exact commands. This is the honest treatment for cross-cutting collection work; the investigation steps cite exact files/lines to read and produce a recorded mapping/mechanism the implementer then codes against.

**Type consistency:** raw columns snake_case (`user_account_control`, `service_principal_name`, `object_class`) → derived `ad_props` columns (`enabled`, `type`, `is_domain_principal`) → CMBP-cased graph fields (`Enabled`, `Type`, `IsDomainPrincipal`, `objectClass`, `servicePrincipalName`, `CN`, `Domain`). `_derive_ad_props`/`_derive_site_system_roles` helper names consistent between their defining task and tests. `resolved_principals` dict keyed by `sid` consistent A2↔A3.

**Known grounding points (flagged, not placeholders):** the A2 SID key name (`object_sid` vs other) — confirm from `clients/ad.py` `_entry_to_dict`; the A2 ordering mechanism; the B3 per-property source map. Each has a cited investigation step and a gating test.
