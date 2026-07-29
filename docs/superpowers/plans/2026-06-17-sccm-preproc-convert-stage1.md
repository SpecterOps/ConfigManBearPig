# SCCM preproc + convert — Stage 1 (Base nodes + Site + hierarchy) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Stage 0's synthetic spike with the first real graph: coalesce each entity from its many collected tables into one row per identity in DuckDB, then emit **Computer / User / Group** nodes (keyed by SID) and **SCCM_Site** nodes (keyed by site code) plus the **SCCM_AdminsReplicatedTo** site↔site edge — all through the Stage 0 Convert2-Read-DB pipeline.

**Architecture:** `preproc` (`transforms.py`) builds `principal_by_name`, a site hierarchy with `root_site_code`, four `node_*` coalesce tables, and a `graph_edges` table — all set-based SQL. `convert` runs the Stage 0 Convert2-Read-DB pipeline, which now reads those real tables and instantiates a typed model per table whose `as_node`/`edges` produce the OpenGraph content. No framework core changes.

**Tech Stack:** Python 3.13+, `dlt`, `duckdb`, `openhound` (v0.2.x), `pytest`, `uv`.

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Never edit OpenHound core (`openhound/...`). (CLAUDE.md)
- **Do NOT `git commit`.** Stage with `git add`; the user commits after testing. Each task ends at a checkpoint, not a commit. (CLAUDE.md)
- **Validate in an isolated uv env** (already synced from Stage 0): `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest <abs test path> -v`. Do not use/modify the repo `.venv`. (AGENTS.md)
- **Log every `if`/`else` and `try`/`except` branch** at an appropriate level, or leave a comment. (CLAUDE.md)
- **Simplicity/YAGNI** — coalescing is set-based SQL (`GROUP BY`), models stay trivial `row → node` / `row → edge`.
- **Node property keys are lowercase, `_`-separated** (e.g. `sccm_site_system_roles`, `site_guid`, `sql_server_name`) — required by an upcoming OpenGraph release. Never emit PascalCase/camelCase keys. Human-friendly capitalization is deferred to `schema.json` display names later, not the emitted keys. The core keys (`name`, `displayname`, `environmentid`, `last_seen`) already comply.
- Tests live next to code as `<module>_test.py`.

### Node identity & `environmentid` (locked — spec §2 "Root/environment node")
- **id (ObjectIdentifier):** Computer/User/Group = **SID** (uppercased). SCCM_Site = **site code**.
- **`environmentid`:**
  - Computer/User/Group = the node's **AD domain SID** = `domain_environment_id(sid)` (strip the RID from `S-1-5-21-X-Y-Z-RID`).
  - Well-known/builtin SIDs (`S-1-5-32-*`, `S-1-5-11`, …) have no domain SID → qualify with the domain SID from the record that produced them (`fallback_domain_sid`); drop + log if none.
  - SCCM_Site = the hierarchy **`root_site_code`**.
- **Merge key** is the node `id`; `environmentid` only scopes. No environment *node* is emitted.

- Schema map (real column names per source table), CMBP node properties, hierarchy algorithm, and the recovered `SCCMSite` shape are summarized inline per task. Spec: [`../specs/2026-06-16-sccm-preproc-convert-design.md`](../specs/2026-06-16-sccm-preproc-convert-design.md). All paths relative to `sccm/sccm/`.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/openhound_sccm/graph.py` | **create** — `SCCMNode` (concrete `Node` with direct `id`), per-kind property dataclasses, and `domain_environment_id(sid, fallback_domain_sid=None)`. |
| `src/openhound_sccm/models/computer.py` / `user.py` / `group.py` / `sccm_site.py` | **create** — `BaseAsset` models; `as_node` builds the node from a coalesced row. |
| `src/openhound_sccm/models/replication_edge.py` | **create** — edge model reading `graph_edges`. |
| `src/openhound_sccm/transforms.py` | **modify** — add `principal_by_name`, hierarchy/`root_site_code`, `node_computer/user/group/site`, `graph_edges`; drop the spike. |
| `src/openhound_sccm/convert_pipeline.py` | **modify** — emit via `(table, model)` specs instead of the hardcoded spike shapers. |
| `src/openhound_sccm/main.py` | **modify** — register the node/edge specs for convert; rebuild `_preproc_table_map()` to real tables. |
| `src/openhound_sccm/collectors/ldap.py` | **modify** — restore `from ..models import SCCMSite` (fixes the `NameError`). |
| `README.md` | **modify** — Node/Edge Reference for the new kinds; relax the "minimal output" Limitation (Assumptions already added). |
| `src/openhound_sccm/*_test.py`, `models/*_test.py` | **create** — per-task tests. |

**Convert registry pattern (used from Task 3 on):** `convert_pipeline.emit_graph_from_duckdb` takes `node_specs: list[tuple[str, type[BaseAsset]]]` and `edge_specs: list[tuple[str, type[BaseAsset]]]`. `main.py` owns the two lists and grows them as tasks land. For each row it does `model(**row)`, injects `_lookup`, and emits `asdict(as_node)` / `[asdict(e) for e in edges]`.

---

## Task 1: `graph.py` — base node dataclasses + `domain_environment_id`

**Files:** Create `src/openhound_sccm/graph.py`, `src/openhound_sccm/graph_test.py`.

**Interfaces — Produces:**
- `domain_environment_id(sid: str, fallback_domain_sid: str | None = None) -> str | None`
- `SCCMNode(Node)` — dataclass with `id: str`, `kinds: list[str]`, `properties: NodeProperties`.
- Property dataclasses: `ComputerProperties`, `UserProperties`, `GroupProperties`, `SCCMSiteProperties` (all extend core `NodeProperties`).

- [ ] **Step 1: Write the failing test**

```python
# src/openhound_sccm/graph_test.py
from dataclasses import asdict
from openhound_sccm.graph import domain_environment_id, SCCMNode, ComputerProperties


def test_domain_env_id_strips_rid():
    assert domain_environment_id("S-1-5-21-11-22-33-1104") == "S-1-5-21-11-22-33"


def test_domain_env_id_uppercases():
    assert domain_environment_id("s-1-5-21-11-22-33-500") == "S-1-5-21-11-22-33"


def test_domain_env_id_builtin_uses_fallback():
    assert domain_environment_id("S-1-5-32-544", fallback_domain_sid="S-1-5-21-11-22-33") == "S-1-5-21-11-22-33"


def test_domain_env_id_builtin_no_fallback_is_none():
    assert domain_environment_id("S-1-5-11") is None


def test_domain_env_id_empty_is_none():
    assert domain_environment_id("") is None


def test_sccm_node_serializes_id_kinds_properties():
    node = SCCMNode(
        id="S-1-5-21-11-22-33-1104",
        kinds=["Computer", "Base"],
        properties=ComputerProperties(name="HOST1", displayname="HOST1", environmentid="S-1-5-21-11-22-33"),
    )
    d = asdict(node)
    assert d["id"] == "S-1-5-21-11-22-33-1104"
    assert d["kinds"] == ["Computer", "Base"]
    assert d["properties"]["name"] == "HOST1"
    assert d["properties"]["environmentid"] == "S-1-5-21-11-22-33"
```

- [ ] **Step 2: Run — expect failure** (`ModuleNotFoundError: openhound_sccm.graph`).
Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/graph_test.py -v`

- [ ] **Step 3: Implement**

```python
# src/openhound_sccm/graph.py
"""Base OpenGraph node/edge dataclasses + shared helpers for the SCCM collector.

Concrete node models (models/*.py) build these in their `as_node`. `SCCMNode`
supplies the `id` directly (we already know the SID / site code), unlike the
framework's UUID-deriving base. `domain_environment_id` derives the AD-domain SID
used as `environmentid` for Base AD nodes (spec §2 "Root/environment node").
"""
import re
from dataclasses import dataclass, field

from openhound.core.models.entries_dataclass import Node, NodeProperties

# A domain SID is the `S-1-5-21-X-Y-Z` prefix; an account SID appends `-RID`.
_DOMAIN_SID = re.compile(r"^(S-1-5-21(?:-\d+){3})-\d+$")


def domain_environment_id(sid: str, fallback_domain_sid: str | None = None) -> str | None:
    """Return the AD-domain SID to use as `environmentid` for a Base AD node.

    - Normal account SID `S-1-5-21-X-Y-Z-RID` -> `S-1-5-21-X-Y-Z`.
    - Well-known/builtin SID (no `S-1-5-21` domain part, e.g. `S-1-5-32-544`,
      `S-1-5-11`) -> `fallback_domain_sid` (the domain SID known from the record
      that produced this principal; SharpHound-style per-domain qualification).
    - `None` if neither applies; caller drops the node and logs.
    """
    if not sid:
        return None
    m = _DOMAIN_SID.match(sid.upper())
    if m:
        return m.group(1)
    return fallback_domain_sid


@dataclass
class SCCMNode(Node):
    """Concrete SCCM node: `id` is supplied directly (no UUID derivation)."""
    id: str = ""

    def __post_init__(self):
        # id is set by the caller; nothing to derive. (Node declares this abstract.)
        return


@dataclass
class ComputerProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_site_system_roles: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=False, kw_only=True)
    sccm_resource_ids: list[str] = field(default_factory=list, kw_only=True)
    sccm_client_device_identifier: str | None = field(default=None, kw_only=True)
    smb_signing_required: bool | None = field(default=None, kw_only=True)
    sccm_has_client_remote_control_spn: bool = field(default=False, kw_only=True)
    network_boot_server: bool = field(default=False, kw_only=True)
    disable_loopback_check: bool | None = field(default=None, kw_only=True)
    restrict_receiving_ntlm_traffic: str | None = field(default=None, kw_only=True)
    sccm_client_certificate_required: bool | None = field(default=None, kw_only=True)
    sccm_hosts_content_library: bool | None = field(default=None, kw_only=True)
    sccm_is_pxe_support_enabled: bool | None = field(default=None, kw_only=True)


@dataclass
class UserProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_resource_ids: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=False, kw_only=True)
    stored_in_sccm_site: str | None = field(default=None, kw_only=True)


@dataclass
class GroupProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_infra: bool = field(default=False, kw_only=True)
    sccm_resource_ids: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class SCCMSiteProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    site_code: str | None = field(default=None, kw_only=True)
    parent_site_code: str | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    site_type: str | None = field(default=None, kw_only=True)
    site_guid: str | None = field(default=None, kw_only=True)
    site_server_name: str | None = field(default=None, kw_only=True)
    sql_server_name: str | None = field(default=None, kw_only=True)
    sql_database_name: str | None = field(default=None, kw_only=True)
    version: str | None = field(default=None, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)
```

- [ ] **Step 4: Run — expect PASS** (6 tests). Same command as Step 2.
- [ ] **Step 5: Checkpoint** — `git add src/openhound_sccm/graph.py src/openhound_sccm/graph_test.py` (stage only).

---

## Task 2: `transforms.py` — `principal_by_name` + site hierarchy / `root_site_code`

Builds the two cross-cutting preproc tables the node coalesces depend on. Replace the Stage-0 `_build_spike` body but KEEP `transforms(con, schema="sccm")` as the entrypoint (spike removal happens in Task 8 once the real node tables exist).

**Source facts (verified):** `(name, SID)` pairs for `principal_by_name` come from `adminservice_r_system`/`wmi_r_system` (`name`,`sid`), `adminservice_r_user`/`wmi_r_user` (`name`,`sid`), AD-resolved tables (`object_sid`,`name`/`dns_host_name`), and `adminservice_admins`/`wmi_admins` (`admin_sid`,`logon_name`). Hierarchy parent fields: `adminservice_sites.reporting_site_code`, `adminservice_site_definitions.parent_site_code`, `site_type`/`type`. Root = the CAS (type 4) or a parentless Primary (type 2) (CMBP `Get-HierarchyRoot` ps1:2620).

**Files:** Modify `src/openhound_sccm/transforms.py`; create `src/openhound_sccm/transforms_principal_test.py`.

**Interfaces — Produces:** in DuckDB after `transforms(con)`: `{schema}.principal_by_name(name, sid)` (deduped, upper(sid)), `{schema}.site_hierarchy(site_code, parent_site_code, site_type, root_site_code)`.

- [ ] **Step 1: Write the failing test**

```python
# src/openhound_sccm/transforms_principal_test.py
import duckdb
from openhound_sccm.transforms import transforms


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'HOST1' AS name, 'S-1-5-21-1-2-3-1104' AS sid")
    con.execute("CREATE TABLE sccm.adminservice_r_user   AS SELECT 'alice' AS name, 's-1-5-21-1-2-3-1106' AS sid")
    # two-site hierarchy: CAS 'CAS' (type 4), Primary 'PS1' (type 2, parent CAS)
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS "
                "SELECT * FROM (VALUES ('CAS', NULL, 4), ('PS1', 'CAS', 2)) AS t(site_code, parent_site_code, site_type)")


def test_principal_by_name_unions_and_uppercases():
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    rows = dict(con.execute("SELECT name, sid FROM sccm.principal_by_name ORDER BY name").fetchall())
    assert rows == {"HOST1": "S-1-5-21-1-2-3-1104", "alice": "S-1-5-21-1-2-3-1106"}


def test_root_site_code_resolves_to_cas():
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    roots = dict(con.execute("SELECT site_code, root_site_code FROM sccm.site_hierarchy ORDER BY site_code").fetchall())
    assert roots == {"CAS": "CAS", "PS1": "CAS"}
```

- [ ] **Step 2: Run — expect failure** (tables/functions missing or wrong values).
Run: `… pytest …/transforms_principal_test.py -v`

- [ ] **Step 3: Implement** — rewrite `transforms.py` (keep the spike builder for now; Task 8 removes it):

```python
# src/openhound_sccm/transforms.py
"""DuckDB transforms for the SCCM collector's preproc phase.

Stage 1 builds the cross-cutting lookup tables (`principal_by_name`, site hierarchy
with `root_site_code`) and — added in later tasks — the coalesced `node_*` tables and
`graph_edges`. Each builder is defensive: a missing source table is logged and
skipped (early stages won't have collected everything).
"""
import logging

import duckdb

logger = logging.getLogger(__name__)


def _safe(con, label, sql):
    """Run one CREATE statement; log and continue if a source table is missing."""
    try:
        con.execute(sql)
    except duckdb.CatalogException as err:
        logger.warning("transform %r skipped (missing source): %s", label, err)
    except duckdb.Error as err:
        logger.error("transform %r failed: %s", label, err)


def _build_spike(con, schema):
    """Stage-0 spike (removed in Stage 1 Task 8 once real node tables exist)."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.node_spike AS SELECT 'SPIKE-1' AS id, 'spike' AS name")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.graph_edges AS "
                "SELECT 'SPIKE-1' AS start_id, 'SPIKE-1' AS end_id, 'SCCM_Spike' AS kind")


def _principal_by_name(con, schema):
    """Union every collected (name, SID) pair for offline name->SID resolution."""
    parts = [
        f"SELECT name, sid FROM {schema}.adminservice_r_system WHERE sid IS NOT NULL",
        f"SELECT name, sid FROM {schema}.wmi_r_system WHERE sid IS NOT NULL",
        f"SELECT name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL",
        f"SELECT name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL",
        f"SELECT logon_name AS name, admin_sid AS sid FROM {schema}.adminservice_admins WHERE admin_sid IS NOT NULL",
        f"SELECT logon_name AS name, admin_sid AS sid FROM {schema}.wmi_admins WHERE admin_sid IS NOT NULL",
    ]
    # Each source is optional; build from whichever exist by trying a UNION and
    # falling back per-part is overkill — instead create an empty base then INSERT.
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.principal_by_name (name VARCHAR, sid VARCHAR)")
    for sql in parts:
        _safe(con, "principal_by_name", f"INSERT INTO {schema}.principal_by_name SELECT upper(trim(name)), upper(sid) FROM ({sql})")
    # dedup
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.principal_by_name AS "
        f"SELECT DISTINCT name, sid FROM {schema}.principal_by_name WHERE name IS NOT NULL AND sid IS NOT NULL"
    )


def _site_hierarchy(con, schema):
    """Build site_code/parent_site_code/site_type, then stamp root_site_code.

    Root = the CAS (type 4) if present, else a parentless Primary (type 2),
    matching CMBP Get-HierarchyRoot (ps1:2620). Single-hierarchy assumption
    (README Assumptions): one root per graph.
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.site_hierarchy (site_code VARCHAR, parent_site_code VARCHAR, site_type INTEGER)")
    _safe(con, "site_hierarchy<-adminservice", f"INSERT INTO {schema}.site_hierarchy "
          f"SELECT site_code, parent_site_code, TRY_CAST(site_type AS INTEGER) FROM {schema}.adminservice_site_definitions")
    _safe(con, "site_hierarchy<-wmi", f"INSERT INTO {schema}.site_hierarchy "
          f"SELECT site_code, parent_site_code, TRY_CAST(site_type AS INTEGER) FROM {schema}.wmi_site_definitions")
    # collapse duplicate site rows
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.site_hierarchy AS "
        f"SELECT site_code, any_value(parent_site_code) AS parent_site_code, max(site_type) AS site_type "
        f"FROM {schema}.site_hierarchy WHERE site_code IS NOT NULL GROUP BY site_code"
    )
    # root: CAS (4) if any, else a parentless Primary (2), else NULL.
    root = con.execute(
        f"SELECT site_code FROM {schema}.site_hierarchy WHERE site_type = 4 "
        f"UNION ALL SELECT site_code FROM {schema}.site_hierarchy "
        f"  WHERE site_type = 2 AND (parent_site_code IS NULL OR parent_site_code IN ('', 'None', 'Undetermined')) "
        f"LIMIT 1"
    ).fetchone()
    root_code = root[0] if root else None
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.site_hierarchy AS "
        f"SELECT site_code, parent_site_code, site_type, ? AS root_site_code FROM {schema}.site_hierarchy",
        [root_code],
    )


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Top-level transform entrypoint (registered via @app.preproc(transformer=transforms))."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    _build_spike(con, schema)          # removed in Task 8
    _principal_by_name(con, schema)
    _site_hierarchy(con, schema)
```

- [ ] **Step 4: Run — expect PASS** (2 tests). Iterate the SQL against the test if DuckDB raises a type error.
- [ ] **Step 5: Checkpoint** — `git add src/openhound_sccm/transforms.py src/openhound_sccm/transforms_principal_test.py`.

---

## Task 3: `node_computer` coalesce + `ComputerNode` + wire the real-model pipeline

First real node, end to end. Refactors `convert_pipeline.emit_graph_from_duckdb` to drive typed models via `(table, model)` specs, and registers Computer.

**Source facts (verified, computer SID column varies):** `adminservice_r_system`/`wmi_r_system` use `sid`; AD-resolved tables (`ldap_cmrc_devices`, `remoteregistry_computers`, `smb_computers`, `*_site_definitions_computers`) use `object_sid`. Role strings: `system_roles` (r_system) and `sccm_site_system_roles` (others, string-or-list). Drop `obsolete` r_system rows. `resource_id`+`source_site_code` → `sccm_resource_ids` (`"<rid>@<site>"`). `sms_unique_identifier` → `sccm_client_device_identifier`. `smb_signing_required` from registry/smb.

**Files:** Modify `transforms.py`, `convert_pipeline.py`, `main.py`; create `models/computer.py`, `models/computer_test.py`, `node_computer_test.py`.

**Interfaces:**
- Produces `{schema}.node_computer(sid, name, dnshostname, sam_account_name, resource_ids[], site_system_roles[], sccm_infra, sms_unique_identifier, smb_signing_required, sccm_has_client_remote_control_spn, network_boot_server, disable_loopback_check, restrict_receiving_ntlm_traffic, sccm_client_certificate_required, sccm_hosts_content_library, sccm_is_pxe_support_enabled)` — one row per uppercased SID.
- `ComputerNode(BaseAsset)` with `as_node -> SCCMNode | None`.
- `emit_graph_from_duckdb(lookup, output_path, source_kind, node_specs, edge_specs)` — new signature.
- Consumes `domain_environment_id` (Task 1), `SCCMLookup.table_rows` (Stage 0).

- [ ] **Step 1: Write the failing tests**

```python
# src/openhound_sccm/node_computer_test.py
import duckdb
from openhound_sccm.transforms import transforms


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # same machine from two sources: r_system (sid) + smb (object_sid), different roles
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT "
                "'HOST1' AS name, 'S-1-5-21-1-2-3-1104' AS sid, false AS obsolete, 7 AS resource_id, "
                "'PS1' AS source_site_code, 'SMS Provider' AS system_roles, 'GUID:abc' AS sms_unique_identifier")
    con.execute("CREATE TABLE sccm.smb_computers AS SELECT "
                "'S-1-5-21-1-2-3-1104' AS object_sid, 'HOST1' AS name, 'host1.lab' AS dns_host_name, "
                "true AS smb_signing_required, 'SMS Distribution Point' AS sccm_site_system_roles, true AS sccm_infra")


def test_node_computer_coalesces_one_row_per_sid():
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    rows = con.execute("SELECT sid, name, dnshostname, sccm_infra, sms_unique_identifier, smb_signing_required, "
                       "list_sort(site_system_roles), list_sort(resource_ids) FROM sccm.node_computer").fetchall()
    assert len(rows) == 1
    sid, name, dns, infra, smsid, signing, roles, rids = rows[0]
    assert sid == "S-1-5-21-1-2-3-1104"
    assert dns == "host1.lab"
    assert infra is True
    assert smsid == "GUID:abc"
    assert signing is True
    assert roles == ["SMS Distribution Point", "SMS Provider"]
    assert rids == ["7@PS1"]
```

```python
# src/openhound_sccm/models/computer_test.py
from openhound_sccm.models.computer import ComputerNode


def test_computer_as_node():
    row = {"sid": "S-1-5-21-1-2-3-1104", "name": "HOST1", "dnshostname": "host1.lab",
           "sccm_infra": True, "site_system_roles": ["SMS Provider"], "resource_ids": ["7@PS1"],
           "sms_unique_identifier": "GUID:abc", "smb_signing_required": True, "sam_account_name": "HOST1$"}
    node = ComputerNode(**row).as_node
    assert node.id == "S-1-5-21-1-2-3-1104"
    assert node.kinds == ["Computer", "Base"]
    assert node.properties.environmentid == "S-1-5-21-1-2-3"
    assert node.properties.sccm_site_system_roles == ["SMS Provider"]


def test_computer_no_sid_returns_none():
    assert ComputerNode(sid=None, name="x").as_node is None
```

- [ ] **Step 2: Run — expect failure.** Run both new test files.

- [ ] **Step 3a: Implement the coalesce** — append to `transforms.py` and call from `transforms()`:

```python
def _node_computer(con, schema):
    """One row per SID, unioning every computer-bearing source. Role columns are
    normalized to VARCHAR[] (some sources emit a string, some a list)."""
    con.execute(f"CREATE OR REPLACE TABLE {schema}.node_computer (sid VARCHAR, name VARCHAR, "
                "dnshostname VARCHAR, sam_account_name VARCHAR, resource_id_str VARCHAR, "
                "roles VARCHAR[], sccm_infra BOOLEAN, sms_unique_identifier VARCHAR, smb_signing_required BOOLEAN)")

    def _arr(col):  # normalize a string-or-list role column to VARCHAR[]
        return (f"CASE WHEN {col} IS NULL THEN [] "
                f"WHEN typeof({col}) = 'VARCHAR' THEN string_split({col}, ',') "
                f"ELSE CAST({col} AS VARCHAR[]) END")

    inserts = [
        # r_system / wmi_r_system: sid; system_roles; resource_id@source_site_code; drop obsolete
        (f"SELECT upper(sid) AS sid, name, NULL AS dnshostname, NULL AS sam_account_name, "
         f"CASE WHEN resource_id IS NULL THEN NULL ELSE resource_id || '@' || source_site_code END AS resource_id_str, "
         f"{_arr('system_roles')} AS roles, false AS sccm_infra, sms_unique_identifier, NULL AS smb_signing_required "
         f"FROM {schema}.adminservice_r_system WHERE sid IS NOT NULL AND NOT coalesce(obsolete, false)"),
        (f"SELECT upper(sid), name, NULL, NULL, "
         f"CASE WHEN resource_id IS NULL THEN NULL ELSE resource_id || '@' || source_site_code END, "
         f"{_arr('system_roles')}, false, sms_unique_identifier, NULL "
         f"FROM {schema}.wmi_r_system WHERE sid IS NOT NULL AND NOT coalesce(obsolete, false)"),
        # AD-resolved sources: object_sid; sccm_site_system_roles; sccm_infra; (smb) smb_signing_required
        (f"SELECT upper(object_sid), name, dns_host_name, sam_account_name, NULL, "
         f"{_arr('sccm_site_system_roles')}, coalesce(sccm_infra, false), NULL, NULL "
         f"FROM {schema}.ldap_cmrc_devices WHERE object_sid IS NOT NULL"),
        (f"SELECT upper(object_sid), name, dns_host_name, sam_account_name, NULL, "
         f"{_arr('sccm_site_system_roles')}, coalesce(sccm_infra, false), NULL, smb_signing_required "
         f"FROM {schema}.smb_computers WHERE object_sid IS NOT NULL"),
        (f"SELECT upper(object_sid), name, dns_host_name, sam_account_name, NULL, "
         f"{_arr('sccm_site_system_roles')}, coalesce(sccm_infra, false), NULL, smb_signing_required "
         f"FROM {schema}.remoteregistry_computers WHERE object_sid IS NOT NULL"),
        (f"SELECT upper(object_sid), name, dns_host_name, NULL, NULL, "
         f"{_arr('sccm_site_system_roles')}, coalesce(sccm_infra, false), NULL, NULL "
         f"FROM {schema}.adminservice_site_definitions_computers WHERE object_sid IS NOT NULL"),
        (f"SELECT upper(object_sid), name, dns_host_name, NULL, NULL, "
         f"{_arr('sccm_site_system_roles')}, coalesce(sccm_infra, false), NULL, NULL "
         f"FROM {schema}.wmi_site_definitions_computers WHERE object_sid IS NOT NULL"),
    ]
    for sql in inserts:
        _safe(con, "node_computer", f"INSERT INTO {schema}.node_computer BY NAME "
              f"SELECT sid, name, dnshostname, sam_account_name, resource_id_str, roles, sccm_infra, "
              f"sms_unique_identifier, smb_signing_required FROM ({sql}) AS s(sid, name, dnshostname, "
              f"sam_account_name, resource_id_str, roles, sccm_infra, sms_unique_identifier, smb_signing_required)")

    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_computer AS SELECT sid, "
        f"any_value(name) AS name, any_value(dnshostname) AS dnshostname, any_value(sam_account_name) AS sam_account_name, "
        f"list_distinct(list_filter(flatten(list(roles)), x -> x IS NOT NULL AND x != '')) AS site_system_roles, "
        f"list_distinct(array_agg(resource_id_str) FILTER (WHERE resource_id_str IS NOT NULL)) AS resource_ids, "
        f"bool_or(sccm_infra) AS sccm_infra, any_value(sms_unique_identifier) AS sms_unique_identifier, "
        f"bool_or(smb_signing_required) AS smb_signing_required "
        f"FROM {schema}.node_computer GROUP BY sid"
    )
```
Add `_node_computer(con, schema)` to `transforms()`.

#### Computer property provenance (the coalesce must populate ALL of these)

Beyond the columns shown in the skeleton above, `node_computer` carries the full Computer-property set. **Four source tables join the union** in addition to those in the skeleton: `ldap_network_boot_servers`, `http_management_points`, `http_distribution_points`, `http_smsproviders`. Each source SELECT supplies its own columns and `NULL`/`false` for the rest (the `INSERT … BY NAME` pattern).

| `node_computer` column → property key | Source table.column (provenance) | GROUP BY aggregation |
|---|---|---|
| `site_system_roles` | r_system `system_roles`; registry/smb/site_def `sccm_site_system_roles` | array union |
| `resource_ids` | r_system `resource_id` + `source_site_code` | array union |
| `sccm_infra` | registry/smb/site_def/http `sccm_infra` | `bool_or` |
| `sms_unique_identifier` | r_system `sms_unique_identifier` | `any_value` |
| `smb_signing_required` | registry/smb `smb_signing_required` | `bool_or` |
| `sccm_has_client_remote_control_spn` | `ldap_cmrc_devices` → **synthesize `TRUE`** (membership signal; no column) | `bool_or` |
| `network_boot_server` | `ldap_network_boot_servers` → **synthesize `TRUE`** (LDAP-discovered; DHCP-discovered land when DHCP collection is implemented) | `bool_or` |
| `disable_loopback_check` | `remoteregistry_computers.disable_loopback_check` (bool) | `bool_or` |
| `restrict_receiving_ntlm_traffic` | `remoteregistry_computers.restrict_receiving_ntlm_traffic` (**string**: `Off`/`Deny_All`/…) | `any_value` (non-null) |
| `sccm_client_certificate_required` | `http_management_points`/`http_distribution_points`/`http_smsproviders` `.client_cert_required`, keyed by `object_sid` (bool) | `bool_or` |
| `sccm_hosts_content_library` | `smb_computers.sccm_hosts_content_library` (bool) | `bool_or` |
| `sccm_is_pxe_support_enabled` | `smb_computers.sccm_is_pxe_support_enabled` (bool) | `bool_or` |

Extend the Step-1 test's seed + assertions to cover a representative subset: an `ldap_cmrc_devices` row → `sccm_has_client_remote_control_spn=true`; an `smb_computers` row with `sccm_hosts_content_library`/`sccm_is_pxe_support_enabled=true`; a `remoteregistry_computers` row with `disable_loopback_check`/`restrict_receiving_ntlm_traffic`.

> **TDD note:** DuckDB's `typeof`/`string_split`/`flatten` handling of mixed string-vs-list columns is the fiddly part. The test in Step 1 is the contract — iterate `_arr` / the casts until it passes. If a source table's role column is consistently a list (or consistently a string) in real data, simplify `_arr` accordingly and note it.

- [ ] **Step 3b: Implement the model:**

```python
# src/openhound_sccm/models/computer.py
from openhound.core.asset import BaseAsset
from pydantic import ConfigDict
from ..graph import SCCMNode, ComputerProperties, domain_environment_id
from ..kinds import nodes as nk


class ComputerNode(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    sid: str | None = None
    name: str | None = None
    dnshostname: str | None = None
    sam_account_name: str | None = None
    site_system_roles: list[str] = []
    resource_ids: list[str] = []
    sccm_infra: bool = False
    sms_unique_identifier: str | None = None
    smb_signing_required: bool | None = None
    sccm_has_client_remote_control_spn: bool = False
    network_boot_server: bool = False
    disable_loopback_check: bool | None = None
    restrict_receiving_ntlm_traffic: str | None = None
    sccm_client_certificate_required: bool | None = None
    sccm_hosts_content_library: bool | None = None
    sccm_is_pxe_support_enabled: bool | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        sid = (self.sid or "").upper() or None
        if not sid:
            return None  # no SID -> can't key/merge; dropped (see Stage 1 identity rule)
        env = domain_environment_id(sid)
        if env is None:
            return None  # non-domain SID with no fallback context; dropped
        display = self.name or self.dnshostname or sid
        return SCCMNode(
            id=sid,
            kinds=[nk.COMPUTER, nk.BASE],
            properties=ComputerProperties(
                name=self.name or display, displayname=display, environmentid=env,
                collection_source=[], sccm_site_system_roles=self.site_system_roles,
                sccm_infra=self.sccm_infra, sccm_resource_ids=self.resource_ids,
                sccm_client_device_identifier=self.sms_unique_identifier,
                smb_signing_required=self.smb_signing_required,
                sccm_has_client_remote_control_spn=self.sccm_has_client_remote_control_spn,
                network_boot_server=self.network_boot_server,
                disable_loopback_check=self.disable_loopback_check,
                restrict_receiving_ntlm_traffic=self.restrict_receiving_ntlm_traffic,
                sccm_client_certificate_required=self.sccm_client_certificate_required,
                sccm_hosts_content_library=self.sccm_hosts_content_library,
                sccm_is_pxe_support_enabled=self.sccm_is_pxe_support_enabled,
            ),
        )

    @property
    def edges(self):
        return iter(())
```

- [ ] **Step 3c: Refactor `convert_pipeline.py`** to drive models via specs:

```python
# src/openhound_sccm/convert_pipeline.py  (replace _spike_* + emit_graph_from_duckdb)
import logging
from dataclasses import asdict
from pathlib import Path

import dlt
from openhound.destinations.opengraph.destination import opengraph_file

from .lookup import SCCMLookup

logger = logging.getLogger(__name__)


def emit_graph_from_duckdb(lookup, output_path, source_kind, node_specs, edge_specs):
    """node_specs/edge_specs: list[(table_name, BaseAsset subclass)]. For each row,
    instantiate the model, inject the lookup, and emit its node/edges as OpenGraph content."""
    out = Path(output_path)
    out.mkdir(parents=True, exist_ok=True)

    @dlt.resource(name="sccm_nodes")
    def nodes():
        for table, model in node_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                node = obj.as_node
                if node is not None:
                    yield {"graph": {"entity_type": "node", "content": asdict(node)}}

    @dlt.resource(name="sccm_edges")
    def edges():
        for table, model in edge_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                parts = [asdict(e) for e in obj.edges]
                if parts:
                    yield {"graph": {"entity_type": "edge", "content": parts}}

    pipeline = dlt.pipeline(pipeline_name="sccm_convert_graph", dataset_name="sccm",
                            destination=opengraph_file(output_path=str(out), source_kind=source_kind))
    pipeline.run([nodes(), edges()])
    logger.info("Convert2-Read-DB pipeline wrote OpenGraph files to %s", out)
```

- [ ] **Step 3d: Update `main.py`'s `convert`** to pass the specs (grows each task):

```python
# main.py — replace the convert() body
from .models.computer import ComputerNode

NODE_SPECS = [("node_computer", ComputerNode)]
EDGE_SPECS = []

@app.convert(lookup=SCCMLookup)
def convert(ctx: ConvertContext):
    emit_graph_from_duckdb(ctx.lookup, ctx.output_path, app.source_kind, NODE_SPECS, EDGE_SPECS)
    return _noop_convert_source(), {}
```

- [ ] **Step 4: Run** the three test files — expect PASS.
- [ ] **Step 5: Checkpoint** — `git add` the changed/created files.

---

## Task 4: `node_user` + `UserNode`

Source: `adminservice_r_user`/`wmi_r_user` (`sid`, `name`, `resource_id`, `source_site_code`) and `remoteregistry_users` (`object_sid`, `sam_account_name`).

**Files:** Modify `transforms.py`, `main.py`; create `models/user.py`, `models/user_test.py`, `node_user_test.py`.

- [ ] **Step 1: Failing tests** — mirror Task 3 (seed `adminservice_r_user` + `remoteregistry_users` with the same SID; assert one `node_user` row; assert `UserNode.as_node` id=SID, kinds `["User","Base"]`, environmentid=domain SID, `sccm_resource_ids`).

```python
# src/openhound_sccm/node_user_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_user_one_row_per_sid():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code")
    transforms(con)
    rows = con.execute("SELECT sid, name, list_sort(resource_ids) FROM sccm.node_user").fetchall()
    assert rows == [("S-1-5-21-1-2-3-1106", "alice", ["9@PS1"])]
```
```python
# src/openhound_sccm/models/user_test.py
from openhound_sccm.models.user import UserNode
def test_user_as_node():
    n = UserNode(sid="S-1-5-21-1-2-3-1106", name="alice", resource_ids=["9@PS1"]).as_node
    assert n.id == "S-1-5-21-1-2-3-1106" and n.kinds == ["User", "Base"]
    assert n.properties.environmentid == "S-1-5-21-1-2-3"
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_node_user`** in `transforms.py` — UNION `adminservice_r_user`/`wmi_r_user` (`upper(sid)`; `resource_id||'@'||source_site_code` → `resource_ids[]`), `remoteregistry_users` (`upper(object_sid)`), `adminservice_admins`/`wmi_admins` where `is_group=false` (`upper(admin_sid)`, contributing `sccm_infra=true`), **and `adminservice_reserved_accounts`/`wmi_reserved_accounts`** (`upper(object_sid)`, contributing `stored_in_sccm_site = site_code`). `GROUP BY sid`; `any_value(name)`, array-union `resource_ids`, `bool_or(sccm_infra)`, `any_value(stored_in_sccm_site)` (scalar per CMBP; a user stored in multiple sites is rare — `any_value` picks one). Call from `transforms()`. (Extend the `node_user` test to assert `sccm_infra=true` for an `admins`-sourced user and `stored_in_sccm_site` for a reserved-account user.)
- [ ] **Step 3b: `models/user.py`** — `UserNode(BaseAsset)` mirroring `ComputerNode` but kinds `[nk.USER, nk.BASE]`, fields `sid` / `name` / `resource_ids` / `sccm_infra` / `stored_in_sccm_site`, `UserProperties(collection_source, sccm_resource_ids, sccm_infra, stored_in_sccm_site)`; same SID→id + `domain_environment_id` + drop-if-none logic.

> **Property vs edge:** `stored_in_sccm_site` is a User *node property* and is populated in Stage 1 (from `*_reserved_accounts`); only the **`SCCM_HasStoredAccount` Site→User/Group *edge* stays Stage 2**. **Deferred entirely:** `is_sccm_network_access_account` — set only via bad-opsec NAA-secret decryption, and the `*_naa_secrets` collector is **not implemented**, so that property *and* the `SCCM_HasNetworkAccessAccount` edge are blocked on building that collector first. Stage 1 emits the User node with `collection_source`, `sccm_resource_ids`, `sccm_infra`, `stored_in_sccm_site`.
- [ ] **Step 3c:** add `("node_user", UserNode)` to `NODE_SPECS` in `main.py`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

---

## Task 5: `node_group` (name→SID) + `GroupNode`

Groups are **name-only** in `security_group_name` lists on `r_system`/`r_user`; the only direct group SID is `admins.admin_sid` where `is_group`. Resolve names via `principal_by_name` (Task 2).

**Files:** Modify `transforms.py`, `main.py`; create `models/group.py`, `models/group_test.py`, `node_group_test.py`.

- [ ] **Step 1: Failing tests:**

```python
# src/openhound_sccm/node_group_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_group_resolves_name_and_includes_admin_group():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # a member group name that resolves via principal_by_name, + a direct admin group SID
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'HOST1' AS name, "
                "'S-1-5-21-1-2-3-1104' AS sid, ['LAB\\\\SCCMAdmins'] AS security_group_name, false AS obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'LAB\\\\SCCMAdmins' AS name, "
                "'S-1-5-21-1-2-3-5001' AS sid")   # provides the (name, sid) for the group
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'LAB\\\\SiteAdmins' AS logon_name, "
                "'S-1-5-21-1-2-3-5002' AS admin_sid, true AS is_group")
    transforms(con)
    sids = sorted(r[0] for r in con.execute("SELECT sid FROM sccm.node_group").fetchall())
    assert sids == ["S-1-5-21-1-2-3-5001", "S-1-5-21-1-2-3-5002"]
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_node_group`** in `transforms.py`:
  - From `r_system`/`r_user`: `unnest(security_group_name)` → group names; resolve via a **case-insensitive join on both sides** — `JOIN principal_by_name pbn ON upper(trim(g.gname)) = upper(pbn.name)` → SID. (Task 2 stores `principal_by_name.name` in **original case**, so always `upper()` both sides or the join silently drops rows. `security_group_name` is a list column; if a source emits a comma-string, normalize like `_arr`.)
  - From `admins`/`wmi_admins`: `SELECT admin_sid AS sid, logon_name AS name WHERE is_group`.
  - UNION, `GROUP BY upper(sid)`, keep `any_value(name)`. Carry a `sccm_infra` flag true for the admin-sourced groups.
- [ ] **Step 3b: `models/group.py`** — `GroupNode(BaseAsset)`, kinds `[nk.GROUP, nk.BASE]`, `GroupProperties`. SID→id + `domain_environment_id`. **Builtin handling:** if `domain_environment_id(sid)` is `None`, use the model's `fallback_domain_sid` field (populated by the coalesce from a co-occurring domain SID where available); if still `None`, return `None` (drop) and `logger.warning` the group name. Add a `fallback_domain_sid: str | None = None` field + the env-id call `domain_environment_id(sid, self.fallback_domain_sid)`.
- [ ] **Step 3c:** add `("node_group", GroupNode)` to `NODE_SPECS`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

> The coalesce should also compute a `fallback_domain_sid` per group row where derivable (e.g. the domain SID of a device/user the group co-occurred with) so builtin group SIDs get qualified per the locked rule; if not derivable, leave NULL (model drops + logs).

---

## Task 6: `SCCMSite` model + `node_site` coalesce + fix `ldap.py` import + `SCCM_Site` node

Rebuilds the deleted `SCCMSite` model (recovered shape) and fixes the collect-path `NameError`.

**Source facts:** sites from `adminservice_sites`/`wmi_sites` (`site_code`, `site_name`, `server_name`, `reporting_site_code`, `type`, `version`, `build_number`, `install_dir`), `adminservice_site_definitions`/`wmi_site_definitions` (`parent_site_code`, `site_guid`, `sql_server_name`, `sql_database_name`, …), `ldap_sites` (`site_code`, `site_guid`, `parent_site_code`). Node id = **site code**; `environmentid` = `root_site_code` (from `site_hierarchy`, Task 2). `site_type` int→string: 1=Secondary, 2=Primary, 4=CAS.

**Files:** Modify `transforms.py`, `main.py`, `collectors/ldap.py`, `models/__init__.py`; create `models/sccm_site.py`, `models/sccm_site_test.py`, `node_site_test.py`.

- [ ] **Step 1: Failing tests** — seed `adminservice_sites` + `adminservice_site_definitions` for `PS1` (parent CAS), assert one `node_site` row with `root_site_code` joined in; assert `SCCMSite(**row).as_node` id=`PS1`, kinds `["SCCM_Site"]`, environmentid=`CAS` (the root), `site_type`=`"Primary Site"`.

```python
# src/openhound_sccm/node_site_test.py
import duckdb
from openhound_sccm.transforms import transforms
def test_node_site_has_root_env():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4), ('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_sites AS SELECT 'PS1' AS site_code, 'Primary' AS site_name, "
                "'srv.lab' AS server_name, 'CAS' AS reporting_site_code, 2 AS type, '5.0' AS version")
    transforms(con)
    r = con.execute("SELECT site_code, root_site_code, site_type FROM sccm.node_site WHERE site_code='PS1'").fetchone()
    assert r == ("PS1", "CAS", 2)
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_node_site`** in `transforms.py` — UNION the site sources to `(site_code, site_name, server_name, parent_site_code, site_type, site_guid, sql_server_name, sql_database_name, version, build_number, install_dir)`, `GROUP BY upper(site_code)` coalescing, then `LEFT JOIN site_hierarchy USING (site_code)` to add `root_site_code`. (Use `reporting_site_code` as parent for the `adminservice_sites` rows, `parent_site_code` for site_definitions/ldap.)
- [ ] **Step 3b: `models/sccm_site.py`** — `SCCMSite(BaseAsset)` with the recovered fields (`site_code`, `site_guid`, `parent_site_code`, `site_type`, `site_name`/`display_name`, `server_name`, `sql_server_name`, `sql_database_name`, `version`, `root_site_code`, `build_number`, `install_dir`, `collection_source`); `model_config = ConfigDict(populate_by_name=True, extra="ignore")`. `as_node`: id=`self.site_code`, kinds=`[nk.SCCM_SITE]`, `environmentid = self.root_site_code or self.site_code`, `SCCMSiteProperties(...)` mapping fields + int→string `site_type`. Re-export from `models/__init__.py`: `from .sccm_site import SCCMSite` + add to `__all__`.
- [x] **Step 3c: Fix `collectors/ldap.py`** — the `ldap_sites` collect resource must NOT pin its table schema to the convert-stage `SCCMSite` model. Use `columns=raw_table_asset("ldap_sites")` (like every sibling raw LDAP resource) and do NOT import the convert `SCCMSite` into the collector. (Corrected 2026-06-22: an earlier draft restored `from ..models import SCCMSite` + `columns=SCCMSite`; that re-coupled collect to the convert model and, because the convert model made `site_code` nullable, broke `collect` with a dlt `freeze` schema-contract violation against the previously-frozen `nullable: False` `ldap_sites.site_code`. The convert side reads the coalesced `node_site` table, never `ldap_sites` directly.) Verify the collect path imports: `… python -c "import openhound_sccm.source"`.
- [ ] **Step 3d:** add `("node_site", SCCMSite)` to `NODE_SPECS`.
- [ ] **Step 4: Run** the site tests + `import openhound_sccm.source` (no `NameError`). **Step 5: Checkpoint.**

---

## Task 7: `graph_edges` — `SCCM_AdminsReplicatedTo` + edge model

**Logic (CMBP ps1:1604-1624):** for each child site with a real `parent_site_code`, find the parent; CAS↔Primary → **two** edges (both directions); Primary→Secondary → **one** edge. Edge id endpoints are **site codes**.

**Files:** Modify `transforms.py`, `main.py`, `kinds/edges.py`; create `models/replication_edge.py`, `models/replication_edge_test.py`, `graph_edges_test.py`.

- [ ] **Step 1: Failing tests** — seed `site_hierarchy`-feeding tables (CAS type 4, PS1 type 2 parent CAS, SS1 type 1 parent PS1); after `transforms`, assert `graph_edges` contains `(CAS,PS1,SCCM_AdminsReplicatedTo)`, `(PS1,CAS,SCCM_AdminsReplicatedTo)`, `(PS1,SS1,SCCM_AdminsReplicatedTo)` and NOT `(SS1,PS1,…)`. Assert `ReplicationEdge(**row).edges` yields one `Edge(kind=…, start=EdgePath(value=start_id), end=EdgePath(value=end_id))`.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a:** add `SCCM_ADMINS_REPLICATED_TO = "SCCM_AdminsReplicatedTo"` to `kinds/edges.py`.
- [ ] **Step 3b: `_graph_edges`** in `transforms.py` — build `graph_edges(start_id, end_id, kind)` from a self-join of `site_hierarchy` on `child.parent_site_code = parent.site_code`, emitting the CAS↔Primary (2-way) and Primary→Secondary (1-way) cases per the type matrix. (Stage 1 only adds `SCCM_AdminsReplicatedTo`; later stages append more kinds.)
- [ ] **Step 3c: `models/replication_edge.py`** — `ReplicationEdge(BaseAsset)` with `start_id`, `end_id`, `kind`; `as_node -> None`; `edges` yields `Edge(kind=self.kind, start=EdgePath(match_by="id", value=self.start_id), end=EdgePath(match_by="id", value=self.end_id), properties=EdgeProperties())` (dataclass `Edge`/`EdgePath`/`EdgeProperties` from `entries_dataclass`).
- [ ] **Step 3d:** add `("graph_edges", ReplicationEdge)` to `EDGE_SPECS` in `main.py`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

---

## Task 8: Remove the spike; point convert at the real tables; update the integration test

**Files:** Modify `transforms.py` (drop `_build_spike` + its call), `convert_integration_test.py`.

- [ ] **Step 1:** Update `convert_integration_test.py` — seed a tiny *real* raw tree (one `adminservice_r_system` row + one `adminservice_site_definitions` pair), run `preprocess` then `convert`, assert a **Computer** node (the seeded SID) and a **SCCM_Site** node (the seeded site code) appear — and that `SPIKE-1` does **not**.
- [ ] **Step 2: Run — expect failure** (spike still present / real nodes absent).
- [ ] **Step 3:** Delete `_build_spike` and its call in `transforms()`. Confirm `EDGE_SPECS`/`NODE_SPECS` reference only real tables (`graph_edges` is now the replication table, not the spike).
- [ ] **Step 4: Run** the integration test + full suite (`pytest src/openhound_sccm -v`) — expect PASS. **Step 5: Checkpoint.**

---

## Task 9: Rebuild `_preproc_table_map()` to the real collected tables

The Stage-0 map is stale (lists `ldap_computers`, etc.). Rebuild to the **actually emitted** table names so `preprocess` loads real data.

**Files:** Modify `main.py`; create `preproc_map_test.py`.

- [ ] **Step 1:** Enumerate real table names — `grep -rno 'yield "' src/openhound_sccm/collectors src/openhound_sccm/source.py` and the `run.table(...)` calls in `privileged.py`; cross-check against a real collected `<raw>/sccm/` tree if one exists. Known corrections: `ldap_computers` → `ldap_cmrc_devices`; include `adminservice_*`/`wmi_*` (sites, site_definitions, site_definitions_computers, r_system, r_user, admins, …), `remoteregistry_*`, `smb_*`, `http_*`, `ldap_*`.
- [ ] **Step 2:** Write `preproc_map_test.py` asserting the map's values are `f"sccm/{table}"` and that key real tables (`adminservice_r_system`, `ldap_cmrc_devices`, `adminservice_site_definitions`) are present and the stale `ldap_computers` is absent.
- [ ] **Step 3:** Rewrite `_preproc_table_map()` with the verified list.
- [ ] **Step 4: Run — expect PASS** (and package still imports). **Step 5: Checkpoint.**

---

## Task 10: README — Node/Edge Reference + relax the "minimal output" Limitation

**Files:** Modify `README.md`.

- [ ] **Step 1:** Under **Node Reference**, add `Computer`, `User`, `Group` entries (id = SID; `environmentid` = domain SID). Computer key properties: `sccm_site_system_roles`, `sccm_resource_ids`, `sccm_infra`, `sccm_client_device_identifier`, `smb_signing_required`, `sccm_has_client_remote_control_spn`, `network_boot_server`, `disable_loopback_check`, `restrict_receiving_ntlm_traffic`, `sccm_client_certificate_required`, `sccm_hosts_content_library`, `sccm_is_pxe_support_enabled`. User key properties: `sccm_resource_ids`, `sccm_infra`, `stored_in_sccm_site` (`is_sccm_network_access_account` arrives once the NAA-secret collector is built). Group key properties: `sccm_infra`, `sccm_resource_ids`. Keep `SCCM_Site` (id = site code; `environmentid` = `root_site_code`).
- [ ] **Step 2:** Under **Edge Reference**, add `SCCM_AdminsReplicatedTo` (Site→Site; CAS↔Primary bidirectional, Primary→Secondary one-way).
- [ ] **Step 3:** Update the **Limitations** "Graph output is minimal" bullet — it now emits Computer/User/Group/SCCM_Site nodes and the SCCM_AdminsReplicatedTo edge. (The **Assumptions** section already documents the site-code/org scoping.)
- [ ] **Step 4:** No tests; **Checkpoint** — `git add README.md`. (README is code-truth: list only what's emitted as of Stage 1.)

---

## Task 11: Stage 1 code-tour validation harness

**Files:** Create `docs/superpowers/plans/2026-06-17-sccm-preproc-convert-stage1-validation.md`.

- [ ] **Step 1:** Write the harness in the Stage-0 code-tour style (spec §6 convention): a `tour_driver.py` that seeds a small *real* raw tree, runs `preprocess` then `convert` in-process via `app.converter(...)`, with breakpoint stops at: `_principal_by_name`/`_site_hierarchy` (inspect `root_site_code`), `_node_computer` (inspect the coalesced row — one per SID, unioned roles), `domain_environment_id` (inspect the stripped domain SID), `ComputerNode.as_node` (inspect kinds/environmentid), `_graph_edges` (inspect the CAS↔Primary pair), and the deep core stop confirming the no-op source stays inert. Include the expected value per stop + a plan-detail→breakpoint map + the black-box output check (Computer + SCCM_Site nodes, the replication edge).
- [ ] **Step 2:** Add a **"Debug: Stage 1 code tour"** profile to `.vscode/launch.json` pointing at the Stage 1 `tour_driver.py` (`justMyCode: false`), mirroring the Stage 0 profile. (Confirm with the user before editing the repo-root launch.json, per the Stage-0 precedent.)
- [ ] **Step 3:** **Checkpoint.**

---

## Self-Review

**Spec coverage (Stage 1 row of §6):** Computer/User/Group/Site coalesce + emit → Tasks 3–6; `root_site_code` + `principal_by_name` → Task 2; `SCCM_AdminsReplicatedTo` → Task 7; root/environment-node decision → encoded in the identity rules (Global Constraints) + per-node `as_node`; `ldap.py` `SCCMSite` carryover → Task 6; preproc map rebuild → Task 9; README → Task 10; validation harness → Task 11.

**Placeholder scan:** the four coalesce tasks provide complete starting SQL + an exact test contract; the "TDD note" flags that the mixed string/list role handling is iterated against the test, not left vague. No "TBD"/"similar to Task N" without code (Tasks 4–7 reference the Computer pattern but each lists its own concrete changes + test).

**Type consistency:** `emit_graph_from_duckdb(lookup, output_path, source_kind, node_specs, edge_specs)` — Task 3 defines it; `main.py` `NODE_SPECS`/`EDGE_SPECS` grow in Tasks 3–7 with the same `(table, ModelClass)` shape. `domain_environment_id(sid, fallback_domain_sid=None)` — defined Task 1, used in Computer/User (no fallback) and Group (with fallback) models. `SCCMNode(id, kinds, properties)` + the four `*Properties` dataclasses — defined Task 1, used by all node models. Node ids: SID for Computer/User/Group, site code for SCCM_Site — consistent across coalesce (`upper(sid)` / `upper(site_code)`) and models.

**Open risk (flagged, not a placeholder):** the coalesce SQL is the part most likely to need iteration against real DuckDB typing (string-vs-list role columns, `BY NAME` insert column matching). Each coalesce task's test is the contract; the implementer iterates the SQL until green and notes any per-source simplification.
