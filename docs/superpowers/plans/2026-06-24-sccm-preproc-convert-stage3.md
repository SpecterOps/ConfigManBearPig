# SCCM preproc + convert — Stage 3 (Containment + RBAC fan-out + node/edge property parity) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the 10 Stage-3 edges (`SCCM_Contains`, the 7 RBAC role edges, `SCCM_AllPermissions`, `SCCM_AssignAllPermissions`), give every edge a `collection_source`, and bring all 8 currently-existing node kinds up to full CMBP property parity so BloodHound entity panels are populated.

**Architecture:** All three are `preproc` (`transforms.py`) changes that flow through the existing Convert2-Read-DB pipeline unchanged. WS-1 re-introduces a typed `collection_source VARCHAR[]` column on `graph_edges` and tags every edge builder. WS-2 adds four set-based edge builders that read the Stage-2 `graph_edges` rows (`SCCM_IsAssigned` + `SCCM_HasMember`) plus the `node_*` tables. WS-3 enriches the `node_*` coalesces + `*Properties` dataclasses + models with every missing CMBP property; relationship-list properties are built raw/faithful from the source tables (no edge→node aggregation). `main.py` `NODE_SPECS`/`EDGE_SPECS` are unchanged — `GraphEdge` already emits every kind. No OpenHound core changes.

**Tech Stack:** Python 3.13+, `dlt`, `duckdb`, `openhound` (v0.2.x), `pytest`, `uv`.

**Tracking:** gtk `ope-1950`. **Baseline:** the post-Stage-2 working tree (`ope-2ff3`) is assumed present and importing. **Spec:** [`../specs/2026-06-16-sccm-preproc-convert-design.md`](../specs/2026-06-16-sccm-preproc-convert-design.md) §6 Stage 3 (Resolved 2026-06-24).

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Never edit OpenHound core (`openhound/...`). (CLAUDE.md)
- **Do NOT `git commit`.** Each task ends at a **checkpoint** = `git add` (stage only); the user commits after testing. (CLAUDE.md) — the `git commit` lines in the writing-plans template are replaced by `git add` here.
- **Validate in the isolated uv env** (already synced from Stage 0–2):
  `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest <abs test path> -v`.
  Do not use/modify the repo `.venv`. (AGENTS.md)
- **Log every `if`/`else` and `try`/`except` branch** at an appropriate level, or leave a comment. (CLAUDE.md)
- **Node/edge property keys are lowercase, `_`-separated** (e.g. `collection_source`, `member_of`). Never emit PascalCase/camelCase. (Stage 1/2 constraint, unchanged.)
- **Tests live in `sccm/sccm/tests/` as `<name>_test.py`** (Stage 2 Phase F relocated all co-located tests there — suite baseline 421 passed / 5 skipped / 0 failed; CLAUDE.md's separate-`/tests` preference is now satisfied). Every `*_test.py` referenced below resolves under `sccm/sccm/tests/`; the existing files to modify already live there (`tests/node_collection_test.py`, `tests/graph_edge_test.py`, etc.), and new tests are created there (`tests/edge_contains_test.py`, `tests/kinds_edges_test.py`, …). Run with the isolated-env pytest targeting `tests/`.
- **No re-collect for Stage 3** — it is preproc/convert-only and reads the existing lab raw tree (with Stage 2's re-collect). Validate (Phase D) against the existing `<raw>` immediately.
- **JSON-array-text gotcha (Stage 2 critical bug):** `collection_names` / `role_names` (and similar AdminService list fields) arrive as JSON-array *text* (`'["All Systems",...]'`). Always route them through `_arr()` (handles JSON-array text, comma-scalar, and native list) — never `string_split`.
- **Simplicity/YAGNI** — edge derivation and node coalescing are set-based SQL; models stay trivial `row → node` / `row → edge`. No per-row Python fan-out.
- **`_safe`, `_ensure_columns`, `_arr`, `_root_code`** already exist in `transforms.py`; reuse them. `_safe` takes no SQL params — inline the 3-char site code literal where needed (established Stage 2 pattern).

### Locked Stage 3 decisions (grilled with the user 2026-06-24)
1. **RBAC fan-out source:** reconstruct from `graph_edges` (Stage-2 `SCCM_IsAssigned` + `SCCM_HasMember`), not the raw tables.
2. **`SCCM_AllPermissions` detection:** by well-known collection IDs `SMS00001` (All Systems) + `SMS00004` (All Users and User Groups), not display name. Code comment cites CMBP's name-match; the validation harness confirms the IDs against the lab.
3. **Property philosophy:** port **all** CMBP node/edge properties for the entity panels, even relationship-encoding ones.
4. **Edge properties:** typed `collection_source VARCHAR[]` column on `graph_edges` (not free-form JSON); retrofit all existing edge builders; dedup array-unions it.
5. **Node parity scope:** full parity for all node kinds; `MSSQL_*` deferred to Stage 5 (those tables don't exist yet). Stage 3 covers the 8 existing kinds.
6. **Relationship-list properties:** built in the preproc node coalesces from the **raw** source tables, kept **raw/faithful** (unresolved resource keys + built-in pseudo-resources included); **no** edge→node aggregation.

### Edge `collection_source` provenance tags (verbatim from CMBP)
Each edge builder stamps a literal `VARCHAR[]` `collection_source`. AdminService rows use the CMBP string; the port's WMI-fallback rows use the `WMI-…` analog; post-processed edges use `SCCM_Invoke-PostProcessing`.

| Edge kind | CMBP `collectionSource` | CMBP line |
|---|---|---|
| `SCCM_AdminsReplicatedTo` | *(none in CMBP)* → port uses `SCCM_Invoke-PostProcessing` | :1617-1624 |
| `SCCM_HasClient` (real) | `AdminService-ClientDevices` (adminservice) / `WMI-ClientDevices` (wmi) | :7258 |
| `SCCM_HasClient` (possible) | `LDAP-CmRcService` | :3284 |
| `SCCM_HasMember` | `AdminService-SMS_FullCollectionMembership` / `WMI-SMS_FullCollectionMembership` | :7630 |
| `SCCM_IsMappedTo` | `AdminService-SMS_Admin` / `WMI-SMS_Admin` | :7805 |
| `SCCM_IsAssigned` | `AdminService-SMS_Admin` / `WMI-SMS_Admin` | :7822/7844/7870 |
| `SCCM_HasPrimaryUser`/`HasCurrentUser`/`HasADLastLogonUser` | `AdminService-ClientDevices` | :7267/7276/7299 |
| `SCCM_HasStoredAccount` | `AdminService-SMS_SCI_Reserved` / `WMI-SMS_SCI_Reserved` | :7148 |
| `MemberOf` | `AdminService-SMS_R_System` / `AdminService-SMS_R_User` (+ `WMI-…` analogs) | :7376/7471 |
| `HasSession` (RemoteRegistry) | `RemoteRegistry-CurrentUser` | :5030 |
| `HasSession` (MSSQL svc acct) | `AdminService-SMS_SCI_SysResUse` / `WMI-SMS_SCI_SysResUse` | :8008 |
| `SCCM_Contains` / `SCCM_FullAdministrator` etc. / `SCCM_AllPermissions` / `SCCM_AssignAllPermissions` | `SCCM_Invoke-PostProcessing` | :1664/1753/1834/1938 |

---

## File Structure

| File | Responsibility |
|---|---|
| `src/openhound_sccm/transforms.py` | **modify** — WS-1: `collection_source` in `_graph_edges_init` + `_graph_edges_dedup` + every `_edge_*` builder. WS-2: four new `_edge_*` builders + wiring in `transforms()`. WS-3: enrich every `_node_*` coalesce with missing columns + relationship-list builders. |
| `src/openhound_sccm/models/graph_edge.py` | **modify** — `GraphEdge` reads `collection_source` and passes it to `SCCMEdgeProperties`. |
| `src/openhound_sccm/kinds/edges.py` | **modify** — add the 10 Stage-3 edge-kind constants. `TRAVERSABLE_EDGE_KINDS` is already correct (no change). |
| `src/openhound_sccm/graph.py` | **modify** — add missing fields to every `*Properties` dataclass (WS-3, matrix-driven). |
| `src/openhound_sccm/models/sccm_collection.py` / `sccm_security_role.py` / `sccm_admin_user.py` / `sccm_client_device.py` / `sccm_site.py` / `computer.py` / `user.py` / `group.py` | **modify** — carry the new fields from the node row into the properties (WS-3). |
| `README.md` | **modify** (WS-4) — Node/Edge Reference: the 10 Stage-3 edges + the newly-ported properties. |
| `ARCHITECTURE.md` | **modify** (WS-4) — §11c: `graph_edges` now 4-col with typed `collection_source`; `GraphEdge` sets it. |
| `docs/superpowers/plans/2026-06-24-sccm-preproc-convert-stage3-validation.md` | **create** (WS-4) — code-tour validation harness. |
| `docs/superpowers/plans/2026-06-24-stage3-property-matrix.md` | **create** (WS-3 Task C0) — authoritative CMBP→port property gap matrix. |
| `*_test.py` next to each module | **create/modify** — per-task tests. |

**Convert registry (unchanged):** `main.py` `NODE_SPECS`/`EDGE_SPECS` are not touched — `EDGE_SPECS = [("graph_edges", GraphEdge)]` already emits every kind, and no new node *tables* are introduced (WS-3 adds *columns* to existing tables).

---

# Phase A — WS-1: Edge `collection_source` infrastructure

Do this first: WS-2's new edges and the Stage-1/2 retrofit both depend on the column existing.

## Task A1: Add the typed `collection_source` column + emit it through `GraphEdge`

**Files:** Modify `src/openhound_sccm/transforms.py` (`_graph_edges_init`, `_graph_edges_dedup`), `src/openhound_sccm/models/graph_edge.py`; modify `src/openhound_sccm/models/graph_edge_test.py`.

**Interfaces — Produces:** `graph_edges(start_id, end_id, kind, collection_source VARCHAR[])`. `GraphEdge(start_id, end_id, kind, collection_source)` emits `Edge(..., properties=SCCMEdgeProperties(traversable=…, collection_source=…))`.

- [ ] **Step 1: Write the failing test** — append to `models/graph_edge_test.py`:

```python
def test_graph_edge_carries_collection_source():
    e = list(GraphEdge(start_id="A", end_id="B", kind="SCCM_HasClient",
                       collection_source=["AdminService-ClientDevices"]).edges)[0]
    assert e.properties.collection_source == ["AdminService-ClientDevices"]
    assert e.properties.traversable is True

def test_graph_edge_collection_source_defaults_empty():
    e = list(GraphEdge(start_id="A", end_id="B", kind="MemberOf").edges)[0]
    assert e.properties.collection_source == []
```

- [ ] **Step 2: Run — expect failure** (`AttributeError`/`TypeError` on `collection_source`).
Run: `… pytest …/models/graph_edge_test.py -v`

- [ ] **Step 3a: `GraphEdge` reads the column** — in `models/graph_edge.py`, add the field and pass it through:

```python
    start_id: str | None = None
    end_id: str | None = None
    kind: str | None = None
    collection_source: list[str] | None = None
```
```python
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=SCCMEdgeProperties(
                traversable=self.kind in TRAVERSABLE_EDGE_KINDS,
                collection_source=self.collection_source or [],
            ),
        )
```

- [ ] **Step 3b: `_graph_edges_init` gains the column** — in `transforms.py`:

```python
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges "
        f"(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[])"
    )
```

- [ ] **Step 3c: `_graph_edges_dedup` array-unions it** — change `SELECT DISTINCT` to a `GROUP BY` that flattens the per-row lists (same idiom as `_node_computer` roles):

```python
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges AS "
        f"SELECT start_id, end_id, kind, "
        f"  coalesce(list_distinct(flatten(list(collection_source))), CAST([] AS VARCHAR[])) AS collection_source "
        f"FROM {schema}.graph_edges "
        f"GROUP BY start_id, end_id, kind"
    )
```

- [ ] **Step 4: Run — expect PASS.** Also run the full `graph_edge_test.py` + `graph_edges_dedup_test.py` to confirm nothing regressed.
- [ ] **Step 5: Checkpoint** — `git add transforms.py models/graph_edge.py models/graph_edge_test.py`.

## Task A2: Tag every existing edge builder with its CMBP `collection_source`

**Why:** WS-1's column is useless until the Stage-1/2 builders populate it; once they do, every edge panel shows provenance. Each `_edge_*` uses `INSERT … BY NAME`, so adding a `… AS collection_source` column to each SELECT maps by name with no positional churn.

**Files:** Modify `src/openhound_sccm/transforms.py` (`_edge_replication`, `_edge_has_client`, `_edge_has_member`, `_edge_is_mapped_to`, `_edge_is_assigned`, `_edge_has_user`, `_edge_member_of`, `_edge_has_session`, `_edge_has_stored_account`); modify the existing per-edge tests.

**Interfaces — Consumes:** the `graph_edges` 4-col schema from A1. **Produces:** every Stage-1/2 edge row carries a non-empty `collection_source`.

- [ ] **Step 1: Write/extend a failing test** — in `graph_edges_test.py` (or the closest existing edge test), seed a minimal site hierarchy + one client device and assert the resulting edges carry the expected tags:

```python
def test_existing_edges_carry_collection_source(tmp_path):
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4),('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)")
    transforms(con)
    rows = con.execute("SELECT DISTINCT kind, collection_source FROM sccm.graph_edges "
                       "WHERE kind='SCCM_AdminsReplicatedTo'").fetchall()
    assert rows and rows[0][1] == ["SCCM_Invoke-PostProcessing"]
```

- [ ] **Step 2: Run — expect failure** (`collection_source` empty/None).

- [ ] **Step 3: Add `… AS collection_source` to each builder's SELECT(s)** using the provenance table in Global Constraints. Concrete edits:

  - **`_edge_replication`** — each of the three `SELECT … '{SCCM_ADMINS_REPLICATED_TO}' AS kind` arms gains `, ['SCCM_Invoke-PostProcessing'] AS collection_source`.
  - **`_edge_has_client`** — tag by the `possible` flag (real vs LDAP-discovered):
    `, CASE WHEN coalesce(possible,false) THEN ['LDAP-CmRcService'] ELSE ['AdminService-ClientDevices'] END AS collection_source`.
  - **`_edge_has_member`** — per source: adminservice arm `['AdminService-SMS_FullCollectionMembership']`, wmi arm `['WMI-SMS_FullCollectionMembership']`. (Inline the literal that matches `_src`.)
  - **`_edge_is_mapped_to`** — adminservice `['AdminService-SMS_Admin']`, wmi `['WMI-SMS_Admin']`.
  - **`_edge_is_assigned`** — all three arms: adminservice `['AdminService-SMS_Admin']`, wmi `['WMI-SMS_Admin']`.
  - **`_edge_has_user`** — `['AdminService-ClientDevices']` (the device user fields originate there).
  - **`_edge_member_of`** — `adminservice_r_system`→`['AdminService-SMS_R_System']`, `wmi_r_system`→`['WMI-SMS_R_System']`, `adminservice_r_user`→`['AdminService-SMS_R_User']`, `wmi_r_user`→`['WMI-SMS_R_User']`.
  - **`_edge_has_session`** — RemoteRegistry arm `['RemoteRegistry-CurrentUser']`; site-systems arm adminservice `['AdminService-SMS_SCI_SysResUse']` / wmi `['WMI-SMS_SCI_SysResUse']`.
  - **`_edge_has_stored_account`** — adminservice `['AdminService-SMS_SCI_Reserved']`, wmi `['WMI-SMS_SCI_Reserved']`.

  Example shape (one builder, BY NAME so column order is free):

```python
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"SELECT coalesce(upper(a.admin_sid), pbn.sid) AS start_id, {end_expr} AS end_id, "
        f"'{SCCM_IS_MAPPED_TO}' AS kind, ['{tag}'] AS collection_source "
        ...
```
  where `tag = "AdminService-SMS_Admin"` for the adminservice source and `"WMI-SMS_Admin"` for wmi (set per `_src` in the existing loop).

- [ ] **Step 4: Run — expect PASS.** Re-run every existing edge `*_test.py` to confirm no kind/endpoint regressions (only the new column added).
- [ ] **Step 5: Checkpoint** — `git add transforms.py` + the touched edge tests.

---

# Phase B — WS-2: The 10 Stage-3 edges

## Task B0: Add the Stage-3 edge-kind constants

**Files:** Modify `src/openhound_sccm/kinds/edges.py`; modify `kinds/edges_test.py` (if present) else create it.

**Interfaces — Produces:** importable constants `SCCM_CONTAINS`, `SCCM_FULL_ADMINISTRATOR`, `SCCM_APPLICATION_AUTHOR`, `SCCM_APPLICATION_ADMINISTRATOR`, `SCCM_COMPLIANCE_SETTINGS_MANAGER`, `SCCM_OSD_MANAGER`, `SCCM_OPERATIONS_ADMINISTRATOR`, `SCCM_SECURITY_ADMINISTRATOR`, `SCCM_ALL_PERMISSIONS`, `SCCM_ASSIGN_ALL_PERMISSIONS`.

- [ ] **Step 1: Write the failing test**

```python
# src/openhound_sccm/kinds/edges_test.py
from openhound_sccm.kinds import edges as ek

def test_stage3_edge_kind_values():
    assert ek.SCCM_CONTAINS == "SCCM_Contains"
    assert ek.SCCM_FULL_ADMINISTRATOR == "SCCM_FullAdministrator"
    assert ek.SCCM_ALL_PERMISSIONS == "SCCM_AllPermissions"
    assert ek.SCCM_ASSIGN_ALL_PERMISSIONS == "SCCM_AssignAllPermissions"

def test_traversable_set_unchanged_for_role_edges():
    # Only FullAdministrator + ApplicationAdministrator are traversable among the 7 (CMBP :2216-2249).
    assert ek.SCCM_FULL_ADMINISTRATOR in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_APPLICATION_ADMINISTRATOR in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_APPLICATION_AUTHOR not in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_OSD_MANAGER not in ek.TRAVERSABLE_EDGE_KINDS
```

- [ ] **Step 2: Run — expect failure** (`AttributeError`).
- [ ] **Step 3: Add the constants** under a `# Stage 3 edge kinds (containment + RBAC fan-out)` header in `kinds/edges.py`:

```python
SCCM_CONTAINS = "SCCM_Contains"
SCCM_FULL_ADMINISTRATOR = "SCCM_FullAdministrator"
SCCM_APPLICATION_AUTHOR = "SCCM_ApplicationAuthor"
SCCM_APPLICATION_ADMINISTRATOR = "SCCM_ApplicationAdministrator"
SCCM_COMPLIANCE_SETTINGS_MANAGER = "SCCM_ComplianceSettingsManager"
SCCM_OSD_MANAGER = "SCCM_OSDManager"
SCCM_OPERATIONS_ADMINISTRATOR = "SCCM_OperationsAdministrator"
SCCM_SECURITY_ADMINISTRATOR = "SCCM_SecurityAdministrator"
SCCM_ALL_PERMISSIONS = "SCCM_AllPermissions"
SCCM_ASSIGN_ALL_PERMISSIONS = "SCCM_AssignAllPermissions"
```
> `TRAVERSABLE_EDGE_KINDS` already lists the string literals `"SCCM_Contains"`, `"SCCM_AllPermissions"`, `"SCCM_AssignAllPermissions"`, `"SCCM_FullAdministrator"`, `"SCCM_ApplicationAdministrator"` — do **not** edit it.

- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint** — `git add kinds/edges.py kinds/edges_test.py`.

## Task B1: `_edge_contains` — Site → Collection/Role/AdminUser

**CMBP:** :1659-1690. Every non-secondary site in the (single) hierarchy contains every collection, security role, and admin user (`@root`).

**Files:** Modify `transforms.py` (add `_edge_contains`, wire into `transforms()`); create `edge_contains_test.py`.

**Interfaces — Consumes:** `node_collection`, `node_security_role`, `node_admin_user` (root-stamped ids), `site_hierarchy`. **Produces:** `SCCM_Contains` rows in `graph_edges`.

- [ ] **Step 1: Failing test**

```python
# src/openhound_sccm/edge_contains_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_contains_site_to_globals():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'PS100016' AS collection_id, 'All Systems' AS name, 2 AS collection_type, 'PS1' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges WHERE kind='SCCM_Contains' ORDER BY start_id, end_id").fetchall()
    # CAS + PS1 (non-secondary) each contain the collection, the role, and the admin user; SEC (secondary) contains nothing.
    assert ("CAS", "PS100016@CAS") in rows
    assert ("PS1", "SMS0001R@CAS") in rows
    assert ("CAS", "MAYYHEM\\ADM@CAS") in rows
    assert not any(start == "SEC" for start, _ in rows)
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement `_edge_contains`** — one INSERT, three UNION-ALL arms (collections, roles, admins), cross-joined to non-secondary sites:

```python
def _edge_contains(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site -> Collection/SecurityRole/AdminUser (CMBP ps1:1659-1690). Every
    non-secondary site (site_type != 1) in the single hierarchy contains every
    global object (all are @root). collection_source = SCCM_Invoke-PostProcessing."""
    from .kinds.edges import SCCM_CONTAINS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL)")
    cs = "['SCCM_Invoke-PostProcessing']"
    _safe(con, "edge_contains",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT s.site_code AS start_id, c.collection_id || '@' || c.root_site_code AS end_id, "
          f"'{SCCM_CONTAINS}' AS kind, {cs} AS collection_source "
          f"FROM {nonsec} s JOIN {schema}.node_collection c ON c.root_site_code IS NOT NULL "
          f"UNION ALL "
          f"SELECT s.site_code, r.role_id || '@' || r.root_site_code, '{SCCM_CONTAINS}', {cs} "
          f"FROM {nonsec} s JOIN {schema}.node_security_role r ON r.root_site_code IS NOT NULL "
          f"UNION ALL "
          f"SELECT s.site_code, upper(a.logon_name) || '@' || a.root_site_code, '{SCCM_CONTAINS}', {cs} "
          f"FROM {nonsec} s JOIN {schema}.node_admin_user a ON a.root_site_code IS NOT NULL")
```
Wire `_edge_contains(con, schema)` into `transforms()` after the Stage-2 edge builders, before `_graph_edges_dedup`.

- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task B2: `_edge_rbac_role_grants` — the 7 role edges (AdminUser → ClientDevice)

**CMBP:** :1714-1827. `SecurityRole →(IsAssigned) AdminUser →(IsAssigned) Collection[Device] →(HasMember) ClientDevice`; the role's well-known ID selects the edge kind. Reconstructed from `graph_edges` (Decision #1).

**Files:** Modify `transforms.py` (add `_edge_rbac_role_grants`, wire in); create `edge_rbac_role_grants_test.py`.

**Interfaces — Consumes:** Stage-2 `graph_edges` rows (`SCCM_IsAssigned`, `SCCM_HasMember`), `node_security_role`, `node_collection` (`collection_type`), `node_client_device`. **Produces:** the 7 role-kind rows in `graph_edges`.

- [ ] **Step 1: Failing test** — an admin assigned Full Administrator AND the "All Systems" Device collection that contains one client device:

```python
# src/openhound_sccm/edge_rbac_role_grants_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_full_administrator_reaches_device():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'SMS00001' AS collection_id, 'All Systems' AS name, 2 AS collection_type, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
                "'All Systems' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, 50 AS resource_id, 'CAS' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT 'SMS00001' AS collection_id, 50 AS resource_id, 'CAS' AS site_code")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges WHERE kind='SCCM_FullAdministrator'").fetchall()
    assert rows == [("MAYYHEM\\ADM@CAS", "GUID-1")]
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement `_edge_rbac_role_grants`**:

```python
# Well-known security-role id -> the client-device edge kind it grants (CMBP ps1:1751-1797).
_ROLE_EDGE_KIND = {
    "SMS0001R": "SCCM_FullAdministrator",
    "SMS0008R": "SCCM_ApplicationAuthor",
    "SMS0009R": "SCCM_ApplicationAdministrator",
    "SMS0006R": "SCCM_ComplianceSettingsManager",
    "SMS000AR": "SCCM_OSDManager",
    "SMS000ER": "SCCM_OperationsAdministrator",
    "SMS000FR": "SCCM_SecurityAdministrator",
}
# Built-in roles CMBP knows but deliberately creates no device edge for (no warning). (CMBP ps1:1811-1818)
_ROLE_KNOWN_NO_EDGE = ("SMS0002R","SMS0003R","SMS0004R","SMS0007R","SMS000BR","SMS000CR","SMS000GR","SMS000HR")


def _edge_rbac_role_grants(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """The 7 RBAC role edges (AdminUser -> ClientDevice), reconstructed from graph_edges
    (CMBP ps1:1714-1827). Path: IsAssigned(admin->role) JOIN IsAssigned(admin->Device-collection)
    JOIN HasMember(collection->clientdevice). The role's well-known id picks the edge kind.
    Custom (non-built-in) roles assigned to admins are counted and logged (CMBP ps1:1820)."""
    role_map = ", ".join(f"('{rid}','{kind}')" for rid, kind in _ROLE_EDGE_KIND.items())
    _safe(con, "edge_rbac_role_grants",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT ia_role.start_id AS start_id, hm.end_id AS end_id, rk.edge_kind AS kind, "
          f"['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.graph_edges ia_role "
          f"JOIN {schema}.node_security_role sr "
          f"  ON sr.role_id || '@' || sr.root_site_code = ia_role.end_id "
          f"JOIN (VALUES {role_map}) AS rk(role_id, edge_kind) ON upper(sr.role_id) = rk.role_id "
          f"JOIN {schema}.graph_edges ia_coll "
          f"  ON ia_coll.start_id = ia_role.start_id AND ia_coll.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection nc "
          f"  ON nc.collection_id || '@' || nc.root_site_code = ia_coll.end_id AND nc.collection_type = 2 "
          f"JOIN {schema}.graph_edges hm "
          f"  ON hm.start_id = ia_coll.end_id AND hm.kind = 'SCCM_HasMember' "
          f"JOIN {schema}.node_client_device cd ON cd.smsid = hm.end_id "
          f"WHERE ia_role.kind = 'SCCM_IsAssigned'")
    # Diagnostic: count custom roles assigned to admins that produce no device edge (CMBP warns per role).
    skip_list = ", ".join(f"'{r}'" for r in (*_ROLE_EDGE_KIND, *_ROLE_KNOWN_NO_EDGE))
    try:
        cnt = con.execute(
            f"SELECT count(DISTINCT sr.role_id) FROM {schema}.graph_edges ia "
            f"JOIN {schema}.node_security_role sr ON sr.role_id || '@' || sr.root_site_code = ia.end_id "
            f"WHERE ia.kind = 'SCCM_IsAssigned' AND upper(sr.role_id) NOT IN ({skip_list})"
        ).fetchone()[0]
    except duckdb.Error as err:
        logger.warning("edge_rbac_role_grants: custom-role audit query failed: %s", err)
        cnt = 0
    if cnt:
        logger.warning("edge_rbac_role_grants: %d custom security role(s) assigned to admins have no "
                       "traversable client-device edge (matches CMBP skip behaviour)", cnt)
    else:
        logger.debug("edge_rbac_role_grants: no custom roles to skip")
```
Wire `_edge_rbac_role_grants(con, schema)` into `transforms()` after `_edge_contains`.

- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task B3: `_edge_all_permissions` — Full Admin (both global collections) → non-secondary sites

**CMBP:** :1730-1837. An admin assigned the Full Administrator role (`SMS0001R`) **and** assigned both `SMS00001` (All Systems) **and** `SMS00004` (All Users and User Groups) gets `SCCM_AllPermissions` to every non-secondary site.

**Files:** Modify `transforms.py` (add `_edge_all_permissions`, wire in); create `edge_all_permissions_test.py`.

**Interfaces — Consumes:** `graph_edges` (`SCCM_IsAssigned`), `node_security_role`, `node_collection`, `site_hierarchy`. **Produces:** `SCCM_AllPermissions` rows.

- [ ] **Step 1: Failing test** — admin with SMS0001R + both SMS00001 and SMS00004 → AllPermissions to CAS and PS1, not SEC:

```python
# src/openhound_sccm/edge_all_permissions_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_all_permissions_requires_both_collections():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT * FROM (VALUES "
                "('SMS00001','All Systems',2),('SMS00004','All Users and User Groups',1)) AS t(collection_id,name,collection_type)")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
                "'All Systems, All Users and User Groups' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names")
    transforms(con)
    ends = sorted(r[0] for r in con.execute("SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AllPermissions' AND start_id='MAYYHEM\\ADM@CAS'").fetchall())
    assert ends == ["CAS", "PS1"]
```
> Note: `collection_names` is comma-separated text here (the AdminService form is JSON-array text — `_edge_is_assigned` routes it through `_arr()`; this test uses the simpler comma form, which `_arr()` also handles via `string_split`).

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement `_edge_all_permissions`** — require BOTH collection assignments via two joins:

```python
def _edge_all_permissions(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AdminUser -> Site SCCM_AllPermissions (CMBP ps1:1730-1837): Full Administrator
    (SMS0001R) AND assigned BOTH SMS00001 (All Systems) and SMS00004 (All Users and User
    Groups) -> every non-secondary site. Detection by well-known collection id (Decision #2;
    CMBP matched display name 'All Systems'/'All Users and User Groups')."""
    from .kinds.edges import SCCM_ALL_PERMISSIONS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL)")
    _safe(con, "edge_all_permissions",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT ia_role.start_id AS start_id, s.site_code AS end_id, "
          f"'{SCCM_ALL_PERMISSIONS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.graph_edges ia_role "
          f"JOIN {schema}.node_security_role sr "
          f"  ON sr.role_id || '@' || sr.root_site_code = ia_role.end_id AND upper(sr.role_id) = 'SMS0001R' "
          f"JOIN {schema}.graph_edges ia_as ON ia_as.start_id = ia_role.start_id AND ia_as.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection c_as "
          f"  ON c_as.collection_id || '@' || c_as.root_site_code = ia_as.end_id AND upper(c_as.collection_id) = 'SMS00001' "
          f"JOIN {schema}.graph_edges ia_au ON ia_au.start_id = ia_role.start_id AND ia_au.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection c_au "
          f"  ON c_au.collection_id || '@' || c_au.root_site_code = ia_au.end_id AND upper(c_au.collection_id) = 'SMS00004' "
          f"CROSS JOIN {nonsec} s "
          f"WHERE ia_role.kind = 'SCCM_IsAssigned'")
```
Wire `_edge_all_permissions(con, schema)` into `transforms()` after `_edge_rbac_role_grants`.

- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task B4: `_edge_assign_all_permissions` — SMS Provider Computer → non-secondary sites

**CMBP:** :1932-1940. A Computer whose site-system roles include `SMS Provider` gets `SCCM_AssignAllPermissions` to every non-secondary site.

**Files:** Modify `transforms.py` (add `_edge_assign_all_permissions`, wire in); create `edge_assign_all_permissions_test.py`.

**Interfaces — Consumes:** `node_computer` (`site_system_roles VARCHAR[]`), `site_hierarchy`. **Produces:** `SCCM_AssignAllPermissions` rows.

- [ ] **Step 1: Failing test**

```python
# src/openhound_sccm/edge_assign_all_permissions_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_assign_all_permissions_from_sms_provider():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) AS t(site_code,parent_site_code,site_type)")
    # a computer with an SMS Provider site-system role (system_roles arrives as JSON-array text)
    con.execute("CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT "
                "'S-1-5-21-1-2-3-1104' AS object_sid, 'SMSPROV' AS name, '[\"SMS Provider@PS1\"]' AS sccm_site_system_roles, true AS sccm_infra")
    transforms(con)
    ends = sorted(r[0] for r in con.execute("SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AssignAllPermissions'").fetchall())
    assert ends == ["CAS", "PS1"]
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: Implement `_edge_assign_all_permissions`**:

```python
def _edge_assign_all_permissions(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer(SMS Provider) -> Site SCCM_AssignAllPermissions (CMBP ps1:1932-1940). Any
    computer whose site_system_roles contains an 'SMS Provider' entry -> every non-secondary
    site in the single hierarchy. start = computer SID (the Computer node id)."""
    from .kinds.edges import SCCM_ASSIGN_ALL_PERMISSIONS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL)")
    _safe(con, "edge_assign_all_permissions",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT nc.sid AS start_id, s.site_code AS end_id, "
          f"'{SCCM_ASSIGN_ALL_PERMISSIONS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.node_computer nc "
          f"CROSS JOIN {nonsec} s "
          f"WHERE nc.sid IS NOT NULL "
          f"  AND len(list_filter(nc.site_system_roles, x -> x LIKE '%SMS Provider%')) > 0")
```
Wire `_edge_assign_all_permissions(con, schema)` into `transforms()` after `_edge_all_permissions` (still before `_graph_edges_dedup` and `_node_backfill`).

- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Checkpoint** + run the FULL test suite to confirm the four new builders + the retrofit coexist and `_graph_edges_dedup` collapses cleanly. `git add transforms.py` + the four new edge tests.

---

# Phase C — WS-3: Node property parity (8 existing kinds)

**Architecture for this phase.** Two kinds of additions:
- **Scalars / timestamps / audit fields / AD attributes** — added inside the existing `_node_*` coalesce: extend the staging-table DDL, add the column to each per-source `INSERT … BY NAME SELECT`, add an `any_value(...)`/`max(...)` to the final `GROUP BY`, then add the field to the `*Properties` dataclass and map it in the model. These need no lookups.
- **Relationship lists** (`members`, `collection_ids`, `role_ids`, `member_of`, `admin_users`, `stored_accounts`) — built in **new `_enrich_*` functions that run after the name lookups** (`collection_by_name`/`role_by_name`) and recreate the node table with a `LEFT JOIN` to a raw aggregation. Kept **raw/faithful** (Decision #6): `collection.members` = literal `ResourceID@SiteCode` keys incl. built-ins/unresolved; **no** edge→node aggregation.

Wire the enrichment block into `transforms()` **after `_role_by_name(con, schema)` and before `_graph_edges_init(con, schema)`**:

```python
    # Relationship-list node properties: raw/faithful, from raw tables, after the name
    # lookups exist. NOT aggregated from graph_edges (Stage 3 Decision #6).
    _enrich_collection_members(con, schema)
    _enrich_role_members(con, schema)
    _enrich_admin_assignments(con, schema)
    _enrich_client_device(con, schema)
    _enrich_site_lists(con, schema)
```

## Task C0: Finalize & commit the property-parity matrix (gates C1–C6)

**Why:** the per-kind tasks below port only fields whose **source column actually exists**. Several CMBP properties are uncollected (DHCP/PXE, NAA) or MSSQL-coupled (Stage 5). This task pins the source column for every field against the real collector tuples + lab data and records the deferrals so nothing is silently dropped.

**Files:** Create `docs/superpowers/plans/2026-06-24-stage3-property-matrix.md`.

- [ ] **Step 1:** Transcribe the gap matrix below into the doc, one table per kind.
- [ ] **Step 2:** For each **port-now** field, confirm its exact source column exists in the collector tuple in [collectors/sms_rows.py](../../src/openhound_sccm/collectors/sms_rows.py) (`DEVICE_COLUMNS`, `COLLECTION_COLUMNS`, `ROLE_COLUMNS`, `ADMIN_COLUMNS`, `RUSER_COLUMNS`, `SYSRES_COLUMNS`) or in the LDAP/SMB/registry collectors. If a field's column is absent, move it to **deferred** with the reason.
- [ ] **Step 3:** Spot-check against a real `lookup.duckdb` (the existing lab raw tree): `SELECT <col> FROM sccm.adminservice_collections LIMIT 3` etc., to confirm the column is non-empty in practice (dlt drops all-NULL columns).
- [ ] **Step 4: Checkpoint** — `git add` the matrix doc.

**Port-now classification (verified against the Stage-2 column tuples):**

| Kind | Port-now scalar/AD fields (source column) | Port-now relationship lists | Deferred (reason) |
|---|---|---|---|
| Computer | `dnshostname`, `sam_account_name` (already in `node_computer`); `distinguished_name` *(C0-verify ldap/smb source)* | — | DHCP/PXE: `is_pxe_server`,`pxe_vendor_class`,`pxe_next_server`,`pxe_boot_file`,`tftp_reachable`,`is_dhcp_server` (no DHCP/PXE collector) |
| User | `distinguished_name`, `user_principal_name` (RUSER_COLUMNS) | — | `is_sccm_network_access_account` (no NAA collector) |
| Group | *(complete — optionally expose `distinguished_name`/`sam_account_name` if C0 finds a source)* | — | — |
| SCCM_Collection | `source_site_code`, `last_change_time`, `last_member_change_time` (COLLECTION_COLUMNS) | `members` (collection_members, raw keys) | — |
| SCCM_SecurityRole | `site_code`(=source_site), `created_by`,`created_date`,`last_modified_by`,`last_modified_date` (ROLE_COLUMNS) | `members` (admins→role, node ids) | — |
| SCCM_AdminUser | `display_name` (staged already), `source_site_code`, `created_by`,`created_date`,`last_modified_by`,`last_modified_date` (ADMIN_COLUMNS) | `collection_ids`, `role_ids`, `member_of` | — |
| SCCM_ClientDevice | `ad_last_logon_time`, `ad_last_logon_user_domain`(=user_domain_name), `source_site_code` (DEVICE_COLUMNS); resolved `primary_user_sid`,`current_logon_user_sid`,`ad_last_logon_user_sid`,`last_reported_mp_server_sid` (via `principal_by_name`) | `collection_ids`, `collection_names` | `current_management_point`,`distinguished_name`,`dnshostname`,`domain`,`previous_smsid*`,`last_active/online/offline_time` (not in DEVICE_COLUMNS) |
| SCCM_Site | `sql_service_account_name`(=SYSRES sql_server_service_logon_account); `display_name`,`distinguished_name`,`source_forest` *(C0-verify ldap_sites)* | `admin_users` (admins, raw), `stored_accounts` (reserved_accounts) | `site_server_domain_sid/fqdn`, `sql_server_domain_sid/fqdn`, `sql_service_port`, `sql_service_account_domain_sid` (MSSQL-coupled → **Stage 5**); `client_certificate_required` (already on Computer) |

> `MSSQL_*` node parity is **Stage 5** (those node tables don't exist yet). The DHCP/PXE and NAA fields are **blocked on their collectors** — open gtk: DHCP/PXE `Ope-o6bh`/`Ope-gqwo`, NAA via `SCCM_HasNetworkAccessAccount` (Stage-2-deferred).

## Task C1: `SCCM_Collection` parity (scalars + `members`)

**Files:** Modify `transforms.py` (`_node_collection`, add `_enrich_collection_members`), `graph.py` (`SCCMCollectionProperties`), `models/sccm_collection.py`; modify `node_collection_test.py`, `models/sccm_collection_test.py`.

- [ ] **Step 1: Failing tests** — (a) `node_collection` has `source_site_code`, `last_change_time`, `last_member_change_time`; (b) `members` is the raw `ResourceID@SiteCode` list incl. a built-in:

```python
def test_node_collection_members_raw_keys():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'SMS00001' AS collection_id, 'All Systems' AS name, 2 AS collection_type, 'CAS' AS source_site_code, '2026-01-01' AS last_change_time")
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT * FROM (VALUES "
                "('SMS00001', 50, 'CAS'), ('SMS00001', 2046820352, 'CAS')) AS t(collection_id, resource_id, site_code)")
    transforms(con)
    r = con.execute("SELECT source_site_code, last_change_time, members FROM sccm.node_collection WHERE collection_id='SMS00001'").fetchone()
    assert r[0] == "CAS" and r[1] == "2026-01-01"
    assert sorted(r[2]) == ["2046820352@CAS", "50@CAS"]   # raw keys incl. the built-in
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a:** In `_node_collection`, add `source_site_code VARCHAR, last_change_time VARCHAR, last_member_change_time VARCHAR` to the staging DDL; add them to `_optional`; select them in each per-source `INSERT` (`source_site_code, last_change_time, last_member_change_time`); add `any_value(source_site_code) AS source_site_code, any_value(last_change_time) AS last_change_time, any_value(last_member_change_time) AS last_member_change_time` to the final `GROUP BY`.
- [ ] **Step 3b:** Add `_enrich_collection_members`:

```python
def _enrich_collection_members(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_collection.members: the raw ResourceID@SiteCode keys per collection
    (CMBP ps1:7605), faithful — built-in/unresolved members included. From the raw
    collection_members tables, NOT from graph_edges (Stage 3 Decision #6)."""
    con.execute(f"CREATE OR REPLACE TEMP TABLE _cmembers (collection_id VARCHAR, member_key VARCHAR)")
    for _src in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _src, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        _safe(con, f"_cmembers<-{_src}",
              f"INSERT INTO _cmembers SELECT upper(collection_id), "
              f"CAST(resource_id AS VARCHAR) || '@' || CAST(site_code AS VARCHAR) "
              f"FROM {schema}.{_src} WHERE collection_id IS NOT NULL AND resource_id IS NOT NULL")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection AS "
        f"SELECT c.*, coalesce(m.members, CAST([] AS VARCHAR[])) AS members "
        f"FROM {schema}.node_collection c "
        f"LEFT JOIN (SELECT collection_id, list_distinct(array_agg(member_key)) AS members "
        f"           FROM _cmembers GROUP BY collection_id) m ON m.collection_id = c.collection_id")
    logger.info("node_collection.members enriched in schema %r", schema)
```

- [ ] **Step 3c:** `SCCMCollectionProperties` gains `source_site_code: str | None`, `last_change_time: str | None`, `last_member_change_time: str | None` (all `kw_only`), and `members: list[str] = field(default_factory=list, kw_only=True)`. `models/sccm_collection.py`: add the matching `BaseAsset` fields and map them into the properties in `as_node`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task C2: `SCCM_SecurityRole` parity (audit fields + `members`)

**Files:** Modify `transforms.py` (`_node_security_role`, add `_enrich_role_members`), `graph.py`, `models/sccm_security_role.py`; modify the two role tests.

- [ ] **Step 1: Failing tests** — role has `site_code`,`created_by`,`created_date`,`last_modified_by`,`last_modified_date`; `members` = the admin node ids assigned to it (`logon_name@root`).

```python
def test_node_security_role_members_admin_ids():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name, 'admin@x' AS created_by")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, 'SMS0001R' AS roles, NULL AS role_names")
    transforms(con)
    r = con.execute("SELECT created_by, members FROM sccm.node_security_role WHERE role_id='SMS0001R'").fetchone()
    assert r[0] == "admin@x"
    assert r[1] == ["MAYYHEM\\ADM@CAS"]
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a:** In `_node_security_role`, add `site_code`(from `source_site`),`created_by`,`created_date`,`last_modified_by`,`last_modified_date` to staging DDL/`_optional`/per-source SELECT (`source_site AS site_code, created_by, created_date, last_modified_by, last_modified_date`) and `any_value(...)` in the GROUP BY.
- [ ] **Step 3b:** Add `_enrich_role_members` — resolve admins→role from the raw `admins` rows (roles list + role_names fallback via `role_by_name`), aggregate `upper(logon_name)||'@'||root` per role id:

```python
def _enrich_role_members(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_security_role.members: the admin node ids assigned to each role
    (CMBP ps1:7854/7880). Resolved from raw admins (roles + role_names fallback via
    role_by_name), NOT from graph_edges (Decision #6)."""
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""
    con.execute("CREATE OR REPLACE TEMP TABLE _rmembers (role_id VARCHAR, admin_id VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR", "roles": "VARCHAR", "role_names": "VARCHAR"})
        # roles (id list)
        _safe(con, f"_rmembers_roles<-{_src}",
              f"INSERT INTO _rmembers SELECT upper(trim(t.rid)), upper(a.logon_name){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rid) != ''")
        # role_names fallback only when roles is empty
        _safe(con, f"_rmembers_names<-{_src}",
              f"INSERT INTO _rmembers SELECT rbn.role_id, upper(a.logon_name){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.role_names')}) AS t(rn) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rn)) = rbn.name "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rn) != '' AND len({_arr('a.roles')}) = 0")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role AS "
        f"SELECT r.*, coalesce(m.members, CAST([] AS VARCHAR[])) AS members "
        f"FROM {schema}.node_security_role r "
        f"LEFT JOIN (SELECT role_id, list_distinct(array_agg(admin_id)) AS members "
        f"           FROM _rmembers GROUP BY role_id) m ON m.role_id = r.role_id")
    logger.info("node_security_role.members enriched in schema %r", schema)
```

- [ ] **Step 3c:** `SCCMSecurityRoleProperties` gains `site_code`,`created_by`,`created_date`,`last_modified_by`,`last_modified_date` (`str|None`) + `members: list[str]`. Map in `models/sccm_security_role.py`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task C3: `SCCM_AdminUser` parity (audit fields + `collection_ids`/`role_ids`/`member_of`)

**Files:** Modify `transforms.py` (`_node_admin_user`, add `_enrich_admin_assignments`), `graph.py`, `models/sccm_admin_user.py`; modify the two admin tests.

- [ ] **Step 1: Failing tests** — admin has `display_name`,`source_site_code`,`last_modified_by`,`last_modified_date`; `role_ids` = raw `roles`; `member_of` = role node ids; `collection_ids` = collection node ids resolved from `collection_names`.

```python
def test_node_admin_user_assignment_lists():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'SMS00001' AS collection_id, 'All Systems' AS name, 2 AS collection_type, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
                "'adm disp' AS display_name, 'CAS' AS source_site, 'All Systems' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names")
    transforms(con)
    r = con.execute("SELECT display_name, source_site_code, collection_ids, role_ids, member_of FROM sccm.node_admin_user").fetchone()
    assert r[0] == "adm disp" and r[1] == "CAS"
    assert r[2] == ["SMS00001@CAS"]      # collection node id
    assert r[3] == ["SMS0001R"]          # raw role id
    assert r[4] == ["SMS0001R@CAS"]      # role node id
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a:** In `_node_admin_user`, add `source_site`(→`source_site_code`),`last_modified_by`,`last_modified_date`,`created_by`,`created_date` to staging/`_optional`/SELECT/GROUP BY (`display_name` is already staged — it's in the table but not yet on the dataclass).
- [ ] **Step 3b:** Add `_enrich_admin_assignments` (`role_ids` raw via `_arr`; `member_of` = role ids resolved to `role_id@root`; `collection_ids` = collection names→`collection_by_name`→`collection_id@root`). Build three temp aggregations keyed on `upper(logon_name)` and LEFT JOIN all three onto `node_admin_user`:

```python
def _enrich_admin_assignments(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_admin_user.collection_ids / role_ids / member_of (CMBP ps1:7775/7783/7848).
    role_ids = raw admin.roles; member_of = resolved role node ids (roles + role_names
    fallback); collection_ids = collection node ids from collection_names. Raw, from the
    admins rows + name lookups, NOT from graph_edges (Decision #6)."""
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""
    con.execute("CREATE OR REPLACE TEMP TABLE _aassign (logon_key VARCHAR, kind VARCHAR, val VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR", "roles": "VARCHAR", "role_names": "VARCHAR", "collection_names": "VARCHAR"})
        # role_ids: raw role id list
        _safe(con, f"_aassign_roleid<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'role_id', upper(trim(t.rid)) "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) WHERE trim(t.rid) != ''")
        # member_of: role node id (from roles list)
        _safe(con, f"_aassign_memberof_id<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'member_of', upper(trim(t.rid)){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) WHERE trim(t.rid) != ''")
        # member_of fallback: role_names -> role_by_name -> role node id (only when roles empty)
        _safe(con, f"_aassign_memberof_name<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'member_of', rbn.role_id{suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.role_names')}) AS t(rn) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rn)) = rbn.name "
              f"WHERE trim(t.rn) != '' AND len({_arr('a.roles')}) = 0")
        # collection_ids: collection_names -> collection_by_name -> collection node id
        _safe(con, f"_aassign_coll<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'collection_id', cbn.collection_id{suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.collection_names')}) AS t(cn) "
              f"JOIN {schema}.collection_by_name cbn ON upper(trim(t.cn)) = cbn.name "
              f"WHERE trim(t.cn) != ''")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user AS SELECT a.*, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x WHERE x.logon_key=upper(a.logon_name) AND x.kind='collection_id'), CAST([] AS VARCHAR[])) AS collection_ids, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x WHERE x.logon_key=upper(a.logon_name) AND x.kind='role_id'), CAST([] AS VARCHAR[])) AS role_ids, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x WHERE x.logon_key=upper(a.logon_name) AND x.kind='member_of'), CAST([] AS VARCHAR[])) AS member_of "
        f"FROM {schema}.node_admin_user a")
    logger.info("node_admin_user assignment lists enriched in schema %r", schema)
```

- [ ] **Step 3c:** `SCCMAdminUserProperties` gains `display_name`,`source_site_code`,`created_by`,`created_date`,`last_modified_by`,`last_modified_date` (`str|None`) + `collection_ids`,`role_ids`,`member_of` (`list[str]`). Map in `models/sccm_admin_user.py` (note `display_name` maps to the dataclass `displayname`/a dedicated field per existing convention — keep `name=logon_name`).
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task C4: `SCCM_ClientDevice` parity (telemetry + resolved `*_sid` + collection lists)

**Files:** Modify `transforms.py` (`_node_client_device`, add `_enrich_client_device`), `graph.py`, `models/sccm_client_device.py`; modify the two device tests.

- [ ] **Step 1: Failing tests** — (a) `ad_last_logon_time`,`ad_last_logon_user_domain`,`source_site_code` carried; (b) `primary_user_sid` resolved via `principal_by_name`; (c) `collection_ids`/`collection_names` = the device's memberships.

```python
def test_client_device_resolved_sid_and_collections():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'S-1-5-21-1-2-3-1200' AS sid, 'MAYYHEM\\\\alice' AS unique_user_name, 5 AS resource_id, 'CAS' AS source_site_code, 'alice' AS name")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, 50 AS resource_id, 'CAS' AS site_code, true AS is_client, false AS is_obsolete, "
                "'MAYYHEM\\\\alice' AS primary_user, 'CORP' AS user_domain_name, '2026-01-02' AS ad_last_logon_time")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'SMS00001' AS collection_id, 'All Systems' AS name, 2 AS collection_type, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT 'SMS00001' AS collection_id, 50 AS resource_id, 'CAS' AS site_code")
    transforms(con)
    r = con.execute("SELECT ad_last_logon_time, ad_last_logon_user_domain, primary_user_sid, collection_ids, collection_names FROM sccm.node_client_device WHERE smsid='GUID-1'").fetchone()
    assert r[0] == "2026-01-02" and r[1] == "CORP"
    assert r[2] == "S-1-5-21-1-2-3-1200"
    assert r[3] == ["SMS00001@CAS"] and r[4] == ["All Systems"]
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a:** In `_node_client_device`, add `ad_last_logon_time`,`user_domain_name`(→`ad_last_logon_user_domain`),`source_site_code` to staging/`_optional`/SELECT/GROUP BY (`user_name AS ad_last_logon_user_name` already present; add `user_domain_name AS ad_last_logon_user_domain`, `ad_last_logon_time`, `source_site_code`).
- [ ] **Step 3b:** Add `_enrich_client_device` — resolve the three name-only user fields + the MP server name to SIDs via `principal_by_name`, and aggregate the device's collection ids/names from `collection_members`⋈`collections`:

```python
def _enrich_client_device(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add resolved *_sid fields (CMBP stored these on the node; ps1:7227/7232/7245/7248)
    and the device's collection_ids/collection_names (ps1:7228-7229). SIDs resolved via
    principal_by_name; collection lists from raw collection_members JOIN collections."""
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""
    # collection memberships per device resource_id
    con.execute("CREATE OR REPLACE TEMP TABLE _devcoll (rid_key VARCHAR, coll_id VARCHAR, coll_name VARCHAR)")
    for _cm in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _cm, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        for _c in ("adminservice_collections", "wmi_collections"):
            _ensure_columns(con, schema, _c, {"collection_id": "VARCHAR", "name": "VARCHAR"})
            _safe(con, f"_devcoll<-{_cm}+{_c}",
                  f"INSERT INTO _devcoll SELECT CAST(cm.resource_id AS VARCHAR)||'@'||CAST(cm.site_code AS VARCHAR), "
                  f"upper(cm.collection_id){suffix}, c.name "
                  f"FROM {schema}.{_cm} cm JOIN {schema}.{_c} c ON upper(c.collection_id)=upper(cm.collection_id) "
                  f"WHERE cm.resource_id IS NOT NULL AND cm.collection_id IS NOT NULL")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS SELECT d.*, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn WHERE upper(pbn.name)=upper(trim(d.primary_user_name)) LIMIT 1) AS primary_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn WHERE upper(pbn.name)=upper(trim(d.current_logon_user_name)) LIMIT 1) AS current_logon_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn WHERE upper(pbn.name)=upper(trim(d.ad_last_logon_user_name)) LIMIT 1) AS ad_last_logon_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn WHERE upper(pbn.name)=upper(trim(d.last_mp_server_name)) LIMIT 1) AS last_reported_mp_server_sid, "
        f"coalesce((SELECT list_distinct(array_agg(coll_id)) FROM _devcoll x WHERE x.rid_key=d.resource_id_str), CAST([] AS VARCHAR[])) AS collection_ids, "
        f"coalesce((SELECT list_distinct(array_agg(coll_name)) FROM _devcoll x WHERE x.rid_key=d.resource_id_str), CAST([] AS VARCHAR[])) AS collection_names "
        f"FROM {schema}.node_client_device d")
    logger.info("node_client_device resolved SIDs + collection lists enriched in schema %r", schema)
```
> `resource_id_str` is the device's `<resource_id>@<site>` key (already built in `_node_client_device`), matching `_devcoll.rid_key`.

- [ ] **Step 3c:** `SCCMClientDeviceProperties` gains `ad_last_logon_time`,`ad_last_logon_user_domain`,`source_site_code`,`primary_user_sid`,`current_logon_user_sid`,`ad_last_logon_user_sid`,`last_reported_mp_server_sid` (`str|None`) + `collection_ids`,`collection_names` (`list[str]`). Map in `models/sccm_client_device.py`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task C5: `SCCM_Site` parity (`admin_users`, `stored_accounts`, `sql_service_account_name`)

**Files:** Modify `transforms.py` (`_node_site`, add `_enrich_site_lists`), `graph.py`, `models/sccm_site.py`; modify the site tests.

> **Deferred to Stage 5:** `site_server_domain_sid/fqdn`, `sql_server_domain_sid/fqdn`, `sql_service_port`, `sql_service_account_domain_sid` (MSSQL-coupled — built when MSSQL nodes are). `display_name`/`distinguished_name`/`source_forest` only if C0 confirms an `ldap_sites` source; else deferred (uncollected).

- [ ] **Step 1: Failing test** — site carries `sql_service_account_name` (from site_systems) and `stored_accounts`/`admin_users` lists:

```python
def test_node_site_lists_and_sql_account():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_sites AS SELECT 'CAS' AS site_code, 'CAS Site' AS site_name, 'srv' AS server_name, 4 AS type")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group")
    con.execute("CREATE TABLE sccm.adminservice_reserved_accounts AS SELECT 'S-1-5-21-1-2-3-1300' AS object_sid, 'CAS' AS site_code, 'svc_naa' AS name")
    con.execute("CREATE TABLE sccm.adminservice_site_systems AS SELECT '\\\\\\\\SQL01.lab' AS network_os_path, 'CAS' AS site_code, 'SMS SQL Server' AS role_name, 'MAYYHEM\\\\sqlsvc' AS sql_server_service_logon_account")
    transforms(con)
    r = con.execute("SELECT sql_service_account_name, admin_users, stored_accounts FROM sccm.node_site WHERE site_code='CAS'").fetchone()
    assert r[0] == "MAYYHEM\\sqlsvc"
    assert r[1] == ["MAYYHEM\\ADM@CAS"]
    assert r[2] == ["S-1-5-21-1-2-3-1300"]
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a:** In `_node_site`, add `sql_service_account_name` sourced from `adminservice_site_systems`/`wmi_site_systems` (`sql_server_service_logon_account`) — join the site-systems row for that site_code (any_value of the non-null service account). Add it to the staging DDL + the GROUP BY.
- [ ] **Step 3b:** Add `_enrich_site_lists` (`admin_users` = all admin node ids — every admin is contained in the single hierarchy; `stored_accounts` = reserved-account SIDs for that site):

```python
def _enrich_site_lists(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_site.admin_users (admin node ids contained in the hierarchy; CMBP ps1:1724)
    and stored_accounts (reserved-account SIDs stored at the site; CMBP ps1:7141). Raw, from
    the admins / reserved_accounts tables."""
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""
    # admin_users: every admin (all are contained by every non-secondary site in the single hierarchy)
    con.execute("CREATE OR REPLACE TEMP TABLE _allabmins (admin_id VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR"})
        _safe(con, f"_allabmins<-{_src}",
              f"INSERT INTO _allabmins SELECT DISTINCT upper(logon_name){suffix} "
              f"FROM {schema}.{_src} WHERE logon_name IS NOT NULL")
    con.execute("CREATE OR REPLACE TEMP TABLE _stored (site_code VARCHAR, sid VARCHAR)")
    for _src in ("adminservice_reserved_accounts", "wmi_reserved_accounts"):
        _ensure_columns(con, schema, _src, {"site_code": "VARCHAR", "object_sid": "VARCHAR"})
        _safe(con, f"_stored<-{_src}",
              f"INSERT INTO _stored SELECT site_code, upper(object_sid) "
              f"FROM {schema}.{_src} WHERE site_code IS NOT NULL AND object_sid IS NOT NULL")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS SELECT s.*, "
        f"coalesce((SELECT list_distinct(array_agg(admin_id)) FROM _allabmins), CAST([] AS VARCHAR[])) AS admin_users, "
        f"coalesce((SELECT list_distinct(array_agg(st.sid)) FROM _stored st WHERE st.site_code = s.site_code), CAST([] AS VARCHAR[])) AS stored_accounts "
        f"FROM {schema}.node_site s")
    logger.info("node_site.admin_users + stored_accounts enriched in schema %r", schema)
```
> `admin_users` is the same list on every site (the single-hierarchy containment), matching CMBP's per-site accumulation. If multi-hierarchy support is ever added, scope by `root_site_code`.

- [ ] **Step 3c:** `SCCMSiteProperties` gains `sql_service_account_name: str | None` + `admin_users`,`stored_accounts` (`list[str]`). Map in `models/sccm_site.py`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task C6: Base AD node SCCM/AD-attribute parity (Computer, User, Group)

**Files:** Modify `transforms.py` (`_node_computer` to expose already-staged cols / add `_node_user` AD attrs), `graph.py` (`ComputerProperties`, `UserProperties`), `models/computer.py`, `models/user.py`; modify the base-node tests.

> **Deferred:** Computer DHCP/PXE (`is_pxe_server`,`pxe_*`,`tftp_reachable`,`is_dhcp_server`) — no DHCP/PXE collector (`Ope-o6bh`/`Ope-gqwo`). User `is_sccm_network_access_account` — no NAA collector. Group is already at parity (per matrix); only optionally expose `distinguished_name`/`sam_account_name` if C0 finds a source.

- [ ] **Step 1: Failing tests** — Computer exposes `dnshostname`+`sam_account_name` (already in `node_computer`); User exposes `distinguished_name`+`user_principal_name`:

```python
def test_computer_exposes_dnshostname_samaccountname():
    n = ComputerNode(sid="S-1-5-21-1-2-3-1104", name="WS01", dnshostname="ws01.lab",
                     sam_account_name="WS01$").as_node
    assert n.properties.dnshostname == "ws01.lab"
    assert n.properties.sam_account_name == "WS01$"
```
```python
def test_node_user_carries_ad_attrs():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'S-1-5-21-1-2-3-1200' AS sid, 'alice' AS name, "
                "5 AS resource_id, 'CAS' AS source_site_code, 'CN=alice,DC=lab' AS distinguished_name, 'alice@lab' AS user_principal_name")
    transforms(con)
    r = con.execute("SELECT distinguished_name, user_principal_name FROM sccm.node_user WHERE sid='S-1-5-21-1-2-3-1200'").fetchone()
    assert r == ("CN=alice,DC=lab", "alice@lab")
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a — Computer:** `node_computer` already produces `dnshostname` + `sam_account_name`; add `dnshostname: str | None` and `sam_account_name: str | None` to `ComputerProperties` and map them in `models/computer.py`. (C0 confirms whether a `distinguished_name` source exists on the Computer source tables; if yes, add it the same way.)
- [ ] **Step 3b — User:** in `_node_user`, add `distinguished_name`,`user_principal_name` to staging/`_optional`, select them from the `adminservice_r_user`/`wmi_r_user` arms (`distinguished_name, user_principal_name`), `any_value(...)` in the GROUP BY; add the two fields to `UserProperties` and map in `models/user.py`.
- [ ] **Step 3c — Group:** confirm via C0 whether `sam_account_name`/`distinguished_name` have a source in the group-bearing tables; if so, expose them on `GroupProperties` the same way; otherwise note Group as complete.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Checkpoint** + run the FULL suite. `git add` the touched files.

---

# Phase D — WS-4: Validation + docs

## Task D1: Update ARCHITECTURE.md §11c (graph_edges schema + collection_source)

**Files:** Modify `ARCHITECTURE.md` (§11c "Traversable allow-list and the generic GraphEdge model").

- [ ] **Step 1:** Update the prose that says `graph_edges` is "three columns (`start_id`, `end_id`, `kind`)" → **four columns**, adding `collection_source VARCHAR[]` (a typed array, not free-form JSON — note the Stage-2 JSON-as-string bug this avoids). Note `GraphEdge` now sets both `traversable` *and* `collection_source` on `SCCMEdgeProperties`, and that the dedup pass array-unions `collection_source` over each `(start_id, end_id, kind)` group.
- [ ] **Step 2:** Update the changelog/divergence table row for "Convert from DuckDB"/edges if it references the column count.
- [ ] **Step 3: Checkpoint** — `git add ARCHITECTURE.md`. (Per AGENTS.md, this rides the same change as the WS-1 code — if executing strictly task-by-task, fold D1 into Task A1's checkpoint instead.)

## Task D2: Update README Node/Edge Reference

**Files:** Modify `README.md` (Edge Reference + Node Reference sections).

- [ ] **Step 1:** Add the 10 Stage-3 edges to the Edge Reference table with start→end, traversable flag, and a one-line abuse/meaning note (`SCCM_Contains`, the 7 role edges, `SCCM_AllPermissions`, `SCCM_AssignAllPermissions`). Mark only `SCCM_FullAdministrator`/`SCCM_ApplicationAdministrator` traversable among the role edges.
- [ ] **Step 2:** Update the Node Reference property lists for the 8 kinds to include the newly-ported properties (and note `collection_source` now appears on every edge). Add a short "Properties deferred to later collectors" note (DHCP/PXE, NAA, MSSQL-coupled site fields).
- [ ] **Step 3:** Add/refresh a mayyhem.com example showing a Full Administrator path to a device and an entity panel with the new properties.
- [ ] **Step 4: Checkpoint** — `git add README.md`.

## Task D3: Write the Stage 3 code-tour validation harness

**Files:** Create `docs/superpowers/plans/2026-06-24-sccm-preproc-convert-stage3-validation.md`.

- [ ] **Step 1:** Following the Stage 2 validation doc's format, write a code-tour: a small in-process driver that runs `transforms(con)` on the lab `lookup.duckdb`, with breakpoint stops (`file:line`) at each new builder (`_edge_contains`, `_edge_rbac_role_grants`, `_edge_all_permissions`, `_edge_assign_all_permissions`) and each `_enrich_*` function — what to inspect, expected state, and which plan detail it verifies.
- [ ] **Step 2:** Add the black-box CLI smoke check (the standard `preprocess` + `convert` loop) and the exact `<graph>/*.json` greps confirming: the 10 edge kinds present; every edge has a non-empty `collection_source`; a known Full Administrator reaches its devices; `SMS00001`+`SMS00004` are the real All Systems / All Users and User Groups ids in the lab; the new node properties populate.
- [ ] **Step 3: Checkpoint** — `git add` the validation doc.

## Task D4: Full real-data validation run

**Files:** none (validation only).

- [ ] **Step 1:** Run the standard loop against the lab raw tree (reuse existing `<raw>`):

```bash
openhound preprocess sccm <raw> <raw>/lookup.duckdb
openhound convert sccm <raw>/sccm <graph> --lookup-file <raw>/lookup.duckdb
```

- [ ] **Step 2:** Confirm against the lab: the 10 new edge kinds appear in `<graph>/*.json`; `collection_source` is non-empty on a sample of every edge kind (incl. the Stage-1/2 retrofit); a Full Administrator's `SCCM_FullAdministrator` edges reach the expected devices; `SCCM_AllPermissions`/`SCCM_AssignAllPermissions` land on the non-secondary sites; the new node properties (`members`, `collection_ids`, resolved `*_sid`, `admin_users`, timestamps) are populated and the deferred ones are absent (not NULL-spammed).
- [ ] **Step 3:** Run the full isolated-env `pytest` suite + `ruff`/`mypy` per `references/validate-extension.md`; report pass/skip.
- [ ] **Step 4:** Update gtk `ope-1950` to closed (or report blockers). No `git commit` — hand off to the user.

---

## Self-Review (completed by plan author)

- **Spec coverage:** WS-1 → Phase A; WS-2 (4 edges + constants) → Phase B; WS-3 (8-kind parity, matrix-first, raw lists) → Phase C; WS-4 (ARCHITECTURE/README/harness/validation) → Phase D. The 6 locked decisions each map to a task (fan-out-from-graph_edges → B2; well-known-ids → B3; collection_source typed column → A1/A2; relationship lists raw from preproc → C1–C5; MSSQL/DHCP/PXE/NAA deferrals → C0 + per-task notes).
- **Placeholders:** the only "verify against lab/collectors" items (Computer `distinguished_name`, Site `display_name`/`distinguished_name`/`source_forest`, Group AD attrs) are explicitly gated on Task C0's source-column verification with a defined fallback (defer if uncollected) — a real engineering gate, not a lazy TODO.
- **Type consistency:** every new node column is added to the coalesce, the `*Properties` dataclass, and the model in the same task; edge `collection_source` is `VARCHAR[]` → `list[str]` end-to-end (A1). The four edge builders and five `_enrich_*` functions are each wired into `transforms()` in a stated position relative to the lookups / dedup / backfill.
- **Ordering invariants:** lookups before `_enrich_*`; `_enrich_*` before `_graph_edges_init`; Stage-2 edge builders before the Stage-3 edge builders (they read `graph_edges`); all edge builders before `_graph_edges_dedup`; `_node_backfill` last (unchanged — Stage-3 kinds are intentionally not in `BACKFILL_END_KIND`, as their endpoints always have nodes).
