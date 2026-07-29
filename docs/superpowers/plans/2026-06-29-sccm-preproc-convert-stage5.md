# SCCM preproc + convert — Stage 5 (MSSQL active) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the 6 `MSSQL_*` node tables (Server, Database, ServerRole, DatabaseRole, Login, DatabaseUser) and the ~14 MSSQL edge kinds in `preproc`, and emit them through the existing Convert2-Read-DB pipeline — porting CMBP's `Add-MSSQLServerNodesAndEdges` / `Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer` / the post-proc `MSSQL_GetTGS` / `MSSQL_ServiceAccountFor` / `MSSQL_GetAdminTGS` logic, with full node-property parity from birth.

**Architecture:** Pure `transforms.py` + `graph.py` + `models/*` + `kinds/edges.py` + `main.py` additions flowing through the unchanged Convert2-Read-DB pipeline. The `MSSQL_Server` node is a **merge** (one-row-per-`host_sid:port` coalesce, like `node_computer`) of three sources — `mssql_server_instances` (EPA scan), `remoteregistry_mssql_servers` (registry), and a per-`(site, SQL-host)` SCCM resolution — so multiple site databases per site and non-SCCM SQL servers are both captured (grilled 2026-06-29). The Database, ServerRole (`sysadmin`), DatabaseRole (`db_owner`), Login, and DatabaseUser nodes are **inferred from SCCM topology** exactly as CMBP infers them (no live SQL enumeration exists, and CMBP never queried SQL either): the fixed roles always exist, the database is `CM_<siteCode>`, and the logins/database-users are the machine accounts of the Primary Site Server / SMS Provider computers that SCCM architecturally grants `sysadmin` on the site DB. MSSQL nodes get `environmentid` = the AD-domain SID of the SQL host (spec §2), so they merge with a future MSSQLHound collection on the same SID-keyed identity.

**Tech Stack:** Python 3.13+, `dlt`, `duckdb`, `openhound` (v0.2.x), `pydantic`, `pytest`, `uv`.

**Tracking:** gtk `ope-6716`. **Baseline:** the post-Stage-4 working tree (`ope-9271`) **plus the AD/SCCM output split** ([`2026-06-29-split-ad-nodes-edges-output.md`](2026-06-29-split-ad-nodes-edges-output.md)) is assumed present and importing — i.e. `main.py` exposes `SCCM_NODE_SPECS`/`AD_NODE_SPECS`/`SCCM_EDGE_SPECS`/`AD_EDGE_SPECS` (not `NODE_SPECS`/`EDGE_SPECS`) and `transforms()` ends with `_graph_edges_split`. See Locked decision #8 for the reconciliation. **Spec:** [`../specs/2026-06-16-sccm-preproc-convert-design.md`](../specs/2026-06-16-sccm-preproc-convert-design.md) §6 Stage 5 + the Node/Edge inventory §3. **CMBP reference:** `Add-MSSQLServerNodesAndEdges` [ps1:6050-6186](../../../ConfigManBearPig.ps1#L6050-L6186); `Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer` [ps1:6187-6292](../../../ConfigManBearPig.ps1#L6187-L6292); `MSSQL_GetTGS` post-proc [ps1:1964-1982](../../../ConfigManBearPig.ps1#L1964-L1982); `MSSQL_ServiceAccountFor` / `MSSQL_GetAdminTGS` [ps1:8005-8018](../../../ConfigManBearPig.ps1#L8005-L8018); db→site `SCCM_AssignAllPermissions` [ps1:6173-6180](../../../ConfigManBearPig.ps1#L6173-L6180). **Skip** the decommissioned `Add-MSSQLNodesAndEdgesForPrimarySite` [ps1:6293](../../../ConfigManBearPig.ps1#L6293) (call site commented at :7075).

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Never edit OpenHound core (`openhound/...`). (CLAUDE.md)
- **Do NOT `git add` or `git commit`.** Each task ends at a **green-test checkpoint only** — run the tests, confirm pass, then stop. (CLAUDE.md)
- **Validate in the isolated uv env** (already synced from Stage 0–4) — never touch the repo `.venv`:
  `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest <abs test path> -v`. (AGENTS.md)
- **Log every `if`/`else` and `try`/`except` branch** at an appropriate level, or leave a comment. (CLAUDE.md)
- **Node/edge property keys are CMBP-cased on output, snake_case in DuckDB.** The `MSSQL*Properties` dataclass field names ARE the output JSON keys and use **ConfigManBearPig.ps1-verbatim casing** (e.g. `dnsHostName`, `forceEncryption`, `extendedProtection`, `SQLServicePort`, `SCCMInfra`, `SCCMSite`, `SQLServer`, `isFixedRole`, `isTrustworthy`, `loginType`, `memberOfRoles`, `SQLServiceAccountDomainSID`, `SQLServiceAccountName`). DuckDB columns + model input fields stay snake_case. (See [[sccm-property-casing-cmbp]].)
- **Tests live in `sccm/sccm/tests/` as `<name>_test.py`.** Run with the isolated-env pytest targeting `tests/`.
- **No re-collect for Stage 5** — it is preproc/convert-only and reads the existing lab raw tree. Validate against the existing `<raw>` immediately.
- **Reuse the existing helpers** in `transforms.py`: `_safe(con, label, sql)`, `_ensure_columns(con, schema, table, coldefs)`, `_arr(col)`, `_root_code(con, schema)`. `_safe` takes no SQL params — inline literals where needed (established Stage 2–4 pattern). `domain_environment_id(sid, fallback_domain_sid=None)` lives in `graph.py` and is used by the models, not the transforms.
- **Standard test loop** (collect once, reuse the raw JSONL):
  ```bash
  openhound preprocess sccm <raw> <raw>/lookup.duckdb
  openhound convert sccm <raw>/sccm <graph> --lookup-file <raw>/lookup.duckdb
  # then inspect <graph>/*.json for MSSQL_* nodes/edges
  ```

### Locked Stage 5 decisions (grilled with the user 2026-06-29)

1. **MSSQL_Server = merge, not site-anchored.** `node_mssql_server` coalesces a UNION of `mssql_server_instances` + `remoteregistry_mssql_servers` + a per-`(site, SQL-host)` SCCM resolution, keyed on `upper(host_sid) || ':' || port`. This captures (a) **multiple site databases in one site** — the SCCM side is built from the per-`(site, SQL-host)` role rows, not `node_site`'s single `any_value`; and (b) **non-SCCM SQL servers** — scan/registry rows with no site match still produce a bare `MSSQL_Server` (+ `MSSQL_HostFor`/`MSSQL_ExecuteOnHost`); `SCCMSite`/`SCCMInfra` stay null/false. The Database/db_owner/`SCCM_AssignAllPermissions` chain only builds for SCCM-linked servers, as in CMBP.
2. **Login/DatabaseUser identity = per-computer DNS domain.** id/name = `<NETBIOS>\<samAccountName>@<host_sid>:<port>[\<db>]` where `<NETBIOS>` = the first label of the sysadmin computer's **own** `dnshostname` domain (`upper(split_part(dnshostname, '.', 2))`). Same FORM as CMBP (`$Domain.Split('.')[0]\<sam>`) but correct for cross-domain Site Server / SMS Provider hosts.
3. **Fold-in fixes ON (all four, grilled):**
   - **Populate role `members`** — CMBP emits `sysadmin`/`db_owner` `members` arrays always-empty (an undefined-variable scope bug at [ps1:6105](../../../ConfigManBearPig.ps1#L6105)/[ps1:6155](../../../ConfigManBearPig.ps1#L6155)); the set-based port fills them from the joined logins/database-users.
   - **Real SQL port for TGS edges** — `MSSQL_ServiceAccountFor`/`MSSQL_GetAdminTGS` use the collected port, not CMBP's hardcoded `:1433` ([ps1:8011](../../../ConfigManBearPig.ps1#L8011) TODO; spec §7 bug register).
   - **Capture non-SCCM SQL servers** — bare `MSSQL_Server` (+ host edges) for scan/registry servers not tied to a site.
   - **Port-only props** `strictEncryption` (TDS 8.0, from `mssql_server_instances.strict_encryption`) + `instanceNames` (from `remoteregistry_mssql_servers.instance_names`) — no CMBP key; marked as such in `graph.py`.
4. **`environmentid` = AD-domain SID of the SQL host** for ALL six MSSQL node kinds (spec §2, locked 2026-06-17). Derived per node by `domain_environment_id(host_sid)`.
5. **Site MSSQL properties are NOT touched.** The six "DEFER-STAGE5" site fields (`siteServerFQDN`, `siteServerDomainSID`, `SQLServerFQDN`, `SQLServerDomainSID`, `SQLServiceAccountDomainSID`, `SQLServicePort`) were already implemented in Stage 3 C5 / Stage 4 — `SCCMSiteProperties` declares them ([graph.py:130-135](../../../src/openhound_sccm/graph.py#L130-L135)), `_node_site` populates them ([transforms.py:1218-1237](../../../src/openhound_sccm/transforms.py#L1218-L1237)), and `SCCMSite.as_node` maps them ([models/sccm_site.py:114-119](../../../src/openhound_sccm/models/sccm_site.py#L114-L119)). Stage 5 does not modify `node_site` or `SCCMSite`.
6. **Spec-vs-code reconciliations (follow the CMBP code, not the loose spec table):**
   - `MSSQL_IsMappedTo` = **Login → DatabaseUser** ([ps1:6276-6280](../../../ConfigManBearPig.ps1#L6276)), not "Login → AD principal" as the spec §3 table loosely says.
   - `MSSQL_HasLogin` = **Computer → Login** ([ps1:6266-6272](../../../ConfigManBearPig.ps1#L6266)); the server→login link is a separate `MSSQL_Contains`.
   - `MSSQL_Contains` is emitted server→role, server→db, server→login, db→db_owner-role, db→database-user (multiple builders share the one kind).
7. **Resolve-or-drop AD endpoints.** Service-account edges (`MSSQL_GetTGS`/`ServiceAccountFor`/`GetAdminTGS`) emit only when the SQL service account resolves to a SID via `principal_by_name` AND that SID exists as a `node_computer`/`node_user` row; otherwise drop + log (matches CMBP's `Resolve-PrincipalInDomain` drop-on-failure and the Stage-2 graph-integrity rule). `_node_backfill` is unchanged — it backfills only the `BACKFILL_END_KIND` edge ENDs, none of which are MSSQL, and every MSSQL node id is a real emitted node.
8. **Reconciliation with the AD/SCCM output split (`2026-06-29-split-ad-nodes-edges-output.md`, landed before Stage 5).** That change replaced `NODE_SPECS`/`EDGE_SPECS` with `SCCM_NODE_SPECS`/`AD_NODE_SPECS`/`SCCM_EDGE_SPECS`/`AD_EDGE_SPECS` and added `transforms._graph_edges_split` (runs LAST, after `_node_backfill`), which partitions `graph_edges` into `graph_edges_ad` (either endpoint is an AD node id — `node_computer ∪ node_user ∪ node_group ∪ node_backfill`) and `graph_edges_sccm` (both endpoints non-AD). Stage 5 slots in cleanly:
   - **MSSQL nodes → `SCCM_NODE_SPECS`** (they are SCCM-owned, `source_kind="SCCM"`; logins/users/roles are not AD principals). They append to that list; `node_backfill` now lives in `AD_NODE_SPECS`, so there is no "before node_backfill" constraint.
   - **MSSQL edges need no special handling.** They still insert into the single `graph_edges` table (Phase G, before `_graph_edges_dedup`); `_graph_edges_split` then auto-routes them: the AD-touching ones (`MSSQL_HostFor`/`MSSQL_ExecuteOnHost`/`MSSQL_HasLogin` whose Computer-SID endpoint is an AD node, and `MSSQL_GetTGS`/`MSSQL_ServiceAccountFor`/`MSSQL_GetAdminTGS` whose service-account-SID endpoint is an AD node) → `graph_edges_ad` (untagged AD payload); the pure MSSQL/SCCM ones (`MSSQL_Contains`/`MSSQL_ControlServer`/`MSSQL_ControlDB`/`MSSQL_MemberOf`/`MSSQL_IsMappedTo` + db→site `SCCM_AssignAllPermissions`) → `graph_edges_sccm`. This is the correct routing and requires **no change to `_graph_edges_split`** (MSSQL node ids are deliberately *not* in its AD id set). An AD-payload MSSQL edge referencing an SCCM-payload MSSQL node is the same cross-file reference the split already relies on (both file sets are uploaded together).

### Edge inventory (the 15 edges this stage adds to `graph_edges`)

| # | Kind | Start → End | CMBP | `collection_source` tag |
|---|---|---|---|---|
| 1 | `MSSQL_Contains` | Server → sysadmin ServerRole | [:6111](../../../ConfigManBearPig.ps1#L6111) | `['SCCM_Add-MSSQLServerNodesAndEdges']` |
| 2 | `MSSQL_ControlServer` | sysadmin ServerRole → Server | [:6115](../../../ConfigManBearPig.ps1#L6115) | same |
| 3 | `MSSQL_HostFor` | host Computer → Server | [:6119](../../../ConfigManBearPig.ps1#L6119) | same |
| 4 | `MSSQL_ExecuteOnHost` | Server → host Computer | [:6123](../../../ConfigManBearPig.ps1#L6123) | same |
| 5 | `MSSQL_Contains` | Server → Database | [:6162](../../../ConfigManBearPig.ps1#L6162) | same |
| 6 | `MSSQL_Contains` | Database → db_owner DatabaseRole | [:6166](../../../ConfigManBearPig.ps1#L6166) | same |
| 7 | `MSSQL_ControlDB` | db_owner DatabaseRole → Database | [:6170](../../../ConfigManBearPig.ps1#L6170) | same |
| 8 | `SCCM_AssignAllPermissions` | Database → every non-secondary Site | [:6173-6180](../../../ConfigManBearPig.ps1#L6173-L6180) | `['SCCM_Add-MSSQLServerNodesAndEdges']` |
| 9 | `MSSQL_MemberOf` | Login → sysadmin ServerRole | [:6262](../../../ConfigManBearPig.ps1#L6262) | `['SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer']` |
| 10 | `MSSQL_Contains` | Server → Login | [:6266](../../../ConfigManBearPig.ps1#L6266) | same as #9 |
| 11 | `MSSQL_HasLogin` | sysadmin Computer → Login | [:6270](../../../ConfigManBearPig.ps1#L6270) | same as #9 |
| 12 | `MSSQL_IsMappedTo` | Login → DatabaseUser | [:6276](../../../ConfigManBearPig.ps1#L6276) | same as #9 |
| 13 | `MSSQL_MemberOf` | DatabaseUser → db_owner DatabaseRole | [:6280](../../../ConfigManBearPig.ps1#L6280) | same as #9 |
| 14 | `MSSQL_Contains` | Database → DatabaseUser | [:6284](../../../ConfigManBearPig.ps1#L6284) | same as #9 |
| 15a | `MSSQL_GetTGS` | service-acct SID → each Login on server | [:1975](../../../ConfigManBearPig.ps1#L1975) | `['AdminService-SMS_SCI_SysResUse']` |
| 15b | `MSSQL_ServiceAccountFor` | service-acct SID → Server (acct≠host) | [:8013](../../../ConfigManBearPig.ps1#L8013) | `['AdminService-SMS_SCI_SysResUse']` |
| 15c | `MSSQL_GetAdminTGS` | service-acct SID → Server (acct≠host) | [:8016](../../../ConfigManBearPig.ps1#L8016) | `['AdminService-SMS_SCI_SysResUse']` |

---

## File Structure

| File | Responsibility |
|---|---|
| `src/openhound_sccm/kinds/edges.py` | **modify** — add 11 named MSSQL edge-kind constants; verify/add `MSSQL_ServiceAccountFor` to `TRAVERSABLE_EDGE_KINDS` per CMBP `:2216-2249`. |
| `src/openhound_sccm/graph.py` | **modify** — add 6 `MSSQL*Properties` dataclasses (CMBP-cased fields). |
| `src/openhound_sccm/transforms.py` | **modify** — add `_mssql_sql_servers` (SCCM SQL-host resolution temp), `_node_mssql_server`, `_node_mssql_database`, `_node_mssql_login`, `_node_mssql_database_user`, `_node_mssql_server_role`, `_node_mssql_database_role`, and `_edge_mssql_structural`, `_edge_mssql_membership`, `_edge_mssql_service_account`, `_edge_mssql_db_assign_all`; wire all into `transforms()`. |
| `src/openhound_sccm/models/mssql_server.py` · `mssql_database.py` · `mssql_server_role.py` · `mssql_database_role.py` · `mssql_login.py` · `mssql_database_user.py` | **create** — one typed model per node table. |
| `src/openhound_sccm/models/__init__.py` | **modify** — import/export the 6 MSSQL models. |
| `src/openhound_sccm/main.py` | **modify** — append 6 MSSQL entries to `SCCM_NODE_SPECS` (post-split registry; see Locked decision #8). |
| `README.md` | **modify** — Node Reference (6 MSSQL kinds) + Edge Reference (the 15 edges). |
| `ARCHITECTURE.md` | **modify** — preproc/convert section: note the MSSQL server merge + topology-inference of logins/users. |
| `docs/superpowers/plans/2026-06-29-sccm-preproc-convert-stage5-validation.md` | **create** — code-tour validation harness (final task). |
| `tests/kinds_edges_mssql_test.py` · `graph_mssql_props_test.py` · `node_mssql_server_test.py` · `node_mssql_database_test.py` · `node_mssql_login_dbuser_test.py` · `node_mssql_roles_test.py` · `edge_mssql_structural_test.py` · `edge_mssql_membership_test.py` · `edge_mssql_service_account_test.py` · `mssql_models_test.py` | **create** — per-task test suites. |

**Convert/lookup (mostly no change):** `SCCMLookup.table_rows` is generic (`SELECT * FROM {schema}.{table}`, missing-table-safe — [lookup.py:22-42](../../../src/openhound_sccm/lookup.py#L22-L42)); `convert_pipeline.emit_graph_from_duckdb` iterates its `(table, model)` spec lists generically. **Post-split (decision #8):** MSSQL nodes register in `SCCM_NODE_SPECS`; MSSQL edges flow through the single `graph_edges` table and are auto-routed by `_graph_edges_split` into `graph_edges_sccm`/`graph_edges_ad` (read by the existing `SCCM_EDGE_SPECS`/`AD_EDGE_SPECS`) — so Stage 5 adds **no** edge-spec entries and makes **no** change to `_graph_edges_split` or `convert_pipeline.py`. `_preproc_table_map()` already lists `mssql_server_instances` and `remoteregistry_mssql_servers` ([main.py:1189-1191](../../../src/openhound_sccm/main.py#L1189-L1191)). `kinds/nodes.py` already defines all 6 MSSQL node-kind constants.

---

# Phase A — Edge-kind constants

### Task A1: Add named MSSQL edge-kind constants + traversable verification

**Files:**
- Modify: `src/openhound_sccm/kinds/edges.py`
- Test: `tests/kinds_edges_mssql_test.py`

**Interfaces:**
- Produces: `edges.MSSQL_CONTAINS == "MSSQL_Contains"`, `MSSQL_CONTROL_SERVER`, `MSSQL_CONTROL_DB`, `MSSQL_HOST_FOR`, `MSSQL_EXECUTE_ON_HOST`, `MSSQL_HAS_LOGIN`, `MSSQL_IS_MAPPED_TO`, `MSSQL_MEMBER_OF`, `MSSQL_SERVICE_ACCOUNT_FOR`, `MSSQL_GET_ADMIN_TGS`, `MSSQL_GET_TGS` (consumed by the Phase G edge builders). `SCCM_ASSIGN_ALL_PERMISSIONS` already exists (reused for edge #8).

- [ ] **Step 1: Confirm CMBP's traversable allow-list for `MSSQL_ServiceAccountFor`.**

Read [ps1:2216-2249](../../../ConfigManBearPig.ps1#L2216-L2249). The existing `TRAVERSABLE_EDGE_KINDS` frozenset ([kinds/edges.py:40-52](../../../src/openhound_sccm/kinds/edges.py#L40-L52)) contains every MSSQL kind EXCEPT `MSSQL_ServiceAccountFor`. Determine whether CMBP lists `MSSQL_ServiceAccountFor` as traversable (uncommented). Record the finding in the commit-less task note.
- If CMBP **lists it traversable** → add `"MSSQL_ServiceAccountFor"` to the frozenset in Step 3.
- If CMBP **does not** (commented/absent) → leave the frozenset as-is (the omission is correct) and note it.

- [ ] **Step 2: Write the failing test** — create `tests/kinds_edges_mssql_test.py`:

```python
from openhound_sccm.kinds import edges as ek


def test_mssql_edge_kind_values():
    assert ek.MSSQL_CONTAINS == "MSSQL_Contains"
    assert ek.MSSQL_CONTROL_SERVER == "MSSQL_ControlServer"
    assert ek.MSSQL_CONTROL_DB == "MSSQL_ControlDB"
    assert ek.MSSQL_HOST_FOR == "MSSQL_HostFor"
    assert ek.MSSQL_EXECUTE_ON_HOST == "MSSQL_ExecuteOnHost"
    assert ek.MSSQL_HAS_LOGIN == "MSSQL_HasLogin"
    assert ek.MSSQL_IS_MAPPED_TO == "MSSQL_IsMappedTo"
    assert ek.MSSQL_MEMBER_OF == "MSSQL_MemberOf"
    assert ek.MSSQL_SERVICE_ACCOUNT_FOR == "MSSQL_ServiceAccountFor"
    assert ek.MSSQL_GET_ADMIN_TGS == "MSSQL_GetAdminTGS"
    assert ek.MSSQL_GET_TGS == "MSSQL_GetTGS"


def test_mssql_structural_edges_are_traversable():
    # All present in the frozenset by string since Stage 0.
    for k in (ek.MSSQL_CONTAINS, ek.MSSQL_CONTROL_DB, ek.MSSQL_CONTROL_SERVER,
              ek.MSSQL_EXECUTE_ON_HOST, ek.MSSQL_HOST_FOR, ek.MSSQL_HAS_LOGIN,
              ek.MSSQL_IS_MAPPED_TO, ek.MSSQL_MEMBER_OF, ek.MSSQL_GET_ADMIN_TGS,
              ek.MSSQL_GET_TGS):
        assert k in ek.TRAVERSABLE_EDGE_KINDS
```

- [ ] **Step 3: Run to verify failure** — `AttributeError: ... has no attribute 'MSSQL_CONTAINS'`.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/kinds_edges_mssql_test.py -v`

- [ ] **Step 4: Add the constants** — in `src/openhound_sccm/kinds/edges.py`, after the Stage-4 block (line 35), before the `TRAVERSABLE_EDGE_KINDS` comment:

```python
# Stage 5 edge kinds (MSSQL). The string values are already in TRAVERSABLE_EDGE_KINDS.
MSSQL_CONTAINS = "MSSQL_Contains"
MSSQL_CONTROL_SERVER = "MSSQL_ControlServer"
MSSQL_CONTROL_DB = "MSSQL_ControlDB"
MSSQL_HOST_FOR = "MSSQL_HostFor"
MSSQL_EXECUTE_ON_HOST = "MSSQL_ExecuteOnHost"
MSSQL_HAS_LOGIN = "MSSQL_HasLogin"
MSSQL_IS_MAPPED_TO = "MSSQL_IsMappedTo"
MSSQL_MEMBER_OF = "MSSQL_MemberOf"
MSSQL_SERVICE_ACCOUNT_FOR = "MSSQL_ServiceAccountFor"
MSSQL_GET_ADMIN_TGS = "MSSQL_GetAdminTGS"
MSSQL_GET_TGS = "MSSQL_GetTGS"
```

If Step 1 found `MSSQL_ServiceAccountFor` is traversable in CMBP, also add `"MSSQL_ServiceAccountFor",` to the `TRAVERSABLE_EDGE_KINDS` frozenset (in the MSSQL block, lines 44-46).

- [ ] **Step 5: Run to verify pass.** Same command as Step 3. Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase B — MSSQL property dataclasses (`graph.py`)

### Task B1: Add the 6 `MSSQL*Properties` dataclasses

**Files:**
- Modify: `src/openhound_sccm/graph.py` (append after `SCCMClientDeviceProperties`, line 239)
- Test: `tests/graph_mssql_props_test.py`

**Interfaces:**
- Produces: `MSSQLServerProperties`, `MSSQLDatabaseProperties`, `MSSQLServerRoleProperties`, `MSSQLDatabaseRoleProperties`, `MSSQLLoginProperties`, `MSSQLDatabaseUserProperties` — each a `NodeProperties` subclass whose field names are the exact CMBP output keys (consumed by the Phase H models).

- [ ] **Step 1: Write the failing test** — create `tests/graph_mssql_props_test.py`:

```python
from dataclasses import asdict

from openhound_sccm.graph import (
    MSSQLDatabaseProperties,
    MSSQLDatabaseRoleProperties,
    MSSQLDatabaseUserProperties,
    MSSQLLoginProperties,
    MSSQLServerProperties,
    MSSQLServerRoleProperties,
)


def test_server_props_cmbp_keys():
    p = MSSQLServerProperties(
        name="SQL01:1433", displayname="SQL01:1433", environmentid="S-1-5-21-1-2-3",
        dnsHostName="SQL01.lab", SQLServicePort="1433", SCCMInfra=True, SCCMSite="PS1",
        forceEncryption=True, extendedProtection="Required", strictEncryption=False,
        databases=["CM_PS1"], instanceNames=["MSSQLSERVER"],
        SQLServiceAccountName="svc_sql", SQLServiceAccountDomainSID="S-1-5-21-1-2-3-1200",
    )
    d = asdict(p)
    # CMBP-cased keys must be present verbatim.
    for key in ("dnsHostName", "SQLServicePort", "SCCMInfra",
                "SCCMSite", "forceEncryption", "extendedProtection", "databases"):
        assert key in d
    # port-added keys (no CMBP equivalent) are present too.
    assert d["strictEncryption"] is False
    assert d["instanceNames"] == ["MSSQLSERVER"]


def test_role_and_login_keys():
    sr = MSSQLServerRoleProperties(name="sysadmin", displayname="sysadmin",
                                   environmentid="S-1-5-21-1-2-3", isFixedRole=True,
                                   members=["lab\\srv$@S-1-5-21-1-2-3-1:1433"],
                                   SCCMSite="PS1", SQLServer="SQL01.lab")
    assert asdict(sr)["isFixedRole"] is True
    lg = MSSQLLoginProperties(name="LAB\\SRV$", displayname="LAB\\SRV$",
                              environmentid="S-1-5-21-1-2-3", loginType="Windows",
                              memberOfRoles=["sysadmin@S-1-5-21-1-2-3-1:1433"],
                              SCCMInfra=True, SCCMSite="PS1", SQLServer="SQL01.lab")
    assert asdict(lg)["loginType"] == "Windows"
    du = MSSQLDatabaseUserProperties(name="LAB\\SRV$", displayname="LAB\\SRV$",
                                     environmentid="S-1-5-21-1-2-3", database="CM_PS1",
                                     login="LAB\\SRV$",
                                     memberOfRoles=["db_owner@S-1-5-21-1-2-3-1:1433\\CM_PS1"],
                                     SCCMInfra=True, SCCMSite="PS1", SQLServer="SQL01.lab")
    assert asdict(du)["login"] == "LAB\\SRV$"
    dbr = MSSQLDatabaseRoleProperties(name="db_owner", displayname="db_owner",
                                      environmentid="S-1-5-21-1-2-3", database="CM_PS1",
                                      isFixedRole=True, members=[], SCCMSite="PS1",
                                      SQLServer="SQL01.lab")
    assert asdict(dbr)["database"] == "CM_PS1"
    db = MSSQLDatabaseProperties(name="CM_PS1", displayname="CM_PS1",
                                 environmentid="S-1-5-21-1-2-3", isTrustworthy=True,
                                 SCCMInfra=True, SCCMSite="PS1", SQLServer="SQL01.lab")
    assert asdict(db)["isTrustworthy"] is True
```

- [ ] **Step 2: Run to verify failure** — `ImportError`.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/graph_mssql_props_test.py -v`

- [ ] **Step 3: Implement** — append to `src/openhound_sccm/graph.py`:

```python
# ----------------------------------------------------------------------------
# MSSQL node properties (Stage 5). Field names mirror ConfigManBearPig.ps1's
# Add-MSSQLServerNodesAndEdges / Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer
# Upsert-Node calls verbatim. `environmentid` is the AD-domain SID of the SQL host
# (spec §2). `strictEncryption` / `instanceNames` are port-added (no CMBP key).
# ----------------------------------------------------------------------------
@dataclass
class MSSQLServerProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    dnsHostName: str | None = field(default=None, kw_only=True)
    SQLServicePort: str | None = field(default=None, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    databases: list[str] = field(default_factory=list, kw_only=True)
    forceEncryption: bool | None = field(default=None, kw_only=True)
    extendedProtection: str | None = field(default=None, kw_only=True)
    SQLServiceAccountDomainSID: str | None = field(default=None, kw_only=True)
    SQLServiceAccountName: str | None = field(default=None, kw_only=True)
    # port-added (no CMBP key)
    strictEncryption: bool | None = field(default=None, kw_only=True)
    instanceNames: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class MSSQLDatabaseProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    isTrustworthy: bool = field(default=True, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLServerRoleProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    isFixedRole: bool = field(default=True, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLDatabaseRoleProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    database: str | None = field(default=None, kw_only=True)
    isFixedRole: bool = field(default=True, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLLoginProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    loginType: str | None = field(default=None, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)


@dataclass
class MSSQLDatabaseUserProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    database: str | None = field(default=None, kw_only=True)
    login: str | None = field(default=None, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)
    SCCMSite: str | None = field(default=None, kw_only=True)
    SQLServer: str | None = field(default=None, kw_only=True)
```

- [ ] **Step 4: Run to verify pass.** Same command as Step 2. Expected: PASS.
- [ ] **Step 5: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase C — Preproc: SCCM SQL-host resolution + `node_mssql_server` merge

### Task C1: `_mssql_sql_servers` — per-(site, SQL-host) SCCM resolution temp

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_mssql_sql_servers` (place after `_enrich_site_lists`, before the MSSQL node builders).
- Test: `tests/node_mssql_server_test.py` (the temp is exercised indirectly via `_node_mssql_server`; this task's test asserts the temp's contents directly).

**Interfaces:**
- Consumes: `adminservice_site_definitions_computers` / `wmi_site_definitions_computers` (`object_sid`, `dns_host_name`, `sccm_site_system_roles` — role `'SMS SQL Server@<site>'`), `node_site` (`site_code`, `root_site_code`, `sql_database_name`, `sql_service_port`, `sql_service_account_name`, `sql_service_account_domain_sid`).
- Produces: persistent table `{schema}._mssql_sql_servers(site_code, root_site_code, host_sid, dns_host_name, port, db_name, service_account_name, service_account_sid)` — one row per `(site, SQL-host computer)`. Keyed-but-not-unique (a site with two SQL hosts yields two rows). **Schema-qualified, not TEMP** (DuckDB TEMP tables live in the `temp` schema and aren't reachable as `sccm.*`; the test + all downstream builders reference `{schema}._mssql_sql_servers`). Consumed by `_node_mssql_server`, `_node_mssql_database`, the login/user builders, and the edge builders.

- [ ] **Step 1: Write the failing test** — create `tests/node_mssql_server_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _standalone_primary(con):
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_sql_server_temp_built_from_role_rows():
    """One _mssql_sql_servers row per (site, SQL host), from the 'SMS SQL Server@<site>' role."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab', 'SMS SQL Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    transforms(con)
    rows = con.execute(
        "SELECT host_sid, dns_host_name, site_code FROM sccm._mssql_sql_servers"
    ).fetchall()
    assert rows == [("S-1-5-21-1-2-3-1200", "SQL01.lab", "PS1")]
```

- [ ] **Step 2: Run to verify failure** — `_mssql_sql_servers` does not exist (Binder/Catalog error).

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_mssql_server_test.py::test_sql_server_temp_built_from_role_rows -v`

- [ ] **Step 3: Implement `_mssql_sql_servers`** — add to `src/openhound_sccm/transforms.py`:

```python
def _mssql_sql_servers(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Resolve every (site, SQL-host computer) pair that runs the site database.

    The privileged collector tagged each site-system computer with its role
    ("SMS SQL Server@<site>") in *_site_definitions_computers (same source the
    Stage-4 site-server resolution reads at transforms.py:1199). One row per
    (site, SQL host) preserves the multiple-site-database-per-site case (grilled
    2026-06-29) — node_site collapses to one SQL host via any_value, so we read the
    role rows directly here instead. Site-level SQL attributes (db name, port,
    service account) are shared across a site's SQL hosts, so they are joined from
    node_site. The database name falls back to CM_<siteCode> (CMBP :6082).
    """
    # Persistent schema-qualified table (NOT a TEMP table): the validation test and the
    # downstream builders reference it as {schema}._mssql_sql_servers, and DuckDB TEMP tables
    # live in the `temp` schema (unreachable as sccm.*). The inner _mssql_sql_hosts staging
    # table stays TEMP (only used within this function).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}._mssql_sql_servers ("
        "site_code VARCHAR, root_site_code VARCHAR, host_sid VARCHAR, dns_host_name VARCHAR, "
        "port VARCHAR, db_name VARCHAR, service_account_name VARCHAR, service_account_sid VARCHAR)"
    )
    con.execute("CREATE OR REPLACE TEMP TABLE _mssql_sql_hosts (site_code VARCHAR, host_sid VARCHAR, dns_host_name VARCHAR)")
    for _sdc in ("adminservice_site_definitions_computers", "wmi_site_definitions_computers"):
        _ensure_columns(con, schema, _sdc, {
            "object_sid": "VARCHAR", "dns_host_name": "VARCHAR", "sccm_site_system_roles": "VARCHAR",
        })
        _safe(con, f"_mssql_sql_hosts<-{_sdc}",
              f"INSERT INTO _mssql_sql_hosts "
              f"SELECT upper(split_part(sccm_site_system_roles, '@', 2)) AS site_code, "
              f"  upper(object_sid) AS host_sid, dns_host_name "
              f"FROM {schema}.{_sdc} "
              f"WHERE object_sid IS NOT NULL AND sccm_site_system_roles LIKE 'SMS SQL Server@%'")
    # Collapse duplicate (site, host) rows, then attach the site-level SQL attributes.
    con.execute(
        f"INSERT INTO {schema}._mssql_sql_servers "
        f"SELECT h.site_code, ns.root_site_code, h.host_sid, any_value(h.dns_host_name) AS dns_host_name, "
        f"  coalesce(any_value(ns.sql_service_port), '1433') AS port, "
        f"  coalesce(any_value(ns.sql_database_name), 'CM_' || h.site_code) AS db_name, "
        f"  any_value(ns.sql_service_account_name) AS service_account_name, "
        f"  any_value(ns.sql_service_account_domain_sid) AS service_account_sid "
        f"FROM _mssql_sql_hosts h "
        f"LEFT JOIN {schema}.node_site ns ON upper(ns.site_code) = h.site_code "
        f"GROUP BY h.site_code, ns.root_site_code, h.host_sid"
    )
    n = con.execute(f"SELECT count(*) FROM {schema}._mssql_sql_servers").fetchone()[0]
    logger.info("_mssql_sql_servers resolved %d (site, SQL-host) pair(s) in schema %r", n, schema)
```

- [ ] **Step 4: Wire it into `transforms()`** — in the `transforms()` body, after `_enrich_site_lists(con, schema)` and before `_graph_edges_init`, start the MSSQL node-building block with **only this task's** call (each subsequent task appends its own call directly below, so `transforms()` always references only functions that already exist):

```python
    # Stage 5: MSSQL nodes (built from SCCM topology + EPA scan; spec §6 Stage 5).
    _mssql_sql_servers(con, schema)
    # (Tasks C2–F2 append _node_mssql_server / _database / _login / _database_user
    #  / _server_role / _database_role calls here, in this order.)
```

- [ ] **Step 5: Run to verify pass** (only `_mssql_sql_servers` wired so far).

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_mssql_server_test.py::test_sql_server_temp_built_from_role_rows -v`
Expected: PASS.

- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task C2: `_node_mssql_server` — merge the three sources

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_node_mssql_server`; append `_node_mssql_server(con, schema)` to the MSSQL block in `transforms()`.
- Test: `tests/node_mssql_server_test.py` (extend)

**Interfaces:**
- Consumes: `_mssql_sql_servers` (SCCM side), `mssql_server_instances` (`domain_computer_sid`, `port`, `name`, `extended_protection`, `force_encryption`, `strict_encryption`), `remoteregistry_mssql_servers` (`domain_computer_sid`, `port`, `name`, `extended_protection`, `force_encryption`, `instance_names`).
- Produces: `node_mssql_server(server_id, host_sid, port, name, dns_host_name, sccm_site, sccm_infra, databases, force_encryption, extended_protection, strict_encryption, instance_names, service_account_name, service_account_domain_sid, collection_source)` — one row per `host_sid:port`. `server_id = upper(host_sid) || ':' || port`. Consumed by every other MSSQL node/edge builder.

- [ ] **Step 1: Append failing tests** to `tests/node_mssql_server_test.py`:

```python
def test_sccm_server_merges_epa_scan():
    """The SCCM site DB and its EPA-scan row collapse to ONE server node keyed host:port."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab', 'SMS SQL Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    con.execute(
        "CREATE TABLE sccm.mssql_server_instances AS SELECT "
        "'MSSQL-ScanForEPA' AS source, true AS force_encryption, 'Required' AS extended_protection, "
        "false AS strict_encryption, 'SQL01.lab' AS name, 'S-1-5-21-1-2-3-1200' AS domain_computer_sid, "
        "1433 AS port"
    )
    transforms(con)
    rows = con.execute(
        "SELECT server_id, sccm_site, sccm_infra, force_encryption, extended_protection, strict_encryption "
        "FROM sccm.node_mssql_server WHERE host_sid = 'S-1-5-21-1-2-3-1200'"
    ).fetchall()
    assert len(rows) == 1
    sid, site, infra, fe, ep, se = rows[0]
    assert sid == "S-1-5-21-1-2-3-1200:1433"
    assert site == "PS1" and infra is True
    assert fe is True and ep == "Required" and se is False
    db = con.execute("SELECT databases FROM sccm.node_mssql_server WHERE host_sid='S-1-5-21-1-2-3-1200'").fetchone()[0]
    assert "CM_PS1" in db


def test_non_sccm_server_kept_as_bare_node():
    """A scan-only SQL server (no SCCM site) still produces a server node; sccm_site is NULL."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.mssql_server_instances AS SELECT "
        "'MSSQL-ScanForEPA' AS source, NULL AS force_encryption, 'Off' AS extended_protection, "
        "NULL AS strict_encryption, 'OTHER.lab' AS name, 'S-1-5-21-1-2-3-9999' AS domain_computer_sid, "
        "1433 AS port"
    )
    transforms(con)
    row = con.execute(
        "SELECT server_id, sccm_site, sccm_infra FROM sccm.node_mssql_server "
        "WHERE host_sid = 'S-1-5-21-1-2-3-9999'"
    ).fetchone()
    assert row == ("S-1-5-21-1-2-3-9999:1433", None, False)
```

- [ ] **Step 2: Run to verify failure** — `node_mssql_server` does not exist.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_mssql_server_test.py -v`

- [ ] **Step 3: Implement `_node_mssql_server`** — add to `src/openhound_sccm/transforms.py`:

```python
def _node_mssql_server(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Coalesce one MSSQL_Server per host_sid:port (CMBP Add-MSSQLServerNodesAndEdges :6088).

    MERGE of three sources (grilled 2026-06-29):
      - _mssql_sql_servers  (SCCM site DB; supplies SCCMSite/db/service-account/dnsHostName)
      - mssql_server_instances     (EPA scan; supplies extendedProtection/forceEncryption/strictEncryption)
      - remoteregistry_mssql_servers (registry; supplies port/forceEncryption/instanceNames)
    Key = upper(host_sid) || ':' || port, so multiple site DBs per site AND non-SCCM SQL
    servers are both captured. Non-SCCM rows have NULL SCCMSite / false SCCMInfra.

    EPA value vocabularies differ (scan: Off/Allowed/Required/Unknown; registry: On/Off);
    Stage 5 carries them as-is (Stage 6 interprets them). extended_protection prefers the
    scan's richer value, then registry. The port is a VARCHAR throughout (matches node_site).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_server ("
        "host_sid VARCHAR, port VARCHAR, name VARCHAR, dns_host_name VARCHAR, "
        "sccm_site VARCHAR, sccm_infra BOOLEAN, databases VARCHAR[], "
        "force_encryption BOOLEAN, extended_protection VARCHAR, strict_encryption BOOLEAN, "
        "instance_names VARCHAR[], service_account_name VARCHAR, service_account_domain_sid VARCHAR, "
        "collection_source VARCHAR[])"
    )
    # Arm 1: SCCM-resolved site databases.
    _safe(con, "node_mssql_server<-_mssql_sql_servers",
          f"INSERT INTO {schema}.node_mssql_server BY NAME "
          f"SELECT host_sid, coalesce(port, '1433') AS port, dns_host_name AS name, dns_host_name, "
          f"  site_code AS sccm_site, true AS sccm_infra, "
          f"  CASE WHEN db_name IS NULL THEN CAST([] AS VARCHAR[]) ELSE [db_name] END AS databases, "
          f"  NULL AS force_encryption, NULL AS extended_protection, NULL AS strict_encryption, "
          f"  CAST([] AS VARCHAR[]) AS instance_names, "
          f"  service_account_name, service_account_sid AS service_account_domain_sid, "
          f"  ['SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source "
          f"FROM {schema}._mssql_sql_servers WHERE host_sid IS NOT NULL")
    # Arm 2: EPA scan.
    _ensure_columns(con, schema, "mssql_server_instances", {
        "domain_computer_sid": "VARCHAR", "port": "INTEGER", "name": "VARCHAR",
        "extended_protection": "VARCHAR", "force_encryption": "BOOLEAN", "strict_encryption": "BOOLEAN",
    })
    _safe(con, "node_mssql_server<-mssql_server_instances",
          f"INSERT INTO {schema}.node_mssql_server BY NAME "
          f"SELECT upper(domain_computer_sid) AS host_sid, CAST(coalesce(port, 1433) AS VARCHAR) AS port, "
          f"  name, name AS dns_host_name, NULL AS sccm_site, false AS sccm_infra, "
          f"  CAST([] AS VARCHAR[]) AS databases, force_encryption, extended_protection, strict_encryption, "
          f"  CAST([] AS VARCHAR[]) AS instance_names, NULL AS service_account_name, "
          f"  NULL AS service_account_domain_sid, ['MSSQL-ScanForEPA'] AS collection_source "
          f"FROM {schema}.mssql_server_instances WHERE domain_computer_sid IS NOT NULL")
    # Arm 3: remote-registry.
    _ensure_columns(con, schema, "remoteregistry_mssql_servers", {
        "domain_computer_sid": "VARCHAR", "port": "INTEGER", "name": "VARCHAR",
        "extended_protection": "VARCHAR", "force_encryption": "BOOLEAN", "instance_names": "VARCHAR",
    })
    _safe(con, "node_mssql_server<-remoteregistry_mssql_servers",
          f"INSERT INTO {schema}.node_mssql_server BY NAME "
          f"SELECT upper(domain_computer_sid) AS host_sid, CAST(coalesce(port, 1433) AS VARCHAR) AS port, "
          f"  name, name AS dns_host_name, NULL AS sccm_site, false AS sccm_infra, "
          f"  CAST([] AS VARCHAR[]) AS databases, force_encryption, extended_protection, NULL AS strict_encryption, "
          f"  {_arr('instance_names')} AS instance_names, NULL AS service_account_name, "
          f"  NULL AS service_account_domain_sid, ['RemoteRegistry-MSSQL'] AS collection_source "
          f"FROM {schema}.remoteregistry_mssql_servers WHERE domain_computer_sid IS NOT NULL")
    # Collapse to one row per host_sid:port. SCCM scalars win via any_value-skip-null ordering;
    # EPA prefers any non-null. server_id minted final here.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_server AS "
        f"SELECT upper(host_sid) || ':' || port AS server_id, "
        f"  host_sid, port, any_value(name) AS name, any_value(dns_host_name) AS dns_host_name, "
        f"  any_value(sccm_site) AS sccm_site, bool_or(sccm_infra) AS sccm_infra, "
        f"  list_distinct(flatten(list(databases))) AS databases, "
        f"  bool_or(force_encryption) AS force_encryption, "
        f"  any_value(extended_protection) AS extended_protection, "
        f"  bool_or(strict_encryption) AS strict_encryption, "
        f"  list_distinct(flatten(list(instance_names))) AS instance_names, "
        f"  any_value(service_account_name) AS service_account_name, "
        f"  any_value(service_account_domain_sid) AS service_account_domain_sid, "
        f"  list_distinct(flatten(list(collection_source))) AS collection_source "
        f"FROM {schema}.node_mssql_server WHERE host_sid IS NOT NULL AND port IS NOT NULL "
        f"GROUP BY upper(host_sid), host_sid, port"
    )
    n = con.execute(f"SELECT count(*) FROM {schema}.node_mssql_server").fetchone()[0]
    logger.info("node_mssql_server built (%d server(s)) in schema %r", n, schema)
```

> **EPA note:** `any_value(extended_protection)` does not guarantee the scan's value wins over the registry's when both are present. If a lab row shows a registry "On"/"Off" shadowing a scan "Required", change the coalesce to an explicit `max`/`CASE` preferring the `MSSQL-ScanForEPA`-sourced value. The validation harness (Phase I) spot-checks this against the live lab; adjust if needed.

- [ ] **Step 4: Append the wiring call** — in `transforms()`, after `_mssql_sql_servers(con, schema)` add `_node_mssql_server(con, schema)`.
- [ ] **Step 5: Run to verify pass.** Run the full `tests/node_mssql_server_test.py`. Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase D — Preproc: `node_mssql_database`

### Task D1: `_node_mssql_database`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_node_mssql_database`; append the call after `_node_mssql_server`.
- Test: `tests/node_mssql_database_test.py`

**Interfaces:**
- Consumes: `_mssql_sql_servers` (SCCM site DBs only — non-SCCM servers have no database). Each row → one database `<server_id>\<db_name>`.
- Produces: `node_mssql_database(database_id, server_id, host_sid, port, name, sccm_site, sql_server, collection_source)`. `database_id = server_id || '\' || db_name`. Consumed by the db_owner role, database-user, and edge builders.

- [ ] **Step 1: Write the failing test** — create `tests/node_mssql_database_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _ps1_with_sql(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab', 'SMS SQL Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )


def test_database_node_id_and_name():
    con = duckdb.connect(":memory:")
    _ps1_with_sql(con)
    transforms(con)
    row = con.execute(
        "SELECT database_id, server_id, name, sccm_site, sql_server FROM sccm.node_mssql_database"
    ).fetchone()
    assert row == ("S-1-5-21-1-2-3-1200:1433\\CM_PS1", "S-1-5-21-1-2-3-1200:1433",
                   "CM_PS1", "PS1", "SQL01.lab")
```

- [ ] **Step 2: Run to verify failure** — `node_mssql_database` does not exist.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_mssql_database_test.py -v`

- [ ] **Step 3: Implement `_node_mssql_database`** — add to `src/openhound_sccm/transforms.py`:

```python
def _node_mssql_database(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One MSSQL_Database per SCCM site DB (CMBP :6140). id = <server_id>\\<db_name>.

    Built only from _mssql_sql_servers (the SCCM-linked servers) — CMBP never creates a
    database for a SQL server it didn't reach via site processing, and non-SCCM scan-only
    servers expose no database name. db_name defaults to CM_<siteCode> in _mssql_sql_servers.
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_database AS "
        f"SELECT DISTINCT "
        f"  upper(host_sid) || ':' || coalesce(port, '1433') || '\\' || db_name AS database_id, "
        f"  upper(host_sid) || ':' || coalesce(port, '1433') AS server_id, "
        f"  upper(host_sid) AS host_sid, coalesce(port, '1433') AS port, "
        f"  db_name AS name, site_code AS sccm_site, dns_host_name AS sql_server, "
        f"  ['SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source "
        f"FROM {schema}._mssql_sql_servers WHERE host_sid IS NOT NULL AND db_name IS NOT NULL"
    )
    n = con.execute(f"SELECT count(*) FROM {schema}.node_mssql_database").fetchone()[0]
    logger.info("node_mssql_database built (%d database(s)) in schema %r", n, schema)
```

- [ ] **Step 4: Append `_node_mssql_database(con, schema)`** to the MSSQL block in `transforms()`.
- [ ] **Step 5: Run to verify pass.** Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase E — Preproc: `node_mssql_login` + `node_mssql_database_user` (sysadmin computers)

CMBP's `Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer` ([ps1:6187-6292](../../../ConfigManBearPig.ps1#L6187)) is called for each computer holding `SMS Site Server@<site>` or `SMS Provider@<site>` that is **not** the site DB computer itself ([ps1:1912-1920](../../../ConfigManBearPig.ps1#L1912)). It creates one MSSQL_Login (server scope) and one MSSQL_DatabaseUser (db scope) per such computer, named `<NETBIOS>\<samAccountName>`. The port builds both as set-based joins of `_mssql_sql_servers` to `node_computer`.

> **Test-fixture note (applies to every fixture in Phases E–G that needs a sysadmin computer):** `_node_computer` takes `sam_account_name` and `dnshostname` from **LDAP/HTTP** sources — the `adminservice_r_system` arm selects `NULL AS sam_account_name, NULL AS dnshostname` ([transforms.py:381](../../../src/openhound_sccm/transforms.py#L381)) — and `site_system_roles` from `*_site_definitions_computers`/HTTP. So a fixture sysadmin computer must be seeded in BOTH `adminservice_site_definitions_computers` (supplies the role + dnshostname) AND an identity source that carries `sam_account_name` (use `ldap_cmrc_devices` — `object_sid`, `name`, `sam_account_name`, `dns_host_name`; `_ensure_columns` fills the rest). Seeding only `adminservice_r_system` yields a `node_computer` row with NULL `sam_account_name`/`dnshostname`, which the login builder skips — the tests would fail for the wrong reason.

### Task E1: `_node_mssql_login`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_node_mssql_login`; append the call after `_node_mssql_database`.
- Test: `tests/node_mssql_login_dbuser_test.py`

**Interfaces:**
- Consumes: `_mssql_sql_servers` (per-site SQL host), `node_computer` (`sid`, `dnshostname`, `sam_account_name`, `site_system_roles` VARCHAR[]).
- Produces: `node_mssql_login(login_id, login_name, server_id, host_sid, port, sql_server, sccm_site, sysadmin_computer_sid, collection_source)`. `login_id = <NETBIOS>\<sam>@<server_id>`, `login_name = <NETBIOS>\<sam>` where `NETBIOS = upper(split_part(dnshostname,'.',2))`. Consumed by the database-user builder, the sysadmin server-role member population, and edges #9–#12, #15a.

- [ ] **Step 1: Write the failing test** — create `tests/node_mssql_login_dbuser_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _ps1_sql_and_provider(con):
    """PS1 with SQL host SQL01 (-1200) and an SMS Provider host PROV (-1300, a sysadmin computer).

    The provider is seeded in BOTH adminservice_site_definitions_computers (role + dnshostname)
    AND ldap_cmrc_devices (sam_account_name) per the Phase E fixture note — node_computer takes
    sam from LDAP/HTTP, not from adminservice_r_system.
    """
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1'), "
        "('S-1-5-21-1-2-3-1300', 'PROV.lab.local', 'SMS Provider@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1300', 'PROV', 'PROV$', 'PROV.lab.local')"
        ") AS t(object_sid, name, sam_account_name, dns_host_name)"
    )


def test_login_id_and_name_from_computer_own_domain():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    row = con.execute(
        "SELECT login_id, login_name, server_id, sysadmin_computer_sid FROM sccm.node_mssql_login"
    ).fetchone()
    assert row == ("LAB\\PROV$@S-1-5-21-1-2-3-1200:1433", "LAB\\PROV$",
                   "S-1-5-21-1-2-3-1200:1433", "S-1-5-21-1-2-3-1300")


def test_sql_host_is_not_its_own_login():
    """The SQL host must NOT become a login on itself, even when it ALSO holds a Site Server
    role and has a samAccountName (CMBP :1920 — the only thing excluding it is sid != host)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    # SQL host -1200 ALSO tagged Site Server, and given a sam — it must STILL be excluded.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1'), "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS Site Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01', 'SQL01$', 'SQL01.lab.local')"
        ") AS t(object_sid, name, sam_account_name, dns_host_name)"
    )
    transforms(con)
    n = con.execute("SELECT count(*) FROM sccm.node_mssql_login").fetchone()[0]
    assert n == 0
```

- [ ] **Step 2: Run to verify failure** — `node_mssql_login` does not exist.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_mssql_login_dbuser_test.py::test_login_id_and_name_from_computer_own_domain -v`

- [ ] **Step 3: Implement `_node_mssql_login`** — add to `src/openhound_sccm/transforms.py`:

```python
def _node_mssql_login(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One MSSQL_Login per (SCCM SQL host, sysadmin computer) (CMBP :6232).

    Sysadmin computer = a Site Server / SMS Provider for the SAME site as the SQL host,
    EXCLUDING the SQL host itself (CMBP :1912-1920). Login id/name use the computer's OWN
    DNS domain first label as NETBIOS (grilled 2026-06-29): <NETBIOS>\\<sam>@<server_id>.
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_login AS "
        f"SELECT DISTINCT "
        f"  upper(split_part(c.dnshostname, '.', 2)) || '\\' || c.sam_account_name "
        f"    || '@' || (upper(s.host_sid) || ':' || coalesce(s.port, '1433')) AS login_id, "
        f"  upper(split_part(c.dnshostname, '.', 2)) || '\\' || c.sam_account_name AS login_name, "
        f"  upper(s.host_sid) || ':' || coalesce(s.port, '1433') AS server_id, "
        f"  upper(s.host_sid) AS host_sid, coalesce(s.port, '1433') AS port, "
        f"  s.dns_host_name AS sql_server, s.site_code AS sccm_site, "
        f"  c.sid AS sysadmin_computer_sid, "
        f"  ['SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer'] AS collection_source "
        f"FROM {schema}._mssql_sql_servers s "
        f"JOIN {schema}.node_computer c "
        f"  ON c.sid != upper(s.host_sid) "
        f"  AND c.sam_account_name IS NOT NULL AND c.dnshostname LIKE '%.%' "
        f"  AND len(list_filter(c.site_system_roles, x -> "
        f"        upper(x) = 'SMS SITE SERVER@' || s.site_code "
        f"        OR upper(x) = 'SMS PROVIDER@' || s.site_code)) > 0 "
        f"WHERE s.host_sid IS NOT NULL"
    )
    n = con.execute(f"SELECT count(*) FROM {schema}.node_mssql_login").fetchone()[0]
    logger.info("node_mssql_login built (%d login(s)) in schema %r", n, schema)
```

- [ ] **Step 4: Append `_node_mssql_login(con, schema)`** to the MSSQL block in `transforms()`.
- [ ] **Step 5: Run to verify pass.** Run the two login tests. Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task E2: `_node_mssql_database_user`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_node_mssql_database_user`; append the call after `_node_mssql_login`.
- Test: `tests/node_mssql_login_dbuser_test.py` (extend)

**Interfaces:**
- Consumes: `node_mssql_login`, `node_mssql_database` (joined on `server_id`).
- Produces: `node_mssql_database_user(dbuser_id, dbuser_name, login_id, login_name, database_id, database, server_id, host_sid, port, sql_server, sccm_site, collection_source)`. `dbuser_id = login_name || '@' || database_id` (= `<NETBIOS>\<sam>@<server_id>\<db>`). The `database` column name matches the `MSSQLDatabaseUser.database` model field so `model(**row)` maps it directly. Consumed by the db_owner role member population and edges #12, #13, #14.

- [ ] **Step 1: Append failing test** to `tests/node_mssql_login_dbuser_test.py`:

```python
def test_database_user_id_and_login_linkage():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    row = con.execute(
        "SELECT dbuser_id, dbuser_name, login_id, database_id, database FROM sccm.node_mssql_database_user"
    ).fetchone()
    assert row == (
        "LAB\\PROV$@S-1-5-21-1-2-3-1200:1433\\CM_PS1", "LAB\\PROV$",
        "LAB\\PROV$@S-1-5-21-1-2-3-1200:1433",
        "S-1-5-21-1-2-3-1200:1433\\CM_PS1", "CM_PS1",
    )
```

- [ ] **Step 2: Run to verify failure** — `node_mssql_database_user` does not exist.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_mssql_login_dbuser_test.py::test_database_user_id_and_login_linkage -v`

- [ ] **Step 3: Implement `_node_mssql_database_user`** — add to `src/openhound_sccm/transforms.py`:

```python
def _node_mssql_database_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One MSSQL_DatabaseUser per (login, database on the same server) (CMBP :6247).

    The sysadmin computer's login is mapped into the site database as a db user with the
    same DOMAIN\\sam name. id = <login_name>@<database_id>. `database` is the db name; `login`
    is the source login name (CMBP sets both).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_database_user AS "
        f"SELECT DISTINCT "
        f"  l.login_name || '@' || d.database_id AS dbuser_id, "
        f"  l.login_name AS dbuser_name, l.login_id, l.login_name, "
        f"  d.database_id, d.name AS database, l.server_id, l.host_sid, l.port, "
        f"  l.sql_server, l.sccm_site, "
        f"  ['SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer'] AS collection_source "
        f"FROM {schema}.node_mssql_login l "
        f"JOIN {schema}.node_mssql_database d ON d.server_id = l.server_id"
    )
    n = con.execute(f"SELECT count(*) FROM {schema}.node_mssql_database_user").fetchone()[0]
    logger.info("node_mssql_database_user built (%d user(s)) in schema %r", n, schema)
```

> The column is aliased `database` (not `db_name`) so it maps directly onto the `MSSQLDatabaseUser.database` model field. `database` is a legal column identifier in DuckDB; if a future DuckDB version rejects it unquoted, quote it as `"database"` in both this SELECT and the test.

- [ ] **Step 4: Append `_node_mssql_database_user(con, schema)`** to the MSSQL block in `transforms()`.
- [ ] **Step 5: Run to verify pass.** Run the full `tests/node_mssql_login_dbuser_test.py`. Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase F — Preproc: role nodes with member population

### Task F1: `_node_mssql_server_role` (sysadmin, members populated)

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_node_mssql_server_role`; append the call after `_node_mssql_database_user`.
- Test: `tests/node_mssql_roles_test.py`

**Interfaces:**
- Consumes: `node_mssql_server` (SCCM-linked only: `sccm_infra = true`), `node_mssql_login` (for `members`).
- Produces: `node_mssql_server_role(role_id, server_id, host_sid, name, members, sccm_site, sql_server, collection_source)`. `role_id = 'sysadmin@' || server_id`, `members = [login_id ...]` on that server (fix for CMBP's empty-array scope bug). Consumed by edges #1, #2, #9.

- [ ] **Step 1: Write the failing test** — create `tests/node_mssql_roles_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _ps1_sql_and_provider(con):
    """PS1 with SQL host SQL01 (-1200) + SMS Provider PROV (-1300). See the Phase E fixture note:
    the provider's sam comes from ldap_cmrc_devices, its role from site_definitions_computers."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1'), "
        "('S-1-5-21-1-2-3-1300', 'PROV.lab.local', 'SMS Provider@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1300', 'PROV', 'PROV$', 'PROV.lab.local')"
        ") AS t(object_sid, name, sam_account_name, dns_host_name)"
    )


def test_sysadmin_role_id_and_members_populated():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    row = con.execute(
        "SELECT role_id, name, members FROM sccm.node_mssql_server_role "
        "WHERE server_id = 'S-1-5-21-1-2-3-1200:1433'"
    ).fetchone()
    assert row[0] == "sysadmin@S-1-5-21-1-2-3-1200:1433"
    assert row[1] == "sysadmin"
    assert "LAB\\PROV$@S-1-5-21-1-2-3-1200:1433" in row[2]   # members fixed (CMBP scope bug)
```

- [ ] **Step 2: Run to verify failure** — `node_mssql_server_role` does not exist.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_mssql_roles_test.py::test_sysadmin_role_id_and_members_populated -v`

- [ ] **Step 3: Implement `_node_mssql_server_role`** — add to `src/openhound_sccm/transforms.py`:

```python
def _node_mssql_server_role(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """The fixed `sysadmin` server role, one per SCCM-linked MSSQL_Server (CMBP :6101).

    members is populated from the logins on the server (fix for CMBP's empty-array scope
    bug at :6105, grilled 2026-06-29). Only SCCM-linked servers get the role — non-SCCM
    scan-only servers are bare (CMBP builds the role inside the per-site server function).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_server_role AS "
        f"SELECT 'sysadmin@' || s.server_id AS role_id, s.server_id, s.host_sid, "
        f"  'sysadmin' AS name, "
        f"  coalesce((SELECT list_distinct(list(l.login_id)) FROM {schema}.node_mssql_login l "
        f"            WHERE l.server_id = s.server_id), CAST([] AS VARCHAR[])) AS members, "
        f"  s.sccm_site, s.dns_host_name AS sql_server, "
        f"  ['SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source "
        f"FROM {schema}.node_mssql_server s WHERE s.sccm_infra"
    )
    n = con.execute(f"SELECT count(*) FROM {schema}.node_mssql_server_role").fetchone()[0]
    logger.info("node_mssql_server_role built (%d sysadmin role(s)) in schema %r", n, schema)
```

- [ ] **Step 4: Append `_node_mssql_server_role(con, schema)`** to the MSSQL block in `transforms()`.
- [ ] **Step 5: Run to verify pass.** Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task F2: `_node_mssql_database_role` (db_owner, members populated)

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_node_mssql_database_role`; append the call after `_node_mssql_server_role`.
- Test: `tests/node_mssql_roles_test.py` (extend)

**Interfaces:**
- Consumes: `node_mssql_database`, `node_mssql_database_user` (for `members`).
- Produces: `node_mssql_database_role(role_id, database_id, server_id, host_sid, name, database, members, sccm_site, sql_server, collection_source)`. `role_id = 'db_owner@' || database_id`, `members = [dbuser_id ...]` in that db. Consumed by edges #6, #7, #13.

- [ ] **Step 1: Append failing test** to `tests/node_mssql_roles_test.py`:

```python
def test_db_owner_role_id_and_members_populated():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    row = con.execute(
        "SELECT role_id, name, database, members FROM sccm.node_mssql_database_role "
        "WHERE database_id = 'S-1-5-21-1-2-3-1200:1433\\CM_PS1'"
    ).fetchone()
    assert row[0] == "db_owner@S-1-5-21-1-2-3-1200:1433\\CM_PS1"
    assert row[1] == "db_owner"
    assert row[2] == "CM_PS1"
    assert "LAB\\PROV$@S-1-5-21-1-2-3-1200:1433\\CM_PS1" in row[3]
```

- [ ] **Step 2: Run to verify failure** — `node_mssql_database_role` does not exist.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_mssql_roles_test.py -v`

- [ ] **Step 3: Implement `_node_mssql_database_role`** — add to `src/openhound_sccm/transforms.py`:

```python
def _node_mssql_database_role(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """The fixed `db_owner` database role, one per MSSQL_Database (CMBP :6151).

    members populated from the database users in the database (fix for CMBP's empty-array
    scope bug at :6155, grilled 2026-06-29).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_database_role AS "
        f"SELECT 'db_owner@' || d.database_id AS role_id, d.database_id, d.server_id, d.host_sid, "
        f"  'db_owner' AS name, d.name AS database, "
        f"  coalesce((SELECT list_distinct(list(u.dbuser_id)) FROM {schema}.node_mssql_database_user u "
        f"            WHERE u.database_id = d.database_id), CAST([] AS VARCHAR[])) AS members, "
        f"  d.sccm_site, d.sql_server, "
        f"  ['SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source "
        f"FROM {schema}.node_mssql_database d"
    )
    n = con.execute(f"SELECT count(*) FROM {schema}.node_mssql_database_role").fetchone()[0]
    logger.info("node_mssql_database_role built (%d db_owner role(s)) in schema %r", n, schema)
```

- [ ] **Step 4: Append `_node_mssql_database_role(con, schema)`** to the MSSQL block in `transforms()`.
- [ ] **Step 5: Run to verify pass.** Run the full `tests/node_mssql_roles_test.py` + re-run `node_mssql_server_test.py`, `node_mssql_database_test.py`, `node_mssql_login_dbuser_test.py` (all MSSQL node tables now build together). Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase G — Preproc: MSSQL edges (into `graph_edges`)

All four builders `INSERT INTO {schema}.graph_edges BY NAME` (the 4-column `start_id, end_id, kind, collection_source` shape — WS-1, Stage 3). They run **after** the existing edge builders and **before** `_graph_edges_dedup`. Wire all four calls together in the MSSQL edge block.

> **Post-split routing (Locked decision #8):** these all write to the single `graph_edges` table. Later in `transforms()`, `_graph_edges_dedup` collapses them, `_node_backfill` runs, and `_graph_edges_split` (LAST) partitions `graph_edges` into `graph_edges_ad`/`graph_edges_sccm`. MSSQL edges are routed automatically by endpoint — no change to `_graph_edges_split` and no new edge-spec is needed. The per-task tests below query `graph_edges` directly (which still exists pre-split), so they are unaffected by the split; Task G4 adds a routing-regression check on the split tables.

### Task G1: `_edge_mssql_structural` (edges #1–#7)

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_edge_mssql_structural`; call it after `_edge_local_admin_required` (before `_graph_edges_dedup`).
- Test: `tests/edge_mssql_structural_test.py`

**Interfaces:**
- Consumes: `node_mssql_server`, `node_mssql_server_role`, `node_mssql_database`, `node_mssql_database_role`.
- Produces: `graph_edges` rows for `MSSQL_Contains` (server→sysadmin, server→db, db→db_owner), `MSSQL_ControlServer` (sysadmin→server), `MSSQL_HostFor` (host→server), `MSSQL_ExecuteOnHost` (server→host), `MSSQL_ControlDB` (db_owner→db).

- [ ] **Step 1: Write the failing test** — create `tests/edge_mssql_structural_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _ps1_with_sql(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )


def _edges(con, kind):
    return con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = ?", [kind]
    ).fetchall()


def test_structural_edges():
    con = duckdb.connect(":memory:")
    _ps1_with_sql(con)
    transforms(con)
    srv = "S-1-5-21-1-2-3-1200:1433"
    db = srv + "\\CM_PS1"
    assert (srv, "sysadmin@" + srv) in _edges(con, "MSSQL_Contains")
    assert ("sysadmin@" + srv, srv) in _edges(con, "MSSQL_ControlServer")
    assert ("S-1-5-21-1-2-3-1200", srv) in _edges(con, "MSSQL_HostFor")       # host computer -> server
    assert (srv, "S-1-5-21-1-2-3-1200") in _edges(con, "MSSQL_ExecuteOnHost")
    assert (srv, db) in _edges(con, "MSSQL_Contains")
    assert (db, "db_owner@" + db) in _edges(con, "MSSQL_Contains")
    assert ("db_owner@" + db, db) in _edges(con, "MSSQL_ControlDB")
```

- [ ] **Step 2: Run to verify failure** — no MSSQL_Contains rows.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_mssql_structural_test.py -v`

- [ ] **Step 3: Implement `_edge_mssql_structural`** — add to `src/openhound_sccm/transforms.py`:

```python
def _edge_mssql_structural(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MSSQL server/database containment + control + host edges (CMBP :6111-6172).

    #1 Server -Contains-> sysadmin role; #2 sysadmin -ControlServer-> Server;
    #3 host Computer -HostFor-> Server; #4 Server -ExecuteOnHost-> host Computer;
    #5 Server -Contains-> Database; #6 Database -Contains-> db_owner role;
    #7 db_owner -ControlDB-> Database. The host Computer node id is the raw host SID.
    """
    from .kinds.edges import (MSSQL_CONTAINS, MSSQL_CONTROL_DB, MSSQL_CONTROL_SERVER,
                              MSSQL_EXECUTE_ON_HOST, MSSQL_HOST_FOR)
    src = "['SCCM_Add-MSSQLServerNodesAndEdges']"
    # #1 + #2 server <-> sysadmin role
    _safe(con, "edge_mssql_server_role",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT server_id AS start_id, role_id AS end_id, '{MSSQL_CONTAINS}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_server_role "
          f"UNION ALL "
          f"SELECT role_id, server_id, '{MSSQL_CONTROL_SERVER}', {src} FROM {schema}.node_mssql_server_role")
    # #3 + #4 host computer <-> server
    _safe(con, "edge_mssql_host",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT host_sid AS start_id, server_id AS end_id, '{MSSQL_HOST_FOR}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_server WHERE host_sid IS NOT NULL "
          f"UNION ALL "
          f"SELECT server_id, host_sid, '{MSSQL_EXECUTE_ON_HOST}', {src} "
          f"FROM {schema}.node_mssql_server WHERE host_sid IS NOT NULL")
    # #5 server -> database
    _safe(con, "edge_mssql_server_db",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT server_id AS start_id, database_id AS end_id, '{MSSQL_CONTAINS}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_database")
    # #6 + #7 database <-> db_owner role
    _safe(con, "edge_mssql_db_role",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT database_id AS start_id, role_id AS end_id, '{MSSQL_CONTAINS}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_database_role "
          f"UNION ALL "
          f"SELECT role_id, database_id, '{MSSQL_CONTROL_DB}', {src} FROM {schema}.node_mssql_database_role")
```

- [ ] **Step 4: Wire it** — in `transforms()`, after `_edge_local_admin_required(con, schema)` add:

```python
    # Stage 5 MSSQL edges.
    _edge_mssql_structural(con, schema)
```

- [ ] **Step 5: Run to verify pass.** Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task G2: `_edge_mssql_membership` (edges #9–#14)

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_edge_mssql_membership`; call it after `_edge_mssql_structural`.
- Test: `tests/edge_mssql_membership_test.py`

**Interfaces:**
- Consumes: `node_mssql_login`, `node_mssql_database_user`.
- Produces: `graph_edges` rows for `MSSQL_MemberOf` (login→sysadmin role, dbuser→db_owner role), `MSSQL_Contains` (server→login, db→dbuser), `MSSQL_HasLogin` (sysadmin computer→login), `MSSQL_IsMappedTo` (login→dbuser).

- [ ] **Step 1: Write the failing test** — create `tests/edge_mssql_membership_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _ps1_sql_and_provider(con):
    """PS1 with SQL host SQL01 (-1200) + SMS Provider PROV (-1300). See the Phase E fixture note:
    the provider's sam comes from ldap_cmrc_devices, its role from site_definitions_computers."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1'), "
        "('S-1-5-21-1-2-3-1300', 'PROV.lab.local', 'SMS Provider@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1300', 'PROV', 'PROV$', 'PROV.lab.local')"
        ") AS t(object_sid, name, sam_account_name, dns_host_name)"
    )


def _edges(con, kind):
    return con.execute("SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = ?", [kind]).fetchall()


def test_membership_edges():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    srv = "S-1-5-21-1-2-3-1200:1433"
    login = "LAB\\PROV$@" + srv
    db = srv + "\\CM_PS1"
    dbuser = "LAB\\PROV$@" + db
    assert (login, "sysadmin@" + srv) in _edges(con, "MSSQL_MemberOf")
    assert (srv, login) in _edges(con, "MSSQL_Contains")
    assert ("S-1-5-21-1-2-3-1300", login) in _edges(con, "MSSQL_HasLogin")   # computer -> login
    assert (login, dbuser) in _edges(con, "MSSQL_IsMappedTo")
    assert (dbuser, "db_owner@" + db) in _edges(con, "MSSQL_MemberOf")
    assert (db, dbuser) in _edges(con, "MSSQL_Contains")
```

- [ ] **Step 2: Run to verify failure** — no MSSQL_HasLogin rows.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_mssql_membership_test.py -v`

- [ ] **Step 3: Implement `_edge_mssql_membership`** — add to `src/openhound_sccm/transforms.py`:

```python
def _edge_mssql_membership(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Login/DatabaseUser membership + containment + host-login edges (CMBP :6262-6286).

    #9  Login -MemberOf-> sysadmin role; #10 Server -Contains-> Login;
    #11 sysadmin Computer -HasLogin-> Login; #12 Login -IsMappedTo-> DatabaseUser;
    #13 DatabaseUser -MemberOf-> db_owner role; #14 Database -Contains-> DatabaseUser.
    """
    from .kinds.edges import MSSQL_CONTAINS, MSSQL_HAS_LOGIN, MSSQL_IS_MAPPED_TO, MSSQL_MEMBER_OF
    src = "['SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer']"
    # #9 + #10 + #11 from logins
    _safe(con, "edge_mssql_login",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT login_id AS start_id, 'sysadmin@' || server_id AS end_id, '{MSSQL_MEMBER_OF}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_login "
          f"UNION ALL SELECT server_id, login_id, '{MSSQL_CONTAINS}', {src} FROM {schema}.node_mssql_login "
          f"UNION ALL SELECT sysadmin_computer_sid, login_id, '{MSSQL_HAS_LOGIN}', {src} "
          f"  FROM {schema}.node_mssql_login WHERE sysadmin_computer_sid IS NOT NULL")
    # #12 + #13 + #14 from database users
    _safe(con, "edge_mssql_dbuser",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT login_id AS start_id, dbuser_id AS end_id, '{MSSQL_IS_MAPPED_TO}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_database_user "
          f"UNION ALL SELECT dbuser_id, 'db_owner@' || database_id, '{MSSQL_MEMBER_OF}', {src} FROM {schema}.node_mssql_database_user "
          f"UNION ALL SELECT database_id, dbuser_id, '{MSSQL_CONTAINS}', {src} FROM {schema}.node_mssql_database_user")
```

- [ ] **Step 4: Wire it** — in `transforms()`, after `_edge_mssql_structural(con, schema)` add `_edge_mssql_membership(con, schema)`.
- [ ] **Step 5: Run to verify pass.** Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task G3: `_edge_mssql_service_account` (edges #15a–#15c)

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_edge_mssql_service_account`; call it after `_edge_mssql_membership`.
- Test: `tests/edge_mssql_service_account_test.py`

**Interfaces:**
- Consumes: `node_mssql_server` (`service_account_domain_sid`, `host_sid`, `server_id`), `node_mssql_login`, `node_computer`, `node_user` (resolve-or-drop guard).
- Produces: `graph_edges` rows `MSSQL_GetTGS` (service-acct→each login on server), `MSSQL_ServiceAccountFor` + `MSSQL_GetAdminTGS` (service-acct→server, only when acct≠host).

- [ ] **Step 1: Write the failing test** — create `tests/edge_mssql_service_account_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _ps1_sql_with_svc_acct(con):
    """SQL host SQL01 with a domain service account svc_sql (SID ...-1400, has a node)."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1'), "
        "('S-1-5-21-1-2-3-1300', 'PROV.lab.local', 'SMS Provider@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    # site_systems carries the SQL service logon account name; principal_by_name resolves it.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_systems AS SELECT "
        "'PS1' AS site_code, 'LAB\\svc_sql' AS sql_server_service_logon_account"
    )
    # r_user gives svc_sql a node_user row + a (name, SID) pair for principal_by_name.
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1400', 'LAB\\svc_sql', 16777240, 'PS1', false)"
        ") AS t(sid, name, resource_id, source_site_code, obsolete)"
    )
    # provider sam (Phase E fixture note): node_computer takes sam from LDAP/HTTP, not r_system.
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1300', 'PROV', 'PROV$', 'PROV.lab.local')"
        ") AS t(object_sid, name, sam_account_name, dns_host_name)"
    )


def _edges(con, kind):
    return con.execute("SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = ?", [kind]).fetchall()


def test_service_account_edges():
    con = duckdb.connect(":memory:")
    _ps1_sql_with_svc_acct(con)
    transforms(con)
    srv = "S-1-5-21-1-2-3-1200:1433"
    login = "LAB\\PROV$@" + srv
    acct = "S-1-5-21-1-2-3-1400"
    assert (acct, login) in _edges(con, "MSSQL_GetTGS")            # service acct -> each login
    assert (acct, srv) in _edges(con, "MSSQL_ServiceAccountFor")   # acct != host
    assert (acct, srv) in _edges(con, "MSSQL_GetAdminTGS")
```

- [ ] **Step 2: Run to verify failure** — no MSSQL_GetTGS rows.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_mssql_service_account_test.py -v`

- [ ] **Step 3: Implement `_edge_mssql_service_account`** — add to `src/openhound_sccm/transforms.py`:

```python
def _edge_mssql_service_account(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SQL service-account edges (CMBP post-proc :1975 + :8013-8016).

    #15a MSSQL_GetTGS: service acct -> EACH login on the server (no acct!=host gate).
    #15b MSSQL_ServiceAccountFor + #15c MSSQL_GetAdminTGS: service acct -> server, only
         when the service account differs from the SQL host computer (CMBP :8012). Uses the
         COLLECTED port (server_id), not CMBP's hardcoded :1433 (fold-in fix, grilled).
    Resolve-or-drop: the service account SID must exist as a node_computer / node_user row
    (decision #7); else the row is skipped (the WHERE EXISTS guard) and nothing is emitted.
    """
    from .kinds.edges import MSSQL_GET_ADMIN_TGS, MSSQL_GET_TGS, MSSQL_SERVICE_ACCOUNT_FOR
    src = "['AdminService-SMS_SCI_SysResUse']"
    acct_exists = (
        f"EXISTS (SELECT 1 FROM {schema}.node_computer c WHERE c.sid = s.service_account_domain_sid) "
        f"OR EXISTS (SELECT 1 FROM {schema}.node_user u WHERE u.sid = s.service_account_domain_sid)"
    )
    # #15a GetTGS: service acct -> each login on the server.
    _safe(con, "edge_mssql_gettgs",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT s.service_account_domain_sid AS start_id, l.login_id AS end_id, "
          f"  '{MSSQL_GET_TGS}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_server s "
          f"JOIN {schema}.node_mssql_login l ON l.server_id = s.server_id "
          f"WHERE s.service_account_domain_sid IS NOT NULL AND ({acct_exists})")
    # #15b + #15c: service acct -> server, only when acct != host.
    _safe(con, "edge_mssql_svcacct_server",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT s.service_account_domain_sid AS start_id, s.server_id AS end_id, "
          f"  '{MSSQL_SERVICE_ACCOUNT_FOR}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_server s "
          f"WHERE s.service_account_domain_sid IS NOT NULL "
          f"  AND s.service_account_domain_sid != s.host_sid AND ({acct_exists}) "
          f"UNION ALL "
          f"SELECT s.service_account_domain_sid, s.server_id, '{MSSQL_GET_ADMIN_TGS}', {src} "
          f"FROM {schema}.node_mssql_server s "
          f"WHERE s.service_account_domain_sid IS NOT NULL "
          f"  AND s.service_account_domain_sid != s.host_sid AND ({acct_exists})")
```

- [ ] **Step 4: Wire it** — in `transforms()`, after `_edge_mssql_membership(con, schema)` add `_edge_mssql_service_account(con, schema)`.
- [ ] **Step 5: Run to verify pass.** Expected: PASS.
- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task G4: `_edge_mssql_db_assign_all` (edge #8)

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_edge_mssql_db_assign_all`; call it after `_edge_mssql_service_account`.
- Test: `tests/edge_mssql_structural_test.py` (extend)

**Interfaces:**
- Consumes: `node_mssql_database`, the non-secondary site set (mirror the exact subquery in the existing `_edge_assign_all_permissions`).
- Produces: `graph_edges` rows `SCCM_AssignAllPermissions` from each Database to every non-secondary site.

- [ ] **Step 1: Read the existing `_edge_assign_all_permissions`** in `transforms.py` (around line 2356). Copy its **non-secondary site subquery and site-node-id expression verbatim** so the db→site edge ends match the SCCM_Site node ids exactly (same `site_hierarchy` filter + same `site_code` casing). The db→site builder differs only in its `start_id` (the database id).

- [ ] **Step 2: Append failing test** to `tests/edge_mssql_structural_test.py`:

```python
def test_db_assign_all_permissions_to_site():
    con = duckdb.connect(":memory:")
    _ps1_with_sql(con)
    transforms(con)
    db = "S-1-5-21-1-2-3-1200:1433\\CM_PS1"
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_AssignAllPermissions' AND start_id = ?",
        [db],
    ).fetchall()
    assert (db, "PS1") in edges   # PS1 is a Primary (non-secondary) site
```

- [ ] **Step 3: Run to verify failure** — no db→site SCCM_AssignAllPermissions rows.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_mssql_structural_test.py::test_db_assign_all_permissions_to_site -v`

- [ ] **Step 4: Implement `_edge_mssql_db_assign_all`** — add to `src/openhound_sccm/transforms.py` (the `site_hierarchy` filter below MUST match the existing `_edge_assign_all_permissions`; adjust the `WHERE` / site-id expression to be identical):

```python
def _edge_mssql_db_assign_all(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Database -SCCM_AssignAllPermissions-> every non-secondary site (CMBP :6173-6180).

    The site DB has full control of the hierarchy. Mirrors the non-secondary site set used
    by _edge_assign_all_permissions (site_type != 1; NULL/unknown included). The site node id
    is the bare site_code (SCCMSite model id), matching the existing assign-all builder.
    """
    from .kinds.edges import SCCM_ASSIGN_ALL_PERMISSIONS
    _safe(con, "edge_mssql_db_assign_all",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT d.database_id AS start_id, sh.site_code AS end_id, "
          f"  '{SCCM_ASSIGN_ALL_PERMISSIONS}' AS kind, "
          f"  ['SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source "
          f"FROM {schema}.node_mssql_database d "
          f"CROSS JOIN {schema}.site_hierarchy sh "
          f"WHERE coalesce(sh.site_type, -1) != 1 AND sh.site_code IS NOT NULL")
```

> Confirm `site_hierarchy` has a `site_type` column and that the SCCM_Site node id equals `site_hierarchy.site_code` (read `_edge_assign_all_permissions`). If the existing builder uses a different table/column/casing for the site set, match it exactly here.

- [ ] **Step 5: Wire it** — in `transforms()`, after `_edge_mssql_service_account(con, schema)` add `_edge_mssql_db_assign_all(con, schema)`.
- [ ] **Step 6: Run to verify pass.** Run the full `tests/edge_mssql_structural_test.py`. Expected: PASS.
- [ ] **Step 7: Regression check** — run the whole edge suite to confirm `_graph_edges_dedup` still collapses cleanly with the new kinds, and that the AD/SCCM split (`graph_edges_split_test.py`) still passes with MSSQL edges present:

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/ -k "edge or split" -v`
Expected: PASS.

- [ ] **Step 8: Append a split-routing assertion** to `tests/edge_mssql_structural_test.py` — confirms `_graph_edges_split` (run as part of `transforms()`) routes a host-touching MSSQL edge to the AD table and a pure-MSSQL edge to the SCCM table:

```python
def test_mssql_edges_route_to_correct_split_table():
    con = duckdb.connect(":memory:")
    _ps1_with_sql(con)
    transforms(con)   # runs _graph_edges_split last
    srv = "S-1-5-21-1-2-3-1200:1433"
    # MSSQL_HostFor (host Computer SID -> server) touches an AD node -> AD payload.
    ad = con.execute(
        "SELECT count(*) FROM sccm.graph_edges_ad WHERE kind = 'MSSQL_HostFor' AND start_id = ?",
        ["S-1-5-21-1-2-3-1200"],
    ).fetchone()[0]
    assert ad == 1
    # MSSQL_Contains (server -> sysadmin role) is pure-MSSQL -> SCCM payload.
    sccm = con.execute(
        "SELECT count(*) FROM sccm.graph_edges_sccm WHERE kind = 'MSSQL_Contains' AND start_id = ?",
        [srv],
    ).fetchone()[0]
    assert sccm >= 1
```

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_mssql_structural_test.py -v`
Expected: PASS.

- [ ] **Step 9: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase H — Convert: models + SCCM_NODE_SPECS

### Task H1: The 6 MSSQL node models

**Files:**
- Create: `src/openhound_sccm/models/mssql_server.py`, `mssql_database.py`, `mssql_server_role.py`, `mssql_database_role.py`, `mssql_login.py`, `mssql_database_user.py`
- Test: `tests/mssql_models_test.py`

**Interfaces:**
- Consumes: the `node_mssql_*` row dicts (snake_case columns) + the `MSSQL*Properties` dataclasses (Task B1) + `domain_environment_id` (graph.py).
- Produces: `MSSQLServer`, `MSSQLDatabase`, `MSSQLServerRole`, `MSSQLDatabaseRole`, `MSSQLLogin`, `MSSQLDatabaseUser` (each a `BaseAsset` with an `as_node` property and `edges` returning `iter(())`). Consumed by `SCCM_NODE_SPECS` (Task H3).

- [ ] **Step 1: Write the failing test** — create `tests/mssql_models_test.py`:

```python
from openhound_sccm.models.mssql_server import MSSQLServer
from openhound_sccm.models.mssql_database import MSSQLDatabase
from openhound_sccm.models.mssql_server_role import MSSQLServerRole
from openhound_sccm.models.mssql_database_role import MSSQLDatabaseRole
from openhound_sccm.models.mssql_login import MSSQLLogin
from openhound_sccm.models.mssql_database_user import MSSQLDatabaseUser
from openhound_sccm.kinds import nodes as nk


def test_server_node():
    n = MSSQLServer(server_id="S-1-5-21-1-2-3-9:1433", host_sid="S-1-5-21-1-2-3-9",
                    port="1433", dns_host_name="SQL01.lab", sccm_site="PS1", sccm_infra=True,
                    databases=["CM_PS1"], force_encryption=True, extended_protection="Required").as_node
    assert n.id == "S-1-5-21-1-2-3-9:1433"
    assert nk.MSSQL_SERVER in n.kinds
    assert n.properties.environmentid == "S-1-5-21-1-2-3"     # domain SID of the host
    assert n.properties.dnsHostName == "SQL01.lab"
    assert n.properties.SCCMSite == "PS1"


def test_server_drops_row_without_id():
    assert MSSQLServer(server_id=None).as_node is None


def test_login_and_dbuser_nodes():
    lg = MSSQLLogin(login_id="LAB\\X$@S-1-5-21-1-2-3-9:1433", login_name="LAB\\X$",
                    host_sid="S-1-5-21-1-2-3-9", server_id="S-1-5-21-1-2-3-9:1433",
                    sql_server="SQL01.lab", sccm_site="PS1").as_node
    assert lg.id == "LAB\\X$@S-1-5-21-1-2-3-9:1433"
    assert nk.MSSQL_LOGIN in lg.kinds
    assert lg.properties.loginType == "Windows"
    assert lg.properties.memberOfRoles == ["sysadmin@S-1-5-21-1-2-3-9:1433"]
    du = MSSQLDatabaseUser(dbuser_id="LAB\\X$@S-1-5-21-1-2-3-9:1433\\CM_PS1", dbuser_name="LAB\\X$",
                           login_name="LAB\\X$", database_id="S-1-5-21-1-2-3-9:1433\\CM_PS1",
                           database="CM_PS1", host_sid="S-1-5-21-1-2-3-9",
                           server_id="S-1-5-21-1-2-3-9:1433", sql_server="SQL01.lab", sccm_site="PS1").as_node
    assert nk.MSSQL_DATABASE_USER in du.kinds
    assert du.properties.memberOfRoles == ["db_owner@S-1-5-21-1-2-3-9:1433\\CM_PS1"]
    assert du.properties.login == "LAB\\X$"


def test_role_nodes():
    sr = MSSQLServerRole(role_id="sysadmin@S-1-5-21-1-2-3-9:1433", server_id="S-1-5-21-1-2-3-9:1433",
                         host_sid="S-1-5-21-1-2-3-9", name="sysadmin",
                         members=["LAB\\X$@S-1-5-21-1-2-3-9:1433"], sccm_site="PS1", sql_server="SQL01.lab").as_node
    assert nk.MSSQL_SERVER_ROLE in sr.kinds
    assert sr.properties.isFixedRole is True
    assert sr.properties.members == ["LAB\\X$@S-1-5-21-1-2-3-9:1433"]
    dbr = MSSQLDatabaseRole(role_id="db_owner@S-1-5-21-1-2-3-9:1433\\CM_PS1",
                            database_id="S-1-5-21-1-2-3-9:1433\\CM_PS1", host_sid="S-1-5-21-1-2-3-9",
                            name="db_owner", database="CM_PS1", members=[], sccm_site="PS1",
                            sql_server="SQL01.lab").as_node
    assert nk.MSSQL_DATABASE_ROLE in dbr.kinds
    db = MSSQLDatabase(database_id="S-1-5-21-1-2-3-9:1433\\CM_PS1", host_sid="S-1-5-21-1-2-3-9",
                       name="CM_PS1", sccm_site="PS1", sql_server="SQL01.lab").as_node
    assert nk.MSSQL_DATABASE in db.kinds
    assert db.properties.isTrustworthy is True
```

- [ ] **Step 2: Run to verify failure** — `ModuleNotFoundError`.

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/mssql_models_test.py -v`

- [ ] **Step 3: Implement the 6 models.** Each mirrors `models/sccm_site.py` (pydantic `BaseAsset`, `model_config = ConfigDict(populate_by_name=True, extra="ignore")`, snake_case input fields, `as_node` building `SCCMNode`, `edges` returns `iter(())`). `environmentid = domain_environment_id(host_sid)`.

`src/openhound_sccm/models/mssql_server.py`:

```python
"""MSSQLServer: one node_mssql_server row -> one MSSQL_Server node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLServerProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLServer(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    server_id: str | None = None
    host_sid: str | None = None
    port: str | None = None
    name: str | None = None
    dns_host_name: str | None = None
    sccm_site: str | None = None
    sccm_infra: bool = False
    databases: list[str] = Field(default_factory=list)
    force_encryption: bool | None = None
    extended_protection: str | None = None
    strict_encryption: bool | None = None
    instance_names: list[str] = Field(default_factory=list)
    service_account_name: str | None = None
    service_account_domain_sid: str | None = None
    collection_source: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.server_id:
            logger.warning("MSSQLServer: dropping row with no server_id")
            return None
        env = domain_environment_id(self.host_sid or "")
        display = self.name or self.server_id
        return SCCMNode(
            id=self.server_id,
            kinds=[nk.MSSQL_SERVER],
            properties=MSSQLServerProperties(
                name=display, displayname=display, environmentid=env,
                collectionSource=list(self.collection_source),
                dnsHostName=self.dns_host_name, SQLServicePort=self.port,
                SCCMInfra=self.sccm_infra, SCCMSite=self.sccm_site,
                databases=list(self.databases),
                forceEncryption=self.force_encryption,
                extendedProtection=self.extended_protection,
                SQLServiceAccountName=self.service_account_name,
                SQLServiceAccountDomainSID=self.service_account_domain_sid,
                strictEncryption=self.strict_encryption,
                instanceNames=list(self.instance_names),
            ),
        )

    @property
    def edges(self):
        return iter(())
```

`src/openhound_sccm/models/mssql_database.py`:

```python
"""MSSQLDatabase: one node_mssql_database row -> one MSSQL_Database node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLDatabaseProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLDatabase(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    database_id: str | None = None
    server_id: str | None = None
    host_sid: str | None = None
    port: str | None = None
    name: str | None = None
    sccm_site: str | None = None
    sql_server: str | None = None
    collection_source: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.database_id:
            logger.warning("MSSQLDatabase: dropping row with no database_id")
            return None
        display = self.name or self.database_id
        return SCCMNode(
            id=self.database_id,
            kinds=[nk.MSSQL_DATABASE],
            properties=MSSQLDatabaseProperties(
                name=display, displayname=display,
                environmentid=domain_environment_id(self.host_sid or ""),
                collectionSource=list(self.collection_source),
                isTrustworthy=True, SCCMInfra=True,
                SCCMSite=self.sccm_site, SQLServer=self.sql_server,
            ),
        )

    @property
    def edges(self):
        return iter(())
```

`src/openhound_sccm/models/mssql_server_role.py`:

```python
"""MSSQLServerRole: one node_mssql_server_role row -> one MSSQL_ServerRole node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLServerRoleProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLServerRole(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    role_id: str | None = None
    server_id: str | None = None
    host_sid: str | None = None
    name: str | None = None
    members: list[str] = Field(default_factory=list)
    sccm_site: str | None = None
    sql_server: str | None = None
    collection_source: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.role_id:
            logger.warning("MSSQLServerRole: dropping row with no role_id")
            return None
        display = self.name or self.role_id
        return SCCMNode(
            id=self.role_id,
            kinds=[nk.MSSQL_SERVER_ROLE],
            properties=MSSQLServerRoleProperties(
                name=display, displayname=display,
                environmentid=domain_environment_id(self.host_sid or ""),
                collectionSource=list(self.collection_source),
                isFixedRole=True, members=list(self.members),
                SCCMSite=self.sccm_site, SQLServer=self.sql_server,
            ),
        )

    @property
    def edges(self):
        return iter(())
```

`src/openhound_sccm/models/mssql_database_role.py`:

```python
"""MSSQLDatabaseRole: one node_mssql_database_role row -> one MSSQL_DatabaseRole node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLDatabaseRoleProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLDatabaseRole(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    role_id: str | None = None
    database_id: str | None = None
    server_id: str | None = None
    host_sid: str | None = None
    name: str | None = None
    database: str | None = None
    members: list[str] = Field(default_factory=list)
    sccm_site: str | None = None
    sql_server: str | None = None
    collection_source: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.role_id:
            logger.warning("MSSQLDatabaseRole: dropping row with no role_id")
            return None
        display = self.name or self.role_id
        return SCCMNode(
            id=self.role_id,
            kinds=[nk.MSSQL_DATABASE_ROLE],
            properties=MSSQLDatabaseRoleProperties(
                name=display, displayname=display,
                environmentid=domain_environment_id(self.host_sid or ""),
                collectionSource=list(self.collection_source),
                database=self.database, isFixedRole=True, members=list(self.members),
                SCCMSite=self.sccm_site, SQLServer=self.sql_server,
            ),
        )

    @property
    def edges(self):
        return iter(())
```

`src/openhound_sccm/models/mssql_login.py`:

```python
"""MSSQLLogin: one node_mssql_login row -> one MSSQL_Login node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLLoginProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLLogin(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    login_id: str | None = None
    login_name: str | None = None
    server_id: str | None = None
    host_sid: str | None = None
    port: str | None = None
    sql_server: str | None = None
    sccm_site: str | None = None
    sysadmin_computer_sid: str | None = None
    collection_source: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.login_id:
            logger.warning("MSSQLLogin: dropping row with no login_id")
            return None
        display = self.login_name or self.login_id
        roles = [f"sysadmin@{self.server_id}"] if self.server_id else []
        return SCCMNode(
            id=self.login_id,
            kinds=[nk.MSSQL_LOGIN],
            properties=MSSQLLoginProperties(
                name=display, displayname=display,
                environmentid=domain_environment_id(self.host_sid or ""),
                collectionSource=list(self.collection_source),
                loginType="Windows", memberOfRoles=roles,
                SCCMInfra=True, SCCMSite=self.sccm_site, SQLServer=self.sql_server,
            ),
        )

    @property
    def edges(self):
        return iter(())
```

`src/openhound_sccm/models/mssql_database_user.py`:

```python
"""MSSQLDatabaseUser: one node_mssql_database_user row -> one MSSQL_DatabaseUser node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLDatabaseUserProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLDatabaseUser(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    dbuser_id: str | None = None
    dbuser_name: str | None = None
    login_id: str | None = None
    login_name: str | None = None
    database_id: str | None = None
    database: str | None = None
    server_id: str | None = None
    host_sid: str | None = None
    port: str | None = None
    sql_server: str | None = None
    sccm_site: str | None = None
    collection_source: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.dbuser_id:
            logger.warning("MSSQLDatabaseUser: dropping row with no dbuser_id")
            return None
        display = self.dbuser_name or self.dbuser_id
        roles = [f"db_owner@{self.database_id}"] if self.database_id else []
        return SCCMNode(
            id=self.dbuser_id,
            kinds=[nk.MSSQL_DATABASE_USER],
            properties=MSSQLDatabaseUserProperties(
                name=display, displayname=display,
                environmentid=domain_environment_id(self.host_sid or ""),
                collectionSource=list(self.collection_source),
                database=self.database, login=self.login_name, memberOfRoles=roles,
                SCCMInfra=True, SCCMSite=self.sccm_site, SQLServer=self.sql_server,
            ),
        )

    @property
    def edges(self):
        return iter(())
```

- [ ] **Step 4: Run to verify pass.** Expected: PASS.
- [ ] **Step 5: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task H2: Export the models from `models/__init__.py`

**Files:**
- Modify: `src/openhound_sccm/models/__init__.py`
- Test: `tests/mssql_models_test.py` (extend)

- [ ] **Step 1: Append failing test** to `tests/mssql_models_test.py`:

```python
def test_models_exported_from_package():
    from openhound_sccm.models import (MSSQLDatabase, MSSQLDatabaseRole, MSSQLDatabaseUser,
                                       MSSQLLogin, MSSQLServer, MSSQLServerRole)
    assert all(m is not None for m in
               (MSSQLServer, MSSQLDatabase, MSSQLServerRole, MSSQLDatabaseRole, MSSQLLogin, MSSQLDatabaseUser))
```

- [ ] **Step 2: Run to verify failure** — `ImportError`.

- [ ] **Step 3: Implement** — in `src/openhound_sccm/models/__init__.py`, add imports next to the existing model imports and extend `__all__`:

```python
from .mssql_database import MSSQLDatabase
from .mssql_database_role import MSSQLDatabaseRole
from .mssql_database_user import MSSQLDatabaseUser
from .mssql_login import MSSQLLogin
from .mssql_server import MSSQLServer
from .mssql_server_role import MSSQLServerRole
```

Add `"MSSQLServer", "MSSQLDatabase", "MSSQLServerRole", "MSSQLDatabaseRole", "MSSQLLogin", "MSSQLDatabaseUser"` to `__all__` (match the existing `__all__` format in the file).

- [ ] **Step 4: Run to verify pass.** Expected: PASS.
- [ ] **Step 5: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task H3: Register the 6 tables in `SCCM_NODE_SPECS`

> **Post-split (Locked decision #8):** the convert registry is now `SCCM_NODE_SPECS`/`AD_NODE_SPECS` (+ `SCCM_EDGE_SPECS`/`AD_EDGE_SPECS`). MSSQL nodes are SCCM-owned → they **append to `SCCM_NODE_SPECS`**. `node_backfill` lives in `AD_NODE_SPECS`, so there is no "before node_backfill" placement and `SCCM_NODE_SPECS` has no backfill entry. MSSQL **edges** need no spec entry — `_graph_edges_split` routes them into the existing `graph_edges_sccm`/`graph_edges_ad` tables read by `SCCM_EDGE_SPECS`/`AD_EDGE_SPECS`.

**Files:**
- Modify: `src/openhound_sccm/main.py` — `SCCM_NODE_SPECS` (the post-split list; read the current `main.py` to confirm its exact line range) + the model imports at the top.
- Test: `tests/mssql_models_test.py` (extend)

**Interfaces:**
- Consumes: the 6 models (Task H1/H2).
- Produces: `SCCM_NODE_SPECS` includes the 6 MSSQL `(table, model)` pairs (appended after `("node_client_device", SCCMClientDevice)`). `AD_NODE_SPECS`/`SCCM_EDGE_SPECS`/`AD_EDGE_SPECS` are unchanged.

- [ ] **Step 1: Append failing test** to `tests/mssql_models_test.py`:

```python
def test_sccm_node_specs_include_mssql_tables():
    from openhound_sccm.main import SCCM_NODE_SPECS
    tables = [t for t, _ in SCCM_NODE_SPECS]
    for t in ("node_mssql_server", "node_mssql_database", "node_mssql_server_role",
              "node_mssql_database_role", "node_mssql_login", "node_mssql_database_user"):
        assert t in tables
    # MSSQL nodes are SCCM-owned, never in the AD payload, and node_backfill is an AD spec.
    assert "node_backfill" not in tables
```

- [ ] **Step 2: Run to verify failure** — `node_mssql_server` not in `SCCM_NODE_SPECS`.

- [ ] **Step 3: Implement** — in `src/openhound_sccm/main.py`, import the models (next to the existing `from .models import ...`) and append the 6 entries to `SCCM_NODE_SPECS`, after the `("node_client_device", SCCMClientDevice)` line:

```python
    ("node_mssql_server", MSSQLServer),
    ("node_mssql_database", MSSQLDatabase),
    ("node_mssql_server_role", MSSQLServerRole),
    ("node_mssql_database_role", MSSQLDatabaseRole),
    ("node_mssql_login", MSSQLLogin),
    ("node_mssql_database_user", MSSQLDatabaseUser),
```

- [ ] **Step 4: Run to verify pass.** Expected: PASS.
- [ ] **Step 5: Package-import smoke check** — confirm the whole package still imports:

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm python -c "import openhound_sccm.main"`
Expected: no output, exit 0.

- [ ] **Step 6: Full suite regression** —

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/ -v`
Expected: PASS (all stages).

- [ ] **Step 7: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase I — Docs + end-to-end validation harness

### Task I1: README Node + Edge Reference

**Files:**
- Modify: `README.md` (Node Reference + Edge Reference sections)

- [ ] **Step 1:** Add the 6 MSSQL node kinds to the **Node Reference** table — for each: kind, id format, key properties (from the Phase B dataclasses), and a one-line "what it represents" (e.g. `MSSQL_Server` = "the SQL Server instance hosting an SCCM site database; id `<hostSID>:<port>`"). Note `environmentid` = the SQL host's AD domain SID, and that Login/DatabaseUser are **inferred** from the sysadmin computers (no live SQL enumeration — README Limitations).
- [ ] **Step 2:** Add the 15 MSSQL edges to the **Edge Reference** table (kind, start→end, traversable yes/no, what it means). Cross-link to the SCCM Site DB.
- [ ] **Step 3:** Add a **Limitations** note: MSSQL logins/database-users/roles are inferred from SCCM topology (Primary Site Server / SMS Provider grants), not enumerated from SQL; non-SCCM SQL servers seen by the EPA scan appear as bare `MSSQL_Server` nodes.
- [ ] **Step 4:** Verify every documented node/edge is one Stage 5 actually emits (README is code-truth — [[readme-code-truth-scope]]).
- [ ] **Step 5: Green checkpoint.**

### Task I2: ARCHITECTURE.md preproc/convert note

**Files:**
- Modify: `ARCHITECTURE.md` (preproc/convert section)

- [ ] **Step 1:** Add a short subsection noting the **MSSQL server merge** (one-row-per-`host_sid:port` coalesce of EPA-scan + registry + per-`(site, SQL-host)` SCCM resolution) and the **topology-inference** of logins/database-users (sysadmin computers → `DOMAIN\sam` logins). Note `environmentid` = SQL host's AD domain SID (cross-references the existing environment-id section). Only add a new "divergence" entry if MSSQL introduces a genuinely new *kind* of divergence; otherwise extend the existing preproc node-coalesce description.
- [ ] **Step 2: Green checkpoint.**

### Task I3: End-to-end validation harness (code tour)

**Files:**
- Create: `docs/superpowers/plans/2026-06-29-sccm-preproc-convert-stage5-validation.md`

This is the **final task of the stage** (spec §6): a standalone code-tour doc that steps through the Stage-5 code in execution order via a small in-process driver, with exact breakpoint `file:line`s, what to inspect at each stop, the expected state, and a black-box CLI/output smoke check.

- [ ] **Step 1:** Write the harness doc with these sections (mirror [`2026-06-29-sccm-preproc-convert-stage4-validation.md`](2026-06-29-sccm-preproc-convert-stage4-validation.md)):
  - **Driver script** — connect to the lab `lookup.duckdb` (or run `transforms()` on the lab raw tree), then query each `node_mssql_*` table + the MSSQL `graph_edges` rows.
  - **Stop 1** — `_mssql_sql_servers` end: inspect the `(site, SQL-host)` rows; confirm one per site DB, db_name = `CM_<site>` fallback works.
  - **Stop 2** — `_node_mssql_server` collapse: confirm one row per `host_sid:port`; the SCCM site DB merged its EPA scan row (single node, EPA populated); a non-SCCM scan server appears with NULL `sccm_site`.
  - **Stop 3** — `_node_mssql_login`/`_node_mssql_database_user`: confirm `DOMAIN\sam` derived from each computer's own DNS domain; the SQL host is not its own login.
  - **Stop 4** — `_node_mssql_server_role`/`_node_mssql_database_role`: confirm `members` are populated (the scope-bug fix).
  - **Stop 5** — the 4 edge builders: confirm the 15 edge kinds present; service-account edges only when the account resolves + differs from the host, on the real port; db→every-non-secondary-site `SCCM_AssignAllPermissions`.
  - **Black-box smoke check** — run the full `openhound preprocess` + `openhound convert` loop on the lab raw tree. The output is now **two payloads** (split, decision #8): MSSQL **nodes** land in the SCCM-tagged `sccm_*.json` files (`grep sccm_*.json` for `MSSQL_Server`/`MSSQL_Login`/`MSSQL_Database` etc.), pure-MSSQL/SCCM **edges** (`MSSQL_Contains`/`MSSQL_ControlServer`/`MSSQL_ControlDB`/`MSSQL_MemberOf`/`MSSQL_IsMappedTo` + db→site `SCCM_AssignAllPermissions`) also in `sccm_*.json`, and AD-touching MSSQL edges (`MSSQL_HostFor`/`MSSQL_ExecuteOnHost`/`MSSQL_HasLogin`/`MSSQL_GetTGS`/`MSSQL_ServiceAccountFor`/`MSSQL_GetAdminTGS`) in the untagged `ad_*.json` files. Spot-check a sysadmin computer's MSSQL chain (`Computer -HasLogin-> Login -MemberOf-> sysadmin -ControlServer-> Server` — note the first hop is in `ad_*`, the rest in `sccm_*`, resolved cross-file by id) and the db→site `SCCM_AssignAllPermissions`, against the live mayyhem.com lab.
- [ ] **Step 2:** Run the black-box smoke check yourself once (against the existing lab raw tree) and record actual observed counts in the doc.
- [ ] **Step 3: Green checkpoint** — Stage 5 complete.

---

## Self-Review (run after the plan is executed, before declaring the stage done)

1. **Spec coverage** — every node/edge in spec §3's Stage-5 rows (`MSSQL_Server`/`Database`/`ServerRole`/`DatabaseRole`/`Login`/`DatabaseUser` + `MSSQL_Contains`/`ControlServer`/`ControlDB`/`HostFor`/`ExecuteOnHost`/`HasLogin`/`IsMappedTo`/`MemberOf`/`ServiceAccountFor`/`GetAdminTGS`/`GetTGS` + db→site `SCCM_AssignAllPermissions`) maps to a task above. The decommissioned `Add-MSSQLNodesAndEdgesForPrimarySite` is correctly **not** ported.
2. **Casing** — every `MSSQL*Properties` field name matches CMBP verbatim (Phase B); DuckDB columns + model input fields stay snake_case.
3. **Type/name consistency** — `server_id`/`database_id`/`login_id`/`dbuser_id`/`role_id` are spelled identically across the node builders (Phases C–F), the edge builders (Phase G), and the models (Phase H). The edge endpoints equal the node ids the models emit.
4. **environmentid** — all 6 models derive it from `host_sid` via `domain_environment_id` (spec §2).
5. **Fold-in fixes** — members populated (F1/F2), real port for TGS (G3), non-SCCM servers kept (C2), `strictEncryption`/`instanceNames` present (B1/H1).

