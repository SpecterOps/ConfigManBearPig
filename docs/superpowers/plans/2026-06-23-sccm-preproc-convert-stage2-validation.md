# Stage 2 — validation harness & real-data results

**Purpose:** confirm the Stage 2 preproc→convert pipeline (4 SCCM-native entity nodes + ~12 inline edge kinds, possible-client nodes, gating, and the stub backfill) produces a correct graph. Unlike Stage 0/1's synthetic code-tours, Stage 2 was validated **against the live lab** (`mayyhem.com`, collected to `C:\tmp\redo`) in addition to the per-task synthetic TDD suite — real data is the stronger evidence and is what surfaced the `IsAssigned` JSON-shape bug below.

> **Re-collect prerequisite:** Stage 2 added two collect-side fields (`host_object_sid` on the RemoteRegistry current-user row; the `collection_settings` table). A collection taken *before* Stage 2 will not have them. Always re-collect before validating on real data. (This is the same re-collect that ope-a88e's `SMS_R_UserGroup` work required.)

---

## 1. How it was run (the three launch profiles)

The `.vscode/launch.json` profiles **Debug: openhound collect / preprocess / convert sccm** run the full pipeline against `C:\tmp\redo` (collect → `lookup.duckdb` → `graph/`). Equivalent CLI (note `DLT_DATA_DIR` keeps dlt's pipeline dir off the indexed `~/.dlt` — WinError 32, see ARCHITECTURE §8):

```bash
DLT_DATA_DIR='C:\dlt-home' python -m openhound collect    sccm /tmp/redo -vv      # picks up host_object_sid + collection_settings
DLT_DATA_DIR='C:\dlt-home' python -m openhound preprocess sccm /tmp/redo /tmp/redo/lookup.duckdb
DLT_DATA_DIR='C:\dlt-home' python -m openhound convert    sccm /tmp/redo /tmp/redo/graph --lookup-file /tmp/redo/lookup.duckdb
```

---

## 2. Real-data results (mayyhem.com, 2026-06-23)

### Coalesced node tables (`lookup.duckdb`, schema `sccm`)
| Table | Rows | Notes |
|---|---|---|
| `node_computer` | 39 | Stage 1 |
| `node_user` | 91 | Stage 1 |
| `node_group` | 21 | Stage 1 (SMS_R_UserGroup-resolved) |
| `node_site` | 3 | hierarchy `CAS` (CAS) → `PS1` (primary) → `SEC` (secondary under PS1); all `root_site_code=CAS` |
| `node_collection` | 10 | id `<collection_id>@CAS` |
| `node_security_role` | 17 | id `<role_id>@CAS` |
| `node_admin_user` | 3 | id `<logon_name>@CAS` (deduped from 4× site-replicated rows) |
| `node_client_device` | 31 | 18 real (smsid) + 13 possible (`object_sid@CAS`) |
| `node_backfill` | 0 | no nodeless edge endpoints (see §3) |

### Derived edges (`graph_edges`, after the `IsAssigned` fix)
| Kind | Count | Traversable |
|---|---|---|
| `SCCM_AdminsReplicatedTo` | 3 | yes |
| `SCCM_HasClient` | 31 | yes |
| `SCCM_HasMember` | 40 | no |
| `SCCM_IsMappedTo` | 3 | yes |
| `SCCM_IsAssigned` | 9 | no |
| `SCCM_HasPrimaryUser` | 1 | yes |
| `SCCM_HasCurrentUser` | 4 | yes |
| `SCCM_HasADLastLogonUser` | 13 | yes |
| `SCCM_HasStoredAccount` | 2 | no |
| `MemberOf` | 77 | (BloodHound-native) |
| `HasSession` | 9 | yes |

The 3 `SCCM_AdminsReplicatedTo` edges are `CAS↔PS1` (bidirectional, 2 edges) + `PS1→SEC` (one-way, 1 edge) — confirming the CMBP CAS↔Primary / Primary→Secondary type matrix on real data.

### Black-box check on the emitted OpenGraph (`graph/*.json`)
- **Node kinds:** `Base` 151 (= 39 Computer + 91 User + 21 Group), `Computer` 39, `User` 91, `Group` 21, `SCCM_Site` 3, `SCCM_Collection` 11, `SCCM_SecurityRole` 17, `SCCM_AdminUser` 3, `SCCM_ClientDevice` 31.
- **Edge kinds:** all 11 kinds above present with the same counts.
- **Spot-checks (PASS):**
  - `SCCM_IsAssigned`: `MAYYHEM\DOMAINADMIN@CAS → SMS0001R@CAS` (Full Administrator role) + collection scopes `SMS00001@CAS`/`SMS00004@CAS`; one edge each (deduped, not 4×).
  - `SCCM_IsMappedTo`: 3 edges from AD principal SIDs → `*@CAS` AdminUser ids.
  - Possible-clients: 13 `SCCM_ClientDevice` with `possible=true`, id `S-1-5-21-…@CAS`, `sccm_ad_domain_sid` = the raw computer SID, each with a `SCCM_HasClient` from the root site.

---

## 3. Findings the real-data run surfaced

1. **`SCCM_IsAssigned` JSON-shape bug (FIXED).** `adminservice_admins.collection_names` / `role_names` arrive as **JSON-array text** (`'["All Systems",...]'`), not comma strings. `_edge_is_assigned` originally used `string_split(…, ',')`, which shredded the JSON → 0 edges. Fixed to use the `_arr()` helper (handles JSON-text / comma / native list — a strict superset). Re-preprocess → `IsAssigned` 0 → 9. Locked by `tests/edge_is_assigned_test.py` (now seeds JSON-array-text inputs).
2. **Builtin-SID dangling concern — NOT triggered.** The whole-branch review flagged that a builtin group SID (`S-1-5-32-*`) reached by `MemberOf`/`HasMember` could have a `node_group` row yet be dropped by the model (no domain env) → dangling edge. On real data there are **zero** non-`S-1-5-21` SID endpoints (the only `…@CAS`-suffixed SID endpoints are the 13 possible-clients) and `node_backfill = 0`. SCCM's `security_group_name`/`user_group` data is domain-direct (omits builtins), as the design spec predicted. **Latent, not occurring** — left as-is; documented.

---

## 4. Synthetic per-task suite

Every Stage 2 builder has a TDD unit test under `sccm/sccm/tests/` (relocated from co-located `*_test.py`). Run:
```bash
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv \
  uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest tests -q
```
Result: **421 passed, 5 skipped.** (13 failures are pre-existing **stale** tests — `test_lookup_computer_site_system_roles.py` + `test_transforms_computer_roles.py` — for a removed lookup/transform design; red since before Stage 2, unrelated.)

---

## 5. Code tour (debugger)

Run the **"Debug: Stage 2 code tour"** launch profile (`tour_driver_stage2.py`). It seeds a small cross-referenced dataset (topology `CAS → PS1 → SEC`, a computer that is also the SQL host + client device, a user, a group, a collection + members, a role, an admin with JSON-array-text assignments, a reserved account, a `site_systems` SQL row, a RemoteRegistry current-user row, a CmRcService device, and `collection_settings`) and runs the full preproc→convert in-process. It emits all 4 entity-node kinds (+ a possible-client) and every Stage 2 edge kind (verified: `IsAssigned` 2, both `HasSession` arms, `AdminsReplicatedTo` 3 = `CAS↔PS1` + `PS1→SEC`), with `node_backfill` empty (self-consistent seed) — so it exercises every builder.

Breakpoints, in execution order (`transforms.py` unless noted): each `_node_*` collapse → the four lookups (`_resource_to_sid`/`_device_by_resourceid`/`_collection_by_name`/`_role_by_name`) → `_edge_has_client` → `_edge_has_member` (device-vs-user resolution) → `_edge_is_mapped_to` → `_edge_is_assigned` (the `_arr` JSON parse + the `len(_arr(roles))=0` name-fallback gate) → `_edge_has_user` / `_edge_member_of` / `_edge_has_session` (the MSSQL domain-account gate) → `_node_client_device_possible` (deterministic id, disable gate) → `_graph_edges_dedup` → `_node_backfill`. Then `GraphEdge.edges` (traversable set) in the convert pipeline.
