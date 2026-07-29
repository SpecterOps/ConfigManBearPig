# Stage 3 — validation harness & real-data results

**Purpose:** confirm the Stage 3 preproc→convert pipeline (10 Stage-3 edges, `collection_source` on every edge, and full node-property parity for the 8 existing node kinds) produces a correct graph. Validation has two parts:

1. **In-process debugger tour** (`tour_driver_stage3.py`) — seeds a synthetic CAS→PS1→SEC hierarchy with enough cross-referenced data to exercise every Stage-3 builder, runs `transforms(con)` and `emit_graph_from_duckdb` in-process, and prints tabular results. Use it with your debugger (VS Code: **"Debug: Stage 3 code tour"**).
2. **Black-box CLI smoke check** (§6) — runs the standard `openhound preprocess` + `openhound convert` loop against the live lab raw tree (`C:\tmp\redo`) and greps the output JSON for confirming conditions.

> **No re-collect required for Stage 3** — it is preproc/convert-only and reads the existing Stage-2 lab raw tree. Validate immediately against `C:\tmp\redo`.

---

## 1. How it was run (the three launch profiles)

The `.vscode/launch.json` profiles **Debug: openhound preprocess / convert sccm** run against `C:\tmp\redo`. Equivalent CLI:

```bash
# DLT_DATA_DIR keeps dlt's pipeline dir off the indexed ~/.dlt (WinError 32, see ARCHITECTURE §8)
DLT_DATA_DIR='C:\dlt-home' python -m openhound preprocess sccm /tmp/redo /tmp/redo/lookup.duckdb
DLT_DATA_DIR='C:\dlt-home' python -m openhound convert    sccm /tmp/redo /tmp/redo/graph --lookup-file /tmp/redo/lookup.duckdb
```

---

## 2. Synthetic driver results (2026-06-24)

Run:
```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv \
  uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm \
  python tour_driver_stage3.py
```

### Node enrichment tables

| Table | Key result verified |
|---|---|
| `node_collection.members` | Raw `ResourceID@Site` keys present incl. built-in `2046820352@PS1`; `source_site_code`, `last_change_time` populated |
| `node_security_role.members` | `['MAYYHEM\SCCMADMIN@CAS']` for SMS0001R |
| `node_admin_user` | `collection_ids=['SMS00001@CAS', 'SMS00004@CAS']`; `role_ids=['SMS0001R']`; `member_of=['SMS0001R@CAS']` |
| `node_client_device` | All three `*_sid` fields → `S-1-5-21-1-2-3-1106`; `ad_last_logon_time`/`source_site_code` populated; `collection_ids=['PS100016@CAS', 'SMS00001@CAS']` |
| `node_site` | `admin_users=['MAYYHEM\SCCMADMIN@CAS']` on all 3 sites; `stored_accounts=['S-1-5-21-1-2-3-1500']` on PS1 only |
| `node_computer.distinguished_name` | `'CN=SQL01,OU=Servers,DC=MAYYHEM,DC=COM'` from smb_computers; `site_system_roles` includes `SMS Provider` |

### Stage-3 edge counts (graph_edges after dedup)

| Kind | Count | Notes |
|---|---|---|
| `SCCM_Contains` | 10 | CAS + PS1 (non-secondary) × 5 objects; SEC (secondary) contains nothing |
| `SCCM_FullAdministrator` | 1 | `MAYYHEM\SCCMADMIN@CAS → GUID-1` |
| `SCCM_AllPermissions` | 2 | sccmadmin → CAS + PS1 (not SEC) |
| `SCCM_AssignAllPermissions` | 2 | SQL01 (SMS Provider) → CAS + PS1 |
| Other Stage-1/2 kinds | 17 | all carry non-empty `collection_source` |

### collection_source coverage

`Total edges: 33 | Empty collection_source: 0` → **PASS**

### convert output

`TOUR OUTPUT: ['sccm_edges-1.json', 'sccm_nodes-1.json']` — no errors; node_backfill = 0.

---

## 3. Findings the real-data run will surface (to be filled in after lab run)

*(Placeholder — update after running the §6 smoke check against `C:\tmp\redo`.)*

---

## 4. Synthetic per-task test suite

Every Stage 3 builder has a TDD unit test under `sccm/sccm/tests/`. Run:
```bash
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv \
  uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest tests -q
```

---

## 5. Code tour (debugger)

Run the **"Debug: Stage 3 code tour"** launch profile (`tour_driver_stage3.py`). It seeds a CAS→PS1→SEC hierarchy with a Full Administrator admin, two built-in global collections (SMS00001 + SMS00004), a custom Device collection, a real client device (SQL01/GUID-1), alice as primary/current/ad-last-logon user, a stored reserved account, an SMS Provider computer, and a possible-client device (WS09). The driver runs the full preproc→convert in-process and emits all 4 Stage-3 edge kinds plus every node-property enrichment.

### Breakpoints in execution order

All breakpoints are in `src/openhound_sccm/transforms.py` unless noted.

---

#### Stop 1 — `_enrich_collection_members` (line 1238)

**What to inspect:** `_cmembers` temp table after the INSERT from `adminservice_collection_members`.

**Expected debugger state:**
- `SMS00001` has two member keys: `5@PS1` (the real client resource) and `2046820352@PS1` (the built-in pseudo-resource). Both appear in `node_collection.members` — the enrichment is raw/faithful and does NOT filter out built-ins or unresolved keys.
- `SMS00004` has `9@PS1` (alice).
- `PS100016` has `5@PS1`.

**Which plan detail it verifies:** Decision #6 (relationship-list properties are raw/faithful from source tables, not edge→node aggregation); CMBP ps1:7605.

---

#### Stop 2 — `_enrich_role_members` (line 1258)

**What to inspect:** `_rmembers` temp table and then `node_security_role.members`.

**Expected debugger state:**
- Arm 1 (roles id list, `'roles': '["SMS0001R"]'`): inserts `(SMS0001R, MAYYHEM\SCCMADMIN@CAS)`. The `@CAS` suffix comes from `_root_code`.
- Arm 2 (role_names fallback): skipped because `len(_arr(a.roles)) != 0` for this admin.
- Final `node_security_role.members` for SMS0001R: `['MAYYHEM\SCCMADMIN@CAS']`.

**Which plan detail it verifies:** CMBP ps1:7854/7880; arm-2 fallback guard (`len=0`).

---

#### Stop 3 — `_enrich_admin_assignments` (line 1295)

**What to inspect:** `_aassign` temp table (three kinds: `role_id`, `member_of`, `collection_id`) and then `node_admin_user.collection_ids / role_ids / member_of`.

**Expected debugger state:**
- `role_id` arm: `(MAYYHEM\SCCMADMIN, 'role_id', 'SMS0001R')`.
- `member_of` id arm: `(MAYYHEM\SCCMADMIN, 'member_of', 'SMS0001R@CAS')`.
- `member_of` name fallback: skipped (roles list is non-empty).
- `collection_id` arm: two rows — `SMS00001@CAS`, `SMS00004@CAS` — resolved from the JSON-array-text `collection_names` via `_arr()` + `collection_by_name`.

**Which plan detail it verifies:** CMBP ps1:7775/7783/7848; the `_arr()` JSON-array-text parse for `collection_names`.

---

#### Stop 4 — `_enrich_client_device` (line 1353)

**What to inspect:** `_devcoll` temp table and then `node_client_device` with the new columns.

**Expected debugger state:**
- `_devcoll` for `5@PS1` (SQL01's resource key): two rows — `SMS00001@CAS`/`All Systems` and `PS100016@CAS`/`Custom Devices`.
- `node_client_device.primary_user_sid` = `S-1-5-21-1-2-3-1106` (alice's SID, resolved via `principal_by_name` lookup on `MAYYHEM\alice`).
- Same SID for `current_logon_user_sid` and `ad_last_logon_user_sid` (all three fields point to alice).
- `ad_last_logon_time` = `2026-06-01 08:00:00`; `source_site_code` = `PS1`.
- `collection_ids` = `['PS100016@CAS', 'SMS00001@CAS']`; `collection_names` = `['Custom Devices', 'All Systems']`.

**Which plan detail it verifies:** CMBP ps1:7227-7248 (SID resolution); ps1:7228-7229 (collection lists); C4 telemetry scalars (`ad_last_logon_time`, `source_site_code`); Decision #6 (raw from source, not graph_edges).

---

#### Stop 5 — `_enrich_site_lists` (line 1399)

**What to inspect:** `_alladmins` and `_stored` temp tables, then `node_site.admin_users` and `node_site.stored_accounts`.

**Expected debugger state:**
- `_alladmins`: one row — `MAYYHEM\SCCMADMIN@CAS`. Every site (CAS, PS1, SEC) gets this list.
- `_stored`: one row — `(PS1, S-1-5-21-1-2-3-1500)`. Only PS1 gets `stored_accounts = ['S-1-5-21-1-2-3-1500']`; CAS and SEC get `[]`.
- `admin_users` subquery has no site_code filter — all admins go to every site (single-hierarchy rule).

**Which plan detail it verifies:** CMBP ps1:1724 (admin_users list); ps1:7141 (stored_accounts per site).

---

#### Stop 6 — `_edge_contains` (line 2089)

**What to inspect:** the three UNION ALL arms and the non-secondary site filter.

**Expected debugger state:**
- `nonsec` subquery returns `CAS` (type=4) and `PS1` (type=2); `SEC` (type=1) is excluded.
- Three arms produce 5 object endpoints per non-secondary site = 10 edges total:
  - Collections: `PS100016@CAS`, `SMS00001@CAS`, `SMS00004@CAS`
  - Roles: `SMS0001R@CAS`
  - Admin users: `MAYYHEM\SCCMADMIN@CAS`
- All edges carry `collection_source = ['SCCM_Invoke-PostProcessing']`.

**Which plan detail it verifies:** CMBP ps1:1659-1690; the SEC-exclusion gate (`site_type != 1`).

---

#### Stop 7 — `_edge_rbac_role_grants` (line 2110)

**What to inspect:** the four-join chain and `_ROLE_EDGE_KIND` lookup.

**Expected debugger state:**
- `ia_role` row: `MAYYHEM\SCCMADMIN@CAS → SMS0001R@CAS` (SCCM_IsAssigned).
- `sr` join resolves `SMS0001R` → Full Administrator; `rk` maps it to edge kind `SCCM_FullAdministrator`.
- `ia_coll` rows from the same admin: three IsAssigned edges; only the two with Device collections (`collection_type=2`) pass the `nc.collection_type = 2` gate — `SMS00001@CAS` and `PS100016@CAS` both qualify.
- `hm` (HasMember) for `SMS00001@CAS` → `GUID-1`; for `PS100016@CAS` → `GUID-1`.
- `cd` join confirms `GUID-1` is a real client device.
- After dedup: one `SCCM_FullAdministrator` edge: `MAYYHEM\SCCMADMIN@CAS → GUID-1`.
- Custom-role audit returns 0 (no non-built-in roles assigned).

**Which plan detail it verifies:** CMBP ps1:1714-1827; Decision #1 (reconstruct from graph_edges, not raw tables); the `collection_type=2` Device-collection gate; the custom-role diagnostic.

---

#### Stop 8 — `_edge_all_permissions` (line 2150)

**What to inspect:** the double-IsAssigned join requiring BOTH SMS00001 and SMS00004.

**Expected debugger state:**
- `ia_role` join + `sr` join: admin has SMS0001R (`Full Administrator`).
- `ia_as` + `c_as` join: admin is assigned `SMS00001@CAS` (All Systems, collection_id upper = `SMS00001`).
- `ia_au` + `c_au` join: admin is also assigned `SMS00004@CAS` (All Users and User Groups, `SMS00004`).
- CROSS JOIN `nonsec`: CAS and PS1 (not SEC).
- Result: 2 `SCCM_AllPermissions` edges (`MAYYHEM\SCCMADMIN@CAS → CAS`, `→ PS1`).

**Which plan detail it verifies:** CMBP ps1:1730-1837; Decision #2 (well-known collection ID detection, not display name); both-collection requirement.

---

#### Stop 9 — `_edge_assign_all_permissions` (line 2175)

**What to inspect:** the `list_filter` on `site_system_roles` for `SMS Provider`.

**Expected debugger state:**
- `node_computer` for SQL01 (`S-1-5-21-1-2-3-1200`) has `site_system_roles = ['SMS SQL Server', 'SMS Provider', 'SMS Provider@PS1', 'SMS SQL Server@PS1']` (union of roles from adminservice_r_system and adminservice_site_definitions_computers).
- `list_filter(..., x -> x LIKE '%SMS Provider%')` matches `'SMS Provider'` and `'SMS Provider@PS1'` — `len > 0` is true.
- CROSS JOIN `nonsec`: CAS + PS1.
- Result: 2 `SCCM_AssignAllPermissions` edges (`S-1-5-21-1-2-3-1200 → CAS`, `→ PS1`).
- WS09 (`S-1-5-21-1-2-3-1300`) has empty `site_system_roles` → no edges.

**Which plan detail it verifies:** CMBP ps1:1932-1940; the `LIKE '%SMS Provider%'` substring match; the SEC-exclusion gate.

---

#### Stop 10 — `_graph_edges_dedup` (line 2195)

**What to inspect:** `collection_source` array-union across duplicate rows.

**Expected debugger state:**
- Before dedup: `SCCM_FullAdministrator` from `SCCM_Invoke-PostProcessing` may appear twice if both `SMS00001` and `PS100016` collections fan out to the same client device (same start→end→kind triple).
- After dedup: one row with `collection_source = ['SCCM_Invoke-PostProcessing']` (list_distinct collapses the duplicate literal).
- Total edges before → after: count reduces to 33 (the distinct set).
- `node_backfill = 0`: all endpoints exist in a node table.

**Which plan detail it verifies:** Stage-3 Decision — `collection_source` array-union; CMBP's Upsert-Edge dedup semantics.

---

#### Stop 11 — `GraphEdge.edges` (models/graph_edge.py, line 51)

**What to inspect:** the `collection_source` field flowing through to `SCCMEdgeProperties`.

**Expected debugger state:**
- `self.collection_source` = `['SCCM_Invoke-PostProcessing']` for a `SCCM_FullAdministrator` row.
- `self.kind in TRAVERSABLE_EDGE_KINDS` = `True` for `SCCM_FullAdministrator`.
- The emitted `Edge.properties` = `SCCMEdgeProperties(traversable=True, collection_source=['SCCM_Invoke-PostProcessing'])`.
- For `SCCM_HasMember` (not traversable): `traversable=False`, `collection_source=['AdminService-SMS_FullCollectionMembership']` (Stage-1/2 retrofit).

**Which plan detail it verifies:** Task A1 (GraphEdge carries collection_source); Task A2 (Stage-1/2 retrofit).

---

## 6. Black-box CLI smoke check

Run against the lab raw tree (no re-collect needed). Adjust `<raw>` to your path:

```powershell
# Windows PowerShell; adjust paths as needed
$raw  = "C:\tmp\redo"
$graph = "C:\tmp\redo\graph"
$env:DLT_DATA_DIR = "C:\dlt-home"

# Step 1: preprocess (builds lookup.duckdb with Stage-3 tables)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    python -m openhound preprocess sccm $raw "$raw\lookup.duckdb"

# Step 2: convert (emits graph/*.json)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    python -m openhound convert sccm $raw $graph --lookup-file "$raw\lookup.duckdb"
```

### Confirming greps on `<graph>/*.json`

Run these after the convert completes. Replace `<graph>` with `C:\tmp\redo\graph`.

#### 6a — The 10 Stage-3 edge kinds are present

```powershell
# Each grep should print at least one matching line
Select-String -Path "$graph\*.json" -Pattern '"kind": "SCCM_Contains"'          | Select-Object -First 1
Select-String -Path "$graph\*.json" -Pattern '"kind": "SCCM_FullAdministrator"' | Select-Object -First 1
Select-String -Path "$graph\*.json" -Pattern '"kind": "SCCM_AllPermissions"'    | Select-Object -First 1
Select-String -Path "$graph\*.json" -Pattern '"kind": "SCCM_AssignAllPermissions"' | Select-Object -First 1
```

Or in one pass — confirm all 10 kinds appear:
```powershell
$stage3 = @("SCCM_Contains","SCCM_FullAdministrator","SCCM_ApplicationAuthor",
             "SCCM_ApplicationAdministrator","SCCM_ComplianceSettingsManager",
             "SCCM_OSDManager","SCCM_OperationsAdministrator",
             "SCCM_SecurityAdministrator","SCCM_AllPermissions","SCCM_AssignAllPermissions")
foreach ($k in $stage3) {
    $hits = (Select-String -Path "$graph\*.json" -Pattern "`"kind`": `"$k`"").Count
    Write-Host "$k : $hits edge(s)"
}
```
> **Expected:** SCCM_Contains, SCCM_FullAdministrator (or another RBAC role if the lab admin has a different role), SCCM_AllPermissions, and SCCM_AssignAllPermissions all have ≥ 1 hit. The other 6 RBAC role kinds appear only if the lab has admins with those roles assigned.

#### 6b — Every edge has a non-empty `collection_source`

```powershell
# Count edges with empty collection_source: should be 0
$edgeFile = Get-ChildItem "$graph\*edges*.json" | Select-Object -First 1
$empty = (Get-Content $edgeFile | ConvertFrom-Json).edges |
    Where-Object { $_.properties.collection_source.Count -eq 0 }
Write-Host "Edges with empty collection_source: $($empty.Count)"
```
> **Expected:** 0.

#### 6c — A known Full Administrator reaches devices

```powershell
# Confirm the lab admin (MAYYHEM\DOMAINADMIN or similar) appears as start_id
Select-String -Path "$graph\*.json" -Pattern '"kind": "SCCM_FullAdministrator"'
```
> **Expected:** the lab Full Administrator account → real client device smsid(s).

#### 6d — SMS00001 and SMS00004 are the real All Systems / All Users IDs

```powershell
# Check lookup.duckdb directly for the collection names
$con = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$raw\lookup.duckdb")
# Alternative: inspect via DuckDB CLI or Python
python -c "
import duckdb
con = duckdb.connect(r'C:\tmp\redo\lookup.duckdb', read_only=True)
print(con.execute(\"SELECT collection_id, name FROM sccm.node_collection WHERE upper(collection_id) IN ('SMS00001','SMS00004')\").fetchall())
"
```
> **Expected:** `[('SMS00001', 'All Systems'), ('SMS00004', 'All Users and User Groups')]` (confirming the well-known IDs match the lab built-in collections).

#### 6e — New node properties populate

```powershell
python -c "
import duckdb
con = duckdb.connect(r'C:\tmp\redo\lookup.duckdb', read_only=True)
# node_collection.members (first collection)
r = con.execute('SELECT collection_id, members FROM sccm.node_collection LIMIT 1').fetchone()
print('collection.members:', r)
# node_security_role.members (Full Administrator)
r = con.execute(\"SELECT role_id, members FROM sccm.node_security_role WHERE role_id='SMS0001R'\").fetchone()
print('security_role.members:', r)
# node_admin_user enrichment (first admin)
r = con.execute('SELECT logon_name, collection_ids, role_ids, member_of FROM sccm.node_admin_user LIMIT 1').fetchone()
print('admin_user:', r)
# node_client_device *_sid (first real device)
r = con.execute('SELECT smsid, primary_user_sid, collection_ids FROM sccm.node_client_device WHERE possible=false LIMIT 1').fetchone()
print('client_device:', r)
# node_site admin_users (CAS)
r = con.execute(\"SELECT site_code, admin_users, stored_accounts FROM sccm.node_site WHERE site_code='CAS'\").fetchone()
print('site CAS:', r)
# node_computer distinguished_name (any SCCM infra computer)
r = con.execute('SELECT sid, distinguished_name FROM sccm.node_computer WHERE sccm_infra=true AND distinguished_name IS NOT NULL LIMIT 1').fetchone()
print('computer.distinguished_name:', r)
"
```
> **Expected:** non-empty lists for members/collection_ids/role_ids/member_of; non-NULL distinguished_name for at least one computer; non-empty admin_users on CAS.

#### 6f — C4 `ad_last_logon_time` column-name check (deferred from C0/C4)

```powershell
python -c "
import duckdb
con = duckdb.connect(r'C:\tmp\redo\lookup.duckdb', read_only=True)
# Confirm the column is named ad_last_logon_time (not a_d_last_logon_time)
cols = [r[0] for r in con.execute('PRAGMA table_info(sccm.node_client_device)').fetchall()]
print('ad_last_logon_time in columns:', 'ad_last_logon_time' in cols)
print('a_d_last_logon_time (bad snake-case) in columns:', 'a_d_last_logon_time' in cols)
"
```
> **Expected:** `ad_last_logon_time in columns: True` / `a_d_last_logon_time in columns: False`.
