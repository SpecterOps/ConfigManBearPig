# Stage 5 — validation harness & code-tour checkpoints

**Purpose:** confirm the Stage 5 preproc→convert additions (MSSQL node builders + 4 edge builders)
produce a correct graph. Validation has two parts:

1. **In-process debugger tour** — open the existing lab `lookup.duckdb` (or run `transforms()`
   against the lab raw tree) and step through each checkpoint. Use it with your debugger
   (VS Code: **"Debug: openhound preprocess sccm"** against `C:\tmp\redo`).
2. **Black-box CLI smoke check** (§6) — runs the standard `openhound preprocess` + `openhound
   convert` loop against the live lab raw tree and checks the two split-output JSON files for
   MSSQL nodes and edges.

> **No re-collect required for Stage 5** — it is preproc/convert-only and reads the existing
> Stage-4 lab raw tree. Validate immediately against `C:\tmp\redo`.

---

## 1. How to run (the standard launch profiles)

The `.vscode/launch.json` profiles **Debug: openhound preprocess / convert sccm** run against
`C:\tmp\redo`. Equivalent CLI:

```powershell
# Windows PowerShell; adjust paths as needed
$raw   = "C:\tmp\redo"
$graph = "C:\tmp\redo\graph"
$env:DLT_DATA_DIR = "C:\dlt-home"
$env:UV_PROJECT_ENVIRONMENT = "C:/Users/domainadmin/AppData/Local/Temp/openhound-venv"

# Step 1: preprocess (builds lookup.duckdb with Stage-5 MSSQL tables)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    python -m openhound preprocess sccm $raw "$raw\lookup.duckdb"

# Step 2: convert (emits sccm_nodes/sccm_edges + ad_nodes/ad_edges JSON)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    python -m openhound convert sccm $raw $graph --lookup-file "$raw\lookup.duckdb"
```

---

## 2. In-process quick driver

Run `transforms()` directly against the existing `lookup.duckdb` for instant inspection without
a full reprocess:

```python
import duckdb
from openhound_sccm.transforms import transforms

con = duckdb.connect(r"C:\tmp\redo\lookup.duckdb")
transforms(con)

# Check Stage 5 results (schema = "sccm")
schema = "sccm"

# Stop 1 — SCCM SQL host resolution
print(con.execute(f"SELECT * FROM {schema}._mssql_sql_servers").fetchall())

# Stop 2 — server merge
print(con.execute(f"SELECT server_id, sccm_site, sccm_infra, extended_protection FROM {schema}.node_mssql_server").fetchall())

# Stop 3 — logins and db-users
print(con.execute(f"SELECT login_id, login_name, server_id FROM {schema}.node_mssql_login").fetchall())

# Stop 4 — role members populated
print(con.execute(f"SELECT role_id, members FROM {schema}.node_mssql_server_role").fetchall())
print(con.execute(f"SELECT role_id, members FROM {schema}.node_mssql_database_role").fetchall())

# Stop 5 — edge inventory
for kind in ["MSSQL_Contains", "MSSQL_ControlServer", "MSSQL_ControlDB",
             "MSSQL_HostFor", "MSSQL_ExecuteOnHost", "MSSQL_HasLogin",
             "MSSQL_IsMappedTo", "MSSQL_MemberOf", "MSSQL_GetTGS",
             "MSSQL_ServiceAccountFor", "MSSQL_GetAdminTGS", "SCCM_AssignAllPermissions"]:
    n = con.execute(f"SELECT count(*) FROM {schema}.graph_edges WHERE kind='{kind}'").fetchone()[0]
    print(f"{kind}: {n}")
```

---

## 3. Code tour (debugger)

All breakpoints are in `src/openhound_sccm/transforms.py` unless noted. The Stage-5 call
sequence inside `transforms()` begins at line 2962 and runs in this order:

```
2963  _mssql_sql_servers(con, schema)
2964  _node_mssql_server(con, schema)
2965  _node_mssql_database(con, schema)
2966  _node_mssql_login(con, schema)
2967  _node_mssql_database_user(con, schema)
2968  _node_mssql_server_role(con, schema)
2969  _node_mssql_database_role(con, schema)
...
2990  _edge_mssql_structural(con, schema)
2991  _edge_mssql_membership(con, schema)
2992  _edge_mssql_service_account(con, schema)
2993  _edge_mssql_db_assign_all(con, schema)
```

---

### Stop 1 — `_mssql_sql_servers` end (transforms.py:2016)

**What to inspect:** the `_mssql_sql_servers` staging table immediately after the final INSERT +
count log (line 2016). This table is the anchor for every downstream MSSQL node — one row per
`(site_code, host_sid)` pair.

**Expected debugger state:**

- One row per `(site, SQL-host)` — not one-per-site. In the mayyhem.com lab this is 3 rows:
  `(SEC, ps1-sec…)`, `(CAS, cas-db…)`, `(PS1, ps1-db…)`.
- `db_name` is set from `node_site.sql_database_name`. If that column was NULL the fallback
  `'CM_' || site_code` fires. In the lab the SEC site database has an unusual name
  (`CONFIGMGRSEC\CM_SEC`) — verify it was picked up from `node_site`, not from the fallback.
- `port` is `'1433'` for all three (no non-standard port in the lab); the coalesce default at
  line 2008 fills any NULL from `node_site.sql_service_port`.
- Non-SCCM SQL servers found only by EPA scan or registry do NOT appear here — they feed
  `node_mssql_server` directly via Arms 2/3.

**Inspection query:**

```sql
SELECT site_code, root_site_code, host_sid, dns_host_name, port, db_name
FROM sccm._mssql_sql_servers
ORDER BY site_code;
-- Expected (lab): 3 rows: CAS, PS1, SEC
```

**Which plan task it verifies:** Stage 5 Task A1 (`_mssql_sql_servers`; CMBP ps1:6082, locked
decision #1 — multiple-site-DB-per-site + fallback db_name).

---

### Stop 2 — `_node_mssql_server` collapse (transforms.py:2097)

**What to inspect:** `node_mssql_server` after the final `CREATE OR REPLACE` rewrite (line 2082)
that collapses three INSERTs into one row per `upper(host_sid):port`. Focus on:

1. Exactly one row per server — the SQL host SID is the natural key.
2. SCCM-linked servers have `sccm_infra = true` and a non-NULL `sccm_site`; servers found only
   by EPA scan or registry have `sccm_infra = false` and `sccm_site = NULL`.
3. When an EPA-scan row and an SCCM row share the same `host_sid:port`, the merge picks
   SCCM-sourced properties first (any_value skips NULL) and supplements EPA properties
   (`extended_protection`, `force_encryption`, `strict_encryption`).

**Expected debugger state (mayyhem.com lab):**

- 3 rows, all `sccm_infra = true`, all `sccm_site` non-NULL (CAS / PS1 / SEC).
- CAS server: `extended_protection = 'Off'`, `force_encryption = False`.
- PS1 server: `extended_protection = 'Allowed/Required'`, `strict_encryption = True`
  (EPA scan label ambiguous — the "Allowed/Required" value is the collected-as-is string, per
  the EPA uncertainty memory note).
- SEC server: `extended_protection = NULL`, `force_encryption = NULL` (no EPA scan data for that
  host; registry also absent — only SCCM arm contributed).
- `collection_source` on merged rows is a de-duped union of all contributing source tags.

**Inspection query:**

```sql
SELECT server_id, sccm_site, sccm_infra, databases,
       extended_protection, force_encryption, strict_encryption,
       collection_source
FROM sccm.node_mssql_server
ORDER BY sccm_site;
-- Expected: 3 rows; PS1 row has EPA values; SEC row has NULLs for EPA columns

-- Confirm no two rows share the same host_sid:port key
SELECT host_sid, port, count(*) AS n
FROM sccm.node_mssql_server
GROUP BY host_sid, port HAVING count(*) > 1;
-- Expected: 0 rows
```

**Which plan task it verifies:** Stage 5 Task A2 (`_node_mssql_server` merge; CMBP ps1:6088;
locked decisions #1, #3 fold-ins — non-SCCM capture + EPA properties; locked decision #4 —
`sccm_infra` flag).

---

### Stop 3 — `_node_mssql_login` / `_node_mssql_database_user` (transforms.py:2149 / 2171)

**What to inspect:** `node_mssql_login` after the CREATE AS SELECT (line 2130), then
`node_mssql_database_user` after its CREATE AS SELECT (line 2161).

**Expected debugger state:**

- **Login identity:** `login_id` = `<NETBIOS>\<sam>@<server_id>` where `<NETBIOS>` is
  `upper(split_part(dnshostname, '.', 2))` — the second DNS label of the sysadmin computer's
  own hostname, not the SQL host's domain. In the mayyhem.com lab the sysadmin computer is
  `PS1-PSS` (a Primary Site Server for PS1) with `dnshostname = 'ps1-pss.mayyhem.com'`, so
  `NETBIOS = 'MAYYHEM'` and the login is `MAYYHEM\PS1-PSS$@<ps1_server_id>`.
- **The SQL host itself is excluded** — the JOIN in `_node_mssql_login` requires
  `c.sid != upper(s.host_sid)`, so the SQL host computer is never its own sysadmin login
  (CMBP ps1:1912-1920; locked decision #2).
- **Only Site Servers and SMS Providers** for the same site as the SQL host get logins. In the
  lab the CAS and SEC SQL hosts have no resolving sysadmin computers with full DNS hostnames, so
  only the PS1 server produces a login.
- **DatabaseUser** `dbuser_id` = `<login_name>@<database_id>` — the cross-join of each login
  with each database on the same server.

**Inspection queries:**

```sql
-- Logins
SELECT login_id, login_name, server_id, sysadmin_computer_sid
FROM sccm.node_mssql_login;
-- Expected (lab): 1 row for MAYYHEM\PS1-PSS$ -> PS1 server

-- Verify the SQL host is NOT its own login (the builder enforces c.sid != upper(s.host_sid),
-- so no login row should have its sysadmin_computer_sid equal to the server's host_sid).
SELECT count(*) AS self_logins
FROM sccm.node_mssql_login
WHERE sysadmin_computer_sid = host_sid;
-- Expected: 0

-- Database users
SELECT dbuser_id, login_name, database_id
FROM sccm.node_mssql_database_user;
-- Expected (lab): 1 row: MAYYHEM\PS1-PSS$ mapped into CM_PS1
```

**Which plan task it verifies:** Stage 5 Task B1/B2 (`_node_mssql_login` / `_node_mssql_database_user`;
CMBP ps1:6232 / ps1:6247; locked decision #2 — NETBIOS from own DNS domain).

---

### Stop 4 — `_node_mssql_server_role` / `_node_mssql_database_role` (transforms.py:2192 / 2212)

**What to inspect:** `node_mssql_server_role` and `node_mssql_database_role` immediately after
their CREATE AS SELECTs. Focus on whether the `members` array is populated.

**Expected debugger state:**

- **Server role** `sysadmin` — one row per SCCM-linked server (only `sccm_infra = true` servers;
  non-SCCM scan-only servers are excluded by the `WHERE s.sccm_infra` predicate at line 2190).
- **`members` populated** — the sub-select at line 2186 pulls `login_id`s for each server.
  In the lab: the PS1 `sysadmin` role has `members = ['MAYYHEM\\PS1-PSS$@<ps1_server_id>']`;
  the CAS and SEC `sysadmin` roles have `members = []` (no resolved sysadmin computers for those
  sites). This is the **scope-bug fix** over CMBP (ps1:6105 used an out-of-scope variable,
  always emitting an empty list).
- **Database role** `db_owner` — one per MSSQL_Database; `members` array populated from
  `node_mssql_database_user` via sub-select at line 2206. In the lab: the PS1 db_owner role has
  `members = ['MAYYHEM\\PS1-PSS$@<ps1_db_id>']`; CAS and SEC db_owner roles have `members = []`.

**Inspection queries:**

```sql
-- Server role members
SELECT role_id, server_id, members
FROM sccm.node_mssql_server_role
ORDER BY server_id;
-- Expected: 3 rows; PS1 role has non-empty members array; CAS/SEC have []

-- Confirm no sysadmin role for non-SCCM-linked (sccm_infra=false) servers
SELECT count(*) FROM sccm.node_mssql_server_role r
JOIN sccm.node_mssql_server s ON r.server_id = s.server_id
WHERE NOT s.sccm_infra;
-- Expected: 0

-- Database role members
SELECT role_id, database_id, members
FROM sccm.node_mssql_database_role
ORDER BY database_id;
-- Expected: 3 rows; PS1 db has non-empty members array
```

**Which plan task it verifies:** Stage 5 Task B3/B4 (`_node_mssql_server_role` /
`_node_mssql_database_role`; CMBP ps1:6101/ps1:6151; locked decision #3 fold-in —
populate `members`, fixing CMBP's empty-array scope bug).

---

### Stop 5 — the four edge builders (transforms.py:2701, 2739, 2772, 2805)

**What to inspect:** `graph_edges` rows for each MSSQL kind after all four builders run.
Step through `_edge_mssql_structural` (line 2689), `_edge_mssql_membership` (line 2729),
`_edge_mssql_service_account` (line 2755), and `_edge_mssql_db_assign_all` (line 2794).

#### 5a — `_edge_mssql_structural` (transforms.py:2689)

Covers the 7 structural edge kinds (edges #1–7 from the plan inventory):

| # | Kind | Direction |
|---|---|---|
| 1 | `MSSQL_Contains` | Server → sysadmin role |
| 2 | `MSSQL_ControlServer` | sysadmin role → Server |
| 3 | `MSSQL_HostFor` | host Computer → Server |
| 4 | `MSSQL_ExecuteOnHost` | Server → host Computer |
| 5 | `MSSQL_Contains` | Server → Database |
| 6 | `MSSQL_Contains` | Database → db_owner role |
| 7 | `MSSQL_ControlDB` | db_owner role → Database |

**Expected state (lab):** 3 servers, one sysadmin role each → 3 `MSSQL_Contains` (server→role) + 3
`MSSQL_ControlServer` (the `UNION ALL` emits one Contains + one ControlServer per server); 3 servers each host-linked → 3 `MSSQL_HostFor` + 3 `MSSQL_ExecuteOnHost`;
3 databases → 3 `MSSQL_Contains` (server→db) + 3 `MSSQL_Contains` (db→db_owner-role) + 3
`MSSQL_ControlDB`. Total `MSSQL_Contains` = 3+3+3 = 9 (before membership adds more).

#### 5b — `_edge_mssql_membership` (transforms.py:2729)

Covers edges #9–14 (login + db-user membership):

| # | Kind | Direction |
|---|---|---|
| 9 | `MSSQL_MemberOf` | Login → sysadmin role |
| 10 | `MSSQL_Contains` | Server → Login |
| 11 | `MSSQL_HasLogin` | sysadmin Computer → Login |
| 12 | `MSSQL_IsMappedTo` | Login → DatabaseUser |
| 13 | `MSSQL_MemberOf` | DatabaseUser → db_owner role |
| 14 | `MSSQL_Contains` | Database → DatabaseUser |

**Expected state (lab):** 1 login → 1 `MSSQL_MemberOf` (login→role) + 1 `MSSQL_Contains`
(server→login) + 1 `MSSQL_HasLogin`; 1 db-user → 1 `MSSQL_IsMappedTo` + 1 `MSSQL_MemberOf`
(dbuser→db-owner-role) + 1 `MSSQL_Contains` (db→dbuser). After this builder:
total `MSSQL_Contains` = 9 + 2 = 11.

#### 5c — `_edge_mssql_service_account` (transforms.py:2755)

Covers edges #15a–15c:

| # | Kind | Gate |
|---|---|---|
| 15a | `MSSQL_GetTGS` | service acct → each login on server; acct must resolve to `node_computer`/`node_user` |
| 15b | `MSSQL_ServiceAccountFor` | service acct → server; acct must resolve AND differ from host |
| 15c | `MSSQL_GetAdminTGS` | service acct → server; same gate as 15b |

**Expected state (lab):**

- The service account SID (`S-1-5-21-…-1116`, `mayyhem\sqlsccmsvc`) resolves as a `node_user`.
- The account differs from the SQL host for both CAS and PS1 servers → 2 `MSSQL_ServiceAccountFor`
  + 2 `MSSQL_GetAdminTGS`.
- The GetTGS fires once per login × server: 1 login on PS1 → 1 `MSSQL_GetTGS`.
- **Port correctness:** all service-account edges reference `server_id` (host_sid:port), NOT a
  hardcoded `:1433`. This is the fold-in fix (locked decision #3; CMBP ps1:8011 TODO).
- No edges for SEC server (service_account_domain_sid is NULL for that site in this lab).

**Inspection query:**

```sql
-- Service-account edges with endpoint detail
SELECT start_id, end_id, kind
FROM sccm.graph_edges
WHERE kind IN ('MSSQL_GetTGS', 'MSSQL_ServiceAccountFor', 'MSSQL_GetAdminTGS')
ORDER BY kind, end_id;
-- Expected: 5 rows total (1 GetTGS, 2 ServiceAccountFor, 2 GetAdminTGS)

-- Confirm no edge where service acct SID == host SID
SELECT ge.start_id, ge.end_id, ge.kind, s.host_sid
FROM sccm.graph_edges ge
JOIN sccm.node_mssql_server s ON ge.end_id = s.server_id
WHERE ge.kind IN ('MSSQL_ServiceAccountFor','MSSQL_GetAdminTGS')
  AND ge.start_id = s.host_sid;
-- Expected: 0 rows (acct != host gate is enforced)
```

#### 5d — `_edge_mssql_db_assign_all` (transforms.py:2794)

**Expected state (lab):**

- One `SCCM_AssignAllPermissions` edge for each `(MSSQL_Database, non-secondary site)` pair.
  In the lab: 3 databases × N non-secondary sites. The non-secondary set excludes SEC (site_type=1).
- The 14 total `SCCM_AssignAllPermissions` in the lab include both db→site edges (from this
  builder) and site→site assignment edges (from the earlier `_edge_assign_all_permissions`
  builder). Filter `start_id LIKE '%CM_%'` to isolate the MSSQL contributions.

**Inspection query:**

```sql
-- MSSQL db -> site AssignAllPermissions
SELECT start_id, end_id, kind, collection_source
FROM sccm.graph_edges
WHERE kind = 'SCCM_AssignAllPermissions'
  AND start_id NOT IN (SELECT site_code FROM sccm.site_hierarchy)
ORDER BY start_id, end_id;
-- Expected: 3 databases × (non-secondary site count) rows
-- collection_source = ['SCCM_Add-MSSQLServerNodesAndEdges'] for these rows
```

**Overall edge count verification:**

```sql
SELECT kind, count(*) AS n
FROM sccm.graph_edges
WHERE kind LIKE 'MSSQL%' OR kind = 'SCCM_AssignAllPermissions'
GROUP BY kind ORDER BY kind;
-- Expected (lab, per observed run 2026-06-30):
--   MSSQL_Contains:          11
--   MSSQL_ControlDB:          3
--   MSSQL_ControlServer:      3
--   MSSQL_ExecuteOnHost:      3
--   MSSQL_GetAdminTGS:        2
--   MSSQL_GetTGS:             1
--   MSSQL_HasLogin:           1
--   MSSQL_HostFor:            3
--   MSSQL_IsMappedTo:         1
--   MSSQL_MemberOf:           2
--   MSSQL_ServiceAccountFor:  2
--   SCCM_AssignAllPermissions: 14  (6 MSSQL-db-origin + 8 existing site-to-site)
```

**Which plan tasks it verifies:** Stage 5 Tasks C1–C4 (4 edge builders; CMBP ps1:6111-6180,
ps1:6262-6286, ps1:1975, ps1:8013-8016; locked decision #3 fold-ins).

---

## 4. Per-task test suite

Every Stage 5 builder has unit tests under `sccm/sccm/tests/`. Run:

```powershell
$env:UV_PROJECT_ENVIRONMENT = "C:/Users/domainadmin/AppData/Local/Temp/openhound-venv"
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm pytest tests -q
```

Expected: 0 failed (all tests passing as of Stage 5 completion).

---

## 5. What each stop verifies (plan cross-reference)

| Stop | Function (`transforms.py`) | Stage 5 plan task | CMBP reference |
|---|---|---|---|
| 1 | `_mssql_sql_servers` (line 1971) | A1 — SCCM SQL-host resolution | ps1:6082 |
| 2 | `_node_mssql_server` (line 2020) | A2 — server merge (3 arms + collapse) | ps1:6088 |
| 3 | `_node_mssql_login` / `_node_mssql_database_user` (lines 2122 / 2153) | B1/B2 — login + db-user identity | ps1:6232 / ps1:6247 |
| 4 | `_node_mssql_server_role` / `_node_mssql_database_role` (lines 2175 / 2196) | B3/B4 — fixed roles with populated members | ps1:6101 / ps1:6151 |
| 5 | `_edge_mssql_structural` (2689) · `_edge_mssql_membership` (2729) · `_edge_mssql_service_account` (2755) · `_edge_mssql_db_assign_all` (2794) | C1–C4 — all 15 edge kinds | ps1:6111-6180, ps1:6262-6286, ps1:1975/8013-8016, ps1:6173-6180 |

The locked architectural decisions that affect Stage 5:

- **Decision #1** — MSSQL_Server is a merge, not site-anchored; non-SCCM SQL servers still
  produce a bare `MSSQL_Server` + host edges (ARCHITECTURE.md §11e).
- **Decision #3 fold-ins** — real SQL port in service-account edges; `members` populated in
  fixed roles; non-SCCM capture.
- **Decision #7** — service-account edges resolve-or-drop via `EXISTS` guard against
  `node_computer`/`node_user`.
- **Decision #8** — MSSQL nodes → `SCCM_NODE_SPECS`; edges auto-routed by `_graph_edges_split`
  (no new spec entries needed).

---

## 6. Black-box CLI smoke check

> **Observed run: 2026-06-30, against the mayyhem.com lab raw tree at `C:\tmp\redo`.**
> All counts below are ACTUAL, not estimated.

Run against the lab raw tree (no re-collect needed):

```powershell
$raw   = "C:\tmp\redo"
$graph = "C:\tmp\redo\graph"
$env:DLT_DATA_DIR = "C:\dlt-home"
$env:UV_PROJECT_ENVIRONMENT = "C:/Users/domainadmin/AppData/Local/Temp/openhound-venv"

uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    python -m openhound preprocess sccm $raw "$raw\lookup.duckdb"

uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    python -m openhound convert sccm $raw $graph --lookup-file "$raw\lookup.duckdb"
```

### 6a — MSSQL nodes are present in `sccm_nodes-*.json`

Stage 5 MSSQL nodes land in the SCCM-tagged payload (locked decision #8: MSSQL nodes →
`SCCM_NODE_SPECS` at `main.py:1273-1278`).

```powershell
Select-String -Path "$graph\sccm_nodes-*.json" -Pattern '"MSSQL_Server"'       | Select-Object -First 1
Select-String -Path "$graph\sccm_nodes-*.json" -Pattern '"MSSQL_Database"'     | Select-Object -First 1
Select-String -Path "$graph\sccm_nodes-*.json" -Pattern '"MSSQL_ServerRole"'   | Select-Object -First 1
Select-String -Path "$graph\sccm_nodes-*.json" -Pattern '"MSSQL_DatabaseRole"' | Select-Object -First 1
Select-String -Path "$graph\sccm_nodes-*.json" -Pattern '"MSSQL_Login"'        | Select-Object -First 1
Select-String -Path "$graph\sccm_nodes-*.json" -Pattern '"MSSQL_DatabaseUser"' | Select-Object -First 1
```

> **Expected (lab — observed 2026-06-30):** each grep hits at least one line.
> Confirmed node-kind counts: `MSSQL_Server: 3`, `MSSQL_Database: 3`, `MSSQL_ServerRole: 3`,
> `MSSQL_DatabaseRole: 3`, `MSSQL_Login: 1`, `MSSQL_DatabaseUser: 1`.

### 6b — Pure-MSSQL edges are in `sccm_edges-*.json`

The pure-MSSQL/SCCM edges (`MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`,
`MSSQL_IsMappedTo`, `MSSQL_MemberOf` + db→site `SCCM_AssignAllPermissions`) route to the SCCM
payload because both endpoints are MSSQL or SCCM node ids — neither is an AD node id.

```powershell
Select-String -Path "$graph\sccm_edges-*.json" -Pattern '"MSSQL_Contains"'     | Select-Object -First 1
Select-String -Path "$graph\sccm_edges-*.json" -Pattern '"MSSQL_ControlServer"'| Select-Object -First 1
Select-String -Path "$graph\sccm_edges-*.json" -Pattern '"MSSQL_ControlDB"'    | Select-Object -First 1
Select-String -Path "$graph\sccm_edges-*.json" -Pattern '"MSSQL_IsMappedTo"'   | Select-Object -First 1
Select-String -Path "$graph\sccm_edges-*.json" -Pattern '"MSSQL_MemberOf"'     | Select-Object -First 1
```

> **Expected (lab — observed 2026-06-30):**
> `MSSQL_Contains: 11`, `MSSQL_ControlServer: 3`, `MSSQL_ControlDB: 3`,
> `MSSQL_IsMappedTo: 1`, `MSSQL_MemberOf: 2` in `sccm_edges-*.json`.
> `SCCM_AssignAllPermissions: 6` (db-origin rows only) also in `sccm_edges-*.json`.

### 6c — AD-touching MSSQL edges are in `ad_edges-*.json`

Edges with a Computer SID or user SID endpoint (`MSSQL_HostFor`, `MSSQL_ExecuteOnHost`,
`MSSQL_HasLogin`, `MSSQL_GetTGS`, `MSSQL_ServiceAccountFor`, `MSSQL_GetAdminTGS`) route to the
AD payload because `_graph_edges_split` detects that one endpoint is an AD node id.

```powershell
Select-String -Path "$graph\ad_edges-*.json" -Pattern '"MSSQL_HostFor"'          | Select-Object -First 1
Select-String -Path "$graph\ad_edges-*.json" -Pattern '"MSSQL_ExecuteOnHost"'    | Select-Object -First 1
Select-String -Path "$graph\ad_edges-*.json" -Pattern '"MSSQL_HasLogin"'         | Select-Object -First 1
Select-String -Path "$graph\ad_edges-*.json" -Pattern '"MSSQL_GetTGS"'           | Select-Object -First 1
Select-String -Path "$graph\ad_edges-*.json" -Pattern '"MSSQL_ServiceAccountFor"'| Select-Object -First 1
Select-String -Path "$graph\ad_edges-*.json" -Pattern '"MSSQL_GetAdminTGS"'      | Select-Object -First 1
```

> **Expected (lab — observed 2026-06-30):**
> `MSSQL_HostFor: 3`, `MSSQL_ExecuteOnHost: 3`, `MSSQL_HasLogin: 1`, `MSSQL_GetTGS: 1`,
> `MSSQL_ServiceAccountFor: 2`, `MSSQL_GetAdminTGS: 2` all in `ad_edges-*.json`.

### 6d — Full-chain sysadmin path traversal

Verify the complete sysadmin computer → login → role → server chain. The first hop
(`Computer -HasLogin-> Login`) crosses payloads: `MSSQL_HasLogin` is in `ad_edges-*.json`;
the rest (`Login -MemberOf-> sysadmin -ControlServer-> Server`) are in `sccm_edges-*.json`.
Cross-file resolution works because both file sets are uploaded together and node ids are shared.

```python
import json, pathlib

graph = pathlib.Path(r"C:\tmp\redo\graph")

def load_edges(path):
    data = json.loads(path.read_text())
    return data["graph"]["edges"]

ad_edges   = load_edges(next(graph.glob("ad_edges-*.json")))
sccm_edges = load_edges(next(graph.glob("sccm_edges-*.json")))

# Find the MSSQL_HasLogin edge (Computer -> Login) in ad_edges
has_login = [e for e in ad_edges if e["kind"] == "MSSQL_HasLogin"]
print("MSSQL_HasLogin (ad_edges):", has_login)

# Follow Login -> sysadmin role (MemberOf, in sccm_edges)
for hl in has_login:
    login_id = hl["end"]
    member_of = [e for e in sccm_edges
                 if e["kind"] == "MSSQL_MemberOf" and e["start"] == login_id]
    print(f"  Login {login_id} -MemberOf->:", [e["end"] for e in member_of])
    for mo in member_of:
        role_id = mo["end"]
        controls = [e for e in sccm_edges
                    if e["kind"] == "MSSQL_ControlServer" and e["start"] == role_id]
        print(f"  Role {role_id} -ControlServer->:", [e["end"] for e in controls])
```

> **Expected (lab):** one chain: `PS1-PSS$ SID` → `MAYYHEM\PS1-PSS$@<server_id>` →
> `sysadmin@<server_id>` → `<server_id>` (PS1 SQL server).

### 6e — DuckDB vs JSON count parity

```python
import json, pathlib, duckdb

con = duckdb.connect(r"C:\tmp\redo\lookup.duckdb", read_only=True)
graph = pathlib.Path(r"C:\tmp\redo\graph")

sccm_edges = json.loads(next(graph.glob("sccm_edges-*.json")).read_text())["graph"]["edges"]
ad_edges   = json.loads(next(graph.glob("ad_edges-*.json")).read_text())["graph"]["edges"]
all_edges  = sccm_edges + ad_edges

mssql_kinds = [
    "MSSQL_Contains", "MSSQL_ControlServer", "MSSQL_ControlDB",
    "MSSQL_HostFor", "MSSQL_ExecuteOnHost", "MSSQL_HasLogin",
    "MSSQL_IsMappedTo", "MSSQL_MemberOf", "MSSQL_GetTGS",
    "MSSQL_ServiceAccountFor", "MSSQL_GetAdminTGS",
]

print(f"{'Kind':<28} {'DuckDB':>7} {'JSON':>7} {'Match?':>7}")
for k in mssql_kinds:
    db_n  = con.execute(f"SELECT count(*) FROM sccm.graph_edges WHERE kind='{k}'").fetchone()[0]
    js_n  = sum(1 for e in all_edges if e["kind"] == k)
    match = "OK" if db_n == js_n else "MISMATCH"
    print(f"{k:<28} {db_n:>7} {js_n:>7} {match:>7}")
```

> **Expected (lab — observed 2026-06-30):** all rows show `OK`; DuckDB and JSON counts match for
> every MSSQL kind.

### 6f — `members` scope-bug fix verified in output JSON

```python
import json, pathlib

sccm_nodes = json.loads(
    next(pathlib.Path(r"C:\tmp\redo\graph").glob("sccm_nodes-*.json")).read_text()
)["graph"]["nodes"]

roles = [n for n in sccm_nodes if "MSSQL_ServerRole" in n.get("kinds", [])]
print("MSSQL_ServerRole nodes and their members:")
for r in roles:
    print(f"  id={r['id']}  members={r['properties'].get('members', [])}")

# Verify at least one role has a non-empty members list
non_empty = [r for r in roles if r["properties"].get("members")]
assert len(non_empty) >= 1, "No sysadmin role has any members — scope-bug fix not working"
print(f"\n{len(non_empty)} role(s) with non-empty members (scope-bug fix confirmed).")
```

> **Expected (lab):** the PS1 `sysadmin` role has `members = ['MAYYHEM\\PS1-PSS$@…']`; CAS and
> SEC have `members = []` (no resolving sysadmin computers for those sites in this lab run).
> The assert passes.
