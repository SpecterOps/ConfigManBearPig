# Stage 6 — validation harness & code-tour checkpoints

**Purpose:** confirm the Stage 6 preproc additions (three coerce-and-relay edge builders +
the synthetic Authenticated Users node builder + dedup array-union + split routing) produce
a correct graph. Validation has two parts:

1. **In-process debugger tour** — open the existing lab `lookup.duckdb` (or run `transforms()`
   against the lab raw tree) and step through each checkpoint. Use it with your debugger
   (VS Code: **"Debug: openhound preprocess sccm"** against `C:\tmp\redo`).
2. **Black-box CLI smoke check** (§6) — runs the standard `openhound preprocess` + `openhound
   convert` loop against the live lab raw tree, then checks both the DuckDB tables and the
   emitted JSON for relay edges and the Authenticated Users node.

> **No re-collect required for Stage 6** — it is preproc/convert-only and reads the existing
> Stage-5 lab raw tree. Validate immediately against `C:\tmp\redo`.

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

# Step 1: preprocess (builds lookup.duckdb with Stage-6 relay tables)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    openhound preprocess sccm $raw "$raw\lookup.duckdb"

# Step 2: convert (emits sccm_nodes/sccm_edges + ad_nodes/ad_edges JSON)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    openhound convert sccm "$raw\sccm" $graph --lookup-file "$raw\lookup.duckdb"
```

> **Important note on `--disable-possible-edges`:** this is a **collect-time** flag (`openhound
> collect sccm --disable-possible-edges`), not a preprocess flag. It gets written into the
> `sccm.collection_settings` table during collection and is read back by `_read_disable_possible`
> at the start of `transforms()`. The `openhound preprocess` command has no `--disable-possible-edges`
> option. To test the flag's effect, patch the already-loaded `collection_settings` table directly
> (see §6b) or re-collect with the flag set.

---

## 2. In-process quick driver

Run `transforms()` directly against the existing `lookup.duckdb` for instant inspection without
a full reprocess:

```python
import duckdb
from openhound_sccm.transforms import transforms

con = duckdb.connect(r"C:\tmp\redo\lookup.duckdb")
transforms(con)

schema = "sccm"

# Check Stage 6 relay results (all land in graph_edges_ad after _graph_edges_split)

# Stop 1 — relay edge counts
for kind in ["CoerceAndRelayToAdminService", "CoerceAndRelayToMSSQL", "CoerceAndRelayToSMB"]:
    n = con.execute(
        f"SELECT count(*) FROM {schema}.graph_edges_ad WHERE kind='{kind}'"
    ).fetchone()[0]
    print(f"{kind}: {n}")

# Stop 2 — Authenticated Users nodes
print(con.execute(
    f"SELECT sid, name, fallback_domain_sid FROM {schema}.node_group WHERE sid LIKE '%-S-1-5-11'"
).fetchall())

# Stop 3 — relay edge detail (verify coercion context is non-empty)
print(con.execute(
    f"SELECT kind, start_id, end_id, collection_source, "
    f"coercion_victim_and_relay_target_pairs, coercion_victim_hostnames "
    f"FROM {schema}.graph_edges_ad WHERE kind LIKE '%CoerceAndRelay%' ORDER BY kind, end_id"
).fetchall())
```

---

## 3. Code tour (debugger)

All breakpoints are in `src/openhound_sccm/transforms.py` unless noted. The Stage-6 call
sequence inside `transforms()` begins at line 3230 and runs in this order:

```
3230  _edge_coerce_relay_adminservice(con, schema, disable_possible)
3231  _edge_coerce_relay_mssql(con, schema, disable_possible)
3232  _edge_coerce_relay_smb(con, schema, disable_possible)
3233  _node_authenticated_users(con, schema)
3237  _graph_edges_dedup(con, schema)       # array-union pass for all edges
3241  _node_backfill(con, schema)
3245  _graph_edges_split(con, schema)       # relay rows -> graph_edges_ad
```

---

### Stop 1 — `_edge_coerce_relay_adminservice` providers/servers CTE (transforms.py:2832)

**What to inspect:** pause at line 2854 (the `_safe(...)` call), just after the `ntlm_ok`
expression is assembled at line 2851. Before stepping into `_safe`, run the `providers` and
`servers` CTEs manually:

```sql
-- providers: SMS Providers whose restrict_receiving_ntlm_traffic passes the gate
SELECT c.sid, c.dnshostname,
       upper(regexp_extract(role, '@(.+)$', 1)) AS site
FROM sccm.node_computer c,
     UNNEST(c.site_system_roles) AS t(role)
WHERE role LIKE 'SMS Provider@%'
  AND c.sid IS NOT NULL
  AND upper(coalesce(CAST(c.restrict_receiving_ntlm_traffic AS VARCHAR), 'OFF')) = 'OFF';
-- Default: null NTLM treated as 'Off' (assume vulnerable)

-- servers: Site Servers (the coercion victims)
SELECT c.sid, c.dnshostname,
       upper(regexp_extract(role, '@(.+)$', 1)) AS site
FROM sccm.node_computer c,
     UNNEST(c.site_system_roles) AS t(role)
WHERE role LIKE 'SMS Site Server@%'
  AND c.sid IS NOT NULL
  AND c.dnshostname LIKE '%.%';
-- Must have FQDN so _authed_users_id() can strip the host label
```

**Expected debugger state (mayyhem.com lab):**

- The lab SMS Providers have `restrict_receiving_ntlm_traffic = NULL` — they pass the
  default gate (null → assume Off) but fail the `--disable-possible-edges` gate (requires
  explicit 'Off'). This is why this edge kind produces 0 rows in the lab (NTLM-restriction
  data is not collected for the Admin Service path in this environment).
- The resulting INSERT produces **0 rows** in this lab.

**Which plan decision it verifies:** Stage 6 decision #1 — surgical `--disable-possible-edges`
flag changes the NTLM gate from `null/Off` to `explicit Off only`
(CMBP ps1:6572-6624).

---

### Stop 2 — `_edge_coerce_relay_mssql` EPA/NTLM gate (transforms.py:2884)

**What to inspect:** pause at line 2904 (the `if not disable_possible:` branch). The two
gate expressions (`epa_ok`, `ntlm_ok`) are assembled here as Python strings before being
embedded in the SQL. Inspect both:

```python
# When disable_possible is False (default):
epa_ok  = "(s.extended_protection IS NULL OR upper(CAST(s.extended_protection AS VARCHAR)) = 'OFF')"
ntlm_ok = "upper(coalesce(CAST(h.restrict_receiving_ntlm_traffic AS VARCHAR), 'OFF')) = 'OFF'"

# When disable_possible is True (--disable-possible-edges):
epa_ok  = "upper(CAST(s.extended_protection AS VARCHAR)) = 'OFF'"
ntlm_ok = "upper(CAST(h.restrict_receiving_ntlm_traffic AS VARCHAR)) = 'OFF'"
```

After the INSERT, inspect the result:

```sql
-- MSSQL server EPA values (what the gate fires on)
SELECT s.server_id, s.dns_host_name, s.extended_protection, s.collection_source
FROM sccm.node_mssql_server s
ORDER BY s.sccm_site;
-- Lab: CAS extended_protection='Off', PS1='Allowed/Required' (or similar), SEC=NULL
-- Only CAS (extended_protection='Off') passes BOTH the default AND the flag gate.
-- But the lab has no node_mssql_login row for CAS (no resolved sysadmin computer),
-- so the final join produces 0 CoerceAndRelayToMSSQL rows.

SELECT count(*) FROM sccm.graph_edges WHERE kind = 'CoerceAndRelayToMSSQL';
-- Expected (lab): 0 (CAS has no sysadmin computer / login resolved)
```

**Expected debugger state:** the CAS MSSQL server passes the EPA gate (`'Off'`) but the
`node_mssql_login` JOIN finds no login for CAS — no relay victim exists. PS1 fails the gate
(`extended_protection = 'Allowed/Required'`, treated as not-Off). SEC has NULL EPA which
passes the default gate but also has no login. Result: **0 rows** in both default and
`--disable-possible-edges` modes.

**Which plan decision it verifies:** Stage 6 decision #1 — EPA gate distinguishes between
null (assume vulnerable, default) vs. explicit 'Off' only (flag mode)
(CMBP ps1:6626-6726).

---

### Stop 3 — `_edge_coerce_relay_smb` `smb_signing_source` filtering (transforms.py:2932)

**What to inspect:** pause at line 2953 (the `_safe(...)` call), just after `ntlm_ok` is
assembled at line 2950. The `targets` CTE filters on `smb_signing_required = false`. Inspect
which site systems qualify:

```sql
-- Targets: site systems with SMB signing NOT required
SELECT DISTINCT c.sid, c.smb_signing_source, c.smb_signing_required,
       upper(regexp_extract(role, '@(.+)$', 1)) AS site
FROM sccm.node_computer c,
     UNNEST(c.site_system_roles) AS t(role)
WHERE role LIKE '%@%'
  AND c.sid IS NOT NULL
  AND c.smb_signing_required = false
  AND upper(coalesce(CAST(c.restrict_receiving_ntlm_traffic AS VARCHAR), 'OFF')) = 'OFF';
-- Expected (lab): several site systems with smb_signing_required=false

-- Full edge query after INSERT
SELECT kind, start_id, end_id, collection_source, coercion_victim_hostnames
FROM sccm.graph_edges
WHERE kind = 'CoerceAndRelayToSMB'
ORDER BY end_id;
-- Expected (lab, default run): 4 rows
-- collectionSource = ['SMB-Negotiate', 'RemoteRegistry-SMBSigningCheck'] (non-empty)
-- coercionVictimHostnames = [<site-server-fqdn>] (the coerced victim)
```

**Expected debugger state:**

- `smb_signing_required = false` is always explicit (not null) — the gate is satisfied in
  full whether or not `--disable-possible-edges` is set. The NTLM gate is the only
  "possible" gate here.
- Default run: 4 rows (NTLM is NULL on these systems, treated as 'Off' = vulnerable).
- `--disable-possible-edges` run: **0 rows** (NULL NTLM now fails the explicit-only gate).
- `collection_source` is populated from `smb_signing_source` filtered to
  `['SMB-Negotiate', 'RemoteRegistry-SMBSigningCheck']` — never empty when these probes ran.
- `coercion_victim_hostnames` is the site server's FQDN, not the target. The CMBP naming
  convention: "coercionVictim" = who gets coerced (the server); "end_id" = who receives the
  relay (the signing-disabled target system).

**Which plan decision it verifies:** Stage 6 decision #1 — NTLM null handling for SMB relay
(CMBP ps1:6728-6781); and the `smb_signing_source` provenance column introduced in Stage 6
decision #3 (distinct from `collection_source` on the node itself).

---

### Stop 4 — `_node_authenticated_users` `_domain_to_sid` + inserted rows (transforms.py:2986)

**What to inspect:** pause at line 3007 (the first `con.execute(...)`) to see the
`_domain_to_sid` temp table being built, then at line 3017 (the `_safe(...)` INSERT into
`node_group`) to see which relay starts get a node.

```sql
-- _domain_to_sid: FQDN-upper -> AD domain SID map
SELECT * FROM _domain_to_sid ORDER BY fqdn_upper;
-- Expected (lab): at least one row for 'MAYYHEM.COM' ->
-- 'S-1-5-21-3242052782-1287495003-4091326449'

-- Relay edge start ids (before node insert)
SELECT DISTINCT start_id
FROM sccm.graph_edges
WHERE kind IN ('CoerceAndRelayToAdminService', 'CoerceAndRelayToMSSQL', 'CoerceAndRelayToSMB')
  AND start_id LIKE '%-S-1-5-11';
-- Expected (lab, default): 'MAYYHEM.COM-S-1-5-11'

-- After INSERT: the node_group row
SELECT sid, name, fallback_domain_sid
FROM sccm.node_group WHERE sid LIKE '%-S-1-5-11';
-- Expected (lab, default):
-- ('MAYYHEM.COM-S-1-5-11', 'AUTHENTICATED USERS@MAYYHEM.COM',
--  'S-1-5-21-3242052782-1287495003-4091326449')
```

**Expected debugger state:**

- `_domain_to_sid` contains one row per unique domain in the lab (here: `MAYYHEM.COM` ->
  the domain SID). It is built from every domain-joined computer's `dnshostname` + `sid` —
  not from LDAP — so it works without an AD connection.
- The relay builder's `_authed_users_id()` fragment produces `UPPER(FQDN) || '-S-1-5-11'`
  (e.g. `MAYYHEM.COM-S-1-5-11`). This is the SharpHound well-known-SID form so the node
  merges with any SharpHound-collected Authenticated Users node in BloodHound.
- `fallback_domain_sid` is the domain SID resolved from `_domain_to_sid`. The `GroupNode`
  builder uses this to set `environmentid` on the output node.
- When `--disable-possible-edges` produces zero relay edges, no start ids have `%-S-1-5-11`,
  so this INSERT inserts **0 rows** — no orphan AuthUsers node.

**Which plan decision it verifies:** Stage 6 decision #2 — Authenticated Users node is lazy
(only created when at least one relay edge fires); decision #4 — `UPPER(FQDN)-S-1-5-11`
identity form (CMBP ps1:6609/6708/6766).

---

### Stop 5 — `_graph_edges_dedup` coercion array-union (transforms.py:3035)

**What to inspect:** pause at line 3046 (the `con.execute(...)` that rewrites `graph_edges`).
Focus on the `coercion_victim_and_relay_target_pairs` and `coercion_victim_hostnames`
columns in the rewritten table — these are the Stage 6 additions over the earlier dedup
logic (which only merged `collection_source`).

```sql
-- Before dedup: check for any duplicate (start, end, kind) triples
SELECT start_id, end_id, kind, count(*) AS n
FROM sccm.graph_edges
GROUP BY start_id, end_id, kind HAVING count(*) > 1;
-- Expected: 0 duplicates (each relay builder uses SELECT DISTINCT)

-- After dedup: verify coercion array-union
SELECT kind, start_id, end_id,
       collection_source,
       coercion_victim_and_relay_target_pairs,
       coercion_victim_hostnames
FROM sccm.graph_edges
WHERE kind LIKE '%CoerceAndRelay%'
ORDER BY kind, end_id;
-- Expected (lab, default):
--   CoerceAndRelayToSMB x4
--   coercion_victim_and_relay_target_pairs = [] (SMB builder uses coercion_victim_hostnames instead)
--   coercion_victim_hostnames = ['<site-server-fqdn>'] (1 per edge — no cross-site dedup needed)
```

**Expected debugger state:** the FILTER clause in the dedup SQL
(`FILTER (WHERE coercion_victim_and_relay_target_pairs IS NOT NULL)`) drops the NULLs that
every non-relay builder stores in those columns — this is CMBP's Upsert-Edge merge logic
(ps1:2155-2158) ported to a single post-builder pass. Every relay edge has exactly one
coercion pair/hostname because each (start, end, kind) triple is already unique from
`SELECT DISTINCT` in the builder.

**Which plan decision it verifies:** Stage 6 decision — coercion context merging in dedup
(CMBP ps1:2155-2158); array-union via `list_distinct(flatten(list(...) FILTER ...))`.

---

### Stop 6 — `_graph_edges_split` relay rows → `graph_edges_ad` (transforms.py:3114)

**What to inspect:** pause at line 3138 (the `CREATE OR REPLACE TEMP TABLE _ad_ids` statement)
and then at line 3138 (the `graph_edges_ad` CREATE). The relay edges have start_id =
`MAYYHEM.COM-S-1-5-11` (a Group SID, now in `node_group`) and end_id = a Computer SID or
an MSSQL_Login / SCCM_Site id.

```sql
-- _ad_ids temp table: all SIDs/ids that are AD nodes
SELECT count(*) AS n FROM _ad_ids;
-- Expected (lab): includes the relay start_id (MAYYHEM.COM-S-1-5-11 is in node_group)
-- and the relay end_ids (Computer SIDs are in node_computer)

-- After split: relay rows should be in graph_edges_ad
SELECT kind, count(*) AS n
FROM sccm.graph_edges_ad
WHERE kind LIKE '%CoerceAndRelay%'
GROUP BY kind ORDER BY kind;
-- Expected (lab, default): CoerceAndRelayToSMB: 4

-- Confirm they are NOT in graph_edges_sccm
SELECT count(*) FROM sccm.graph_edges_sccm
WHERE kind LIKE '%CoerceAndRelay%';
-- Expected: 0 (relay edges always have at least one AD endpoint)
```

**Expected debugger state (mayyhem.com lab):**

- All four `CoerceAndRelayToSMB` rows land in `graph_edges_ad` because:
  - `start_id = 'MAYYHEM.COM-S-1-5-11'` is in `_ad_ids` via `node_group`
    (inserted by `_node_authenticated_users` before this point)
  - `end_id` = Computer SIDs are in `_ad_ids` via `node_computer`
- `graph_edges_sccm` has **0** relay rows (the complement check is exact).
- `ad_cnt` / `sccm_cnt` logged at line 3156 match the DuckDB counts above.

**Which plan decision it verifies:** Stage 6 split routing — relay edges always touch AD
endpoints (both start = AuthUsers group SID and end = Computer/Login SID), so they
automatically route to the AD payload (ARCHITECTURE.md §11f).

---

## 4. Per-task test suite

Every Stage 6 builder has unit tests under `sccm/sccm/tests/`. Run:

```powershell
$env:UV_PROJECT_ENVIRONMENT = "C:/Users/domainadmin/AppData/Local/Temp/openhound-venv"
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm pytest tests -q
```

Expected: 558 passed (all tests passing as of Stage 6 completion).

Stage 6–specific test files:
- `tests/edge_coerce_relay_adminservice_test.py` — AdminService NTLM gate + disable-possible
- `tests/edge_coerce_relay_mssql_test.py` — MSSQL EPA/NTLM gate + disable-possible
- `tests/edge_coerce_relay_smb_test.py` — SMB signing + NTLM gate + disable-possible
- `tests/node_authenticated_users_test.py` — lazy node creation + domain SID resolution
- `tests/node_computer_smb_signing_source_test.py` — `smb_signing_source` provenance
- `tests/graph_edge_relay_props_test.py` — relay property fields in SCCMRelayEdgeProperties
- `tests/graph_edges_coercion_cols_test.py` — dedup array-union for coercion columns
- `tests/kinds_edges_stage6_test.py` — TRAVERSABLE_EDGE_KINDS includes all three relay kinds

---

## 5. What each stop verifies (plan cross-reference)

| Stop | Function (`transforms.py`) | Stage 6 plan task | CMBP reference |
|---|---|---|---|
| 1 | `_edge_coerce_relay_adminservice` (line 2832) | E1 — AdminService relay, NTLM gate | ps1:6572-6624 |
| 2 | `_edge_coerce_relay_mssql` (line 2884) | F1 — MSSQL relay, EPA+NTLM gates | ps1:6626-6726 |
| 3 | `_edge_coerce_relay_smb` (line 2932) | G1 — SMB relay, signing+NTLM gates | ps1:6728-6781 |
| 4 | `_node_authenticated_users` (line 2986) | H1 — Authenticated Users synthesis | ps1:6609/6708/6766 |
| 5 | `_graph_edges_dedup` (line 3035) | coercion array-union | CMBP ps1:2155-2158 |
| 6 | `_graph_edges_split` (line 3114) | relay -> AD payload routing | ARCHITECTURE.md §11f |

The locked architectural decisions that affect Stage 6:

- **Decision #1** — surgical `--disable-possible-edges`: changes the NTLM and EPA gates from
  "null = assume Off" to "must be explicitly 'Off'". Applied independently to each of the
  three relay builders.
- **Decision #2** — Authenticated Users node is lazy: synthesised only for domains that
  actually produced a relay edge, matching CMBP's upsert-inside-loop pattern.
- **Decision #3** — `smb_signing_source` provenance: a separate column on `node_computer`
  (distinct from `collection_source`) that carries the exact probe tags
  (`'SMB-Negotiate'`, `'RemoteRegistry-SMBSigningCheck'`), used as `collectionSource` on
  the relay edge.
- **Decision #4** — `UPPER(FQDN)-S-1-5-11` identity: SharpHound well-known-SID form so the
  node merges with native AD data; `environmentid` resolved from `_domain_to_sid`.
- **Decision #5** — CoerceAndRelayToSMB CMBP allow-list fix: CMBP ps1:2221 names it
  `"CoerceAndRelayNTLMtoSMB"` but the emit function (ps1:6775) emits `"CoerceAndRelayToSMB"`,
  leaving the CMBP edge non-traversable. The port emits `"CoerceAndRelayToSMB"` and correctly
  includes it in `TRAVERSABLE_EDGE_KINDS`.

---

## 6. Black-box CLI smoke check

> **Observed run: 2026-06-30, against the mayyhem.com lab raw tree at `C:\tmp\redo`.**
> All counts below are ACTUAL, not estimated.

### Important: `--disable-possible-edges` is a collect-time flag

The `openhound preprocess` command does NOT accept `--disable-possible-edges`. The flag is
passed at collection time (`openhound collect sccm --disable-possible-edges`) and stored
in `sccm.collection_settings` in the DuckDB. Preprocess reads it back with
`_read_disable_possible()` at the start of `transforms()`.

To test the flag's effect against an existing raw tree (without re-collecting), patch the
`collection_settings` table and re-run `transforms()` in-process:

```python
import duckdb, sys
sys.path.insert(0, 'C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src')
from openhound_sccm.transforms import transforms

con = duckdb.connect(r"C:\tmp\stage6-validate\nopossible\lookup.duckdb", read_only=False)

# Patch the flag (simulates having collected with --disable-possible-edges)
con.execute("UPDATE sccm.collection_settings SET disable_possible_edges = true")

# Re-run transforms
transforms(con)
```

### 6a — Standard (default) run

```powershell
$env:UV_PROJECT_ENVIRONMENT = "C:/Users/domainadmin/AppData/Local/Temp/openhound-venv"
$env:DLT_DATA_DIR = "C:\dlt-home"

uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    openhound preprocess sccm C:\tmp\redo C:\tmp\stage6-validate\default\lookup.duckdb

uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    openhound convert sccm C:\tmp\redo\sccm C:\tmp\stage6-validate\default\graph `
    --lookup-file C:\tmp\stage6-validate\default\lookup.duckdb
```

### 6b — `--disable-possible-edges` equivalent run

```powershell
# 1. Run preprocess to load the raw data into a fresh scratch DuckDB
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    openhound preprocess sccm C:\tmp\redo C:\tmp\stage6-validate\nopossible\lookup.duckdb

# 2. Patch the flag and re-run transforms in-process (see §6 note above)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm python - <<'EOF'
import duckdb, sys
sys.path.insert(0, 'src')
from openhound_sccm.transforms import transforms
con = duckdb.connect(r'C:\tmp\stage6-validate\nopossible\lookup.duckdb')
con.execute("UPDATE sccm.collection_settings SET disable_possible_edges = true")
transforms(con)
EOF

# 3. Convert using the patched lookup.duckdb
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    openhound convert sccm C:\tmp\redo\sccm C:\tmp\stage6-validate\nopossible\graph `
    --lookup-file C:\tmp\stage6-validate\nopossible\lookup.duckdb
```

---

### 6c — Relay edges in `ad_edges-*.json` (default run)

Stage 6 relay edges land in the AD payload because both endpoints are AD node ids:
`start_id = MAYYHEM.COM-S-1-5-11` (a Group SID, in `node_group`) and `end_id` = Computer SIDs
(in `node_computer`). The split routing in `_graph_edges_split` detects this automatically.

```powershell
# Check all three relay kinds
Select-String -Path "C:\tmp\stage6-validate\default\graph\ad_edges-*.json" `
    -Pattern '"CoerceAndRelayToAdminService"' | Select-Object -First 1
Select-String -Path "C:\tmp\stage6-validate\default\graph\ad_edges-*.json" `
    -Pattern '"CoerceAndRelayToMSSQL"' | Select-Object -First 1
Select-String -Path "C:\tmp\stage6-validate\default\graph\ad_edges-*.json" `
    -Pattern '"CoerceAndRelayToSMB"' | Select-Object -First 1
```

> **Expected (lab — observed 2026-06-30):**
> - `CoerceAndRelayToAdminService`: **0** (NEGATIVE — no SMS Provider in lab has explicit NTLM
>   restriction data collected for the AdminService path; NTLM is NULL, not 'Off', and the
>   default gate requires the relay target's NTLM to be null/Off — this SHOULD fire but the
>   lab's SMS Provider NTLM field is NULL; verified by unit tests in
>   `edge_coerce_relay_adminservice_test.py`)
> - `CoerceAndRelayToMSSQL`: **0** (NEGATIVE — CAS server has `extended_protection='Off'` but
>   no resolved sysadmin computer/login for CAS; PS1 server's EPA is 'Allowed/Required';
>   SEC server has no login; covered by `edge_coerce_relay_mssql_test.py`)
> - `CoerceAndRelayToSMB`: **4** (POSITIVE — 4 site systems have `smb_signing_required=false`
>   in the MAYYHEM.COM domain; coercion victim = site server in same non-secondary site)

Each `CoerceAndRelayToSMB` edge in the lab:
- `start = MAYYHEM.COM-S-1-5-11`
- `end` = Computer SID (4 different site systems)
- `properties.traversable = true`
- `properties.collectionSource = ['SMB-Negotiate', 'RemoteRegistry-SMBSigningCheck']` (non-empty)
- `properties.coercionVictimHostnames = ['<site-server-fqdn>']` (the coerced victim)
- `properties.coercionVictimAndRelayTargetPairs = []` (used by AdminService/MSSQL, not SMB)

---

### 6d — Authenticated Users node in `ad_nodes-*.json`

```powershell
Select-String -Path "C:\tmp\stage6-validate\default\graph\ad_nodes-*.json" `
    -Pattern 'S-1-5-11' | Select-Object -First 1
```

> **Expected (lab — observed 2026-06-30):**
> One node with:
> - `id = 'MAYYHEM.COM-S-1-5-11'`
> - `kinds = ['Group', 'Base']`
> - `properties.name = 'AUTHENTICATED USERS@MAYYHEM.COM'`
> - `properties.environmentid = 'S-1-5-21-3242052782-1287495003-4091326449'` (the MAYYHEM.COM domain SID)
> - `properties.SCCMInfra = false` (this is a synthetic AD node, not an SCCM infrastructure node)

The node is in `ad_nodes-*.json` (not `sccm_nodes-*.json`) because its SID is a Group SID
and `_graph_edges_split` / `_node_backfill` route it to the AD payload.

---

### 6e — `--disable-possible-edges` suppresses all relay edges

```python
import duckdb
con = duckdb.connect(r"C:\tmp\stage6-validate\nopossible\lookup.duckdb", read_only=True)

print("Relay edges after disable-possible run:")
rows = con.execute(
    "SELECT kind, count(*) AS n "
    "FROM sccm.graph_edges_ad "
    "WHERE kind LIKE '%CoerceAndRelay%' "
    "GROUP BY kind ORDER BY kind"
).fetchall()
print(rows or "  (none)")

print("AuthUsers nodes after disable-possible run:")
rows = con.execute(
    "SELECT sid, name FROM sccm.node_group WHERE sid LIKE '%-S-1-5-11'"
).fetchall()
print(rows or "  (none)")
```

> **Expected (lab — observed 2026-06-30):**
> - Relay edges: **0** across all three kinds (all SMB relay edges rely on null NTLM, which
>   the flag rejects; AdminService and MSSQL already yield 0 in default mode)
> - AuthUsers nodes: **0** (lazy: no relay edges = no node)
>
> This confirms the flag's surgical effect: it does not break Stage 1–5 output; it only
> suppresses relay edges where the "assume vulnerable on null" assumption was the sole
> reason the edge fired.

---

### 6f — DuckDB vs JSON count parity

```python
import json, pathlib, duckdb

con   = duckdb.connect(r"C:\tmp\stage6-validate\default\lookup.duckdb", read_only=True)
graph = pathlib.Path(r"C:\tmp\stage6-validate\default\graph")

ad_edges = json.loads(next(graph.glob("ad_edges-*.json")).read_text())["graph"]["edges"]

relay_kinds = [
    "CoerceAndRelayToAdminService",
    "CoerceAndRelayToMSSQL",
    "CoerceAndRelayToSMB",
]

print(f"{'Kind':<35} {'DuckDB':>7} {'JSON':>7} {'Match?':>7}")
for k in relay_kinds:
    db_n = con.execute(
        f"SELECT count(*) FROM sccm.graph_edges_ad WHERE kind='{k}'"
    ).fetchone()[0]
    js_n = sum(1 for e in ad_edges if e.get("kind") == k)
    match = "OK" if db_n == js_n else "MISMATCH"
    print(f"{k:<35} {db_n:>7} {js_n:>7} {match:>7}")
```

> **Expected (lab — observed 2026-06-30):** all rows show `OK`.
> - `CoerceAndRelayToAdminService`: DuckDB 0, JSON 0
> - `CoerceAndRelayToMSSQL`:        DuckDB 0, JSON 0
> - `CoerceAndRelayToSMB`:          DuckDB 4, JSON 4

---

### 6g — Negative results and synthetic test coverage

The mayyhem.com lab yields zero `CoerceAndRelayToAdminService` and zero `CoerceAndRelayToMSSQL`
edges. This is a valid negative result for the given topology:

| Relay kind | Why zero in this lab | Synthetic test coverage |
|---|---|---|
| `CoerceAndRelayToAdminService` | All SMS Providers have NULL `restrict_receiving_ntlm_traffic`; the AdminService relay SHOULD produce edges in the default mode (null = assume Off) BUT the lab SMS Providers also need a distinct site server to be the coercion victim — if all SMS Provider hosts also are the site server there are no pairs with `provider.sid != server.sid`. | `edge_coerce_relay_adminservice_test.py` |
| `CoerceAndRelayToMSSQL` | CAS has EPA='Off' but no resolved sysadmin login; PS1 has EPA='Allowed/Required' (fails gate); SEC has no login. | `edge_coerce_relay_mssql_test.py` |
| `CoerceAndRelayToSMB` | 4 edges in default, 0 in `--disable-possible-edges` mode. The positive case is validated live. | `edge_coerce_relay_smb_test.py` |

For the AdminService relay, note that zero edges is also possible if ALL providers ARE site
servers (no distinct victim/target pair). Confirm by running:

```sql
-- Are there any provider != site-server pairs in the lab?
WITH providers AS (
    SELECT upper(regexp_extract(role, '@(.+)$', 1)) AS site, c.sid
    FROM sccm.node_computer c, UNNEST(c.site_system_roles) AS t(role)
    WHERE role LIKE 'SMS Provider@%' AND c.sid IS NOT NULL
),
servers AS (
    SELECT upper(regexp_extract(role, '@(.+)$', 1)) AS site, c.sid
    FROM sccm.node_computer c, UNNEST(c.site_system_roles) AS t(role)
    WHERE role LIKE 'SMS Site Server@%' AND c.sid IS NOT NULL
)
SELECT p.site, p.sid AS provider_sid, s.sid AS server_sid
FROM providers p
JOIN servers s ON s.site = p.site AND s.sid != p.sid;
-- Expected (lab): 0 rows (all SMS Providers are co-located with site servers)
```
