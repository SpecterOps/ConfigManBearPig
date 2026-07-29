# Stage 4 — validation harness & code-tour checkpoints

**Purpose:** confirm the Stage 4 preproc→convert additions (`_dedup_client_device`, `_edge_same_host`, `_edge_local_admin_required`, and the real-client `ad_domain_sid` resolution in `_enrich_client_device`) produce a correct graph. Validation has two parts:

1. **In-process debugger tour** — open the existing lab `lookup.duckdb` (or run `transforms()` against the lab raw tree) and step through each checkpoint. Use it with your debugger (VS Code: **"Debug: openhound preprocess sccm"** against `C:\tmp\redo`).
2. **Black-box CLI smoke check** (§6) — runs the standard `openhound preprocess` + `openhound convert` loop against the live lab raw tree and greps the output JSON for confirming conditions.

> **No re-collect required for Stage 4** — it is preproc/convert-only and reads the existing Stage-3 lab raw tree. Validate immediately against `C:\tmp\redo`.

---

## 1. How to run (the standard launch profiles)

The `.vscode/launch.json` profiles **Debug: openhound preprocess / convert sccm** run against `C:\tmp\redo`. Equivalent CLI:

```bash
# DLT_DATA_DIR keeps dlt's pipeline dir off the indexed ~/.dlt (WinError 32, see ARCHITECTURE §8)
DLT_DATA_DIR='C:\dlt-home' python -m openhound preprocess sccm /tmp/redo /tmp/redo/lookup.duckdb
DLT_DATA_DIR='C:\dlt-home' python -m openhound convert    sccm /tmp/redo /tmp/redo/graph --lookup-file /tmp/redo/lookup.duckdb
```

Or via the isolated uv env:

```powershell
$env:UV_PROJECT_ENVIRONMENT = "C:/Users/domainadmin/AppData/Local/Temp/openhound-venv"
uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm `
    python -m openhound preprocess sccm C:\tmp\redo C:\tmp\redo\lookup.duckdb
uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm `
    python -m openhound convert sccm C:\tmp\redo C:\tmp\redo\graph `
    --lookup-file C:\tmp\redo\lookup.duckdb
```

---

## 2. In-process quick driver

Run `transforms()` directly against the existing `lookup.duckdb` for instant inspection without a full reprocess:

```python
import duckdb
from openhound_sccm.transforms import transforms

con = duckdb.connect(r"C:\tmp\redo\lookup.duckdb")
transforms(con)

# Check Stage 4 results
print(con.execute("SELECT count(*) FROM sccm.node_client_device").fetchone())
print(con.execute("SELECT * FROM sccm.graph_edges WHERE kind='SameHostAs' LIMIT 5").fetchall())
print(con.execute("SELECT * FROM sccm.graph_edges WHERE kind='LocalAdminRequired' LIMIT 5").fetchall())
```

---

## 3. Code tour (debugger)

All breakpoints are in `src/openhound_sccm/transforms.py` unless noted.

---

### Stop 1 — `_enrich_client_device` final rebuild (line 1509)

**What to inspect:** `node_client_device` immediately after the `CREATE OR REPLACE TABLE` at line 1509, focusing on the `ad_domain_sid` column.

**Expected debugger state:**

- A known real client (e.g. `SQL01`, `is_confirmed_active_client = True`) now has a non-NULL `ad_domain_sid` — the AD computer SID resolved from `SMS_R_System` via the `_dev_sid` temp table.
- The inferred possible-client (e.g. `WS09`, `is_confirmed_active_client = False`) retains its `ad_domain_sid` as set at inferred-client insert time (`upper(object_sid)` from the LDAP CmRcService SPN) — unchanged by the `coalesce(d.ad_domain_sid, ...)` because it was already non-NULL.
- Real clients whose `SMS_R_System` SID was NULL or missing still have `ad_domain_sid = NULL`; they will not produce a `SameHostAs` edge (matches CMBP).

**Inspection query:**

```sql
SELECT smsid, name, is_confirmed_active_client, ad_domain_sid
FROM sccm.node_client_device
ORDER BY is_confirmed_active_client DESC;
```

**Which plan task it verifies:** Stage 4 Task C1 (real-client `ad_domain_sid` from `SMS_R_System`; CMBP ps1:7388-7392).

---

### Stop 2 — `_dedup_client_device` (line 1531)

**What to inspect:** the `before` and `after` row counts logged, and `node_client_device` after the dedup rewrite.

**Expected debugger state:**

- `before` = count before dedup (e.g. `N` rows including any real+inferred twin pairs).
- `after` = count after dedup (e.g. `N - k` where `k` is the number of inferred twins merged into their real counterpart).
- A machine that is both a confirmed real client (SMSID-keyed) and an inferred CmRcService-SPN target (SID@root-keyed) with the same `ad_domain_sid` now has **exactly one row** — the real client survivor, with `is_confirmed_active_client = True`.
- Inferred-client rows with no matching real client (unique `ad_domain_sid`) are preserved unchanged.
- Real clients with `ad_domain_sid = NULL` are preserved (their partition key isolates each by `smsid`).

**Inspection query:**

```sql
-- Count before vs after (compare to the logged values)
SELECT count(*) FROM sccm.node_client_device;

-- Confirm no inferred twin survives if a real twin exists for the same SID
SELECT ad_domain_sid, count(*), bool_or(is_confirmed_active_client) AS has_real
FROM sccm.node_client_device
WHERE ad_domain_sid IS NOT NULL
GROUP BY ad_domain_sid
HAVING count(*) > 1;
-- Expected: 0 rows (no shared ad_domain_sid after dedup)
```

**Which plan task it verifies:** Stage 4 Task C2 (dedup before edges; CMBP ps1:2269-2311; ARCHITECTURE §11d locked decision — dedup before `_graph_edges_init`).

---

### Stop 3 — `_edge_same_host` (line 2377)

**What to inspect:** `graph_edges` rows with `kind = 'SameHostAs'` immediately after the INSERT.

**Expected debugger state:**

- For each real client with a non-NULL `ad_domain_sid` that matches a `Computer` node's `sid`, there are **two rows**: one with `start_id = computer.sid, end_id = dev.smsid` and one with `start_id = dev.smsid, end_id = computer.sid`.
- Both rows carry `collection_source = ['SCCM_Invoke-PostProcessing']`.
- Inferred-client survivors (no matching real twin) that have `ad_domain_sid` matching a `Computer` node also get the bidirectional pair — only the deduped twin that was discarded gets none.
- No `SameHostAs` edge appears for a client with `ad_domain_sid = NULL`.

**Inspection query:**

```sql
SELECT * FROM sccm.graph_edges WHERE kind = 'SameHostAs';

-- Confirm both directions for a sample host SID
SELECT * FROM sccm.graph_edges
WHERE kind = 'SameHostAs'
  AND (start_id = '<KNOWN_COMPUTER_SID>' OR end_id = '<KNOWN_COMPUTER_SID>');
-- Expected: 2 rows (one in each direction)

-- Confirm collection_source is set
SELECT kind, collection_source FROM sccm.graph_edges WHERE kind = 'SameHostAs' LIMIT 1;
-- Expected: collection_source = ['SCCM_Invoke-PostProcessing']
```

**Which plan task it verifies:** Stage 4 Task D1 (`SameHostAs` edge builder; CMBP ps1:2314-2320).

---

### Stop 4 — `_edge_local_admin_required` (line 2400)

**What to inspect:** `graph_edges` rows with `kind = 'LocalAdminRequired'` immediately after the INSERT.

**Expected debugger state:**

- For each non-secondary site that has both a site server and other site systems, the site server's `Computer` node (`sid`) has an outgoing `LocalAdminRequired` edge to every other site system in that site (by matching the `@<site>` suffix on `site_system_roles`).
- When a site has more than one site server, the site servers are mutually linked (the set-based rule captures all combinations with `ss.sid != sys.sid`).
- No self-edge exists (`start_id != end_id` enforced by `ss.sid != sys.sid`).
- Secondary sites are excluded (the `nonsec` CTE filters `site_type != 1`).
- All rows carry `collection_source = ['SCCM_Invoke-PostProcessing']`.

**Inspection query:**

```sql
SELECT * FROM sccm.graph_edges WHERE kind = 'LocalAdminRequired';

-- Verify no self-edges
SELECT * FROM sccm.graph_edges WHERE kind = 'LocalAdminRequired' AND start_id = end_id;
-- Expected: 0 rows

-- Confirm collection_source is set
SELECT kind, collection_source FROM sccm.graph_edges WHERE kind = 'LocalAdminRequired' LIMIT 1;
-- Expected: collection_source = ['SCCM_Invoke-PostProcessing']
```

**Which plan task it verifies:** Stage 4 Task D2 (`LocalAdminRequired` edge builder; CMBP ps1:1882-1909; ARCHITECTURE §11d).

---

## 4. Per-task test suite

Every Stage 4 builder has unit tests under `sccm/sccm/tests/`. Run:

```powershell
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv `
  uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest tests -q
```

Expected: 0 failed (497 passing, 5 skipped as of Stage 4 completion).

---

## 5. What each stop verifies (plan cross-reference)

| Stop | Function (transforms.py) | Stage 4 plan task | CMBP reference |
|---|---|---|---|
| 1 | `_enrich_client_device` (line 1466) | C1 — real-client `ad_domain_sid` from `SMS_R_System` | ps1:7388-7392 |
| 2 | `_dedup_client_device` (line 1531) | C2 — collapse real+inferred twins before edges | ps1:2269-2311 |
| 3 | `_edge_same_host` (line 2377) | D1 — `SameHostAs` both directions | ps1:2314-2320 |
| 4 | `_edge_local_admin_required` (line 2400) | D2 — `LocalAdminRequired` site server → peers | ps1:1882-1909 |

The locked architectural decision that `_dedup_client_device` runs **before** `_graph_edges_init` (and thus before all edge builders) is documented in ARCHITECTURE.md §11d. This diverges from CMBP's post-edge merge order, but eliminates the need for any `graph_edges` rewrite pass.

---

## 6. Black-box CLI smoke check

Run against the lab raw tree (no re-collect needed). Adjust `<raw>` and `<graph>` to your paths:

```powershell
# Windows PowerShell; adjust paths as needed
$raw   = "C:\tmp\redo"
$graph = "C:\tmp\redo\graph"
$env:DLT_DATA_DIR = "C:\dlt-home"
$env:UV_PROJECT_ENVIRONMENT = "C:/Users/domainadmin/AppData/Local/Temp/openhound-venv"

# Step 1: preprocess (builds lookup.duckdb with Stage-4 tables)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    python -m openhound preprocess sccm $raw "$raw\lookup.duckdb"

# Step 2: convert (emits graph/*.json)
uv run --project C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm `
    python -m openhound convert sccm $raw $graph --lookup-file "$raw\lookup.duckdb"
```

### 6a — Stage 4 edges are present in the output JSON

```powershell
# Both should print at least one matching line
Select-String -Path "$graph\*.json" -Pattern '"kind": "SameHostAs"'           | Select-Object -First 1
Select-String -Path "$graph\*.json" -Pattern '"kind": "LocalAdminRequired"'   | Select-Object -First 1
```

> **Expected:** at least one hit for `SameHostAs` (assuming the lab has real clients with resolved `ad_domain_sid`) and at least one for `LocalAdminRequired` (assuming the lab site server has peers).

### 6b — Edge counts match the DuckDB `graph_edges` table

```powershell
python -c "
import duckdb
con = duckdb.connect(r'C:\tmp\redo\lookup.duckdb', read_only=True)
same_host = con.execute(\"SELECT count(*) FROM sccm.graph_edges WHERE kind='SameHostAs'\").fetchone()[0]
local_admin = con.execute(\"SELECT count(*) FROM sccm.graph_edges WHERE kind='LocalAdminRequired'\").fetchone()[0]
print(f'SameHostAs in DuckDB:         {same_host}')
print(f'LocalAdminRequired in DuckDB: {local_admin}')
"

# Then count in the JSON output and compare
$sameHostJson    = (Select-String -Path "$graph\*.json" -Pattern '\"SameHostAs\"').Count
$localAdminJson  = (Select-String -Path "$graph\*.json" -Pattern '\"LocalAdminRequired\"').Count
Write-Host "SameHostAs in JSON:         $sameHostJson"
Write-Host "LocalAdminRequired in JSON: $localAdminJson"
```

> **Expected:** the JSON counts match the DuckDB counts (each edge kind appears exactly once per edge in the output JSON; the `kind` field appears twice per edge object — once in the edge and once possibly in properties, so adjust the pattern or parse JSON directly if needed).

### 6c — Dedup reduced inferred-twin rows

```powershell
python -c "
import duckdb
con = duckdb.connect(r'C:\tmp\redo\lookup.duckdb', read_only=True)
# All surviving client devices
total = con.execute('SELECT count(*) FROM sccm.node_client_device').fetchone()[0]
confirmed = con.execute('SELECT count(*) FROM sccm.node_client_device WHERE is_confirmed_active_client').fetchone()[0]
inferred = con.execute('SELECT count(*) FROM sccm.node_client_device WHERE NOT is_confirmed_active_client').fetchone()[0]
# No two rows share an ad_domain_sid after dedup
dups = con.execute('''
    SELECT count(*) FROM (
        SELECT ad_domain_sid FROM sccm.node_client_device
        WHERE ad_domain_sid IS NOT NULL
        GROUP BY ad_domain_sid HAVING count(*) > 1
    )
''').fetchone()[0]
print(f'Total client devices:     {total}')
print(f'  Confirmed (real):       {confirmed}')
print(f'  Inferred:               {inferred}')
print(f'  Duplicate ad_domain_sid (should be 0): {dups}')
"
```

> **Expected:** `Duplicate ad_domain_sid: 0` (dedup collapsed all twins). The `Inferred` count covers inferred-client survivors that had no matching real client.

### 6d — SameHostAs is bidirectional and has correct collection_source

```powershell
python -c "
import duckdb
con = duckdb.connect(r'C:\tmp\redo\lookup.duckdb', read_only=True)
edges = con.execute(\"\"\"
    SELECT start_id, end_id, kind, collection_source
    FROM sccm.graph_edges WHERE kind='SameHostAs'
    LIMIT 4
\"\"\").fetchall()
for e in edges:
    print(e)
# Check collection_source is non-empty on all SameHostAs edges
empty = con.execute(\"\"\"
    SELECT count(*) FROM sccm.graph_edges
    WHERE kind='SameHostAs' AND len(collection_source) = 0
\"\"\").fetchone()[0]
print(f'SameHostAs edges with empty collection_source (should be 0): {empty}')
"
```

> **Expected:** pairs of rows with swapped `start_id`/`end_id`, each with `collection_source = ['SCCM_Invoke-PostProcessing']`. Empty-collection_source count = 0.

### 6e — LocalAdminRequired excludes self-edges and secondary sites

```powershell
python -c "
import duckdb
con = duckdb.connect(r'C:\tmp\redo\lookup.duckdb', read_only=True)
# No self-edges
self_edges = con.execute(\"\"\"
    SELECT count(*) FROM sccm.graph_edges
    WHERE kind='LocalAdminRequired' AND start_id = end_id
\"\"\").fetchone()[0]
print(f'LocalAdminRequired self-edges (should be 0): {self_edges}')
# Sample to verify site_server -> site_system direction
sample = con.execute(\"\"\"
    SELECT start_id, end_id FROM sccm.graph_edges
    WHERE kind='LocalAdminRequired' LIMIT 3
\"\"\").fetchall()
print('Sample LocalAdminRequired edges:', sample)
"
```

> **Expected:** 0 self-edges. The `start_id` values should be Computer SIDs of hosts carrying an `SMS Site Server@<site>` role in `node_computer.site_system_roles`.
