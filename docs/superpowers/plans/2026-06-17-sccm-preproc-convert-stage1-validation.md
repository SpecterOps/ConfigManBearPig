# Stage 1 — code tour & breakpoint validation harness

**Purpose:** step through the actual Stage 1 code in execution order and confirm that the real preproc→convert pipeline produces correct output: a `Computer` node (keyed by SID), an `SCCM_Site` node (keyed by site code), and at least one `SCCM_AdminsReplicatedTo` edge — all from small but genuinely-structured coalesced data, not a spike. Unlike Stage 0's plumbing tour, this tour validates *real SCCM data shapes*.

> **Re-collection note (read before running on real collections):** Task 3 changed how collected data lands in the schema (clean snake_case AD-key column names). Any collection run *before* Stage 1 may have differently-named columns and will produce wrong or empty nodes. Always re-collect with the Stage 1 collector before validating on real data.

---

## 0. Baseline (optional, ~15 s)

```powershell
cd sccm\sccm
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv `
  uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm `
  pytest src/openhound_sccm -v
# Expect: all tests pass; no SPIKE-1 in any output.
```

---

## 1. The tour driver

The driver already lives at `sccm\sccm\tour_driver_stage1.py` (run it via the **"Debug: Stage 1 code tour"** launch profile). It seeds a minimal *real* raw tree — the same gzipped JSONL format the collector writes — **loads it into DuckDB**, then runs the preproc transforms and the convert pipeline in-process so every breakpoint fires. The load step is essential: without it, `transforms()` runs on an empty DB, every coalesce table is empty, and convert emits no files. The full source is below for reference.

```python
# tour_driver_stage1.py — set the breakpoints listed below, then debug THIS file.
#
# Why we seed non-null values for optional columns:
#   dlt drops entire columns from a JSONL file when every row in that batch has
#   NULL for that column (the "all-null column drop" behaviour). If a column that
#   the coalesce SQL references is silently absent, the INSERT … BY NAME skips it
#   and the coalesced row gets the column's default instead of the seeded value.
#   Seeding a concrete non-null value for every column the coalesce touches avoids
#   this trap and ensures the breakpoint inspection matches the expected values.
import gzip
import json
import tempfile
from pathlib import Path

import duckdb

import openhound_sccm.main as m               # registers @app.preproc / @app.convert
from openhound_sccm.transforms import transforms

# ---------------------------------------------------------------------------
# 1. Build the raw JSONL tree that preproc will load into DuckDB.
#    Directory layout must match what _preproc_table_map() maps:
#      <work>/sccm/<table>/<file>.jsonl.gz
# ---------------------------------------------------------------------------
work = Path(tempfile.mkdtemp(prefix="sccm_stage1_tour_"))
db   = work / "lookup.duckdb"

def _gz(table: str, rows: list[dict]) -> None:
    """Write rows as gzipped JSONL under <work>/sccm/<table>/."""
    d = work / "sccm" / table
    d.mkdir(parents=True, exist_ok=True)
    with gzip.open(d / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

# adminservice_r_system — one computer with a real S-1-5-21 SID.
# system_roles is a comma string here; the coalesce normalises it to an array.
# Seed every column the coalesce touches so dlt doesn't drop any.
_gz("adminservice_r_system", [{
    "name":                 "HOST1",
    "sid":                  "S-1-5-21-111-222-333-1104",
    "obsolete":             False,
    "resource_id":          7,
    "source_site_code":     "PS1",
    "system_roles":         "SMS Provider",
    "sms_unique_identifier":"GUID:tour-abc",
    "security_group_name":  [],            # no groups on this host for this tour
}])

# adminservice_site_definitions — CAS + Primary so _site_hierarchy resolves root.
# Seed site_type as integers (TRY_CAST handles both int and string).
_gz("adminservice_site_definitions", [
    {"site_code": "CAS", "parent_site_code": None,  "site_type": 4,
     "site_guid": "GUID-CAS", "sql_server_name": "sql-cas.lab",
     "sql_database_name": "CM_CAS"},
    {"site_code": "PS1", "parent_site_code": "CAS", "site_type": 2,
     "site_guid": "GUID-PS1", "sql_server_name": "sql-ps1.lab",
     "sql_database_name": "CM_PS1"},
])

# ---------------------------------------------------------------------------
# 2. Preproc: LOAD the seeded JSONL into DuckDB, then run transforms() exactly
#    as @app.preproc does. The real preproc loads with dlt first; here we load
#    the two seeded tables directly so the Stage-1 code (coalesces, models, emit)
#    runs against real rows without standing up the framework's 30-table load.
#    Skipping this load (calling transforms() on an empty DB) leaves every
#    coalesce table empty and convert emits NOTHING — that was the original bug.
# ---------------------------------------------------------------------------
con = duckdb.connect(str(db))
con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
for table in ("adminservice_r_system", "adminservice_site_definitions"):
    src = (work / "sccm" / table / "data.jsonl.gz").as_posix()
    con.execute(
        f"CREATE TABLE sccm.{table} AS "
        f"SELECT * FROM read_json_auto('{src}', format='newline_delimited')"
    )
transforms(con)                              # Stops 1, 2, 3, 6 are in here
con.close()

# ---------------------------------------------------------------------------
# 3. Convert: app.converter IS the framework's run_convert. It opens the lookup
#    read-only, injects SCCMLookup, calls our convert(ctx), which runs
#    emit_graph_from_duckdb (Stops 3–5), then hands the framework _noop_convert_source
#    (Stop 6).
# ---------------------------------------------------------------------------
m.app.converter(input_path=work, output_path=work / "graph", lookup_file=db)

print("TOUR OUTPUT:", [p.name for p in (work / "graph").glob("*.json")])
print("WORKDIR:", work)
```

**Run it under a debugger — two options:**

- **VS Code (recommended):** set the interpreter to the isolated env (`C:/Users/domainadmin/AppData/Local/Temp/openhound-venv`), open `tour_driver_stage1.py`, place the breakpoints from the table below by clicking the gutter, then **Run → Start Debugging** (F5). Inspect variables in the *Debug Console* / *Variables* pane.
- **Terminal pdb:** `uv run python -m pdb tour_driver_stage1.py`, then:
  ```
  b src/openhound_sccm/transforms.py:69
  b src/openhound_sccm/transforms.py:123
  b src/openhound_sccm/transforms.py:451
  b src/openhound_sccm/graph.py:29
  b src/openhound_sccm/models/computer.py:72
  b src/openhound_sccm/transforms.py:912
  b src/openhound_sccm/models/sccm_site.py:77
  b src/openhound_sccm/main.py:1161
  b .venv/Lib/site-packages/openhound/core/convert.py:105
  c
  ```
  At each stop type expressions to inspect, then `c` to continue.

---

## 2. The tour stops (execution order)

| # | Breakpoint (`file:line`) | What runs here | Inspect (debug console) | Expected | Plan detail verified |
|---|---|---|---|---|---|
| **1** | `transforms.py:69` (after `CREATE OR REPLACE TABLE … principal_by_name AS …`) | `_principal_by_name` finished deduplication | `con.execute('SELECT name, sid FROM sccm.principal_by_name ORDER BY name').fetchall()` | `[('HOST1', 'S-1-5-21-111-222-333-1104')]` (uppercased SID, original-case name) | Task 2 — `principal_by_name` unions all sources, uppercases SIDs, deduplicates; name-lookup join must upper() both sides |
| **2** | `transforms.py:123` (after `root_code = root[0] if root else None`) | `_site_hierarchy` resolved the root site | `root_code` · `con.execute('SELECT site_code, root_site_code FROM sccm.site_hierarchy ORDER BY site_code').fetchall()` | `'CAS'` · `[('CAS', 'CAS'), ('PS1', 'CAS')]` | Task 2 — CAS (type 4) wins as root; every row stamped with `root_site_code`; `environmentid` for `SCCM_Site` nodes will be `'CAS'` |
| **3** | `transforms.py:451` (the final `CREATE OR REPLACE TABLE … node_computer AS … GROUP BY sid`) | `_node_computer` collapsed all staging rows | `con.execute('SELECT sid, name, site_system_roles, resource_ids FROM sccm.node_computer').fetchall()` | one row: `('S-1-5-21-111-222-333-1104', 'HOST1', ['SMS Provider'], ['7@PS1'])` | Task 3 — one row per SID after GROUP BY; `_arr()` normalised the role string; resource_id@source_site_code assembled correctly |
| **4** | `graph.py:29` (the `if m:` branch inside `domain_environment_id`) | `domain_environment_id` matched the account SID | `sid` · `m.group(1)` | `'S-1-5-21-111-222-333-1104'` · `'S-1-5-21-111-222-333'` | Task 1 — the regex strips the RID (`-1104`), returning the domain SID prefix as `environmentid`; builtin SIDs without an `S-1-5-21` prefix would fall through to `return fallback_domain_sid` |
| **5** | `models/computer.py:72` (the `return SCCMNode(…)` line) | `ComputerNode.as_node` is building the node | `sid` · `env` · `self.site_system_roles` | `'S-1-5-21-111-222-333-1104'` · `'S-1-5-21-111-222-333'` · `['SMS Provider']` | Task 3 — `kinds=['Computer','Base']`; property keys are lowercase snake_case; `environmentid` is the domain SID not the full account SID |
| **6** | `transforms.py:912` (inside `_graph_edges`, the `con.execute(CREATE OR REPLACE TABLE … graph_edges …)` call — the big UNION ALL query) | `_graph_edges` is building the replication edge table | After stepping over: `con.execute('SELECT start_id, end_id, kind FROM sccm.graph_edges ORDER BY start_id').fetchall()` | `[('CAS', 'PS1', 'SCCM_AdminsReplicatedTo'), ('PS1', 'CAS', 'SCCM_AdminsReplicatedTo')]` (bidirectional; no Secondary in seed) | Task 7 — CAS↔Primary bidirectional (two rows); Primary→Secondary one-way (absent because no Secondary seeded); endpoints are site codes; CMBP ps1:1604-1624 type matrix |
| **7** | `models/sccm_site.py:77` (the `return SCCMNode(…)` line) | `SCCMSite.as_node` is building the site node | `self.site_code` · `env` · `self.site_type` | e.g. `'PS1'` · `'CAS'` · `2` (integer; model converts to `'Primary Site'` string in `site_type_str`) | Task 6 — `id=site_code`; `environmentid=root_site_code` (hierarchy root); `kinds=['SCCM_Site']`; integer→label mapping |
| **8** | `main.py:1161` (the `return _noop_convert_source(), {}` line) | `convert(ctx)` is finishing after `emit_graph_from_duckdb` has already run | `type(ctx.lookup).__name__` · `ctx.output_path` | `'SCCMLookup'` · the graph dir path | Framework wiring — lookup injected as `ctx.lookup`; all real graph content was already written by the Convert2-Read-DB pipeline before this return |
| **9** *(deep, optional — steps into core; read-only)* | `.venv/Lib/site-packages/openhound/core/convert.py:105` (`valid_resources = []`) | `Converter.run` is filtering graph-resource models from the no-op source | `source_models` · `valid_resources` (after the `for` loop) | `{}` · `[]` | Proves the no-op source is genuinely inert — the framework finds zero graph-resource models, so its own pipeline emits nothing; all output came from Convert2-Read-DB (spec §2 Decision #1). Do **not** edit core; just observe. |

> **Line number note:** `transforms.py:451` is the `CREATE OR REPLACE TABLE … node_computer AS … GROUP BY sid` collapse — the line that writes the final one-row-per-SID table. Step *over* it, then inspect `sccm.node_computer`. Similarly for Stop 6: step over the `con.execute(…)` call at line 912 before querying `graph_edges`.

---

## 3. After the tour

Let the driver finish. It prints `TOUR OUTPUT: ['sccm_nodes-1.json', 'sccm_edges-1.json']` (or similar) and the `WORKDIR`. Inspect the output:

```powershell
# List the JSON output files
Get-ChildItem $env:TEMP\sccm_stage1_tour_*\graph\

# Pretty-print nodes
Get-Content $env:TEMP\sccm_stage1_tour_*\graph\sccm_nodes-1.json -Raw | python -m json.tool

# Pretty-print edges
Get-Content $env:TEMP\sccm_stage1_tour_*\graph\sccm_edges-1.json -Raw | python -m json.tool
```

**PASS** = every "Expected" column in the breakpoint table matched, and the black-box checks below all pass.

Cleanup (the driver itself is a kept repo file — only the temp work dirs are disposable):
```powershell
Remove-Item -Recurse -Force $env:TEMP\sccm_stage1_tour_*
```

---

## 4. Black-box output check

After the driver finishes (no debugger needed), verify the JSON output directly:

| Check | What to look for | How |
|---|---|---|
| **Computer node** | `"kinds": ["Computer", "Base"]`, `"id": "S-1-5-21-111-222-333-1104"`, `"properties.environmentid": "S-1-5-21-111-222-333"`, `"properties.sccm_site_system_roles": ["SMS Provider"]`, `"properties.sccm_resource_ids": ["7@PS1"]` | in `sccm_nodes-*.json` → `graph.nodes` array |
| **SCCM_Site nodes** | Two entries with `"kinds": ["SCCM_Site"]`, ids `"CAS"` and `"PS1"`, both with `"properties.environmentid": "CAS"` | same file |
| **No SPIKE-1** | The string `SPIKE-1` does not appear anywhere in any output file | `Select-String -Pattern "SPIKE" -Path <graph>\*.json` → no matches |
| **Replication edges** | Two edge entries with `"kind": "SCCM_AdminsReplicatedTo"`: `start=CAS, end=PS1` and `start=PS1, end=CAS` | in `sccm_edges-*.json` → `graph.edges` array |
| **No extra edge directions** | No `SS1`-related edges (no Secondary was seeded) | same file — only two edge objects |
| **OpenGraph metadata** | Each file has `"metadata": {"source_kind": "Kind"}` | top-level of each JSON file |

---

## 5. Plan-detail → breakpoint map (quick reference)

| Plan detail | Confirmed at |
|---|---|
| `principal_by_name` unions sources, uppercases SIDs, deduplicates | Stop 1 |
| CAS (type 4) resolves as `root_site_code`; every site row stamped | Stop 2 |
| `node_computer` collapses to one row per SID; roles array-unioned | Stop 3 |
| `domain_environment_id` strips the RID from an account SID | Stop 4 |
| `ComputerNode.as_node` → `kinds=['Computer','Base']`; `environmentid`=domain SID; lowercase property keys | Stop 5 |
| `graph_edges` CAS↔Primary bidirectional; Primary→Secondary one-way | Stop 6 |
| `SCCMSite.as_node` → `id`=site_code; `environmentid`=`root_site_code`; integer `site_type`→string label | Stop 7 |
| `SCCMLookup` injected as `ctx.lookup`; all real emission done before `return` | Stop 8 |
| No-op source returns zero valid graph-resource models → framework pipeline is inert | Stop 9 |

---

## 6. Known benign noise (not failures)

- **`Logging error … [WinError 32]`** on `run_convert` invocations: a pre-existing Windows log-rollover quirk fixed for production runs via `_make_core_rotation_windows_safe()`, but the tour driver doesn't go through the full CLI so it may still surface. Harmless; exit codes are unaffected.
- **uv `VIRTUAL_ENV does not match`** warning: cosmetic; appears when running under an isolated env path that doesn't match the project `.venv`.
- **`transform 'node_computer<-wmi_r_system' skipped (missing source)`** and similar: expected. The tour seeds only `adminservice_r_system` and `adminservice_site_definitions`. Every other source table is absent, so `_safe()` logs a warning and skips it. This is the designed defensive behaviour; the warnings confirm the skip-on-missing-source logic works.
- **dlt all-null column drop (the known Stage 1 gotcha):** if you modify the seed to omit a value and set it to `None`, dlt may drop that column entirely from the JSONL batch. The coalesce SQL then silently misses it (the `INSERT … BY NAME` simply has no matching column) and the node property gets the schema default instead of the seeded value. The tour driver seeds all referenced columns with non-null values to avoid this trap. If you add sources to the seed, follow the same rule: every column that the coalesce touches must have at least one non-null value somewhere in the batch.
