# Stage 0 — code tour & breakpoint validation harness

**Purpose:** rather than only black-box-checking the output, **step through the actual Stage 0 code in execution order** and confirm at a breakpoint that each plan detail is really in place: the preproc transform builds the spike tables, the lookup streams rows on an *independent* cursor, the Convert2-Read-DB pipeline shapes nodes/edges correctly (edge content a *list*), and the framework's convert source is genuinely a *no-op*.

This is for a human on the dev machine (Windows). Run it before committing Stage 0.

> Stage 0 uses a synthetic *spike* (`node_spike` / `graph_edges` built in `transforms.py`), so the tour validates the **plumbing and wiring**, not real SCCM data. Real-data tours come in later stages.

---

## 0. Baseline (optional, ~5s)

```powershell
cd sccm\sccm
uv run pytest src/openhound_sccm -v   # expect: 6 passed
```

---

## 1. The tour driver

Save this as `sccm\sccm\tour_driver.py` (delete it after; it's not part of the collector). It runs the **whole preproc→convert path in-process** so your breakpoints actually fire:

```python
# tour_driver.py — set the breakpoints listed below, then debug THIS file.
import tempfile
from pathlib import Path

import duckdb

import openhound_sccm.main as m              # importing registers @app.collect/@app.preproc/@app.convert
from openhound_sccm.transforms import transforms

work = Path(tempfile.mkdtemp(prefix="sccm_tour_"))
db = work / "lookup.duckdb"

# --- preproc: build the spike tables exactly as @app.preproc's transformer does ---
con = duckdb.connect(str(db))
transforms(con)                              # Stop 1 lives in here
con.close()

# --- convert: app.converter IS the framework's run_convert. It opens the lookup
#     read-only, builds SCCMLookup(client), calls our convert(ctx) -> emit_graph_from_duckdb,
#     then runs Converter.run with the no-op source. Stops 2-4 all fire under this one call. ---
m.app.converter(input_path=work, output_path=work / "graph", lookup_file=db)

print("TOUR OUTPUT:", [p.name for p in (work / "graph").glob("*.json")])
print("WORKDIR:", work)
```

**Run it under a debugger — two options:**

- **VS Code (recommended):** set the interpreter to `sccm\sccm\.venv` (Command Palette → *Python: Select Interpreter*), open `tour_driver.py`, place the breakpoints from the table below by clicking the gutter at each `file:line`, then **Run → Start Debugging** (F5) with `tour_driver.py` active. Inspect variables in the *Debug Console* / *Variables* pane.
- **Terminal pdb:** `uv run python -m pdb tour_driver.py`, then set breakpoints and continue:
  ```
  b src/openhound_sccm/transforms.py:28
  b src/openhound_sccm/lookup.py:36
  b src/openhound_sccm/convert_pipeline.py:52
  b src/openhound_sccm/convert_pipeline.py:59
  b src/openhound_sccm/convert_pipeline.py:65
  b src/openhound_sccm/main.py:1164
  c
  ```
  At each stop, type expressions (e.g. `con.execute('SELECT * FROM sccm.node_spike').fetchall()`) to inspect, then `c` to continue.

---

## 2. The tour stops (execution order)

| # | Breakpoint (`file:line`) | What runs here | Inspect (debug console) | Expected | Plan detail it verifies |
|---|---|---|---|---|---|
| **1** | `transforms.py:28` (after both `CREATE`s) | `_build_spike` built the spike tables | `schema` · `con.execute('SELECT * FROM sccm.node_spike').fetchall()` · `con.execute('SELECT * FROM sccm.graph_edges').fetchall()` | `'sccm'` · `[('SPIKE-1','spike')]` · `[('SPIKE-1','SPIKE-1','SCCM_Spike')]` | spec §4 — preproc builds `node_*` + `graph_edges` in schema `sccm` (here the literal spike). Set a breakpoint on `transforms.py:19` too if you want to step each `CREATE`. |
| **2** | `lookup.py:36` (after `cur.execute`, `cols` about to build) | `table_rows` opened its scan | `self.schema` · `cur is self.client` · `self.schema, table` | `'sccm'` · **`False`** · the table being read | **The independent cursor** — `cur is self.client` is `False`, so streaming this scan can't clobber other `self._lookup` queries on the shared connection (spec §4 / the proposal's corrected reader). `table_rows` fires **twice**: once for `node_spike`, once for `graph_edges`. |
| **2b** | `lookup.py:42` (the `yield`) | one row about to be yielded | `dict(zip(cols, row))` | `{'id':'SPIKE-1','name':'spike'}` then later `{'start_id':'SPIKE-1','end_id':'SPIKE-1','kind':'SCCM_Spike'}` | rows come back as **column-named dicts**. |
| **3a** | `convert_pipeline.py:52` (`out.mkdir`) | helper ensures the output dir | step over, then `out.exists()` | `True` | the helper **mkdirs `output_path` itself** — the destination doesn't, and this runs *before* the framework would (spec §4). |
| **3b** | `convert_pipeline.py:59` (node `yield`) | a node item about to be emitted | `_spike_node(row)` | `{'id':'SPIKE-1','kinds':['SCCM_Spike','Base'],'properties':{'name':'spike','displayname':'spike','environmentid':'sccm-spike'}}` | node `content` is a **dict** → lands in `graph.nodes`. |
| **3c** | `convert_pipeline.py:65` (edge `yield`) | an edge item about to be emitted | `[_spike_edge(row)]` · `type([_spike_edge(row)]) is list` | the edge dict wrapped in `[...]` · **`True`** | **edge `content` MUST be a list** — the destination does `edges.extend(content)`; a bare dict would break it. The single most breakage-prone detail. |
| **3d** | `convert_pipeline.py:72` (`pipeline.run`) | the Convert2-Read-DB dlt pipeline runs to `opengraph_file` | `pipeline.pipeline_name` | `'sccm_convert_graph'` | spec §2 Decision #1 — convert runs **its own** `dlt.pipeline` reading DuckDB → `opengraph_file`. |
| **4a** | `main.py:1164` (`emit_graph_from_duckdb(...)`) | the registered `convert(ctx)` body | `type(ctx.lookup).__name__` · `ctx.output_path` | `'SCCMLookup'` · the graph dir | the lookup is injected as `ctx.lookup` (an `SCCMLookup`), and convert hands it to the Convert2-Read-DB helper. |
| **4b** | `main.py:1154` (the `return` in `_empty`) | the no-op source's resource | step — confirm `_empty` returns immediately and never reaches the `yield` | resource yields **nothing** | the returned source carries no graph-resource model. |
| **4c** *(deep, optional — steps into core, read-only)* | `.venv/Lib/site-packages/openhound/core/convert.py:114` (the `self._run(opengraph(valid_resources, ...))` call in `Converter.run`) | the framework's own convert pipeline | `source_models` · `valid_resources` | **`{}`** · **`[]`** | **Proves the no-op source is genuinely inert** — the framework finds zero graph-resource models, so its pipeline emits nothing; all output came from Convert2-Read-DB (spec §2 Decision #1). Do **not** edit core; just observe. |

---

## 3. After the tour

Let the driver finish. It prints `TOUR OUTPUT: ['sccm_nodes-1.json', 'sccm_edges-1.json']` (or similar) and the `WORKDIR`. Open those JSON files (`Get-Content <workdir>\graph\*.json -Raw`) and confirm **exactly one** `SPIKE-1` node and **exactly one** `SCCM_Spike` edge, with `"metadata": {"source_kind": "Kind"}` — the black-box confirmation of what you watched happen at the breakpoints.

**PASS** = every "Expected" column matched, and the output has exactly one node + one edge.

Cleanup:
```powershell
Remove-Item sccm\sccm\tour_driver.py
Remove-Item -Recurse -Force $env:TEMP\sccm_tour_*
```

---

## 4. Plan-detail → breakpoint map (quick reference)

| Plan detail (spec/plan) | Confirmed at |
|---|---|
| preproc builds `node_*` + `graph_edges` in schema `sccm` | Stop 1 |
| lookup uses an **independent cursor** (no clobber) | Stop 2 |
| rows returned as column-named dicts | Stop 2b |
| helper mkdirs `output_path` before the destination writes | Stop 3a |
| node content shape → `graph.nodes` | Stop 3b |
| **edge content is a list** (`edges.extend`) | Stop 3c |
| convert runs its own DuckDB-reading `dlt.pipeline` | Stop 3d |
| `SCCMLookup` injected as `ctx.lookup` | Stop 4a |
| returned framework source is a **no-op** (zero resources / inert) | Stops 4b, 4c |

---

## Known benign noise (not failures)

- **`Logging error … [WinError 32]`** on `openhound`/`run_convert` invocations: a pre-existing Windows log-rollover quirk; harmless, exit codes unaffected.
- **uv `VIRTUAL_ENV does not match`** warning if you run under an isolated env: cosmetic.
