# SCCM preproc + convert — Stage 0 (Unblock & scaffold) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `openhound_sccm` package import again and prove the convert mechanism — the **Second Convert Pipeline with DuckDB Read** (`Convert2-Read-DB` for short), a convert-time `dlt.pipeline` reading the preproc DuckDB — emits a node and an edge end-to-end, so later stages build on a working preproc→convert skeleton.

**Architecture:** `preproc` builds tables in a DuckDB lookup file; `convert` runs a manual `dlt.pipeline` that reads those tables via the open lookup connection and writes OpenGraph JSON through the `opengraph_file` destination. Stage 0 uses a self-contained *spike* (one literal node row + one literal edge row built in `transforms.py`) so the plumbing is validated before any typed models or real coalescing SQL exist.

**Tech Stack:** Python 3.13+, `dlt` (pipelines/resources/destinations), `duckdb`, `openhound` (git dev dep, v0.2.x), `pytest`, `uv`.

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Never edit OpenHound core (`openhound/...`); if a core change seems required, stop and ask. (CLAUDE.md)
- **Do NOT `git commit`.** Leave changes staged; the user commits after testing. Each task ends at a checkpoint, not a commit. (CLAUDE.md)
- **Validate in an isolated uv env outside the repo**, e.g. `UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest ...`. Do not create/modify the repo-local `.venv`. If a command needs credentials/external services, report instead of forcing. (AGENTS.md)
- **Log every `if`/`else` and `try`/`except` branch** at an appropriate level, or leave a comment explaining why no log is needed. (CLAUDE.md)
- **Readability over efficiency; simplicity first.** No speculative features, no abstractions for single-use code. (CLAUDE.md / AGENTS.md)
- Tests live next to code as `<module>_test.py` (existing convention, e.g. `per_host_phases_test.py`).
- Spec: [`docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md`](../specs/2026-06-16-sccm-preproc-convert-design.md). All paths below are relative to `sccm/sccm/`.

**Scope note / deviations from the spec's Stage-0 list:** the spec groups `graph.py` (base node/edge classes), the full `kinds/edges.py` constants, and the `_preproc_table_map()` rebuild under Stage 0. This plan **defers** those to Stage 1, where they are first *used and testable* (base classes with no concrete node, and 35 edge constants with no emitter, would be untested scaffolding here — YAGNI). Stage 0's spike does not depend on the preproc map (the transformer builds literal tables), so the stale map is harmless until Stage 1.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/openhound_sccm/transforms.py` | **create** — `transforms(con, schema="sccm")` preproc entrypoint; Stage 0 builds literal spike tables `node_spike` + `graph_edges`. |
| `src/openhound_sccm/lookup.py` | **create** — `SCCMLookup(LookupManager)` with a `table_rows(table)` row iterator the Convert2-Read-DB pipeline streams. |
| `src/openhound_sccm/convert_pipeline.py` | **create** — `emit_graph_from_duckdb(...)`: the Convert2-Read-DB manual pipeline (read DuckDB → `opengraph_file`). |
| `src/openhound_sccm/models/__init__.py` | **modify** — remove the dangling `from .sccm_site import SCCMSite` import that breaks package import. |
| `src/openhound_sccm/main.py` | **modify** — `.transforms` import now resolves; register `@app.convert(lookup=SCCMLookup)` that runs the Convert2-Read-DB pipeline and returns a no-op source. |
| `src/openhound_sccm/transforms_test.py` | **create** — unit test for the spike transform. |
| `src/openhound_sccm/lookup_test.py` | **create** — unit test for `table_rows`. |
| `src/openhound_sccm/convert_pipeline_test.py` | **create** — unit test for the Convert2-Read-DB helper. |

---

## Task 1: De-risking spike — prove the Convert2-Read-DB mechanism with a throwaway script

Resolves three framework uncertainties before we build real code: (a) the `opengraph_file` output shape, (b) reading a DuckDB table through a `dlt.resource`, (c) that a manual convert pipeline writes a valid OpenGraph file. Throwaway — deleted at the end of the task.

**Files:**
- Create (temporary): `/tmp/sccm_spike.py`

**Interfaces:**
- Consumes: `openhound.destinations.opengraph.destination.opengraph_file`
- Produces: confirmed knowledge only (no committed artifact)

- [ ] **Step 1: Write the spike script**

```python
# /tmp/sccm_spike.py
import duckdb, dlt, json, pathlib
from openhound.destinations.opengraph.destination import opengraph_file

db = "/tmp/sccm_spike.duckdb"
con = duckdb.connect(db)
con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
con.execute("CREATE OR REPLACE TABLE sccm.node_spike AS SELECT 'SPIKE-1' AS id, 'spike' AS name")
con.execute("CREATE OR REPLACE TABLE sccm.graph_edges AS "
            "SELECT 'SPIKE-1' AS start_id, 'SPIKE-1' AS end_id, 'SCCM_Spike' AS kind")
con.close()

lookup = duckdb.connect(db, read_only=True)

@dlt.resource(name="sccm_nodes")
def nodes():
    cur = lookup.cursor(); cur.execute("SELECT * FROM sccm.node_spike")
    cols = [c[0] for c in cur.description]
    for r in cur.fetchall():
        row = dict(zip(cols, r))
        yield {"graph": {"entity_type": "node", "content": {
            "id": row["id"], "kinds": ["SCCM_Spike", "Base"],
            "properties": {"name": row["name"], "displayname": row["name"], "environmentid": "sccm-spike"}}}}

@dlt.resource(name="sccm_edges")
def edges():
    cur = lookup.cursor(); cur.execute("SELECT * FROM sccm.graph_edges")
    cols = [c[0] for c in cur.description]
    for r in cur.fetchall():
        row = dict(zip(cols, r))
        yield {"graph": {"entity_type": "edge", "content": [{
            "kind": row["kind"],
            "start": {"match_by": "id", "value": row["start_id"]},
            "end": {"match_by": "id", "value": row["end_id"]},
            "properties": {"composed": False}}]}}

out = pathlib.Path("/tmp/sccm_spike_out"); out.mkdir(parents=True, exist_ok=True)
p = dlt.pipeline(pipeline_name="sccm_spike", dataset_name="sccm",
                 destination=opengraph_file(output_path=str(out), source_kind="Kind"))
p.run([nodes(), edges()])
for f in sorted(out.glob("*.json")):
    print(f.name, json.loads(f.read_text()))
```

- [ ] **Step 2: Run it**

Run: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run --project sccm/sccm python /tmp/sccm_spike.py`
Expected: prints one or more `*.json` files whose combined content has the spike node under `graph.nodes` (id `SPIKE-1`) and the spike edge under `graph.edges` (kind `SCCM_Spike`), each with `metadata.source_kind == "Kind"`.

- [ ] **Step 3: Record findings, then delete the spike**

Confirm: the destination wrote at least one file; node content went to `nodes[]` and edge content (a list) to `edges[]`. If the shape differs, the discovered shape governs Tasks 2–7 (adjust the node/edge dicts accordingly). Then:

Run: `rm /tmp/sccm_spike.py /tmp/sccm_spike.duckdb && rm -rf /tmp/sccm_spike_out`

- [ ] **Step 4: Checkpoint** — no files changed in the repo; nothing to stage. Proceed.

---

## Task 2: `transforms.py` — preproc spike tables

**Files:**
- Create: `src/openhound_sccm/transforms.py`
- Test: `src/openhound_sccm/transforms_test.py`

**Interfaces:**
- Consumes: `duckdb.DuckDBPyConnection`
- Produces: `transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None` — registered via `@app.preproc(transformer=transforms)` in `main.py`. After it runs, `{schema}.node_spike(id, name)` and `{schema}.graph_edges(start_id, end_id, kind)` exist with one row each.

- [ ] **Step 1: Write the failing test**

```python
# src/openhound_sccm/transforms_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_transforms_builds_spike_tables():
    con = duckdb.connect(":memory:")
    transforms(con, schema="sccm")
    nodes = con.execute("SELECT id, name FROM sccm.node_spike").fetchall()
    edges = con.execute("SELECT start_id, end_id, kind FROM sccm.graph_edges").fetchall()
    assert nodes == [("SPIKE-1", "spike")]
    assert edges == [("SPIKE-1", "SPIKE-1", "SCCM_Spike")]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/transforms_test.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'openhound_sccm.transforms'`.

- [ ] **Step 3: Write the implementation**

```python
# src/openhound_sccm/transforms.py
"""DuckDB transforms for the SCCM collector's preproc phase.

Stage 0: a self-contained spike that proves the preproc -> convert (Convert2-Read-DB) path end to
end. Builds one node row and one edge row from literal SQL (no dependency on collected
data) so `convert` can read them back from DuckDB. Real coalescing SQL (node_* tables,
the full graph_edges UNION) is added in Stage 1+.
See docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md
"""
import logging

import duckdb

logger = logging.getLogger(__name__)


def _build_spike(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Create one node row and one edge row so the Convert2-Read-DB pipeline has something to emit."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_spike AS "
        "SELECT 'SPIKE-1' AS id, 'spike' AS name"
    )
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges AS "
        "SELECT 'SPIKE-1' AS start_id, 'SPIKE-1' AS end_id, 'SCCM_Spike' AS kind"
    )
    logger.info("Stage-0 spike tables built in schema %r", schema)


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Top-level transform entrypoint (registered via @app.preproc(transformer=transforms))."""
    _build_spike(con, schema)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/transforms_test.py -v`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `git add src/openhound_sccm/transforms.py src/openhound_sccm/transforms_test.py` (stage only; do NOT commit).

---

## Task 3: `lookup.py` — `SCCMLookup` + `table_rows`

**Files:**
- Create: `src/openhound_sccm/lookup.py`
- Test: `src/openhound_sccm/lookup_test.py`

**Interfaces:**
- Consumes: `openhound.core.lookup.LookupManager` (base provides `self.client`, `self.schema`); a DuckDB connection.
- Produces:
  - `SCCMLookup(client, schema="sccm")` — constructible with **one** positional arg (the framework calls `lookup(client)`), schema defaulted.
  - `SCCMLookup.table_rows(table: str) -> Iterator[dict]` — yields each row of `{schema}.{table}` as a column-named dict via an independent cursor; yields nothing (and warns) if the table is missing.

- [ ] **Step 1: Write the failing test**

```python
# src/openhound_sccm/lookup_test.py
import duckdb
from openhound_sccm.lookup import SCCMLookup


def _db(tmp_path):
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.node_spike AS SELECT 'SPIKE-1' AS id, 'spike' AS name")
    con.close()
    return str(path)


def test_table_rows_yields_dicts(tmp_path):
    client = duckdb.connect(_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)               # one-arg construction, schema defaults to "sccm"
    rows = list(lookup.table_rows("node_spike"))
    assert rows == [{"id": "SPIKE-1", "name": "spike"}]


def test_table_rows_missing_table_is_empty(tmp_path):
    client = duckdb.connect(_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    assert list(lookup.table_rows("does_not_exist")) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/lookup_test.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'openhound_sccm.lookup'`.

- [ ] **Step 3: Write the implementation**

```python
# src/openhound_sccm/lookup.py
"""DuckDB lookup helpers for the SCCM convert phase.

`SCCMLookup` is injected into convert as `ctx.lookup` and as `self._lookup` on each
model. Stage 0 needs only `table_rows`, the streaming iterator the Convert2-Read-DB convert pipeline
reads. Cached point/list lookups (for edge resolution) are added in later stages.
"""
import logging
from collections.abc import Iterator

from duckdb import DuckDBPyConnection
from openhound.core.lookup import LookupManager

logger = logging.getLogger(__name__)


class SCCMLookup(LookupManager):
    def __init__(self, client: DuckDBPyConnection, schema: str = "sccm"):
        # The framework constructs this as `lookup(client)` (one arg), so schema must default.
        super().__init__(client, schema)

    def table_rows(self, table: str) -> Iterator[dict]:
        """Yield each row of {schema}.{table} as a column-named dict.

        Uses an independent cursor so this streaming scan never clobbers the active
        result of other `self._lookup` queries that share the connection.
        """
        try:
            cur = self.client.cursor()
            cur.execute(f"SELECT * FROM {self.schema}.{table}")
        except Exception as err:
            # Missing/!readable table — log and yield nothing so a not-yet-built table
            # can't crash convert.
            logger.warning("SCCMLookup.table_rows(%r) failed: %s", table, err)
            return
        cols = [c[0] for c in cur.description]
        while True:
            batch = cur.fetchmany(2000)
            if not batch:
                break
            for row in batch:
                yield dict(zip(cols, row))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/lookup_test.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Checkpoint** — `git add src/openhound_sccm/lookup.py src/openhound_sccm/lookup_test.py` (stage only).

---

## Task 4: `convert_pipeline.py` — the Convert2-Read-DB helper

**Files:**
- Create: `src/openhound_sccm/convert_pipeline.py`
- Test: `src/openhound_sccm/convert_pipeline_test.py`

**Interfaces:**
- Consumes: `SCCMLookup.table_rows`; `openhound.destinations.opengraph.destination.opengraph_file`.
- Produces: `emit_graph_from_duckdb(lookup: SCCMLookup, output_path, source_kind: str, node_tables: list[str] | None = None, edge_table: str = "graph_edges") -> None` — runs a `dlt.pipeline` that writes OpenGraph JSON (one node per `node_tables` row, one edge per `edge_table` row) under `output_path`; `mkdir`s `output_path` first. Stage 0 emits raw spike shapes via `_spike_node`/`_spike_edge`; Stage 1+ swaps these for `model.as_node` / `model.edges`.

- [ ] **Step 1: Write the failing test**

```python
# src/openhound_sccm/convert_pipeline_test.py
import json
import duckdb
from openhound_sccm.lookup import SCCMLookup
from openhound_sccm.convert_pipeline import emit_graph_from_duckdb


def _db(tmp_path):
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.node_spike AS SELECT 'SPIKE-1' AS id, 'spike' AS name")
    con.execute("CREATE TABLE sccm.graph_edges AS "
                "SELECT 'SPIKE-1' AS start_id, 'SPIKE-1' AS end_id, 'SCCM_Spike' AS kind")
    con.close()
    return str(path)


def test_emit_writes_one_node_and_one_edge(tmp_path):
    client = duckdb.connect(_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"
    emit_graph_from_duckdb(lookup, out, "Kind", node_tables=["node_spike"])

    nodes, edges = [], []
    for f in out.glob("*.json"):
        doc = json.loads(f.read_text())
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]
    assert [n["id"] for n in nodes] == ["SPIKE-1"]
    assert [e["kind"] for e in edges] == ["SCCM_Spike"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/convert_pipeline_test.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'openhound_sccm.convert_pipeline'`.

- [ ] **Step 3: Write the implementation**

```python
# src/openhound_sccm/convert_pipeline.py
"""Convert-time pipeline (Convert2-Read-DB): read node_* tables and graph_edges from the preproc
DuckDB and emit them as OpenGraph nodes/edges.

The framework's built-in convert reader only globs JSONL from the bucket, so a
coalesced DuckDB table can't be iterated by it. We run our own dlt pipeline that reads
DuckDB directly via the open lookup connection -> opengraph_file. See
docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md §4.
"""
import logging
from pathlib import Path

import dlt
from openhound.destinations.opengraph.destination import opengraph_file

from .lookup import SCCMLookup

logger = logging.getLogger(__name__)


def _spike_node(row: dict) -> dict:
    """Stage-0 raw node shape (Stage 1+ replaces with a typed model's as_node)."""
    name = row.get("name") or row["id"]
    return {
        "id": row["id"],
        "kinds": ["SCCM_Spike", "Base"],
        "properties": {"name": name, "displayname": name, "environmentid": "sccm-spike"},
    }


def _spike_edge(row: dict) -> dict:
    """Stage-0 raw edge shape (Stage 1+ replaces with a typed model's edges)."""
    return {
        "kind": row["kind"],
        "start": {"match_by": "id", "value": row["start_id"]},
        "end": {"match_by": "id", "value": row["end_id"]},
        "properties": {"composed": False},
    }


def emit_graph_from_duckdb(
    lookup: SCCMLookup,
    output_path,
    source_kind: str,
    node_tables: list[str] | None = None,
    edge_table: str = "graph_edges",
) -> None:
    """Read node/edge tables from the lookup DuckDB and write OpenGraph JSON to output_path."""
    out = Path(output_path)
    # The opengraph_file destination opens files without creating the dir, and this runs
    # before the framework would create output_path — so make it ourselves.
    out.mkdir(parents=True, exist_ok=True)
    node_tables = node_tables or ["node_spike"]

    @dlt.resource(name="sccm_nodes")
    def nodes():
        for table in node_tables:
            for row in lookup.table_rows(table):
                yield {"graph": {"entity_type": "node", "content": _spike_node(row)}}

    @dlt.resource(name="sccm_edges")
    def edges():
        for row in lookup.table_rows(edge_table):
            # Edge content is a LIST: the destination does edges.extend(content).
            yield {"graph": {"entity_type": "edge", "content": [_spike_edge(row)]}}

    pipeline = dlt.pipeline(
        pipeline_name="sccm_convert_graph",
        dataset_name="sccm",
        destination=opengraph_file(output_path=str(out), source_kind=source_kind),
    )
    pipeline.run([nodes(), edges()])
    logger.info("Convert2-Read-DB convert pipeline wrote OpenGraph files to %s", out)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/convert_pipeline_test.py -v`
Expected: PASS.

- [ ] **Step 5: Checkpoint** — `git add src/openhound_sccm/convert_pipeline.py src/openhound_sccm/convert_pipeline_test.py` (stage only).

---

## Task 5: Make the package import — fix `models/__init__.py`

`models/__init__.py` imports `from .sccm_site import SCCMSite` (a deleted file); `main.py:32` imports `.transforms` (now created in Task 2). Removing the dangling models import lets the package load.

**Files:**
- Modify: `src/openhound_sccm/models/__init__.py`
- Test: `src/openhound_sccm/models/__init___test.py` (new)

**Interfaces:**
- Produces: importable `openhound_sccm.models` and `openhound_sccm.main`.

- [ ] **Step 1: Write the failing test**

```python
# src/openhound_sccm/models/__init___test.py
def test_models_and_main_import():
    import importlib
    importlib.import_module("openhound_sccm.models")
    importlib.import_module("openhound_sccm.main")   # registers @app.collect/@app.preproc/@app.convert
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/models/__init___test.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'openhound_sccm.models.sccm_site'` (and/or, after that is fixed, an error from `main.py` until Task 6 registers convert — that's fine; this test passes once imports resolve, which Task 6 completes).

- [ ] **Step 3: Replace the dangling import**

Replace the entire contents of `src/openhound_sccm/models/__init__.py` with:

```python
"""SCCM extension model registry.

Each module here defines `BaseAsset` subclasses the convert phase uses to produce
OpenGraph nodes/edges. Concrete node/edge models arrive in Stage 1+; Stage 0 has none,
so this package is intentionally empty of model imports.
"""

__all__: list[str] = []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/models/__init___test.py -v`
Expected: PASS (importing `openhound_sccm.models` succeeds; importing `openhound_sccm.main` succeeds because `.transforms` now exists. If `main` still errors, it is the missing `@app.convert` wiring — complete Task 6, then re-run; the two tasks land together).

- [ ] **Step 5: Checkpoint** — `git add src/openhound_sccm/models/__init__.py src/openhound_sccm/models/__init___test.py` (stage only).

---

## Task 6: Register `@app.convert` to run the Convert2-Read-DB pipeline

**Files:**
- Modify: `src/openhound_sccm/main.py` (add convert registration near the existing `@app.preproc`, ~line 1135)

**Interfaces:**
- Consumes: `emit_graph_from_duckdb` (Task 4), `SCCMLookup` (Task 3), `ConvertContext` (already imported at `main.py:26`), `dlt`.
- Produces: an `openhound convert sccm <input> <output> --lookup-file <db>` CLI command that runs the Convert2-Read-DB pipeline and returns a no-op framework source.

- [ ] **Step 1: Add imports**

At the top of `main.py`, alongside the existing `from .transforms import transforms` (line 32), add:

```python
import dlt
from .convert_pipeline import emit_graph_from_duckdb
from .lookup import SCCMLookup
```

- [ ] **Step 2: Register the convert command**

Immediately after the existing `@app.preproc(...)` `preproc(...)` function (ends ~line 1138), append:

```python
@dlt.source(name="sccm_convert_noop")
def _noop_convert_source():
    """The framework runs Converter.run over whatever @app.convert returns. All real
    emission happens in the Convert2-Read-DB pipeline (run in `convert` below), so this source carries
    no graph-resource models — Converter.run finds no models and its own pipeline is a
    no-op. opengraph_file appends uniquely-numbered files, so the two pipelines writing
    to the same output dir never collide."""

    @dlt.resource(name="_noop")
    def _empty():
        return
        yield  # unreachable; makes _empty a generator yielding nothing

    return _empty


@app.convert(lookup=SCCMLookup)
def convert(ctx: ConvertContext):
    """Emit the SCCM graph by reading the preproc DuckDB directly (Convert2-Read-DB), then hand the
    framework a no-op source."""
    emit_graph_from_duckdb(ctx.lookup, ctx.output_path, app.source_kind)
    return _noop_convert_source(), {}
```

- [ ] **Step 3: Verify the package imports and the command registers**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/models/__init___test.py -v`
Expected: PASS (both `openhound_sccm.models` and `openhound_sccm.main` import cleanly).

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run openhound convert sccm --help`
Expected: help text for the `sccm` convert command prints (exit 0), confirming registration.

> **Contingency (only if `openhound convert sccm` errors on the empty source):** if dlt rejects the no-op `opengraph([])` run, give `_empty` one harmless real graph resource instead — but first confirm this is actually needed; the Task 1 spike behavior and the no-columns filter in `Converter.run` indicate the empty source is skipped cleanly. Report the exact error before changing approach.

- [ ] **Step 4: Checkpoint** — `git add src/openhound_sccm/main.py` (stage only).

---

## Task 7: End-to-end integration — `preprocess` then `convert` emit the spike

**Files:**
- Create (test fixture, temporary): a tiny raw tree under a temp dir
- Test: `src/openhound_sccm/convert_integration_test.py`

**Interfaces:**
- Consumes: the `openhound preprocess sccm` and `openhound convert sccm` CLIs (wired in Tasks 2–6).
- Produces: confirmation that the full preproc→convert path emits the spike node + edge.

- [ ] **Step 1: Write the failing integration test**

```python
# src/openhound_sccm/convert_integration_test.py
import gzip
import json
import subprocess
import sys
from pathlib import Path


def _seed_raw(raw: Path):
    """Minimal raw tree: one row in one real table dir. The Stage-0 transformer ignores
    inputs and builds literal spike tables, so any nonempty raw tree is enough for
    preprocess to run."""
    d = raw / "sccm" / "adminservice_r_system"
    d.mkdir(parents=True)
    with gzip.open(d / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({"sid": "S-1-5-21-1-1-1-1104", "name": "DESKTOP-CHRIS"}) + "\n")


def test_preprocess_then_convert_emits_spike(tmp_path):
    raw = tmp_path / "raw"
    _seed_raw(raw)
    db = tmp_path / "lookup.duckdb"
    graph = tmp_path / "graph"

    def run(*args):
        return subprocess.run([sys.executable, "-m", "openhound", *args],
                              capture_output=True, text=True)

    pre = run("preprocess", "sccm", str(raw), str(db))
    assert pre.returncode == 0, pre.stderr
    conv = run("convert", "sccm", str(raw / "sccm"), str(graph), "--lookup-file", str(db))
    assert conv.returncode == 0, conv.stderr

    nodes, edges = [], []
    for f in graph.glob("*.json"):
        doc = json.loads(f.read_text())
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]
    assert "SPIKE-1" in [n["id"] for n in nodes]
    assert "SCCM_Spike" in [e["kind"] for e in edges]
```

> If `python -m openhound` is not the correct CLI entrypoint in this environment, substitute the installed console script (e.g. `openhound`) — confirm with `UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run openhound --help` and adjust the `run` helper accordingly.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm/convert_integration_test.py -v`
Expected: FAIL initially if any earlier wiring is incomplete (non-zero return code surfaced via the assertion message).

- [ ] **Step 3: Make it pass**

No new code if Tasks 2–6 are correct. If it fails, read the captured `stderr` in the assertion output and fix the responsible module (most likely: schema name mismatch between `transforms` and `SCCMLookup` — both must use `sccm`; or the `output_path` not existing — `emit_graph_from_duckdb` must `mkdir`).

- [ ] **Step 4: Run the full Stage-0 suite**

Run: `cd sccm/sccm && UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest src/openhound_sccm -v`
Expected: all Stage-0 tests PASS.

- [ ] **Step 5: Checkpoint** — `git add src/openhound_sccm/convert_integration_test.py` (stage only). Stage 0 complete: report the staged files to the user for commit.

---

## Self-Review

**Spec coverage (Stage 0 row of §6):** "package imports" → Tasks 5–6; "`openhound preprocess`/`convert` run to completion" → Task 7; "spike `graph_edges` row appears as one edge (and one node)" → Tasks 1, 4, 7. `transforms.py`/`lookup.py`/`convert_pipeline.py` recreated → Tasks 2–4. `@app.convert` registered → Task 6. `main.py` import fixed → Tasks 2 + 6. `models/__init__.py` fixed → Task 5. **Deferred with note (top of plan):** `graph.py` base classes, full `kinds/edges.py` constants, `_preproc_table_map()` rebuild → Stage 1 (first used/tested there; the spike doesn't need them).

**Placeholder scan:** no TBD/TODO; every code step shows complete code; the two contingency notes (empty-source, CLI entrypoint) are real fallbacks with concrete actions, not placeholders.

**Type consistency:** `SCCMLookup(client, schema="sccm")` constructed one-arg by the framework (Task 6) and in tests (Task 3) — consistent. `table_rows(table)` signature identical across Tasks 3, 4. `emit_graph_from_duckdb(lookup, output_path, source_kind, node_tables=None, edge_table="graph_edges")` — call sites in Task 4 test and Task 6 match. Schema string `"sccm"` consistent across `transforms`, `SCCMLookup`, and the preproc `dataset_name`. Node/edge dict shapes identical between the Task 1 spike, `_spike_node`/`_spike_edge` (Task 4), and the assertions (Tasks 4, 7).

---

## Manual validation (final deliverable)

After the tasks pass, validate Stage 0 by hand with the harness:
[`2026-06-16-sccm-preproc-convert-stage0-validation.md`](./2026-06-16-sccm-preproc-convert-stage0-validation.md)
— copy-pasteable `preprocess`/`convert` commands plus the expected DuckDB tables and OpenGraph output.
Per the spec §6 convention, **every stage plan ends with writing such a harness** so a human can
confirm real behavior before committing (the automated `*_test.py` suite only exercises synthetic data).
