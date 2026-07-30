# Move MSSQL Nodes/Edges into Their Own `source_kind="MSSQL"` Payload — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (1) Emit MSSQL nodes and MSSQL-only edges as a third OpenGraph payload (`mssql_nodes-*.json` / `mssql_edges-*.json`, tagged `source_kind="MSSQL"`), so the SQL topology this collector produces is owned by the MSSQL source (which matches `schema_MSSQL.json`) instead of being mis-homed under `source_kind="SCCM"`. (2) After the `--run-all` convert stage, bundle the emitted graph `.json` files into a single `graph/configmanbearpig_collection_<timestamp>.zip` (via a helper in the shared `openhound-collector-common` library), so the operator has one upload-ready, run-stamped artifact for BloodHound File Ingest.

**Architecture:** *Split* — extends the existing two-payload split (ARCHITECTURE.md §11f) into three. Node routing is free — move the six `node_mssql_*` tables out of `SCCM_NODE_SPECS` into a new `MSSQL_NODE_SPECS` and add a third `emit_graph_from_duckdb` pass. Edge routing is one change to the existing preproc step `transforms._graph_edges_split`: it already partitions `graph_edges` into an **AD-touching** set (`graph_edges_ad`, either endpoint is an AD node id) and an SCCM set. We add an **MSSQL-only** set (`graph_edges_mssql`) between them: edges that are *not* AD-touching and whose **both** endpoints are MSSQL node ids. Everything else stays in `graph_edges_sccm`. The AD rule keeps top precedence, so AD↔MSSQL edges stay in the untagged AD payload; MSSQL↔SCCM edges (e.g. `SCCM_AssignAllPermissions`) stay in the SCCM payload — exactly the routing the change owner specified: *"move only the nodes/edges where MSSQL nodes are both source and destination."* *Zip* — a new standalone helper `zip_graph_output(graph_dir, archive_name)` in `openhound_collector_common.orchestration.run` flat-bundles every `*.json` in the graph dir into `graph/<archive_name>` (the exact shape `integration_testing.graph.load_graph` and BloodHound File Ingest read); `run_end_to_end` gains a `graph_zip_name` parameter and calls it once, right after `app.converter(...)`. The archive name is a **parameter** (the helper is shared with the MSSQL collector, so it can't hardcode `configmanbearpig`); this collector's `--run-all` path passes `configmanbearpig_collection_<ts>.zip`, reusing the run's existing timestamp so it matches that run's `collect_full_<ts>.log`. Loose `.json` files are kept. The zip fires only on the `--run-all` path (per owner decision), never on a standalone `openhound convert`.

**Tech Stack:** Python 3, DuckDB SQL (preproc transforms), `dlt` (resources + custom destination), `dataclasses`/`pydantic` (graph models), `pytest`.

## Global Constraints

- **Two repositories, by explicit owner authorization.** The MSSQL split (Tasks 1–2) lives entirely in this repo (`ConfigManBearPig/`: `src/openhound_sccm/`, `tests/`, `README.md`, `ARCHITECTURE.md`). The zip feature (Task 3) edits the **shared library `openhound-collector-common/`** — normally off-limits per `AGENTS.md`/`CLAUDE.md`, but Meatbag has explicitly directed this change. `openhound/` framework **core remains off-limits** — do not touch it.
- **Shared-library governance (Task 3).** `openhound-collector-common` is consumed by **both** this SCCM collector and the sibling **MSSQL collector**, and it releases on its own git tag (`hatch-vcs`; a release is `git tag vX.Y.Z && git push`). Therefore: (a) the zip step changes the MSSQL collector's `--run-all` behavior too — update the **library's own** tests/README here, but the **MSSQL collector repo's** re-validation is a separate, owner-run task this plan does not cover; (b) **tagging/publishing the library release is Meatbag's action, not the implementer's** — the plan stops at "tests pass locally against the editable path checkout."
- **Do not `git add` or commit anything.** Each task ends when its tests pass; Meatbag reviews and commits after testing (`CLAUDE.md`: "Ask before committing each time. Never push."). This overrides the writing-plans skill's "Commit" step.
- **`source_kind` for MSSQL is the literal string `"MSSQL"`** — it must equal `schema_MSSQL.json`'s `"name"` / `"namespace"` (`"MSSQL"`) so BloodHound matches the payload to the uploaded MSSQL schema.
- **File basenames come from `resource_prefix`.** The MSSQL pass uses `resource_prefix="mssql"`, yielding `mssql_nodes-*.json` and `mssql_edges-*.json`. `sccm`/`ad` prefixes are unchanged.
- **Edge routing rule (three-way, mutually exclusive, exhaustive):**
  1. **AD** (`graph_edges_ad`, untagged) — **either** endpoint id is an AD node id (`node_computer`/`node_user`/`node_group`/`node_container`/`node_backfill`). Highest precedence, **unchanged**.
  2. **MSSQL** (`graph_edges_mssql`, `source_kind="MSSQL"`) — not AD-touching **and both** endpoint ids are MSSQL node ids.
  3. **SCCM** (`graph_edges_sccm`, `source_kind="SCCM"`) — everything else (not AD-touching, not both-MSSQL; at least one SCCM endpoint).
- **MSSQL node id set** = the id columns of the six MSSQL node tables: `node_mssql_server.server_id`, `node_mssql_database.database_id`, `node_mssql_login.login_id`, `node_mssql_database_user.dbuser_id`, `node_mssql_server_role.role_id`, `node_mssql_database_role.role_id`.
- **Property casing stays CMBP-verbatim.** This change moves nodes/edges between files; it does not rename or restructure any property or kind.
- **Always-on:** no CLI flag. The three-payload split is the new default output shape.
- **Zip = flat `*.json` archive at `graph/configmanbearpig_collection_<timestamp>.zip`.** Bundle every `*.json` in the graph dir, stored by basename (no directory prefix) — the shape `integration_testing.graph.load_graph` reads (`sorted(zf.namelist())`, `.json` only) and BloodHound File Ingest accepts. `<timestamp>` is the **run's** stamp `_ts` in `%Y%m%d_%H%M%S` ([main.py:1186](../../src/openhound_sccm/main.py#L1186)) so the zip shares the suffix of that run's `collect_full_<ts>.log`. **Keep** the loose `.json` files (non-destructive). Only `*.json` are added, so a prior archive is never nested in. Skip (log a WARNING, emit no zip) if the graph dir holds no `*.json`.
- **The archive name is a parameter, never hardcoded in the shared library.** `zip_graph_output(graph_dir, archive_name)` and `run_end_to_end(..., graph_zip_name=...)` take the name; the collector-agnostic default is `f"{app.name}_collection.zip"` (so the MSSQL collector is not mislabeled `configmanbearpig`). This SCCM collector's `--run-all` path passes `f"configmanbearpig_collection_{_ts}.zip"`.
- **Zip fires only on `--run-all`.** The step lives in `openhound_collector_common.orchestration.run.run_end_to_end`, after `app.converter(...)`, reached from this repo via `_run_e2e_after_collect`. A standalone `openhound convert` does not zip (owner decision).
- **Library version/consumer floor.** Release the library as a backward-compatible `v0.1.1` (stays within this repo's existing `<0.2.0` cap) and bump this repo's dependency floor to `openhound-collector-common>=0.1.1,<0.2.0` ([pyproject.toml:45](../../pyproject.toml#L45)). Tagging/publishing is Meatbag's action.
- **Tests live under `tests/`** and are named `*_test.py` (house convention).
- **Logging:** `_graph_edges_split`'s existing INFO summary line must be extended to report the MSSQL-only count alongside the AD and SCCM counts (per `CLAUDE.md`/`.agents/standards/workflow.md`, every branch logs; here we only extend an existing log, no new branch).
- **Preserve intent in comments**; do not annotate "ported from line X".
- **Validation venv:** run tests in an isolated uv environment so the repo's `.venv` is never touched (`AGENTS.md` §5). On this Windows/PowerShell host:
  `$env:UV_PROJECT_ENVIRONMENT="$env:TEMP\openhound-venv"; uv run pytest ...`
  Per-step commands below omit the prefix for brevity — set the env var once per shell.
- **Ticket hygiene (`CLAUDE.md`):** before starting, create a `gtk` ticket for this work (`gtk help` for commands) and move it to in-progress; regenerate `TICKETS-BY-STATUS.md` from `gtk list` after any status change. Do not hand-edit `TICKETS-BY-STATUS.md`.

---

## File Structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `src/openhound_sccm/transforms.py` | Modify | Rework `_graph_edges_split` into a three-way partition; add the `_mssql_ids` set and the `graph_edges_mssql` table; extend the summary log. |
| `src/openhound_sccm/main.py` | Modify | (Task 2) Add `MSSQL_SOURCE_KIND` + `MSSQL_NODE_SPECS` + `MSSQL_EDGE_SPECS`; remove the six MSSQL tables from `SCCM_NODE_SPECS`; add the third emit pass in `_emit_split_graph`. (Task 3 Step 7) Thread `graph_zip_name` through `_run_e2e_after_collect` and pass `configmanbearpig_collection_<ts>.zip` at the `--run-all` call site. |
| `tests/collect_run_all_test.py` | Modify | Assert `--run-all` forwards the timestamped `configmanbearpig_collection_<ts>.zip` name into `run_end_to_end` (Task 3 Step 7). |
| `tests/graph_edges_split_test.py` | Modify | Seed the six `node_mssql_*` tables + MSSQL/AD↔MSSQL/MSSQL↔SCCM edges; assert the three-way partition. |
| `tests/graph_edges_coercion_cols_test.py` | Modify | Seed six empty `node_mssql_*` tables so the split doesn't error; assert `graph_edges_mssql` carries the coercion columns. |
| `tests/edge_mssql_structural_test.py` | Modify | Flip the routing assertion: `MSSQL_Contains` now lands in `graph_edges_mssql`; add an assertion that `SCCM_AssignAllPermissions` stays in `graph_edges_sccm`. |
| `tests/mssql_models_test.py` | Modify | Replace `test_sccm_node_specs_include_mssql_tables` with one asserting the six tables are in `MSSQL_NODE_SPECS` and **absent** from `SCCM_NODE_SPECS`. |
| `tests/convert_split_output_test.py` | Modify | Extend the emit test to three payloads: seed a `node_mssql_server` row + a both-MSSQL `graph_edges_mssql` edge; assert `mssql_*.json` files carry `source_kind="MSSQL"` and hold the MSSQL node/edge. |
| `../openhound-collector-common/src/openhound_collector_common/orchestration/run.py` | Modify | Add `zip_graph_output(graph_dir)`; call it in `run_end_to_end` after convert. |
| `../openhound-collector-common/src/openhound_collector_common/orchestration/__init__.py` | Modify | Export `zip_graph_output`. |
| `../openhound-collector-common/tests/test_orchestration.py` | Modify | Unit-test the helper (flat bundle, empty-dir skip, non-json/prior-zip exclusion) + a `run_end_to_end` wiring test. |
| `../openhound-collector-common/README.md` | Modify | Note `run_end_to_end` now flat-zips graph `*.json` after convert (name via `graph_zip_name`, default `<app.name>_collection.zip`). |
| `pyproject.toml` | Modify | Bump the `openhound-collector-common` floor to `>=0.1.1`. |
| `README.md` | Modify | Update the output-files table, the Graph Model payload table + mermaid, the Limitations note, the Node/Edge Reference payload notes, and the `--run-all` docs (now writes `graph/configmanbearpig_collection_<timestamp>.zip`). |
| `ARCHITECTURE.md` | Modify | Update §11f (two→three payloads, new `_graph_edges_split` description), §11g "Output routing", §11h relay note, §12 (`--run-all` now zips), the quick-reference row, and add a changelog entry. |

**Task ordering:** Task 1 (preproc split) → Task 2 (emit pass; its full-suite regression reads `graph_edges_mssql`, so Task 1 lands first) → Task 3 (zip: the shared-library helper is independent of 1–2, but its Step 7 edits this repo's `main.py` — a different region than Task 2's spec lists — so run it after Task 2 to keep sequential edits to that file clean) → Task 4 (docs + dependency floor bump, no code dependency) → Task 5 (full verification gate; run last, after everything else is done). Each code task is independently unit-testable — the emit test seeds `graph_edges_mssql` directly, and the zip helper is tested standalone.

---

### Task 1: Three-way edge split (`_graph_edges_split`)

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — rewrite `_graph_edges_split` (currently [transforms.py:4998-5042](../../src/openhound_sccm/transforms.py#L4998-L5042)). Its call site (last line of `transforms()`, [transforms.py:5152](../../src/openhound_sccm/transforms.py#L5152)) is unchanged.
- Test: `tests/graph_edges_split_test.py`, `tests/graph_edges_coercion_cols_test.py`, `tests/edge_mssql_structural_test.py`

**Interfaces:**
- Consumes: tables `node_computer(sid)`, `node_user(sid)`, `node_group(sid)`, `node_backfill(id)`, the six `node_mssql_*` tables (id columns listed in Global Constraints), and `graph_edges` (9 columns: `start_id, end_id, kind, collection_source, coercion_victim_and_relay_target_pairs, coercion_victim_hostnames, sccm_infra, assumed, assumption_basis`). All are built earlier in `transforms()` with `CREATE OR REPLACE TABLE`, so all exist when this step runs.
- Produces: tables `graph_edges_ad`, `graph_edges_mssql`, `graph_edges_sccm`, each with the same 9 columns as `graph_edges`. Together they are a complete, disjoint partition. Consumed by `SCCM_EDGE_SPECS` / `MSSQL_EDGE_SPECS` / `AD_EDGE_SPECS` in Task 2.

- [ ] **Step 1: Update the failing test in `graph_edges_split_test.py`**

Replace the whole file with the version below. It seeds the six MSSQL node tables and adds one edge of each new class (both-MSSQL, AD↔MSSQL, MSSQL↔SCCM), then asserts the three-way partition:

```python
import duckdb
from openhound_sccm.transforms import _graph_edges_split, _graph_edges_init


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.node_computer AS SELECT 'S-1-5-21-1-2-3-1104' AS sid")
    con.execute("CREATE TABLE sccm.node_user AS SELECT 'S-1-5-21-1-2-3-1110' AS sid")
    con.execute("CREATE TABLE sccm.node_group AS SELECT 'S-1-5-21-1-2-3-512' AS sid")
    con.execute("CREATE TABLE sccm.node_backfill AS SELECT 'S-1-5-21-1-2-3-9999' AS id, 'Base' AS kind")
    # Six MSSQL node tables: _graph_edges_split now unions their id columns into _mssql_ids,
    # so every one must exist (empty is fine) or DuckDB raises on the missing table.
    con.execute("CREATE TABLE sccm.node_mssql_server AS SELECT 'S-1-DB:1433' AS server_id")
    con.execute(r"CREATE TABLE sccm.node_mssql_database AS SELECT 'S-1-DB:1433\CM_PS1' AS database_id")
    con.execute("CREATE TABLE sccm.node_mssql_login AS SELECT NULL::VARCHAR AS login_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_database_user AS SELECT NULL::VARCHAR AS dbuser_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_server_role AS SELECT 'sysadmin@S-1-DB:1433' AS role_id")
    con.execute("CREATE TABLE sccm.node_mssql_database_role AS SELECT NULL::VARCHAR AS role_id WHERE false")
    # Use _graph_edges_init so the schema stays current (includes the coercion columns).
    _graph_edges_init(con, "sccm")
    con.execute(
        "INSERT INTO sccm.graph_edges (start_id, end_id, kind, collection_source) VALUES "
        # AD<->AD
        "('S-1-5-21-1-2-3-1104','S-1-5-21-1-2-3-1110','HasSession', ['x']), "
        # AD<->SCCM (end is a user) -> AD payload
        "('GUID:dev1','S-1-5-21-1-2-3-1110','SCCM_HasPrimaryUser', ['x']), "
        # SCCM<->SCCM
        "('PS1','CAS','SCCM_Contains', ['x']), "
        # SCCM<->stub (backfill = AD) -> AD payload
        "('PS1','S-1-5-21-1-2-3-9999','SCCM_HasStoredAccount', ['x']), "
        # SCCM<->SCCM (neither is AD)
        "('PS1','GUID:dev1','SCCM_HasClient', ['x']), "
        # AD<->MSSQL: host computer -> server. start is AD -> AD payload (stays untagged)
        "('S-1-5-21-1-2-3-1104','S-1-DB:1433','MSSQL_HostFor', ['x']), "
        # MSSQL<->MSSQL: server -> its sysadmin role. both MSSQL -> MSSQL payload
        "('S-1-DB:1433','sysadmin@S-1-DB:1433','MSSQL_Contains', ['x']), "
        # MSSQL<->SCCM: database -> site. one SCCM endpoint, no AD -> SCCM payload
        r"('S-1-DB:1433\CM_PS1','PS1','SCCM_AssignAllPermissions', ['x'])"
    )


def test_split_partitions_completely_and_disjointly():
    con = duckdb.connect(":memory:")
    _seed(con)
    _graph_edges_split(con, "sccm")

    def _rows(table):
        return {r[0] for r in con.execute(
            f"SELECT start_id || '|' || end_id || '|' || kind FROM sccm.{table}").fetchall()}

    ad = _rows("graph_edges_ad")
    mssql = _rows("graph_edges_mssql")
    sccm = _rows("graph_edges_sccm")

    assert ad == {
        "S-1-5-21-1-2-3-1104|S-1-5-21-1-2-3-1110|HasSession",
        "GUID:dev1|S-1-5-21-1-2-3-1110|SCCM_HasPrimaryUser",
        "PS1|S-1-5-21-1-2-3-9999|SCCM_HasStoredAccount",
        "S-1-5-21-1-2-3-1104|S-1-DB:1433|MSSQL_HostFor",
    }
    assert mssql == {
        "S-1-DB:1433|sysadmin@S-1-DB:1433|MSSQL_Contains",
    }
    assert sccm == {
        "PS1|CAS|SCCM_Contains",
        "PS1|GUID:dev1|SCCM_HasClient",
        r"S-1-DB:1433\CM_PS1|PS1|SCCM_AssignAllPermissions",
    }
    # Complete + disjoint partition of the 8 original edges.
    assert len(ad) + len(mssql) + len(sccm) == 8
    assert ad.isdisjoint(mssql) and ad.isdisjoint(sccm) and mssql.isdisjoint(sccm)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests\graph_edges_split_test.py -v`
Expected: FAIL — `graph_edges_mssql` does not exist yet (`CatalogException`), and/or the current two-way split routes `MSSQL_Contains` into `graph_edges_sccm`.

- [ ] **Step 3: Rewrite `_graph_edges_split` in `transforms.py`**

Replace the whole function ([transforms.py:4998-5042](../../src/openhound_sccm/transforms.py#L4998-L5042)) with:

```python
def _graph_edges_split(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Partition graph_edges into three payloads: AD-touching, MSSQL-only, SCCM-only.

    Routing precedence (each edge lands in exactly one payload):
      1. AD    -- EITHER endpoint is an AD node id (Computer/User/Group/Container coalesce
                  row, or a backfill stub). Emitted untagged (no source_kind) so BloodHound
                  merges it into the native AD graph. This is what keeps AD<->MSSQL edges
                  (MSSQL_HostFor, MSSQL_HasLogin, the service-account and relay edges) here.
      2. MSSQL -- NOT AD-touching AND BOTH endpoints are MSSQL node ids. Emitted under
                  source_kind="MSSQL" so the separate MSSQL source owns its own SQL topology.
      3. SCCM  -- everything else: not AD-touching, not both-MSSQL, so at least one endpoint
                  is an SCCM node. This keeps MSSQL<->SCCM edges (SCCM_AssignAllPermissions,
                  database -> site) here.

    Runs LAST, after _node_backfill, so the AD id set includes the stub ids minted there.
    Every node_* table it reads is built earlier in transforms() with CREATE OR REPLACE
    TABLE, so all are guaranteed present. EXISTS/NOT EXISTS make the three outputs an exact,
    disjoint, complete partition, NULL-safe even for a malformed edge with a NULL endpoint
    (it falls to the SCCM side deterministically). MSSQL node ids never collide with AD SIDs,
    but the explicit NOT-AD guard on the MSSQL and SCCM arms keeps the precedence unambiguous.
    """
    # _ad_ids / _mssql_ids are session-local TEMP TABLEs (DuckDB's temp schema);
    # intentionally unqualified -- do NOT add a {schema}. prefix, that is invalid for a temp table.
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _ad_ids AS "
        f"SELECT sid AS id FROM {schema}.node_computer WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_user WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_group WHERE sid IS NOT NULL "
        f"UNION SELECT id FROM {schema}.node_backfill WHERE id IS NOT NULL"
    )
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _mssql_ids AS "
        f"SELECT server_id AS id FROM {schema}.node_mssql_server WHERE server_id IS NOT NULL "
        f"UNION SELECT database_id FROM {schema}.node_mssql_database WHERE database_id IS NOT NULL "
        f"UNION SELECT login_id FROM {schema}.node_mssql_login WHERE login_id IS NOT NULL "
        f"UNION SELECT dbuser_id FROM {schema}.node_mssql_database_user WHERE dbuser_id IS NOT NULL "
        f"UNION SELECT role_id FROM {schema}.node_mssql_server_role WHERE role_id IS NOT NULL "
        f"UNION SELECT role_id FROM {schema}.node_mssql_database_role WHERE role_id IS NOT NULL"
    )
    # The full 9-column projection every payload keeps identical (one place, added arrays free).
    cols = (
        "e.start_id, e.end_id, e.kind, e.collection_source, "
        "e.coercion_victim_and_relay_target_pairs, e.coercion_victim_hostnames, e.sccm_infra, "
        "e.assumed, e.assumption_basis"
    )
    start_ad = "EXISTS (SELECT 1 FROM _ad_ids a WHERE a.id = e.start_id)"
    end_ad = "EXISTS (SELECT 1 FROM _ad_ids a WHERE a.id = e.end_id)"
    start_mssql = "EXISTS (SELECT 1 FROM _mssql_ids m WHERE m.id = e.start_id)"
    end_mssql = "EXISTS (SELECT 1 FROM _mssql_ids m WHERE m.id = e.end_id)"
    # 1. AD payload: either endpoint is an AD node id (highest precedence, unchanged).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges_ad AS "
        f"SELECT {cols} FROM {schema}.graph_edges e "
        f"WHERE {start_ad} OR {end_ad}"
    )
    # 2. MSSQL payload: not AD-touching AND both endpoints are MSSQL node ids.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges_mssql AS "
        f"SELECT {cols} FROM {schema}.graph_edges e "
        f"WHERE NOT {start_ad} AND NOT {end_ad} "
        f"  AND {start_mssql} AND {end_mssql}"
    )
    # 3. SCCM payload: not AD-touching AND not both-MSSQL (at least one SCCM endpoint).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges_sccm AS "
        f"SELECT {cols} FROM {schema}.graph_edges e "
        f"WHERE NOT {start_ad} AND NOT {end_ad} "
        f"  AND NOT ({start_mssql} AND {end_mssql})"
    )
    ad_cnt = _scalar(con, f"SELECT count(*) FROM {schema}.graph_edges_ad")
    mssql_cnt = _scalar(con, f"SELECT count(*) FROM {schema}.graph_edges_mssql")
    sccm_cnt = _scalar(con, f"SELECT count(*) FROM {schema}.graph_edges_sccm")
    logger.info(
        "graph_edges split: %d AD-touching, %d MSSQL-only, %d SCCM-only",
        ad_cnt, mssql_cnt, sccm_cnt,
    )
```

Leave the call site at the end of `transforms()` as-is; update only its trailing comment ([transforms.py:5149-5152](../../src/openhound_sccm/transforms.py#L5149-L5152)) to read:

```python
    # Split the finalised graph_edges into the AD payload (either endpoint is an AD node id,
    # including the backfill stubs minted just above), the MSSQL-only payload (both endpoints
    # are MSSQL node ids), and the SCCM payload (everything else). Must run after _node_backfill
    # so stub ids are in the AD id set. See ARCHITECTURE.md §11f.
    _graph_edges_split(con, schema)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests\graph_edges_split_test.py -v`
Expected: PASS (1 test).

- [ ] **Step 5: Fix `graph_edges_coercion_cols_test.py` (seed + new assertion)**

This test calls `_graph_edges_split` in isolation and only seeds the AD node tables, so it will now hit a missing-`node_mssql_*` error. In `test_split_carries_coercion_columns_to_ad_payload`, immediately after the four `node_computer`/`node_user`/`node_group`/`node_backfill` creations ([graph_edges_coercion_cols_test.py:48-53](../../tests/graph_edges_coercion_cols_test.py#L48-L53)), add six empty MSSQL node tables:

```python
    # _graph_edges_split now unions the six MSSQL node id columns into _mssql_ids;
    # create them empty so the split does not error (no edge here is both-MSSQL).
    con.execute("CREATE TABLE sccm.node_mssql_server AS SELECT NULL::VARCHAR AS server_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_database AS SELECT NULL::VARCHAR AS database_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_login AS SELECT NULL::VARCHAR AS login_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_database_user AS SELECT NULL::VARCHAR AS dbuser_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_server_role AS SELECT NULL::VARCHAR AS role_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_database_role AS SELECT NULL::VARCHAR AS role_id WHERE false")
```

Then, after the existing `sccm_cols` assertions ([graph_edges_coercion_cols_test.py:58-60](../../tests/graph_edges_coercion_cols_test.py#L58-L60)), add a check that the new table carries the coercion columns too:

```python
    mssql_cols = [d[0] for d in con.execute("DESCRIBE sccm.graph_edges_mssql").fetchall()]
    assert "coercion_victim_and_relay_target_pairs" in mssql_cols
    assert "coercion_victim_hostnames" in mssql_cols
```

- [ ] **Step 6: Fix the routing assertion in `edge_mssql_structural_test.py`**

This test drives the real `transforms()` pipeline (all six MSSQL node tables are built), so it is the end-to-end check of the split. In `test_mssql_edges_route_to_correct_split_table` ([edge_mssql_structural_test.py:51-67](../../tests/edge_mssql_structural_test.py#L51-L67)), change the `MSSQL_Contains` assertion from the SCCM table to the MSSQL table, and add a check that the MSSQL↔SCCM edge stays in the SCCM table. Replace lines 62-67 with:

```python
    # MSSQL_Contains (server -> sysadmin role) is both-MSSQL -> MSSQL payload.
    mssql = con.execute(
        "SELECT count(*) FROM sccm.graph_edges_mssql WHERE kind = 'MSSQL_Contains' AND start_id = ?",
        [srv],
    ).fetchone()[0]
    assert mssql >= 1
    # SCCM_AssignAllPermissions (database -> site) is MSSQL<->SCCM -> SCCM payload.
    db = srv + "\\CM_PS1"
    sccm = con.execute(
        "SELECT count(*) FROM sccm.graph_edges_sccm WHERE kind = 'SCCM_AssignAllPermissions' AND start_id = ?",
        [db],
    ).fetchone()[0]
    assert sccm == 1
```

- [ ] **Step 7: Run the affected preproc/edge tests**

Run: `uv run pytest tests\graph_edges_split_test.py tests\graph_edges_coercion_cols_test.py tests\edge_mssql_structural_test.py tests\graph_edges_dedup_test.py tests\graph_edge_test.py -v`
Expected: PASS. (The split now produces three tables; the other MSSQL/SCCM builder tests read `graph_edges` pre-split and are unaffected.)

---

### Task 2: MSSQL node/edge specs + third emit pass

**Files:**
- Modify: `src/openhound_sccm/main.py` — spec lists and `_emit_split_graph` ([main.py:1835-1887](../../src/openhound_sccm/main.py#L1835-L1887)).
- Test: `tests/mssql_models_test.py`, `tests/convert_split_output_test.py`

**Interfaces:**
- Consumes: `emit_graph_from_duckdb(lookup, output_path, source_kind, node_specs, edge_specs, resource_prefix=...)` ([convert_pipeline.py:96](../../src/openhound_sccm/convert_pipeline.py#L96)) — unchanged signature; the `source_kind` string routes through core's `opengraph_file`, so `"MSSQL"` writes a `metadata.source_kind="MSSQL"` block. `graph_edges_mssql` from Task 1.
- Produces: module-level `MSSQL_SOURCE_KIND = "MSSQL"`, `MSSQL_NODE_SPECS`, `MSSQL_EDGE_SPECS`; a `SCCM_NODE_SPECS` with the six MSSQL tables removed; a three-pass `_emit_split_graph(lookup, output_path) -> None`.

- [ ] **Step 1: Update `tests/mssql_models_test.py`**

Replace `test_sccm_node_specs_include_mssql_tables` ([mssql_models_test.py:67-73](../../tests/mssql_models_test.py#L67-L73)) with:

```python
def test_mssql_node_specs_hold_mssql_tables_and_sccm_specs_do_not():
    from openhound_sccm.main import MSSQL_NODE_SPECS, SCCM_NODE_SPECS
    mssql_tables = [t for t, _ in MSSQL_NODE_SPECS]
    sccm_tables = [t for t, _ in SCCM_NODE_SPECS]
    for t in ("node_mssql_server", "node_mssql_database", "node_mssql_server_role",
              "node_mssql_database_role", "node_mssql_login", "node_mssql_database_user"):
        assert t in mssql_tables            # MSSQL nodes are their own source_kind="MSSQL" payload
        assert t not in sccm_tables         # ...and no longer live under the SCCM payload
```

- [ ] **Step 2: Update `tests/convert_split_output_test.py`**

In `_seed_db`, add a `node_mssql_server` row and a third split edge table `graph_edges_mssql` with a both-MSSQL edge. After the `node_site` creation ([convert_split_output_test.py:26-30](../../tests/convert_split_output_test.py#L26-L30)) add:

```python
    # MSSQL node: node_mssql_server. MSSQLServer.as_node needs only server_id to emit;
    # host_sid feeds environmentid, name is the display label (extra columns are ignored).
    con.execute(
        "CREATE TABLE sccm.node_mssql_server AS SELECT "
        "'S-1-5-21-1-2-3-9:1433' AS server_id, 'S-1-5-21-1-2-3-9' AS host_sid, 'SQL01' AS name"
    )
```

Change the split-edge-table loop ([convert_split_output_test.py:32-36](../../tests/convert_split_output_test.py#L32-L36)) to include the MSSQL table:

```python
    for t in ("graph_edges_ad", "graph_edges_mssql", "graph_edges_sccm"):
        con.execute(
            f"CREATE TABLE sccm.{t} "
            "(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[])"
        )
```

After the `graph_edges_sccm` insert ([convert_split_output_test.py:41-44](../../tests/convert_split_output_test.py#L41-L44)) add a both-MSSQL edge:

```python
    con.execute(
        "INSERT INTO sccm.graph_edges_mssql VALUES "
        "('S-1-5-21-1-2-3-9:1433','sysadmin@S-1-5-21-1-2-3-9:1433','MSSQL_Contains', ['s'])"
    )
```

Rename `test_emit_split_writes_two_payloads` to `test_emit_split_writes_three_payloads` and add MSSQL assertions after the existing AD block ([convert_split_output_test.py:75-79](../../tests/convert_split_output_test.py#L75-L79)):

```python
    # MSSQL payload: the MSSQL_Server node, the both-MSSQL edge, source_kind="MSSQL".
    mssql_nodes, mssql_edges, mssql_docs = _load(out, "mssql_*.json")
    assert any("MSSQL_Server" in n["kinds"] for n in mssql_nodes)
    assert {e["kind"] for e in mssql_edges} == {"MSSQL_Contains"}
    assert all(d["metadata"]["source_kind"] == "MSSQL" for _, d in mssql_docs)
    # The MSSQL node must NOT appear in the SCCM payload any more.
    assert all("MSSQL_Server" not in n["kinds"] for n in sccm_nodes)
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests\mssql_models_test.py tests\convert_split_output_test.py -v`
Expected: FAIL — `MSSQL_NODE_SPECS` does not exist yet; `_emit_split_graph` writes no `mssql_*.json`.

- [ ] **Step 4: Edit `main.py` spec lists**

Replace the spec block ([main.py:1835-1870](../../src/openhound_sccm/main.py#L1835-L1870)) with:

```python
# Registry of (table_name, ModelClass) pairs the convert pipeline iterates, split into three
# OpenGraph payloads (ARCHITECTURE.md §11f):
#   - SCCM payload  -> source_kind="SCCM"   (custom SCCM_* kinds only)
#   - MSSQL payload -> source_kind="MSSQL"  (MSSQL_* kinds; the separate MSSQL OpenGraph
#                                            schema, schema_MSSQL.json, owns these)
#   - AD payload    -> NO source_kind       (native Computer/User/Group/Container + backfill
#                                            stubs; BloodHound merges these into its AD graph)

# MSSQL nodes/edges belong to the separately maintained MSSQL schema (schema_MSSQL.json,
# name/namespace "MSSQL"), even though this SCCM collector emits them. Their own source_kind
# means re-ingesting or deleting the SCCM source never touches SQL topology.
MSSQL_SOURCE_KIND = "MSSQL"

SCCM_NODE_SPECS: list[tuple[str, type]] = [
    ("node_site", SCCMSite),
    ("node_collection", SCCMCollection),
    ("node_security_role", SCCMSecurityRole),
    ("node_admin_user", SCCMAdminUser),
    ("node_client_device", SCCMClientDevice),
]

MSSQL_NODE_SPECS: list[tuple[str, type]] = [
    ("node_mssql_server", MSSQLServer),
    ("node_mssql_database", MSSQLDatabase),
    ("node_mssql_server_role", MSSQLServerRole),
    ("node_mssql_database_role", MSSQLDatabaseRole),
    ("node_mssql_login", MSSQLLogin),
    ("node_mssql_database_user", MSSQLDatabaseUser),
]

AD_NODE_SPECS: list[tuple[str, type]] = [
    ("node_computer", ComputerNode),
    ("node_user", UserNode),
    ("node_group", GroupNode),
    # Container (Task 11, Tier A+) is a standard BloodHound base kind, like the
    # three above -- its id (objectGUID) merges with SharpHound's own node.
    ("node_container", ContainerNode),
    # node_backfill is LAST so a real AD node wins any id overlap via append semantics.
    # Every backfill stub is an AD principal (User/Group/Computer or bare Base).
    ("node_backfill", StubNode),
]

# graph_edges_{sccm,mssql,ad} are the partition built by transforms._graph_edges_split.
SCCM_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_sccm", GraphEdge)]
MSSQL_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_mssql", GraphEdge)]
AD_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_ad", GraphEdge)]
```

(The `MSSQLServer`/`MSSQLDatabase`/… imports already exist in `main.py` — they were in the old `SCCM_NODE_SPECS` — so no import change is needed.)

- [ ] **Step 5: Add the third emit pass in `_emit_split_graph`**

Replace `_emit_split_graph` ([main.py:1873-1887](../../src/openhound_sccm/main.py#L1873-L1887)) with:

```python
def _emit_split_graph(lookup: SCCMLookup, output_path) -> None:
    """Emit the graph as three payloads into the same directory.

    SCCM payload (sccm_* files, source_kind="SCCM"): SCCM_* nodes + every edge with at
    least one SCCM endpoint (including MSSQL<->SCCM edges). MSSQL payload (mssql_* files,
    source_kind="MSSQL"): MSSQL_* nodes + every edge whose endpoints are BOTH MSSQL nodes.
    AD payload (ad_* files, no source_kind): native Computer/User/Group/Container/stub nodes
    + every edge touching one (including AD<->MSSQL), so BloodHound merges them into the
    native AD graph. See ARCHITECTURE.md §11f.
    """
    emit_graph_from_duckdb(
        lookup, output_path, app.source_kind,
        SCCM_NODE_SPECS, SCCM_EDGE_SPECS, resource_prefix="sccm",
    )
    emit_graph_from_duckdb(
        lookup, output_path, MSSQL_SOURCE_KIND,
        MSSQL_NODE_SPECS, MSSQL_EDGE_SPECS, resource_prefix="mssql",
    )
    emit_graph_from_duckdb(
        lookup, output_path, None,
        AD_NODE_SPECS, AD_EDGE_SPECS, resource_prefix="ad",
    )
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests\mssql_models_test.py tests\convert_split_output_test.py -v`
Expected: PASS.

- [ ] **Step 7: Full CI-gate regression + lint + types**

Run:
```powershell
uv run pytest tests\extension_metadata_test.py tests\integration_wiring_test.py `
    tests\convert_pipeline_test.py tests\integration_fixtures_test.py -q
uv run pytest tests\ -q
uv run ruff check src tests
uv run mypy src\openhound_sccm
```
Expected: PASS. `integration_wiring_test.py` / `integration_fixtures_test.py` confirm the integration loader (which globs the whole graph dir) still passes with a third `mssql_*` file set present — the loader is prefix-agnostic, exactly as it already is for `ad_*`. `mypy` covers the `main.py` spec-list and `transforms.py` changes.

---

### Task 3: Zip the graph output after `--run-all` convert (shared library)

> **Repo boundary:** this task edits **`openhound-collector-common/`**, a separate checkout at `../openhound-collector-common` relative to this repo. Develop and validate it **in that checkout** (its own venv and `tests/`), not this repo's. Do **not** `git tag`/publish — that release is Meatbag's action (see Global Constraints).

**Files:**
- Modify: `../openhound-collector-common/src/openhound_collector_common/orchestration/run.py`
- Modify: `../openhound-collector-common/src/openhound_collector_common/orchestration/__init__.py`
- Modify: `../openhound-collector-common/README.md`
- Test: `../openhound-collector-common/tests/test_orchestration.py`

**Interfaces:**
- Produces: `zip_graph_output(graph_dir: Path, archive_name: str = "opengraph.zip") -> Path | None` — flat-bundles every `*.json` in `graph_dir` into `graph_dir/<archive_name>` (stored by basename), keeping the loose files. Returns the zip path, or `None` when the dir is missing or holds no `*.json`. Exported from `openhound_collector_common.orchestration`. **The name must be a parameter, not a hardcoded constant**, because this helper is shared with the MSSQL collector — hardcoding `configmanbearpig_collection` would mislabel MSSQL's archive.
- Produces: `run_end_to_end(app, output_path, *, progress=None, graph_zip_name: str | None = None) -> StagePaths` — new keyword-only `graph_zip_name`; after convert it calls `zip_graph_output(paths.graph_out, graph_zip_name or f"{app.name}_collection.zip")`. The `f"{app.name}_collection.zip"` default is collector-agnostic (MSSQL gets `mssql_collection.zip`, no leak); this SCCM collector passes an explicit, timestamped name.
- Consumes (this repo, Step 7): `_run_e2e_after_collect` gains a `graph_zip_name: str | None = None` param and the `collect_sccm --run-all` call site passes `f"configmanbearpig_collection_{_ts}.zip"`, reusing the run timestamp `_ts` from [main.py:1186](../../src/openhound_sccm/main.py#L1186) so the zip shares the same suffix as that run's `collect_full_{_ts}.log`.

- [ ] **Step 1: Write the failing tests**

Append to `../openhound-collector-common/tests/test_orchestration.py`:

```python
import zipfile

_NAME = "configmanbearpig_collection_20260730_101112.zip"  # a representative run-stamped name


def test_zip_graph_output_flat_bundles_json_under_given_name(tmp_path):
    from openhound_collector_common.orchestration import zip_graph_output
    g = tmp_path / "graph"
    g.mkdir()
    for n in ("sccm_nodes-1.json", "mssql_edges-1.json", "ad_nodes-1.json"):
        (g / n).write_text('{"graph": {"nodes": [], "edges": []}}', encoding="utf-8")
    zp = zip_graph_output(g, _NAME)
    assert zp == g / _NAME
    with zipfile.ZipFile(zp) as zf:
        assert sorted(zf.namelist()) == ["ad_nodes-1.json", "mssql_edges-1.json", "sccm_nodes-1.json"]
    assert (g / "sccm_nodes-1.json").exists()  # loose files kept (non-destructive)


def test_zip_graph_output_default_name_is_opengraph_zip(tmp_path):
    from openhound_collector_common.orchestration import zip_graph_output
    g = tmp_path / "graph"
    g.mkdir()
    (g / "sccm_nodes-1.json").write_text("{}", encoding="utf-8")
    assert zip_graph_output(g) == g / "opengraph.zip"  # collector-agnostic default


def test_zip_graph_output_skips_when_no_json(tmp_path):
    from openhound_collector_common.orchestration import zip_graph_output
    g = tmp_path / "graph"
    g.mkdir()
    assert zip_graph_output(g, _NAME) is None
    assert not (g / _NAME).exists()
    # A missing dir is also a no-op (not an error).
    assert zip_graph_output(tmp_path / "nope", _NAME) is None


def test_zip_graph_output_excludes_nonjson_and_prior_zip(tmp_path):
    from openhound_collector_common.orchestration import zip_graph_output
    g = tmp_path / "graph"
    g.mkdir()
    (g / "sccm_nodes-1.json").write_text("{}", encoding="utf-8")
    (g / "collect.log").write_text("noise", encoding="utf-8")
    (g / "configmanbearpig_collection_20260101_000000.zip").write_bytes(b"stale")  # a prior run's archive
    zp = zip_graph_output(g, _NAME)
    with zipfile.ZipFile(zp) as zf:
        assert zf.namelist() == ["sccm_nodes-1.json"]  # only json; not the log or the old zip


def test_run_end_to_end_zips_under_given_name(tmp_path):
    def preprocessor(**kwargs):
        pass

    def converter(**kwargs):
        out = kwargs["output_path"]  # the derived graph dir
        out.mkdir(parents=True, exist_ok=True)
        (out / "sccm_nodes-1.json").write_text('{"graph": {"nodes": [], "edges": []}}', encoding="utf-8")

    app = SimpleNamespace(name="sccm", preprocessor=preprocessor, converter=converter)
    paths = run_end_to_end(app, tmp_path, progress=None, graph_zip_name=_NAME)
    assert (paths.graph_out / _NAME).exists()


def test_run_end_to_end_defaults_zip_name_to_app_collection(tmp_path):
    def preprocessor(**kwargs):
        pass

    def converter(**kwargs):
        out = kwargs["output_path"]
        out.mkdir(parents=True, exist_ok=True)
        (out / "sccm_nodes-1.json").write_text("{}", encoding="utf-8")

    app = SimpleNamespace(name="sccm", preprocessor=preprocessor, converter=converter)
    paths = run_end_to_end(app, tmp_path, progress=None)
    assert (paths.graph_out / "sccm_collection.zip").exists()  # f"{app.name}_collection.zip"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (in the library checkout): `uv run pytest tests\test_orchestration.py -v`
Expected: FAIL — `cannot import name 'zip_graph_output'`.

- [ ] **Step 3: Add the helper, wire it in, and export it**

In `run.py`, add `import zipfile` under `import logging` (line ~14), and a default-name constant beside the existing ones (after [run.py:30](../../openhound-collector-common/src/openhound_collector_common/orchestration/run.py#L30)):

```python
_DEFAULT_GRAPH_ZIP_NAME = "opengraph.zip"
```

Add the helper (place it after `derive_stage_paths`, before `_NullProgress`):

```python
def zip_graph_output(graph_dir: Path, archive_name: str = _DEFAULT_GRAPH_ZIP_NAME) -> Optional[Path]:
    """Bundle every *.json in *graph_dir* into a flat ``graph_dir/<archive_name>``.

    The archive stores each file by basename (no directory prefix), which is exactly
    the shape ``integration_testing.graph.load_graph`` reads back (``sorted(zf.namelist())``,
    ``.json`` only) and BloodHound File Ingest accepts — so the operator has one
    upload-ready artifact. The loose ``.json`` files are left in place (non-destructive),
    and only ``*.json`` are added, so a prior archive (any ``.zip``) is never nested in.

    *archive_name* is a parameter, not a constant, because this library is shared with the
    MSSQL collector — each collector names its own archive (this one passes a timestamped
    ``configmanbearpig_collection_<ts>.zip``). Returns the zip path, or ``None`` when there
    is nothing to bundle (a missing dir, or a dir with no ``*.json``) — those are no-ops,
    not errors, so a caller can call this unconditionally after convert.
    """
    if not graph_dir.is_dir():
        logger.debug("Graph dir %s does not exist; no %s written.", graph_dir, archive_name)
        return None
    json_files = sorted(graph_dir.glob("*.json"))
    if not json_files:
        logger.warning("No *.json in %s; skipping %s.", graph_dir, archive_name)
        return None
    zip_path = graph_dir / archive_name
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in json_files:
            zf.write(f, arcname=f.name)  # arcname = basename -> flat archive
    logger.info("Bundled %d graph file(s) into %s", len(json_files), zip_path)
    return zip_path
```

Add the keyword-only `graph_zip_name` parameter to `run_end_to_end` (extend its signature and docstring), and wire the call in by replacing the function's final two lines ([run.py:123-125](../../openhound-collector-common/src/openhound_collector_common/orchestration/run.py#L123-L125)):

```python
def run_end_to_end(
    app: "OpenHound",
    output_path: Path,
    *,
    progress: "Optional[Progress]" = None,
    graph_zip_name: Optional[str] = None,
) -> StagePaths:
    # ... (unchanged body up to the convert call) ...
    logger.info("Convert complete. Graph written to: %s", paths.graph_out)
    # One upload-ready archive for BloodHound File Ingest; a no-op if convert wrote no json.
    # Collector-agnostic default name; the caller may pass a run-specific one.
    zip_graph_output(paths.graph_out, graph_zip_name or f"{app.name}_collection.zip")
    return paths
```

Add a line to the docstring's parameter notes: *"graph_zip_name: basename for the bundled graph archive written into the graph dir after convert; defaults to ``<app.name>_collection.zip``."*

In `orchestration/__init__.py`, add `zip_graph_output` to the `from .run import ...` line and to `__all__`.

- [ ] **Step 4: Run the tests to verify they pass**

Run (in the library checkout): `uv run pytest tests\test_orchestration.py -v`
Expected: PASS. (The pre-existing fake-app tests whose converter writes no graph dir still pass — `zip_graph_output` hits the missing-dir DEBUG branch and returns `None`, changing nothing they assert.)

- [ ] **Step 5: Update the library README**

In `../openhound-collector-common/README.md`, in the section that describes `orchestration.run` (the "Layout" list), add a line noting that `run_end_to_end` now bundles the convert output: *"After convert, `run_end_to_end` flat-zips the emitted graph `*.json` into the graph dir (name from `graph_zip_name`, default `<app.name>_collection.zip`), ready for BloodHound File Ingest (loose files kept)."*

- [ ] **Step 6: Library regression**

Run (in the library checkout): `uv run pytest tests\ -q` (plus `ruff`/`mypy` if the library configures them).
Expected: PASS. **Stop here for the library — do not `git tag`/publish; that release is Meatbag's action.**

- [ ] **Step 7: Wire the run-specific archive name from this repo's `--run-all` path**

Back in **this repo** (`ConfigManBearPig/`), thread the timestamped name so `--run-all` produces `graph/configmanbearpig_collection_<ts>.zip`. Local dev resolves `openhound-collector-common` via the `[tool.uv.sources]` editable path, so the Step 3 change is already importable here.

First the failing test — append to `tests/collect_run_all_test.py`:

```python
def test_run_e2e_forwards_configmanbearpig_zip_name(monkeypatch, tmp_path):
    """--run-all must pass a timestamped configmanbearpig_collection_<ts>.zip through
    to the shared run_end_to_end (which writes it into the graph dir)."""
    import openhound_collector_common.orchestration as orch
    from openhound_sccm.main import _run_e2e_after_collect, ProgressOption

    captured = {}

    def fake_run_end_to_end(app, output_path, *, progress=None, graph_zip_name=None):
        captured["graph_zip_name"] = graph_zip_name
        from openhound_collector_common.orchestration import derive_stage_paths
        return derive_stage_paths(app, output_path)

    # _run_e2e_after_collect does a function-local `from ... import run_end_to_end`,
    # which resolves the attribute at call time, so patching the module attr takes effect.
    monkeypatch.setattr(orch, "run_end_to_end", fake_run_end_to_end)
    _run_e2e_after_collect(
        tmp_path, ProgressOption.off,
        graph_zip_name="configmanbearpig_collection_20260730_101112.zip",
    )
    assert captured["graph_zip_name"] == "configmanbearpig_collection_20260730_101112.zip"
```

Run: `uv run pytest tests\collect_run_all_test.py::test_run_e2e_forwards_configmanbearpig_zip_name -v`
Expected: FAIL — `_run_e2e_after_collect` takes no `graph_zip_name`.

Then implement. In `_run_e2e_after_collect` ([main.py:1613](../../src/openhound_sccm/main.py#L1613)), add a keyword param (default `None` so any existing direct call keeps working) and forward it:

```python
def _run_e2e_after_collect(
    output_path: pathlib.Path, progress: ProgressOption, graph_zip_name: str | None = None,
) -> "StagePaths":
    ...
        return run_end_to_end(app, output_path, progress=e2e_progress, graph_zip_name=graph_zip_name)
```

At the `--run-all` call site ([main.py:1364](../../src/openhound_sccm/main.py#L1364)), pass the run-stamped name (reusing `_ts` from [main.py:1186](../../src/openhound_sccm/main.py#L1186), the same suffix as `collect_full_{_ts}.log`):

```python
        _paths = _run_e2e_after_collect(
            output_path, progress,
            graph_zip_name=f"configmanbearpig_collection_{_ts}.zip",
        )
```

Run: `uv run pytest tests\collect_run_all_test.py -v`
Expected: PASS (the new test plus the file's existing ones).

---

### Task 4: Documentation — README + ARCHITECTURE (+ dependency floor bump)

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- Modify: `pyproject.toml`

No automated test; the deliverable is reviewed prose held to the repo's "README is code-truth above all else" rule (`CLAUDE.md`/`AGENTS.md`). Verify with the doc-truth checks in Step 5.

- [ ] **Step 1: README — output-files table**

In the output-files table ([README.md:144-145](../../README.md#L144-L145)) replace the single combined SCCM+MSSQL row with three rows:

```markdown
| `graph\sccm_nodes-*.json`, `graph\sccm_edges-*.json` | **SCCM payload** — every `SCCM_*` node, and every edge with at least one SCCM endpoint (including SCCM↔MSSQL) |
| `graph\mssql_nodes-*.json`, `graph\mssql_edges-*.json` | **MSSQL payload** — every `MSSQL_*` node, and every edge whose endpoints are **both** MSSQL nodes |
| `graph\ad_nodes-*.json`, `graph\ad_edges-*.json` | **AD payload** — `Computer` / `User` / `Group` / `Container` nodes and every edge touching one (including AD↔MSSQL) |
```

- [ ] **Step 2: README — Limitations note (reframe the fixed limitation)**

The note at [README.md:385](../../README.md#L385) currently documents MSSQL nodes landing in the SCCM payload as a limitation. That is exactly what this change fixes, so rewrite it to describe the corrected routing:

```markdown
- **MSSQL nodes and MSSQL-only edges get their own `source_kind`.** The six MSSQL node kinds are written to `mssql_nodes-*.json` / `mssql_edges-*.json` (tagged `source_kind = "MSSQL"`, matching `schema_MSSQL.json`), together with every edge whose endpoints are **both** MSSQL nodes (`MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_MemberOf`, `MSSQL_IsMappedTo`). Edges that touch an AD node — `MSSQL_HostFor`, `MSSQL_ExecuteOnHost`, `MSSQL_HasLogin`, `MSSQL_GetTGS`, `MSSQL_ServiceAccountFor`, `MSSQL_GetAdminTGS`, and `MSSQL_CoerceAndRelayToMSSQL` — stay in `ad_edges-*.json`; the MSSQL↔SCCM edge `SCCM_AssignAllPermissions` (database → site) stays in `sccm_edges-*.json`. Upload all three file sets together.
```

- [ ] **Step 3: README — Graph Model payload table + mermaid**

In the payload table ([README.md:672-677](../../README.md#L672-L677)), (a) change the SCCM row's "Contents" to `SCCM-specific nodes (…) and edges where **at least one** endpoint is an SCCM node`; (b) insert an MSSQL row:

```markdown
| `mssql_nodes-*.json`, `mssql_edges-*.json` | `"MSSQL"` | MSSQL nodes (`MSSQL_Server`, `MSSQL_Database`, `MSSQL_ServerRole`, `MSSQL_DatabaseRole`, `MSSQL_Login`, `MSSQL_DatabaseUser`) and edges where **both** endpoints are MSSQL nodes (`MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_MemberOf`, `MSSQL_IsMappedTo`). |
```

(c) update the closing sentence ([README.md:677](../../README.md#L677)) from "upload both file sets" to "upload **all three** file sets (the whole output directory)". (d) In the mermaid graph ([README.md:703-704](../../README.md#L703-L704)), insert a third output node between the SCCM and AD ones:

```
    V --> O1["sccm_nodes/edges-*.json<br/>source_kind = SCCM"]
    V --> O3["mssql_nodes/edges-*.json<br/>source_kind = MSSQL"]
    V --> O2["ad_nodes/edges-*.json<br/>untagged — merges into AD graph"]
```

- [ ] **Step 4: README — Node/Edge Reference payload notes**

(a) **Node Reference** — for each of the six MSSQL node entries (`MSSQL_Server`, `MSSQL_Database`, `MSSQL_ServerRole`, `MSSQL_DatabaseRole`, `MSSQL_Login`, `MSSQL_DatabaseUser`), add a one-line note: `- **Note:** Emitted to the **MSSQL payload** (`mssql_nodes-*.json`, `source_kind = "MSSQL"`).` (Locate them by searching the Node Reference for each `MSSQL_` kind heading.)

(b) **Edge Reference** — for the five both-MSSQL edges (`MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_MemberOf`, `MSSQL_IsMappedTo`), add: `- **Note:** Lands in the **MSSQL payload** (`mssql_edges-*.json`) — both endpoints are MSSQL nodes.` Confirm the existing AD-payload notes on `MSSQL_CoerceAndRelayToMSSQL` ([README.md:1428](../../README.md#L1428)) and the AD-touching MSSQL edges ([README.md:1691](../../README.md#L1691)) are still accurate (they are — those edges keep an AD endpoint) and leave them.

- [ ] **Step 5: ARCHITECTURE — §11f, §11g, §11h, quick-reference, changelog**

In `ARCHITECTURE.md`:

(a) **§11f** ([ARCHITECTURE.md:1111-1160](../../ARCHITECTURE.md#L1111-L1160)) — keep the heading text and anchor **unchanged** (it is referenced by the TOC line 63 and by §11g/§11h at lines 1168/1221; changing it would break those anchors). Update the body:
  - In "#### The add-on", change the subheading and opening from "a second emit pass" / "Two emit passes" to **three** passes, and add the MSSQL pass to the node-routing bullet: `SCCM_NODE_SPECS` (`node_site`/`collection`/`security_role`/`admin_user`/`client_device`), **`MSSQL_NODE_SPECS`** (the six `node_mssql_*` tables, `source_kind="MSSQL"`, `resource_prefix="mssql"`), and `AD_NODE_SPECS`.
  - Rewrite the "Edge routing is one preproc step" bullet to describe the **three-way** partition: `graph_edges_ad` (either endpoint in the AD id set — highest precedence), `graph_edges_mssql` (not AD-touching **and both** endpoints in the new `_mssql_ids` set, unioned from the six MSSQL node id columns), and `graph_edges_sccm` (the remaining complement). Note that AD↔MSSQL edges stay in `graph_edges_ad` and MSSQL↔SCCM edges (`SCCM_AssignAllPermissions`) stay in `graph_edges_sccm`.
  - In "#### Trade-offs", change "both file sets must be uploaded together" to "**all three** file sets must be uploaded together".

(b) **§11g "Output routing"** ([ARCHITECTURE.md:1210-1217](../../ARCHITECTURE.md#L1210-L1217)) — replace with:

```markdown
**Output routing.** MSSQL nodes register in `MSSQL_NODE_SPECS` (`source_kind="MSSQL"`,
`mssql_*` files) — the separate MSSQL OpenGraph schema (`schema_MSSQL.json`) owns them,
even though this collector emits them. MSSQL edges insert into the single `graph_edges`
table and are routed by `_graph_edges_split` (§11f) **by endpoint**: both-MSSQL edges
(`MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_MemberOf`,
`MSSQL_IsMappedTo`) go to `graph_edges_mssql`; edges with an AD endpoint (`MSSQL_HostFor`,
`MSSQL_ExecuteOnHost`, `MSSQL_HasLogin`, `MSSQL_GetTGS`, `MSSQL_ServiceAccountFor`,
`MSSQL_GetAdminTGS`) go to `graph_edges_ad` (untagged AD payload); and the MSSQL↔SCCM
`SCCM_AssignAllPermissions` (database → site) goes to `graph_edges_sccm`. `_graph_edges_split`
builds an `_mssql_ids` set from the six MSSQL node id columns to make this decision.
```

Also update the "**`environmentid`**" note wording is unchanged, but change the earlier sentence that says MSSQL nodes are "SCCM-owned, `source_kind="SCCM"`" (if present in §11g's intro) to reflect the MSSQL source_kind.

(c) **§11h relay note** ([ARCHITECTURE.md:1248](../../ARCHITECTURE.md#L1248)) — `MSSQL_CoerceAndRelayToMSSQL` is still AD-routed (its start node is the Authenticated Users AD `Group`). Add a clause noting it therefore lands in the AD payload, **not** the MSSQL payload, despite its `MSSQL_` kind — the by-endpoint rule wins over the kind name.

(d) **Quick-reference table** — update the §11f row (the "Split output" row) to say the split now produces **three** payloads (SCCM-tagged, MSSQL-tagged, untagged AD).

(e) **Changelog** — add a new row at the top of the changelog table ([ARCHITECTURE.md:1866](../../ARCHITECTURE.md#L1866) onward, newest-first):

```markdown
| 2026-07-30 | **MSSQL payload split out.** MSSQL nodes and MSSQL-only edges now emit as a third OpenGraph payload (`mssql_*` files, `source_kind="MSSQL"`, matching `schema_MSSQL.json`) instead of under `source_kind="SCCM"`. `transforms._graph_edges_split` became a three-way partition — added `graph_edges_mssql` (not AD-touching, both endpoints in the new `_mssql_ids` set) between the existing AD and SCCM sets; AD keeps top precedence so AD↔MSSQL edges stay untagged and MSSQL↔SCCM edges (`SCCM_AssignAllPermissions`) stay SCCM. `main.py` gained `MSSQL_NODE_SPECS` / `MSSQL_EDGE_SPECS` / `MSSQL_SOURCE_KIND` and a third `_emit_split_graph` pass; the six `node_mssql_*` tables moved out of `SCCM_NODE_SPECS`. Updated §11f/§11g/§11h and the README. No framework/shared-library change. |
```

- [ ] **Step 6: Bump the shared-library dependency floor (`pyproject.toml`)**

The zip behavior ships in `openhound-collector-common` `v0.1.1`. Raise this repo's floor so an install is guaranteed to have it, keeping the existing upper cap ([pyproject.toml:45](../../pyproject.toml#L45)):

```toml
    "openhound-collector-common>=0.1.1,<0.2.0",
```

(Local development uses the `[tool.uv.sources]` editable-path redirect, which is unaffected; the floor guards installed/published wheels.)

- [ ] **Step 7: Document the `--run-all` zip (README + ARCHITECTURE §12)**

(a) `README.md` — in the `--run-all` entry of the Command Line Options table and in the Quick Start end-to-end example, add that the run now also writes `graph\configmanbearpig_collection_<timestamp>.zip` — a single upload-ready archive of the graph `.json` files for BloodHound File Ingest (loose files kept; `<timestamp>` matches the run's `collect_full_<ts>.log`). If the output-files table (Step 1) is nearby, add a row: `| `graph\configmanbearpig_collection_<timestamp>.zip` | **Bundle** — every graph `.json` above, flat-zipped for one-shot upload (written by `--run-all` only) |`.

(b) `ARCHITECTURE.md` §12 ("One-command end-to-end: a `--run-all` flag") — add a sentence that `run_end_to_end` now finishes by calling the shared `openhound_collector_common.orchestration.zip_graph_output`, which flat-bundles the graph `*.json` into `graph/<archive_name>`; the `--run-all` path passes `configmanbearpig_collection_<ts>.zip` (the shared default is `<app.name>_collection.zip`). Add `zip_graph_output` to the `orchestration/run` cell of the "Where this code lives" table's §12 row. Extend the changelog entry from Task 4 Step 5 to mention the zip addition (or add a companion line).

- [ ] **Step 8: Doc-truth verification**

Confirm the docs match the shipped code:
- README's three file-name patterns (`sccm_*` / `mssql_*` / `ad_*`) match the `resource_prefix` values in `_emit_split_graph`.
- README's per-payload node lists match `SCCM_NODE_SPECS` / `MSSQL_NODE_SPECS` / `AD_NODE_SPECS`.
- README's both-MSSQL vs AD-touching vs MSSQL↔SCCM edge lists match the endpoints in `transforms._edge_mssql_*` and `_edge_mssql_db_assign_all`.
- ARCHITECTURE §11f/§11g code references (`_graph_edges_split`, `graph_edges_mssql`, `_mssql_ids`, `MSSQL_NODE_SPECS`, `MSSQL_EDGE_SPECS`, `MSSQL_SOURCE_KIND`, `_emit_split_graph`) all exist in the code.
- The `--run-all` zip claims match the shipped code: `--run-all` passes `configmanbearpig_collection_<ts>.zip` (via `_run_e2e_after_collect` → `run_end_to_end(graph_zip_name=...)`), written into `graph/` by `zip_graph_output`, with the shared default `<app.name>_collection.zip`; the `pyproject.toml` floor reads `>=0.1.1`.

Run: `uv run pytest tests\ -q`
Expected: PASS (final full-suite confirmation that documented behavior holds).

---

### Task 5: Full verification gate — all tests (unit + integration) green across both repos

*No code changes. This is the explicit "everything passes after the changes" gate. Run it only after Tasks 1–4 are complete, using the isolated validation venv from Global Constraints. Do not claim completion until every command below is green (`superpowers:verification-before-completion`).*

- [ ] **Step 1: This repo — the CI-gate four files (the PR gate)**

Run:
```powershell
uv run pytest tests\extension_metadata_test.py tests\integration_wiring_test.py `
    tests\convert_pipeline_test.py tests\integration_fixtures_test.py -q
```
Expected: PASS, 0 failed. These are the four files `ci.yml` runs (`AGENTS.md` → Tests).

- [ ] **Step 2: This repo — full unit + offline-integration suite**

Run: `uv run pytest tests\ -q`
Expected: 0 failed. Skips are acceptable **only** for the minority of tests that need a live SCCM/AD hierarchy (`AGENTS.md`: "Most of the suite is offline; a minority needs a live SCCM hierarchy and is skipped without one"). The offline integration suites — `integration_fixtures_test.py`, `integration_wiring_test.py`, `integration_cli_flags_test.py`, `integration_lowpriv_fixtures_test.py` — must **run and pass**, not skip. Confirm the summary reads `0 failed` and that every skip is a documented live-only test; investigate any other skip.

- [ ] **Step 3: This repo — lint + types**

Run: `uv run ruff check src tests` then `uv run mypy src\openhound_sccm`
Expected: both clean (0 errors).

- [ ] **Step 4: Shared library — full suite (in its own checkout)**

Because Task 3 changed `openhound-collector-common`, run its suite too, in that checkout's venv:
```powershell
cd ..\openhound-collector-common
uv run pytest tests\ -q
```
Expected: 0 failed (includes the new `zip_graph_output` / `run_end_to_end` tests). Run its `ruff`/`mypy` if that repo configures them. Return to this repo afterward.

- [ ] **Step 5: Record the result and close out**

State the outcome plainly — passed/failed/skipped counts for each suite above, with the reason for every skip. If anything failed, fix it under the owning task and re-run this gate before claiming completion; never report success on a red or unexplained-skip suite. Then move the `gtk` ticket to done and regenerate `TICKETS-BY-STATUS.md` from `gtk list`.

---

## Self-Review

**Spec coverage**

- ✅ MSSQL nodes → their own file with `source_kind="MSSQL"`: `MSSQL_NODE_SPECS` + MSSQL emit pass (Task 2).
- ✅ Edges where MSSQL nodes are **both** source and destination → MSSQL file: `graph_edges_mssql` (both endpoints in `_mssql_ids`, not AD-touching) + `MSSQL_EDGE_SPECS` (Tasks 1, 2).
- ✅ AD↔MSSQL edges stay in `ad_*.json`: AD rule keeps top precedence; unchanged (Task 1).
- ✅ SCCM↔MSSQL edges stay in `sccm_*.json`: they are not both-MSSQL, so they fall to `graph_edges_sccm` — verified with `SCCM_AssignAllPermissions` in Tasks 1 and 2 tests.
- ✅ File basenames `mssql_nodes-*.json` / `mssql_edges-*.json`: `resource_prefix="mssql"` (Task 2).
- ✅ `source_kind="MSSQL"` matches `schema_MSSQL.json`: `MSSQL_SOURCE_KIND` constant (Task 2).
- ✅ Zip graph output after `--run-all` convert → `graph/configmanbearpig_collection_<ts>.zip`: `zip_graph_output(graph_dir, archive_name)` in the shared library, called by `run_end_to_end(graph_zip_name=...)`, with the name threaded from this repo's `_run_e2e_after_collect` reusing the run's `_ts` (Task 3).
- ✅ Filename is exactly `configmanbearpig_collection_<timestamp>.zip`: the `--run-all` call site passes `f"configmanbearpig_collection_{_ts}.zip"` (Task 3 Step 7); the shared helper keeps the name a parameter so the MSSQL collector isn't mislabeled (default `<app.name>_collection.zip`).
- ✅ Zip is a flat archive of the graph `*.json`, loose files kept, `--run-all` only: helper spec + placement (Task 3); owner decisions honored.
- ✅ All tests (unit + integration) pass after the changes, across both repos: Task 5 gate (CI-gate four files, full suite, lint/types, shared-library suite), with only documented live-only skips permitted.
- ✅ Consumer floor bumped so installs include the zip: `pyproject.toml` `>=0.1.1` (Task 4 Step 6).
- ✅ Docs updated (README output/Graph Model/Node+Edge Reference/mermaid + `--run-all` zip; ARCHITECTURE §11f/§11g/§11h/§12/quick-ref/changelog): Task 4.
- ✅ `openhound/` framework core untouched. `openhound-collector-common/` is edited **only** for the zip (Task 3), by explicit owner authorization; its release tag + the MSSQL collector's re-validation are owner tasks noted in Global Constraints, not steps here.
- ✅ Cleanup/summary unaffected: `_clean_previous_collection` removes whole artifact dirs (so the `--run-all` zip, living inside `graph/`, is swept with it) and the run-all summary globs `*.json` — both prefix-agnostic, so no code change needed (verified during planning).

**Placeholder scan:** No `TBD`/`TODO`. Every code step shows full code; every doc step shows the exact replacement text or a precise locate-and-edit instruction with the target lines.

**Type consistency:** `emit_graph_from_duckdb(lookup, output_path, source_kind, node_specs, edge_specs, resource_prefix)` is called in Task 2's `_emit_split_graph` with `MSSQL_SOURCE_KIND` (a `str`), matching the existing `source_kind: str | None` parameter. Table name `graph_edges_mssql` is produced in Task 1 and consumed by `MSSQL_EDGE_SPECS` in Task 2. The six `node_mssql_*` id columns used to build `_mssql_ids` in Task 1 (`server_id`, `database_id`, `login_id`, `dbuser_id`, `role_id`, `role_id`) match the columns the edge builders already join on (`_edge_mssql_structural`/`_membership`/`_db_assign_all`). `MSSQL_NODE_SPECS` / `MSSQL_EDGE_SPECS` are defined in Task 2 and asserted by name in `mssql_models_test.py` (Task 2). `zip_graph_output(graph_dir: Path) -> Optional[Path]` is defined and exported in Task 3 and imported by name in the Task 3 tests; `run_end_to_end` calls it with `paths.graph_out` (a `Path`), matching the signature.

**Edge classification cross-check** (endpoints confirmed against the builders in `transforms.py`):

| Edge kind | Start → End | Endpoints | Payload |
|---|---|---|---|
| `MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_MemberOf`, `MSSQL_IsMappedTo` | MSSQL ↔ MSSQL | both MSSQL | **MSSQL** |
| `MSSQL_HostFor`, `MSSQL_ExecuteOnHost` | Computer ↔ Server | one AD | AD |
| `MSSQL_HasLogin`, `MSSQL_GetTGS`, `MSSQL_ServiceAccountFor`, `MSSQL_GetAdminTGS` | AD principal ↔ MSSQL | one AD | AD |
| `MSSQL_CoerceAndRelayToMSSQL` | Auth Users (Group) → Login | one AD | AD |
| `SCCM_AssignAllPermissions` | Database → SCCM_Site | one SCCM | SCCM |

---

## Execution Handoff

(Filled in by the orchestrator after Meatbag approves.)
