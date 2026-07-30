# Move MSSQL Nodes/Edges into Their Own `source_kind="MSSQL"` Payload — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit MSSQL nodes and MSSQL-only edges as a third OpenGraph payload (`mssql_nodes-*.json` / `mssql_edges-*.json`, tagged `source_kind="MSSQL"`), so the SQL topology this collector produces is owned by the MSSQL source (which matches `schema_MSSQL.json`) instead of being mis-homed under `source_kind="SCCM"`.

**Architecture:** This extends the existing two-payload split (ARCHITECTURE.md §11f) into three. Node routing is free — move the six `node_mssql_*` tables out of `SCCM_NODE_SPECS` into a new `MSSQL_NODE_SPECS` and add a third `emit_graph_from_duckdb` pass. Edge routing is one change to the existing preproc step `transforms._graph_edges_split`: it already partitions `graph_edges` into an **AD-touching** set (`graph_edges_ad`, either endpoint is an AD node id) and an SCCM set. We add an **MSSQL-only** set (`graph_edges_mssql`) between them: edges that are *not* AD-touching and whose **both** endpoints are MSSQL node ids. Everything else stays in `graph_edges_sccm`. The AD rule keeps top precedence, so AD↔MSSQL edges stay in the untagged AD payload; MSSQL↔SCCM edges (e.g. `SCCM_AssignAllPermissions`) stay in the SCCM payload — exactly the routing the change owner specified: *"move only the nodes/edges where MSSQL nodes are both source and destination."*

**Tech Stack:** Python 3, DuckDB SQL (preproc transforms), `dlt` (resources + custom destination), `dataclasses`/`pydantic` (graph models), `pytest`.

## Global Constraints

- **Only modify code under this repository (`ConfigManBearPig/`).** Never edit anything under `openhound/` (framework core) or `openhound-collector-common/` (shared library) — both are off-limits per `AGENTS.md`/`CLAUDE.md`. This change lives entirely in `src/openhound_sccm/` and `tests/`, plus `README.md`/`ARCHITECTURE.md`.
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
| `src/openhound_sccm/main.py` | Modify | Add `MSSQL_SOURCE_KIND` + `MSSQL_NODE_SPECS` + `MSSQL_EDGE_SPECS`; remove the six MSSQL tables from `SCCM_NODE_SPECS`; add the third emit pass in `_emit_split_graph`. |
| `tests/graph_edges_split_test.py` | Modify | Seed the six `node_mssql_*` tables + MSSQL/AD↔MSSQL/MSSQL↔SCCM edges; assert the three-way partition. |
| `tests/graph_edges_coercion_cols_test.py` | Modify | Seed six empty `node_mssql_*` tables so the split doesn't error; assert `graph_edges_mssql` carries the coercion columns. |
| `tests/edge_mssql_structural_test.py` | Modify | Flip the routing assertion: `MSSQL_Contains` now lands in `graph_edges_mssql`; add an assertion that `SCCM_AssignAllPermissions` stays in `graph_edges_sccm`. |
| `tests/mssql_models_test.py` | Modify | Replace `test_sccm_node_specs_include_mssql_tables` with one asserting the six tables are in `MSSQL_NODE_SPECS` and **absent** from `SCCM_NODE_SPECS`. |
| `tests/convert_split_output_test.py` | Modify | Extend the emit test to three payloads: seed a `node_mssql_server` row + a both-MSSQL `graph_edges_mssql` edge; assert `mssql_*.json` files carry `source_kind="MSSQL"` and hold the MSSQL node/edge. |
| `README.md` | Modify | Update the output-files table, the Graph Model payload table + mermaid, the Limitations note, and the Node/Edge Reference payload notes. |
| `ARCHITECTURE.md` | Modify | Update §11f (two→three payloads, new `_graph_edges_split` description), §11g "Output routing", §11h relay note, the quick-reference row, and add a changelog entry. |

**Task ordering:** Task 1 (preproc split) must land before Task 2's full-suite regression (the emit pass reads `graph_edges_mssql`). Each task is independently unit-testable because the emit test seeds `graph_edges_mssql` directly. Task 3 (docs) is last and has no code dependency.

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

### Task 3: Documentation — README + ARCHITECTURE

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`

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

- [ ] **Step 6: Doc-truth verification**

Confirm the docs match the shipped code:
- README's three file-name patterns (`sccm_*` / `mssql_*` / `ad_*`) match the `resource_prefix` values in `_emit_split_graph`.
- README's per-payload node lists match `SCCM_NODE_SPECS` / `MSSQL_NODE_SPECS` / `AD_NODE_SPECS`.
- README's both-MSSQL vs AD-touching vs MSSQL↔SCCM edge lists match the endpoints in `transforms._edge_mssql_*` and `_edge_mssql_db_assign_all`.
- ARCHITECTURE §11f/§11g code references (`_graph_edges_split`, `graph_edges_mssql`, `_mssql_ids`, `MSSQL_NODE_SPECS`, `MSSQL_EDGE_SPECS`, `MSSQL_SOURCE_KIND`, `_emit_split_graph`) all exist in the code.

Run: `uv run pytest tests\ -q`
Expected: PASS (final full-suite confirmation that documented behavior holds).

- [ ] **Step 7: Ticket close-out**

Move the `gtk` ticket to done and regenerate `TICKETS-BY-STATUS.md` from `gtk list`.

---

## Self-Review

**Spec coverage**

- ✅ MSSQL nodes → their own file with `source_kind="MSSQL"`: `MSSQL_NODE_SPECS` + MSSQL emit pass (Task 2).
- ✅ Edges where MSSQL nodes are **both** source and destination → MSSQL file: `graph_edges_mssql` (both endpoints in `_mssql_ids`, not AD-touching) + `MSSQL_EDGE_SPECS` (Tasks 1, 2).
- ✅ AD↔MSSQL edges stay in `ad_*.json`: AD rule keeps top precedence; unchanged (Task 1).
- ✅ SCCM↔MSSQL edges stay in `sccm_*.json`: they are not both-MSSQL, so they fall to `graph_edges_sccm` — verified with `SCCM_AssignAllPermissions` in Tasks 1 and 2 tests.
- ✅ File basenames `mssql_nodes-*.json` / `mssql_edges-*.json`: `resource_prefix="mssql"` (Task 2).
- ✅ `source_kind="MSSQL"` matches `schema_MSSQL.json`: `MSSQL_SOURCE_KIND` constant (Task 2).
- ✅ Docs updated (README output/Graph Model/Node+Edge Reference/mermaid; ARCHITECTURE §11f/§11g/§11h/quick-ref/changelog): Task 3.
- ✅ Only this repo modified; `openhound/` and `openhound-collector-common/` untouched.
- ✅ Cleanup/summary unaffected: `_clean_previous_collection` removes whole artifact dirs and the run-all summary globs `*.json` — both prefix-agnostic, so no code change needed (verified during planning).

**Placeholder scan:** No `TBD`/`TODO`. Every code step shows full code; every doc step shows the exact replacement text or a precise locate-and-edit instruction with the target lines.

**Type consistency:** `emit_graph_from_duckdb(lookup, output_path, source_kind, node_specs, edge_specs, resource_prefix)` is called in Task 2's `_emit_split_graph` with `MSSQL_SOURCE_KIND` (a `str`), matching the existing `source_kind: str | None` parameter. Table name `graph_edges_mssql` is produced in Task 1 and consumed by `MSSQL_EDGE_SPECS` in Task 2. The six `node_mssql_*` id columns used to build `_mssql_ids` in Task 1 (`server_id`, `database_id`, `login_id`, `dbuser_id`, `role_id`, `role_id`) match the columns the edge builders already join on (`_edge_mssql_structural`/`_membership`/`_db_assign_all`). `MSSQL_NODE_SPECS` / `MSSQL_EDGE_SPECS` are defined in Task 2 and asserted by name in `mssql_models_test.py` (Task 2).

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
