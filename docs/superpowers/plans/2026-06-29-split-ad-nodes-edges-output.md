# Split AD Nodes/Edges into a Separate Untagged OpenGraph File — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `convert` write two OpenGraph payloads into the same output directory — an SCCM-tagged set (`sccm_*`, `source_kind="SCCM"`) and an AD set (`ad_*`, **no `metadata` block at all**) — so BloodHound merges the AD `Computer`/`User`/`Group`/stub nodes (and every edge touching one) into its native AD graph instead of registering them under the SCCM source.

**Architecture:** Node routing is free — the coalesced `node_*` tables are already segregated by type, so we just partition the convert spec lists. Edge routing is one new preproc step (`_graph_edges_split`) that runs *after* `node_backfill` and splits the single `graph_edges` table into `graph_edges_ad` (either endpoint is an AD node id, including backfill-stub ids) and `graph_edges_sccm` (both endpoints SCCM). Convert then runs two emit passes; the AD pass uses a new extension-local dlt destination that mirrors core's `opengraph_file` but omits the `metadata` block (core requires a `source_kind` and can't express "no metadata", and core is off-limits).

**Tech Stack:** Python 3, DuckDB SQL (preproc transforms), `dlt` (resources + custom destination), `dataclasses`, `pytest`.

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Never edit anything under `openhound/` or any `.venv` (OpenHound core is off-limits per CLAUDE.md). The "no metadata" writer is therefore an extension-local destination, not a core change.
- **Do not `git add` or commit anything.** Each task ends when its tests pass; the user (Meatbag) commits after testing. (This overrides the writing-plans skill's "Commit" step.)
- **AD payload shape is exactly** `{"graph": {"nodes": [...], "edges": [...]}}` — **no `metadata` key** (confirmed decision: BloodHound treats these as native AD nodes).
- **SCCM payload keeps** `"metadata": {"source_kind": "SCCM"}` via core's unchanged `opengraph_file`.
- **AD node set** = `node_computer`, `node_user`, `node_group`, `node_backfill` (every backfill stub — including bare-`Base` — is an unresolved AD principal). **SCCM node set** = `node_site`, `node_collection`, `node_security_role`, `node_admin_user`, `node_client_device`.
- **Edge routing rule:** an edge goes to the AD payload iff **either** endpoint id is an AD node id; otherwise it stays in the SCCM payload.
- **Property casing stays CMBP-verbatim** — this change moves nodes/edges between files, it does not rename or restructure any property.
- **Always-on:** no CLI flag. The split is the new default output shape.
- **Tests live under `sccm/sccm/tests/`** and are named `*_test.py` (house convention; existing files use that suffix).
- **Logging:** the new preproc step logs an INFO line with the AD/SCCM edge counts; the new destination logs a DEBUG line per file written.
- **Preserve intent in comments**; do not annotate "ported from line X".

---

## File Structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `sccm/sccm/src/openhound_sccm/transforms.py` | Modify | Add `_graph_edges_split(con, schema)`; call it last in `transforms()`. |
| `sccm/sccm/src/openhound_sccm/opengraph_untagged.py` | Create | Extension-local dlt destination `opengraph_file_untagged` — writes `{"graph": {...}}` with no `metadata`. |
| `sccm/sccm/src/openhound_sccm/convert_pipeline.py` | Modify | `emit_graph_from_duckdb` gains `resource_prefix` and treats `source_kind=None` as "use the untagged destination". |
| `sccm/sccm/src/openhound_sccm/main.py` | Modify | Replace `NODE_SPECS`/`EDGE_SPECS` with `SCCM_NODE_SPECS`/`AD_NODE_SPECS`/`SCCM_EDGE_SPECS`/`AD_EDGE_SPECS`; add `_emit_split_graph`; two-pass `convert`. |
| `sccm/sccm/tests/graph_edges_split_test.py` | Create | Unit-test the preproc partition. |
| `sccm/sccm/tests/convert_untagged_emit_test.py` | Create | Unit-test the untagged destination + `resource_prefix` via `emit_graph_from_duckdb`. |
| `sccm/sccm/tests/convert_split_output_test.py` | Create | Integration-test `_emit_split_graph`: two file sets, AD untagged, SCCM tagged, correct node partition. |
| `sccm/sccm/README.md` | Modify | Document the two-file output and ingestion. |
| `sccm/sccm/ARCHITECTURE.md` | Modify | New §11f divergence section + quick-reference row + changelog entry. |

---

### Task 1: Preproc edge split (`_graph_edges_split`)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add function near `_graph_edges_dedup` / `_node_backfill` ~line 2478; call it at the end of `transforms()` ~line 2570)
- Test: `sccm/sccm/tests/graph_edges_split_test.py`

**Interfaces:**
- Consumes: tables `node_computer(sid)`, `node_user(sid)`, `node_group(sid)`, `node_backfill(id)`, `graph_edges(start_id, end_id, kind, collection_source VARCHAR[])` — all guaranteed to exist by the time `transforms()` reaches this step (their builders all use `CREATE OR REPLACE TABLE`).
- Produces: tables `graph_edges_ad` and `graph_edges_sccm`, each with the same four columns as `graph_edges`. Together they are a complete, disjoint partition of `graph_edges`. These table names are read by `AD_EDGE_SPECS` / `SCCM_EDGE_SPECS` in Task 3.

- [ ] **Step 1: Write the failing test**

Create `sccm/sccm/tests/graph_edges_split_test.py`:

```python
import duckdb
from openhound_sccm.transforms import _graph_edges_split


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # Minimal AD node tables — _graph_edges_split only reads the id columns.
    con.execute("CREATE TABLE sccm.node_computer AS SELECT 'S-1-5-21-1-2-3-1104' AS sid")
    con.execute("CREATE TABLE sccm.node_user     AS SELECT 'S-1-5-21-1-2-3-1110' AS sid")
    con.execute("CREATE TABLE sccm.node_group     AS SELECT 'S-1-5-21-1-2-3-512'  AS sid")
    # A bare-Base backfill stub (ambiguous AD principal) — its id must count as AD.
    con.execute("CREATE TABLE sccm.node_backfill  AS SELECT 'S-1-5-21-1-2-3-9999' AS id, 'Base' AS kind")
    con.execute(
        "CREATE TABLE sccm.graph_edges "
        "(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[])"
    )
    con.execute(
        "INSERT INTO sccm.graph_edges VALUES "
        # AD<->AD: computer -> user
        "('S-1-5-21-1-2-3-1104','S-1-5-21-1-2-3-1110','HasSession', ['x']), "
        # AD<->SCCM: client device (SCCM) -> user (AD)  => touches AD
        "('GUID:dev1','S-1-5-21-1-2-3-1110','SCCM_HasPrimaryUser', ['x']), "
        # SCCM<->SCCM: site -> site
        "('PS1','CAS','SCCM_Contains', ['x']), "
        # SCCM<->stub: site -> bare-Base stub (AD principal) => touches AD
        "('PS1','S-1-5-21-1-2-3-9999','SCCM_HasStoredAccount', ['x']), "
        # SCCM<->SCCM: site -> client device (neither is AD)
        "('PS1','GUID:dev1','SCCM_HasClient', ['x'])"
    )


def test_split_routes_ad_touching_edges_to_ad_table():
    con = duckdb.connect(":memory:")
    _seed(con)
    _graph_edges_split(con, "sccm")

    ad = set(con.execute(
        "SELECT start_id || '->' || end_id FROM sccm.graph_edges_ad"
    ).fetchall().__iter__().__next__() and  # placeholder; replaced below
        [])  # noqa


def test_split_partitions_completely_and_disjointly():
    con = duckdb.connect(":memory:")
    _seed(con)
    _graph_edges_split(con, "sccm")

    ad = {r[0] for r in con.execute(
        "SELECT start_id || '|' || end_id || '|' || kind FROM sccm.graph_edges_ad").fetchall()}
    sccm = {r[0] for r in con.execute(
        "SELECT start_id || '|' || end_id || '|' || kind FROM sccm.graph_edges_sccm").fetchall()}

    # AD-touching edges: the two endpoints-in-AD cases + the stub case.
    assert ad == {
        "S-1-5-21-1-2-3-1104|S-1-5-21-1-2-3-1110|HasSession",
        "GUID:dev1|S-1-5-21-1-2-3-1110|SCCM_HasPrimaryUser",
        "PS1|S-1-5-21-1-2-3-9999|SCCM_HasStoredAccount",
    }
    # SCCM-only edges: both ends are SCCM nodes.
    assert sccm == {
        "PS1|CAS|SCCM_Contains",
        "PS1|GUID:dev1|SCCM_HasClient",
    }
    # Complete + disjoint partition of the 5 original edges.
    assert len(ad) + len(sccm) == 5
    assert ad.isdisjoint(sccm)
```

> Note: delete the malformed `test_split_routes_ad_touching_edges_to_ad_table` stub above before Step 3 — it was scaffolding; `test_split_partitions_completely_and_disjointly` is the real assertion. (Keeping this note so a reviewer reading out of order doesn't reintroduce it.)

Replace the file's body with just the `_seed` helper and `test_split_partitions_completely_and_disjointly`:

```python
import duckdb
from openhound_sccm.transforms import _graph_edges_split


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.node_computer AS SELECT 'S-1-5-21-1-2-3-1104' AS sid")
    con.execute("CREATE TABLE sccm.node_user     AS SELECT 'S-1-5-21-1-2-3-1110' AS sid")
    con.execute("CREATE TABLE sccm.node_group     AS SELECT 'S-1-5-21-1-2-3-512'  AS sid")
    con.execute("CREATE TABLE sccm.node_backfill  AS SELECT 'S-1-5-21-1-2-3-9999' AS id, 'Base' AS kind")
    con.execute(
        "CREATE TABLE sccm.graph_edges "
        "(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[])"
    )
    con.execute(
        "INSERT INTO sccm.graph_edges VALUES "
        "('S-1-5-21-1-2-3-1104','S-1-5-21-1-2-3-1110','HasSession', ['x']), "
        "('GUID:dev1','S-1-5-21-1-2-3-1110','SCCM_HasPrimaryUser', ['x']), "
        "('PS1','CAS','SCCM_Contains', ['x']), "
        "('PS1','S-1-5-21-1-2-3-9999','SCCM_HasStoredAccount', ['x']), "
        "('PS1','GUID:dev1','SCCM_HasClient', ['x'])"
    )


def test_split_partitions_completely_and_disjointly():
    con = duckdb.connect(":memory:")
    _seed(con)
    _graph_edges_split(con, "sccm")

    ad = {r[0] for r in con.execute(
        "SELECT start_id || '|' || end_id || '|' || kind FROM sccm.graph_edges_ad").fetchall()}
    sccm = {r[0] for r in con.execute(
        "SELECT start_id || '|' || end_id || '|' || kind FROM sccm.graph_edges_sccm").fetchall()}

    assert ad == {
        "S-1-5-21-1-2-3-1104|S-1-5-21-1-2-3-1110|HasSession",
        "GUID:dev1|S-1-5-21-1-2-3-1110|SCCM_HasPrimaryUser",
        "PS1|S-1-5-21-1-2-3-9999|SCCM_HasStoredAccount",
    }
    assert sccm == {
        "PS1|CAS|SCCM_Contains",
        "PS1|GUID:dev1|SCCM_HasClient",
    }
    assert len(ad) + len(sccm) == 5
    assert ad.isdisjoint(sccm)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sccm/sccm && uv run pytest tests/graph_edges_split_test.py -v`
Expected: FAIL with `ImportError: cannot import name '_graph_edges_split'`.

- [ ] **Step 3: Add `_graph_edges_split` to `transforms.py`**

Insert this function immediately after `_node_backfill` (after ~line 2507, before `def transforms`):

```python
def _graph_edges_split(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Partition graph_edges into an AD-touching set and an SCCM-only set.

    An edge belongs to the AD payload when EITHER endpoint is an AD node id: a
    Computer/User/Group coalesce row, or a backfill stub (every backfill stub is an
    unresolved AD principal, including the bare-'Base' ones). The AD payload is emitted to
    the untagged ad_* OpenGraph files (no source_kind) so BloodHound merges those nodes and
    relationships into its native AD graph. Every other edge has both ends in the SCCM_*
    node space and stays in the SCCM-tagged payload.

    Runs LAST, after _node_backfill, so the AD id set includes the stub ids minted there.
    Reads graph_edges without mutating it (node_backfill has already consumed it). EXISTS /
    NOT EXISTS make the two output tables an exact complement, NULL-safe even for a malformed
    edge with a NULL endpoint (it falls to the SCCM-only side deterministically).
    """
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _ad_ids AS "
        f"SELECT sid AS id FROM {schema}.node_computer WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_user WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_group WHERE sid IS NOT NULL "
        f"UNION SELECT id FROM {schema}.node_backfill WHERE id IS NOT NULL"
    )
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges_ad AS "
        f"SELECT e.start_id, e.end_id, e.kind, e.collection_source "
        f"FROM {schema}.graph_edges e "
        f"WHERE EXISTS (SELECT 1 FROM _ad_ids a WHERE a.id = e.start_id) "
        f"   OR EXISTS (SELECT 1 FROM _ad_ids a WHERE a.id = e.end_id)"
    )
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges_sccm AS "
        f"SELECT e.start_id, e.end_id, e.kind, e.collection_source "
        f"FROM {schema}.graph_edges e "
        f"WHERE NOT EXISTS (SELECT 1 FROM _ad_ids a WHERE a.id = e.start_id) "
        f"  AND NOT EXISTS (SELECT 1 FROM _ad_ids a WHERE a.id = e.end_id)"
    )
    ad_cnt = con.execute(f"SELECT count(*) FROM {schema}.graph_edges_ad").fetchone()[0]
    sccm_cnt = con.execute(f"SELECT count(*) FROM {schema}.graph_edges_sccm").fetchone()[0]
    logger.info("graph_edges split: %d AD-touching, %d SCCM-only", ad_cnt, sccm_cnt)
```

Then add the call as the **last** line of `transforms()` (after `_node_backfill(con, schema)`):

```python
    _node_backfill(con, schema)
    # Split the finalised graph_edges into the AD payload (either endpoint is an AD node id,
    # including the backfill stubs minted just above) and the SCCM-only payload. Must run
    # after _node_backfill so stub ids are in the AD id set. See ARCHITECTURE.md §11f.
    _graph_edges_split(con, schema)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sccm/sccm && uv run pytest tests/graph_edges_split_test.py -v`
Expected: PASS (1 test).

- [ ] **Step 5: Regression — run the existing edge/preproc tests**

Run: `cd sccm/sccm && uv run pytest tests/graph_edges_test.py tests/graph_edges_dedup_test.py tests/graph_edge_test.py -v`
Expected: PASS (the new step only adds tables; it does not touch `graph_edges`, `node_backfill`, or any existing table).

---

### Task 2: Untagged destination + parameterized `emit_graph_from_duckdb`

**Files:**
- Create: `sccm/sccm/src/openhound_sccm/opengraph_untagged.py`
- Modify: `sccm/sccm/src/openhound_sccm/convert_pipeline.py`
- Test: `sccm/sccm/tests/convert_untagged_emit_test.py`

**Interfaces:**
- Produces: `opengraph_file_untagged(output_path: str)` — a `@dlt.destination` writing `{"graph": {"nodes": [...], "edges": [...]}}` files named `<table_name>-<part>.json`, no `metadata` block.
- Produces: `emit_graph_from_duckdb(lookup, output_path, source_kind, node_specs=None, edge_specs=None, resource_prefix="sccm")` — when `source_kind is None`, emits via `opengraph_file_untagged`; otherwise via core `opengraph_file(source_kind=source_kind)`. `resource_prefix` sets the dlt resource names (`<prefix>_nodes`, `<prefix>_edges`), which become the output file basenames, and the dlt pipeline name. Consumed by `_emit_split_graph` in Task 3.

- [ ] **Step 1: Write the failing test**

Create `sccm/sccm/tests/convert_untagged_emit_test.py`:

```python
import json
import duckdb
from openhound_sccm.lookup import SCCMLookup
from openhound_sccm.convert_pipeline import emit_graph_from_duckdb
from openhound_sccm.models.computer import ComputerNode


def _db_with_computer(tmp_path):
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'HOST1' AS name, 'host1.lab' AS dnshostname, "
        "'HOST1$' AS sam_account_name, ['SMS Provider'] AS site_system_roles, "
        "['7@PS1'] AS resource_ids, true AS sccm_infra, 'GUID:abc' AS sms_unique_identifier, "
        "true AS smb_signing_required, false AS sccm_has_client_remote_control_spn, "
        "false AS network_boot_server, NULL AS disable_loopback_check, "
        "NULL AS restrict_receiving_ntlm_traffic, NULL AS sccm_client_certificate_required, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    con.close()
    return str(path)


def test_untagged_emit_writes_no_metadata_and_ad_prefix(tmp_path):
    """source_kind=None must write files with NO metadata key, named by resource_prefix."""
    client = duckdb.connect(_db_with_computer(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"

    emit_graph_from_duckdb(
        lookup, out, None,
        node_specs=[("node_computer", ComputerNode)], edge_specs=[],
        resource_prefix="ad",
    )

    files = list(out.glob("*.json"))
    assert files, "expected at least one output file"
    # Every file uses the ad_ prefix and carries no metadata block.
    for f in files:
        assert f.name.startswith("ad_"), f"unexpected file name {f.name}"
        doc = json.loads(f.read_text())
        assert "graph" in doc
        assert "metadata" not in doc, f"AD payload must have no metadata: {f.name}"


def test_tagged_emit_still_writes_source_kind(tmp_path):
    """A real source_kind still routes through core's writer and stamps metadata."""
    client = duckdb.connect(_db_with_computer(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"

    emit_graph_from_duckdb(
        lookup, out, "SCCM",
        node_specs=[("node_computer", ComputerNode)], edge_specs=[],
        resource_prefix="sccm",
    )

    docs = [json.loads(f.read_text()) for f in out.glob("sccm_*.json")]
    assert docs, "expected sccm_-prefixed output"
    assert all(d["metadata"]["source_kind"] == "SCCM" for d in docs)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sccm/sccm && uv run pytest tests/convert_untagged_emit_test.py -v`
Expected: FAIL — `resource_prefix` is an unexpected keyword argument, and `source_kind=None` currently crashes core's writer (requires a value).

- [ ] **Step 3a: Create the untagged destination module**

Create `sccm/sccm/src/openhound_sccm/opengraph_untagged.py`:

```python
"""Convert-time OpenGraph file destination that writes NO `metadata` block.

Core's `opengraph_file` (openhound.destinations.opengraph.destination) always writes
`{"graph": {...}, "metadata": {"source_kind": ...}}` and requires a `source_kind`. The AD
payload must carry no `source_kind` at all — a file with no `metadata` block — so BloodHound
merges its Computer/User/Group/stub nodes into the native AD graph (and existing SharpHound
data) instead of registering them under a custom SCCM source. Core is off-limits, so the
extension ships this sibling writer. It is identical to core's writer except the `metadata`
block is omitted entirely. See ARCHITECTURE.md §11f.
"""
import logging
from collections import defaultdict
from pathlib import Path

import dlt
from dlt.common import json
from dlt.common.schema import TTableSchema
from dlt.common.typing import TDataItems

logger = logging.getLogger(__name__)

# Per-table file-part counter, mirroring core's DEST_PART. Module-global so repeated
# pipeline.run() calls in one process keep numbering files uniquely.
_DEST_PART: defaultdict[str, int] = defaultdict(int)


@dlt.destination(skip_dlt_columns_and_tables=True, batch_size=1000)
def opengraph_file_untagged(
    items: TDataItems,
    table: TTableSchema,
    output_path: str = dlt.config.value,
):
    table_name = table.get("name") or "opengraph"
    _DEST_PART[table_name] += 1

    nodes = []
    edges = []
    for item in items:
        if item["graph"]["entity_type"] == "node":
            nodes.append(item["graph"]["content"])
        if item["graph"]["entity_type"] == "edge":
            edges.extend(item["graph"]["content"])

    file_name = f"{table_name}-{_DEST_PART[table_name]}.json"
    file_path = Path(output_path) / file_name
    with file_path.open("w", encoding="utf-8") as fh:
        # No "metadata" block: BloodHound treats these nodes as native AD objects.
        fh.write(json.dumps({"graph": {"nodes": nodes, "edges": edges}}))
    logger.debug(
        "Wrote untagged OpenGraph file %s (%d nodes, %d edges)",
        file_path, len(nodes), len(edges),
    )
```

- [ ] **Step 3b: Parameterize `emit_graph_from_duckdb`**

In `sccm/sccm/src/openhound_sccm/convert_pipeline.py`, add the import below the existing core-destination import:

```python
from openhound.destinations.opengraph.destination import opengraph_file

from .lookup import SCCMLookup
from .opengraph_untagged import opengraph_file_untagged
```

Change the signature and docstring of `emit_graph_from_duckdb` (currently line ~46):

```python
def emit_graph_from_duckdb(
    lookup: SCCMLookup,
    output_path,
    source_kind: str | None,
    node_specs: list[tuple[str, type]] | None = None,
    edge_specs: list[tuple[str, type]] | None = None,
    resource_prefix: str = "sccm",
) -> None:
    """Read node/edge tables from the lookup DuckDB and write OpenGraph JSON to output_path.

    node_specs and edge_specs are lists of (table_name, ModelClass) pairs. For each row in
    each table, the model is instantiated with the row dict, given access to the lookup, and
    its as_node / edges properties are called to produce OpenGraph content.

    source_kind controls the writer: a string routes through core's opengraph_file, which
    stamps {"metadata": {"source_kind": ...}}; None routes through opengraph_file_untagged,
    which writes no metadata block at all (the AD payload, merged natively by BloodHound).

    resource_prefix names the two dlt resources (<prefix>_nodes / <prefix>_edges), which
    become the output file basenames, and the dlt pipeline — so two passes into the same
    output directory never collide.

    Passing empty lists for both specs produces an empty but valid OpenGraph output.
    """
```

Update the two `@dlt.resource` names to use the prefix:

```python
    @dlt.resource(name=f"{resource_prefix}_nodes")
    def nodes():
        ...

    @dlt.resource(name=f"{resource_prefix}_edges")
    def edges():
        ...
```

Replace the pipeline/destination construction at the bottom of the function:

```python
    destination = (
        opengraph_file_untagged(output_path=str(out))
        if source_kind is None
        else opengraph_file(output_path=str(out), source_kind=source_kind)
    )
    pipeline = dlt.pipeline(
        pipeline_name=f"sccm_convert_graph_{resource_prefix}",
        dataset_name="sccm",
        destination=destination,
    )
    pipeline.run([nodes(), edges()])
    kind_label = source_kind if source_kind is not None else "<untagged AD payload>"
    logger.info(
        "Convert2-Read-DB convert pipeline wrote OpenGraph files (prefix=%r, source_kind=%s) to %s",
        resource_prefix, kind_label, out,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sccm/sccm && uv run pytest tests/convert_untagged_emit_test.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Regression — existing convert-pipeline tests still pass**

Run: `cd sccm/sccm && uv run pytest tests/convert_pipeline_test.py -v`
Expected: PASS. Those tests call `emit_graph_from_duckdb(lookup, out, "Kind", node_specs=..., edge_specs=...)` — `source_kind="Kind"` is still a string (tagged path) and `resource_prefix` defaults to `"sccm"`, so behavior is unchanged.

---

### Task 3: Split convert specs + two-pass `convert`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (replace `NODE_SPECS`/`EDGE_SPECS` ~line 1181-1197; rewrite `convert` ~line 1200-1205; add `_emit_split_graph`)
- Test: `sccm/sccm/tests/convert_split_output_test.py`

**Interfaces:**
- Consumes: `emit_graph_from_duckdb(..., resource_prefix=...)` (Task 2); `_graph_edges_split`'s output tables `graph_edges_ad` / `graph_edges_sccm` (Task 1).
- Produces: module-level `SCCM_NODE_SPECS`, `AD_NODE_SPECS`, `SCCM_EDGE_SPECS`, `AD_EDGE_SPECS`, and `_emit_split_graph(lookup, output_path) -> None`. The latter runs the SCCM pass (`source_kind="SCCM"`, prefix `"sccm"`) then the AD pass (`source_kind=None`, prefix `"ad"`).

- [ ] **Step 1: Write the failing test**

Create `sccm/sccm/tests/convert_split_output_test.py`:

```python
import json
import duckdb
from openhound_sccm.lookup import SCCMLookup
from openhound_sccm.main import _emit_split_graph


def _seed_db(tmp_path):
    """A lookup DB with one SCCM node (node_site), one AD node (node_computer),
    and split edge tables already built (one AD-touching, one SCCM-only)."""
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")

    # AD node: node_computer (only the columns ComputerNode reads).
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'HOST1' AS name, 'host1.lab' AS dnshostname, "
        "'HOST1$' AS sam_account_name, ['SMS Provider'] AS site_system_roles, "
        "['7@PS1'] AS resource_ids, true AS sccm_infra, 'GUID:abc' AS sms_unique_identifier, "
        "true AS smb_signing_required, false AS sccm_has_client_remote_control_spn, "
        "false AS network_boot_server, NULL AS disable_loopback_check, "
        "NULL AS restrict_receiving_ntlm_traffic, NULL AS sccm_client_certificate_required, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    # SCCM node: node_site (only the columns SCCMSite reads to produce an id + kind).
    con.execute(
        "CREATE TABLE sccm.node_site AS SELECT "
        "'PS1' AS site_code, 'PS1' AS root_site_code, NULL AS parent_site_code, "
        "'Primary' AS site_type"
    )
    # Edge tables as produced by _graph_edges_split.
    for t in ("graph_edges_ad", "graph_edges_sccm"):
        con.execute(
            f"CREATE TABLE sccm.{t} "
            "(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[])"
        )
    con.execute(
        "INSERT INTO sccm.graph_edges_ad VALUES "
        "('PS1','S-1-5-21-1-2-3-1104','SCCM_HasStoredAccount', ['s'])"  # site -> computer (AD)
    )
    con.execute(
        "INSERT INTO sccm.graph_edges_sccm VALUES "
        "('PS1','CAS','SCCM_Contains', ['s'])"  # site -> site (SCCM only)
    )
    con.close()
    return str(path)


def _load(out, pattern):
    nodes, edges, docs = [], [], []
    for f in out.glob(pattern):
        doc = json.loads(f.read_text())
        docs.append((f.name, doc))
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]
    return nodes, edges, docs


def test_emit_split_writes_two_payloads(tmp_path):
    client = duckdb.connect(_seed_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"

    _emit_split_graph(lookup, out)

    sccm_nodes, sccm_edges, sccm_docs = _load(out, "sccm_*.json")
    ad_nodes, ad_edges, ad_docs = _load(out, "ad_*.json")

    # SCCM payload: the SCCM_Site node, the SCCM-only edge, source_kind stamped.
    assert any("SCCM_Site" in n["kinds"] for n in sccm_nodes)
    assert all("Computer" not in n["kinds"] for n in sccm_nodes)
    assert {e["kind"] for e in sccm_edges} == {"SCCM_Contains"}
    assert all(d["metadata"]["source_kind"] == "SCCM" for _, d in sccm_docs)

    # AD payload: the Computer node, the AD-touching edge, NO metadata block.
    assert any("Computer" in n["kinds"] for n in ad_nodes)
    assert all("SCCM_Site" not in n["kinds"] for n in ad_nodes)
    assert {e["kind"] for e in ad_edges} == {"SCCM_HasStoredAccount"}
    assert all("metadata" not in d for _, d in ad_docs)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sccm/sccm && uv run pytest tests/convert_split_output_test.py -v`
Expected: FAIL with `ImportError: cannot import name '_emit_split_graph'`.

- [ ] **Step 3: Replace the spec lists and `convert` in `main.py`**

Replace the `NODE_SPECS` / `EDGE_SPECS` block (lines ~1178-1197) with:

```python
# Registry of (table_name, ModelClass) pairs the convert pipeline iterates, split into the
# two OpenGraph payloads (ARCHITECTURE.md §11f):
#   - SCCM payload  -> source_kind="SCCM"  (custom SCCM_* kinds only)
#   - AD payload    -> NO source_kind      (native Computer/User/Group + backfill stubs;
#                                           BloodHound merges these into its AD graph)
SCCM_NODE_SPECS: list[tuple[str, type]] = [
    ("node_site", SCCMSite),
    ("node_collection", SCCMCollection),
    ("node_security_role", SCCMSecurityRole),
    ("node_admin_user", SCCMAdminUser),
    ("node_client_device", SCCMClientDevice),
]

AD_NODE_SPECS: list[tuple[str, type]] = [
    ("node_computer", ComputerNode),
    ("node_user", UserNode),
    ("node_group", GroupNode),
    # node_backfill is LAST so a real AD node wins any id overlap via append semantics.
    # Every backfill stub is an AD principal (User/Group/Computer or bare Base).
    ("node_backfill", StubNode),
]

# graph_edges_sccm / graph_edges_ad are the partition built by transforms._graph_edges_split.
SCCM_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_sccm", GraphEdge)]
AD_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_ad", GraphEdge)]
```

Replace the `convert` function (lines ~1200-1205) with a helper plus the thin entry point:

```python
def _emit_split_graph(lookup: SCCMLookup, output_path) -> None:
    """Emit the SCCM graph as two payloads into the same directory.

    The SCCM payload (sccm_* files) carries source_kind="SCCM"; the AD payload (ad_* files)
    carries no source_kind so BloodHound merges its Computer/User/Group/stub nodes and the
    edges touching them into the native AD graph. See ARCHITECTURE.md §11f.
    """
    emit_graph_from_duckdb(
        lookup, output_path, app.source_kind,
        SCCM_NODE_SPECS, SCCM_EDGE_SPECS, resource_prefix="sccm",
    )
    emit_graph_from_duckdb(
        lookup, output_path, None,
        AD_NODE_SPECS, AD_EDGE_SPECS, resource_prefix="ad",
    )


@app.convert(lookup=SCCMLookup)
def convert(ctx: ConvertContext):
    """Emit the SCCM graph by reading the preproc DuckDB directly (Convert2-Read-DB), as two
    payloads (SCCM-tagged + untagged AD), then hand the framework a no-op source."""
    _emit_split_graph(ctx.lookup, ctx.output_path)
    return _noop_convert_source(), {}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sccm/sccm && uv run pytest tests/convert_split_output_test.py -v`
Expected: PASS (1 test).

- [ ] **Step 5: Full regression + lint**

Run: `cd sccm/sccm && uv run pytest tests/ -q && uv run ruff check src/`
Expected: PASS. (If `mypy` is configured for the project, also run `uv run mypy src/openhound_sccm/convert_pipeline.py src/openhound_sccm/opengraph_untagged.py`; report it skipped if mypy isn't set up.)

---

### Task 4: Documentation — README + ARCHITECTURE.md

**Files:**
- Modify: `sccm/sccm/README.md` (Graph Model / output section near line 344-362, and the intro line 7 mention of "an OpenGraph dataset")
- Modify: `sccm/sccm/ARCHITECTURE.md` (new §11f, quick-reference table row ~line 855, changelog ~line 879, table of contents ~line 50)

No automated test; the deliverable is reviewed prose. Verify with the doc-truth checks in Step 3.

- [ ] **Step 1: Add the README output/ingestion subsection**

Under **Graph Model** in `sccm/sccm/README.md`, after the "Convert-time enrichment" paragraph (~line 362), add:

```markdown
**Two output payloads.** `convert` writes the graph as **two file sets** into the same output directory:

| Files | `metadata.source_kind` | Contents |
|---|---|---|
| `sccm_nodes-*.json`, `sccm_edges-*.json` | `"SCCM"` | SCCM-specific nodes (`SCCM_Site`, `SCCM_Collection`, `SCCM_AdminUser`, `SCCM_SecurityRole`, `SCCM_ClientDevice`) and edges where **both** endpoints are SCCM nodes. |
| `ad_nodes-*.json`, `ad_edges-*.json` | *(none — no `metadata` block)* | AD-native nodes (`Computer`, `User`, `Group`, and backfill stubs) and every edge where **either** endpoint is an AD node (AD↔AD and AD↔SCCM). |

The AD payload deliberately carries **no `source_kind`** so BloodHound merges those nodes into its **native AD graph** by SID — augmenting existing SharpHound data rather than registering a separate SCCM-owned copy. An AD↔SCCM edge lives in the AD payload but references an `SCCM_*` node defined in the SCCM payload; BloodHound resolves the reference by id across both files at ingest, so **upload both file sets** (the whole output directory) to File Ingest.
```

- [ ] **Step 2: Add ARCHITECTURE.md §11f, TOC entry, quick-reference row, and changelog entry**

In `sccm/sccm/ARCHITECTURE.md`:

(a) Table of contents — add under the §11 sub-bullets (~line 50, after the 11e line):

```markdown
  - [11f. Split output: an untagged AD payload beside the SCCM source](#11f-split-output-an-untagged-ad-payload-beside-the-sccm-source)
```

(b) New section — insert after §11e (before "Quick reference", ~line 838):

```markdown
### 11f. Split output: an untagged AD payload beside the SCCM source

*This is a new category of divergence from a stock OpenHound collector.*

#### The framework baseline

A stock collector emits one OpenGraph dataset under a single `source_kind`. Core's
`opengraph_file` destination takes `source_kind` as a required `dlt.config.value` and stamps
`{"metadata": {"source_kind": ...}}` into every file. There is no provision for emitting part
of the graph under a *different* source — or under *no* source at all.

#### Why it breaks for SCCM

The SCCM graph mixes two ownership domains. `SCCM_*` nodes are genuinely SCCM-owned and should
register under the `SCCM` source. But `Computer` / `User` / `Group` (and the backfill stubs) are
**Active Directory** objects — the same objects SharpHound collects. Tagging them with
`source_kind="SCCM"` makes the SCCM source *own* native AD nodes, so re-ingesting or deleting the
SCCM source would touch AD data it shouldn't. We want the AD nodes (and the edges touching them)
to merge into BloodHound's **native AD graph** by SID, augmenting SharpHound rather than shadowing
it — which means emitting them with **no `source_kind` at all**.

#### The add-on: a second emit pass + an untagged extension destination

- **Node routing is free.** The coalesced `node_*` tables are already segregated by type, so the
  convert spec list is just split into `SCCM_NODE_SPECS` (`node_site`/`collection`/`security_role`/
  `admin_user`/`client_device`) and `AD_NODE_SPECS` (`node_computer`/`user`/`group`/`backfill`) in
  [main.py](src/openhound_sccm/main.py).
- **Edge routing is one preproc step.** `transforms._graph_edges_split` runs *after*
  `_node_backfill` and partitions `graph_edges` into `graph_edges_ad` (either endpoint id is in
  `node_computer ∪ node_user ∪ node_group ∪ node_backfill`) and `graph_edges_sccm` (the EXISTS/NOT
  EXISTS complement). Every backfill stub id counts as AD, so the `SCCM_HasMember` /
  `SCCM_HasStoredAccount` edges to bare-`Base` principals follow their stub into the AD payload.
- **Two emit passes.** `_emit_split_graph` calls `emit_graph_from_duckdb` twice into the same
  directory: the SCCM pass (`source_kind="SCCM"`, `resource_prefix="sccm"`) through core's
  `opengraph_file`, and the AD pass (`source_kind=None`, `resource_prefix="ad"`) through the
  extension's [`opengraph_file_untagged`](src/openhound_sccm/opengraph_untagged.py) — a sibling of
  core's writer that omits the `metadata` block entirely. Distinct resource prefixes give distinct
  file basenames (`sccm_*` vs `ad_*`), so two pipelines writing to one directory never collide.

#### Trade-offs

- An AD↔SCCM edge lives in the untagged file but references an `SCCM_*` node defined in the tagged
  file; this is safe only because BloodHound resolves edge endpoints by id across all ingested
  files — so both file sets must be uploaded together.
- `opengraph_file_untagged` duplicates core's writer logic (a coupling to watch on OpenHound
  upgrades), because core's destination can't express "no metadata" and core is off-limits.
- `_graph_edges_split` must run after `node_backfill`; a future reordering of `transforms()` that
  breaks that would silently route stub-edges to the wrong file. Guarded by
  `graph_edges_split_test.py`.
```

(c) Quick-reference table — add a row (~line 855, after the stub-node backfill row):

```markdown
| Split output (untagged AD payload) | A second `convert`-time emit pass through an extension `opengraph_file_untagged` destination (no `metadata`); preproc `_graph_edges_split` partitions edges | A `source_kind=None` / multi-source option on `@app.convert` |
```

(d) Changelog — add a row at the top of the changelog table (~line 879):

```markdown
| 2026-06-29 | Split output shipped. Added §11f: `convert` now writes two payloads — the SCCM-tagged set (`sccm_*`, `source_kind="SCCM"`) and an untagged AD set (`ad_*`, no `metadata` block) for native AD-graph merge. New preproc step `transforms._graph_edges_split` partitions `graph_edges` into `graph_edges_ad` / `graph_edges_sccm`; new extension destination `opengraph_file_untagged`; `emit_graph_from_duckdb` gained `resource_prefix` + `source_kind=None` (untagged) handling; `NODE_SPECS`/`EDGE_SPECS` split into `SCCM_*`/`AD_*` spec lists. |
```

- [ ] **Step 3: Doc-truth verification**

Confirm the docs match the shipped code:
- README's two file-name patterns (`sccm_*` / `ad_*`) match `resource_prefix` values in `main.py`.
- README's node lists match `SCCM_NODE_SPECS` / `AD_NODE_SPECS`.
- ARCHITECTURE §11f code references (`_graph_edges_split`, `opengraph_file_untagged`, `_emit_split_graph`) all exist.

Run: `cd sccm/sccm && uv run pytest tests/ -q`
Expected: PASS (final full-suite confirmation that the documented behavior holds).

---

## Self-Review

**Spec coverage**

- ✅ AD nodes → separate file: `AD_NODE_SPECS` + AD emit pass (Task 3).
- ✅ Edges connecting AD↔SCCM or AD↔AD → separate file: `_graph_edges_split` → `graph_edges_ad` + `AD_EDGE_SPECS` (Tasks 1, 3).
- ✅ AD file has no `source_kind` (no `metadata` key): `opengraph_file_untagged` + `source_kind=None` (Task 2).
- ✅ SCCM file keeps `source_kind="SCCM"`: SCCM emit pass unchanged writer (Task 3).
- ✅ Bare-`Base` stubs treated as AD: included in `node_backfill` (AD specs) and the `_ad_ids` set (Task 1).
- ✅ Always-on (no flag): `convert` always runs both passes (Task 3).
- ✅ Same directory, `ad_*` / `sccm_*` prefixes: `resource_prefix` (Task 2).
- ✅ Docs (README + ARCHITECTURE): Task 4.
- ✅ Only `sccm/sccm/` modified; core untouched (untagged writer is extension-local).

**Placeholder scan:** No `TBD`/`TODO`. Every code step shows full code. (The deliberately-malformed scaffold in Task 1 Step 1 is called out and replaced within the same step.)

**Type consistency:** `emit_graph_from_duckdb(..., source_kind: str | None, ..., resource_prefix="sccm")` is defined in Task 2 and called with those exact params in Task 3's `_emit_split_graph`. Table names `graph_edges_ad` / `graph_edges_sccm` are produced in Task 1 and consumed in Task 3's `*_EDGE_SPECS`. `_emit_split_graph(lookup, output_path)` is defined in Task 3 and called with those args in `convert_split_output_test.py`.

---

## Execution Handoff

(Filled in by the orchestrator after you approve.)
