# Design sketch: Computer nodes via multi-driver emit + preproc merge

**Date:** 2026-06-16
**Status:** **History — the spec is authoritative.** The chosen mechanism is **Convert2-Read-DB (a convert-time
`dlt.pipeline` reading the coalesced DuckDB tables)**, per
[`../superpowers/specs/2026-06-16-sccm-preproc-convert-design.md`](../superpowers/specs/2026-06-16-sccm-preproc-convert-design.md)
§2 Decision #1; **writeback** is the documented fallback. This file is retained for the tradeoff
history only: **Approach A (multi-driver) was rejected on scale**, and the "Convert2-Read-DB" section here is an early
sketch of the now-chosen approach. Note one correction: this doc's earlier claim that Convert2-Read-DB had "no clean
story for the ~35 edge kinds" was an **error** — `graph_edges` is read from DuckDB exactly like the
node tables (see spec §2 "Edges" open point). Read the spec for the decision; read this for the history.
**Relates to:** [`2026-06-16-convert-read-from-duckdb.md`](./2026-06-16-convert-read-from-duckdb.md)

## Context

The SCCM collector assembles a single `Computer` node from several collected tables
(LDAP, AdminService `SMS_R_System`, WMI, RemoteRegistry, SMB, site-definition servers),
each keyed by AD SID. OpenHound's `convert` phase can only iterate JSONL files from the
collected-data bucket — it cannot iterate a DuckDB table built in `preproc` to emit one
node per row (see the related proposal for the core-level detail).

This document records the **no-core-change** approach recommended by the OpenHound
developer (Joey Dreijer): build a unified table in `preproc`, then emit Computer nodes
from each contributing JSONL table as a *driver*, enriching every emission from the
unified table via a single-row lookup. BloodHound merges the resulting duplicate nodes by
`ObjectIdentifier`.

This is the convert-time counterpart to the per-host collection design: the per-host
phase pipeline forces one table per source (phases run in order per target, and a DLT
resource closes once a target advances past it), so a Computer's properties are
necessarily spread across multiple tables. The merge + multi-driver emit reconciles them.

## What we would create

The prior preproc/convert layer was removed in HEAD (`6af5cc0 "Delete preproc/convert data"`),
so this is a rebuild of four pieces:

| File | Role |
|---|---|
| `transforms.py` (recreate) | preproc SQL: build the `computers_merged` mega-table, one row per SID |
| `lookup.py` (recreate) | `SCCMLookup.computer_by_sid(sid)` → the merged row as a dict |
| `models/computer.py` (new) | base `Computer(BaseAsset)` + thin per-source subclasses |
| `convert` command + convert source in `main.py` (recreate) | declares which driver table feeds which sub-model |

## Data flow

```
COLLECT (per-host pipeline)          PREPROC (DuckDB)              CONVERT (reads JSONL off disk)
─────────────────────────────       ──────────────────           ─────────────────────────────────────
adminservice_r_system  ─┐                                     ┌─ adminservice_r_system  → ComputerFromRSystem ─┐
remoteregistry_computers─┤  load    sccm.<each table>         │  remoteregistry_computers→ ComputerFromRegistry─┤
smb_computers           ─┼────────► ───────────────►  UNION   │  smb_computers           → ComputerFromSmb     ─┤
ldap_computers          ─┤          + GROUP BY sid   coalesce │  ldap_computers          → ComputerFromLdap    ─┤
*_site_definitions_comp ─┘             │                      │                                                 │
                                       ▼                      │   each as_node:                                 ▼
                                 computers_merged ◄───────────┘   row.sid → lookup → SAME full node ──► BloodHound
                                 (1 row per SID)    computer_by_sid(sid)                                merge by id
```

The left two columns happen in separate CLI runs. `convert` only ever touches the JSONL on
disk plus the `computers_merged` table via the lookup connection.

## 1. preproc — `transforms.py` builds the mega-table

```python
# transforms.py  (illustrative)
def _merge_computers(con, schema="sccm"):
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.computers_merged AS
        WITH unioned AS (
            -- normalize every source to a common shape, then stack
            SELECT sid, name, NULL  AS dnshostname, resource_id,
                   []  AS site_system_roles, FALSE AS sccm_infra
            FROM {schema}.adminservice_r_system
            UNION ALL BY NAME
            SELECT object_sid AS sid, name, dnshostname, NULL,
                   string_split(sccm_site_system_roles, ',') , sccm_infra
            FROM {schema}.remoteregistry_computers
            UNION ALL BY NAME
            SELECT object_sid AS sid, name, dnshostname, NULL, [], FALSE
            FROM {schema}.smb_computers
            -- ... ldap_computers, *_site_definitions_computers, wmi_* ...
        )
        SELECT
            sid,
            any_value(name)        AS name,          -- coalesce scalars
            any_value(dnshostname) AS dnshostname,
            max(resource_id)       AS resource_id,
            list_distinct(flatten(list(site_system_roles))) AS site_system_roles,  -- union arrays
            bool_or(sccm_infra)    AS sccm_infra
        FROM unioned
        WHERE sid IS NOT NULL
        GROUP BY sid
    """)

def transforms(con, schema="sccm"):
    _merge_computers(con, schema)
```

This is the in-DuckDB equivalent of CMBP's in-memory `Upsert-Node` merge: scalars coalesce,
array properties (site-system roles, resource IDs) union. One row per SID comes out.

## 2. lookup — single-row fetch by SID

```python
# lookup.py  (illustrative)
from functools import lru_cache
from openhound.core.lookup import LookupManager

class SCCMLookup(LookupManager):
    @lru_cache
    def computer_by_sid(self, sid: str) -> dict | None:
        cur = self.client.execute(
            f"SELECT * FROM {self.schema}.computers_merged WHERE sid = ?", [sid]
        )
        row = cur.fetchone()
        if row is None:
            return None
        return dict(zip([c[0] for c in cur.description], row))  # column-named dict
```

`_find_single_object` only returns one column; we want the whole merged row, so this is a
thin custom method on top of the shared lookup connection.

## 3. convert — one base class, thin per-source subclasses

```python
# models/computer.py  (illustrative)
from openhound.core.asset import BaseAsset
from ..kinds import nodes as nk

class Computer(BaseAsset):
    """All Computer node/edge logic lives here. Subclasses only differ by which
    driver table feeds them; every subclass produces the SAME node."""
    object_sid: str | None = None
    name: str | None = None

    @property
    def _sid(self) -> str | None:
        return (self.object_sid or "").upper() or None

    @property
    def as_node(self):
        sid = self._sid
        if not sid:
            return None                               # SID-less handling = open question
        merged = self._lookup.computer_by_sid(sid)    # full merged props, identical for all subclasses
        if not merged:
            return None
        return Node(
            id=sid,
            kinds=[nk.COMPUTER, nk.BASE],
            properties={
                "name": merged["name"],
                "dnshostname": merged["dnshostname"],
                "sccm_site_system_roles": merged["site_system_roles"],
                "sccm_infra": merged["sccm_infra"],
                # ...
            },
        )

    @property
    def edges(self):
        return iter(())   # computer→site/collection edges added later

# ── per-source subclasses: unique model name, identical node ──
@app.asset(node=COMPUTER_NODE, edges=[])
class ComputerFromRSystem(Computer):  ...

@app.asset(node=COMPUTER_NODE, edges=[])
class ComputerFromRegistry(Computer): ...

@app.asset(node=COMPUTER_NODE, edges=[])
class ComputerFromSmb(Computer):      ...
```

Each subclass is empty — it just gives the framework a uniquely-named asset to register and
a distinct driver binding. All the logic stays in the base.

## 4. The key mechanic — how a model binds to a driver table

The convert command returns a **thin, declarative convert source** — one `dlt.resource` per
driver table, each with `table_name` set to the on-disk table and `columns=` set to the
sub-model:

```python
# main.py  (illustrative)
@app.source(name="sccm_convert")
def convert_source():
    yield dlt.resource([], name="r_system_driver",
                       table_name="adminservice_r_system", columns=ComputerFromRSystem)
    yield dlt.resource([], name="registry_driver",
                       table_name="remoteregistry_computers", columns=ComputerFromRegistry)
    yield dlt.resource([], name="smb_driver",
                       table_name="smb_computers", columns=ComputerFromSmb)
    # ...

@app.convert(lookup=SCCMLookup)
def convert(ctx: ConvertContext):
    return convert_source(), {}
```

`Converter.run` reads this source **only** to learn each model's `table_name` (via
`resource.validator.model`) — it never executes the resources' generators, so the empty `[]`
bodies are fine. The actual rows are streamed off disk from `sccm/<table_name>/*.jsonl.gz`.
This convert source is therefore *metadata only*, completely separate from the per-host
collection source and its streams.

> **Note — the binding mechanism.** `columns=<Model>` does double duty: at collect time it is
> a schema contract/validator; at convert time `validator.model` is the hook the framework
> uses to map "this Pydantic model" → "this on-disk table." There is no separate registry.
> Because the convert source's generators never run, drivers can be declared as one-liners —
> the weight of convert is entirely in `as_node`/`edges` + the lookup.

## Why the duplicate emissions are safe

If a computer (SID `S-1-5-…-1104`) was seen by AdminService, RemoteRegistry, and SMB, then
`ComputerFromRSystem`, `ComputerFromRegistry`, and `ComputerFromSmb` each emit a node with
`id = S-1-5-…-1104`. But each one calls the *same* `computer_by_sid` and builds the *same*
properties from `computers_merged` — so the three nodes are byte-identical. BloodHound's
ingest merges nodes by `ObjectIdentifier`, collapsing them to one. The redundancy costs a few
extra JSON objects on disk; it cannot produce conflicting data, because no emitter uses its
own sparse row — they all read the single merged row.

## Alternative: side pipeline over the mega-table (fallback, not chosen)

The OpenHound developer offered a second option for "anything you can't generate from the
resources themselves": inside the registered `@app.convert`, run a *separate* DLT pipeline
that reads the mega-table directly and writes nodes to the OpenGraph destination, bypassing
the framework's filesystem-only convert reader. The main convert pipeline still runs
afterward for everything else (edges, other node types). Computers would come out of the
side pipeline; the rest from the main one.

There are two forms, and only one is sane:

- **Literal form** — use `dlt.sources.sql_database` to read the DuckDB table. This pulls in
  SQLAlchemy + a DuckDB dialect (`duckdb-engine`) and a full reflection/extract cycle, just
  to read a DuckDB file we already hold an open read-only connection to. Unjustified weight;
  avoid.
- **Connection-reuse form (Convert2-Read-DB)** — skip `sql_database`; make the side pipeline's source a
  plain `@dlt.resource` that queries the mega-table through the lookup connection we already
  have. Same single-emission benefit, no new dependency. This is essentially the core
  proposal's `_duckdb_reader`, hand-rolled in the collector with no core change.

```python
# main.py  (illustrative — Convert2-Read-DB)
import dlt
from dataclasses import asdict
from openhound.destinations.opengraph.destination import opengraph_file
from openhound.sources.opengraph.entries import GraphContent

def _emit_computers_from_megatable(lookup, output_path):
    @dlt.resource(name="computer", columns=GraphContent)
    def computer_nodes():
        cur = lookup.client.cursor()        # independent cursor: do NOT clobber self._lookup calls
        cur.execute(f"SELECT * FROM {lookup.schema}.computers_merged")
        cols = [c[0] for c in cur.description]
        for row in cur.fetchall():
            obj = Computer(**dict(zip(cols, row)))
            obj._lookup = lookup
            node = obj.as_node
            if node:
                yield {"graph": {"content": asdict(node), "entity_type": "node"}}
            # edges similarly, if Computer.edges is non-empty
    dest = opengraph_file(output_path=str(output_path), source_kind=app.source_kind)
    pipeline = dlt.pipeline(
        pipeline_name="sccm_convert_computers", dataset_name=app.name, destination=dest,
    )
    pipeline.run(computer_nodes())

@app.convert(lookup=SCCMLookup)
def convert(ctx: ConvertContext):
    _emit_computers_from_megatable(ctx.lookup, ctx.output_path)   # side pipeline first
    return convert_source_without_computers(), {}                # main convert for the rest
```

### Why this was not chosen

1. **Framework fit.** It runs a second pipeline bolted inside the convert hook — the
   developer flagged this as a *temporary workaround*, not the supported pattern. The
   multi-driver approach uses only public, stable extension points.
2. **Two pipelines, one output directory.** Both the side pipeline and the main convert write
   OpenGraph files to the same `output_path`; their dataset/naming must be coordinated to
   avoid clobbering each other's load artifacts.
3. **Reimplements node-shaping.** It hand-rolls the row → `{"graph": {...}}` shaping that the
   framework's `generate_graph` transformer does, which can drift on an OpenHound upgrade.

### What it wins (acknowledged)

The `Computer` model is genuinely cleaner under Convert2-Read-DB: the row already *is* the merged row, so
`as_node` reads its own fields and needs no lookup for properties (the lookup is only for
cross-entity edges). And each computer is emitted exactly once — no reliance on
BloodHound's merge.

### Trigger to switch (Computer path only)

Adopt Convert2-Read-DB for the Computer path — and only the Computer path — if duplicate emission turns out
to actually hurt: e.g. a contributing table carries many near-duplicate rows per host so
emission volume explodes, or a future node type can't guarantee byte-identical copies and so
can't rely safely on merge-by-id.

## Open questions

1. **SID format consistency — RESOLVED.** Both sides carry the canonical `S-1-5-21-…` string,
   so the `GROUP BY sid` collapses the same computer correctly:
   - AD-resolved tables expose `object_sid` from `bytes_to_sid()` (`clients/ad.py:254-255`):
     `"S-" + "-".join(...)`, uppercase, decimal sub-authorities (no hex letters).
   - `adminservice_r_system` / `wmi_r_system` expose `sid` (snake-cased from SMS's `SID`
     column, `collectors/sms_rows.py:78`), passed through unchanged from `SMS_R_System.SID`,
     which SCCM stores as the same `S-1-5-…` string.

   Required handling in the merge SQL (reflected in the sketch above):
   - **Alias the differing column names** to one (`object_sid AS sid` for AD sources; `sid`
     directly for the r_system sources).
   - **Drop SMS obsolete duplicates** (`SMS_R_System` keeps obsolete records; `Obsolete` is in
     `RSYSTEM_COLUMNS`) and **NULL SIDs** (`WHERE sid IS NOT NULL`). NULL-SID rows fall to #2.
   - `upper(sid)` normalization is harmless insurance (SIDs carry no hex letters, so case is a
     non-issue in practice).

2. **SID-less rows (open).** Decide what to do with a host that was reached (e.g. via SMB) but
   never resolved to a SID in AD: drop it, or key the node on a deterministic fallback id
   derived from `dNSHostName`/`name`. To be decided against CMBP's actual behavior.
