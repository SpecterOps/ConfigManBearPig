# Proposal: Let the `convert` phase read graph-resource rows from the preproc DuckDB

**To:** OpenHound core maintainer(s)
**From:** SCCM collector authors
**Date:** 2026-06-16
**Against:** `openhound` 0.2.1 (runtime package verified byte-identical to 0.1.4 for every file cited below — the convert/preproc/lookup/opengraph machinery did not change across v0.1.5 → v0.2.1; module paths map to the core repo's `src/openhound/...`)
**Status:** Proposal / request for guidance before we implement a workaround

---

## TL;DR

`convert` can only iterate **JSONL files from the collected-data bucket**. Tables that `preproc`
builds in DuckDB are reachable **only** through `self._lookup` point/list queries — `convert` cannot
*iterate* them to emit one node/edge per row.

That is fine for collectors where **one API resource == one graph entity** (Okta, GitHub). It breaks
for collectors where **one graph entity is assembled from many collected tables** — which is the
normal case for the SCCM collector (a single `Computer` node is described by LDAP, the SMS provider
DB, SMB, the registry, and HTTP probes, all keyed by AD SID).

We propose a small, **opt-in, backward-compatible** change: a `read_from="duckdb"` mode on
`@app.convert` that makes `convert` iterate the preproc DuckDB tables directly (reusing the lookup
connection that is already open), instead of globbing JSONL from the bucket.

---

## Background: the three-phase contract

Per the OpenHound standards, every collector is `collect → preproc → convert`:

| Phase | Stated purpose |
|---|---|
| `collect` | Collect upstream data, write raw JSONL tables. |
| `preproc` | Load raw tables into DuckDB, run SQL transforms, build lookup/derived tables. |
| `convert` | Read JSONL + lookup data, emit OpenGraph nodes/edges. |

`preproc` exists to do cross-table correlation in DuckDB. The shipped GitHub collector uses it exactly
this way — building derived tables and then consuming them at convert time:

- Derived tables built in SQL:
  [`transforms.py`](https://github.com/SpecterOps/OpenHound-github/blob/main/src/openhound_github/transforms.py)
  (`branch_bpr`, `actor_branch_bypass`, `actor_branch_gates`, …).
- Consumed in convert via lookups returning whole row sets:
  [`lookup.py`](https://github.com/SpecterOps/OpenHound-github/blob/main/src/openhound_github/lookup.py)
  (`_find_all_objects(...)`).
- Fanned out into edges from a raw driver row:
  [`models/repo_role_assignment.py`](https://github.com/SpecterOps/OpenHound-github/blob/main/src/openhound_github/models/repo_role_assignment.py)
  (`self._lookup.actor_gate_bypass(...)` → one `CAN_WRITE_BRANCH` edge per returned row).

This lookup-driven pattern works well for **edges**. The gap is specifically about **iterating a
preproc-built table to emit nodes**.

---

## The problem, with code evidence

### 1. `convert`'s row source is hardwired to filesystem JSONL

`Converter.run` takes the `DltSource` the collector returns, but uses it **only** to learn the
`model → table_name` mapping; it then discards the source's data resources and reads rows off disk via
the `opengraph` source.

`openhound/core/convert.py` — `Converter.run` (lines 88–124):

```python
def run(self, source_object, graph_resources, extra_context, **kwargs):
    ...
    # only the model->table_name mapping is taken from the returned source
    source_models = {
        dlt_resource.validator.model: dlt_resource.table_name
        for dlt_resource in source_object.resources.values()
        if dlt_resource.validator and hasattr(dlt_resource.validator, "model")
    }
    valid_resources = []
    for graph_resource in graph_resources:
        if graph_resource in source_models:
            table_name = source_models[graph_resource]
            valid_resources.append(GraphResource(table=str(table_name), model=graph_resource))
    ...
    result = self._run(
        opengraph(
            valid_resources,
            lookup=self.lookup,
            bucket_url=str(self.input_path),   # <-- rows come from the bucket, not DuckDB
            extras=extra_context,
        )
    )
```

`openhound/sources/opengraph/source.py` — the reader is filesystem-only (lines 33–71):

```python
for graph_resource in graph_resources:
    table_name = f"{graph_resource.model.__name__.lower()}_fs"
    reader = (
        filesystemsource(
            bucket_url=bucket_url,
            file_glob=f"{graph_resource.table}/**/*.jsonl.gz",   # <-- hardwired JSONL glob
        )
        | read_jsonl()
    )

    @dlt.transformer(parallelized=False, name=table_name, columns=GraphContent)
    def generate_graph(resources, model, apply_context=None):
        for resource in resources:
            parsed_resource = model(**resource)
            ...
            yield {"graph": {"content": asdict(parsed_resource.as_node), "entity_type": "node"}}
            ...

    yield reader | generate_graph(model=graph_resource.model, apply_context=apply_context)
```

There is no code path that points this reader at a DuckDB table.

### 2. `preproc` exists to build DuckDB tables — but `convert` can't iterate them

`openhound/core/preproc.py` — `PreProcessor.run` (lines 84–106) loads JSONL into DuckDB and then runs
the transformer, which can `CREATE OR REPLACE TABLE` anything:

```python
def run(self, resources, filters=None):
    source = resource_files(self.input_path, resources=resources)
    result = self._run(source, write_disposition="replace")
    if self.transformer:
        con = duckdb.connect(str(self.output_file))
        try:
            self.transformer(con)   # builds derived/coalesced tables in DuckDB
        ...
    return result
```

Those tables persist in the lookup DuckDB, but the **only** way `convert` can touch them is
`self._lookup`:

`openhound/core/lookup.py` (lines 20–56) — point/list queries, not iteration drivers:

```python
def _find_all_objects(self, *args) -> list: ...
def _find_single_object(self, *args) -> str | None: ...
```

And the lookup connection is already open during convert — `openhound/core/app.py`, `run_convert`
(line 160):

```python
client = duckdb.connect(str(lookup_file), read_only=True)
lookup_session = lookup(client)
```

### 3. Why this blocks coalescing collectors

When each entity maps 1:1 to a collected resource (Okta user, GitHub repo), there is always a natural
"one row per node" driver file, so the filesystem reader is sufficient.

The SCCM collector violates that assumption: a single `Computer` node is assembled from several
collected tables (LDAP objects, `SMS_R_System`, site-definition servers, SMB signing probes, registry,
HTTP role probes), unioning array properties (e.g. site-system roles, resource IDs). The PS1 reference
tool (`ConfigManBearPig.ps1`) does this with an in-memory `Upsert-Node` merge. The natural OpenHound
equivalent is a DuckDB `GROUP BY`/`UNION` in `preproc` that yields **one coalesced row per SID** — but
`convert` then has no way to iterate that coalesced table to emit one node per row.

The only workarounds available today are both unsatisfying:

- **Emit duplicates from every source file** and rely on BloodHound merging by `ObjectIdentifier`.
  Requires a near-duplicate emitter class per contributing table, emits each node many times, and
  forces every emitter to pull identical merged arrays from a lookup to stay consistent.
- **Write the coalesced tables back to the bucket as JSONL** from `preproc`, so `convert` can read them
  as ordinary driver files. No shipped collector does this; `preproc`'s transformer only receives a
  DuckDB connection (not the bucket path), so it is awkward and fragile, and it couples the
  `preprocess` and `convert` path arguments.

Both are workarounds for a missing capability: **iterate a preproc-built table in convert.**

---

## Proposed solution

Add an **opt-in** `read_from` selector to the convert phase. Default (`"filesystem"`) preserves today's
behavior byte-for-byte; `"duckdb"` makes `convert` iterate the preproc tables via the lookup connection
that is already open. Three small, additive edits:

### Edit 1 — `openhound/core/app.py`: accept the selector on `@app.convert`

In `OpenHound.convert(...)` (currently lines 135–232), add a parameter and thread it into the
`Converter`:

```python
def convert(self, lookup=None, read_from: str = "filesystem", help="OpenGraph convert pipeline", **typer_kwargs):
    ...
    converter = Converter(
        name=self.name,
        source_kind=self.source_kind,
        input_path=input_path,
        output_path=output_path,
        lookup=lookup_session,
        progress=progress,
        method=method,
        read_from=read_from,          # <-- new
    )
```

### Edit 2 — `openhound/core/convert.py`: store and forward the selector

`Converter.__init__` stores `self.read_from = read_from` (default `"filesystem"`). `Converter.run`
forwards it to `opengraph`, along with the lookup schema/connection it already passes:

```python
result = self._run(
    opengraph(
        valid_resources,
        lookup=self.lookup,
        bucket_url=str(self.input_path),
        extras=extra_context,
        read_from=self.read_from,     # <-- new
    )
)
```

### Edit 3 — `openhound/sources/opengraph/source.py`: branch the reader

`opengraph(...)` gains `read_from: str = "filesystem"`. When `"duckdb"`, build the reader from the
lookup connection instead of the filesystem. The lookup already carries `.client` (the DuckDB
connection) and `.schema`:

```python
def _duckdb_reader(lookup, table, batch=2000):
    @dlt.resource(name=f"{table}_db")
    def _rows():
        # Use an INDEPENDENT cursor, not lookup.client directly. A DuckDB connection
        # holds a single active result set: while we are suspended mid-scan, each yielded
        # row flows into generate_graph, whose as_node/edges call self._lookup -> execute()
        # on lookup.client. That second execute would replace the connection's active
        # result and silently truncate this SELECT. lookup.client.cursor() shares the same
        # database but keeps its own result set, so the driver scan survives those lookups.
        cur = lookup.client.cursor()
        cur.execute(f"SELECT * FROM {lookup.schema}.{table}")
        cols = [c[0] for c in cur.description]
        while (rows := cur.fetchmany(batch)):
            for row in rows:
                yield dict(zip(cols, row))
    return _rows()

...
for graph_resource in graph_resources:
    if read_from == "duckdb":
        reader = _duckdb_reader(lookup, graph_resource.table)
    else:
        reader = filesystemsource(bucket_url=bucket_url,
                                  file_glob=f"{graph_resource.table}/**/*.jsonl.gz") | read_jsonl()
    yield reader | generate_graph(model=graph_resource.model, apply_context=apply_context)
```

The independent cursor is load-bearing, not stylistic: the SCCM use case is *iterate one coalesced
`Computer` row, then call `self._lookup` to fan out its edges* — so a driver scan running
concurrently with lookups on the same connection is the expected path, not an edge case. Reading
straight off `lookup.client` would corrupt the scan on the first lookup. (See open question 2 for the
remaining cross-resource/parallel-extraction concern, which the cursor does not fully settle.)

`generate_graph` is unchanged: it still does `model(**row)` and yields `as_node`/`edges`. In DuckDB
mode, `graph_resource.table` names a **DuckDB table** (the collector's convert source declares its
resources with `table_name` set to the preproc table names and the matching Pydantic `columns=` model,
exactly as today — only the row origin changes).

### Behavioral contract

- Default `read_from="filesystem"` → **no change** for existing collectors.
- `read_from="duckdb"` → `convert` iterates `{schema}.{table}` for each registered graph resource.
- `self._lookup` continues to work in both modes (same connection).
- **Precondition:** `read_from="duckdb"` requires the collector to register a lookup class on
  `@app.convert(lookup=...)`. The reader needs `lookup.client`/`lookup.schema`; with no lookup,
  `run_convert` leaves `lookup_session = None` (`app.py` lines 158–161) and DuckDB mode cannot run.
  This is acceptable for coalescing collectors, which already require a lookup, but core should
  raise a clear error rather than `AttributeError` on `None.client` if the flag is set without one.

---

## Why this is the right layer

- It keeps `preproc` as the single place for set-based correlation (its documented purpose) and lets
  `convert` models stay trivial (`row → node` / `row → edge`), which improves readability and makes
  per-stage testing straightforward.
- It is additive and backward compatible — a new optional flag, default preserves current behavior.
- It reuses infrastructure already present in convert (the open DuckDB lookup connection), so it adds
  no new dependency, file format, or path-coordination requirement.

---

## Open questions for the maintainer

1. **API surface.** Global `read_from="duckdb"` on `@app.convert` (proposed, simplest) vs a per-resource
   flag on `GraphResource` for mixed filesystem/DuckDB sources?
2. **Connection concurrency.** Edit 3 already resolves the *single-threaded* hazard: the reader scans
   through `lookup.client.cursor()` (its own result set) so per-row `self._lookup` calls on
   `lookup.client` no longer clobber the in-flight scan. The remaining open question is the *parallel*
   case — DLT may extract the per-resource readers in separate threads, and a single DuckDB connection
   is not safe for concurrent use across threads. Should the lookup itself hand out a per-thread cursor
   (or should core open a dedicated read-only connection per reader) so that parallel extraction is
   safe, rather than relying on every collector to serialize convert?
3. **Schema/table naming.** Confirm the reader should resolve tables as `{lookup.schema}.{table}` using
   the lookup's `schema` (the preproc `dataset_name`), matching where the transformer writes them.
4. **Node de-duplication.** Independent of this change: is there interest in convert/destination-side
   de-duplication of nodes by `id`, which would also make the "emit duplicates and merge" workaround
   safe for any collector?

---

## What we'll do if this isn't accepted

We can ship the SCCM collector without core changes using the lookup-driven pattern plus
BloodHound's `ObjectIdentifier` merge (workaround #1 above), or by writing coalesced tables back to the
bucket from `preproc` (workaround #2). We're raising this first because the DuckDB-read capability is
small, general, and benefits any future collector that assembles entities from multiple sources.
