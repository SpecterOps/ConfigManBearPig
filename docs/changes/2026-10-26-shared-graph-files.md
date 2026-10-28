# Preserve SCCM output while sharing file mechanics

The approved MSSQL feature plan promotes generic custom/native graph writing
into `openhound-collector-common`. Previously SCCM used the SDK for labelled
files and duplicated that destination for unlabelled native files. Those two
writers would need separate maintenance as SDK behavior changes.

`convert_pipeline.py::emit_graph_from_duckdb` still reads the same prepared
tables, instantiates the same models, normalizes their properties, and adds the
same SCCM/MSSQL secondary kinds. It now passes each complete record to common's
`GraphFileWriter`. That helper keeps bounded batches, writes explicit source
labels or no metadata, stages files, and retires only previous parts recorded
in its ownership manifest. The local duplicate `opengraph_untagged.py` is
removed. `_emit_split_graph` and all preprocessing routing rules stay unchanged.
The special `hybrid_edges.json` writer remains local and unchanged.

Another destination copy was rejected because it retains the duplicated
maintenance. Rebuilding SCCM graph rules in common would exceed the agreed
boundary. No new dependency, schema change, collection behavior, or command
option is introduced. The shared package will be released once, after both
collectors pass the complete acceptance work; do not invent a published floor.

## Checks and manual verification

On official Python 3.13.15, 15 affected conversion/routing tests passed; Ruff
and mypy passed for the changed adapter. Real network-blocked conversion over
the existing prepared lab database produced 99 nodes and 307 relationships.
Exact comparison to the previous output found zero differences with only
`tests/fixtures/graph_comparison/conversion-time-allowances.json` applied.
Those explicit allowances name the timestamp and kind; no evidence, identity,
endpoint, relationship property, or source label was excluded.

Before output is `C:\Users\domainadmin\.tmp\ev26-a\graph`; after output is
`C:\Users\domainadmin\.tmp\gf26-sccm`. The task directory's
`graph-writer-exact-results.json` records both consumer comparisons.

To repeat locally, set the intended isolated project environment and a unique
`RUNTIME__LOG_PATH`, then run:

```powershell
uv run pytest tests/convert_pipeline_test.py tests/convert_integration_test.py tests/convert_split_output_test.py tests/convert_untagged_emit_test.py tests/graph_edges_split_test.py tests/graph_mssql_props_test.py
uv run openhound convert sccm .\out\sccm .\graph-review --lookup-file .\out\lookup.duckdb --progress off
```

Use a fresh output directory when moving from the old writer. Its old DLT files
are not owned by the new manifest. Review the graph comparison before ingesting.
The outer SDK conversion adapter still exists; removing it is a separate change.

Suggested owner commit after reviewing these files and their existing pending
changes:

```powershell
git add -- src/openhound_sccm/convert_pipeline.py src/openhound_sccm/opengraph_untagged.py tests/convert_untagged_emit_test.py README.md ARCHITECTURE.md docs/changes/2026-10-26-shared-graph-files.md
git commit -m "Use shared custom and native graph file writing"
```

The agent has not staged, committed, or pushed anything. Overall feature-plan
acceptance remains unfinished.
