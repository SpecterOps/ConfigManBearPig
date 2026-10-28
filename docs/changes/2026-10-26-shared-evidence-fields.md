# Shared evidence fields

The approved feature-completion plan shares the three graph evidence fields
already used by ConfigManBearPig and requested for MSSQL. SQL-specific graph
rules stay in each collector. No schema or external dependency is added here.

`graph.py` now inherits `EvidenceProperties` from common in `SCCMEdgeProperties`
and the six SQL node-property classes that already carried all three fields.
The helper declares `collectionSource`, `assumed`, and `assumptionBasis`, keeps
ordered unique source tags, and requires a nonempty explanation when `assumed`
is true. Confirmed records keep null assumption fields, which the existing writer
omits. Other property classes keep their existing fields.

This removes duplicated declarations without moving SCCM evidence decisions
into common. Copying the fields again into MSSQL would allow the field names
and validation to drift. Moving SCCM rules into common would couple unrelated
collectors and was rejected.

Before the adapter edit, preparation and conversion were rerun over `out/sccm`
into a separate temporary directory. Both stages rejected Python socket network
calls. Both stages also passed after the edit. Both outputs have 99 nodes and
307 relationships. Initial exact comparison found only `last_seen` differences
on the 99 nodes, because OpenHound supplies a new conversion time in each process.
Recorded per-kind allowances ignore only that timestamp. Exact comparison then
passed, including raw file checks, complete relationship records, source labels,
evidence values/order, and every other property. The affected selection passed
60 tests; Ruff and type checking of the adapter passed. This is cached-data
verification, not fresh live collection.
The owner's original output, cached database, and pending source changes remain
untouched. The three files edited here were also copied to the task's additional
October 26 snapshot before editing.

This source needs the pending common release. Development uses the approved
isolated editable checkout. After owner review/publication, update the dependency
floor and lock to its actual released version; no sibling path belongs in the
published project metadata.

Manual check after that release:

```powershell
uv run openhound preprocess sccm .\out .\evidence-check\lookup.duckdb
uv run openhound convert sccm .\out\sccm .\evidence-check\graph --lookup-file .\evidence-check\lookup.duckdb
uv run openhound-compare .\before-evidence\graph .\evidence-check\graph --exact --allowances .\tests\fixtures\graph_comparison\conversion-time-allowances.json --json .\evidence-check\comparison.json
```

Use a saved graph generated from the same raw collection as `before-evidence`.
Review all pending changes before staging anything. Suggested commit message:
`Use shared evidence fields without changing SCCM graph output`.

```powershell
git add src/openhound_sccm/graph.py README.md ARCHITECTURE.md docs/changes/2026-10-26-shared-evidence-fields.md tests/fixtures/graph_comparison/conversion-time-allowances.json
git commit -m "Use shared evidence fields without changing SCCM graph output"
```

The owner performs these actions manually. No Git actions were taken by the agent.
