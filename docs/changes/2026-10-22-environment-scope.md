# Group nodes by service and scope MSSQL findings to the AD domain

Date: 2026-10-22.

## Problem and agreed behavior

BloodHound needs broad SCCM/MSSQL labels alongside specific node kinds. SQL
findings should be grouped across an AD domain, rather than one SQL instance.
The owner selected the hierarchy root as the SCCM environment: shared roles and
replicated collections belong together, though individual-site filtering then
requires their site properties or relationships.

## How it works and alternatives

[`emit_graph_from_duckdb`](../../src/openhound_sccm/convert_pipeline.py) copies
each model's node into its output dictionary and appends `SCCM` or `MSSQL` after
the existing specific kind. The constants live in
[`kinds/nodes.py`](../../src/openhound_sccm/kinds/nodes.py). AD kinds are untouched.
This single writing boundary covers every model without repeating the rule in
each model. It also keeps the existing first kind, IDs, properties, and edge
references intact. A debug message identifies each added label.

SCCM models already use the hierarchy-root site code as `environmentid`; MSSQL
models already derive the host's AD domain SID. These behaviors are retained.
[`schema_MSSQL.json`](../../src/openhound_sccm/schema_MSSQL.json) now selects
`Domain` as `environment_kind`. The identical schema is added to the standalone
MSSQL collector's package. The schema on the local OpenHound integration branch
was identical before this change; no OpenHound files were edited.

A node property called `environment_kind` was considered and rejected after
clarification: it is a schema setting, while broad node labels belong in `kinds`.
Specific-site SCCM scope would separate site findings but needs an ownership rule
for shared objects. Per-server SQL scope was rejected because it is too narrow
for viewing findings. No dependency, collection, preprocessing, or shared-library
changes were needed. Previously emitted files need conversion again to gain the
labels; importing the updated MSSQL schema enables Domain findings scope.

## Validation

- 21 tests passed: extension metadata, integration wiring, conversion pipeline,
  integration fixtures, and three-way split output.
- The split-output test now uses a PS1 site under CAS to check that scope remains
  CAS, checks MSSQL domain scope, and checks exact kind order and unchanged AD output.
- Replayed the saved `out/lookup.duckdb` through the old and new writing behavior:
  99 nodes (42 SCCM, 24 MSSQL, 33 AD), 322 edges. Only requested secondary labels
  changed. IDs, other properties, AD content, and edges matched. The comparison
  ignored timestamps. This held the prepared data constant; it did not recollect
  or rerun preprocessing, because preprocessing was unchanged.
- Ruff and mypy passed; source package and wheel built successfully.
- The schema copies were compared, and the packaged files were checked.

Validation uses an isolated environment outside the repository. No live collection
or BloodHound upload was performed; server-side findings display remains a manual check.

## Manual verification

```powershell
Set-Location C:\Users\domainadmin\ConfigManBearPig
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.tmp\cmbp-environment-venv'
uv run --locked pytest tests/convert_split_output_test.py tests/convert_pipeline_test.py -q
```

Convert a saved collection using the normal README commands. Inspect the output:
SCCM kinds should resemble `["SCCM_Site", "SCCM"]` with `environmentid: "CAS"`;
MSSQL kinds should resemble `["MSSQL_Server", "MSSQL"]` with the host's domain SID.
AD nodes should gain neither label. Import the updated MSSQL schema through the
existing BloodHound schema workflow, ingest all output files, and check Domain
findings scope. The corresponding AD Domain must already be present in BloodHound.

## Suggested commit after review

There are unrelated edits in this working tree. Select only this change's portions
of shared files; do not stage the entire tree. No files were staged or committed.

```powershell
git add -p -- README.md ARCHITECTURE.md src/openhound_sccm/convert_pipeline.py src/openhound_sccm/kinds/nodes.py src/openhound_sccm/schema_MSSQL.json tests/convert_split_output_test.py
git add -- docs/changes/2026-10-22-environment-scope.md
git diff --cached
git commit -m "Label SCCM and MSSQL nodes and scope SQL findings to Domain" -m "Retain hierarchy-root SCCM and host-domain MSSQL environment IDs. Append service kinds after specific kinds; preserve AD output and edge references. Document alternatives and manual checks. Validate 21 tests, saved graph comparison, lint, types, and package builds. No new dependencies."
```

Do not push as part of this change.
