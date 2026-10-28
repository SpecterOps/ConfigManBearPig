# Saved-search location and separate SQL-to-SCCM connections

Date: October 23, 2026.

## What needed changing

The owner requested two changes. Saved searches should live in
`extension/saved_searches/`, and the three searches with blank descriptions
should explain their purpose. SQL-to-SCCM connections should be written to a
separate file named exactly `hybrid_edges.json`.

The owner is happy with the existing information shown when clicking an object.
This change does not edit those screens or either graph schema.

Previously, the saved searches lived in `cypher_queries/`. A connection from a
SQL site database to its SCCM site was included in the file labelled SCCM.
The extension publishing process instead asks for connections between products
to be kept separately without a product source label. This change follows that
rule; it does not claim the previous placement was proven to fail ingestion.

## Saved searches

All 24 JSON files moved to [the new directory](../../extension/saved_searches/).
Their names and queries are unchanged. Only these three descriptions changed:

| File | What the description explains |
| --- | --- |
| `SCCM ELEVATE-1.json` | Potential SCCM SMB coercion-and-relay paths from Authenticated Users to computers that do not require SMB signing. |
| `SCCM Sites.json` | Discovered SCCM sites and the relationships connecting them. |
| `SCCM Site Database Service Account to Client Device.json` | An example search. Replace `'PS1-DEV'` in the query with the computer name to investigate; it matches names containing that text. |

The example still starts at user accounts and follows selected SQL/SCCM
connections for up to five steps. Its description makes those limits clear;
it does not promise that every starting account is a site database service
account. Review the returned path to understand the account's actual access.

Keeping one directory avoids maintaining duplicate copies. Keeping the existing
search names means moving the files does not create renamed searches in
BloodHound. The README, extension guide, publishing runbook, and archived
PowerShell README link now point users to the current location. Older dated
planning records retain their historical paths.

From the repository root:

```powershell
uv run openhound searches upload .\extension\saved_searches --strategy overwrite
```

This command changes searches in BloodHound and requires the existing configured
BloodHound connection. It was not run for this change. `--strategy overwrite`
updates descriptions of searches already installed under those names; omit it
to keep the uploader's default of skipping existing names.

## How connections are separated

[`_graph_edges_split`](../../src/openhound_sccm/transforms.py) makes the decision
during preprocessing, after all graph nodes and connections have been prepared:

| Connection | Prepared table | Output |
| --- | --- | --- |
| Touches an AD object | `graph_edges_ad` | Existing untagged `ad_edges-*.json` |
| Both ends are SQL objects | `graph_edges_mssql` | Existing SQL-labelled `mssql_edges-*.json` |
| One end is SQL and the other is SCCM | `graph_edges_hybrid` | Untagged `hybrid_edges.json` |
| Both ends are SCCM objects | `graph_edges_sccm` | Existing SCCM-labelled `sccm_edges-*.json` |

AD takes priority. The SQL ID list comes from the six existing SQL node tables.
After missing endpoints have been backfilled, exactly one SQL endpoint on a
non-AD connection identifies the SQL/SCCM crossing. The decision works in either
direction and does not depend on the relationship's name.

[`_emit_split_graph`](../../src/openhound_sccm/main.py) runs the three existing
writers, then calls
[`emit_hybrid_edges_from_duckdb`](../../src/openhound_sccm/convert_pipeline.py).
That helper reads the hybrid table and uses the existing `GraphEdge` model and
property cleanup. The connection's endpoints, meaning, properties, and ability
to form an attack path are preserved. Only its file placement and source label
change.

The file contains the usual OpenGraph `graph` object, an empty `nodes` list,
and its `edges` list. It has no `metadata` block. No node is moved to this file.

The helper writes one connection at a time to `hybrid_edges.json.tmp`, then
replaces `hybrid_edges.json` when the complete document is ready. It writes an
empty list if there are no connections, so a repeat conversion cannot leave
old hybrid results behind. A write or model failure is logged and raised;
the earlier complete file is not replaced by a partial one. A temporary file
can remain after a failure, but it is not a `.json` graph file or ZIP input.
The existing lookup logs a warning if its prepared table is unavailable;
rerun preprocessing before converting an older lookup database.

The normal `--run-all` ZIP already includes all graph JSON files. It therefore
includes `hybrid_edges.json` without a shared-library change.

## Why this approach

- Keeping the SQL-to-SCCM connections in the SCCM-labelled file would not follow
  the requested separation.
- Reusing the existing untagged DLT writer would produce numbered files such as
  `hybrid_edges-1.json`, rather than the exact filename requested. Joining and
  deleting those batches afterward would add more moving parts.
- Loading all connections into one Python list would use unnecessary memory.
  The small local writer streams the existing edge model's results instead.
- No change to OpenHound or `openhound-collector-common` is needed. No dependency
  was added or changed. A reusable fixed-name writer could be proposed to common
  if another collector needs it; that is separate work requiring owner approval.

## Verification performed

Validation used the existing isolated environment
`C:\Users\domainadmin\.codex\venvs\configmanbearpig-pz`, without changing the
repository's `.venv`: Python 3.13.15, OpenHound 0.2.12, common library 0.1.4,
pytest 9.0.3, Ruff 0.15.13, and mypy 2.1.0.

- All 24 files loaded through OpenHound's actual `SavedSearch` model and have
  nonempty descriptions. The 21 other files match their previous SHA-256 hashes.
  The three changed files retain their original names and queries.
- **31 focused tests passed**, covering routing, hybrid file contents, the existing
  conversion behavior, and the four required collector test files. The new checks
  cover 1,001 connections in one file, replacement with an empty result, and a
  forced failure that must preserve the previous complete file and log an error.
- Ruff passed across `src` and `tests`; formatting passed for the two formatted
  files; mypy passed across all 63 source files.
- Preprocessing and conversion ran before and after the change over the same
  cached `out/sccm` collection. Both produced **99 objects and 322 connections**.
  Exactly two database-to-site connections moved to the untagged hybrid file.
  The common-library graph comparison and per-file checks confirmed matching
  IDs, kinds, endpoints, properties, and connection counts. Only automatic
  `last_seen` timestamps were ignored.
- The existing shared ZIP helper included the exact `hybrid_edges.json` bytes.
- Source and wheel builds passed. Build outputs are outside the repository.

Review copies are under `.tmp/cmbp-hybrid-before-20261023`. Cached-run outputs,
logs, `comparison.json`, and `verification-summary.json` are under `.tmp/hy0`
and `.tmp/hy1`, all outside the repository. Test/build outputs are under `.tmp/hyt`.

No live collection, BloodHound upload, or finding-generation test was performed.
The cached-data check verifies output preservation; it does not establish live
BloodHound acceptance of the new file arrangement.

## Repeat the focused checks

From the repository root, with the project's external environment already set up:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.codex\venvs\configmanbearpig-pz'
$env:PYTHONPATH = 'C:\Users\domainadmin\ConfigManBearPig\src'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:RUNTIME__LOG_PATH = Join-Path $env:TEMP ('cmbp-hybrid-logs-' + [guid]::NewGuid().ToString('N'))

uv run --no-sync --offline python -B -m pytest tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py tests/graph_edges_split_test.py tests/edge_mssql_structural_test.py tests/convert_split_output_test.py tests/convert_untagged_emit_test.py tests/graph_edges_coercion_cols_test.py -q -p no:cacheprovider
uv run --no-sync --offline python -B -m ruff check --no-cache src tests
uv run --no-sync --offline python -B -m ruff format --check src/openhound_sccm/convert_pipeline.py tests/convert_split_output_test.py
uv run --no-sync --offline python -B -m mypy --cache-dir "$env:TEMP\cmbp-hybrid-mypy" src/openhound_sccm
```

These checks need no SCCM or BloodHound connection. The isolated environment above
exists on this workstation; another machine should create its own external
environment using `uv sync --locked --group dev` first.

## Manually check saved collection output

Use a new output directory so old SCCM files cannot be uploaded alongside the
revised files. Preprocessing and conversion read saved collection data; they do
not contact SCCM:

```powershell
Set-Location C:\Users\domainadmin\ConfigManBearPig
$reviewOutput = Join-Path $env:TEMP ('cmbp-hybrid-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $reviewOutput | Out-Null

uv run openhound preprocess sccm .\out "$reviewOutput\lookup.duckdb"
uv run openhound convert sccm .\out "$reviewOutput\graph" --lookup-file "$reviewOutput\lookup.duckdb"

$hybrid = Get-Content -LiteralPath "$reviewOutput\graph\hybrid_edges.json" -Raw | ConvertFrom-Json
$hybrid.graph.edges | Select-Object kind, start, end
$hybrid.PSObject.Properties.Name
```

For the cached collection used here, expect two `SCCM_AssignAllPermissions`
connections, from `CM_PS1` to PS1 and from `CM_CAS` to CAS. The top-level property
list must contain `graph` and no `metadata`. These database-to-site connections
must not also appear in the SCCM-labelled files. Other collections may contain
different counts, including zero.

When ready to check BloodHound, ingest all graph JSON files together into an
appropriate test instance and confirm the two database-to-site connections remain
available. Installation and analysis are separate manual checks.

## Review and suggested commit

Suggested message: `Move saved searches and separate SQL-to-SCCM connections`.

Suggested description: `Move 24 searches, explain three searches and the replaceable computer-name example, preserve SQL-to-SCCM connections in an untagged hybrid_edges.json, and update instructions and automated checks. Verify 31 tests, the unchanged cached 99-object/322-connection graph, code checks, and package builds. No new dependencies or object-screen changes.`

Several files already contained unrelated owner changes before this task. Review
those portions separately; do not stage the whole tree. The extension README was
already untracked and contains earlier rule/schema instructions, so review that
whole file before adding it.

After review, the owner can select the relevant changes and save the move:

```powershell
git add -p -- README.md ARCHITECTURE.md .github/workflows/ci.yml src/openhound_sccm/main.py src/openhound_sccm/convert_pipeline.py tests/convert_split_output_test.py
git add -- src/openhound_sccm/transforms.py tests/graph_edges_split_test.py tests/edge_mssql_structural_test.py
git add -- cypher_queries extension/saved_searches docs/PUBLISHING.md powershell_deprecated/README.md
git add -- extension/README.md docs/changes/2026-10-23-saved-searches-and-hybrid-output.md
git diff --cached
git commit -m "Move saved searches and separate SQL-to-SCCM connections" -m "Explain three searches and the replaceable computer-name example. Write untagged hybrid_edges.json while preserving graph contents. Update instructions and automated checks. Verify 31 tests, cached graph preservation, code checks, and package builds; no new dependencies or object-screen changes."
```

No files were staged, committed, tagged, pushed, or published by the agent.
