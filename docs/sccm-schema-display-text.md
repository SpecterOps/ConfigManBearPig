# SCCM schema display names and descriptions

The SCCM schema previously registered five node types with empty display names
and descriptions, and 24 relationship types with empty descriptions. One
relationship, `SCCM_HasNetworkAccessAccount`, had no Python producer.

The owner reviewed and supplied the final wording on October 21, 2026. The
shipped [schema_SCCM.json](../src/openhound_sccm/schema_SCCM.json) now contains
those exact five node display names, five node descriptions, and 23 relationship
descriptions. The unimplemented `SCCM_HasNetworkAccessAccount` entry was removed
at the owner's request.

## How it works and why this approach was selected

BloodHound receives this JSON file when the operator registers the SCCM
extension. Each `node_kinds` entry supplies a `display_name` and `description`;
each `relationship_kinds` entry supplies a `description`. Editing those existing
fields puts the explanations alongside the type definitions that BloodHound
already reads. The schema remains hand-maintained.

The five type names are listed in the README's
[Node Reference](../README.md#node-reference). Individual object names, stable
identifiers, kind names used by queries, icons, colors, relationship directions,
and attack-path settings are unchanged. The MSSQL schema is unchanged.

The relationship wording explains the source and destination objects, the
applicable permissions, and important conditions. Application Author still
requires an editable application already deployed to the client. User affinity
and recorded logons do not guarantee a current session. Stored-account
configuration does not establish that the collector recovered a password or that
stored credentials remain valid.

Renaming the actual graph kinds was unnecessary and would change names used by
queries. Adding more help properties to every emitted node or edge was also
unnecessary: this change supplies type descriptions through the existing schema
fields. The subsequent [Site entity panel change](sccm-site-entity-panel.md) adds
detailed sections and related-object links for sites. The
[Administrative User panel](sccm-admin-user-entity-panel.md) adds assignment links
and direct control-path links. The
[Security Role panel](sccm-security-role-entity-panel.md) adds a two-column
assignment table; its saved description remains under Object Information. The
[Collection and Client Device panels](sccm-collection-client-panels.md) add
membership tables, assignment query links, and client control links. All five
SCCM node kinds now have custom sections alongside built-in Object Information.
Keeping an unused NAA relationship would register a feature the collector does
not produce. Its separate client-cache collection feature remains tracked in
[ope-e10b](../.tickets/ope-e10b.md); the implemented site-to-account
`SCCM_HasStoredAccount` relationship remains registered.

The display-text and entity-panel edits change no collection, preprocessing,
conversion, authentication, logging, or shared-library code and add no dependency.
The panels use existing node properties; they add no graph properties.
Existing edge help properties remain independent of the schema descriptions.

## Validation

At completion of the display-text change, the seven selected test files passed:
**36 tests passed**. These include the four
repository-required metadata, wiring, conversion, and fixture files, together
with the existing kind, edge-property, and split-output checks. Ruff passed for
all source and test files. Mypy passed for all 63 source files. An offline wheel
build succeeded.

A separate JSON audit confirmed that the schema's five node names and 23
relationship names match the SCCM constants in
[kinds/nodes.py](../src/openhound_sccm/kinds/nodes.py) and
[kinds/edges.py](../src/openhound_sccm/kinds/edges.py), including every relationship's
attack-path setting. All descriptions and node display names are nonempty, and
names are unique. After excluding the approved text fields and removed NAA
entry, the parsed schema equaled the previous committed schema before the later
Site panel was added. The README's
five display names and descriptions match the JSON exactly, and the local links
in these notes resolve.

Both schema files in the built wheel match their checkout files byte for byte.
The MSSQL schema's content also matches its previous committed version; Windows
checkout line endings were normalized for that comparison.

The following commands used an existing Python 3.13.15 environment outside the
repository. `--no-sync --offline` retained its installed dependencies and left
the repository's `.venv` and lockfile alone. Logs and caches were also outside
the repository.

```powershell
Set-Location C:\Users\domainadmin\ConfigManBearPig
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.tmp\cmbp-traversability-venv'
$env:PYTHONPATH = 'C:\Users\domainadmin\ConfigManBearPig\src'
$env:RUNTIME__LOG_PATH = 'C:\Users\domainadmin\.tmp\cmbp-schema-logs'
uv run --no-sync --offline python -B -m pytest tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py tests/kinds_edges_test.py tests/graph_edge_test.py tests/convert_split_output_test.py -q -p no:cacheprovider --basetemp C:\Users\domainadmin\.tmp\cmbp-schema-tests-20261021
uv run --no-sync --offline python -B -m ruff check src tests --no-cache
uv run --no-sync --offline python -B -m mypy src/openhound_sccm --cache-dir C:\Users\domainadmin\.tmp\cmbp-schema-mypy-cache
uv build --wheel --offline --out-dir C:\Users\domainadmin\.tmp\cmbp-schema-build-20261021
```

Use a fresh `--basetemp` directory when repeating the test command: pytest clears
that directory before using it. No new test files were needed for the display
text edit. No live collection or BloodHound upload was performed, so UI display
remains a manual verification step. These checks validate the delivered schema,
collector integration, and packaging rather than a particular BloodHound UI
version.

## Manual verification

From the checkout, inspect the delivered JSON without connecting to the lab:

```powershell
Set-Location C:\Users\domainadmin\ConfigManBearPig
$sccmSchema = Get-Content .\src\openhound_sccm\schema_SCCM.json -Raw -Encoding UTF8 | ConvertFrom-Json
$sccmSchema.node_kinds | Format-Table name, display_name
$sccmSchema.relationship_kinds | Format-List name, description
$sccmSchema.node_kinds.Count          # Expected: 5
$sccmSchema.relationship_kinds.Count  # Expected: 23
$sccmSchema.relationship_kinds.name -contains 'SCCM_HasNetworkAccessAccount'  # Expected: False
```

Review the descriptions against the owner's wording and confirm every entry has
a description. In BloodHound, upload the updated `schema_SCCM.json` using
**Administration → OpenGraph Management → Upload File**, as described in the
README's [Quick Start](../README.md#quick-start).

Inspect an existing `SCCM_Site`, `SCCM_AdminUser`, and `SCCM_ClientDevice` from the
mayyhem.com collection. Confirm the type labels match the README table and their
individual names and identifiers remain the same. Inspect the registered
relationship descriptions, including `SCCM_ApplicationAuthor` and
`SCCM_HasStoredAccount`, to check that their prerequisites and limitations are
present. No new collection or conversion is needed for these schema changes.

Removing the NAA definition from this file does not itself delete an earlier
registration or graph data from an existing BloodHound instance. This change
does not contact or modify BloodHound; it prepares the file for operator upload.

## Suggested commit after review

The display-text change and subsequent Site panel are still uncommitted in the
same schema file. The [Site panel notes](sccm-site-entity-panel.md#suggested-commit-after-review)
provide the current combined commit message and commands, including how to
exclude unrelated README and CI changes. No files have been staged, committed,
or pushed by the agent.
