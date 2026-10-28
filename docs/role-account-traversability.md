# Role and stored-account paths in graph output

The SCCM schema already allowed five role relationships and the site-stored-account relationship in attack paths, but Python emitted them with `traversable: false`. Conversion now emits `traversable: true` for these six existing relationships:

- `SCCM_ApplicationAuthor`
- `SCCM_ComplianceSettingsManager`
- `SCCM_OSDManager`
- `SCCM_OperationsAdministrator`
- `SCCM_SecurityAdministrator`
- `SCCM_HasStoredAccount`

The change is in [`TRAVERSABLE_EDGE_KINDS`](../src/openhound_sccm/kinds/edges.py). [`GraphEdge.edges`](../src/openhound_sccm/models/graph_edge.py) already reads this list to set the emitted property, so no new conversion logic or collection is needed. Endpoints, relationship kinds, collected records, and secret-handling behavior are unchanged. The two schema files needed no edits.

## Why these are potential paths

Separate fresh-account tests in the authorized mayyhem.com lab demonstrated SYSTEM execution on ps1-dev for each of the five role routes. Application Author modified an application already deployed to the client. Compliance Settings Manager created and deployed a script-based discovery baseline. OSD Manager created and deployed a custom task sequence containing one harmless marker command. Operations Administrator created and deployed an application. Security Administrator assigned Full Administrator to itself, then deployed an application using that resulting access.

Application Author still needs an application it can edit within its security scope and a deployment that permits the changed command to run. The owner explicitly chose to include this potential path even when a suitable application is not currently confirmed as deployed: a future deployment can make the existing permission actionable. No new deployed-application check was added. Security Administrator's execution route includes role delegation; it is not described as direct application deployment under the initial role alone.

Stored-account traversal represents potential credential recovery from a site-associated account. It does not mean the collector recovered a password. Account type, credential storage, and access to the relevant SCCM systems determine the recovery route. This change adds no task-sequence secret parsing or collection-variable value collection.

Changing only the schema was rejected because it would leave the Python output false. Keeping the historical PowerShell list was rejected because it would hide these approved paths. Extending secret collection was not necessary to change traversal and is outside this change. The existing conversion-time list is the smallest place to express the decision.

## Separate NAA work

The open ticket [`ope-e10b`](../.tickets/ope-e10b.md) tracks `SCCM_HasNetworkAccessAccount` from Local collection: client `Computer` to the resolved NAA principal from cached credential policy. That relationship is separate from site-to-account `SCCM_HasStoredAccount`. It still has no Python producer and is not introduced here.

Related open tickets are [`Ope-padv`](../.tickets/Ope-padv.md), local repository recovery including historical NAA, task-sequence, and collection-variable secrets, and [`Ope-t7kv`](../.tickets/Ope-t7kv.md), client registration and HTTP policy decryption. Their status and contents were not changed. Some older acceptance criteria use placeholder edge names; those need review when the respective features are implemented.

## Validation

The six new emitted-property cases in [`graph_edge_test.py`](../tests/graph_edge_test.py) failed with false flags before the list changed, then passed after it changed. The updated [`kinds_edges_test.py`](../tests/kinds_edges_test.py) checks all seven built-in role paths plus stored accounts. Existing non-traversable membership checks remain in place.

The split-output conversion test also checks that the stored-account edge is written to the actual JSON payload with a true traversal flag. The focused tests and the four repository-required integration test files completed with **42 passed, 1 expected skip**. The skip is the existing help-content placeholder test, which has no pending help entry to exercise. Ruff passed for all `src` and `tests`; mypy passed for all 63 source files. No new lab activity was needed for this flag change. The test environment was outside the repository and reused the installed dependencies read-only; the repository's environment and lockfile were not changed. No new dependency was added.

Commands for a normal prepared development environment:

```powershell
uv run python -B -m pytest tests/kinds_edges_test.py tests/graph_edge_test.py tests/edge_has_stored_account_test.py tests/edge_help_emit_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/convert_split_output_test.py tests/integration_fixtures_test.py -q -p no:cacheprovider
uv run ruff check src tests
uv run mypy src/openhound_sccm
```

During this review, `UV_PROJECT_ENVIRONMENT` selected `C:\Users\domainadmin\.tmp\cmbp-traversability-venv`, `PYTHONPATH` selected this checkout's `src`, and commands used `uv run --no-sync --offline python -B -m ...`. Logs, type-checker cache, and pytest temporary directories were outside the repository. The initial test run passed but hit a Windows permission warning while cleaning an older default pytest temporary directory; rerunning with a fresh explicit `--basetemp` completed cleanly.

## Manual verification and downstream effect

Re-run conversion for an existing preprocessed collection using a new output directory. For example, from this checkout, with the earlier Quick Start collection still at `.\out`:

```powershell
uv run openhound convert sccm .\out\sccm .\out\graph-traversable --lookup-file .\out\lookup.duckdb
```

Inspect emitted edges of the six kinds and confirm `properties.traversable` is true. The graph should retain the same nodes and relationship endpoints. An old graph archive will retain its old flags until regenerated. After importing regenerated output, BloodHound can follow more existing relationships in attack paths; this does not automatically create findings from the ignored local Markdown drafts.

## Suggested commit after review

Suggested message: `fix: make SCCM role and stored-account paths traversable`

The commands below omit unrelated files and the ignored `edges/` drafts. README also contains separate privilege-zone work: at the interactive prompts, choose `n` for the privilege-zone table-of-contents/upload additions and `y` for the traversal and six affected edge-reference changes. Run these commands yourself after review; nothing has been staged or committed by the agent.

```powershell
git add -- src/openhound_sccm/kinds/edges.py tests/kinds_edges_test.py tests/graph_edge_test.py tests/convert_split_output_test.py ARCHITECTURE.md docs/role-account-traversability.md
git add -p -- README.md
git diff --cached
git commit -m "fix: make SCCM role and stored-account paths traversable" -m "Align six emitted traversal flags with the SCCM schema. Document conditional execution and credential-recovery routes, retain deferred NAA collection under ope-e10b, and verify graph output with focused regression and integration checks. No new dependencies or collection changes."
```

No push is performed or recommended as an automatic next step.
