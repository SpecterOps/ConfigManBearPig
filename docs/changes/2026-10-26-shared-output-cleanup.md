# Share output cleanup while preserving SCCM policy

The approved feature plan promotes `_prior_load_packages`, reusable parts of
`_clean_previous_collection`, and `_cli_path_arg` into common. `main.py` now
delegates inspection/cleanup to `orchestration/artifacts.py` and imports the
path formatter from `orchestration/commands.py`.

SCCM retains exactly `sccm`, `graph`, and `lookup.duckdb` as its reusable artifact
list. Logs/reports survive, warning-only mode does not remove data, and a failed
clean still becomes the collector's existing argument error. The shared helper
also rejects resolved paths outside the chosen output directory before removing
any artifact. PowerShell continuation paths with expansion characters are quoted
literally; ordinary and space-containing path displays remain familiar.

Keeping another implementation was rejected because SQL needs the same generic
file mechanics but a different artifact list. No SCCM collection, scheduling,
graph, profile, schema, default option, or dependency change is introduced.

Existing cleanup, summary, and integration-CLI tests passed **30 checks** on
official CPython 3.13.15. Ruff passed for the changed file. Source comparison
against the saved pre-extraction copy showed 47 other definitions unchanged,
with only two adapters and the promoted formatter changed. Common's grouped
cleanup/orchestration check passed **28 tests**, including an actual Windows
junction outside the named output root and preservation of earlier valid paths.

Manual checks from the configured environment:

```powershell
uv run pytest tests/clean_output_test.py tests/collect_summary_test.py tests/integration_cli_flags_test.py
```

Use a disposable output directory to check `--clean`; keep a log/report in it
and confirm those files survive while the three reusable artifacts are removed.
Do not run cleanup against a baseline graph you intend to keep.

Suggested owner commit after reviewing the existing pending changes:

```powershell
git add -- src/openhound_sccm/main.py README.md ARCHITECTURE.md docs/changes/2026-10-26-shared-output-cleanup.md
git commit -m "Use shared output cleanup and path hints"
```

The agent has not staged, committed, or pushed anything. Shared publication and
complete cross-project acceptance remain part of the unfinished initiative.
