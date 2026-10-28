# Use the shared full/issues logging lifecycle

The reviewed SQL feature-completion plan promotes SCCM's reusable full/issues
handlers into common. `main.py` now imports those handlers for its existing
consumer checks and uses `RunFileLogs` for their runtime lifecycle. SCCM retains
its line layout, counters, console choices, completion ordering, and diagnostics
through chained preparation/conversion. Graph calculations and schema are unchanged.

Unfinished groups are spooled immediately to private files, replacing growing
lists of messages and traceback objects in memory. Required write failures are
reported and fail cleanup; unpublished redacted spools remain recoverable.
Known secrets and inline credentials are redacted while preserving existing
formats. Cleanup restores handlers, callbacks, and namespace levels after
collection failure as well as later-stage failure. Unexpected failures are
recorded with tracebacks before returning code 1. Intentional test/command exit
statuses keep their existing handling.

Stale-output cleanup now precedes opening the new handlers. Otherwise a failed
cleanup could leak handlers before the collection try/finally started. Keeping
issues solely in the collection finally block would lose chained-stage errors;
the shared scope deliberately retains them until the whole command ends.

The before-edit snapshot includes the owner's current pending changes. A parsed
code comparison verified all 49 other top-level functions/classes unchanged;
only `collect_sccm` changed and the two promoted handler classes were removed.
The CLI seed-target helper was retained. Architecture links to moved `main.py`
definitions were corrected.

Checks: **71 affected tests passed**, including a real registered command forced
to fail before discovery. That case retains a redacted exception and releases
both handlers. Existing handler layout, warning/error counts, ordered target
blocks, silent/verbose controls, clean-output behavior, chained stages, and
integration wiring also passed. Lint and type checking of the edited adapters
passed. No lab target was contacted by these checks. The separate evidence
extraction also preserved the cached graph's 99 nodes/307 relationships exactly,
apart from explicitly allowed regenerated conversion timestamps.

No new dependency or core edit was added. The owner's pending common release
must precede final dependency-floor/lock updates and ordinary-installation checks.
After that release:

```powershell
uv run pytest tests/shared_file_logs_test.py tests/debug_exc_info_filter_test.py tests/per_host_log_blocks_test.py tests/verbose_silent_flags_test.py tests/collect_run_all_test.py tests/clean_output_test.py tests/integration_wiring_test.py
```

Suggested owner commit after reviewing other pending changes in these files:
`Use shared full/issues logs and release diagnostics after failures`.

```powershell
git add src/openhound_sccm/main.py tests/shared_file_logs_test.py README.md ARCHITECTURE.md docs/changes/2026-10-26-shared-file-logs.md
git commit -m "Use shared full/issues logs and release diagnostics after failures"
```

The owner performs these actions manually. No files were staged or committed.
