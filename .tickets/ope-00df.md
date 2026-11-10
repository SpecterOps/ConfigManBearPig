---
id: ope-00df
status: in_progress
deps: []
links: [ope-76f1]
created: 2026-07-22T14:35:20Z
type: task
priority: 3
---

# Add --no-diagnostics-log / --no-collect-log to suppress on-disk logs individually

## Current completion scope (2026-11-09)

[The completion plan](../docs/superpowers/plans/2026-11-09-sccm-extension-completion.md)
includes independent full/issues file choices, enabled by default. Implemented names
are `--no-full-log` and `--no-issues-log`, matching current files. Keep warning/error
counts and final status even without file output. The shared `RunFileLogs` owns
these handlers now; its proposal was approved and the changes are implemented.
Focused tests and a Windows run with both files disabled pass. The older names,
handler locations, and attachment-only design below are superseded.

Follow-up to ope-76f1. Add two flags to independently suppress the on-disk logs written during collect: --no-diagnostics-log (skips collect_diagnostics_<ts>.log, the WARNING+ with-tracebacks file from _DiagnosticFileHandler) and --no-collect-log (skips collect_log_<ts>.log, the ordered human-readable file from _OrderedLogFileHandler). Cleanest implementation gates whether each handler is attached at all (main.py ~1015-1016) rather than attaching-then-muting, since these buffer and flush on completion. These compose with --silent (console-only) so a user can pick exactly which sinks stay on. Update README CLI options and ARCHITECTURE section 7.
