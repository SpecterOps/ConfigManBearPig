---
id: ope-76f1
status: closed
deps: []
links: [ope-00df]
created: 2026-07-22T14:35:05Z
type: task
priority: 1
---

# Make -v enable VERBOSE and add --silent to mute console output

Change the -v/--verbose flag from a repeatable count (where -v was a no-op INFO and -vv gave VERBOSE) to a boolean that enables VERBOSE directly. Default stays INFO; --debug stays the separate DEBUG switch; -vv becomes invalid. Add a --silent flag that silences all console log output while leaving the two on-disk logs (collect_log_*, collect_diagnostics_*) writing. --silent composes with -v/--debug: quiet console, file logs at the requested detail level. Implemented by raising only the console handlers above CRITICAL (not the root logger). Touches main.py, README CLI options, ARCHITECTURE section 7 + changelog, and a new test.

## Notes

**2026-07-22T14:42:00Z**

Code + offline tests complete (not committed; not live-checked). main.py: verbose option is now boolean -v/--verbose=VERBOSE (was count; -v was a no-op INFO, -vv gave VERBOSE); added --silent; _apply_log_level(verbose,debug,silent) rewritten; new _is_console_handler / _silence_console_handlers helpers (_CONSOLE_MUTE_LEVEL=CRITICAL+1); --silent forces --progress off. Docs: README verbosity tip + CLI table; ARCHITECTURE section 7 VERBOSE bullet (-vv->-v) + new --silent bullet + changelog. Tests: tests/test_verbose_silent_flags.py (13 pass); test_debug_exc_info_filter.py + test_per_host_log_blocks.py still green (30). Remaining: user live-run eyeball + commit. Follow-up ope-00df (per-file --no-diagnostics-log/--no-collect-log).

**2026-07-22T16:04:31Z**

Live-tested and verified by user 2026-07-22. Closing.
