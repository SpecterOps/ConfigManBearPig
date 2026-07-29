---
id: ope-54be
status: closed
deps: []
links: []
created: 2026-07-22T15:20:22Z
type: task
priority: 1
---

# Fix ordered-log per-host grouping; always-DEBUG full log; rename logs; truncate HTTP content log

Three coupled ordered-log/full-log fixes in the SCCM logging layer, plus an HTTP log truncation. (1) Ordered-log per-host grouping bug: the six Stage-2 per-host collectors (collect_registry/mssql/adminservice/wmi/http/smb) were @with_log_context-decorated, which set a resource context (func.__name__) and fired resource-complete once per (host,phase); the _OrderedLogFileHandler buckets by resource over host, so the ordered log filled with repeated '# collect_registry' fragments and the intended per-host flush_host was a no-op. Fix: remove the decorator from those six (engine phase_scope already tags [target][phase]); Stage-1 discovery collectors keep it. (2) Full log always DEBUG: create the ordered handler at DEBUG and pin openhound_sccm + openhound_collector_common loggers to DEBUG for the run, so the full log always has the complete collector trace regardless of console level; dlt/ldap3 still need --debug. (3) Rename collect_log_* -> collect_full_*, collect_diagnostics_* -> collect_issues_* (+ summary labels). Also truncate the ccmsetup.exe HTTP body-preview debug line in clients/http.py to 1024 chars. Tests: tests/test_per_host_log_blocks.py (+1 regression guard). Docs: README verbosity tip / --silent / --run-all rows, ARCHITECTURE section 7 + changelog.

## Notes

**2026-07-22T15:20:45Z**

Code + tests complete (not committed; not live-run-verified). Fixed in: collectors/{registry,mssql,privileged,http,smb}.py (removed @with_log_context + unused import from the 6 per-host collectors); main.py (_OrderedLogFileHandler at DEBUG; pin openhound_sccm + openhound_collector_common to DEBUG w/ save+restore; rename collect_log_->collect_full_, collect_diagnostics_->collect_issues_; summary labels Full log/Issues log; --silent help text; _apply_log_level docstring); clients/http.py (truncate ccmsetup body preview to 1024). Tests: tests/test_per_host_log_blocks.py +1 (test_per_host_collectors_do_not_fire_resource_complete) failing-before/passing-after; 105 collector+log tests green. Docs: README + ARCHITECTURE section 7 + changelog. NOTE: encountered an UNRELATED in-progress user refactor in kinds/edges.py (namespacing edge kinds to SCCM_/MSSQL_ prefixes) that transiently broke import via dangling edge_help.py refs; user was reconciling live, import now clean. Remaining: user live-run eyeball + commit.

**2026-07-22T15:56:05Z**

Follow-up (same session): always-DEBUG full log surfaced a latent label bug — VERBOSE (15) was absent from _ORDERED_LEVEL_LABEL so full-log VERBOSE lines rendered 'L15'. Fixed _OrderedLogFileHandler._write_section fallback to use logging.getLevelName(rec.levelno) padded (renders 'VERBOSE'; robust for any named level). Regression test tests/test_per_host_log_blocks.py::test_verbose_records_render_with_level_name_not_l15.

**2026-07-22T16:04:31Z**

Live-tested and verified by user 2026-07-22 (full log groups per-host, always-DEBUG, renamed files, VERBOSE label, HTTP content truncated). Closing.
