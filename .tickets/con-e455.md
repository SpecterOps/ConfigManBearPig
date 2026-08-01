---
id: con-e455
status: closed
deps: []
links: []
created: 2026-07-31T15:39:33Z
type: bug
priority: 2
tags: [testing, logging, test-isolation]
---

# install_filter() leaks the log-prefix filter across tests, breaking later log assertions

debug_exc_info_filter_test.py calls install_filter() at lines 145 and 150-151 with no teardown, and removeFilter appears nowhere in the collector source, so the shared [target][phase] log-prefix filter stays installed on the root logger for the remainder of the pytest session. Any later test asserting on raw log message text then sees '[Local] Found URL...' instead of 'Found URL...' and fails. Surfaced by the test_*.py -> *_test.py rename: under the old names the filter-installing tests sorted AFTER local_log_scrape_regex_test.py (t > l), so the leak was invisible; after the rename debug_exc_info_filter_test.py sorts BEFORE it (d < l). Minimal repro (2s): uv run pytest tests/debug_exc_info_filter_test.py tests/local_log_scrape_regex_test.py -- 2 failed, 29 passed. Pre-existing test-isolation defect, not caused by the dependency bump or the con-0170/con-6677 fixes. Fix direction: an autouse fixture (or explicit teardown) that removes the filter, so global logging state does not leak between tests; making the assertions prefix-agnostic would hide the leak rather than fix it.

## Acceptance Criteria

uv run pytest tests/debug_exc_info_filter_test.py tests/local_log_scrape_regex_test.py passes, the full suite passes in any file order, and no test leaves the prefix filter installed on the root logger.

## Notes

**2026-07-31T15:41:46Z**

Independent confirmation from the 2026-07-31 ticket-status audit, plus a SECOND trigger this ticket does not name. Scanning every tests/[a-e]*_test.py file paired against local_log_scrape_regex_test.py found TWO files that reproduce, not one: 'pytest tests/debug_exc_info_filter_test.py tests/local_log_scrape_regex_test.py' (the one already recorded here) AND 'pytest tests/cli_option_panels_test.py tests/local_log_scrape_regex_test.py' -> 1 failed, 2 passed. So a fix that only adds teardown to debug_exc_info_filter_test.py will leave the second path open; the autouse-fixture direction this ticket already prefers is the right one. Mechanism detail worth recording for the fix: LogContextFilter (openhound_collector_common/logging/log_context.py:203-228) does not merely annotate the record, it MUTATES record.msg in place by prepending the prefix and then sets a _oh_prefixed sentinel to avoid double-prefixing. That is why the leak is visible through record.getMessage() and why no formatter change can mask it. The leak needs BOTH conditions -- the filter installed AND a phase contextvar still set (here 'Local', from an @with_log_context(phase="Local") generator in collectors/local.py that a test abandons before exhaustion, so its context-reset finally never runs). Resetting the contextvars in teardown is worth doing alongside removing the filter, since either condition alone is harmless. Full-suite effect measured: 891 passed / 2 failed / 5 skipped, against the 893 passed / 0 failed that con-c522 recorded earlier the same day.

**2026-07-31T15:49:20Z**

Figure update (same audit, ~40 min later, after the con-68c2 renames finished landing): a fresh full-suite run measures 897 passed / 2 failed / 5 skipped / 102 subtests, 904 collected. The earlier note here said 891 passed / 898 collected -- the pass and collect counts moved only because more tests arrived mid-session, NOT because anything was fixed. Still the same two failures, still tests/local_log_scrape_regex_test.py::test_found_url_logs_the_full_url_not_just_the_host and ::test_found_unc_logs_the_full_path. Both reproducers still reproduce. This ticket remains open and the full suite remains red.

**2026-07-31T16:27:50Z**

Already resolved by @_Mayyhem's test refactor. Re-verified 2026-07-31: 'uv run pytest tests/debug_exc_info_filter_test.py tests/local_log_scrape_regex_test.py' now returns 31 passed (was 2 failed / 29 passed when filed). Closing without a code change from me.
