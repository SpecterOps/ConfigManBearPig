---
id: con-68c2
status: in_progress
deps: []
links: []
created: 2026-07-31T15:03:42Z
type: task
priority: 2
---

# Standardize test filenames on *_test.py, pin the glob, retire docs-site scaffolding -type chore -priority 2 -tags tests,cleanup,naming,docs -description Rename the 33 remaining test_*.py files to the *_test.py suffix convention (30 straight renames + 3 name collisions resolved by topical rename, no test bodies touched), pin python_files = "*_test.py" in pyproject.toml, retire the never-configured docs-site scaffolding (docs/javascript, docs/stylesheets, the zensical dev dependency, two dead pre-commit excludes), and repath the two ARCHITECTURE.md links the renames break plus document the pin in README. Plan: docs/superpowers/plans/2026-07-24-sccm-repo-cleanup.md. Collected-test count is the invariant: 898 before and after.

## Notes

**2026-07-31T15:30:46Z**

Tasks 1-6 implemented, uncommitted on main per owner choice. 30+1 renames (Task 1), stub_per_host_phases extraction + all_table_names de-duplication + 3 import repoints (Task 2), 3 topical renames for the remaining collisions (Task 3), python_files pinned (Task 4), docs-site scaffolding retired + re-locked (Task 5), 2 ARCHITECTURE links repathed + README pin paragraph (Task 6). Zero test bodies changed. CI's four gated files 19/19 pass, ruff clean, mypy clean on 63 files, 901 collected. FOUND A PRE-EXISTING BUG: debug_exc_info_filter_test.py's two install_filter() tests leak a root-logger filter with no teardown; the Task 1 rename flipped alphabetical order so it now runs before local_log_scrape_regex_test.py, failing 2 of its tests. Order-dependence proven both directions with a control. Awaiting owner decision on the fix.

**2026-07-31T15:38:01Z**

Status audit 2026-07-31: CORRECTLY IN PROGRESS. Remaining work measured against the working tree: 159 of 164 test files now use the *_test.py suffix, TWO stragglers remain -- tests/test_privileged.py and tests/test_registry_current_user.py; and the python_files pin is NOT in place (pyproject.toml has no [tool.pytest.ini_options] section at all, so the suffix convention is currently unenforced and a future test_*.py would still be collected). Docs-site retirement is under way: the zensical dev dependency is gone from pyproject.toml and docs/javascript + docs/stylesheets are staged as deleted in git, though still present on disk. CAUTION -- THE RENAME HAS BROKEN TWO TESTS. The full suite is now 891 passed / 2 failed / 5 skipped, against 893 passed / 0 failed reported by con-c522 earlier today. Both failures are tests/local_log_scrape_regex_test.py (test_found_url_logs_the_full_url_not_just_the_host, test_found_unc_logs_the_full_path). The collected-test count invariant this ticket set for itself held at 898 -- but the PASS count did not, because the invariant does not catch order dependence. Mechanism: install_filter() attaches the shared LogContextFilter process-wide and never removes it, a leaked 'Local' phase contextvar makes it prepend '[Local] ' to record.msg, and those two tests assert exact message equality. The rename moved test_debug_exc_info_filter.py -> debug_exc_info_filter_test.py and test_cli_option_panels.py -> cli_option_panels_test.py, i.e. from 't' to 'd' and 'c', so they now run BEFORE local_log_scrape_regex_test.py instead of after. Minimal reproducers: 'pytest tests/debug_exc_info_filter_test.py tests/local_log_scrape_regex_test.py' and 'pytest tests/cli_option_panels_test.py tests/local_log_scrape_regex_test.py'. The product code is fine (see ope-8b99); the tests need to stop asserting on the un-prefixed message, or install_filter needs to be undone in a fixture. This must be fixed before this ticket closes -- a rename that leaves the suite red is not a no-op refactor.

**2026-07-31T15:39:55Z**

CORRECTION to the audit note above (same day, ~10 minutes later): the working tree moved while the audit was running -- another session completed Tasks 1-6 mid-review. Re-verified now: python_files = "*_test.py" IS pinned (pyproject.toml:216-222, with a good comment recording the consequence that a test_something.py file is now silently NOT collected), and ZERO test_*.py files remain under tests/, so the two stragglers named above (test_privileged.py, test_registry_current_user.py) have been resolved by topical rename. Disregard those two points. What STANDS from the audit note: the two red tests in tests/local_log_scrape_regex_test.py, the mechanism, and the second reproducer via cli_option_panels_test.py -- that reproducer is additional to the debug_exc_info_filter_test.py one already recorded in this ticket's own 15:30 note, so the leak has at least two triggers, and a fix that only adds teardown to debug_exc_info_filter_test.py will not be sufficient.

**2026-07-31T15:49:20Z**

Figure update: re-ran the full suite after Tasks 1-6 finished landing -- 897 passed / 2 failed / 5 skipped, 904 collected (the audit note above measured 891 / 898 mid-flight). The two failures are unchanged and still tests/local_log_scrape_regex_test.py; they are tracked in their own ticket con-e455 now, so treat that as this ticket's blocker rather than re-diagnosing here. The point stands: the collected-test count invariant this ticket set held, but the suite is red, so the rename is not yet the no-op refactor it is meant to be.

**2026-07-31T16:02:50Z**

COMPLETE, uncommitted on main per owner choice. Root-caused and fixed the isolation leak: install_filter() installs BOTH singletons on the root logger AND on every handler of the '' and 'dlt' loggers, with no uninstall. The damaging one is _FILTER_SINGLETON (LogContextFilter), which rewrites record.msg to carry a [target][phase] prefix -- that broke local_log_scrape_regex_test.py's exact-match message assertions. A first fix removing only _EXC_INFO_FILTER_SINGLETON from root did NOT work; the complete teardown (both singletons, root + both loggers' handlers) does. Pre-existing bug, hidden purely by alphabetical order until the rename moved this file from 't' to 'd'. Full suite: 899 passed, 5 skipped, 0 failed. CI's four 19/19, ruff clean, mypy clean on 63 files, 904 collected, zero test_*.py remain, zero test bodies changed apart from the isolation fixture.
