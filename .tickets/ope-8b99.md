---
id: ope-8b99
status: closed
deps: []
links: []
created: 2026-07-24T17:56:29Z
type: task
priority: 2
---

# Fix truncated full-URL verbose log in local client-log scrape

The local client-log scrape (collectors/local.py) logs 'Found URL: <full_url>' using the URL regex's group(0), but the ported regex stops at the hostname, so only 'scheme://fqdn' is logged instead of the full URL (port + path + query). CMBP's original regex captured the whole URL via its path tail. Fix: extend the Python URL regex so group(0) spans the entire URL while group(1) stays the bare hostname (host discovery unchanged, log-accuracy only). Decision: keep broad any-scheme discovery (do NOT restore CMBP http/https-only host restriction); leave UNC regex as-is (already logs full path; over-capture quirk is faithful to CMBP).

## Notes

**2026-07-24T18:01:09Z**

Fixed in collectors/local.py: extended url_pattern to consume optional port + path/query so group(0) (the value logged as 'Found URL') spans the whole URL; group(1) (bare host used for discovery) unchanged, so log-accuracy only. Decisions honored: kept broad any-scheme discovery; left UNC regex untouched. Added tests/local_log_scrape_regex_test.py (3 tests, all pass); existing local tests still green (12 pass).

**2026-07-31T15:37:31Z**

Status audit 2026-07-31: the FIX is intact but its two REGRESSION TESTS ARE NOW RED, broken by an unrelated in-flight rename. The product code is correct: collectors/local.py:287 and :291 log the full UNC path and full URL respectively, and the captured log output proves the whole URL and whole UNC path are emitted. What fails is the assertion, because tests/local_log_scrape_regex_test.py compares record.getMessage() for EXACT equality while the shared LogContextFilter (openhound_collector_common/logging/log_context.py:203-228) mutates record.msg to prepend '[target][phase] '. When an earlier test has called install_filter() and left a phase contextvar set to 'Local', the message becomes '[Local] Found URL in test.log: ...' and the exact match fails. It is order-dependent: the file passes 3/3 alone, and fails in the full suite. Two minimal reproducers, both files that con-68c2 has just renamed from test_*.py (moving them alphabetically BEFORE local_log_scrape_regex_test.py, which is why this only started failing now): 'pytest tests/debug_exc_info_filter_test.py tests/local_log_scrape_regex_test.py' and 'pytest tests/cli_option_panels_test.py tests/local_log_scrape_regex_test.py'. Tracked as a test-isolation defect, not a regression of this ticket's fix -- leaving closed.
