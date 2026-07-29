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
