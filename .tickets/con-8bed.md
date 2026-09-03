---
id: con-8bed
status: closed
deps: []
links: []
created: 2026-09-03T12:00:00Z
type: bug
priority: 1
tags: [real-env, local]
---

# Local client-log scrape ran without the SCCM-client gate the WMI resources have

Found during a real-environment (non-lab) assessment: `local_client_logs_targets()`
(`collectors/local.py`) only checked `platform.system() == "Windows"` before scraping
`CCM\Logs`/`ccmsetup\Logs`, unlike the three WMI resources beside it, which all gate on
`_wmi_ccm()` (root\CCM namespace present — i.e. this box is a genuine, currently-enrolled
SCCM client). CMBP's original `Invoke-LocalCollection` (PS1) returned at its own top when
that namespace was absent, before ever reaching its log-scrape code later in the same
function — so this was a fidelity gap introduced when the port split one PS1 function into
separate resource functions, not a deliberate divergence.

Symptom: on a real, long-lived SCCM client with a large `DataTransferService.log`
(logs one line per content byte-range chunk), this printed thousands of VERBOSE
"Found URL" lines per second, and ran on any Windows box regardless of whether it
was actually a current SCCM client.

## Fix

`local_client_logs_targets()` now gates on `_wmi_ccm()` too, so a box with leftover
log folders from an uninstalled client (or any non-client box) is skipped before
ever opening a log file. A real, currently-enrolled client still scrapes its logs,
unchanged from before.

## Notes

**2026-09-03T12:00:00Z**

Fixed and tested. New regression test `test_log_scrape_skipped_when_not_an_sccm_client`
in `tests/local_log_scrape_regex_test.py`; existing tests updated to mock `_wmi_ccm`
instead of `platform.system`.
