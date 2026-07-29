---
id: ope-00ca
status: closed
deps: []
links: []
created: 2026-07-15T19:24:10Z
type: task
priority: 2
tags: [sccm, cli, logging]
---

# SCCM collect: silence dlt progress bars by default (--progress off)

The dlt tqdm progress bars (adminservice_* counters) smear into the SCCM collector's clean [host][phase] INFO/VERBOSE log output during collection. Add an 'off' choice to the collect sccm --progress flag and make it the default, silencing dlt progress entirely (dlt maps progress=None to its NULL_COLLECTOR). Implemented SCCM-side only via a duck-typed shim whose .value is None, passed to core Collector; no OpenHound-core edits. tqdm/log/alive_progress remain opt-in. Update README + add a test.

## Notes

**2026-07-15T19:27:40Z**

Done. main.py: added ProgressOption enum (off/tqdm/log/alive_progress), _SilentProgress shim (.value=None), _resolve_progress(); collect sccm --progress now defaults to off. dlt maps progress=None -> NULL_COLLECTOR, so no core edit. README CLI table updated. tests/test_progress_option.py added (3 tests). Verified: 21 CLI/collect tests pass; 'collect sccm --help' renders [off|tqdm|log|alive_progress], exit 0.
