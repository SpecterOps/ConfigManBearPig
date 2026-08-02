---
id: con-a4ec
status: open
deps: []
links: []
created: 2026-08-02T01:49:16Z
type: task
priority: 3
tags: [sccm, run-all, shared-lib]
---

# Adopt StagePaths.graph_zip once openhound-collector-common is released

openhound-collector-common gained StagePaths.graph_zip: run_end_to_end now returns the archive zip_graph_output actually wrote (None when convert emitted no *.json), instead of discarding it. Implemented in the sibling checkout at Desktop/openhound-collector-common (unreleased at time of writing).

_log_all_output_locations currently reconstructs graph_out / graph_zip_name and re-tests existence, because the field did not exist when con-8a28 added the 'Upload to BloodHound' line. Once the library is released, drop the graph_zip_name parameter from _log_all_output_locations and read _paths.graph_zip instead -- the path that was written rather than the one we asked for. The two can disagree; only the returned one is evidence.

Blocked on a published release: ConfigManBearPig installs openhound-collector-common from PyPI (currently 0.1.2, floor '>=0.1.2,<0.2.0' in pyproject.toml) and deliberately carries no [tool.uv.sources] redirect, so adopting the field before the release would break uv sync for anyone who is not developing against a sibling checkout.

## Acceptance Criteria

openhound-collector-common >=0.1.3 released; ConfigManBearPig's dependency floor bumped to match; _log_all_output_locations takes the StagePaths and reads .graph_zip with no reconstruction; tests updated; ARCHITECTURE section 12 note about the shared-library gap removed since it is closed.

## Notes

**2026-08-02T02:29:44Z**

Library half is done and committed: openhound-collector-common 961f1c5 'feat(orchestration): report the graph archive run_end_to_end actually wrote' (local commit on main, not pushed, not tagged).

This ticket stays OPEN because the collector half cannot land yet: ConfigManBearPig resolves openhound-collector-common from PyPI (0.1.2 installed, floor '>=0.1.2,<0.2.0') and deliberately carries no [tool.uv.sources] redirect, so reading paths.graph_zip before a release would break uv sync for anyone without a sibling checkout.

Unblocks when 961f1c5 is pushed and tagged v0.1.3 and published. Then: bump the floor to >=0.1.3, drop the graph_zip_name parameter from _log_all_output_locations and read _paths.graph_zip instead, update tests/collect_run_all_test.py, and remove the 'shared-library gap' sentence from ARCHITECTURE section 12.
