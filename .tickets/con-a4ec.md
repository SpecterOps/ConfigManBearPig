---
id: con-a4ec
status: closed
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

**2026-08-02T03:15:48Z**

DONE. openhound-collector-common 0.1.3 published; floor bumped >=0.1.2 -> >=0.1.3 and uv sync resolves it (note: uv needed --refresh-package openhound-collector-common, its index cache still claimed only <=0.1.2 was available minutes after the release went live).

_log_all_output_locations lost its graph_zip_name parameter and reads paths.graph_zip. The name now travels one way only, from collect_sccm into run_end_to_end. Two tests pin the distinction by placing a DIFFERENTLY NAMED stale archive in the graph dir beside the reported one -- the exact shape produced by re-running into a used output directory, which is what --clean exists to manage, and which a reconstructed path cannot disambiguate.

Also corrected stale floors the bump exposed: ARCHITECTURE said >=0.1.0 in the shared-library section and still carried a section-12 note claiming the 0.1.1 bump was 'deferred'; README and PUBLISHING both said >=0.1.0. All now >=0.1.3. ARCHITECTURE section 12 rewritten and a changelog entry added.

Verified: pytest 1027 passed / 5 skipped (up 2 from the new tests), ruff clean, mypy clean across 63 files. Four live cells against mayyhem.com; the privileged pe-on graph is IDENTICAL to out/priv9 apart from timestamp drift -- 0 regressions, 0 additions, 156 changed values -- confirming this change is display-only as intended.
