---
id: con-acdd
status: closed
deps: []
links: []
created: 2026-07-31T21:44:56Z
type: task
priority: 2
tags: [testing, integration, shared-lib, diagnostics]
---

# Integration runner conflates 'no such edge' with 'edge rejected by property match'

The integration runner reports a case as 'not found' both when NO edge of that kind exists and when edges exist but every candidate was rejected by the property matcher. Those are opposite problems and the wording hides which one you have. This cost real time: three separate tickets (con-c509, con-2249, con-6198) were opened to hunt for edges that were being emitted correctly the whole time -- the true cause was that their shared endpoint node lacked samAccountName, so the matcher rejected otherwise-correct edges. A run reporting 'property mismatch on samAccountName: expected sqlsccmsvc, got <absent>' would have pointed at the real bug immediately. Fix direction: in the shared runner, when edges_of_kind(case.kind) is non-empty but edge_matches rejected them all, report FAIL with 'property mismatch' plus the first failing key/expected/actual instead of 'not found'. LANDS IN openhound-collector-common (a separate repo), so it cannot be fixed from this one -- filed here so the finding is not lost.

## Acceptance Criteria

A case whose kind has candidate edges but no property match reports 'property mismatch' naming the first failing key, expected and actual; a case with no candidates still reports 'not found'.

## Notes

**2026-07-31T22:42:41Z**

FIXED in openhound-collector-common (@_Mayyhem authorised working in the sibling repo 2026-07-31).
integration_testing/runner.py: run_edge_case and run_node_case now distinguish 'no candidate of this kind exists' from 'candidates existed and every one was rejected by the property matcher'. The first still reports 'not found'; the second reports 'property mismatch (N candidates of this kind, none matched)'. Shared helper _no_match_detail carries the reasoning so both call sites stay in step.
Four tests written first; the two property-mismatch ones failed with 'AssertionError: not found', which is the exact conflation. Shared-library suite 117 passed, ruff and mypy clean.
NOT YET EFFECTIVE IN THE COLLECTOR: ConfigManBearPig resolves openhound-collector-common 0.1.1 from PyPI (site-packages, not an editable path), so this only reaches the SCCM integration output once a new library version is published and the dependency floor bumped.
