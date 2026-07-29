---
id: ope-50cc
status: closed
deps: []
links: [ope-2419]
created: 2026-07-29T22:10:40Z
type: bug
priority: 3
tags: [tests, edge-help, sccm]
---

# edge_help scope test red since GenericAll became an emitted kind

tests/edge_help_test.py::test_scope_is_complete had been failing unnoticed. It asserts that every emitted edge kind has entity-panel help, excluding the kinds BloodHound documents natively (MemberOf, HasSession). GenericAll became an emitted kind during the Tier A+ System Management container DACL work (ope-e191 / Task 11) but was never added to that exclusion, and PENDING_HELP_KINDS is empty, so the assertion went red. Nobody saw it because nothing was running the full suite -- the same gap that left ruff at 50 errors and mypy at 273. FIXED by naming the exclusion set NATIVELY_DOCUMENTED_KINDS = {MEMBER_OF, HAS_SESSION, GENERIC_ALL} with a comment explaining the category: this collector emits these standard base kinds so its nodes merge into the native AD graph, and writing our own help for them would duplicate and eventually contradict BloodHound's own. kinds/edges.py already says as much ('same as SharpHound's own GenericAll/MemberOf edges'). Found while sweeping the full suite after the BloodHound upload removal (ope-2419).

## Acceptance Criteria

Full collector suite green: 890 passed, 5 skipped. GenericAll is excluded by name with a documented reason rather than by a silent count.
