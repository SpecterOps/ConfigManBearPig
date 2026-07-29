---
id: ope-f1ce
status: closed
deps: []
links: [ope-60fe]
created: 2026-07-29T19:20:46Z
type: bug
priority: 2
tags: [convert, determinism, sccm]
---

# Graph array properties emitted in nondeterministic order

Graph array properties were emitted in nondeterministic order. The ~20 DuckDB list()/array_agg() aggregations that build graph arrays give no ordering guarantee and DuckDB aggregates multi-threaded, so two converts over byte-identical input emitted the same elements in different orders. Measured 2026-07-29 by reprocessing one cached bucket twice: 14 node + 6 edge property differences, in SCCM_AdminUser.collectionIds, SCCM_Site.siteSystemRoles, SCCM_CoerceAndRelayToSMB.coercionVictimHostnames, SCCM_CoerceAndRelayToAdminService.coercionVictimAndRelayTargetPairs. Node/edge counts, kinds, identities and triples were all stable -- only element order moved. Cost: BloodHound saw property changes on re-ingest that had not happened, and any run-to-run graph diff (which is what --compare-to-zip parity checking is) filled with false positives that could mask a real regression. FIXED at the single emit boundary in convert_pipeline.py: _without_null_properties renamed _normalize_properties, which now sorts array properties in addition to dropping nulls. Chosen over adding ORDER BY to 20 SQL expressions because one place cannot end up half-applied and it covers arrays added later for free. objectClass is exempt via _ORDER_SIGNIFICANT_PROPERTIES -- LDAP returns it in class-hierarchy order (top, person, organizationalPerson, user, computer), which is meaningful to a reader and already reproducible. Found while validating openhound 0.2.12 under ope-60fe; version-independent and pre-existing.

## Acceptance Criteria

Two preprocess+convert runs over the same cached bucket produce graphs that are identical property-for-property (timestamps excluded). Verified: was 14 node + 6 edge diffs, now 0 and 0. objectClass retains LDAP hierarchy order. Three offline tests in tests/convert_pipeline_test.py.
