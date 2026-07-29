---
id: ope-194a
status: closed
deps: []
links: []
created: 2026-07-14T19:09:34Z
type: bug
priority: 1
---

# Fix SCCM_AdminUser displayName/displayname case-collision (breaks OpenGraph ingestion)

SCCM_AdminUser nodes emitted the same display-name property under two casings: the framework base lowercase 'displayname' AND a camelCase 'displayName'. Case-insensitive consumers (PowerShell ConvertFrom-Json, BloodHound/Neo4j ingestion) reject this as a duplicate key, so the entire OpenGraph payload fails to parse. CMBP emits only camelCase displayName and never collided. Discovered while running Invoke-ConfigManBearPigUnitTests.ps1 against OpenHound output on 2026-07-14. FIX (keep-camelCase, CMBP parity): models/sccm_admin_user.py sets base displayname=None (pruned) and keeps displayName (empty pruned to match CMBP); graph.py comments corrected; regression test added in tests/sccm_admin_user_test.py. Validated: 553 passed / 5 skipped, ruff+mypy clean.
