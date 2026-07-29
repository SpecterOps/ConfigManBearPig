---
id: ope-16f5
status: closed
deps: []
links: []
created: 2026-06-26T14:19:45Z
type: task
priority: 1
tags: [sccm, graph, property-naming]
---

# Rename SCCM node/edge properties to ConfigManBearPig.ps1 casing

Reverse the snake_case property-name decision: rename every SCCM node/edge OUTPUT property in graph.py (and all model construction sites) to ConfigManBearPig.ps1's EXACT casing so BloodHound entity panels render them, mirroring MSSQL D11. Also add 6 missing SCCM_Site props (siteServerFQDN, siteServerDomainSID, SQLServerFQDN, SQLServerDomainSID, SQLServiceAccountDomainSID, SQLServicePort) derived from already-collected data. Update tests + README + ARCHITECTURE.

## Acceptance Criteria

All node/edge output property keys match CMBP casing (verified against ConfigManBearPig.ps1); 6 new SCCM_Site props emitted from collected data; pytest + ruff green in isolated venv; README Node/Edge Reference and ARCHITECTURE updated.

## Notes

**2026-06-26T18:17:37Z**

Implemented: renamed all SCCM node/edge OUTPUT properties in graph.py + 9 model construction sites to ConfigManBearPig.ps1-verbatim casing (verified against ps1 source lines). Added 6 SCCM_Site props (siteServerFQDN/siteServerDomainSID/SQLServerFQDN/SQLServerDomainSID/SQLServiceAccountDomainSID/SQLServicePort) derived in _node_site from already-collected data (no re-collect). Updated 11 test files + new-prop coverage, README Node/Edge Reference + ARCHITECTURE.md. Validation: pytest 483 passed / 5 skipped; ruff clean on all changed files. Mapping doc: docs/superpowers/plans/2026-06-26-sccm-cmbp-property-casing.md. Not committed (user commits after testing).
