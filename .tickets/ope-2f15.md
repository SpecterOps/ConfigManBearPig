---
id: ope-2f15
status: closed
deps: []
links: [ope-e10b]
created: 2026-07-22T16:05:01Z
type: task
priority: 2
tags: [sccm, edge, schema]
---

# Rename SCCM edge kinds to match schema.json (SCCM_/MSSQL_ namespacing)

Aligned the SCCM collector edge kind strings with the hand-maintained OpenGraph schema (schema.json). Added the SCCM_ namespace prefix to four edges: SameHostAs->SCCM_SameHostAs, LocalAdminRequired->SCCM_LocalAdminRequired, CoerceAndRelayToAdminService->SCCM_CoerceAndRelayToAdminService, CoerceAndRelayToSMB->SCCM_CoerceAndRelayToSMB. Moved the SQL relay into the separate MSSQL schema namespace: CoerceAndRelayToMSSQL->MSSQL_CoerceAndRelayToMSSQL (end node is MSSQL_Login; declared in the MSSQL schema the operator uploads, NOT sccm/sccm/schema.json). Corrected schema.json the other direction: SCCM_SameAdminsAs->SCCM_AdminsReplicatedTo to match the code-true kind. Changed kinds/edges.py constant values + identifiers + TRAVERSABLE_EDGE_KINDS; propagated to transforms.py, models/graph_edge.py, edge_help.py, cve_table.py, collectors/mssql.py, 7 cypher_queries/*.json, README, ARCHITECTURE (body + changelog), and 12 offline edge tests. CMBP-history and dated changelog rows left verbatim. No graph-shape change. SCCM_HasNetworkAccessAccount left as a schema placeholder, spun out to ope-e10b. Validated: 41 passed / 1 skipped targeted edge tests, py_compile + ruff clean, 19/19 JSON valid.

## Notes

**2026-07-22T16:05:12Z**

Tested and verified by Mayyhem (2026-07-22). Closing.
