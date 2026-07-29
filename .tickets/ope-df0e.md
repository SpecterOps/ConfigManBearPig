---
id: ope-df0e
status: closed
deps: []
links: []
created: 2026-07-15T14:36:55Z
type: bug
priority: 1
---

# Fix SCCM_AssignAllPermissions DB->every-site over-emission (own-site only)

SCCM_AssignAllPermissions from databases did node_mssql_database CROSS JOIN every non-secondary site -> every DB (incl. secondary CM_SEC) -> every primary site (6 edges). CMBP live output: each PRIMARY site DB -> its OWN site only (2), no secondary DB node. FIX: transforms.py _edge_mssql_db_assign_all joins each DB to its own sccm_site with site_type!=1 (drops secondary DBs, removes DB->every-site false positives like PS1-DB->CAS). Matches CMBP; recovered 1 test.
