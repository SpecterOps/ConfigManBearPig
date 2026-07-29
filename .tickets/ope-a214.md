---
id: ope-a214
status: open
deps: []
links: [ope-aa39, Ope-rhzx]
created: 2026-07-16T18:51:17Z
type: task
priority: 3
tags: [sccm, graph, edges, composition, entity-panel]
---

# SCCM edge Composition property + admin-user AssignAllPermissions gap

Deferred from ope-aa39. (1) Add a 'composition' string property + Cypher to edges that need a BloodHound Composition tab (starting with the admin-user 'assign all permissions' path: SCCM_IsAssigned to a Full/Security Admin role [roleID SMS0001R/SMS000FR] + All Systems/All Users collections [collectionID SMS00001/SMS00004], with site recursion over SCCM_AdminsReplicatedTo). (2) INVESTIGATE collector gap: the SCCM_AssignAllPermissions abuse text lists 'SCCM admin user' as source principal #1, but transforms._edge_assign_all_permissions/_edge_mssql_db_assign_all emit SCCM_AssignAllPermissions only from Computer(SMS Provider)/Database->Site; the admin-user case is emitted as SCCM_AllPermissions instead. Decide whether an admin-user->SCCM_AssignAllPermissions edge should be emitted, or whether the composition belongs on SCCM_AllPermissions. (3) Reconcile spec schema names (SCCM_SameAdminsAs, SourceSiteIdentifier, SiteIdentifier) with our actual (SCCM_AdminsReplicatedTo, roleID/collectionID/rootSiteCode/sourceSiteCode).

## Notes

**2026-07-17T14:39:32Z**

Also relevant: MSSQL edge help now authored in SCCM extension (SCCM-local per low-reuse). If MSSQL extension mirrors these, note upstream MSSQLHound.ps1 MSSQL_GetTGS setspn bug (references login instead of SQL server).

**2026-07-20T19:56:58Z**

Scope pairing (2026-07-20): work jointly with Ope-rhzx (same underlying decision). Ope-rhzx ('Individual Permissions') is the still-unimplemented granular per-operation permission enumeration (SCCM_AssignSpecificPermissions). This ticket's item (2) — whether the admin-user path emits admin-user to SCCM_AssignAllPermissions or carries the composition on SCCM_AllPermissions — is the governing decision for both. Resolve once, then implement the edge composition property + the specific-permissions edges together.
