---
id: ope-aa39
status: closed
deps: []
links: [ope-a214]
created: 2026-07-15T20:28:47Z
type: task
priority: 2
tags: [sccm, graph, entity-panel, edges]
---

# Add entity-panel help content to SCCM edge property bags

Add per-edge entity-panel help content (general/windowsAbuse/linuxAbuse/opsec/references) to the property bag of every SCCM-emitted custom edge kind that BloodHound lacks native help for. Per-kind content map (edge_help.py) + 5 nullable fields on SCCMEdgeProperties + tiny lookup in graph_edge.py. User provides all prose; vertical slice wires SCCM_AdminsReplicatedTo and scaffolds stubs for the rest. Spec: docs/superpowers/specs/2026-07-15-edge-entity-panel-help-design.md

## Notes

**2026-07-15T21:11:07Z**

Spec + plan written. Spec: docs/superpowers/specs/2026-07-15-edge-entity-panel-help-design.md. Plan: docs/superpowers/plans/2026-07-15-edge-entity-panel-help.md (3 tasks: edge_help.py content map; graph.py fields + graph_edge.py lookup; e2e validation + README). Vertical slice wires SCCM_AdminsReplicatedTo; PENDING_HELP_KINDS holds the 34 kinds awaiting user-provided prose.

**2026-07-16T15:01:54Z**

COMPLETE (mechanism + vertical slice), no commit per CLAUDE.md. Shipped: edge_help.py (EdgeHelp + EDGE_HELP + PENDING_HELP_KINDS), 5 nullable help fields on SCCMEdgeProperties, GraphEdge merge, 3 test files, README Edge Reference. 27/27 targeted tests green; ruff clean; mypy no new errors. All per-task reviews + final opus review passed (all findings fixed). REMAINING (user): author prose for the 34 kinds in PENDING_HELP_KINDS, then move each into EDGE_HELP. Flagged: MSSQL_* blocks duplicated SCCM-local per low-reuse directive (optional ticket for MSSQL agent to mirror).

**2026-07-16T18:16:27Z**

Authored SCCM_HasClient block (user-provided prose); removed from PENDING_HELP_KINDS. Now 2 authored / 33 pending. Fixed 2 prose typos in provided content (stray backtick in 'get devices' command; missing ')' in FileContent KQL). Reworked edge_help_integration_test.py: SCCM_HasClient was its unauthored example, so switched the pruning proof to SCCM_IsMappedTo (still pending), added a positive e2e assertion for SCCM_HasClient, and made the negative check dynamic vs EDGE_HELP. 13/13 help tests green, ruff clean. No commit.

**2026-07-16T18:44:14Z**

Authored 4 more edges (IsMappedTo, HasPrimaryUser, HasCurrentUser, HasADLastLogonUser) with {source/target}Name tokens rephrased to generic wording per user; single 'Abuse' section -> windowsAbuse, linuxAbuse omitted. Plus IsAssigned + AssignAllPermissions (5 standard fields) earlier this session. Now 8 authored / 27 pending. Hardened tests against author-my-own-example fragility: emit test picks PENDING_HELP_KINDS[0] dynamically; integration test negative case now uses HasSession (permanently excluded, seeded via remoteregistry_users) instead of a PENDING kind. 13/13 help tests green, ruff clean. BLOCKED on AssignAllPermissions Composition: user's spec describes admin-user path (Full/Security Admin role + All Systems/All Users collections via SCCM_IsAssigned) but our collector emits SCCM_AssignAllPermissions only from Computer(SMS Provider)/Database->Site; admin-user 'all perms' case is SCCM_AllPermissions. Spec also references SCCM_SameAdminsAs/SourceSiteIdentifier/SiteIdentifier not in our schema. Awaiting user decision on composition target/scope.

**2026-07-16T18:51:26Z**

Composition for SCCM_AssignAllPermissions DEFERRED per user ('add later'); tracked in ope-a214 (composition property + admin-user AssignAllPermissions collector-gap investigation). No composition field added. Batch result: 8 authored / 27 pending; 13/13 help tests green; ruff clean; no commit.

**2026-07-16T19:19:49Z**

Authored SCCM_AllPermissions (admin-user 'has all perms': Full Administrator SMS0001R + All Systems SMS00001 + All Users SMS00004 -> site, per transforms._edge_all_permissions:2618) and TRIMMED SCCM_AssignAllPermissions to code-truth sources only: SMS Provider computer (:2646) + MSSQL_Database (:2835). Removed 'SCCM admin user' paragraph (that's AllPermissions) and 'Primary site server' paragraph (indirect via MSSQL->Database, not a direct source). Fixed abuse text 'Full Administrator OR Security Administrator' -> code requires Full Administrator only. Now 9 authored / 26 pending. 13/13 help tests green, ruff clean. No commit.

**2026-07-16T19:39:26Z**

Authored 7 RBAC role edges (FullAdministrator, OperationsAdministrator, ApplicationAdministrator, ApplicationAuthor, ComplianceSettingsManager, OSDManager, SecurityAdministrator), all AdminUser->ClientDevice per _edge_rbac_role_grants:2575. SKIPPED SCCM_CMPivotAdministrator: not in our code (role SMS000CR is in _ROLE_KNOWN_NO_EDGE:2549, no edge emitted). Tokens rephrased generic; single 'Abuse' sections -> windowsAbuse; fixed provided-content typos (stray backtick in get-devices cmd, FileContent missing paren, SecurityAdmin 'that'->'than'). Now 16 authored / 19 pending. 13/13 help tests green, ruff clean. No commit.

**2026-07-17T14:30:59Z**

Authored 7 SCCM edges (PROPOSED copy, drafted by me, code-accurate): SCCM_HasStoredAccount (Site->reserved acct; NAA/DPAPI recovery), SCCM_Contains (structural, no abuse), SameHostAs (Computer<->ClientDevice identity link, no abuse), LocalAdminRequired (site server->co-located site systems = AdminTo-style lateral), and 3 coerce-relay POSSIBLE edges (CoerceAndRelayToAdminService/MSSQL/SMB: coerce+ntlmrelayx, Misconfiguration Manager TAKEOVER refs). Now 24 authored / 11 pending (all MSSQL). MSSQL extraction dispatched to subagent (fetch MSSQLHound.ps1 EdgePropertyGenerators, genericize, skip Composition). 12/12 unit+emit green, ruff clean. No commit.

**2026-07-17T14:39:32Z**

Authored all 11 MSSQL edges from MSSQLHound.ps1 EdgePropertyGenerators (subagent-extracted to .sdd/mssql_edge_help.md, genericized: variable-substitution/node-type conditionals collapsed, Composition skipped). MSSQL_Contains has no opsec (source omits it). Backslashes escaped (.\Rubeus, internal.lab\sqlsvc, DOMAIN\COMPUTER$). PENDING_HELP_KINDS now empty (all 35 scoped edges authored); emit test skips its pending-kind case when empty. UPSTREAM BUG flagged by subagent: MSSQLHound.ps1 MSSQL_GetTGS abuse uses 'setspn -L <login>' (copy/paste from GetAdminTGS) but target is a login not a server; genericized both to 'setspn -L target_sql_server' per intent -- worth raising with MSSQL extension. 35 authored / 0 pending. ruff+mypy clean, 12 passed +1 skipped (help), 14 edge-regression green. No commit.

**2026-07-17T15:18:07Z**

Reworked the 3 CoerceAndRelayTo* edges to follow MSSQLHound.ps1 CoerceAndRelayToMSSQL format (subagent-extracted): 3-step numbered abuse (ntlmrelayx.py target -> coerce via SpoolSample/PetitPotam/Coercer -> relay outcome), separate Windows/Linux command variants. Kept code-accurate framing (AuthUsers source, per-edge gates, possible-edge caveat). Fixed References from the generic TAKEOVER list to specific techniques: AdminService=TAKEOVER-5, MSSQL=TAKEOVER-1, SMB=TAKEOVER-2/6/7; added Coercer (p0dalirius) + Extended Protection doc (MSSQL). Backslashes escaped (DOMAIN\COMPUTER$). Still 35 authored/0 pending. ruff clean, 11 passed+1 skipped. No commit.

**2026-07-17T17:47:55Z**

Closed: committed + pushed in 4379303. Edge entity-panel help shipped; 35/35 scoped edges authored, PENDING_HELP_KINDS empty. Deferred composition work tracked separately in ope-a214.
