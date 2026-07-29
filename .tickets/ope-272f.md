---
id: ope-272f
status: closed
deps: []
links: []
created: 2026-06-25T19:45:07Z
type: feature
priority: 1
tags: [mssql, opengraph, port]
---

# MSSQL OpenHound collector port (MSSQLHound parity)

## Notes

**2026-06-25T21:26:26Z**

Stage 3.3 (DLT source wiring) complete. Added openhound-collector-common/dlt/source_bridge.py (StreamBridge push->pull + extract_workers_for). Wired openhound_mssql/source.py (18 emit resources over COLLECTED_TABLES) + models/raw_table.py + collection/run.py (worker pool producer, partial-on-connect-failure) + main.py _run_collection (bg producer thread, collector.run drains, drain-while-join cleanup). Found+fixed a real impacket 0.13.1 bug: the _Tds.parseRow override (in shared mssql.py, value-decode path) never returned the consumed byte length, so impacket's _parse_reply_tokens sliced token Data [:None] and swallowed all rows after the first -> exactly 1 row per result set. Restored the consumed-length return; added regression test. Live verify as MAYYHEM\domainadmin vs ps1-db.mayyhem.com: server_principals=51, databases=5, database_permissions=6943; compatibility_level=160 (int); SQL NULL -> JSON null. 126 pytest pass. NOTE: dlt filesystem destination fails on 8.3 short-name bucket paths (DOMAIN~2) - use a full path; this is a dlt/Windows issue, not collector code.

**2026-06-25T21:46:44Z**

Stage 4 (preproc DuckDB derivations + lookup) complete. main.py @app.preproc returns the 18-table map keyed mssql/<table> (dlt writes JSONL under <bucket>/<dataset>/<table>/; the dataset-name prefix was the load-bearing fix - without it preproc loaded zero raw tables and all derived tables were empty). transforms.py builds (live counts vs ps1-db as domainadmin): server_principal_map=51, database_principal_map=141, server_role_closure=42 (nested + implicit public), database_role_closure=89 (per-db), effective_high_priv=13 + effective_high_priv_summary (domainPrincipalsWith{Sysadmin,ControlServer,Securityadmin,ImpersonateAnyLogin} + isAnyDomainPrincipalSysadmin=True), server_fixed_role_permissions=4, database_fixed_role_permissions=20, linked_server_flags=1. Ported collector.go hasEffectivePermission/hasNestedRoleMembership BFS + fixedServer/DatabaseRolePermissions; SID hex->S-1-5 decoder reproduces convertHexSIDToString. lookup.py MSSQLLookup with dict-backed point lookups + lru_cache lists. DECISION: raw rows are not per-server-stamped, so Stage 4 derives ONE server_oid from the servers row (correct for single-target; multi-server stamping is a Stage 3 follow-up; server_oid column on every derived table). BLOCKER: linked-server remote-privilege flags come from MSSQLHound's recursive probe Stage 3 does not collect yet -> ensure_columns'd as NULL, is_linked_as_admin=False until Stage 7. 137 pytest pass; live preproc builds lookup.duckdb, no BinderException.

**2026-06-29T15:19:19Z**

Stage 7b complete (linked-server recursion + remaining AD/credential/service-account/coercion edges). COLLECT: replaced level-0 query with the verbatim Go collectLinkedServers server-side recursive batch (queries.LINKED_SERVERS_RECURSIVE: #mssqlhound_linked + OPENQUERY RoleHierarchy probe, level<=10, cycle-safe) -> populates remote sysadmin/securityadmin/control-server/impersonate-any-login/mixed-mode/current-login flags. server.py honors --skip-linked-servers; run.py implements --collect-from-linked (queue discovered DataSources, cycle-safe visited set). transforms.linked_server_flags reads the now-populated flags + the full Go LinkedTo prop bag. EDGES: new edges/derive_ad.py iterated alongside derive.py by edge_rules (Stage-6 untouched). LinkedTo(possible)/LinkedAsAdmin/HasLogin/HasSession/ServiceAccountFor(possible)/GetTGS/GetAdminTGS/HostFor/ExecuteOnHost/HasMappedCred+HasDBScopedCred+HasProxyCred(possible,+credentialId/proxyId as Go-style strings)/CoerceAndRelay, edges.go-verbatim property bags + 4 composition Cypher, SID-based endpoints; credential_identity->SID via ad_resolved name index. Decisions (Go-preferred): ServiceAccountFor uses the 2nd edges.go generator (map-overwrite winner); credentialId/proxyId as strings. LIVE (domainadmin -t ps1-db): recursion found ps1-db->CAS-DB(L0) + chained CAS-DB->ps1-db(L1); 33/38 knownEdgeTypes incl every new kind the lab supports (HasLogin=10 GetTGS=8 CoerceAndRelay=5 LinkedTo=2 LinkedAsAdmin=1 ServiceAccountFor=1 etc). 5 absent are data-gated not impl gaps (Alter/AlterAnyServerRole/ChangeOwner/TakeOwnership=no lab grants; HasProxyCred=no authorized proxy_logins). 213 nodes/611 edges, no Stage5/6 regression. 206 pytest pass (17 new). OUTSTANDING: README still WIP stub.
