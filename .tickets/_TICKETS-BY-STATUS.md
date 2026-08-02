# Tickets by status

Generated from the ticket files in this directory, which are the source of truth.
Regenerate after any status change rather than editing by hand.
`.gitattributes` marks this file `merge=ours`, which needs a one-time
`git config merge.ours.driver true` per clone.

**147 tickets** — 6 in progress · 29 open · 112 closed

## In progress (6)

| Ticket | P | Type | Title | Tags |
|---|---|---|---|---|
| [`ope-60fe`](ope-60fe.md) | 1 | task | Publish ConfigManBearPig 2.0 and openhound-collector-common to PyPI | publishing, packaging, sccm |
| [`Ope-liu7`](Ope-liu7.md) | 1 | feature | System Management Container Abuse | sccm, ldap, acl, takeover |
| [`Ope-rhzx`](Ope-rhzx.md) | 1 | feature | Individual Permissions (Port from PowerShell) | sccm, adminservice, rbac, permissions |
| [`con-68c2`](con-68c2.md) | 2 | task | Standardize test filenames on *_test.py, pin the glob, retire docs-site scaffolding -type chore -priority 2 -tags tests,cleanup,naming,docs -descri... | — |
| [`con-907c`](con-907c.md) | 2 | task | Rebaseline fixture expected values on the full lab + add host-level SEC assertions | testing, integration, fixtures, lab |
| [`ope-1f0f`](ope-1f0f.md) | 2 | task | Code-Quality Pass: Conditional Logging, Exception Handling, Variable Scope, Linting & Cleanup -type chore -priority 2 -assignee Mayyhem -tags sccm,... | — |

## Open (29)

| Ticket | P | Type | Title | Tags |
|---|---|---|---|---|
| [`Ope-0t3h`](Ope-0t3h.md) | 1 | feature | Client Push Installation Issues (CRED-1 / ELEVATE-1) | sccm, cred-1, elevate-1, client-push, credentials |
| [`Ope-emhc`](Ope-emhc.md) | 1 | feature | Implement --enable-bad-opsec Gating | sccm, opsec |
| [`Ope-o6bh`](Ope-o6bh.md) | 1 | feature | DHCP Collection and PXE Credential Theft Chain (CRED-1) | sccm, dhcp, pxe, cred-1, credentials |
| [`Ope-t7kv`](Ope-t7kv.md) | 1 | feature | CRED-2: Machine Account Registration and Policy Decryption (HTTP) | sccm, cred-2, http, credentials |
| [`Ope-txs0`](Ope-txs0.md) | 1 | feature | Search Other Discovered Domains via LDAP | sccm, ldap, multi-domain |
| [`Ope-zaja`](Ope-zaja.md) | 1 | feature | Relay to Management Point | sccm, http, relay, takeover |
| [`con-0289`](con-0289.md) | 2 | bug | Integration fixtures cannot be gated on possible-edges, so low-priv + --disable-possible-edges reports 4 false failures | sccm, integration, fixtures, possible-edges |
| [`con-0394`](con-0394.md) | 2 | task | Positively identify a secondary site or site server as a plain domain user | sccm, lowpriv, secondary, discovery |
| [`con-2ca2`](con-2ca2.md) | 2 | bug | _safe silently swallows BinderException, turning transform bugs into no-ops | preproc, diagnostics, transforms, testing |
| [`con-c542`](con-c542.md) | 2 | task | Tag fixture cases from measured privileged/unprivileged A/B | testing, integration, fixtures, lowpriv |
| [`con-d857`](con-d857.md) | 2 | task | Add TAKEOVER from parent CAS to child primary as possible/assumed edge | — |
| [`ope-1172`](ope-1172.md) | 2 | task | Test different port / named instance | — |
| [`ope-7da1`](ope-7da1.md) | 2 | task | Wire --socks-proxy in MSSQL collector via shared proxy interception | mssql, proxy |
| [`ope-961c`](ope-961c.md) | 2 | task | Flesh out disableLoopbackCheck and add an NTLM-reflection relay edge | sccm, edge, relay, cred |
| [`ope-ad1c`](ope-ad1c.md) | 2 | task | AdminService/WMI (privileged.py) do not identify Distribution Point roles or client-certificate-required status; only HTTP does, so the HTTP skip-g... | sccm, http, distribution-point |
| [`Ope-ew5k`](Ope-ew5k.md) | 2 | feature | WMI Collection | sccm, collection, wmi |
| [`ope-f173`](ope-f173.md) | 2 | task | Add Kerberos to the LDAP auth ladder when explicit credentials are provided at the CLI | — |
| [`Ope-gqwo`](Ope-gqwo.md) | 2 | feature | CRED-6: PXE Media Download and Policy Decryption (SMB/TFTP) | sccm, cred-6, smb, pxe, credentials |
| [`Ope-padv`](Ope-padv.md) | 2 | feature | CRED-4: Local CIM Repository Scraping (Bad Opsec) | sccm, cred-4, local, credentials, bad-opsec |
| [`Ope-pofz`](Ope-pofz.md) | 2 | feature | Add --skip-ad-enum option to suppress AD-derived object creation | — |
| [`con-53eb`](con-53eb.md) | 3 | task | Emit BUILTIN\Administrators as sysadmin on an SCCM-installed Express secondary site database | sccm, mssql, secondary, bloodhound |
| [`con-d061`](con-d061.md) | 3 | task | Investigate emitting SCCM default collections as soon as a site is known | sccm, graph, collections, design |
| [`ope-00df`](ope-00df.md) | 3 | task | Add --no-diagnostics-log / --no-collect-log to suppress on-disk logs individually | — |
| [`ope-6b93`](ope-6b93.md) | 3 | task | Local-only/low-priv collector host gets no SCCM_ClientDevice node (CMBP builds it via Local Upsert-Node) | sccm, clientdevice, lowpriv, collection |
| [`ope-90fc`](ope-90fc.md) | 3 | task | Collapse duplicate cross-site SCCMResourceIDs to a root/parent-site-suffixed canonical entry | — |
| [`ope-a214`](ope-a214.md) | 3 | task | SCCM edge Composition property + admin-user AssignAllPermissions gap | sccm, graph, edges, composition, entity-panel |
| [`ope-e10b`](ope-e10b.md) | 3 | task | Emit SCCM_HasNetworkAccessAccount from Local collection (NAA from client WMI) | sccm, edge, local-collection, naa |
| [`Ope-exvi`](Ope-exvi.md) | 3 | feature | Findings / Remediations | sccm, findings, reporting |
| [`ope-4ba1`](ope-4ba1.md) | 4 | task | Make shared AdClient credential-summary warning flag-name-agnostic (do not name collector-specific CLI flags) | shared-lib, openhound-collector-common, ldap, logging, auth |

## Closed (112)

| Ticket | P | Type | Title | Tags |
|---|---|---|---|---|
| [`con-3354`](con-3354.md) | 1 | bug | Site-code conflict discards a real secondary site (one scalar site_code per target) | sccm, context, site-discovery, data-loss |
| [`con-401c`](con-401c.md) | 1 | bug | Collector console log output does not reach redirected stdout | logging, diagnostics, cli |
| [`con-7296`](con-7296.md) | 1 | task | Emit MSSQL nodes/edges as source_kind=MSSQL payload + zip graph output on --run-all | sccm, mssql, convert, packaging |
| [`con-c522`](con-c522.md) | 1 | task | Clear 14 Dependabot alerts via lock-only dependency bump | security, dependencies |
| [`ope-0495`](ope-0495.md) | 1 | task | SCCM collector vs live CMBP unit-test parity gaps (2026-07-14 comparison) | — |
| [`ope-1201`](ope-1201.md) | 1 | bug | node_mssql_server drops registry-only SQL servers (coalesce port VARCHAR vs INTEGER_LITERAL) | sccm, preproc, mssql, dlt |
| [`Ope-15m7`](Ope-15m7.md) | 1 | task | Seed Nodes / Edges Audit | sccm, graph, audit |
| [`ope-16f5`](ope-16f5.md) | 1 | task | Rename SCCM node/edge properties to ConfigManBearPig.ps1 casing | sccm, graph, property-naming |
| [`ope-194a`](ope-194a.md) | 1 | bug | Fix SCCM_AdminUser displayName/displayname case-collision (breaks OpenGraph ingestion) | — |
| [`ope-1950`](ope-1950.md) | 1 | task | Stage 3: Containment + RBAC fan-out + node/edge property parity (preproc/convert port) | sccm, preproc, convert, stage3, edges, properties, parity |
| [`ope-1f49`](ope-1f49.md) | 1 | task | Migrate SCCM onto openhound-collector-common shared library | migration, shared-lib |
| [`ope-255b`](ope-255b.md) | 1 | task | Stage 7: Docs + validation (preproc/convert port) | sccm, docs, validation, stage7, preproc-convert |
| [`ope-272f`](ope-272f.md) | 1 | feature | MSSQL OpenHound collector port (MSSQLHound parity) | mssql, opengraph, port |
| [`ope-2732`](ope-2732.md) | 1 | task | Fix RemoteRegistry trigger-start race + double-logoff in registry collector | registry, smb, bugfix |
| [`ope-2ff3`](ope-2ff3.md) | 1 | task | Stage 2: SCCM entities + inline edges (preproc/convert port) | sccm, preproc, convert, stage2, edges, nodes |
| [`ope-3dbc`](ope-3dbc.md) | 1 | bug | Convert emits null OpenGraph properties -> BloodHound schema validation rejects file | convert, opengraph, bloodhound |
| [`ope-3de2`](ope-3de2.md) | 1 | bug | Fix User nodes missing samAccountName (MSSQL service-account + AD-user endpoint resolution) | — |
| [`ope-5271`](ope-5271.md) | 1 | bug | Fix invalid server address on NetBIOS-prefixed account resolution (NAA, sccm_push) | — |
| [`ope-54be`](ope-54be.md) | 1 | task | Fix ordered-log per-host grouping; always-DEBUG full log; rename logs; truncate HTTP content log | — |
| [`ope-57cf`](ope-57cf.md) | 1 | bug | Fix MSSQL login/user under-population (SysResUse role@site + sam_account_name propagation) | — |
| [`ope-6716`](ope-6716.md) | 1 | task | SCCM preproc/convert Stage 5 - MSSQL nodes and edges | sccm, stage5, mssql, preproc, convert |
| [`Ope-6cei`](Ope-6cei.md) | 1 | feature | Concurrency / Parallelism | sccm, performance |
| [`ope-76f1`](ope-76f1.md) | 1 | task | Make -v enable VERBOSE and add --silent to mute console output | — |
| [`ope-86f8`](ope-86f8.md) | 1 | bug | Realign coerce/relay --disable-possible-edges: NULL NTLM = Windows-default-vulnerable (match CMBP) | — |
| [`ope-9271`](ope-9271.md) | 1 | task | Stage 4: SameHostAs + LocalAdminRequired + ClientDevice dedup (preproc/convert port) | sccm, preproc, convert, stage4 |
| [`ope-a88e`](ope-a88e.md) | 1 | task | Stage 1 hardening: SMS_R_UserGroup group resolution + node_site/node_group/role real-data fixes | sccm, preproc, collect, group-resolution, real-data |
| [`ope-d820`](ope-d820.md) | 1 | task | Stage 6: Coerce-and-relay possible edges (preproc/convert port) | sccm, graph, relay, preproc, convert, possible-edges |
| [`ope-df0e`](ope-df0e.md) | 1 | bug | Fix SCCM_AssignAllPermissions DB->every-site over-emission (own-site only) | — |
| [`ope-e191`](ope-e191.md) | 1 | feature | Recursively expand group members of GenericAll holders on System Management container | sccm, ldap, acl, recursion, takeover |
| [`ope-ec50`](ope-ec50.md) | 1 | bug | Fix SCCM_ClientDevice name missing @siteCode suffix | — |
| [`ope-ff28`](ope-ff28.md) | 1 | task | Stage 8.1: MSSQLHound output adapter (convert -> validator envelope) | mssql, adapter, output, validators |
| [`Ope-o008`](Ope-o008.md) | 1 | task | Verify CoerceAndRelayToSMB Lifecycle (Collection to Postprocessing) | sccm, audit, relay, smb |
| [`con-0170`](con-0170.md) | 2 | bug | Guard the remote sitesigncert X.509 parse and log parse failures distinctly | http, sccm, robustness, logging |
| [`con-2249`](con-2249.md) | 2 | feature | Emit HasSession from MSSQLSvc SPN host to service account during low-priv LDAP | sccm, ldap, mssql, lowpriv, edges |
| [`con-3be4`](con-3be4.md) | 2 | task | Refresh README.md and ARCHITECTURE.md against current code | docs, readme, architecture |
| [`con-5e71`](con-5e71.md) | 2 | feature | Emit SCCM_ClientDevice + SameHostAs from SPN during low-priv collection | sccm, lowpriv, edges, clientdevice |
| [`con-6198`](con-6198.md) | 2 | bug | SCCM_CoerceAndRelayToAdminService not produced by low-priv collection | sccm, lowpriv, edges, relay |
| [`con-6677`](con-6677.md) | 2 | bug | Wire integration harness low-privilege mode to a CLI flag | testing, integration, cli, lowpriv |
| [`con-7842`](con-7842.md) | 2 | task | Adopt openhound-collector-common v0.1.2: baseline/candidate compare orientation, regression exit codes, three-way privilege flag | testing, integration, cli, compare |
| [`con-8a28`](con-8a28.md) | 2 | task | Silence expected access-denied noise on non-admin runs; show the zip path in the --run-all summary | sccm, logging, registry, wmi, run-all |
| [`con-ab59`](con-ab59.md) | 2 | bug | get_mssql_settings cannot see named SQL instances -- every probed registry path is default-instance only | sccm, registry, mssql, epa |
| [`con-acdd`](con-acdd.md) | 2 | task | Integration runner conflates 'no such edge' with 'edge rejected by property match' | testing, integration, shared-lib, diagnostics |
| [`con-be15`](con-be15.md) | 2 | bug | Review MSSQL_Server inclusion + CM_<site> attribution for the passive site server | sccm, mssql, preproc, inference |
| [`con-be32`](con-be32.md) | 2 | task | CI red: --help substring tests break under forced colour and narrow terminals -type bug -priority 1 -tags testing,ci,cli,help -assignee cthompson -... | — |
| [`con-c509`](con-c509.md) | 2 | bug | Secondary sites should not inherit primary-site MSSQL sysadmin/login assumptions | sccm, mssql, preproc, secondary-site |
| [`con-e455`](con-e455.md) | 2 | bug | install_filter() leaks the log-prefix filter across tests, breaking later log assertions | testing, logging, test-isolation |
| [`ope-00ca`](ope-00ca.md) | 2 | task | SCCM collect: silence dlt progress bars by default (--progress off) | sccm, cli, logging |
| [`ope-0112`](ope-0112.md) | 2 | task | Concurrent per-host collection framework (reusable engine + SCCM stubs) -type task -priority 1 -description Build the portable phased_pipeline engi... | — |
| [`ope-065f`](ope-065f.md) | 2 | task | Port test-epa-matrix as live EPA validation harness (impacket rrp+scmr) | sccm, mssql, epa, validation, matrix, impacket |
| [`ope-0947`](ope-0947.md) | 2 | task | Wire collected-but-unread site-code and role sources into preprocess (site_hierarchy D5 + node_computer orphaned roles) | sccm, lowpriv, preprocess, collection |
| [`ope-0f66`](ope-0f66.md) | 2 | task | local.py mypy 31->0: cross-resource state on SourceContext + unresolved-target guards + typed logger | sccm, local, typing, tech-debt |
| [`ope-140f`](ope-140f.md) | 2 | task | Collect summary prints real next-step commands instead of placeholders | — |
| [`ope-1d06`](ope-1d06.md) | 2 | bug | AdminService read timeout silently reported as 'Collected 0' | logging, adminservice, sccm |
| [`ope-215a`](ope-215a.md) | 2 | task | Return single fsp_hostname from _parse_mp_capabilities -type chore -priority 2 -tags sccm,ldap,fsp -assignee cthompson -description Change _parse_m... | — |
| [`ope-2419`](ope-2419.md) | 2 | task | Remove direct BloodHound CE upload from the published packages | bloodhound, cleanup, sccm, packaging |
| [`ope-2f15`](ope-2f15.md) | 2 | task | Rename SCCM edge kinds to match schema.json (SCCM_/MSSQL_ namespacing) | sccm, edge, schema |
| [`ope-334f`](ope-334f.md) | 2 | task | Windows-safe core log rotation: copy+truncate + per-run timestamped openhound.log --type task --priority 2 --description OpenHound core attaches a ... | — |
| [`ope-38ad`](ope-38ad.md) | 2 | chore | Merge AdminService + WMI collectors into privileged.py; genericize WmiClient | sccm, refactor, collectors, wmi, adminservice, dry, simplify |
| [`ope-3d28`](ope-3d28.md) | 2 | task | Implement MSSQL per-host collector -type task -priority 2 -description Port Invoke-MSSQLCollection from ConfigManBearPig.ps1 into the per-host pipe... | — |
| [`ope-3f2a`](ope-3f2a.md) | 2 | feature | SMS Provider WMI fallback collection (AdminService mirror) | sccm, collection, wmi |
| [`ope-4483`](ope-4483.md) | 2 | task | SMB Collection (Port from PowerShell) | sccm, smb, collector, collect |
| [`ope-46ef`](ope-46ef.md) | 2 | task | Move mssql_epa_test.py into tests/ as test_mssql_epa.py | tests, refactor |
| [`ope-4787`](ope-4787.md) | 2 | task | Add Kerberos to smb_sso.py | — |
| [`ope-4c6f`](ope-4c6f.md) | 2 | task | Collect summary: replace directory scan with true per-run dlt metric | sccm, collect, summary, tech-debt |
| [`Ope-4tdt`](Ope-4tdt.md) | 2 | feature | DCOnly Mode (--dc-only flag) | sccm, collection, opsec |
| [`ope-5186`](ope-5186.md) | 2 | task | Quiet expected non-SCCM-client root\CCM namespace error in local collector | sccm, local, logging |
| [`ope-6569`](ope-6569.md) | 2 | task | Quiet expected http_/smb_ fallback-table misses in preproc (WARNING->DEBUG when a privileged transport ran) | sccm, logging, preproc |
| [`ope-676f`](ope-676f.md) | 2 | task | Implement SMB per-host collector -type task -priority 2 -description Port Invoke-SMBCollection from ConfigManBearPig.ps1 into the per-host pipeline... | — |
| [`ope-6aa7`](ope-6aa7.md) | 2 | feature | Split AD nodes/edges into a separate untagged OpenGraph file | sccm, convert, preproc, opengraph, ad, output |
| [`ope-7313`](ope-7313.md) | 2 | task | Testing panel: reserve rich_help_panel; define its flags (dry-run / auth pre-flight) later | sccm, cli, help, testing |
| [`ope-7e54`](ope-7e54.md) | 2 | task | Implement RemoteRegistry per-host collector -type task -priority 2 -description Port Invoke-RemoteRegistryCollection from ConfigManBearPig.ps1 into... | — |
| [`ope-7f61`](ope-7f61.md) | 2 | chore | Fix README edge-count banner miscount (Stages 1-2 = 11, not 10) | sccm, docs, readme |
| [`ope-8b99`](ope-8b99.md) | 2 | task | Fix truncated full-URL verbose log in local client-log scrape | — |
| [`ope-8c44`](ope-8c44.md) | 2 | task | Direct BloodHound CE upload (schema + results) from SCCM via shared openhound-collector-common uploader | sccm, bloodhound, upload, shared-lib, collector-common |
| [`Ope-8wi2`](Ope-8wi2.md) | 2 | feature | Upload Directly to BloodHound | sccm, bloodhound, output |
| [`ope-9989`](ope-9989.md) | 2 | task | Make HasUser edges' abuse info less prescriptive | sccm, edge-help, docs |
| [`ope-9d62`](ope-9d62.md) | 2 | task | Implement HTTP per-host collector -type task -priority 2 -description Port Invoke-HTTPCollection from ConfigManBearPig.ps1 into the per-host pipeli... | — |
| [`ope-aa39`](ope-aa39.md) | 2 | task | Add entity-panel help content to SCCM edge property bags | sccm, graph, entity-panel, edges |
| [`ope-afc8`](ope-afc8.md) | 2 | bug | SCCM_HasMember edge wrongly lands on Computer nodes for non-client collection members | — |
| [`ope-b287`](ope-b287.md) | 2 | task | Implement AdminService per-host collector -type task -priority 2 -description Port Invoke-AdminServiceCollection from ConfigManBearPig.ps1 into the... | — |
| [`ope-b916`](ope-b916.md) | 2 | feature | Wire SCCM version->CVE fingerprinting into HTTP collection + site node | sccm, http, preproc, convert, cve, version |
| [`Ope-bmyk`](Ope-bmyk.md) | 2 | feature | Abuse Info on Edges | sccm, graph, ux |
| [`ope-c0c0`](ope-c0c0.md) | 2 | bug | SCCM_ClientDevice lastOnlineTime/lastOfflineTime always empty (c_n_ vs cn_ raw column typo) | sccm, clientdevice, preproc |
| [`ope-c141`](ope-c141.md) | 2 | task | Populate all AD node properties (Computer/User/Group) to CMBP parity instead of relying on SharpHound | sccm, graph, ldap, ad-parity |
| [`ope-c660`](ope-c660.md) | 2 | task | Implement WMI per-host collector -type task -priority 2 -description Port Invoke-SmsProviderWmiCollection from ConfigManBearPig.ps1 into the per-ho... | — |
| [`ope-c8cc`](ope-c8cc.md) | 2 | task | Port MSSQLHound TestEPA network EPA scan into _get_extended_protection_settings | sccm, mssql, epa, tds, ntlm, relay |
| [`ope-cc0f`](ope-cc0f.md) | 2 | task | Rename --socks-proxy flag to -x / --proxy | sccm |
| [`ope-d57d`](ope-d57d.md) | 2 | task | Shared HTTP client (Negotiate auth) for AdminService + HTTP collectors | sccm, http, auth, negotiate, adminservice |
| [`ope-e512`](ope-e512.md) | 2 | task | Per-domain collector pipeline to rerun LDAP/DNS against discovered domains | — |
| [`ope-e739`](ope-e739.md) | 2 | bug | Inferred CmRcService clients attached to CAS root instead of a Primary site | sccm, possible-client, cmbp-parity, has-client |
| [`ope-f1ce`](ope-f1ce.md) | 2 | bug | Graph array properties emitted in nondeterministic order | convert, determinism, sccm |
| [`ope-f27c`](ope-f27c.md) | 2 | task | collect sccm --run-all: end-to-end flag + shared orchestration lib fn | — |
| [`ope-fb99`](ope-fb99.md) | 2 | task | Emit missing SCCM node/edge properties (ClientDevice extras, Site.siteSystemRoles, IsMappedTo.SCCMInfra) to CMBP parity | sccm, graph |
| [`ope-fbb0`](ope-fbb0.md) | 2 | task | Route ALL SCCM collection traffic through --socks-proxy (shared interception) | sccm |
| [`ope-feb0`](ope-feb0.md) | 2 | bug | BloodHound upload-only CLI path is silent (no operator feedback; failed upload still exits 0) | sccm, bloodhound, upload, cli, observability |
| [`Ope-l6fu`](Ope-l6fu.md) | 2 | feature | TDS and EPA Implementation Coverage | sccm, mssql, relay |
| [`Ope-scp1`](Ope-scp1.md) | 2 | task | Audit Variables Leaking Across Python Scopes | sccm, audit, python, scope |
| [`Ope-vpdw`](Ope-vpdw.md) | 2 | feature | Add --resolver option for custom DNS nameserver | — |
| [`con-727a`](con-727a.md) | 3 | task | edge-hascurrentuser-ps1-dev-domainuser fails on lab state, not code -- domainuser is not logged on to PS1-DEV | sccm, integration, fixtures, lab |
| [`con-7741`](con-7741.md) | 3 | task | SMS Provider probe is skipped when port 80 is filtered despite being HTTPS-only | sccm, http, lowpriv, collection |
| [`con-894a`](con-894a.md) | 3 | task | Expose the System Management container's DN as a queryable lowercase distinguishedname property | cypher, container, graph |
| [`con-8a33`](con-8a33.md) | 3 | bug | Guard --ticket base64/KRB-CRED decoding in smb_sso.py and wmi.py | sccm, auth, kerberos, ux, robustness |
| [`con-a4ec`](con-a4ec.md) | 3 | task | Adopt StagePaths.graph_zip once openhound-collector-common is released | sccm, run-all, shared-lib |
| [`con-edee`](con-edee.md) | 3 | task | Reconcile SCCM_AssignAllPermissions SMS-Provider-hosts count against PS1 logic | sccm, fixtures, mssql, lowpriv |
| [`ope-272e`](ope-272e.md) | 3 | task | LDAP pass-the-hash (--nt-hash) support — placeholder | sccm, ldap, pth, placeholder |
| [`ope-50cc`](ope-50cc.md) | 3 | bug | edge_help scope test red since GenericAll became an emitted kind | tests, edge-help, sccm |
| [`ope-b1e8`](ope-b1e8.md) | 3 | bug | Dead collect flag: --sms / --sms-provider accepted but ignored | sccm, cli, collect |
| [`ope-b7b2`](ope-b7b2.md) | 3 | task | Wire --nt-hash / --ticket into LDAP, SMB, RemoteRegistry, MSSQL auth paths | sccm, auth, pth, ptt, credentials, deferred |
| [`ope-c8dd`](ope-c8dd.md) | 3 | chore | Write OpenHound SCCM collector README.md | sccm, docs, readme |
| [`ope-da2a`](ope-da2a.md) | 3 | task | Filter debug_per_host.py to specific collectors (mirror -m) | — |
| [`Ope-f3di`](Ope-f3di.md) | 3 | chore | Logging Audit: Ensure All Conditional Branches Have Appropriate Log Messages | sccm, logging, observability |
| [`ope-f651`](ope-f651.md) | 3 | task | Migrate SCCM extension onto openhound-collector-common shared library | sccm, refactor, shared-lib |
