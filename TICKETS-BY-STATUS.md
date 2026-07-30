# Tickets by status

Generated from `gtk list --json`; regenerate after any ticket status change rather than
editing by hand -- the ticket files under `.tickets/` are the source of truth.
`.gitattributes` marks this file `merge=ours`, which needs a one-time
`git config merge.ours.driver true` per clone.

**116 tickets** — 7 in progress · 28 open · 81 closed

## In progress (7)

| Ticket | P | Type | Title | Tags |
|---|---|---|---|---|
| [`Ope-15m7`](.tickets/Ope-15m7.md) | 1 | task | Seed Nodes / Edges Audit | sccm, graph, audit |
| [`ope-60fe`](.tickets/ope-60fe.md) | 1 | task | Publish ConfigManBearPig 2.0 and openhound-collector-common to PyPI | publishing, packaging, sccm |
| [`Ope-liu7`](.tickets/Ope-liu7.md) | 1 | feature | System Management Container Abuse | sccm, ldap, acl, takeover |
| [`Ope-rhzx`](.tickets/Ope-rhzx.md) | 1 | feature | Individual Permissions (Port from PowerShell) | sccm, adminservice, rbac, permissions |
| [`con-3be4`](.tickets/con-3be4.md) | 2 | task | Refresh README.md and ARCHITECTURE.md against current code | docs, readme, architecture |
| [`ope-1f0f`](.tickets/ope-1f0f.md) | 2 | task | Code-Quality Pass: Conditional Logging, Exception Handling, Variable Scope, Linting & Cleanup -type chore -priority 2 -assignee Mayyhem -tags sccm,audit,cleanup,logging,scope,linting,best-practices -description Comprehensive code-quality pass over the entire sccm/sccm tree (collectors, context, source, and the preprocess/convert stages). Supersedes Ope-f3di (logging-branch audit) and Ope-scp1 (variable-scope audit), folding both into one cleanup effort. | — |
| [`ope-e512`](.tickets/ope-e512.md) | 2 | task | Per-domain collector pipeline to rerun LDAP/DNS against discovered domains | — |

## Open (28)

| Ticket | P | Type | Title | Tags |
|---|---|---|---|---|
| [`Ope-0t3h`](.tickets/Ope-0t3h.md) | 1 | feature | Client Push Installation Issues (CRED-1 / ELEVATE-1) | sccm, cred-1, elevate-1, client-push, credentials |
| [`Ope-emhc`](.tickets/Ope-emhc.md) | 1 | feature | Implement --enable-bad-opsec Gating | sccm, opsec |
| [`Ope-o6bh`](.tickets/Ope-o6bh.md) | 1 | feature | DHCP Collection and PXE Credential Theft Chain (CRED-1) | sccm, dhcp, pxe, cred-1, credentials |
| [`Ope-t7kv`](.tickets/Ope-t7kv.md) | 1 | feature | CRED-2: Machine Account Registration and Policy Decryption (HTTP) | sccm, cred-2, http, credentials |
| [`Ope-txs0`](.tickets/Ope-txs0.md) | 1 | feature | Search Other Discovered Domains via LDAP | sccm, ldap, multi-domain |
| [`Ope-zaja`](.tickets/Ope-zaja.md) | 1 | feature | Relay to Management Point | sccm, http, relay, takeover |
| [`ope-0947`](.tickets/ope-0947.md) | 2 | task | Wire collected-but-unread site-code and role sources into preprocess (site_hierarchy D5 + node_computer orphaned roles) | sccm, lowpriv, preprocess, collection |
| [`ope-1172`](.tickets/ope-1172.md) | 2 | task | Test different port / named instance | — |
| [`Ope-4tdt`](.tickets/Ope-4tdt.md) | 2 | feature | DCOnly Mode (--dc-only flag) | sccm, collection, opsec |
| [`ope-7313`](.tickets/ope-7313.md) | 2 | task | Testing panel: reserve rich_help_panel; define its flags (dry-run / auth pre-flight) later | sccm, cli, help, testing |
| [`ope-7da1`](.tickets/ope-7da1.md) | 2 | task | Wire --socks-proxy in MSSQL collector via shared proxy interception | mssql, proxy |
| [`ope-8c44`](.tickets/ope-8c44.md) | 2 | task | Direct BloodHound CE upload (schema + results) from SCCM via shared openhound-collector-common uploader | sccm, bloodhound, upload, shared-lib, collector-common |
| [`Ope-8wi2`](.tickets/Ope-8wi2.md) | 2 | feature | Upload Directly to BloodHound | sccm, bloodhound, output |
| [`ope-961c`](.tickets/ope-961c.md) | 2 | task | Flesh out disableLoopbackCheck and add an NTLM-reflection relay edge | sccm, edge, relay, cred |
| [`ope-ad1c`](.tickets/ope-ad1c.md) | 2 | task | AdminService/WMI (privileged.py) do not identify Distribution Point roles or client-certificate-required status; only HTTP does, so the HTTP skip-gate can miss them on hosts privileged collection already reached | sccm, http, distribution-point |
| [`Ope-ew5k`](.tickets/Ope-ew5k.md) | 2 | feature | WMI Collection | sccm, collection, wmi |
| [`ope-f173`](.tickets/ope-f173.md) | 2 | task | Add Kerberos to the LDAP auth ladder when explicit credentials are provided at the CLI | — |
| [`ope-feb0`](.tickets/ope-feb0.md) | 2 | bug | BloodHound upload-only CLI path is silent (no operator feedback; failed upload still exits 0) | sccm, bloodhound, upload, cli, observability |
| [`Ope-gqwo`](.tickets/Ope-gqwo.md) | 2 | feature | CRED-6: PXE Media Download and Policy Decryption (SMB/TFTP) | sccm, cred-6, smb, pxe, credentials |
| [`Ope-padv`](.tickets/Ope-padv.md) | 2 | feature | CRED-4: Local CIM Repository Scraping (Bad Opsec) | sccm, cred-4, local, credentials, bad-opsec |
| [`Ope-pofz`](.tickets/Ope-pofz.md) | 2 | feature | Add --skip-ad-enum option to suppress AD-derived object creation | — |
| [`ope-00df`](.tickets/ope-00df.md) | 3 | task | Add --no-diagnostics-log / --no-collect-log to suppress on-disk logs individually | — |
| [`ope-6b93`](.tickets/ope-6b93.md) | 3 | task | Local-only/low-priv collector host gets no SCCM_ClientDevice node (CMBP builds it via Local Upsert-Node) | sccm, clientdevice, lowpriv, collection |
| [`ope-90fc`](.tickets/ope-90fc.md) | 3 | task | Collapse duplicate cross-site SCCMResourceIDs to a root/parent-site-suffixed canonical entry | — |
| [`ope-a214`](.tickets/ope-a214.md) | 3 | task | SCCM edge Composition property + admin-user AssignAllPermissions gap | sccm, graph, edges, composition, entity-panel |
| [`ope-e10b`](.tickets/ope-e10b.md) | 3 | task | Emit SCCM_HasNetworkAccessAccount from Local collection (NAA from client WMI) | sccm, edge, local-collection, naa |
| [`Ope-exvi`](.tickets/Ope-exvi.md) | 3 | feature | Findings / Remediations | sccm, findings, reporting |
| [`ope-4ba1`](.tickets/ope-4ba1.md) | 4 | task | Make shared AdClient credential-summary warning flag-name-agnostic (do not name collector-specific CLI flags) | shared-lib, openhound-collector-common, ldap, logging, auth |

## Closed (81)

| Ticket | P | Type | Title | Tags |
|---|---|---|---|---|
| [`ope-0495`](.tickets/ope-0495.md) | 1 | task | SCCM collector vs live CMBP unit-test parity gaps (2026-07-14 comparison) | — |
| [`ope-1201`](.tickets/ope-1201.md) | 1 | bug | node_mssql_server drops registry-only SQL servers (coalesce port VARCHAR vs INTEGER_LITERAL) | sccm, preproc, mssql, dlt |
| [`ope-16f5`](.tickets/ope-16f5.md) | 1 | task | Rename SCCM node/edge properties to ConfigManBearPig.ps1 casing | sccm, graph, property-naming |
| [`ope-194a`](.tickets/ope-194a.md) | 1 | bug | Fix SCCM_AdminUser displayName/displayname case-collision (breaks OpenGraph ingestion) | — |
| [`ope-1950`](.tickets/ope-1950.md) | 1 | task | Stage 3: Containment + RBAC fan-out + node/edge property parity (preproc/convert port) | sccm, preproc, convert, stage3, edges, properties, parity |
| [`ope-1f49`](.tickets/ope-1f49.md) | 1 | task | Migrate SCCM onto openhound-collector-common shared library | migration, shared-lib |
| [`ope-255b`](.tickets/ope-255b.md) | 1 | task | Stage 7: Docs + validation (preproc/convert port) | sccm, docs, validation, stage7, preproc-convert |
| [`ope-272f`](.tickets/ope-272f.md) | 1 | feature | MSSQL OpenHound collector port (MSSQLHound parity) | mssql, opengraph, port |
| [`ope-2732`](.tickets/ope-2732.md) | 1 | task | Fix RemoteRegistry trigger-start race + double-logoff in registry collector | registry, smb, bugfix |
| [`ope-2ff3`](.tickets/ope-2ff3.md) | 1 | task | Stage 2: SCCM entities + inline edges (preproc/convert port) | sccm, preproc, convert, stage2, edges, nodes |
| [`ope-3dbc`](.tickets/ope-3dbc.md) | 1 | bug | Convert emits null OpenGraph properties -> BloodHound schema validation rejects file | convert, opengraph, bloodhound |
| [`ope-3de2`](.tickets/ope-3de2.md) | 1 | bug | Fix User nodes missing samAccountName (MSSQL service-account + AD-user endpoint resolution) | — |
| [`ope-5271`](.tickets/ope-5271.md) | 1 | bug | Fix invalid server address on NetBIOS-prefixed account resolution (NAA, sccm_push) | — |
| [`ope-54be`](.tickets/ope-54be.md) | 1 | task | Fix ordered-log per-host grouping; always-DEBUG full log; rename logs; truncate HTTP content log | — |
| [`ope-57cf`](.tickets/ope-57cf.md) | 1 | bug | Fix MSSQL login/user under-population (SysResUse role@site + sam_account_name propagation) | — |
| [`ope-6716`](.tickets/ope-6716.md) | 1 | task | SCCM preproc/convert Stage 5 - MSSQL nodes and edges | sccm, stage5, mssql, preproc, convert |
| [`Ope-6cei`](.tickets/Ope-6cei.md) | 1 | feature | Concurrency / Parallelism | sccm, performance |
| [`ope-76f1`](.tickets/ope-76f1.md) | 1 | task | Make -v enable VERBOSE and add --silent to mute console output | — |
| [`ope-86f8`](.tickets/ope-86f8.md) | 1 | bug | Realign coerce/relay --disable-possible-edges: NULL NTLM = Windows-default-vulnerable (match CMBP) | — |
| [`ope-9271`](.tickets/ope-9271.md) | 1 | task | Stage 4: SameHostAs + LocalAdminRequired + ClientDevice dedup (preproc/convert port) | sccm, preproc, convert, stage4 |
| [`ope-a88e`](.tickets/ope-a88e.md) | 1 | task | Stage 1 hardening: SMS_R_UserGroup group resolution + node_site/node_group/role real-data fixes | sccm, preproc, collect, group-resolution, real-data |
| [`ope-d820`](.tickets/ope-d820.md) | 1 | task | Stage 6: Coerce-and-relay possible edges (preproc/convert port) | sccm, graph, relay, preproc, convert, possible-edges |
| [`ope-df0e`](.tickets/ope-df0e.md) | 1 | bug | Fix SCCM_AssignAllPermissions DB->every-site over-emission (own-site only) | — |
| [`ope-e191`](.tickets/ope-e191.md) | 1 | feature | Recursively expand group members of GenericAll holders on System Management container | sccm, ldap, acl, recursion, takeover |
| [`ope-ec50`](.tickets/ope-ec50.md) | 1 | bug | Fix SCCM_ClientDevice name missing @siteCode suffix | — |
| [`ope-ff28`](.tickets/ope-ff28.md) | 1 | task | Stage 8.1: MSSQLHound output adapter (convert -> validator envelope) | mssql, adapter, output, validators |
| [`Ope-o008`](.tickets/Ope-o008.md) | 1 | task | Verify CoerceAndRelayToSMB Lifecycle (Collection to Postprocessing) | sccm, audit, relay, smb |
| [`ope-00ca`](.tickets/ope-00ca.md) | 2 | task | SCCM collect: silence dlt progress bars by default (--progress off) | sccm, cli, logging |
| [`ope-0112`](.tickets/ope-0112.md) | 2 | task | Concurrent per-host collection framework (reusable engine + SCCM stubs) -type task -priority 1 -description Build the portable phased_pipeline engine (work queue, bounded streams, ordered per-target phase runner, thread pool with recursion + quiescent shutdown) and the SCCM adapter that plugs in stub phases, per-table emit resources, two-stage main.py orchestration, and per-host log blocks. Stubs only; real collectors are follow-ups. Plan: sccm/sccm/docs/superpowers/plans/2026-06-03-per-host-collection-framework.md | — |
| [`ope-065f`](.tickets/ope-065f.md) | 2 | task | Port test-epa-matrix as live EPA validation harness (impacket rrp+scmr) | sccm, mssql, epa, validation, matrix, impacket |
| [`ope-0f66`](.tickets/ope-0f66.md) | 2 | task | local.py mypy 31->0: cross-resource state on SourceContext + unresolved-target guards + typed logger | sccm, local, typing, tech-debt |
| [`ope-140f`](.tickets/ope-140f.md) | 2 | task | Collect summary prints real next-step commands instead of placeholders | — |
| [`ope-1d06`](.tickets/ope-1d06.md) | 2 | bug | AdminService read timeout silently reported as 'Collected 0' | logging, adminservice, sccm |
| [`ope-215a`](.tickets/ope-215a.md) | 2 | task | Return single fsp_hostname from _parse_mp_capabilities -type chore -priority 2 -tags sccm,ldap,fsp -assignee cthompson -description Change _parse_mp_capabilities to return a single fsp_hostname (str\|None) instead of fsp_hostnames (list). Only-if-one semantics: warn and take first if multiple FSPServer nodes. Update full chain: caller registration loop, yielded row column, transforms UNNEST->scalar, and both affected test files. | — |
| [`ope-2419`](.tickets/ope-2419.md) | 2 | task | Remove direct BloodHound CE upload from the published packages | bloodhound, cleanup, sccm, packaging |
| [`ope-2f15`](.tickets/ope-2f15.md) | 2 | task | Rename SCCM edge kinds to match schema.json (SCCM_/MSSQL_ namespacing) | sccm, edge, schema |
| [`ope-334f`](.tickets/ope-334f.md) | 2 | task | Windows-safe core log rotation: copy+truncate + per-run timestamped openhound.log --type task --priority 2 --description OpenHound core attaches a TimedRotatingFileHandler (when=midnight) to BOTH the root and dlt loggers, each on the same openhound.log (openhound/core/logging.py). First record after midnight fires a rollover whose os.rename() fails on Windows with WinError 32 because the sibling handler still holds the file open -- so daily rotation has never worked on Windows. Core is off-limits per CLAUDE.md. Fix lives in sccm/sccm main.py startup: locate core's two RotatingFileHandler instances, repoint each to a per-run timestamped file, and replace doRollover with a Windows-safe copy+truncate. Windows-only; POSIX unchanged. | — |
| [`ope-38ad`](.tickets/ope-38ad.md) | 2 | chore | Merge AdminService + WMI collectors into privileged.py; genericize WmiClient | sccm, refactor, collectors, wmi, adminservice, dry, simplify |
| [`ope-3d28`](.tickets/ope-3d28.md) | 2 | task | Implement MSSQL per-host collector -type task -priority 2 -description Port Invoke-MSSQLCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the MSSQL stub with the real collector and its table/model(s). | — |
| [`ope-3f2a`](.tickets/ope-3f2a.md) | 2 | feature | SMS Provider WMI fallback collection (AdminService mirror) | sccm, collection, wmi |
| [`ope-4483`](.tickets/ope-4483.md) | 2 | task | SMB Collection (Port from PowerShell) | sccm, smb, collector, collect |
| [`ope-46ef`](.tickets/ope-46ef.md) | 2 | task | Move mssql_epa_test.py into tests/ as test_mssql_epa.py | tests, refactor |
| [`ope-4787`](.tickets/ope-4787.md) | 2 | task | Add Kerberos to smb_sso.py | — |
| [`ope-4c6f`](.tickets/ope-4c6f.md) | 2 | task | Collect summary: replace directory scan with true per-run dlt metric | sccm, collect, summary, tech-debt |
| [`ope-5186`](.tickets/ope-5186.md) | 2 | task | Quiet expected non-SCCM-client root\CCM namespace error in local collector | sccm, local, logging |
| [`ope-6569`](.tickets/ope-6569.md) | 2 | task | Quiet expected http_/smb_ fallback-table misses in preproc (WARNING->DEBUG when a privileged transport ran) | sccm, logging, preproc |
| [`ope-676f`](.tickets/ope-676f.md) | 2 | task | Implement SMB per-host collector -type task -priority 2 -description Port Invoke-SMBCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the SMB stub with the real collector and its table/model(s). | — |
| [`ope-6aa7`](.tickets/ope-6aa7.md) | 2 | feature | Split AD nodes/edges into a separate untagged OpenGraph file | sccm, convert, preproc, opengraph, ad, output |
| [`ope-7e54`](.tickets/ope-7e54.md) | 2 | task | Implement RemoteRegistry per-host collector -type task -priority 2 -description Port Invoke-RemoteRegistryCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the RemoteRegistry stub with the real collector and its table/model(s). | — |
| [`ope-7f61`](.tickets/ope-7f61.md) | 2 | chore | Fix README edge-count banner miscount (Stages 1-2 = 11, not 10) | sccm, docs, readme |
| [`ope-8b99`](.tickets/ope-8b99.md) | 2 | task | Fix truncated full-URL verbose log in local client-log scrape | — |
| [`ope-9989`](.tickets/ope-9989.md) | 2 | task | Make HasUser edges' abuse info less prescriptive | sccm, edge-help, docs |
| [`ope-9d62`](.tickets/ope-9d62.md) | 2 | task | Implement HTTP per-host collector -type task -priority 2 -description Port Invoke-HTTPCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the HTTP stub. HTTP MP enrollment can discover new targets (register_target -> recursion). | — |
| [`ope-aa39`](.tickets/ope-aa39.md) | 2 | task | Add entity-panel help content to SCCM edge property bags | sccm, graph, entity-panel, edges |
| [`ope-afc8`](.tickets/ope-afc8.md) | 2 | bug | SCCM_HasMember edge wrongly lands on Computer nodes for non-client collection members | — |
| [`ope-b287`](.tickets/ope-b287.md) | 2 | task | Implement AdminService per-host collector -type task -priority 2 -description Port Invoke-AdminServiceCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the AdminService stub. Note: emits multiple tables (admin users, client devices, components, roles, etc.); clients are data rows, not probe targets. | — |
| [`ope-b916`](.tickets/ope-b916.md) | 2 | feature | Wire SCCM version->CVE fingerprinting into HTTP collection + site node | sccm, http, preproc, convert, cve, version |
| [`Ope-bmyk`](.tickets/Ope-bmyk.md) | 2 | feature | Abuse Info on Edges | sccm, graph, ux |
| [`ope-c0c0`](.tickets/ope-c0c0.md) | 2 | bug | SCCM_ClientDevice lastOnlineTime/lastOfflineTime always empty (c_n_ vs cn_ raw column typo) | sccm, clientdevice, preproc |
| [`ope-c141`](.tickets/ope-c141.md) | 2 | task | Populate all AD node properties (Computer/User/Group) to CMBP parity instead of relying on SharpHound | sccm, graph, ldap, ad-parity |
| [`ope-c660`](.tickets/ope-c660.md) | 2 | task | Implement WMI per-host collector -type task -priority 2 -description Port Invoke-SmsProviderWmiCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), adding WMI as a per-host phase (currently disabled in PS1 active config) with its table/model(s). | — |
| [`ope-c8cc`](.tickets/ope-c8cc.md) | 2 | task | Port MSSQLHound TestEPA network EPA scan into _get_extended_protection_settings | sccm, mssql, epa, tds, ntlm, relay |
| [`ope-cc0f`](.tickets/ope-cc0f.md) | 2 | task | Rename --socks-proxy flag to -x / --proxy | sccm |
| [`ope-d57d`](.tickets/ope-d57d.md) | 2 | task | Shared HTTP client (Negotiate auth) for AdminService + HTTP collectors | sccm, http, auth, negotiate, adminservice |
| [`ope-e739`](.tickets/ope-e739.md) | 2 | bug | Inferred CmRcService clients attached to CAS root instead of a Primary site | sccm, possible-client, cmbp-parity, has-client |
| [`ope-f1ce`](.tickets/ope-f1ce.md) | 2 | bug | Graph array properties emitted in nondeterministic order | convert, determinism, sccm |
| [`ope-f27c`](.tickets/ope-f27c.md) | 2 | task | collect sccm --run-all: end-to-end flag + shared orchestration lib fn | — |
| [`ope-fb99`](.tickets/ope-fb99.md) | 2 | task | Emit missing SCCM node/edge properties (ClientDevice extras, Site.siteSystemRoles, IsMappedTo.SCCMInfra) to CMBP parity | sccm, graph |
| [`ope-fbb0`](.tickets/ope-fbb0.md) | 2 | task | Route ALL SCCM collection traffic through --socks-proxy (shared interception) | sccm |
| [`Ope-l6fu`](.tickets/Ope-l6fu.md) | 2 | feature | TDS and EPA Implementation Coverage | sccm, mssql, relay |
| [`Ope-scp1`](.tickets/Ope-scp1.md) | 2 | task | Audit Variables Leaking Across Python Scopes | sccm, audit, python, scope |
| [`Ope-vpdw`](.tickets/Ope-vpdw.md) | 2 | feature | Add --resolver option for custom DNS nameserver | — |
| [`con-894a`](.tickets/con-894a.md) | 3 | task | Expose the System Management container's DN as a queryable lowercase distinguishedname property | cypher, container, graph |
| [`ope-272e`](.tickets/ope-272e.md) | 3 | task | LDAP pass-the-hash (--nt-hash) support — placeholder | sccm, ldap, pth, placeholder |
| [`ope-50cc`](.tickets/ope-50cc.md) | 3 | bug | edge_help scope test red since GenericAll became an emitted kind | tests, edge-help, sccm |
| [`ope-b1e8`](.tickets/ope-b1e8.md) | 3 | bug | Dead collect flag: --sms / --sms-provider accepted but ignored | sccm, cli, collect |
| [`ope-b7b2`](.tickets/ope-b7b2.md) | 3 | task | Wire --nt-hash / --ticket into LDAP, SMB, RemoteRegistry, MSSQL auth paths | sccm, auth, pth, ptt, credentials, deferred |
| [`ope-c8dd`](.tickets/ope-c8dd.md) | 3 | chore | Write OpenHound SCCM collector README.md | sccm, docs, readme |
| [`ope-da2a`](.tickets/ope-da2a.md) | 3 | task | Filter debug_per_host.py to specific collectors (mirror -m) | — |
| [`Ope-f3di`](.tickets/Ope-f3di.md) | 3 | chore | Logging Audit: Ensure All Conditional Branches Have Appropriate Log Messages | sccm, logging, observability |
| [`ope-f651`](.tickets/ope-f651.md) | 3 | task | Migrate SCCM extension onto openhound-collector-common shared library | sccm, refactor, shared-lib |
