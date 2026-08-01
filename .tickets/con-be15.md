---
id: con-be15
status: closed
deps: []
links: [con-2ca2]
created: 2026-07-31T18:31:47Z
type: bug
priority: 2
tags: [sccm, mssql, preproc, inference]
---

# Review MSSQL_Server inclusion + CM_<site> attribution for the passive site server

node_mssql_server merges three arms (transforms.py:3497): _mssql_sql_servers (SCCM site DB, basis SPN+SCCM), mssql_server_instances (EPA scan), remoteregistry_mssql_servers (registry). Privileged full-lab run yields 5 MSSQL_Server nodes where the lab has 3 real site databases. Provenance dump: cas-db/ps1-db = expected; ps1-sec = ['MSSQL-ScanForEPA','SCCM-SiteDBDefaultSchema'] with databases ['CONFIGMGRSEC\CM_SEC'] = correct (SEC secondary has its own site DB); PS2-PSS = ['MSSQL-SPN'] only, SCCMInfra=False, no databases = a stale MSSQLSvc SPN on sqlsccmsvc for a decommissioned site (@_Mayyhem: not in the lab plan, not yet removed -- EXPECTED FAILURE, no code fix wanted); ps1-psv = ['RemoteRegistry-MSSQL','SCCM-SiteDBDefaultSchema'], instanceNames ['MSSQLSERVER'], service account mayyhem\sqlsccmsvc, databases ['CM_PS1'].\nThe ps1-psv case is the one to decide. RemoteRegistry found a genuine MSSQL instance there, so the NODE is evidence-backed, but @_Mayyhem states psv does not run SQL for the site and the CM_PS1 attribution comes from the SCCM-SiteDBDefaultSchema arm -- ps1-db holds CM_PS1. Suspect the default-schema arm attributes the site database to every site server including the passive one. AD confirms no MSSQLSvc SPN exists for ps1-psv or ps1-sec (only ps1-db, cas-db, ps2-pss on sqlsccmsvc), so SPN is not the source for psv.

## Acceptance Criteria

Decide whether a passive site server with SQL installed should carry an MSSQL_Server node; if yes, stop attributing the primary's CM_<site> database to it. MSSQL_Server count and the dependent HasLogin/IsMappedTo/MemberOf/GetTGS/ExecuteOnHost/HostFor counts reconcile with the lab, with PS2-PSS remaining an accepted stale-SPN artifact.

## Notes

**2026-07-31T18:46:16Z**

ROOT CAUSE FOUND for the ps1-psv arm (@_Mayyhem, verified manually 2026-07-31: there is NO MSSQL service running on ps1-psv). It is not that psv has SQL installed -- it is an unverified inference.
collectors/registry.py:419-430: when HKLM\SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers is PRESENT BUT EMPTY, the collector concludes 'the site database is local to this site server' and emits sccm_site_system_roles = ['SMS SQL Server','SMS Site Server'] for the host, with no check that SQL is actually there. That inference holds for a standalone primary site server but is wrong for a PASSIVE site server, which has the same empty key while the site database lives elsewhere (ps1-db).
Corroborating signals that agree psv runs no SQL: AD has no MSSQLSvc SPN for ps1-psv (sqlsccmsvc carries SPNs only for ps1-db, cas-db, ps2-pss), and the EPA scan never probed it, so nothing answered on 1433.
FIX DIRECTION (@_Mayyhem): after seeing the key empty, CONFIRM MSSQL is actually present before creating MSSQL nodes/edges for the host. Candidate corroborators, cheapest first and all usable at low privilege except the last: an MSSQLSvc SPN for the host in AD; a successful 1433/EPA probe; the SQL Server SuperSocketNetLib registry keys (admin-gated, so unavailable to a plain domain user -- cannot be the only gate). Note the 'SMS Site Server' half of the role assertion is unaffected and should still be emitted.
This is the single upstream cause of the inflated MSSQL counts (HasLogin 6, IsMappedTo 6, MemberOf 6, GetTGS 6, ExecuteOnHost 5, HostFor 5, MSSQL_Server 5) -- fixing it should reconcile them without editing each expectation.

**2026-07-31T19:01:01Z**

SCOPE + CONSTRAINTS measured 2026-07-31 (matters for choosing the fix):
1. The empty-key branch fires for a SMALL set. Low-priv run: ps1-psv ONLY. Privileged run: ps1-psv AND ps1-sec. ps1-db and cas-db are NOT at risk -- they are REMOTE site databases and arrive through the else-branch (subkeys non-empty), so gating the empty-key branch cannot regress them.
2. ps1-sec genuinely runs SQL (EPA answered on 1433, databases ['CONFIGMGRSEC\CM_SEC']) and DOES hit this branch when privileged. Any gate must keep ps1-sec while dropping ps1-psv.
3. The obvious corroborators each have a problem at the point this code runs:
   - SQL SuperSocketNetLib registry keys: rpc_s_access_denied on ALL 8 paths at low privilege (confirmed in the unpriv3 log). Cannot be the low-priv gate.
   - MSSQLSvc SPN: does NOT discriminate. The SPN lives on the service account, not the host, and sqlsccmsvc carries SPNs only for ps1-db/cas-db/ps2-pss. ps1-sec has NO MSSQLSvc SPN (it runs as LocalSystem) -- an SPN gate would wrongly drop ps1-sec.
   - A 1433/EPA answer DOES discriminate correctly (ps1-sec answers, ps1-psv does not) -- but PER_HOST_PHASES runs RemoteRegistry BEFORE MSSQL, so the EPA result does not exist yet when this branch executes.
DESIGN OPTIONS (needs a decision):
   (a) Move the SMS SQL Server role assertion out of the collector into preprocess, where EPA/registry/SPN evidence has all landed and can be correlated. Architecturally cleanest and matches CLAUDE.md's 'move work to preprocess where it improves things'; largest change.
   (b) Inline lightweight TCP 1433 reachability check in the registry collector before asserting the role. Small and local, but adds a network probe to a registry phase and duplicates what the MSSQL phase already does.
   (c) Keep emitting the role but mark it assumed with an assumption_basis, and let preprocess drop or downgrade it when no SQL evidence corroborates. node_mssql_server already carries assumed/assumption_basis columns, so the vocabulary exists.
   (d) Reorder PER_HOST_PHASES so MSSQL runs before RemoteRegistry. Cheapest to state, but changes collection ordering, which CLAUDE.md says must match ConfigManBearPig.ps1 -- likely disqualifying.
My recommendation: (c) then (a) -- emit as assumed now so no evidence is lost, and let preprocess make the call, which is where every other cross-source correlation in this collector already happens.

**2026-07-31T19:37:27Z**

IMPLEMENTED (c)+(a) per @_Mayyhem's choice, TDD, verified against real lab data.
(c) collectors/registry.py: the empty-key branch now emits sql_role_assumed=True alongside the roles, and its log line states plainly that the key is ambiguous between 'local site database' and 'passive site server'. The role is still emitted -- nothing is lost, it is labelled.
(a) transforms._assumed_site_dbs: a host is dropped from the RemoteRegistry arm only when ALL THREE hold -- the SQL role is flagged assumed, no unflagged source also claims it, and nothing answered on 1433 (mssql_server_instances.port_open). Verified against out/priv5: the gate excludes exactly S-1-...-1111 (ps1-psv) and keeps S-1-...-1113 (ps1-sec).
TWO BUGS FOUND IN MY OWN FIRST ATTEMPT, both worth remembering:
 - Single-statement gate referencing both remoteregistry_computers and mssql_server_instances: _safe drops the WHOLE statement when any named table is missing, so a run without mssql_server_instances would have lost the gate rather than finding no corroboration. Split into two temp tables.
 - The unit-test fixture typed sccm_site_system_roles as VARCHAR[]; dlt actually lands it as JSON. list_filter() cannot bind on JSON, _safe swallowed the BinderException, and the gate silently no-opped in production while every test passed. Fixture now uses JSON; the predicate matches on the stringified column so it binds for JSON/VARCHAR/VARCHAR[] alike. See con-9b3a for the underlying _safe diagnosability gap.
STILL OPEN -- needs @_Mayyhem: a SECOND, independent arm also creates psv's MSSQL_Server node. get_mssql_settings genuinely found SQL Server registry keys on ps1-psv (instance MSSQLSERVER, port 1433), i.e. SQL Server is INSTALLED there even though the service is not running. After this fix psv loses all site-DB scaffolding (SCCMSite, sccm_infra, CM_PS1, logins, db-users, role memberships) but survives as a BARE MSSQL_Server node, which matches the README's documented 'non-SCCM SQL servers appear as bare MSSQL_Server nodes'. So node-mssql-server-count would be 5 (cas-db, ps1-db, ps1-sec, ps1-psv installed-not-running, PS2-PSS stale SPN), not the 3 the worksheet asked for. Decide whether an installed-but-stopped SQL Server should yield a node at all -- dropping it would also drop legitimately firewalled SQL servers, which the SPN arm exists to catch.

**2026-07-31T19:38:20Z**

Correction to the previous note: the _safe diagnosability ticket is con-2ca2, not con-9b3a (I wrote the ID before filing it).

**2026-07-31T20:22:16Z**

COMPLETE per @_Mayyhem's decisions: always create the MSSQL_Server node, enrich its properties, and read service state from the registry rather than a port probe so firewalls cannot hide a healthy instance.
Delivered: (c) registry emits sql_role_assumed on the empty-key inference; (a) _assumed_site_dbs drops an assumed SQL role only when no unflagged source claims it AND nothing answered on 1433; plus new reads of HKLM\SYSTEM\CurrentControlSet\Services\{MSSQLSERVER|MSSQL$<instance>}\Start and \ObjectName, surfaced as SQLServiceStartType and SQLServiceAccountName. The ObjectName read also fills SQLServiceAccountName, which the RemoteRegistry arm previously hard-coded to NULL.
A SQLServiceRunningPossible property was added and then REMOVED at @_Mayyhem's request -- SQLServiceStartType alone carries the information ('Disabled' being the one value that proves the engine is not running), and the derived boolean was an unwanted judgement on the node.
Verified: full suite 915 passed / 5 skipped / 0 failed; ruff and mypy clean. Privileged lab run went 50 pass/22 fail -> 68 pass/4 fail, and MSSQL_Server is now exactly 3 (cas-db, ps1-db, ps1-sec). Note that result combines this fix with @_Mayyhem uninstalling MSSQLServer on ps1-psv and removing the ps2-db SPN, so the fix alone is not solely responsible; the gate itself was verified independently against out/priv5, where it excluded S-1-...-1111 (ps1-psv) and kept S-1-...-1113 (ps1-sec).
Per @_Mayyhem: fixture counts were NOT updated for the ps1-psv / ps2-db discrepancies -- those were manual lab additions, to be retried in a clean lab.
