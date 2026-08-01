---
id: con-c509
status: closed
deps: []
links: []
created: 2026-07-31T18:31:47Z
type: bug
priority: 2
tags: [sccm, mssql, preproc, secondary-site]
---

# Secondary sites should not inherit primary-site MSSQL sysadmin/login assumptions

The SEC secondary site is being given MSSQL relationships that @_Mayyhem says only hold for PRIMARY site databases. From the fixture review: MSSQL_GetTGS (found 6, want 4), MSSQL_GetAdminTGS (found 3, want 2), MSSQL_IsMappedTo (found 6, want 4), MSSQL_MemberOf x2 (found 6, want 4), SCCM_AssignAllPermissions site-databases (found 3, want 2 -- 'This edge should NOT be created for SEC'). @_Mayyhem's reasoning: for a primary site database we can assume site servers are sysadmins, so the service-account TGS/login/dbuser assumptions follow; for a secondary we cannot assume any domain user or computer has a login or is a sysadmin. The extra edge in each count is SEC's. Note MSSQL_ControlDB is the opposite case -- 'Update count to 3 for SEC' -- so SEC does legitimately get some MSSQL structure; this is about which assumptions extend to a secondary, not about excluding SEC wholesale.

## Acceptance Criteria

Primary-site-only MSSQL assumptions (service-account GetTGS/GetAdminTGS, login->dbuser IsMappedTo, sysadmin/db_owner MemberOf, SCCM_AssignAllPermissions) are not generated for secondary sites; MSSQL_ControlDB still includes SEC; the affected fixture counts pass without inflating expectations.

## Notes

**2026-07-31T19:25:49Z**

HYPOTHESIS BEFORE DOING ANY WORK HERE -- con-be15 may already resolve most of this; re-measure before editing anything.
_node_mssql_login's contract: 'Sysadmin computer = a Site Server / SMS Provider for the SAME site as the SQL host, EXCLUDING the SQL host itself'. For SEC the only host carrying an SMS Site Server@SEC role is ps1-sec, which IS the SQL host and is therefore excluded by 'c.sid != upper(s.host_sid)'. So SEC should contribute ZERO logins/dbusers, and the +2 on MSSQL_HasLogin / IsMappedTo / MemberOf is unlikely to be SEC's.
The likelier source is ps1-psv. Under the empty-key inference it became a PS1 SQL host, so every PS1 Site Server / SMS Provider (ps1-pss, ps1-sms) gets a login on it -- exactly +2 -- with matching db-users and sysadmin/db_owner memberships, which is the same +2 seen on all four counts.
Independent supporting evidence: when ps1-psv dropped offline between the unpriv3 and unpriv4 runs, six MSSQL cases started passing with no code change (contains-ps1-server-cm-ps1-database, contains-ps1-server-ps1-pss-login, contains-ps1-database-db-owner-role, contains-ps1-database-ps1-pss-user, controldb-db-owner-site-databases, assignallpermissions-site-databases).
ACTION: after the con-be15 gate lands, re-run both privilege levels and re-measure. If the counts reconcile, this ticket shrinks to whatever genuinely remains for SEC (@_Mayyhem's MSSQL_ControlDB note says SEC legitimately DOES get some MSSQL structure, so it is not simply 'exclude SEC').

**2026-07-31T20:12:32Z**

HYPOTHESIS CONFIRMED -- most of this ticket has resolved itself. Re-measured 2026-07-31 after con-be15 landed AND @_Mayyhem uninstalled MSSQLServer on ps1-psv / removed the ps2-db SPN.
MSSQL_Server is now exactly 3 (cas-db, ps1-db, ps1-sec) at privileged, matching the worksheet expectation.
The four counts this ticket was opened for NO LONGER show 'wrong count': MSSQL_HasLogin, MSSQL_IsMappedTo (mssql logins->dbusers) and MSSQL_MemberOf x2 now PASS unprivileged and are absent from the failure list entirely. The +2 was ps1-psv all along, not SEC's service account -- the secondary never contributed those edges, because _node_mssql_login excludes the SQL host itself and ps1-sec is the only host carrying an SMS Site Server@SEC role.
WHAT REMAINS, and it is a different problem from the one filed: MSSQL_GetTGS, MSSQL_GetAdminTGS and MSSQL_ServiceAccountFor now fail unprivileged as 'not found' rather than 'wrong count' -- i.e. they are not over-produced for SEC, they are UNDER-produced at low privilege. That matches @_Mayyhem's worksheet note 'Should be created with low priv based on assumed MSSQL data', which is a low-privilege gap in the same family as con-2249/con-5e71, not a secondary-site over-assumption.
SUGGESTION: re-scope this ticket to the low-priv under-production of GetTGS/GetAdminTGS/ServiceAccountFor, or close it and fold those into a low-priv MSSQL ticket. The original 'secondary sites inherit primary-site assumptions' premise is not supported by the current measurements.

**2026-07-31T20:26:58Z**

@_Mayyhem 2026-07-31: 'should not require privileges in SCCM'. Confirms the re-scope -- this ticket is now about MSSQL_GetTGS, MSSQL_GetAdminTGS and MSSQL_ServiceAccountFor being UNDER-produced at low privilege (they fail unprivileged as 'not found' while passing privileged), not about secondary sites over-inheriting primary-site assumptions. The original premise was disproved by re-measurement: the +2 on HasLogin/IsMappedTo/MemberOf was ps1-psv, and those cases now pass.

**2026-07-31T22:21:53Z**

FIXED (shared fix with con-2249) and verified on the lab. Root cause was NOT what the ticket assumed: the edges were never missing. MSSQL_GetTGS(4), MSSQL_GetAdminTGS(2) and MSSQL_ServiceAccountFor(2) reach graph_edges identically at both privilege levels. What was missing was samAccountName on their shared endpoint -- the sqlsccmsvc service account -- because every one of _node_user's seven arms read an SCCM-privileged source. node_user held 23 rows privileged vs 1 unprivileged, so the account fell through to node_backfill and shipped as a SID-only stub. Five fixtures pin that endpoint by samAccountName, so the matcher rejected otherwise-correct edges and the runner said 'not found'.
Fix: collectors/mssql.py keeps holder['sam_account_name'] (the LDAP lookup already resolved AND logged it) and emits service_account_name; transforms._node_user gains an eighth arm reading mssql_server_instances -- its first low-privilege arm -- guarded by _ensure_columns and excluding machine accounts, which belong in node_computer.
Verified on a fresh unprivileged collection: the -1116 node now carries samAccountName 'sqlsccmsvc'. Lab went 45->54 passing unprivileged; all five of these cases now pass. Full suite 923 passed / 5 skipped / 0 failed.
