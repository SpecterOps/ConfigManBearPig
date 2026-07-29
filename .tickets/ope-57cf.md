---
id: ope-57cf
status: closed
deps: []
links: []
created: 2026-07-14T20:12:03Z
type: bug
priority: 1
---

# Fix MSSQL login/user under-population (SysResUse role@site + sam_account_name propagation)

OpenHound built only 1 of 4 expected MSSQL logins (MSSQL_HasLogin 5->1, MemberOf 9->2, IsMappedTo 5->1, GetTGS 5->1), starving the MSSQL_DatabaseUser/HasLogin/IsMappedTo/MemberOf/GetTGS tests. Logins are INFERRED in preproc (_node_mssql_login), one per (SQL server, computer with 'SMS Site Server@<site>'/'SMS Provider@<site>'). Two root causes: (1) the @site-suffixed role was built only by SMS_SCI_SiteDefinition (privileged.py:129), which lists only the active site server + SQL host; SMS_SCI_SysResUse (adminservice_site_systems) has passive server + SMS provider with role_name+site_code but was never folded into node_computer as role@site. (2) node_computer arms for remoteregistry_computers/adminservice_site_definitions_computers/smb_computers did 'NULL AS sam_account_name' on a stale assumption, leaving cas-pss (seen only via those) with null sam -> excluded. FIX: post-collapse augmentation in _node_computer joins SysResUse by hostname adding role_name@site_code; the 3 arms now read sam_account_name. RESULT: MSSQL_Login 1->4 (CAS-PSS,PS1-PSS,PS1-PSV,PS1-SMS), cascade HasLogin/IsMappedTo/GetTGS 1->4, MemberOf 2->8; also recovered LocalAdminRequired DP+passive. Live kit PASS 29->37, 0 blast-radius regressions. 3 regression tests added; 556 passed. Files: transforms.py, tests/node_computer_test.py.
