---
id: ope-3de2
status: closed
deps: []
links: []
created: 2026-07-14T21:06:40Z
type: bug
priority: 1
---

# Fix User nodes missing samAccountName (MSSQL service-account + AD-user endpoint resolution)

MSSQL service-account edges (HasSession, MSSQL_GetTGS/GetAdminTGS/ServiceAccountFor) all existed in correct counts but failed 'not found' because their User endpoint (sqlsccmsvc SID ...1116) lacked a samAccountName property - as did all 99 User nodes (0/99). Kit matches CMBP's SamAccountName via case-insensitive PS lookup. ROOT CAUSE: UserProperties had no samAccountName field, UserNode never set one, and _node_user dropped the bare SAM (adminservice_r_user.user_name = SMS_R_User.UserName, e.g. 'sqlsccmsvc'). FIX: added samAccountName to UserProperties (graph.py, camelCase to match ComputerProperties.samAccountName) + UserNode (models/user.py); plumbed sam_account_name through _node_user from user_name / remoteregistry_users.sam_account_name (transforms.py). RESULT: User samAccountName 0/99 -> 99/99; live kit PASS 37 -> 42; blast radius 0 regressions, +5 passes. 3 regression tests added (node_user_test.py, user_test.py); 559 passed.
