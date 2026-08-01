---
id: Ope-rhzx
status: in_progress
deps: []
links: [ope-a214]
created: 2026-05-28T13:32:31Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, adminservice, rbac, permissions]
---

# Individual Permissions (Port from PowerShell)

Port granular SCCM RBAC permission collection from ConfigManBearPig.ps1 to the Python/OpenHound implementation. The PS1 script collects which AD principals have which SCCM security roles on which collections, mapping to SMS_Admin, SMS_Role, SMS_SecuredCategory, and SMS_Collection. The OpenHound model includes SCCM_AdminUser, SCCM_SecurityRole, SCCM_Collection node kinds but no RBAC edge collection.

## Design

Implement AdminService collection of: GET /AdminService/wmi/SMS_Admin (admin principals with RoleIDs and CategoryIDs), GET /AdminService/wmi/SMS_Role (role definitions and permissions), GET /AdminService/wmi/SMS_SecuredCategory (secured categories), GET /AdminService/wmi/SMS_Collection (collection membership for scoped permissions). Store in adminservice_sms_admins, adminservice_sms_roles, adminservice_sms_categories. In transforms.py: derive role_assignment_edges and all_permissions_edges. Resolve AD SIDs for each SMS_Admin entry to User/Group/Computer nodes. Emit EX_RoleAssignment (principal -> SecurityRole), EX_Scoped (role -> collection). Full-admin principals emit EX_AdminTo to site node.

## Acceptance Criteria

All SCCM admin principals, their roles, and collection scopes are collected. Role assignment edges appear in graph output. Full-admin principals emit EX_AdminTo edge to site node (matches PS1 behavior).

## Notes

**2026-07-20T19:56:58Z**

Scope pairing (2026-07-20): work jointly with ope-a214 (same underlying decision). The audit first graded this DONE because the role-based RBAC edges exist (IsMappedTo/IsAssigned/Contains/7 role grants/AllPermissions), but 'Individual Permissions' means the granular per-operation permissions beyond role membership, i.e. the still-unimplemented SCCM_AssignSpecificPermissions (0 lab instances; see ope-0495 gap analysis). OPEN DECISION (shared with ope-a214 item 2): should the admin-user assign-all-permissions path emit an admin-user to SCCM_AssignAllPermissions edge, or should the composition live on SCCM_AllPermissions? Resolve once, implement together.

**2026-07-31T15:37:02Z**

Status audit 2026-07-31: CORRECTLY IN PROGRESS -- code confirms the gap. SCCM_AssignSpecificPermissions is NOT an emitted edge kind: it does not appear in kinds/edges.py at all, and its only occurrence in the tree is src/openhound_sccm/integration/fixtures/edges.py:531-537, where the fixture's own description says 'constraint-less in the PS kit; presence is not asserted' -- i.e. the test kit deliberately does not check for it, so a green suite is not evidence it works. The role-based RBAC layer that the 2026-07-20 audit noted DOES exist (SCCM_IsMappedTo, SCCM_IsAssigned, SCCM_Contains, the 7 role-grant kinds, SCCM_AllPermissions, SCCM_AssignAllPermissions are all in kinds/edges.py), which is why an earlier pass mis-graded this DONE -- but 'Individual Permissions' means the granular per-operation permissions beyond role membership, and none of that is implemented. The blocking open decision is unchanged and still shared with ope-a214 item 2: does the admin-user assign-all-permissions path emit an admin-user -> SCCM_AssignAllPermissions edge, or does the composition live on SCCM_AllPermissions? Nothing can be implemented until that is answered, so this ticket is decision-blocked rather than merely unstarted.
