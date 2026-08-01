---
id: Ope-liu7
status: in_progress
deps: []
links: []
created: 2026-05-28T13:30:45Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, ldap, acl, takeover]
---

# System Management Container Abuse

Collect AD ACL permissions on the System Management container and model the privilege escalation path to SCCM site admin. Any principal with GenericWrite, CreateChild, or WriteDACL on CN=System Management,CN=System,<domain> can create/modify SCCM site objects to gain SCCM admin. The ldap_system_management_acl preproc table is planned but has no collector. Reference: Misconfiguration Manager TAKEOVER-5.

## Design

In collectors/ldap.py: collect the DACL of CN=System Management,CN=System,<base_dn> using ldap3 with ALL controls. Parse ACEs for principals with GenericAll, GenericWrite, WriteDACL, WriteOwner, or CreateChild on mSSMSSite/mSSMSManagementPoint object classes. Store in ldap_system_management_acl: { principal_sid, access_mask, ace_type, inherited, object_type }. In transforms.py: derive edges for each qualifying principal to SCCM site nodes. Resolve principal SIDs to AD objects via ctx.resolve_principal().

## Acceptance Criteria

System Management container ACL is collected. Principals with write access have edges to SCCM site nodes. Inherited vs. explicit ACEs are distinguished.

## Notes

**2026-07-31T15:36:31Z**

Status audit 2026-07-31: CORRECTLY IN PROGRESS -- roughly half the acceptance criteria are met. DONE: the container DACL is collected (ldap_system_management_dacl resource, collectors/ldap.py:586) and is now read by a transform (transforms.py:2320, it previously fed no node at all); the Container node carries a queryable lowercase distinguishedname (con-894a); GenericAll holders that are groups are recursively expanded with a cycle guard (ope-e191, _expand_group_targets at ldap.py:718); computer holders are registered as scan targets with source LDAP-GenericAllSystemManagement. NOT DONE, and both are explicit acceptance criteria: (1) only GenericAll is extracted -- _parse_sd_generic_all (ldap.py:790) tests access_mask against AD_GENERIC_ALL 0x000F01FF and raw GENERIC_ALL 0x10000000 only, so the GenericWrite / WriteDACL / WriteOwner / CreateChild principals the ticket names are never surfaced; (2) inherited vs explicit ACEs are NOT distinguished -- the parser reads ace_type at the ACE header and access_mask at pos+4 but never reads the AceFlags byte at pos+1, which is where INHERITED_ACE (0x10) lives, so nothing downstream can tell an inherited grant from an explicit one. Also note the edges land on a Container node (kind GenericAll), not on SCCM site nodes as the original design text describes -- if that is the intended final shape, the acceptance criteria should be reworded to match.
