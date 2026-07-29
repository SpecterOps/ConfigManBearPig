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

