---
id: ope-e191
status: closed
deps: []
links: []
created: 2026-06-03T20:38:59Z
type: feature
priority: 1
tags: [sccm, ldap, acl, recursion, takeover]
---

# Recursively expand group members of GenericAll holders on System Management container

When LDAP collection finds a principal with GenericAll on CN=System Management,CN=System,<base_dn>, collectors/ldap.py (ldap_system_management_dacl) only acts on computers -- registering them as collection targets -- while users and groups are merely logged and yielded. A group with GenericAll grants effective Full Control to every member, including members of nested groups, so those principals are missed today. Add recursive group-membership expansion so the real set of principals controlling the container is discovered and acted on. Reference: existing handling at sccm/sccm/src/openhound_sccm/collectors/ldap.py:562-604.

## Design

In collectors/ldap.py ldap_system_management_dacl: when a resolved GenericAll principal is a group, recurse its membership. For each member, resolve the SID to an AD object, then:

- If the member is a computer, register it as a collection target (source LDAP-GenericAllSystemManagement, same path as direct computer holders).
- If the member is a user, yield it for graph modeling.
- If the member is a group, recurse into it.

Track visited group SIDs/DNs in a set to avoid infinite loops from circular group nesting. Reuse ctx.resolve_principal() and the existing register_target() path. Preserve the ordered per-table emit conventions; do not change emit ordering.

## Acceptance Criteria

- Groups with GenericAll on the System Management container have their members expanded recursively, including nested groups.
- Computer members are registered as collection targets.
- User members are yielded for modeling.
- Circular group nesting does not cause infinite recursion (visited-set).
- Behavior for direct, non-group GenericAll principals is unchanged.

## Notes

**2026-07-21T15:56:50Z**

Closed (2026-07-21): recursive GenericAll group expansion added to ldap_system_management_dacl via _expand_group_targets — computer members registered as targets (LDAP-GenericAllSystemManagement), users logged, nested groups recursed, cycle guard keyed on group_dn. Range handling reconciled to ldap3 auto_range (which already pages large groups fully); a defensive warning fires only if a residual member;range= key shows auto_range did not complete (no silent truncation). Tests: tests/test_ldap_smc_recursion.py; per-task + whole-branch reviewed; green. Code pushed by user.
