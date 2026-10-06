---
id: con-7b9e
status: open
deps: []
links: []
created: 2026-10-06T01:06:21Z
type: bug
priority: 2
tags: [powershell, sccm, ldap, acl]
---

# Fix System Management ACL Full Control filtering in deprecated PowerShell collector

`powershell_deprecated/ConfigManBearPig.ps1` incorrectly treats some System Management container ACEs as Full Control. In the AD-module path near line 3459, the `Where-Object` filter is missing `-and` before the `NT AUTHORITY` exclusion, so its last expression can admit Deny and non-GenericAll ACEs. Both the AD-module and DirectoryServices paths also need to exclude inherit-only ACEs and rights scoped by `ObjectType`; Exchange ACEs of these forms can otherwise make Exchange servers appear to be SCCM collection targets. See ConfigManBearPig PR #14 for the Python collector's related fix.

## Acceptance Criteria

- Both PowerShell ACL paths retain effective Allow Full Control on the container, including a container-inherit ACE and an object ACE whose only GUID is `InheritedObjectType` and that is not inherit-only. `InheritedObjectType` limits child inheritance; by itself it does not remove rights on the current container.
- Deny, non-Full-Control, inherit-only, and `ObjectType`-scoped ACEs do not produce Full Control principals or targets. Exclude LOCAL SYSTEM, BUILTIN\Administrators, and CREATOR OWNER from SCCM target inference.
- A regression test covers the AD-module filter's missing `-and` and the Exchange/SCCM mixed-ACL case. A lab check confirms Exchange servers are no longer added solely through this ACL while genuine SCCM site servers still are.
