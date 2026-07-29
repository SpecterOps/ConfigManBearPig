---
id: ope-b287
status: closed
deps: [ope-0112, ope-d57d]
links: []
created: 2026-06-03T19:29:25Z
type: task
priority: 2
---

# Implement AdminService per-host collector -type task -priority 2 -description Port Invoke-AdminServiceCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the AdminService stub. Note: emits multiple tables (admin users, client devices, components, roles, etc.); clients are data rows, not probe targets.

## Notes

**2026-06-11T14:43:09Z**

Collect-only port implemented (not committed; owner commits after testing). New collectors/adminservice.py: orchestrator collect_adminservice + SMS_Identification gate + 13 collection helpers in exact PS1 order (sites, site_definitions, stored_accounts, client_devices [IsClient/IsObsolete filtered], r_system_security_groups, r_user_security_groups, collections, collection_members, security_roles, admins, site_systems) plus 2 new appended last (collection_variables, task_sequences). Shared _get_value/_paginate($top/$skip)/_row(snake-case raw fields + source/source_site_code)/_prop(Props flatten). Uses HttpClient NEGOTIATE (ope-d57d). AdminService phase registered in per_host_phases.py after MSSQL with 13 streams. tests/test_adminservice.py: 21 tests (fake client), all green; ruff clean; mypy baseline-only. DEFERRED to a future convert stage: AD/SID resolution, all OpenGraph nodes/edges (SCCM_Site/Collection/AdminUser/ClientDevice + memberships/assignments), and adminservice_role_members derivation. Spec+plan: docs/superpowers/{specs,plans}/2026-06-09-sccm-adminservice-collector*.md.
