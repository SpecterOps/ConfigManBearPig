---
id: con-53eb
status: open
deps: []
links: []
created: 2026-08-01T18:04:06Z
type: task
priority: 3
tags: [sccm, mssql, secondary, bloodhound]
---

# Emit BUILTIN\Administrators as sysadmin on an SCCM-installed Express secondary site database

A secondary site database installed by SCCM as SQL Express has BUILTIN\Administrators in the sysadmin server role by default -- lab-verified by @_Mayyhem 2026-08-01. That is BROADER than what is emitted today.

WHAT SHIPPED (2026-08-01): only the parent-primary grant. node_mssql_login gained an arm giving the parent primary site servers sysadmin on a confirmed secondary site database. That grant is correct on BOTH install paths -- directly when the instance pre-existed (documented), and transitively through local Administrators when setup installed Express -- so it needs no discriminator.

WHAT IS MISSING: on the Express path, EVERY member of the secondary site server local Administrators group is a sysadmin, not just the parent primary. In the mayyhem lab SharpHound shows ADMINISTRATORS@PS1-SEC.MAYYHEM.COM containing DOMAIN ADMINS, SCCM_PUSH_ACCOUNTS, PS1-PSS$ and PS1-PSV$. Three of those four are invisible in the graph today.

DISCRIMINATOR (already collected, privileged only). node_mssql_server.databases carries an instance-qualified name for a secondary: CONFIGMGRSEC\CM_SEC, versus a bare CM_CAS / CM_PS1 on default MSSQLSERVER instances. Corroborated by service_account_name LocalSystem rather than a domain service account, and has_mssql_spn false. Source is adminservice_site_definitions.sql_database_name.

PROPOSED SHAPE. Emit the local Administrators group as the sysadmin holder so it MERGES with the group SharpHound already collects, rather than synthesizing a login per principal we guess is in it. Membership then comes from SharpHound and no inference is needed -- including for the passive-site-server question, which stops mattering entirely.

IMPLEMENTATION TRAPS, both verified 2026-08-01:
  - SID format is <computer AD object SID>-544, e.g. S-1-5-21-3242052782-1287495003-4091326449-1113-544, name ADMINISTRATORS@PS1-SEC.MAYYHEM.COM. Confirmed against a real SharpHound v2.13.0 capture of this lab, consistent across 10 hosts and every RID, not just 544.
  - graph.py domain_environment_id matches ^(S-1-5-21(?:-\d+){3})-\d+$ -- ONE trailing RID. A local group SID has two, so it does not match and falls back. node_group.fallback_domain_sid MUST be populated or models/group.py drops the node with a warning and the edge dangles. _node_authenticated_users is the working precedent.
  - Domain controllers are the exception: SharpHound emits MAYYHEM.COM-S-1-5-32-544 with Name IGNOREME. Restrict any builder to non-DC hosts.
  - This would be the collector first emitted local-group node; schema_SCCM.json and schema_MSSQL.json declare only custom namespaces, and Group/Base come from the repo own models/group.py.

BLOCKED ON A DECISION: whether an instance-name prefix is confident enough to assert that every local admin holds sysadmin. Getting it wrong over-claims on a pre-existing-instance secondary. Deliberately deferred rather than guessed.
