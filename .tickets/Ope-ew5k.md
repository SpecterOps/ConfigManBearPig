---
id: Ope-ew5k
status: open
deps: []
links: [ope-3f2a]
created: 2026-05-28T13:27:40Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, collection, wmi]
---

# WMI Collection

Implement WMI-based collection for client devices, logged-on users, and SQL service accounts. Three WMI-sourced preproc tables are defined but have no collector: wmi_clients, wmi_users_seen, wmi_sql_service_accounts.

## Design

Create collectors/wmi.py. Use impacket or wmi library for remote WMI queries (respect --socks-proxy). Query root\ccm:SMS_Client for client GUID/version/site, root\cimv2:Win32_LoggedOnUser for active users, root\cimv2:Win32_Service WHERE Name LIKE MSSQL% for SQL service accounts. Gate on ctx.method_enabled(WMI). Register resources in source.py Phase 3.

## Acceptance Criteria

With --collection-methods WMI, collector queries each target host and yields wmi_clients, wmi_users_seen, wmi_sql_service_accounts records. Data flows into preproc tables and populates graph edges.

## Notes

**2026-06-11T22:48:07Z**

Scope clarification (see ope-3f2a): this ticket is CLIENT-SIDE CIM scraping (root\ccm SMS_Client, root\cimv2 Win32_LoggedOnUser, Win32_Service LIKE MSSQL%) -> wmi_clients / wmi_users_seen / wmi_sql_service_accounts. The per-host WMI *phase* token and collectors/wmi.py are owned by ope-3f2a (SMS Provider AdminService fallback, server-side root\SMS\site_<code>). When implemented, this client-side work likely needs a distinct phase/token (e.g. LocalCIM) or to fold into Ope-padv (CRED-4). Its three preproc tables remain reserved and untouched by ope-3f2a.
