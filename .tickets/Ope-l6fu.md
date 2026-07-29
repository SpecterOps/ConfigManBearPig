---
id: Ope-l6fu
status: closed
deps: []
links: [ope-c8cc]
created: 2026-05-28T13:28:17Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, mssql, relay]
---

# TDS and EPA Implementation Coverage

Ensure SQL Server TDS channel binding and EPA (Extended Protection for Authentication) flags are fully collected and reflected in graph edges. The mssql_epa_flags preproc table is defined but has no collector. EPA enforcement determines whether NTLM relay to MSSQL is feasible, making CoerceAndRelay edges inaccurate without this data.

## Design

Collect EPA flags via MSSQL query or registry key HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<instance>\MSSQLServer\ExtendedProtection (0=Off, 1=Allowed, 2=Required). Detect TDS EPA negotiation by attempting connection with/without channel binding. Store in mssql_epa_flags: { hostname, instance, epa_level, channel_binding_required }. Filter coerce_and_relay_edges for MSSQL targets to only include epa_level != 2.

## Acceptance Criteria

mssql_epa_flags table is populated during MSSQL collection. CoerceAndRelay edges to MSSQL only emitted when EPA is not Required. EPA status visible as a property on the relevant node.

