---
id: Ope-zaja
status: open
deps: [Ope-l6fu, Ope-o008]
links: [ope-d820]
created: 2026-05-28T13:31:00Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, http, relay, takeover]
---

# Relay to Management Point

Model NTLM relay attack paths targeting the SCCM management point AdminService API. If NTLM is accepted on AdminService (https://<MP>/AdminService/) without Extended Protection, a relay from a coerced site server allows executing AdminService operations as the site server computer account, which typically has site admin rights. References: Misconfiguration Manager TAKEOVER-1, TAKEOVER-2.

## Design

Collect AdminService NTLM/EPA configuration via HTTP: attempt anonymous OPTIONS request and parse WWW-Authenticate header for EPA token requirement. Collect IIS Extended Protection config on MP host via registry or WMI. Store in http_management_points preproc table: { ntlm_accepted, epa_required, https_enforced }. In transforms.py: emit EX_RelayToMP edge when site server has SMB signing disabled AND MP accepts NTLM without EPA. Add finding: AdminService accepts NTLM without Extended Protection -> CRITICAL.

## Acceptance Criteria

MP EPA status is collected and stored. Relay-feasible paths emitted as edges. Finding generated for unprotected MPs.

