---
id: con-edee
status: closed
deps: []
links: []
created: 2026-07-31T18:32:46Z
type: task
priority: 3
tags: [sccm, fixtures, mssql, lowpriv]
---

# Reconcile SCCM_AssignAllPermissions SMS-Provider-hosts count against PS1 logic

@_Mayyhem question on edge-assignallpermissions-smsprovider-hosts (want exact=8, privileged PASS, unprivileged found 6): 'Should this pass unprivileged now that ps1-psv is back online? Compare code to ConfigManBearPig.ps1 logic if there is a discrepancy. Should it be at_least?' The case asserts that domain computers hosting the SMS Provider role (CAS-PSS, PS1-PSS, PS1-PSV, PS1-SMS) can assign all permissions. Needs a three-way comparison: current collector behaviour at each privilege level, the ConfigManBearPig.ps1 original logic, and whether exact=8 or at_least is the right shape.

## Acceptance Criteria

The unprivileged shortfall (6 vs 8) is explained, the collector is reconciled against ConfigManBearPig.ps1's logic where they differ, and the count spec is set to exact or at_least with a documented reason.

## Notes

**2026-07-31T22:22:21Z**

FIXED. The verifier confirmed 8 is correct and the COLLECTOR was wrong, not the fixture -- switching to at_least would have silently passed the 12 and hidden four false 'can take over the hierarchy' edges from a site that is a secondary.
Root cause: the non-secondary filter was coalesce(site_type, 0) != 1, which reads an UNKNOWN type as non-secondary. At low privilege mayyhem's SEC secondary is discovered only as a bare site code (SMB share comments) and carries site_type NULL, so every SMS Provider gained a spurious edge to it.
Fix: the predicate now requires a KNOWN Primary(2) or CAS(4), inverting the default to 'exclude what we could not characterize' -- a false takeover edge costs an operator more than a missing one. It was copy-pasted across five builders (_edge_contains, _edge_all_permissions, _edge_assign_all_permissions, _edge_local_admin_required, _edge_coerce_relay_smb), so it is now one shared constant _NON_SECONDARY_SITE_TYPE_SQL and the unknown-type policy is decided once. That also fixes the spurious PS1-SEC -> PS1-MP SCCM_LocalAdminRequired edge the investigation found, which no fixture was catching.
Verified: low-priv SCCM_AssignAllPermissions went 12 -> 10 total (8 smsprovider-hosts + 2 site-databases, both cases passing). Two tests written first, both watched fail. Full suite 923 passed.
