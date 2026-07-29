---
id: ope-fb99
status: closed
deps: []
links: [ope-c141, ope-c0c0, ope-6b93]
created: 2026-07-23T19:20:16Z
type: task
priority: 2
tags: [sccm, graph]
---

# Emit missing SCCM node/edge properties (ClientDevice extras, Site.siteSystemRoles, IsMappedTo.SCCMInfra) to CMBP parity

A --compare-to-zip diff (OpenHound vs CMBP baseline) found SCCM-specific properties present in CMBP output but not emitted by the OpenHound collector. Emit all of these (CMBP-exact casing): (1) SCCM_ClientDevice: currentManagementPoint, currentManagementPointSID, previousSMSID, previousSMSIDChangeDate, userName, userDomainName, lastReportedMPServerSID (and DNSHostName/distinguishedName if resolvable). (2) SCCM_Site: siteSystemRoles. (3) SCCM_IsMappedTo edge: SCCMInfra property. Determine each source from ConfigManBearPig.ps1 (AdminService/WMI SMS_R_System / SMS_CombinedDeviceResources fields for the client-device extras; site-definition/SysResUse for siteSystemRoles) and plumb through preproc/convert to the node/edge property dataclasses. Update README node/edge reference + ARCHITECTURE. Part of the same CMBP-parity effort as the AD-property ticket; needs brainstorm/spec/plan.

## Notes

**2026-07-24T18:03:00Z**

COMPLETE + pushed (integration). Phase B: SCCM_Site.siteSystemRoles (empty on Secondary Sites), SCCM_IsMappedTo.SCCMInfra edge prop, six SCCM_ClientDevice telemetry extras (currentManagementPoint/SID, previousSMSID/ChangeDate, userName/userDomainName). Live re-validation vs CMBP baseline confirmed real values (siteSystemRoles 2/3, ClientDevice extras 14/20, SCCMInfra 4/4). Full suite 716 pass. Spawned ope-c0c0 (bug, fixed) and ope-6b93 (Local-only-node investigation, still open).
