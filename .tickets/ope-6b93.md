---
id: ope-6b93
status: open
deps: []
links: [ope-fb99, ope-0947]
created: 2026-07-24T14:14:47Z
type: task
priority: 3
tags: [sccm, clientdevice, lowpriv, collection]
---

# Local-only/low-priv collector host gets no SCCM_ClientDevice node (CMBP builds it via Local Upsert-Node)

A collector host that is an SCCM client but is NOT enumerated via AdminService/WMI (e.g. a Local-only run, or low-priv with no SCCM admin rights) collects local_wmi_ccm_client (root\CCM CCM_Client + SMS_Authority) but gets NO SCCM_ClientDevice node at all. transforms._node_client_device only builds device rows from adminservice_client_devices / wmi_client_devices; the Local phase only ENRICHES existing rows (see _enrich_client_device). CMBP by contrast unconditionally creates the device node via a Local Upsert-Node (ConfigManBearPig.ps1:4008). PARITY GAP. INVESTIGATE: (1) real-world impact -- how often is the collector host absent from AdminService/WMI enumeration; (2) whether to build the SCCM_ClientDevice node from local_wmi_ccm_client when no privileged row exists (mind dedup by ad_domain_sid + downstream edges). Discovered during Task B3 (ope-fb99). Relates to low-priv work (see memory: sccm-lowpriv-comparison, sccm-lowpriv-assumed-edges-plan).

## Notes

**2026-07-24T14:15:15Z**

Investigate what OTHER collection methods might be available remotely to someone with LOCAL ADMIN privileges but NO SCCM admin privileges -- i.e. what can be read from an SCCM client / site system remotely (RemoteRegistry, SMB named pipes, WMI over DCOM/root\ccm, admin shares, DPAPI-protected blobs, MP/DP HTTP endpoints) when you have local admin on the box but can't hit the AdminService. Enumerate which of those OpenHound already uses vs. what CMBP or other tooling does, and what net-new device/site/role data each could yield. Feeds the broader low-priv assumed-edges effort.
