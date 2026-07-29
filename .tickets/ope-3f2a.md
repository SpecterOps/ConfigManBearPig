---
id: ope-3f2a
status: closed
deps: []
links: [Ope-ew5k, ope-38ad]
created: 2026-06-11T22:47:52Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, collection, wmi]
---

# SMS Provider WMI fallback collection (AdminService mirror)

Port ConfigManBearPig.ps1 Invoke-SmsProviderWmiCollection as the per-host WMI phase: a fallback for AdminService that queries the site WMI namespace (root SMS site_code) over DCOM/WMI when AdminService is unreachable. Mirrors the AdminService collector exactly (same 10 collections, same order). Hybrid auth ladder reusing choose_auth: impacket DCOM for kerberos/ntlm/ticket (incl PtH/PtT), pywin32 for current-user SSPI, anonymous skipped. Gate via TargetEntry.completed_phases checked in should_run_phase. Writes separate wmi_* tables. Distinct from Ope-ew5k, which is client-side CIM scraping (SMS_Client, Win32_LoggedOnUser, Win32_Service).

## Notes

**2026-06-12T16:28:17Z**

Implemented + live-validated against ps1-sms.mayyhem.com (site PS1). All 5 auth rungs confirmed end-to-end (identify + SMS_Site/SMS_SCI_SiteDefinition/SMS_Admin queries returning rows): SSPI (pywin32 current user), Kerberos (explicit password, impacket DCOM), pass-the-hash, NTLM (IP literal), pass-the-ticket. Live testing caught 4 bugs the mocks could not: (1) IWbemLevel1Login takes the interface positionally not as iinterface=; (2) impacket breaks on a 2nd IWbemLevel1Login over one DCOMConnection -> use one connection per namespace; (3) embedded SMS Props come back as unparsed ENCODING_UNIT -> call ObjectBlock.parseObject() before normalizing; (4) ticket-only PtT needs the client principal derived from the .kirbi. Unit suite: 270 passed / 5 skipped / 0 failed; ruff clean on new code. Collect-only (raw wmi_* tables; graph convert deferred, same as AdminService).
