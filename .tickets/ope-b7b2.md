---
id: ope-b7b2
status: closed
deps: []
links: [ope-272e, ope-4ba1]
created: 2026-06-09T20:50:25Z
type: task
priority: 3
tags: [sccm, auth, pth, ptt, credentials, deferred]
---

# Wire --nt-hash / --ticket into LDAP, SMB, RemoteRegistry, MSSQL auth paths

DEFERRED. The HTTP-client work (ope-d57d) introduces the global --nt-hash and --ticket CLI flags + SourceContext.kerberos_ticket, but initially only the HTTP client consumes them. This ticket threads those same credentials into the OTHER already-implemented auth paths so pass-the-hash and pass-the-ticket work uniformly across all protocols: LDAP (clients/ad.py ADCredentials + bind: NTLM pass-the-hash and Kerberos pass-the-ticket), SMB/RemoteRegistry (clients/smb_sso.py connect_smb: explicit NTLM-hash login + Kerberos ticket path), MSSQL (clients/mssql_epa.py: nt_hash already supported, add ticket). Relates to / subsumes ope-272e (LDAP PtH placeholder).

## Notes

**2026-07-21T21:19:54Z**

Code complete + offline-validated. LDAP PtH/PtT wired (subsumes ope-272e); MSSQL EPA logs a WARNING and skips on ticket-only creds (pass-the-ticket cannot probe channel binding) - full MSSQL pass-the-ticket-for-EPA deliberately NOT implemented, no follow-up ticket (owner decision). Docs updated: --nt-hash/--ticket help, ARCHITECTURE section 6 + changelog, README auth coverage. Offline tests: test_ad_pth_ptt.py (3), test_mssql_epa.py (+2). REMAINING before done: live-lab LDAP PtH/PtT validation vs dc.mayyhem.com (needs NT hash + base64 .kirbi).

**2026-07-21T22:00:50Z**

LIVE-VALIDATED vs dc.mayyhem.com: LDAP pass-the-hash bound auth=ntlm_hash and pass-the-ticket (runtime-minted .kirbi) bound auth=kerberos, both LDAPS:636+CBT as MAYYHEM\domainadmin (whoami confirmed), no lockout. MSSQL ticket-only warning covered by offline test (not live-reachable on Windows: SSPI precedes the warning by design). All in-scope work complete; closing.
