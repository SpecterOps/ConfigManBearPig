---
id: ope-f173
status: open
deps: []
links: []
created: 2026-06-17T14:55:11Z
type: task
priority: 2
---

# Add Kerberos to the LDAP auth ladder when explicit credentials are provided at the CLI

## Notes

**2026-07-31T15:37:02Z**

Status audit 2026-07-31: CORRECTLY OPEN, and here is the exact code that proves it. The LDAP bind ladder now lives in the shared library after the ope-1f49 migration (SCCM's clients/ad.py is a thin subclass; it only forwards kerberos_ticket at ad.py:154). The selector is AdClient._select_auth_modes in .venv/Lib/site-packages/openhound_collector_common/clients/ad.py:447 and it returns: ['kerberos'] for pass-the-ticket, ['ntlm_hash'] for pass-the-hash, ['ntlm'] for an explicit username+password, and only in the NO-explicit-credential case does it try integrated ['kerberos', 'sspi_ntlm']. So Kerberos is reachable from a ticket or from the current Windows identity, but an operator who passes -u/-p at the CLI gets NTLM and nothing else -- exactly the gap this ticket describes. The comment at lines 456-458 records that as a deliberate NTLM-first choice mirroring the Go implementation, so this is a design change to argue for, not an oversight to patch. IMPORTANT SCOPING: the fix belongs in openhound-collector-common, which is a separate repository and package shared with the MSSQL collector, so it is not a change to this repo -- same class as ope-4ba1. Both collectors need re-validating against the lab afterwards.
