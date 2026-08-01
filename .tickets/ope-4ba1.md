---
id: ope-4ba1
status: open
deps: []
links: [ope-b7b2]
created: 2026-07-22T13:48:15Z
type: task
priority: 4
tags: [shared-lib, openhound-collector-common, ldap, logging, auth]
---

# Make shared AdClient credential-summary warning flag-name-agnostic (do not name collector-specific CLI flags)

In openhound-collector-common AdClient._log_credential_summary (src/openhound_collector_common/clients/ad.py, ~line 596-598), the anonymous-fallback warning hardcodes specific CLI flag names (--ldap-user / --ldap-password / --ldap-nt-hash / --ldap-ticket). Those are the MSSQL collector's flag names; the SCCM collector uses -u/--username, -p/--password, --nt-hash, --ticket. The shared library serves BOTH collectors, so it must NOT name any one collector's flags. Fix: reword the warning to describe credential TYPES generically (username+password, NT hash, Kerberos ticket) with no CLI flag spellings. Only fires on the no-credentials anonymous LDAP bind path. Surfaced during ope-b7b2 (SCCM LDAP now supports PtH/PtT, so this warning is likelier to reach SCCM operators showing the wrong flag names). Owner-approved shared-lib change; re-validate SCCM + MSSQL. Cosmetic / low-risk.

## Notes

**2026-07-31T15:38:22Z**

Status audit 2026-07-31: CORRECTLY OPEN and still reproducible, but flagging the scope so it is not mistaken for work in this repo. Verified in the installed shared library: openhound_collector_common/clients/ad.py still hardcodes the MSSQL collector's flag spellings in its anonymous-fallback credential-summary warning, while the SCCM collector's equivalents are -u/--username, -p/--password, --nt-hash and --ticket. Since the ope-1f49 migration SCCM's ADClient is a thin subclass of the shared AdClient, so SCCM operators DO reach this warning and are shown flag names that do not exist in their CLI. The fix is a reword to describe credential TYPES generically (username+password, NT hash, Kerberos ticket) with no flag spellings. This lives in a separate repository and package used by more than one collector, so it is not part of a change here; both collectors need re-validating after. Same scoping applies to ope-f173 (Kerberos in the LDAP ladder), which is also a shared-library change, and to ope-7da1, which belongs to the MSSQL collector's branch.
