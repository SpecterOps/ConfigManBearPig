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
