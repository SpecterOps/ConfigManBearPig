---
id: con-c522
status: closed
deps: []
links: []
created: 2026-07-31T14:06:46Z
type: task
priority: 1
tags: [security, dependencies]
---

# Clear 14 Dependabot alerts via lock-only dependency bump

Bump uv.lock only (no pyproject.toml range changes) to clear all 14 open Dependabot alerts: GitPython 3.1.50->3.1.57 (9 High), pyasn1 0.6.3->0.6.4 (2 High), cryptography 48.0.0->48.0.1 (1 High), setuptools 82.0.1->83.0.0 (1 Moderate), pymdown-extensions 10.21.3->11.0.1 (1 Moderate, dev-only docs). cryptography pinned to 48.0.1 rather than latest 49.0.0: 49.0.0 drops win32 and macOS x86_64/universal2 wheels and newly raises ValueError on X.509 certs with NULL AlgorithmIdentifier params, which the remote sitesigncert probe in collectors/http.py parses. 48.0.1 is a pure OpenSSL rebuild with no API change.

## Acceptance Criteria

All 14 alerts resolved; full suite passes; ruff and mypy clean; LDAP sign-and-seal, LDAP channel binding, SMB signing and MSSQL EPA verified unaffected against the mayyhem lab.

## Notes

**2026-07-31T14:13:38Z**

Verified against mayyhem.com lab (lowpriv explicit creds, DC enforcing LDAP signing + channel binding).
Lock: cryptography 48.0.0->48.0.1, gitpython 3.1.50->3.1.57, pyasn1 0.6.3->0.6.4, setuptools 82.0.1->83.0.0, pymdown-extensions 10.21.3->11.0.1. Exactly 5 version lines changed; impacket/ldap3/pycryptodomex/pywin32/winkerberos/pyopenssl all held.
Gates: ruff check src tests clean; mypy src/openhound_sccm clean (63 files); pytest 893 passed / 5 skipped / 0 failed / 114 subtests.
Lab A/B: baseline proven deterministic (3 runs, identical sha256 944ce60e). Bumped run fixture hash identical. All 13 LDAP/SMB/EPA evidence lines identical, covering both LDAPS+CBT and LDAP+sign/seal rungs. All 192 graph nodes/edges identical as order-insensitive sets (raw bytes differ only by worker emission order and last_seen timestamps).
14/14 Dependabot alerts cleared.
