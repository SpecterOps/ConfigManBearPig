---
id: con-8a33
status: closed
deps: []
links: []
created: 2026-07-31T16:53:57Z
type: bug
priority: 3
tags: [sccm, auth, kerberos, ux, robustness]
---

# Guard --ticket base64/KRB-CRED decoding in smb_sso.py and wmi.py

clients/smb_sso.py:206 and clients/wmi.py:127 both call base64.b64decode(kerberos_ticket, validate=True) followed by CCache().fromKRBCRED(...) with no guard. A malformed --ticket value (not base64, or base64 that is not a KRB-CRED) raises binascii.Error or an impacket parse error and surfaces as a raw traceback instead of a clear message naming the offending flag. Both functions already raise ValueError('--ticket contains no usable credentials') for the empty-credentials case, so the clean-error pattern exists -- these two decode steps just skip it. This is user input, not remote input, so it is a UX defect rather than a robustness one, but it is the same shape as con-0170.

## Acceptance Criteria

A malformed --ticket (non-base64, and valid base64 that is not a KRB-CRED) produces a ValueError naming --ticket and the reason, from both the SMB SSO and WMI paths; regression tests cover both inputs on both paths.

## Notes

**2026-07-31T17:12:19Z**

Fixed via TDD. Four tests written first and all four watched fail (assertion failures on the non-base64 inputs because binascii.Error subclasses ValueError but its message says 'Only base64 data is allowed' and never names the flag; raw pyasn1.error.EndOfStreamError on the non-KRB-CRED inputs). Each decode step now has its own guard in both smb_sso._load_ticket and WmiClient._load_ticket: bad base64 -> '--ticket is not valid base64: ...', non-KRB-CRED -> '--ticket is not a valid KRB-CRED (.kirbi): ...'. The existing empty-credentials ValueError is unchanged. No logging added -- the raised message is the report, and logging it too would double-report. Verified: 903 passed / 5 skipped / 0 failed; ruff and mypy clean.
FOLLOW-UP: smb_sso._load_ticket and WmiClient._load_ticket are now near-identical (their docstrings already say 'Mirrors clients/wmi.py'). Decoding a base64 KRB-CRED into (username, TGT, TGS) is generic pass-the-ticket plumbing with nothing SCCM-specific in it -- a candidate for openhound-collector-common, which is a separate repo and so out of scope here.
