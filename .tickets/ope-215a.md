---
id: ope-215a
status: closed
deps: []
links: []
created: 2026-06-02T20:49:02Z
type: task
priority: 2
---

# Return single fsp_hostname from _parse_mp_capabilities -type chore -priority 2 -tags sccm,ldap,fsp -assignee cthompson -description Change _parse_mp_capabilities to return a single fsp_hostname (str|None) instead of fsp_hostnames (list). Only-if-one semantics: warn and take first if multiple FSPServer nodes. Update full chain: caller registration loop, yielded row column, transforms UNNEST->scalar, and both affected test files.

## Notes

**2026-06-02T20:51:15Z**

Implemented: _parse_mp_capabilities now returns scalar fsp_hostname (None default), warns and takes first when multiple FSPServer nodes. Updated caller registration, yielded column, transforms scalar select, and both test files. 15/15 affected tests pass.
