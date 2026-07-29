---
id: ope-676f
status: closed
deps: [ope-0112]
links: []
created: 2026-06-03T19:29:31Z
type: task
priority: 2
---

# Implement SMB per-host collector -type task -priority 2 -description Port Invoke-SMBCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the SMB stub with the real collector and its table/model(s).

## Notes

**2026-07-15T19:04:33Z**

Closed as duplicate (2026-07-15): superseded by ope-4483 (SMB Collection), which implemented collectors/smb.py + clients/smb.py, wired the SMB per-host phase in per_host_phases.py, and added tests/test_smb.py (live-validated across 4 auth methods).
