---
id: ope-c660
status: closed
deps: [ope-0112]
links: []
created: 2026-06-03T19:29:27Z
type: task
priority: 2
---

# Implement WMI per-host collector -type task -priority 2 -description Port Invoke-SmsProviderWmiCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), adding WMI as a per-host phase (currently disabled in PS1 active config) with its table/model(s).

## Notes

**2026-07-15T19:04:33Z**

Closed as duplicate (2026-07-15): superseded by ope-3f2a (SMS Provider WMI fallback). The WMI per-host phase exists as privileged.collect_wmi, gated as an AdminService fallback via should_run_phase, and was folded into privileged.py by ope-38ad.
