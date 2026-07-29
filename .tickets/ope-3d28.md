---
id: ope-3d28
status: closed
deps: [ope-0112]
links: []
created: 2026-06-03T19:29:22Z
type: task
priority: 2
---

# Implement MSSQL per-host collector -type task -priority 2 -description Port Invoke-MSSQLCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the MSSQL stub with the real collector and its table/model(s).

## Notes

**2026-07-15T19:03:47Z**

Audit (per-ticket-criteria sweep, 2026-07-15): core deliverable MET — real collect_mssql is wired into per_host_phases.py and emits mssql_server_instances (SPN-driven port, TCP/1433 check, EPA probe). Kept OPEN for pending cleanup: (1) no direct collect_mssql unit test (only the mssql_epa client adapter is unit-tested); (2) module docstring over-advertises sysadmin-login / service-account detection, which actually derive in the convert stage, not this collector.
