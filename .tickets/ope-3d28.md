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

**2026-07-31T15:37:31Z**

Status audit 2026-07-31: STATUS IS CORRECT (closed) but the 2026-07-15 note contradicted it -- reconciling. That note says 'Kept OPEN for pending cleanup' while the ticket has been closed since; the ticket's actual scope, 'replace the MSSQL stub with the real collector and its table/model(s)', is met and then some: collect_mssql (collectors/mssql.py) is wired into per_host_phases.py, emits mssql_server_instances, and has since been extended under ope-0947 to record has_mssql_spn / port_open so an SPN-only SQL host with 1433 filtered still reaches the graph. Re-checked both residual cleanup items today: item 2 (docstring over-advertising) is now HALF fixed -- the collect_mssql function docstring is accurate and precise about what it does, but the MODULE docstring at collectors/mssql.py:1-7 still lists 'sysadmin login detection' and 'Service account detection', which derive in the convert stage, not this collector. Item 1 is UNFIXED -- there is still no direct collect_mssql unit test; grep for collect_mssql across tests/ returns nothing, and the 17 mssql-named test files all cover the preproc/convert transforms or the mssql_epa client adapter instead. Both are small and cosmetic; leaving this closed and recording them here rather than reopening a delivered port. If they matter, open a one-line chore.
