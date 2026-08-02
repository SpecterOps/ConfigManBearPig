---
id: con-ab59
status: closed
deps: []
links: []
created: 2026-08-02T01:49:48Z
type: bug
priority: 2
tags: [sccm, registry, mssql, epa]
---

# get_mssql_settings cannot see named SQL instances -- every probed registry path is default-instance only

get_mssql_settings in collectors/registry.py probes eight hard-coded SuperSocketNetLib paths, and EVERY ONE names the default instance: MSSQL16.MSSQLSERVER, MSSQL15.MSSQLSERVER, ... MSSQL.1, plus the legacy SOFTWARE\Microsoft\MSSQLServer path. A named instance lives at MSSQL<ver>.<InstanceName>, so none of them can ever match one.

Proven on the FULLY PRIVILEGED lab run (out/priv8, 14:17): ps1-sec runs the SEC site database as a named instance -- SCCM's own site definition reports SQLDatabaseName 'CONFIGMGRSEC\CM_SEC', SQLServerName ps1-sec.mayyhem.com, SQLServicePort 1433. The registry probe tried all eight default-instance paths, logged 'not found' for each, and warned 'Could not access any MSSQL registry paths on ps1-sec.mayyhem.com'. That warning is a TRUE POSITIVE that reads like noise: it sits among six identical warnings from hosts that genuinely have no SQL at all (cas-pss, ps1-dp, ps1-mp, ps1-pss, ps1-psv, ps1-sms), which is why it went unnoticed.

Consequences, all limited to the registry arm: force_encryption, extended_protection, port, instance_names, service_start_type and service_account_name are never read for a named instance, and the function returns before it ever reads 'Instance Names\SQL' -- so it cannot even discover that an instance exists. Note _mssql_service_name already handles the MSSQL$<name> service naming correctly; that code is simply unreachable for a named instance because the early return fires first.

Severity is moderate, not urgent, because the separate MSSQL phase compensates for a REACHABLE instance: the same privileged run shows '[ps1-sec][MSSQL] MSSQL port 1433 is open' and 'EPA testing ps1-sec.mayyhem.com via current-user SSPI'. The gap bites where that probe cannot reach -- a firewalled or non-listening named instance gets no EPA at all -- and for service_start_type / service_account_name, which the live probe does not provide (service account has its own WMI Win32_Service and sys.dm_server_services fallbacks).

Two candidate fixes, cheapest first: (1) read 'SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' FIRST and build the candidate SuperSocketNetLib paths from the instance names it returns, instead of the hard-coded default-instance list -- this fixes the gap rather than reporting it, and the key is readable at the same privilege as the paths it replaces. (2) At minimum, gate the 'Could not access any MSSQL registry paths' warning on that same key: no instances listed means no SQL Server on the host, which is the normal case and deserves verbose, while instances listed with no matching path is the real blind spot and deserves the warning. Option 2 alone would silence six of the seven privileged-run warnings and make the seventh say something true.

## Acceptance Criteria

The registry arm reads EPA/port/service state for a named instance (verified against ps1-sec's CONFIGMGRSEC instance in the mayyhem lab, privileged run). A host with no SQL Server at all no longer emits a warning. Graph impact on MSSQL_Server properties and any EPA-dependent edge is reviewed before merge, since this changes collected data and not just logging.

## Notes

**2026-08-02T02:10:43Z**

Both halves implemented (unverified against the lab -- a privileged run is needed, since the SQL registry keys are admin-gated and this change is invisible at low privilege).

Fix: _mssql_instances() reads SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL and derives each instance's SuperSocketNetLib path from the value DATA, which is the instance's own subkey (MSSQL16.CONFIGMGRSEC). Exact path, no version prefix guessed, no default-instance assumption. The eight hard-coded paths are gone; the single pre-2000 fallback SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib remains for SQL 7.0/2000, which predate the inventory key. The duplicate second read of Instance Names\SQL further down get_mssql_settings is removed -- one read now serves both the candidate paths and the reported instance_names.

Warning triage: denied -> verbose (per-host denial summary covers it); inventory lists instances but no settings key readable -> WARNING naming the instances (the real gap); no inventory and no legacy key -> verbose, because that is a host without SQL Server and was seven of nine lab hosts on a fully privileged run.

TEST FIXTURE WAS COMPLICIT: _mssql_probe seeded the inventory as [(instance, instance)] -- the instance NAME where the registry stores the SUBKEY -- so test_mssql_named_instance_uses_the_dollar_service_name passed against code that could never reach a named instance. Fixture corrected to [(instance, f'MSSQL16.{instance}')]. Eight tests added covering named instance, default instance unchanged, arbitrary version prefix used verbatim, silent no-SQL host, the contradiction warning, no double-warning when denied, legacy fallback, and an inventory value with no subkey.

Suite 1025 passed / 5 skipped; ruff and mypy clean. Also fixed three SyntaxWarnings for invalid \s escapes in tests/registry_collect_test.py (two pre-existing, one mine).

**2026-08-02T02:22:24Z**

VERIFIED on a PRIVILEGED run against mayyhem.com (integrated auth as the current domainadmin), out/priv9, collect_full_20260801_221516.log.

Hosts with a readable MSSQL settings key: 2 -> 3.
  BEFORE (out/priv8, 14:17): cas-db, ps1-db -- both default instances.
  AFTER: cas-db and ps1-db unchanged at MSSQL16.MSSQLSERVER, PLUS
         ps1-sec at SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.CONFIGMGRSEC\MSSQLServer\SuperSocketNetLib.

Note MSSQL13, i.e. SQL 2016. Even a hypothetical hard-coded list extended with named instances would have had to guess that version prefix; deriving the path from the inventory's value data gets it exactly right with no guessing.

Newly collected for ps1-sec: ForceEncryption=No, ExtendedProtection=Off, TCP port 1433, instanceNames ['CONFIGMGRSEC'], and service MSSQL$CONFIGMGRSEC startup=Automatic account=LocalSystem -- the last of these proving _mssql_service_name's named-instance branch, previously unreachable behind the early return, now runs.

Graph impact (openhound-compare out/priv8/graph out/priv9/graph, exit 0): 0 REGRESSIONS. Entirely confined to the ps1-sec MSSQL_Server node S-1-5-21-3242052782-1287495003-4091326449-1113:1433 --
  + SQLServiceStartType = Automatic (added)
  ~ instanceNames [] -> ['CONFIGMGRSEC']
  ~ collectionSource gained 'RemoteRegistry-MSSQL'
No new nodes, no new edges, no lost properties. forceEncryption/extendedProtection did not change because the live MSSQL-ScanForEPA arm already supplied them -- the registry arm now corroborates rather than contradicts, which is the expected result and a useful cross-check. SQLServiceAccountName was likewise already 'LocalSystem' from another arm.

CAVEAT ON THE COMPARISON: the same report shows 71 name + 71 displayname changes that are NOT from this work. They come from commit 290bfcd 'Fix AD name prop, cypher queries' (transforms.py, models/*.py, graph.py), which landed after the priv8 baseline was collected at 14:17. The remaining 150 changed values are last_seen timestamps and 10 lastActiveTime, i.e. eight hours of live-lab drift. This change's own footprint is the three ps1-sec properties above and nothing else.

Warnings on the privileged run: 25 -> 20, zero errors. The seven 'Could not access any MSSQL registry paths' warnings are gone: six were hosts with no SQL (now verbose) and the seventh was ps1-sec, which now succeeds. No registry warnings remain at all.
