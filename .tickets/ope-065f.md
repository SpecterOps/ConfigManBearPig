---
id: ope-065f
status: closed
deps: []
links: []
created: 2026-06-08T20:55:10Z
type: task
priority: 2
assignee: cthompson
parent: ope-c8cc
tags: [sccm, mssql, epa, validation, matrix, impacket]
---

# Port test-epa-matrix as live EPA validation harness (impacket rrp+scmr)

Port MSSQLHound test-epa-matrix (cmd_test_epa_matrix.go + internal/epamatrix/*) as a standalone live-validation harness in sccm/sccm (alongside debug_per_host.py). Full faithful port: auto-detect SQL instance registry path + service name; save originals; iterate all 12 combos (ForceEncryption x ForceStrictEncryption x ExtendedProtection); for each write the 3 SuperSocketNetLib DWORDs + restart SQL service + wait for TCP/1433 + run clients/mssql_epa.test_epa + compare detected vs expected (EP 0/1/2 -> Off/Allowed/Required); restore originals on exit/interrupt; print results table + summary. Transport: impacket rrp (hBaseRegSetValue) for registry writes + scmr (hRControlService/hRStartServiceW) for service restart, reusing registry.py/smb_sso auth incl. current-user SSPI. Validates against ps1-db.mayyhem.com:1433 as MAYYHEM/domainadmin (sysadmin/DA/local admin) to exercise integrated auth.
