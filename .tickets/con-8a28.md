---
id: con-8a28
status: closed
deps: []
links: []
created: 2026-08-01T23:57:23Z
type: task
priority: 2
tags: [sccm, logging, registry, wmi, run-all]
---

# Silence expected access-denied noise on non-admin runs; show the zip path in the --run-all summary

A non-admin run drowns the console in expected access-denied noise, and the --run-all summary never shows the upload-ready zip.

125 of 125 ERRORs in the 2026-08-01 19:37 low-priv run are RemoteRegistry rpc_s_access_denied (0x5); the same run privileged (out/priv8) has zero. 120 are per-read failures from _RegistryProbe's read helpers, 5 are a redundant 'Error querying SOFTWARE\Microsoft\SMS\CurrentUser' that duplicates a denial logged one line earlier. Separately, impacket's own logger emits CRITICAL 'CCache file is not found. Skipping...' once per host (9x) when the WMI kerberos rung runs without --ticket: impacket checks KRB5CCNAME, finds nothing on Windows, and then succeeds via the supplied password anyway.

Third, on ps1-mp/ps1-sms/ps1-dp/ps1-db/cas-db the SMS\Triggers read is DENIED, but the read helpers cannot tell denied from absent, so collect_registry logs 'does not exist or no site code subkey found' -- telling the operator the host is not a site server when the truth is a permissions gap.

Fourth, _log_all_output_locations ends with the graph/*.json list and never prints graph/configmanbearpig_collection_<ts>.zip, the one artifact an operator uploads to BloodHound. run_end_to_end discards zip_graph_output's return value and StagePaths has no zip field.

## Acceptance Criteria

A low-priv collect against mayyhem.com reports 0 ERRORs (down from 125) and no CRITICAL lines. Each denied registry read logs at VERBOSE to collect_full_<ts>.log; each affected host emits exactly one WARNING naming the capabilities lost and that local Administrators is required. A denied SMS\Triggers read reports as access-denied, not as a missing key. impacket's CCache CRITICAL is demoted to DEBUG and wmi.py logs its own VERBOSE explanation on the kerberos rung. The --run-all summary block closes with the .zip path. Tests in /tests cover all five behaviours and the existing suite stays green.

## Notes

**2026-08-02T00:36:49Z**

VERIFIED against mayyhem.com as MAYYHEM\lowpriv, --run-all, output in out/unpriv9 (collect_full_20260801_202924.log).

Baseline out/collect_issues_20260801_193720.log: 31 WARNINGs, 125 ERRORs, 9 CRITICALs.
After: 36 WARNINGs, 0 ERRORs, 0 CRITICALs. Zero ERROR lines anywhere in the full DEBUG log.

Warning arithmetic reconciles exactly: 31 + 9 per-host denial summaries + 5 denied-Triggers site-code warnings - 9 removed 'Could not access any MSSQL registry paths' dumps = 36.

Detail preserved, not discarded: 111 'Access denied reading' lines at VERBOSE in collect_full (the same 111 reads that were ERRORs before), and impacket's 9 CRITICALs now appear as 9 DEBUGs. wmi.py's replacement explanation logged 12 times (one per kerberos-rung construction, slightly more than impacket's 9 ccache lookups).

The 5 denied-Triggers hosts are exactly the predicted set: ps1-mp, ps1-sms, ps1-dp, ps1-db, cas-db. Each now says 'Access denied reading ... site code is unknown' instead of 'does not exist or no site code subkey found'.

--run-all summary block ends with 'Upload to BloodHound: out\unpriv9\graph\configmanbearpig_collection_20260801_202924.zip'.

No collection regression: graph totals identical to the baseline run at 57 nodes / 148 edges.

Suite 991 passed / 5 skipped; ruff and mypy clean.
