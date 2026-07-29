---
id: ope-c0c0
status: closed
deps: []
links: [ope-fb99]
created: 2026-07-24T14:14:33Z
type: bug
priority: 2
tags: [sccm, clientdevice, preproc]
---

# SCCM_ClientDevice lastOnlineTime/lastOfflineTime always empty (c_n_ vs cn_ raw column typo)

SCCM_ClientDevice lastOnlineTime/lastOfflineTime were always empty. transforms._node_client_device read the raw columns c_n_last_online_time / c_n_last_offline_time, but the collector (sms_rows._snake) and dlt both snake-case CNLastOnlineTime/CNLastOfflineTime with 'CN' as a single token -> the real raw columns are cn_last_online_time / cn_last_offline_time. _ensure_columns silently created the non-existent c_n_* columns as NULL stubs, masking the typo, so both output properties were always empty. FIX APPLIED (this session, awaiting user test/commit): corrected the raw source names to cn_* in the _optional dict + the SELECT arm, updated the comment, and added regression test tests/client_device_extras_test.py::test_client_device_cn_online_offline_times_populate (proven red before fix, green after). Discovered during Task B3 (ope-fb99).

## Notes

**2026-07-24T18:03:00Z**

FIXED + pushed (integration). Corrected c_n_→cn_ raw column names in _node_client_device so SCCM_ClientDevice lastOnlineTime/lastOfflineTime populate (were always empty). Regression test proven red→green; live re-validation shows 14/13 of 20 populated. Full suite 716 pass.
