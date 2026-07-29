---
id: ope-4c6f
status: closed
deps: []
links: []
created: 2026-06-29T16:59:40Z
type: task
priority: 2
tags: [sccm, collect, summary, tech-debt]
---

# Collect summary: replace directory scan with true per-run dlt metric

The collect summary in main.py::_log_collect_summary counts rows by scanning every table folder under <output>/sccm/ (iterdir). It therefore double-counts STALE/ORPHAN folders left by renamed/removed resources from older code (observed: computers=5, users=1, sccm_sites=2 -- the pre-rename RemoteRegistry tables, now remoteregistry_computers/users/sites). Verified inert for preprocess/convert (allow-list + per-entry resource_files reader), so this is a cosmetic reporting bug only.

Fix: replace the disk scan with a TRUE per-run metric from dlt. Read pipeline.last_trace.last_normalize_info.row_counts after each of the two pipeline.run passes (Stage 1 discovery via LoadInfo.pipeline; Stage 2 per-host via the pipeline object _run_per_host_stage holds), strip _dlt* tables, merge. WARN when an expected stage produced no counts (partial run). Additionally WARN about orphan folders on disk not in _preproc_table_map() keys.

Plan: sccm/sccm/docs/superpowers/plans/2026-06-29-collect-summary-per-run-metric.md (3 TDD tasks). Stale lab folders moved (reversible) to C:/tmp/redo_stale_backup_20260629/.
