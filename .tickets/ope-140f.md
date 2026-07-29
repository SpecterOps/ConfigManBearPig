---
id: ope-140f
status: closed
deps: []
links: []
created: 2026-07-16T18:24:46Z
type: task
priority: 2
---

# Collect summary prints real next-step commands instead of placeholders

The end-of-collect 'Next steps' INFO log hard-coded <raw>/<lookup.duckdb>/<graph> placeholders. Now derives every next-stage path from OUTPUT_PATH (lookup.duckdb, sccm dataset dir, and graph all under it) and prints copy-pasteable preprocess/convert commands. Paths with spaces are double-quoted. main.py: new _cli_path_arg helper + rewritten hint in _log_collect_summary. Tests added in tests/collect_summary_test.py.
