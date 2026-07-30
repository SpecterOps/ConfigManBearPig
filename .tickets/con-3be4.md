---
id: con-3be4
status: in_progress
deps: []
links: []
created: 2026-07-30T17:12:19Z
type: task
priority: 2
tags: [docs, readme, architecture]
---

# Refresh README.md and ARCHITECTURE.md against current code

Both documents have drifted from the code. Bring them back into agreement, alphabetize the Node/Edge reference lists within each namespace group, expand every shorthand plan/stage/task reference so it names its source plan, and sort the ARCHITECTURE changelog by date. Documentation-only: no code, no behavior change.

Executes `docs/superpowers/plans/2026-07-30-docs-update-readme-architecture.md`.

Known drift going in: the deleted `README-CMBP.md` is still linked twice; `extension.yaml` is linked at the repo root but lives in `src/openhound_sccm/`; the Collection Overview diagram still says edges are planned and names only two of the six per-host phases; the Stage-2 phase table and the intro banner still describe AdminService/WMI/HTTP/SMB as collect-only, which stopped being true when the preproc/convert Stage 3-6 work shipped; the file tree omits `convert_pipeline.py`, `edge_help.py`, `opengraph_untagged.py`, `cve_table.py` and `integration/`; the debug-harness list predates the move into `dev/` and misses four scripts; the `User` table omits `samAccountName`; the `Group` table and the Limitations bullet contradict each other.

## Acceptance Criteria

No dangling relative link or in-page anchor in either file; `README-CMBP.md` and root-level `extension.yaml` references gone; file tree and debug-harness list match the filesystem; Node/Edge reference sections and their TOC entries alphabetized A-Z within the AD / `SCCM_` / `MSSQL_` groups; counts read 15 node kinds and 38 edge kinds throughout; every first-use of a Stage/D/Task/Phase token names its source plan; ARCHITECTURE changelog dates monotonically non-increasing; the uncommitted `# Testing Changes` section preserved verbatim.
