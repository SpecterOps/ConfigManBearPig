---
id: con-3be4
status: closed
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

## Notes

**2026-07-31T15:35:17Z**

Status audit 2026-07-31: EVERY ACCEPTANCE CRITERION VERIFIED -> closing. Checked mechanically against the working tree: (1) no dangling relative link in either file -- 59 unique link targets resolved in README.md, 31 in ARCHITECTURE.md, 0 missing; (2) README-CMBP.md references gone (0 hits in both files) and no root-level extension.yaml reference remains; (3) counts are code-true and consistent -- README says 15 node kinds and 38 edge kinds at every occurrence (lines 406, 744, 798, 915, 1404, 2200), matching kinds/nodes.py (15 emitted primaries + the Base secondary label) and the 38 constants in kinds/edges.py; (4) file tree now lists convert_pipeline.py, edge_help.py, opengraph_untagged.py, cve_table.py and integration/; (5) debug-harness list matches dev/ -- the four debug_*.py and spike_smb_sso.py named individually and tour_driver_stage0.py..stage3.py as a range (README:2005-2010); spike_socks_proxy.md is a runbook, not a script, so its absence from that list is correct; (6) Node and Edge Reference subsections are alphabetized A-Z within the AD / SCCM_ / MSSQL_ groups; (7) ARCHITECTURE changelog is monotonically non-increasing across all 28 dated rows; (8) the '# Testing Changes' section is preserved at README:2018.
