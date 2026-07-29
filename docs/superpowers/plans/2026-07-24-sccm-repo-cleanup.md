# SCCM Repo Cleanup — Reorganize `tools/`, Standardize Tests, Prune Dead Files — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tidy the `sccm/` tree without changing any collector behavior: move loose dev/lab scripts into `sccm/sccm/tools/`, standardize test filenames on the `*_test.py` majority convention (and pin it), delete a small set of *provably-dead* files, and consolidate the live-comparison report snapshots to one canonical report. Everything removed stays recoverable from git history.

**Architecture:** This is a housekeeping change, not a code change. No node/edge/graph-schema changes, no collector-logic changes. The only source edit is a 3-line `pyproject.toml` addition (pin the pytest file glob); the only "logic-adjacent" work is merging three colliding test files. Package root: `sccm/sccm/src/openhound_sccm/`. Tests: `sccm/sccm/tests/`.

**Tech Stack:** Python 3.13+, pytest, git. No runtime deps touched.

## Decisions locked (from grilling, 2026-07-24)
| Fork | Decision |
|---|---|
| Scope | Reorganize + remove **provably-dead** only; **flag** maybe-stale items for manual verification; recommend `.gitignore` additions. |
| Loose scripts | Move **all** into `sccm/sccm/tools/` (stale-looking ones move too, then get flagged). |
| Test naming | Rename `test_*.py` → `*_test.py`; pin `python_files = *_test.py`. |
| Test layout | Keep **flat** (no `unit/` vs `integration/` split). |
| Docs | Leave `docs/` structure as-is; only flag orphans. |
| Comparison reports | Consolidate to one canonical `report.md`; flag intermediate snapshots. |

## Global Constraints (apply to EVERY task)
- **NO COMMITS.** Per CLAUDE.md, do not `git add`/`git commit`. Each task ends at a **green checkpoint**; Meatbag commits.
- **Use `git mv`** for every move/rename so history is preserved.
- **Behavior must not change.** This is pure housekeeping — no collector, graph, or CLI behavior may change. The only source edit is the `pyproject.toml` pytest pin.
- **Targeted tests only** (per the "targeted tests, not full suite" preference): from `sccm/sccm/`, run specific files with the extension venv, e.g. `.venv/Scripts/python -m pytest ../tests/<file>.py -q`. Use `--collect-only` for the before/after count check.
- **Update docs in the same change as the move** (AGENTS.md rule for `ARCHITECTURE.md`), and fix any `file:line` links a move invalidates.

## File Structure
| Path | Change |
|---|---|
| `sccm/sccm/tools/` | **New dir.** Destination for the 10 loose dev/lab scripts. No `__init__.py` (run directly, not imported). |
| `sccm/sccm/debug_*.py`, `spike_*`, `tour_driver_stage*.py` | **Move** → `tools/`. |
| `sccm/sccm/ARCHITECTURE.md` | Repath live script links (lines 294, 295, 298, 418, 691, 1367). Leave the line-1425 changelog prose as a dated record. |
| `sccm/sccm/README.md` | Update "Debug harnesses (lab use only)" bullets (lines 1483–1485) to `tools/…` paths. |
| `sccm/sccm/tests/test_*.py` | **Rename** 28 files → `*_test.py`; merge 3 colliding pairs; rename `__init___test.py`. |
| `sccm/sccm/pyproject.toml` | Add `[tool.pytest.ini_options]` with `python_files = "*_test.py"` (LAST, after all renames). |
| `sccm/sccm/extension.yaml` | **Delete** (never read by OpenHound). |
| `sccm/sccm/src/main.py` | **Delete** (dead cookiecutter shim). |
| `sccm/bloodhound-sccm-openhound-20260715_104718.zip` | **Delete** (tracked output artifact). |
| `sccm/tests/live-comparison/report*.md` | Consolidate: `report_FINAL.md` → `report.md`; delete 7 intermediate snapshots. |
| repo-root `.gitignore` (or new `sccm/.gitignore`) | Add `bloodhound-sccm-*.zip` pattern. |

## ⚠ Manual-only ripple (cannot be committed — `.vscode/` is gitignored)
`.vscode/launch.json` (repo root) pins 5 debug profiles to script paths at lines **90, 100, 110, 120, 130**:
`${workspaceFolder}/sccm/sccm/debug_per_host.py`, `tour_driver_stage0.py`, `tour_driver_stage1.py`, `tour_driver_stage2.py`, `tour_driver_stage3.py`. After Task 1, add `/tools` to each `program` path or the debug launchers break. **Meatbag must do this by hand.**

---

### Task 1: Move loose dev/lab scripts into `sccm/sccm/tools/`

**Files (10, all `git mv` into `tools/`):**
`debug_epa_matrix.py`, `debug_per_host.py`, `debug_smb_auth.py`, `debug_wmi_auth.py`, `spike_smb_sso.py`, `spike_socks_proxy.md`, `tour_driver_stage0.py`, `tour_driver_stage1.py`, `tour_driver_stage2.py`, `tour_driver_stage3.py`.

**Steps:**
- [ ] Create `sccm/sccm/tools/` (no `__init__.py`).
- [ ] `git mv` all 10 files in.
- [ ] `ARCHITECTURE.md`: prefix `tools/` on the live links — line 294 `[debug_per_host.py](debug_per_host.py)`, 295 (`debug_epa_matrix.py`, `spike_smb_sso.py`), 298 `[debug_per_host.py:74](debug_per_host.py#L74)`, 418, 691 `tour_driver_stage1.py`, 1367 `spike_socks_proxy.md`. Leave line 1425 (changelog) unchanged.
- [ ] `README.md`: update the three bullets at 1483–1485 to `tools/debug_epa_matrix.py`, `tools/debug_per_host.py`, `tools/spike_smb_sso.py`.
- [ ] **Flag to Meatbag:** update `.vscode/launch.json` paths (manual — see ripple note above).

**Verify:** scripts import cleanly from the new location (imports resolve via the editable-installed package, not CWD; `tour_driver_stage1.py` already uses `tempfile.mkdtemp()` so no path breakage). Spot-run one tour driver if convenient. `grep -rnE '\((debug_|spike_|tour_driver_)' ARCHITECTURE.md README.md` returns no un-prefixed link.

---

### Task 2: Rename the 28 non-colliding `test_*.py` files

**Steps:**
- [ ] `git mv` each (strip `test_` prefix, append `_test`):

  `test_ad_auth_warnings` · `test_ad_pth_ptt` · `test_allowed_targets` · `test_cli_argument_warnings` · `test_debug_exc_info_filter` · `test_dns_resolver_flag` · `test_extension_methods` · `test_http` · `test_http_auth` · `test_http_cli_flags` · `test_http_client` · `test_http_negotiate_integration` · `test_ldap_management_points_raw` · `test_ldap_smc_recursion` · `test_mssql_epa` · `test_per_host_integration` · `test_per_host_log_blocks` · `test_per_host_wiring` · `test_pp_engine` · `test_pp_streams` · `test_pp_work_queue` · `test_principal_resolution_referral` · `test_progress_option` · `test_smb` · `test_smb_sso` · `test_smb_sso_integration` · `test_sms_rows` · `test_wmi_client`

  → each becomes `<name>_test.py` (e.g. `test_http.py` → `http_test.py`).
- [ ] Rename the smoke test `__init___test.py` → `models_main_import_test.py`.
- [ ] (When it's committed) rename the untracked `test_verbose_silent_flags.py` → `verbose_silent_flags_test.py`.

**Verify:** `pytest --collect-only -q` count unchanged vs. baseline; no import errors.

---

### Task 3: Resolve the 3 rename collisions (needs Meatbag sign-off per pair)

Each `test_*.py` below would land on an **existing, different** `*_test.py`. All three are distinct tests — do **not** overwrite. Recommended fix: **merge** the incoming test body into the existing canonical file, then delete the `test_*.py`.

- [ ] **`test_per_host_phases.py` → `per_host_phases_test.py`** — ⚠ the existing file is a *hybrid*: it's collected as a test **and** imported as a fixture module (`from tests.per_host_phases_test import PER_HOST_PHASES, all_table_names`). Merge the two test bodies, and move the shared `PER_HOST_PHASES` / `all_table_names` symbols into a non-test helper (or `conftest.py`) so a `*_test.py` file is no longer imported by another test (the pinned convention in Task 4 makes that fragile).
- [ ] **`test_privileged.py` → `privileged_test.py`** — merge the two bodies (existing = shared-helper angle with stub `_Run`; incoming = ten collection helpers parameterized + orchestrator).
- [ ] **`test_registry_current_user.py` → `registry_current_user_test.py`** — merge (existing = `get_current_user` host-SID row; incoming = CurrentUser SID selection + Multisite role logic).

**Verify (per pair):** show the diff to Meatbag before touching; after merge, run the merged file plus `per_host_phases_test.py` importers green.

---

### Task 4: Pin the test-file convention (do this LAST)

- [ ] Add to `sccm/sccm/pyproject.toml`:
  ```toml
  [tool.pytest.ini_options]
  python_files = "*_test.py"
  ```
- [ ] **Ordering trap:** this must land only after Tasks 2–3 are complete. Pinning to `*_test.py` only means any leftover `test_*.py` **silently stops being collected** (no error). Confirm zero `test_*.py` remain first: `git ls-files 'sccm/sccm/tests/test_*.py'` returns nothing.

**Verify:** `pytest --collect-only -q` count still matches baseline (minus the 3 files merged in Task 3).

---

### Task 5: Remove provably-dead files

- [ ] `git rm sccm/sccm/extension.yaml` — never read. OpenHound loads metadata via `resources.files("openhound_sccm")/extension.yaml` (see `openhound/core/manager.py:114-116`), so only `src/openhound_sccm/extension.yaml` is authoritative; the top-level copy is unreachable (both are still cookiecutter boilerplate).
- [ ] `git rm sccm/sccm/src/main.py` — 4-line shim importing `openhound.main:app` (core CLI, not the `openhound_sccm.main:app` entry point declared in `pyproject.toml`); referenced nowhere. Leave `src/__init__.py`.
- [ ] `git rm sccm/bloodhound-sccm-openhound-20260715_104718.zip` — 18 KB `Package-OpenHoundZip.ps1` output artifact tracked in git, referenced nowhere.

**Verify:** `pytest --collect-only` still green; `openhound` still discovers the `sccm` extension (metadata resolves from `src/openhound_sccm/extension.yaml`).

---

### Task 6: Consolidate the live-comparison reports

- [ ] Replace `sccm/tests/live-comparison/report.md` contents with `report_FINAL.md` (the Jul-15 final; the dir's `.gitignore` already names `report.md` as canonical), then `git rm report_FINAL.md`.
- [ ] **Keep:** `SUMMARY.md`, `GAP_ANALYSIS.md`, `report_possible_edges_on.md` (SUMMARY.md lines 17–18 cite it for "Finding 2").
- [ ] `git rm` the 7 intermediate snapshots: `report_asis.md`, `report_after_ac.md`, `report_after_d.md`, `report_after_mssql_fix.md`, `report_after_sam_fix.md`, `report_fresh_collect.md`, `_blast3.md`.
- [ ] Reword `SUMMARY.md` line 55 ("see `report_after_*.md` / `report_FINAL.md`") so it doesn't point at deleted files.

**Verify:** `grep -rnE 'report_FINAL|report_after|report_asis|report_fresh|_blast3' sccm/tests/live-comparison/*.md` returns no dangling references.

---

### Task 7: `.gitignore` recommendation

- [ ] Add a collector-output-zip ignore so `Package-OpenHoundZip.ps1` output can't be re-committed like the deleted zip. Pattern: `bloodhound-sccm-*.zip`. Target the repo-root `.gitignore` (there is no outer `sccm/.gitignore` today — only `sccm/sccm/.gitignore` and `sccm/tests/live-comparison/.gitignore`); confirm the right file at implementation time so `tests/live-comparison/results/*.zip` (already ignored) isn't double-covered.

---

## FLAGGED for manual verification (no auto-action in this plan)
These are surfaced for Meatbag to decide, not deleted by the plan:
- **Possibly-stale scripts** (moved to `tools/` in Task 1, but referenced by no live doc): `debug_smb_auth.py`, `debug_wmi_auth.py`, `tour_driver_stage0.py`, `tour_driver_stage2.py`, `tour_driver_stage3.py`. Only `tour_driver_stage1`, `debug_per_host`, `debug_epa_matrix`, and `spike_smb_sso` are doc-cited. Verify you still use the others' debug profiles before pruning.
- **`docs/proposals/`** (`2026-06-16-computer-node-multi-driver-merge.md`, `2026-06-16-convert-read-from-duckdb.md`) — likely already implemented; verify, then prune.
- **`docs/javascript/` + `docs/stylesheets/`** — doc-site theme assets (`custom.mjs`, `mermaid.mjs`, `mermaid-custom.css`) with **no committed `mkdocs`/`zensical` site config** and zero references. Verify no external build needs them, else delete.

## Explicitly OUT of scope (current-branch work, NOT cruft)
Do not sweep these up — they are active work that should be committed/organized:
- `sccm/cypher_queries/` (18 saved BloodHound queries, untracked)
- `sccm/schema.json` (untracked)
- `sccm/tests/test_verbose_silent_flags.py` (untracked; rename per Task 2 convention when committed)

## Execution order & final validation
1. Task 1 (move + doc fixes) → smoke-check imports.
2. Task 2 (28 renames) → Task 3 (3 merges, with sign-off) → **then** Task 4 (pin glob).
3. Task 5 (dead files) + Task 6 (reports) + Task 7 (gitignore).
4. **Baseline first:** capture `pytest --collect-only -q` count before any change; after Tasks 2–4 it must match (minus the 3 merged files). Run the offline test subset to confirm green.
