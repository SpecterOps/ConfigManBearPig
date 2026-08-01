# ConfigManBearPig Repo Cleanup — Standardize Test Naming, Retire Doc-Site Scaffolding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Repository:** This plan applies to the **standalone `ConfigManBearPig` repository**
(`C:\Users\domainadmin\Desktop\ConfigManBearPig`, PyPI distribution `configmanbearpig`), **not** the
OpenHound monorepo's `sccm/sccm/` copy at `C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm`. Every path
below is relative to this repo's root. Rescoped from the original monorepo-relative plan on 2026-07-30 —
see [Rescoped 2026-07-30](#rescoped-2026-07-30-what-the-repo-split-already-settled).

**Goal:** Standardize every test filename on the `*_test.py` majority convention and pin that convention
in `pyproject.toml`, resolve the three name collisions the renames create **without merging any test
bodies**, retire the never-completed documentation-site scaffolding, then repair the two `ARCHITECTURE.md`
links the renames break and tell contributors in `README.md` that the pin means a `test_*.py` file
silently does not run. No collector behavior changes, and no test body changes at all.

**Architecture (approach):** Housekeeping, and deliberately body-free. Every one of the 35 file moves is a
pure `git mv`; the only content edits in the whole plan are three import lines, one docstring paragraph,
two config files, and three documentation edits. That makes the collected-test count an exact invariant
rather than an approximate one: it must read **901** at every checkpoint, and each individual file's count
must be unchanged too. Package root is `src/openhound_sccm/`; tests are flat in `tests/`. Everything
removed stays recoverable from git history.

**Tech Stack:** Python 3.13+, pytest 9, uv, ruff, mypy, git. No runtime dependency is touched.

---

## Rescoped 2026-07-30: what the repo split already settled

The original plan was written against the monorepo path `sccm/sccm/`. Splitting the collector into its own
repository satisfied or invalidated four of its seven tasks. **Do not redo these** — each was verified
against the working tree on 2026-07-30, with the evidence recorded so a reviewer can re-check.

| Original task | Status | Evidence |
|---|---|---|
| **1** — move 10 loose dev/lab scripts into `tools/` | **Done, under the name `dev/`** | All 10 are tracked in `dev/` (`git ls-files dev`). `ARCHITECTURE.md` lines 297, 298, 301, 705, 1740 and `README.md` lines 1821–1823, 1959, 1965 already say `dev/`. **Decision: keep `dev/`, do not rename to `tools/`.** |
| **2** — rename 28 `test_*.py` | **Still needed, now 30** | `git ls-files 'tests/test_*.py'` returns 33; 3 are the collisions handled in Tasks 2–3. New since 2026-07-24: `test_cli_option_panels.py`; and `test_verbose_silent_flags.py` is now tracked rather than untracked. → **Task 1** |
| **3** — resolve 3 rename collisions | **Still needed; both halves changed shape** | Same 3 pairs, but neither original recommendation survived contact with the code. `tests/per_host_phases_test.py` contains **zero tests** — it is a shared-data module, resolved by renaming, not merging (**Task 2**). The other two are **not** drift to be merged away but topically distinct tests that this repo's conventions say should stay separate (**Task 3**). |
| **4** — pin `python_files = "*_test.py"` | **Still needed** | No `[tool.pytest.ini_options]` exists anywhere: no `pytest.ini`, no `setup.cfg`, no `tox.ini`, and `grep pytest pyproject.toml` matches only the `pytest>=9.0.1` dev dependency. → **Task 4** |
| **5** — delete `extension.yaml`, `src/main.py`, the tracked zip | **Done — all three already absent** | `find . -name extension.yaml` returns only `src/openhound_sccm/extension.yaml`, which is the authoritative copy OpenHound loads via `resources.files("openhound_sccm")`. `src/` contains only `openhound_sccm/`. `git ls-files '*.zip'` returns only the five deliberate `powershell_deprecated/sample_data/` fixtures, none of them the `bloodhound-sccm-openhound-*.zip` build artifact. |
| **6** — consolidate live-comparison reports | **Left this repository** | Those files are at `C:\Users\domainadmin\Desktop\OpenHound\sccm\tests\live-comparison\`. This repo has no `tests/live-comparison/` at all. If the consolidation still matters it belongs to a monorepo plan, not this one. |
| **7** — add `bloodhound-sccm-*.zip` to `.gitignore` | **Obsolete** | The rationale was `Package-OpenHoundZip.ps1` output. No such script exists in this repo; `PUBLISHING.md` builds wheels into `dist/`, which `.gitignore` already covers. Nothing here produces a `bloodhound-sccm-*.zip`. |

Two of the original plan's three **flags** also flipped, and are corrected in
[FLAGGED for manual verification](#flagged-for-manual-verification-no-auto-action-in-this-plan): `docs/proposals/`
is now referenced by live docs (so it must not be pruned), and the doc-site theme assets turned out to
have a declared-but-unconfigured build tool rather than no tool at all — which is why they became Task 5
instead of staying a flag.

---

## Decisions locked

From the original grilling (2026-07-24) and two rounds of rescoping (2026-07-30). Later rounds win.

| Fork | Decision | When |
|---|---|---|
| Scope | Reorganize + remove **provably-dead** only; **flag** maybe-stale items for manual verification. | 2026-07-24 |
| Test naming | Rename `test_*.py` → `*_test.py`; pin `python_files = "*_test.py"`. | 2026-07-24 |
| Test layout | Keep **flat** — no `unit/` vs `integration/` split. | 2026-07-24 |
| Docs structure | Leave `docs/` structure as-is; only flag orphans. | 2026-07-24 |
| Lab-script directory | **Keep `dev/`.** The move is already done and both docs already point at `dev/`. Renaming would force edits to `README.md` and `ARCHITECTURE.md` for no gain. | 2026-07-30 |
| Doc updates | **In scope, narrowly** (reverses an earlier "do not touch" constraint). `README.md` and `ARCHITECTURE.md` are edited **only** where this cleanup makes them wrong — Task 6. A general correctness audit of either file stays with ticket `con-3be4`. | 2026-07-30 |
| Doc-site scaffolding | **Delete it.** Remove `docs/javascript/` + `docs/stylesheets/`, drop `zensical>=0.0.27`, remove the dead `.pre-commit-config.yaml` excludes, re-lock. No site config exists in this repo **or** the monorepo, and `docs/` has no `index.md`. | 2026-07-30 |
| `per_host_phases` helper name | **`tests/stub_per_host_phases.py`.** Mirrors the production module name with a `stub_` prefix, so the relationship reads at a glance and the prefix sorts it away from the two confusable `per_host_phases*` test files. Avoids "fixture" (pytest-reserved) and matches neither collection glob. | 2026-07-30 |
| The two real collisions | **Rename to distinct topical names. Do NOT merge.** This repo organizes tests one-file-per-behavior, many per module — 26 `edge_*`, 18 `node_*`, 8 `graph_*`, 7 `transforms_*` files, and `registry_test.py` scoped to just "the RemoteRegistry collector's pure helpers". Two files testing one module is the convention, not drift. Renaming touches **zero test bodies**. | 2026-07-30 |
| `TICKETS-BY-STATUS.md` | **No task.** The file exists (20,829 bytes, correctly generated from `gtk list --json`); it is merely untracked. Recorded as a flag. | 2026-07-30 |

---

## Global Constraints (apply to EVERY task)

- **Commit rule for THIS repo: "Ask before committing each time. Never push."** (`CLAUDE.md` line 32.)
  This differs from the monorepo's stricter "no commits at all." Each task ends by showing its diff and
  **asking Meatbag** whether to commit; on approval, commit that task only; never push. Do not batch
  commits across tasks without asking.
- **No test body changes.** Not one assertion, not one helper, not one stub. Every collision is resolved
  by renaming. This is what makes the count invariant exact — see below. If you find yourself editing a
  test function, you have left the plan.
- **`git mv` for every move and rename**, so history is preserved.
- **Behavior must not change.** No collector, graph, CLI, or emitted-property change. The only content
  edits are three import lines (Task 2), one docstring paragraph (Task 2), `pyproject.toml`,
  `.pre-commit-config.yaml`, and the three documentation edits in Task 6.
- **Collected-test count is an exact invariant: 901.** It was 897 when this plan was drafted and shifted
  twice during execution, both times from concurrent work in files this plan does not own: **+1** from the
  committed `feat: emit MSSQL nodes/edges under source_kind=MSSQL` (tests added to
  `edge_mssql_structural_test.py`, `graph_edges_coercion_cols_test.py`, `graph_edges_split_test.py`), and
  **+3** from ticket `con-0170` adding sitesigncert-parse guard tests to `http_test.py` mid-execution. Every
  one of those files already used the suffix convention, so none was renamed here. Captured with
  `.venv\Scripts\python -m pytest --collect-only -q`. It must read **901 tests collected** at the end of
  every task. Per-file counts must also hold: `privileged_test.py` 22 → 22 under its new name,
  `privileged_user_group_test.py` 3, `registry_collect_test.py` 9, `registry_current_user_test.py` 1,
  `per_host_phases_test.py` 7.
- **`README.md` and `ARCHITECTURE.md`: Task 6 only, and only where this cleanup made them wrong.** Do not
  audit them generally, do not restructure, do not fix unrelated staleness you notice in passing. Ticket
  `con-3be4` ("Refresh README.md and ARCHITECTURE.md against current code", `in_progress`) is doing
  exactly that audit and holds uncommitted edits to both files right now. **Task 6 has a sequencing
  precondition — read it before starting.**
- **Do not modify the repository-local `.venv`** (`AGENTS.md` §5). Every command here calls the existing
  binaries directly — `.venv\Scripts\python.exe`, `.venv\Scripts\ruff.exe`, `.venv\Scripts\mypy.exe` —
  because `uv run` would sync the environment. Task 5 runs `uv lock`, which edits `uv.lock` only and
  creates no environment. Side effect: `.venv\Scripts\zensical.exe` lingers until Meatbag's next
  `uv sync`. Harmless — nothing invokes it.
- **Targeted tests, not the full suite**, for per-task checks (`AGENTS.md` → Tests). Before finishing, run
  the four files `ci.yml` gates on, plus ruff and mypy — see [Final validation](#final-validation).
- **Everyone is working in one tree on `main`.** `git branch -a` shows a single local branch and no
  worktrees. So the risk with `con-3be4` is **not** a merge conflict — it is a concurrent-edit race, where
  a stale read followed by a write silently discards the other agent's uncommitted work. Re-read any file
  immediately before editing it.
- **The working tree already carries other people's uncommitted work, and it is moving.** Snapshot
  2026-07-30, already drifting within the hour: `README.md`, `ARCHITECTURE.md`,
  `src/openhound_sccm/collectors/registry.py`, `src/openhound_sccm/graph.py`,
  `src/openhound_sccm/models/container.py`, `tests/smc_container_test.py` modified;
  `TICKETS-BY-STATUS.md`, `.tickets/con-3be4.md`, `.tickets/con-894a.md`, a `cypher_queries/*.json`, and
  two untracked plans present. **Do not revert, stage, or clobber any of it**, and **re-run
  `git status --short` yourself** — this is a snapshot, not a contract. `tests/smc_container_test.py` is
  already `*_test.py`, so no rename here touches a modified test file.
- **Open a `gtk` ticket before starting.** No ticket covers this cleanup. Per `CLAUDE.md` line 38 create
  one — but see the `TICKETS-BY-STATUS.md` flag before regenerating that file, which `con-3be4` touched
  at 13:44 on 2026-07-30.
- **Line numbers here are as of 2026-07-30 and will drift.** Re-locate by the quoted anchor text.

---

## File Structure

| Path | Change | Task |
|---|---|---|
| `tests/test_*.py` (30 non-colliding) | **Rename** → `<name>_test.py` | 1 |
| `tests/__init___test.py` | **Rename** → `tests/models_main_import_test.py` | 1 |
| `tests/per_host_phases_test.py` (0 tests, stub phase data) | **Rename** → `tests/stub_per_host_phases.py`; stop redefining `all_table_names` and import it from the package instead | 2 |
| `tests/test_per_host_phases.py` (7 tests) | **Rename** → `tests/per_host_phases_test.py`, claiming the freed name | 2 |
| `tests/ldap_resolved_principals_test.py:209` | **Repoint** import → `tests.stub_per_host_phases` | 2 |
| `tests/per_host_integration_test.py:17` (renamed in Task 1) | **Repoint** import → `tests.stub_per_host_phases` | 2 |
| `tests/per_host_phases_test.py:8` (the renamed 7-test file) | **Repoint** import → `tests.stub_per_host_phases` | 2 |
| `tests/privileged_test.py` (3 `_user_group` tests) | **Rename** → `tests/privileged_user_group_test.py` | 3 |
| `tests/test_privileged.py` (22 tests) | **Rename** → `tests/privileged_test.py`, claiming the freed name | 3 |
| `tests/test_registry_current_user.py` (9 tests via `collect_registry`) | **Rename** → `tests/registry_collect_test.py` | 3 |
| `tests/registry_current_user_test.py` (1 direct-call test) | **Unchanged** — its name is already accurate and already correct-convention | 3 |
| `pyproject.toml` | **Add** `[tool.pytest.ini_options]` with `python_files = "*_test.py"` (Task 4, LAST); **remove** `"zensical>=0.0.27"` (Task 5) | 4, 5 |
| `docs/javascript/` (`custom.mjs`, `mermaid.mjs`) | **Delete** | 5 |
| `docs/stylesheets/` (`mermaid-custom.css`) | **Delete** | 5 |
| `.pre-commit-config.yaml` | **Remove** `exclude: mkdocs.yml` under `check-yaml` and `exclude: ^cookiecutter-templates/` under `black` | 5 |
| `uv.lock` | **Re-lock** after dropping `zensical` | 5 |
| `ARCHITECTURE.md` (~186, ~697) | **Repath** two markdown links to test files Task 1 renames. Changelog rows naming old test filenames stay as dated records. | 6 |
| `README.md` ("Run the checks") | **Add** one paragraph: `python_files` is pinned, so a `test_*.py` file is silently not collected | 6 |

No file under `src/` is edited anywhere in this plan.

---

### Task 1: Rename the 30 non-colliding `test_*.py` files

**Files:**
- Rename: 30 files under `tests/`, per the mapping table below
- Rename: `tests/__init___test.py` → `tests/models_main_import_test.py`

**Interfaces:**
- Produces: the renamed module paths Task 2 repoints imports against — in particular
  `tests/test_per_host_integration.py` becomes `tests/per_host_integration_test.py`.
- Consumes: nothing.

**Why `__init___test.py` gets a real name:** it is a 4-line smoke test asserting that
`openhound_sccm.models` and `openhound_sccm.main` import cleanly (the latter being what registers the
`@app.collect` / `@app.preproc` / `@app.convert` phases). The filename is a cookiecutter accident — it
reads as a test *of* `__init__.py`, which it is not — and it sits next to the real, deliberately empty
`tests/__init__.py` that makes `tests` a package.

- [ ] **Step 1: Capture the baseline count**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
```

Expected: `901 tests collected`. If it is not 901, **stop** — the tree has moved and every later count
assertion is void. Report the number rather than adjusting it silently.

- [ ] **Step 2: Rename the 30 non-colliding files**

This loop renames exactly the non-colliding ones: it computes each destination and skips any whose
destination already exists, which is precisely the definition of the three collisions handled in Tasks 2
and 3.

```powershell
foreach ($f in (git ls-files 'tests/test_*.py')) {
    $base = [IO.Path]::GetFileNameWithoutExtension($f)          # e.g. test_http
    $dest = "tests/$($base -replace '^test_', '')_test.py"      # e.g. tests/http_test.py
    if (Test-Path $dest) { Write-Host "SKIP collision (Tasks 2/3): $f -> $dest"; continue }
    git mv $f $dest
}
```

Expected: 30 renames, and exactly three `SKIP collision` lines naming `tests/test_per_host_phases.py`,
`tests/test_privileged.py`, and `tests/test_registry_current_user.py`.

The full mapping, so a reviewer can verify the loop did what it claims:

| From | To |
|---|---|
| `test_ad_auth_warnings.py` | `ad_auth_warnings_test.py` |
| `test_ad_pth_ptt.py` | `ad_pth_ptt_test.py` |
| `test_allowed_targets.py` | `allowed_targets_test.py` |
| `test_cli_argument_warnings.py` | `cli_argument_warnings_test.py` |
| `test_cli_option_panels.py` | `cli_option_panels_test.py` |
| `test_debug_exc_info_filter.py` | `debug_exc_info_filter_test.py` |
| `test_dns_resolver_flag.py` | `dns_resolver_flag_test.py` |
| `test_extension_methods.py` | `extension_methods_test.py` |
| `test_http.py` | `http_test.py` |
| `test_http_auth.py` | `http_auth_test.py` |
| `test_http_cli_flags.py` | `http_cli_flags_test.py` |
| `test_http_client.py` | `http_client_test.py` |
| `test_http_negotiate_integration.py` | `http_negotiate_integration_test.py` |
| `test_ldap_management_points_raw.py` | `ldap_management_points_raw_test.py` |
| `test_ldap_smc_recursion.py` | `ldap_smc_recursion_test.py` |
| `test_mssql_epa.py` | `mssql_epa_test.py` |
| `test_per_host_integration.py` | `per_host_integration_test.py` |
| `test_per_host_log_blocks.py` | `per_host_log_blocks_test.py` |
| `test_per_host_wiring.py` | `per_host_wiring_test.py` |
| `test_pp_engine.py` | `pp_engine_test.py` |
| `test_pp_streams.py` | `pp_streams_test.py` |
| `test_pp_work_queue.py` | `pp_work_queue_test.py` |
| `test_principal_resolution_referral.py` | `principal_resolution_referral_test.py` |
| `test_progress_option.py` | `progress_option_test.py` |
| `test_smb.py` | `smb_test.py` |
| `test_smb_sso.py` | `smb_sso_test.py` |
| `test_smb_sso_integration.py` | `smb_sso_integration_test.py` |
| `test_sms_rows.py` | `sms_rows_test.py` |
| `test_verbose_silent_flags.py` | `verbose_silent_flags_test.py` |
| `test_wmi_client.py` | `wmi_client_test.py` |

- [ ] **Step 3: Rename the smoke test**

```powershell
git mv tests/__init___test.py tests/models_main_import_test.py
```

- [ ] **Step 4: Verify the count is unchanged and only the collisions remain**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
git ls-files 'tests/test_*.py'
```

Expected: `901 tests collected`, and the `git ls-files` output is exactly these three lines:

```
tests/test_per_host_phases.py
tests/test_privileged.py
tests/test_registry_current_user.py
```

- [ ] **Step 5: Confirm no import broke**

Note the `Get-ChildItem | Select-String` pipe rather than `Select-String -Path`: this is Windows
PowerShell 5.1, whose `-Path` does **not** understand a `**` recursive wildcard (it fails with "Cannot
find path").

```powershell
Get-ChildItem -Recurse -Filter *.py -Path tests,src,dev | Select-String -Pattern 'tests\.test_'
```

Expected: no matches. (There were none before this task either; the three real cross-module imports all
target `tests.per_host_phases_test`, which this task does not move — the same command with
`-Pattern 'tests\.per_host_phases_test'` returns exactly 3 matches, in
`ldap_resolved_principals_test.py:209`, `test_per_host_integration.py:17`, and
`test_per_host_phases.py:8`.)

- [ ] **Step 6: Lint**

```powershell
.venv\Scripts\ruff.exe check src tests
```

Expected: `All checks passed!`. Content did not change, so any failure means something other than the
renames — investigate rather than reformatting.

- [ ] **Step 7: Show the diff and ask Meatbag whether to commit**

```
chore(tests): rename 30 test_*.py to the *_test.py convention

Also renames the __init___test.py smoke test to models_main_import_test.py,
which is what it actually asserts (openhound_sccm.models and .main import
cleanly, the latter registering the collect/preproc/convert phases).

Pure renames via git mv; no test body changed. Collected count unchanged
at 901. The three name collisions are handled separately.
```

---

### Task 2: Untangle `per_host_phases` — the stub data out of the test namespace, the real test into the freed name

**Files:**
- Rename: `tests/per_host_phases_test.py` → `tests/stub_per_host_phases.py`
- Modify: `tests/stub_per_host_phases.py` — import `all_table_names` from the package instead of
  redefining it; add two docstring paragraphs
- Rename: `tests/test_per_host_phases.py` → `tests/per_host_phases_test.py`
- Modify: `tests/ldap_resolved_principals_test.py:209`
- Modify: `tests/per_host_integration_test.py:17` (named `test_per_host_integration.py` before Task 1)
- Modify: `tests/per_host_phases_test.py:8` (the file arriving from `test_per_host_phases.py`)

**Interfaces:**
- Consumes: Task 1's rename of `test_per_host_integration.py` → `per_host_integration_test.py`.
- Produces: module `tests.stub_per_host_phases` exporting `PER_HOST_PHASES: tuple[Phase, ...]` (the stub
  phases) and re-exporting `all_table_names` from `openhound_sccm.per_host_phases`. Both keep their
  current names, so importers change only the module path.

**Background — two competing `PER_HOST_PHASES`, and why this is not a merge.**

`tests/per_host_phases_test.py` defines **no tests at all**. It holds the stub phase tuple plus a copy of
`all_table_names()`. pytest collects it today only because its name matches the default `*_test.py` glob,
and collects zero items from it. Three test files import it.

Meanwhile `src/openhound_sccm/per_host_phases.py` is the **production** module: 6 phases
(`RemoteRegistry`, `MSSQL`, `AdminService`, `WMI`, `HTTP`, `SMB`), ~40 tables, real collectors, plus
`should_run_phase()`. Six test files import *that* one — `dc_only_flag_test.py`,
`per_host_phases_streams_test.py`, `test_http.py`, `test_per_host_log_blocks.py`,
`test_per_host_wiring.py`, `test_privileged.py`.

So the suite has two sources of `PER_HOST_PHASES`, and `tests/per_host_phases_streams_test.py` (which
imports the production one) sits alphabetically beside `tests/per_host_phases_test.py` (which *is* the
stub one). Two nearly identical filenames meaning opposite things, one letter apart from a silent
wrong-fixture bug. That is what this task fixes, and it is why the new name says `stub_`.

**Two things that look like staleness and are not:**

- **The stub list has 5 phases, not 6.** `collectors/stubs.py` defines exactly five stubs —
  `stub_remote_registry`, `stub_mssql`, `stub_adminservice`, `stub_http`, `stub_smb`. There is no
  `stub_wmi`. The `WMI` phase arrived later with a real collector and never got a stub, so the stub list is
  5 because five stubs exist. WMI's fallback gating is covered instead against the *production* list, in
  `test_privileged.py` and `test_http.py`. Step 2 records this so the next reader does not "fix" it.
- **`all_table_names` is byte-identical** between the two modules (verified by `diff`; only a trailing
  blank line differs). That one *is* pointless duplication, and since this task already edits the file,
  Step 2 replaces the copy with an import.

- [ ] **Step 1: Move the stub data out of the test namespace, then move the real test in**

Order matters — the first rename frees the name the second claims.

```powershell
git mv tests/per_host_phases_test.py tests/stub_per_host_phases.py
git mv tests/test_per_host_phases.py tests/per_host_phases_test.py
```

- [ ] **Step 2: Stop duplicating `all_table_names`, and record why the file is named this way**

In `tests/stub_per_host_phases.py`, delete the local definition:

```python
def all_table_names(phases: Sequence[Phase]) -> list[str]:
    """Every table the phases may write, de-duplicated, in declaration order."""
    return list(dict.fromkeys(table for phase in phases for table in phase.streams))
```

and import it from the production module instead, replacing the existing import block:

```python
from typing import Sequence

from openhound_sccm.collectors import stubs
from openhound_sccm.phased_pipeline import Phase
```

with:

```python
from openhound_sccm.collectors import stubs
from openhound_sccm.per_host_phases import all_table_names  # re-exported for importers
from openhound_sccm.phased_pipeline import Phase

__all__ = ["PER_HOST_PHASES", "all_table_names"]
```

`Sequence` was used only by the deleted function, so its import goes too — that is the one orphan this
task creates and is therefore in scope to remove (`AGENTS.md` §3: clean up your own mess, not
pre-existing mess).

Then replace the module docstring. The current one is copied word-for-word from the production module,
including the claim "each is replaced by a real collector in its own follow-up ticket" — true of this
copy, and no longer true of the original it was copied from:

```python
"""Stub per-host phases, for tests that need the pipeline without real collectors.

The production list is ``openhound_sccm.per_host_phases.PER_HOST_PHASES`` — 6 phases
wired to real collectors. This is its stub counterpart: the same ordered shape, but
every phase points at ``collectors/stubs.py``, so engine-level tests (ordering,
concurrency, recursion, termination) run without touching a network.

It has **5 phases, not 6**: ``collectors/stubs.py`` defines no ``stub_wmi``, because
the ``WMI`` phase arrived later with a real collector. WMI's fallback gating is
covered against the production list in ``privileged_test.py`` and ``http_test.py``.

Deliberately NOT named ``*_test.py``: this module holds no tests. ``pyproject.toml``
pins ``python_files = "*_test.py"``, and a collected module that is also imported by
name is a ``sys.modules`` collision waiting to happen.
"""
```

- [ ] **Step 3: Repoint the three importers**

`tests/ldap_resolved_principals_test.py` line 209 — indented, inside a function:

```python
    from tests.per_host_phases_test import PER_HOST_PHASES
```

becomes

```python
    from tests.stub_per_host_phases import PER_HOST_PHASES
```

`tests/per_host_integration_test.py` line 17 — module level:

```python
from tests.per_host_phases_test import PER_HOST_PHASES, all_table_names
```

becomes

```python
from tests.stub_per_host_phases import PER_HOST_PHASES, all_table_names
```

`tests/per_host_phases_test.py` line 8 — module level, in the file that just arrived from
`test_per_host_phases.py`. Identical text, identical replacement:

```python
from tests.per_host_phases_test import PER_HOST_PHASES, all_table_names
```

becomes

```python
from tests.stub_per_host_phases import PER_HOST_PHASES, all_table_names
```

- [ ] **Step 4: Verify no stale import path survives**

```powershell
Get-ChildItem -Recurse -Filter *.py -Path tests | Select-String -Pattern 'per_host_phases_test import'
```

Expected: no matches.

- [ ] **Step 5: Run the affected files**

```powershell
.venv\Scripts\python.exe -m pytest tests\per_host_phases_test.py tests\per_host_integration_test.py tests\ldap_resolved_principals_test.py tests\per_host_phases_streams_test.py -q
.venv\Scripts\python.exe -m pytest --collect-only -q tests\per_host_phases_test.py | Select-Object -Last 1
```

Expected: all pass; `7 tests collected`. `per_host_phases_streams_test.py` is included deliberately — it
imports the *production* module, and running it proves Step 2's re-export did not disturb that side.

- [ ] **Step 6: Verify the stub module is not collected, and the count held**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q tests\stub_per_host_phases.py | Select-Object -Last 2
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
```

Expected: `no tests collected`, then `901 tests collected`.

Worth understanding precisely, because it is easy to over-read: naming a file explicitly makes pytest
import and collect it **regardless** of `python_files` — the glob governs directory recursion, not named
arguments. So the first output proves the module holds no tests, and *directory* recursion is what stops
picking it up. Verified against a scratch repo with the Task 4 pin in place.

- [ ] **Step 7: Show the diff and ask Meatbag whether to commit**

```
chore(tests): name the stub per-host phases for what they are

tests/per_host_phases_test.py held no tests -- only a stub PER_HOST_PHASES
and a byte-identical copy of all_table_names(). It becomes
tests/stub_per_host_phases.py, which frees per_host_phases_test.py for the
real 7-test file (was test_per_host_phases.py) and ends the collision with
per_host_phases_streams_test.py, which imports the PRODUCTION list.

all_table_names is now imported from openhound_sccm.per_host_phases instead
of duplicated. Docstring records why the stub list has 5 phases (there is no
stub_wmi) and why the file is not named *_test.py.

Collected count unchanged at 901.
```

---

### Task 3: Resolve the two remaining collisions by topical rename — no merges

**Files:**
- Rename: `tests/privileged_test.py` → `tests/privileged_user_group_test.py`
- Rename: `tests/test_privileged.py` → `tests/privileged_test.py`
- Rename: `tests/test_registry_current_user.py` → `tests/registry_collect_test.py`
- Unchanged: `tests/registry_current_user_test.py`

**Interfaces:** none — none of these files is imported by another module.

**Why rename instead of merge.** The 2026-07-24 plan called these "collisions to be merged," on the
assumption that two files testing one module means duplication. Measured against the suite, that
assumption is wrong: **this repo organizes tests one file per behavior, many per module.** There are 26
`edge_*_test.py` files, 18 `node_*`, 8 `graph_*`, 7 `transforms_*` — and `registry_test.py` is scoped by
its own docstring to "the RemoteRegistry collector's *pure helpers*", 3 tests on `_roles`. Two files
testing `collectors/privileged.py` is the house style, not drift.

Renaming also touches **zero test bodies**, which keeps this plan's central invariant exact and makes the
diff reviewable at a glance. Merging would have required reconciling two import styles, adapting three
tests to `p.` prefixes, and reconciling two docstrings — real risk, for a worse fit with the codebase.

**What each file actually covers**, so the new names can be checked against the contents:

| File | Tests | Subject |
|---|---|---|
| `privileged_test.py` (from `test_privileged.py`) | 22 (17 functions, 5 parameterized over both `FLAVORS`) | The whole merged privileged collector: the ten collection helpers over both transports, `_http_identify`/`_http_fetch`, `_wmi_identify`/`_wmi_fetch`, the orchestrator, and `should_run_phase` gating. Imports the module as `p`. |
| `privileged_user_group_test.py` (from `privileged_test.py`) | 3 | Only `_user_group` — that `SMS_R_UserGroup` is queried, that the row carries the `DOMAIN\group` name and the group SID, that the table prefix follows the transport, and that it is wired into `_COLLECTIONS`. Uses its own `_stub_run`. |
| `registry_collect_test.py` (from `test_registry_current_user.py`) | 9 | `collect_registry` end to end: `UserSID` selected by *name* not enumeration position (6 tests, a regression guard), and the Multisite Component Servers absent/empty/populated cases (3 tests). |
| `registry_current_user_test.py` (unchanged) | 1 | `get_current_user` called **directly**, asserting the row carries both the logged-on user's `object_sid` and the host's `host_object_sid`. |

The one imperfection, recorded rather than papered over: `registry_collect_test.py`'s 9 tests span two
topics (`UserSID` selection and Multisite), so its name describes the *entry point* they share rather than
a single behavior. Splitting it into `registry_current_user_selection_test.py` and
`registry_multisite_test.py` would fit the house style even better, but that means moving test bodies and
duplicating the `FakeProbe`/`FakeCtx` stubs. Left as a flag, not done here.

- [ ] **Step 1: Record the per-file baselines**

```powershell
foreach ($f in 'tests\test_privileged.py','tests\privileged_test.py','tests\test_registry_current_user.py','tests\registry_current_user_test.py') {
    $n = (.venv\Scripts\python.exe -m pytest --collect-only -q $f | Select-Object -Last 1)
    Write-Host ("{0,-45} {1}" -f $f, $n)
}
```

Expected: 22, 3, 9, 1 respectively. These exact numbers must reappear under the new names in Step 4.

- [ ] **Step 2: Rename the privileged pair**

Order matters — move the 3-test file out of the way first, then the 22-test file claims the freed name.

```powershell
git mv tests/privileged_test.py tests/privileged_user_group_test.py
git mv tests/test_privileged.py tests/privileged_test.py
```

- [ ] **Step 3: Rename the registry file**

Only one rename here: `registry_current_user_test.py` already has both an accurate name and the right
convention, so it is left alone and there is no collision to break.

```powershell
git mv tests/test_registry_current_user.py tests/registry_collect_test.py
```

- [ ] **Step 4: Verify every count survived the renames**

```powershell
foreach ($f in 'tests\privileged_test.py','tests\privileged_user_group_test.py','tests\registry_collect_test.py','tests\registry_current_user_test.py') {
    $n = (.venv\Scripts\python.exe -m pytest --collect-only -q $f | Select-Object -Last 1)
    Write-Host ("{0,-45} {1}" -f $f, $n)
}
.venv\Scripts\python.exe -m pytest tests\privileged_test.py tests\privileged_user_group_test.py tests\registry_collect_test.py tests\registry_current_user_test.py -q
```

Expected: 22, 3, 9, 1 — matching Step 1 exactly — and all 35 pass.

- [ ] **Step 5: Confirm zero `test_*.py` remain**

```powershell
git ls-files 'tests/test_*.py'
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
.venv\Scripts\ruff.exe check src tests
```

Expected: `git ls-files` returns **nothing**; `901 tests collected`; ruff clean.

- [ ] **Step 6: Show the diff and ask Meatbag whether to commit**

```
chore(tests): rename the last two colliding test files by topic

Not merged. This suite is organized one file per behavior, many per module
(26 edge_*, 18 node_*, 8 graph_*, 7 transforms_* files), so two files
testing collectors/privileged.py is the convention rather than drift.

  privileged_test.py (3 _user_group tests) -> privileged_user_group_test.py
  test_privileged.py (22 tests)            -> privileged_test.py
  test_registry_current_user.py (9 tests)  -> registry_collect_test.py
  registry_current_user_test.py            -> unchanged, already correct

Pure renames; no test body touched. Per-file counts 22/3/9/1 unchanged,
total unchanged at 901. No test_*.py files remain.
```

---

### Task 4: Pin the test-file convention — **do this LAST of the test tasks**

**Files:**
- Modify: `pyproject.toml` — add a new `[tool.pytest.ini_options]` table

**Interfaces:** none.

- [ ] **Step 1: Verify the precondition, or do not proceed**

```powershell
git ls-files 'tests/test_*.py'
```

Expected: **no output.** If any line appears, **stop.**

**The ordering trap:** pytest's default is `python_files = test_*.py *_test.py` — both patterns. Pinning
it to `*_test.py` alone means any surviving `test_*.py` **silently stops being collected**. No error, no
warning, just a lower count. That is why this task runs after Tasks 1–3, and why the check above is a hard
gate rather than a note.

- [ ] **Step 2: Add the pin**

Append to `pyproject.toml`, after the `[tool.mypy]` block and its overrides — i.e. at the end of the file —
so it sits with the other tool configuration rather than splitting the mypy overrides:

```toml
[tool.pytest.ini_options]
# Pinned to the *_test.py suffix only. pytest's default also accepts the test_*.py
# prefix; allowing both is what let the suite drift into two conventions at once.
# A consequence worth knowing: a file named test_something.py is now silently NOT
# collected by `pytest tests`, so a new test added under the old prefix would pass
# by never running. (Naming it explicitly on the command line still collects it.)
python_files = "*_test.py"
```

- [ ] **Step 3: Verify the pin collects exactly what it did before**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
```

Expected: `901 tests collected`. Because Tasks 1–3 left zero `test_*.py` files, narrowing the glob must
change nothing — if the number drops, a file was missed and Step 1 ran against a stale tree.

- [ ] **Step 4: Confirm the stub module is still excluded and still importable**

```powershell
.venv\Scripts\python.exe -m pytest tests\per_host_phases_test.py tests\per_host_integration_test.py tests\ldap_resolved_principals_test.py -q
```

Expected: all pass. This is the check that the pin did not break the `tests.stub_per_host_phases` import
Task 2 created.

- [ ] **Step 5: Show the diff and ask Meatbag whether to commit**

```
chore(tests): pin python_files to the *_test.py convention

pytest's default accepts both test_*.py and *_test.py, which is how the suite
ended up running two conventions at once. Now that every file uses the suffix
form, pin it. Collected count unchanged at 901.
```

---

### Task 5: Retire the never-completed documentation-site scaffolding

**Files:**
- Delete: `docs/javascript/custom.mjs`, `docs/javascript/mermaid.mjs`
- Delete: `docs/stylesheets/mermaid-custom.css`
- Modify: `pyproject.toml` — remove `"zensical>=0.0.27"` from `[dependency-groups] dev`
- Modify: `.pre-commit-config.yaml` — remove two excludes naming files this repo does not have
- Modify: `uv.lock` — regenerate

**Interfaces:** none. **Independent of Tasks 1–4** — nothing here touches tests, so it can run at any
point.

**Evidence that this is scaffolding, not a working site.** There is no `mkdocs.yml` and no
`zensical.toml` — not in this repo and not in the monorepo it split from (`find` across both returns only
`.venv` binaries). `docs/` has no `index.md`; its only top-level page is
`per-host-collection-framework-tour.md`. `zensical` appears nowhere outside `pyproject.toml` and
`uv.lock`. The only thing referencing the assets is `docs/javascript/custom.mjs:100`, pointing at
`/stylesheets/mermaid-custom.css` — the assets referencing each other, with no page loading either. And
`.pre-commit-config.yaml` excludes `mkdocs.yml` from `check-yaml`, which is independent evidence a site
config was intended and never committed.

- [ ] **Step 1: Re-confirm nothing outside the assets references them**

```powershell
Select-String -Path *.md, *.toml, *.yaml, .github\workflows\*.yml -Pattern 'custom\.mjs|mermaid\.mjs|mermaid-custom\.css|zensical|mkdocs'
```

Expected: exactly two matches — `"zensical>=0.0.27"` in `pyproject.toml` and `exclude: mkdocs.yml` in
`.pre-commit-config.yaml`. (`*.yaml` does match the dotted `.pre-commit-config.yaml` — verified.) If a
`mkdocs.yml` or `zensical.toml` has appeared since 2026-07-30, **stop**: a site now exists and this task
is wrong.

- [ ] **Step 2: Delete the theme assets**

```powershell
git rm -r docs/javascript docs/stylesheets
```

- [ ] **Step 3: Drop the dev dependency**

In `pyproject.toml`, inside `[dependency-groups] dev`, remove this line:

```toml
    "zensical>=0.0.27",
```

Leave every other entry and every explanatory comment in that block untouched — the `ruff>=0.15.5,<0.16`
cap and the type-stub commentary are load-bearing notes about real breakage, not decoration.

- [ ] **Step 4: Remove the two dead pre-commit excludes**

Both name paths that do not exist here; both are inherited cookiecutter/monorepo residue, the same class
of artifact the split already removed in dropping `extension.yaml` and `src/main.py`. Neither removal
changes behavior today — an exclude for a nonexistent path is a no-op either way — but leaving them is a
latent trap: if anyone ever creates `cookiecutter-templates/`, `black` would silently skip it.

`check-yaml` currently reads:

```yaml
      - id: check-yaml
        exclude: mkdocs.yml
```

becomes:

```yaml
      - id: check-yaml
```

`black` currently reads:

```yaml
      - id: black
        exclude: ^cookiecutter-templates/
```

becomes:

```yaml
      - id: black
```

- [ ] **Step 5: Re-lock**

```powershell
uv lock
git diff --stat uv.lock
Select-String -Path uv.lock -Pattern 'zensical'
```

Expected: `Resolved 118 packages`, with exactly three removals — `zensical` plus its own private
dependencies `deepmerge` and `tomli` — and no `zensical` matches remain.

**Corrected during execution:** an earlier draft of this step predicted the `mkdocs`, `mkdocs-autorefs`
and `mkdocs-get-deps` tree would drop too. It does not, and should not. Those come in via
`openhound` → `mkdocstrings[python]`, so they are the framework's transitive dependencies, not
`zensical`'s. Their staying is correct; only `zensical`'s own subtree leaves.

`uv lock` writes only the lockfile; it creates no environment, so the repository-local `.venv` is left
alone per `AGENTS.md` §5.

- [ ] **Step 6: Verify nothing broke**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
.venv\Scripts\ruff.exe check src tests
.venv\Scripts\mypy.exe src\openhound_sccm
```

Expected: `901 tests collected`; ruff clean; mypy as clean as before this task (record before/after if it
reports anything, since none of these edits can affect it). `.venv\Scripts\zensical.exe` still exists —
this plan deliberately does not sync the venv. It becomes unreachable at Meatbag's next `uv sync`.

- [ ] **Step 7: Show the diff and ask Meatbag whether to commit**

```
chore: retire the never-completed docs-site scaffolding

No mkdocs.yml or zensical.toml exists in this repo or the monorepo it split
from, and docs/ has no index.md -- so docs/javascript/ and docs/stylesheets/
were theme assets for a site that was never configured, referenced only by
each other. Drops them, drops the zensical dev dependency (named nowhere
else), re-locks, and removes two .pre-commit-config.yaml excludes that point
at files this repo does not have (mkdocs.yml, cookiecutter-templates/).

Recoverable from history if the site is ever started for real.
```

---

### Task 6: Update `README.md` and `ARCHITECTURE.md` for what this cleanup invalidated

**Files:**
- Modify: `ARCHITECTURE.md` — two markdown links to test files Task 1 renames
- Modify: `README.md` — document the pinned test-filename convention

**Interfaces:** none.

**Sequencing precondition — read this first.** Run after Task 1 (whose renames break the links) and after
Task 4 (which is what the README paragraph describes). More importantly, **coordinate with `con-3be4`**:

- Everyone is in **one working tree on `main`** — no branches, no worktrees. So the risk is not a merge
  conflict; it is a concurrent-edit race where a stale read plus a write silently discards the other
  agent's uncommitted work.
- `con-3be4` is making **large-scale** edits to both files (alphabetizing the Node and Edge reference
  sections, sorting the changelog, expanding shorthand references). This task makes **three surgical**
  edits anchored on quoted text. Small-after-large is strictly easier than large-after-small, and this
  task's anchors survive any amount of line movement because they are quoted strings, not line numbers.
- Therefore: **let `con-3be4` commit first, then run this task.** Tasks 1–5 touch no documentation and
  need not wait — run them meanwhile.
- **`con-3be4` may have already done Steps 1–2.** Its plan includes a broken-link pass, and once Task 1
  lands, those two links *are* broken and visible to it. Both steps below are idempotent: check first, and
  if the links are already repaired, say so and skip to Step 3.

**Scope discipline.** These are the *only* doc edits this cleanup earns. Both files were surveyed on
2026-07-30 for everything else this plan touches, and nothing else needs changing:

- **No other broken link.** Every other test file either doc links is already `*_test.py` and untouched by
  this plan: `extension_metadata_test.py` (README line 419), CI's four files (README lines 2076–2077),
  `graph_edges_split_test.py` (ARCHITECTURE line 1166), `graph_edges_dedup_test.py` / `graph_edge_test.py`
  (line 1113), `edge_coerce_relay_smb_test.py` (line 1599).
- **The README file tree needs nothing.** It lists `dev/`, `tests/`, `cypher_queries/`,
  `powershell_deprecated/` and the `src/openhound_sccm/` contents — `dev/` is already correct, `tests/` is
  named without enumerating files, and `docs/` does not appear in the tree at all, so Task 5's deletions
  are invisible to it.
- **Task 5 needs no doc edit whatsoever.** Neither document mentions `docs/javascript`,
  `docs/stylesheets`, `zensical`, or `mkdocs`. README Contributing item 4 describes pre-commit as running
  "`black` formatting plus YAML/JSON/whitespace/large-file checks" — still accurate, because Task 5
  removes two *excludes* and keeps both hooks.
- **No ARCHITECTURE changelog entry for this cleanup.** `AGENTS.md` requires one for a change to a
  cross-cutting *subsystem*; test file layout is not a subsystem. The contributor-facing fact — the pin —
  belongs in the README, which is where Step 3 puts it.
- **The ARCHITECTURE changelog stays as written.** Rows dated 2026-07-29, 2026-07-22 and 2026-07-21 name
  `test_extension_methods.py`, `tests/test_per_host_log_blocks.py`, `tests/test_verbose_silent_flags.py`,
  `tests/test_ad_pth_ptt.py`, `tests/test_mssql_epa.py`, `tests/test_ldap_smc_recursion.py`. Those are
  **dated records of what was true when the work happened** — the same call the 2026-07-24 plan made about
  changelog prose, and the same reason this plan leaves `sccm/sccm` paths alone in `.tickets/`. Rewriting a
  record to match today's filenames destroys the record. None are markdown links, so none 404.

- [ ] **Step 1: Fix the `pp_engine` link in `ARCHITECTURE.md`** (~line 186)

Body prose, not changelog. Locate by the anchor text `that one** shared dependency`:

```markdown
that one** shared dependency, and nothing else ([`tests/test_pp_engine.py`](tests/test_pp_engine.py)).
```

becomes

```markdown
that one** shared dependency, and nothing else ([`tests/pp_engine_test.py`](tests/pp_engine_test.py)).
```

- [ ] **Step 2: Fix the `per_host_log_blocks` link in `ARCHITECTURE.md`** (~line 697)

Also body prose. Locate by the anchor text `once, when the host finishes all its phases`:

```markdown
  once, when the host finishes all its phases. Guarded by [`tests/test_per_host_log_blocks.py`](tests/test_per_host_log_blocks.py).
```

becomes

```markdown
  once, when the host finishes all its phases. Guarded by [`tests/per_host_log_blocks_test.py`](tests/per_host_log_blocks_test.py).
```

- [ ] **Step 3: Document the pinned convention in `README.md`**

The one genuinely *new* thing a reader needs to know, and it is contributor-facing: after Task 4, a test
file named with the old `test_` prefix is silently not collected. It goes in **Run the checks**, because
that is the section someone is reading when they wonder why their test did not run. Locate the paragraph
ending `without a hierarchy to talk to.` and add a new paragraph immediately after it:

```markdown
**Name a new test file `<subject>_test.py`.** [pyproject.toml](pyproject.toml) pins
`python_files = "*_test.py"`, so pytest collects the suffix form only. A file named
`test_something.py` is **not collected** when you run `pytest tests` — it does not run, it does not
fail, and nothing warns you. (Naming it explicitly on the command line *does* collect it, which is a
good way to be misled into thinking it is wired up.)
```

- [ ] **Step 4: Verify no link in either document points at a renamed file**

```powershell
Get-ChildItem README.md, ARCHITECTURE.md | Select-String -Pattern '\]\(tests/test_[a-z0-9_]+\.py'
```

Expected: no matches. This checks *links* specifically, so it deliberately ignores the changelog's
plain-text `test_*.py` mentions, which stay.

Then confirm every test file the two documents link to actually exists:

```powershell
Get-ChildItem README.md, ARCHITECTURE.md |
  Select-String -Pattern '\]\((tests/[a-z0-9_]+\.py)' -AllMatches |
  ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value } |
  Sort-Object -Unique | ForEach-Object { if (-not (Test-Path $_)) { Write-Host "MISSING: $_" } }
```

Expected: no `MISSING:` lines.

- [ ] **Step 5: Show the diff and ask Meatbag whether to commit**

Keep this commit separate from the rename commits even if both are approved in one sitting — a reviewer
comparing the doc edit against the rename wants two diffs, not one.

```
docs: repath two test-file links and document the *_test.py pin

ARCHITECTURE.md lines ~186 and ~697 linked tests/test_pp_engine.py and
tests/test_per_host_log_blocks.py, both renamed by the test-naming
standardization. README "Run the checks" now states that python_files is
pinned to the suffix form, since a test_*.py file is silently not collected.

Changelog rows naming old test filenames are left as dated records.
```

---

## FLAGGED for manual verification (no auto-action in this plan)

Surfaced for Meatbag to decide, each with a recommendation. Two of these correct claims the 2026-07-24
plan got wrong, because the repo changed underneath them.

- **~~`TICKETS-BY-STATUS.md` is untracked~~ — RESOLVED during execution, by someone else.** The flag was
  raised when the file existed but had never been committed, leaving the `merge=ours` attribute in
  `.gitattributes` inert (git cannot apply a merge driver to a file it does not track). It has since been
  committed **and relocated** to `.tickets/_TICKETS-BY-STATUS.md`, with `.gitattributes`, `AGENTS.md`,
  `CLAUDE.md`, `PUBLISHING.md` and the `README.md` merge-driver note updated to match. No action remains
  here. The one-time `git config merge.ours.driver true` per clone is still required, and is still
  documented in `.gitattributes`.
- **~~`docs/proposals/` is unreferenced and probably prunable~~ — WRONG as of 2026-07-30.**
  `ARCHITECTURE.md` line 797 links `docs/proposals/2026-06-16-convert-read-from-duckdb.md` and line 824
  links `docs/proposals/2026-06-16-computer-node-multi-driver-merge.md`;
  `docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md` cites the first twice; the two
  proposals cross-reference each other.
  **Recommendation: keep them.** Deleting would break live documentation links, and if they really are
  implemented and should go, that is `con-3be4`'s territory — it owns the file that links them.
- **`registry_collect_test.py` spans two topics.** After Task 3 it holds 6 `UserSID`-selection tests and
  3 Multisite Component Servers tests, so its name describes the shared entry point rather than one
  behavior. Splitting into `registry_current_user_selection_test.py` and `registry_multisite_test.py`
  would fit the house style better.
  **Recommendation: leave it, open a follow-up ticket.** The split moves test bodies and duplicates the
  `FakeProbe`/`FakeCtx` stubs, which is real work with real risk — the wrong thing to fold into a
  rename-only commit.
- **The two `_Run` builders in `privileged_test.py` overlap.** After Task 3 the 22-test file has
  `_run(name, eq, pages, principal=None, calls=None)` and the 3-test file has
  `_stub_run(rows, *, name, site_code)`; both build a `_Run` with a canned `fetch`, and `_run`'s `calls`
  list records exactly what `_stub_run`'s `captured` dict does. They now live in *separate* files, so this
  is no longer duplication inside one module — but it is still two ways to do one thing.
  **Recommendation: leave it, and do not chase it.** The files are separate and each helper is 8 lines.
  Consolidating would mean one importing from the other, which re-creates the cross-test-module import
  Task 2 just removed. (For the record, it *would* be safe: `_user_group` delegates straight to `_simple`
  and never reads `run.ctx`, so `_stub_run`'s `ctx=None` and `_run`'s real `_Ctx` are interchangeable
  here.)
- **The stub and production `PER_HOST_PHASES` still differ in shape.** Task 2 removes the duplicated
  `all_table_names` and makes the naming honest, but the stub list still has 5 phases against
  production's 6.
  **Recommendation: leave the 5 phases.** This is structural, not stale: `collectors/stubs.py` defines no
  `stub_wmi`, because `WMI` arrived later with a real collector, and WMI's fallback gating is already
  covered against the production list in `privileged_test.py` and `http_test.py`. Task 2's docstring
  records this. The open question worth a ticket is different: **is `collectors/stubs.py` still anything
  but test scaffolding** now that every phase has a real collector? If not, it and the stub phase list
  could move under `tests/` entirely.
- **Possibly-stale lab scripts in `dev/`, referenced by no live doc:** `debug_smb_auth.py`,
  `debug_wmi_auth.py`, `tour_driver_stage0.py`, `tour_driver_stage2.py`, `tour_driver_stage3.py`. Only
  `debug_per_host.py`, `debug_epa_matrix.py`, `spike_smb_sso.py` (README 1821–1823, ARCHITECTURE
  297–301), `tour_driver_stage1.py` (ARCHITECTURE 705) and `spike_socks_proxy.md` (ARCHITECTURE 1740) are
  doc-cited.
  **Recommendation: keep all five.** Closed tickets record them doing real live validation —
  `debug_smb_auth.py` in `ope-4483` (all four auth methods against three lab hosts),
  `debug_wmi_auth.py` in `ope-1f49` and `ope-38ad` (all five auth rungs against the SMS Provider).
  "Unreferenced by docs" is not "unused", and they cost nothing to keep.
- **pre-commit runs `black`; CI runs `ruff`.** `.pre-commit-config.yaml` pins `black` 25.12.0 while
  `.github/workflows/ci.yml:29` runs `ruff check src tests`. Two formatters with different opinions over
  one tree, and the `ruff` dependency is deliberately capped below 0.16 because that release widened the
  default rule set. ARCHITECTURE's 2026-07-29 changelog row notes neither tool had ever passed until that
  date "despite both being declared dev dependencies and documented commands — the pre-commit config runs
  `black` and the standard hooks only."
  **Recommendation: resolve it deliberately, in its own ticket — not here.** The likely end state is
  `ruff format` replacing `black` so one tool defines formatting and CI gates what pre-commit applies. But
  that reformats files, which has no business inside a rename-only cleanup.
- **No `gtk` ticket covers this cleanup.** `gtk list` shows 116 tickets, none about repo cleanup
  (`ope-1f0f`, "Code-Quality Pass", is nearest and is about logging/exception/scope quality, not layout).
  **Recommendation: open one before implementing**, per `CLAUDE.md` line 38 — and see the
  `TICKETS-BY-STATUS.md` flag above before regenerating that file.

## Explicitly OUT of scope

- **A general audit of `README.md` or `ARCHITECTURE.md`.** Task 6 edits both, but only where *this*
  cleanup invalidated them. Ticket `con-3be4` and plan
  `docs/superpowers/plans/2026-07-30-docs-update-readme-architecture.md` own the broad pass —
  alphabetizing node/edge references, sorting the changelog, expanding shorthand, auditing prose against
  code. Report unrelated staleness you notice; do not fix it here.
- **`sccm/tests/live-comparison/` report consolidation** — those files live in the OpenHound monorepo now.
  Original Task 6, retired here.
- **The `sccm/sccm/...` paths in `.tickets/*.md` and `docs/superpowers/plans/*.md`** — dated historical
  records of work done when the collector lived in the monorepo. Leave them. Rewriting a record to match
  today's layout destroys the record.
- **`powershell_deprecated/`** — the PowerShell predecessor and its own test kit, deliberately retained
  and cited by `ARCHITECTURE.md` line 1758. Its five `sample_data/*.zip` fixtures are intentional, not
  the build artifact the original plan deleted.
- **`openhound-collector-common`** — a separate published package and repository. `AGENTS.md` is explicit:
  trace into it to understand behavior, never edit it as part of a change here.
- **`cypher_queries/`** — now tracked (18+ saved BloodHound queries), with one untracked addition in the
  working tree. Active work, not cruft.

## Execution order & final validation

1. **Baseline first.** `.venv\Scripts\python.exe -m pytest --collect-only -q` must read
   **901 tests collected** before any change. If not, stop and report.
2. **Task 1** (30 renames + the smoke-test rename) → count still 901.
3. **Task 2** (stub data renamed out of the test namespace, real test claims the name, 3 imports
   repointed, `all_table_names` de-duplicated) → count still 901.
4. **Task 3** (two topical renames + one, zero bodies touched) → per-file counts 22/3/9/1 unchanged, total
   901, and `git ls-files 'tests/test_*.py'` returns nothing.
5. **Task 4** (pin `python_files`) — **only** after step 4's `git ls-files` check is empty.
6. **Task 5** (retire the docs-site scaffolding) — independent; may run at any point.
7. **Task 6** (the three doc edits) — **last**, and only after `con-3be4` has committed. Check whether it
   already repaired the two links.

**Final validation.** Run the four files `ci.yml` gates on, since those are what a pull request must pass,
plus both linters (`AGENTS.md` → Tests):

```powershell
.venv\Scripts\python.exe -m pytest tests\extension_metadata_test.py tests\integration_wiring_test.py `
    tests\convert_pipeline_test.py tests\integration_fixtures_test.py -q
.venv\Scripts\ruff.exe check src tests
.venv\Scripts\mypy.exe src\openhound_sccm
```

Then the whole-suite collection check one last time:

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
```

Expected: **901 tests collected.** That number is the whole proof of this plan — 35 renames, one
de-duplicated helper, three repointed imports and a narrowed collection glob, with not a single test lost
and not a single test body touched.

**Not required:** a live-lab run. No collector, client, or transform code is touched, so there is nothing
a live SCCM hierarchy would exercise that the offline suite does not.
