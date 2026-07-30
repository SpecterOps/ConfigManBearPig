# ConfigManBearPig Repo Cleanup — Standardize Test Naming, Retire Doc-Site Scaffolding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Repository:** This plan applies to the **standalone `ConfigManBearPig` repository**
(`C:\Users\domainadmin\Desktop\ConfigManBearPig`, PyPI distribution `configmanbearpig`), **not** the
OpenHound monorepo's `sccm/sccm/` copy at `C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm`. Every path
below is relative to this repo's root. Rescoped from the original monorepo-relative plan on 2026-07-30 —
see [Rescoped 2026-07-30](#rescoped-2026-07-30-what-the-repo-split-already-settled).

**Goal:** Standardize every test filename on the `*_test.py` majority convention and pin that convention
in `pyproject.toml`, resolve the three name clashes the renames create, and retire the never-completed
documentation-site scaffolding (`docs/javascript/`, `docs/stylesheets/`, the `zensical` dev dependency,
and the `.pre-commit-config.yaml` excludes that name files this repo does not have). No collector
behavior changes.

**Architecture (approach):** Housekeeping. The tests move but their bodies are preserved verbatim except
for import repointing and the two concatenations in Task 4, so the collected-test count is the invariant
that proves nothing was lost. The only source edits are two config files: `pyproject.toml` (add the
pytest file glob, drop one dev dependency) and `.pre-commit-config.yaml` (drop two dead excludes). Package
root is `src/openhound_sccm/`; tests are flat in `tests/`. Everything removed stays recoverable from git
history.

**Tech Stack:** Python 3.13+, pytest 9, uv, ruff, mypy, git. No runtime dependency is touched.

---

## Rescoped 2026-07-30: what the repo split already settled

The original plan was written against the monorepo path `sccm/sccm/`. Splitting the collector into its own
repository satisfied or invalidated four of its seven tasks. **Do not redo these** — each was verified
against the working tree on 2026-07-30, with the evidence recorded so a reviewer can re-check.

| Original task | Status | Evidence |
|---|---|---|
| **1** — move 10 loose dev/lab scripts into `tools/` | **Done, under the name `dev/`** | All 10 are tracked in `dev/` (`git ls-files dev`). `ARCHITECTURE.md` lines 297, 298, 301, 705, 1740 and `README.md` lines 1821–1823, 1959, 1965 already say `dev/`. **Decision 2026-07-30: keep `dev/`, do not rename to `tools/`** — see Decisions locked. |
| **2** — rename 28 `test_*.py` | **Still needed, now 30** | `git ls-files 'tests/test_*.py'` returns 33; 3 are the collisions handled in Tasks 3–4. New since 2026-07-24: `test_cli_option_panels.py`; and `test_verbose_silent_flags.py` is now tracked rather than untracked. → **Task 1** |
| **3** — resolve 3 rename collisions | **Still needed; one changed shape** | Same 3 pairs. But `tests/per_host_phases_test.py` contains **zero tests** — it is a shared-data module, not a test — so its clash is resolved by renaming the helper, not by merging. → **Tasks 2 and 4** |
| **4** — pin `python_files = "*_test.py"` | **Still needed** | No `[tool.pytest.ini_options]` exists anywhere: no `pytest.ini`, no `setup.cfg`, no `tox.ini`, and `grep pytest pyproject.toml` matches only the `pytest>=9.0.1` dev dependency. → **Task 5** |
| **5** — delete `extension.yaml`, `src/main.py`, the tracked zip | **Done — all three already absent** | `find . -name extension.yaml` returns only `src/openhound_sccm/extension.yaml`, which is the authoritative copy OpenHound loads via `resources.files("openhound_sccm")`. `src/` contains only `openhound_sccm/`. `git ls-files '*.zip'` returns only the five deliberate `powershell_deprecated/sample_data/` fixtures, none of them the `bloodhound-sccm-openhound-*.zip` build artifact. |
| **6** — consolidate live-comparison reports | **Left this repository** | Those files are at `C:\Users\domainadmin\Desktop\OpenHound\sccm\tests\live-comparison\`. This repo has no `tests/live-comparison/` at all. If the consolidation still matters it belongs to a monorepo plan, not this one. |
| **7** — add `bloodhound-sccm-*.zip` to `.gitignore` | **Obsolete** | The rationale was `Package-OpenHoundZip.ps1` output. No such script exists in this repo; `PUBLISHING.md` builds wheels into `dist/`, which `.gitignore` already covers (`dist/`, line in the Distribution/packaging block). Nothing here produces a `bloodhound-sccm-*.zip`. |

Two of the original plan's three **flags** also flipped, and are corrected in
[FLAGGED for manual verification](#flagged-for-manual-verification) below: `docs/proposals/` is now
referenced by live docs (so it must not be pruned), and the doc-site theme assets turned out to have a
declared-but-unconfigured build tool rather than no tool at all — which is why they became Task 6 instead
of staying a flag.

---

## Decisions locked

From the original grilling (2026-07-24) and the rescoping grilling (2026-07-30). Where the two disagree,
2026-07-30 wins.

| Fork | Decision | When |
|---|---|---|
| Scope | Reorganize + remove **provably-dead** only; **flag** maybe-stale items for manual verification. | 2026-07-24 |
| Test naming | Rename `test_*.py` → `*_test.py`; pin `python_files = "*_test.py"`. | 2026-07-24 |
| Test layout | Keep **flat** — no `unit/` vs `integration/` split. | 2026-07-24 |
| Docs structure | Leave `docs/` structure as-is; only flag orphans. | 2026-07-24 |
| Lab-script directory | **Keep `dev/`.** Do not rename to `tools/`. The move is already done, both docs already point at `dev/`, and renaming would force edits to `README.md` and `ARCHITECTURE.md` — the two files ticket `con-3be4` currently owns exclusively. Keeping `dev/` lets this plan run with **zero doc edits** and therefore zero conflict. | 2026-07-30 |
| `per_host_phases` clash | **Rename the helper out of the test namespace.** `tests/per_host_phases_test.py` has 0 tests and 3 importers; it becomes `tests/per_host_phases.py`, freeing the `per_host_phases_test.py` name for the real 7-test file. No merge, no test bodies touched, and after Task 5's pin no `*_test.py` file is imported by another test. | 2026-07-30 |
| Doc-site scaffolding | **Delete it.** Remove `docs/javascript/` + `docs/stylesheets/`, drop `zensical>=0.0.27` from the dev dependency group, remove the dead `.pre-commit-config.yaml` excludes, and re-lock. There is no site config in this repo **or** the monorepo, and `docs/` has no `index.md`, so there is no site to build. | 2026-07-30 |
| `TICKETS-BY-STATUS.md` | **No task.** The file exists (20,829 bytes, correctly generated from `gtk list --json`); it is merely untracked (`??`). Recorded as a flag instead — see FLAGGED. | 2026-07-30 |

---

## Global Constraints (apply to EVERY task)

- **Commit rule for THIS repo: "Ask before committing each time. Never push."** (`CLAUDE.md` line 32.)
  This differs from the monorepo's stricter "no commits at all." Each task ends by showing its diff and
  **asking Meatbag** whether to commit; on approval, commit that task only; never push. Do not batch
  commits across tasks without asking.
- **Do NOT touch `README.md` or `ARCHITECTURE.md`.** Ticket `con-3be4` ("Refresh README.md and
  ARCHITECTURE.md against current code", status `in_progress`) and its plan
  `docs/superpowers/plans/2026-07-30-docs-update-readme-architecture.md` claim those two files
  exclusively. This plan needs no edits to either: the `dev/` links in both are already correct, and no
  test filename appears in either document. If you believe a doc edit is required, stop and say so
  rather than editing.
- **`git mv` for every move and rename**, so history is preserved.
- **Behavior must not change.** No collector, graph, CLI, or emitted-property change. The only source
  edits in the whole plan are `pyproject.toml` and `.pre-commit-config.yaml`.
- **Collected-test count is the invariant: 897.** Captured on the 2026-07-30 working tree with
  `.venv\Scripts\python -m pytest --collect-only -q`. It must read **897 tests collected** at the end of
  every task. Renames do not change it; the two concatenations in Task 4 preserve every test body; the
  helper rename in Task 2 removes a module that contributed 0 tests.
- **Do not modify the repository-local `.venv`** (`AGENTS.md` §5). Every command in this plan calls the
  existing binaries directly — `.venv\Scripts\python.exe`, `.venv\Scripts\ruff.exe`,
  `.venv\Scripts\mypy.exe` — because `uv run` would sync the environment. Task 6 runs `uv lock`, which
  edits `uv.lock` only and creates no environment. A side effect: `.venv\Scripts\zensical.exe` will
  linger after Task 6 until Meatbag's next `uv sync`. That is harmless — nothing invokes it.
- **Targeted tests, not the full suite**, for per-task checks (`AGENTS.md` → Tests). Before finishing,
  run the four files `ci.yml` gates on, plus ruff and mypy — see [Final validation](#final-validation).
- **The working tree already carries other people's uncommitted work, and it is moving.** Snapshot taken
  2026-07-30 late afternoon, already drifting within the hour: `README.md`, `ARCHITECTURE.md`,
  `src/openhound_sccm/collectors/registry.py`, `src/openhound_sccm/graph.py`,
  `src/openhound_sccm/models/container.py`, and `tests/smc_container_test.py` modified;
  `TICKETS-BY-STATUS.md`, `.tickets/con-3be4.md`, `.tickets/con-894a.md`, a `cypher_queries/*.json`, and
  two untracked plans (`2026-07-30-docs-update-readme-architecture.md`,
  `2026-07-30-mssql-split-output.md`) present. **Do not revert, stage, or clobber any of it**, and
  **re-run `git status --short` yourself** rather than trusting this list — it is a snapshot, not a
  contract. `tests/smc_container_test.py` is already `*_test.py`, so no rename here touches a modified
  test file.
- **Coordination hazard for Task 4: `src/openhound_sccm/collectors/registry.py` has uncommitted
  changes.** That is the exact module the `registry_current_user` merge pair tests — `get_current_user`
  and `collect_registry`. Before merging those two files, re-run both of them against the current working
  tree and confirm 9 + 1 still pass. If the in-flight `registry.py` edit has changed either function's
  behavior, **stop and report** rather than adjusting a test body to fit: this plan's whole premise is
  that no behavior changes, so a failing test here is somebody else's change to reconcile, not yours.
- **Open a `gtk` ticket before starting.** No ticket covers this cleanup (`gtk list` shows the docs
  refresh as `con-3be4` and nothing for repo cleanup). Per `CLAUDE.md` line 38, create one, then
  regenerate `TICKETS-BY-STATUS.md` — but see the FLAGGED note first: that file is currently untracked
  and was regenerated by the in-flight docs work at 13:44 on 2026-07-30, so coordinate rather than
  racing it.
- **Line numbers in this plan are as of 2026-07-30 and will drift.** Re-locate by the quoted anchor text,
  never by line number alone.

---

## File Structure

| Path | Change | Task |
|---|---|---|
| `tests/test_*.py` (30 non-colliding) | **Rename** → `<name>_test.py` | 1 |
| `tests/__init___test.py` | **Rename** → `tests/models_main_import_test.py` | 1 |
| `tests/per_host_phases_test.py` (0 tests, shared data) | **Rename** → `tests/per_host_phases.py` — no longer collected, no longer name-shadowed | 2 |
| `tests/test_per_host_phases.py` (7 tests) | **Rename** → `tests/per_host_phases_test.py`, claiming the freed name | 2 |
| `tests/ldap_resolved_principals_test.py:209` | **Repoint** import to `tests.per_host_phases` | 2 |
| `tests/per_host_integration_test.py:17` (renamed in Task 1) | **Repoint** import to `tests.per_host_phases` | 2 |
| `tests/per_host_phases_test.py:8` (the renamed 7-test file) | **Repoint** import to `tests.per_host_phases` | 2 |
| `tests/privileged_test.py` (3 tests) | **Fold into** `tests/test_privileged.py`, then delete | 4 |
| `tests/test_privileged.py` (22 tests) | Receives the 3, then **renamed** → `tests/privileged_test.py` | 4 |
| `tests/registry_current_user_test.py` (1 test) | **Fold into** `tests/test_registry_current_user.py`, then delete | 4 |
| `tests/test_registry_current_user.py` (9 tests) | Receives the 1, then **renamed** → `tests/registry_current_user_test.py` | 4 |
| `pyproject.toml` | **Add** `[tool.pytest.ini_options]` with `python_files = "*_test.py"` (Task 5, LAST); **remove** `"zensical>=0.0.27"` from `[dependency-groups] dev` (Task 6) | 5, 6 |
| `docs/javascript/` (`custom.mjs`, `mermaid.mjs`) | **Delete** | 6 |
| `docs/stylesheets/` (`mermaid-custom.css`) | **Delete** | 6 |
| `.pre-commit-config.yaml` | **Remove** `exclude: mkdocs.yml` under `check-yaml`; **remove** `exclude: ^cookiecutter-templates/` under `black` | 6 |
| `uv.lock` | **Re-lock** after dropping `zensical` | 6 |

No `README.md`, `ARCHITECTURE.md`, or `src/` file is edited anywhere in this plan.

---

### Task 1: Rename the 30 non-colliding `test_*.py` files

**Files:**
- Rename: 30 files under `tests/`, per the mapping table below
- Rename: `tests/__init___test.py` → `tests/models_main_import_test.py`

**Interfaces:**
- Produces: the renamed module paths Task 2 repoints imports against. In particular
  `tests/test_per_host_integration.py` becomes `tests/per_host_integration_test.py`; Task 2 edits it
  under that new name.
- Consumes: nothing.

**Why `__init___test.py` gets a real name:** it is a 4-line smoke test asserting that
`openhound_sccm.models` and `openhound_sccm.main` import cleanly (the latter being what registers the
`@app.collect` / `@app.preproc` / `@app.convert` phases). The filename is a cookiecutter accident —
it reads as a test *of* `__init__.py`, which it is not — and it sits next to the real, deliberately empty
`tests/__init__.py` that makes `tests` a package.

- [ ] **Step 1: Capture the baseline count**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
```

Expected: `897 tests collected`. If it is not 897, **stop** — the tree has moved since this plan was
written and every later count assertion is void. Report the number rather than adjusting it silently.

- [ ] **Step 2: Rename the 30 non-colliding files**

This loop renames exactly the non-colliding ones: it computes each destination and skips any whose
destination already exists, which is precisely the definition of the three collisions handled in Tasks 2
and 4.

```powershell
foreach ($f in (git ls-files 'tests/test_*.py')) {
    $base = [IO.Path]::GetFileNameWithoutExtension($f)          # e.g. test_http
    $dest = "tests/$($base -replace '^test_', '')_test.py"      # e.g. tests/http_test.py
    if (Test-Path $dest) { Write-Host "SKIP collision (Tasks 2/4): $f -> $dest"; continue }
    git mv $f $dest
}
```

Expected: 30 renames, and exactly three `SKIP collision` lines naming
`tests/test_per_host_phases.py`, `tests/test_privileged.py`, and `tests/test_registry_current_user.py`.

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

Expected: `897 tests collected`, and the `git ls-files` output is exactly these three lines:

```
tests/test_per_host_phases.py
tests/test_privileged.py
tests/test_registry_current_user.py
```

- [ ] **Step 5: Confirm no import broke**

Only one import target moved in this task — `tests.test_per_host_integration` — and nothing imports it.
This search proves nothing references a now-stale `tests.test_*` module path. Note the
`Get-ChildItem | Select-String` pipe rather than `Select-String -Path`: this is Windows PowerShell 5.1,
whose `-Path` does **not** understand a `**` recursive wildcard (it fails with "Cannot find path").

```powershell
Get-ChildItem -Recurse -Filter *.py -Path tests,src,dev | Select-String -Pattern 'tests\.test_'
```

Expected: no matches. (Before this task there were also none; the three real cross-module imports all
target `tests.per_host_phases_test`, which this task does not move — the same command with
`-Pattern 'tests\.per_host_phases_test'` returns exactly 3 matches, in
`ldap_resolved_principals_test.py:209`, `test_per_host_integration.py:17`, and
`test_per_host_phases.py:8`.)

- [ ] **Step 6: Lint the renamed files**

```powershell
.venv\Scripts\ruff.exe check src tests
```

Expected: `All checks passed!`. Content did not change, so any failure means something other than the
renames — investigate rather than reformatting.

- [ ] **Step 7: Show the diff and ask Meatbag whether to commit**

```powershell
git status --short
git diff --cached --stat
```

Suggested message if approved:

```
chore(tests): rename 30 test_*.py to the *_test.py convention

Also renames the __init___test.py smoke test to models_main_import_test.py,
which is what it actually asserts (openhound_sccm.models and .main import
cleanly, the latter registering the collect/preproc/convert phases).

Pure renames via git mv; no test body changed. Collected count unchanged
at 897. The three name collisions are handled separately.
```

---

### Task 2: Untangle `per_host_phases` — helper out of the test namespace, real test into the freed name

**Files:**
- Rename: `tests/per_host_phases_test.py` → `tests/per_host_phases.py`
- Rename: `tests/test_per_host_phases.py` → `tests/per_host_phases_test.py`
- Modify: `tests/ldap_resolved_principals_test.py:209`
- Modify: `tests/per_host_integration_test.py:17` (named `test_per_host_integration.py` before Task 1)
- Modify: `tests/per_host_phases_test.py:8` (the file that arrives from `test_per_host_phases.py`)

**Interfaces:**
- Consumes: Task 1's rename of `test_per_host_integration.py` → `per_host_integration_test.py`.
- Produces: module `tests.per_host_phases` exporting `PER_HOST_PHASES: tuple[Phase, ...]` and
  `all_table_names(phases: Sequence[Phase]) -> list[str]`. These are the same objects at the same names —
  only the module path changes.

**Background — why this is not a merge.** `tests/per_host_phases_test.py` defines **no tests at all**. It
is 31 lines of shared data: the `PER_HOST_PHASES` tuple (the ordered SCCM per-host phases, whose names
double as the `--collection-methods` gating tokens) and the `all_table_names()` helper. pytest collects it
today only because its name matches the default `*_test.py` glob, and collects zero items from it. Three
other test files import it. Meanwhile `test_per_host_phases.py` holds the real 7 tests — and imports the
helper too. Renaming the helper to a non-test name resolves the clash with no test body touched, and
removes the exact fragility the 2026-07-24 plan warned about: after Task 5 pins `python_files`, a
`*_test.py` file that other tests import is a module pytest inserts into `sys.modules` under its own
rules, which can collide with a plain import of the same path.

- [ ] **Step 1: Move the helper out of the test namespace, then move the real test in**

Order matters — the first rename frees the name the second one claims.

```powershell
git mv tests/per_host_phases_test.py tests/per_host_phases.py
git mv tests/test_per_host_phases.py tests/per_host_phases_test.py
```

- [ ] **Step 2: Record why the helper is not named `*_test.py`**

Append to the module docstring of `tests/per_host_phases.py`, so the next agent does not "helpfully"
rename it back. Insert as a new final paragraph inside the existing docstring, before the closing `"""`:

```python
Deliberately NOT named ``*_test.py``: this module holds no tests, only shared
data that other test modules import. ``pyproject.toml`` pins
``python_files = "*_test.py"``, and a collected module that is also imported by
name is a ``sys.modules`` collision waiting to happen.
```

- [ ] **Step 3: Repoint the three importers**

`tests/ldap_resolved_principals_test.py` line 209 — note it is indented, inside a function:

```python
    from tests.per_host_phases_test import PER_HOST_PHASES
```

becomes

```python
    from tests.per_host_phases import PER_HOST_PHASES
```

`tests/per_host_integration_test.py` line 17 — module level:

```python
from tests.per_host_phases_test import PER_HOST_PHASES, all_table_names
```

becomes

```python
from tests.per_host_phases import PER_HOST_PHASES, all_table_names
```

`tests/per_host_phases_test.py` line 8 — module level, in the file that just arrived from
`test_per_host_phases.py`. Identical text, identical replacement:

```python
from tests.per_host_phases_test import PER_HOST_PHASES, all_table_names
```

becomes

```python
from tests.per_host_phases import PER_HOST_PHASES, all_table_names
```

- [ ] **Step 4: Verify no stale import path survives**

```powershell
Select-String -Path tests\*.py -Pattern 'per_host_phases_test import' -AllMatches
```

Expected: no matches.

- [ ] **Step 5: Run the three affected files plus the new test file**

```powershell
.venv\Scripts\python.exe -m pytest tests\per_host_phases_test.py tests\per_host_integration_test.py tests\ldap_resolved_principals_test.py -q
```

Expected: all pass, no collection errors. `tests\per_host_phases_test.py` alone must collect **7** tests:

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q tests\per_host_phases_test.py | Select-Object -Last 1
```

Expected: `7 tests collected`.

- [ ] **Step 6: Verify the helper is no longer collected**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q tests\per_host_phases.py | Select-Object -Last 2
```

Expected: `no tests collected`. Worth understanding precisely, because it is easy to over-read: passing a
file explicitly makes pytest import and collect it **regardless** of `python_files` — the glob governs
directory recursion, not named arguments. So this output proves the module holds no tests, and *directory*
recursion is what stops picking it up. Verified against a scratch repo with the Task 5 pin in place: an
explicitly-named non-matching file reports `no tests collected`, while the same directory scanned as a
whole collects only the `*_test.py` file. Then confirm the whole-suite count:

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
```

Expected: `897 tests collected` — unchanged, because the module that stopped being collected contributed
zero tests.

- [ ] **Step 7: Show the diff and ask Meatbag whether to commit**

```
chore(tests): move the shared per-host phase data out of the test namespace

tests/per_host_phases_test.py held no tests -- only PER_HOST_PHASES and
all_table_names(), imported by three test modules. It becomes
tests/per_host_phases.py, which frees per_host_phases_test.py for the real
7-test file (was test_per_host_phases.py) and stops a *_test.py module from
being imported by other tests before the python_files pin lands.

Collected count unchanged at 897.
```

---

### Task 3: Show Meatbag the two genuine merges before touching them

**This task produces no file changes.** It exists because the 2026-07-24 grilling required per-pair
sign-off before any test bodies are combined, and Task 4 combines two pairs. A reviewer can reject Task 4
while approving Tasks 1, 2, 5, and 6 — which is exactly why this is its own gate.

**Files:** none modified. Read-only inspection of four files.

- [ ] **Step 1: Present the `privileged` pair**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q tests\test_privileged.py tests\privileged_test.py | Select-Object -Last 1
Select-String -Path tests\test_privileged.py, tests\privileged_test.py -Pattern '^(def |class |[A-Z_]+ =|import |from )'
```

State to Meatbag:

- `tests/privileged_test.py` — 59 lines, **3 tests**, all `test_user_group_*`. Exercises `_user_group`
  through a stub `_Run` built by a local helper `_stub_run(rows, *, name, site_code)` that returns
  `(run, captured)` and records the class/columns the collector asked for. Imports three names directly:
  `from openhound_sccm.collectors.privileged import _COLLECTIONS, _Run, _user_group`.
- `tests/test_privileged.py` — 320 lines, **22 collected tests** (17 functions, 5 of them parameterized
  over the two `FLAVORS`). Covers the ten collection helpers, both transports' `identify`/`fetch`, and
  the orchestrator. Imports the module aliased: `from openhound_sccm.collectors import privileged as p`.
- **No symbol collides.** `_stub_run` vs `_run`; the larger file also owns `_Ctx`, `_FakeHttp`, `_qint`,
  `_FakeWmi`, `ALL_CLASSES`, `EXPECT_AS`, `_GateCtx`, `_wmi_phase`, `FLAVORS`. No test name appears in
  both.
- Merged total: **25**.

- [ ] **Step 2: Present the `registry_current_user` pair**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q tests\test_registry_current_user.py tests\registry_current_user_test.py | Select-Object -Last 1
```

State to Meatbag:

- `tests/registry_current_user_test.py` — 27 lines, **1 test**. Calls `registry.get_current_user()`
  directly and asserts the emitted row carries both the logged-on user's `object_sid` and the host's
  `host_object_sid`. Local helpers `_FakeProbe` and `_fake_ctx()`.
- `tests/test_registry_current_user.py` — 218 lines, **9 tests**. Goes through
  `registry.collect_registry()` end to end, covering `UserSID` selection by name rather than enumeration
  position, and the Multisite Component Servers absent/empty/populated cases. Local helpers `_Entry`,
  `FakeProbe`, `FakeCtx`, `_run()`, `_site_server()`.
- **No symbol collides** — `_FakeProbe`/`_fake_ctx` vs `FakeProbe`/`FakeCtx` differ. No test name
  appears in both. Different entry points into the same collector, so both are worth keeping.
- Merged total: **10**.

- [ ] **Step 3: Get an explicit per-pair decision**

Ask Meatbag to approve, defer, or reject **each pair separately**. Record the answer in this plan before
starting Task 4. If a pair is rejected, its `test_*.py` file stays — and Task 5 **must not run** until
it is resolved, because pinning `python_files = "*_test.py"` would make that file silently stop being
collected. See the ordering trap in Task 5.

---

### Task 4: Perform the two approved merges

**Files:**
- Modify then rename: `tests/test_privileged.py` → `tests/privileged_test.py`
- Delete: `tests/privileged_test.py` (the 3-test original, after its tests are folded in)
- Modify then rename: `tests/test_registry_current_user.py` → `tests/registry_current_user_test.py`
- Delete: `tests/registry_current_user_test.py` (the 1-test original, after its test is folded in)

**Interfaces:** none — these files export nothing other test module imports.

**Merge direction, and why.** Fold the *smaller* file into the *larger*, then `git mv` the larger onto the
target name. Git's rename detection then attaches history to the 320-line and 218-line files rather than
to the 59-line and 27-line ones, which is where the history is worth keeping.

- [ ] **Step 1: Fold the 3 `_user_group` tests into `tests/test_privileged.py`**

Append to the end of `tests/test_privileged.py`. The three test bodies are copied verbatim from
`tests/privileged_test.py` **except** that `_Run`, `_user_group`, and `_COLLECTIONS` become `p._Run`,
`p._user_group`, and `p._COLLECTIONS` to match the receiving file's aliased import — so no new
module-level import is added:

```python
# --- _user_group, via a stub _Run with canned SMS Provider rows ------------

def _stub_run(rows, *, name="AdminService", site_code="PS1"):
    """Build a _Run whose fetch yields *rows*; records the class it was asked for."""
    captured = {}

    def fetch(cls, columns=None, where=None):
        captured["cls"] = cls
        captured["columns"] = columns
        yield from rows

    run = p._Run(fetch=fetch, name=name, eq="eq", site_code=site_code, ctx=None)
    return run, captured


def test_user_group_collects_sms_r_usergroup_with_name_and_sid():
    """_user_group queries SMS_R_UserGroup and yields user_group rows carrying the
    DOMAIN\\group name (UniqueUsergroupName) and the group SID — the (name, SID)
    pair principal_by_name needs to resolve security_group_name memberships."""
    rows = [{
        "UniqueUsergroupName": "mayyhem\\Domain Users",
        "SID": "S-1-5-21-1-2-3-513",
        "ResourceId": 2080374784,
        "UsergroupName": "Domain Users",
    }]
    run, captured = _stub_run(rows)

    out = list(p._user_group(run))

    assert captured["cls"] == "SMS_R_UserGroup"
    assert len(out) == 1
    table, row = out[0]
    assert table == "adminservice_user_group"
    assert row["unique_usergroup_name"] == "mayyhem\\Domain Users"
    assert row["sid"] == "S-1-5-21-1-2-3-513"
    assert row["source"] == "AdminService-SMS_R_UserGroup"
    assert row["source_site_code"] == "PS1"


def test_user_group_table_prefix_follows_transport():
    """WMI transport must produce wmi_user_group (table prefix = run.name.lower())."""
    run, _ = _stub_run(
        [{"UniqueUsergroupName": "mayyhem\\Domain Admins", "SID": "S-1-5-21-1-2-3-512"}],
        name="WMI",
    )
    table, _row = list(p._user_group(run))[0]
    assert table == "wmi_user_group"


def test_user_group_registered_in_collections():
    """The resource must be wired into the shared collection set so both
    transports actually run it."""
    assert p._user_group in p._COLLECTIONS
```

Then extend the receiving file's module docstring so it still describes its whole contents. The existing
docstring ends `Transport-neutral row shaping (``_snake``/``_row``/``_prop``) is covered in
``test_sms_rows.py``.` — two edits there: correct that filename, which Task 1 renamed, and note the folded
tests. Replace that closing sentence with:

```
Transport-neutral row shaping (``_snake``/``_row``/``_prop``) is covered in
``sms_rows_test.py``. The ``_user_group`` tests at the end use their own
``_stub_run`` stub, folded in from the former ``privileged_test.py``.
```

- [ ] **Step 2 (optional, sign-off required): consolidate `_stub_run` onto `_run`**

`_run(name, eq, pages, principal=None, calls=None)` already records `(class_name, columns, where)` into
its `calls` list, which is what `_stub_run`'s `captured` dict does. The two differ in one respect that
matters: `_stub_run` passes `ctx=None` while `_run` passes `ctx=_Ctx(principal=principal)`. Collapsing
them is a genuine simplification (`CLAUDE.md`: "Take opportunities to simplify code and remove
unnecessary code") but it changes what the three folded tests exercise, so it is **not** part of the
behavior-preserving merge. If Meatbag wants it: rewrite the three tests to use
`_run("AdminService", "eq", {"SMS_R_UserGroup": rows}, calls=calls)`, delete `_stub_run`, and require all
three to pass unchanged. If any fails, `_user_group` depends on `ctx` being `None` — keep `_stub_run` and
leave a comment saying so. **Default: skip this step**, and raise the overlap as a follow-up ticket.

- [ ] **Step 3: Verify the privileged merge, then take the name**

```powershell
.venv\Scripts\python.exe -m pytest tests\test_privileged.py -q
.venv\Scripts\python.exe -m pytest --collect-only -q tests\test_privileged.py | Select-Object -Last 1
```

Expected: all pass; `25 tests collected` (22 + 3).

```powershell
git rm tests/privileged_test.py
git mv tests/test_privileged.py tests/privileged_test.py
.venv\Scripts\python.exe -m pytest tests\privileged_test.py -q
```

Expected: 25 pass.

- [ ] **Step 4: Fold the 1 test into `tests/test_registry_current_user.py`**

Append to the end of `tests/test_registry_current_user.py`, copied verbatim from
`tests/registry_current_user_test.py`. The receiving file already has
`from openhound_sccm.collectors import registry`, so only `types` is a new import — add
`import types` above that existing import line, and drop the incoming file's stale line-1 comment
(`# src/openhound_sccm/collectors/registry_current_user_test.py`, a path that does not exist — the file
is in `tests/`):

```python
# --- get_current_user called directly ------------------------------------------

class _FakeProbe:
    hostname = "host1.lab"
    def read_values(self, _key):
        return [("UserSID", "S-1-5-21-1-2-3-1106"), ("Session", 1)]


def _fake_ctx():
    host_obj = {"name": "HOST1", "object_sid": "S-1-5-21-1-2-3-1104"}
    user_obj = {"sam_account_name": "alice", "object_sid": "S-1-5-21-1-2-3-1106"}
    ctx = types.SimpleNamespace()
    ctx.resolve_principal = lambda sid: dict(user_obj)
    ctx.target_hosts_by_hostname = {"host1.lab": types.SimpleNamespace(ad_object=host_obj)}
    return ctx


def test_current_user_row_has_host_object_sid():
    rows = list(registry.get_current_user(_FakeProbe(), _fake_ctx()))
    assert len(rows) == 1
    table, row = rows[0]
    assert table == "remoteregistry_users"
    assert row["object_sid"] == "S-1-5-21-1-2-3-1106"        # the logged-on user
    assert row["host_object_sid"] == "S-1-5-21-1-2-3-1104"   # the host it logged onto
```

Then extend that file's module docstring, which currently describes only the `collect_registry` paths, by
appending a final paragraph before the closing `"""`:

```
The final test calls ``get_current_user`` directly rather than through
``collect_registry``, with its own ``_FakeProbe``/``_fake_ctx`` stubs — folded in
from the former ``registry_current_user_test.py``.
```

Note the deliberate coexistence of `_FakeProbe`/`_fake_ctx` (direct-call stubs) and
`FakeProbe`/`FakeCtx` (whole-`collect_registry` stubs). They are not duplicates: the underscore-prefixed
pair is minimal on purpose, and merging them would drag the direct-call test through the full collector.

- [ ] **Step 5: Verify the registry merge, then take the name**

```powershell
.venv\Scripts\python.exe -m pytest tests\test_registry_current_user.py -q
.venv\Scripts\python.exe -m pytest --collect-only -q tests\test_registry_current_user.py | Select-Object -Last 1
```

Expected: all pass; `10 tests collected` (9 + 1).

```powershell
git rm tests/registry_current_user_test.py
git mv tests/test_registry_current_user.py tests/registry_current_user_test.py
.venv\Scripts\python.exe -m pytest tests\registry_current_user_test.py -q
```

Expected: 10 pass.

- [ ] **Step 6: Confirm zero `test_*.py` remain and the count held**

```powershell
git ls-files 'tests/test_*.py'
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
.venv\Scripts\ruff.exe check src tests
```

Expected: `git ls-files` returns **nothing**; `897 tests collected`; ruff clean.

- [ ] **Step 7: Show the diff and ask Meatbag whether to commit**

```
chore(tests): merge the two genuine *_test.py name collisions

privileged_test.py (3 _user_group tests) folds into test_privileged.py
(22 tests) -> privileged_test.py, 25 total. registry_current_user_test.py
(1 direct get_current_user test) folds into test_registry_current_user.py
(9 collect_registry tests) -> registry_current_user_test.py, 10 total.

Merged into the larger file in each pair so git keeps the history that
matters. No symbol collided; no test body changed beyond p.* prefixes on
the three folded privileged tests. Also fixes a stale test_sms_rows.py
docstring reference and a bogus src/ path comment. Count unchanged at 897.
```

---

### Task 5: Pin the test-file convention — **do this LAST of the test tasks**

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
warning, just a lower count. That is why this task runs after Tasks 1, 2, and 4, and why the check above
is a hard gate rather than a note.

- [ ] **Step 2: Add the pin**

Append to `pyproject.toml`. Put it after the `[tool.mypy]` block and its overrides — i.e. at the end of
the file — so it sits with the other tool configuration rather than splitting the mypy overrides:

```toml
[tool.pytest.ini_options]
# Pinned to the *_test.py suffix only. pytest's default also accepts the test_*.py
# prefix; allowing both is what let the suite drift into two conventions at once.
# A consequence worth knowing: a file named test_something.py is now silently NOT
# collected, so a new test added under the old prefix would pass by not running.
python_files = "*_test.py"
```

- [ ] **Step 3: Verify the pin collects exactly what it did before**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
```

Expected: `897 tests collected`. Because Tasks 1–4 left zero `test_*.py` files, narrowing the glob must
change nothing — if the number drops, a file was missed and the check in Step 1 was run against a stale
tree.

- [ ] **Step 4: Confirm the helper module is still excluded and still importable**

```powershell
.venv\Scripts\python.exe -m pytest tests\per_host_phases_test.py tests\per_host_integration_test.py tests\ldap_resolved_principals_test.py -q
```

Expected: all pass. This is the check that the pin did not break the `tests.per_host_phases` import that
Task 2 created.

- [ ] **Step 5: Show the diff and ask Meatbag whether to commit**

```
chore(tests): pin python_files to the *_test.py convention

pytest's default accepts both test_*.py and *_test.py, which is how the suite
ended up running two conventions at once. Now that every file uses the suffix
form, pin it. Collected count unchanged at 897.
```

---

### Task 6: Retire the never-completed documentation-site scaffolding

**Files:**
- Delete: `docs/javascript/custom.mjs`, `docs/javascript/mermaid.mjs`
- Delete: `docs/stylesheets/mermaid-custom.css`
- Modify: `pyproject.toml` — remove `"zensical>=0.0.27"` from `[dependency-groups] dev`
- Modify: `.pre-commit-config.yaml` — remove two excludes naming files this repo does not have
- Modify: `uv.lock` — regenerate

**Interfaces:** none.

**Independent of Tasks 1–5.** Nothing here touches tests, so this task can run before, after, or beside
them.

**Evidence that this is scaffolding, not a working site.** There is no `mkdocs.yml` and no
`zensical.toml` — not in this repo and not in the monorepo it split from (`find` across both returns only
`.venv` binaries). `docs/` has no `index.md`; its only top-level page is
`per-host-collection-framework-tour.md`. `zensical` appears nowhere outside `pyproject.toml` and
`uv.lock`. The only thing referencing the assets is `docs/javascript/custom.mjs:100`, which points at
`/stylesheets/mermaid-custom.css` — the assets referencing each other, with no page loading either. And
`.pre-commit-config.yaml` excludes `mkdocs.yml` from `check-yaml`, which is independent evidence a site
config was intended and never committed.

- [ ] **Step 1: Re-confirm nothing outside the assets references them**

```powershell
Select-String -Path *.md, *.toml, *.yaml, .github\workflows\*.yml -Pattern 'custom\.mjs|mermaid\.mjs|mermaid-custom\.css|zensical|mkdocs' -AllMatches
```

Expected: exactly one match — `"zensical>=0.0.27"` in `pyproject.toml` — plus the
`exclude: mkdocs.yml` line in `.pre-commit-config.yaml`. If a `mkdocs.yml` or `zensical.toml` has
appeared since 2026-07-30, **stop**: a site now exists and this task is wrong.

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

Both name paths that do not exist in this repo; both are inherited cookiecutter/monorepo residue, the same
class of artifact the split already removed in dropping `extension.yaml` and `src/main.py`.

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

There is no `cookiecutter-templates/` directory here. **Flag to Meatbag:** this second removal was
surfaced during the 2026-07-30 grilling but the locked decision named only the `mkdocs.yml` exclude — drop
this half of the step if you would rather keep the change minimal.

- [ ] **Step 5: Re-lock**

```powershell
uv lock
```

Expected: `uv.lock` shrinks — the `zensical` entry and its `mkdocs`, `mkdocs-autorefs`,
`mkdocs-get-deps` transitive tree drop out. `uv lock` writes only the lockfile; it does not create or
sync an environment, so the repository-local `.venv` is left alone per `AGENTS.md` §5.

```powershell
git diff --stat uv.lock
Select-String -Path uv.lock -Pattern 'zensical' -AllMatches
```

Expected: `uv.lock` modified; no `zensical` matches remain.

- [ ] **Step 6: Verify nothing broke**

```powershell
.venv\Scripts\python.exe -m pytest --collect-only -q | Select-Object -Last 1
.venv\Scripts\ruff.exe check src tests
.venv\Scripts\mypy.exe src\openhound_sccm
```

Expected: `897 tests collected`; ruff clean; mypy as clean as it was before this task (record the
before/after if it reports anything, since none of these edits can affect it). Note that
`.venv\Scripts\zensical.exe` still exists — the plan deliberately does not sync the venv. It becomes
unreachable at Meatbag's next `uv sync`.

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

## FLAGGED for manual verification (no auto-action in this plan)

Surfaced for Meatbag to decide. Two of these correct claims the 2026-07-24 plan got wrong, because the
repo changed underneath them.

- **`TICKETS-BY-STATUS.md` is untracked.** The file **does** exist (20,829 bytes, header says "Generated
  from `gtk list --json`", reports 116 tickets), and it was regenerated at 13:44 on 2026-07-30 —
  almost certainly by the in-flight docs work, which created ticket `con-3be4`. But `git status` shows it
  as `??`. It has never been committed, which means the `TICKETS-BY-STATUS.md merge=ours` attribute in
  `.gitattributes` is currently inert: git cannot apply a merge driver to a file it does not track.
  Committing it is Meatbag's call, and coordinating with `con-3be4` matters more than winning a race to
  regenerate it. `.gitattributes` also documents the one-time `git config merge.ours.driver true` each
  clone needs, since `.git/config` is not committable.
- **~~`docs/proposals/` is unreferenced and probably prunable~~ — WRONG as of 2026-07-30. Do not
  prune.** `ARCHITECTURE.md` line 759 links
  `docs/proposals/2026-06-16-convert-read-from-duckdb.md` and line 786 links
  `docs/proposals/2026-06-16-computer-node-multi-driver-merge.md`;
  `docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md` cites the first at lines 271 and
  488, and the two proposals cross-reference each other. Deleting them would break live documentation
  links — and `ARCHITECTURE.md` is currently owned by `con-3be4`. If they really are implemented and you
  want them gone, that is a docs-plan change, not a cleanup-plan change.
- **Possibly-stale lab scripts in `dev/`, referenced by no live doc:** `debug_smb_auth.py`,
  `debug_wmi_auth.py`, `tour_driver_stage0.py`, `tour_driver_stage2.py`, `tour_driver_stage3.py`. Only
  `debug_per_host.py`, `debug_epa_matrix.py`, `spike_smb_sso.py` (README lines 1821–1823,
  ARCHITECTURE lines 297–301), `tour_driver_stage1.py` (ARCHITECTURE line 705), and
  `spike_socks_proxy.md` (ARCHITECTURE line 1740) are doc-cited. All five unreferenced ones are cited by
  closed tickets as having done real validation work (`debug_smb_auth.py` in `ope-4483`,
  `debug_wmi_auth.py` in `ope-1f49`/`ope-38ad`), so "unreferenced by docs" is not "unused". Confirm you
  no longer need them before pruning.
- **pre-commit runs `black`; CI runs `ruff`.** `.pre-commit-config.yaml` pins `black` 25.12.0 while
  `.github/workflows/ci.yml:29` runs `ruff check src tests`. Two formatters with different opinions over
  one tree, and the `ruff` dependency is deliberately capped below 0.16 because that release widened the
  default rule set (see the comment in `pyproject.toml`). This is a tooling-policy decision, not cruft —
  which is why it is a flag and not a task. Worth resolving deliberately rather than discovering it
  through a surprising diff.
- **No `gtk` ticket covers this cleanup.** `gtk list` shows 116 tickets, none about repo cleanup
  (`ope-1f0f`, "Code-Quality Pass", is the nearest and is about logging/exception/scope quality across
  the collector, not file layout). `CLAUDE.md` line 38 requires ticket tracking for requested work, so
  open one before implementing — and see the `TICKETS-BY-STATUS.md` flag above before regenerating that
  file.

## Explicitly OUT of scope

- **`README.md` and `ARCHITECTURE.md`** — owned by ticket `con-3be4` and plan
  `docs/superpowers/plans/2026-07-30-docs-update-readme-architecture.md`, in progress. This plan is
  written to need zero edits to either.
- **`sccm/tests/live-comparison/` report consolidation** — those files live in the OpenHound monorepo
  now (`OpenHound\sccm\tests\live-comparison\`). Original Task 6, retired here.
- **The `sccm/sccm/...` paths in `.tickets/*.md` and `docs/superpowers/plans/*.md`** — dated historical
  records of work done when the collector lived in the monorepo. Leave them. Rewriting a record to
  match today's layout destroys the record. (The 2026-07-24 plan made the same call about the
  `ARCHITECTURE.md` changelog prose.)
- **`powershell_deprecated/`** — the PowerShell predecessor and its own test kit, deliberately retained
  and cited by `ARCHITECTURE.md` line 1758. Its five `sample_data/*.zip` fixtures are intentional, not
  the build artifact the original plan deleted.
- **`openhound-collector-common`** — a separate published package and repository
  (`..\openhound-collector-common`). `AGENTS.md` is explicit: trace into it to understand behavior, never
  edit it as part of a change here.
- **`cypher_queries/`** — now tracked (18+ saved BloodHound queries), with one untracked addition in the
  working tree. Active work, not cruft. The original plan listed it as out-of-scope-because-untracked;
  it is now out of scope because it is real content.

## Execution order & final validation

1. **Baseline first.** `.venv\Scripts\python.exe -m pytest --collect-only -q` must read
   **897 tests collected** before any change. If it does not, stop and report.
2. **Task 1** (30 renames + the smoke-test rename) → count still 897.
3. **Task 2** (helper out of the test namespace, real test claims the name, 3 imports repointed) →
   count still 897.
4. **Task 3** (present both merges, get per-pair sign-off) → no file changes.
5. **Task 4** (perform the approved merges) → count still 897, and `git ls-files 'tests/test_*.py'`
   returns nothing.
6. **Task 5** (pin `python_files`) — **only** after step 5's `git ls-files` check is empty.
7. **Task 6** (retire the docs-site scaffolding) — independent; may run at any point.

**Final validation.** Run the four files `ci.yml` gates on, since those are what a pull request has to
pass, plus both linters (`AGENTS.md` → Tests):

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

Expected: **897 tests collected.** That number is the whole proof of this plan — 30 renames, one helper
extraction, two merges, and a narrowed collection glob, with not a single test lost along the way.

**Not required:** a live-lab run. No collector, client, or transform code is touched, so there is nothing
a live SCCM hierarchy would exercise that the offline suite does not.
