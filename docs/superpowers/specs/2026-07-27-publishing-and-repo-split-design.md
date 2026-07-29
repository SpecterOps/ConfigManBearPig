# Design: publishing the collectors to PyPI

**Date:** 2026-07-27, simplified and re-reviewed 2026-07-29 · **Status:** decided

This records **why** the publishing setup looks the way it does. Everything you *run* is in
[`../../../PUBLISHING.md`](../../../PUBLISHING.md).

An earlier version of this document was 483 lines, paired with a 1,740-line task plan that restated
most of it. A review found five factual errors, every one of them a case of "the two copies disagree" —
including a step that would have made OpenHound reject the extension's metadata at startup. Both files
were collapsed into `PUBLISHING.md` plus this record. **That collapse is itself a design decision: with
one developer, duplicated documentation is a defect source, not redundancy.**

A second review the same day found the collapse had missed two copies. The first was the shared
library's checkout location, described one way in the runbook (`~/Desktop/dev/…`) and another in the two
`[tool.uv.sources]` fixes that depend on it — leaving both paths pointing at a directory that would
never exist. The second was the comment blocks inside `sccm/sccm/pyproject.toml`, which still described
a `just dev` workflow that had been deleted, including an instruction not to add the very
`[tool.uv.sources]` table sitting forty lines below it. **The lesson generalises: a comment that
restates a design decision is a copy of that decision, and it rots exactly like a duplicated document.**
State constraints in comments; leave rationale here.

## Goal

Three directories that only worked inside one checkout become published packages, so a new user runs:

```bash
uv tool install openhound --with configmanbearpig
```

| Package | PyPI | Home | Version |
|---|---|---|---|
| SCCM collector | `configmanbearpig` | `SpecterOps/ConfigManBearPig` (Python at root of `main`, PowerShell → `powershell_deprecated/`) | `2.0.0` |
| Shared library | `openhound-collector-common` | `Mayyhem/openhound-collector-common` (new) | `0.1.0` |
| MSSQL collector | `mssqlhound` | `SpecterOps/MSSQLHound`, deferred until feature-complete | `3.0.0` |

## Decisions that outlive execution

**Three different names, deliberately.** Distribution `configmanbearpig`, import package
`openhound_sccm`, CLI verb `sccm`. The verb names the *data source*, matching every other OpenHound
collector (`jamf`, `okta`, `github`). Renaming the import package would churn ~40 test modules for no
user-visible gain.

**Apache-2.0 everywhere, and this one is not a preference.** The shared library was factored out of the
SCCM collector, itself a port of the Apache-2.0 `ConfigManBearPig.ps1`. Apache-2.0 does not permit
silently re-labelling derived work, so the library's original `license = "MIT"` (with no license text
shipped at all) was simply wrong. The MSSQL extension carries the identical defect — `license = "MIT"`,
no `LICENSE` file, in a port of the Apache-2.0 MSSQLHound — and is corrected now rather than at its
release, because a misstatement of terms is wrong while it sits in the tree, not only when it is
uploaded.

**The shared-library dependency is a version range, never a path.** `[project.dependencies]` carries
`openhound-collector-common>=0.1.0,<0.2.0` — that is what lands in wheel METADATA and what users
resolve. A `[tool.uv.sources]` table may sit alongside it as a **local redirect**: uv-only, never built
into the wheel. The cap exists because a `0.x` library makes no API-stability promise; a breaking `0.2`
should require an explicit bump, not arrive silently.

**`openhound` is declared, with a floor and no cap.** The collector imports a dozen openhound modules
and hand-registers commands on its Typer objects, so it genuinely depends on the framework — unlike
`openhound-jamf`, which uses only the public decorator surface and declares no dependencies at all.
It gets `openhound>=0.2.12` once validated against that version. No upper bound: an invented cap
guarantees a re-release the day 0.3.0 ships. If a future version breaks the hand-registration, a version
check in `main.py` with a clear message is more honest than a guessed resolver bound.

**"Validated" means a live collect, not a green test run.** Eleven releases separate the version this was
built against from the version PyPI serves. The offline suite and `collect sccm --help` / `convert sccm --help`
prove the extension still *binds* — the entry point resolves, the hand-registered Typer commands attach,
`app.converter` is assignable. None of that reaches the thing most likely to have moved underneath a
framework minor bump: how openhound drives the preprocess and convert stages, which is where this
collector does nearly all of its work and where a change produces a different graph rather than an
exception. So step 1's gate is the offline tests plus a full `--run-all` against the lab, with node and
edge counts compared to the 0.1.4 baseline. The distinction being drawn is between "it loads" and "it
still produces the same graph", and only the second one is what a user gets.

The dev group's `openhound @ git+…` entry is **deleted** rather than restated as a range, because a
direct reference outranks a version range during resolution. Keeping both would have meant local runs
silently testing an unpublished commit while users resolved 0.2.12 — reintroducing the exact
developer-only divergence that made the schema-path bug ship.

**Any runtime data file must live inside `src/openhound_sccm/`.** The wheel ships only that directory.
`extension.yaml`, `schema_SCCM.json`, and `schema_MSSQL.json` were resolved with
`Path(__file__).resolve().parents[2]` — correct in a checkout, and pointing *above* `site-packages`
once installed. Result: `-B/--bloodhound` upload raised `FileNotFoundError` for every user who
installed from an index, while working perfectly for the developer. It survived because
`extension.yaml` was already correctly placed and is the one file OpenHound validates loudly on every
run; the two that failed did so silently, on a path only the upload flow touches. The SCCM release
workflow now asserts all three are present in the built wheel. The shared library has no release-time
data-file check because it has no runtime data files.

**Wheel assertions belong in the release workflow, not in a pre-flight you run by hand.** The checks
that matter — data files present, entry point registered, no local path leaked into METADATA — began as
an eleven-line snippet in the runbook, complete with a paragraph explaining why it had to be piped to
stdin rather than passed as `python -c` (PowerShell strips quotes from multi-line arguments to native
executables). Moved into `release.yml`, they run *before* `uv publish` on every release forever, and a
failure aborts the job instead of consuming a version number. That is strictly safer than a manual
check and strictly shorter, which is a rare combination — when it appears, take it.

**CI provisions its own interpreter; the `only-system` preference is never loosened.** That setting
exists for a Windows-only bug — uv's bundled CPython ships a `libcrypto` lacking the `OPENSSL_Applink`
shim, so any TLS handshake aborts the process — and its comment described it as "harmless on Linux".
Harmless for TLS; not harmless for interpreter *discovery*, which is the other thing it controls.
`requires-python` is `>=3.13,<3.15`, `ubuntu-latest`'s system Python is 3.12, and 3.13 sits in the
runner's tool cache off `PATH`. Verified locally that the preference makes uv fail rather than fall back:
`error: No interpreter found for Python >=3.99 in virtual environments, search path, or registry`. So
`uv build` in CI had nothing it was permitted to use.

The fix is `actions/setup-python` in each workflow, chosen over two cheaper-looking alternatives:

| Alternative | Why not |
|---|---|
| Relax to `python-preference = "system"` (prefer system, fall back to managed) | One word, fixes CI, and the dev machine keeps picking its own 3.13 — until the day it does not. Then uv silently downloads a managed CPython and the collector aborts mid-TLS-handshake against a live SCCM server. The `only-` prefix is what converts that into a startup error, and the failure it guards against is bad enough to keep the hard guarantee. |
| `UV_PYTHON_PREFERENCE: managed` as a job-level env var in CI | Two lines, but platform-blind: add a Windows job or a matrix later and it inherits the override, reintroducing the exact bug. That is the original mistake in reverse — a setting whose blast radius is wider than the reasoning behind it. |

`setup-python` wins on a second count that has nothing to do with this bug: CI should pin the interpreter
that builds a wheel regardless, so it is the fix that would be right even if the preference did not exist.
The same block goes in `ci.yml`, which means the first pull request proves it before any tag is pushed.

The shared library had no `[tool.uv]` section at all, so its release workflow was never broken — but it
also had no Windows protection, and it is the half of the codebase doing TLS-sensitive work (BloodHound CE
HTTPS, TDS with EPA channel binding, LDAPS). It borrowed the collector's preference for as long as it was
a path dependency inside one venv; becoming its own repo silently ends that. It gets its own copy, added
before the archive rather than after, since `git archive` reads `HEAD`.

**The shared library becomes testable in its own right, which reverses the `ci.yml` decision.** The same
"it borrowed the collector's venv" observation applies to something larger than a uv preference: the
library has no `[dependency-groups]` at all. Every one of its tests has only ever run through the
collector's interpreter, which works because `[tool.uv.sources]` installs the library editable there. The
moment it is a repo of its own, `uv sync --group dev` errors and `uv run pytest` finds no pytest — tests
present in the tree and reachable only by pointing another project's venv at them.

It gets a `dev` group (pytest, ruff, mypy) and, reversing the table entry below, a `ci.yml`. The original
rejection rested on "four offline tests"; there are **21 test files and 108 tests**, covering the
BloodHound CE client and uploader, the zip and schema builders, DuckDB safety, the SOCKS proxy and its
monkey-patch, MSSQL TDS decoding, DNS TCP fallback, log context, orchestration, and the seven-module
integration harness. That is not an appendix to the collector's suite — it is the test surface for every
network and auth path both collectors depend on, and it is where a regression would be least visible,
because neither collector's own suite exercises the library directly.

The asymmetry the original entry defended still holds, but it is an asymmetry of *scope*, not of
existence: the collector's `ci.yml` runs a curated list of files known to pass without a lab, because most
of its suite needs one. The library's runs `pytest tests` entire, because none of its tests do — verified
green at 108 passed before the workflow was written, since a `ci.yml` that has never been run is a guess.

**Both `ci.yml` files lint `src` and `tests`, which required clearing lint debt neither package knew it
had.** Writing the workflows exposed that `ruff` has never been enforced in either package: it is declared
in the collector's dev group and documented in the runbook's command table, but the pre-commit config runs
`black` and the standard hooks, with no ruff hook at all. Measured at the point the workflows were added:
**27 errors in the collector (every one in `tests/`; `src/` was already clean) and 23 in the library (5 in
`src/`, 18 in `tests/`)** — unused imports, semicolon-joined statements, imports below module level, one
unused local. A `ci.yml` running `ruff check src tests` would therefore have been red on its first run in
both repos, which is worse than having no lint step: it is the state that teaches a contributor to ignore
CI on their first pull request.

All 50 were fixed by hand rather than with `ruff check --fix`, and the reason is worth recording because
it generalises past this cleanup. `tests/test_bloodhound_exports.py` consists of a single test whose entire
purpose is asserting that eight names are importable from `openhound_collector_common.bloodhound`. Ruff
correctly reports seven of them as unused — they are named, not called — so `--fix` would have deleted
them and left a test that asserts one unrelated thing, still green, no longer checking the published API
surface of a library about to be published. **An automated fix for an unused import cannot distinguish
dead code from a contract being asserted by its mere presence**, and the failure is invisible: the suite
stays green, so nothing tells you the check is gone. Those imports carry a `# noqa: F401` explaining what
they are for.

**The general lesson: a setting justified by one platform's bug still applies everywhere, and it surfaces
in the environment nobody runs interactively.** The comment made it worse by recording the motivation
("Windows TLS") instead of the constraint ("no environment may download an interpreter"), so the reader
who needed the warning had no way to see it applied to them.

**`extension.yaml` must keep `version`, `credentials`, and `parameters`.** They look like cookiecutter
filler but all three are **required** fields on OpenHound's pydantic model (`Extension` in
`openhound/core/models/extension.py`, in the framework — not this repo) with no defaults. Removing them
makes `Extension.from_yaml` raise `ValidationError` on every run. Fill them in with truthful values
instead.

**The tag gates the publish, so a branch cannot.** This is the fact that settles the recurring
"shouldn't we stage this on a branch and test before promoting?" question. `release.yml` fires on
`refs/tags/v*`; a tag can be created on any commit on any branch, and creating one is the single
irreversible act in the whole process. So the control that protects you is "do not tag until the
rehearsal passes" — the runbook's git-URL install rehearsal, which behaves identically whether the tree
sits on `main` or on a branch. A branch changes *who can see a half-migrated repo*, which is a presentation property, not a
safety property. Both are legitimate wants; conflating them leads to a staging branch that feels like
insurance and insures nothing.

Worse than neutral, in fact: **a branch adds a way to make the irreversible mistake.** A tag lands on
whatever `HEAD` you happen to be on. With a branch there are two commits a `v2.0.0` tag could point at,
and picking the wrong one publishes from the branch and leaves `main` permanently behind whatever went to
PyPI. On `main` alone there is exactly one candidate, and the class of error disappears. A second, milder
trap is specific to branch-thinking: restricting the `pypi` environment's *Deployment branches and tags*
to a branch name will not authorize a tag-triggered run, and the resulting failure does not name the
cause. (An earlier draft treated that as an argument against branching; it is really an argument against
one specific misconfiguration, and the fix is to leave the setting unrestricted or add the tag pattern.)

What `main`-only genuinely costs is worth stating rather than glossing. **The rehearsal cannot happen
before the push**, because it installs from the repository's git URL — so there is a window, bounded by
one install and one collect run, in which `main` holds a restructure that has not yet been proven through
the real user path. Closing that window is the only thing a branch buys. It is acceptable here because
nothing is on PyPI yet, so no installing user can reach the repo by accident; because `ConfigManBearPig`
has no open pull requests, so no in-flight contribution can be orphaned; and because the artefact people
actually arrive for — the PowerShell script — has a permanent tagged URL and Release before anything
moves. If the rehearsal fails, the response is to fix forward with another commit, not to unwind.

Revert difficulty changes at exactly one point, the first push. Before it, everything is local and
`git reset --hard origin/main` is a complete undo — the same recovery a discarded branch offers, without
a branch to manage. After it, `git revert` restores the content as a visible commit, or a force-push
erases it (`main` is unprotected and single-writer, so this is safe though it does rewrite public
history). Either way the pristine PowerShell tree stays permanently reachable at `v1.2-powershell`, which
is the property that made the branch dispensable in the first place.

**Releases are tag-driven Trusted Publishing.** Pushing a `v*` tag runs
`.github/workflows/release.yml`, which builds, asserts the built version matches the tag, asserts the
data files are in the wheel, and publishes via OIDC. No API token exists to leak. The version comes
from the tag via `hatch-vcs`, with `local_scheme = "no-local-version"` because PyPI rejects any version
carrying a `+local` segment — which is exactly what setuptools-scm produces on a non-tag commit.

**Both public repos receive a tree, not a history.** `git archive -o <file>.tar HEAD:<prefix>` followed
by `tar -xf` writes exactly the files git tracks at that prefix. Three properties follow, and together
they outweigh 106 commits of blame in a repo nobody else works in:

- *Nothing unintended travels.* `sccm/sccm/` currently also holds `.venv/`, three `.duckdb` files,
  `logs/`, `output/`, `out/`, and `__pycache__/`. A recursive file copy carries all of them; an archive
  of tracked files cannot.
- *No credentials travel **from the history**.* Commits `bcb1243` and `46c4114` contain
  `_LAB_PASSWORD = "password"` and the NTLM hash of that string, from before the debug scripts were moved
  to environment variables. The values are worthless, but a tree copy removes the question rather than
  answering it.

  The emphasis is a correction. This property was originally written as "no credentials travel" flat, and
  that overstated it: the archive governs only what git tracks under the two prefixes. Step 8 *also*
  copies `.tickets/` with `Copy-Item`, and one ticket recorded its integration-test lab connection as a
  literal `USER=… PASSWORD=… NTHASH=… KDC=…` tuple — into a public repo, past a safety argument that
  never applied to it. Scrubbed in step 3. **A safety property proven for one mechanism does not transfer
  to a different mechanism moving the same data**, and the argument's own confidence is what hid the gap:
  a section headed "no credentials travel" is where you stop looking for credentials.
- *No merge, so no conflict predictions to get wrong.* The rejected approach — `git subtree split` then
  `git pull --allow-unrelated-histories` — came with a table predicting five add/add conflicts. Checked
  against both real trees, two of the five could not occur (the collector's `powershell_deprecated/`
  holds no `.ps1`, and its `README.md` there has no counterpart on `main`), and the duplicate
  `cypher_queries/` was attributed to the wrong side. If the conflict set cannot be predicted correctly
  while reading both trees at leisure, it will not be pleasant to resolve live.

The history is not lost: it stays in the fork on `origin/integration` and under the
`pre-split-2026-07-29` tag. Because `git archive` reads `HEAD`, the one new requirement is that
everything intended to travel is *committed* first — an uncommitted file is simply absent, with no
warning.

**The two new repos are siblings of the fork on the Desktop.** `~/Desktop/OpenHound`,
`~/Desktop/openhound-collector-common`, `~/Desktop/ConfigManBearPig`. This is load-bearing rather than
tidy: `[tool.uv.sources]` paths are resolved relative to the `pyproject.toml` that declares them, so the
layout decides whether `../openhound-collector-common` (from the collector repo) and
`../../../openhound-collector-common` (from `mssql/mssql` in the fork) are correct. An earlier draft
nested the checkouts one level deeper under `~/Desktop/dev/` and left both of those paths broken.

**Local development is just `uv sync --group dev`.** The `[tool.uv.sources]` entry redirects the
shared-library dependency to the sibling checkout as an *editable* install, so edits there take effect
immediately with no reinstall — and `uv sync` maintains that rather than clobbering it.

An intermediate design used a `just dev` recipe that ran `uv sync` and then re-applied
`uv pip install -e` on top, plus `check-dev` / `check-pinned` / `dev-local` helpers and a task runner to
invoke them. That existed only because the source entry had been removed, which was itself justified by
"a contributor cloning one repo would fail `uv sync`" — a problem that does not exist with one
developer. Restoring one line of config deleted a task runner, four recipes, and the rule *"any later
`uv sync` silently drops the overlay, so re-run `just dev`."* No task runner is used; plain `uv`
commands are listed in the runbook.

## Decided against

Recording these so they are not re-litigated.

| Rejected | Why |
|---|---|
| **A long-lived `openhound-port` staging branch on both public repos, promoted to `main` later** | The property actually wanted is "don't break existing PowerShell/Go users", and that is delivered entirely by the `v1.2-powershell` tag plus moving rather than deleting. MSSQLHound already restructured `main` this way — `powershell_deprecated/` is at the root of its `main` today. A long-lived branch also fights the concurrency harness, which wants trunk to be `main` with CI firing on it. |
| **A short-lived restructure branch, merged to `main` before tagging** | Considered on its merits and declined: it cannot gate the publish (the tag does), it cannot host the rehearsal any earlier than `main` can (the rehearsal needs a push either way), and it introduces a second commit a release tag could point at — a new route to the one irreversible mistake. See "the tag gates the publish" above. |
| **A `v2.0.0rc1` pre-release before `v2.0.0`** | Publishing the shared library first is already forced by the dependency, and it is the same workflow on a package nobody watches — so trusted-publishing wiring is rehearsed for free. Installing from the git URL rehearses the rest. |
| **`git subtree split` for either repo** | The shared library has 12 commits, the first a bulk add — no blame worth preserving. The SCCM collector has 106 commits of real porting work, which is a genuine loss, and still not worth a manual merge in a repo with one developer: see "a tree, not a history" above. |
| **Piping `git archive` straight into `tar`** | PowerShell 5.1 re-encodes bytes crossing a pipeline and corrupts the stream. `git archive -o <file>.tar` then `tar -xf` is two commands and cannot corrupt anything. |
| **Sorting 109 tickets across three repos** | 76 of the 109 are closed and at least 91 mention SCCM (the tickets carry no tag field, so the split cannot be measured more precisely than that — which is itself a reason not to try sorting them). An archive in one place beats an archive in three. |
| **Reflowing `README.md` + `ARCHITECTURE.md` to one sentence per line** | 3,842 lines of churn whose only benefit is merge-conflict reduction between concurrent agent lanes that do not exist yet. Deferred to the project that needs it. |
| ~~**`ci.yml` in the shared library**~~ | **Reversed 2026-07-29 — see "the shared library becomes testable in its own right" above.** The original entry rested on "four offline tests"; there are 21 files and 108 tests, covering every network and auth path both collectors depend on. |
| **Removing the fork's packages via a pull request** | Own fork, nothing in production, nothing depending on it. `git rm`, commit, push; `git revert` if wrong. |
| **TestPyPI** | Cannot resolve `impacket`/`ldap3`, so it proves less than a local wheel install while costing more to set up. |

## Pre-execution review, 2026-07-29

The runbook was read end to end and its factual claims checked against the live repos, PyPI, and GitHub
before any step ran. **Everything checkable was correct**: PyPI serves openhound 0.2.12; all three
distribution names are unregistered; `SpecterOps/ConfigManBearPig`'s root is exactly the eight items
listed, with zero tags and no open pull requests; the collector tree does supply the four things step 8
relies on it for; the three stale `just dev` comment blocks are where step 1 says; `grill-me` has no
SKILL.md; the library has no `[tool.uv]`; `out/` is not ignored; and nothing at the fork root references
either package by path. Two counts were verified and corrected rather than assumed: the library archive is
61 tracked files, not "about 60", and its fork-root plans and specs do not collide by filename with the
collector's, so step 8's `Copy-Item` needs no rename pass.

Seven things the review added, all recorded in place above rather than listed only here:

1. **Step 1's gate became a live collect** — see "validated means a live collect" above.
2. **The `.tickets/` credential scrub** — see the corrected "no credentials travel" bullet.
3. **The library gets a `dev` group and a `ci.yml`** — reversing a decision in the table below.
4. **50 ruff errors cleared by hand** — a defect the review found in the runbook's own step 2c, whose
   `ci.yml` would have failed on its first run in both repos.
5. **`merge=ours` needs a per-clone `git config`** — see the correction under the concurrency harness.
6. **Two `README.md` line references were incomplete** (line 1798 also roots the tree at `sccm/sccm/`).
7. **Step 10's rehearsal reports version `0.0.0`**, because `v1.2-powershell` is not a PEP 440 version and
   `hatch-vcs` falls back. Harmless, and noted so it is not read as a failure.

The pattern in items 2, 4, and 5 is the same one this document was created to fight, in a new form. Each is
a claim that was *true when written about the thing it was written about* and then quietly applied to
something else: an archive's safety guarantee borrowed by a file copy, a lint command documented before it
had ever passed, a git attribute assumed self-sufficient. None was a duplicated document — the earlier
failure mode — so collapsing the docs did not catch them. **Checking a plan means re-deriving its claims
against the system, not re-reading them for consistency**, because a plan can be perfectly self-consistent
and still wrong about the world.

## Superseded

- **Branch-first staging (D4/D14/D16, 2026-07-29 → removed entirely 2026-07-29).** Added for testability, briefly retained as an optional variant, then dropped once the reasoning was followed through: the tag is what publishes, the rehearsal needs a push regardless of which branch receives it, and a second branch is a second thing a release tag can point at. It also carried a confused premise about GitHub deployment-branch rules. The runbook is now single-path, which is the property that makes it readable.
- **`git subtree split` + `git pull --allow-unrelated-histories` for the SCCM collector (2026-07-29 → reverted 2026-07-29).** Replaced by a tracked-files archive; see the decision above. Its conflict table was two-fifths wrong when checked against the real trees, and it also required a separate "bring across what the split left behind" step, because a split at `--prefix=sccm/sccm` carries nothing from the fork root.
- **A manual wheel-inspection snippet before tagging (2026-07-29 → moved into `release.yml`).** Same assertions, now enforced before every `uv publish` instead of on the runs you remember to read.
- **`~/Desktop/dev/` as the parent for the new checkouts (2026-07-29 → flattened to `~/Desktop/`).** It put the library one level deeper than the two `[tool.uv.sources]` fixes assumed, breaking both.
- **`openhound` deliberately *not* declared (original §3c).** Reversed: `openhound` is on PyPI, so the dependency is resolvable, and without it `pip install configmanbearpig` yields a package that cannot even import.
- **`openhound-collector-common` licensed MIT.** Wrong from the start; see Apache-2.0 above.
- **`importlib.resources.files()` for the schema files.** Not used: `run_suite()` types `schema_path` as `Path | None`, and `Traversable` has no `.exists()`. `Path(__file__).resolve().parent` is location-independent for files inside the package and keeps the type contract.

## Relationship to the concurrency harness

The [multi-agent concurrency harness](2026-07-29-multi-agent-concurrency-design.md) names this work as a
prerequisite: it needs trunk to be `main` in each repo with CI firing on it. Publishing straight to
`main` satisfies that on day one.

Two things this work deliberately does **not** do for it, because both exist solely for concurrent lanes:
the `README`/`ARCHITECTURE` reflow (its Task 1), and per-lane redirection of the shared-library
dependency (its Task 3 Step 1).

That second one changes shape now that there is no task runner. Its purpose is to stop two lanes sharing
one editable checkout, where lane A's *uncommitted* edit silently changes what lane B's tests execute.
With a single `[tool.uv.sources]` path in a committed `pyproject.toml`, every lane resolves to the same
directory — so the harness needs a per-lane override. The natural mechanism is `UV_*` environment
variables or a per-worktree `uv.toml`, not a recipe parameter. **That is the harness's design problem to
solve, and its Task 3 verification — "editing the shared library in lane A provably does not change what
lane B imports" — is the check that matters.**

The one piece kept here is `TICKETS-BY-STATUS.md merge=ours` in `.gitattributes`, which pays for itself
immediately: that file is generated and its longest line is ~3,500 characters.

With one correction: **the attribute does nothing on its own.** Git's built-in merge drivers are `text`,
`binary`, and `union` — `ours` is not among them and has to be defined per clone, via
`git config merge.ours.driver true`, in `.git/config`, which is not a committable file. So the mechanism
is two pieces and only one of them can travel in the tree. Left as written it would have looked configured
and silently done nothing, which is the worse of the two failure modes: a merge conflict in a 3,500-
character generated line, in a repo where you had already decided that could not happen.

## Out of scope

- Publishing `mssqlhound` (deferred to feature-completeness). Two things are fixed in `mssql/mssql` now:
  its shared-library path dependency, which the SCCM publish breaks, and its `license = "MIT"`
  declaration. The licence is not deferrable for the same reason it was not deferrable for the shared
  library — the MSSQL collector is a port of the Apache-2.0 MSSQLHound, so declaring MIT is a
  misstatement of terms today, not a packaging detail that matters only at upload time.
- Adding `py.typed` to the shared library.
- Any change to OpenHound core.
