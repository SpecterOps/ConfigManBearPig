# Publishing runbook

How to get `configmanbearpig` and `openhound-collector-common` onto PyPI so a user can run:

```bash
uv tool install openhound --with configmanbearpig
openhound collect sccm .\out --run-all
```

(Targets are discovered from LDAP, and on Windows the domain comes from `$env:USERDNSDOMAIN`, so a
privileged run needs no flags beyond the output directory. There is no `--site-server` option — an earlier
version of this file invented one in all three of its example commands.)

Thirteen steps. Design rationale lives in
[`docs/superpowers/specs/2026-07-27-publishing-and-repo-split-design.md`](docs/superpowers/specs/2026-07-27-publishing-and-repo-split-design.md);
everything you run is here.

**Only two steps are irreversible: 6 and 11 — the two PyPI publishes.** Everything else is a
`git revert`, a file move, a tag deletion, or a settings change.

## Prerequisites

A PyPI account with 2FA enabled. **No API token** — publishing uses Trusted Publishing, where PyPI
trusts a specific GitHub repo + workflow and mints a short-lived token at release time.

Nothing else to install. `gh` is optional convenience for creating the repo and Release from the
terminal; the GitHub web UI does both.

## Where things end up

Two sibling directories on the Desktop, both beside the existing fork. Keeping them siblings is not
cosmetic — it is what makes the `[tool.uv.sources]` paths in steps 9 and 13 correct:

```
~\Desktop\OpenHound\                      the fork you work in today
~\Desktop\openhound-collector-common\     shared library repo      (step 4)
~\Desktop\ConfigManBearPig\               the published collector   (step 8)
```

## Why it looks like this

| Decision | Reason |
|---|---|
| **Shared library publishes first** | `configmanbearpig` declares `openhound-collector-common>=0.1.0,<0.2.0`. Until that exists on PyPI, nothing resolves. An ordering constraint, not a preference. |
| **Archive the PowerShell script before touching anything** | People `iwr` the raw `main` URL. A tag + Release gives it a permanent home first, so restructuring cannot orphan it. |
| **Restructure `main` directly — no branch anywhere** | MSSQLHound already did this: `powershell_deprecated/` sits at the root of its `main` today. The tag is what publishes, so a branch adds no protection over "don't tag until step 10 passes" — and it subtracts some, by creating a second commit a tag could point at. On `main` only, there is exactly one. Rejected alternatives are in the design record. |
| **The new repo gets a tree, not a history** | `git archive` writes exactly the tracked files — no `.venv`, no `*.duckdb`, no `out/`, and no pre-scrub lab credentials from old commits. You publish what you can see. The 106 porting commits stay in the fork on `origin/integration` and under the recovery tag from step 3. |
| **Runtime data files must live inside `src/openhound_sccm/`** | The wheel ships only that directory. `Path(__file__).parents[2]` worked in a checkout and pointed above `site-packages` once installed — a real bug for every PyPI user, found via the schema files. `schema_SCCM.json` is still read at runtime (the integration-test kit's coverage check), so the rule stands. |
| **The shared-library dependency is a version range, not a path** | `[project.dependencies]` is what users resolve; `[tool.uv.sources]` is a uv-only local redirect that never reaches wheel METADATA. |
| **Wheel checks live in CI, not in your terminal** | `release.yml` asserts before `uv publish`, so a bad wheel aborts the release instead of burning an immutable version number. A manual pre-flight only protects you on the runs you remember to read carefully. |

---

## Prep — local and reversible

### 1. Adopt the openhound version PyPI actually serves

Built against **0.1.4**; PyPI ships **0.2.12**, which is what a new user gets. Switch to it first, then
prove the collector still works, because everything downstream is tested against whatever this step
settles on.

In `pyproject.toml`, three edits:

- Add to `[project.dependencies]`: `"openhound>=0.2.12"`. No upper cap — an invented bound guarantees a
  re-release the day 0.3.0 ships.
- In `[dependency-groups] dev`, **delete** the `openhound @ git+https://github.com/SpecterOps/openhound.git`
  line rather than restating the constraint there. A direct git reference wins over a version range when
  uv resolves, so leaving it would mean local runs kept testing an unpublished commit while users got
  0.2.12 — the exact divergence this step exists to close.
- **Delete three stale comment blocks** that still describe a `just dev` workflow this repo no longer
  has (there is no `justfile` and no `DEVELOPMENT.md`): the *"Do NOT add a `[tool.uv.sources]` path
  entry… run `just dev`"* paragraph above `[project.dependencies]`, which contradicts the sources table
  forty lines below it; the `PENDING: openhound is required at runtime but is not declared yet` block,
  which the first edit obsoletes; and *"or drop this table entirely and rely on `just dev`'s editable
  overlay"* inside `[tool.uv.sources]`.

Then sync and run the checks. `python-preference = "only-system"` in `pyproject.toml` already forces a
system interpreter, which matters on Windows: uv's bundled CPython ships a `libcrypto` without the
`OPENSSL_Applink` shim and aborts on any TLS handshake.

```powershell
cd $HOME\Desktop\OpenHound\sccm\sccm
uv sync --group dev
uv run pytest tests\extension_metadata_test.py tests\integration_wiring_test.py `
    tests\convert_pipeline_test.py tests\integration_fixtures_test.py -v
uv run openhound collect sccm --help
uv run openhound convert sccm --help
```

`convert sccm` is hand-registered on openhound's Typer object, so it exercises the most fragile binding.

**Then collect against the live lab**, because the checks above prove the extension still *binds* to the
framework and nothing more. Eleven releases separate 0.1.4 from 0.2.12, and the way openhound drives the
preprocess and convert stages is exactly the kind of thing that can change without breaking an import or
a `--help`. A run against real SCCM is what distinguishes "it loads" from "it still produces the same
graph":

```powershell
# ps1-sms is often powered off. Confirm it answers before committing to a run.
Test-NetConnection ps1-sms.mayyhem.com -Port 443 -InformationLevel Quiet

uv run openhound collect sccm .\out --clean --run-all
```

`--clean` is not optional here. Without it dlt *appends* beside the previous load packages and preprocess
merges every accumulated run into one graph, so the raw row counts multiply by the number of runs in the
directory and any table this run finds empty silently keeps the previous run's rows. A baseline built that
way cannot be compared to anything.

**Do not compare two live collects to each other** — the answer will be noise. Two runs against this lab
minutes apart differ because AdminService queries hit a 5-second read timeout under load and a timeout is
reported as `Collected 0 …`, which silently drops whole resources. Compare *the same cached bucket*
reprocessed under each framework version instead, which holds collection constant and tests only the thing
that changed:

```powershell
# Reprocess an existing bucket. INPUT_PATH is the PARENT of the sccm/ directory, not sccm/ itself.
# Use a short path: dlt's state filenames are ~130 characters and blow past Windows' 260-character
# limit under a deep output directory, failing with FileNotFoundError on a file dlt just wrote.
Copy-Item -Recurse .\out\sccm C:\ohcheck\sccm
uv run openhound preprocess sccm C:\ohcheck C:\ohcheck\lookup.duckdb
uv run openhound convert sccm C:\ohcheck C:\ohcheck\graph --lookup-file C:\ohcheck\lookup.duckdb
```

Compare node and edge counts, kinds, node identities, edge triples, and which properties are populated.
**Expect a handful of list-valued properties to differ in element order** — `collectionIds`,
`siteSystemRoles`, `coercionVictimHostnames`, `coercionVictimAndRelayTargetPairs`. That is pre-existing
nondeterminism in the collector's own array aggregation, not a framework difference: two reprocess runs of
one bucket under one version differ from each other the same way. Verified 2026-07-29 by running the
comparison three ways.

**If any of this fails, stop** — `git checkout pyproject.toml uv.lock` puts you back on 0.1.4. Handling
a framework migration is separate work.

### 2. Fix and finish the workflows, then build

Two release-workflow fixes (2a, 2b), a CI workflow for each package (2c, 2d), the `pyproject.toml`
corrections that fall out of them, and a lint pass (2e) without which the new CI fails on its first run.
Note that no workflow here fires while either package lives in the fork — GitHub only reads
`.github/workflows/` at a repository *root* — so these files are dormant until steps 4 and 8 make these
directories repo roots. That is also why they can be written now and travel in the archives for free.

**2a. Provision Python 3.13 in `release.yml`.** `requires-python` is `>=3.13,<3.15` and
`pyproject.toml` sets `python-preference = "only-system"`, which forbids uv from downloading a managed
interpreter. Confirmed locally that this makes uv *fail* rather than fall back:

```
error: No interpreter found for Python >=3.99 in virtual environments, search path, or registry
```

`ubuntu-latest`'s system Python is 3.12, and 3.13 exists on the image only in the tool cache, which is
not on `PATH` until `actions/setup-python` runs — so `uv build` very likely has no interpreter it is
permitted to use. Add this to **both** `release.yml` files, immediately before the `astral-sh/setup-uv`
step:

```yaml
      # python-preference = "only-system" forbids a managed download, so a Python satisfying
      # requires-python (>=3.13) must be on PATH before uv runs. ubuntu-latest's system Python
      # is 3.12, and the tool-cache 3.13 is not on PATH until this step puts it there.
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
```

The runner image's contents cannot be verified from a workstation, so treat the diagnosis as very likely
rather than certain. It does not change what to do: pinning CI's interpreter is correct regardless — you
want to know which Python built a wheel — and the step is harmless if the diagnosis is wrong. The `ci.yml`
in 2c runs `uv sync` on the same image, so **the first pull request proves this before any tag is
pushed**, which is the cheap way to find out.

Two things to fix rather than work around, both consequences of the same root cause:

- **The comment on `python-preference` is misleading** and is why this stayed hidden. It explains the
  Windows TLS motivation and then says "on Linux this preference is harmless (the bug doesn't exist
  there)". Harmless for TLS; not harmless for interpreter discovery, which is the *other* thing the
  setting controls. Rewrite it to state the constraint — that no environment may download an
  interpreter, so every environment must already have one satisfying `requires-python`.
- **The shared library has no `[tool.uv]` section at all**, so it never had this problem in CI — but it
  also has no Windows protection. That does not matter today, because you work on it through the
  collector's venv, which carries the preference. It starts mattering at step 4, when the library becomes
  a repo with a venv of its own — and it is the half of the codebase doing the TLS-sensitive work
  (`clients/ad.py` does LDAPS, `clients/mssql.py` does TDS with EPA channel
  binding, `clients/ad.py` does LDAPS), which is exactly what aborts on a managed Windows CPython. Add
  to `openhound-collector-common/pyproject.toml` **now**, so step 3 commits it and the archive carries
  it:

```toml
[tool.uv]
# Never use a uv-managed (python-build-standalone) interpreter: on Windows its
# libcrypto-3-x64.dll lacks the OPENSSL_Applink cross-CRT shim and any TLS handshake aborts
# the process — which is every TLS-using code path in clients/ (LDAPS, TDS).
# Consequence everywhere, not only Windows: uv may not download an interpreter, so each
# environment must already have one satisfying requires-python (>=3.13). That is why the
# release workflow provisions Python explicitly.
python-preference = "only-system"
```

**2b. Assert the wheel's entry point and metadata.** `release.yml` already checks that the built version
matches the tag and that the three data files are present. Add one more step, right after the data-file
check. Every assertion runs **before** `uv publish`, so a failure aborts the release without consuming a
version number.

```yaml
      - name: Verify the wheel's entry point and metadata
        run: |
          set -euo pipefail
          whl="$(ls dist/*.whl)"
          unzip -p "$whl" '*/entry_points.txt' | grep -q '^sccm = openhound_sccm.main:app$' \
            || { echo "entry point missing or wrong"; exit 1; }
          meta="$(unzip -p "$whl" '*/METADATA')"
          grep -q '^Name: configmanbearpig$' <<<"$meta" || { echo "wrong distribution name"; exit 1; }
          # Accepts either metadata spelling: hatchling emits License-Expression under
          # PEP 639 and plain License on older metadata versions.
          grep -qE '^License(-Expression)?: Apache-2.0$' <<<"$meta" || { echo "wrong license"; exit 1; }
          grep -q '^Requires-Dist: openhound-collector-common' <<<"$meta" \
            || { echo "shared library not declared"; exit 1; }
          # The bracket class stops this from matching openhound-collector-common.
          grep -qE '^Requires-Dist: openhound[><=]' <<<"$meta" \
            || { echo "framework not declared"; exit 1; }
          ! grep -q 'file://' <<<"$meta" || { echo "a local path leaked into METADATA"; exit 1; }
          echo "entry point + metadata OK"
```

The library's own `release.yml` needs no equivalent assertion step: it has no data files and no entry
points, so "version matches tag" is the whole surface. It does need 2a.

**2c. Add a `ci.yml`.** The collector has no CI at all today. Once it is a public repo taking pull
requests from people who cannot run your lab, tests-on-PR is what makes a contribution reviewable — and
the concurrency harness design already assumes this file exists. Create
`sccm/sccm/.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - uses: astral-sh/setup-uv@v7
      - run: uv sync --group dev
      - run: uv run ruff check src tests
      # Deliberately a named list, not `pytest tests`: these are the files known to pass
      # offline, with no lab, no live AdminService, and no cached DuckDB. Widen it only
      # after confirming the wider set is green on a clean machine — a red default branch
      # teaches contributors to ignore CI.
      - run: >
          uv run pytest tests/extension_metadata_test.py
          tests/integration_wiring_test.py tests/convert_pipeline_test.py
          tests/integration_fixtures_test.py -q
```

**2d. Make the shared library able to test itself.** It ships 21 test files (108 tests) and has no
`[dependency-groups]` at all — today it borrows the collector's venv, which works only because
`[tool.uv.sources]` installs it editable there. Step 4 turns it into a repo of its own, at which point
`uv sync --group dev` errors and `uv run pytest` finds no pytest: a suite reachable only by pointing
another project's interpreter at it. Add the group to
`openhound-collector-common/pyproject.toml`, beside the `[tool.uv]` block from 2a so step 3 commits both:

```toml
[dependency-groups]
# Until step 4 this package had no dev group, because it was only ever installed into the
# collector's venv. As its own repo it needs enough to run its own tests and checks.
dev = [
    "pytest>=9.0.1",
    "ruff>=0.15.5",
    "mypy>=1.19.1",
]
```

And give it `openhound-collector-common/.github/workflows/ci.yml`. This reverses the design record's
"no `ci.yml` in the shared library" decision — recorded there rather than restated here. Unlike the
collector's, this one runs the whole `tests/` directory: all 21 files are offline, with no lab and no
DuckDB fixture, so there is no subset to curate. (The one test that opens a socket binds a loopback echo
server, which a runner handles fine.)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      # python-preference = "only-system" forbids a managed download, so a Python satisfying
      # requires-python (>=3.13) must be on PATH before uv runs.
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - uses: astral-sh/setup-uv@v7
      - run: uv sync --group dev
      - run: uv run ruff check src tests
      # The whole suite, unlike the collector's curated list: every test here is offline.
      - run: uv run pytest tests -q
```

**2e. Clear the lint and type debt both `ci.yml` files would otherwise fail on.** `ruff` and `mypy` are
both declared in the collector's dev group and both listed in the command table at the bottom of this file,
and **neither had ever passed** — the pre-commit config runs `black` and the standard hooks, with no ruff
or mypy hook, so nothing enforced them. Measured before the fix:

| | ruff (`src tests`) | mypy (`src`) |
|---|---:|---:|
| Collector | 27 (all in `tests/`) | 206 in 36 files |
| Shared library | 23 (5 `src`, 18 `tests`) | 67 in 12 files |

Both `ci.yml` files above run both commands, so without this pass they are red on their first run — which
is worse than having no checks at all, because it is what teaches a first-time contributor to ignore CI.

Four root causes accounted for nearly all of the mypy count, and each has a single fix:

- **88 × `logger.verbose` unknown.** The shared library already provides `get_logger()`, which returns a
  `VerboseLogger` declaring the custom level — 18 modules just called `logging.getLogger()` instead. Five
  of them additionally carried a side-effect-only `from .. import log_context  # noqa: F401` whose whole
  job was installing the monkeypatch at runtime; switching to `get_logger` does that *and* types it.
- **85 × `import-untyped`.** `impacket`, `openhound` and `sspi` ship no `py.typed`. That is a fact about
  those distributions, so they get `ignore_missing_imports` overrides in `[tool.mypy]`.
- **Three stub packages exist and were missing:** `types-ldap3`, `types-pywin32`, `types-pyasn1`. Adding
  them is strictly better than suppressing — and they immediately surfaced three real issues in the
  library. Note `types-ldap3` targets 2.9.13 while this package pins ldap3 2.10.2rc4, so `ENCRYPT`,
  `TLS_CHANNEL_BINDING` and `session_security` read as missing; those carry a narrow `type: ignore` naming
  the version gap, which is a better trade than losing ldap3 checking entirely.
- **28 × `fetchone()[0]` not indexable.** DuckDB types it `tuple | None`. Replaced with a `_scalar()`
  helper in `transforms.py` that raises a query-naming error instead.

**Do not run `ruff check --fix` blind, and do not chase mypy with `type: ignore`.** Several findings were
real bugs, and the fix is only obvious once you look:

- A shared-library test (since retired with the BloodHound upload feature — the lesson outlives the
  file) existed to assert eight names are
  importable from the package root. Seven read as unused because they are *named, never called*, so
  `--fix` would have deleted them and left a still-green test checking nothing. Rewritten to assert the
  export list as data.
- `registry.py`'s `get_current_user` and `get_ntlm_settings` were annotated `Optional[list[str]]` /
  `Optional[dict]` but are generators yielding `(table, row)` tuples like their sibling.
- Two sites in `ldap.py` did `if target:` then yielded `target.ad_object`, which is optional — a target
  without one would have yielded `None` into a dlt resource and failed schema validation downstream, with
  nothing naming the host.
- `dns.py` referenced `dns.resolver.NXDOMAIN` in an `except` clause where `dns` is bound only if the import
  succeeded, correlated to a separate boolean.
- `test_extension_methods.py` wrapped an import in a bare `try/except` that swallowed every exception and
  bound a name nothing used — and skipped a test as "convert phase not yet implemented", which is false.
  The test passes.

Where a suppression genuinely is the answer — the SOCKS `socket` module patch, the per-instance dnspython
`resolve` override, pywin32's read-only-typed `PySecBuffer.Buffer` — each one names why in a comment.
**Never open a comment with the words `type: ignore`**: mypy parses that as a real directive and reports
`Invalid "type: ignore" comment`.

All four must be clean:

```powershell
cd $HOME\Desktop\OpenHound\sccm\sccm
uv run ruff check src tests
uv run mypy src\openhound_sccm

cd $HOME\Desktop\OpenHound\openhound-collector-common
uv run ruff check src tests
uv run mypy src\openhound_collector_common
```

Then re-run the live collect from step 1 and compare the fingerprint again. Offline tests and a cached-bucket
reprocess do not exercise the *collect-time* modules this pass touched (`ldap.py`, `dns.py`, `registry.py`,
`privileged.py`, and the library's `ad.py` / `mssql.py` / `auth.py` / `proxy`), so a live run is the only
gate that covers them.

**Then confirm both wheels build**, and eyeball their contents if you want to:

```powershell
cd $HOME\Desktop\OpenHound\sccm\sccm
uv build
uv run python -m zipfile -l (Get-Item dist\*.whl)   # optional; CI asserts the specifics
Remove-Item -Recurse dist

cd $HOME\Desktop\OpenHound\openhound-collector-common
uv build
Remove-Item -Recurse dist
```

### 3. Commit everything that must travel, then tag a recovery point

Steps 4 and 8 build the new repos with `git archive`, which reads **`HEAD`** — anything uncommitted is
silently absent, with no warning. Three things are uncommitted right now and all three must travel: the
`dev/` move (the `debug_*` / `spike_*` / `tour_driver_*` scripts), `PUBLISHING.md` itself, and
**`openhound-collector-common/.gitignore`**, without which the library's new repo starts with no ignore
rules at all.

Two directories in `sccm/sccm/` are untracked and *not* gitignored. They need opposite treatment:

- **`dev/`** — commit it. The four debug scripts read `$SCCM_LAB_PASSWORD` / `$SCCM_LAB_NT_HASH` from
  the environment, so they carry no credentials.
- **`out/`** — add `out/` to `.gitignore`. It is collector output from live lab runs and must never
  reach a public repo. (`*.duckdb`, `logs`, `output`, and `__pycache__/` are already ignored, so those
  need nothing.)

**One ticket must be scrubbed first.** Step 8 copies all 109 tickets into a public repo, and
`.tickets/ope-1f49.md` records the lab connection for its integration tests as a literal
`USER=… PASSWORD=… NTHASH=… KDC=…` tuple. Replace the values with the environment-variable names the
`dev/` scripts already read. All 109 were scanned; this is the only one.

```powershell
cd $HOME\Desktop\OpenHound
git add -A
git commit -m "Move dev scripts to dev/, add the publishing runbook, ignore out/, scrub lab creds from ope-1f49"
git status --short        # must now list nothing at all
git tag pre-split-2026-07-29
git push origin pre-split-2026-07-29
```

A tag survives branch deletion and garbage collection, unlike the branches the code lives on.

> **On credentials in the fork's history:** commits `bcb1243` and `46c4114` (among others) contain
> `_LAB_PASSWORD = "password"` and `_LAB_NT_HASH = "8846f7ea…"` — the well-known NTLM hash of the string
> "password". Nothing needs rotating, and step 8's tree copy keeps all of it out of the public repo.
> Noted so it is a decision rather than a discovery.
>
> The values are worthless, which is why the *history* needed no rewrite — but that argument covers the
> history only. The ticket scrub above is a separate path the tree-copy reasoning never reached:
> `.tickets/` is copied wholesale, not archived from tracked files, so nothing filters it. Worth
> remembering as a general shape — a safety property proven for one mechanism does not transfer to a
> different mechanism moving the same data.
>
> The README's `--nt-hash 8846f7ea…` examples (lines 451, 459) stay as they are: the same worthless
> value, but there deliberately, as copy-pasteable lab documentation.

---

## Shared library — `openhound-collector-common` v0.1.0

### 4. Copy it into its own repo

Create an empty `Mayyhem/openhound-collector-common` on GitHub (no README, no license, no
`.gitignore`). A plain copy rather than a history split: 12 commits, the first a bulk add, so there is
no blame worth preserving — and it stays in the fork regardless.

Confirm all three of step 2's additions to this package are committed before you archive — `git archive`
reads `HEAD`, so anything uncommitted is simply absent: the `[tool.uv]` block from 2a (without which the
new repo has no Windows TLS protection, and you find out when a handshake aborts mid-collection), and the
`[dependency-groups]` and `ci.yml` from 2d (without which the repo cannot run its own tests).

```powershell
cd $HOME\Desktop\OpenHound
git archive -o $HOME\Desktop\common.tar HEAD:openhound-collector-common
mkdir $HOME\Desktop\openhound-collector-common -Force
tar -xf $HOME\Desktop\common.tar -C $HOME\Desktop\openhound-collector-common
Remove-Item $HOME\Desktop\common.tar

cd $HOME\Desktop\openhound-collector-common
git init -b main
git add -A
git commit -m "Import openhound-collector-common from the OpenHound fork"
git remote add origin https://github.com/Mayyhem/openhound-collector-common.git
git push -u origin main
```

`git archive` to a file and then `tar -xf`, rather than piping one into the other: PowerShell 5.1
re-encodes bytes passing through a pipeline and corrupts the tar stream. Two commands, no corruption.
It also means no `.venv` / `dist` cleanup afterwards — untracked files were never copied. `uv.lock` *is*
tracked here, so it comes along; that is fine, since a lock file affects only development environments
and never reaches the wheel.

Expect **51 files**: the 61 tracked before this run, plus the `.gitignore` and the `ci.yml` committed in
step 3, minus the 12 the BloodHound upload removal took out (6 modules under `bloodhound/`, 6 tests).
2a's `[tool.uv]` and 2d's `[dependency-groups]` edit `pyproject.toml`, which is already tracked, so they
add no file.

Then prove the repo stands on its own — the point of 2d, and something that could not be checked while the
package lived inside the collector's venv:

```powershell
uv sync --group dev
uv run pytest tests -q
uv run ruff check src tests
```

### 5. Wire up Trusted Publishing

At <https://pypi.org/manage/account/publishing/> → *Add a pending publisher*. All five fields are
literal and case-sensitive:

| Field | Value |
|---|---|
| PyPI Project Name | `openhound-collector-common` |
| Owner | `Mayyhem` |
| Repository name | `openhound-collector-common` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

"Pending" means the project does not exist yet — the first publish creates it, which also reserves the
name.

Then on GitHub: Settings → Environments → **New environment** named `pypi`. Leave *Deployment branches
and tags* at **No restriction**: the workflow fires on `refs/tags/v*`, and a branch rule would not
authorize a tag-triggered run. Optionally add yourself as a required reviewer, which makes every
release a deliberate click.

### 6. ⚠ IRREVERSIBLE — publish

```powershell
git tag v0.1.0
git push origin v0.1.0
```

Watch the Actions run, then verify from outside any checkout:

```powershell
uv run --with openhound-collector-common --no-project python -c "import openhound_collector_common; print('ok')"
```

PyPI filenames are immutable. If this release is wrong, **yank** it and publish `0.1.1` — never delete
and re-upload the same version.

This is also your Trusted Publishing rehearsal: same workflow, same mechanism, on a package nobody is
watching. If it works here it will work for ConfigManBearPig.

---

## ConfigManBearPig — v2.0.0

### 7. Archive the PowerShell script first

Reversible (see Backout), but do it before restructuring so the script never lacks a permanent home.
The repo has **zero tags** today, so `v1.2-powershell` is uncontested.

```powershell
cd $HOME\Desktop
git clone https://github.com/SpecterOps/ConfigManBearPig.git
cd ConfigManBearPig
git tag v1.2-powershell        # the script self-reports $script:ScriptVersion = "1.2"
git push origin v1.2-powershell
```

Cut a GitHub Release from that tag titled *ConfigManBearPig 1.2 (PowerShell)*, noting that 2.0 is a
Python OpenHound collector and the script remains here. Its permanent raw URL becomes:

`https://raw.githubusercontent.com/SpecterOps/ConfigManBearPig/v1.2-powershell/ConfigManBearPig.ps1`

### 8. Assemble the new repo

Push the PowerShell files down, drop the two the collector supersedes, then lay the collector tree over
the top. No merge, so no conflicts are possible.

The public repo's root today is exactly `ConfigManBearPig.ps1`,
`Invoke-ConfigManBearPigUnitTests.ps1`, `LICENSE`, `README.md`, `RELEASE_NOTES.md`, `seed_data.json`,
`cypher_queries/`, `sample_data/`. The collector tree already ships its own `powershell_deprecated/`
(holding the unit-test script and a deprecation README), its own `cypher_queries/`, and its own
`README.md` and `LICENSE` — so only four items need placing by hand.

Both `git rm`s below were checked against the real trees and lose nothing. The collector's copy of
`Invoke-ConfigManBearPigUnitTests.ps1` is byte-identical to the one on `main` (both blob
`20c27f9613d3`), and its 23 saved queries are a strict superset of the 17 upstream — same names, plus six
new ones. Should you want to confirm before deleting, `git show main:cypher_queries` lists the originals,
and everything on `main` today stays reachable at `v1.2-powershell` regardless.

```powershell
cd $HOME\Desktop\ConfigManBearPig
mkdir powershell_deprecated -Force
git mv ConfigManBearPig.ps1 RELEASE_NOTES.md seed_data.json sample_data powershell_deprecated\
git rm -r -q Invoke-ConfigManBearPigUnitTests.ps1 cypher_queries   # the collector tree supplies both

cd $HOME\Desktop\OpenHound
git archive -o $HOME\Desktop\sccm.tar HEAD:sccm/sccm
tar -xf $HOME\Desktop\sccm.tar -C $HOME\Desktop\ConfigManBearPig   # overwrites README.md and LICENSE
Remove-Item $HOME\Desktop\sccm.tar

# Things that live at the fork root and would otherwise be orphaned in an abandoned repo:
# 109 tickets (the large majority SCCM — one archive beats three) and six SCCM-topic plans/specs.
Copy-Item -Recurse .tickets $HOME\Desktop\ConfigManBearPig\
Copy-Item docs\superpowers\plans\* $HOME\Desktop\ConfigManBearPig\docs\superpowers\plans\
Copy-Item docs\superpowers\specs\* $HOME\Desktop\ConfigManBearPig\docs\superpowers\specs\

cd $HOME\Desktop\ConfigManBearPig
git status --short        # read it: this is exactly what the public repo will contain
git add -A
git commit -m "ConfigManBearPig 2.0: Python OpenHound collector; PowerShell 1.2 to powershell_deprecated/"
```

Do **not** bring the generated ticket index across — it self-declares as generated and will be
regenerated here on the next ticket update. It now lives at `.tickets/_TICKETS-BY-STATUS.md`,
beside the tickets it summarises, so create `.gitattributes` (the repo has none) with:

```gitattributes
# Generated from the ticket files in `.tickets/` and regenerated on every ticket
# update. Never merge it -- take whatever this side already has and let the next
# regeneration settle it.
.tickets/_TICKETS-BY-STATUS.md merge=ours
```

**The attribute alone is inert.** Git's built-in merge drivers are `text`, `binary`, and `union` —
`ours` is not among them, so it must be defined per clone, in `.git/config`, which is not a committable
file:

```powershell
git config merge.ours.driver true
```

Run that in every clone that will ever merge this repo. Two pieces are needed and only one of them can
travel in the tree, which is the whole reason this is worth spelling out rather than leaving as a
one-liner that looks like it works.

Everything so far is local. Nothing has been pushed, so `git reset --hard origin/main` returns this
clone to the pristine PowerShell repo with no trace — which is the same recovery a discarded branch
would have given you, without a branch to manage. The first push is at the end of step 9.

### 9. Fix what the move invalidates, verify, push

Four fixes: three things that were true in the fork and are false at the root of this repo, plus one
pre-existing bug worth fixing while you are in there.

- **`[tool.uv.sources]` in `pyproject.toml`** — change `../../openhound-collector-common` to
  `../openhound-collector-common`. The library is now a sibling of this repo, one level up instead of
  two. Without this, the `uv lock` below fails with *"not found in the package registry"*, which reads
  like a PyPI problem and is not. (Deleting the table is the alternative — the library is on PyPI as of
  step 6 — but then editing it locally means adding the entry back each time.)
- **`README.md`** — three places assume the fork layout. Quick Start (lines 95, 100) says `uv sync` "from
  this directory (`sccm/sccm/`)"; System Requirements (line 279) says the framework is "pulled from
  `git+https://github.com/SpecterOps/openhound.git`"; and Understanding the Codebase (line 1798) draws
  the tree rooted at `sccm/sccm/`. Lead with `uv tool install openhound --with configmanbearpig` for
  users, keep `uv sync --group dev` as the contributor path, drop the git-URL claim (step 1 replaced it
  with `openhound>=0.2.12`), and reroot the tree diagram.
- **`CLAUDE.md` and `AGENTS.md`** — this tree carries only `AGENTS.md`. Author both from the fork root's
  shared sections plus its SCCM-only section, dropping the MSSQL section. Keep them identical, as the
  fork root does.
- **The `grill-me` skill has no file.** `CLAUDE.md` points it at the *openhound* skill's path, but
  grill-me is the second frontmatter block inside that file, so every subagent fails to resolve it and
  silently improvises. Give it `.agents/skills/grill-me/SKILL.md` of its own.

```powershell
uv lock                 # resolvable now that the shared library is published
uv sync --group dev
uv run pytest tests\extension_metadata_test.py tests\convert_pipeline_test.py -v
uv run openhound collect sccm --help
git add -A; git commit -m "Repoint the shared-library path and refresh the docs for the new repo root"
git push origin main
```

### 10. Rehearse the real user path — at zero PyPI cost

```powershell
uv tool install openhound --with "configmanbearpig @ git+https://github.com/SpecterOps/ConfigManBearPig.git"
openhound collect sccm --help
openhound collect sccm .\out --clean --run-all
```

This builds the real wheel, discovers the entry point, and loads the data files exactly as a published
install would — the shared library even comes from PyPI. The only thing a release adds is where the
filename came from, which is why there is no release-candidate step.

**Expect the installed version to read `0.0.0`, and do not treat it as a failure.** The only tag on the
repo at this point is `v1.2-powershell` (step 7), which is not a PEP 440 version, so `hatch-vcs` cannot
derive anything from it and falls back to `fallback_version = "0.0.0"`. That fallback exists precisely so
a tagless or unparseable-tag checkout still builds. It cannot leak into a release: `release.yml` asserts
the built version equals the tag before it publishes, so a `0.0.0` would abort the job.

### 11. ⚠ IRREVERSIBLE — publish

Register the publisher first, exactly as in step 5 but with owner `SpecterOps`, repository
`ConfigManBearPig`, project `configmanbearpig` — and create that repo's `pypi` environment too.

```powershell
git tag v2.0.0
git push origin v2.0.0
```

Verify from a machine that has never seen the source:

```powershell
uv tool install openhound --with configmanbearpig
openhound collect sccm --help
```

If something is wrong, yank `2.0.0` and ship `2.0.1`. There is no earlier `2.x` for anyone to be
stranded on, so fixing forward is cheap.

---

## Cleanup

### 12. Remove the published packages from the fork

```powershell
cd $HOME\Desktop\OpenHound
git rm -r sccm/sccm openhound-collector-common
git commit -m "Remove packages now published from their own repos"
git push origin integration
```

There is no uv workspace table at the fork root, so nothing else references these directories by path —
except MSSQL, which step 13 handles.

### 13. Unblock MSSQL — nothing more

`mssql/mssql` depends on the shared library through `path = "../../openhound-collector-common"`, which
just stopped existing. That is the only forcing function, so fix exactly that and defer the rest until
the collector is feature-complete.

The edits live in one place — §1b of `mssql/mssql/docs/superpowers/plans/2026-07-27-mssqlhound-publishing.md`
in the fork — because two copies of four TOML lines is how the last version of this runbook grew a wrong
path. Work that section, not a summary of it. (Path given as text, not a link: this file moves to the
root of another repo at step 8, and any relative link would break there.)

§1a of that plan — correcting MSSQL's `license = "MIT"` to Apache-2.0 — is independent of publishing and
can be done at any time.

---

## Everyday commands after this

No task runner; these are the whole set.

| Task | Command |
|---|---|
| Set up / refresh the environment | `uv sync --group dev` (editable shared library comes free via `[tool.uv.sources]`) |
| Run specific tests | `uv run pytest tests\<file> -v` — targeted files only, never the full suite |
| Lint | `uv run ruff check src tests` — clean as of 2026-07-29; keep it that way |
| Type-check | `uv run mypy src\openhound_sccm` — clean as of 2026-07-29 (was 206 errors; see step 2e) |
| Build | `uv build` |
| List a built wheel's contents | `uv run python -m zipfile -l (Get-Item dist\*.whl)` — CI asserts the specifics at tag time |
| Release | `git tag vX.Y.Z; git push origin vX.Y.Z` |

Editing the shared library: with `[tool.uv.sources]` pointing at your sibling checkout, edits take
effect immediately — no reinstall. When ready, tag the library, and raise the floor in
`[project.dependencies]` only if the collector now needs a symbol the old version lacks.

---

## Backout

| Step | If it goes wrong |
|---|---|
| 1–2 (dependency + CI edits) | `git checkout pyproject.toml uv.lock .github` |
| 4 (create + copy) | Delete the GitHub repo. Nothing references it yet |
| 5 (PyPI publisher, environment) | Delete the pending publisher. No artifact exists |
| **6 (publish 0.1.0)** | **Cannot be undone.** Yank the release — resolvers stop selecting it, pinned installs keep working — then publish `0.1.1` |
| 7 (archive tag) | `git push origin :refs/tags/v1.2-powershell` and delete the Release. `main` is untouched at this point |
| 8–9 (restructure) | **Before the push at the end of step 9:** `git reset --hard origin/main` — a complete, traceless undo. **After it:** `git revert` restores the content as a visible commit, or `git reset --hard <pre-restructure sha>; git push --force origin main` erases it (`main` is unprotected and you are the only writer, so this is safe, though it rewrites public history). Nothing is published to PyPI either way, and `v1.2-powershell` keeps the original tree permanently reachable |
| **11 (publish 2.0.0)** | Yank and ship `2.0.1`. Steps 2, 9, and 10 exist to catch this first |
| 12 (fork cleanup) | `git revert`, or `git checkout pre-split-2026-07-29 -- sccm/sccm openhound-collector-common` |
| Total loss of the fork | `origin/integration`, `origin/sccm`, `origin/ohsccm`, `origin/ohmssql` all carry the collectors, plus the `pre-split-2026-07-29` tag |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `uv sync` / `uv lock`: *"openhound-collector-common was not found in the package registry"* | Almost always a stale `[tool.uv.sources]` path, not a PyPI problem — uv reports a missing local directory this way | In the new repo the path is `../openhound-collector-common` (step 9); before step 6, `uv run --no-sync` also works |
| *"Trusted publishing exchange failure"* | Owner / repo / workflow filename / environment do not match the PyPI form exactly | Re-read the pending-publisher entry; every field is literal and case-sensitive |
| CI: *"No interpreter found for Python >=3.13,<3.15 in virtual environments, search path, or registry"* | `python-preference = "only-system"` forbids uv from downloading one, and the runner's system Python is 3.12 | The `actions/setup-python@v5` step from 2a is missing from that workflow. Do not "fix" it by loosening the preference — that reintroduces the Windows TLS abort |
| Published version is `0.0.0` or `0.1.dev4+g1a2b3c` | Shallow checkout — no tags for `hatch-vcs` to see | `fetch-depth: 0` is already set; the workflow's version check should have failed the job first |
| Step 10's git-URL install reports version `0.0.0` | Expected, not a fault: the repo's only tag is `v1.2-powershell`, which is not a PEP 440 version, so `hatch-vcs` uses `fallback_version` | Nothing. The rehearsal tests the entry point and data files, not the version. `release.yml` asserts version-equals-tag, so this cannot reach PyPI |
| `.tickets/_TICKETS-BY-STATUS.md` still produces merge conflicts | The `merge=ours` attribute is present but `ours` is not a built-in git merge driver | `git config merge.ours.driver true` in that clone (step 8). The `.gitattributes` line cannot work alone |
| *"File already exists"* on upload | That version was already published; filenames are immutable | Bump to the next patch and tag again. Never overwrite |
| Installs, but `openhound collect sccm` does not exist | Entry point missing from the wheel | Step 2's CI assertion covers this — it must find `sccm = openhound_sccm.main:app` |
| `FileNotFoundError` on `schema_SCCM.json` | A data file is not inside the package directory | The release workflow's data-file assertion covers this — it must list `openhound_sccm/schema_SCCM.json` |
| The new repo is missing `dev/`, `PUBLISHING.md`, or a recent edit | `git archive` reads `HEAD`; uncommitted work is invisible to it | Commit in the fork, then re-run step 8 (delete the repo directory and re-clone first) |
| A `dev/` script complains about a missing variable | Lab credentials come from the environment now | `$env:SCCM_LAB_PASSWORD = "..."` / `$env:SCCM_LAB_NT_HASH = "..."` |
| `PipelineStepFailed … FileNotFoundError` on a `_dlt_pipeline_state/*.jsonl` file dlt just wrote | Windows 260-character path limit. dlt's state filenames are ~130 characters, so a deep output directory overflows | Collect to a short path (`C:\ohcheck`), not a nested temp directory |
| Raw row counts are an exact multiple of what the lab holds | `--clean` was omitted, so dlt appended and preprocess merged every run in the directory | Re-collect with `--clean`. Also why a table this run finds empty can still show old rows |
| A resource reports `Collected 0 …` but the lab has data | An AdminService read timed out (5s) and the failure is only logged at VERBOSE; the issues log stays empty | Check the full log for `Read timed out` on that URL. Re-run when the site server is warm — this is not a collector regression |
