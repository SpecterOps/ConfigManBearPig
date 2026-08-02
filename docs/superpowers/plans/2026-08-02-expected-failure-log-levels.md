# Expected-Failure Log Levels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut a low-privilege run's `collect_issues_<ts>.log` from 146 WARNINGs to 23 by reclassifying 123 expected outcomes below WARNING and rewriting two messages that were too long to read.

**Architecture:** Seven independent message/level changes across two repositories. `openhound-collector-common` gets an import guard for impacket's Python 3.14 `SyntaxWarning` and a one-line replacement for the five-line skipped-transform block; ConfigManBearPig gets the RemoteRegistry message rewrites, a third expected-miss case in `_sccm_expected_miss`, and two probe-negative level changes. No behaviour outside logging changes — every code path still returns exactly what it returned before.

**Tech Stack:** Python 3.14, pytest (`caplog`), DuckDB, impacket 0.13.1, `hatch-vcs` + PyPI trusted publishing, `gtk` ticket CLI.

**Spec:** [`docs/superpowers/specs/2026-08-02-expected-failure-log-levels-design.md`](../specs/2026-08-02-expected-failure-log-levels-design.md)

## Global Constraints

- **Two repositories.** `openhound-collector-common` lives at `../openhound-collector-common` (sibling checkout). It is a separate repo published to PyPI; ConfigManBearPig consumes it as a capped dependency.
- **Test file naming differs between the repos.** ConfigManBearPig pins `python_files = "*_test.py"` — a `test_*.py` file is **silently not collected**. `openhound-collector-common` uses the default `test_*.py` prefix. Match the repo you are in.
- **Dependency floor after release:** `"openhound-collector-common>=0.1.4,<0.2.0"`.
- **No hostname in log message text** for any message this plan touches. `LogContextFilter` already prefixes every per-host record with `[target][phase]`.
- **Never push.** Ask before each commit (CLAUDE.md). Tagging a release is the one exception and has its own explicit gate in Task 3.
- **Write a log line for every if/else and try/except branch** unless there is genuinely nothing to say, in which case leave a comment (CLAUDE.md).
- **Preserve comment intent.** Where a comment explains *why* a branch exists, keep it; only rewrite the parts that describe text being changed.
- **Checks — ConfigManBearPig:**
  ```powershell
  uv run ruff check src tests
  uv run mypy src\openhound_sccm
  uv run pytest tests -q
  ```
- **Checks — openhound-collector-common:**
  ```powershell
  uv run ruff check src tests
  uv run mypy src\openhound_collector_common
  uv run pytest tests -q
  ```

## File Structure

**`../openhound-collector-common`**

| File | Responsibility in this change |
|---|---|
| `src/openhound_collector_common/clients/mssql.py` | Guard the top-level impacket import (line 52) so its `SyntaxWarning` never reaches the console |
| `src/openhound_collector_common/dlt/duckdb_safe.py` | `safe_execute` logs a one-line summary; full DuckDB text moves to a companion DEBUG on the WARNING path only |
| `tests/test_duckdb_safe.py` | Two existing assertions retargeted; three new tests |
| `tests/test_impacket_import_quiet.py` | **New.** Subprocess test proving the guard holds under a forced recompile |

**`ConfigManBearPig`**

| File | Responsibility in this change |
|---|---|
| `src/openhound_sccm/collectors/registry.py` | D1 Triggers message, D2 roll-up, §5.1 hostname removal, delete the capability map |
| `src/openhound_sccm/transforms.py` | Third expected-miss case in `_sccm_expected_miss` |
| `src/openhound_sccm/collectors/http.py` | `_request` connect failure → INFO |
| `src/openhound_sccm/collectors/privileged.py` | `_http_get_value` 404-while-probing → VERBOSE |
| `pyproject.toml` | Dependency floor bump |
| `tests/registry_access_denied_test.py` | Roll-up assertions rewritten; capability test deleted; three new tests |
| `tests/registry_collect_test.py` | One assertion retargeted (line 387) |
| `tests/transforms_safe_fallback_test.py` | One test inverted + renamed; one new test |
| `tests/probe_negative_levels_test.py` | **New.** D4 + D5 level assertions |
| `README.md`, `ARCHITECTURE.md` | Sample block, low-privilege section, §7 triage bullet, new changelog entry |

---

## Task 0: Ticket and branches

**Files:**
- Create: `.tickets/<generated-id>.md` (via `gtk`)
- Modify: `.tickets/_TICKETS-BY-STATUS.md` (generated — never hand-edited)

**Interfaces:**
- Consumes: nothing
- Produces: a ticket ID referenced in every commit message below as `<TICKET>`

- [ ] **Step 1: Create the ticket**

```bash
cd /c/Users/domainadmin/Desktop/ConfigManBearPig
gtk create "Quiet expected-failure logs: RemoteRegistry keys, transform downgrade, probe levels, impacket SyntaxWarning" \
  -type task -priority 1 \
  -description "146 WARNINGs on a healthy low-privilege run -> 23. Spec: docs/superpowers/specs/2026-08-02-expected-failure-log-levels-design.md"
gtk start <TICKET>
```

- [ ] **Step 2: Regenerate the ticket index**

Run: `uv run python dev/regen_ticket_index.py`
Expected: `_TICKETS-BY-STATUS.md` rewritten with the new ticket under in-progress.

- [ ] **Step 3: Verify the index is not stale**

Run: `uv run python dev/regen_ticket_index.py --check`
Expected: exit 0, no output.

- [ ] **Step 4: Branch both repos off their default branch**

```bash
cd /c/Users/domainadmin/Desktop/ConfigManBearPig && git checkout -b quiet-expected-failure-logs
cd /c/Users/domainadmin/Desktop/openhound-collector-common && git checkout -b quiet-expected-failure-logs
```

- [ ] **Step 5: Commit the ticket (ask first)**

```bash
cd /c/Users/domainadmin/Desktop/ConfigManBearPig
git add .tickets/
git commit -m "chore(<TICKET>): open ticket for expected-failure log levels"
```

---

## Task 1: Silence impacket's SyntaxWarning (D6)

**Repo:** `../openhound-collector-common`

**Files:**
- Modify: `src/openhound_collector_common/clients/mssql.py:52`
- Test: `tests/test_impacket_import_quiet.py` (create)

**Interfaces:**
- Consumes: nothing
- Produces: no API change. `clients/mssql.py` still exports the same names; `ntlm` and `tds` remain module-level.

- [ ] **Step 1: Write the failing test**

Create `tests/test_impacket_import_quiet.py`:

```python
"""impacket's Python 3.14 SyntaxWarning must not reach a collector's console.

impacket 0.13.1's `mssql/version.py:182` returns from inside a `finally` block.
Python 3.14 reports that as a SyntaxWarning, emitted by the COMPILER -- so it
fires once, when the module's bytecode is first built, and never again while a
valid .pyc exists. `clients/mssql.py` imports `impacket.tds` at module level,
and `tds.py:54` imports the offending module, so the warning surfaces on the
operator's console as noise about a third-party file they cannot act on.

Testing this needs care on two counts:

* The warning only fires on a COMPILE. A test that just imports the module
  passes for the wrong reason as soon as the venv has a cached .pyc.
  `PYTHONPYCACHEPREFIX` redirects the whole bytecode cache into an empty tmp
  directory, which forces a recompile WITHOUT deleting anything from the venv
  (which would be a side effect on a shared environment, and racy under -n).
* `-W error::SyntaxWarning` promotes the warning at compile time, where it
  surfaces as a `SyntaxError`, not a `SyntaxWarning`. So assert on the
  subprocess exit status rather than trying to catch a specific type.
"""
import os
import subprocess
import sys
import textwrap


def test_importing_mssql_client_emits_no_syntax_warning(tmp_path):
    program = textwrap.dedent(
        """
        import warnings
        warnings.simplefilter("error", SyntaxWarning)
        import openhound_collector_common.clients.mssql  # must not raise
        print("clean")
        """
    )
    env = {**os.environ, "PYTHONPYCACHEPREFIX": str(tmp_path)}
    done = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, env=env
    )
    assert done.returncode == 0, (
        "importing clients.mssql raised on a forced recompile -- the impacket "
        f"SyntaxWarning guard is missing or ineffective:\n{done.stderr}"
    )
    assert "clean" in done.stdout, done.stdout


def test_the_guard_is_scoped_and_does_not_hide_our_own_return_in_finally(tmp_path):
    """The guard must not leave a process-wide filter behind.

    A global `filterwarnings(message=...)` would also silence a return-in-finally
    written in OUR code, or any other dependency's. Importing the module and then
    compiling such a function must still warn.
    """
    program = textwrap.dedent(
        """
        import warnings
        import openhound_collector_common.clients.mssql  # installs nothing global
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            compile("def f():\\n try:\\n  pass\\n finally:\\n  return 1\\n", "ours.py", "exec")
        assert any("finally" in str(w.message) for w in caught), \\
            "our own return-in-finally was silenced by a leaked global filter"
        print("scoped")
        """
    )
    env = {**os.environ, "PYTHONPYCACHEPREFIX": str(tmp_path)}
    done = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, env=env
    )
    assert done.returncode == 0, done.stderr
    assert "scoped" in done.stdout, done.stdout
```

- [ ] **Step 2: Run the test to verify the first one fails**

Run: `uv run pytest tests/test_impacket_import_quiet.py -q`
Expected: `test_importing_mssql_client_emits_no_syntax_warning` FAILS with the assertion message quoting a `SyntaxError: 'return' in a 'finally' block` traceback from `impacket/mssql/version.py:182`. The second test PASSES already (there is no global filter today).

- [ ] **Step 3: Add the guard**

In `src/openhound_collector_common/clients/mssql.py`, add `import warnings` to the stdlib import block (alphabetical: after `import ssl`), then replace line 52:

```python
from impacket import ntlm, tds
```

with:

```python
# impacket 0.13.1's mssql/version.py:182 returns from inside a finally block, which
# Python 3.14 reports as a SyntaxWarning the first time the module is compiled.
# impacket.tds imports it (tds.py:54), so without this the warning lands on the
# operator's console -- noise about a third-party file they cannot act on.
#
# Scoped rather than a global filterwarnings(): a return-in-finally in OUR code must
# still be reported. Note module= does NOT work here -- for a compile-time warning
# CPython calls warn_explicit() with module=None and warnings.py then derives the
# module from the FILE PATH, not the dotted name, so `module=r"impacket\..*"` never
# matches. Import time and single-threaded, so catch_warnings' documented
# thread-unsafety does not apply.
with warnings.catch_warnings():
    warnings.simplefilter("ignore", SyntaxWarning)
    from impacket import ntlm, tds
```

Leave the redundant lazy `from impacket.tds import TDS_SSVARIANT` at line ~307 alone — it sits inside the verbatim-copied `parseRow`, where fidelity to upstream is the point, and it costs only a `sys.modules` hit.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_impacket_import_quiet.py -q`
Expected: 2 passed.

- [ ] **Step 5: Run the full suite and linters**

```powershell
uv run ruff check src tests
uv run mypy src\openhound_collector_common
uv run pytest tests -q
```
Expected: all green. If ruff flags the import as not-at-top-of-file (`E402`), the `with` block is still at the top of the module — move it above any non-import statement rather than adding a `noqa`.

- [ ] **Step 6: Commit (ask first)**

```bash
git add src/openhound_collector_common/clients/mssql.py tests/test_impacket_import_quiet.py
git commit -m "fix: silence impacket's Python 3.14 SyntaxWarning at the import that triggers it"
```

---

## Task 2: Compact the skipped-transform message (D7)

**Repo:** `../openhound-collector-common`

**Files:**
- Modify: `src/openhound_collector_common/dlt/duckdb_safe.py:88-95`
- Test: `tests/test_duckdb_safe.py:138-153` (modify) and new tests appended

**Interfaces:**
- Consumes: nothing
- Produces: `safe_execute(con, label, sql, *, expected_miss=None, logger=None) -> None` — signature unchanged. Only the emitted log text changes:
  - unexpected miss → one `WARNING`: `transform '<label>' skipped: source table '<table>' does not exist`, plus one companion `DEBUG`: `transform '<label>': <full DuckDB exception>`
  - expected miss → one `DEBUG`: `transform '<label>' skipped: expected missing source table '<table>'`, and **no** companion record

- [ ] **Step 1: Write the failing tests**

Replace the bodies of the two existing tests at `tests/test_duckdb_safe.py:138-153` and append three new ones:

```python
def test_catalog_error_that_is_not_a_missing_table_is_loud(con, caplog):
    """A misspelled function must be reported as a failure, not a skipped source."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "bad-function", "SELECT list_filtr([1], x -> x > 0)")
    text = caplog.text
    assert "skipped" not in text, text
    assert "bad-function" in text and "failed" in text, text


def test_missing_source_table_is_still_quiet(con, caplog):
    """The intended quiet path is unchanged: logged and swallowed, never raised."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "absent-source", "SELECT * FROM s.never_collected")
    assert "absent-source" in caplog.text, caplog.text
    assert "never_collected" in caplog.text, caplog.text


def test_unexpected_miss_is_one_warning_line_plus_a_debug_with_the_detail(con, caplog):
    """The WARNING is scannable; DuckDB's spell-check guess and SQL echo move to DEBUG.

    DuckDB's CatalogException carries a 'Did you mean "x"?' guess and a re-print of
    the failing SQL with a caret, so logging the whole exception made every skipped
    transform a five-line block -- ~535 lines in one low-privilege run.
    """
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "node_x<-absent_y", "SELECT * FROM s.absent_y")

    warnings_ = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings_) == 1, [r.getMessage() for r in warnings_]
    summary = warnings_[0].getMessage()
    assert "node_x<-absent_y" in summary
    assert "absent_y" in summary
    assert "\n" not in summary, f"the WARNING must be one line, got:\n{summary}"
    assert "Did you mean" not in summary, summary

    debugs = [r for r in caplog.records
              if r.levelno == logging.DEBUG and "node_x<-absent_y" in r.getMessage()]
    assert debugs, "expected a companion DEBUG carrying the full DuckDB text"
    assert any("Catalog Error" in r.getMessage() for r in debugs), \
        [r.getMessage() for r in debugs]


def test_expected_miss_is_one_debug_line_with_no_companion_detail(con, caplog):
    """An expected absence needs no diagnosis, so it does not get the noisy detail."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "node_x<-absent_y", "SELECT * FROM s.absent_y",
                     expected_miss=lambda _con, _missing: True)

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    relevant = [r for r in caplog.records if "node_x<-absent_y" in r.getMessage()]
    assert len(relevant) == 1, [r.getMessage() for r in relevant]
    assert relevant[0].levelno == logging.DEBUG
    assert "Catalog Error" not in relevant[0].getMessage(), relevant[0].getMessage()


def test_summary_names_the_table_even_when_the_label_does_not(con, caplog):
    """The label is free-form, so the missing table must be named independently."""
    import logging
    with caplog.at_level(logging.DEBUG):
        safe_execute(con, "some-opaque-label", "SELECT * FROM s.absent_y")
    warnings_ = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings_) == 1
    assert "absent_y" in warnings_[0].getMessage()
```

- [ ] **Step 2: Run the tests to verify the new ones fail**

Run: `uv run pytest tests/test_duckdb_safe.py -q`
Expected: `test_unexpected_miss_is_one_warning_line_plus_a_debug_with_the_detail` FAILS on `"\n" not in summary` (today's WARNING embeds DuckDB's multi-line text), and `test_expected_miss_is_one_debug_line_with_no_companion_detail` FAILS on `"Catalog Error" not in ...`.

- [ ] **Step 3: Rewrite the logging in `safe_execute`**

In `src/openhound_collector_common/dlt/duckdb_safe.py`, replace lines 88-95:

```python
        if downgrade:
            log.debug(
                "transform %r skipped (expected fallback miss on %r): %s",
                label, match, err,
            )
        else:
            # A missing source table is expected before all sources have run.
            log.warning("transform %r skipped (missing source): %s", label, err)
```

with:

```python
        if downgrade:
            # An expected absence needs no diagnosis: the summary already says
            # everything DuckDB's exception would, so no companion detail record.
            log.debug("transform %r skipped: expected missing source table %r", label, match)
        else:
            # A missing source table is expected before all sources have run, so this
            # is a WARNING and not an ERROR. One line: DuckDB's exception carries a
            # 'Did you mean' guess and a re-print of the failing SQL with a caret,
            # which turned every skipped transform into a five-line block.
            log.warning("transform %r skipped: source table %r does not exist", label, match)
            # The guess and the SQL echo only earn their space when the miss is a
            # SURPRISE -- that is when a typo'd table name is worth diagnosing.
            log.debug("transform %r: %s", label, err)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_duckdb_safe.py -q`
Expected: all pass.

- [ ] **Step 5: Update the docstring**

`safe_execute`'s docstring says the collector marks benign misses "without baking that knowledge in here". Add one sentence recording the new output shape, so a reader does not have to infer it from the branches:

```
    On a missing source table this logs a one-line summary naming the label and the
    absent table. When the miss is *unexpected* a companion DEBUG record carries the
    full DuckDB exception (its "Did you mean" guess and the SQL echo), which is worth
    reading only when the absence is a surprise -- e.g. a typo'd table name.
```

- [ ] **Step 6: Run the full suite and linters**

```powershell
uv run ruff check src tests
uv run mypy src\openhound_collector_common
uv run pytest tests -q
```
Expected: all green.

- [ ] **Step 7: Commit (ask first)**

```bash
git add src/openhound_collector_common/dlt/duckdb_safe.py tests/test_duckdb_safe.py
git commit -m "refactor: one-line skipped-transform log, full DuckDB text at DEBUG"
```

---

## Task 3: Release openhound-collector-common v0.1.4

**Repo:** `../openhound-collector-common`

**Files:** none — the tag *is* the release (`hatch-vcs` derives the version from it).

**Interfaces:**
- Consumes: Tasks 1 and 2, merged to the default branch
- Produces: `openhound-collector-common==0.1.4` on PyPI, which Task 7's floor bump requires

> **This task contains a blocking human gate and an irreversible step.** PyPI filenames are immutable — a tag on the wrong commit burns that version number permanently. Do not run Step 2 without explicit go-ahead.

- [ ] **Step 1: Merge the branch and confirm the tag target**

```bash
cd /c/Users/domainadmin/Desktop/openhound-collector-common
git checkout main && git merge --no-ff quiet-expected-failure-logs
git log --oneline -3          # confirm both commits are present
git status --short            # must be clean
```

- [ ] **Step 2: Tag and push the tag — ASK BEFORE RUNNING**

```bash
git tag -a v0.1.4 -m "Silence impacket's Python 3.14 SyntaxWarning; one-line skipped-transform log"
git push origin v0.1.4
```

- [ ] **Step 3: Approve the release in GitHub**

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which builds, asserts the built version matches the tag, and publishes through trusted publishing. **The job runs in the `pypi` GitHub environment, which has a required reviewer** — someone must click approve. Watch it:

Run: `gh run watch` (or the Actions tab)
Expected: the `pypi` job waits for approval, then publishes.

- [ ] **Step 4: Verify the release actually published**

The tag being on origin is not proof. `release.yml` waits in the `pypi` environment for a reviewer, so
check PyPI itself (see Task 7 Step 1 for why `uv pip index versions` is not the command):

```bash
./.venv/Scripts/python.exe -c "
import json, urllib.request
with urllib.request.urlopen('https://pypi.org/pypi/openhound-collector-common/json', timeout=20) as r:
    print(sorted(json.load(r)['releases']))
"
```
Expected: `0.1.4` in the list. Do not start Task 7 until it appears.

---

## Task 4: RemoteRegistry messages (D1, D2, §5.1)

**Repo:** `ConfigManBearPig`

**Files:**
- Modify: `src/openhound_sccm/collectors/registry.py` — delete 75-99, rewrite 224-248, 265-272, 457-462
- Modify: `tests/registry_access_denied_test.py` — rewrite 86-106, delete 130-132, append 3 tests
- Modify: `tests/registry_collect_test.py:387` — one assertion
- Modify: `README.md:712-724` — the sample block

**Interfaces:**
- Consumes: nothing
- Produces: `_RegistryProbe.log_denied_summary() -> None` (unchanged signature). `_capability_for` and `_DENIED_CAPABILITIES` **cease to exist** — no later task may reference them.

- [ ] **Step 1: Write the failing tests**

In `tests/registry_access_denied_test.py`, replace `test_summary_is_one_warning_naming_each_lost_capability` (lines 86-106) and delete `test_unmapped_path_falls_back_to_the_raw_key` (lines 130-132). Add:

```python
def test_summary_is_one_warning_listing_each_denied_key(caplog):
    """Denied reads collapse to one WARNING listing the keys, one per line."""
    probe = _probe()
    probe._log_read_failure("a", LANMAN, Exception(DENIED))
    probe._log_read_failure("b", LSA, Exception(DENIED))
    probe._log_read_failure("c", registry.SCCM_REG_KEYS["msv10"], Exception(DENIED))
    probe._log_read_failure("d", SQL_2022, Exception(DENIED))

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe.log_denied_summary()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()

    assert "4 registry key(s)" in message, message
    for key in (LANMAN, LSA, registry.SCCM_REG_KEYS["msv10"], SQL_2022):
        assert key in message, f"{key} missing from:\n{message}"
    # One key per line, each indented -- seven paths semicolon-joined is a
    # 300-character wall that wraps at arbitrary points.
    assert message.count("\n") == 4, message
    assert "\n    " + LANMAN in message, message


def test_summary_counts_distinct_keys_not_reads(caplog):
    """Several values under ONE key are one entry, and the count matches the list.

    _read_mssql_service_state reads Start and ObjectName under the same service key,
    so a read count can exceed the number of paths. A message saying "2" above one
    path reads as a bug.
    """
    probe = _probe()
    probe._log_read_failure("DWORD value Start under " + LSA, LSA, Exception(DENIED))
    probe._log_read_failure("DWORD value DisableLoopbackCheck under " + LSA, LSA, Exception(DENIED))

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe.log_denied_summary()

    message = [r for r in caplog.records if r.levelno == logging.WARNING][0].getMessage()
    assert "1 registry key(s)" in message, message
    assert message.count(LSA) == 1, message


def test_no_message_repeats_the_hostname(caplog):
    """LogContextFilter already prefixes [target][phase]; repeating it is duplication."""
    probe = _probe()
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe._log_read_failure(f"registry key {LANMAN}", LANMAN, Exception(DENIED))
        probe._log_read_failure(f"registry key {SQL_2022}", SQL_2022, Exception("ERROR_FILE_NOT_FOUND"))
        probe._log_read_failure(f"registry key {LSA}", LSA, Exception("connection reset by peer"))
        probe.log_denied_summary()

    for record in caplog.records:
        assert HOST not in record.getMessage(), \
            f"{record.levelname} repeats the hostname: {record.getMessage()}"
```

Also update the module docstring's contract list (lines 9-16): `each host emits exactly ONE WARNING naming the capabilities it lost` becomes `naming the keys it could not read`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/registry_access_denied_test.py -q`
Expected: the three new tests FAIL. `test_summary_is_one_warning_listing_each_denied_key` fails on `"4 registry key(s)" in message` (today's text is `"4 registry read(s) denied on cas-db.mayyhem.com -- not collected: ..."`); `test_no_message_repeats_the_hostname` fails on the first record.

- [ ] **Step 3: Delete the capability map**

Delete `registry.py` lines 75-99 in full — the `_DENIED_CAPABILITIES` tuple with its comment block, and the `_capability_for` function.

- [ ] **Step 4: Rewrite `log_denied_summary`**

Replace `registry.py:224-248` with:

```python
    def log_denied_summary(self) -> None:
        """Report this host's refused reads as one WARNING listing the keys, or nothing.

        A non-admin run against a site system is refused on the order of a dozen
        reads. Logged individually those were ~120 of the 125 ERRORs in a
        low-privilege lab run, none of them a fault: the same run as a local admin
        produced zero. So each read logs at verbose (still in collect_full_<ts>.log
        for anyone diagnosing a specific key) and the host emits this one line.

        Keys rather than capability names, and no remediation prose: the operator
        reads a registry path faster than a sentence about it, and README's "What a
        low-privilege run looks like" already explains once that these keys are
        admin-gated. One key per line -- seven paths semicolon-joined is a
        300-character wall that wraps at arbitrary points.

        The count is of DISTINCT keys, not reads, so it always equals the length of
        the list beneath it. Several values under one key can each be refused (e.g.
        _read_mssql_service_state reads Start and ObjectName under one service key),
        which would otherwise print a number larger than the list.

        No hostname in the text: LogContextFilter prefixes [target][phase] already.
        """
        if not self._denied:
            # Either everything was readable or nothing was tried; no news is fine.
            logger.debug("No registry reads were denied.")
            return
        # dict.fromkeys keeps first-seen order, so keys appear in the order the phase
        # actually attempted them rather than an arbitrary set order.
        keys = list(dict.fromkeys(self._denied))
        logger.warning(
            "Access denied reading %d registry key(s):\n%s",
            len(keys), "\n".join(f"    {key}" for key in keys),
        )
```

The explicit four spaces matter: Rich aligns a multi-line message to its own column for free, but the two file handlers use a plain `logging.Formatter` that does not, so without them the paths start at column 0 in `collect_issues_<ts>.log`.

- [ ] **Step 5: Drop the hostname from the per-read lines**

Replace `registry.py:265-272` (inside `_log_read_failure`) with:

```python
        error_text = str(ex)
        if "ERROR_FILE_NOT_FOUND" in error_text:
            logger.verbose("%s not found", description)
        elif _is_access_denied(error_text):
            self._denied.append(key_path)
            logger.verbose("Access denied reading %s", description)
        else:
            logger.error("Failed to read %s: %s", description, ex)
```

Leave the `_log_read_failure` docstring alone. Its three-way explanation (absent → verbose, denied → verbose plus a tally, anything else → error) is still exactly right, and it refers to `log_denied_summary` by name without describing the message shape — checked, it never mentions capabilities.

- [ ] **Step 6: Shorten the Triggers warning**

Replace `registry.py:457-462` with:

```python
                logger.warning(
                    "Access denied reading %s, skipping remaining Remote Registry checks",
                    SCCM_REG_KEYS["triggers"],
                )
```

**Keep the comment above it (lines 449-456) exactly as it is** — it records why this branch exists (reporting a refused read as "does not exist" sent the operator away from a host that may well be a site system), which is still true.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `uv run pytest tests/registry_access_denied_test.py -q`
Expected: all pass.

- [ ] **Step 8: Fix the collateral assertion in `registry_collect_test.py`**

`test_denied_triggers_key_reports_access_denied_not_a_missing_key` asserts `"site code is unknown" in text` at line 387 — a phrase D1 deletes. The test's intent survives; retarget it:

```python
    assert "Access denied reading" in text
    assert "skipping remaining Remote Registry checks" in text
    assert "does not exist or no site code subkey found" not in text
```

Run: `uv run pytest tests/registry_collect_test.py -q`
Expected: all pass. `test_absent_triggers_key_still_reports_the_host_as_not_a_site_server` needs no change.

- [ ] **Step 9: Update the README sample block**

Replace `README.md:712-724` with:

````markdown
- **Refused registry reads.** Roughly a dozen reads per site system are admin-gated (the SMB-signing,
  NTLM and SQL Server keys). Each denied read is logged at VERBOSE into `collect_full_<timestamp>.log`,
  and each host then emits **one** warning listing the keys it could not read:

  ```
  WARNING [ps1-sms.mayyhem.com][RemoteRegistry] Access denied reading 7 registry key(s):
          SOFTWARE\Microsoft\SMS\CurrentUser
          SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
          SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
          SYSTEM\CurrentControlSet\Control\Lsa
          SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL
          SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib
          SOFTWARE\Microsoft\SMS\Triggers
  ```

  The host-hardening and SQL Server keys require local Administrators on the target. Re-running as a
  local administrator on those hosts is what fills the gap; nothing else is wrong.
````

That last paragraph is now the **only** place the remediation advice lives, which is the point of dropping it from the per-host line.

- [ ] **Step 10: Verify nothing still references the deleted symbols**

Run: `grep -rn "_capability_for\|_DENIED_CAPABILITIES" src tests README.md ARCHITECTURE.md`
Expected: no matches.

- [ ] **Step 11: Run the linters and full suite**

```powershell
uv run ruff check src tests
uv run mypy src\openhound_sccm
uv run pytest tests -q
```
Expected: all green.

- [ ] **Step 12: Commit (ask first)**

```bash
git add src/openhound_sccm/collectors/registry.py tests/registry_access_denied_test.py tests/registry_collect_test.py README.md
git commit -m "refactor(<TICKET>): RemoteRegistry denials list keys, drop capability map and host duplication"
```

---

## Task 5: Downgrade transform misses when no privileged transport ran (D3)

**Repo:** `ConfigManBearPig`

**Files:**
- Modify: `src/openhound_sccm/transforms.py:48-88`
- Modify: `tests/transforms_safe_fallback_test.py:1-21` (docstring), `:87-105` (invert + rename), append 1 test

**Interfaces:**
- Consumes: `_privileged_transport_ran(con: duckdb.DuckDBPyConnection) -> bool` (already exists, `transforms.py:23`)
- Produces: `_sccm_expected_miss(con, missing: str) -> bool` — signature unchanged, third case added

- [ ] **Step 1: Invert the pinned test and add the new one**

In `tests/transforms_safe_fallback_test.py`, replace `test_safe_no_sibling_logs_warning` (lines 87-105):

```python
# ---------------------------------------------------------------------------
# (c) No sibling AND no privileged transport at all -> DEBUG
#
# This test used to assert WARNING here, on the grounds that "no sibling" meant a
# real miss. That is exactly backwards for the run it fires on: with NEITHER
# transport table present, the AdminService/WMI phases never produced anything, so
# every table they would have built is expected to be absent. 106 of the 146
# WARNINGs in a low-privilege lab run were this one case. Case (c2) below keeps the
# signal the old test was really protecting.
# ---------------------------------------------------------------------------

def test_safe_no_sibling_and_no_privileged_transport_logs_debug(caplog):
    """Neither transport ran, so an absent transport table is expected, not news."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # Deliberately empty: no adminservice_* or wmi_* table exists.

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(con, "test<-wmi_baz", "SELECT 1 FROM sccm.wmi_baz")

    relevant = [r for r in caplog.records if "test<-wmi_baz" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-wmi_baz"
    for rec in relevant:
        assert rec.levelno == logging.DEBUG, (
            f"Expected DEBUG when no privileged transport ran, got {rec.levelname}: {rec.message}"
        )


# ---------------------------------------------------------------------------
# (c2) No sibling, but a privileged transport DID run -> WARNING
# ---------------------------------------------------------------------------

def test_safe_no_sibling_but_privileged_transport_ran_logs_warning(caplog):
    """AdminService worked and produced tables, yet THIS pair is missing -- real news.

    Distinguishes "we never had privilege" (expected) from "the transport was up and
    this one query came back with nothing" (a gap worth investigating).
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # A privileged transport landed *something*, just not wmi_baz or its sibling.
    con.execute("CREATE TABLE sccm.adminservice_unrelated (id INTEGER)")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(con, "test<-wmi_baz", "SELECT 1 FROM sccm.wmi_baz")

    relevant = [r for r in caplog.records if "test<-wmi_baz" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-wmi_baz"
    warning_records = [r for r in relevant if r.levelno == logging.WARNING]
    assert warning_records, (
        "Expected WARNING when a privileged transport ran but this table is absent; "
        f"got levels: {[r.levelname for r in relevant]}"
    )
```

Update the module docstring (lines 3-20), replacing the `Missing table with no sibling at all -> WARNING (unchanged)` line with:

```
  - Missing wmi_/adminservice_ table, no sibling, no privileged transport -> DEBUG
  - Missing wmi_/adminservice_ table, no sibling, but a privileged transport ran -> WARNING
```

- [ ] **Step 2: Run the tests to verify the first fails**

Run: `uv run pytest tests/transforms_safe_fallback_test.py -q`
Expected: `test_safe_no_sibling_and_no_privileged_transport_logs_debug` FAILS (`Expected DEBUG ... got WARNING`). `test_safe_no_sibling_but_privileged_transport_ran_logs_warning` PASSES already.

- [ ] **Step 3: Add case 3 to `_sccm_expected_miss`**

Replace the tail of `transforms.py` (lines 80-88):

```python
    try:
        found = con.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ?",
            [sibling],
        ).fetchone()
    except duckdb.Error:
        # Can't query the catalog — stay safe and treat as a real miss (WARNING).
        return False
    return found is not None
```

with:

```python
    try:
        found = con.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ?",
            [sibling],
        ).fetchone()
    except duckdb.Error:
        # Can't query the catalog — stay safe and treat as a real miss (WARNING).
        return False
    if found is not None:
        # Case 2: the other transport produced this data under the sibling name.
        return True

    # Case 3: NEITHER transport produced this table. When no adminservice_*/wmi_*
    # table exists at all the privileged phases never ran, so every table they would
    # have built is expected to be absent — that is an unprivileged run behaving
    # correctly, and it accounted for 106 of the 146 WARNINGs in a low-privilege lab
    # run. But when some DID land, this one query came back empty while its transport
    # was working, which is a real gap and stays a WARNING.
    return not _privileged_transport_ran(con)
```

Then update the function's docstring: `Two benign-miss cases are specific to this collector` becomes `Three benign-miss cases`, and add the third to the numbered list:

```
    3. No transport at all (wmi_ and adminservice_ both absent). If the catalog holds
       no privileged table whatsoever, the AdminService/WMI phases produced nothing
       this run, so their tables are expected to be missing. If some are present, an
       absent one is a real gap and stays a WARNING.
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/transforms_safe_fallback_test.py -q`
Expected: all pass, including the four untouched http_/smb_ fallback tests.

- [ ] **Step 5: Run the linters and full suite**

```powershell
uv run ruff check src tests
uv run mypy src\openhound_sccm
uv run pytest tests -q
```
Expected: all green.

- [ ] **Step 6: Commit (ask first)**

```bash
git add src/openhound_sccm/transforms.py tests/transforms_safe_fallback_test.py
git commit -m "refactor(<TICKET>): skipped transforms are DEBUG when no privileged transport ran"
```

---

## Task 6: Probe-negative levels (D4, D5)

**Repo:** `ConfigManBearPig`

**Files:**
- Modify: `src/openhound_sccm/collectors/http.py:310-312`
- Modify: `src/openhound_sccm/collectors/privileged.py:276-278`
- Test: `tests/probe_negative_levels_test.py` (create)

**Interfaces:**
- Consumes: `ErrorClass` (`clients/http.py:36`) with members `RESPONSE`, `CONNECT_FAILURE`, `TLS_FAILURE`; `HttpResult(status_code, content, error_class)` (`clients/http.py:43`)
- Produces: no signature changes. `_HttpProbe._request` still returns `Optional[HttpResult]` and still sets `self.connection_failed`; `_http_get_value` still returns `Optional[list]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/probe_negative_levels_test.py`:

```python
"""A probe that comes back negative is a discovery result, not a fault.

Two phases spend most of their time asking hosts "are you an X?" and being told
no. Reported at WARNING that is 17 lines per low-privilege run about hosts that
are behaving perfectly normally.

The two get DIFFERENT levels, deliberately:

* AdminService (privileged.py) already logs an INFO conclusion right after the
  404 -- "<host> is not a reachable AdminService provider; skipping". The 404 is
  the evidence behind that line, so promoting it to INFO would state the same
  fact twice per host. VERBOSE.
* HTTP (http.py) has NO conclusion line -- it logs only positives between
  "Attempting HTTP collection on: X" and "HTTP collection completed for X". Drop
  its connect failure below INFO and a host that served nothing reads as a clean
  successful collection. So there the message IS the conclusion. INFO.
"""
import logging

import pytest

from openhound_sccm.clients.http import ErrorClass, HttpResult
from openhound_sccm.collectors import http as http_collector
from openhound_sccm.collectors import privileged

HTTP_LOGGER = "openhound_sccm.collectors.http"
PRIV_LOGGER = "openhound_sccm.collectors.privileged"
URL = "https://ps1-dev.mayyhem.com/AdminService/wmi/SMS_Identification"


class _FakeClient:
    """Minimal HttpClient stand-in: returns one canned result per get()."""

    def __init__(self, result):
        self.result = result

    def get(self, _path):
        return self.result


def _probe(result):
    probe = http_collector._HttpProbe.__new__(http_collector._HttpProbe)
    probe.client = _FakeClient(result)
    probe.target = "ps1-dev.mayyhem.com"
    probe.connection_failed = False
    return probe


# --- D4: HTTP connect failure -------------------------------------------------

@pytest.mark.parametrize("error_class", [ErrorClass.CONNECT_FAILURE, ErrorClass.TLS_FAILURE])
def test_http_connect_failure_logs_info_not_warning(caplog, error_class):
    probe = _probe(HttpResult(status_code=None, content=None, error_class=error_class))

    with caplog.at_level(logging.DEBUG, logger=HTTP_LOGGER):
        assert probe._request(URL) is None

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    infos = [r for r in caplog.records if r.levelno == logging.INFO]
    assert infos, [r.levelname for r in caplog.records]
    assert "Unable to connect" in infos[0].getMessage()
    # The short-circuit behaviour must be untouched by a level change.
    assert probe.connection_failed is True


def test_http_connect_failure_message_does_not_repeat_the_host(caplog):
    """The [target] prefix is LogContextFilter's job; the URL already carries the host."""
    probe = _probe(HttpResult(None, None, ErrorClass.CONNECT_FAILURE))
    with caplog.at_level(logging.DEBUG, logger=HTTP_LOGGER):
        probe._request(URL)
    message = caplog.records[0].getMessage()
    assert message.count("ps1-dev.mayyhem.com") == 1, message


def test_http_success_is_returned_untouched(caplog):
    """Only the failure path changes; a real response still comes back."""
    ok = HttpResult(status_code=200, content=b"<xml/>", error_class=ErrorClass.RESPONSE)
    probe = _probe(ok)
    with caplog.at_level(logging.DEBUG, logger=HTTP_LOGGER):
        assert probe._request(URL) is ok
    assert probe.connection_failed is False


# --- D5: AdminService non-200 -------------------------------------------------

def _result(status):
    return HttpResult(status_code=status, content=b"{}", error_class=ErrorClass.RESPONSE)


def test_adminservice_404_while_probing_logs_verbose(caplog):
    """404 on the probe means "not an SMS Provider" -- a negative, not a fault."""
    client = _FakeClient(_result(404))
    with caplog.at_level(logging.DEBUG, logger=PRIV_LOGGER):
        assert privileged._http_get_value(client, "/AdminService/wmi/SMS_Identification",
                                          probing=True) is None

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("not an SMS Provider" in r.getMessage() for r in caplog.records), \
        [r.getMessage() for r in caplog.records]


@pytest.mark.parametrize("status", [401, 403, 500, 503])
def test_adminservice_non_404_while_probing_still_warns(caplog, status):
    """A provider that exists and rejected us, or broke, is a finding -- stay loud."""
    client = _FakeClient(_result(status))
    with caplog.at_level(logging.DEBUG, logger=PRIV_LOGGER):
        assert privileged._http_get_value(client, "/AdminService/wmi/SMS_Identification",
                                          probing=True) is None

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, [r.levelname for r in caplog.records]
    assert str(status) in warnings[0].getMessage()


def test_adminservice_404_when_not_probing_still_warns(caplog):
    """Past the probe the host IS a provider, so a 404 means a short collection."""
    client = _FakeClient(_result(404))
    with caplog.at_level(logging.DEBUG, logger=PRIV_LOGGER):
        assert privileged._http_get_value(client, "/AdminService/wmi/SMS_Role") is None

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, [r.levelname for r in caplog.records]
    assert "404" in warnings[0].getMessage()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/probe_negative_levels_test.py -q`
Expected: `test_http_connect_failure_logs_info_not_warning` (both params) and `test_adminservice_404_while_probing_logs_verbose` FAIL — both find a WARNING. The other five PASS already.

`_probe()` bypasses `__init__` on purpose: `_request` reads only `self.client` and writes only `self.connection_failed` (verified against `http.py:306-315`), so constructing the full probe would drag in an `HttpClient` and a `SourceContext` for nothing. `target` is set anyway so a failure message stays readable if one of these tests ever regresses.

- [ ] **Step 3: Change the HTTP level (D4)**

In `src/openhound_sccm/collectors/http.py`, replace lines 310-312:

```python
        if _is_connection_failure(result):
            logger.warning("Unable to connect to %s (%s) - skipping remaining HTTP checks",
                           url, result.error_class.value)
```

with:

```python
        if _is_connection_failure(result):
            # A host that does not serve this endpoint is a discovery RESULT, not a
            # fault -- and unlike the AdminService probe, this phase has no separate
            # "not an MP/DP" conclusion line, logging only positives between
            # "Attempting HTTP collection on" and "HTTP collection completed". So this
            # line IS the conclusion and stays on the default console at INFO; drop it
            # lower and a host that served nothing reads as a clean collection.
            logger.info("Unable to connect to %s (%s); skipping remaining HTTP checks",
                        url, result.error_class.value)
```

- [ ] **Step 4: Change the AdminService level (D5)**

In `src/openhound_sccm/collectors/privileged.py`, replace lines 276-278:

```python
    if result.status_code != 200:
        logger.warning("AdminService GET %s returned HTTP %s", path, result.status_code)
        return None
```

with:

```python
    if result.status_code != 200:
        if probing and result.status_code == 404:
            # No AdminService at this path: the host is not an SMS Provider. The caller
            # turns this into the INFO "is not a reachable AdminService provider;
            # skipping" line, so this is only the evidence behind it -- promoting it to
            # INFO would state the same fact twice per non-provider host.
            logger.verbose("AdminService GET %s returned HTTP 404; not an SMS Provider", path)
        else:
            # Any other status while probing means the provider IS there and rejected us
            # (401/403) or broke (500) -- a finding, not a negative. And past the probe,
            # the host is known to be a provider, so any non-200 is a short collection.
            logger.warning("AdminService GET %s returned HTTP %s", path, result.status_code)
        return None
```

Then extend the `_http_get_value` docstring, which currently explains `probing` for connect failures only:

```
    The same distinction applies to a 404: while probing it means "no AdminService
    here", so it is VERBOSE. Any other status while probing, and any non-200 once the
    host is known to be a provider, stays a WARNING.
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/probe_negative_levels_test.py -q`
Expected: all pass.

- [ ] **Step 6: Run the linters and full suite**

```powershell
uv run ruff check src tests
uv run mypy src\openhound_sccm
uv run pytest tests -q
```
Expected: all green.

- [ ] **Step 7: Commit (ask first)**

```bash
git add src/openhound_sccm/collectors/http.py src/openhound_sccm/collectors/privileged.py tests/probe_negative_levels_test.py
git commit -m "refactor(<TICKET>): probe negatives are discovery results, not warnings"
```

---

## Task 7: Bump the dependency floor

**Repo:** `ConfigManBearPig` · **Requires:** Task 3 complete and `0.1.4` live on PyPI

**Files:**
- Modify: `pyproject.toml:43-47`
- Modify: `uv.lock` (regenerated, not hand-edited)

**Interfaces:**
- Consumes: `openhound-collector-common==0.1.4` from PyPI
- Produces: nothing downstream

- [ ] **Step 1: Confirm 0.1.4 is actually published**

`uv pip index versions` does not exist in this uv build. Ask PyPI directly, and use the venv
interpreter rather than `uv run` — `uv run` re-syncs first, so once the floor is bumped it fails before
your query executes:

```bash
./.venv/Scripts/python.exe -c "
import json, urllib.request
with urllib.request.urlopen('https://pypi.org/pypi/openhound-collector-common/json', timeout=20) as r:
    print(sorted(json.load(r)['releases']))
"
```
Expected: `0.1.4` in the list. **Stop here if not** — Task 3 has not finished. A pushed tag is not a
published release: `release.yml` parks in the `pypi` environment until a reviewer approves it, so
`git ls-remote --tags origin` showing `v0.1.4` proves only that the tag landed.

- [ ] **Step 2: Raise the floor**

In `pyproject.toml`, replace line 47 and extend the comment above it (lines 43-46 explain the cap; add why the floor moved):

```toml
    # Capped below 0.2 because a 0.x library makes no API-stability promise — an
    # uncapped floor would let a breaking 0.2 land silently in users' installs.
    # Floor is 0.1.4: that release silences impacket's Python 3.14 SyntaxWarning at
    # the import that triggers it (clients/mssql.py -> impacket.tds ->
    # impacket.mssql.version:182, a return inside a finally block), and shortens the
    # skipped-transform log from a five-line DuckDB exception dump to one line.
    # 0.1.3 added StagePaths.graph_zip, which the --run-all output summary reads to
    # name the archive the chain actually wrote.
    "openhound-collector-common>=0.1.4,<0.2.0",
```

- [ ] **Step 3: Re-resolve and verify the installed version**

**`--refresh-package` is required, not optional.** uv caches the package index, so a plain `uv sync`
right after a release resolves against stale metadata and fails with
`Because only openhound-collector-common<=0.1.3 is available … requirements are unsatisfiable` —
which looks exactly like "the release did not publish" even when PyPI already serves it. Step 1 is what
tells the two apart.

```bash
uv sync --group dev --refresh-package openhound-collector-common
./.venv/Scripts/python.exe -c "import importlib.metadata as m; print(m.version('openhound-collector-common'))"
```
Expected: `0.1.4`.

- [ ] **Step 4: Verify the warning is actually gone end to end**

```bash
uv run python -c "
import os, subprocess, sys, tempfile
with tempfile.TemporaryDirectory() as d:
    env = {**os.environ, 'PYTHONPYCACHEPREFIX': d}
    r = subprocess.run([sys.executable, '-W', 'error::SyntaxWarning', '-c',
                        'import openhound_collector_common.clients.mssql'],
                       capture_output=True, text=True, env=env)
    print('exit', r.returncode); print(r.stderr[-400:])
"
```
Expected: `exit 0` and no `SyntaxWarning` / `SyntaxError` in stderr.

- [ ] **Step 5: Run the linters and full suite**

```powershell
uv run ruff check src tests
uv run mypy src\openhound_sccm
uv run pytest tests -q
```
Expected: all green.

- [ ] **Step 6: Commit (ask first)**

```bash
git add pyproject.toml uv.lock
git commit -m "build(<TICKET>): require openhound-collector-common>=0.1.4"
```

---

## Task 8: Documentation, acceptance run, and ticket close

**Repo:** `ConfigManBearPig`

**Files:**
- Modify: `README.md` — the "What a low-privilege run looks like" bullet list
- Modify: `ARCHITECTURE.md:698-718` — §7 "Expected-failure triage"
- Modify: `ARCHITECTURE.md` changelog — a **new** entry, leaving 2026-08-01's alone
- Modify: `.tickets/`

**Interfaces:**
- Consumes: Tasks 4-7 all landed
- Produces: nothing

- [ ] **Step 1: Add the two new cases to README's low-privilege section**

After the "Refused registry reads" bullet Task 4 rewrote, and before the "impacket's Kerberos-cache notice" bullet, insert:

````markdown
- **Skipped preprocess transforms.** Most `node_*` and edge tables are built from AdminService or WMI
  data. Without privilege neither transport produces anything, so the transforms that read them are
  skipped — 106 of them in a nine-host lab run. When *no* privileged table exists at all this is an
  unprivileged run behaving correctly, so each skip is logged at DEBUG. If AdminService *did* run and a
  single table is still missing, that one stays a WARNING: the transport was up and that query came
  back empty, which is worth investigating.

- **Probes that come back negative.** Asking a host "are you an SMS Provider?" and being told no is a
  discovery result, not a failure. A host that does not serve the endpoint is reported at INFO
  (`Unable to connect to https://… ; skipping remaining HTTP checks`), and an AdminService probe
  answered with HTTP 404 at VERBOSE — the INFO line right behind it,
  `… is not a reachable AdminService provider; skipping`, is the conclusion worth reading. A 401, 403
  or 500 is **not** downgraded: those mean the provider exists and rejected you or broke, which is a
  finding.
````

- [ ] **Step 2: Update ARCHITECTURE §7**

In the "Expected-failure triage, so severity means something" bullet (line 698), rewrite the "Refused registry reads" sub-bullet's last sentences — it currently describes the summary as naming capabilities. Then add two sub-bullets alongside it and the impacket CRITICAL one:

````markdown
  - **Transport tables that were never collected.** `_sccm_expected_miss` downgrades a missing
    `wmi_`/`adminservice_` source from WARNING to DEBUG in two situations: the sibling transport
    produced the data under the other name, or — added 2026-08-02 — *no* privileged table exists at
    all, meaning the AdminService/WMI phases never ran. The second case was 106 of the 146 WARNINGs a
    healthy low-privilege run emitted. The narrow condition matters: when some privileged tables *did*
    land, an absent one means that query came back empty while its transport was working, and stays a
    WARNING.
  - **Probes that come back negative.** `_HttpProbe._request` and `_http_get_value` spend most of their
    calls establishing that a host is *not* a given role. Both were WARNING. They now split by whether
    a separate conclusion line already exists: `privileged.py` logs
    `"%s is not a reachable AdminService provider; skipping"` at INFO right after the 404, so the 404
    itself is only evidence and drops to VERBOSE; `http.py` has no such line, so its connect failure
    *is* the conclusion and sits at INFO. Status codes other than 404 are never downgraded — a 401/403
    means the provider exists and refused you.
````

- [ ] **Step 3: Add a changelog entry**

Add a new dated row to the ARCHITECTURE changelog table. **Do not edit the 2026-08-01 entry at line 2058**, even though it documents the capability-naming roll-up this change replaces — the changelog is a record of what changed when. Say explicitly that this supersedes it:

```
| 2026-08-02 | **A healthy low-privilege run stopped emitting 146 WARNINGs** (§7; <TICKET>). Every one was the collector working as designed, which is the same failure mode the 2026-08-01 entry fixed one severity level up — an operator who learns to ignore the file cannot find the 23 real entries in it. **(1) Transport tables that were never collected.** `_sccm_expected_miss` gained a third case: a missing `wmi_`/`adminservice_` table whose sibling is *also* absent is DEBUG when the catalog holds no privileged table at all, because then the AdminService/WMI phases never ran. 106 of the 146. It stays a WARNING when some privileged tables did land, which is the case the old `test_safe_no_sibling_logs_warning` was really protecting — that test asserted the opposite for the no-transport case and was inverted deliberately. **(2) Probe negatives.** A host answering the AdminService probe with 404 is not an SMS Provider, and a host refusing the HTTP probe does not serve that endpoint; both are discovery results. The 404 drops to VERBOSE because `privileged.py` already logs an INFO conclusion immediately after it, and the HTTP connect failure drops to INFO because `http.py` has no conclusion line — below INFO, a host that served nothing would read as a clean collection. 401/403/500 are untouched: a provider that exists and refuses you is a finding. **(3) The RemoteRegistry roll-up lists keys, superseding the capability names introduced 2026-08-01.** `_DENIED_CAPABILITIES` and `_capability_for` are deleted; the message is now the distinct denied key paths, one per line, and the count is of keys rather than reads so it always matches the list. The "requires local Administrators, re-run as admin" prose moved to README's low-privilege section, which said it already. Both RemoteRegistry warnings also dropped the trailing `on <host>` — `LogContextFilter` prefixes `[target][phase]` on every record from a per-host phase, so it was always duplication. **(4) impacket's Python 3.14 SyntaxWarning**, from a `return` inside a `finally` at `mssql/version.py:182`, is silenced in `openhound-collector-common` 0.1.4 by a scoped `catch_warnings()` around the `from impacket import ntlm, tds` that triggers the compile — scoped, so a return-in-finally in our own code still reports. `module=` filters do not work on compile-time warnings: `warnings.py` derives the module from the file path, not the dotted name. Floor raised to `>=0.1.4`. |
```

- [ ] **Step 4: Acceptance run against the lab**

Re-run the collection that produced the baseline, then count:

```bash
uv run openhound collect sccm ./out/verify-lowpriv -d mayyhem.com -u MAYYHEM\\lowpriv -p '<password>' --run-all
grep -c "\[WARNING " ./out/verify-lowpriv/collect_issues_*.log
```
Expected: **23**, down from 146. None of them from the five reclassified categories — verify with:

```bash
grep -E "\[WARNING " ./out/verify-lowpriv/collect_issues_*.log \
  | grep -cE "Unable to connect to|returned HTTP 404|transform .* skipped.*(adminservice_|wmi_)"
```
Expected: `0`. Note the transform pattern is scoped to the two transport prefixes on purpose — a bare
`transform .* skipped` also matches `remoteregistry_mssql_servers`, which D3 deliberately leaves at
WARNING, and would report `1` on a correct run.

If the count differs, do not adjust the target — find out which category moved and why. A *lower*
number than 23 means something legitimate got swallowed.

**Result (2026-08-02, `out/verify-lowpriv`, lowpriv / `-m All` / `--disable-possible-edges`):** 23
WARNINGs, and every bucket matched the spec's §1 prediction exactly — 9 RemoteRegistry roll-ups,
5 `SMS\Triggers`, 4 site-code conflicts, 2 competing-site-code, 1 `remoteregistry_mssql_servers`,
1 LDAP `S-1-5-18`, 1 summary line. The run exits **1**, which is `--run-integration-tests` reporting
50 passed / 4 failed (`SCCM_ClientDevice`, `SCCM_HasClient`, `SCCM_SameHostAs` ×2) — byte-identical to
the baseline, so pre-existing and not caused by this change. Redirecting stdout produces a **0-byte**
console log: the framework picks its logging mode from `sys.stdout.isatty()` and a redirected run gets
only a file handler. Use `LOG_CONTAINER=1` if you need the console stream captured.

- [ ] **Step 5: Full check run**

```powershell
uv run ruff check src tests
uv run mypy src\openhound_sccm
uv run pytest tests -q
uv run python dev/regen_ticket_index.py --check
```
Expected: all green, index not stale.

- [ ] **Step 6: Close the ticket**

```bash
gtk close <TICKET>
uv run python dev/regen_ticket_index.py
uv run python dev/regen_ticket_index.py --check
```

- [ ] **Step 7: Commit (ask first)**

```bash
git add README.md ARCHITECTURE.md .tickets/
git commit -m "docs(<TICKET>): record the expected-failure triage cases and the new roll-up shape"
```

---

## Appendix: cutting the openhound-collector-common release

Recorded here because it is the one step in this plan that cannot be undone.

**The tag is the release.** `hatch-vcs` derives the package version from it, so there is no number to bump by hand and nothing to upload manually.

```bash
cd /c/Users/domainadmin/Desktop/openhound-collector-common
git checkout main
git pull
git log --oneline -3        # the tag lands on HEAD -- confirm it is the right commit
git status --short          # must be clean

git tag -a v0.1.4 -m "Silence impacket's Python 3.14 SyntaxWarning; one-line skipped-transform log"
git push origin v0.1.4
```

Pushing a `v*` tag triggers [`release.yml`](../../../../openhound-collector-common/.github/workflows/release.yml), which builds, asserts the built version matches the tag, and publishes to PyPI through trusted publishing. The job runs in the `pypi` GitHub environment, which has a **required reviewer** — each release is a deliberate click, not an automatic consequence of the push.

**PyPI filenames are immutable.** A tag on the wrong commit burns that version number permanently; the recovery is `v0.1.5`, not a re-upload. Check `git log` before tagging.

**Local development against an unreleased shared library.** There is deliberately no `[tool.uv.sources]` in ConfigManBearPig's `pyproject.toml` — a `path = "../openhound-collector-common"` entry breaks CI and every clone that lacks a sibling checkout. To test Tasks 4-6 against the unreleased library before Task 3 finishes, add the redirect temporarily and hide it from git:

```toml
[tool.uv.sources]
openhound-collector-common = { path = "../openhound-collector-common", editable = true }
```

```bash
git update-index --skip-worktree pyproject.toml
uv sync --group dev
```

Reverse it before Task 7:

```bash
git update-index --no-skip-worktree pyproject.toml
git checkout pyproject.toml
uv sync --group dev
```

Two alternatives that look right and are not, both already tested: `uv pip install -e ../openhound-collector-common` installs a **copy**, so edits are invisible and the next `uv sync` reverts it; and `[sources]` in a gitignored `uv.toml` is rejected outright.
