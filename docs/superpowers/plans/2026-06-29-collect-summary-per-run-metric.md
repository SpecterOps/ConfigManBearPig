# Collect Summary: True Per-Run Metric Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the collect summary's on-disk directory scan with a true per-run row-count metric sourced from dlt, so the summary reflects only what *this* run extracted and never counts stale/orphan table folders.

**Architecture:** A collect invocation runs two `pipeline.run` passes on one dlt pipeline — Stage 1 (discovery) via `collector.run(...)` and Stage 2 (per-host streaming) via `_run_per_host_stage(...)`. dlt records per-run row counts on each run's pipeline trace (`pipeline.last_trace.last_normalize_info.row_counts`). We read those counts from the in-memory trace of each pass (Stage 1 via `LoadInfo.pipeline`, Stage 2 via the pipeline object the stage already holds), merge them, and print them. The summary additionally warns when a stage produced no counts (partial run) and when stale table folders not in the canonical table universe are found on disk.

**Tech Stack:** Python 3, dlt (filesystem destination, JSONL), pytest with `caplog`/`tmp_path`, Typer CLI.

## Global Constraints

- Only modify code under `sccm/sccm/`. Do not edit OpenHound framework code (the `.venv` / `openhound` package). Verbatim from CLAUDE.md.
- Tests live under `sccm/sccm/tests/`, organized; new tests use the `<name>_test.py` convention (matches recent files like `dedup_client_device_test.py`).
- Write logs of appropriate level (error / warning / info / verbose / debug) for every if/else and try/except branch, unless there is no need (then leave a comment).
- Prioritize readability; simplify and remove unnecessary code (delete the old disk-scan path entirely — no backwards-compat retention).
- Preserve/update comments to capture intent, not line-by-line provenance.

---

### Task 1: `_normalize_row_counts` helper

A small, defensive reader that turns a dlt pipeline's most-recent normalize step into a `{table: rows}` dict. Isolating the dlt API access here keeps the wiring trivial and the behavior unit-testable without running dlt.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (add a module-level function near `_log_collect_summary`, ~line 1024)
- Test: `sccm/sccm/tests/collect_summary_test.py` (new)

**Interfaces:**
- Produces: `_normalize_row_counts(pipeline) -> dict[str, int]` — reads `pipeline.last_trace.last_normalize_info.row_counts`, drops `_dlt*` bookkeeping tables, returns `{}` on any missing-trace / error condition. Consumed by Task 3.

- [ ] **Step 1: Write the failing tests**

Create `sccm/sccm/tests/collect_summary_test.py`:

```python
from openhound_sccm import main as sccm_main


class _FakeNormalizeInfo:
    def __init__(self, row_counts):
        self.row_counts = row_counts


class _FakeTrace:
    def __init__(self, info):
        self.last_normalize_info = info


class _FakePipeline:
    def __init__(self, trace):
        self._trace = trace

    @property
    def last_trace(self):
        return self._trace


def test_normalize_row_counts_strips_dlt_bookkeeping_tables():
    pipe = _FakePipeline(
        _FakeTrace(
            _FakeNormalizeInfo(
                {"ldap_sites": 2, "_dlt_pipeline_state": 1, "smb_computers": 5}
            )
        )
    )
    assert sccm_main._normalize_row_counts(pipe) == {
        "ldap_sites": 2,
        "smb_computers": 5,
    }


def test_normalize_row_counts_returns_empty_when_no_trace():
    assert sccm_main._normalize_row_counts(_FakePipeline(None)) == {}


def test_normalize_row_counts_returns_empty_when_no_normalize_info():
    assert sccm_main._normalize_row_counts(_FakePipeline(_FakeTrace(None))) == {}


def test_normalize_row_counts_swallows_errors():
    class _Boom:
        @property
        def last_trace(self):
            raise RuntimeError("trace exploded")

    assert sccm_main._normalize_row_counts(_Boom()) == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd sccm/sccm && uv run pytest tests/collect_summary_test.py -v`
Expected: FAIL with `AttributeError: module 'openhound_sccm.main' has no attribute '_normalize_row_counts'`

- [ ] **Step 3: Implement the helper**

Add to `sccm/sccm/src/openhound_sccm/main.py`, immediately above `_log_collect_summary` (currently ~line 1024):

```python
def _normalize_row_counts(pipeline) -> dict[str, int]:
    """Return ``{table_name: rows}`` from *pipeline*'s most recent normalize step.

    dlt records per-run row counts on the pipeline trace. ``last_trace`` is
    replaced by each multi-step ``pipeline.run``, so callers must read this right
    after the run whose counts they want — not once at the end. dlt bookkeeping
    tables (``_dlt_*``) are dropped. Returns ``{}`` when no trace or normalize
    info is available (e.g. a run that failed before normalize); the summary
    treats an empty result from an expected stage as a "partial run" signal.
    """
    try:
        trace = pipeline.last_trace
        if trace is None:
            # No run has completed on this pipeline object yet.
            logger.debug("No dlt trace on pipeline; row counts unavailable")
            return {}
        info = trace.last_normalize_info
        if info is None:
            # Trace exists but the run never reached the normalize step.
            logger.debug("No dlt normalize info on trace; row counts unavailable")
            return {}
        return {
            table: int(rows)
            for table, rows in info.row_counts.items()
            if not table.startswith("_dlt")
        }
    except Exception as ex:
        # A metrics read must never break the collection summary.
        logger.warning("Could not read dlt row counts for the collection summary: %s", ex)
        return {}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd sccm/sccm && uv run pytest tests/collect_summary_test.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add sccm/sccm/src/openhound_sccm/main.py sccm/sccm/tests/collect_summary_test.py
git commit -m "feat(sccm): add _normalize_row_counts dlt metric reader"
```

---

### Task 2: Rewrite `_log_collect_summary` to use merged per-run counts

Replace the directory-scan body with: merge the two stages' counts, print them, warn when an expected stage reported nothing (partial), and warn about stale/orphan table folders. The orphan check compares disk folders against the canonical table universe (`_preproc_table_map()` keys) rather than this run's counts, so a current table that legitimately got 0 rows is never mis-flagged.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py:1024-1063` (replace the entire `_log_collect_summary` function, including its old `import gzip`)
- Test: `sccm/sccm/tests/collect_summary_test.py` (extend)

**Interfaces:**
- Consumes: `_preproc_table_map() -> dict[str, str]` (already defined at ~line 1073; its keys are the authoritative table-name universe).
- Produces: `_log_collect_summary(discovery_counts: dict[str, int], per_host_counts: dict[str, int], per_host_expected: bool, output_path: pathlib.Path) -> None`. Consumed by Task 3.

- [ ] **Step 1: Write the failing tests**

Append to `sccm/sccm/tests/collect_summary_test.py`:

```python
import logging


def test_summary_prints_merged_counts_sorted_desc(caplog):
    caplog.set_level(logging.INFO, logger=sccm_main.__name__)
    sccm_main._log_collect_summary(
        discovery_counts={"ldap_sites": 2},
        per_host_counts={"smb_computers": 5, "remoteregistry_users": 1},
        per_host_expected=True,
        output_path=__import__("pathlib").Path("does/not/exist"),
    )
    messages = [r.getMessage() for r in caplog.records]
    assert any("Extracted 8 rows across 3 resources" in m for m in messages)
    # Highest count first.
    rows = [m for m in messages if m.strip().startswith(("ldap_sites", "smb_computers", "remoteregistry_users"))]
    assert rows[0].strip().startswith("smb_computers")


def test_summary_warns_when_discovery_empty(caplog):
    caplog.set_level(logging.WARNING, logger=sccm_main.__name__)
    sccm_main._log_collect_summary(
        discovery_counts={},
        per_host_counts={"smb_computers": 5},
        per_host_expected=True,
        output_path=__import__("pathlib").Path("does/not/exist"),
    )
    assert any("Discovery stage reported no row counts" in r.getMessage() for r in caplog.records)


def test_summary_warns_when_expected_per_host_empty(caplog):
    caplog.set_level(logging.WARNING, logger=sccm_main.__name__)
    sccm_main._log_collect_summary(
        discovery_counts={"ldap_sites": 2},
        per_host_counts={},
        per_host_expected=True,
        output_path=__import__("pathlib").Path("does/not/exist"),
    )
    assert any("Per-host stage reported no row counts" in r.getMessage() for r in caplog.records)


def test_summary_no_per_host_warning_when_not_expected(caplog):
    caplog.set_level(logging.WARNING, logger=sccm_main.__name__)
    sccm_main._log_collect_summary(
        discovery_counts={"ldap_sites": 2},
        per_host_counts={},
        per_host_expected=False,
        output_path=__import__("pathlib").Path("does/not/exist"),
    )
    assert not any("Per-host stage reported no row counts" in r.getMessage() for r in caplog.records)


def test_summary_warns_about_orphan_folders(caplog, tmp_path):
    caplog.set_level(logging.WARNING, logger=sccm_main.__name__)
    dataset = tmp_path / "sccm"
    dataset.mkdir()
    # One known (current) table, one stale orphan, one dlt bookkeeping dir.
    (dataset / "ldap_sites").mkdir()
    (dataset / "computers").mkdir()  # stale: renamed to remoteregistry_computers
    (dataset / "_dlt_loads").mkdir()
    sccm_main._log_collect_summary(
        discovery_counts={"ldap_sites": 2},
        per_host_counts={},
        per_host_expected=False,
        output_path=tmp_path,
    )
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    orphan_warnings = [m for m in warnings if "stale table folder" in m]
    assert len(orphan_warnings) == 1
    assert "computers" in orphan_warnings[0]
    assert "ldap_sites" not in orphan_warnings[0]
    assert "_dlt_loads" not in orphan_warnings[0]


def test_summary_no_orphan_warning_when_all_known(caplog, tmp_path):
    caplog.set_level(logging.WARNING, logger=sccm_main.__name__)
    dataset = tmp_path / "sccm"
    dataset.mkdir()
    (dataset / "ldap_sites").mkdir()
    (dataset / "remoteregistry_computers").mkdir()
    sccm_main._log_collect_summary(
        discovery_counts={"ldap_sites": 2},
        per_host_counts={"remoteregistry_computers": 1},
        per_host_expected=True,
        output_path=tmp_path,
    )
    assert not any("stale table folder" in r.getMessage() for r in caplog.records)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd sccm/sccm && uv run pytest tests/collect_summary_test.py -v`
Expected: FAIL — the new tests call `_log_collect_summary` with the new 4-arg signature, but the current function takes `(load_info, output_path)`, so they raise `TypeError`.

- [ ] **Step 3: Replace the function**

In `sccm/sccm/src/openhound_sccm/main.py`, replace the entire existing `_log_collect_summary` (currently lines ~1024-1063, the version that does `import gzip` and `dataset_dir.iterdir()` row counting) with:

```python
def _log_collect_summary(
    discovery_counts: dict[str, int],
    per_host_counts: dict[str, int],
    per_host_expected: bool,
    output_path: pathlib.Path,
) -> None:
    """Emit an end-of-collection summary at INFO level.

    Row counts are a TRUE per-run metric: they come from dlt's normalize step
    for this run's two passes (discovery + per-host), merged here. This replaces
    the old on-disk directory scan, which double-counted stale tables left by
    older code or prior runs. The final node/edge totals aren't known yet — those
    come from ``output.py::package`` after convert.
    """
    logger.info("Collection complete.")
    logger.info("Raw output directory: %s", output_path)

    # Merge the two stages. Their table sets are disjoint (discovery emits
    # ldap_*/dns_*/local_*/collection_settings; per-host emits the rest), but sum
    # on overlap so a future shared table can never silently drop rows.
    counts: dict[str, int] = dict(discovery_counts)
    for table, rows in per_host_counts.items():
        counts[table] = counts.get(table, 0) + rows

    # A stage we expected to run but got no counts from means the numbers below
    # are partial — e.g. the stage raised before dlt normalized, or its trace was
    # lost. Surface it rather than silently under-reporting.
    if not discovery_counts:
        logger.warning("Discovery stage reported no row counts; the collection summary may be incomplete.")
    if per_host_expected and not per_host_counts:
        logger.warning("Per-host stage reported no row counts; the collection summary may be incomplete.")

    if counts:
        total = sum(counts.values())
        logger.info("Extracted %d rows across %d resources:", total, len(counts))
        for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            logger.info("    %-40s %d", name, count)
    else:
        # Both stages empty — nothing was extracted at all.
        logger.warning("No rows were extracted during this collection run.")

    # Flag stale/orphan table folders so an operator notices data left by older
    # code or earlier runs (e.g. a renamed resource). Compared against the
    # authoritative table universe (the preproc map) rather than this run's
    # counts, so a current table that legitimately got 0 rows is never mis-flagged.
    try:
        dataset_dir = output_path / "sccm"
        if dataset_dir.is_dir():
            known = set(_preproc_table_map().keys())
            on_disk = {
                d.name
                for d in dataset_dir.iterdir()
                if d.is_dir() and not d.name.startswith("_dlt")
            }
            orphans = sorted(on_disk - known)
            if orphans:
                logger.warning(
                    "Found %d stale table folder(s) under %s not produced by any current "
                    "collector (likely from older code or prior runs): %s. Preprocess/convert "
                    "ignore them, but you may want to delete them.",
                    len(orphans), dataset_dir, ", ".join(orphans),
                )
            else:
                logger.debug("No orphan table folders under %s", dataset_dir)
        else:
            logger.debug("Dataset dir %s missing; skipping orphan-folder check", dataset_dir)
    except Exception as ex:
        # Orphan detection is best-effort — never fail collect because of it.
        logger.error("Orphan-folder check failed: %s", ex)

    logger.info(
        "Next steps: 'openhound preprocess sccm <raw> <lookup.duckdb>' then "
        "'openhound convert sccm <raw>/sccm <graph> --lookup-file <lookup.duckdb>'"
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd sccm/sccm && uv run pytest tests/collect_summary_test.py -v`
Expected: PASS (all Task 1 + Task 2 tests green)

- [ ] **Step 5: Commit**

```bash
git add sccm/sccm/src/openhound_sccm/main.py sccm/sccm/tests/collect_summary_test.py
git commit -m "feat(sccm): summary uses merged per-run counts + orphan/partial warnings"
```

---

### Task 3: Capture and plumb the per-run counts into the summary

Wire the helper into the two stages: read Stage 1's counts from `LoadInfo.pipeline`, return Stage 2's counts out of `_run_per_host_stage`, and call the new summary with both. This is what makes the per-run metric live.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py:761` (`_run_per_host_stage` signature + capture + return)
- Modify: `sccm/sccm/src/openhound_sccm/main.py:972-994` (`collect_sccm`: capture discovery counts, capture per-host counts, new summary call)
- Test: `sccm/sccm/tests/collect_summary_test.py` (extend)

**Interfaces:**
- Consumes: `_normalize_row_counts(pipeline)` (Task 1); `_log_collect_summary(discovery_counts, per_host_counts, per_host_expected, output_path)` (Task 2).
- Produces: `_run_per_host_stage(pipeline, work_queue, ctx, threads, maxsize=1000, phases=None) -> dict[str, int]` (was `-> None`).

- [ ] **Step 1: Write the failing test**

Append to `sccm/sccm/tests/collect_summary_test.py`:

```python
def test_run_per_host_stage_returns_dlt_counts(monkeypatch):
    """The stage must return this run's dlt row counts so collect_sccm can
    feed them to the summary."""
    from openhound_sccm import phased_pipeline as pp

    # No-op engine so the background pool thread finishes immediately.
    monkeypatch.setattr(pp, "run_pipeline", lambda *a, **k: None)
    # Force the metric read to a known value.
    monkeypatch.setattr(sccm_main, "_normalize_row_counts", lambda pipeline: {"smb_computers": 7})

    class _FakePipeline:
        def run(self, *a, **k):
            return None

    result = sccm_main._run_per_host_stage(_FakePipeline(), work_queue=None, ctx=None, threads=1)
    assert result == {"smb_computers": 7}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd sccm/sccm && uv run pytest tests/collect_summary_test.py::test_run_per_host_stage_returns_dlt_counts -v`
Expected: FAIL with `assert None == {'smb_computers': 7}` (the function currently returns `None`).

- [ ] **Step 3: Make `_run_per_host_stage` return its counts**

In `sccm/sccm/src/openhound_sccm/main.py`, change the signature (line ~761):

```python
def _run_per_host_stage(pipeline, work_queue, ctx, threads, maxsize: int = 1000, phases=None) -> dict[str, int]:
```

Initialize a counts dict before the `try` (just before `pool_thread = threading.Thread(...)`, line ~816):

```python
    per_host_counts: dict[str, int] = {}
```

Inside the existing `try` block, immediately after the `pipeline.run(...)` call returns (line ~825, before the `finally:`), capture the counts:

```python
        # Capture this run's per-table row counts from dlt's normalize step while
        # the in-memory trace still reflects the per-host pass — a later run on the
        # same pipeline would replace it.
        per_host_counts = _normalize_row_counts(pipeline)
```

Add the return after the `finally` block completes (the last line of the function, after the env-restore loop):

```python
    return per_host_counts
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd sccm/sccm && uv run pytest tests/collect_summary_test.py::test_run_per_host_stage_returns_dlt_counts -v`
Expected: PASS

- [ ] **Step 5: Wire `collect_sccm` to capture and pass both stages' counts**

In `sccm/sccm/src/openhound_sccm/main.py`, in `collect_sccm`:

Replace the Stage 1 line (line ~972):

```python
        load_info = collector.run(src.with_resources(*DISCOVERY_RESOURCE_NAMES))
```

with:

```python
        load_info = collector.run(src.with_resources(*DISCOVERY_RESOURCE_NAMES))
        # Capture discovery row counts from the pipeline that just ran (held via
        # LoadInfo.pipeline) before the per-host pass replaces the trace.
        discovery_counts = _normalize_row_counts(load_info.pipeline) if load_info else {}
```

Replace the Stage 2 guard block (lines ~983-984):

```python
        if per_host_ctx is not None and PER_HOST_PHASES:
            _run_per_host_stage(collector.pipeline, work_queue, per_host_ctx, threads)
```

with:

```python
        per_host_counts: dict[str, int] = {}
        per_host_expected = bool(per_host_ctx is not None and PER_HOST_PHASES)
        if per_host_expected:
            per_host_counts = _run_per_host_stage(collector.pipeline, work_queue, per_host_ctx, threads)
```

Replace the summary call (line ~994):

```python
            _log_collect_summary(load_info, output_path)
```

with:

```python
            _log_collect_summary(discovery_counts, per_host_counts, per_host_expected, output_path)
```

- [ ] **Step 6: Run the full SCCM test suite to confirm no regressions**

Run: `cd sccm/sccm && uv run pytest -q`
Expected: PASS (no failures). The pre-existing suite plus the new `collect_summary_test.py` all green.

- [ ] **Step 7: Manual smoke verification**

Run a real collect (lab) into a fresh empty directory and confirm:
- The "Extracted N rows across M resources" counts now come from dlt and match the actual rows written this run.
- No `computers` / `users` / `sccm_sites` (or other stale) names appear in the counts.
- To confirm the orphan warning fires, create a dummy stale folder before re-running and check for the "stale table folder(s)" WARNING:

```bash
mkdir -p <output>/sccm/computers && touch <output>/sccm/computers/x.jsonl
# re-run collect, then look for the WARNING line in the console / collect_log_*.log
```

- [ ] **Step 8: Commit**

```bash
git add sccm/sccm/src/openhound_sccm/main.py sccm/sccm/tests/collect_summary_test.py
git commit -m "feat(sccm): wire per-run dlt counts into collect summary"
```

---

## Notes / Out of Scope

- **README:** This change is operator-visible (summary wording, new WARNINGs). If the README documents collect output, add a one-line note that counts are per-run and that a stale-folder WARNING can appear; otherwise no README change is needed. Confirm with the maintainer.
- **Framework untouched:** All edits are in `sccm/sccm/src/openhound_sccm/main.py` and `sccm/sccm/tests/`. The OpenHound framework (`collector.run`, `PreProcessor`, dlt) is read-only here.
- **Orphan-check reference set:** `_preproc_table_map()` is the single source of truth for legitimate table names. If a new collector adds a table, adding it to that map (already required for preproc) automatically keeps the orphan check correct — no second list to maintain.
