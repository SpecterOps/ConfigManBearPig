# OpenHound `--run-all` End-to-End Orchestrator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator run `openhound collect sccm --run-all [args]` to collect, preprocess, and convert to an OpenGraph in one command, with the chaining logic living in a reusable, source-agnostic shared-library function.

**Architecture:** Stock OpenHound has no single end-to-end command — `collect`, `preprocess`, and `convert` are three separate CLI invocations, and a brand-new top-level verb (`openhound run`) is impossible without editing core (the root Typer app mounts all verbs before any extension is imported). So we expose the feature as a **flag on the existing `collect sccm` command** (no core edit) and put the actual chaining in a new **framework-agnostic shared-library module** (`openhound_collector_common.orchestration`). After collect finishes, the flag handler calls `run_end_to_end(app, output_path, progress=...)`, which invokes the app's already-registered `preprocessor` then `converter` hooks **in-process**, deriving every path from the single collect `OUTPUT_PATH`.

**Tech Stack:** Python 3.13+, Typer/Click CLI, dlt (via the framework's `PreProcessor`/`Converter`), pytest. The shared library is `openhound-collector-common` (editable local path dep). The framework `openhound` is a git dependency in `.venv/site-packages` and is **off-limits to edit**.

## Global Constraints

- **Do NOT modify anything under `openhound/` core** (`.venv/.../site-packages/openhound/`). The feature must work purely through the framework's public extension points.
- **The shared library must stay framework-agnostic.** No shared module may `import openhound.*` or `import dlt` at runtime. Type hints referencing `OpenHound`/`Progress` go under a `TYPE_CHECKING` guard only.
- **Do NOT git add or commit.** Each task ends at a *green checkpoint* (tests passing); Meatbag commits after testing. Where a normal plan would say "Commit," this plan says "Green checkpoint."
- **Tests live in `/tests`** dirs: shared-lib tests in `openhound-collector-common/tests/`, SCCM tests in `sccm/sccm/tests/`.
- **Run tests with the SCCM venv** (it has both `openhound` and the editable `openhound_collector_common` installed): `sccm\sccm\.venv\Scripts\python -m pytest <path> -v`.
- **Log every branch.** Each `if/else` and `try/except` gets an appropriately-levelled log line (error/warning/info/verbose/debug) unless truly unwarranted (then a comment).
- **Property/path casing:** the derived layout must match the framework defaults exactly — `lookup.duckdb` (from `DEFAULT_LOOKUP_FILE`), the dlt dataset dir named after `app.name` (`sccm`), and `graph/` for convert output.
- **Progress representation:** the shared orchestrator's contract is `Progress | None` where `None` means silent. This is required because the framework stages read progress inconsistently (see Task 1).

---

## File Structure

**Created:**
- `openhound-collector-common/src/openhound_collector_common/orchestration/__init__.py` — package docstring + public exports (`StagePaths`, `derive_stage_paths`, `run_end_to_end`).
- `openhound-collector-common/src/openhound_collector_common/orchestration/run.py` — the orchestrator: path derivation, the `_NullProgress` shim, and `run_end_to_end`.
- `openhound-collector-common/tests/test_orchestration.py` — unit tests against a fake OpenHound-shaped object (no framework, no dlt).
- `sccm/sccm/tests/collect_run_all_test.py` — offline tests for SCCM's flag glue (progress mapping, failure handling, next-steps suppression).

**Modified:**
- `sccm/sccm/src/openhound_sccm/main.py` — add the `--run-all` flag to `collect_sccm`; add the `_run_e2e_after_collect` helper; suppress the manual "next steps" hint when `--run-all`; de-duplicate the path convention through `derive_stage_paths`.
- `sccm/sccm/README.md` — document `--run-all` (Command Line Options + a Quick Start example).
- `sccm/sccm/ARCHITECTURE.md` — new divergence section (end-to-end orchestration), a row in the shared-library table, an entry in the extension-point quick-reference, and a changelog entry.

**Why this decomposition:** Task 1 is the reusable core and is independently testable with zero framework dependencies. Task 2 wires SCCM to it and is reviewable on its own (a reviewer could accept the shared function but reject the SCCM glue, or vice versa). Task 3 is docs, gated separately.

---

### Task 1: Shared-library orchestrator (`openhound_collector_common.orchestration`)

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/orchestration/__init__.py`
- Create: `openhound-collector-common/src/openhound_collector_common/orchestration/run.py`
- Test: `openhound-collector-common/tests/test_orchestration.py`

**Interfaces:**
- Produces:
  - `StagePaths` — frozen dataclass with fields `dataset_dir: Path`, `lookup_db: Path`, `graph_out: Path`.
  - `derive_stage_paths(app, output_path: Path) -> StagePaths` — derives the three paths from `output_path` and `app.name`.
  - `run_end_to_end(app, output_path: Path, *, progress=None) -> StagePaths` — runs `app.preprocessor` then `app.converter` in-process; returns the derived paths; raises `RuntimeError` if either hook is unregistered; re-raises whatever a stage raises (stopping the chain).
  - The `app` argument is duck-typed: it must expose `.name: str`, `.preprocessor` (callable or `None`), and `.converter` (callable or `None`) — exactly what `openhound.core.app.OpenHound` provides.

- [ ] **Step 1: Write the failing tests**

Create `openhound-collector-common/tests/test_orchestration.py`:

```python
"""Unit tests for openhound_collector_common.orchestration.run (no live pipelines).

The orchestrator is exercised against a fake OpenHound-shaped object whose
preprocessor/converter just record how they were called, so these tests need
neither the openhound framework nor dlt installed.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from openhound_collector_common.orchestration import (
    StagePaths,
    derive_stage_paths,
    run_end_to_end,
)


def _fake_app(name="sccm"):
    """An OpenHound-shaped stand-in whose hooks append (stage, kwargs) to `calls`."""
    calls = []

    def preprocessor(**kwargs):
        calls.append(("preproc", kwargs))

    def converter(**kwargs):
        calls.append(("convert", kwargs))

    app = SimpleNamespace(name=name, preprocessor=preprocessor, converter=converter)
    return app, calls


def test_derive_stage_paths_matches_openhound_layout():
    app, _ = _fake_app(name="sccm")
    paths = derive_stage_paths(app, Path("/data/out"))
    assert paths == StagePaths(
        dataset_dir=Path("/data/out/sccm"),
        lookup_db=Path("/data/out/lookup.duckdb"),
        graph_out=Path("/data/out/graph"),
    )


def test_runs_preproc_then_convert_in_order():
    app, calls = _fake_app()
    run_end_to_end(app, Path("/data/out"), progress=None)
    assert [c[0] for c in calls] == ["preproc", "convert"]


def test_passes_derived_paths_to_each_stage():
    app, calls = _fake_app(name="sccm")
    run_end_to_end(app, Path("/data/out"), progress=None)
    preproc_kwargs = dict(calls[0][1])
    convert_kwargs = dict(calls[1][1])
    assert preproc_kwargs["input_path"] == Path("/data/out")
    assert preproc_kwargs["output_file"] == Path("/data/out/lookup.duckdb")
    assert convert_kwargs["input_path"] == Path("/data/out/sccm")
    assert convert_kwargs["output_path"] == Path("/data/out/graph")
    assert convert_kwargs["lookup_file"] == Path("/data/out/lookup.duckdb")


def test_none_progress_raw_to_preproc_but_shimmed_for_convert():
    app, calls = _fake_app()
    run_end_to_end(app, Path("/data/out"), progress=None)
    preproc_kwargs = dict(calls[0][1])
    convert_kwargs = dict(calls[1][1])
    # PreProcessor forwards the object straight to dlt.pipeline(), which accepts None.
    assert preproc_kwargs["progress"] is None
    # Converter reads progress.value, so None is wrapped in a .value=None shim.
    assert convert_kwargs["progress"] is not None
    assert convert_kwargs["progress"].value is None


def test_real_progress_passed_through_to_both_stages():
    app, calls = _fake_app()
    sentinel = SimpleNamespace(value="tqdm")  # stand-in for a framework Progress member
    run_end_to_end(app, Path("/data/out"), progress=sentinel)
    assert dict(calls[0][1])["progress"] is sentinel
    assert dict(calls[1][1])["progress"] is sentinel


def test_returns_derived_paths():
    app, _ = _fake_app(name="sccm")
    result = run_end_to_end(app, Path("/data/out"), progress=None)
    assert result == derive_stage_paths(app, Path("/data/out"))


def test_missing_preproc_hook_raises_before_running_anything():
    app, calls = _fake_app()
    app.preprocessor = None
    with pytest.raises(RuntimeError, match="preproc"):
        run_end_to_end(app, Path("/data/out"), progress=None)
    assert calls == []


def test_missing_convert_hook_raises_before_running_anything():
    app, calls = _fake_app()
    app.converter = None
    with pytest.raises(RuntimeError, match="convert"):
        run_end_to_end(app, Path("/data/out"), progress=None)
    assert calls == []


def test_convert_not_run_when_preproc_fails():
    calls = []

    def boom(**kwargs):
        calls.append(("preproc", kwargs))
        raise ValueError("preprocess exploded")

    def converter(**kwargs):
        calls.append(("convert", kwargs))

    app = SimpleNamespace(name="sccm", preprocessor=boom, converter=converter)
    with pytest.raises(ValueError, match="preprocess exploded"):
        run_end_to_end(app, Path("/data/out"), progress=None)
    assert [c[0] for c in calls] == ["preproc"]  # convert never reached
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `sccm\sccm\.venv\Scripts\python -m pytest openhound-collector-common\tests\test_orchestration.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'openhound_collector_common.orchestration'`.

- [ ] **Step 3: Create the package `__init__.py`**

Create `openhound-collector-common/src/openhound_collector_common/orchestration/__init__.py`:

```python
"""End-to-end phase orchestration for OpenHound collectors.

Stock OpenHound runs ``collect`` -> ``preprocess`` -> ``convert`` as three separate
CLI commands, and offers no single "collect all the way to a graph" verb (a new
top-level verb can't be added without editing framework core). This subpackage
provides the reusable, framework-agnostic chaining that lets an extension expose
that convenience as a flag on its own ``collect`` command (e.g.
``openhound collect sccm --run-all``).

Modules:
- ``run`` — derive the preproc/convert paths from one collect OUTPUT_PATH and run
  both stages in-process off an OpenHound app's registered hooks.
"""

from .run import StagePaths, derive_stage_paths, run_end_to_end

__all__ = [
    "StagePaths",
    "derive_stage_paths",
    "run_end_to_end",
]
```

- [ ] **Step 4: Implement the orchestrator**

Create `openhound-collector-common/src/openhound_collector_common/orchestration/run.py`:

```python
"""Chain a collector's preproc + convert stages in-process after collect.

This is the shareable half of an extension's "run everything" convenience flag.
It is deliberately framework-agnostic: it never imports ``openhound`` or ``dlt``
at runtime, and treats the app as a duck-typed object exposing ``name``,
``preprocessor``, and ``converter`` (exactly what ``openhound.core.app.OpenHound``
registers via its ``@app.preproc`` / ``@app.convert`` decorators). Every path is
derived from the single collect OUTPUT_PATH, matching the framework's own layout
so ``--run-all`` and the manual three-command workflow touch identical files.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # type hints only — never import the framework at runtime
    from openhound.core.app import OpenHound
    from openhound.core.progress import Progress

logger = logging.getLogger(__name__)

# The framework's chained-phase filesystem convention, kept in one place so both
# --run-all and any "next steps" hint agree. `lookup.duckdb` mirrors the core
# DEFAULT_LOOKUP_FILE; the dlt dataset dir is named after the pipeline/dataset,
# which is the app name; `graph` is the convert output dir.
_LOOKUP_DB_NAME = "lookup.duckdb"
_GRAPH_DIR_NAME = "graph"


@dataclass(frozen=True)
class StagePaths:
    """The three paths the preproc + convert stages read/write, derived from OUTPUT_PATH."""

    dataset_dir: Path  # convert input: the dlt dataset dir (OUTPUT_PATH / app.name)
    lookup_db: Path    # preproc output and convert lookup (OUTPUT_PATH / lookup.duckdb)
    graph_out: Path    # convert output dir (OUTPUT_PATH / graph)


def derive_stage_paths(app: "OpenHound", output_path: Path) -> StagePaths:
    """Derive the preproc/convert paths from the single collect OUTPUT_PATH.

    Matches what a collector's manual "next steps" hint prints, so the automated
    and manual workflows read/write the exact same locations.
    """
    return StagePaths(
        dataset_dir=output_path / app.name,
        lookup_db=output_path / _LOOKUP_DB_NAME,
        graph_out=output_path / _GRAPH_DIR_NAME,
    )


class _NullProgress:
    """Progress stand-in whose ``.value`` is None (maps to dlt's NULL_COLLECTOR).

    The framework reads progress inconsistently: ``Converter`` uses
    ``progress.value``, so a bare ``None`` would raise ``AttributeError`` there,
    while ``PreProcessor`` forwards the object straight to ``dlt.pipeline()``,
    which happily accepts ``None``. This shim lets "silent" satisfy the converter;
    a bare ``None`` satisfies the preprocessor. See ``run_end_to_end``.
    """

    value = None


def run_end_to_end(
    app: "OpenHound",
    output_path: Path,
    *,
    progress: "Optional[Progress]" = None,
) -> StagePaths:
    """Run *app*'s preproc then convert stages in-process, chained off one collect run.

    Assumes collect has already written its raw JSONL under *output_path*. Runs
    preprocess (builds the DuckDB lookup) then convert (emits the OpenGraph
    files). The chain stops immediately if a stage raises — the exception
    propagates unchanged so the caller can report it. Returns the derived paths.

    progress: a framework ``Progress`` member for a live tracker, or ``None`` for
    silent (dlt NULL_COLLECTOR). Applied per-stage because the framework stages
    consume it differently (see ``_NullProgress``).
    """
    # A hook can be missing if an extension registered collect but not preproc /
    # convert; without both there is nothing to chain, so fail loudly and early
    # (before touching disk) rather than half-running.
    if app.preprocessor is None:
        logger.error("Cannot run end-to-end for '%s': no preproc hook is registered.", app.name)
        raise RuntimeError(f"{app.name}: no preproc hook registered; cannot run end-to-end.")
    if app.converter is None:
        logger.error("Cannot run end-to-end for '%s': no convert hook is registered.", app.name)
        raise RuntimeError(f"{app.name}: no convert hook registered; cannot run end-to-end.")

    paths = derive_stage_paths(app, output_path)

    # Preprocess: PreProcessor forwards `progress` straight to dlt.pipeline(),
    # which accepts a Progress (a str Enum) or None — so pass it through as-is.
    logger.info("Preprocessing raw data into lookup DB: %s", paths.lookup_db)
    app.preprocessor(
        input_path=output_path,
        output_file=paths.lookup_db,
        progress=progress,
    )
    logger.info("Preprocess complete: %s", paths.lookup_db)

    # Convert: Converter reads `progress.value`, so a bare None would crash it;
    # wrap None in the .value=None shim. A real Progress member already has .value.
    if progress is None:
        convert_progress = _NullProgress()
        logger.debug("Convert progress silenced (dlt NULL_COLLECTOR).")
    else:
        convert_progress = progress
        logger.debug("Convert progress backend: %s", getattr(progress, "value", progress))

    logger.info("Converting collected data into OpenGraph: %s", paths.graph_out)
    app.converter(
        input_path=paths.dataset_dir,
        output_path=paths.graph_out,
        lookup_file=paths.lookup_db,
        progress=convert_progress,
    )
    logger.info("Convert complete. Graph written to: %s", paths.graph_out)

    return paths
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `sccm\sccm\.venv\Scripts\python -m pytest openhound-collector-common\tests\test_orchestration.py -v`
Expected: PASS (9 tests).

- [ ] **Step 6: Green checkpoint** (do NOT commit — Meatbag commits after testing)

Confirm the new module imports cleanly outside the framework:
Run: `sccm\sccm\.venv\Scripts\python -c "import openhound_collector_common.orchestration as o; print(o.__all__)"`
Expected: `['StagePaths', 'derive_stage_paths', 'run_end_to_end']`

---

### Task 2: Wire SCCM's `--run-all` flag to the shared orchestrator

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py`
- Test: `sccm/sccm/tests/collect_run_all_test.py`

**Interfaces:**
- Consumes: `run_end_to_end`, `derive_stage_paths` from `openhound_collector_common.orchestration` (Task 1); `Progress` from `openhound.core.progress` (already imported in `main.py:28`); the existing `ProgressOption`, `_cli_path_arg`, module-level `app`, and `logger`.
- Produces (for the test to target):
  - `collect_sccm(..., run_all: bool = ...)` — new Typer option `--run-all`.
  - `_run_e2e_after_collect(output_path: pathlib.Path, progress: ProgressOption) -> None` — maps the collector's `--progress` choice to `Progress | None` and delegates to `run_end_to_end`; on failure logs the equivalent manual commands and re-raises.
  - `_log_collect_summary(..., run_all: bool = False)` — when `run_all` is True, suppress the manual "next steps" hint.

- [ ] **Step 1: Write the failing tests**

Create `sccm/sccm/tests/collect_run_all_test.py`:

```python
"""Offline tests for SCCM collect --run-all end-to-end chaining glue.

Run with the SCCM venv (has openhound + editable openhound_collector_common):
    sccm\\sccm\\.venv\\Scripts\\python -m pytest sccm\\sccm\\tests\\collect_run_all_test.py -v
"""
import logging
from pathlib import Path

import pytest

import openhound_sccm.main as m
from openhound_sccm.main import ProgressOption


def test_progress_off_maps_to_none(monkeypatch):
    seen = {}

    def fake_run_end_to_end(app, output_path, *, progress=None):
        seen["progress"] = progress
        seen["output_path"] = output_path

    monkeypatch.setattr(
        "openhound_collector_common.orchestration.run_end_to_end",
        fake_run_end_to_end,
    )
    m._run_e2e_after_collect(Path("/data/out"), ProgressOption.off)
    assert seen["progress"] is None
    assert seen["output_path"] == Path("/data/out")


def test_progress_tqdm_maps_to_framework_progress(monkeypatch):
    from openhound.core.progress import Progress

    seen = {}
    monkeypatch.setattr(
        "openhound_collector_common.orchestration.run_end_to_end",
        lambda app, output_path, *, progress=None: seen.update(progress=progress),
    )
    m._run_e2e_after_collect(Path("/data/out"), ProgressOption.tqdm)
    assert seen["progress"] == Progress.tqdm


def test_failure_reraises_and_logs_manual_steps(monkeypatch, caplog):
    def boom(app, output_path, *, progress=None):
        raise RuntimeError("convert failed")

    monkeypatch.setattr(
        "openhound_collector_common.orchestration.run_end_to_end", boom
    )
    with caplog.at_level(logging.ERROR, logger="openhound_sccm.main"):
        with pytest.raises(RuntimeError, match="convert failed"):
            m._run_e2e_after_collect(Path("/data/out"), ProgressOption.off)
    assert any("Resume manually" in r.getMessage() for r in caplog.records)


def test_summary_suppresses_next_steps_when_run_all(caplog):
    with caplog.at_level(logging.INFO, logger="openhound_sccm.main"):
        m._log_collect_summary({"ldap_x": 1}, {}, False, Path("/data/out"), run_all=True)
    messages = [r.getMessage() for r in caplog.records]
    assert not any("Next steps" in msg for msg in messages)
    assert any("run automatically" in msg for msg in messages)


def test_summary_prints_next_steps_when_not_run_all(caplog):
    with caplog.at_level(logging.INFO, logger="openhound_sccm.main"):
        m._log_collect_summary({"ldap_x": 1}, {}, False, Path("/data/out"), run_all=False)
    assert any("Next steps" in r.getMessage() for r in caplog.records)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `sccm\sccm\.venv\Scripts\python -m pytest sccm\sccm\tests\collect_run_all_test.py -v`
Expected: FAIL — `AttributeError: module 'openhound_sccm.main' has no attribute '_run_e2e_after_collect'` and a `TypeError` for the unexpected `run_all` kwarg on `_log_collect_summary`.

- [ ] **Step 3: Add the `--run-all` Typer option to `collect_sccm`**

In `sccm/sccm/src/openhound_sccm/main.py`, inside the `collect_sccm` signature, in the `# ---- Behavior ----` group, immediately after the `show_cleartext_passwords` option (currently `main.py:935`), add:

```python
    run_all: bool = typer.Option(
        False, "--run-all",
        help="After collecting, automatically run preprocess and convert in-process so a "
        "single command produces the OpenGraph files. All paths are derived from OUTPUT_PATH "
        "(lookup.duckdb, the sccm/ dataset dir, and graph/).",
    ),
```

- [ ] **Step 4: Pass `run_all` into the summary and suppress the hint**

In `collect_sccm`, update the summary call (currently `main.py:1050`) from:

```python
        with target_context(None), phase_context(None):
            _log_collect_summary(discovery_counts, per_host_counts, per_host_expected, output_path)
        return load_info
```

to (note: the `return load_info` moves out of the `try` — see Step 6):

```python
        with target_context(None), phase_context(None):
            _log_collect_summary(
                discovery_counts, per_host_counts, per_host_expected, output_path, run_all=run_all
            )
```

Then update `_log_collect_summary`'s signature (currently `main.py:1124-1129`) to add the `run_all` flag:

```python
def _log_collect_summary(
    discovery_counts: dict[str, int],
    per_host_counts: dict[str, int],
    per_host_expected: bool,
    output_path: pathlib.Path,
    run_all: bool = False,
) -> None:
```

And replace the "next steps" block at the end of `_log_collect_summary` (currently `main.py:1194-1208`) with:

```python
    # When --run-all is set, preprocess and convert run automatically right after
    # this summary, so the manual copy-paste hint would only mislead. Derive the
    # printed paths from the shared convention so this hint and --run-all can
    # never disagree about where files land.
    if run_all:
        logger.info("--run-all set: preprocess and convert will run automatically next.")
        return

    from openhound_collector_common.orchestration import derive_stage_paths

    paths = derive_stage_paths(app, output_path)
    preprocess_cmd = (
        f"openhound preprocess sccm {_cli_path_arg(output_path)} {_cli_path_arg(paths.lookup_db)}"
    )
    convert_cmd = (
        f"openhound convert sccm {_cli_path_arg(paths.dataset_dir)} {_cli_path_arg(paths.graph_out)} "
        f"--lookup-file {_cli_path_arg(paths.lookup_db)}"
    )
    logger.info("Next steps: '%s' then '%s'", preprocess_cmd, convert_cmd)
```

- [ ] **Step 5: Add the `_run_e2e_after_collect` helper**

In `sccm/sccm/src/openhound_sccm/main.py`, add this helper immediately after `_log_collect_summary` (before the `app.collector = collect_sccm` assignment at `main.py:1215`):

```python
def _run_e2e_after_collect(output_path: pathlib.Path, progress: ProgressOption) -> None:
    """Chain preprocess + convert in-process after a successful --run-all collect.

    Maps the collector's --progress choice to what the shared orchestrator wants
    (a framework Progress member, or None for silent), then delegates to
    run_end_to_end. If a stage fails, the raw collected data is left intact and
    the equivalent manual commands are logged so the operator can resume from
    preprocess without recollecting.
    """
    from openhound_collector_common.orchestration import (
        derive_stage_paths,
        run_end_to_end,
    )

    # 'off' -> None (dlt NULL_COLLECTOR in both stages); any real backend -> the
    # matching framework Progress member. (Note: unlike collect, we can't reuse
    # _resolve_progress here — its 'off' path returns a .value=None *object*,
    # which the preprocess stage would hand raw to dlt. run_end_to_end needs the
    # None/Progress form and applies the convert-side shim itself.)
    if progress is ProgressOption.off:
        e2e_progress = None
        logger.debug("--run-all: preprocess/convert progress disabled (matches --progress off).")
    else:
        e2e_progress = Progress(progress.value)
        logger.debug("--run-all: preprocess/convert progress backend: %s", progress.value)

    logger.info("--run-all: continuing with preprocess and convert (in-process).")
    try:
        run_end_to_end(app, output_path, progress=e2e_progress)
    except Exception:
        # Collect already succeeded, so the raw data on disk is still good; tell
        # the operator exactly how to resume rather than lose that work.
        paths = derive_stage_paths(app, output_path)
        logger.error(
            "--run-all: preprocess/convert failed after a successful collect. Your raw data "
            "is intact at %s. Resume manually: 'openhound preprocess sccm %s %s' then "
            "'openhound convert sccm %s %s --lookup-file %s'.",
            output_path,
            _cli_path_arg(output_path), _cli_path_arg(paths.lookup_db),
            _cli_path_arg(paths.dataset_dir), _cli_path_arg(paths.graph_out),
            _cli_path_arg(paths.lookup_db),
        )
        raise
```

- [ ] **Step 6: Invoke the orchestrator after collect completes**

In `collect_sccm`, the `return load_info` currently sits inside the `try` (at `main.py:1051`, removed in Step 4). Add the post-collection block **after** the `finally` block ends (currently `main.py:1078`, right before the `def _normalize_row_counts` at `main.py:1080`), so it runs only when collection succeeded (any exception in the `try` propagates past the `finally` and skips this):

```python
    # Collection succeeded here — an exception in the try above would have
    # propagated past the finally and never reached this point. Chain the
    # remaining phases only when the operator asked for it.
    if run_all:
        _run_e2e_after_collect(output_path, progress)
    else:
        logger.debug("--run-all not set; leaving preprocess/convert to the operator.")
    return load_info
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `sccm\sccm\.venv\Scripts\python -m pytest sccm\sccm\tests\collect_run_all_test.py -v`
Expected: PASS (5 tests).

- [ ] **Step 8: Guard against regressions in the existing summary test**

Run: `sccm\sccm\.venv\Scripts\python -m pytest sccm\sccm\tests\collect_summary_test.py -v`
Expected: PASS. If `collect_summary_test.py` calls `_log_collect_summary` positionally, the new trailing `run_all=False` default keeps it green; if any assertion checked the "Next steps" line, confirm it still appears (default path unchanged).

- [ ] **Step 9: Green checkpoint** (do NOT commit — Meatbag commits after testing)

Verify the flag is wired into the CLI surface:
Run: `sccm\sccm\.venv\Scripts\python -m openhound collect sccm --help`
Expected: the help text lists `--run-all` under the options.

---

### Task 3: Documentation (README + ARCHITECTURE)

**Files:**
- Modify: `sccm/sccm/README.md`
- Modify: `sccm/sccm/ARCHITECTURE.md`

**Interfaces:**
- Consumes: the `--run-all` behavior from Task 2 (no code interface).

- [ ] **Step 1: Document `--run-all` in the README Command Line Options**

In `sccm/sccm/README.md`, in the Command Line Options section (the table/list that documents collect flags, near `--disable-possible-edges` / `--threads`), add a row/entry:

```markdown
| `--run-all` | After collecting, automatically run **preprocess** and **convert** in-process, producing the OpenGraph files in a single command. All paths are derived from `OUTPUT_PATH`: `lookup.duckdb`, the `sccm/` dataset dir, and `graph/`. Omit it to run the three stages manually (the default; a "next steps" hint is printed). |
```

- [ ] **Step 2: Add a Quick Start one-command example**

In `sccm/sccm/README.md` Quick Start, after the existing three-step (collect → preprocess → convert) example, add:

````markdown
#### One command, end to end

Run all three stages against the lab in a single command:

```powershell
openhound collect sccm .\out --run-all -d mayyhem.com -u MAYYHEM\lowpriv -p Password123!
```

This collects into `.\out`, builds `.\out\lookup.duckdb`, and writes the OpenGraph
files to `.\out\graph\`. It is exactly equivalent to running:

```powershell
openhound collect sccm .\out -d mayyhem.com -u MAYYHEM\lowpriv -p Password123!
openhound preprocess sccm .\out .\out\lookup.duckdb
openhound convert sccm .\out\sccm .\out\graph --lookup-file .\out\lookup.duckdb
```

If preprocess or convert fails, your raw collected data in `.\out` is left intact
and the exact resume commands are logged, so you never have to recollect.
````

- [ ] **Step 3: Add the ARCHITECTURE divergence section**

In `sccm/sccm/ARCHITECTURE.md`, add a new numbered section (after the last existing section, before "Quick reference"). Keep the standard spine (baseline / why it breaks / add-on / trade-offs):

```markdown
## 12. One-command end-to-end: a `--run-all` flag, not a new verb

### The framework baseline

OpenHound models the pipeline as three separate top-level CLI verbs — `collect`,
`preprocess`, `convert` — each a Typer group mounted on the root app at
construction time. There is no "run everything" verb, and no public hook to add a
new top-level verb: the root app mounts all verbs *before* any extension is
imported, so an extension can only hang commands off the pre-existing groups.

### Why it breaks for SCCM

Operators expect to point the tool at an environment and get a graph — one
command, not three, and without hand-deriving the intermediate `lookup.duckdb` /
dataset-dir / `graph` paths each time. But the natural shape (`openhound run
sccm`) is exactly the thing the framework can't express without a core edit.

### The add-on: a flag on `collect`, backed by a shared orchestrator

- **CLI surface:** a `--run-all` flag on the already-hand-registered `collect sccm`
  command ([`collect_sccm`](src/openhound_sccm/main.py)), so no new verb and no
  core edit. When set, `collect_sccm` runs collection as usual, then calls
  [`_run_e2e_after_collect`](src/openhound_sccm/main.py) once the collect log
  handlers are torn down, so the two follow-on stages log through the normal
  console handlers.
- **The chaining itself is shared.** The actual "preproc then convert" logic lives
  in `openhound_collector_common.orchestration.run_end_to_end` (see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)),
  which invokes the app's registered `preprocessor` / `converter` hooks
  **in-process** and derives every path from the single collect `OUTPUT_PATH`.
  It is framework-agnostic (duck-types the app; no `openhound`/`dlt` import), so
  the MSSQL collector can adopt the same flag by calling it.
- **Progress plumbing quirk:** the framework stages read progress inconsistently
  (`Converter` uses `progress.value`; `PreProcessor` forwards the object straight
  to `dlt.pipeline()`), so the orchestrator's contract is `Progress | None` and it
  applies a `.value=None` shim on the convert side for the silent case.

### Trade-offs

- `--run-all` runs all three stages in **one process**, an execution mode the
  manual three-command workflow never exercises. Collect's process-global state
  (the planted `StreamBridge`, the bumped `EXTRACT__WORKERS`) is cleaned up in its
  `finally` before the chain starts, so the follow-on stages start clean.
- It is a *flag*, not the `openhound run sccm` verb an operator might expect —
  the price of not editing core.
- On failure the chain stops and re-raises, leaving raw data intact and logging
  the manual resume commands (stop-on-first-failure).
```

- [ ] **Step 4: Add the shared-library table row and quick-reference entry**

In `sccm/sccm/ARCHITECTURE.md`, in the "Where this code lives" table (the "What moved" table), add a row:

```markdown
| End-to-end phase chaining ([§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)) | `orchestration/run` (`run_end_to_end`, `derive_stage_paths`, `StagePaths`) | `main.py::_run_e2e_after_collect` maps `--progress` and delegates; the `--run-all` flag on `collect_sccm` triggers it |
```

And in the "Quick reference: which framework extension point each add-on uses" table, add:

```markdown
| One-command end-to-end ([§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)) | A flag on the hand-registered `collect` Typer command + in-process calls to the app's registered `preproc`/`convert` hooks |
```

Also add `## 12 ...` to the Table of Contents near the top of the file.

- [ ] **Step 5: Add a changelog entry**

In `sccm/sccm/ARCHITECTURE.md` Changelog, add an entry dated `2026-07-16`:

```markdown
- **2026-07-16** — Added §12: a `--run-all` flag on `collect sccm` that chains
  preprocess + convert in-process via the new framework-agnostic
  `openhound_collector_common.orchestration.run_end_to_end`. New kind of
  divergence (end-to-end orchestration without a new top-level verb).
```

- [ ] **Step 6: Green checkpoint** (do NOT commit — Meatbag commits after testing)

Re-read §12 and the README additions against the final code in `main.py` and
`run.py`; fix any drifted path names, flag spellings, or `file:line` references.

---

## Self-Review

**1. Spec coverage:**
- New end-to-end command → Task 2 (`--run-all` flag) + Task 1 (orchestrator). ✓
- "openhound common/shared library function" → Task 1 lands `run_end_to_end` in `openhound-collector-common`. ✓
- In-process orchestration → `run_end_to_end` calls `app.preprocessor`/`app.converter` directly. ✓
- Stop-on-first-failure → chain re-raises; convert not reached if preproc fails (test `test_convert_not_run_when_preproc_fails`). ✓
- Zero-config derived paths → `derive_stage_paths`. ✓
- Single progress setting for all stages → `_run_e2e_after_collect` maps once, passes through. ✓
- Suppress "next steps" hint → Task 2 Step 4 + test `test_summary_suppresses_next_steps_when_run_all`. ✓
- No core edit → flag on existing `collect` group only. ✓
- Shared lib stays framework-agnostic → `TYPE_CHECKING`-only imports; tests use a `SimpleNamespace`. ✓
- Docs (README + ARCHITECTURE) → Task 3. ✓

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to" — every code and test step contains complete content. ✓

**3. Type consistency:** `run_end_to_end(app, output_path, *, progress=None) -> StagePaths`, `derive_stage_paths(app, output_path) -> StagePaths`, and `StagePaths(dataset_dir, lookup_db, graph_out)` are used identically across Task 1 (impl + tests) and Task 2 (SCCM glue + tests). `_run_e2e_after_collect(output_path, progress)` and `_log_collect_summary(..., run_all=False)` match between impl and tests. ✓
```

