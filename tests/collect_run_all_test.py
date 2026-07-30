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

    def fake_run_end_to_end(app, output_path, *, progress=None, graph_zip_name=None):
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
        lambda app, output_path, *, progress=None, graph_zip_name=None: seen.update(progress=progress),
    )
    m._run_e2e_after_collect(Path("/data/out"), ProgressOption.tqdm)
    assert seen["progress"] == Progress.tqdm


def test_failure_reraises_and_logs_manual_steps(monkeypatch, caplog):
    def boom(app, output_path, *, progress=None, graph_zip_name=None):
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


def test_run_e2e_returns_stage_paths(monkeypatch):
    """_run_e2e_after_collect propagates run_end_to_end's StagePaths to its caller,
    so collect_sccm can report every output location."""
    sentinel = object()
    monkeypatch.setattr(
        "openhound_collector_common.orchestration.run_end_to_end",
        lambda app, output_path, *, progress=None, graph_zip_name=None: sentinel,
    )
    assert m._run_e2e_after_collect(Path("/data/out"), ProgressOption.off) is sentinel


def test_output_locations_summary_lists_every_artifact(tmp_path, caplog):
    """The final --run-all summary names raw JSONL, both collect logs, the lookup
    DB, and each emitted OpenGraph file, with the warning/error count annotated."""
    from openhound_collector_common.orchestration import StagePaths

    (tmp_path / "sccm").mkdir()
    collect_log = tmp_path / "collect_log_x.log"
    collect_log.write_text("log")
    diag_log = tmp_path / "collect_diagnostics_x.log"
    diag_log.write_text("diag")
    lookup = tmp_path / "lookup.duckdb"
    lookup.write_text("db")
    graph = tmp_path / "graph"
    graph.mkdir()
    (graph / "sccm_nodes-1.json").write_text("{}")
    (graph / "ad_edges-1.json").write_text("{}")
    paths = StagePaths(dataset_dir=tmp_path / "sccm", lookup_db=lookup, graph_out=graph)

    with caplog.at_level(logging.INFO, logger="openhound_sccm.main"):
        m._log_all_output_locations(tmp_path, paths, collect_log, diag_log, 2)
    text = "\n".join(r.getMessage() for r in caplog.records)

    assert "Output files:" in text
    assert str(tmp_path / "sccm") in text        # raw JSONL dataset dir
    assert str(collect_log) in text              # collection log
    assert str(diag_log) in text                 # diagnostics log
    assert "2 warning(s)/error(s)" in text       # issue-count annotation
    assert str(lookup) in text                   # lookup DB
    assert "OpenGraph files (2)" in text
    assert str(graph / "sccm_nodes-1.json") in text
    assert str(graph / "ad_edges-1.json") in text


def test_output_locations_summary_handles_no_warnings_and_empty_graph(tmp_path, caplog):
    """With zero warnings the diagnostics line says so, and an empty graph dir is
    surfaced as a warning rather than a bare (0) count."""
    from openhound_collector_common.orchestration import StagePaths

    (tmp_path / "sccm").mkdir()
    collect_log = tmp_path / "collect_log_x.log"
    collect_log.write_text("log")
    diag_log = tmp_path / "collect_diagnostics_x.log"
    diag_log.write_text("")
    lookup = tmp_path / "lookup.duckdb"
    lookup.write_text("db")
    graph = tmp_path / "graph"
    graph.mkdir()  # no .json files
    paths = StagePaths(dataset_dir=tmp_path / "sccm", lookup_db=lookup, graph_out=graph)

    with caplog.at_level(logging.INFO, logger="openhound_sccm.main"):
        m._log_all_output_locations(tmp_path, paths, collect_log, diag_log, 0)
    text = "\n".join(r.getMessage() for r in caplog.records)

    assert "no warnings/errors" in text
    assert "has no .json files" in text


def test_output_locations_summary_omits_absent_logs_and_flags_missing_graph(tmp_path, caplog):
    """A clean run creates no diagnostics file (delay=True) and may create no collect
    log; both are omitted from the visible summary rather than listed, and a missing
    graph directory is surfaced as a warning."""
    from openhound_collector_common.orchestration import StagePaths

    (tmp_path / "sccm").mkdir()
    lookup = tmp_path / "lookup.duckdb"
    lookup.write_text("db")
    # Paths for logs that were never created (a clean collect run), and a graph dir
    # that convert never produced.
    collect_log = tmp_path / "collect_log_absent.log"
    diag_log = tmp_path / "collect_diagnostics_absent.log"
    graph = tmp_path / "graph"
    paths = StagePaths(dataset_dir=tmp_path / "sccm", lookup_db=lookup, graph_out=graph)

    with caplog.at_level(logging.INFO, logger="openhound_sccm.main"):
        m._log_all_output_locations(tmp_path, paths, collect_log, diag_log, 0)

    # Absent logs are dropped to DEBUG (filtered at INFO), so they never appear in
    # the operator-facing summary; the lookup DB still does.
    info_text = "\n".join(r.getMessage() for r in caplog.records if r.levelno == logging.INFO)
    assert str(collect_log) not in info_text
    assert str(diag_log) not in info_text
    assert str(lookup) in info_text
    # A missing graph dir is flagged rather than silently skipped.
    assert any("directory is missing" in r.getMessage() for r in caplog.records)


def test_run_e2e_forwards_configmanbearpig_zip_name(monkeypatch, tmp_path):
    """--run-all must pass a timestamped configmanbearpig_collection_<ts>.zip through
    to the shared run_end_to_end (which writes it into the graph dir)."""
    import openhound_collector_common.orchestration as orch
    from openhound_sccm.main import _run_e2e_after_collect, ProgressOption

    captured = {}

    def fake_run_end_to_end(app, output_path, *, progress=None, graph_zip_name=None):
        captured["graph_zip_name"] = graph_zip_name
        from openhound_collector_common.orchestration import derive_stage_paths
        return derive_stage_paths(app, output_path)

    # _run_e2e_after_collect does a function-local `from ... import run_end_to_end`,
    # which resolves the attribute at call time, so patching the module attr takes effect.
    monkeypatch.setattr(orch, "run_end_to_end", fake_run_end_to_end)
    _run_e2e_after_collect(
        tmp_path, ProgressOption.off,
        graph_zip_name="configmanbearpig_collection_20260730_101112.zip",
    )
    assert captured["graph_zip_name"] == "configmanbearpig_collection_20260730_101112.zip"
