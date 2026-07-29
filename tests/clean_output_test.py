# tests/clean_output_test.py
"""--clean discards a previous collection; without it, the operator is warned.

Re-running into a used output directory does NOT overwrite the raw data: dlt appends a
new load package beside the old ones and preprocess reads every .jsonl.gz per table, so
the previous run's rows are UNIONed into this run's graph. A table the new run finds
empty keeps ONLY the old rows. Both are invisible -- exit code 0, fresh graph/ mtimes.
Observed live on 2026-07-28: 11 of 24 raw tables held rows from two different dates.
"""
import logging

import pytest
import typer

from openhound_sccm.main import (
    _clean_previous_collection,
    _prior_load_packages,
)


def _prior_run(tmp_path, *, loads=2, tables=("ldap_sites", "http_management_points")):
    """Lay out an output dir the way a finished collection leaves it."""
    ds = tmp_path / "sccm"
    (ds / "_dlt_loads").mkdir(parents=True)
    for i in range(loads):
        (ds / "_dlt_loads" / f"sccm__17848394{i}.jsonl").write_text("{}", encoding="utf-8")
    for t in tables:
        (ds / t).mkdir(parents=True)
        (ds / t / "17848394.abc.jsonl.gz").write_bytes(b"\x1f\x8b")
    (tmp_path / "graph").mkdir()
    (tmp_path / "graph" / "ad_edges-1.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lookup.duckdb").write_bytes(b"DUCK")
    # Per-run artifacts: uniquely named, never re-read, must SURVIVE --clean.
    (tmp_path / "collect_full_20260723_164417.log").write_text("old log", encoding="utf-8")
    (tmp_path / "compare-20260723_164417.json").write_text("{}", encoding="utf-8")
    (tmp_path / "integration_results-20260723_164417.json").write_text("{}", encoding="utf-8")
    return tmp_path


def test_counts_prior_load_packages(tmp_path):
    _prior_run(tmp_path, loads=3)
    count, oldest = _prior_load_packages(tmp_path)
    assert count == 3 and oldest is not None


def test_counts_zero_on_a_fresh_dir(tmp_path):
    assert _prior_load_packages(tmp_path) == (0, None)


def test_clean_removes_only_the_tainting_artifacts(tmp_path):
    out = _prior_run(tmp_path)
    _clean_previous_collection(out, clean=True)

    # The taint vectors are gone...
    assert not (out / "sccm").exists()
    assert not (out / "graph").exists()
    assert not (out / "lookup.duckdb").exists()
    # ...and the evidence trail is intact.
    assert (out / "collect_full_20260723_164417.log").read_text(encoding="utf-8") == "old log"
    assert (out / "compare-20260723_164417.json").exists()
    assert (out / "integration_results-20260723_164417.json").exists()


def test_without_clean_nothing_is_deleted_but_a_warning_names_the_count(tmp_path, caplog):
    out = _prior_run(tmp_path, loads=2)
    with caplog.at_level(logging.WARNING):
        _clean_previous_collection(out, clean=False)

    assert (out / "sccm").exists() and (out / "lookup.duckdb").exists()
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1, warnings
    msg = warnings[0]
    # The count is the actionable part -- it is what makes contamination visible.
    assert "2" in msg and "--clean" in msg
    # One collection writes SEVERAL load packages (3, measured live), so the count
    # alone cannot mean "N previous runs" -- the oldest-written date is what tells
    # an operator the directory holds another day's data.
    assert "oldest written" in msg


def test_no_warning_on_a_genuinely_fresh_directory(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        _clean_previous_collection(tmp_path, clean=False)
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_clean_on_a_fresh_directory_is_a_no_op_not_an_error(tmp_path):
    _clean_previous_collection(tmp_path, clean=True)   # must not raise
    assert list(tmp_path.iterdir()) == []


def test_clean_on_a_nonexistent_directory_is_a_no_op(tmp_path):
    missing = tmp_path / "not-created-yet"
    _clean_previous_collection(missing, clean=True)    # must not raise
    assert not missing.exists()


def test_warns_when_a_dataset_dir_exists_but_holds_no_load_packages(tmp_path, caplog):
    # An aborted prior run can leave the bucket without _dlt_loads. Still dirty.
    (tmp_path / "sccm").mkdir()
    with caplog.at_level(logging.WARNING):
        _clean_previous_collection(tmp_path, clean=False)
    assert len([r for r in caplog.records if r.levelno >= logging.WARNING]) == 1


def test_unremovable_artifact_aborts_rather_than_collecting_onto_stale_data(tmp_path, monkeypatch):
    out = _prior_run(tmp_path)

    def _boom(path):
        raise OSError("being used by another process")

    # Simulates lookup.duckdb held open by BloodHound/DBeaver on Windows.
    monkeypatch.setattr("openhound_sccm.main.shutil.rmtree", _boom)
    with pytest.raises(typer.BadParameter) as ex:
        _clean_previous_collection(out, clean=True)
    assert "--clean could not remove" in str(ex.value)
