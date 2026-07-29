import logging

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
    assert sccm_main._normalize_row_counts(_FakeTrace(None)) == {}


def test_normalize_row_counts_swallows_errors():
    class _Boom:
        @property
        def last_trace(self):
            raise RuntimeError("trace exploded")

    assert sccm_main._normalize_row_counts(_Boom()) == {}


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


def test_summary_prints_runnable_next_steps(caplog):
    """The next-steps hint must be real, copy-pasteable commands (no <...>
    placeholders), with every path derived from OUTPUT_PATH."""
    import pathlib

    caplog.set_level(logging.INFO, logger=sccm_main.__name__)
    raw = pathlib.Path("out")
    sccm_main._log_collect_summary(
        discovery_counts={"ldap_sites": 2},
        per_host_counts={},
        per_host_expected=False,
        output_path=raw,
    )
    next_steps = next(
        r.getMessage() for r in caplog.records if r.getMessage().startswith("Next steps:")
    )
    # No leftover placeholders from the old hard-coded hint.
    for placeholder in ("<raw>", "<lookup.duckdb>", "<graph>"):
        assert placeholder not in next_steps
    # Commands are `uv run`-prefixed (README style) so they resolve to the sccm
    # venv, and every path is derived from OUTPUT_PATH ("out").
    assert f"uv run openhound preprocess sccm {raw} {raw / 'lookup.duckdb'}" in next_steps
    assert (
        f"uv run openhound convert sccm {raw / 'sccm'} {raw / 'graph'} "
        f"--lookup-file {raw / 'lookup.duckdb'}"
    ) in next_steps


def test_cli_path_arg_leaves_plain_path_bare():
    import pathlib

    assert sccm_main._cli_path_arg(pathlib.Path("out")) == "out"


def test_cli_path_arg_quotes_path_with_spaces():
    import pathlib

    # A path with spaces must stay a single argument when pasted into a shell.
    p = pathlib.Path("C:/Program Files/out")
    assert sccm_main._cli_path_arg(p) == f'"{p}"'


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
