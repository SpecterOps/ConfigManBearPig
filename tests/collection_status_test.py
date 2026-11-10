"""Keep partial rows, allow fallback, and fail only for work that remains missing."""

import json
import os
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner
from openhound_collector_common.collection.outcomes import OperationResult

from openhound_sccm.collection_status import observe_phase, save_run_status, unrecovered_operations
from openhound_sccm.collectors import privileged
from openhound_sccm.models.target_entry import TargetEntry
from openhound_sccm.per_host_phases import should_run_phase
from openhound_sccm.phased_pipeline import Phase


@pytest.mark.parametrize("run_all", [True, False])
@pytest.mark.parametrize("is_incomplete", [True, False])
def test_cli_saves_status_runs_requested_later_stages_then_returns_final_status(
    monkeypatch, tmp_path, run_all, is_incomplete,
):
    from openhound_sccm import main, source
    from openhound_sccm.context import SourceContext

    monkeypatch.setattr(os, "environ", dict(os.environ))
    monkeypatch.delenv("SOURCES__SCCM__COMPUTER_FILE", raising=False)
    monkeypatch.delenv("SOURCES__SCCM__COMPUTERS", raising=False)
    monkeypatch.setattr(main, "_apply_log_level", lambda *args: None)
    monkeypatch.setattr(main, "_apply_connection_context", lambda _: None)
    monkeypatch.setattr(main, "_check_credentials_before_collection", lambda _: None)
    monkeypatch.setattr(main, "_normalize_row_counts", lambda _: {})
    context = SourceContext(ad=None, domain="mayyhem.com")
    entry = TargetEntry("host", None, saved_row_count=1)
    context._targets.bind_alias("host", entry)
    entry.operation_results["MSSQL"] = OperationResult(
        "MSSQL", "failed" if is_incomplete else "completed",
        None if is_incomplete else 1, 0,
        "phase_read_failed" if is_incomplete else None,
    )
    monkeypatch.setattr(source, "get_last_ctx", lambda: context)
    monkeypatch.setattr(source, "source", lambda **kwargs: SimpleNamespace(with_resources=lambda *args: None))

    class Collector:
        def __init__(self, **kwargs):
            self.pipeline = self

        def run(self, *args):
            return None

    monkeypatch.setattr(main, "Collector", Collector)
    monkeypatch.setattr(main, "_run_per_host_stage", lambda *args: {"mssql_server_instances": 1})
    later_stages = []

    def convert(*args, **kwargs):
        later_stages.append("converted")
        return SimpleNamespace(graph_out=tmp_path / "graph")

    monkeypatch.setattr(main, "_run_e2e_after_collect", convert)
    monkeypatch.setattr(main, "_log_all_output_locations", lambda *args: None)
    command = typer.Typer()
    command.command()(main.collect_sccm)
    arguments = [str(tmp_path), "-d", "mayyhem.com", "-m", "MSSQL", "--no-full-log", "--no-issues-log"]
    if run_all:
        arguments.append("--run-all")
    result = CliRunner().invoke(command, arguments)
    assert result.exit_code == int(is_incomplete), result.exception
    assert later_stages == (["converted"] if run_all else [])
    saved = json.loads(next(tmp_path.glob("collection_status_*.json")).read_text())
    assert saved["targets"][0]["state"] == ("partial" if is_incomplete else "completed")


def context_for(entry):
    return SimpleNamespace(
        target_hosts_by_hostname={entry.hostname: entry},
        target_hosts_snapshot=lambda: [entry],
        method_enabled=lambda name: True,
    )


def test_failed_phase_preserves_earlier_rows_and_saved_failure_record(tmp_path):
    entry = TargetEntry("host", None)
    context = context_for(entry)

    def partial(target, ctx):
        yield "raw", {"name": target}
        raise OSError("illustrative failed read")

    rows = iter(observe_phase(Phase("MSSQL", ("raw",), partial)).run("host", context))
    assert next(rows) == ("raw", {"name": "host"})
    with pytest.raises(OSError):
        next(rows)
    result = save_run_status(context, tmp_path, "test")
    assert result.has_incomplete_work and result.has_saved_rows
    assert result.targets[0].row_count == 1
    saved = json.loads((tmp_path / "collection_status_test.json").read_text())
    assert saved["operations"][0]["failure_category"] == "phase_read_failed"
    assert "illustrative failed read" not in json.dumps(saved)  # No unfiltered exception.


def test_partial_provider_does_not_suppress_wmi_and_recovery_clears_missing_work(monkeypatch, tmp_path):
    entry = TargetEntry("host", None)
    context = context_for(entry)

    def required_read(run):
        if run.name == "AdminService":
            raise OSError("illustrative timeout")
        yield "wmi_sites", {"site_code": "PS1"}

    def successful_read(run):
        yield "raw", {"name": "kept"}

    monkeypatch.setattr(privileged, "_COLLECTIONS", (required_read, successful_read))
    admin = privileged._Run(lambda *args: iter([]), "AdminService", "eq", "PS1", context)
    assert list(privileged._collect(admin, "host")) == [("raw", {"name": "kept"})]
    assert "AdminService" not in entry.completed_phases
    wmi_phase = Phase("WMI", (), lambda *args: iter([]))
    assert should_run_phase("host", wmi_phase, context)
    assert len(unrecovered_operations(entry)) == 1
    wmi = privileged._Run(lambda *args: iter([]), "WMI", "=", "PS1", context)
    assert len(list(privileged._collect(wmi, "host"))) == 2
    assert "WMI" in entry.completed_phases
    assert unrecovered_operations(entry) == []
    assert not save_run_status(context, tmp_path, "recovered").has_incomplete_work


def test_successful_empty_provider_read_is_complete(monkeypatch):
    entry = TargetEntry("host", None)
    context = context_for(entry)

    def empty_read(run):
        return iter([])

    monkeypatch.setattr(privileged, "_COLLECTIONS", (empty_read,))
    run = privileged._Run(lambda *args: iter([]), "AdminService", "eq", "PS1", context)
    assert list(privileged._collect(run, "host")) == []
    assert "AdminService" in entry.completed_phases
    assert entry.operation_results["AdminService.empty_read"].row_count == 0


def test_complete_wmi_recovers_a_failed_adminservice_phase():
    entry = TargetEntry("host", None, completed_phases={"WMI"})
    entry.operation_results["AdminService"] = OperationResult(
        "AdminService", "failed", None, 0, "phase_read_failed",
    )
    assert unrecovered_operations(entry) == []


def test_failed_http_page_does_not_return_successful_empty_data(monkeypatch):
    monkeypatch.setattr(privileged, "_http_get_value", lambda *args: None)
    with pytest.raises(RuntimeError, match="SMS_R_System"):
        list(privileged._http_fetch(None)("SMS_R_System"))
