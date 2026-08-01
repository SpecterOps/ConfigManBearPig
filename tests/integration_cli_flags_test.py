"""Offline tests for the SCCM collect `--run-integration-tests` / `--compare-to-zip` flags.

Run with the SCCM venv (has openhound + editable openhound_collector_common):
    sccm\\sccm\\.venv\\Scripts\\python -m pytest sccm\\sccm\\tests\\integration_cli_flags_test.py -v
"""
from pathlib import Path

import typer
from typer.testing import CliRunner

from openhound_sccm import main
from openhound_sccm.main import collect_sccm

runner = CliRunner()


def _help_output():
    # collect_sccm is a plain function decorated with typer.Option defaults, not
    # itself a Typer app — wrap it the same way test_cli_option_panels.py does to
    # drive a real --help render.
    app = typer.Typer()
    app.command()(collect_sccm)
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    return result.output


def test_testing_flags_registered_in_help():
    out = _help_output()
    assert "--run-integration-tests" in out
    assert "--compare-to-zip" in out
    assert "Testing" in out  # rich_help_panel


def test_compare_to_zip_takes_a_path():
    out = _help_output()
    assert "--compare-to-zip" in out


# --- privilege selection (con-6677, superseded by --integration-privilege) ----
#
# --integration-lowpriv was a boolean the operator had to remember, and forgetting
# it on a low-privilege run asserted SCCM-admin-only cases that could never have
# been collected. The three-way flag replaces it: `low` is that boolean, `high`
# forces the full set for a partially-privileged collection, and `auto` -- the
# default -- reads the run's own AdminService/WMI row counts.

def test_integration_privilege_registered_in_help():
    out = _help_output()
    assert "--integration-privilege" in out
    assert "Testing" in out  # same rich_help_panel as the other testing flags


def test_superseded_boolean_flag_is_gone():
    assert "--integration-lowpriv" not in _help_output()


def test_suite_translates_privileged_to_the_harness(monkeypatch):
    """``privileged`` reaches the harness verbatim -- no double negative in between."""
    import openhound_sccm.integration as integ
    seen = {}
    monkeypatch.setattr(integ, "run_integration_tests",
                        lambda graph_dir, **kw: seen.update(kw) or 0)
    rc = main._run_integration_suite(Path("graph"), Path("results.json"), privileged=False)
    assert rc == 0
    assert seen["privileged"] is False
