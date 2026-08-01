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


# --- low-privilege fixture mode (con-6677) ---------------------------------
#
# integration.run_integration_tests has always accepted privileged=False for a
# graph collected without AdminService/WMI, but nothing outside the unit tests
# could reach it: main.py called the harness without the argument, so SCCM-admin-only RBAC
# cases were asserted even on a low-privilege run and failed for behaving
# correctly. These cover the flag and the negation that translates it.

def test_integration_lowpriv_registered_in_help():
    out = _help_output()
    assert "--integration-lowpriv" in out
    assert "Testing" in out  # same rich_help_panel as the other testing flags


def test_lowpriv_flag_selects_unprivileged_assertions(monkeypatch):
    """``lowpriv=True`` must reach the harness as ``privileged=False``."""
    import openhound_sccm.integration as integ
    seen = {}
    monkeypatch.setattr(integ, "run_integration_tests",
                        lambda graph_dir, **kw: seen.update(kw) or 0)
    rc = main._run_integration_suite(Path("graph"), Path("results.json"), lowpriv=True)
    assert rc == 0
    assert seen["privileged"] is False


def test_default_keeps_privileged_assertions(monkeypatch):
    """Absent the flag, behaviour is unchanged: every case is still asserted."""
    import openhound_sccm.integration as integ
    seen = {}
    monkeypatch.setattr(integ, "run_integration_tests",
                        lambda graph_dir, **kw: seen.update(kw) or 0)
    main._run_integration_suite(Path("graph"), Path("results.json"), lowpriv=False)
    assert seen["privileged"] is True
