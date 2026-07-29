"""Offline tests for the SCCM collect `--run-integration-tests` / `--compare-to-zip` flags.

Run with the SCCM venv (has openhound + editable openhound_collector_common):
    sccm\\sccm\\.venv\\Scripts\\python -m pytest sccm\\sccm\\tests\\integration_cli_flags_test.py -v
"""
import typer
from typer.testing import CliRunner

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
