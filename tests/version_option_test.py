"""The SCCM version flag reports the installed collector's package version."""

from unittest import mock

from typer.testing import CliRunner

from openhound_sccm.main import _collect_typer


def test_version_uses_installed_distribution_without_output_path():
    with mock.patch("openhound_sccm.main.importlib.metadata.version", return_value="9.8.7") as installed_version:
        result = CliRunner().invoke(_collect_typer, ["sccm", "--version"])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == "ConfigManBearPig 9.8.7"
    installed_version.assert_called_once_with("configmanbearpig")
