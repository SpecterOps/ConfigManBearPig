"""Unsupported method names must fail before any directory or host discovery."""

import os

import pytest
import typer
from typer.testing import CliRunner

from openhound_sccm import main
from openhound_sccm.context import validate_collection_methods


@pytest.mark.parametrize("value", [None, "All", "ldap,DNS", " http, smb "])
def test_supported_method_names_are_accepted(value):
    validate_collection_methods(value)


@pytest.mark.parametrize("value", ["DHCP", "All,DHCP", "LDAP,typo", " , "])
def test_unsupported_or_empty_method_selection_is_rejected(value):
    with pytest.raises(ValueError):
        validate_collection_methods(value)


@pytest.mark.parametrize("use_environment", [True, False])
def test_invalid_method_stops_cli_before_connection_context(monkeypatch, tmp_path, use_environment):
    monkeypatch.setattr(os, "environ", dict(os.environ))
    monkeypatch.setattr(main, "_apply_log_level", lambda *args: None)
    calls = []
    monkeypatch.setattr(main, "_apply_connection_context", lambda _: calls.append("network discovery"))
    cli = typer.Typer()
    cli.command()(main.collect_sccm)
    arguments = [str(tmp_path)]
    if use_environment:
        monkeypatch.setenv("SOURCES__SCCM__COLLECTION_METHODS", "DHCP")
    else:
        arguments.extend(["-m", "DHCP"])
    result = CliRunner().invoke(cli, arguments)
    assert result.exit_code == 2
    assert calls == []
