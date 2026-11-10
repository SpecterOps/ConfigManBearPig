"""Tests for allow-list (Test-AllowedTarget) construction in source.py.

The allow-list must be **lowercased**: ``SourceContext._is_allowed_target``
compares lowercased candidate names against ``allowed_targets``, so any entry
that keeps its original casing can never match. Both ``--computers`` and
``--computer-file`` feed the same expansion, so both must lowercase and both
must add the short-name form (the text before the first dot).
"""
from pathlib import Path
import os

import pytest
import typer
from typer.testing import CliRunner

from openhound_sccm import main
from openhound_sccm.context import SourceContext
from openhound_sccm.source import _expand_allowed_targets


def test_expand_lowercases_and_adds_short_name():
    """An uppercase FQDN yields its lowercased FQDN and short-name forms."""
    assert _expand_allowed_targets(["PS1-PSS.MAYYHEM.COM"]) == {
        "ps1-pss.mayyhem.com",
        "ps1-pss",
    }


def test_expand_strips_and_skips_blanks():
    """Blank/whitespace entries are dropped; surrounding whitespace is stripped."""
    assert _expand_allowed_targets(["  ", "Host2 ", ""]) == {"host2"}


def test_uppercase_computer_allows_lowercased_target():
    """Regression: an uppercase --computers value must still match a host that is
    later presented in lowercase (the casing-mismatch bug).
    """
    allowed = frozenset(_expand_allowed_targets(["PS1-PSS.MAYYHEM.COM"]))
    ctx = SourceContext(ad=None, domain="mayyhem.com", allowed_targets=allowed)
    assert ctx._is_allowed_target("ps1-pss.mayyhem.com", None) is True
    assert ctx._is_allowed_target("ps1-pss", None) is True


@pytest.mark.parametrize("computers", [None, "ps1-sms.mayyhem.com"])
def test_missing_target_file_cannot_be_ignored(tmp_path, computers):
    """Even another explicit target must not hide an invalid file argument."""
    with pytest.raises(ValueError, match="Cannot read computer file"):
        main._cli_seed_targets(computers, tmp_path / "missing.txt")


def test_empty_target_file_cannot_mean_unrestricted_collection(tmp_path):
    target_file = tmp_path / "empty.txt"
    target_file.write_text("\n  \n", encoding="utf-8")
    with pytest.raises(ValueError, match="contains no computer targets"):
        main._cli_seed_targets(None, target_file)


def test_unreadable_target_file_is_an_explicit_error(monkeypatch, tmp_path):
    def denied(*args, **kwargs):
        raise PermissionError("Access denied")

    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(ValueError, match="Cannot read computer file"):
        main._cli_seed_targets(None, tmp_path / "restricted.txt")


def test_target_file_accepts_utf8_bom_and_preserves_seed_names(tmp_path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("PS1-SMS.mayyhem.com\n\n ps1-db.mayyhem.com \n", encoding="utf-8-sig")
    assert main._cli_seed_targets("ps1-mp", target_file) == [
        "ps1-mp", "PS1-SMS.mayyhem.com", "ps1-db.mayyhem.com",
    ]


def test_invalid_file_stops_before_network_context_discovery(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(os, "environ", dict(os.environ))
    monkeypatch.setattr(main, "_apply_log_level", lambda *args: None)
    monkeypatch.setenv("SOURCES__SCCM__COMPUTER_FILE", "")
    monkeypatch.setattr(main, "_apply_connection_context", lambda _: calls.append("network discovery"))
    command = typer.Typer()
    command.command()(main.collect_sccm)
    result = CliRunner().invoke(command, [str(tmp_path / "output"), "--computer-file", str(tmp_path / "missing.txt")])
    assert result.exit_code == 2
    assert calls == []
