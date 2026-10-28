"""The real SCCM command must release shared diagnostics after early failure."""

import logging
import os

import typer
from typer.testing import CliRunner

from openhound_collector_common.logging.files import DiagnosticFileHandler, GroupedFileHandler
from openhound_sccm import main


def test_collection_failure_closes_diagnostics_and_preserves_redacted_exception(monkeypatch, tmp_path):
    loggers = [logging.getLogger(name) for name in ("", "dlt", "openhound", "openhound_sccm", "openhound_collector_common")]
    saved = [(logger, list(logger.handlers), logger.level, logger.propagate) for logger in loggers]
    formats = {handler: handler.formatter for logger in loggers for handler in logger.handlers}
    monkeypatch.setattr(os, "environ", dict(os.environ))
    def fail_before_discovery():
        raise RuntimeError("private-value deliberate provider failure")
    monkeypatch.setattr(main, "_warn_for_suspicious_cli_arguments", fail_before_discovery)
    cli = typer.Typer()
    cli.add_typer(main._collect_typer, name="collect")
    try:
        result = CliRunner().invoke(cli, ["collect", "sccm", str(tmp_path), "--password", "private-value"])
        assert result.exit_code != 0
        assert not any(isinstance(handler, (DiagnosticFileHandler, GroupedFileHandler)) for handler in logging.root.handlers)
        issues = list(tmp_path.glob("collect_issues_*.log"))
        assert len(issues) == 1
        text = issues[0].read_text(encoding="utf-8")
        assert "RuntimeError" in text and "deliberate provider failure" in text
        assert "private-value" not in text + result.output
        assert not list(tmp_path.glob("openhound-logs-*"))
    finally:
        for logger, handlers, level, propagate in saved:
            logger.handlers = handlers
            logger.setLevel(level)
            logger.propagate = propagate
        for handler, formatter in formats.items():
            handler.setFormatter(formatter)
