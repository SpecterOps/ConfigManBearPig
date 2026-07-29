"""Tests for the -v/--verbose (VERBOSE) and --silent console-mute flags.

These exercise ``_apply_log_level`` and its console-handler helpers directly,
because driving the whole ``collect`` command would require live domain
auto-detection. ``_apply_log_level`` mutates the *real* root and ``dlt`` loggers
(there is only one logging tree), so every test saves and restores the global
state it touches.
"""
import logging
import os

import pytest

from openhound_collector_common.logging.log_context import VERBOSE
from openhound_sccm.main import (
    _apply_log_level,
    _is_console_handler,
    _silence_console_handlers,
    _OrderedLogFileHandler,
    _DiagnosticFileHandler,
    collect_sccm,
)


@pytest.fixture()
def restore_logging(tmp_path):
    """Snapshot the global logging + env state _apply_log_level touches, and
    restore it after the test so nothing leaks between tests."""
    root = logging.getLogger()
    dlt = logging.getLogger("dlt")
    saved = {
        "root_level": root.level,
        "root_handlers": list(root.handlers),
        "dlt_handlers": list(dlt.handlers),
        "env": {k: os.environ.get(k) for k in ("RUNTIME__LOG_LEVEL", "RUNTIME__LOG_CLI_LEVEL")},
    }
    yield
    root.setLevel(saved["root_level"])
    root.handlers[:] = saved["root_handlers"]
    dlt.handlers[:] = saved["dlt_handlers"]
    for k, v in saved["env"].items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ---------------------------------------------------------------------------
# Flag shape: -v and --silent are booleans, not a repeatable count
# ---------------------------------------------------------------------------

def test_verbose_and_silent_are_boolean_flags():
    ann = collect_sccm.__annotations__
    assert ann["verbose"] is bool  # was `int` (count=True); now on/off
    assert ann["silent"] is bool


# ---------------------------------------------------------------------------
# Level mapping: none -> INFO, -v -> VERBOSE, --debug -> DEBUG
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "verbose, debug, expected_level, expected_name",
    [
        (False, False, logging.INFO, "INFO"),
        (True, False, VERBOSE, "VERBOSE"),
        (False, True, logging.DEBUG, "DEBUG"),
        (True, True, logging.DEBUG, "DEBUG"),  # --debug wins over -v
    ],
)
def test_level_mapping(restore_logging, verbose, debug, expected_level, expected_name):
    # Start from a high level so we can observe the lowering.
    logging.getLogger().setLevel(logging.WARNING)
    _apply_log_level(verbose=verbose, debug=debug, silent=False)
    assert logging.getLogger().level == expected_level
    assert os.environ["RUNTIME__LOG_LEVEL"] == expected_name


# ---------------------------------------------------------------------------
# _is_console_handler: terminal sinks yes, on-disk sinks no
# ---------------------------------------------------------------------------

def test_stream_handler_is_console():
    assert _is_console_handler(logging.StreamHandler()) is True


def test_file_handler_is_not_console(tmp_path):
    h = logging.FileHandler(tmp_path / "f.log", delay=True)
    try:
        assert _is_console_handler(h) is False
    finally:
        h.close()


def test_richlike_handler_is_console():
    # RichHandler is not a StreamHandler subclass; we duck-type on `.console`.
    h = logging.Handler()
    h.console = object()  # stand-in for rich.console.Console
    assert _is_console_handler(h) is True


def test_ordered_file_handler_is_not_console(tmp_path):
    h = _OrderedLogFileHandler(tmp_path / "ordered.log", level=logging.INFO)
    try:
        assert _is_console_handler(h) is False
    finally:
        h.close()


def test_diagnostic_file_handler_is_not_console(tmp_path):
    h = _DiagnosticFileHandler(tmp_path / "diag.log")
    try:
        assert _is_console_handler(h) is False
    finally:
        h.close()


# ---------------------------------------------------------------------------
# --silent: console handler muted, file handler + root logger untouched
# ---------------------------------------------------------------------------

def test_silent_mutes_console_but_not_file_or_root(restore_logging, tmp_path):
    root = logging.getLogger()
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    file_h = logging.FileHandler(tmp_path / "f.log", delay=True)
    file_h.setLevel(logging.INFO)
    root.handlers[:] = [console, file_h]

    try:
        # --silent --debug: quiet console, file logs at DEBUG detail.
        _apply_log_level(verbose=False, debug=True, silent=True)

        # Console handler is raised past CRITICAL so nothing prints.
        assert console.level > logging.CRITICAL
        # The file handler keeps its own level — the on-disk log still records.
        assert file_h.level == logging.INFO
        # The root logger is set to the requested detail level (NOT raised),
        # so records still reach the file handler.
        assert root.level == logging.DEBUG
    finally:
        file_h.close()


def test_silent_leaves_room_for_info_files_by_default(restore_logging, tmp_path):
    root = logging.getLogger()
    console = logging.StreamHandler()
    root.handlers[:] = [console]
    root.setLevel(logging.WARNING)

    _apply_log_level(verbose=False, debug=False, silent=True)

    assert console.level > logging.CRITICAL
    # Plain --silent still lets INFO through the (silenced) root to file handlers.
    assert root.level == logging.INFO


def test_silence_console_handlers_helper_skips_files(tmp_path):
    """The helper raises only console handlers, leaving file handlers alone."""
    root = logging.getLogger()
    saved = list(root.handlers)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    file_h = logging.FileHandler(tmp_path / "f.log", delay=True)
    file_h.setLevel(logging.INFO)
    root.handlers[:] = [console, file_h]
    try:
        _silence_console_handlers()
        assert console.level > logging.CRITICAL
        assert file_h.level == logging.INFO
    finally:
        file_h.close()
        root.handlers[:] = saved
