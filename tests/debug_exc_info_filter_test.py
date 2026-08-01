import logging

import pytest

# The debug exc-info filter + its singleton now live in the shared library
# (SCCM's install_filter re-exports the shared one, which installs the shared
# singleton), so test them at their new home.
from openhound_collector_common.logging.log_context import (
    _DebugExcInfoFilter,
    _EXC_INFO_FILTER_SINGLETON,
    _FILTER_SINGLETON,
    install_filter,
)
from openhound_sccm.main import _DiagnosticFileHandler


def _record(levelno: int, exc_info=False) -> logging.LogRecord:
    return logging.LogRecord(
        name="test.module",
        level=levelno,
        pathname="test.py",
        lineno=1,
        msg="test message",
        args=(),
        exc_info=exc_info,
    )


@pytest.fixture()
def debug_filter():
    original = logging.root.level
    logging.root.setLevel(logging.DEBUG)
    yield _DebugExcInfoFilter()
    logging.root.setLevel(original)


# ---------------------------------------------------------------------------
# Core injection behaviour
# ---------------------------------------------------------------------------

def test_injects_exc_info_on_warning_in_debug_mode(debug_filter):
    record = _record(logging.WARNING)
    try:
        raise ValueError("boom")
    except ValueError:
        debug_filter.filter(record)
    assert record.exc_info is not None
    assert record.exc_info[0] is ValueError


def test_injects_exc_info_on_error_in_debug_mode(debug_filter):
    record = _record(logging.ERROR)
    try:
        raise RuntimeError("oops")
    except RuntimeError:
        debug_filter.filter(record)
    assert record.exc_info is not None
    assert record.exc_info[0] is RuntimeError


def test_injects_exc_info_on_critical_in_debug_mode(debug_filter):
    record = _record(logging.CRITICAL)
    try:
        raise TypeError("bad type")
    except TypeError:
        debug_filter.filter(record)
    assert record.exc_info is not None
    assert record.exc_info[0] is TypeError


# ---------------------------------------------------------------------------
# Guard conditions that suppress injection
# ---------------------------------------------------------------------------

def test_does_not_inject_on_info_in_debug_mode(debug_filter):
    record = _record(logging.INFO)
    try:
        raise ValueError("boom")
    except ValueError:
        debug_filter.filter(record)
    assert not record.exc_info


def test_does_not_inject_when_not_in_debug_mode():
    # setLevel() is used (not direct attribute assignment) so Python's internal
    # isEnabledFor cache is properly invalidated — monkeypatch.setattr bypasses it.
    original = logging.root.level
    logging.root.setLevel(logging.WARNING)
    try:
        f = _DebugExcInfoFilter()
        record = _record(logging.WARNING)
        try:
            raise ValueError("boom")
        except ValueError:
            f.filter(record)
        assert not record.exc_info
    finally:
        logging.root.setLevel(original)


def test_does_not_inject_outside_except_block(debug_filter):
    record = _record(logging.WARNING)
    debug_filter.filter(record)
    assert not record.exc_info


def test_does_not_overwrite_existing_exc_info(debug_filter):
    original = (TypeError, TypeError("original"), None)
    record = _record(logging.WARNING, exc_info=original)
    try:
        raise ValueError("different")
    except ValueError:
        debug_filter.filter(record)
    assert record.exc_info is original


def test_sentinel_prevents_double_injection(debug_filter):
    """The same LogRecord passing through two handlers should only be injected once."""
    record = _record(logging.WARNING)
    try:
        raise ValueError("boom")
    except ValueError:
        debug_filter.filter(record)
        assert record.exc_info is not None
        record.exc_info = False  # simulate: first handler consumed it, cleared the field
        debug_filter.filter(record)  # second handler pass
    assert not record.exc_info  # sentinel blocked re-injection


# ---------------------------------------------------------------------------
# filter() return value — must never swallow records
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("levelno", [
    logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL,
])
def test_filter_always_returns_true(debug_filter, levelno):
    assert debug_filter.filter(_record(levelno)) is True


# ---------------------------------------------------------------------------
# install_filter() integration
# ---------------------------------------------------------------------------

@pytest.fixture()
def clean_installed_filters():
    """Undo install_filter()'s filter installations after the test.

    install_filter() offers no uninstall, and it installs in four places: both
    singletons on the root logger, and both again on every handler of the root and
    ``dlt`` loggers. Removing only some of them is not enough -- this fixture mirrors
    the install exactly.

    The one that actually leaks damage is ``_FILTER_SINGLETON``
    (:class:`LogContextFilter`), which rewrites ``record.msg`` to carry a
    ``[target][phase]`` prefix. Left installed, it silently prefixed every later
    module's log records and broke local_log_scrape_regex_test.py's exact-match
    message assertions. That was invisible until this file was renamed from
    test_debug_exc_info_filter.py, which moved it from "t" to "d" in collection order
    -- ahead of the file it was polluting instead of behind it.

    Not undone: install_filter() also sets ``markup``/``show_path`` on any Rich
    handler it finds. Nothing asserts on those and pytest's caplog is not a Rich
    handler, so they are left alone rather than snapshotted.
    """
    yield
    for f in (_FILTER_SINGLETON, _EXC_INFO_FILTER_SINGLETON):
        logging.getLogger().removeFilter(f)
        for logger_name in ("", "dlt"):
            for handler in logging.getLogger(logger_name).handlers:
                handler.removeFilter(f)


def test_install_filter_registers_exc_info_filter(clean_installed_filters):
    install_filter()
    assert _EXC_INFO_FILTER_SINGLETON in logging.getLogger().filters


def test_install_filter_is_idempotent(clean_installed_filters):
    install_filter()
    install_filter()
    count = sum(1 for f in logging.getLogger().filters if f is _EXC_INFO_FILTER_SINGLETON)
    assert count == 1


# ---------------------------------------------------------------------------
# _DiagnosticFileHandler
# ---------------------------------------------------------------------------

@pytest.fixture()
def diag(tmp_path) -> _DiagnosticFileHandler:
    h = _DiagnosticFileHandler(tmp_path / "diag.log")
    yield h
    h.close()


def test_diag_counts_warnings(diag):
    diag.emit(_record(logging.WARNING))
    assert diag.warning_count == 1
    assert diag.error_count == 0


def test_diag_counts_errors(diag):
    diag.emit(_record(logging.ERROR))
    assert diag.warning_count == 0
    assert diag.error_count == 1


def test_diag_counts_critical_as_error(diag):
    diag.emit(_record(logging.CRITICAL))
    assert diag.error_count == 1
    assert diag.warning_count == 0


def test_diag_ignores_info(diag):
    diag.emit(_record(logging.INFO))
    assert diag.warning_count == 0
    assert diag.error_count == 0


def test_diag_writes_to_file(tmp_path):
    log_path = tmp_path / "diag.log"
    h = _DiagnosticFileHandler(log_path)
    try:
        h.emit(_record(logging.WARNING))
    finally:
        h.close()
    assert log_path.exists()
    assert "test message" in log_path.read_text(encoding="utf-8")


def test_diag_writes_traceback_when_inside_except_block(tmp_path):
    log_path = tmp_path / "diag.log"
    h = _DiagnosticFileHandler(log_path)
    try:
        try:
            raise ValueError("injected traceback")
        except ValueError:
            h.emit(_record(logging.WARNING))
    finally:
        h.close()
    content = log_path.read_text(encoding="utf-8")
    assert "ValueError" in content
    assert "injected traceback" in content


def test_diag_restores_exc_info_after_emit(diag):
    """Console handler must not see the injected exc_info after the file handler runs."""
    record = _record(logging.WARNING)
    try:
        raise ValueError("boom")
    except ValueError:
        diag.emit(record)
    assert not record.exc_info


def test_diag_restores_exc_text_after_emit(diag):
    """Cached traceback string must not survive on the record after emit."""
    record = _record(logging.WARNING)
    try:
        raise ValueError("boom")
    except ValueError:
        diag.emit(record)
    assert record.exc_text is None


def test_diag_does_not_inject_when_exc_info_already_set(diag, tmp_path):
    """If the record already carries exc_info, emit it as-is without restoring."""
    existing = (TypeError, TypeError("pre-existing"), None)
    record = _record(logging.WARNING, exc_info=existing)
    try:
        raise ValueError("different")
    except ValueError:
        diag.emit(record)
    assert record.exc_info is existing  # unchanged


def test_diag_no_file_created_without_records(tmp_path):
    """delay=True means the file is only created on first write."""
    log_path = tmp_path / "diag.log"
    h = _DiagnosticFileHandler(log_path)
    h.close()
    assert not log_path.exists()


def test_diag_captures_debug_inside_except_block(tmp_path):
    """DEBUG records emitted from within an active exception handler go to the file."""
    log_path = tmp_path / "diag.log"
    h = _DiagnosticFileHandler(log_path)
    try:
        try:
            raise ValueError("original error")
        except ValueError:
            h.emit(_record(logging.DEBUG))
    finally:
        h.close()
    assert log_path.exists()
    assert "test message" in log_path.read_text(encoding="utf-8")


def test_diag_drops_debug_outside_except_block(tmp_path):
    """DEBUG records outside an active exception handler are silently dropped."""
    log_path = tmp_path / "diag.log"
    h = _DiagnosticFileHandler(log_path)
    try:
        h.emit(_record(logging.DEBUG))
    finally:
        h.close()
    assert not log_path.exists()


def test_diag_debug_not_counted_as_warning_or_error(diag):
    """Companion debug lines must not inflate warning/error counts."""
    try:
        raise ValueError("context")
    except ValueError:
        diag.emit(_record(logging.DEBUG))
    assert diag.warning_count == 0
    assert diag.error_count == 0
