"""Tests for the demotion of impacket's benign "no Kerberos cache" CRITICAL.

impacket looks for a Kerberos credential cache in ``KRB5CCNAME`` -- a Unix
convention that is essentially never set on Windows -- whenever the WMI Kerberos
rung runs without ``--ticket``. It finds none, logs
``CRITICAL: CCache file is not found. Skipping...``, and then requests a fresh TGT
with the supplied password and succeeds. Nine hosts, nine CRITICALs, nothing wrong
(con-8a28). They are the only CRITICALs the collector ever emits, so they read as
"collection is broken" when it isn't.

The filter rewrites that one record's level to DEBUG. It must NOT touch anything
else impacket says.
"""
import logging

from openhound_sccm import main as m


def _record(level, message, name="impacket"):
    return logging.LogRecord(name, level, __file__, 1, message, None, None)


def test_ccache_critical_is_demoted_to_debug():
    record = _record(logging.CRITICAL, "CCache file is not found. Skipping...")

    assert m._ImpacketNoiseFilter().filter(record) is True  # kept, not dropped
    assert record.levelno == logging.DEBUG
    assert record.levelname == "DEBUG"


def test_other_impacket_criticals_are_left_alone():
    """A blanket cap on the impacket logger would have hidden this one too."""
    record = _record(logging.CRITICAL, "Something genuinely broke")

    m._ImpacketNoiseFilter().filter(record)
    assert record.levelno == logging.CRITICAL


def test_demotion_survives_impacket_rewording_around_the_phrase():
    """Matched on a substring because impacket's surrounding wording has changed
    across releases; the phrase itself has not."""
    record = _record(logging.ERROR, "Kerberos: CCache file is not found at /tmp/x, giving up")

    m._ImpacketNoiseFilter().filter(record)
    assert record.levelno == logging.DEBUG


def test_a_record_already_at_debug_is_untouched():
    """No pointless rewriting when the level is already where we want it."""
    record = _record(logging.DEBUG, "CCache file is not found. Skipping...")

    m._ImpacketNoiseFilter().filter(record)
    assert record.levelno == logging.DEBUG


def test_demoted_record_no_longer_reaches_a_warning_level_handler():
    """The point of the demotion: it drops out of the console and out of
    collect_issues_<ts>.log, both of which gate on record.levelno."""
    handler = logging.Handler(level=logging.WARNING)
    record = _record(logging.CRITICAL, "CCache file is not found. Skipping...")

    m._ImpacketNoiseFilter().filter(record)
    assert record.levelno < handler.level
