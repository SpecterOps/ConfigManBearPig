"""Tests for how the RemoteRegistry phase reports reads it is not allowed to make.

A non-admin run against a site system is refused on the order of a dozen registry
reads per host: the host-hardening values, all eight SQL Server SuperSocketNetLib
paths, and on tightly-ACL'd hosts the SMS keys too. Logged one-per-read those were
~120 of the 125 ERRORs in a low-privilege lab run against mayyhem.com, none of them
a fault -- the same collection run as a local admin produced zero (con-8a28).

So the contract these tests pin down is:

* a denied read logs at VERBOSE, not ERROR -- detail stays in collect_full_<ts>.log;
* each host emits exactly ONE WARNING naming the capabilities it lost;
* a host that was denied nothing says nothing;
* a genuinely broken read is still an ERROR;
* "denied" and "absent" are distinguishable, so a refused SMS\\Triggers read stops
  claiming the host has no site code.
"""
import logging

import pytest

from openhound_sccm.collectors import registry

HOST = "cas-db.mayyhem.com"
LANMAN = registry.SCCM_REG_KEYS["lanmanserver_parameters"]
LSA = registry.SCCM_REG_KEYS["lsa"]
TRIGGERS = registry.SCCM_REG_KEYS["triggers"]
SQL_2022 = r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib"

# The exact text impacket raises for a refused winreg open, as seen in the lab logs.
DENIED = "DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied"


def _probe():
    """A _RegistryProbe with no live connection -- only the logging/accounting half.

    The read helpers are not exercised here (they need a DCE/RPC binding); these
    tests drive _log_read_failure directly, which is the single place all four
    helpers funnel their failures through.
    """
    return registry._RegistryProbe(HOST, "MAYYHEM", None, None)


# --- classifying one failed read ----------------------------------------------

def test_denied_read_logs_verbose_not_error(caplog):
    probe = _probe()
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe._log_read_failure(f"DWORD value RequireSecuritySignature under {LANMAN}", LANMAN, Exception(DENIED))

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("Access denied reading" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("marker", ["rpc_s_access_denied", "ERROR_ACCESS_DENIED", "STATUS_ACCESS_DENIED"])
def test_every_access_denied_spelling_is_recognised(marker):
    """impacket reports the same refusal through several exception layers."""
    probe = _probe()
    probe._log_read_failure("a value", LANMAN, Exception(f"boom: {marker}"))
    assert probe.was_denied(LANMAN)


def test_absent_key_is_not_counted_as_denied(caplog):
    """A missing key means the host lacks SCCM/SQL -- normal, and not a privilege gap."""
    probe = _probe()
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe._log_read_failure(f"registry key {SQL_2022}", SQL_2022, Exception("ERROR_FILE_NOT_FOUND"))

    assert not probe.was_denied(SQL_2022)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("not found" in r.getMessage() for r in caplog.records)


def test_unexpected_failure_is_still_an_error(caplog):
    """Quieting the expected cases must not quiet a genuine fault."""
    probe = _probe()
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe._log_read_failure(f"registry key {LSA}", LSA, Exception("connection reset by peer"))

    assert not probe.was_denied(LSA)
    assert [r for r in caplog.records if r.levelno == logging.ERROR]


# --- the per-host summary ------------------------------------------------------

def test_summary_is_one_warning_naming_each_lost_capability(caplog):
    """Twelve denied reads collapse to one line listing what was lost, deduplicated."""
    probe = _probe()
    probe._log_read_failure("a", LANMAN, Exception(DENIED))
    probe._log_read_failure("b", LSA, Exception(DENIED))
    probe._log_read_failure("c", registry.SCCM_REG_KEYS["msv10"], Exception(DENIED))
    for suffix in ("MSSQL16", "MSSQL15", "MSSQL14"):
        probe._log_read_failure("d", SQL_2022.replace("MSSQL16", suffix), Exception(DENIED))

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe.log_denied_summary()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "6 registry read(s) denied" in message      # every read counted...
    assert message.count("SQL Server encryption") == 1  # ...but each capability named once
    assert "SMB signing requirement" in message
    assert "NTLM restrictions" in message
    assert "local Administrators" in message            # tells the operator what to do
    assert HOST in message


def test_summary_is_silent_when_nothing_was_denied(caplog):
    """A fully privileged run must not gain a warning it never had."""
    probe = _probe()
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe.log_denied_summary()
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_summary_fires_on_context_exit_even_when_the_phase_returns_early(caplog):
    """collect_registry returns early when the site code is unreadable -- which is
    exactly the denied case -- so the summary hangs off __exit__, not the function end."""
    probe = _probe()
    probe._log_read_failure("a", TRIGGERS, Exception(DENIED))

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        probe.__exit__(None, None, None)

    assert any(r.levelno == logging.WARNING and "registry read(s) denied" in r.getMessage()
               for r in caplog.records)


def test_unmapped_path_falls_back_to_the_raw_key():
    """A newly added SCCM_REG_KEYS entry with no capability label still gets named."""
    assert registry._capability_for(r"SOFTWARE\Vendor\Unmapped") == r"SOFTWARE\Vendor\Unmapped"
