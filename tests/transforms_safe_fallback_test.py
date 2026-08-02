"""Tests for _safe() expected-miss log-level logic.

Two benign-miss cases downgrade a "missing source table" from WARNING to DEBUG:

Transport-mirror (wmi_ <-> adminservice_): the collector produces EITHER
wmi_<X> OR adminservice_<X> per data type, depending on which transport was
used. When only one family is present, referencing the absent sibling would
otherwise log a WARNING, creating noise in routine operation.
  - Missing wmi_<X> when adminservice_<X> exists  -> DEBUG
  - Missing adminservice_<X> when wmi_<X> exists   -> DEBUG
  - No sibling AND no privileged transport at all  -> DEBUG
  - No sibling but a privileged transport ran      -> WARNING

Fallback-phase skip (http_ / smb_): HTTP and SMB are fallback phases that
should_run_phase skips once a privileged transport (AdminService/WMI) has
collected a host. So when a privileged transport ran this collection, an
absent http_/smb_ role table just means every relevant host was collected the
privileged way -- expected, not a problem. In an HTTP-only/SMB-only run no
privileged table exists, so the miss stays a WARNING.
  - Missing http_/smb_ table WHEN adminservice_*/wmi_* exists -> DEBUG
  - Missing http_/smb_ table with NO privileged transport     -> WARNING
"""
import logging

import duckdb

from openhound_sccm.transforms import _safe


# ---------------------------------------------------------------------------
# (a) wmi_foo absent but adminservice_foo present -> DEBUG, not WARNING
# ---------------------------------------------------------------------------

def test_safe_wmi_miss_with_adminservice_sibling_logs_debug(caplog):
    """Missing wmi_foo when adminservice_foo exists must log at DEBUG."""
    con = duckdb.connect(":memory:")
    # Seed the adminservice sibling but NOT the wmi table.
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.adminservice_foo (id INTEGER)")
    con.execute("INSERT INTO sccm.adminservice_foo VALUES (1)")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "test<-wmi_foo",
            "INSERT INTO sccm.adminservice_foo SELECT id FROM sccm.wmi_foo",
        )

    # Find the log record that mentions this label.
    relevant = [r for r in caplog.records if "test<-wmi_foo" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-wmi_foo"
    for rec in relevant:
        assert rec.levelno == logging.DEBUG, (
            f"Expected DEBUG for expected fallback miss, got {rec.levelname}: {rec.message}"
        )


# ---------------------------------------------------------------------------
# (b) adminservice_bar absent but wmi_bar present -> DEBUG, not WARNING
# ---------------------------------------------------------------------------

def test_safe_adminservice_miss_with_wmi_sibling_logs_debug(caplog):
    """Missing adminservice_bar when wmi_bar exists must log at DEBUG."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.wmi_bar (id INTEGER)")
    con.execute("INSERT INTO sccm.wmi_bar VALUES (2)")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "test<-adminservice_bar",
            "INSERT INTO sccm.wmi_bar SELECT id FROM sccm.adminservice_bar",
        )

    relevant = [r for r in caplog.records if "test<-adminservice_bar" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-adminservice_bar"
    for rec in relevant:
        assert rec.levelno == logging.DEBUG, (
            f"Expected DEBUG for expected fallback miss, got {rec.levelname}: {rec.message}"
        )


# ---------------------------------------------------------------------------
# (c) No sibling AND no privileged transport at all -> DEBUG
#
# This test used to assert WARNING here, on the grounds that "no sibling" meant a
# real miss. That is exactly backwards for the run it fires on: with NEITHER
# transport table present, the AdminService/WMI phases never produced anything, so
# every table they would have built is expected to be absent. 106 of the 146
# WARNINGs in a low-privilege lab run were this one case. Case (c2) below keeps the
# signal the old test was really protecting.
# ---------------------------------------------------------------------------

def test_safe_no_sibling_and_no_privileged_transport_logs_debug(caplog):
    """Neither transport ran, so an absent transport table is expected, not news."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # Deliberately empty: no adminservice_* or wmi_* table exists.

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "test<-wmi_baz",
            "SELECT 1 FROM sccm.wmi_baz",
        )

    relevant = [r for r in caplog.records if "test<-wmi_baz" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-wmi_baz"
    for rec in relevant:
        assert rec.levelno == logging.DEBUG, (
            f"Expected DEBUG when no privileged transport ran, got {rec.levelname}: {rec.message}"
        )


# ---------------------------------------------------------------------------
# (c2) No sibling, but a privileged transport DID run -> WARNING
# ---------------------------------------------------------------------------

def test_safe_no_sibling_but_privileged_transport_ran_logs_warning(caplog):
    """AdminService worked and produced tables, yet THIS pair is missing -- real news.

    Distinguishes "we never had privilege" (expected) from "the transport was up and
    this one query came back with nothing" (a gap worth investigating).
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # A privileged transport landed *something*, just not wmi_baz or its sibling.
    con.execute("CREATE TABLE sccm.adminservice_unrelated (id INTEGER)")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "test<-wmi_baz",
            "SELECT 1 FROM sccm.wmi_baz",
        )

    relevant = [r for r in caplog.records if "test<-wmi_baz" in r.message]
    assert relevant, "Expected at least one log record mentioning test<-wmi_baz"
    warning_records = [r for r in relevant if r.levelno == logging.WARNING]
    assert warning_records, (
        "Expected WARNING when a privileged transport ran but this table is absent; "
        f"got levels: {[r.levelname for r in relevant]}"
    )


# ---------------------------------------------------------------------------
# (d) http_ fallback table absent but a privileged transport ran -> DEBUG
# ---------------------------------------------------------------------------

def test_safe_http_fallback_miss_with_privileged_transport_logs_debug(caplog):
    """Missing http_smsproviders is expected when AdminService/WMI ran: the SMS
    Provider is the AdminService host, so it's privileged-collected and the HTTP
    fallback probe is skipped -> the resource yields no rows -> table absent."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # A privileged transport ran this collection (some adminservice_* table exists).
    con.execute("CREATE TABLE sccm.adminservice_r_system (id INTEGER)")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "node_computer<-http_smsproviders",
            "SELECT 1 FROM sccm.http_smsproviders",
        )

    relevant = [r for r in caplog.records if "node_computer<-http_smsproviders" in r.message]
    assert relevant, "Expected a log record mentioning node_computer<-http_smsproviders"
    for rec in relevant:
        assert rec.levelno == logging.DEBUG, (
            f"Expected DEBUG for a fallback miss when a privileged transport ran, "
            f"got {rec.levelname}: {rec.message}"
        )


# ---------------------------------------------------------------------------
# (e) http_ fallback table absent and NO privileged transport -> WARNING
# ---------------------------------------------------------------------------

def test_safe_http_fallback_miss_without_privileged_transport_logs_warning(caplog):
    """In an HTTP-only run (no adminservice_*/wmi_* table), a missing http_ role
    table might mean the role truly wasn't found, so it must stay a WARNING."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # No adminservice_*/wmi_* table exists: nothing privileged ran.

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "node_computer<-http_smsproviders",
            "SELECT 1 FROM sccm.http_smsproviders",
        )

    relevant = [r for r in caplog.records if "node_computer<-http_smsproviders" in r.message]
    assert relevant, "Expected a log record mentioning node_computer<-http_smsproviders"
    warning_records = [r for r in relevant if r.levelno == logging.WARNING]
    assert warning_records, (
        f"Expected WARNING when no privileged transport ran; "
        f"got levels: {[r.levelname for r in relevant]}"
    )


# ---------------------------------------------------------------------------
# (f) smb_ fallback table absent but a privileged transport ran -> DEBUG
# ---------------------------------------------------------------------------

def test_safe_smb_fallback_miss_with_privileged_transport_logs_debug(caplog):
    """SMB is a fallback phase like HTTP: a missing smb_computers when a
    privileged transport ran is an expected miss, so DEBUG."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.wmi_r_system (id INTEGER)")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "node_computer<-smb_computers",
            "SELECT 1 FROM sccm.smb_computers",
        )

    relevant = [r for r in caplog.records if "node_computer<-smb_computers" in r.message]
    assert relevant, "Expected a log record mentioning node_computer<-smb_computers"
    for rec in relevant:
        assert rec.levelno == logging.DEBUG, (
            f"Expected DEBUG for an SMB fallback miss when a privileged transport ran, "
            f"got {rec.levelname}: {rec.message}"
        )


# ---------------------------------------------------------------------------
# (g) smb_ fallback table absent and NO privileged transport -> WARNING
# ---------------------------------------------------------------------------

def test_safe_smb_fallback_miss_without_privileged_transport_logs_warning(caplog):
    """In an SMB-only run, a missing smb_computers stays a WARNING."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _safe(
            con,
            "node_computer<-smb_computers",
            "SELECT 1 FROM sccm.smb_computers",
        )

    relevant = [r for r in caplog.records if "node_computer<-smb_computers" in r.message]
    assert relevant, "Expected a log record mentioning node_computer<-smb_computers"
    warning_records = [r for r in relevant if r.levelno == logging.WARNING]
    assert warning_records, (
        f"Expected WARNING when no privileged transport ran; "
        f"got levels: {[r.levelname for r in relevant]}"
    )
