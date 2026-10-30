"""One rejected password stops every later sign-in in an SCCM run.

A lab run with a wrong password against one computer cost the account 42
failed sign-ins, and the run still reported success. These checks cover each
SCCM sign-in path: SMB (also used by remote registry), WMI, the AdminService
web client, the SQL connection-security probes, and the main run's one-time
check and failure report. Nothing here touches the network.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import typer
from impacket.smbconnection import SessionError

from openhound_collector_common.clients.credential_guard import (
    CREDENTIALS_REJECTED_REASON,
    CredentialCheck,
    CredentialGuard,
)
from openhound_collector_common.clients.kerberos import KerberosAcquisitionError
from openhound_sccm.clients import smb_sso
from openhound_sccm.clients.http import ErrorClass, HttpClient
from openhound_sccm.clients.http_auth import AuthMode
from openhound_sccm.clients.wmi import WmiClient
from openhound_sccm.main import _check_credentials_before_collection, _stop_if_credentials_rejected
from openhound_sccm.phased_pipeline import WorkQueue

STATUS_LOGON_FAILURE = 0xC000006D
WRONG_PASSWORD = 24  # Kerberos KDC_ERR_PREAUTH_FAILED


def rejected_ticket_request():
    return KerberosAcquisitionError("refused", kdc_error_code=WRONG_PASSWORD)


# --- SMB and remote registry ------------------------------------------------


def fake_smb(monkeypatch, failure):
    created = []

    class Connection:
        def __init__(self, *args, **kwargs):
            created.append(args[0])

        def login(self, *args, **kwargs):
            raise failure

        def close(self):
            pass

    monkeypatch.setattr(smb_sso, "SMBConnection", Connection)
    return created


def test_smb_wrong_password_stops_the_run(monkeypatch):
    guard = CredentialGuard()
    fake_smb(monkeypatch, SessionError(STATUS_LOGON_FAILURE))
    smb = smb_sso.connect_smb(
        "ps1-sms.example.test", "example.test", "EXAMPLE\\reader", "wrong",
        credential_guard=guard,
    )
    assert smb is None
    assert guard.rejected_by == "SMB on ps1-sms.example.test"


def test_smb_is_not_attempted_after_another_rejection(monkeypatch):
    guard = CredentialGuard()
    guard.record_rejection("The domain controller")
    created = fake_smb(monkeypatch, AssertionError("must not sign in"))
    assert smb_sso.connect_smb(
        "ps1-mp.example.test", "example.test", "EXAMPLE\\reader", "wrong",
        credential_guard=guard,
    ) is None
    assert created == []


def test_refused_anonymous_session_does_not_stop_the_run(monkeypatch):
    # A null session uses no account, so its refusal proves nothing about a password.
    guard = CredentialGuard()
    fake_smb(monkeypatch, SessionError(STATUS_LOGON_FAILURE))
    monkeypatch.setattr(smb_sso, "_SSPI_NEGOTIATE_AVAILABLE", False)
    assert smb_sso.connect_smb(
        "ps1-sms.example.test", "example.test", None, None, credential_guard=guard
    ) is None
    assert not guard.is_rejected


# --- WMI --------------------------------------------------------------------


def test_wmi_kerberos_refusal_never_tries_ntlm_with_the_same_password(monkeypatch):
    guard = CredentialGuard()
    built = []

    class Backend:
        def connect(self):
            raise rejected_ticket_request()

        def close(self):
            pass

    client = WmiClient(
        target="ps1-sms.example.test", domain="example.test",
        username="EXAMPLE\\reader", password="wrong", credential_guard=guard,
    )
    monkeypatch.setattr(client, "_build_backend", lambda rung: built.append(rung) or Backend())
    assert list(client.query("root\\cimv2", "Win32_Service")) == []
    assert built == ["kerberos"]
    assert guard.rejected_by == "WMI on ps1-sms.example.test"


def test_wmi_is_not_attempted_after_another_rejection(monkeypatch):
    guard = CredentialGuard()
    guard.record_rejection("The domain controller")
    client = WmiClient(
        target="ps1-mp.example.test", domain="example.test",
        username="EXAMPLE\\reader", password="wrong", credential_guard=guard,
    )
    monkeypatch.setattr(
        client, "_build_backend", lambda rung: pytest.fail("must not sign in")
    )
    assert list(client.query("root\\cimv2", "Win32_Service")) == []


# --- AdminService web client ------------------------------------------------


def web_client(guard):
    return HttpClient(
        base_url="https://ps1-sms.example.test",
        auth=AuthMode.NEGOTIATE,
        domain="example.test",
        username="EXAMPLE\\reader",
        password="wrong",
        credential_guard=guard,
    )


def test_web_kerberos_refusal_never_tries_ntlm_with_the_same_password(monkeypatch):
    guard = CredentialGuard()
    client = web_client(guard)

    class Refused:
        def step(self, server_token):
            raise rejected_ticket_request()

    def negotiator(rung):
        if rung != "kerberos":
            pytest.fail(f"The {rung} rung submitted a rejected password again")
        return Refused()

    monkeypatch.setattr(client, "_build_negotiator", negotiator)
    result = client.get("/AdminService/wmi/SMS_Identification")
    assert result.error_class is ErrorClass.SIGN_IN_REFUSED
    assert guard.rejected_by == "Kerberos for ps1-sms.example.test"


def test_web_client_is_not_attempted_after_another_rejection(monkeypatch):
    guard = CredentialGuard()
    guard.record_rejection("The domain controller")
    client = web_client(guard)
    monkeypatch.setattr(client, "_build_negotiator", lambda rung: pytest.fail("must not sign in"))
    monkeypatch.setattr(client, "_request", lambda *args, **kwargs: pytest.fail("must not connect"))
    assert client.get("/AdminService/wmi/SMS_Identification").error_class is ErrorClass.SIGN_IN_REFUSED


# --- SQL connection-security probes -----------------------------------------


def test_sql_security_probes_are_skipped_after_a_rejection(monkeypatch):
    from openhound_sccm.collectors import mssql

    guard = CredentialGuard()
    guard.record_rejection("The domain controller")
    ad = SimpleNamespace(get_spns=lambda target: ["MSSQLSvc/ps1-db.example.test:1433"])
    ctx = SimpleNamespace(
        ad=ad, domain="example.test", username="EXAMPLE\\reader", password="wrong",
        nt_hash=None, kerberos_ticket=None, credential_guard=guard,
        method_enabled=lambda method: True, target_hosts_by_hostname={},
    )
    monkeypatch.setattr(mssql, "_check_port", lambda host, port: True)
    monkeypatch.setattr(mssql, "test_epa", lambda **kwargs: pytest.fail("EPA probe signed in"))
    list(mssql.collect_mssql("ps1-db.example.test", ctx))


# --- the main run -----------------------------------------------------------


def test_rejected_first_sign_in_ends_the_run_before_discovery():
    ctx = SimpleNamespace(
        ad=SimpleNamespace(confirm_credentials=lambda: CredentialCheck.REJECTED),
        credential_guard=CredentialGuard(),
    )
    with pytest.raises(typer.Exit) as stopped:
        _check_credentials_before_collection(ctx)
    assert stopped.value.exit_code == 1


@pytest.mark.parametrize(
    "outcome", [CredentialCheck.ACCEPTED, CredentialCheck.UNCHECKED, CredentialCheck.NOT_NEEDED]
)
def test_other_first_sign_in_outcomes_let_collection_continue(outcome):
    ctx = SimpleNamespace(ad=SimpleNamespace(confirm_credentials=lambda: outcome))
    _check_credentials_before_collection(ctx)


def test_rejection_during_the_run_reports_failure(caplog):
    guard = CredentialGuard()
    ctx = SimpleNamespace(credential_guard=guard)
    _stop_if_credentials_rejected(ctx)  # Nothing rejected: no effect.
    guard.record_rejection("SMB on ps1-mp.example.test")
    with pytest.raises(typer.Exit) as stopped:
        _stop_if_credentials_rejected(ctx)
    assert stopped.value.exit_code == 1
    assert "SMB on ps1-mp.example.test rejected the supplied sign-in details" in caplog.text


def test_rejection_stops_computers_that_have_not_started():
    guard = CredentialGuard()
    queue = WorkQueue()
    guard.add_stop_action(lambda: queue.stop(CREDENTIALS_REJECTED_REASON))
    assert queue.submit("ps1-sms.example.test")
    guard.record_rejection("WMI on ps1-mp.example.test")
    assert queue.stop_reason == CREDENTIALS_REJECTED_REASON
    assert queue.unstarted_targets() == ("ps1-sms.example.test",)
    assert not queue.submit("ps1-dp.example.test")


def test_directory_client_and_run_settings_share_one_record(monkeypatch):
    from openhound_sccm.source import get_last_ctx, source

    for name in ("USERNAME", "PASSWORD", "NT_HASH", "KERBEROS_TICKET"):
        monkeypatch.delenv(f"SOURCES__SCCM__{name}", raising=False)
    source(domain="example.test", http_proxy=None)
    ctx = get_last_ctx()
    assert ctx.ad.credential_guard is ctx.credential_guard
