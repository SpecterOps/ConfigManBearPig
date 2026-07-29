import logging
import socket

from openhound_sccm.clients import ad
# The lockout-safe bind waterfall + IP-DC Kerberos fallback now live in the
# shared library (SCCM's ADClient is a thin subclass). The availability flags,
# the socket used for reverse DNS, and the logger are all in the shared module,
# so patch/observe THERE — but still build SCCM's ADClient so this exercises the
# subclass + shared integration end-to-end.
from openhound_collector_common.clients import ad as shared_ad


def _client(domain_controller: str, password: str | None = None) -> ad.ADClient:
    return ad.ADClient(
        ad.ADCredentials(
            domain="mayyhem.com",
            domain_controller=domain_controller,
            username="domainadmin",
            password=password,
        )
    )


def _bind_host(domain_controller: str, password: str | None = None) -> str:
    client = _client(domain_controller, password=password)
    attempts, host = client._prepare_attempts_and_host(client._build_attempt_plan())
    client._log_credential_summary(attempts)
    return host


def _attempt_modes(domain_controller: str, password: str | None = None) -> list[str]:
    return [attempt.auth_mode for attempt in _client(domain_controller, password)._build_attempt_plan()]


def _prepared_attempt_modes(domain_controller: str, password: str | None = None) -> list[str]:
    client = _client(domain_controller, password)
    attempts, _ = client._prepare_attempts_and_host(client._build_attempt_plan())
    return [attempt.auth_mode for attempt in attempts]


def _missing_reverse_dns(ip: str):
    raise socket.herror("not found")


def _unexpected_reverse_dns(ip: str):
    raise AssertionError("rDNS should not run")


def test_uses_reverse_dns_when_integrated_kerberos_gets_ip_domain_controller(
    caplog, monkeypatch
):
    monkeypatch.setattr(shared_ad, "_INTEGRATED_AUTH_AVAILABLE", True)
    monkeypatch.setattr(shared_ad, "_CURRENT_USER_NTLM_AVAILABLE", True)
    caplog.set_level(logging.WARNING, logger=shared_ad.__name__)
    monkeypatch.setattr(
        shared_ad.socket,
        "gethostbyaddr",
        lambda ip: ("dc01.mayyhem.com.", [], [ip]),
    )

    host = _bind_host("10.2.10.100")

    assert host == "dc01.mayyhem.com"
    assert caplog.records == []


def test_uses_current_user_ntlm_fallback_when_reverse_dns_fails(caplog, monkeypatch):
    monkeypatch.setattr(shared_ad, "_INTEGRATED_AUTH_AVAILABLE", True)
    monkeypatch.setattr(shared_ad, "_CURRENT_USER_NTLM_AVAILABLE", True)
    monkeypatch.setattr(shared_ad.socket, "gethostbyaddr", _missing_reverse_dns)
    caplog.set_level(logging.INFO, logger=shared_ad.__name__)

    host = _bind_host("10.2.10.100")

    assert host == "10.2.10.100"
    modes = _prepared_attempt_modes("10.2.10.100")
    assert "sspi_ntlm" in modes
    assert "kerberos" not in modes
    assert all(record.levelno < logging.WARNING for record in caplog.records)
    assert "skipping Kerberos and using current-user NTLM via Windows SSPI" in caplog.text


def test_warns_when_integrated_kerberos_ip_domain_controller_has_no_reverse_dns(
    caplog, monkeypatch
):
    monkeypatch.setattr(shared_ad, "_INTEGRATED_AUTH_AVAILABLE", True)
    monkeypatch.setattr(shared_ad, "_CURRENT_USER_NTLM_AVAILABLE", False)
    monkeypatch.setattr(shared_ad.socket, "gethostbyaddr", _missing_reverse_dns)
    caplog.set_level(logging.WARNING, logger=shared_ad.__name__)

    host = _bind_host("10.2.10.100")

    assert host == "10.2.10.100"
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "integrated Kerberos is using domain controller '10.2.10.100'" in message
    assert "IP address" in message
    assert "reverse DNS did not return a hostname" in message
    assert "hostname (FQDN or NetBIOS name)" in message
    assert "explicit credentials to force NTLM" in message


def test_does_not_warn_when_integrated_kerberos_uses_hostname_domain_controller(
    caplog, monkeypatch
):
    monkeypatch.setattr(shared_ad, "_INTEGRATED_AUTH_AVAILABLE", True)
    monkeypatch.setattr(shared_ad, "_CURRENT_USER_NTLM_AVAILABLE", True)
    monkeypatch.setattr(shared_ad.socket, "gethostbyaddr", _unexpected_reverse_dns)
    caplog.set_level(logging.WARNING, logger=shared_ad.__name__)

    host = _bind_host("dc01.mayyhem.com")

    assert host == "dc01.mayyhem.com"
    assert caplog.records == []


def test_does_not_warn_when_ntlm_uses_ip_domain_controller(caplog, monkeypatch):
    monkeypatch.setattr(shared_ad, "_INTEGRATED_AUTH_AVAILABLE", True)
    monkeypatch.setattr(shared_ad, "_CURRENT_USER_NTLM_AVAILABLE", True)
    monkeypatch.setattr(shared_ad.socket, "gethostbyaddr", _unexpected_reverse_dns)
    caplog.set_level(logging.WARNING, logger=shared_ad.__name__)

    host = _bind_host("10.2.10.100", password="not-secret")

    assert host == "10.2.10.100"
    assert caplog.records == []


def test_uses_current_user_ntlm_when_kerberos_backend_is_unavailable(monkeypatch):
    monkeypatch.setattr(shared_ad, "_INTEGRATED_AUTH_AVAILABLE", False)
    monkeypatch.setattr(shared_ad, "_CURRENT_USER_NTLM_AVAILABLE", True)

    modes = _attempt_modes("10.2.10.100")

    assert modes == ["sspi_ntlm", "sspi_ntlm", "sspi_ntlm"]
