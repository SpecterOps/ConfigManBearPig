"""The SCCM adapter inherits the shared stop rule for rejected passwords."""

import pytest
from ldap3.core.exceptions import LDAPBindError

from openhound_sccm.clients.ad import ADClient, ADCredentials


@pytest.mark.parametrize("label", ["invalidCredentials", "Invalid Credentials"])
def test_rejected_password_is_submitted_only_once_by_sccm(monkeypatch, label):
    client = ADClient(
        ADCredentials(
            domain="example.test",
            domain_controller="dc.example.test",
            username="EXAMPLE\\reader",
            password="illustrative-password",
        )
    )
    calls = []
    failure = LDAPBindError(f"{label}: data 52e")
    monkeypatch.setattr(
        client,
        "_prepare_attempts_and_host",
        lambda attempts: (attempts, "dc.example.test"),
    )

    def rejected(*, host, attempt):
        calls.append(attempt.label)
        raise failure

    monkeypatch.setattr(client, "_open_connection", rejected)
    assert len(client._build_attempt_plan()) > 1
    for _ in range(2):
        with pytest.raises(LDAPBindError) as caught:
            client.bind()
        assert caught.value is failure
    assert len(calls) == 1
    assert client._credential_failure is failure
