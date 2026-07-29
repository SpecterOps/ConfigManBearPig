"""Offline unit tests for SCCM LDAP pass-the-hash / pass-the-ticket wiring.

SCCM's ADClient forwards --nt-hash / --ticket onto the shared LdapAuth so the
shared lockout-safe waterfall picks the right bind mode. These assert the
forwarding and the resulting auth-mode selection without a live DC (ADClient
binds lazily, so construction does no network I/O).
"""
from openhound_sccm.clients.ad import ADClient, ADCredentials


def test_password_selects_ntlm_mode():
    client = ADClient(ADCredentials(domain="mayyhem.com", username="MAYYHEM\\u", password="pw"))
    assert client.auth.password == "pw"
    assert client._select_auth_modes() == ["ntlm"]


def test_nt_hash_forwarded_and_selects_ntlm_hash_mode():
    client = ADClient(ADCredentials(domain="mayyhem.com", username="MAYYHEM\\u", nt_hash="a" * 32))
    assert client.auth.nt_hash == "a" * 32
    assert client._select_auth_modes() == ["ntlm_hash"]


def test_ticket_forwarded_and_selects_kerberos_mode():
    client = ADClient(ADCredentials(domain="mayyhem.com", kerberos_ticket="Zm9vYmFy"))
    assert client.auth.kerberos_ticket == "Zm9vYmFy"
    assert client._select_auth_modes() == ["kerberos"]
