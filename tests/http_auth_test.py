"""Unit tests for the pure auth-ladder selection and helpers in http_auth."""
import pytest

from openhound_sccm.clients import http_auth as ha


# --- choose_auth ladder selection (pure; no network) ---------------------

def plan(**kw):
    base = dict(username=None, password=None, nt_hash=None, ticket=None,
                target_host="mp.mayyhem.com", sspi_available=False)
    base.update(kw)
    return ha.choose_auth(**base)


def test_ticket_is_kerberos_only_no_ntlm_fallback():
    assert plan(ticket="QUJD") == ["kerberos"]


def test_explicit_password_is_kerberos_then_ntlm():
    assert plan(username="mayyhem\\admin", password="Pw") == ["kerberos", "ntlm"]


def test_explicit_nthash_is_kerberos_then_ntlm():
    assert plan(username="mayyhem\\admin", nt_hash="aabbccdd") == ["kerberos", "ntlm"]


def test_ip_target_skips_kerberos():
    assert plan(username="mayyhem\\admin", password="Pw", target_host="10.10.0.5") == ["ntlm"]


def test_explicit_creds_win_over_sspi():
    assert plan(username="mayyhem\\admin", password="Pw", sspi_available=True) == ["kerberos", "ntlm"]


def test_sspi_when_no_creds():
    assert plan(sspi_available=True) == ["sspi"]


def test_anonymous_last_resort():
    assert plan() == ["anonymous"]


def test_username_without_secret_is_not_explicit():
    # A username with no password/hash can't do explicit auth -> SSPI/anon.
    assert plan(username="mayyhem\\admin", sspi_available=True) == ["sspi"]
    assert plan(username="mayyhem\\admin") == ["anonymous"]


# --- helpers -------------------------------------------------------------

def test_format_hashes_bare_and_full():
    assert ha.format_hashes("aabbccdd").endswith(":aabbccdd")
    assert ha.format_hashes("aabbccdd").startswith(ha.EMPTY_LM_HASH)
    assert ha.format_hashes("lm:nt") == "lm:nt"
    assert ha.format_hashes(None) is None


def test_http_spn():
    assert ha.http_spn("MP.mayyhem.com") == "HTTP/MP.mayyhem.com"


def test_split_user_domain():
    assert ha.split_user_domain("MAYYHEM\\admin", "mayyhem.com") == ("MAYYHEM", "admin")
    assert ha.split_user_domain("admin@mayyhem.com", "x") == ("mayyhem.com", "admin")
    assert ha.split_user_domain("admin", "mayyhem.com") == ("mayyhem.com", "admin")


def test_is_ip():
    assert ha.is_ip("10.0.0.1") is True
    assert ha.is_ip("mp.mayyhem.com") is False


# --- negotiator pure parts ----------------------------------------------

def test_ntlm_negotiator_first_token_is_bytes_not_done():
    neg = ha.NtlmNegotiator(domain="MAYYHEM", username="admin", password="Pw", nt_hash=None)
    token, done = neg.step(None)
    assert isinstance(token, (bytes, bytearray)) and len(token) > 0
    assert done is False  # NTLM needs the server challenge before completing


def test_ntlm_negotiator_accepts_nt_hash():
    neg = ha.NtlmNegotiator(domain="MAYYHEM", username="admin", password=None,
                            nt_hash="8846f7eaee8fb117ad06bdd830b7586c")
    assert neg._nt == "8846f7eaee8fb117ad06bdd830b7586c"
    assert neg._lm == ha.EMPTY_LM_HASH


def test_kerberos_negotiator_caches_service_ticket(monkeypatch):
    # KerberosNegotiator now delegates minting to the shared KerberosToken, which
    # does the KDC exchange once and reuses the cached service ticket; later steps
    # rebuild only the AP-REQ. Patch the token's internals to prove the caching.
    neg = ha.KerberosNegotiator(target_host="mp.mayyhem.com", realm="MAYYHEM.COM",
                                username="admin", password="Pw", nt_hash=None,
                                ticket=None, kdc_host="dc.mayyhem.com")
    calls = {"n": 0}

    def fake_service_ticket():
        calls["n"] += 1
        return (b"TGS", object(), object())

    monkeypatch.setattr(neg._token, "_service_ticket", fake_service_ticket)
    monkeypatch.setattr(neg._token, "_build_blob", lambda tgs, cipher, sk: b"APREQ")
    t1, d1 = neg.step(None)
    t2, d2 = neg.step(None)
    assert (t1, t2) == (b"APREQ", b"APREQ") and d1 and d2
    assert calls["n"] == 1  # one KDC exchange, reused (cached inside KerberosToken)


def test_kerberos_negotiator_rejects_bad_ticket():
    with pytest.raises(ValueError):
        ha.KerberosNegotiator(target_host="mp.mayyhem.com", realm="MAYYHEM.COM",
                              username=None, password=None, nt_hash=None,
                              ticket="!!!not-base64!!!", kdc_host=None)
