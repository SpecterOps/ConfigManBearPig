"""Unit tests for the HTTP transport: result classification, AuthMode.NONE, loop."""
import base64
import types
from unittest import mock

import requests

from openhound_sccm.clients import http_auth
from openhound_sccm.clients.http import (
    ErrorClass, HttpClient, HttpResult, classify_exception, _parse_negotiate_token,
)
from openhound_sccm.clients.http_auth import AuthMode


# --- result classification (pure) ---------------------------------------

def test_classify_timeout_is_connect_failure():
    assert classify_exception(requests.exceptions.ConnectTimeout()) is ErrorClass.CONNECT_FAILURE
    assert classify_exception(requests.exceptions.ConnectionError()) is ErrorClass.CONNECT_FAILURE


def test_classify_ssl_error_is_tls_failure():
    assert classify_exception(requests.exceptions.SSLError()) is ErrorClass.TLS_FAILURE


def test_httpresult_shape():
    r = HttpResult(status_code=403, content=b"", error_class=ErrorClass.RESPONSE)
    assert r.status_code == 403 and r.error_class is ErrorClass.RESPONSE


def test_parse_negotiate_token():
    assert _parse_negotiate_token("Negotiate") is None          # bare challenge
    assert _parse_negotiate_token("NTLM x") is None             # wrong scheme
    assert _parse_negotiate_token("Negotiate " + base64.b64encode(b"hi").decode()) == b"hi"


# --- transport behaviour (mocked session) --------------------------------

class _FakeResp:
    def __init__(self, status, content=b"", headers=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}


def _client(session, auth=AuthMode.NONE, **kw):
    c = HttpClient(base_url="https://mp.mayyhem.com", auth=auth, domain="mayyhem.com", **kw)
    c._session = session
    return c


def test_none_mode_never_sends_authorization():
    sess = mock.Mock()
    sess.get.return_value = _FakeResp(401, b"deny")
    c = _client(sess, auth=AuthMode.NONE)
    result = c.get("/SMS_MP/.sms_aut?SMSTRC")
    assert result.status_code == 401 and result.error_class is ErrorClass.RESPONSE
    _, kwargs = sess.get.call_args
    assert "Authorization" not in (kwargs.get("headers") or {})


def test_get_classifies_connection_error():
    sess = mock.Mock()
    sess.get.side_effect = requests.exceptions.ConnectionError()
    c = _client(sess, auth=AuthMode.NONE)
    result = c.get("/SMS_DP_SMSPKG$")
    assert result.status_code is None and result.error_class is ErrorClass.CONNECT_FAILURE


def test_get_classifies_ssl_error():
    sess = mock.Mock()
    sess.get.side_effect = requests.exceptions.SSLError()
    c = _client(sess, auth=AuthMode.NONE)
    assert c.get("/x").error_class is ErrorClass.TLS_FAILURE


def test_from_context_reads_credentials():
    ctx = types.SimpleNamespace(
        domain="mayyhem.com", username="MAYYHEM\\a", password="Pw", nt_hash=None,
        kerberos_ticket=None,
        ad=types.SimpleNamespace(creds=types.SimpleNamespace(domain_controller="dc.mayyhem.com")),
    )
    c = HttpClient.from_context(ctx, "mp.mayyhem.com", auth=AuthMode.NEGOTIATE)
    assert c._base_url == "https://mp.mayyhem.com"
    assert c._username == "MAYYHEM\\a" and c._kdc_host == "dc.mayyhem.com"


def test_negotiate_one_shot_sends_token_then_200():
    sess = mock.Mock()
    sess.get.return_value = _FakeResp(200, b"{}")
    c = _client(sess, auth=AuthMode.NEGOTIATE, username="MAYYHEM\\a", password="Pw")

    class _OneShot:
        def step(self, server_token):
            return b"TOKENBYTES", True

    with mock.patch.object(http_auth, "KerberosNegotiator", return_value=_OneShot()):
        result = c.get("/AdminService/wmi/SMS_Identification")

    assert result.status_code == 200
    headers = sess.get.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Negotiate " + base64.b64encode(b"TOKENBYTES").decode()


def test_negotiate_ntlm_two_legs():
    challenge_b64 = base64.b64encode(b"CHALLENGE").decode()
    sess = mock.Mock()
    sess.get.side_effect = [
        _FakeResp(401, b"", {"WWW-Authenticate": "Negotiate " + challenge_b64}),  # after type1
        _FakeResp(200, b"{}"),                                                    # after type3
    ]
    c = _client(sess, auth=AuthMode.NEGOTIATE, username="MAYYHEM\\a", password="Pw")

    class _Ntlm:
        def __init__(self):
            self.tokens = []

        def step(self, server_token):
            self.tokens.append(server_token)
            if server_token is None:
                return b"T1", False
            return b"T3", True

    # IP target forces the ladder to NTLM-only so this test is deterministic.
    c._host = "10.0.0.9"
    with mock.patch.object(http_auth, "NtlmNegotiator", return_value=_Ntlm()):
        result = c.get("/AdminService")
    assert result.status_code == 200
    assert sess.get.call_count == 2


def test_negotiate_falls_back_kerberos_to_ntlm_on_protocol_error():
    sess = mock.Mock()
    sess.get.return_value = _FakeResp(200, b"{}")
    c = _client(sess, auth=AuthMode.NEGOTIATE, username="MAYYHEM\\a", password="Pw")

    class _Boom:
        def step(self, server_token):
            raise RuntimeError("no SPN / clock skew")  # protocol failure

    class _Ntlm:
        def step(self, server_token):
            return b"NTLMTOK", True

    with mock.patch.object(http_auth, "KerberosNegotiator", return_value=_Boom()), \
         mock.patch.object(http_auth, "NtlmNegotiator", return_value=_Ntlm()):
        result = c.get("/AdminService")
    assert result.status_code == 200


def test_negotiate_reuses_auth_after_first_success():
    # First get authenticates (token); the second rides the persistent connection
    # with a plain GET (no Authorization) and no second handshake.
    sess = mock.Mock()
    sess.get.side_effect = [_FakeResp(200, b"{}"), _FakeResp(200, b"[]")]
    c = _client(sess, auth=AuthMode.NEGOTIATE, username="MAYYHEM\\a", password="Pw")

    class _OneShot:
        def __init__(self):
            self.calls = 0

        def step(self, server_token):
            self.calls += 1
            return b"TOK", True

    one = _OneShot()
    with mock.patch.object(http_auth, "KerberosNegotiator", return_value=one):
        r1 = c.get("/a")
        r2 = c.get("/b")
    assert r1.status_code == 200 and r2.status_code == 200
    assert one.calls == 1  # handshake ran only on the first request
    second_headers = sess.get.call_args_list[1].kwargs.get("headers") or {}
    assert "Authorization" not in second_headers  # reused connection, no token resent


def test_negotiate_reauths_when_reused_connection_401s():
    # Authenticated, then the reused connection returns 401 (server forgot) ->
    # the client transparently re-runs the handshake and recovers.
    sess = mock.Mock()
    sess.get.side_effect = [
        _FakeResp(200, b"{}"),                                       # first auth
        _FakeResp(401, b"", {"WWW-Authenticate": "Negotiate"}),      # reused -> 401
        _FakeResp(200, b"{}"),                                       # re-auth -> 200
    ]
    c = _client(sess, auth=AuthMode.NEGOTIATE, username="MAYYHEM\\a", password="Pw")

    class _OneShot:
        def __init__(self):
            self.calls = 0

        def step(self, server_token):
            self.calls += 1
            return b"TOK", True

    one = _OneShot()
    with mock.patch.object(http_auth, "KerberosNegotiator", return_value=one):
        r1 = c.get("/a")
        r2 = c.get("/b")
    assert r1.status_code == 200 and r2.status_code == 200
    assert one.calls == 2  # re-authenticated after the 401


def test_negotiate_stops_probing_reuse_after_failure():
    # Non-persisting server: after one reuse probe 401s, later gets skip the
    # probe and go straight to the handshake (no repeated wasted round-trip).
    sess = mock.Mock()
    sess.get.side_effect = [
        _FakeResp(200, b"{}"),                                     # get1: handshake -> 200
        _FakeResp(401, b"", {"WWW-Authenticate": "Negotiate"}),    # get2: reuse probe -> 401
        _FakeResp(200, b"{}"),                                     # get2: re-auth -> 200
        _FakeResp(200, b"{}"),                                     # get3: handshake (no probe)
    ]
    c = _client(sess, auth=AuthMode.NEGOTIATE, username="MAYYHEM\\a", password="Pw")

    class _OneShot:
        def __init__(self):
            self.calls = 0

        def step(self, server_token):
            self.calls += 1
            return b"TOK", True

    one = _OneShot()
    with mock.patch.object(http_auth, "KerberosNegotiator", return_value=one):
        c.get("/a")
        c.get("/b")
        c.get("/c")
    assert sess.get.call_count == 4   # 1 + (probe + reauth) + 1; get3 has no probe
    assert one.calls == 3             # handshake on get1, get2 re-auth, get3
    assert "Authorization" in (sess.get.call_args_list[3].kwargs.get("headers") or {})


def test_client_caches_kerberos_negotiator():
    # The Kerberos negotiator (holding the cached ticket) is reused across
    # requests, not rebuilt each time.
    c = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NEGOTIATE,
                   domain="mayyhem.com", username="MAYYHEM\\a", password="Pw")
    assert c._build_negotiator("kerberos") is c._build_negotiator("kerberos")


def test_negotiate_credential_rejection_does_not_fall_through():
    # A final 401 (server rejects our completed token) is returned as-is; the
    # ladder must NOT advance to NTLM (avoids extra lockout-risking attempts).
    sess = mock.Mock()
    sess.get.return_value = _FakeResp(401, b"", {"WWW-Authenticate": "Negotiate"})
    c = _client(sess, auth=AuthMode.NEGOTIATE, username="MAYYHEM\\a", password="Pw")

    class _OneShot:
        def step(self, server_token):
            return b"TOK", True

    ntlm_ctor = mock.Mock()
    with mock.patch.object(http_auth, "KerberosNegotiator", return_value=_OneShot()), \
         mock.patch.object(http_auth, "NtlmNegotiator", ntlm_ctor):
        result = c.get("/AdminService")
    assert result.status_code == 401
    ntlm_ctor.assert_not_called()
