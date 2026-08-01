"""Unit tests for the transport-only WMI client (clients/wmi.py).

Transports are mocked: these cover the auth-ladder logic, the rung->backend
mapping, WQL construction, and the row normalization (including the embedded
SMS ``Props`` array) without any network or DCOM. The client is SCCM-agnostic —
the caller supplies the namespace and class; site-code identification lives in
the privileged collector (see test_privileged.py).
"""
import base64

import pytest

from openhound_sccm.clients import wmi as w
# Row normalization + the DCOM/pywin32 backends moved to the shared library
# (SCCM's wmi now imports the backends from there), so test _normalize at its
# new home. The WQL builder and the auth-ladder wrapper stay SCCM-local (w.*).
from openhound_collector_common.clients import wmi as shared_wmi


# --- WQL builder ----------------------------------------------------------

def test_build_wql_select_star_when_no_columns():
    assert w._build_wql("SMS_Role") == "SELECT * FROM SMS_Role"


def test_build_wql_columns_and_where():
    wql = w._build_wql("SMS_SCI_SiteDefinition", ("SiteCode", "Props"), "SiteCode = 'PS1'")
    assert wql == "SELECT SiteCode,Props FROM SMS_SCI_SiteDefinition WHERE SiteCode = 'PS1'"


# --- normalization --------------------------------------------------------

class _FakeObj:
    """Stand-in for impacket IWbemClassObject: getProperties() -> {name: {'value': ...}}."""
    def __init__(self, props):
        self._props = props

    def getProperties(self):
        return self._props


def test_normalize_flattens_scalar_values():
    props = {"SiteCode": {"value": "PS1"}, "BuildNumber": {"value": 9078}}
    assert shared_wmi._normalize(props) == {"SiteCode": "PS1", "BuildNumber": 9078}


def test_normalize_unwraps_embedded_props_array():
    props = {
        "SiteCode": {"value": "PS1"},
        "Props": {"value": [
            _FakeObj({"PropertyName": {"value": "siteGUID"}, "Value1": {"value": "{G}"}}),
        ]},
    }
    out = shared_wmi._normalize(props)
    assert out["SiteCode"] == "PS1"
    assert out["Props"] == [{"PropertyName": "siteGUID", "Value1": "{G}"}]


# --- ladder + streaming query ---------------------------------------------

class FakeBackend:
    """Records connect/execquery; `open_error` simulates an auth failure on the
    first real query (impacket raises when the DCOM connection is established).
    The fake's "raw enumerator" is just the row list, which `stream` replays."""
    def __init__(self, *, rows=None, open_error=None):
        self.rows = rows if rows is not None else []
        self.open_error = open_error
        self.connected = False
        self.queries = []
        self.closed = False

    def connect(self):
        self.connected = True

    def execquery(self, namespace, wql):
        self.queries.append((namespace, wql))
        if self.open_error:
            raise self.open_error
        return self.rows

    def stream(self, raw):
        for r in raw:
            yield r

    def close(self):
        self.closed = True


def _client(**kw):
    base = dict(target="ps1-sms.mayyhem.com", domain="mayyhem.com")
    base.update(kw)
    return w.WmiClient(**base)


def test_first_query_runs_ladder_then_streams(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: False)
    kerb = FakeBackend(open_error=OSError("kerberos down"))
    ntlm = FakeBackend(rows=[{"SiteCode": "PS1", "ProviderForLocalSite": True}])
    backends = {"kerberos": kerb, "ntlm": ntlm}
    client = _client(username="MAYYHEM\\domainadmin", password="pw")
    monkeypatch.setattr(client, "_build_backend", lambda rung: backends.get(rung))
    rows = list(client.query("root\\SMS", "SMS_ProviderLocation"))
    assert rows == [{"SiteCode": "PS1", "ProviderForLocalSite": True}]
    assert kerb.closed and ntlm.connected   # failed rung closed, winner kept
    assert client._backend is ntlm


def test_second_query_reuses_backend_and_builds_namespace_wql(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: False)
    ntlm = FakeBackend(rows=[{"SiteCode": "PS1", "ProviderForLocalSite": True}])
    client = _client(username="u", password="p")
    monkeypatch.setattr(client, "_build_backend", lambda rung: ntlm if rung == "kerberos" else None)
    list(client.query("root\\SMS", "SMS_ProviderLocation"))   # runs the ladder once
    ntlm.rows = [{"RoleName": "Full Admin"}]
    rows = list(client.query("root\\SMS\\site_PS1", "SMS_Role", where="RoleName = 'x'"))
    assert rows == [{"RoleName": "Full Admin"}]
    ns, wql = ntlm.queries[-1]
    assert ns == "root\\SMS\\site_PS1"
    assert wql == "SELECT * FROM SMS_Role WHERE RoleName = 'x'"


def test_ladder_exhausted_yields_nothing(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: False)
    dead = FakeBackend(open_error=OSError("nope"))
    client = _client(username="u", password="p")
    monkeypatch.setattr(client, "_build_backend", lambda rung: dead if rung in ("kerberos", "ntlm") else None)
    assert list(client.query("root\\SMS", "SMS_ProviderLocation")) == []
    assert client._backend is None


def test_query_skips_anonymous_when_no_creds(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: False)
    client = _client()  # no creds -> only the anonymous rung, which DCOM cannot use
    assert list(client.query("root\\SMS", "SMS_ProviderLocation")) == []
    assert client._backend is None


# --- rung -> backend mapping ----------------------------------------------

def test_build_backend_sspi_uses_pywin32_backend(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: True)
    client = _client()  # no creds + sspi available -> ['sspi']
    backend = client._build_backend("sspi")
    assert isinstance(backend, w._PyWin32Backend)


def test_build_backend_maps_rungs_to_impacket_with_kerberos_flag():
    client = _client(username="MAYYHEM\\domainadmin", password="pw", nt_hash="8846f7eaee8fb117ad06bdd830b7586c")
    ntlm = client._build_backend("ntlm")
    kerb = client._build_backend("kerberos")
    assert isinstance(ntlm, w._ImpacketBackend) and ntlm._do_kerberos is False
    assert isinstance(kerb, w._ImpacketBackend) and kerb._do_kerberos is True
    # NT hash flows into the LM:NT split impacket expects.
    assert ntlm._nthash == "8846f7eaee8fb117ad06bdd830b7586c"
    assert client._build_backend("anonymous") is None


# --- --ticket decoding (con-8a33) ------------------------------------------
#
# Mirrors smb_sso_test.py: the WMI path decodes the same base64 KRB-CRED and
# had the same unguarded pair of calls.

def _ticket_client(value):
    return w.WmiClient(target="host", domain="mayyhem.com", kerberos_ticket=value)


def test_load_ticket_rejects_non_base64():
    with pytest.raises(ValueError, match="--ticket"):
        _ticket_client("not!base64!")._load_ticket()


def test_load_ticket_rejects_base64_that_is_not_a_krbcred():
    not_a_ticket = base64.b64encode(b"hello world").decode()
    with pytest.raises(ValueError, match="--ticket"):
        _ticket_client(not_a_ticket)._load_ticket()
