# tests/test_smb_sso.py
from openhound_sccm.clients import smb_sso
from openhound_sccm.collectors import registry


def test_sspi_unavailable_off_windows(monkeypatch):
    monkeypatch.setattr(smb_sso.sys, "platform", "linux")
    assert smb_sso._sspi_negotiate_available() is False


def test_sspi_available_on_windows_when_modules_import(monkeypatch):
    monkeypatch.setattr(smb_sso.sys, "platform", "win32")
    monkeypatch.setattr(smb_sso.importlib, "import_module", lambda name: object())
    assert smb_sso._sspi_negotiate_available() is True


def test_sspi_unavailable_when_modules_missing(monkeypatch):
    monkeypatch.setattr(smb_sso.sys, "platform", "win32")

    def _raise(name):
        raise ImportError(name)

    monkeypatch.setattr(smb_sso.importlib, "import_module", _raise)
    assert smb_sso._sspi_negotiate_available() is False


def test_cifs_spn():
    assert smb_sso._cifs_spn("ps1-pss.mayyhem.com") == "cifs/ps1-pss.mayyhem.com"


def test_split_user_domain_backslash():
    assert smb_sso._split_user_domain("MAYYHEM\\admin", "mayyhem.com") == ("MAYYHEM", "admin")


def test_split_user_domain_upn():
    assert smb_sso._split_user_domain("admin@mayyhem.com", "fallback.com") == ("mayyhem.com", "admin")


def test_split_user_domain_bare_user_uses_default():
    assert smb_sso._split_user_domain("admin", "mayyhem.com") == ("mayyhem", "admin")


def test_split_user_domain_empty_uses_default():
    assert smb_sso._split_user_domain(None, "mayyhem.com") == ("mayyhem", "")


class _FakeSecBuffer:
    def __init__(self, data):
        self.Buffer = data


class _FakeCtxt:
    def QueryContextAttributes(self, attr):
        return b"K" * 16


class _FakeClientAuth:
    """Two-leg fake: first authorize returns continue, second returns done."""

    def __init__(self):
        self.inputs = []
        self.ctxt = _FakeCtxt()
        self._calls = 0

    def authorize(self, in_token):
        self.inputs.append(in_token)
        self._calls += 1
        done = self._calls >= 2
        self.authenticated = done
        return (0 if done else 0x90312, [_FakeSecBuffer(b"token-%d" % self._calls)])


def test_negotiate_client_steps_and_returns_session_key(monkeypatch):
    fake = _FakeClientAuth()
    monkeypatch.setattr(smb_sso, "_make_negotiate_auth", lambda spn: fake)
    monkeypatch.setattr(smb_sso, "_query_session_key", lambda auth: b"K" * 16)

    client = smb_sso._SSPINegotiateClient("cifs/host")
    token1, done1 = client.step(None)
    token2, done2 = client.step(b"server-challenge")

    assert token1 == b"token-1" and done1 is False
    assert token2 == b"token-2" and done2 is True
    assert fake.inputs == [None, b"server-challenge"]
    assert client.session_key() == b"K" * 16


class _FakeAns(dict):
    def __init__(self, status, session_id, data, raw=b"raw"):
        super().__init__()
        self["Status"] = status
        self["SessionID"] = session_id
        self["Data"] = data
        self.rawData = raw

    def isValidAnswer(self, expected):
        if self["Status"] != expected:
            raise AssertionError("unexpected status")
        return True


class _FakeSMB3:
    """Scripts a 1-leg (Kerberos-style) success: send once, server returns SUCCESS."""

    def __init__(self):
        self.RequireMessageSigning = False
        self._Connection = {"Dialect": 0x0300, "RequireSigning": False,
                            "SupportsEncryption": False, "PreauthIntegrityHashValue": b"\x00" * 64}
        self._Session = {}
        self.sent = []
        self._answers = iter([_FakeAns(smb_sso.STATUS_SUCCESS, b"sid-1", b"")])

    def SMB_PACKET(self):
        return {}

    def sendSMB(self, packet):
        self.sent.append(packet)
        return len(self.sent)

    def recvSMB(self, packet_id):
        return next(self._answers)


class _OneLegClient:
    def __init__(self, spn):
        self.spn = spn

    def step(self, server_token):
        return (b"ap-req", True)

    def session_key(self):
        return b"S" * 16


def test_smb_login_sspi_one_leg_installs_session_key(monkeypatch):
    smb3 = _FakeSMB3()
    fake_conn = type("C", (), {"getSMBServer": lambda self: smb3})()
    monkeypatch.setattr(smb_sso, "_SSPINegotiateClient", _OneLegClient)
    # The corrected loop parses the response buffer before the success check; stub the
    # parser so this control-flow test needs no real SMB2 wire bytes.
    monkeypatch.setattr(smb_sso, "SMB2SessionSetup_Response", lambda data: {"Buffer": b""})
    # Skip impacket key derivation in this control-flow test.
    monkeypatch.setattr(smb_sso, "_install_session_keys",
                        lambda s, key: s._Session.__setitem__("SessionKey", key))

    smb_sso.smb_login_sspi(fake_conn, "cifs/host")

    assert len(smb3.sent) == 1
    assert smb3._Session["SessionKey"] == b"S" * 16
    assert smb3._Session["SessionID"] == b"sid-1"


class _RecordingSMB:
    instances = []

    def __init__(self, *args, **kwargs):
        self.login_calls = []
        self.closed = False
        self.raise_on_login = False
        _RecordingSMB.instances.append(self)

    def login(self, user, password, domain, *a, **k):
        self.login_calls.append((user, password, domain))
        if self.raise_on_login:
            raise OSError("auth failed")

    def close(self):
        self.closed = True


def _patch_smb(monkeypatch, raise_on_login=False):
    _RecordingSMB.instances = []

    def _factory(*a, **k):
        smb = _RecordingSMB()
        smb.raise_on_login = raise_on_login
        return smb

    monkeypatch.setattr(smb_sso, "SMBConnection", _factory)


def test_connect_smb_explicit_creds_uses_ntlm_login(monkeypatch):
    _patch_smb(monkeypatch)
    monkeypatch.setattr(smb_sso, "_SSPI_NEGOTIATE_AVAILABLE", True)
    called = []
    monkeypatch.setattr(smb_sso, "smb_login_sspi", lambda c, spn: called.append(spn))

    smb = smb_sso.connect_smb("host", "mayyhem.com", "MAYYHEM\\admin", "pw")

    assert smb.login_calls == [("admin", "pw", "MAYYHEM")]
    assert called == []  # SSPI not used when full creds present


def test_connect_smb_no_password_uses_sspi(monkeypatch):
    _patch_smb(monkeypatch)
    monkeypatch.setattr(smb_sso, "_SSPI_NEGOTIATE_AVAILABLE", True)
    called = []
    monkeypatch.setattr(smb_sso, "smb_login_sspi", lambda c, spn: called.append(spn))

    smb = smb_sso.connect_smb("ps1.mayyhem.com", "mayyhem.com", "MAYYHEM\\admin", None)

    assert smb.login_calls == []
    assert called == ["cifs/ps1.mayyhem.com"]


def test_connect_smb_no_sspi_falls_back_to_null_session(monkeypatch):
    _patch_smb(monkeypatch)
    monkeypatch.setattr(smb_sso, "_SSPI_NEGOTIATE_AVAILABLE", False)

    smb = smb_sso.connect_smb("host", "mayyhem.com", None, None)

    assert smb.login_calls == [("", "", "mayyhem")]


def test_connect_smb_returns_none_and_closes_on_auth_failure(monkeypatch):
    _patch_smb(monkeypatch, raise_on_login=True)
    monkeypatch.setattr(smb_sso, "_SSPI_NEGOTIATE_AVAILABLE", False)

    result = smb_sso.connect_smb("host", "mayyhem.com", "MAYYHEM\\admin", "pw")

    assert result is None
    assert _RecordingSMB.instances[0].closed is True


def test_connect_smb_sspi_failure_does_not_fall_through(monkeypatch):
    _patch_smb(monkeypatch)
    monkeypatch.setattr(smb_sso, "_SSPI_NEGOTIATE_AVAILABLE", True)

    def _boom(conn, spn):
        raise OSError("no ticket")

    monkeypatch.setattr(smb_sso, "smb_login_sspi", _boom)

    result = smb_sso.connect_smb("host", "mayyhem.com", None, None)

    assert result is None
    assert _RecordingSMB.instances[0].login_calls == []  # no null-session retry


class _NoopCtx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_registry_probe_delegates_to_connect_smb(monkeypatch):
    captured = {}

    def _fake_connect(hostname, domain, username, password, **kw):
        captured.update(hostname=hostname, domain=domain, username=username, password=password)
        return object()  # truthy "connection"; the winreg bind then fails harmlessly

    monkeypatch.setattr(registry, "connect_smb", _fake_connect)
    # Make the TCP/445 reachability probe succeed without real network I/O.
    monkeypatch.setattr(registry.socket, "create_connection", lambda *a, **k: _NoopCtx())

    probe = registry._RegistryProbe("ps1.mayyhem.com", "mayyhem.com", None, None)
    probe.__enter__()

    assert captured["hostname"] == "ps1.mayyhem.com"
    assert captured["domain"] == "mayyhem.com"


class _FakeSMB:
    """Stand-in for an authenticated SMBConnection returned by connect_smb."""

    def getRemoteHost(self):
        return "1.2.3.4"

    def logoff(self):
        pass


class _FakeDCE:
    def connect(self):
        pass

    def bind(self, uuid):
        pass

    def disconnect(self):
        pass


def _patch_probe_transport(monkeypatch, connect_behaviour):
    """Wire up a _RegistryProbe so __enter__ reaches the winreg bind offline.

    *connect_behaviour* is called on each fake ``rpc.connect()`` (the point where
    the real ``\\winreg`` pipe is opened) with the 1-based attempt number; it may
    raise to simulate a bind failure. Returns the recorded ``sleeps`` list so the
    test can assert on retry timing.
    """
    from impacket.dcerpc.v5 import rrp as impacket_rrp
    from impacket.dcerpc.v5 import transport as impacket_transport

    monkeypatch.setattr(registry, "connect_smb", lambda *a, **k: _FakeSMB())
    monkeypatch.setattr(registry.socket, "create_connection", lambda *a, **k: _NoopCtx())

    sleeps = []
    monkeypatch.setattr(registry.time, "sleep", lambda s: sleeps.append(s))

    state = {"connects": 0}

    class _FakeRPC:
        def connect(self):
            state["connects"] += 1
            connect_behaviour(state["connects"])

        def get_dce_rpc(self):
            return _FakeDCE()

    monkeypatch.setattr(impacket_transport, "SMBTransport", lambda *a, **k: _FakeRPC())
    monkeypatch.setattr(impacket_rrp, "hOpenLocalMachine", lambda dce: {"phKey": "ROOT"})
    return sleeps, state


def test_registry_probe_retries_then_succeeds_on_pipe_not_available(monkeypatch):
    # The trigger-start race: the first opens find the \winreg pipe not yet
    # listening; the bind must wait and retry until RemoteRegistry is up.
    from impacket.nt_errors import STATUS_PIPE_NOT_AVAILABLE
    from impacket.smbconnection import SessionError

    def _behaviour(attempt):
        if attempt < 3:
            raise SessionError(error=STATUS_PIPE_NOT_AVAILABLE)

    sleeps, state = _patch_probe_transport(monkeypatch, _behaviour)

    probe = registry._RegistryProbe("ps1.mayyhem.com", "mayyhem.com", None, None)
    result = probe.__enter__()

    assert result is probe                       # bind eventually succeeded
    assert state["connects"] == 3                # took three attempts
    assert probe.root_key == "ROOT"
    # Slept once between each of the three attempts, never after success.
    assert sleeps == [registry.WINREG_BIND_RETRY_DELAY, registry.WINREG_BIND_RETRY_DELAY]


def test_registry_probe_does_not_retry_on_other_smb_errors(monkeypatch):
    # A non-transient SMB error (e.g. access denied) must fail fast: no retry,
    # no sleep -- we don't want to stall on hosts that will never answer.
    from impacket.nt_errors import STATUS_ACCESS_DENIED
    from impacket.smbconnection import SessionError

    def _behaviour(attempt):
        raise SessionError(error=STATUS_ACCESS_DENIED)

    sleeps, state = _patch_probe_transport(monkeypatch, _behaviour)

    probe = registry._RegistryProbe("ps1.mayyhem.com", "mayyhem.com", None, None)
    result = probe.__enter__()

    assert result is None
    assert state["connects"] == 1                # single attempt, no retry
    assert sleeps == []


# --- pass-the-hash / pass-the-ticket routing (added with the SMB collector) --

class _RoutingSMB:
    """Records which impacket auth method connect_smb invoked, with hashes/TGT."""

    def __init__(self):
        self.calls = []

    def login(self, user, password, domain="", lmhash="", nthash="", *a, **k):
        self.calls.append(("login", user, password, domain, lmhash, nthash))

    def kerberosLogin(self, user, password, domain="", lmhash="", nthash="",
                      aesKey="", kdcHost=None, TGT=None, TGS=None, *a, **k):
        self.calls.append(("kerberosLogin", user, domain, kdcHost, TGT))

    def close(self):
        pass


def _patch_routing(monkeypatch):
    created = {}
    monkeypatch.setattr(smb_sso, "SMBConnection", lambda *a, **k: created.setdefault("smb", _RoutingSMB()))
    # Keep the SSPI / null rungs out of the way and skip real ticket decoding.
    monkeypatch.setattr(smb_sso, "_SSPI_NEGOTIATE_AVAILABLE", False)
    monkeypatch.setattr(smb_sso, "_load_ticket", lambda t: ("ticketuser", "FAKE_TGT", None))
    return created


def test_connect_smb_nt_hash_uses_pass_the_hash(monkeypatch):
    created = _patch_routing(monkeypatch)
    smb_sso.connect_smb("host", "mayyhem.com", "MAYYHEM\\admin", None, nt_hash="a" * 32)
    method, user, password, domain, lmhash, nthash = created["smb"].calls[0]
    assert method == "login" and password == ""      # hash used, password ignored
    assert (user, domain) == ("admin", "MAYYHEM")
    assert nthash == "a" * 32
    assert lmhash == smb_sso.format_hashes("a" * 32).split(":")[0]


def test_connect_smb_ticket_uses_pass_the_ticket(monkeypatch):
    created = _patch_routing(monkeypatch)
    smb_sso.connect_smb("host", "mayyhem.com", None, None,
                        kerberos_ticket="Zm9v", kdc_host="dc.mayyhem.com")
    method, user, domain, kdc, tgt = created["smb"].calls[0]
    assert method == "kerberosLogin"
    assert user == "ticketuser"        # client principal derived from the ticket
    assert domain == "mayyhem.com"     # full DNS domain as the Kerberos realm
    assert kdc == "dc.mayyhem.com"
    assert tgt == "FAKE_TGT"


def test_connect_smb_ticket_prefers_explicit_user(monkeypatch):
    created = _patch_routing(monkeypatch)
    smb_sso.connect_smb("host", "mayyhem.com", "MAYYHEM\\admin", None,
                        kerberos_ticket="Zm9v", kdc_host="dc")
    method, user, _domain, _kdc, _tgt = created["smb"].calls[0]
    assert method == "kerberosLogin" and user == "admin"
