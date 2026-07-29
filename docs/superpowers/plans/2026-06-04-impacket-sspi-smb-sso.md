# SSPI SMB Single Sign-On Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **DO NOT COMMIT TO GIT.** Per the project owner's instruction, this plan creates and modifies files but performs **no** git commits. Leave all work uncommitted in the working tree for manual review. Ignore any "commit" / "frequent commits" guidance in the executing-plans or subagent-driven-development sub-skills.

**Goal:** Let the SCCM collector's impacket SMB phases authenticate as the current logged-in Windows user via SSPI Negotiate (Kerberos-preferred, NTLM fallback) when no explicit password is given, replacing the unauthenticated null-session fallback.

**Architecture:** A new `clients/smb_sso.py` module owns a `connect_smb(...)` auth ladder (explicit creds → SSPI Negotiate → null session) and returns an authenticated `SMBConnection`. SSO is implemented *on top of* impacket's public API: a single SSPI Negotiate security context drives a custom SMB2 SESSION_SETUP loop, then installs the session/signing keys the way `impacket.smb3.SMB3.login` does. The Remote Registry probe is the first consumer.

**Tech Stack:** Python 3.13+, impacket (`smbconnection`, `smb3structs`, `crypto`), pywin32 SSPI (`sspi`/`sspicon`), pytest, ruff, mypy. No new dependencies — `pywin32`/`winkerberos` are already declared for `win32`.

**Spec:** [2026-06-04-impacket-sspi-smb-sso-design.md](../specs/2026-06-04-impacket-sspi-smb-sso-design.md)

**Validation status:** The core mechanism was proven end-to-end against the live host `ps1-pss.mayyhem.com` (SMB 3.1.1, signing **required**) via a throwaway spike before this plan was finalized — SSPI Negotiate/Kerberos login, a signed `connectTree("IPC$")`, and a real `\winreg` Remote Registry read all succeeded as the current user. Three corrections from that spike are baked into Task 4: (1) **finalize** the SSPI context with the server's final token before reading the session key; (2) **truncate** the GSS session key to its first 16 bytes (MS-SMB2 3.2.5.3.1); (3) fold **only intermediate** SESSION_SETUP responses into the 3.1.1 pre-auth hash — never the final success response (requests are folded automatically by impacket's `sendSMB`). This makes Task 7 a confirmation, not a discovery.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/openhound_sccm/clients/smb_sso.py` (create) | Capability gate, SSPI Negotiate client wrapper, SESSION_SETUP loop, `connect_smb` ladder, and the `cifs/<host>` SPN + `DOMAIN\user` split helpers. |
| `src/openhound_sccm/collectors/registry.py` (modify) | `_RegistryProbe.__enter__` calls `connect_smb` instead of building/logging into an `SMBConnection` itself; the now-unused `_split_user_domain` moves to `smb_sso.py`. |
| `tests/test_smb_sso.py` (create) | Unit tests for the auth ladder, capability gating, SPN/user-domain helpers, the SSPI client wrapper (fake `sspi`), and the SESSION_SETUP loop (fake `SMB3`). |
| `tests/test_smb_sso_integration.py` (create) | Live-host Windows-only integration test (skipped unless opted in) proving a real signed SMB session against `ps1-pss.mayyhem.com`. |

No `pyproject.toml` change: `sspi`/`sspicon` ship with the already-declared `pywin32`.

---

## Task 1: Module skeleton + SSPI capability gate

**Files:**
- Create: `src/openhound_sccm/clients/smb_sso.py`
- Test: `tests/test_smb_sso.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smb_sso.py
from openhound_sccm.clients import smb_sso


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_smb_sso.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'openhound_sccm.clients.smb_sso'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/openhound_sccm/clients/smb_sso.py
"""Current-user Windows SSO for impacket SMB connections.

Mirrors the LDAP SSO in clients/ad.py: when no complete username+password is
supplied, authenticate to SMB as the logged-in Windows user via SSPI Negotiate
(Kerberos-preferred, NTLM fallback) instead of an anonymous null session.

Built entirely on top of impacket's public API — no impacket source edits.
"""
from __future__ import annotations

import importlib
import logging
import sys

logger = logging.getLogger(__name__)


def _sspi_negotiate_available() -> bool:
    """True only on Windows with the pywin32 SSPI modules importable."""
    if sys.platform != "win32":
        return False
    try:
        importlib.import_module("sspi")
        importlib.import_module("sspicon")
        return True
    except ImportError:
        return False


_SSPI_NEGOTIATE_AVAILABLE = _sspi_negotiate_available()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_smb_sso.py -v`
Expected: PASS (3 passed)

_(No commit — leave changes uncommitted in the working tree for review.)_

---

## Task 2: SPN + DOMAIN\user split helpers

**Files:**
- Modify: `src/openhound_sccm/clients/smb_sso.py`
- Test: `tests/test_smb_sso.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smb_sso.py (append)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_smb_sso.py -k "spn or split" -v`
Expected: FAIL with `AttributeError: module ... has no attribute '_cifs_spn'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/openhound_sccm/clients/smb_sso.py (add imports + helpers)
from typing import Optional


def _cifs_spn(hostname: str) -> str:
    """The SMB service principal name SSPI uses to request a Kerberos ticket."""
    return f"cifs/{hostname}"


def _split_user_domain(username: Optional[str], default_domain: str) -> tuple[str, str]:
    """Split ``DOMAIN\\user`` or ``user@domain`` into ``(domain, user)``.

    Falls back to the first label of ``default_domain`` when no explicit prefix
    is present. (Moved verbatim from collectors/registry.py.)
    """
    if not username:
        return default_domain.split(".")[0], ""
    if "\\" in username:
        d, u = username.split("\\", 1)
        return d, u
    if "@" in username:
        u, d = username.split("@", 1)
        return d, u
    return default_domain.split(".")[0], username
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_smb_sso.py -k "spn or split" -v`
Expected: PASS (5 passed)

_(No commit — leave changes uncommitted in the working tree for review.)_

---

## Task 3: `_SSPINegotiateClient` (single Negotiate context)

The wrapper that produces SPNEGO tokens as the current user and exposes the negotiated session key. `_make_negotiate_auth` isolates the real `sspi` import so tests can inject a fake.

**Files:**
- Modify: `src/openhound_sccm/clients/smb_sso.py`
- Test: `tests/test_smb_sso.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smb_sso.py (append)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_smb_sso.py -k negotiate_client -v`
Expected: FAIL with `AttributeError: module ... has no attribute '_make_negotiate_auth'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/openhound_sccm/clients/smb_sso.py (append)
def _make_negotiate_auth(spn: str):
    """Build a current-user SSPI Negotiate client context (isolated for tests)."""
    import sspi

    return sspi.ClientAuth("Negotiate", targetspn=spn)


def _query_session_key(auth) -> bytes:
    """Read the negotiated session key from the completed SSPI context."""
    import sspicon

    return bytes(auth.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SESSION_KEY))


class _SSPINegotiateClient:
    """Drives one SSPI 'Negotiate' handshake as the current Windows user.

    Mirrors ad.py's _SSPICurrentUserNtlmClient. ``step`` is called once with
    ``None`` to start, then once per server token until ``done`` is True.
    """

    def __init__(self, spn: str) -> None:
        self._auth = _make_negotiate_auth(spn)

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        error, sec_buffers = self._auth.authorize(server_token if server_token else None)
        token = bytes(sec_buffers[0].Buffer) if sec_buffers else b""
        # pywin32: error==0 (SEC_E_OK) means the handshake is complete;
        # SEC_I_CONTINUE_NEEDED (0x90312) means another leg is required.
        return token, error == 0

    def session_key(self) -> bytes:
        return _query_session_key(self._auth)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_smb_sso.py -k negotiate_client -v`
Expected: PASS

_(No commit — leave changes uncommitted in the working tree for review.)_

---

## Task 4: `smb_login_sspi` — SMB2 SESSION_SETUP loop + key install

Drives the SESSION_SETUP exchange with SSPI tokens, then installs the session/signing keys exactly as `impacket.smb3.SMB3.login` does (mirrors [smb3.py:1083-1141](../../../.venv/Lib/site-packages/impacket/smb3.py)). The unit test exercises control flow with a scripted fake `SMB3`; wire-level correctness is validated by the integration test in Task 7.

**Files:**
- Modify: `src/openhound_sccm/clients/smb_sso.py`
- Test: `tests/test_smb_sso.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smb_sso.py (append)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_smb_sso.py -k smb_login_sspi -v`
Expected: FAIL with `AttributeError: module ... has no attribute 'STATUS_SUCCESS'` (and `smb_login_sspi` undefined)

- [ ] **Step 3: Write minimal implementation**

```python
# src/openhound_sccm/clients/smb_sso.py (add imports at top)
from impacket import crypto
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS
from impacket.smb3structs import (
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
    SMB2_NEGOTIATE_SIGNING_ENABLED,
    SMB2_NEGOTIATE_SIGNING_REQUIRED,
    SMB2_SESSION_SETUP,
    SMB2SessionSetup,
    SMB2SessionSetup_Response,
)
```

```python
# src/openhound_sccm/clients/smb_sso.py (append)
def _install_session_keys(smb3, gss_session_key: bytes) -> None:
    """Install the session key and derive signing/encryption subkeys.

    Mirrors impacket.smb3.SMB3.login's post-handshake derivation so signed (and,
    where required, encrypted) SMB requests work. Reaches into the private
    _Session dict by design (see spec); labels/inputs are fixed by the SMB spec.
    """
    conn = smb3._Connection
    dialect = conn["Dialect"]
    # MS-SMB2 3.2.5.3.1: the SMB session key is the FIRST 16 bytes of the GSS key
    # (zero-padded if shorter). Kerberos AES256 hands back 32 bytes; using all of
    # them produces a wrong signing key -> server returns ACCESS_DENIED. (Validated
    # against ps1-pss; impacket's own kerberosLogin does the same [:16] truncation.)
    session_key = gss_session_key[:16].ljust(16, b"\x00")
    smb3._Session["SessionKey"] = session_key
    if smb3._Session.get("SigningRequired") and dialect >= SMB2_DIALECT_30:
        if dialect == SMB2_DIALECT_311:
            smb3._Session["SigningKey"] = crypto.KDF_CounterMode(
                session_key, b"SMBSigningKey\x00", smb3._Session["PreauthIntegrityHashValue"], 128)
        else:
            smb3._Session["SigningKey"] = crypto.KDF_CounterMode(
                session_key, b"SMB2AESCMAC\x00", b"SmbSign\x00", 128)
        smb3._Session["SigningActivated"] = True
    if dialect >= SMB2_DIALECT_30 and conn.get("SupportsEncryption"):
        if dialect == SMB2_DIALECT_311:
            ph = smb3._Session["PreauthIntegrityHashValue"]
            smb3._Session["ApplicationKey"] = crypto.KDF_CounterMode(session_key, b"SMBAppKey\x00", ph, 128)
            smb3._Session["EncryptionKey"] = crypto.KDF_CounterMode(session_key, b"SMBC2SCipherKey\x00", ph, 128)
            smb3._Session["DecryptionKey"] = crypto.KDF_CounterMode(session_key, b"SMBS2CCipherKey\x00", ph, 128)
        else:
            smb3._Session["ApplicationKey"] = crypto.KDF_CounterMode(session_key, b"SMB2APP\x00", b"SmbRpc\x00", 128)
            smb3._Session["EncryptionKey"] = crypto.KDF_CounterMode(session_key, b"SMB2AESCCM\x00", b"ServerIn \x00", 128)
            smb3._Session["DecryptionKey"] = crypto.KDF_CounterMode(session_key, b"SMB2AESCCM\x00", b"ServerOut\x00", 128)
    smb3._Session["CalculatePreAuthHash"] = False


def smb_login_sspi(smb_connection, target_spn: str) -> None:
    """Authenticate *smb_connection* as the current user via SSPI Negotiate.

    Drives the SMB2 SESSION_SETUP exchange with tokens from one SSPI Negotiate
    context, then installs session/signing keys. Built on impacket's public API
    (getSMBServer / sendSMB / recvSMB / smb3structs); raises on any failure.
    """
    smb3 = smb_connection.getSMBServer()
    client = _SSPINegotiateClient(target_spn)

    smb3._Session["SigningRequired"] = smb3._Connection["RequireSigning"]
    smb3._Session["PreauthIntegrityHashValue"] = smb3._Connection["PreauthIntegrityHashValue"]
    is_311 = smb3._Connection["Dialect"] == SMB2_DIALECT_311
    update_preauth = getattr(smb3, "_SMB3__UpdatePreAuthHash", None)

    session_setup = SMB2SessionSetup()
    session_setup["SecurityMode"] = (
        SMB2_NEGOTIATE_SIGNING_REQUIRED if smb3.RequireMessageSigning
        else SMB2_NEGOTIATE_SIGNING_ENABLED
    )
    session_setup["Flags"] = 0

    token, done = client.step(None)
    while True:
        session_setup["SecurityBufferLength"] = len(token)
        session_setup["Buffer"] = token
        packet = smb3.SMB_PACKET()
        packet["Command"] = SMB2_SESSION_SETUP
        packet["Data"] = session_setup

        # sendSMB folds the outgoing SESSION_SETUP *request* into the 3.1.1 preauth hash.
        ans = smb3.recvSMB(smb3.sendSMB(packet))
        smb3._Session["SessionID"] = ans["SessionID"]
        status = ans["Status"]
        resp = SMB2SessionSetup_Response(ans["Data"])
        server_token = bytes(resp["Buffer"]) if resp["Buffer"] else b""

        if status == STATUS_SUCCESS:
            # MS-SMB2: the final success response is NOT folded into the preauth hash.
            # Kerberos finishes in one leg, so the SSPI context isn't 'done' until we
            # feed back the server's final token (AP-REP); do that before reading the key.
            if not done and server_token:
                token, done = client.step(server_token)
            break
        if status != STATUS_MORE_PROCESSING_REQUIRED:
            ans.isValidAnswer(STATUS_SUCCESS)  # raises the proper impacket SessionError
        # Intermediate response only: fold into the 3.1.1 preauth hash before the next leg.
        if is_311 and update_preauth is not None:
            update_preauth(ans.rawData)
        token, done = client.step(server_token)

    _install_session_keys(smb3, client.session_key())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_smb_sso.py -k smb_login_sspi -v`
Expected: PASS

_(No commit — leave changes uncommitted in the working tree for review.)_

---

## Task 5: `connect_smb` — the auth ladder (core)

**Files:**
- Modify: `src/openhound_sccm/clients/smb_sso.py`
- Test: `tests/test_smb_sso.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smb_sso.py (append)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_smb_sso.py -k connect_smb -v`
Expected: FAIL with `AttributeError: module ... has no attribute 'SMBConnection'` (and `connect_smb` undefined)

- [ ] **Step 3: Write minimal implementation**

```python
# src/openhound_sccm/clients/smb_sso.py (add import at top)
from impacket.smbconnection import SMBConnection
```

```python
# src/openhound_sccm/clients/smb_sso.py (append)
def connect_smb(
    hostname: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
    *,
    timeout: int = 5,
) -> Optional[SMBConnection]:
    """Return an authenticated SMBConnection to *hostname*, or None on failure.

    Auth ladder (no fall-through after the chosen rung is attempted):
      1. complete creds (username AND password) -> explicit NTLM login
      2. else SSPI available                    -> current-user SSPI Negotiate
      3. else                                   -> anonymous null session
    """
    try:
        smb = SMBConnection(hostname, hostname, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - any transport error means unreachable
        logger.verbose("SMB connect to %s failed: %s", hostname, exc)
        return None

    try:
        if username and password:
            d, u = _split_user_domain(username, domain)
            logger.verbose("SMB auth: explicit NTLM as %s\\%s on %s", d, u, hostname)
            smb.login(u, password, d)
        elif _SSPI_NEGOTIATE_AVAILABLE:
            logger.verbose("SMB auth: current Windows user via SSPI Negotiate on %s", hostname)
            smb_login_sspi(smb, _cifs_spn(hostname))
        else:
            logger.verbose("SMB auth: null session on %s (no creds; SSPI unavailable)", hostname)
            smb.login("", "", domain.split(".")[0])
        return smb
    except Exception as exc:  # noqa: BLE001 - auth failure -> host not collectable
        logger.verbose("SMB auth to %s failed: %s", hostname, exc)
        try:
            smb.close()
        except Exception:
            pass
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_smb_sso.py -k connect_smb -v`
Expected: PASS (5 passed)

_(No commit — leave changes uncommitted in the working tree for review.)_

---

## Task 6: Wire the Remote Registry probe to `connect_smb`

Replace the probe's inline `SMBConnection` build + `smb.login(...)` ([registry.py:79-90](../../../src/openhound_sccm/collectors/registry.py)) with one `connect_smb(...)` call, and delete the now-unused `_split_user_domain` (moved to `smb_sso.py` in Task 2).

**Files:**
- Modify: `src/openhound_sccm/collectors/registry.py`
- Test: `tests/test_smb_sso.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_smb_sso.py (append)
from openhound_sccm.collectors import registry


def test_registry_probe_delegates_to_connect_smb(monkeypatch):
    captured = {}

    def _fake_connect(hostname, domain, username, password, **kw):
        captured.update(hostname=hostname, domain=domain, username=username, password=password)
        return object()  # a truthy "connection"

    monkeypatch.setattr(registry, "connect_smb", _fake_connect)
    # Make the TCP/445 reachability probe succeed without real network I/O.
    monkeypatch.setattr(registry.socket, "create_connection", lambda *a, **k: _NoopCtx())
    # Stop after SMB connect by making the winreg bind a no-op failure path.
    monkeypatch.setattr(registry, "HAS_IMPACKET", True)

    probe = registry._RegistryProbe("ps1.mayyhem.com", "mayyhem.com", None, None)
    probe.__enter__()

    assert captured["hostname"] == "ps1.mayyhem.com"
    assert captured["domain"] == "mayyhem.com"


class _NoopCtx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False
```

> Note: the winreg DCE/RPC bind after the SMB connect needs a live host, so this
> test only asserts that `__enter__` routes SMB auth through `connect_smb` with
> the right arguments; full bind behavior is covered by Task 7.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_smb_sso.py -k registry_probe_delegates -v`
Expected: FAIL (`registry` has no attribute `connect_smb`, or `__enter__` still builds SMBConnection directly)

- [ ] **Step 3: Write minimal implementation**

In `src/openhound_sccm/collectors/registry.py`:

Add the import near the existing imports:

```python
from ..clients.smb_sso import connect_smb
```

Delete the `_split_user_domain` function (lines ~30-44) — it now lives in `smb_sso.py`.

Replace the SMB connect/login block inside `_RegistryProbe.__enter__` (the `d, u = _split_user_domain(...)` through `self.smb = smb`) with:

```python
        smb = connect_smb(self.hostname, self.domain, self.username, self.password)
        if smb is None:
            return None
        self.smb = smb
```

(The preceding fast TCP/445 probe and the following winreg DCE/RPC bind are unchanged. The `SMBConnection` import at registry.py top and the `from impacket.smbconnection import SMBConnection` inside `__enter__` become unused — remove both; keep the `rrp, transport` imports used by the bind.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_smb_sso.py -k registry_probe_delegates -v`
Expected: PASS

- [ ] **Step 5: Verify `_split_user_domain` has no remaining references**

Run: `rg -n "_split_user_domain" src/`
Expected: matches only in `src/openhound_sccm/clients/smb_sso.py`

_(No commit — leave changes uncommitted in the working tree for review.)_

---

## Task 7: Live-host integration test (Windows, opt-in)

Proves a real signed SMB session as the current user against `ps1-pss.mayyhem.com`. Skipped unless on Windows with SSPI available **and** the opt-in env var set, so CI/non-domain machines stay green.

**Files:**
- Create: `tests/test_smb_sso_integration.py`

- [ ] **Step 1: Write the test (it is its own verification)**

```python
# tests/test_smb_sso_integration.py
import os

import pytest

from openhound_sccm.clients import smb_sso

TARGET = os.environ.get("OH_SSO_TEST_HOST", "ps1-pss.mayyhem.com")
DOMAIN = os.environ.get("OH_SSO_TEST_DOMAIN", "mayyhem.com")

pytestmark = pytest.mark.skipif(
    not smb_sso._SSPI_NEGOTIATE_AVAILABLE or os.environ.get("OH_SSO_INTEGRATION") != "1",
    reason="Set OH_SSO_INTEGRATION=1 on a domain-joined Windows host to run.",
)


def test_sspi_negotiate_login_and_signed_op():
    """Current-user SSO connects and a signed SMB op (list shares) succeeds."""
    smb = smb_sso.connect_smb(TARGET, DOMAIN, None, None)
    assert smb is not None, "SSPI Negotiate login returned no connection"
    try:
        # A signed tree/IPC op exercises the derived SigningKey end to end.
        shares = smb.listShares()
        assert shares is not None
    finally:
        smb.close()
```

- [ ] **Step 2: Run on the lab host**

Run (in the integrated terminal on the domain-joined box):
```powershell
$env:OH_SSO_INTEGRATION = "1"
$env:UV_PROJECT_ENVIRONMENT = "$env:TEMP\openhound-sccm-venv"
uv run pytest tests/test_smb_sso_integration.py -v
```
Expected: PASS (real Kerberos/NTLM SSO session established; signed op succeeds). If it errors on a private `_Session` field, that is the impacket-internals drift the spec warned about — pin/inspect impacket before proceeding.

- [ ] **Step 3: Verify it skips cleanly elsewhere**

Run (without the env var): `uv run pytest tests/test_smb_sso_integration.py -v`
Expected: SKIPPED (1 skipped)

_(No commit — leave changes uncommitted in the working tree for review.)_

---

## Task 8: Full validation + spec status update

**Files:**
- Modify: `docs/superpowers/specs/2026-06-04-impacket-sspi-smb-sso-design.md`

- [ ] **Step 1: Run the full unit suite + linters (isolated env)**

Run:
```powershell
$env:UV_PROJECT_ENVIRONMENT = "$env:TEMP\openhound-sccm-venv"
uv run pytest
uv run ruff check src/ tests/
uv run mypy src/
```
Expected: pytest all pass (integration test SKIPPED without the opt-in var); ruff clean; mypy clean. Report any check that cannot run and why.

- [ ] **Step 2: Mark the spec implemented**

Change the spec header `Status:` line to `Implemented` and add a one-line pointer to this plan.

_(No commit — leave changes uncommitted in the working tree for review.)_

---

## Self-Review

**Spec coverage:**

| Spec section | Covered by |
|---|---|
| §3.1 `sspi_negotiate_available()` | Task 1 |
| §3.1 `_SSPINegotiateClient` | Task 3 |
| §4 SESSION_SETUP loop / `smb_login_sspi` | Task 4 |
| §5 session key + signing-key derivation | Task 4 (`_install_session_keys`) |
| §3.1 / §3.3 `connect_smb` ladder | Task 5 |
| §2 SSO trigger (incomplete creds → SSO) | Task 5 (`test_connect_smb_no_password_uses_sspi`) |
| §2 give-up-on-failure (no fall-through) | Task 5 (`test_connect_smb_sspi_failure_does_not_fall_through`) |
| §3.2 registry consumer wiring | Task 6 |
| Assumption: `cifs/<host>` SPN | Task 2 (`_cifs_spn`) + Task 5 |
| Assumption: null-session preserved when SSPI absent | Task 5 (`test_connect_smb_no_sspi_falls_back_to_null_session`) |
| §5 3.1.1 pre-auth-hash coupling | Task 4 (`update_preauth`) + Task 7 (live validation) |
| §9 unit + integration + validation commands | Tasks 1-7 (unit), Task 7 (integration), Task 8 (commands) |

**Placeholder scan:** No TBD/TODO; every code step shows complete code; the only deferred item (SESSION_SETUP wire correctness) is explicitly gated by the Task 7 integration test, not left vague.

**Type consistency:** `connect_smb(hostname, domain, username, password, *, timeout)` is consistent across Tasks 5/6/7. `_split_user_domain` returns `(domain, user)` everywhere. `_SSPINegotiateClient.step(server_token) -> (token, done)` and `.session_key()` are used consistently in Tasks 3/4. `_install_session_keys(smb3, session_key)` and `smb_login_sspi(smb_connection, target_spn)` signatures match their call sites.

**Known risk carried forward:** `smb_login_sspi` depends on impacket's private `_Session`/`_Connection` dicts and the name-mangled `_SMB3__UpdatePreAuthHash`. Task 7 is the guard that this still holds for the pinned impacket version.
