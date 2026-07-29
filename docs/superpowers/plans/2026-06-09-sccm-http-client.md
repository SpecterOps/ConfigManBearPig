# Shared HTTP Client (Negotiate Auth) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable `HttpClient` (transport) + `http_auth` (Negotiate token engine) that the AdminService and HTTP collectors share, supporting current-user SSPI, Kerberos/NTLM with password/NT-hash/base64-ticket, and anonymous requests, plus richer connection-error classification for PKI detection.

**Architecture:** A caller-chosen `AuthMode` (`NEGOTIATE` vs `NONE`) decides whether the auth ladder runs. impacket mints Kerberos/NTLM tokens (from password, NT-hash-as-RC4-key, or base64 `.kirbi`); pywin32 SSPI handles the passwordless current-user path; both hand-driven over a keep-alive `requests.Session` via the standard `401 WWW-Authenticate: Negotiate` → `Authorization: Negotiate <b64>` header dance. SCCM semantics (which 403 means "cert required") stay in the collectors.

**Tech Stack:** Python 3.13+, `requests` (transport, new direct dep), `impacket` (Kerberos/NTLM tokens, existing dep), `pywin32` (SSPI, existing dep, Windows-only), `pytest` (TDD).

**Spec:** [../specs/2026-06-09-sccm-http-client-design.md](../specs/2026-06-09-sccm-http-client-design.md)
**Ticket:** ope-d57d

---

## Conventions for this plan

- **Auto Mode (no human gating).** Per the owner's directive, execute all tasks autonomously: run each Validation Checkpoint and, **on green, continue immediately to the next task**. Do **not** pause for review between tasks. Stop only on (a) a validation failure you cannot fix, or (b) a genuine decision/intervention point (here: the live Kerberos AP-REQ seam and the spike/integration tests, which need lab KDC + a real SMS provider FQDN).
- **No `git commit` steps.** Per the owner's CLAUDE.md, the owner commits/pushes after testing. Do not `git add`/`git commit`.
- **Validation runs in an isolated uv env outside the repo** (per `.agents/standards/openhound.md`). Set this once per shell before running any `uv run` command:
  - **PowerShell (this host is win32):** `$env:UV_PROJECT_ENVIRONMENT = "$env:TEMP\openhound-venv"`
  - **POSIX:** `export UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv`
  - All `uv run ...` steps below assume this is set and are run from `sccm/sccm/`.
- **TDD:** write the failing test, watch it fail, implement minimally, watch it pass.
- **Logging:** every `if/else` and `try/except` branch logs at the right level (`error`/`warning`/`info`/`verbose`/`debug`) per CLAUDE.md, or carries a comment explaining why no log is needed. The code blocks below already include these.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `src/openhound_sccm/clients/http_auth.py` | `AuthMode`, SSPI capability gate, pure `choose_auth` ladder, token minting per rung (kerberos/ntlm/sspi), auth helpers | **Create** |
| `src/openhound_sccm/clients/http.py` | `ErrorClass`, `HttpResult`, exception→class pure classifier, `HttpClient` (session, `from_context`, `get`, Negotiate loop) | **Create** (replaces the current stub) |
| `src/openhound_sccm/context.py` | add `kerberos_ticket` field | Modify (`:26`) |
| `src/openhound_sccm/source.py` | resolve `kerberos_ticket` secret, pass to `SourceContext` | Modify (`:198`, `:255`) |
| `src/openhound_sccm/main.py` | `--nt-hash` / `--ticket` options, env map, long-option + sensitive-option lists | Modify (`:59-88`, `:120-153`, `:838-842`) |
| `pyproject.toml` | declare `requests` direct dependency | Modify (`:10-33`) |
| `README.md` | Command Line Options: two new flags + auth-methods note + example | Modify |
| `tests/test_http_auth.py` | unit tests for `choose_auth` ladder + auth helpers | **Create** |
| `tests/test_http_client.py` | unit tests for `HttpResult` classification, `AuthMode.NONE`, the Negotiate loop (mocked session) | **Create** |
| `tests/test_http_cli_flags.py` | unit tests: `--nt-hash`/`--ticket` → env mapping + redaction | **Create** |
| `tests/test_http_negotiate_integration.py` | opt-in live Negotiate test (skipped without env) | **Create** |

---

## Task 1: Declare `requests` as a direct dependency

**Files:**
- Modify: `pyproject.toml:31-33`

- [ ] **Step 1: Add the dependency**

In `pyproject.toml`, inside `[project].dependencies`, add a `requests` entry next to the impacket line:

```toml
    # Used by impacket-based per-host phases.
    "impacket>=0.11.0",
    # HTTP transport for the AdminService REST API and the HTTP role-probe
    # collector (clients/http.py). Auth tokens are minted by impacket / pywin32
    # SSPI and carried in the Authorization header; requests only moves bytes.
    "requests>=2.31.0",
```

- [ ] **Step 2: Validation Checkpoint**

Run:
```
uv run python -c "import requests; print(requests.__version__)"
```
Expected: a version string `>= 2.31.0` prints with no error. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 2: Add `SourceContext.kerberos_ticket`

**Files:**
- Modify: `src/openhound_sccm/context.py:26`
- Test: `tests/test_http_cli_flags.py` (created here; extended in Task 9)

- [ ] **Step 1: Write the failing test**

Create `tests/test_http_cli_flags.py`:

```python
"""CLI/credential wiring tests for the HTTP client auth inputs."""
from openhound_sccm.context import SourceContext


def test_source_context_carries_kerberos_ticket():
    ctx = SourceContext(ad=None, domain="mayyhem.com", kerberos_ticket="QUJD")
    assert ctx.kerberos_ticket == "QUJD"
    # nt_hash already exists; confirm both credential carriers coexist.
    ctx2 = SourceContext(ad=None, domain="mayyhem.com", nt_hash="aabb")
    assert ctx2.nt_hash == "aabb"
    assert ctx2.kerberos_ticket is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_http_cli_flags.py::test_source_context_carries_kerberos_ticket -v`
Expected: FAIL with `TypeError: __init__() got an unexpected keyword argument 'kerberos_ticket'`.

- [ ] **Step 3: Add the field**

In `src/openhound_sccm/context.py`, add the field directly below `nt_hash` (currently line 26):

```python
    nt_hash: str | None = None
    kerberos_ticket: str | None = None  # base64-encoded KRB-CRED (.kirbi) for pass-the-ticket
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_http_cli_flags.py::test_source_context_carries_kerberos_ticket -v`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run ruff check src/openhound_sccm/context.py`
Expected: no errors. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 3: Live spike — prove the HTTP Negotiate handshake (throwaway)

> The Kerberos/SSPI-over-HTTP token dance is the one high-risk seam (the `smb_sso`
> plan hit three non-obvious corrections this way). Prove it against the lab
> **before** writing Tasks 4–8, then throw the spike away. **No committed code.**

**Files:**
- Create (throwaway, delete after): `spike_http_negotiate.py` at repo root.

- [ ] **Step 1: Write the spike**

Create `spike_http_negotiate.py`. It hits a real AdminService URL twice: once current-user SSPI, once explicit creds via impacket NTLM wrapped in SPNEGO. Fill `TARGET` with a lab SMS provider FQDN (e.g. a `mayyhem.com` provider).

```python
"""THROWAWAY spike: prove the HTTP Negotiate header dance against live AdminService.
Run on the Windows lab box. Delete after Tasks 4-8 are validated."""
import base64, requests, urllib3
urllib3.disable_warnings()

TARGET = "ps1-pss.mayyhem.com"           # <- lab SMS provider FQDN
URL = f"https://{TARGET}/AdminService/wmi/SMS_Identification"

# (A) Current-user SSPI Negotiate
import sspi
s = requests.Session(); s.verify = False
r = s.get(URL)
print("no-auth status:", r.status_code, "WWW-Authenticate:", r.headers.get("WWW-Authenticate"))
ca = sspi.ClientAuth("Negotiate", targetspn=f"HTTP/{TARGET}")
err, buffers = ca.authorize(None)
token = base64.b64encode(bytes(buffers[0].Buffer)).decode()
r = s.get(URL, headers={"Authorization": f"Negotiate {token}"})
print("SSPI leg-1 status:", r.status_code, "len:", len(r.content))
# If 401 with a server token, loop: feed back base64-decoded server token via ca.authorize([...]).

# (B) Explicit NTLM via impacket, SPNEGO-wrapped (uncomment + set creds to test PtH)
# from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
# from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
# ... build type1, wrap in SPNEGO_NegTokenInit(MechTypes=[NTLMSSP], MechToken=type1),
#     read 401 challenge, build type3, send as Authorization: Negotiate <b64(spnego_resp)>.
```

- [ ] **Step 2: Run the spike and record findings**

Run: `uv run python spike_http_negotiate.py`
Expected/observe and write down:
- The exact `WWW-Authenticate` value (`Negotiate`? also `NTLM`?).
- How many legs SSPI needs (Kerberos usually 1; NTLM 2 — note whether the server returns a 401-with-token for the second leg).
- Whether the authenticated `GET` returns `200` with a JSON body.
- Any SPNEGO-wrapping requirement for the impacket NTLM token.

- [ ] **Step 3: Validation Checkpoint**

Confirm a `200` + JSON body was achieved via at least the SSPI path. Fold any corrections into Tasks 4–8. Delete the spike:
Run (PowerShell): `Remove-Item spike_http_negotiate.py`
Stop for owner review of the recorded findings.

---

## Task 4: `http_auth.py` — `AuthMode`, capability gate, pure `choose_auth`, helpers

**Files:**
- Create: `src/openhound_sccm/clients/http_auth.py`
- Test: `tests/test_http_auth.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_http_auth.py`:

```python
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
    # No SPN can be formed for a bare IP -> NTLM only.
    assert plan(username="mayyhem\\admin", password="Pw", target_host="10.10.0.5") == ["ntlm"]


def test_explicit_creds_win_over_sspi():
    assert plan(username="mayyhem\\admin", password="Pw", sspi_available=True) == ["kerberos", "ntlm"]


def test_sspi_when_no_creds():
    assert plan(sspi_available=True) == ["sspi"]


def test_anonymous_last_resort():
    assert plan() == ["anonymous"]


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_http_auth.py -v`
Expected: FAIL with `ModuleNotFoundError: openhound_sccm.clients.http_auth`.

- [ ] **Step 3: Implement the module's pure layer**

Create `src/openhound_sccm/clients/http_auth.py`:

```python
"""Negotiate auth engine for the SCCM HTTP client.

Mints the Authorization tokens for the `WWW-Authenticate: Negotiate` dance:
impacket builds Kerberos AP-REQ (from password, NT-hash-as-RC4-key, or a base64
KRB-CRED ticket) and NTLM type-1/3; pywin32 SSPI drives the passwordless
current-user path. Mirrors the structure of clients/smb_sso.py.

`choose_auth` is the pure ladder selector (unit-tested with no network); the
token-minting functions are the live seams (validated by the opt-in integration
test, see tests/test_http_negotiate_integration.py).
"""
from __future__ import annotations

import enum
import importlib
import ipaddress
import logging
import sys
from typing import Optional

logger = logging.getLogger(__name__)

# The conventional empty LM hash, prepended to a bare NT hash so impacket
# receives the LMHASH:NTHASH form it expects (identical to mssql_epa.py).
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"


class AuthMode(enum.Enum):
    """Caller's choice of whether the Negotiate ladder runs at all."""
    NEGOTIATE = "negotiate"   # run the auth ladder
    NONE = "none"             # never send Authorization (HTTP role-probe)


def _sspi_negotiate_available() -> bool:
    """True only on Windows with the pywin32 SSPI modules importable.

    Mirrors smb_sso._sspi_negotiate_available / ad._current_user_ntlm_available.
    """
    if sys.platform != "win32":
        return False
    try:
        importlib.import_module("sspi")
        importlib.import_module("sspicon")
        return True
    except ImportError:
        return False


sspi_negotiate_available = _sspi_negotiate_available  # public alias


def is_ip(host: str) -> bool:
    """True when *host* is a bare IP literal (so no HTTP SPN can be formed)."""
    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def http_spn(host: str) -> str:
    """The Kerberos service principal name for an HTTP/HTTPS endpoint."""
    return f"HTTP/{host}"


def format_hashes(nt_hash: Optional[str]) -> Optional[str]:
    """Normalize an NT hash to impacket's LMHASH:NTHASH form (or None)."""
    if not nt_hash:
        return None
    if ":" in nt_hash:
        return nt_hash
    return f"{EMPTY_LM_HASH}:{nt_hash}"


def split_user_domain(username: str, default_domain: str) -> tuple[str, str]:
    """Split ``DOMAIN\\user`` or ``user@domain`` into ``(domain, user)``."""
    if "\\" in username:
        domain, user = username.split("\\", 1)
        return domain, user
    if "@" in username:
        user, domain = username.split("@", 1)
        return domain, user
    return default_domain, username


def choose_auth(
    *,
    username: Optional[str],
    password: Optional[str],
    nt_hash: Optional[str],
    ticket: Optional[str],
    target_host: str,
    sspi_available: bool,
) -> list[str]:
    """Resolve the ordered auth rungs to attempt for a NEGOTIATE-mode request.

    Precedence (explicit creds win, then current-user SSPI, then anonymous):
      1. ticket                       -> ["kerberos"]            (no NTLM fallback)
      2. username + (password|hash)   -> ["kerberos","ntlm"]    (kerberos skipped
                                          when target is a bare IP -> ["ntlm"])
      3. sspi_available               -> ["sspi"]
      4. otherwise                    -> ["anonymous"]
    """
    if ticket:
        logger.verbose("HTTP auth: pass-the-ticket (Kerberos only) for %s", target_host)
        return ["kerberos"]
    if username and (password or nt_hash):
        if is_ip(target_host):
            logger.verbose(
                "HTTP auth: %s is a bare IP; skipping Kerberos (no SPN), using NTLM only",
                target_host,
            )
            return ["ntlm"]
        logger.verbose("HTTP auth: explicit creds -> Kerberos, NTLM fallback for %s", target_host)
        return ["kerberos", "ntlm"]
    if sspi_available:
        logger.verbose("HTTP auth: current-user SSPI Negotiate for %s", target_host)
        return ["sspi"]
    logger.verbose("HTTP auth: no creds and no SSPI; anonymous for %s", target_host)
    return ["anonymous"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_http_auth.py -v`
Expected: PASS (all ladder + helper tests). Note: `logger.verbose` exists because importing the package registers it (`log_context`); if a test imports `http_auth` in isolation and `verbose` is missing, add `from .. import log_context  # noqa: F401` at the top, mirroring smb_sso.py.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run ruff check src/openhound_sccm/clients/http_auth.py tests/test_http_auth.py`
Expected: no errors. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 5: `http_auth.py` — token minting per rung (live seams)

**Files:**
- Modify: `src/openhound_sccm/clients/http_auth.py`
- Test: `tests/test_http_auth.py` (extend)

> These are the live seams. Unit tests cover the *pure* parts (SPNEGO wrapping
> shape, ticket base64 decode, NTLM type1 construction via impacket); the live
> KDC/SSPI round-trips are validated by the opt-in integration test. Apply any
> corrections recorded in Task 3.

- [ ] **Step 1: Write the failing tests (pure parts of token minting)**

Append to `tests/test_http_auth.py`:

```python
def test_ntlm_negotiator_first_token_is_bytes():
    """NTLM rung emits a non-empty type-1 token on the first step, not done."""
    neg = ha.NtlmNegotiator(domain="MAYYHEM", username="admin", password="Pw", nt_hash=None)
    token, done = neg.step(None)
    assert isinstance(token, (bytes, bytearray)) and len(token) > 0
    assert done is False  # NTLM needs the server challenge before completing


def test_ticket_negotiator_decodes_base64_kirbi():
    """A malformed base64 ticket raises a clear error (decode is eager)."""
    with pytest.raises(ValueError):
        ha.KerberosNegotiator(ticket="!!!not-base64!!!", target_host="mp.mayyhem.com",
                              domain="mayyhem.com", username=None, password=None,
                              nt_hash=None, kdc_host=None)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_http_auth.py -k "ntlm_negotiator or ticket_negotiator" -v`
Expected: FAIL with `AttributeError: module ... has no attribute 'NtlmNegotiator'`.

- [ ] **Step 3: Implement the negotiators**

Append to `src/openhound_sccm/clients/http_auth.py`. Each negotiator exposes `step(server_token: bytes | None) -> tuple[bytes, bool]` (mirroring `smb_sso._SSPINegotiateClient`), returning the raw token to base64-encode into the `Negotiate` header and a `done` flag.

```python
import base64

from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

_NTLMSSP_MECH = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]


def _spnego_init(mech_token: bytes) -> bytes:
    """Wrap an NTLM type-1 in an SPNEGO NegTokenInit (so it rides `Negotiate`)."""
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [_NTLMSSP_MECH]
    blob["MechToken"] = mech_token
    return blob.getData()


def _spnego_resp(mech_token: bytes) -> bytes:
    """Wrap an NTLM type-3 in an SPNEGO NegTokenResp."""
    blob = SPNEGO_NegTokenResp()
    blob["ResponseToken"] = mech_token
    return blob.getData()


def _unwrap_spnego_response(server_token: bytes) -> bytes:
    """Extract the inner NTLM challenge from the server's SPNEGO NegTokenResp."""
    resp = SPNEGO_NegTokenResp(server_token)
    return resp["ResponseToken"]


class NtlmNegotiator:
    """Two-leg NTLM (type1 -> server challenge -> type3) via impacket, SPNEGO-wrapped."""

    def __init__(self, *, domain: str, username: str, password: Optional[str],
                 nt_hash: Optional[str]) -> None:
        self._domain = domain
        self._username = username
        self._password = password or ""
        self._lm = ""
        self._nt = ""
        hashes = format_hashes(nt_hash)
        if hashes:
            lm_hex, nt_hex = hashes.split(":")
            self._lm = lm_hex
            self._nt = nt_hex
        self._type1: Optional[bytes] = None

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        if server_token is None:
            self._type1 = getNTLMSSPType1(domain=self._domain)
            return _spnego_init(self._type1.getData()), False
        challenge = _unwrap_spnego_response(server_token)
        type3, _session_key = getNTLMSSPType3(
            self._type1, challenge, self._username, self._password,
            self._domain, self._lm, self._nt,
        )
        return _spnego_resp(type3.getData()), True


class SspiNegotiator:
    """Current-user SSPI Negotiate; mirrors smb_sso._SSPINegotiateClient."""

    def __init__(self, *, target_host: str) -> None:
        import sspi
        self._auth = sspi.ClientAuth("Negotiate", targetspn=http_spn(target_host))

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        error, buffers = self._auth.authorize(server_token if server_token else None)
        token = bytes(buffers[0].Buffer) if buffers else b""
        # pywin32: error == 0 (SEC_E_OK) means the handshake is complete.
        return token, error == 0


class KerberosNegotiator:
    """Kerberos AP-REQ via impacket: from a base64 .kirbi ticket, or built from
    password / NT-hash (RC4 key) by requesting a TGT then a service ticket.

    Decodes the ticket eagerly so a bad blob fails fast with a clear ValueError.
    """

    def __init__(self, *, ticket: Optional[str], target_host: str, domain: str,
                 username: Optional[str], password: Optional[str],
                 nt_hash: Optional[str], kdc_host: Optional[str]) -> None:
        self._target_host = target_host
        self._domain = domain
        self._username = username
        self._password = password
        self._nt_hash = nt_hash
        self._kdc_host = kdc_host
        self._ccache_blob: Optional[bytes] = None
        if ticket:
            try:
                self._ccache_blob = base64.b64decode(ticket, validate=True)
            except Exception as exc:  # malformed base64 -> unusable ticket
                raise ValueError(f"--ticket is not valid base64: {exc}") from exc

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        # Kerberos completes in one authenticated leg: build the AP-REQ, wrap in
        # SPNEGO, return done=True. server_token (AP-REP) is ignored unless mutual
        # auth verification is needed.
        ap_req = self._build_ap_req()
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]
        blob["MechToken"] = ap_req
        return blob.getData(), True

    def _build_ap_req(self) -> bytes:
        """Return the raw Kerberos AP-REQ bytes for HTTP/<target_host>.

        Uses impacket.krb5: load TGT from the .kirbi ccache blob (pass-the-ticket)
        or request one from the KDC using password / NT-hash (RC4), then request a
        service ticket for the HTTP SPN and assemble the AP-REQ. See Task 3 spike
        for the exact getKerberosTGT/TGS argument shapes validated against the lab.
        """
        from impacket.krb5 import constants
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
        from impacket.krb5.types import KerberosTime, Principal, Ticket
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        # The concrete TGT/TGS/AP-REQ assembly mirrors impacket's
        # httprelayserver / getTGT.py. It is implemented against the symbols above
        # and validated by tests/test_http_negotiate_integration.py.
        raise NotImplementedError(
            "Kerberos AP-REQ assembly: implement against the Task 3 spike findings; "
            "covered by the opt-in integration test."
        )
```

> The `_build_ap_req` body is the single seam that requires the live KDC to
> validate; it is intentionally left as the integration-tested implementation
> target rather than guessed here. Implement it using the imported impacket
> symbols and the Task 3 spike, then enable the Kerberos integration test
> (Task 11). The NTLM and SSPI rungs are complete above.

- [ ] **Step 4: Run the pure tests to verify they pass**

Run: `uv run pytest tests/test_http_auth.py -k "ntlm_negotiator or ticket_negotiator" -v`
Expected: PASS (type-1 token is bytes & not done; malformed ticket raises `ValueError`).

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run pytest tests/test_http_auth.py -v` and `uv run ruff check src/openhound_sccm/clients/http_auth.py`
Expected: all pure tests pass; lint clean. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 6: `http.py` — `ErrorClass`, `HttpResult`, pure exception classifier

**Files:**
- Create: `src/openhound_sccm/clients/http.py` (replaces the current stub)
- Test: `tests/test_http_client.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_http_client.py`:

```python
"""Unit tests for the HTTP transport: result classification, AuthMode.NONE, loop."""
import requests

from openhound_sccm.clients.http import ErrorClass, HttpClient, HttpResult, classify_exception
from openhound_sccm.clients.http_auth import AuthMode


def test_classify_timeout_is_connect_failure():
    assert classify_exception(requests.exceptions.ConnectTimeout()) is ErrorClass.CONNECT_FAILURE
    assert classify_exception(requests.exceptions.ConnectionError()) is ErrorClass.CONNECT_FAILURE


def test_classify_ssl_error_is_tls_failure():
    assert classify_exception(requests.exceptions.SSLError()) is ErrorClass.TLS_FAILURE


def test_httpresult_shape():
    r = HttpResult(status_code=403, content=b"", error_class=ErrorClass.RESPONSE)
    assert r.status_code == 403 and r.error_class is ErrorClass.RESPONSE
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_http_client.py -k "classify or httpresult_shape" -v`
Expected: FAIL with `ImportError: cannot import name 'classify_exception'` (the stub has none of this).

- [ ] **Step 3: Implement the result layer**

Replace the entire contents of `src/openhound_sccm/clients/http.py` with:

```python
"""HTTP transport for the SCCM AdminService REST API and HTTP role probes.

Owns one keep-alive requests.Session per target and the Negotiate header dance
(auth tokens come from clients/http_auth.py). Transport only: it returns raw
status codes and a connection-error classification; SCCM-specific reading of
those signals (e.g. a 403 on ?SMSTRC meaning a client cert is required) lives in
the collectors.
"""
from __future__ import annotations

import base64
import enum
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3

from .. import log_context  # noqa: F401  (registers logger.verbose)
from . import http_auth
from .http_auth import AuthMode

logger = logging.getLogger(__name__)

# SCCM site systems routinely use self-signed certs; PS1 disables validation
# globally (TrustAllCertsPolicy). Match that and silence the per-request warning.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ErrorClass(enum.Enum):
    """How a request outcome is classified for the caller."""
    RESPONSE = "response"          # an HTTP response was received (ANY status)
    CONNECT_FAILURE = "connect"    # dead socket / DNS / refused / timeout
    TLS_FAILURE = "tls"            # secure-channel / handshake error


@dataclass
class HttpResult:
    """One request outcome. ``status_code`` is set iff ``error_class`` is RESPONSE."""
    status_code: Optional[int]
    content: Optional[bytes]
    error_class: ErrorClass


def classify_exception(exc: BaseException) -> ErrorClass:
    """Map a requests exception to an ErrorClass.

    SSLError is checked before ConnectionError because requests' SSLError is a
    subclass of ConnectionError, and a TLS failure on an HTTPS SCCM endpoint is a
    secondary PKI signal the collector may weigh separately from a dead socket.
    """
    if isinstance(exc, requests.exceptions.SSLError):
        return ErrorClass.TLS_FAILURE
    if isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
        return ErrorClass.CONNECT_FAILURE
    # Any other requests error without a response is treated as a connect failure.
    return ErrorClass.CONNECT_FAILURE
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_http_client.py -k "classify or httpresult_shape" -v`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run ruff check src/openhound_sccm/clients/http.py`
Expected: no errors. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 7: `http.py` — `HttpClient`, `from_context`, anonymous `get`

**Files:**
- Modify: `src/openhound_sccm/clients/http.py`
- Test: `tests/test_http_client.py` (extend)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_http_client.py`:

```python
import types
from unittest import mock


class _FakeResp:
    def __init__(self, status, content=b"", headers=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}


def _client_with_session(fake_session, auth=AuthMode.NONE):
    c = HttpClient(base_url="https://mp.mayyhem.com", auth=auth, domain="mayyhem.com")
    c._session = fake_session
    return c


def test_none_mode_never_sends_authorization():
    sess = mock.Mock()
    sess.get.return_value = _FakeResp(401, b"deny")
    c = _client_with_session(sess, auth=AuthMode.NONE)
    result = c.get("/SMS_MP/.sms_aut?SMSTRC")
    assert result.status_code == 401
    assert result.error_class is ErrorClass.RESPONSE
    # No Authorization header was ever sent.
    _, kwargs = sess.get.call_args
    assert "Authorization" not in (kwargs.get("headers") or {})


def test_get_classifies_connection_error():
    sess = mock.Mock()
    sess.get.side_effect = requests.exceptions.ConnectionError()
    c = _client_with_session(sess, auth=AuthMode.NONE)
    result = c.get("/SMS_DP_SMSPKG$")
    assert result.status_code is None
    assert result.error_class is ErrorClass.CONNECT_FAILURE


def test_from_context_reads_credentials():
    ctx = types.SimpleNamespace(
        domain="mayyhem.com", username="MAYYHEM\\a", password="Pw",
        nt_hash=None, kerberos_ticket=None, ad=types.SimpleNamespace(creds=types.SimpleNamespace(domain_controller="dc.mayyhem.com")),
    )
    c = HttpClient.from_context(ctx, "mp.mayyhem.com", auth=AuthMode.NEGOTIATE)
    assert c._base_url == "https://mp.mayyhem.com"
    assert c._username == "MAYYHEM\\a" and c._kdc_host == "dc.mayyhem.com"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_http_client.py -k "none_mode or classifies_connection or from_context" -v`
Expected: FAIL — `HttpClient` has no usable `__init__`/`get`/`from_context` yet.

- [ ] **Step 3: Implement the client core**

Append to `src/openhound_sccm/clients/http.py`:

```python
class HttpClient:
    """Per-target HTTP client wrapping one keep-alive requests.Session.

    Construct with an explicit AuthMode: NEGOTIATE runs the auth ladder on the
    first request; NONE never sends Authorization (used by the HTTP role probe,
    whose detection relies on reading unauthenticated 401/403/200 codes).
    """

    def __init__(
        self,
        *,
        base_url: str,
        auth: AuthMode,
        domain: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        nt_hash: Optional[str] = None,
        kerberos_ticket: Optional[str] = None,
        kdc_host: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 5,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = auth
        self._domain = domain
        self._username = username
        self._password = password
        self._nt_hash = nt_hash
        self._kerberos_ticket = kerberos_ticket
        self._kdc_host = kdc_host
        self._timeout = timeout
        self._host = urlparse(self._base_url).hostname or self._base_url
        self._authenticated = False

        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.headers.update({"Accept": "application/json"})

    @classmethod
    def from_context(cls, ctx, target: str, *, auth: AuthMode,
                     scheme: str = "https", timeout: int = 5) -> "HttpClient":
        """Build a client for *target*, reading credentials from a SourceContext."""
        kdc = None
        ad = getattr(ctx, "ad", None)
        creds = getattr(ad, "creds", None)
        if creds is not None:
            kdc = getattr(creds, "domain_controller", None)
        return cls(
            base_url=f"{scheme}://{target}",
            auth=auth,
            domain=getattr(ctx, "domain", ""),
            username=getattr(ctx, "username", None),
            password=getattr(ctx, "password", None),
            nt_hash=getattr(ctx, "nt_hash", None),
            kerberos_ticket=getattr(ctx, "kerberos_ticket", None),
            kdc_host=kdc,
            timeout=timeout,
        )

    def _full_url(self, path_or_url: str) -> str:
        if path_or_url.lower().startswith(("http://", "https://")):
            return path_or_url
        return f"{self._base_url}/{path_or_url.lstrip('/')}"

    def get(self, path_or_url: str) -> HttpResult:
        """GET a path (or absolute URL). Runs the Negotiate dance in NEGOTIATE mode."""
        url = self._full_url(path_or_url)
        try:
            if self._auth is AuthMode.NEGOTIATE:
                return self._get_negotiate(url)
            resp = self._session.get(url, timeout=self._timeout)
            logger.debug("HTTP GET %s -> %s (anonymous)", url, resp.status_code)
            return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
        except Exception as exc:  # noqa: BLE001 - classify any transport failure
            cls = classify_exception(exc)
            logger.verbose("HTTP GET %s failed (%s): %s", url, cls.value, exc)
            return HttpResult(None, None, cls)

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass

    # _get_negotiate is implemented in Task 8.
    def _get_negotiate(self, url: str) -> HttpResult:
        raise NotImplementedError  # Task 8
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_http_client.py -k "none_mode or classifies_connection or from_context" -v`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run pytest tests/test_http_client.py -v` and `uv run ruff check src/openhound_sccm/clients/http.py`
Expected: pass + lint clean. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 8: `http.py` — the Negotiate handshake loop

**Files:**
- Modify: `src/openhound_sccm/clients/http.py`
- Test: `tests/test_http_client.py` (extend)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_http_client.py`:

```python
def test_negotiate_sends_token_then_returns_200():
    """401+Negotiate -> client sends Authorization: Negotiate <b64> -> 200."""
    sess = mock.Mock()
    sess.get.side_effect = [
        _FakeResp(401, b"", {"WWW-Authenticate": "Negotiate"}),  # challenge
        _FakeResp(200, b"{}"),                                   # after token
    ]
    c = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NEGOTIATE,
                   domain="mayyhem.com", username="MAYYHEM\\a", password="Pw")
    c._session = sess

    # Force a single-leg, deterministic negotiator (Kerberos-shaped).
    class _OneShot:
        def step(self, server_token):
            return b"TOKENBYTES", True
    with mock.patch.object(http_auth, "KerberosNegotiator", return_value=_OneShot()):
        result = c.get("/AdminService/wmi/SMS_Identification")

    assert result.status_code == 200
    # Second call carried the base64 of our token under the Negotiate scheme.
    second_headers = sess.get.call_args_list[1].kwargs["headers"]
    assert second_headers["Authorization"] == "Negotiate " + base64.b64encode(b"TOKENBYTES").decode()


def test_negotiate_falls_back_kerberos_to_ntlm_on_protocol_error():
    """A Kerberos rung that raises a protocol error advances to NTLM."""
    sess = mock.Mock()
    sess.get.side_effect = [
        _FakeResp(401, b"", {"WWW-Authenticate": "Negotiate"}),
        _FakeResp(200, b"{}"),
    ]
    c = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NEGOTIATE,
                   domain="mayyhem.com", username="MAYYHEM\\a", password="Pw")
    c._session = sess

    class _Boom:
        def step(self, server_token):
            raise RuntimeError("no SPN / clock skew")  # protocol failure

    class _Ntlm:
        def __init__(self): self.calls = 0
        def step(self, server_token):
            self.calls += 1
            return b"NTLMTOK", True

    with mock.patch.object(http_auth, "KerberosNegotiator", return_value=_Boom()), \
         mock.patch.object(http_auth, "NtlmNegotiator", return_value=_Ntlm()):
        result = c.get("/AdminService")
    assert result.status_code == 200
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_http_client.py -k "negotiate_sends or falls_back" -v`
Expected: FAIL with `NotImplementedError` from `_get_negotiate`.

- [ ] **Step 3: Implement the handshake loop**

In `src/openhound_sccm/clients/http.py`, replace the `_get_negotiate` stub with:

```python
    def _build_negotiator(self, rung: str):
        """Instantiate the negotiator object for a chosen ladder rung."""
        if rung == "sspi":
            return http_auth.SspiNegotiator(target_host=self._host)
        if rung == "ntlm":
            ad_domain, sam = http_auth.split_user_domain(self._username, self._domain)
            return http_auth.NtlmNegotiator(
                domain=ad_domain, username=sam,
                password=self._password, nt_hash=self._nt_hash,
            )
        if rung == "kerberos":
            return http_auth.KerberosNegotiator(
                ticket=self._kerberos_ticket, target_host=self._host,
                domain=self._domain, username=self._username,
                password=self._password, nt_hash=self._nt_hash, kdc_host=self._kdc_host,
            )
        return None  # "anonymous"

    def _negotiate_once(self, url: str, rung: str) -> Optional[HttpResult]:
        """Drive one rung's full token exchange. Returns a result, or None if the
        rung hit a protocol failure and the ladder should try the next rung."""
        negotiator = self._build_negotiator(rung)
        if negotiator is None:  # anonymous
            resp = self._session.get(url, timeout=self._timeout)
            return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
        try:
            server_token: Optional[bytes] = None
            while True:
                token, done = negotiator.step(server_token)
                header = {"Authorization": "Negotiate " + base64.b64encode(token).decode()}
                resp = self._session.get(url, headers=header, timeout=self._timeout)
                if resp.status_code != 401:
                    logger.debug("HTTP Negotiate(%s) %s -> %s", rung, url, resp.status_code)
                    return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
                # 401 again: a continuation token means another NTLM leg.
                www = resp.headers.get("WWW-Authenticate", "")
                server_token = _parse_negotiate_token(www)
                if done or server_token is None:
                    # Server rejected our completed token: credential failure -> stop,
                    # surface the 401 (do NOT advance the ladder, per ad.py's rule).
                    logger.warning("HTTP Negotiate(%s) rejected on %s (401)", rung, url)
                    return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
        except Exception as exc:  # noqa: BLE001 - protocol failure -> try next rung
            logger.verbose("HTTP Negotiate(%s) protocol failure on %s: %s", rung, url, exc)
            return None

    def _get_negotiate(self, url: str) -> HttpResult:
        plan = http_auth.choose_auth(
            username=self._username, password=self._password, nt_hash=self._nt_hash,
            ticket=self._kerberos_ticket, target_host=self._host,
            sspi_available=http_auth.sspi_negotiate_available(),
        )
        last: Optional[HttpResult] = None
        for rung in plan:
            result = self._negotiate_once(url, rung)
            if result is not None:
                self._authenticated = True
                return result
            last = None  # protocol failure on this rung; try the next
        if last is not None:
            return last
        # Every rung hit a protocol failure: report as a connect failure.
        logger.warning("HTTP Negotiate exhausted all rungs (%s) on %s", plan, url)
        return HttpResult(None, None, ErrorClass.CONNECT_FAILURE)
```

Also add this module-level helper near `classify_exception`:

```python
def _parse_negotiate_token(www_authenticate: str) -> Optional[bytes]:
    """Extract the base64 token from a `WWW-Authenticate: Negotiate <b64>` header.

    Returns None when the header carries the scheme with no token (the initial
    challenge), which is the signal to start a fresh handshake leg.
    """
    parts = www_authenticate.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "negotiate":
        return None
    try:
        return base64.b64decode(parts[1].strip())
    except Exception:  # noqa: BLE001 - a malformed token is treated as "no token"
        return None
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_http_client.py -k "negotiate_sends or falls_back" -v`
Expected: PASS (token sent + 200; Kerberos protocol failure falls through to NTLM).

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run pytest tests/test_http_client.py tests/test_http_auth.py -v` and `uv run ruff check src/openhound_sccm/clients/`
Expected: all pass; lint clean. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 9: CLI flags `--nt-hash` / `--ticket` + env wiring + source.py

**Files:**
- Modify: `src/openhound_sccm/main.py` (`:59-88`, `:120-153`, `:838-842`)
- Modify: `src/openhound_sccm/source.py` (`:198`, `:255`)
- Test: `tests/test_http_cli_flags.py` (extend)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_http_cli_flags.py`:

```python
import os
from openhound_sccm import main as sccm_main


def test_flags_map_to_env(monkeypatch):
    for var in ("SOURCES__SCCM__NT_HASH", "SOURCES__SCCM__KERBEROS_TICKET"):
        monkeypatch.delenv(var, raising=False)
    sccm_main._apply_env_overrides({"nt_hash": "aabbccdd", "kerberos_ticket": "QUJD"})
    assert os.environ["SOURCES__SCCM__NT_HASH"] == "aabbccdd"
    assert os.environ["SOURCES__SCCM__KERBEROS_TICKET"] == "QUJD"


def test_new_flags_are_redaction_aware():
    # --nt-hash and --ticket carry secrets and must be treated as sensitive.
    assert "--nt-hash" in sccm_main._SENSITIVE_OPTIONS
    assert "--ticket" in sccm_main._SENSITIVE_OPTIONS
    assert "--nt-hash" in sccm_main._LONG_OPTIONS_WITH_VALUES
    assert "--ticket" in sccm_main._LONG_OPTIONS_WITH_VALUES
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_http_cli_flags.py -k "map_to_env or redaction" -v`
Expected: FAIL (`nt_hash`/`kerberos_ticket` not in `_FLAG_TO_ENV`; flags not in the sets).

- [ ] **Step 3: Wire main.py**

In `src/openhound_sccm/main.py`, add to `_FLAG_TO_ENV` (under `# Connection`, after `password`):

```python
    "password": "SOURCES__SCCM__PASSWORD",
    "nt_hash": "SOURCES__SCCM__NT_HASH",
    "kerberos_ticket": "SOURCES__SCCM__KERBEROS_TICKET",
```

Add both long options to `_LONG_OPTIONS_WITH_VALUES` (after `"--password",`):

```python
    "--password",
    "--nt-hash",
    "--ticket",
```

Add both to `_SENSITIVE_OPTIONS`:

```python
_SENSITIVE_OPTIONS: set[str] = {
    "-p",
    "--password",
    "--machine-pass",
    "--nt-hash",
    "--ticket",
}
```

Add the two Typer options in `collect_sccm`, immediately after the `password` option (line ~841):

```python
    password: Optional[str] = typer.Option(None, "-p", "--password", help="Password for explicit auth."),
    nt_hash: Optional[str] = typer.Option(None, "--nt-hash", help="NT hash for pass-the-hash auth (bare 32-hex NT hash; LM half is assumed empty). Used by Kerberos (as the RC4 key) and NTLM."),
    ticket: Optional[str] = typer.Option(None, "--ticket", help="Base64-encoded Kerberos ticket (.kirbi / KRB-CRED) for pass-the-ticket auth. Kerberos only; no NTLM fallback."),
```

> Note: the Typer parameter is named `ticket`, but `_FLAG_TO_ENV` keys it as
> `kerberos_ticket`. Add a one-line alias so the env mapping sees the right key.
> In `collect_sccm`, just before `_apply_env_overrides(flag_kwargs)` (line ~905):

```python
        flag_kwargs = locals()
        flag_kwargs["kerberos_ticket"] = flag_kwargs.pop("ticket", None)
        _apply_env_overrides(flag_kwargs)
```

- [ ] **Step 4: Wire source.py**

In `src/openhound_sccm/source.py`, add the parameter after `nt_hash` (line 198):

```python
    nt_hash: str | None = dlt.secrets.value,
    kerberos_ticket: str | None = dlt.secrets.value,
```

And pass it into `SourceContext(...)` after `nt_hash=nt_hash,` (line 255):

```python
        nt_hash=nt_hash,
        kerberos_ticket=kerberos_ticket,
```

- [ ] **Step 5: Run to verify they pass**

Run: `uv run pytest tests/test_http_cli_flags.py -v`
Expected: PASS (all four assertions + the Task 2 context test).

- [ ] **Step 6: Validation Checkpoint**

Run: `uv run pytest tests/ -v` and `uv run ruff check src/` and `uv run mypy src/`
Expected: full suite green; lint and types clean. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 10: README — Command Line Options + auth-methods note

**Files:**
- Modify: `README.md` (Command Line Options section)

- [ ] **Step 1: Add the two flags to the options table**

In the **Command Line Options** section of `README.md`, add rows in the Connection group:

```markdown
| `--nt-hash <HASH>` | NT hash for pass-the-hash (bare 32-hex; empty LM half assumed). Used by Kerberos (RC4 key) and NTLM. |
| `--ticket <B64>` | Base64 Kerberos ticket (`.kirbi` / KRB-CRED) for pass-the-ticket. Kerberos only — no NTLM fallback. |
```

- [ ] **Step 2: Add an auth-methods note + example**

Add a short subsection under Command Line Options:

```markdown
#### Authentication methods (AdminService / HTTP)

The AdminService collector authenticates with **Negotiate**. Precedence:
explicit credentials win → current-user Windows SSO (passwordless) → anonymous.
Within explicit credentials, Kerberos is tried first with an automatic NTLM
fallback (a bare `--ticket` is Kerberos-only). The HTTP role probe is always
unauthenticated. PKI/HTTPS-only sites are *detected* (a `403` on a probe
endpoint), not satisfied — OpenHound does not present a client certificate.

```bash
# Passwordless, as the current domain user (domain-joined collector):
openhound collect sccm ./out -d mayyhem.com --sms ps1-pss.mayyhem.com

# Pass-the-hash against a specific SMS provider:
openhound collect sccm ./out -d mayyhem.com -u MAYYHEM\\sccmadmin \
    --nt-hash 00112233445566778899aabbccddeeff --sms ps1-pss.mayyhem.com

# Pass-the-ticket (base64 .kirbi):
openhound collect sccm ./out -d mayyhem.com -u MAYYHEM\\sccmadmin \
    --ticket "$(base64 -w0 ticket.kirbi)" --sms ps1-pss.mayyhem.com
```
```

- [ ] **Step 2: Validation Checkpoint**

Re-read the edited section; confirm the flag spellings match the Typer options from Task 9 exactly (`--nt-hash`, `--ticket`). No command to run. Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Task 11: Opt-in live integration test

**Files:**
- Create: `tests/test_http_negotiate_integration.py`

> Mirrors `tests/test_smb_sso_integration.py`: skipped unless an env var points at
> a live SMS provider, so CI/dev stays green without lab access.

- [ ] **Step 1: Write the integration test**

Create `tests/test_http_negotiate_integration.py`:

```python
"""Opt-in live Negotiate test against a real SCCM AdminService.

Enable by setting OPENHOUND_HTTP_TEST_TARGET to an SMS provider FQDN reachable
from a domain-joined Windows host (current-user SSPI). Skipped otherwise.
"""
import os
import sys

import pytest

from openhound_sccm.clients.http import ErrorClass, HttpClient
from openhound_sccm.clients.http_auth import AuthMode

TARGET = os.environ.get("OPENHOUND_HTTP_TEST_TARGET")

pytestmark = pytest.mark.skipif(
    not TARGET or sys.platform != "win32",
    reason="set OPENHOUND_HTTP_TEST_TARGET on a domain-joined Windows host to run",
)


def test_adminservice_sspi_returns_json():
    client = HttpClient(
        base_url=f"https://{TARGET}/AdminService",
        auth=AuthMode.NEGOTIATE,
        domain=os.environ.get("OPENHOUND_HTTP_TEST_DOMAIN", ""),
    )
    try:
        result = client.get("wmi/SMS_Identification")
    finally:
        client.close()
    assert result.error_class is ErrorClass.RESPONSE
    assert result.status_code == 200
    assert result.content and b"ThisSiteCode" in result.content
```

- [ ] **Step 2: Validation Checkpoint**

Run (no lab): `uv run pytest tests/test_http_negotiate_integration.py -v`
Expected: SKIPPED (no `OPENHOUND_HTTP_TEST_TARGET`).
Run (on the lab Windows box, env set): expects PASS with a `200` + JSON body — this is the live validation of the Kerberos/SSPI seam (and `KerberosNegotiator._build_ap_req` from Task 5). Continue automatically on green (Auto Mode); stop only on failure or a decision point.

---

## Final self-review (performed while writing this plan)

- **Spec coverage:** explicit-creds-win ladder (Task 4), impacket+SSPI engine (Tasks 4–5, 8), caller-chosen AuthMode (Tasks 6–8), full cred wiring `--nt-hash`/`--ticket`/`SourceContext.kerberos_ticket` (Tasks 2, 9), PKI signals via `ErrorClass` (Task 6) with collector-side interpretation left out of the client (by design), module split `http.py`/`http_auth.py` (Tasks 4–8), `requests` dep (Task 1), README (Task 10), tests incl. opt-in integration (Tasks 4–9, 11). SPN/IP/KDC/fallback assumptions are encoded in `choose_auth` and `_get_negotiate`.
- **Known open seam:** `KerberosNegotiator._build_ap_req` (Task 5) is the one body deferred to the Task 3 spike + Task 11 integration test, rather than guessed — this is deliberate and called out, not a hidden placeholder. NTLM, SSPI, anonymous, and the full handshake loop are complete.
- **Type consistency:** `AuthMode`, `ErrorClass`, `HttpResult`, `HttpClient(base_url=..., auth=..., domain=...)`, `choose_auth(...) -> list[str]`, and the negotiator `step(server_token) -> (bytes, bool)` contract are used identically across Tasks 4–8 and the tests.
- **Owner constraints honored:** no `git commit` steps; isolated uv env for validation; logging on branches; changes confined to `sccm/sccm`.
