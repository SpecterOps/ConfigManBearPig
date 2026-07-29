"""Negotiate auth engine for the SCCM HTTP client.

Mints the ``Authorization: Negotiate <base64>`` tokens for the
``WWW-Authenticate: Negotiate`` dance used by the AdminService REST API:

  * **Kerberos** (impacket) from a password, an NT hash (used as the RC4 key),
    or a base64 KRB-CRED (``.kirbi``) ticket — pass-the-ticket.
  * **NTLM** (impacket) from a password or NT hash.
  * **Current-user SSPI** (pywin32) for passwordless Windows single sign-on.

Mirrors the structure of ``clients/smb_sso.py`` (capability gate + per-handshake
client objects). ``choose_auth`` is the pure ladder selector (unit-tested with
no network); the negotiator classes are the live seams, validated end-to-end
against a real AdminService during development.

Each negotiator exposes ``step(server_token) -> (token_bytes, done)``: the
client base64-encodes ``token_bytes`` into the ``Negotiate`` header, and feeds
any server continuation token (NTLM's second leg) back into ``step``.

The explicit-Kerberos AP-REQ deliberately omits ``GSS_C_DCE_STYLE`` from the
GSS checksum flags: http.sys / IIS HTTP Negotiate rejects DCE-style tokens with
a 401 (only RPC-style endpoints such as WinRM accept them). Validated live.
"""
from __future__ import annotations

import enum
import importlib
import sys
from typing import Any, Optional

from ..log_context import get_logger

from impacket.krb5.gssapi import (
    GSS_C_INTEG_FLAG,
    GSS_C_MUTUAL_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
)
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
from impacket.spnego import (
    SPNEGO_NegTokenInit,
    SPNEGO_NegTokenResp,
    TypesMech,
)

# EMPTY_LM_HASH / format_hashes / split_user_domain are byte-identical to the
# shared library's originals (the shared clients/auth.py was generalized from this
# very module). Import them here so this module's callers — http.py, wmi.py and
# smb_sso.py all import format_hashes/split_user_domain from here — transparently
# use the single shared implementation instead of a local copy.
from openhound_collector_common.clients.auth import (  # noqa: F401 (re-exported)
    EMPTY_LM_HASH,
    KerberosToken,
    SspiClient,
    choose_auth,
    format_hashes,
    is_ip,
    split_user_domain,
)

logger = get_logger(__name__)

# GSS checksum flags for the explicit-Kerberos authenticator. Matches impacket's
# getKerberosType1 set MINUS GSS_C_DCE_STYLE (and GSS_C_CONF, unnecessary here):
# http.sys/IIS HTTP Negotiate rejects DCE-style tokens. Validated live against a
# real AdminService (DCE-style -> 401; this set -> accepted).
_GSS_HTTP_FLAGS = GSS_C_INTEG_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG


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


def http_spn(host: str) -> str:
    """The Kerberos service principal name for an HTTP/HTTPS endpoint."""
    return f"HTTP/{host}"


# EMPTY_LM_HASH, format_hashes, split_user_domain, is_ip and choose_auth all come
# from the shared library (imported at the top of this module); the local copies
# were equivalent. choose_auth is the shared credential-precedence ladder used by
# both this HTTP client and the WMI client (clients/wmi.py).


# --- SPNEGO helpers ---------------------------------------------------------


def _spnego_init(mech, mech_token: bytes) -> bytes:
    """Wrap a mechanism token in an SPNEGO NegTokenInit advertising *mech*."""
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [mech]
    blob["MechToken"] = mech_token
    return blob.getData()


def _spnego_resp(mech_token: bytes) -> bytes:
    """Wrap a continuation mechanism token in an SPNEGO NegTokenResp."""
    blob = SPNEGO_NegTokenResp()
    blob["ResponseToken"] = mech_token
    return blob.getData()


def _unwrap_spnego_response(server_token: bytes) -> bytes:
    """Extract the inner mechanism token from a server SPNEGO NegTokenResp."""
    return SPNEGO_NegTokenResp(server_token)["ResponseToken"]


# --- Negotiators ------------------------------------------------------------


class SspiNegotiator:
    """Current-user SSPI Negotiate; thin wrapper over the shared :class:`SspiClient`.

    ``SspiClient.step`` returns ``(out_token, done)`` with ``done == (error == 0)``
    (SEC_E_OK); the caller still inspects the HTTP status for the optional mutual
    leg. Same behavior as before — the pywin32 ``ClientAuth`` handshake now lives
    in the shared library.
    """

    def __init__(self, *, target_host: str) -> None:
        self._client = SspiClient(package="Negotiate", target_spn=http_spn(target_host))

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        return self._client.step(server_token)


class NtlmNegotiator:
    """Two-leg NTLM (type1 -> server challenge -> type3) via impacket, SPNEGO-wrapped."""

    _MECH = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]

    def __init__(self, *, domain: str, username: str, password: Optional[str],
                 nt_hash: Optional[str]) -> None:
        self._domain = domain
        self._username = username
        self._password = password or ""
        self._lm = ""
        self._nt = ""
        hashes = format_hashes(nt_hash)
        if hashes:
            self._lm, self._nt = hashes.split(":")
        self._type1: Any = None  # impacket NTLMSSP type-1 (untyped), set on first step

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        if server_token is None:
            self._type1 = getNTLMSSPType1(domain=self._domain)
            return _spnego_init(self._MECH, self._type1.getData()), False
        challenge = _unwrap_spnego_response(server_token)
        type3, _session_key = getNTLMSSPType3(
            self._type1, challenge, self._username, self._password,
            self._domain, self._lm, self._nt,
        )
        return _spnego_resp(type3.getData()), True


class KerberosNegotiator:
    """One-shot Kerberos AP-REQ over SPNEGO for the HTTP Negotiate handshake.

    Thin wrapper over the shared :class:`KerberosToken`, which mints the AP-REQ
    for ``HTTP/<host>`` from a password / NT hash (fresh TGT+TGS) or a base64
    KRB-CRED ``.kirbi`` ticket (pass-the-ticket), wraps it in an SPNEGO
    NegTokenInit, and caches the KDC exchange after the first call.

    The only HTTP-specific input is the GSS checksum flag set: ``_GSS_HTTP_FLAGS``
    omits ``GSS_C_DCE_STYLE`` (http.sys/IIS reject DCE-style tokens with a 401).
    That flexibility is exactly the ``gss_flags`` seam the shared token exposes.
    """

    def __init__(self, *, target_host: str, realm: str, username: Optional[str],
                 password: Optional[str], nt_hash: Optional[str],
                 ticket: Optional[str], kdc_host: Optional[str]) -> None:
        self._token = KerberosToken(
            spn=http_spn(target_host),
            realm=realm,
            username=username,
            password=password,
            nt_hash=nt_hash,
            ticket=ticket,
            kdc_host=kdc_host,
            gss_flags=_GSS_HTTP_FLAGS,
        )

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        # Kerberos completes in one leg (no server challenge needed); the shared
        # token does the KDC exchange on first call and caches it.
        return self._token.ap_req_spnego(), True
