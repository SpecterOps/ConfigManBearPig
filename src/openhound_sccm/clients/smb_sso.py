"""Current-user Windows SSO for impacket SMB connections.

Mirrors the LDAP SSO in clients/ad.py: when no complete username+password is
supplied, authenticate to SMB as the logged-in Windows user via SSPI Negotiate
(Kerberos-preferred, NTLM fallback) instead of an anonymous null session.

Built entirely on top of impacket's public API — no impacket source edits.
"""
from __future__ import annotations

import base64
import importlib
import sys
from typing import Optional

from ..log_context import get_logger
from .http_auth import format_hashes  # canonical NT-hash -> "LM:NT" normalizer
from impacket import crypto
from impacket.nt_errors import STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import (
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
    SMB2_NEGOTIATE_SIGNING_ENABLED,
    SMB2_NEGOTIATE_SIGNING_REQUIRED,
    SMB2_SESSION_SETUP,
    SMB2SessionSetup,
    SMB2SessionSetup_Response,
)

logger = get_logger(__name__)


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
    dialect = smb3._Connection["Dialect"]
    is_311 = dialect == SMB2_DIALECT_311
    update_preauth = getattr(smb3, "_SMB3__UpdatePreAuthHash", None)

    session_setup = SMB2SessionSetup()
    session_setup["SecurityMode"] = (
        SMB2_NEGOTIATE_SIGNING_REQUIRED if smb3.RequireMessageSigning else SMB2_NEGOTIATE_SIGNING_ENABLED
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


def _load_ticket(kerberos_ticket: str):
    """Decode a base64 KRB-CRED (.kirbi) into ``(username, TGT, TGS)`` for impacket.

    Mirrors clients/wmi.py: the client principal is read from the ticket so
    pass-the-ticket works even when no ``-u`` was supplied. ``kerberosLogin``
    requests the ``cifs/<host>`` service ticket from this TGT, so TGS is None.
    """
    from impacket.krb5.ccache import CCache

    ccache = CCache()
    ccache.fromKRBCRED(base64.b64decode(kerberos_ticket, validate=True))
    if not ccache.credentials:
        raise ValueError("--ticket contains no usable credentials")
    cred = ccache.credentials[0]
    username = cred["client"].prettyPrint().decode("utf-8", "replace").split("@")[0]
    return username, cred.toTGT(), None


def connect_smb(
    hostname: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
    *,
    nt_hash: Optional[str] = None,
    kerberos_ticket: Optional[str] = None,
    kdc_host: Optional[str] = None,
    timeout: int = 5,
) -> Optional[SMBConnection]:
    """Return an authenticated SMBConnection to *hostname*, or None on failure.

    Auth ladder (explicit creds win; the chosen rung is the only one attempted):
      1. kerberos_ticket    -> pass-the-ticket (kerberosLogin with the TGT)
      2. nt_hash            -> pass-the-hash (NTLM login with the NT hash)
      3. username+password  -> explicit NTLM login
      4. SSPI available     -> current-user SSPI Negotiate
      5. otherwise          -> anonymous null session

    ``nt_hash`` / ``kerberos_ticket`` / ``kdc_host`` mirror the tool's
    ``--nt-hash`` / ``--ticket`` flags and the resolved DC, so SMB honors the same
    credential set as the AdminService / WMI clients (via impacket's
    ``SMBConnection.login`` / ``kerberosLogin``).
    """
    try:
        smb = SMBConnection(hostname, hostname, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - any transport error means unreachable
        logger.verbose("SMB connect to %s failed: %s", hostname, exc)
        return None

    try:
        if kerberos_ticket:
            ticket_user, tgt, tgs = _load_ticket(kerberos_ticket)
            # Pass-the-ticket may carry no -u; impacket still needs a client
            # principal for the AP-REQ, so fall back to the ticket's own cname.
            _, u = _split_user_domain(username or ticket_user, domain)
            lmhash, nthash = (format_hashes(nt_hash) or ":").split(":")
            logger.verbose("SMB auth: pass-the-ticket as %s on %s", u, hostname)
            # doKerberos treats `domain` as the realm -> pass the full DNS domain.
            smb.kerberosLogin(u, password or "", domain, lmhash, nthash, "", kdc_host, TGT=tgt, TGS=tgs)
        elif nt_hash:
            d, u = _split_user_domain(username, domain)
            lmhash, nthash = (format_hashes(nt_hash) or ":").split(":")
            logger.verbose("SMB auth: pass-the-hash as %s\\%s on %s", d, u, hostname)
            smb.login(u, "", d, lmhash, nthash)
        elif username and password:
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
