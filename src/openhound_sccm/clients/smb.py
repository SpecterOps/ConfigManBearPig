"""SMB signing-requirement probe and SCCM share enumeration.

Two SMB collection helpers used by ``collectors/smb.py`` (and the signing helper
by ``collectors/registry.py``).

The signing check reports the **server's advertised** signing requirement -- the
``SecurityMode`` ``SMB2_NEGOTIATE_SIGNING_REQUIRED`` (``0x0002``) bit from the SMB2
NEGOTIATE response. It deliberately does **not** use impacket's
``_Connection['RequireSigning']``: impacket forces that flag ``True`` for SMB
3.1.1 (smb3.py:658-663, "always sign"), which is the default dialect on modern
Windows, so it would report "signing required" on hosts that do not require it --
a false positive that would hide relay targets. Instead:

* ``check_smb_signing`` (standalone) does a raw, unauthenticated SMB2 NEGOTIATE
  over a socket and parses the response ``SecurityMode`` bit, exactly like PS1's
  ``Get-SMBSigningRequiredViaSMBNegotiate`` -- dialect-independent, no impacket
  internals.
* ``negotiated_signing_required`` reads the server value impacket *does* retain
  uncontaminated, ``_Connection['ServerSecurityMode']`` (smb3.py:687), off an
  already-open connection so callers like registry.py pay no extra round-trip.

Share enumeration authenticates via ``clients/smb_sso.py``'s ``connect_smb``
(reused unchanged); impacket's ``listShares()`` is the ``NetShareEnum`` level-1
equivalent PS1 P/Invokes.
"""
from __future__ import annotations

import socket
import struct
import uuid
from typing import Optional

from ..log_context import get_logger
from impacket.smb3structs import SMB2_DIALECT_30, SMB2_NEGOTIATE_SIGNING_REQUIRED

logger = get_logger(__name__)

# Dialects we advertise in the probe NEGOTIATE (SMB 2.0.2 .. 3.1.1), matching
# PS1's Get-SMBSigningRequiredViaSMBNegotiate dialect list.
_PROBE_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
# Absolute byte offset of SecurityMode in the response: 4 (NetBIOS) + 64 (SMB2
# header) + 2 (NEGOTIATE response StructureSize) = 70. (PS1 reads the same offset.)
_SECURITY_MODE_OFFSET = 70


def _build_smb2_negotiate() -> bytes:
    """Build a NetBIOS-framed, unauthenticated SMB2 NEGOTIATE request.

    Faithful to PS1's hand-built packet: a 64-byte SMB2 header (NEGOTIATE,
    message id 0) followed by the NEGOTIATE request body advertising five
    dialects. The client ``SecurityMode`` we send is irrelevant -- the server
    reports its own policy regardless.
    """
    header = b"\xfeSMB" + struct.pack(
        "<HHIHHIIQIIQ16s",
        64,   # StructureSize
        0,    # CreditCharge
        0,    # Status
        0,    # Command = NEGOTIATE
        1,    # CreditRequest
        0,    # Flags
        0,    # NextCommand
        0,    # MessageId
        0,    # Reserved
        0,    # TreeId
        0,    # SessionId
        b"\x00" * 16,  # Signature
    )
    body = struct.pack(
        "<HHHHI16sQHH",
        36,                      # StructureSize (fixed per MS-SMB2)
        len(_PROBE_DIALECTS),    # DialectCount
        SMB2_NEGOTIATE_SIGNING_REQUIRED,  # client SecurityMode (does not affect the reply)
        0,                       # Reserved
        0x000000FF,              # Capabilities
        uuid.uuid4().bytes,      # ClientGuid
        0,                       # ClientStartTime / NegotiateContextOffset
        0,                       # NegotiateContextCount
        0,                       # Reserved2
    ) + b"".join(struct.pack("<H", d) for d in _PROBE_DIALECTS)
    smb2 = header + body
    # NetBIOS session-message header: 1 message-type byte (0x00) + 3 length bytes,
    # i.e. the 24-bit length in a 4-byte big-endian field with a zero top byte.
    return struct.pack(">I", len(smb2)) + smb2


def _parse_security_mode(data: bytes) -> Optional[bool]:
    """Return whether the SMB2 NEGOTIATE *response* requires signing, or None.

    None when the buffer is too short or is not an SMB2 reply (PS1's
    undetermined path)."""
    if len(data) < _SECURITY_MODE_OFFSET + 2:
        return None
    if data[4:8] != b"\xfeSMB":  # SMB2 protocol id at offset 4
        return None
    security_mode = struct.unpack_from("<H", data, _SECURITY_MODE_OFFSET)[0]
    return bool(security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED)


def check_smb_signing(hostname: str, timeout: int = 2) -> Optional[bool]:
    """Probe *hostname* for whether SMB signing is required -- unauthenticated.

    Sends a raw SMB2 NEGOTIATE to TCP/445 and reads the server's advertised
    ``SecurityMode`` signing-required bit. Returns ``True``/``False`` when
    determined, or ``None`` when the host can't be reached or didn't answer with
    a parseable SMB2 reply (PS1's ``$result.Error`` path, which gates share
    enumeration).
    """
    try:
        with socket.create_connection((hostname, 445), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_build_smb2_negotiate())
            data = b""
            while len(data) < _SECURITY_MODE_OFFSET + 2:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                data += chunk
    except OSError as ex:  # connect/timeout/reset -> undetermined (gates share enum)
        logger.verbose("SMB2 negotiate for signing check failed on %s: %s", hostname, ex)
        return None

    required = _parse_security_mode(data)
    if required is None:
        logger.warning("Could not parse SMB signing requirement response from %s", hostname)
    else:
        logger.info(
            "SMB signing %s on %s (via SMB2 negotiate)",
            "REQUIRED" if required else "NOT required",
            hostname,
        )
    return required


def negotiated_signing_required(smb) -> Optional[bool]:
    """Whether SMB signing is *required*, read off an already-open connection.

    Reads the server's advertised ``SecurityMode`` from impacket's
    ``_Connection['ServerSecurityMode']`` (smb3.py:687) and tests the
    ``SMB2_NEGOTIATE_SIGNING_REQUIRED`` bit. This is the *server's* policy --
    unlike ``_Connection['RequireSigning']``, which impacket forces ``True`` on
    SMB 3.1.1 regardless of the server.

    Returns ``True``/``False`` for an SMB 3.0+ connection; ``None`` for a
    pre-3.0 dialect (where impacket leaves ``ServerSecurityMode`` 0, so the bit
    can't be trusted) or no connection.
    """
    if smb is None:
        return None
    try:
        conn = smb.getSMBServer()._Connection
        # ServerSecurityMode is only populated for dialect >= 3.0; for older
        # dialects it stays 0, which would read as a false "not required".
        if conn.get("Dialect", 0) < SMB2_DIALECT_30:
            return None
        return bool(conn["ServerSecurityMode"] & SMB2_NEGOTIATE_SIGNING_REQUIRED)
    except (AttributeError, KeyError, TypeError) as ex:
        logger.verbose("Negotiated SMB signing flag unavailable on %s: %s", smb.getRemoteHost(), ex)
        return None


def list_shares(smb) -> list[tuple[str, str]]:
    """Enumerate shares on an authenticated session as ``(name, description)`` pairs.

    impacket's ``listShares()`` is the ``NetShareEnum`` level-1 (``SHARE_INFO_1``)
    call PS1 P/Invokes; each entry exposes ``shi1_netname`` and ``shi1_remark`` as
    null-terminated NDR strings, which we strip. Raises on RPC/SMB failure so the
    collector can log and move on.
    """
    shares: list[tuple[str, str]] = []
    for info in smb.listShares():
        name = (info["shi1_netname"] or "").rstrip("\x00").strip()
        remark = (info["shi1_remark"] or "").rstrip("\x00").strip()
        shares.append((name, remark))
    return shares
