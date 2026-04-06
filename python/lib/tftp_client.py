"""
Minimal TFTP client for ConfigManBearPig.

Downloads files from TFTP servers (port 69) using the TFTP protocol (RFC 1350).
Used for PXE boot media variable file retrieval (CRED-1, CRED-6).

Supports both direct UDP and SOCKS5 UDP relay (for proxied environments).
SOCKS5 TFTP is limited to the first block (~512 bytes) because ACKs are
sent to the relay, not to the TFTP server's ephemeral data port.

Reference: https://datatracker.ietf.org/doc/html/rfc1350
"""

import logging
import socket
import struct
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from lib.socks5_udp import SOCKS5UDPRelay

logger = logging.getLogger("ConfigManBearPig")

# TFTP opcodes
_OPCODE_RRQ = 1   # Read Request
_OPCODE_DATA = 3  # Data
_OPCODE_ACK = 4   # Acknowledgment
_OPCODE_ERROR = 5 # Error

# Default TFTP block size (RFC 1350)
_BLOCK_SIZE = 512


def tftp_download(
    host: str,
    filename: str,
    port: int = 69,
    timeout: float = 5.0,
    max_size: int = 10 * 1024 * 1024,  # 10 MB max
) -> Optional[bytes]:
    """
    Download a file from a TFTP server.

    Args:
        host: TFTP server hostname or IP
        filename: Remote file path (e.g., 'SMSTemp\\\\...\\\\file.boot.var')
        port: TFTP server port (default 69)
        timeout: Socket timeout in seconds
        max_size: Maximum file size to download

    Returns:
        File contents as bytes, or None on failure
    """
    try:
        # Resolve hostname to IPv4
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        if not addr_info:
            logger.warning(f"Cannot resolve TFTP server: {host}")
            return None
        server_addr = (addr_info[0][4][0], port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Build and send RRQ (Read Request)
        # Format: [opcode(2)] [filename(N)] [\0] [mode(N)] [\0]
        rrq = struct.pack(">H", _OPCODE_RRQ)
        rrq += filename.encode('ascii') + b'\x00'
        rrq += b'octet\x00'

        sock.sendto(rrq, server_addr)

        filedata = b''
        expected_block = 1

        while True:
            try:
                data, from_addr = sock.recvfrom(4 + _BLOCK_SIZE)
            except socket.timeout:
                logger.debug(f"TFTP timeout waiting for block {expected_block}")
                break

            if len(data) < 4:
                break

            opcode, block = struct.unpack(">HH", data[:4])

            if opcode == _OPCODE_ERROR:
                error_msg = data[4:].split(b'\x00')[0].decode('ascii', errors='ignore')
                logger.debug(f"TFTP error from {host}: {error_msg}")
                sock.close()
                return None

            if opcode != _OPCODE_DATA:
                logger.debug(f"Unexpected TFTP opcode: {opcode}")
                break

            if block != expected_block:
                logger.debug(f"TFTP block mismatch: expected {expected_block}, got {block}")
                # Re-send ACK for last block
                ack = struct.pack(">HH", _OPCODE_ACK, expected_block - 1)
                sock.sendto(ack, from_addr)
                continue

            filedata += data[4:]
            expected_block += 1

            # Send ACK — use the source address from the DATA packet
            # (TFTP servers may use a different port than 69 for data transfer)
            ack = struct.pack(">HH", _OPCODE_ACK, block)
            sock.sendto(ack, from_addr)

            # Check max size
            if len(filedata) > max_size:
                logger.warning(f"TFTP download exceeded max size ({max_size} bytes), aborting")
                break

            # If data block is less than 512 bytes, this is the last block
            if len(data) - 4 < _BLOCK_SIZE:
                break

        sock.close()

        if filedata:
            logger.info(f"TFTP download complete: {filename} ({len(filedata)} bytes)")
            return filedata
        else:
            logger.debug(f"TFTP download returned no data for {filename}")
            return None

    except Exception as e:
        logger.debug(f"TFTP download failed ({host}:{filename}): {e}")
        return None


def tftp_reachable(
    host: str,
    filename: str = "pxecheck.bin",
    port: int = 69,
    timeout_ms: int = 1500,
) -> Optional[bool]:
    """
    Test if a TFTP server is reachable by sending a RRQ.

    Any response (DATA or ERROR) indicates the server is listening.

    Args:
        host: TFTP server hostname or IP
        filename: Filename to request (doesn't need to exist)
        port: TFTP server port (default 69)
        timeout_ms: Timeout in milliseconds

    Returns:
        True if reachable, False if timeout, None on error
    """
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
        if not addr_info:
            return None
        server_addr = (addr_info[0][4][0], port)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_ms / 1000.0)

        # RRQ packet
        rrq = struct.pack(">H", _OPCODE_RRQ)
        rrq += filename.encode('ascii') + b'\x00'
        rrq += b'octet\x00'

        sock.sendto(rrq, server_addr)

        try:
            data, _ = sock.recvfrom(4 + _BLOCK_SIZE)
            sock.close()
            return True  # Any response means server is listening
        except socket.timeout:
            sock.close()
            return False

    except Exception:
        return None


def tftp_download_socks5(
    host: str,
    filename: str,
    socks_relay: "SOCKS5UDPRelay",
    port: int = 69,
    timeout: float = 5.0,
) -> Optional[bytes]:
    """
    Download a file from a TFTP server via SOCKS5 UDP relay.

    IMPORTANT: Due to SOCKS5 relay limitations, only the first data block
    (~512 bytes) can be reliably retrieved. The SOCKS5 proxy relays ACKs
    to its own relay port, not to the TFTP server's ephemeral data port,
    so multi-block transfers fail. For full files, use SMB to download
    from \\\\server\\REMINST after discovering the path via DHCP.

    Args:
        host: TFTP server IP address
        filename: Remote file path
        socks_relay: Connected SOCKS5UDPRelay instance
        port: TFTP server port (default 69)
        timeout: Receive timeout in seconds

    Returns:
        File contents (first block only) as bytes, or None on failure
    """
    try:
        # Build RRQ
        rrq = struct.pack(">H", _OPCODE_RRQ)
        rrq += filename.encode('ascii') + b'\x00'
        rrq += b'octet\x00'

        logger.info(f"[TFTP/SOCKS5] Sending RRQ ({len(rrq)} bytes) -> {host}:{port} for '{filename}'")
        socks_relay.sendto(rrq, host, port)

        # Receive first DATA block
        result = socks_relay.recvfrom(bufsize=4 + _BLOCK_SIZE, timeout=timeout)
        if result is None:
            logger.debug(f"[TFTP/SOCKS5] No response from {host}:{port}")
            return None

        data, sender_ip, sender_port = result
        if len(data) < 4:
            logger.debug(f"[TFTP/SOCKS5] Response too short ({len(data)} bytes)")
            return None

        opcode, block = struct.unpack(">HH", data[:4])

        if opcode == _OPCODE_ERROR:
            error_msg = data[4:].split(b'\x00')[0].decode('ascii', errors='ignore')
            logger.info(f"[TFTP/SOCKS5] Error from {host}: {error_msg}")
            return None

        if opcode != _OPCODE_DATA or block != 1:
            logger.debug(f"[TFTP/SOCKS5] Unexpected response: opcode={opcode} block={block}")
            return None

        filedata = data[4:]
        logger.info(
            f"[TFTP/SOCKS5] Received block 1 ({len(filedata)} bytes) from {sender_ip}:{sender_port}"
        )

        # Send ACK for block 1 (may not reach the TFTP server's data port)
        ack = struct.pack(">HH", _OPCODE_ACK, 1)
        socks_relay.sendto(ack, host, port)

        # If block is full (512 bytes), there are more blocks we can't get
        if len(filedata) >= _BLOCK_SIZE:
            logger.warning(
                f"[TFTP/SOCKS5] File is larger than {_BLOCK_SIZE} bytes. "
                f"SOCKS5 relay limits TFTP to the first block. "
                f"Download full file via SMB from \\\\{host}\\REMINST{filename}"
            )

        if filedata:
            logger.info(f"[TFTP/SOCKS5] Download complete: {filename} ({len(filedata)} bytes, first block)")
            return filedata
        return None

    except Exception as e:
        logger.debug(f"[TFTP/SOCKS5] Download failed ({host}:{filename}): {e}")
        return None


def tftp_reachable_socks5(
    host: str,
    socks_relay: "SOCKS5UDPRelay",
    filename: str = "pxecheck.bin",
    port: int = 69,
    timeout: float = 1.5,
) -> Optional[bool]:
    """
    Test if a TFTP server is reachable via SOCKS5 relay.

    Returns:
        True if reachable, False if timeout, None on error
    """
    try:
        rrq = struct.pack(">H", _OPCODE_RRQ)
        rrq += filename.encode('ascii') + b'\x00'
        rrq += b'octet\x00'

        socks_relay.sendto(rrq, host, port)
        result = socks_relay.recvfrom(bufsize=4 + _BLOCK_SIZE, timeout=timeout)
        return True if result is not None else False
    except Exception:
        return None
