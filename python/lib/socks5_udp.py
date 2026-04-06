"""
SOCKS5 UDP relay for UDP-over-SOCKS communication.

Enables DHCP and TFTP operations through SOCKS5 proxies by using
the SOCKS5 UDP ASSOCIATE mechanism (RFC 1928 Section 7).

Used for CRED-1 PXE boot media abuse when operating through a tunnel.
Modeled after SpecterOps cred1py (reference_tools/cred1py/lib/socks.py).

Limitations:
- Only no-auth SOCKS5 proxies are supported
- TFTP multi-block transfers are unreliable over SOCKS5 because ACKs
  are sent to the relay, not to the TFTP server's ephemeral data port.
  Typically only the first block (~512 bytes) is received.
- Broadcast (255.255.255.255) does not work; unicast only.
"""

import logging
import socket
from typing import Optional

logger = logging.getLogger("ConfigManBearPig")


class SOCKS5UDPRelay:
    """
    SOCKS5 UDP relay client.

    Maintains a TCP control channel to the SOCKS5 proxy and uses
    UDP ASSOCIATE to relay UDP packets through the proxy.

    Usage:
        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()
        relay.sendto(packet, "10.0.0.1", 4011)
        data = relay.recvfrom(timeout=5.0)
        relay.close()
    """

    def __init__(self, proxy_host: str, proxy_port: int):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self._control_sock: Optional[socket.socket] = None
        self._udp_sock: Optional[socket.socket] = None
        self._relay_dst: Optional[str] = None
        self._relay_dst_port: Optional[int] = None

    @property
    def connected(self) -> bool:
        return self._relay_dst_port is not None

    def connect(self) -> None:
        """Establish SOCKS5 connection and set up UDP relay."""
        logger.debug(
            f"SOCKS5: connecting to proxy {self.proxy_host}:{self.proxy_port}"
        )

        self._control_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._control_sock.settimeout(10.0)
        self._control_sock.connect((self.proxy_host, self.proxy_port))

        # SOCKS5 negotiation — no-auth only (method 0x00)
        self._control_sock.send(b'\x05\x01\x00')
        resp = self._control_sock.recv(1024)
        if len(resp) < 2 or resp[0] != 5:
            raise SOCKS5Error("Not a SOCKS5 proxy")
        if resp[1] != 0:
            raise SOCKS5Error(
                "SOCKS5 proxy requires authentication (not supported)"
            )

        # UDP ASSOCIATE request
        # CMD=0x03 (UDP ASSOCIATE), ATYP=0x01 (IPv4), DST.ADDR=0.0.0.0, DST.PORT=0
        req = b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00'
        self._control_sock.send(req)
        resp = self._control_sock.recv(1024)

        if len(resp) < 10 or resp[0] != 5 or resp[1] != 0:
            error_code = resp[1] if len(resp) > 1 else -1
            raise SOCKS5Error(
                f"UDP ASSOCIATE failed (error code: {error_code})"
            )

        # Parse relay address from response
        if resp[3] == 1:  # IPv4
            self._relay_dst = socket.inet_ntoa(resp[4:8])
            self._relay_dst_port = int.from_bytes(resp[8:10], 'big')
        elif resp[3] == 3:  # Domain
            domain_len = resp[4]
            self._relay_dst = resp[5:5 + domain_len].decode()
            self._relay_dst_port = int.from_bytes(
                resp[5 + domain_len:5 + domain_len + 2], 'big'
            )
        else:
            raise SOCKS5Error(
                f"Unsupported relay address type: {resp[3]}"
            )

        # If relay reports 0.0.0.0, use the proxy host instead
        if self._relay_dst in ("0.0.0.0", ""):
            self._relay_dst = self.proxy_host

        logger.debug(
            f"SOCKS5: UDP relay established at "
            f"{self._relay_dst}:{self._relay_dst_port}"
        )

    def sendto(self, data: bytes, dest_ip: str, dest_port: int) -> None:
        """Send UDP data through the SOCKS5 relay."""
        if not self.connected:
            raise SOCKS5Error("Not connected — call connect() first")

        # Create a fresh UDP socket for each send
        # (the TCP control channel must stay open for the relay to work)
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except Exception:
                pass

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.connect((self._relay_dst, self._relay_dst_port))

        # SOCKS5 UDP request header (RFC 1928 Section 7):
        #   RSV (2 bytes, 0x0000) + FRAG (1 byte, 0x00) +
        #   ATYP (1 byte, 0x01=IPv4) + DST.ADDR (4 bytes) + DST.PORT (2 bytes)
        header = b'\x00\x00\x00\x01'
        header += socket.inet_aton(dest_ip)
        header += dest_port.to_bytes(2, 'big')

        self._udp_sock.send(header + data)
        logger.debug(
            f"SOCKS5: sent {len(data)} bytes -> {dest_ip}:{dest_port} "
            f"(via relay {self._relay_dst}:{self._relay_dst_port})"
        )

    def recvfrom(
        self, bufsize: int = 4096, timeout: float = 5.0
    ) -> Optional[tuple[bytes, str, int]]:
        """
        Receive UDP data from the SOCKS5 relay.

        Strips the SOCKS5 relay header and returns (payload, sender_ip, sender_port).
        Returns None on timeout or error.
        """
        if not self._udp_sock:
            return None

        self._udp_sock.settimeout(timeout)
        try:
            data = self._udp_sock.recv(bufsize + 10)  # extra for relay header
        except socket.timeout:
            return None
        except OSError:
            return None

        if len(data) < 10:
            logger.debug(f"SOCKS5: received packet too small ({len(data)} bytes)")
            return None

        # Validate header
        if data[0] != 0 or data[1] != 0:
            logger.debug("SOCKS5: invalid relay header (RSV bytes non-zero)")
            return None

        # Strip SOCKS5 relay header and extract sender info
        if data[3] == 1:  # IPv4
            sender_ip = socket.inet_ntoa(data[4:8])
            sender_port = int.from_bytes(data[8:10], 'big')
            payload = data[10:]
        elif data[3] == 3:  # Domain
            domain_len = data[4]
            sender_ip = data[5:5 + domain_len].decode('ascii', errors='ignore')
            sender_port = int.from_bytes(
                data[5 + domain_len:5 + domain_len + 2], 'big'
            )
            payload = data[5 + domain_len + 2:]
        else:
            logger.debug(f"SOCKS5: unsupported address type in response: {data[3]}")
            return None

        logger.debug(
            f"SOCKS5: received {len(payload)} bytes from {sender_ip}:{sender_port}"
        )
        return (payload, sender_ip, sender_port)

    def close(self) -> None:
        """Close all sockets."""
        if self._udp_sock:
            try:
                self._udp_sock.close()
            except Exception:
                pass
            self._udp_sock = None
        if self._control_sock:
            try:
                self._control_sock.close()
            except Exception:
                pass
            self._control_sock = None
        self._relay_dst = None
        self._relay_dst_port = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


class SOCKS5Error(Exception):
    """SOCKS5 protocol error."""
    pass
