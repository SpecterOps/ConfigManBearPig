"""
Unit tests for SOCKS5 UDP relay (socks5_udp.py).

Tests SOCKS5 negotiation, UDP ASSOCIATE, relay header construction,
and error handling. All network operations are mocked.
"""

import sys
import os
import socket
import struct
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from lib.socks5_udp import SOCKS5UDPRelay, SOCKS5Error


class TestSOCKS5Connect:
    """Tests for SOCKS5 connection establishment."""

    @patch('lib.socks5_udp.socket.socket')
    def test_successful_connect_ipv4(self, mock_socket_cls):
        """Successful connect with IPv4 relay address."""
        mock_tcp = MagicMock()
        mock_socket_cls.return_value = mock_tcp

        # Negotiation response: version 5, no auth
        # UDP ASSOCIATE response: version 5, success, rsv, ipv4, 10.0.0.1:9999
        mock_tcp.recv.side_effect = [
            b'\x05\x00',  # Auth OK
            b'\x05\x00\x00\x01' + socket.inet_aton("10.0.0.1") + (9999).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()

        assert relay.connected
        assert relay._relay_dst == "10.0.0.1"
        assert relay._relay_dst_port == 9999

    @patch('lib.socks5_udp.socket.socket')
    def test_successful_connect_domain(self, mock_socket_cls):
        """Successful connect with domain relay address."""
        mock_tcp = MagicMock()
        mock_socket_cls.return_value = mock_tcp

        domain = b'proxy.local'
        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x03' + bytes([len(domain)]) + domain + (8888).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()

        assert relay.connected
        assert relay._relay_dst == "proxy.local"
        assert relay._relay_dst_port == 8888

    @patch('lib.socks5_udp.socket.socket')
    def test_zero_relay_address_uses_proxy_host(self, mock_socket_cls):
        """0.0.0.0 relay address should fall back to proxy host."""
        mock_tcp = MagicMock()
        mock_socket_cls.return_value = mock_tcp

        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x01' + socket.inet_aton("0.0.0.0") + (5555).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("192.168.1.1", 1080)
        relay.connect()

        assert relay._relay_dst == "192.168.1.1"

    @patch('lib.socks5_udp.socket.socket')
    def test_auth_required_raises(self, mock_socket_cls):
        """SOCKS5 proxy requiring auth should raise."""
        mock_tcp = MagicMock()
        mock_socket_cls.return_value = mock_tcp
        mock_tcp.recv.return_value = b'\x05\x02'  # Requires auth method 2

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        with pytest.raises(SOCKS5Error, match="authentication"):
            relay.connect()

    @patch('lib.socks5_udp.socket.socket')
    def test_not_socks5_raises(self, mock_socket_cls):
        """Non-SOCKS5 response should raise."""
        mock_tcp = MagicMock()
        mock_socket_cls.return_value = mock_tcp
        mock_tcp.recv.return_value = b'\x04\x00'  # SOCKS4

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        with pytest.raises(SOCKS5Error, match="Not a SOCKS5"):
            relay.connect()

    @patch('lib.socks5_udp.socket.socket')
    def test_udp_associate_failure_raises(self, mock_socket_cls):
        """UDP ASSOCIATE failure should raise."""
        mock_tcp = MagicMock()
        mock_socket_cls.return_value = mock_tcp
        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x05\x00\x01' + b'\x00' * 6,  # error code 5
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        with pytest.raises(SOCKS5Error, match="UDP ASSOCIATE failed"):
            relay.connect()


class TestSOCKS5SendTo:
    """Tests for SOCKS5 relay sending."""

    @patch('lib.socks5_udp.socket.socket')
    def test_sendto_constructs_relay_header(self, mock_socket_cls):
        """sendto should prepend SOCKS5 relay header."""
        mock_tcp = MagicMock()
        mock_udp = MagicMock()
        # First call = TCP control, second call = UDP relay
        mock_socket_cls.side_effect = [mock_tcp, mock_udp]

        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x01' + socket.inet_aton("127.0.0.1") + (9999).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()

        payload = b'test_payload'
        relay.sendto(payload, "10.0.0.5", 4011)

        # Check the sent data has relay header
        sent_data = mock_udp.send.call_args[0][0]
        # Header: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2) = 10 bytes
        assert sent_data[:4] == b'\x00\x00\x00\x01'
        assert sent_data[4:8] == socket.inet_aton("10.0.0.5")
        assert int.from_bytes(sent_data[8:10], 'big') == 4011
        assert sent_data[10:] == payload

    def test_sendto_without_connect_raises(self):
        """sendto before connect should raise."""
        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        with pytest.raises(SOCKS5Error, match="Not connected"):
            relay.sendto(b'data', "10.0.0.1", 69)


class TestSOCKS5RecvFrom:
    """Tests for SOCKS5 relay receiving."""

    @patch('lib.socks5_udp.socket.socket')
    def test_recvfrom_strips_ipv4_header(self, mock_socket_cls):
        """recvfrom should strip IPv4 relay header."""
        mock_tcp = MagicMock()
        mock_udp = MagicMock()
        mock_socket_cls.side_effect = [mock_tcp, mock_udp]

        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x01' + socket.inet_aton("127.0.0.1") + (9999).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()

        # Simulate sending (creates _udp_sock)
        relay.sendto(b'', "10.0.0.1", 4011)

        # Build relay response with IPv4 header
        payload = b'response_data'
        relay_header = b'\x00\x00\x00\x01' + socket.inet_aton("10.0.0.1") + (4011).to_bytes(2, 'big')
        mock_udp.recv.return_value = relay_header + payload

        result = relay.recvfrom(timeout=1.0)
        assert result is not None
        data, sender_ip, sender_port = result
        assert data == payload
        assert sender_ip == "10.0.0.1"
        assert sender_port == 4011

    @patch('lib.socks5_udp.socket.socket')
    def test_recvfrom_strips_domain_header(self, mock_socket_cls):
        """recvfrom should strip domain relay header."""
        mock_tcp = MagicMock()
        mock_udp = MagicMock()
        mock_socket_cls.side_effect = [mock_tcp, mock_udp]

        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x01' + socket.inet_aton("127.0.0.1") + (9999).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()
        relay.sendto(b'', "10.0.0.1", 4011)

        # Domain header
        domain = b'server.local'
        relay_header = b'\x00\x00\x00\x03' + bytes([len(domain)]) + domain + (69).to_bytes(2, 'big')
        payload = b'tftp_response'
        mock_udp.recv.return_value = relay_header + payload

        result = relay.recvfrom(timeout=1.0)
        assert result is not None
        data, sender_ip, sender_port = result
        assert data == payload
        assert sender_ip == "server.local"
        assert sender_port == 69

    @patch('lib.socks5_udp.socket.socket')
    def test_recvfrom_timeout_returns_none(self, mock_socket_cls):
        """Timeout should return None."""
        mock_tcp = MagicMock()
        mock_udp = MagicMock()
        mock_socket_cls.side_effect = [mock_tcp, mock_udp]

        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x01' + socket.inet_aton("127.0.0.1") + (9999).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()
        relay.sendto(b'', "10.0.0.1", 4011)
        mock_udp.recv.side_effect = socket.timeout()

        result = relay.recvfrom(timeout=0.1)
        assert result is None

    @patch('lib.socks5_udp.socket.socket')
    def test_recvfrom_short_packet_returns_none(self, mock_socket_cls):
        """Packet shorter than 10 bytes should return None."""
        mock_tcp = MagicMock()
        mock_udp = MagicMock()
        mock_socket_cls.side_effect = [mock_tcp, mock_udp]

        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x01' + socket.inet_aton("127.0.0.1") + (9999).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()
        relay.sendto(b'', "10.0.0.1", 4011)
        mock_udp.recv.return_value = b'\x00\x00\x00'

        result = relay.recvfrom(timeout=0.1)
        assert result is None

    def test_recvfrom_no_socket_returns_none(self):
        """recvfrom without UDP socket should return None."""
        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        assert relay.recvfrom() is None


class TestSOCKS5Close:
    """Tests for SOCKS5 relay cleanup."""

    @patch('lib.socks5_udp.socket.socket')
    def test_close_cleans_up(self, mock_socket_cls):
        """close() should reset all state."""
        mock_tcp = MagicMock()
        mock_socket_cls.return_value = mock_tcp

        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x01' + socket.inet_aton("127.0.0.1") + (9999).to_bytes(2, 'big'),
        ]

        relay = SOCKS5UDPRelay("127.0.0.1", 1080)
        relay.connect()
        assert relay.connected

        relay.close()
        assert not relay.connected
        assert relay._control_sock is None
        assert relay._udp_sock is None

    @patch('lib.socks5_udp.socket.socket')
    def test_context_manager(self, mock_socket_cls):
        """Context manager should connect and close."""
        mock_tcp = MagicMock()
        mock_socket_cls.return_value = mock_tcp

        mock_tcp.recv.side_effect = [
            b'\x05\x00',
            b'\x05\x00\x00\x01' + socket.inet_aton("127.0.0.1") + (9999).to_bytes(2, 'big'),
        ]

        with SOCKS5UDPRelay("127.0.0.1", 1080) as relay:
            assert relay.connected
        assert not relay.connected
