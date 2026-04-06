"""
Unit tests for the TFTP client (tftp_client.py).

Tests TFTP packet construction, download logic, reachability checking,
and SOCKS5 relay download using mocked sockets.
"""

import sys
import os
import struct
import socket
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from lib.tftp_client import (
    tftp_download, tftp_reachable,
    tftp_download_socks5, tftp_reachable_socks5,
)


class TestTftpReachable:
    """Tests for TFTP reachability check."""

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_reachable_returns_true(self, mock_getaddrinfo, mock_socket_cls):
        """Any response from TFTP server should return True."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        # Return a DATA packet response
        data_packet = struct.pack(">HH", 3, 1) + b"test data"
        mock_sock.recvfrom.return_value = (data_packet, ('10.0.0.1', 12345))

        result = tftp_reachable("10.0.0.1", "test.bin")
        assert result is True
        mock_sock.close.assert_called()

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_timeout_returns_false(self, mock_getaddrinfo, mock_socket_cls):
        """Timeout should return False."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        import socket
        mock_sock.recvfrom.side_effect = socket.timeout()

        result = tftp_reachable("10.0.0.1", "test.bin")
        assert result is False

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_error_response_returns_true(self, mock_getaddrinfo, mock_socket_cls):
        """Even TFTP error response indicates server is listening."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        # Return an ERROR packet
        error_packet = struct.pack(">HH", 5, 1) + b"File not found\x00"
        mock_sock.recvfrom.return_value = (error_packet, ('10.0.0.1', 12345))

        result = tftp_reachable("10.0.0.1", "test.bin")
        assert result is True

    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_unresolvable_returns_none(self, mock_getaddrinfo):
        """DNS failure should return None."""
        mock_getaddrinfo.return_value = []
        result = tftp_reachable("nonexistent.local", "test.bin")
        assert result is None

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_rrq_packet_format(self, mock_getaddrinfo, mock_socket_cls):
        """RRQ should be opcode 1 + filename + null + 'octet' + null."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        import socket
        mock_sock.recvfrom.side_effect = socket.timeout()

        tftp_reachable("10.0.0.1", "myfile.bin", timeout_ms=100)

        # Check the RRQ packet
        sent_data = mock_sock.sendto.call_args[0][0]
        assert sent_data[:2] == struct.pack(">H", 1)  # opcode RRQ
        assert b'myfile.bin\x00' in sent_data
        assert b'octet\x00' in sent_data


class TestTftpDownload:
    """Tests for TFTP file download."""

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_single_block_download(self, mock_getaddrinfo, mock_socket_cls):
        """Single-block file (< 512 bytes) download."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Return a single DATA block with less than 512 bytes
        file_content = b"Hello TFTP World"
        data_packet = struct.pack(">HH", 3, 1) + file_content
        mock_sock.recvfrom.return_value = (data_packet, ('10.0.0.1', 12345))

        result = tftp_download("10.0.0.1", "test.txt", timeout=1.0)
        assert result == file_content

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_multi_block_download(self, mock_getaddrinfo, mock_socket_cls):
        """Multi-block file download."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Block 1: full 512 bytes
        block1_data = b'A' * 512
        block1 = struct.pack(">HH", 3, 1) + block1_data
        # Block 2: partial (last block)
        block2_data = b'B' * 100
        block2 = struct.pack(">HH", 3, 2) + block2_data

        mock_sock.recvfrom.side_effect = [
            (block1, ('10.0.0.1', 12345)),
            (block2, ('10.0.0.1', 12345)),
        ]

        result = tftp_download("10.0.0.1", "test.bin", timeout=1.0)
        assert result == block1_data + block2_data

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_error_response_returns_none(self, mock_getaddrinfo, mock_socket_cls):
        """TFTP error should return None."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        error_packet = struct.pack(">HH", 5, 1) + b"File not found\x00"
        mock_sock.recvfrom.return_value = (error_packet, ('10.0.0.1', 12345))

        result = tftp_download("10.0.0.1", "missing.txt", timeout=1.0)
        assert result is None

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_ack_sent_for_each_block(self, mock_getaddrinfo, mock_socket_cls):
        """ACK should be sent after each received block."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        block1 = struct.pack(">HH", 3, 1) + b'A' * 100
        mock_sock.recvfrom.return_value = (block1, ('10.0.0.1', 12345))

        tftp_download("10.0.0.1", "test.txt", timeout=1.0)

        # Find ACK calls (not counting the initial RRQ)
        sendto_calls = mock_sock.sendto.call_args_list
        ack_calls = [c for c in sendto_calls
                     if len(c[0][0]) == 4 and struct.unpack(">H", c[0][0][:2])[0] == 4]
        assert len(ack_calls) >= 1
        # ACK for block 1
        ack_data = ack_calls[0][0][0]
        assert struct.unpack(">HH", ack_data) == (4, 1)

    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_unresolvable_returns_none(self, mock_getaddrinfo):
        """Unresolvable host returns None."""
        mock_getaddrinfo.return_value = []
        result = tftp_download("bad.host", "test.txt")
        assert result is None

    @patch('lib.tftp_client.socket.socket')
    @patch('lib.tftp_client.socket.getaddrinfo')
    def test_timeout_returns_none(self, mock_getaddrinfo, mock_socket_cls):
        """Timeout with no data returns None."""
        mock_getaddrinfo.return_value = [(2, 2, 17, '', ('10.0.0.1', 69))]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        import socket
        mock_sock.recvfrom.side_effect = socket.timeout()

        result = tftp_download("10.0.0.1", "test.txt", timeout=0.1)
        assert result is None


class TestTftpDownloadSocks5:
    """Tests for TFTP download via SOCKS5 relay."""

    def _make_mock_relay(self):
        """Create a mock SOCKS5UDPRelay."""
        relay = MagicMock()
        return relay

    def test_single_block_download(self):
        """Should receive first block via relay."""
        relay = self._make_mock_relay()

        file_content = b"Hello SOCKS5 TFTP"
        data_packet = struct.pack(">HH", 3, 1) + file_content
        relay.recvfrom.return_value = (data_packet, "10.0.0.1", 12345)

        result = tftp_download_socks5("10.0.0.1", "test.txt", relay)
        assert result == file_content
        relay.sendto.assert_called()

    def test_error_returns_none(self):
        """TFTP error response should return None."""
        relay = self._make_mock_relay()

        error_packet = struct.pack(">HH", 5, 1) + b"File not found\x00"
        relay.recvfrom.return_value = (error_packet, "10.0.0.1", 12345)

        result = tftp_download_socks5("10.0.0.1", "missing.txt", relay)
        assert result is None

    def test_timeout_returns_none(self):
        """Timeout should return None."""
        relay = self._make_mock_relay()
        relay.recvfrom.return_value = None

        result = tftp_download_socks5("10.0.0.1", "test.txt", relay)
        assert result is None

    def test_sends_rrq(self):
        """Should send RRQ packet to relay."""
        relay = self._make_mock_relay()
        relay.recvfrom.return_value = None

        tftp_download_socks5("10.0.0.1", "myfile.var", relay, port=69)

        # Check sendto was called with RRQ
        sendto_call = relay.sendto.call_args
        rrq_data = sendto_call[0][0]
        assert struct.unpack(">H", rrq_data[:2])[0] == 1  # RRQ opcode
        assert b'myfile.var\x00' in rrq_data
        assert b'octet\x00' in rrq_data
        assert sendto_call[0][1] == "10.0.0.1"
        assert sendto_call[0][2] == 69

    def test_full_block_warns_truncation(self):
        """512-byte block should still return data (with truncation warning)."""
        relay = self._make_mock_relay()

        file_content = b'X' * 512
        data_packet = struct.pack(">HH", 3, 1) + file_content
        relay.recvfrom.return_value = (data_packet, "10.0.0.1", 12345)

        result = tftp_download_socks5("10.0.0.1", "big.var", relay)
        assert result == file_content
        assert len(result) == 512


class TestTftpReachableSocks5:
    """Tests for TFTP reachability via SOCKS5 relay."""

    def test_response_returns_true(self):
        """Any response should return True."""
        relay = MagicMock()
        data_packet = struct.pack(">HH", 3, 1) + b"data"
        relay.recvfrom.return_value = (data_packet, "10.0.0.1", 12345)

        result = tftp_reachable_socks5("10.0.0.1", relay)
        assert result is True

    def test_timeout_returns_false(self):
        """Timeout should return False."""
        relay = MagicMock()
        relay.recvfrom.return_value = None

        result = tftp_reachable_socks5("10.0.0.1", relay)
        assert result is False

    def test_exception_returns_none(self):
        """Exception should return None."""
        relay = MagicMock()
        relay.sendto.side_effect = Exception("broken")

        result = tftp_reachable_socks5("10.0.0.1", relay)
        assert result is None
