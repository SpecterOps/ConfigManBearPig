"""
Unit tests for the DHCP collector (dhcp_collector.py).

Tests DHCP packet construction, response parsing, PXE detection,
server hint resolution, option 243 extraction, privilege detection,
and SOCKS5 mode routing.
All tests are pure functions — no network required.
"""

import sys
import os
import struct
import socket
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from lib.collectors.dhcp_collector import (
    _get_local_mac,
    _build_bootp_header,
    _build_dhcp_inform_packet,
    _build_dhcp_discover_packet,
    _build_pxe_request_packet,
    _parse_dhcp_response,
    _convert_opt66_to_host,
    _is_pxe_response,
    _get_server_hint,
    _extract_boot_files_from_option243,
    _collect_responses,
    _check_udp_privileges,
    _log_parsed_response,
    invoke_dhcp_collection,
)


class TestGetLocalMac:
    """Tests for MAC address detection."""

    def test_returns_6_bytes(self):
        """Should always return 6 bytes."""
        mac = _get_local_mac()
        assert len(mac) == 6
        assert isinstance(mac, bytes)

    @patch('os.path.isdir', return_value=False)
    def test_fallback_to_zeros(self, mock_isdir):
        """When /sys/class/net is unavailable, should return zeros."""
        mac = _get_local_mac()
        assert mac == b'\x00' * 6


class TestBuildBootpHeader:
    """Tests for BOOTP header construction."""

    def test_length(self):
        """BOOTP header should be 236 bytes."""
        mac = b'\xAA\xBB\xCC\xDD\xEE\xFF'
        xid = b'\x01\x02\x03\x04'
        header = _build_bootp_header(mac, xid)
        assert len(header) == 236

    def test_op_field(self):
        """op field should be 1 (BOOTREQUEST)."""
        header = _build_bootp_header(b'\x00' * 6, b'\x00' * 4)
        assert header[0] == 0x01

    def test_htype_field(self):
        """htype should be 1 (Ethernet)."""
        header = _build_bootp_header(b'\x00' * 6, b'\x00' * 4)
        assert header[1] == 0x01

    def test_hlen_field(self):
        """hlen should be 6."""
        header = _build_bootp_header(b'\x00' * 6, b'\x00' * 4)
        assert header[2] == 0x06

    def test_broadcast_flag(self):
        """Broadcast flag (byte 10) should be 0x80."""
        header = _build_bootp_header(b'\x00' * 6, b'\x00' * 4)
        assert header[10] == 0x80

    def test_xid_field(self):
        """Transaction ID should be at bytes 4-7."""
        xid = b'\xDE\xAD\xBE\xEF'
        header = _build_bootp_header(b'\x00' * 6, xid)
        assert header[4:8] == xid

    def test_mac_in_chaddr(self):
        """MAC address should be at bytes 28-33."""
        mac = b'\xAA\xBB\xCC\xDD\xEE\xFF'
        header = _build_bootp_header(mac, b'\x00' * 4)
        assert header[28:34] == mac


class TestBuildDhcpInformPacket:
    """Tests for DHCPINFORM packet construction."""

    def test_starts_with_bootp_header(self):
        """First 236 bytes should be BOOTP header."""
        packet = _build_dhcp_inform_packet(b'\x00' * 6)
        assert len(packet) > 236

    def test_magic_cookie(self):
        """Bytes 236-239 should be DHCP magic cookie."""
        packet = _build_dhcp_inform_packet(b'\x00' * 6)
        assert packet[236:240] == b'\x63\x82\x53\x63'

    def test_option_53_inform(self):
        """Option 53 should be INFORM (8)."""
        packet = _build_dhcp_inform_packet(b'\x00' * 6)
        options = packet[240:]
        # Option 53: code=35(0x35), len=1, value=8(INFORM)
        assert b'\x35\x01\x08' in options

    def test_option_60_pxeclient(self):
        """Option 60 should be 'PXEClient'."""
        packet = _build_dhcp_inform_packet(b'\x00' * 6)
        assert b'PXEClient' in packet

    def test_option_55_parameter_list(self):
        """Option 55 should request options 60, 66, 67."""
        packet = _build_dhcp_inform_packet(b'\x00' * 6)
        options = packet[240:]
        # Option 55: code=37(0x37), len=3, values=60,66,67
        assert b'\x37\x03\x3c\x42\x43' in options

    def test_end_marker(self):
        """Packet should end with option 255."""
        packet = _build_dhcp_inform_packet(b'\x00' * 6)
        assert packet[-1] == 0xFF


class TestBuildDhcpDiscoverPacket:
    """Tests for DHCPDISCOVER packet construction."""

    def test_option_53_discover(self):
        """Option 53 should be DISCOVER (1)."""
        packet = _build_dhcp_discover_packet(b'\x00' * 6)
        options = packet[240:]
        assert b'\x35\x01\x01' in options

    def test_option_55_extended_list(self):
        """Option 55 should request options 1,3,6,15,60,66,67."""
        packet = _build_dhcp_discover_packet(b'\x00' * 6)
        options = packet[240:]
        # code=55, len=7, values=[1,3,6,15,60,66,67]
        assert bytes([55, 7, 1, 3, 6, 15, 60, 66, 67]) in options

    def test_option_60_pxeclient(self):
        """Option 60 should be 'PXEClient'."""
        packet = _build_dhcp_discover_packet(b'\x00' * 6)
        assert b'PXEClient' in packet


class TestBuildPxeRequestPacket:
    """Tests for PXE REQUEST packet construction."""

    def test_client_ip_field(self):
        """ciaddr should contain the client IP."""
        packet = _build_pxe_request_packet(b'\x00' * 6, "10.0.0.5", "10.0.0.1")
        ciaddr = packet[12:16]
        assert ciaddr == socket.inet_aton("10.0.0.5")

    def test_option_53_request(self):
        """Option 53 should be REQUEST (3)."""
        packet = _build_pxe_request_packet(b'\x00' * 6, "10.0.0.5", "10.0.0.1")
        assert b'\x35\x01\x03' in packet

    def test_option_93_x86(self):
        """Option 93 (PXE Client Architecture) should be x86."""
        packet = _build_pxe_request_packet(b'\x00' * 6, "10.0.0.5", "10.0.0.1")
        assert b'\x5d\x02\x00\x00' in packet

    def test_option_97_machine_id(self):
        """Option 97 (Machine Identifier) should be present."""
        packet = _build_pxe_request_packet(b'\x00' * 6, "10.0.0.5", "10.0.0.1")
        options = packet[240:]
        # Find option 97 (0x61)
        idx = 0
        found = False
        while idx < len(options):
            code = options[idx]
            if code == 255:
                break
            if code == 0:
                idx += 1
                continue
            length = options[idx + 1]
            if code == 97:
                found = True
                assert length == 17  # 1 byte type + 16 bytes GUID
                assert options[idx + 2] == 0  # Type 0
                break
            idx += 2 + length
        assert found, "Option 97 not found in PXE REQUEST packet"


class TestParseDhcpResponse:
    """Tests for DHCP response parsing."""

    def _build_response(self, siaddr=b'\x00' * 4, boot_file=b'',
                        options=b'', pad_to_min=True):
        """Helper to build a minimal DHCP response packet."""
        response = bytearray(240)
        response[0] = 0x02   # op: BOOTREPLY
        response[20:24] = siaddr
        if boot_file:
            file_bytes = boot_file[:128]
            response[108:108 + len(file_bytes)] = file_bytes
        # Magic cookie
        response[236:240] = b'\x63\x82\x53\x63'
        # Append options + end
        return bytes(response) + options + b'\xff'

    def test_valid_response(self):
        """Valid DHCP response should parse successfully."""
        response = self._build_response(
            siaddr=socket.inet_aton("10.0.0.1"),
            boot_file=b'pxeboot.com',
        )
        parsed = _parse_dhcp_response(response)
        assert parsed is not None
        assert parsed["siaddr"] == "10.0.0.1"
        assert parsed["boot_file"] == "pxeboot.com"

    def test_too_short(self):
        """Packet shorter than 240 bytes should return None."""
        result = _parse_dhcp_response(b'\x00' * 100)
        assert result is None

    def test_bad_magic_cookie(self):
        """Wrong magic cookie should return None."""
        data = bytearray(240)
        data[236:240] = b'\x00\x00\x00\x00'  # Wrong cookie
        result = _parse_dhcp_response(bytes(data))
        assert result is None

    def test_option_60_vendor_class(self):
        """Option 60 should be extracted as vendor_class."""
        vendor = b'PXEClient'
        opt = bytes([60, len(vendor)]) + vendor
        response = self._build_response(options=opt)
        parsed = _parse_dhcp_response(response)
        assert parsed["vendor_class"] == "PXEClient"

    def test_option_66_tftp_server(self):
        """Option 66 should be extracted as tftp_server."""
        # 4-byte IP
        opt = bytes([66, 4]) + socket.inet_aton("10.0.0.2")
        response = self._build_response(options=opt)
        parsed = _parse_dhcp_response(response)
        assert parsed["tftp_server"] == "10.0.0.2"

    def test_option_67_boot_file(self):
        """Option 67 should be extracted as boot_file_option."""
        boot_file = b'SMSBoot\\x64\\pxeboot.com'
        opt = bytes([67, len(boot_file)]) + boot_file
        response = self._build_response(options=opt)
        parsed = _parse_dhcp_response(response)
        assert parsed["boot_file_option"] == "SMSBoot\\x64\\pxeboot.com"

    def test_option_243_pxe_data(self):
        """Option 243 should be extracted as raw bytes."""
        pxe_data = b'\x01\x10' + b'path/to/file.var'
        opt = bytes([243, len(pxe_data)]) + pxe_data
        response = self._build_response(options=opt)
        parsed = _parse_dhcp_response(response)
        assert parsed["option_243"] == pxe_data

    def test_pad_option_skipped(self):
        """Option 0 (pad) should be skipped without error."""
        opt = b'\x00\x00\x00' + bytes([60, 3]) + b'ABC'
        response = self._build_response(options=opt)
        parsed = _parse_dhcp_response(response)
        assert parsed["vendor_class"] == "ABC"

    def test_null_trimmed_boot_file(self):
        """Boot file should be null-trimmed."""
        boot_file = b'test.com\x00\x00\x00'
        response = self._build_response(boot_file=boot_file)
        parsed = _parse_dhcp_response(response)
        assert parsed["boot_file"] == "test.com"


class TestConvertOpt66ToHost:
    """Tests for DHCP option 66 parsing."""

    def test_ipv4_address(self):
        """4-byte value should be parsed as IPv4."""
        result = _convert_opt66_to_host(socket.inet_aton("192.168.1.1"))
        assert result == "192.168.1.1"

    def test_ascii_hostname(self):
        """Non-4-byte value should be decoded as ASCII."""
        result = _convert_opt66_to_host(b'pxe-server.domain.com')
        assert result == "pxe-server.domain.com"

    def test_empty_returns_none(self):
        """Empty input should return None."""
        result = _convert_opt66_to_host(b'')
        assert result is None

    def test_null_terminated_hostname(self):
        """Null-terminated hostname should be stripped."""
        result = _convert_opt66_to_host(b'myhost.local\x00')
        assert result == "myhost.local"


class TestIsPxeResponse:
    """Tests for PXE response detection."""

    def test_pxeclient_vendor(self):
        """PXEClient vendor class should indicate PXE."""
        assert _is_pxe_response({"vendor_class": "PXEClient:Arch:00000"}) is True

    def test_boot_file_present(self):
        """Boot file in BOOTP field should indicate PXE."""
        assert _is_pxe_response({"boot_file": "pxeboot.com"}) is True

    def test_boot_file_option(self):
        """Option 67 boot file should indicate PXE."""
        assert _is_pxe_response({"boot_file_option": "SMSBoot/x64/pxeboot.com"}) is True

    def test_no_indicators(self):
        """No PXE indicators should return False."""
        assert _is_pxe_response({}) is False
        assert _is_pxe_response({"vendor_class": None, "boot_file": "", "boot_file_option": None}) is False


class TestGetServerHint:
    """Tests for server IP hint resolution."""

    def test_option_66_preferred(self):
        """Option 66 TFTP server should take priority."""
        parsed = {"tftp_server": "10.0.0.2", "siaddr": "10.0.0.1"}
        assert _get_server_hint(parsed, "10.0.0.3") == "10.0.0.2"

    def test_siaddr_fallback(self):
        """siaddr should be used when no option 66."""
        parsed = {"tftp_server": None, "siaddr": "10.0.0.1"}
        assert _get_server_hint(parsed, "10.0.0.3") == "10.0.0.1"

    def test_zero_siaddr_skipped(self):
        """0.0.0.0 siaddr should be skipped."""
        parsed = {"tftp_server": None, "siaddr": "0.0.0.0"}
        assert _get_server_hint(parsed, "10.0.0.3") == "10.0.0.3"

    def test_sender_ip_last_resort(self):
        """Sender IP should be used when nothing else available."""
        parsed = {}
        assert _get_server_hint(parsed, "10.0.0.3") == "10.0.0.3"


class TestExtractBootFilesFromOption243:
    """Tests for DHCP option 243 parsing."""

    def test_empty_returns_none(self):
        """Empty option 243 should return (None, None)."""
        assert _extract_boot_files_from_option243(None) == (None, None)
        assert _extract_boot_files_from_option243(b'') == (None, None)
        assert _extract_boot_files_from_option243(b'\x00\x00') == (None, None)

    def test_packet_type_1_direct_path(self):
        """Packet type 1: direct file path."""
        filename = b'SMSTemp\\12345\\file.boot.var'
        data = bytes([1, len(filename)]) + filename
        path, key = _extract_boot_files_from_option243(data)
        assert path == 'SMSTemp\\12345\\file.boot.var'
        assert key is None

    def test_packet_type_2_encrypted_key(self):
        """Packet type 2: encrypted key + file path."""
        enc_key = b'\xAA' * 20
        filename = b'path\\to\\file.var'
        # [2][key_len][encrypted_key][1][str_len][filename]
        data = bytes([2, len(enc_key)]) + enc_key + bytes([1, len(filename)]) + filename
        path, key = _extract_boot_files_from_option243(data)
        assert path == 'path\\to\\file.var'
        assert key == enc_key

    def test_unknown_packet_type(self):
        """Unknown packet type should return (None, None)."""
        data = bytes([3, 5]) + b'hello'
        assert _extract_boot_files_from_option243(data) == (None, None)


class TestCollectResponses:
    """Tests for the UDP response collection loop."""

    @patch('lib.collectors.dhcp_collector.time.monotonic')
    def test_collects_responses(self, mock_monotonic):
        """Should collect responses within timeout."""
        mock_monotonic.side_effect = [0.0, 0.0, 0.1, 0.1, 2.1]

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = [
            (b'response1', ('10.0.0.1', 67)),
            socket.timeout(),
        ]

        responses = _collect_responses(mock_sock, timeout_ms=2000)
        assert len(responses) == 1
        assert responses[0][0] == b'response1'

    @patch('lib.collectors.dhcp_collector.time.monotonic')
    def test_timeout_returns_empty(self, mock_monotonic):
        """Timeout with no responses should return empty list."""
        mock_monotonic.side_effect = [0.0, 0.0, 2.1]

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout()

        responses = _collect_responses(mock_sock, timeout_ms=2000)
        assert len(responses) == 0


class TestCheckUdpPrivileges:
    """Tests for privilege detection."""

    @patch('os.geteuid', return_value=0)
    def test_root_returns_true(self, mock_euid):
        """Root user should pass privilege check."""
        assert _check_udp_privileges() is True

    @patch('os.geteuid', return_value=1000)
    @patch('lib.collectors.dhcp_collector.socket.socket')
    def test_non_root_with_capability_returns_true(self, mock_socket_cls, mock_euid):
        """Non-root with CAP_NET_RAW should pass."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        assert _check_udp_privileges() is True

    @patch('os.geteuid', return_value=1000)
    @patch('lib.collectors.dhcp_collector.socket.socket')
    def test_non_root_no_capability_returns_false(self, mock_socket_cls, mock_euid):
        """Non-root without capability should fail."""
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = PermissionError("Operation not permitted")
        mock_socket_cls.return_value = mock_sock
        assert _check_udp_privileges() is False


class TestLogParsedResponse:
    """Tests for verbose response logging."""

    def test_logs_without_error(self):
        """Should log parsed fields without raising."""
        parsed = {
            "siaddr": "10.0.0.1",
            "boot_file": "pxeboot.com",
            "vendor_class": "PXEClient",
            "tftp_server": "10.0.0.2",
            "boot_file_option": "SMSBoot\\x64\\pxeboot.com",
            "option_243": b'\x01\x10test',
            "option_252": "\\SMSTemp\\bcd",
            "options_raw": {53: b'\x05', 60: b'PXEClient'},
        }
        # Should not raise
        _log_parsed_response(parsed, "10.0.0.1")

    def test_logs_minimal_response(self):
        """Should handle minimal parsed dict."""
        parsed = {
            "siaddr": "0.0.0.0",
            "boot_file": "",
            "vendor_class": None,
            "tftp_server": None,
            "boot_file_option": None,
            "option_243": None,
            "option_252": None,
            "options_raw": {},
        }
        _log_parsed_response(parsed, "10.0.0.1")


class TestInvokeDhcpCollectionRouting:
    """Tests for invoke_dhcp_collection routing logic."""

    @patch('lib.collectors.dhcp_collector._check_udp_privileges', return_value=False)
    def test_no_sudo_no_socks_returns_early(self, mock_priv):
        """Without sudo and without SOCKS, should return early with error."""
        from lib.graph import GraphStore
        from lib.targets import TargetManager
        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)
        tm._targets = {}
        tm._by_hostname = {}
        tm._by_sid = {}
        tm._lock = MagicMock()
        # Should not raise
        invoke_dhcp_collection(graph, tm, "test.com")
        assert len(graph.nodes) == 0

    @patch('lib.collectors.dhcp_collector._run_socks5_mode')
    def test_socks_proxy_routes_to_socks_mode(self, mock_socks_mode):
        """With --socks-proxy, should route to SOCKS5 mode."""
        from lib.graph import GraphStore
        from lib.targets import TargetManager
        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)
        tm._targets = {}
        tm._by_hostname = {}
        tm._by_sid = {}
        tm._lock = MagicMock()
        invoke_dhcp_collection(graph, tm, "test.com", socks_proxy="127.0.0.1:1080")
        mock_socks_mode.assert_called_once()

    def test_invalid_socks_proxy_format(self):
        """Invalid SOCKS proxy format should return early."""
        from lib.graph import GraphStore
        from lib.targets import TargetManager
        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)
        tm._targets = {}
        tm._by_hostname = {}
        tm._by_sid = {}
        tm._lock = MagicMock()
        # Should not raise
        invoke_dhcp_collection(graph, tm, "test.com", socks_proxy="badformat")
        assert len(graph.nodes) == 0
