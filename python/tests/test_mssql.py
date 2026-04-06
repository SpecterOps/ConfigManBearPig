"""
Unit tests for MSSQL TDS PRELOGIN packet construction.
"""

import pytest
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.collectors.mssql_collector import (
    _build_tds_prelogin,
    _parse_prelogin_response,
    TDS_PRELOGIN_VERSION,
    TDS_PRELOGIN_ENCRYPTION,
    TDS_PRELOGIN_TERMINATOR,
)


class TestTDSPrelogin:
    """Tests for TDS PRELOGIN packet construction and parsing."""

    def test_prelogin_packet_structure(self):
        payload = _build_tds_prelogin()

        # Should start with option headers and end with data
        assert len(payload) > 0

        # First option should be VERSION (0x00)
        assert payload[0] == TDS_PRELOGIN_VERSION

        # Should contain TERMINATOR byte somewhere
        assert TDS_PRELOGIN_TERMINATOR in payload

    def test_prelogin_contains_encryption_option(self):
        payload = _build_tds_prelogin()

        # Find ENCRYPTION option in the header
        found_encryption = False
        offset = 0
        while offset < len(payload):
            token = payload[offset]
            if token == TDS_PRELOGIN_TERMINATOR:
                break
            if token == TDS_PRELOGIN_ENCRYPTION:
                found_encryption = True
                break
            offset += 5  # Each option header is 5 bytes

        assert found_encryption, "ENCRYPTION option not found in PRELOGIN"

    def test_parse_encrypt_off(self):
        """Test parsing a response with ENCRYPT_OFF."""
        # Build a minimal PRELOGIN response with ENCRYPT_OFF
        response = _build_test_prelogin_response(encryption=0x00)
        result = _parse_prelogin_response(response)
        assert result is False  # ENCRYPT_OFF = no EPA

    def test_parse_encrypt_on(self):
        """Test parsing a response with ENCRYPT_ON."""
        response = _build_test_prelogin_response(encryption=0x01)
        result = _parse_prelogin_response(response)
        assert result is True  # ENCRYPT_ON = EPA enabled

    def test_parse_encrypt_req(self):
        """Test parsing a response with ENCRYPT_REQ."""
        response = _build_test_prelogin_response(encryption=0x03)
        result = _parse_prelogin_response(response)
        assert result is True  # ENCRYPT_REQ = EPA enabled

    def test_parse_empty_response(self):
        result = _parse_prelogin_response(b"")
        assert result is None

    def test_parse_none_response(self):
        result = _parse_prelogin_response(None)
        assert result is None


def _build_test_prelogin_response(encryption: int = 0x00) -> bytes:
    """Build a minimal test PRELOGIN response."""
    # Option headers
    version_data = b"\x10\x00\x00\x01\x00\x00"  # 6 bytes
    encryption_data = bytes([encryption])  # 1 byte

    # Calculate offsets (2 options + terminator = 11 bytes header)
    header_size = 2 * 5 + 1  # 2 options * 5 bytes each + terminator

    options = bytearray()
    offset = header_size

    # VERSION
    options.extend(struct.pack(">BHH", TDS_PRELOGIN_VERSION, offset, len(version_data)))
    offset += len(version_data)

    # ENCRYPTION
    options.extend(struct.pack(">BHH", TDS_PRELOGIN_ENCRYPTION, offset, len(encryption_data)))
    offset += len(encryption_data)

    # TERMINATOR
    options.extend(bytes([TDS_PRELOGIN_TERMINATOR]))

    return bytes(options) + version_data + encryption_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
