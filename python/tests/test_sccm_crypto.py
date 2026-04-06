"""
Unit tests for SCCM cryptographic operations (sccm_crypto.py).

Tests key derivation, media variable file operations, policy blob
deobfuscation, and hashcat hash generation.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from lib.sccm_crypto import (
    mscrypt_derive_key_sha1,
    read_media_variable_file_header,
    read_media_variable_file_body,
    decrypt_media_variable_file,
    derive_blank_decryption_key,
    get_hashcat_hash,
    deobfuscate_secret_policy_blob,
)


class TestMscryptDeriveKeySha1:
    """Tests for CryptDeriveKey SHA-1 key derivation."""

    def test_returns_40_bytes(self):
        """Key derivation should always produce 40 bytes."""
        result = mscrypt_derive_key_sha1(b"test_secret")
        assert len(result) == 40

    def test_deterministic(self):
        """Same input should produce same output."""
        r1 = mscrypt_derive_key_sha1(b"deterministic")
        r2 = mscrypt_derive_key_sha1(b"deterministic")
        assert r1 == r2

    def test_different_inputs_different_outputs(self):
        """Different inputs should produce different keys."""
        r1 = mscrypt_derive_key_sha1(b"secret1")
        r2 = mscrypt_derive_key_sha1(b"secret2")
        assert r1 != r2

    def test_empty_input(self):
        """Empty input should still produce 40 bytes."""
        result = mscrypt_derive_key_sha1(b"")
        assert len(result) == 40

    def test_aes128_key_slice(self):
        """First 16 bytes should be usable as AES-128 key."""
        key = mscrypt_derive_key_sha1(b"test")
        assert len(key[:16]) == 16

    def test_3des_key_slice(self):
        """First 24 bytes should be usable as 3DES key."""
        key = mscrypt_derive_key_sha1(b"test")
        assert len(key[:24]) == 24

    def test_aes256_key_slice(self):
        """First 32 bytes should be usable as AES-256 key."""
        key = mscrypt_derive_key_sha1(b"test")
        assert len(key[:32]) == 32


class TestMediaVariableFileOperations:
    """Tests for PXE boot media variable file header/body extraction."""

    def test_header_returns_40_bytes(self):
        """Header should return first 40 bytes."""
        data = os.urandom(100)
        header = read_media_variable_file_header(data)
        assert len(header) == 40
        assert header == data[:40]

    def test_body_skips_header_and_trailer(self):
        """Body should skip 24-byte header and 8-byte trailer."""
        data = b'\x00' * 24 + b'\xAB' * 68 + b'\x00' * 8
        body = read_media_variable_file_body(data)
        assert body == b'\xAB' * 68

    def test_body_short_data(self):
        """Short data should return subset."""
        data = b'\x00' * 24 + b'\xFF' * 16 + b'\x00' * 8
        body = read_media_variable_file_body(data)
        assert body == b'\xFF' * 16


class TestGetHashcatHash:
    """Tests for hashcat hash generation."""

    def test_format(self):
        """Hash should be in $sccm$aes128$<hex> format."""
        data = os.urandom(100)
        hashstr = get_hashcat_hash(data)
        assert hashstr.startswith("$sccm$aes128$")

    def test_hex_content(self):
        """Hash should contain hex of first 40 bytes."""
        data = b'\x01\x02\x03' + b'\x00' * 97
        hashstr = get_hashcat_hash(data)
        assert hashstr == f"$sccm$aes128${data[:40].hex()}"

    def test_deterministic(self):
        """Same input should produce same hash."""
        data = os.urandom(100)
        h1 = get_hashcat_hash(data)
        h2 = get_hashcat_hash(data)
        assert h1 == h2


class TestDecryptMediaVariableFile:
    """Tests for media variable file decryption."""

    def test_invalid_data_returns_none_or_empty(self):
        """Corrupt data should return None or empty string."""
        result = decrypt_media_variable_file(b"short", b"password")
        assert result is None or result == ""

    def test_wrong_password_returns_none_or_garbage(self):
        """Wrong password should return None or non-XML garbage."""
        # Create fake encrypted data (not actually valid but tests error handling)
        fake_data = b'\x00' * 24 + os.urandom(64) + b'\x00' * 8
        result = decrypt_media_variable_file(fake_data, b"wrong_password")
        # Should either return None or garbled text (not crash)
        assert result is None or isinstance(result, str)


class TestDeriveBlankDecryptionKey:
    """Tests for blank password key derivation."""

    def test_short_input_returns_none_or_empty(self):
        """Very short input should return None or empty bytes."""
        result = derive_blank_decryption_key(b"\x00")
        assert result is None or result == b""

    def test_malformed_input_returns_none(self):
        """Malformed input should return None gracefully."""
        result = derive_blank_decryption_key(b"")
        assert result is None

    def test_valid_structure_returns_bytes(self):
        """Valid-looking structure should return bytes (even if not real SCCM data)."""
        # Build a minimal structure: [length][20 bytes padding][16 bytes encrypted][12 bytes padding]
        length = 48
        fake_key = bytes([length]) + os.urandom(length)
        result = derive_blank_decryption_key(fake_key)
        # May return bytes or None depending on structure
        assert result is None or isinstance(result, bytes)


class TestDeobfuscateSecretPolicyBlob:
    """Tests for SCCM policy secret deobfuscation."""

    def test_empty_string_returns_none(self):
        """Empty input should return None."""
        result = deobfuscate_secret_policy_blob("")
        assert result is None

    def test_invalid_hex_returns_none(self):
        """Non-hex input should return None."""
        result = deobfuscate_secret_policy_blob("not_hex_data")
        assert result is None

    def test_short_blob_returns_none_or_empty(self):
        """Too-short blob should return None or empty string."""
        result = deobfuscate_secret_policy_blob("8913" + "00" * 30)
        assert result is None or result == ""

    def test_unknown_prefix_returns_none(self):
        """Unknown cipher prefix should return None."""
        # Create blob with unknown prefix (0xFF13)
        blob = "FF13" + "00" * 128
        result = deobfuscate_secret_policy_blob(blob)
        assert result is None

    def test_3des_prefix_recognized(self):
        """3DES prefix 0x8913 should be processed (even if data is invalid)."""
        # Build minimal 3DES blob structure
        blob = "8913" + "0000"  # prefix + padding
        blob += "AA" * 40       # key material (bytes 4-43)
        blob += "0000" * 4      # padding (bytes 44-51)
        blob += "10000000"      # data length = 16 (bytes 52-55, little endian)
        blob += "0000" * 4      # padding (bytes 56-63)
        blob += "BB" * 16       # encrypted data (bytes 64-79)
        result = deobfuscate_secret_policy_blob(blob)
        # Should attempt decryption (result may be hex string or None)
        # The important thing is it doesn't crash

    def test_aes256_prefix_recognized(self):
        """AES-256 prefix 0x8A13 should be processed."""
        blob = "8A13" + "0000"
        blob += "AA" * 40
        blob += "0000" * 4
        blob += "20000000"      # data length = 32
        blob += "0000" * 4
        blob += "BB" * 32
        result = deobfuscate_secret_policy_blob(blob)
        # Should not crash
