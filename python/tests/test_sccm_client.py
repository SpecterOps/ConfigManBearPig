"""
Unit tests for the SCCM Management Point client (sccm_client.py).

Tests certificate generation, signing, public key blob construction,
and policy flag parsing.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from lib.sccm_client import (
    create_sccm_private_key,
    create_sccm_certificate,
    sccm_sign,
    build_ms_public_key_blob,
    SCCMPolicyClient,
)


class TestCreateSccmPrivateKey:
    """Tests for RSA private key generation."""

    def test_returns_rsa_key(self):
        """Should return an RSA private key."""
        key = create_sccm_private_key()
        assert key is not None
        assert key.key_size == 2048

    def test_different_keys_each_time(self):
        """Two calls should produce different keys."""
        k1 = create_sccm_private_key()
        k2 = create_sccm_private_key()
        n1 = k1.public_key().public_numbers().n
        n2 = k2.public_key().public_numbers().n
        assert n1 != n2

    def test_public_exponent(self):
        """Public exponent should be 65537."""
        key = create_sccm_private_key()
        assert key.public_key().public_numbers().e == 65537


class TestCreateSccmCertificate:
    """Tests for self-signed certificate creation."""

    def test_returns_certificate(self):
        """Should return an x509 Certificate."""
        key = create_sccm_private_key()
        cert = create_sccm_certificate(key)
        assert cert is not None

    def test_subject_cn(self):
        """Subject CN should be 'ConfigMgr Client'."""
        from cryptography.x509.oid import NameOID
        key = create_sccm_private_key()
        cert = create_sccm_certificate(key)
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert len(cn_attrs) == 1
        assert cn_attrs[0].value == "ConfigMgr Client"

    def test_issuer_matches_subject(self):
        """Self-signed: issuer should equal subject."""
        key = create_sccm_private_key()
        cert = create_sccm_certificate(key)
        assert cert.issuer == cert.subject

    def test_sms_oids_in_eku(self):
        """Certificate should have SMS-specific OIDs in Extended Key Usage."""
        from cryptography import x509
        key = create_sccm_private_key()
        cert = create_sccm_certificate(key)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        oid_strings = [usage.dotted_string for usage in eku.value]
        assert "1.3.6.1.4.1.311.101.2" in oid_strings  # SMS Signing
        assert "1.3.6.1.4.1.311.101" in oid_strings     # SMS Encryption

    def test_key_usage(self):
        """Certificate should have digital_signature and data_encipherment."""
        from cryptography import x509
        key = create_sccm_private_key()
        cert = create_sccm_certificate(key)
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.value.digital_signature is True
        assert ku.value.data_encipherment is True
        assert ku.value.key_encipherment is False


class TestSccmSign:
    """Tests for SCCM reversed signature scheme."""

    def test_returns_bytes(self):
        """Should return bytes."""
        key = create_sccm_private_key()
        sig = sccm_sign(key, b"test data")
        assert isinstance(sig, bytes)

    def test_signature_length(self):
        """2048-bit key should produce 256-byte signature."""
        key = create_sccm_private_key()
        sig = sccm_sign(key, b"test data")
        assert len(sig) == 256

    def test_signature_is_reversed(self):
        """Signature bytes should be reversed compared to standard PKCS1v15."""
        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
        from cryptography.hazmat.primitives import hashes

        key = create_sccm_private_key()
        data = b"test data for signing"

        # Standard signature
        standard_sig = key.sign(data, PKCS1v15(), hashes.SHA256())
        # SCCM signature (reversed)
        sccm_sig = sccm_sign(key, data)

        assert sccm_sig == bytes(reversed(standard_sig))

    def test_deterministic(self):
        """Same key + data should produce same signature."""
        key = create_sccm_private_key()
        data = b"deterministic"
        s1 = sccm_sign(key, data)
        s2 = sccm_sign(key, data)
        assert s1 == s2


class TestBuildMsPublicKeyBlob:
    """Tests for Microsoft PUBLICKEYBLOB construction."""

    def test_returns_hex_string(self):
        """Should return uppercase hex string."""
        key = create_sccm_private_key()
        blob = build_ms_public_key_blob(key)
        assert isinstance(blob, str)
        assert blob == blob.upper()
        # Verify it's valid hex
        bytes.fromhex(blob)

    def test_starts_with_rsa1_header(self):
        """Blob should start with PUBLICKEYBLOB header (RSA1 magic)."""
        key = create_sccm_private_key()
        blob = build_ms_public_key_blob(key)
        blob_bytes = bytes.fromhex(blob)
        # Header: 06 02 00 00 00 A4 00 00 52 53 41 31 (RSA1)
        assert blob_bytes[:4] == b'\x06\x02\x00\x00'
        assert blob_bytes[8:12] == b'\x52\x53\x41\x31'  # "RSA1"

    def test_contains_public_exponent(self):
        """Blob should contain public exponent 65537 (01 00 01 00)."""
        key = create_sccm_private_key()
        blob = build_ms_public_key_blob(key)
        blob_bytes = bytes.fromhex(blob)
        # Exponent at bytes 16-19: 01 00 01 00 (little-endian)
        assert blob_bytes[16:20] == b'\x01\x00\x01\x00'

    def test_blob_length(self):
        """Blob for 2048-bit key: 20 byte header + 256 byte modulus = 276 bytes."""
        key = create_sccm_private_key()
        blob = build_ms_public_key_blob(key)
        blob_bytes = bytes.fromhex(blob)
        assert len(blob_bytes) == 276


class TestSCCMPolicyClientParsePolicyFlags:
    """Tests for policy flag bitmask parsing."""

    def test_no_flags(self):
        """Zero should produce empty list."""
        assert SCCMPolicyClient._parse_policy_flags(0) == []

    def test_tasksequence_flag(self):
        """Bit 0 = TASKSEQUENCE."""
        flags = SCCMPolicyClient._parse_policy_flags(0x01)
        assert "TASKSEQUENCE" in flags

    def test_requiresauth_flag(self):
        """Bit 1 = REQUIRESAUTH."""
        flags = SCCMPolicyClient._parse_policy_flags(0x02)
        assert "REQUIRESAUTH" in flags

    def test_secret_flag(self):
        """Bit 2 = SECRET."""
        flags = SCCMPolicyClient._parse_policy_flags(0x04)
        assert "SECRET" in flags

    def test_multiple_flags(self):
        """Combined flags should all be present."""
        flags = SCCMPolicyClient._parse_policy_flags(0x07)
        assert "TASKSEQUENCE" in flags
        assert "REQUIRESAUTH" in flags
        assert "SECRET" in flags

    def test_compressed_flag(self):
        """Bit 6 = COMPRESSED."""
        flags = SCCMPolicyClient._parse_policy_flags(0x40)
        assert "COMPRESSED" in flags

    def test_all_flags(self):
        """All bits set should produce all flags."""
        flags = SCCMPolicyClient._parse_policy_flags(0x7F)
        assert len(flags) == 7


class TestSCCMPolicyClientTLSCertBehavior:
    """Tests for TLS client certificate behavior in different auth modes.

    Verifies that the self-signed TLS client cert is NOT presented when
    NTLM auth is configured (windowsauth mode), as this causes IIS to
    return empty responses.
    """

    def test_ntlm_auth_does_not_set_tls_client_cert(self):
        """NTLM auth mode should NOT present a self-signed TLS client cert.

        When machine_name and machine_pass are provided, the windowsauth
        endpoint uses NTLM headers — not client certificates. Presenting an
        untrusted self-signed cert causes IIS to return empty responses.
        """
        client = SCCMPolicyClient(
            management_point="https://mp.test.com",
            client_name="TEST-PC.test.com",
            machine_name="TEST\\MACHINE$",
            machine_pass="Password123",
        )
        try:
            assert client.session.cert is None, \
                f"NTLM auth mode should not set TLS client cert, got: {client.session.cert}"
            assert client.session.auth is not None
            assert client._temp_cert_dir is None
        finally:
            client.cleanup()

    def test_enhanced_http_sets_self_signed_cert(self):
        """Enhanced HTTP mode (no machine creds, no altauth) SHOULD set self-signed cert.

        When no authentication is configured, SCCM's Enhanced HTTP feature
        accepts self-signed client certificates in the TLS handshake.
        """
        client = SCCMPolicyClient(
            management_point="https://mp.test.com",
            client_name="TEST-PC.test.com",
        )
        try:
            assert client.session.cert is not None
            assert isinstance(client.session.cert, tuple)
            assert len(client.session.cert) == 2
            assert client._temp_cert_dir is not None
        finally:
            client.cleanup()

    def test_altauth_does_not_set_tls_client_cert(self):
        """altauth mode should NOT set a TLS client cert."""
        client = SCCMPolicyClient(
            management_point="https://mp.test.com",
            client_name="TEST-PC.test.com",
            use_altauth=True,
        )
        try:
            assert client.session.cert is None
            assert client._temp_cert_dir is None
        finally:
            client.cleanup()

    def test_pki_cert_overrides_ntlm(self):
        """Explicit PKI cert should be used even when NTLM auth is also set."""
        import tempfile
        import shutil
        tmp_dir = tempfile.mkdtemp()
        cert_path = os.path.join(tmp_dir, "cert.pem")
        key_path = os.path.join(tmp_dir, "key.pem")
        with open(cert_path, 'w') as f:
            f.write("DUMMY_CERT")
        with open(key_path, 'w') as f:
            f.write("DUMMY_KEY")

        try:
            client = SCCMPolicyClient(
                management_point="https://mp.test.com",
                client_name="TEST-PC.test.com",
                machine_name="TEST\\MACHINE$",
                machine_pass="Password123",
                pki_cert_path=cert_path,
                pki_key_path=key_path,
            )
            assert client.session.cert == (cert_path, key_path)
            assert client._temp_cert_dir is None
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_http_no_tls_cert(self):
        """HTTP (not HTTPS) should never set TLS client cert."""
        client = SCCMPolicyClient(
            management_point="http://mp.test.com",
            client_name="TEST-PC.test.com",
        )
        try:
            assert client.session.cert is None
            assert client._temp_cert_dir is None
        finally:
            client.cleanup()
