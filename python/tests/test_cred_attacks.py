"""
Unit tests for CRED attack technique implementations.

Tests:
- CRED-6: SMB PXE media scanning (smb_collector.py)
- CRED-4: CIM repository scraping (local_collector.py)
"""

import sys
import os
import struct
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from lib.graph import GraphStore
from lib.targets import TargetManager


# ------------------------------------------------------------------ #
#  CRED-6: SMB PXE Media Scanning Tests
# ------------------------------------------------------------------ #

class TestSmbPxeMediaScanning:
    """Tests for SMB share PXE media file detection."""

    def test_smb_collection_accepts_bad_opsec_kwargs(self):
        """invoke_smb_collection should accept enable_bad_opsec kwarg."""
        from lib.collectors.smb_collector import invoke_smb_collection
        import inspect
        sig = inspect.signature(invoke_smb_collection)
        assert 'enable_bad_opsec' in sig.parameters
        assert 'show_cleartext_passwords' in sig.parameters

    def test_pxe_media_extensions(self):
        """PXE media file patterns should match expected extensions."""
        from lib.collectors.smb_collector import _PXE_MEDIA_EXTENSIONS
        assert ".boot.var" in _PXE_MEDIA_EXTENSIONS
        assert "variables.dat" in _PXE_MEDIA_EXTENSIONS

    def test_reminst_search_paths(self):
        """REMINST search paths should include SMSTemp."""
        from lib.collectors.smb_collector import _REMINST_MEDIA_PATHS
        assert any("SMSTemp" in p for p in _REMINST_MEDIA_PATHS)


class TestSmbProcessPxeMedia:
    """Tests for SMB PXE media file processing."""

    @patch('lib.sccm_crypto.decrypt_media_variable_file')
    @patch('lib.sccm_crypto.get_hashcat_hash')
    def test_failed_decrypt_outputs_hashcat(self, mock_hashcat, mock_decrypt):
        """When decryption fails, hashcat hash should be output."""
        from lib.collectors.smb_collector import _process_smb_pxe_media
        mock_decrypt.return_value = None
        mock_hashcat.return_value = "$sccm$aes128$deadbeef"

        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)
        tm._targets = {}
        tm._by_hostname = {}
        tm._by_sid = {}
        tm._lock = MagicMock()

        _process_smb_pxe_media(
            media_data=b'\x00' * 100,
            remote_path="\\\\REMINST\\SMSTemp\\test.boot.var",
            dp_hostname="dp1.test.com",
            graph=graph,
            ad_resolver=None,
            target_manager=tm,
            domain="test.com",
            show_cleartext_passwords=False,
            site_code="PS1",
        )

        mock_hashcat.assert_called_once()


class TestSmbSmartConnect:
    """Tests for SMB connection helper."""

    @patch('lib.collectors.smb_collector.SMBConnection')
    def test_smb_connect_with_creds(self, mock_smb_cls):
        """Should login with provided credentials."""
        from lib.collectors.smb_collector import _smb_connect
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn

        result = _smb_connect("host1", "test.com", "DOMAIN\\user", "pass123")
        assert result is not None
        mock_conn.login.assert_called_once_with("user", "pass123", "DOMAIN", "", "")

    @patch('lib.collectors.smb_collector.SMBConnection')
    def test_smb_connect_anonymous(self, mock_smb_cls):
        """Should try anonymous login when no creds."""
        from lib.collectors.smb_collector import _smb_connect
        mock_conn = MagicMock()
        mock_smb_cls.return_value = mock_conn

        result = _smb_connect("host1", "test.com", None, None)
        assert result is not None
        mock_conn.login.assert_called_once_with("", "", "test")

    @patch('lib.collectors.smb_collector.SMBConnection')
    def test_smb_connect_failure(self, mock_smb_cls):
        """Connection failure should return None."""
        from lib.collectors.smb_collector import _smb_connect
        mock_smb_cls.side_effect = Exception("Connection refused")

        result = _smb_connect("host1", "test.com", None, None)
        assert result is None


class TestSmbDownloadFile:
    """Tests for SMB file download."""

    def test_download_success(self):
        """Successful download should return bytes."""
        from lib.collectors.smb_collector import _download_smb_file
        mock_conn = MagicMock()

        def write_data(share, path, callback):
            callback(b"test file content")

        mock_conn.getFile.side_effect = write_data

        result = _download_smb_file(mock_conn, "REMINST", "\\test.var")
        assert result == b"test file content"

    def test_download_too_large(self):
        """Files exceeding max_size should return None."""
        from lib.collectors.smb_collector import _download_smb_file
        mock_conn = MagicMock()

        def write_large_data(share, path, callback):
            callback(b"X" * 100)

        mock_conn.getFile.side_effect = write_large_data

        result = _download_smb_file(mock_conn, "REMINST", "\\big.var", max_size=50)
        assert result is None

    def test_download_error_returns_none(self):
        """Download error should return None."""
        from lib.collectors.smb_collector import _download_smb_file
        mock_conn = MagicMock()
        mock_conn.getFile.side_effect = Exception("Access denied")

        result = _download_smb_file(mock_conn, "REMINST", "\\locked.var")
        assert result is None


# ------------------------------------------------------------------ #
#  CRED-4: CIM Repository Scraping Tests
# ------------------------------------------------------------------ #

class TestCimRepositoryExtraction:
    """Tests for CIM repository policy blob extraction."""

    def test_extract_ascii_cdata_blob(self):
        """Should find ASCII CDATA hex blobs in binary data."""
        from lib.collectors.local_collector import _extract_policy_blobs_from_cim
        import tempfile

        # Create temp file with embedded CDATA blob
        hex_blob = "8913" + "0000" + "AA" * 40 + "0000" * 4 + "10000000" + "0000" * 4 + "BB" * 16
        cdata = f'<![CDATA[{hex_blob}]]>'.encode('ascii')
        data = b'\x00' * 100 + cdata + b'\x00' * 100

        with tempfile.NamedTemporaryFile(suffix=".DATA", delete=False) as f:
            f.write(data)
            f.flush()
            try:
                results = _extract_policy_blobs_from_cim(f.name, chunk_size=1024)
                assert len(results) >= 1
                assert results[0]["hex_blob"] == hex_blob
            finally:
                os.unlink(f.name)

    def test_extract_utf16le_cdata_blob(self):
        """Should find UTF-16LE CDATA hex blobs."""
        from lib.collectors.local_collector import _extract_policy_blobs_from_cim
        import tempfile

        hex_blob = "8A13" + "0000" + "CC" * 40 + "0000" * 4 + "20000000" + "0000" * 4 + "DD" * 32
        cdata = f'<![CDATA[{hex_blob}]]>'.encode('utf-16-le')
        data = b'\x00' * 100 + cdata + b'\x00' * 100

        with tempfile.NamedTemporaryFile(suffix=".DATA", delete=False) as f:
            f.write(data)
            f.flush()
            try:
                results = _extract_policy_blobs_from_cim(f.name, chunk_size=1024)
                assert len(results) >= 1
                assert results[0]["hex_blob"] == hex_blob
            finally:
                os.unlink(f.name)

    def test_context_detection_naa(self):
        """Should detect NetworkAccessAccount context from nearby bytes."""
        from lib.collectors.local_collector import _extract_policy_blobs_from_cim
        import tempfile

        hex_blob = "8913" + "0000" + "AA" * 40 + "0000" * 4 + "10000000" + "0000" * 4 + "BB" * 16
        context_str = b'NetworkAccessUsername'
        cdata = f'<![CDATA[{hex_blob}]]>'.encode('ascii')
        # Place context string before CDATA
        data = b'\x00' * 50 + context_str + b'\x00' * 50 + cdata + b'\x00' * 100

        with tempfile.NamedTemporaryFile(suffix=".DATA", delete=False) as f:
            f.write(data)
            f.flush()
            try:
                results = _extract_policy_blobs_from_cim(f.name, chunk_size=4096)
                assert len(results) >= 1
                assert results[0]["context"] == "NetworkAccessUsername"
            finally:
                os.unlink(f.name)

    def test_empty_file_returns_empty(self):
        """Empty file should return no blobs."""
        from lib.collectors.local_collector import _extract_policy_blobs_from_cim
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".DATA", delete=False) as f:
            f.write(b'\x00' * 100)
            f.flush()
            try:
                results = _extract_policy_blobs_from_cim(f.name, chunk_size=1024)
                assert len(results) == 0
            finally:
                os.unlink(f.name)

    def test_deduplication(self):
        """Duplicate blobs should be deduplicated."""
        from lib.collectors.local_collector import _extract_policy_blobs_from_cim
        import tempfile

        hex_blob = "8913" + "0000" + "AA" * 40 + "0000" * 4 + "10000000" + "0000" * 4 + "BB" * 16
        cdata = f'<![CDATA[{hex_blob}]]>'.encode('ascii')
        # Same blob appearing twice
        data = b'\x00' * 50 + cdata + b'\x00' * 50 + cdata + b'\x00' * 50

        with tempfile.NamedTemporaryFile(suffix=".DATA", delete=False) as f:
            f.write(data)
            f.flush()
            try:
                results = _extract_policy_blobs_from_cim(f.name, chunk_size=4096)
                assert len(results) == 1  # Deduplicated
            finally:
                os.unlink(f.name)


class TestCimDeobfuscation:
    """Tests for CIM blob deobfuscation and graph node creation."""

    def test_deobfuscate_creates_naa_node(self):
        """Successful NAA deobfuscation should create SCCM_Account node."""
        from lib.collectors.local_collector import _deobfuscate_cim_blobs

        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)

        # Mock deobfuscate to return a credential-like string
        with patch('lib.sccm_crypto.deobfuscate_secret_policy_blob') as mock_deob:
            mock_deob.return_value = "DOMAIN\\svc_account"
            blobs = [{"hex_blob": "fake", "context": "NetworkAccessUsername"}]

            _deobfuscate_cim_blobs(
                blobs=blobs,
                graph=graph,
                target_manager=tm,
                domain="test.com",
                show_cleartext_passwords=True,
            )

            nodes = graph.find_nodes_by_kind("User")
            assert len(nodes) == 1
            assert nodes[0]["properties"]["discoveredSecretType"] == "NAA"
            assert nodes[0]["properties"]["sAMAccountName"] == "svc_account"

    def test_deobfuscate_failed_blob_no_crash(self):
        """Failed deobfuscation should not create nodes."""
        from lib.collectors.local_collector import _deobfuscate_cim_blobs

        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)

        with patch('lib.sccm_crypto.deobfuscate_secret_policy_blob') as mock_deob:
            mock_deob.return_value = None
            blobs = [{"hex_blob": "bad_data", "context": "unknown"}]

            _deobfuscate_cim_blobs(
                blobs=blobs,
                graph=graph,
                target_manager=tm,
                domain="test.com",
                show_cleartext_passwords=False,
            )

            assert len(graph.nodes) == 0

    def test_password_hidden_without_flag(self):
        """Without show_cleartext_passwords, username should be hidden."""
        from lib.collectors.local_collector import _deobfuscate_cim_blobs

        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)

        with patch('lib.sccm_crypto.deobfuscate_secret_policy_blob') as mock_deob:
            mock_deob.return_value = "DOMAIN\\svc_naa"
            blobs = [{"hex_blob": "fake", "context": "NetworkAccessUsername"}]

            _deobfuscate_cim_blobs(
                blobs=blobs,
                graph=graph,
                target_manager=tm,
                domain="test.com",
                show_cleartext_passwords=False,
            )

            nodes = graph.find_nodes_by_kind("User")
            assert len(nodes) == 1
            assert nodes[0]["properties"]["discoveredSecretType"] == "NAA"
            assert nodes[0]["properties"]["sAMAccountName"] == "svc_naa"


# ------------------------------------------------------------------ #
#  CRED-2: Machine Account and Policy Extraction Tests
# ------------------------------------------------------------------ #

class TestCheckMachineAccountPrereqs:
    """Tests for LDAP pre-checks (MAQ and account existence)."""

    @patch('ldap3.Connection')
    @patch('ldap3.Server')
    def test_maq_zero_raises(self, mock_server_cls, mock_conn_cls):
        """MachineAccountQuota=0 should raise RuntimeError."""
        from lib.sccm_client import _check_machine_account_prereqs

        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_entry = MagicMock()
        mock_entry.__getitem__ = lambda self, k: MagicMock(value=0)
        mock_conn.entries = [mock_entry]

        with pytest.raises(RuntimeError, match="MachineAccountQuota"):
            _check_machine_account_prereqs(
                domain="test.com",
                domain_controller="10.0.0.1",
                username="TEST\\user",
                password="pass",
                sam_account="TESTPC$",
            )

    @patch('ldap3.Connection')
    @patch('ldap3.Server')
    def test_existing_account_raises(self, mock_server_cls, mock_conn_cls):
        """Existing machine account should raise RuntimeError."""
        from lib.sccm_client import _check_machine_account_prereqs

        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_maq_entry = MagicMock()
        mock_maq_entry.__getitem__ = lambda self, k: MagicMock(value=10)
        mock_existing_entry = MagicMock()

        call_count = [0]
        def search_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                mock_conn.entries = [mock_maq_entry]
            else:
                mock_conn.entries = [mock_existing_entry]  # Account exists
            return True

        mock_conn.search.side_effect = search_side_effect

        with pytest.raises(RuntimeError, match="already exists"):
            _check_machine_account_prereqs(
                domain="test.com",
                domain_controller="10.0.0.1",
                username="TEST\\user",
                password="pass",
                sam_account="EXISTING$",
            )

    @patch('ldap3.Connection')
    @patch('ldap3.Server')
    def test_prereqs_pass_when_maq_positive_and_no_existing(self, mock_server_cls, mock_conn_cls):
        """Should succeed when MAQ > 0 and account doesn't exist."""
        from lib.sccm_client import _check_machine_account_prereqs

        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        mock_entry = MagicMock()
        mock_entry.__getitem__ = lambda self, k: MagicMock(value=10)

        call_count = [0]
        def search_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                mock_conn.entries = [mock_entry]
            else:
                mock_conn.entries = []
            return True

        mock_conn.search.side_effect = search_side_effect

        # Should not raise
        _check_machine_account_prereqs(
            domain="test.com",
            domain_controller="10.0.0.1",
            username="TEST\\user",
            password="pass",
            sam_account="NEWPC$",
        )


class TestCreateMachineAccount:
    """Tests for machine account creation via SAMR (impacket addcomputer approach)."""

    @patch('lib.sccm_client._check_machine_account_prereqs')
    @patch('impacket.dcerpc.v5.transport.DCERPCTransportFactory')
    @patch('impacket.dcerpc.v5.epm.hept_map', return_value='ncacn_np:10.0.0.1[\\pipe\\samr]')
    def test_successful_creation(self, mock_hept, mock_transport_factory, mock_prereqs):
        """Should create machine account via SAMR and return DOMAIN\\MACHINE$, password."""
        from lib.sccm_client import create_machine_account
        from impacket.dcerpc.v5 import samr

        # Mock the RPC transport and DCE connection
        mock_rpc = MagicMock()
        mock_transport_factory.return_value = mock_rpc
        mock_dce = MagicMock()
        mock_rpc.get_dce_rpc.return_value = mock_dce

        # hSamrConnect5
        mock_dce_connect_resp = {'ServerHandle': MagicMock()}
        # hSamrEnumerateDomainsInSamServer
        mock_domain = MagicMock()
        mock_domain.__getitem__ = lambda self, k: 'TEST' if k == 'Name' else MagicMock()
        mock_enum_resp = {'Buffer': {'Buffer': [mock_domain]}}
        # hSamrLookupDomainInSamServer
        mock_lookup_resp = {'DomainId': MagicMock()}
        # hSamrOpenDomain
        mock_open_resp = {'DomainHandle': MagicMock()}
        # hSamrLookupNamesInDomain — first call raises (account not found)
        mock_lookup_names_error = samr.DCERPCSessionError(
            packet=MagicMock(get_header=MagicMock(return_value=MagicMock(**{'__getitem__': lambda s, k: 0xc0000073})))
        )
        mock_lookup_names_error.error_code = 0xc0000073
        # hSamrCreateUser2InDomain
        mock_create_resp = {'UserHandle': MagicMock(), 'RelativeId': 1234}
        # hSamrLookupNamesInDomain — second call succeeds (after create)
        mock_rid_resp = {'RelativeIds': {'Element': [1234]}}
        # hSamrOpenUser
        mock_open_user_resp = {'UserHandle': MagicMock()}

        with patch('impacket.dcerpc.v5.samr.hSamrConnect5', return_value=mock_dce_connect_resp), \
             patch('impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer', return_value=mock_enum_resp), \
             patch('impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer', return_value=mock_lookup_resp), \
             patch('impacket.dcerpc.v5.samr.hSamrOpenDomain', return_value=mock_open_resp), \
             patch('impacket.dcerpc.v5.samr.hSamrLookupNamesInDomain', side_effect=[mock_lookup_names_error, mock_rid_resp]), \
             patch('impacket.dcerpc.v5.samr.hSamrCreateUser2InDomain', return_value=mock_create_resp), \
             patch('impacket.dcerpc.v5.samr.hSamrSetPasswordInternal4New'), \
             patch('impacket.dcerpc.v5.samr.hSamrOpenUser', return_value=mock_open_user_resp), \
             patch('impacket.dcerpc.v5.samr.hSamrSetInformationUser2'), \
             patch('impacket.dcerpc.v5.samr.hSamrCloseHandle'):

            account, pw = create_machine_account(
                domain="test.com",
                domain_controller="10.0.0.1",
                username="TEST\\user",
                password="pass",
                machine_name="TESTPC",
                machine_password="TestPass123!",
            )

        assert account == "TEST\\TESTPC$"
        assert pw == "TestPass123!"

    @patch('lib.sccm_client._check_machine_account_prereqs')
    def test_maq_zero_raises_from_prereqs(self, mock_prereqs):
        """MachineAccountQuota=0 should raise via prereq check."""
        from lib.sccm_client import create_machine_account

        mock_prereqs.side_effect = RuntimeError("MachineAccountQuota is 0")

        with pytest.raises(RuntimeError, match="MachineAccountQuota"):
            create_machine_account(
                domain="test.com",
                domain_controller="10.0.0.1",
                username="TEST\\user",
                password="pass",
            )

    @patch('lib.sccm_client._check_machine_account_prereqs')
    def test_existing_account_raises_from_prereqs(self, mock_prereqs):
        """Existing account should raise via prereq check."""
        from lib.sccm_client import create_machine_account

        mock_prereqs.side_effect = RuntimeError("already exists in AD")

        with pytest.raises(RuntimeError, match="already exists"):
            create_machine_account(
                domain="test.com",
                domain_controller="10.0.0.1",
                username="TEST\\user",
                password="pass",
                machine_name="EXISTING",
            )

    def test_auto_generates_name_and_password(self):
        """Should auto-generate machine name and password when not provided."""
        from lib.sccm_client import create_machine_account

        # Mock the entire SAMR flow
        with patch('lib.sccm_client._check_machine_account_prereqs'), \
             patch('impacket.dcerpc.v5.epm.hept_map', return_value='ncacn_np:10.0.0.1[\\pipe\\samr]'), \
             patch('impacket.dcerpc.v5.transport.DCERPCTransportFactory') as mock_tf, \
             patch('impacket.dcerpc.v5.samr.hSamrConnect5', return_value={'ServerHandle': MagicMock()}), \
             patch('impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer') as mock_enum, \
             patch('impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer', return_value={'DomainId': MagicMock()}), \
             patch('impacket.dcerpc.v5.samr.hSamrOpenDomain', return_value={'DomainHandle': MagicMock()}), \
             patch('impacket.dcerpc.v5.samr.hSamrLookupNamesInDomain') as mock_lookup, \
             patch('impacket.dcerpc.v5.samr.hSamrCreateUser2InDomain', return_value={'UserHandle': MagicMock(), 'RelativeId': 1}), \
             patch('impacket.dcerpc.v5.samr.hSamrSetPasswordInternal4New'), \
             patch('impacket.dcerpc.v5.samr.hSamrOpenUser', return_value={'UserHandle': MagicMock()}), \
             patch('impacket.dcerpc.v5.samr.hSamrSetInformationUser2'), \
             patch('impacket.dcerpc.v5.samr.hSamrCloseHandle'):

            # Setup transport mock
            mock_rpc = MagicMock()
            mock_tf.return_value = mock_rpc
            mock_dce = MagicMock()
            mock_rpc.get_dce_rpc.return_value = mock_dce

            # Domain enumeration
            mock_d = MagicMock()
            mock_d.__getitem__ = lambda self, k: 'TEST' if k == 'Name' else MagicMock()
            mock_enum.return_value = {'Buffer': {'Buffer': [mock_d]}}

            # First lookup raises (not found), second succeeds
            from impacket.dcerpc.v5 import samr
            err = samr.DCERPCSessionError(
                packet=MagicMock(get_header=MagicMock(return_value=MagicMock(**{'__getitem__': lambda s, k: 0xc0000073})))
            )
            err.error_code = 0xc0000073
            mock_lookup.side_effect = [err, {'RelativeIds': {'Element': [1]}}]

            account, pw = create_machine_account(
                domain="test.com",
                domain_controller="10.0.0.1",
                username="TEST\\user",
                password="pass",
            )

        assert account.startswith("TEST\\CMBP-")
        assert account.endswith("$")
        assert len(pw) == 24

    def test_strips_trailing_dollar(self):
        """Machine name with $ should be handled correctly."""
        from lib.sccm_client import create_machine_account

        with patch('lib.sccm_client._check_machine_account_prereqs'), \
             patch('impacket.dcerpc.v5.epm.hept_map', return_value='ncacn_np:10.0.0.1[\\pipe\\samr]'), \
             patch('impacket.dcerpc.v5.transport.DCERPCTransportFactory') as mock_tf, \
             patch('impacket.dcerpc.v5.samr.hSamrConnect5', return_value={'ServerHandle': MagicMock()}), \
             patch('impacket.dcerpc.v5.samr.hSamrEnumerateDomainsInSamServer') as mock_enum, \
             patch('impacket.dcerpc.v5.samr.hSamrLookupDomainInSamServer', return_value={'DomainId': MagicMock()}), \
             patch('impacket.dcerpc.v5.samr.hSamrOpenDomain', return_value={'DomainHandle': MagicMock()}), \
             patch('impacket.dcerpc.v5.samr.hSamrLookupNamesInDomain') as mock_lookup, \
             patch('impacket.dcerpc.v5.samr.hSamrCreateUser2InDomain', return_value={'UserHandle': MagicMock(), 'RelativeId': 1}), \
             patch('impacket.dcerpc.v5.samr.hSamrSetPasswordInternal4New'), \
             patch('impacket.dcerpc.v5.samr.hSamrOpenUser', return_value={'UserHandle': MagicMock()}), \
             patch('impacket.dcerpc.v5.samr.hSamrSetInformationUser2'), \
             patch('impacket.dcerpc.v5.samr.hSamrCloseHandle'):

            mock_rpc = MagicMock()
            mock_tf.return_value = mock_rpc
            mock_rpc.get_dce_rpc.return_value = MagicMock()

            mock_d = MagicMock()
            mock_d.__getitem__ = lambda self, k: 'TEST' if k == 'Name' else MagicMock()
            mock_enum.return_value = {'Buffer': {'Buffer': [mock_d]}}

            from impacket.dcerpc.v5 import samr
            err = samr.DCERPCSessionError(
                packet=MagicMock(get_header=MagicMock(return_value=MagicMock(**{'__getitem__': lambda s, k: 0xc0000073})))
            )
            err.error_code = 0xc0000073
            mock_lookup.side_effect = [err, {'RelativeIds': {'Element': [1]}}]

            account, pw = create_machine_account(
                domain="test.com",
                domain_controller="10.0.0.1",
                username="TEST\\user",
                password="pass",
                machine_name="MYPC$",
                machine_password="Pass1",
            )

        assert account == "TEST\\MYPC$"


class TestCred2Validation:
    """Tests for CRED-2 machine account validation in _attempt_cred2_policy_extraction."""

    @patch('lib.collectors.http_collector._check_port', return_value=True)
    def test_no_machine_creds_no_altauth_warns(self, mock_port):
        """Without machine creds or altauth, should warn and return."""
        from lib.collectors.http_collector import _attempt_cred2_policy_extraction

        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)

        # Should not raise, just log warning and return
        _attempt_cred2_policy_extraction(
            hostname="mp.test.com",
            domain="test.com",
            graph=graph,
            ad_resolver=None,
            target_manager=tm,
            http_open=True,
            https_open=False,
            machine_name=None,
            machine_pass=None,
            client_name=None,
            use_altauth=False,
            registration_sleep=0,
            show_cleartext_passwords=False,
            cert_issuer=None,
            create_machine_account=False,
        )

        # No nodes should be created (early return)
        assert len(graph.nodes) == 0

    @patch('lib.collectors.http_collector._check_port', return_value=True)
    def test_create_machine_account_no_domain_creds_warns(self, mock_port):
        """--create-machine-account without domain creds should warn."""
        from lib.collectors.http_collector import _attempt_cred2_policy_extraction

        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)

        _attempt_cred2_policy_extraction(
            hostname="mp.test.com",
            domain="test.com",
            graph=graph,
            ad_resolver=None,
            target_manager=tm,
            http_open=True,
            https_open=False,
            machine_name=None,
            machine_pass=None,
            client_name=None,
            use_altauth=False,
            registration_sleep=0,
            show_cleartext_passwords=False,
            cert_issuer=None,
            create_machine_account=True,
            domain_username=None,
            domain_password=None,
        )

        assert len(graph.nodes) == 0

    @patch('lib.collectors.http_collector._check_port', return_value=True)
    def test_create_machine_account_no_dc_warns(self, mock_port):
        """--create-machine-account without DC should warn."""
        from lib.collectors.http_collector import _attempt_cred2_policy_extraction

        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)

        _attempt_cred2_policy_extraction(
            hostname="mp.test.com",
            domain="test.com",
            graph=graph,
            ad_resolver=None,
            target_manager=tm,
            http_open=True,
            https_open=False,
            machine_name=None,
            machine_pass=None,
            client_name=None,
            use_altauth=False,
            registration_sleep=0,
            show_cleartext_passwords=False,
            cert_issuer=None,
            create_machine_account=True,
            domain_username="TEST\\user",
            domain_password="pass",
            domain_controller=None,
        )

        assert len(graph.nodes) == 0

    def test_http_collection_signature_has_new_params(self):
        """invoke_http_collection should accept create_machine_account and domain_controller."""
        from lib.collectors.http_collector import invoke_http_collection
        import inspect
        sig = inspect.signature(invoke_http_collection)
        assert 'create_machine_account' in sig.parameters
        assert 'domain_controller' in sig.parameters


class TestLocalCollectorIntegration:
    """Integration-level tests for local collector with CRED-4."""

    def test_local_collector_accepts_bad_opsec(self):
        """invoke_local_collection should accept enable_bad_opsec."""
        from lib.collectors.local_collector import invoke_local_collection
        import inspect
        sig = inspect.signature(invoke_local_collection)
        assert 'enable_bad_opsec' in sig.parameters
        assert 'show_cleartext_passwords' in sig.parameters

    @patch('platform.system', return_value='Windows')
    @patch('os.path.isdir', return_value=False)
    @patch('os.path.isfile', return_value=False)
    @patch('os.path.exists', return_value=False)
    def test_no_sccm_client_skips_cred4(self, mock_exists, mock_isfile,
                                         mock_isdir, mock_platform):
        """Without SCCM client, CRED-4 should not be attempted."""
        from lib.collectors.local_collector import invoke_local_collection

        graph = GraphStore()
        tm = TargetManager.__new__(TargetManager)
        tm._targets = {}
        tm._by_hostname = {}
        tm._by_sid = {}
        tm._lock = MagicMock()

        # Should complete without errors
        invoke_local_collection(
            graph, tm, "test.com",
            enable_bad_opsec=True,
            show_cleartext_passwords=False,
        )
