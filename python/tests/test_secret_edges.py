"""
Tests for CRED-discovered secret node creation and post-processing edge creation.

Tests cover:
- secret_utils.py: resolve_and_create_secret_user, create_secret_node, extract_domain_users
- post_processing.py: _add_secret_policy_edges
- Integration: end-to-end flow from secret discovery to edge creation
"""

import pytest
from unittest.mock import MagicMock, patch

from lib.graph import GraphStore, TRAVERSABLE_EDGE_TYPES
from lib.post_processing import _add_secret_policy_edges, invoke_post_processing
from lib.secret_utils import (
    DOMAIN_USER_PATTERN,
    create_secret_node,
    extract_domain_users,
    resolve_and_create_secret_user,
)


# ------------------------------------------------------------------ #
#  secret_utils: extract_domain_users
# ------------------------------------------------------------------ #

class TestExtractDomainUsers:

    def test_simple_domain_user(self):
        assert extract_domain_users(r"DOMAIN\user") == [r"DOMAIN\user"]

    def test_multiple_matches(self):
        text = r"Connect as CORP\admin or fallback to CORP\svc_backup"
        result = extract_domain_users(text)
        assert len(result) == 2
        assert r"CORP\admin" in result
        assert r"CORP\svc_backup" in result

    def test_no_match(self):
        assert extract_domain_users("just a regular string") == []

    def test_empty_string(self):
        assert extract_domain_users("") == []

    def test_dotted_domain(self):
        assert extract_domain_users(r"SUB.DOMAIN\user.name") == [r"SUB.DOMAIN\user.name"]

    def test_embedded_in_xml(self):
        xml = '<value>MAYYHEM\\svc_naa</value>'
        result = extract_domain_users(xml)
        assert r"MAYYHEM\svc_naa" in result

    def test_task_sequence_script(self):
        script = 'net use \\\\server\\share /user:CORP\\deploy P@ss'
        result = extract_domain_users(script)
        # Should find CORP\deploy (and possibly server\share)
        assert any("CORP" in u and "deploy" in u for u in result)


# ------------------------------------------------------------------ #
#  secret_utils: resolve_and_create_secret_user
# ------------------------------------------------------------------ #

class TestResolveAndCreateSecretUser:

    def test_creates_user_node_with_ad_resolution(self):
        graph = GraphStore()
        mock_resolver = MagicMock()
        mock_resolver.resolve_principal.return_value = {
            "objectSid": "S-1-5-21-1234-5678",
            "sAMAccountName": "svc_naa",
            "distinguishedName": "CN=svc_naa,OU=Service,DC=test,DC=com",
        }

        node_id = resolve_and_create_secret_user(
            mock_resolver, graph, r"TEST\svc_naa", "NAA", "PS1", "HTTP-CRED2",
        )

        assert node_id == "S-1-5-21-1234-5678"
        node = graph.get_node(node_id)
        assert "User" in node["kinds"]
        assert "Base" in node["kinds"]
        assert node["properties"]["discoveredSecretType"] == "NAA"
        assert node["properties"]["discoveredInSite"] == "PS1"
        assert node["properties"]["isSCCMNetworkAccessAccount"] is True
        assert node["properties"]["sAMAccountName"] == "svc_naa"

    def test_creates_user_node_without_ad_resolution(self):
        graph = GraphStore()
        mock_resolver = MagicMock()
        mock_resolver.resolve_principal.return_value = None

        node_id = resolve_and_create_secret_user(
            mock_resolver, graph, r"TEST\svc_naa", "NAA", "PS1", "HTTP-CRED2",
        )

        assert node_id == "SCCM_Secret_NAA_TEST\\svc_naa"
        node = graph.get_node(node_id)
        assert "User" in node["kinds"]
        assert node["properties"]["sAMAccountName"] == "svc_naa"

    def test_creates_user_node_with_no_resolver(self):
        graph = GraphStore()

        node_id = resolve_and_create_secret_user(
            None, graph, r"DOMAIN\user", "CollectionVariable", "PS1", "Local-CRED4",
        )

        assert "SCCM_Secret_CollectionVariable_" in node_id
        node = graph.get_node(node_id)
        assert node["properties"]["discoveredSecretType"] == "CollectionVariable"
        assert "isSCCMNetworkAccessAccount" not in node["properties"]

    def test_extra_props_merged(self):
        graph = GraphStore()

        resolve_and_create_secret_user(
            None, graph, r"DOMAIN\user", "NAA", "PS1", "HTTP-CRED2",
            extra_props={"isHistoric": True},
        )

        nodes = graph.find_nodes_by_kind("User")
        assert len(nodes) == 1
        assert nodes[0]["properties"]["isHistoric"] is True

    def test_ad_resolution_exception_handled(self):
        graph = GraphStore()
        mock_resolver = MagicMock()
        mock_resolver.resolve_principal.side_effect = Exception("LDAP error")

        # Should not raise
        node_id = resolve_and_create_secret_user(
            mock_resolver, graph, r"TEST\user", "NAA", "PS1", "HTTP-CRED2",
        )
        assert node_id is not None
        assert len(graph.find_nodes_by_kind("User")) == 1


# ------------------------------------------------------------------ #
#  secret_utils: create_secret_node
# ------------------------------------------------------------------ #

class TestCreateSecretNode:

    def test_creates_sccm_secret_node(self):
        graph = GraphStore()

        node_id = create_secret_node(
            graph, "NAA_Password", "P@ssw0rd!", "PS1", "HTTP-CRED2",
            name="NAA Password",
        )

        assert node_id.startswith("SCCM_Secret_NAA_Password_")
        node = graph.get_node(node_id)
        assert "SCCM_Secret" in node["kinds"]
        assert node["properties"]["secretType"] == "NAA_Password"
        assert node["properties"]["discoveredSecretType"] == "NAA_Password"
        assert node["properties"]["discoveredInSite"] == "PS1"
        assert node["properties"]["name"] == "NAA Password"

    def test_cleartext_hidden_by_default(self):
        graph = GraphStore()

        node_id = create_secret_node(
            graph, "CollectionVariable", "secret_value", "PS1", "HTTP-CRED2",
        )

        node = graph.get_node(node_id)
        assert "secretValue" not in node["properties"]

    def test_cleartext_shown_when_enabled(self):
        graph = GraphStore()

        node_id = create_secret_node(
            graph, "CollectionVariable", "secret_value", "PS1", "HTTP-CRED2",
            show_cleartext=True,
        )

        node = graph.get_node(node_id)
        assert node["properties"]["secretValue"] == "secret_value"

    def test_deterministic_deduplication(self):
        graph = GraphStore()

        id1 = create_secret_node(graph, "NAA_Password", "same_pass", "PS1", "CRED2")
        id2 = create_secret_node(graph, "NAA_Password", "same_pass", "PS1", "CRED4")

        # Same value = same hash = same ID
        assert id1 == id2
        assert len(graph.find_nodes_by_kind("SCCM_Secret")) == 1

    def test_different_values_different_nodes(self):
        graph = GraphStore()

        id1 = create_secret_node(graph, "NAA_Password", "pass1", "PS1", "CRED2")
        id2 = create_secret_node(graph, "NAA_Password", "pass2", "PS1", "CRED2")

        assert id1 != id2
        assert len(graph.find_nodes_by_kind("SCCM_Secret")) == 2

    def test_extra_props_merged(self):
        graph = GraphStore()

        create_secret_node(
            graph, "TaskSequence", "script", "PS1", "CRED4",
            extra_props={"isHistoric": True},
        )

        nodes = graph.find_nodes_by_kind("SCCM_Secret")
        assert nodes[0]["properties"]["isHistoric"] is True


# ------------------------------------------------------------------ #
#  post_processing: _add_secret_policy_edges
# ------------------------------------------------------------------ #

class TestAddSecretPolicyEdges:

    def _setup_graph_with_secrets(self):
        """Helper: create a graph with SCCM_ClientDevices and discovered secrets."""
        graph = GraphStore()

        # Two client devices in site PS1
        graph.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1", "name": "DEV1@PS1",
        })
        graph.upsert_node("GUID:dev2", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1", "name": "DEV2@PS1",
        })

        # One client device in site CAS
        graph.upsert_node("GUID:dev3", ["SCCM_ClientDevice"], properties={
            "siteCode": "CAS", "name": "DEV3@CAS",
        })

        # NAA User node discovered in PS1
        graph.upsert_node("S-1-5-21-1234", ["User", "Base"], properties={
            "discoveredSecretType": "NAA",
            "discoveredInSite": "PS1",
            "isSCCMNetworkAccessAccount": True,
            "sAMAccountName": "svc_naa",
        })

        return graph

    def test_naa_edges_created_for_matching_site(self):
        graph = self._setup_graph_with_secrets()

        _add_secret_policy_edges(graph)

        # Should create edges from dev1 and dev2 (PS1) to the NAA user
        naa_edges = graph.find_edges_by_kind("SCCM_HasNetworkAccessAccount")
        assert len(naa_edges) == 2

        sources = {e["start"]["value"] for e in naa_edges}
        assert sources == {"GUID:dev1", "GUID:dev2"}

        targets = {e["end"]["value"] for e in naa_edges}
        assert targets == {"S-1-5-21-1234"}

    def test_no_edges_for_wrong_site(self):
        graph = self._setup_graph_with_secrets()

        _add_secret_policy_edges(graph)

        # dev3 is in CAS, should NOT have edge to PS1 secret
        naa_edges = graph.find_edges_by_kind("SCCM_HasNetworkAccessAccount")
        for edge in naa_edges:
            assert edge["start"]["value"] != "GUID:dev3"

    def test_collection_variable_edges(self):
        graph = GraphStore()
        graph.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1",
        })
        graph.upsert_node("SCCM_Secret_CollectionVariable_abc123", ["SCCM_Secret"], properties={
            "discoveredSecretType": "CollectionVariable",
            "discoveredInSite": "PS1",
        })

        _add_secret_policy_edges(graph)

        cv_edges = graph.find_edges_by_kind("SCCM_HasCollectionVar")
        assert len(cv_edges) == 1
        assert cv_edges[0]["start"]["value"] == "GUID:dev1"

    def test_task_sequence_edges(self):
        graph = GraphStore()
        graph.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1",
        })
        graph.upsert_node("SCCM_Secret_TaskSequence_xyz", ["SCCM_Secret"], properties={
            "discoveredSecretType": "TaskSequence",
            "discoveredInSite": "PS1",
        })

        _add_secret_policy_edges(graph)

        ts_edges = graph.find_edges_by_kind("SCCM_HasTaskSequence")
        assert len(ts_edges) == 1

    def test_naa_password_gets_naa_edge(self):
        """NAA_Password secret type should produce SCCM_HasNetworkAccessAccount edge."""
        graph = GraphStore()
        graph.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1",
        })
        graph.upsert_node("SCCM_Secret_NAA_Password_hash", ["SCCM_Secret"], properties={
            "discoveredSecretType": "NAA_Password",
            "discoveredInSite": "PS1",
        })

        _add_secret_policy_edges(graph)

        naa_edges = graph.find_edges_by_kind("SCCM_HasNetworkAccessAccount")
        assert len(naa_edges) == 1

    def test_no_secrets_no_crash(self):
        graph = GraphStore()
        graph.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1",
        })

        # Should not raise
        _add_secret_policy_edges(graph)
        assert len(graph.edges) == 0

    def test_no_devices_no_edges(self):
        graph = GraphStore()
        graph.upsert_node("S-1-5-21-1234", ["User", "Base"], properties={
            "discoveredSecretType": "NAA",
            "discoveredInSite": "PS1",
        })

        _add_secret_policy_edges(graph)
        assert len(graph.edges) == 0

    def test_edges_are_traversable(self):
        """New edge types should be in TRAVERSABLE_EDGE_TYPES."""
        assert "SCCM_HasCollectionVar" in TRAVERSABLE_EDGE_TYPES
        assert "SCCM_HasTaskSequence" in TRAVERSABLE_EDGE_TYPES
        assert "SCCM_HasNetworkAccessAccount" in TRAVERSABLE_EDGE_TYPES

    def test_multiple_secret_types_in_same_site(self):
        """Multiple secret types discovered in same site should all get edges."""
        graph = GraphStore()

        graph.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1",
        })
        graph.upsert_node("user-sid-1", ["User", "Base"], properties={
            "discoveredSecretType": "NAA",
            "discoveredInSite": "PS1",
        })
        graph.upsert_node("secret-cv-1", ["SCCM_Secret"], properties={
            "discoveredSecretType": "CollectionVariable",
            "discoveredInSite": "PS1",
        })
        graph.upsert_node("secret-ts-1", ["SCCM_Secret"], properties={
            "discoveredSecretType": "TaskSequence",
            "discoveredInSite": "PS1",
        })

        _add_secret_policy_edges(graph)

        naa = graph.find_edges_by_kind("SCCM_HasNetworkAccessAccount")
        cv = graph.find_edges_by_kind("SCCM_HasCollectionVar")
        ts = graph.find_edges_by_kind("SCCM_HasTaskSequence")
        assert len(naa) == 1
        assert len(cv) == 1
        assert len(ts) == 1


# ------------------------------------------------------------------ #
#  Integration: DPE gating
# ------------------------------------------------------------------ #

class TestDPEGating:

    def test_dpe_skips_secret_edges(self):
        """With disable_possible_edges, secret policy edges should NOT be created."""
        graph = GraphStore()
        graph.upsert_node("PS1", ["SCCM_Site"], properties={
            "siteCode": "PS1", "siteType": "2",
        })
        graph.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1",
        })
        graph.upsert_node("S-1-5-21-1234", ["User", "Base"], properties={
            "discoveredSecretType": "NAA",
            "discoveredInSite": "PS1",
            "isSCCMNetworkAccessAccount": True,
        })

        invoke_post_processing(graph, disable_possible_edges=True, domain="test.com")

        naa_edges = graph.find_edges_by_kind("SCCM_HasNetworkAccessAccount")
        assert len(naa_edges) == 0

    def test_no_dpe_creates_secret_edges(self):
        """Without disable_possible_edges, secret policy edges SHOULD be created."""
        graph = GraphStore()
        graph.upsert_node("PS1", ["SCCM_Site"], properties={
            "siteCode": "PS1", "siteType": "2",
        })
        graph.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], properties={
            "siteCode": "PS1",
        })
        graph.upsert_node("S-1-5-21-1234", ["User", "Base"], properties={
            "discoveredSecretType": "NAA",
            "discoveredInSite": "PS1",
            "isSCCMNetworkAccessAccount": True,
        })

        invoke_post_processing(graph, disable_possible_edges=False, domain="test.com")

        naa_edges = graph.find_edges_by_kind("SCCM_HasNetworkAccessAccount")
        assert len(naa_edges) == 1
        assert naa_edges[0]["start"]["value"] == "GUID:dev1"
        assert naa_edges[0]["end"]["value"] == "S-1-5-21-1234"


# ------------------------------------------------------------------ #
#  Integration: CRED-2 HTTP collector creates proper nodes
# ------------------------------------------------------------------ #

class TestCred2SecretNodeCreation:

    @patch('lib.sccm_crypto.deobfuscate_secret_policy_blob')
    def test_cred4_naa_creates_user_node(self, mock_deob):
        """CRED-4: NAA username should create User node, not SCCM_Account."""
        from lib.collectors.local_collector import _deobfuscate_cim_blobs

        graph = GraphStore()
        tm = MagicMock()

        mock_deob.return_value = r"MAYYHEM\svc_naa"
        blobs = [{"hex_blob": "fake", "context": "NetworkAccessUsername"}]

        mock_resolver = MagicMock()
        mock_resolver.resolve_principal.return_value = {
            "objectSid": "S-1-5-21-999-888",
            "sAMAccountName": "svc_naa",
        }

        _deobfuscate_cim_blobs(
            blobs=blobs, graph=graph, target_manager=tm, domain="test.com",
            show_cleartext_passwords=True, ad_resolver=mock_resolver, site_code="PS1",
        )

        # Should create User node, NOT SCCM_Account
        assert len(graph.find_nodes_by_kind("SCCM_Account")) == 0
        users = graph.find_nodes_by_kind("User")
        assert len(users) == 1
        assert users[0]["id"] == "S-1-5-21-999-888"
        assert users[0]["properties"]["discoveredSecretType"] == "NAA"
        assert users[0]["properties"]["discoveredInSite"] == "PS1"
        assert users[0]["properties"]["isHistoric"] is True

    @patch('lib.sccm_crypto.deobfuscate_secret_policy_blob')
    def test_cred4_password_creates_secret_node(self, mock_deob):
        """CRED-4: NAA password should create SCCM_Secret node."""
        from lib.collectors.local_collector import _deobfuscate_cim_blobs

        graph = GraphStore()
        tm = MagicMock()

        # Return username first, then password
        mock_deob.side_effect = [r"DOMAIN\user", "P@ssw0rd!"]
        blobs = [
            {"hex_blob": "fake1", "context": "NetworkAccessUsername"},
            {"hex_blob": "fake2", "context": "NetworkAccessPassword"},
        ]

        _deobfuscate_cim_blobs(
            blobs=blobs, graph=graph, target_manager=tm, domain="test.com",
            show_cleartext_passwords=True, site_code="PS1",
        )

        users = graph.find_nodes_by_kind("User")
        secrets = graph.find_nodes_by_kind("SCCM_Secret")
        assert len(users) == 1  # NAA username
        assert len(secrets) == 1  # NAA password
        assert secrets[0]["properties"]["secretType"] == "NAA_Password"
        assert secrets[0]["properties"]["discoveredInSite"] == "PS1"
