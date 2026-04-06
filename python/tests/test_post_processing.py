"""
Unit tests for post-processing logic.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.graph import GraphStore
from lib.post_processing import (
    get_hierarchy_root,
    get_sites_in_hierarchy,
    get_all_hierarchies,
    invoke_post_processing,
)


class TestHierarchyDetection:
    """Tests for hierarchy detection functions."""

    def _setup_cas_hierarchy(self) -> GraphStore:
        """Create a CAS + PS1 + PS2 hierarchy."""
        g = GraphStore()
        g.upsert_node("CAS", ["SCCM_Site"], {
            "siteType": 4, "isCAS": True, "siteCode": "CAS",
            "reportToSite": "CAS",
        })
        g.upsert_node("PS1", ["SCCM_Site"], {
            "siteType": 2, "siteCode": "PS1", "reportToSite": "CAS",
        })
        g.upsert_node("PS2", ["SCCM_Site"], {
            "siteType": 2, "siteCode": "PS2", "reportToSite": "CAS",
        })
        return g

    def _setup_standalone_primary(self) -> GraphStore:
        """Create a standalone primary site."""
        g = GraphStore()
        g.upsert_node("PS1", ["SCCM_Site"], {
            "siteType": 2, "siteCode": "PS1", "reportToSite": "PS1",
        })
        return g

    def test_find_cas_root(self):
        g = self._setup_cas_hierarchy()
        root = get_hierarchy_root(g)
        assert root == "CAS"

    def test_find_standalone_root(self):
        g = self._setup_standalone_primary()
        root = get_hierarchy_root(g)
        assert root == "PS1"

    def test_hierarchy_members(self):
        g = self._setup_cas_hierarchy()
        members = get_sites_in_hierarchy(g, "CAS")
        assert "CAS" in members
        assert "PS1" in members
        assert "PS2" in members

    def test_all_hierarchies(self):
        g = self._setup_cas_hierarchy()
        hierarchies = get_all_hierarchies(g)
        assert len(hierarchies) == 1
        assert "CAS" in hierarchies
        assert len(hierarchies["CAS"]) == 3

    def test_secondary_site_excluded_from_replication(self):
        g = GraphStore()
        g.upsert_node("CAS", ["SCCM_Site"], {
            "siteType": 4, "isCAS": True, "reportToSite": "CAS",
        })
        g.upsert_node("PS1", ["SCCM_Site"], {
            "siteType": 2, "reportToSite": "CAS",
        })
        g.upsert_node("SEC", ["SCCM_Site"], {
            "siteType": 1, "reportToSite": "PS1",
        })

        invoke_post_processing(g, disable_possible_edges=True)

        # Should have AdminsReplicatedTo between CAS and PS1 (bidirectional)
        assert g.has_edge("CAS", "PS1", "SCCM_AdminsReplicatedTo")
        assert g.has_edge("PS1", "CAS", "SCCM_AdminsReplicatedTo")

        # Should NOT have AdminsReplicatedTo from/to SEC
        assert not g.has_edge("SEC", "CAS", "SCCM_AdminsReplicatedTo")
        assert not g.has_edge("SEC", "PS1", "SCCM_AdminsReplicatedTo")
        assert not g.has_edge("CAS", "SEC", "SCCM_AdminsReplicatedTo")


class TestContainsEdges:
    """Tests for SCCM_Contains edge creation."""

    def test_site_contains_admin_user(self):
        g = GraphStore()
        g.upsert_node("PS1", ["SCCM_Site"], {"siteCode": "PS1"})
        g.upsert_node("mayyhem\\domainadmin@PS1", ["SCCM_AdminUser"], {
            "siteCode": "PS1",
        })

        invoke_post_processing(g, disable_possible_edges=True)

        assert g.has_edge("PS1", "mayyhem\\domainadmin@PS1", "SCCM_Contains")

    def test_site_contains_security_role(self):
        g = GraphStore()
        g.upsert_node("PS1", ["SCCM_Site"], {"siteCode": "PS1"})
        g.upsert_node("SMS0001R@PS1", ["SCCM_SecurityRole"], {
            "siteCode": "PS1",
        })

        invoke_post_processing(g, disable_possible_edges=True)

        assert g.has_edge("PS1", "SMS0001R@PS1", "SCCM_Contains")

    def test_site_contains_collection(self):
        g = GraphStore()
        g.upsert_node("PS1", ["SCCM_Site"], {"siteCode": "PS1"})
        g.upsert_node("SMS00001@PS1", ["SCCM_Collection"], {
            "siteCode": "PS1",
        })

        invoke_post_processing(g, disable_possible_edges=True)

        assert g.has_edge("PS1", "SMS00001@PS1", "SCCM_Contains")


class TestRoleAssignments:
    """Tests for security role assignment processing."""

    def test_full_admin_creates_edges(self):
        g = GraphStore()
        g.upsert_node("PS1", ["SCCM_Site"], {
            "siteCode": "PS1", "siteType": 2, "reportToSite": "PS1",
        })
        # Security role node
        g.upsert_node("SMS0001R@PS1", ["SCCM_SecurityRole"], {
            "roleName": "Full Administrator",
            "siteCode": "PS1",
        })
        # Collection node (type 2 = Device collection)
        g.upsert_node("SMS00001@PS1", ["SCCM_Collection"], {
            "name": "All Systems@PS1",
            "collectionType": 2,
            "siteCode": "PS1",
        })
        # Admin user with role and collection assignments
        g.upsert_node("mayyhem\\domainadmin@PS1", ["SCCM_AdminUser"], {
            "securityRoles": ["SMS0001R@PS1"],
            "collectionIDs": ["SMS00001@PS1"],
            "isAllInstances": True,
            "siteCode": "PS1",
        })
        # Client device
        g.upsert_node("GUID:device1", ["SCCM_ClientDevice"], {
            "siteCode": "PS1",
        })
        # Collection membership edge (collection -> device)
        g.upsert_edge("SMS00001@PS1", "GUID:device1", "SCCM_HasMember")

        invoke_post_processing(g, disable_possible_edges=True)

        # Full admin should have SCCM_FullAdministrator to devices
        assert g.has_edge(
            "mayyhem\\domainadmin@PS1", "GUID:device1", "SCCM_FullAdministrator"
        )


class TestSameHostAs:
    """Tests for SameHostAs edge creation."""

    def test_client_device_matched_to_computer(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer", "Base"], {
            "sAMAccountName": "PS1-DEV$",
            "dNSHostName": "ps1-dev.mayyhem.com",
            "name": "PS1-DEV$",
        })
        g.upsert_node("GUID:abc", ["SCCM_ClientDevice"], {
            "name": "PS1-DEV@PS1",
            "siteCode": "PS1",
        })
        g.upsert_node("PS1", ["SCCM_Site"], {
            "siteCode": "PS1", "siteType": 2, "reportToSite": "PS1",
        })

        invoke_post_processing(g, disable_possible_edges=True)

        # Bidirectional SameHostAs
        assert g.has_edge("GUID:abc", "S-1-5-21-123", "SameHostAs")
        assert g.has_edge("S-1-5-21-123", "GUID:abc", "SameHostAs")


class TestLocalAdminRequired:
    """Tests for LocalAdminRequired edge creation."""

    def test_site_server_to_role_host(self):
        g = GraphStore()
        g.upsert_node("PS1", ["SCCM_Site"], {
            "siteCode": "PS1", "siteType": 2, "reportToSite": "PS1",
        })
        # Site server
        g.upsert_node("S-1-PSS", ["Computer", "Base"], {
            "SCCMSiteSystemRoles": ["SMS Site Server@PS1"],
            "dNSHostName": "ps1-pss.mayyhem.com",
        })
        # DB server
        g.upsert_node("S-1-DB", ["Computer", "Base"], {
            "SCCMSiteSystemRoles": ["SMS SQL Server@PS1"],
            "dNSHostName": "ps1-db.mayyhem.com",
        })

        invoke_post_processing(g, disable_possible_edges=True)

        assert g.has_edge("S-1-PSS", "S-1-DB", "LocalAdminRequired")
        # Site server should NOT have LocalAdminRequired to itself
        assert not g.has_edge("S-1-PSS", "S-1-PSS", "LocalAdminRequired")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
