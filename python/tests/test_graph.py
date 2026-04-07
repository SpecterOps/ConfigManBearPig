"""
Unit tests for the GraphStore (Upsert-Node/Upsert-Edge merge semantics).
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.graph import GraphStore, TRAVERSABLE_EDGE_TYPES


class TestUpsertNode:
    """Tests for GraphStore.upsert_node matching PowerShell Upsert-Node behavior."""

    def test_create_new_node(self):
        g = GraphStore()
        node = g.upsert_node("S-1-5-21-123", ["Computer", "Base"], {"name": "TEST$"})
        assert node["id"] == "S-1-5-21-123"
        assert "Computer" in node["kinds"]
        assert "Base" in node["kinds"]
        assert node["properties"]["name"] == "TEST$"

    def test_merge_kinds(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer", "Base"])
        node = g.upsert_node("S-1-5-21-123", ["SCCM_ClientDevice"])
        assert "Computer" in node["kinds"]
        assert "Base" in node["kinds"]
        assert "SCCM_ClientDevice" in node["kinds"]

    def test_no_duplicate_kinds(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer", "Base"])
        node = g.upsert_node("S-1-5-21-123", ["Computer", "Base"])
        # Should not have duplicate Computer or Base
        assert node["kinds"].count("Computer") == 1
        assert node["kinds"].count("Base") == 1

    def test_merge_scalar_properties(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer"], {"name": "TEST$"})
        node = g.upsert_node("S-1-5-21-123", ["Computer"], {"dNSHostName": "test.mayyhem.com"})
        assert node["properties"]["name"] == "TEST$"
        assert node["properties"]["dNSHostName"] == "test.mayyhem.com"

    def test_scalar_override(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer"], {"name": "OLD"})
        node = g.upsert_node("S-1-5-21-123", ["Computer"], {"name": "NEW"})
        assert node["properties"]["name"] == "NEW"

    def test_none_does_not_override(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer"], {"name": "TEST$"})
        node = g.upsert_node("S-1-5-21-123", ["Computer"], {"name": None})
        assert node["properties"]["name"] == "TEST$"

    def test_merge_array_properties(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer"], {"roles": ["Role1"]})
        node = g.upsert_node("S-1-5-21-123", ["Computer"], {"roles": ["Role2"]})
        assert "Role1" in node["properties"]["roles"]
        assert "Role2" in node["properties"]["roles"]

    def test_array_dedup(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer"], {"roles": ["Role1", "Role2"]})
        node = g.upsert_node("S-1-5-21-123", ["Computer"], {"roles": ["Role1", "Role3"]})
        assert len([r for r in node["properties"]["roles"] if r == "Role1"]) == 1
        assert "Role3" in node["properties"]["roles"]

    def test_collection_source_merge(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer"], {"collectionSource": ["LDAP"]})
        node = g.upsert_node("S-1-5-21-123", ["Computer"], {"collectionSource": ["DNS"]})
        assert "LDAP" in node["properties"]["collectionSource"]
        assert "DNS" in node["properties"]["collectionSource"]

    def test_ad_object_properties(self):
        g = GraphStore()
        ad_obj = {"sAMAccountName": "TEST$", "dNSHostName": "test.mayyhem.com"}
        node = g.upsert_node("S-1-5-21-123", ["Computer"], ad_object=ad_obj)
        assert node["properties"]["sAMAccountName"] == "TEST$"
        assert node["properties"]["dNSHostName"] == "test.mayyhem.com"

    def test_explicit_props_over_ad_object(self):
        g = GraphStore()
        ad_obj = {"name": "AD_NAME"}
        node = g.upsert_node("S-1-5-21-123", ["Computer"],
                            properties={"name": "EXPLICIT"}, ad_object=ad_obj)
        assert node["properties"]["name"] == "EXPLICIT"

    def test_node_count(self):
        g = GraphStore()
        g.upsert_node("A", ["X"])
        g.upsert_node("B", ["X"])
        g.upsert_node("A", ["Y"])  # Update, not new
        assert len(g.nodes) == 2

    def test_find_by_kind(self):
        g = GraphStore()
        g.upsert_node("A", ["Computer", "Base"])
        g.upsert_node("B", ["SCCM_Site"])
        g.upsert_node("C", ["Computer", "Base"])

        computers = g.find_nodes_by_kind("Computer")
        assert len(computers) == 2

        sites = g.find_nodes_by_kind("SCCM_Site")
        assert len(sites) == 1


class TestUpsertEdge:
    """Tests for GraphStore.upsert_edge matching PowerShell Upsert-Edge behavior."""

    def test_create_edge(self):
        g = GraphStore()
        edge = g.upsert_edge("A", "B", "SCCM_Contains")
        assert edge["kind"] == "SCCM_Contains"
        assert edge["start"]["value"] == "A"
        assert edge["end"]["value"] == "B"

    def test_traversable_edge(self):
        g = GraphStore()
        edge = g.upsert_edge("A", "B", "SCCM_FullAdministrator")
        # Traversable edges should NOT have traversable=False
        assert "traversable" not in edge

    def test_non_traversable_edge(self):
        g = GraphStore()
        edge = g.upsert_edge("A", "B", "SomeCustomEdge")
        assert edge.get("traversable") is False

    def test_edge_dedup(self):
        g = GraphStore()
        g.upsert_edge("A", "B", "SCCM_Contains")
        g.upsert_edge("A", "B", "SCCM_Contains")
        assert len(g.edges) == 1

    def test_different_kinds_not_deduped(self):
        g = GraphStore()
        g.upsert_edge("A", "B", "SCCM_Contains")
        g.upsert_edge("A", "B", "SCCM_HasClient")
        assert len(g.edges) == 2

    def test_merge_edge_properties(self):
        g = GraphStore()
        g.upsert_edge("A", "B", "MSSQL_CoerceAndRelayToMSSQL",
                      properties={"pairs": ["pair1"]})
        edge = g.upsert_edge("A", "B", "MSSQL_CoerceAndRelayToMSSQL",
                            properties={"pairs": ["pair2"]})
        assert "pair1" in edge["properties"]["pairs"]
        assert "pair2" in edge["properties"]["pairs"]

    def test_has_edge(self):
        g = GraphStore()
        g.upsert_edge("A", "B", "X")
        assert g.has_edge("A", "B", "X") is True
        assert g.has_edge("A", "B", "Y") is False
        assert g.has_edge("B", "A", "X") is False

    def test_all_seed_edge_types_traversable(self):
        """All edge types from seed_data.json should be traversable."""
        from lib.output import SEED_EDGE_KINDS
        for kind in SEED_EDGE_KINDS:
            assert kind in TRAVERSABLE_EDGE_TYPES, f"{kind} not in TRAVERSABLE_EDGE_TYPES"


class TestGraphQueries:
    """Tests for graph query methods."""

    def test_find_edges_by_kind(self):
        g = GraphStore()
        g.upsert_edge("A", "B", "X")
        g.upsert_edge("C", "D", "X")
        g.upsert_edge("E", "F", "Y")
        assert len(g.find_edges_by_kind("X")) == 2
        assert len(g.find_edges_by_kind("Y")) == 1

    def test_find_edges_from(self):
        g = GraphStore()
        g.upsert_edge("A", "B", "X")
        g.upsert_edge("A", "C", "Y")
        g.upsert_edge("B", "C", "Z")
        assert len(g.find_edges_from("A")) == 2
        assert len(g.find_edges_from("B")) == 1

    def test_find_edges_to(self):
        g = GraphStore()
        g.upsert_edge("A", "C", "X")
        g.upsert_edge("B", "C", "Y")
        g.upsert_edge("A", "D", "Z")
        assert len(g.find_edges_to("C")) == 2
        assert len(g.find_edges_to("D")) == 1

    def test_get_node(self):
        g = GraphStore()
        g.upsert_node("A", ["X"])
        assert g.get_node("A") is not None
        assert g.get_node("B") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
