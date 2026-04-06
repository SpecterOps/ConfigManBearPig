"""
Unit tests for output generation.
"""

import json
import os
import tempfile
import zipfile

import pytest
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.graph import GraphStore
from lib.output import (
    StreamingBloodHoundWriter,
    export_bloodhound_data,
    generate_custom_nodes_json,
    SEED_EDGE_KINDS,
    SEED_ID,
)


class TestStreamingWriter:
    """Tests for StreamingBloodHoundWriter."""

    def test_write_nodes_and_edges(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            writer = StreamingBloodHoundWriter(path, include_source_kind=True)
            writer.write_node({"id": "A", "kinds": ["X"], "properties": {"name": "A"}})
            writer.write_node({"id": "B", "kinds": ["Y"], "properties": {"name": "B"}})
            writer.write_edge({"kind": "Z", "start": {"value": "A"}, "end": {"value": "B"}})
            writer.close()

            with open(path, "r") as f:
                data = json.load(f)

            assert "$schema" in data
            assert "graph" in data
            assert len(data["graph"]["nodes"]) == 2
            assert len(data["graph"]["edges"]) == 1
            assert data["graph"]["nodes"][0]["id"] == "A"
            assert data["graph"]["edges"][0]["kind"] == "Z"
        finally:
            os.unlink(path)

    def test_write_nodes_only(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            writer = StreamingBloodHoundWriter(path, include_source_kind=False)
            writer.write_node({"id": "A", "kinds": ["X"], "properties": {}})
            writer.close()

            with open(path, "r") as f:
                data = json.load(f)

            assert "metadata" not in data
            assert len(data["graph"]["nodes"]) == 1
            assert len(data["graph"]["edges"]) == 0
        finally:
            os.unlink(path)

    def test_source_kind_metadata(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name

        try:
            writer = StreamingBloodHoundWriter(path, include_source_kind=True)
            writer.write_node({"id": "A", "kinds": ["X"], "properties": {}})
            writer.close()

            with open(path, "r") as f:
                data = json.load(f)

            assert data["metadata"]["source_kind"] == "SCCM_Base"
        finally:
            os.unlink(path)


class TestExportBloodHoundData:
    """Tests for export_bloodhound_data."""

    def test_export_creates_zip(self):
        g = GraphStore()
        g.upsert_node("S-1-5-21-123", ["Computer", "Base"], {"name": "TEST$"})
        g.upsert_node("PS1", ["SCCM_Site"], {"siteCode": "PS1"})
        g.upsert_edge("PS1", "S-1-5-21-123", "SCCM_Contains")

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "test-output.zip")
            result = export_bloodhound_data(
                graph=g,
                temp_dir=os.path.join(tmpdir, "temp"),
                zip_dir=zip_path,
            )

            assert result is not None
            assert os.path.exists(result)

            with zipfile.ZipFile(result, "r") as zf:
                names = zf.namelist()
                assert "computers.json" in names
                assert "sccm.json" in names
                assert "seed_data.json" in names

                # Verify computers.json has the computer node
                with zf.open("computers.json") as f:
                    data = json.load(f)
                    assert len(data["graph"]["nodes"]) == 1
                    assert data["graph"]["nodes"][0]["id"] == "S-1-5-21-123"
                    # computers.json should NOT have source_kind
                    assert "metadata" not in data

                # Verify sccm.json has SCCM node and edges
                with zf.open("sccm.json") as f:
                    data = json.load(f)
                    assert data["metadata"]["source_kind"] == "SCCM_Base"
                    assert len(data["graph"]["nodes"]) == 1  # PS1 site
                    assert len(data["graph"]["edges"]) == 1  # Contains edge

                # Verify seed_data.json
                with zf.open("seed_data.json") as f:
                    data = json.load(f)
                    assert data["metadata"]["source_kind"] == "SCCM_Seed"
                    assert len(data["graph"]["edges"]) == len(SEED_EDGE_KINDS)

    def test_export_separates_node_types(self):
        g = GraphStore()
        g.upsert_node("S-COMP", ["Computer", "Base"], {"name": "COMP$"})
        g.upsert_node("S-USER", ["User", "Base"], {"name": "user1"})
        g.upsert_node("S-GROUP", ["Group", "Base"], {"name": "group1"})
        g.upsert_node("PS1", ["SCCM_Site"], {"siteCode": "PS1"})
        g.upsert_node("GUID:dev1", ["SCCM_ClientDevice"], {"name": "DEV@PS1"})

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "test.zip")
            result = export_bloodhound_data(g, os.path.join(tmpdir, "temp"), zip_path)

            with zipfile.ZipFile(result, "r") as zf:
                with zf.open("computers.json") as f:
                    data = json.load(f)
                    assert len(data["graph"]["nodes"]) == 1

                with zf.open("users.json") as f:
                    data = json.load(f)
                    assert len(data["graph"]["nodes"]) == 1

                with zf.open("groups.json") as f:
                    data = json.load(f)
                    assert len(data["graph"]["nodes"]) == 1

                with zf.open("sccm.json") as f:
                    data = json.load(f)
                    # PS1 + GUID:dev1 = 2 SCCM nodes
                    assert len(data["graph"]["nodes"]) == 2


class TestCustomNodes:
    """Tests for custom node type definitions."""

    def test_custom_nodes_structure(self):
        custom = generate_custom_nodes_json()
        assert "custom_types" in custom

        expected_types = [
            "SCCM_Site", "SCCM_AdminUser", "SCCM_SecurityRole",
            "SCCM_Collection", "SCCM_ClientDevice",
            "MSSQL_DatabaseUser", "MSSQL_Login", "MSSQL_DatabaseRole",
            "MSSQL_Database", "MSSQL_Server", "MSSQL_ServerRole",
        ]

        for node_type in expected_types:
            assert node_type in custom["custom_types"], f"Missing {node_type}"
            icon = custom["custom_types"][node_type]["icon"]
            assert "color" in icon
            assert "name" in icon
            assert "type" in icon
            assert icon["type"] == "font-awesome"


class TestSeedData:
    """Tests for seed_data.json content."""

    def test_all_edge_kinds_present(self):
        """All declared edge kinds should be in seed data."""
        expected = [
            "LocalAdminRequired", "CoerceAndRelayToAdminService",
            "CoerceAndRelayToMSSQL", "CoerceAndRelayToSMB",
            "HasSession", "MSSQL_Contains", "MSSQL_ControlDB",
            "MSSQL_ControlServer", "MSSQL_ExecuteOnHost",
            "MSSQL_GetAdminTGS", "MSSQL_GetTGS", "MSSQL_HasLogin",
            "MSSQL_HostFor", "MSSQL_IsMappedTo", "MSSQL_LinkedAsAdmin",
            "MSSQL_MemberOf", "MSSQL_ServiceAccountFor",
            "SameHostAs", "SCCM_AdminsReplicatedTo",
            "SCCM_AllPermissions", "SCCM_ApplicationAdministrator",
            "SCCM_AssignAllPermissions", "SCCM_AssignSpecificPermissions",
            "SCCM_Contains", "SCCM_FullAdministrator",
            "SCCM_HasADLastLogonUser", "SCCM_HasClient",
            "SCCM_HasCurrentUser", "SCCM_HasMember",
            "SCCM_HasNetworkAccessAccount", "SCCM_HasPrimaryUser",
            "SCCM_HasStoredAccount", "SCCM_IsAssigned",
            "SCCM_IsMappedTo",
        ]

        for kind in expected:
            assert kind in SEED_EDGE_KINDS, f"Missing seed edge kind: {kind}"

    def test_seed_id_is_valid(self):
        assert SEED_ID == "9c3a1f7a-1d6b-4d87-b61b-1c3b7a9e4f01"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
