# src/openhound_sccm/models/sccm_collection_test.py
from openhound_sccm.models.sccm_collection import SCCMCollection


def test_collection_as_node():
    n = SCCMCollection(collection_id="PS100016", name="All Systems", collection_type=2,
                       member_count=42, collection_variables_count=3, root_site_code="CAS").as_node
    assert n.id == "PS100016@CAS"
    assert n.kinds == ["SCCM_Collection"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.collectionID == "PS100016"
    assert n.properties.collectionType == "Device"
    assert n.properties.collectionVariablesCount == 3


def test_collection_no_id_returns_none():
    assert SCCMCollection(collection_id=None, root_site_code="CAS").as_node is None


def test_collection_scalar_parity_fields():
    """source_site_code, last_change_time, last_member_change_time mapped through to properties (CMBP parity)."""
    n = SCCMCollection(
        collection_id="SMS00001",
        name="All Systems",
        collection_type=2,
        root_site_code="CAS",
        source_site_code="CAS",
        last_change_time="2026-01-01",
        last_member_change_time="2026-01-02",
    ).as_node
    assert n.properties.sourceSiteCode == "CAS"
    assert n.properties.lastChangeTime == "2026-01-01"
    assert n.properties.lastMemberChangeTime == "2026-01-02"


def test_collection_members_on_node():
    """members list is passed through to node properties."""
    n = SCCMCollection(
        collection_id="SMS00001",
        name="All Systems",
        collection_type=2,
        root_site_code="CAS",
        members=["50@CAS", "2046820352@CAS"],
    ).as_node
    assert sorted(n.properties.members) == ["2046820352@CAS", "50@CAS"]


def test_collection_members_defaults_empty():
    """members defaults to empty list when not provided."""
    n = SCCMCollection(collection_id="PS100016", name="Test", root_site_code="CAS").as_node
    assert n.properties.members == []
