# src/openhound_sccm/models/sccm_security_role_test.py
from openhound_sccm.models.sccm_security_role import SCCMSecurityRole


def test_security_role_as_node():
    n = SCCMSecurityRole(role_id="SMS000AR", role_name="Full Administrator",
                         root_site_code="CAS", is_built_in=True).as_node
    assert n.id == "SMS000AR@CAS"
    assert n.kinds == ["SCCM_SecurityRole"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.roleName == "Full Administrator"


def test_security_role_no_id_returns_none():
    assert SCCMSecurityRole(role_id=None, root_site_code="CAS").as_node is None


def test_security_role_audit_scalars_round_trip():
    """Audit scalars from node_security_role survive the model -> node conversion."""
    n = SCCMSecurityRole(
        role_id="SMS0001R",
        role_name="Full Administrator",
        root_site_code="CAS",
        site_code="CAS",
        created_by="admin@x",
        created_date="2024-01-01",
        last_modified_by="mod@x",
        last_modified_date="2024-06-01",
    ).as_node
    assert n is not None
    assert n.properties.siteCode == "CAS"
    assert n.properties.createdBy == "admin@x"
    assert n.properties.createdDate == "2024-01-01"
    assert n.properties.lastModifiedBy == "mod@x"
    assert n.properties.lastModifiedDate == "2024-06-01"


def test_security_role_members_round_trip():
    """members list survives the model -> node conversion."""
    # Use raw string to be unambiguous: one backslash in each member id.
    n = SCCMSecurityRole(
        role_id="SMS0001R",
        role_name="Full Administrator",
        root_site_code="CAS",
        members=[r"MAYYHEM\ADM@CAS", r"MAYYHEM\READER@CAS"],
    ).as_node
    assert n is not None
    assert n.properties.members == [r"MAYYHEM\ADM@CAS", r"MAYYHEM\READER@CAS"]


def test_security_role_members_default_empty():
    """members defaults to [] when not provided."""
    n = SCCMSecurityRole(role_id="SMS000AR", role_name="OSD Manager", root_site_code="CAS").as_node
    assert n is not None
    assert n.properties.members == []
