# src/openhound_sccm/models/sccm_admin_user_test.py
from openhound_sccm.models.sccm_admin_user import SCCMAdminUser


def test_admin_user_as_node():
    n = SCCMAdminUser(logon_name="MAYYHEM\\sccmadmin", admin_sid="S-1-5-21-1-2-3-1110",
                      is_group=False, root_site_code="CAS").as_node
    assert n.id == "MAYYHEM\\SCCMADMIN@CAS"      # id uppercases logon_name
    assert n.kinds == ["SCCM_AdminUser"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.isGroup is False


def test_admin_user_no_logon_returns_none():
    assert SCCMAdminUser(logon_name=None, root_site_code="CAS").as_node is None


def test_admin_user_audit_scalars_on_node():
    """Audit scalar fields are exposed on the node properties."""
    n = SCCMAdminUser(
        logon_name="MAYYHEM\\adm",
        admin_sid="S-1-5-21-1-2-3-1110",
        is_group=False,
        root_site_code="CAS",
        display_name="adm disp",
        source_site_code="CAS",
        created_by="admin@x",
        created_date="2024-01-01",
        last_modified_by="mod@x",
        last_modified_date="2024-06-01",
    ).as_node
    assert n.properties.displayName == "adm disp"
    assert n.properties.sourceSiteCode == "CAS"
    assert n.properties.createdBy == "admin@x"
    assert n.properties.createdDate == "2024-01-01"
    assert n.properties.lastModifiedBy == "mod@x"
    assert n.properties.lastModifiedDate == "2024-06-01"


def test_admin_user_list_fields_on_node():
    """List fields (collection_ids, role_ids, member_of) are exposed on node properties."""
    n = SCCMAdminUser(
        logon_name="MAYYHEM\\adm",
        root_site_code="CAS",
        collection_ids=["SMS00001@CAS"],
        role_ids=["SMS0001R"],
        member_of=["SMS0001R@CAS"],
    ).as_node
    assert n.properties.collectionIds == ["SMS00001@CAS"]
    assert n.properties.roleIDs == ["SMS0001R"]
    assert n.properties.memberOf == ["SMS0001R@CAS"]


def test_admin_user_list_fields_default_empty():
    """List fields default to empty lists when not provided."""
    n = SCCMAdminUser(logon_name="MAYYHEM\\adm", root_site_code="CAS").as_node
    assert n.properties.collectionIds == []
    assert n.properties.roleIDs == []
    assert n.properties.memberOf == []


def test_admin_user_no_displayname_displayName_case_collision():
    """Admin-user nodes must NOT carry both `displayName` and `displayname`.

    The two differ only by case, so a case-insensitive consumer (BloodHound/Neo4j
    ingestion, or the PowerShell unit-test kit's ConvertFrom-Json) treats them as one
    duplicate key and rejects the whole payload. CMBP emits only the camelCase key, so
    the port drops the framework base lowercase `displayname` on admin-user nodes.
    """
    from dataclasses import asdict

    # display_name set: camelCase kept, base lowercase suppressed -> no collision.
    n = SCCMAdminUser(logon_name="MAYYHEM\\adm", root_site_code="CAS",
                      display_name="Adm Disp").as_node
    props = asdict(n.properties)
    assert props["displayName"] == "Adm Disp"
    assert props["displayname"] is None  # pruned on emit; absent from output JSON
    populated = [k for k, v in props.items() if k.lower() == "displayname" and v is not None]
    assert populated == ["displayName"], f"case-collision on display name: {populated}"

    # display_name empty: camelCase also None (CMBP omits empty), so neither key emits.
    n2 = SCCMAdminUser(logon_name="MAYYHEM\\adm", root_site_code="CAS",
                       display_name="").as_node
    props2 = asdict(n2.properties)
    assert props2["displayName"] is None
    assert props2["displayname"] is None
