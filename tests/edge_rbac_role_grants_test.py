import json
# tests/edge_rbac_role_grants_test.py
import duckdb
import pytest
from openhound_sccm.transforms import transforms


def test_full_administrator_reaches_device():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'SMS00001' AS collection_id, 'All Systems' AS name, 2 AS collection_type, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
                "'All Systems' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, 50 AS resource_id, 'CAS' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT 'SMS00001' AS collection_id, 50 AS resource_id, 'CAS' AS site_code")
    con.execute("ALTER TABLE sccm.adminservice_admins ADD COLUMN permissions JSON")
    con.execute("UPDATE sccm.adminservice_admins SET permissions = ?", [json.dumps([{'RoleID': 'SMS0001R', 'CategoryID': 'SMS00001', 'CategoryTypeID': 1}])])
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges WHERE kind='SCCM_FullAdministrator'").fetchall()
    assert rows == [("MAYYHEM\\ADM@CAS", "GUID-1")]


def _seed_base(con: duckdb.DuckDBPyConnection) -> None:
    """Seed the CAS hierarchy, one admin, one Device collection, and one client device."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'SMS00001' AS collection_id, 'All Systems' AS name, 2 AS collection_type, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, 50 AS resource_id, 'CAS' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT 'SMS00001' AS collection_id, 50 AS resource_id, 'CAS' AS site_code")


@pytest.mark.parametrize("role_id, role_name, is_built_in", [
    ("ABC00099", "Custom Role", False),
    ("SMS000IR", "CMPivot Administrator", True),
])
def test_unsupported_role_produces_no_edge_and_accurate_warning(role_id, role_name, is_built_in, caplog):
    """A newer built-in and a custom role get the same accurate support warning."""
    con = duckdb.connect(":memory:")
    _seed_base(con)
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS "
                "SELECT ? AS role_id, ? AS role_name, ? AS is_built_in", [role_id, role_name, is_built_in])
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
                "'All Systems' AS collection_names, ? AS roles, NULL AS role_names", [role_id])
    con.execute("ALTER TABLE sccm.adminservice_admins ADD COLUMN permissions JSON")
    con.execute("UPDATE sccm.adminservice_admins SET permissions = ?", [json.dumps([{'RoleID': role_id, 'CategoryID': 'SMS00001', 'CategoryTypeID': 1}])])
    transforms(con)
    rows = con.execute(
        "SELECT kind FROM sccm.graph_edges WHERE "
        "kind LIKE 'SCCM_%Administrator' "
        "OR kind IN ('SCCM_ApplicationAuthor','SCCM_OSDManager','SCCM_ComplianceSettingsManager','SCCM_FullAdministrator')"
    ).fetchall()
    assert rows == []
    role_warnings = [record.getMessage() for record in caplog.records
                     if record.getMessage().startswith("edge_rbac_role_grants:")]
    assert role_warnings == [
        "edge_rbac_role_grants: 1 assigned security role(s) are not supported for "
        "device-access calculations; these may be built-in or custom roles"
    ]


def test_non_device_collection_no_edge():
    """A User collection (collection_type=1) must not produce a FullAdministrator edge."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    # collection_type=1 → User collection; the builder filters to type=2 only
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'SMS00002' AS collection_id, 'All Users' AS name, 1 AS collection_type, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-2' AS smsid, 'WS02' AS name, 51 AS resource_id, 'CAS' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT 'SMS00002' AS collection_id, 51 AS resource_id, 'CAS' AS site_code")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
                "'All Users' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names")
    con.execute("ALTER TABLE sccm.adminservice_admins ADD COLUMN permissions JSON")
    con.execute("UPDATE sccm.adminservice_admins SET permissions = ?", [json.dumps([{'RoleID': 'SMS0001R', 'CategoryID': 'SMS00002', 'CategoryTypeID': 1}])])
    transforms(con)
    rows = con.execute("SELECT kind FROM sccm.graph_edges WHERE kind='SCCM_FullAdministrator'").fetchall()
    assert rows == []


def test_role_without_collection_assignment_no_edge():
    """An admin assigned a known role but NO collection must not produce any role edge."""
    con = duckdb.connect(":memory:")
    _seed_base(con)
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    # collection_names is empty — no collection assigned to this admin
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
                "'' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names")
    con.execute("ALTER TABLE sccm.adminservice_admins ADD COLUMN permissions JSON")
    con.execute("UPDATE sccm.adminservice_admins SET permissions = ?", [json.dumps([])])
    transforms(con)
    rows = con.execute("SELECT kind FROM sccm.graph_edges WHERE kind='SCCM_FullAdministrator'").fetchall()
    assert rows == []
