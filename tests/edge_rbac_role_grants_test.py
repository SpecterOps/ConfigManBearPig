# tests/edge_rbac_role_grants_test.py
import duckdb
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


def test_custom_role_produces_no_edge():
    """A custom role id (not in the known map) must not produce any role edge."""
    con = duckdb.connect(":memory:")
    _seed_base(con)
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'ABC00099' AS role_id, 'Custom Role' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
                "'All Systems' AS collection_names, 'ABC00099' AS roles, NULL AS role_names")
    transforms(con)
    rows = con.execute(
        "SELECT kind FROM sccm.graph_edges WHERE "
        "kind LIKE 'SCCM_%Administrator' "
        "OR kind IN ('SCCM_ApplicationAuthor','SCCM_OSDManager','SCCM_ComplianceSettingsManager','SCCM_FullAdministrator')"
    ).fetchall()
    assert rows == []


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
    transforms(con)
    rows = con.execute("SELECT kind FROM sccm.graph_edges WHERE kind='SCCM_FullAdministrator'").fetchall()
    assert rows == []
