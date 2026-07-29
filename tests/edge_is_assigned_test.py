# src/openhound_sccm/edge_is_assigned_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_is_assigned_collection_and_role_with_name_fallback():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'PS100016' AS collection_id, 'All Systems' AS name")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT * FROM (VALUES "
                "('SMS000AR','Full Administrator'), ('SMS0001R','Read-only Analyst')) AS t(role_id, role_name)")
    # admin1: collection + role via the role-id list.
    #   collection_names / role_names arrive as JSON-array text from the AdminService
    #   collector (e.g. '["All Systems"]'), matching real-data shape.
    # admin2: no roles list -> role assigned via role_names name fallback.
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\a1', '[\"All Systems\"]', '[\"SMS000AR\"]', '[\"Full Administrator\"]'), "
                "('MAYYHEM\\a2', NULL,                NULL,            '[\"Read-only Analyst\"]')) "
                "AS t(logon_name, collection_names, roles, role_names)")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_IsAssigned' ORDER BY start_id, end_id").fetchall()
    assert rows == [
        ("MAYYHEM\\A1@CAS", "PS100016@CAS"),   # collection
        ("MAYYHEM\\A1@CAS", "SMS000AR@CAS"),   # role via id list
        ("MAYYHEM\\A2@CAS", "SMS0001R@CAS"),   # role via name fallback (roles empty)
    ]
