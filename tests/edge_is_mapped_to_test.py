# src/openhound_sccm/edge_is_mapped_to_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_is_mapped_to_direct_sid_and_name_resolution():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    # admin 1: has admin_sid directly. admin 2: name-only, resolved via principal_by_name.
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\sccmadmin','S-1-5-21-1-2-3-1110', false), "
                "('MAYYHEM\\helpdesk', NULL,               true)) "
                "AS t(logon_name, admin_sid, is_group)")
    # provides (name, sid) for the name-only admin via principal_by_name unique_user_name enrichment
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'helpdesk' AS name, "
                "'S-1-5-21-1-2-3-1200' AS sid, 'MAYYHEM\\helpdesk' AS unique_user_name")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_IsMappedTo' ORDER BY end_id").fetchall()
    assert rows == [
        ("S-1-5-21-1-2-3-1200", "MAYYHEM\\HELPDESK@CAS"),   # name-only -> resolved SID
        ("S-1-5-21-1-2-3-1110", "MAYYHEM\\SCCMADMIN@CAS"),   # direct admin_sid
    ]
