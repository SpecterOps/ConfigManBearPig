# src/openhound_sccm/edge_has_user_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_has_user_three_kinds():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete, "
                "'MAYYHEM\\alice' AS primary_user, 'MAYYHEM\\bob' AS current_logon_user, "
                "'MAYYHEM\\carol' AS user_name")
    # principal_by_name gets these via the C1 unique_user_name enrichment
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT * FROM (VALUES "
                "('alice','S-1-5-21-1-2-3-1201','MAYYHEM\\alice'), "
                "('bob',  'S-1-5-21-1-2-3-1202','MAYYHEM\\bob'), "
                "('carol','S-1-5-21-1-2-3-1203','MAYYHEM\\carol')) AS t(name, sid, unique_user_name)")
    transforms(con)
    rows = con.execute("SELECT kind, start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind LIKE 'SCCM_Has%User' ORDER BY kind").fetchall()
    assert rows == [
        ("SCCM_HasADLastLogonUser", "GUID-1", "S-1-5-21-1-2-3-1203"),
        ("SCCM_HasCurrentUser",     "GUID-1", "S-1-5-21-1-2-3-1202"),
        ("SCCM_HasPrimaryUser",     "GUID-1", "S-1-5-21-1-2-3-1201"),
    ]
