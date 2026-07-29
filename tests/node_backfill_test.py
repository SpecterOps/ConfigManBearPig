# src/openhound_sccm/node_backfill_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_node_backfill_synthesizes_missing_endpoint():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    # device whose primary_user resolves (via principal_by_name) to a SID that is in NO node table
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete, "
                "'MAYYHEM\\ghost' AS primary_user")
    # user_group feeds principal_by_name['MAYYHEM\\ghost']=9999 but, being unreferenced by any
    # security_group_name, does NOT become a node_group -> the HasPrimaryUser end is nodeless.
    con.execute("CREATE TABLE sccm.adminservice_user_group AS SELECT 'S-1-5-21-1-2-3-9999' AS sid, "
                "'MAYYHEM\\ghost' AS unique_usergroup_name, 'ghost' AS usergroup_name, 50 AS resource_id")
    transforms(con)
    rows = con.execute("SELECT id, kind FROM sccm.node_backfill WHERE id='S-1-5-21-1-2-3-9999'").fetchall()
    assert rows == [("S-1-5-21-1-2-3-9999", "User")]   # kind inferred from HasPrimaryUser end
    # it really was nodeless:
    assert con.execute("SELECT count(*) FROM sccm.node_group WHERE sid='S-1-5-21-1-2-3-9999'").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM sccm.node_user WHERE sid='S-1-5-21-1-2-3-9999'").fetchone()[0] == 0
