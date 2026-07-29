# src/openhound_sccm/edge_member_of_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_member_of_computer_and_user():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # computer in a group
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'WS01' AS name, "
                "'S-1-5-21-1-2-3-1104' AS sid, ['MAYYHEM\\SCCMAdmins'] AS security_group_name, false AS obsolete")
    # user in the same group
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, ['MAYYHEM\\SCCMAdmins'] AS security_group_name")
    # the group's SID (feeds principal_by_name via unique_usergroup_name)
    con.execute("CREATE TABLE sccm.adminservice_user_group AS SELECT 'S-1-5-21-1-2-3-5001' AS sid, "
                "'MAYYHEM\\SCCMAdmins' AS unique_usergroup_name, 'SCCMAdmins' AS usergroup_name, 99 AS resource_id")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='MemberOf' ORDER BY start_id").fetchall()
    assert rows == [
        ("S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-5001"),   # computer -> group
        ("S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-5001"),   # user -> group
    ]
