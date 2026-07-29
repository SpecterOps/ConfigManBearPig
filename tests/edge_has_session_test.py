# src/openhound_sccm/edge_has_session_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_has_session_registry_and_mssql():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # RemoteRegistry arm: host -> logged-on user
    con.execute("CREATE TABLE sccm.remoteregistry_users AS SELECT "
                "'S-1-5-21-1-2-3-1106' AS object_sid, 'S-1-5-21-1-2-3-1104' AS host_object_sid")
    # MSSQL arm: a node_computer for SQL01 (from r_system), a domain svc account, and a local account (excluded)
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'SQL01' AS name, "
                "'S-1-5-21-1-2-3-1200' AS sid, false AS obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'svc_sql' AS name, "
                "'S-1-5-21-1-2-3-1300' AS sid, 'MAYYHEM\\svc_sql' AS unique_user_name")
    con.execute("CREATE TABLE sccm.adminservice_site_systems AS SELECT * FROM (VALUES "
                "('\\\\SQL01.lab', 'MAYYHEM\\svc_sql'), "
                "('\\\\SQL01.lab', 'NT AUTHORITY\\SYSTEM')) "
                "AS t(network_os_path, sql_server_service_logon_account)")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='HasSession' ORDER BY start_id, end_id").fetchall()
    assert rows == [
        ("S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1106"),   # RemoteRegistry: host -> user
        ("S-1-5-21-1-2-3-1200", "S-1-5-21-1-2-3-1300"),   # MSSQL: SQL01 host -> svc account
    ]
    # the NT AUTHORITY\SYSTEM local account produced no edge
