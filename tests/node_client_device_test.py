# src/openhound_sccm/node_client_device_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_client_device_resolved_sid_and_collections():
    """Stage 3 C4: telemetry scalars, resolved *_sid fields, collection lists."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS "
                "SELECT 'S-1-5-21-1-2-3-1200' AS sid, 'MAYYHEM\\\\alice' AS unique_user_name, "
                "5 AS resource_id, 'CAS' AS source_site_code, 'alice' AS name")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS "
                "SELECT 'GUID-1' AS smsid, 'WS01' AS name, 50 AS resource_id, 'CAS' AS site_code, "
                "true AS is_client, false AS is_obsolete, "
                "'MAYYHEM\\\\alice' AS primary_user, 'CORP' AS user_domain_name, "
                "'2026-01-02' AS ad_last_logon_time, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_collections AS "
                "SELECT 'SMS00001' AS collection_id, 'All Systems' AS name, "
                "2 AS collection_type, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS "
                "SELECT 'SMS00001' AS collection_id, 50 AS resource_id, 'CAS' AS site_code")
    transforms(con)
    r = con.execute(
        "SELECT ad_last_logon_time, ad_last_logon_user_domain, source_site_code, "
        "primary_user_sid, collection_ids, collection_names "
        "FROM sccm.node_client_device WHERE smsid='GUID-1'"
    ).fetchone()
    assert r[0] == "2026-01-02", f"ad_last_logon_time: {r[0]}"
    assert r[1] == "CORP", f"ad_last_logon_user_domain: {r[1]}"
    assert r[2] == "CAS", f"source_site_code: {r[2]}"
    assert r[3] == "S-1-5-21-1-2-3-1200", f"primary_user_sid: {r[3]}"
    assert r[4] == ["SMS00001@CAS"], f"collection_ids: {r[4]}"
    assert r[5] == ["All Systems"], f"collection_names: {r[5]}"


def test_client_device_timestamp_scalars():
    """Stage 3 C4 (matrix reclassification): last_active_time, last_online/offline_time."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1',NULL,2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS "
                "SELECT 'GUID-A' AS smsid, 'SRV01' AS name, 10 AS resource_id, 'PS1' AS site_code, "
                "true AS is_client, false AS is_obsolete, "
                # Raw columns are cn_last_online_time/cn_last_offline_time (dlt/_snake treat
                # "CN" as one token); the old c_n_* names were a typo that never matched real
                # data -- see ope-c0c0 and client_device_extras_test.py.
                "'2026-01-10' AS last_active_time, '2026-01-11' AS cn_last_online_time, "
                "'2026-01-09' AS cn_last_offline_time")
    transforms(con)
    r = con.execute(
        "SELECT last_active_time, last_online_time, last_offline_time "
        "FROM sccm.node_client_device WHERE smsid='GUID-A'"
    ).fetchone()
    assert r[0] == "2026-01-10", f"last_active_time: {r[0]}"
    assert r[1] == "2026-01-11", f"last_online_time: {r[1]}"
    assert r[2] == "2026-01-09", f"last_offline_time: {r[2]}"


def test_node_client_device_filters_and_keys_on_smsid():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT * FROM (VALUES "
                "('GUID-1','WS01', 7, 'PS1', true,  false, 'MAYYHEM\\\\alice','MAYYHEM\\\\bob','MAYYHEM\\\\carol'), "
                "('GUID-2','WS02', 8, 'PS1', false, false, NULL, NULL, NULL), "       # not a client -> dropped
                "('GUID-3','WS03', 9, 'PS1', true,  true,  NULL, NULL, NULL)) "        # obsolete -> dropped
                "AS t(smsid, name, resource_id, site_code, is_client, is_obsolete, primary_user, current_logon_user, user_name)")
    transforms(con)
    rows = con.execute("SELECT smsid, name, resource_id_str, is_confirmed_active_client FROM sccm.node_client_device ORDER BY smsid").fetchall()
    assert rows == [("GUID-1", "WS01", "7@PS1", True)]
