# src/openhound_sccm/edge_has_client_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_has_client():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id, kind FROM sccm.graph_edges "
                       "WHERE kind='SCCM_HasClient' ORDER BY end_id").fetchall()
    assert rows == [("PS1", "GUID-1", "SCCM_HasClient")]
