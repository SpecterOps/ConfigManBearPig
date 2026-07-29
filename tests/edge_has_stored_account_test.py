# src/openhound_sccm/edge_has_stored_account_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_has_stored_account():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_reserved_accounts AS SELECT "
                "'S-1-5-21-1-2-3-1500' AS object_sid, 'PS1' AS site_code, 'naa' AS name")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_HasStoredAccount' ORDER BY end_id").fetchall()
    assert rows == [("PS1", "S-1-5-21-1-2-3-1500")]
