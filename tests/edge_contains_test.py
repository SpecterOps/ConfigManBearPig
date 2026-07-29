# tests/edge_contains_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_contains_site_to_globals():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'PS100016' AS collection_id, 'All Systems' AS name, 2 AS collection_type, 'PS1' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT 'MAYYHEM\\\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges WHERE kind='SCCM_Contains' ORDER BY start_id, end_id").fetchall()
    # CAS + PS1 (non-secondary) each contain the collection, the role, and the admin user; SEC (secondary) contains nothing.
    assert ("CAS", "PS100016@CAS") in rows
    assert ("PS1", "SMS0001R@CAS") in rows
    assert ("CAS", "MAYYHEM\\\\ADM@CAS") in rows
    assert not any(start == "SEC" for start, _ in rows)
