# src/openhound_sccm/node_collection_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_node_collection_one_row_per_id_with_root():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4), ('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT "
                "'PS100016' AS collection_id, 'All Systems' AS name, 2 AS collection_type, "
                "42 AS member_count, false AS is_built_in, 'PS1' AS source_site_code")
    transforms(con)
    rows = con.execute("SELECT collection_id, name, member_count, root_site_code FROM sccm.node_collection").fetchall()
    assert rows == [("PS100016", "All Systems", 42, "CAS")]


def test_node_collection_scalar_fields():
    """node_collection carries source_site_code, last_change_time, last_member_change_time (CMBP parity)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT "
                "'SMS00001' AS collection_id, 'All Systems' AS name, 2 AS collection_type, "
                "'CAS' AS source_site_code, '2026-01-01' AS last_change_time, "
                "'2026-01-02' AS last_member_change_time")
    transforms(con)
    row = con.execute(
        "SELECT source_site_code, last_change_time, last_member_change_time "
        "FROM sccm.node_collection WHERE collection_id='SMS00001'"
    ).fetchone()
    assert row[0] == "CAS"
    assert row[1] == "2026-01-01"
    assert row[2] == "2026-01-02"


def test_node_collection_members_raw_keys():
    """node_collection.members holds raw ResourceID@SiteCode keys; built-ins included (CMBP ps1:7605)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT "
                "'SMS00001' AS collection_id, 'All Systems' AS name, 2 AS collection_type, "
                "'CAS' AS source_site_code, '2026-01-01' AS last_change_time")
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT * FROM "
                "(VALUES ('SMS00001', 50, 'CAS'), ('SMS00001', 2046820352, 'CAS')) "
                "AS t(collection_id, resource_id, site_code)")
    transforms(con)
    row = con.execute(
        "SELECT source_site_code, last_change_time, members "
        "FROM sccm.node_collection WHERE collection_id='SMS00001'"
    ).fetchone()
    assert row[0] == "CAS" and row[1] == "2026-01-01"
    # Raw keys — built-in resource id 2046820352 must appear
    assert sorted(row[2]) == ["2046820352@CAS", "50@CAS"]
