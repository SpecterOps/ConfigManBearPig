import duckdb
from openhound_sccm.transforms import transforms


def _standalone_primary(con):
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_same_host_as_both_directions_for_real_client():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'GUID:ABC' AS sms_unique_identifier, "
        "16777220 AS resource_id, 'PS1' AS source_site_code, false AS obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'GUID:ABC' AS smsid, 'HOST1' AS name, 'PS1' AS site_code, "
        "16777220 AS resource_id, true AS is_client, false AS is_obsolete"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_SameHostAs'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-1104", "GUID:ABC") in edges
    assert ("GUID:ABC", "S-1-5-21-1-2-3-1104") in edges


def test_same_host_as_for_possible_client_without_twin():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'HOST2' AS name"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_SameHostAs'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-1200", "S-1-5-21-1-2-3-1200@PS1") in edges
    assert ("S-1-5-21-1-2-3-1200@PS1", "S-1-5-21-1-2-3-1200") in edges


def test_same_host_as_collection_source_tagged():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'HOST2' AS name"
    )
    transforms(con)
    src = con.execute(
        "SELECT collection_source FROM sccm.graph_edges WHERE kind = 'SCCM_SameHostAs' LIMIT 1"
    ).fetchone()[0]
    assert src == ["SCCM_Invoke-PostProcessing"]
