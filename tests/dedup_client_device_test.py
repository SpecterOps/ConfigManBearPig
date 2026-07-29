import duckdb
from openhound_sccm.transforms import transforms


def _standalone_primary(con):
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_real_and_possible_twin_merge_to_real():
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
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'HOST1' AS name"
    )
    transforms(con)
    rows = con.execute(
        "SELECT smsid, is_confirmed_active_client FROM sccm.node_client_device "
        "WHERE ad_domain_sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "GUID:ABC"
    assert rows[0][1] is True


def test_null_ad_domain_sid_rows_are_kept_independently():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT * FROM (VALUES "
        "('GUID:AAA', 'HOSTA', 'PS1', 1, true, false), "
        "('GUID:BBB', 'HOSTB', 'PS1', 2, true, false)"
        ") AS t(smsid, name, site_code, resource_id, is_client, is_obsolete)"
    )
    transforms(con)
    n = con.execute(
        "SELECT count(*) FROM sccm.node_client_device WHERE ad_domain_sid IS NULL"
    ).fetchone()[0]
    assert n == 2


def test_collection_arrays_union_into_survivor():
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
    con.execute(
        "CREATE TABLE sccm.adminservice_collections AS SELECT "
        "'PS100001' AS collection_id, 'All Desktops' AS name"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_collection_members AS SELECT "
        "'PS100001' AS collection_id, 16777220 AS resource_id, 'PS1' AS site_code"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'HOST1' AS name"
    )
    transforms(con)
    coll = con.execute(
        "SELECT collection_ids FROM sccm.node_client_device "
        "WHERE ad_domain_sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchone()[0]
    assert "PS100001@PS1" in coll
