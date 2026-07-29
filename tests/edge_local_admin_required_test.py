import duckdb
from openhound_sccm.transforms import transforms


def test_site_server_is_local_admin_on_other_site_systems():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-100', 'SITESRV', '[\"SMS Site Server@PS1\"]', true), "
        "('S-1-5-21-1-2-3-200', 'MP', '[\"SMS Management Point@PS1\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_LocalAdminRequired'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-200") in edges      # site server -> MP
    assert ("S-1-5-21-1-2-3-200", "S-1-5-21-1-2-3-100") not in edges  # MP is NOT admin on the server
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-100") not in edges  # no self-edge


def test_no_local_admin_required_for_secondary_site():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2), ('SEC', 'PS1', 1)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-300', 'SECSRV', '[\"SMS Site Server@SEC\"]', true), "
        "('S-1-5-21-1-2-3-400', 'SECDP', '[\"SMS Distribution Point@SEC\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    n = con.execute(
        "SELECT count(*) FROM sccm.graph_edges WHERE kind = 'SCCM_LocalAdminRequired'"
    ).fetchone()[0]
    assert n == 0


def test_multiple_site_servers_are_mutually_local_admin():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-100', 'SRV1', '[\"SMS Site Server@PS1\"]', true), "
        "('S-1-5-21-1-2-3-101', 'SRV2', '[\"SMS Site Server@PS1\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_LocalAdminRequired'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-101") in edges
    assert ("S-1-5-21-1-2-3-101", "S-1-5-21-1-2-3-100") in edges
