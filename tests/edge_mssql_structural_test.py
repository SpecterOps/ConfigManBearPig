import duckdb
from openhound_sccm.transforms import transforms


def _ps1_with_sql(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )


def _edges(con, kind):
    return con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = ?", [kind]
    ).fetchall()


def test_structural_edges():
    con = duckdb.connect(":memory:")
    _ps1_with_sql(con)
    transforms(con)
    srv = "S-1-5-21-1-2-3-1200:1433"
    db = srv + "\\CM_PS1"
    assert (srv, "sysadmin@" + srv) in _edges(con, "MSSQL_Contains")
    assert ("sysadmin@" + srv, srv) in _edges(con, "MSSQL_ControlServer")
    assert ("S-1-5-21-1-2-3-1200", srv) in _edges(con, "MSSQL_HostFor")       # host computer -> server
    assert (srv, "S-1-5-21-1-2-3-1200") in _edges(con, "MSSQL_ExecuteOnHost")
    assert (srv, db) in _edges(con, "MSSQL_Contains")
    assert (db, "db_owner@" + db) in _edges(con, "MSSQL_Contains")
    assert ("db_owner@" + db, db) in _edges(con, "MSSQL_ControlDB")


def test_db_assign_all_permissions_to_site():
    con = duckdb.connect(":memory:")
    _ps1_with_sql(con)
    transforms(con)
    db = "S-1-5-21-1-2-3-1200:1433\\CM_PS1"
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_AssignAllPermissions' AND start_id = ?",
        [db],
    ).fetchall()
    assert (db, "PS1") in edges   # PS1 is a Primary (non-secondary) site


def test_mssql_edges_route_to_correct_split_table():
    con = duckdb.connect(":memory:")
    _ps1_with_sql(con)
    transforms(con)   # runs _graph_edges_split last
    srv = "S-1-5-21-1-2-3-1200:1433"
    # MSSQL_HostFor (host Computer SID -> server) touches an AD node -> AD payload.
    ad = con.execute(
        "SELECT count(*) FROM sccm.graph_edges_ad WHERE kind = 'MSSQL_HostFor' AND start_id = ?",
        ["S-1-5-21-1-2-3-1200"],
    ).fetchone()[0]
    assert ad == 1
    # MSSQL_Contains (server -> sysadmin role) is pure-MSSQL -> SCCM payload.
    sccm = con.execute(
        "SELECT count(*) FROM sccm.graph_edges_sccm WHERE kind = 'MSSQL_Contains' AND start_id = ?",
        [srv],
    ).fetchone()[0]
    assert sccm >= 1
