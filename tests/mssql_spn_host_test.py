"""Task 1c: MSSQLSvc-SPN hosts reach the graph even when TCP/1433 is filtered.

D2(a): an MSSQLSvc SPN is AD-readable proof a host runs SQL Server, so it must get
a Computer node whether or not port 1433 answered. Running SQL is NOT an SCCM role
(sccm_infra stays false, no roles) -- a real SCCM role, if any, arrives from another
_node_computer arm and merges on sid. The MSSQL_HostFor / MSSQL_ExecuteOnHost edges
follow the same resolve-or-drop convention _edge_mssql_service_account already uses:
no Computer node, no edge (never a dangling reference).
"""
import duckdb

from openhound_sccm.transforms import _edge_mssql_structural, _graph_edges_init, _node_computer

SCHEMA = "sccm"


def _con():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.mssql_server_instances "
                "(domain_computer_sid VARCHAR, name VARCHAR, port INTEGER, "
                " has_mssql_spn BOOLEAN, port_open BOOLEAN)")
    con.execute(f"INSERT INTO {SCHEMA}.mssql_server_instances "
                "VALUES ('S-1-DB','ps1-db.mayyhem.com',1433,true,false)")
    return con


def test_spn_host_becomes_a_computer_node_even_with_1433_filtered():
    con = _con()
    _node_computer(con, SCHEMA)
    row = con.execute(f"SELECT sid, sccm_infra, site_system_roles FROM {SCHEMA}.node_computer "
                      f"WHERE sid = 'S-1-DB'").fetchone()
    # D2b (reviewer M4): both halves of "not thereby SCCM infrastructure" must hold --
    # the SPN proves it runs SQL, but that is NOT an SCCM role, so sccm_infra stays
    # false AND no role string (bare or "@site") gets attached either.
    assert row is not None and row[1] is False and row[2] == []


def test_host_edges_do_not_dangle():
    con = _con()
    _node_computer(con, SCHEMA)
    con.execute(f"CREATE TABLE {SCHEMA}.node_mssql_server "
                "(server_id VARCHAR, host_sid VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES ('S-1-DB:1433','S-1-DB')")
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES ('S-1-GHOST:1433','S-1-GHOST')")
    # _edge_mssql_structural INSERTs into graph_edges, which the transforms() pipeline
    # creates once via _graph_edges_init before any edge builder runs. Called directly
    # here (deviation from the brief's snippet, which omits it -- without it the table
    # never exists and the SELECT below raises a DuckDB CatalogException).
    _graph_edges_init(con, SCHEMA)
    _edge_mssql_structural(con, SCHEMA)
    ends = {(s, e) for s, e in con.execute(
        f"SELECT start_id, end_id FROM {SCHEMA}.graph_edges "
        f"WHERE kind IN ('MSSQL_HostFor','MSSQL_ExecuteOnHost')").fetchall()}
    assert ("S-1-DB", "S-1-DB:1433") in ends          # resolved host -> edges
    assert not any("S-1-GHOST" in pair for pair in ends)   # unresolved -> dropped, not dangling


def test_host_edges_uppercase_the_endpoint_to_match_the_guard():
    # BREAK-1: the resolve-or-drop guard matches nc.sid = upper(host_sid), so the
    # emitted endpoint must ALSO be upper(host_sid) -- a feeder yielding a
    # differently-cased host_sid ('s-1-db') would otherwise pass the guard (since
    # upper('s-1-db') = 'S-1-DB' does match node_computer.sid) but then emit the
    # RAW lowercase host_sid as the edge endpoint, which resolves to no
    # node_computer row at all -- a dangling edge, exactly what resolve-or-drop
    # exists to prevent.
    con = _con()
    _node_computer(con, SCHEMA)
    con.execute(f"CREATE TABLE {SCHEMA}.node_mssql_server "
                "(server_id VARCHAR, host_sid VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES ('S-1-DB:1433','s-1-db')")
    _graph_edges_init(con, SCHEMA)
    _edge_mssql_structural(con, SCHEMA)
    ends = {(s, e) for s, e in con.execute(
        f"SELECT start_id, end_id FROM {SCHEMA}.graph_edges "
        f"WHERE kind IN ('MSSQL_HostFor','MSSQL_ExecuteOnHost')").fetchall()}
    assert ("S-1-DB", "S-1-DB:1433") in ends
    assert ("S-1-DB:1433", "S-1-DB") in ends
    assert not any("s-1-db" in pair for pair in ends)   # never the raw lowercase form
