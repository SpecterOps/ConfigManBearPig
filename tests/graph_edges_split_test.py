import duckdb
from openhound_sccm.transforms import _graph_edges_split, _graph_edges_init


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.node_computer AS SELECT 'S-1-5-21-1-2-3-1104' AS sid")
    con.execute("CREATE TABLE sccm.node_user AS SELECT 'S-1-5-21-1-2-3-1110' AS sid")
    con.execute("CREATE TABLE sccm.node_group AS SELECT 'S-1-5-21-1-2-3-512' AS sid")
    con.execute("CREATE TABLE sccm.node_backfill AS SELECT 'S-1-5-21-1-2-3-9999' AS id, 'Base' AS kind")
    # Six MSSQL node tables: _graph_edges_split now unions their id columns into _mssql_ids,
    # so every one must exist (empty is fine) or DuckDB raises on the missing table.
    con.execute("CREATE TABLE sccm.node_mssql_server AS SELECT 'S-1-DB:1433' AS server_id")
    con.execute(r"CREATE TABLE sccm.node_mssql_database AS SELECT 'S-1-DB:1433\CM_PS1' AS database_id")
    con.execute("CREATE TABLE sccm.node_mssql_login AS SELECT NULL::VARCHAR AS login_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_database_user AS SELECT NULL::VARCHAR AS dbuser_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_server_role AS SELECT 'sysadmin@S-1-DB:1433' AS role_id")
    con.execute("CREATE TABLE sccm.node_mssql_database_role AS SELECT NULL::VARCHAR AS role_id WHERE false")
    # Use _graph_edges_init so the schema stays current (includes the coercion columns).
    _graph_edges_init(con, "sccm")
    con.execute(
        "INSERT INTO sccm.graph_edges (start_id, end_id, kind, collection_source) VALUES "
        # AD<->AD
        "('S-1-5-21-1-2-3-1104','S-1-5-21-1-2-3-1110','HasSession', ['x']), "
        # AD<->SCCM (end is a user) -> AD payload
        "('GUID:dev1','S-1-5-21-1-2-3-1110','SCCM_HasPrimaryUser', ['x']), "
        # SCCM<->SCCM
        "('PS1','CAS','SCCM_Contains', ['x']), "
        # SCCM<->stub (backfill = AD) -> AD payload
        "('PS1','S-1-5-21-1-2-3-9999','SCCM_HasStoredAccount', ['x']), "
        # SCCM<->SCCM (neither is AD)
        "('PS1','GUID:dev1','SCCM_HasClient', ['x']), "
        # AD<->MSSQL: host computer -> server. start is AD -> AD payload (stays untagged)
        "('S-1-5-21-1-2-3-1104','S-1-DB:1433','MSSQL_HostFor', ['x']), "
        # MSSQL<->MSSQL: server -> its sysadmin role. both MSSQL -> MSSQL payload
        "('S-1-DB:1433','sysadmin@S-1-DB:1433','MSSQL_Contains', ['x']), "
        # MSSQL<->SCCM: database -> site. one SCCM endpoint, no AD -> SCCM payload
        r"('S-1-DB:1433\CM_PS1','PS1','SCCM_AssignAllPermissions', ['x'])"
    )


def test_split_partitions_completely_and_disjointly():
    con = duckdb.connect(":memory:")
    _seed(con)
    _graph_edges_split(con, "sccm")

    def _rows(table):
        return {r[0] for r in con.execute(
            f"SELECT start_id || '|' || end_id || '|' || kind FROM sccm.{table}").fetchall()}

    ad = _rows("graph_edges_ad")
    mssql = _rows("graph_edges_mssql")
    sccm = _rows("graph_edges_sccm")

    assert ad == {
        "S-1-5-21-1-2-3-1104|S-1-5-21-1-2-3-1110|HasSession",
        "GUID:dev1|S-1-5-21-1-2-3-1110|SCCM_HasPrimaryUser",
        "PS1|S-1-5-21-1-2-3-9999|SCCM_HasStoredAccount",
        "S-1-5-21-1-2-3-1104|S-1-DB:1433|MSSQL_HostFor",
    }
    assert mssql == {
        "S-1-DB:1433|sysadmin@S-1-DB:1433|MSSQL_Contains",
    }
    assert sccm == {
        "PS1|CAS|SCCM_Contains",
        "PS1|GUID:dev1|SCCM_HasClient",
        r"S-1-DB:1433\CM_PS1|PS1|SCCM_AssignAllPermissions",
    }
    # Complete + disjoint partition of the 8 original edges.
    assert len(ad) + len(mssql) + len(sccm) == 8
    assert ad.isdisjoint(mssql) and ad.isdisjoint(sccm) and mssql.isdisjoint(sccm)
