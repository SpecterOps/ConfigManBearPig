import duckdb

from openhound_sccm.transforms import _graph_edges_init, _graph_edges_dedup, _graph_edges_split


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _graph_edges_init(con, "sccm")
    # Two duplicate relay rows for the same (start,kind,end) with different pairs:
    # dedup must array-union them (mirrors CMBP Upsert-Edge merge).
    # Trailing NULLs on each row are sccm_infra/assumed/assumption_basis (unrelated
    # to this test; only SCCM_IsMappedTo populates sccm_infra -- see
    # edge_is_mapped_to_sccminfra_test.py -- and no builder here stamps assumed).
    con.execute(
        "INSERT INTO sccm.graph_edges VALUES "
        "('MAYYHEM.COM-S-1-5-11','PS1','SCCM_CoerceAndRelayToAdminService',"
        " ['Post-processing'], ['Coerce A, relay to X'], NULL, NULL, NULL, NULL),"
        "('MAYYHEM.COM-S-1-5-11','PS1','SCCM_CoerceAndRelayToAdminService',"
        " ['Post-processing'], ['Coerce B, relay to X'], NULL, NULL, NULL, NULL),"
        # A non-relay edge with NULL coercion columns must survive as empty lists.
        "('PS1','C1','SCCM_Contains', ['SCCM_Invoke-PostProcessing'], NULL, NULL, NULL, NULL, NULL)"
    )


def test_dedup_unions_coercion_pairs_and_handles_nulls():
    con = duckdb.connect()
    _seed(con)
    _graph_edges_dedup(con, "sccm")
    rows = con.execute(
        "SELECT kind, list_sort(coercion_victim_and_relay_target_pairs), coercion_victim_hostnames "
        "FROM sccm.graph_edges WHERE kind = 'SCCM_CoerceAndRelayToAdminService'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][1] == ["Coerce A, relay to X", "Coerce B, relay to X"]
    assert rows[0][2] == []  # NULL -> []
    nonrelay = con.execute(
        "SELECT coercion_victim_and_relay_target_pairs, coercion_victim_hostnames "
        "FROM sccm.graph_edges WHERE kind = 'SCCM_Contains'"
    ).fetchone()
    assert nonrelay == ([], [])  # NULL coalesced to [] for non-relay rows too


def test_split_carries_coercion_columns_to_ad_payload():
    con = duckdb.connect()
    _seed(con)
    _graph_edges_dedup(con, "sccm")
    # Minimal node tables so the AuthUsers start id lands in the AD id set.
    con.execute("CREATE TABLE sccm.node_computer AS SELECT NULL::VARCHAR AS sid WHERE false")
    con.execute("CREATE TABLE sccm.node_user AS SELECT NULL::VARCHAR AS sid WHERE false")
    con.execute(
        "CREATE TABLE sccm.node_group AS SELECT 'MAYYHEM.COM-S-1-5-11'::VARCHAR AS sid"
    )
    con.execute("CREATE TABLE sccm.node_backfill AS SELECT NULL::VARCHAR AS id WHERE false")
    # _graph_edges_split now unions the six MSSQL node id columns into _mssql_ids;
    # create them empty so the split does not error (no edge here is both-MSSQL).
    con.execute("CREATE TABLE sccm.node_mssql_server AS SELECT NULL::VARCHAR AS server_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_database AS SELECT NULL::VARCHAR AS database_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_login AS SELECT NULL::VARCHAR AS login_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_database_user AS SELECT NULL::VARCHAR AS dbuser_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_server_role AS SELECT NULL::VARCHAR AS role_id WHERE false")
    con.execute("CREATE TABLE sccm.node_mssql_database_role AS SELECT NULL::VARCHAR AS role_id WHERE false")
    _graph_edges_split(con, "sccm")
    ad_cols = [d[0] for d in con.execute("DESCRIBE sccm.graph_edges_ad").fetchall()]
    assert "coercion_victim_and_relay_target_pairs" in ad_cols
    assert "coercion_victim_hostnames" in ad_cols
    sccm_cols = [d[0] for d in con.execute("DESCRIBE sccm.graph_edges_sccm").fetchall()]
    assert "coercion_victim_and_relay_target_pairs" in sccm_cols
    assert "coercion_victim_hostnames" in sccm_cols
    mssql_cols = [d[0] for d in con.execute("DESCRIBE sccm.graph_edges_mssql").fetchall()]
    assert "coercion_victim_and_relay_target_pairs" in mssql_cols
    assert "coercion_victim_hostnames" in mssql_cols
    # The AdminService relay (AuthUsers start) is AD-routed.
    ad_kinds = [r[0] for r in con.execute("SELECT kind FROM sccm.graph_edges_ad").fetchall()]
    assert "SCCM_CoerceAndRelayToAdminService" in ad_kinds
