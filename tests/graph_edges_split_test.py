import duckdb
from openhound_sccm.transforms import _graph_edges_split, _graph_edges_init


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.node_computer AS SELECT 'S-1-5-21-1-2-3-1104' AS sid")
    con.execute("CREATE TABLE sccm.node_user AS SELECT 'S-1-5-21-1-2-3-1110' AS sid")
    con.execute("CREATE TABLE sccm.node_group AS SELECT 'S-1-5-21-1-2-3-512' AS sid")
    con.execute("CREATE TABLE sccm.node_backfill AS SELECT 'S-1-5-21-1-2-3-9999' AS id, 'Base' AS kind")
    # Use _graph_edges_init so the schema stays current (includes Stage 6 coercion columns).
    _graph_edges_init(con, "sccm")
    con.execute(
        "INSERT INTO sccm.graph_edges (start_id, end_id, kind, collection_source) VALUES "
        "('S-1-5-21-1-2-3-1104','S-1-5-21-1-2-3-1110','HasSession', ['x']), "
        "('GUID:dev1','S-1-5-21-1-2-3-1110','SCCM_HasPrimaryUser', ['x']), "
        "('PS1','CAS','SCCM_Contains', ['x']), "
        "('PS1','S-1-5-21-1-2-3-9999','SCCM_HasStoredAccount', ['x']), "
        "('PS1','GUID:dev1','SCCM_HasClient', ['x'])"
    )


def test_split_partitions_completely_and_disjointly():
    con = duckdb.connect(":memory:")
    _seed(con)
    _graph_edges_split(con, "sccm")

    ad = {r[0] for r in con.execute(
        "SELECT start_id || '|' || end_id || '|' || kind FROM sccm.graph_edges_ad").fetchall()}
    sccm = {r[0] for r in con.execute(
        "SELECT start_id || '|' || end_id || '|' || kind FROM sccm.graph_edges_sccm").fetchall()}

    assert ad == {
        "S-1-5-21-1-2-3-1104|S-1-5-21-1-2-3-1110|HasSession",
        "GUID:dev1|S-1-5-21-1-2-3-1110|SCCM_HasPrimaryUser",
        "PS1|S-1-5-21-1-2-3-9999|SCCM_HasStoredAccount",
    }
    assert sccm == {
        "PS1|CAS|SCCM_Contains",
        "PS1|GUID:dev1|SCCM_HasClient",
    }
    assert len(ad) + len(sccm) == 5
    assert ad.isdisjoint(sccm)
