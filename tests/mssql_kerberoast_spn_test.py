# src/openhound_sccm/transforms_test (Task 14): MSSQL_GetTGS + MSSQL_GetAdminTGS from
# the SPN-resolved service account (Task 13) to Task 4's site-server/provider
# sysadmin logins (node_mssql_login). Every node_mssql_login row is, by
# construction, a domain sysadmin login (see transforms._node_mssql_login), so
# "a login exists for this server" already means "a domain principal is
# sysadmin" -- no is_domain/is_sysadmin columns are needed on node_mssql_login
# for this builder (unlike the plan's illustrative test schema).
import duckdb

from openhound_sccm.kinds.edges import MSSQL_GET_ADMIN_TGS, MSSQL_GET_TGS
from openhound_sccm.transforms import _edge_mssql_kerberoast_spn, _graph_edges_init

SCHEMA = "sccm"


def _con():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_mssql_server "
        "(server_id VARCHAR, service_account_sid VARCHAR)"
    )
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES ('S-1-DB:1433','S-1-SVC')")
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_mssql_login "
        "(login_id VARCHAR, server_id VARCHAR, assumed BOOLEAN, "
        " assumption_basis VARCHAR, collection_source VARCHAR[])"
    )
    _graph_edges_init(con, SCHEMA)
    return con


def _login(con, assumed):
    con.execute(
        f"INSERT INTO {SCHEMA}.node_mssql_login VALUES "
        "('S-1-PSS$@S-1-DB:1433', 'S-1-DB:1433', ?, ?, ?)",
        [assumed, "SPN+SCCM site database" if assumed else None,
         ["LDAP-MSSQLSvcSPN"] if assumed else ["RemoteRegistry-SiteSystemRole"]],
    )


def test_getadmin_and_gettgs_built_from_a_site_server_login():
    con = _con()
    _login(con, assumed=True)
    _edge_mssql_kerberoast_spn(con, SCHEMA)
    got = {
        (k, s, e) for s, e, k in con.execute(
            f"SELECT start_id, end_id, kind FROM {SCHEMA}.graph_edges "
            f"WHERE kind IN ('{MSSQL_GET_ADMIN_TGS}', '{MSSQL_GET_TGS}')"
        ).fetchall()
    }
    assert (MSSQL_GET_ADMIN_TGS, "S-1-SVC", "S-1-DB:1433") in got
    assert (MSSQL_GET_TGS, "S-1-SVC", "S-1-PSS$@S-1-DB:1433") in got


def test_edge_inherits_the_confidence_of_its_login():
    # Login off a confirmed site DB -> confirmed edge. _site_db_provenance_cols
    # (Task 4) stores an explicit False (not NULL) for a confirmed row; GraphEdge's
    # model layer prunes `assumed or None` before emit, so this still renders as
    # "no stamp" in the final OpenGraph output -- see models/graph_edge.py.
    con = _con()
    _login(con, assumed=False)
    _edge_mssql_kerberoast_spn(con, SCHEMA)
    assert con.execute(f"SELECT DISTINCT assumed FROM {SCHEMA}.graph_edges").fetchone()[0] is False

    # Login off an SPN+SCCM site DB -> assumed edge, stamped.
    con2 = _con()
    _login(con2, assumed=True)
    _edge_mssql_kerberoast_spn(con2, SCHEMA)
    assert con2.execute(f"SELECT DISTINCT assumed FROM {SCHEMA}.graph_edges").fetchone()[0] is True


def test_no_logins_means_no_edges():
    # Under --disable-possible-edges an SPN+SCCM site DB contributes no logins at
    # all (filtered upstream in _assumed_site_dbs, Task 2), so the edges vanish
    # without this builder checking any flag.
    con = _con()
    _edge_mssql_kerberoast_spn(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.graph_edges").fetchone()[0] == 0


def test_edge_mssql_kerberoast_spn_tolerates_missing_source_tables():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    _graph_edges_init(con, SCHEMA)
    _edge_mssql_kerberoast_spn(con, SCHEMA)  # must not raise
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.graph_edges").fetchone()[0] == 0
