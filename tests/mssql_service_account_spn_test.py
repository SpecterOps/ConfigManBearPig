# src/openhound_sccm/transforms_test (Task 13): MSSQL_ServiceAccountFor + HasSession
# from the MSSQLSvc SPN holder (Tier A+, confirmed, low-priv).
#
# Reads node_mssql_server (the coalesced table), not the raw mssql_server_instances
# collector table -- server_id is minted there, and the privileged sibling builder
# (_edge_mssql_service_account) reads the same coalesced table, so this stays
# consistent with that convention.
import duckdb

from openhound_sccm.kinds.edges import HAS_SESSION, MSSQL_SERVICE_ACCOUNT_FOR
from openhound_sccm.transforms import _edge_has_session, _edge_mssql_service_account_spn, _graph_edges_init

SCHEMA = "sccm"


def _con(rows):
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_mssql_server "
        "(server_id VARCHAR, host_sid VARCHAR, service_account_sid VARCHAR, "
        " service_account_is_computer BOOLEAN)"
    )
    con.executemany(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES (?,?,?,?)", rows)
    _graph_edges_init(con, SCHEMA)
    return con


def test_domain_service_account_gets_both_edges():
    con = _con([("S-1-DB:1433", "S-1-DB", "S-1-SVC", False)])
    _edge_mssql_service_account_spn(con, SCHEMA)
    _edge_has_session(con, SCHEMA)
    got = {
        (k, s, e) for s, e, k in con.execute(
            f"SELECT start_id, end_id, kind FROM {SCHEMA}.graph_edges "
            f"WHERE kind IN ('{MSSQL_SERVICE_ACCOUNT_FOR}', '{HAS_SESSION}')"
        ).fetchall()
    }
    assert (MSSQL_SERVICE_ACCOUNT_FOR, "S-1-SVC", "S-1-DB:1433") in got  # sa -> server
    assert (HAS_SESSION, "S-1-DB", "S-1-SVC") in got                     # host computer -> sa


def test_machine_account_service_skips_hassession():
    con = _con([("S-1-DB:1433", "S-1-DB", "S-1-DB", True)])  # runs as the host machine account
    _edge_mssql_service_account_spn(con, SCHEMA)
    _edge_has_session(con, SCHEMA)
    kinds = [r[0] for r in con.execute(f"SELECT kind FROM {SCHEMA}.graph_edges").fetchall()]
    assert MSSQL_SERVICE_ACCOUNT_FOR in kinds
    assert HAS_SESSION not in kinds


def test_no_holder_produces_no_edges():
    con = _con([("S-1-DB:1433", "S-1-DB", None, None)])
    _edge_mssql_service_account_spn(con, SCHEMA)
    _edge_has_session(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.graph_edges").fetchone()[0] == 0


def test_service_account_for_is_not_traversable():
    # CMBP comments MSSQL_ServiceAccountFor out of its traversable allow-list
    # (ps1:2233); the low-priv arm mirrors that, unlike HasSession which is.
    from openhound_sccm.kinds.edges import TRAVERSABLE_EDGE_KINDS
    assert MSSQL_SERVICE_ACCOUNT_FOR not in TRAVERSABLE_EDGE_KINDS
    assert HAS_SESSION in TRAVERSABLE_EDGE_KINDS


def test_edge_mssql_service_account_spn_tolerates_missing_source_table():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    _graph_edges_init(con, SCHEMA)
    _edge_mssql_service_account_spn(con, SCHEMA)  # must not raise
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.graph_edges").fetchone()[0] == 0
