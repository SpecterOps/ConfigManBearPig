# src/openhound_sccm/transforms_test (Task 12): MemberOf edges for the full nested
# membership chain of each System Management DACL Full-Control group. Wires up
# ldap_smc_group_members, the new raw table collectors/ldap.py::_expand_group_targets
# emits (routed out of ldap_system_management_dacl via dlt.mark.with_table_name).
import duckdb

from openhound_sccm.kinds.edges import MEMBER_OF, TRAVERSABLE_EDGE_KINDS
from openhound_sccm.transforms import _edge_member_of_smc, _graph_edges_init

SCHEMA = "sccm"


def _con():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.ldap_smc_group_members "
        "(group_sid VARCHAR, member_sid VARCHAR, member_type VARCHAR)"
    )
    return con


def test_memberof_edges_full_nested_chain():
    con = _con()
    # SMC group 513 contains a nested group 600; 600 contains a user 1201. The
    # recursive collector records BOTH hops (513<-600 and 600<-1201).
    con.executemany(
        f"INSERT INTO {SCHEMA}.ldap_smc_group_members VALUES (?,?,?)",
        [
            ("S-1-5-21-1-513", "S-1-5-21-1-600", "group"),
            ("S-1-5-21-1-600", "S-1-5-21-1-1201", "user"),
        ],
    )
    _graph_edges_init(con, SCHEMA)
    _edge_member_of_smc(con, SCHEMA)
    edges = {
        (s, e) for s, e in con.execute(
            f"SELECT start_id, end_id FROM {SCHEMA}.graph_edges WHERE kind = '{MEMBER_OF}'"
        ).fetchall()
    }
    # Both nesting levels present -> the user can path transitively to the SMC group.
    assert ("S-1-5-21-1-600", "S-1-5-21-1-513") in edges
    assert ("S-1-5-21-1-1201", "S-1-5-21-1-600") in edges


def test_rows_missing_either_sid_are_skipped():
    con = _con()
    con.execute(
        f"INSERT INTO {SCHEMA}.ldap_smc_group_members VALUES (NULL, 'S-1-5-21-1-1201', 'user')"
    )
    _graph_edges_init(con, SCHEMA)
    _edge_member_of_smc(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.graph_edges").fetchone()[0] == 0


def test_member_of_is_traversable():
    assert MEMBER_OF in TRAVERSABLE_EDGE_KINDS


def test_edge_member_of_smc_tolerates_missing_source_table():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    _graph_edges_init(con, SCHEMA)
    _edge_member_of_smc(con, SCHEMA)  # must not raise
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.graph_edges").fetchone()[0] == 0
