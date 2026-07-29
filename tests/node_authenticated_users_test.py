import duckdb

from openhound_sccm.transforms import (
    _graph_edges_init, _edge_coerce_relay_adminservice, _node_authenticated_users,
)
from openhound_sccm.models.group import GroupNode
from openhound_sccm.kinds.edges import MSSQL_COERCE_AND_RELAY_TO_MSSQL


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type")
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1001','PROV01.mayyhem.com',['SMS Provider@PS1'], NULL), "
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, restrict_receiving_ntlm_traffic)"
    )
    # node_group with the final coalesce columns (empty to start).
    con.execute(
        "CREATE TABLE sccm.node_group (sid VARCHAR, name VARCHAR, sccm_infra BOOLEAN, "
        "sccm_resource_ids VARCHAR[], fallback_domain_sid VARCHAR)"
    )
    _graph_edges_init(con, "sccm")
    _edge_coerce_relay_adminservice(con, "sccm")


def test_authenticated_users_node_built_for_relay_domain():
    con = duckdb.connect()
    _seed(con)
    _node_authenticated_users(con, "sccm")
    row = con.execute(
        "SELECT sid, name, sccm_infra, sccm_resource_ids, fallback_domain_sid "
        "FROM sccm.node_group WHERE sid = 'MAYYHEM.COM-S-1-5-11'"
    ).fetchone()
    assert row is not None
    sid, name, infra, rids, fallback = row
    assert name == "AUTHENTICATED USERS@MAYYHEM.COM"
    assert infra is False
    assert rids == []
    assert fallback == "S-1-5-21-1-2-3"   # domain SID stripped from a domain computer SID


def test_group_model_emits_authusers_with_domain_environmentid():
    con = duckdb.connect()
    _seed(con)
    _node_authenticated_users(con, "sccm")
    r = con.execute(
        "SELECT sid, name, sccm_infra, sccm_resource_ids, fallback_domain_sid "
        "FROM sccm.node_group WHERE sid = 'MAYYHEM.COM-S-1-5-11'"
    ).fetchone()
    node = GroupNode(
        sid=r[0], name=r[1], sccm_infra=r[2], sccm_resource_ids=r[3], fallback_domain_sid=r[4]
    ).as_node
    assert node is not None
    assert node.id == "MAYYHEM.COM-S-1-5-11"
    assert node.properties.environmentid == "S-1-5-21-1-2-3"
    assert "Group" in node.kinds and "Base" in node.kinds


def test_authenticated_users_built_from_non_adminservice_relay_kind():
    """Proves the relay_kinds IN-clause covers MSSQL (not just AdminService).

    Seeds a MSSQL_CoerceAndRelayToMSSQL edge directly into graph_edges (start_id already in
    AuthUsers form) plus the matching node_computer row so _domain_to_sid resolves, then
    confirms _node_authenticated_users inserts the AuthUsers node."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        "('S-1-5-21-9-8-7-1001', 'DB01.corp.example.com', CAST([] AS VARCHAR[]), NULL)"
        ") AS t(sid, dnshostname, site_system_roles, restrict_receiving_ntlm_traffic)"
    )
    con.execute(
        "CREATE TABLE sccm.node_group (sid VARCHAR, name VARCHAR, sccm_infra BOOLEAN, "
        "sccm_resource_ids VARCHAR[], fallback_domain_sid VARCHAR)"
    )
    _graph_edges_init(con, "sccm")
    # Seed a MSSQL relay edge whose start_id is the AuthUsers form for corp.example.com.
    # Trailing NULLs are sccm_infra/assumed/assumption_basis (unrelated to this test;
    # only SCCM_IsMappedTo populates sccm_infra, and no builder here stamps assumed).
    con.execute(
        f"INSERT INTO sccm.graph_edges VALUES "
        f"('CORP.EXAMPLE.COM-S-1-5-11', 'some-login-id', '{MSSQL_COERCE_AND_RELAY_TO_MSSQL}', "
        f"['MSSQL-ScanForEPA'], ['Coerce DB01.corp.example.com, relay to db01:1433'], NULL, NULL, NULL, NULL)"
    )
    _node_authenticated_users(con, "sccm")
    row = con.execute(
        "SELECT sid, name, fallback_domain_sid FROM sccm.node_group "
        "WHERE sid = 'CORP.EXAMPLE.COM-S-1-5-11'"
    ).fetchone()
    assert row is not None
    assert row[1] == "AUTHENTICATED USERS@CORP.EXAMPLE.COM"
    assert row[2] == "S-1-5-21-9-8-7"   # domain SID stripped from the seeded computer SID
