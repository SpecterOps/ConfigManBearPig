"""_edge_coerce_relay_adminservice suppresses the edge for confirmed SCCM 2509+ sites."""
import duckdb

from openhound_sccm.transforms import _edge_coerce_relay_adminservice


def _seed(con, schema, site_code, version):
    # Provider (NTLM open) + Site Server in the same site, distinct SIDs.
    con.execute(
        f"INSERT INTO {schema}.node_computer VALUES "
        f"('SID-PROV-{site_code}', 'prov-{site_code}.lab', ['SMS Provider@{site_code}'], NULL), "
        f"('SID-SRV-{site_code}', 'srv-{site_code}.lab', ['SMS Site Server@{site_code}'], NULL)"
    )
    con.execute(f"INSERT INTO {schema}.site_hierarchy VALUES ('{site_code}', 2)")
    con.execute(
        f"INSERT INTO {schema}.node_site VALUES (?, ?)",
        [site_code, version],
    )


def _kinds_for_site(con, schema, site_code):
    return [r[0] for r in con.execute(
        f"SELECT kind FROM {schema}.graph_edges WHERE end_id = '{site_code}'"
    ).fetchall()]


def test_gate_suppresses_2509_keeps_older_and_unknown():
    con = duckdb.connect()
    s = "s"
    con.execute(f"CREATE SCHEMA {s}")
    con.execute(f"CREATE TABLE {s}.node_computer (sid VARCHAR, dnshostname VARCHAR, "
                f"site_system_roles VARCHAR[], restrict_receiving_ntlm_traffic VARCHAR)")
    con.execute(f"CREATE TABLE {s}.site_hierarchy (site_code VARCHAR, site_type INTEGER)")
    con.execute(f"CREATE TABLE {s}.node_site (site_code VARCHAR, version VARCHAR)")
    con.execute(f"CREATE TABLE {s}.graph_edges (start_id VARCHAR, end_id VARCHAR, kind VARCHAR, "
                f"collection_source VARCHAR[], coercion_victim_and_relay_target_pairs VARCHAR[], "
                f"coercion_victim_hostnames VARCHAR[], assumed BOOLEAN, assumption_basis VARCHAR)")
    _seed(con, s, "P09", "5.00.9141.1015")   # 2509 -> suppressed
    _seed(con, s, "P03", "5.00.9135.1013")   # 2503 -> kept
    _seed(con, s, "PNK", None)               # unknown -> kept (fail open)

    _edge_coerce_relay_adminservice(con, s)

    assert "SCCM_CoerceAndRelayToAdminService" not in _kinds_for_site(con, s, "P09")
    assert "SCCM_CoerceAndRelayToAdminService" in _kinds_for_site(con, s, "P03")
    assert "SCCM_CoerceAndRelayToAdminService" in _kinds_for_site(con, s, "PNK")


def test_gate_no_node_site_table_fails_open():
    """When _edge_coerce_relay_adminservice runs in isolation (node_site not yet
    built -- e.g. a caller that hasn't run _node_site first), the join must not
    take down the whole INSERT via safe_execute's missing-table skip. The function
    guarantees node_site exists (CREATE TABLE IF NOT EXISTS) so unknown-version
    fail-open applies instead of silently dropping every edge."""
    con = duckdb.connect()
    s = "s2"
    con.execute(f"CREATE SCHEMA {s}")
    con.execute(f"CREATE TABLE {s}.node_computer (sid VARCHAR, dnshostname VARCHAR, "
                f"site_system_roles VARCHAR[], restrict_receiving_ntlm_traffic VARCHAR)")
    con.execute(f"CREATE TABLE {s}.site_hierarchy (site_code VARCHAR, site_type INTEGER)")
    con.execute(f"CREATE TABLE {s}.graph_edges (start_id VARCHAR, end_id VARCHAR, kind VARCHAR, "
                f"collection_source VARCHAR[], coercion_victim_and_relay_target_pairs VARCHAR[], "
                f"coercion_victim_hostnames VARCHAR[], assumed BOOLEAN, assumption_basis VARCHAR)")
    con.execute(
        f"INSERT INTO {s}.node_computer VALUES "
        f"('SID-PROV-X', 'prov-x.lab', ['SMS Provider@X'], NULL), "
        f"('SID-SRV-X', 'srv-x.lab', ['SMS Site Server@X'], NULL)"
    )
    con.execute(f"INSERT INTO {s}.site_hierarchy VALUES ('X', 2)")

    _edge_coerce_relay_adminservice(con, s)

    assert "SCCM_CoerceAndRelayToAdminService" in _kinds_for_site(con, s, "X")
