import duckdb

from openhound_sccm.transforms import COERCE_RELAY_SOURCE, _graph_edges_init, _edge_coerce_relay_adminservice


def _seed(con, provider_ntlm):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type "
        "UNION ALL SELECT 'SEC' AS site_code, 1 AS site_type"
    )
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        # provider: SMS Provider@PS1 with given NTLM value
        "('S-1-5-21-1-2-3-1001','PROV01.mayyhem.com',['SMS Provider@PS1'], ?), "
        # site server: SMS Site Server@PS1, NTLM unknown
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'], NULL), "
        # a secondary-site system, must be ignored
        "('S-1-5-21-1-2-3-1003','SEC01.mayyhem.com',['SMS Site Server@SEC'], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, restrict_receiving_ntlm_traffic)",
        [provider_ntlm],
    )
    _graph_edges_init(con, "sccm")


def test_adminservice_relay_emits_with_null_ntlm():
    # An unset RestrictReceivingNTLMTraffic is the Windows default (0 = allow all inbound
    # NTLM) = genuinely vulnerable, so this edge is emitted regardless of
    # --disable-possible-edges. The builder deliberately takes no flag: its NTLM gate is
    # flag-independent and the confirmed gate is the provider's SMS Provider role. Matches
    # CMBP, which also emits this confirmed edge under its own flag.
    con = duckdb.connect()
    _seed(con, None)  # provider NTLM unknown -> assume vulnerable
    _edge_coerce_relay_adminservice(con, "sccm")
    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source, "
        "coercion_victim_and_relay_target_pairs FROM sccm.graph_edges"
    ).fetchall()
    assert len(rows) == 1
    start, end, kind, csrc, pairs = rows[0]
    assert start == "MAYYHEM.COM-S-1-5-11"
    assert end == "PS1"          # non-secondary site code (raw case)
    assert kind == "SCCM_CoerceAndRelayToAdminService"
    # Task 5/D3: unconditionally assumed -- the existing 'Post-processing' tag is
    # preserved (Task 3's append semantics), not replaced.
    assert csrc == ["Post-processing", COERCE_RELAY_SOURCE]
    assert pairs == ["Coerce SS01.mayyhem.com, relay to PROV01.mayyhem.com"]


def test_adminservice_relay_drops_explicit_ntlm_restricted():
    # Explicitly restricted provider NTLM (not 'Off') -> relayed NTLM refused -> no edge, even
    # without the flag.
    con = duckdb.connect()
    _seed(con, "DenyAll")
    _edge_coerce_relay_adminservice(con, "sccm")
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_adminservice_relay_emits_with_confirmed_ntlm_off():
    con = duckdb.connect()
    _seed(con, "Off")  # explicitly confirmed not-restricting NTLM
    _edge_coerce_relay_adminservice(con, "sccm")
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1
