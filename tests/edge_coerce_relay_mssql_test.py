import duckdb

from openhound_sccm.transforms import _graph_edges_init, _edge_coerce_relay_mssql


def _seed(con, host_ntlm, epa, port_open=None):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # SQL host computer (the site DB server) + the sysadmin victim computer.
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-5001','SQL01.mayyhem.com', ?), "       # host (site DB)
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com', NULL)"        # sysadmin victim
        ") AS t(sid, dnshostname, restrict_receiving_ntlm_traffic)",
        [host_ntlm],
    )
    # port_open defaults to NULL (not asserted either way) -- I2 ruling: this builder
    # must never gate on it (see _edge_coerce_relay_mssql's docstring), so its value
    # is inert here; callers only set it explicitly to prove that inertness.
    con.execute(
        "CREATE TABLE sccm.node_mssql_server AS SELECT "
        "'S-1-5-21-1-2-3-5001:1433' AS server_id, 'SQL01.mayyhem.com' AS dns_host_name, "
        "'SQL01.mayyhem.com' AS name, '1433' AS port, ? AS extended_protection, "
        "? AS port_open, "
        "['MSSQL-ScanForEPA','SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source",
        [epa, port_open],
    )
    con.execute(
        "CREATE TABLE sccm.node_mssql_login AS SELECT "
        "'MAYYHEM\\SS01$@S-1-5-21-1-2-3-5001:1433' AS login_id, "
        "'S-1-5-21-1-2-3-5001:1433' AS server_id, 'S-1-5-21-1-2-3-5001' AS host_sid, "
        "'S-1-5-21-1-2-3-1002' AS sysadmin_computer_sid"
    )
    _graph_edges_init(con, "sccm")


def test_mssql_relay_default_emits_when_epa_null():
    con = duckdb.connect()
    _seed(con, host_ntlm=None, epa=None)  # both unknown -> assume vulnerable
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=False)
    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source, "
        "coercion_victim_and_relay_target_pairs FROM sccm.graph_edges"
    ).fetchall()
    assert len(rows) == 1
    start, end, kind, csrc, pairs = rows[0]
    assert start == "MAYYHEM.COM-S-1-5-11"
    assert end == "MAYYHEM\\SS01$@S-1-5-21-1-2-3-5001:1433"
    assert kind == "MSSQL_CoerceAndRelayToMSSQL"
    assert csrc == ["MSSQL-ScanForEPA"]  # EPA sources only
    assert pairs == ["Coerce SS01.mayyhem.com, relay to SQL01.mayyhem.com:1433"]


def test_mssql_relay_skips_when_epa_enabled():
    con = duckdb.connect()
    _seed(con, host_ntlm="Off", epa="Required")  # EPA on -> never a relay target
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=False)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_mssql_relay_flag_drops_assumed_epa():
    con = duckdb.connect()
    _seed(con, host_ntlm="Off", epa=None)  # EPA unknown -> dropped under the flag
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_mssql_relay_flag_keeps_null_ntlm_with_confirmed_epa():
    # New semantics: host NTLM unset = Windows default (allow all inbound NTLM) = vulnerable, so
    # with EPA explicitly 'Off' (the confirmed gate) the edge survives --disable-possible-edges.
    # NTLM is flag-independent; only EPA must be explicit 'Off' under the flag. Matches CMBP.
    con = duckdb.connect()
    _seed(con, host_ntlm=None, epa="Off")  # EPA explicit Off (confirmed), host NTLM unset (default-vulnerable)
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1


def test_mssql_relay_drops_explicit_ntlm_restricted():
    # Explicitly restricted host NTLM (not 'Off') -> the relayed NTLM is refused -> no edge, even
    # with EPA off and even without the flag.
    con = duckdb.connect()
    _seed(con, host_ntlm="DenyAll", epa="Off")
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


# --- I2 ruling: port_open must NOT gate this edge (Task 1c review, fix round 3) ---
# node_mssql_login only ever comes from _mssql_sql_servers (a confirmed SCCM site
# DB), never from the SPN-only mssql_server_instances arm, so every row this
# builder can see is already a confirmed site DB -- an earlier revision gated on
# port_open here, reasoning that a closed 1433 meant "can't relay." That reasoning
# was wrong: this edge models attacker capability, and a port unreachable from the
# COLLECTOR's network position is not evidence an attacker elsewhere on the network
# can't reach it. The two tests below pin that port_open has zero effect on the
# outcome in either flag mode, regressing that mistake.

def test_mssql_relay_ignores_port_open_false_in_default_mode():
    con = duckdb.connect()
    # EPA unmeasured (None) -> still assumed vulnerable in default mode, exactly
    # like test_mssql_relay_default_emits_when_epa_null -- port_open=False must not
    # change that outcome.
    _seed(con, host_ntlm=None, epa=None, port_open=False)
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=False)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1


def test_mssql_relay_flag_still_drops_assumed_epa_regardless_of_port_open():
    con = duckdb.connect()
    # Same as test_mssql_relay_flag_drops_assumed_epa (EPA unknown -> dropped under
    # the flag), but with port_open=False seeded explicitly -- the outcome must be
    # unchanged either way. Note: this yields 0 edges for an EPA reason (EPA is
    # unmeasured, and the flag requires it explicit) regardless of port_open, so on
    # its own it can't distinguish "port_open is truly inert" from "a port_open gate
    # happens not to fire here" -- see the discriminating case below.
    _seed(con, host_ntlm="Off", epa=None, port_open=False)
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_mssql_relay_emits_under_flag_with_confirmed_epa_off_and_port_open_false():
    # The discriminating case (reviewer I3-remainder): EPA is EXPLICITLY measured
    # 'Off' (not merely unmeasured/assumed) under --disable-possible-edges, with
    # port_open=False. If a port_open gate were ever reintroduced, THIS is the case
    # it would wrongly suppress -- the test above can't catch that reintroduction
    # because it already yields 0 for an unrelated (EPA) reason.
    con = duckdb.connect()
    _seed(con, host_ntlm=None, epa="Off", port_open=False)
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1


def test_mssql_relay_assumed_stamp_is_per_row_not_per_family():
    """Only the rows that RELIED on the EPA-off assumption carry assumed=true.

    Unlike SCCM_CoerceAndRelayToSMB / ToAdminService, which design spec D3 marks
    unconditionally assumed, this family's assumption is conditional: an explicitly
    measured extended_protection='Off' is evidence, while a NULL EPA (host never probed)
    is the inference spec §7 calls out. Stamping the whole family would libel the measured
    rows; stamping none of it would hide the inference.
    """
    import duckdb
    from openhound_sccm.transforms import _edge_coerce_relay_mssql

    def _run(epa):
        con = duckdb.connect()
        _seed(con, host_ntlm=None, epa=epa)   # NULL NTLM = Windows default = vulnerable
        _edge_coerce_relay_mssql(con, "sccm", disable_possible=False)
        return con.execute(
            "SELECT assumed, assumption_basis FROM sccm.graph_edges "
            "WHERE kind = 'MSSQL_CoerceAndRelayToMSSQL'").fetchall()

    measured = _run("Off")
    assert measured and measured[0][0] is False, measured
    assert measured[0][1] is None, "a measured EPA must carry no assumptionBasis"

    inferred = _run(None)
    assert inferred and inferred[0][0] is True, inferred
    assert inferred[0][1] and "never measured" in inferred[0][1]
