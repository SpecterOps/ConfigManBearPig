# tests/possible_client_provenance_test.py
"""Possible client devices and their edges must carry the D3 assumed stamp.

A "possible" client device is inferred from a CmRcService SPN alone: the SPN proves
remote control was once configured, not that the SCCM client is still installed. So the
device and both edges hanging off it (SCCM_HasClient, SCCM_SameHostAs) are assumptions.

Found by Task 10's live run: --disable-possible-edges removed 42 of these edges -- proving
the tool itself treats them as assumptions -- yet in default mode they carried NO `assumed`
property, so an operator could not tell them from confirmed client data. That is precisely
the D3 gap the stamp exists to close.
"""
import duckdb

from openhound_sccm.transforms import (
    POSSIBLE_CLIENT_BASIS, _edge_has_client, _edge_same_host, _graph_edges_init,
)

SCHEMA = "sccm"


def _con(confirmed):
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.node_client_device "
                "(smsid VARCHAR, site_code VARCHAR, ad_domain_sid VARCHAR, "
                " is_confirmed_active_client BOOLEAN)")
    con.execute(f"INSERT INTO {SCHEMA}.node_client_device VALUES ('DEV-1','PS1','S-1-C',?)",
                [confirmed])
    con.execute(f"CREATE TABLE {SCHEMA}.node_computer (sid VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.node_computer VALUES ('S-1-C')")
    _graph_edges_init(con, SCHEMA)
    return con


def _stamps(con, kind):
    return con.execute(
        f"SELECT DISTINCT assumed, assumption_basis FROM {SCHEMA}.graph_edges "
        f"WHERE kind = ?", [kind]).fetchall()


def test_hasclient_from_an_inferred_device_is_stamped():
    con = _con(False)
    _edge_has_client(con, SCHEMA)
    assert _stamps(con, "SCCM_HasClient") == [(True, POSSIBLE_CLIENT_BASIS)]


def test_hasclient_from_a_confirmed_device_is_not_stamped():
    con = _con(True)
    _edge_has_client(con, SCHEMA)
    assert _stamps(con, "SCCM_HasClient") == [(False, None)]


def test_samehostas_inherits_the_devices_confidence_both_directions():
    con = _con(False)
    _edge_same_host(con, SCHEMA)
    rows = con.execute(
        f"SELECT start_id, end_id, assumed FROM {SCHEMA}.graph_edges "
        f"WHERE kind = 'SCCM_SameHostAs' ORDER BY start_id").fetchall()
    # Both directions are emitted, and BOTH must be stamped -- stamping only one would
    # let an operator reach the same assumption from the other end unmarked.
    assert len(rows) == 2, rows
    assert all(r[2] is True for r in rows), rows

    con = _con(True)
    _edge_same_host(con, SCHEMA)
    assert all(r[0] is False for r in con.execute(
        f"SELECT assumed FROM {SCHEMA}.graph_edges WHERE kind='SCCM_SameHostAs'").fetchall())


def test_provenance_tag_accompanies_the_stamp():
    # The stamp and the collectionSource tag use the same predicate, so they can never
    # disagree -- a row marked assumed must also carry the Assumed-* source.
    con = _con(False)
    _edge_has_client(con, SCHEMA)
    src = con.execute(
        f"SELECT collection_source FROM {SCHEMA}.graph_edges WHERE kind='SCCM_HasClient'"
    ).fetchone()[0]
    assert any(s.startswith("Assumed-") for s in src), src
