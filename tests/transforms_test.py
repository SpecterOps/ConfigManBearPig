"""Smoke test for the transforms() entrypoint after Stage-0 spike removal (Task 8).

Verifies that transforms() runs without error on an empty schema and that the
spike artefacts are gone — node_spike must not exist, and graph_edges must be
present but empty (no site data → no replication edges, but the table is always
created so convert can read it without a separate existence check).
"""
import duckdb
from openhound_sccm.transforms import transforms


def test_transforms_no_spike_node():
    """node_spike must not exist after transforms() — the Stage-0 spike is removed."""
    con = duckdb.connect(":memory:")
    transforms(con, schema="sccm")
    tables = {row[2] for row in con.execute("SHOW ALL TABLES").fetchall()}
    assert "node_spike" not in tables, "Stage-0 spike table node_spike should be absent"


def test_transforms_graph_edges_always_created():
    """graph_edges must always exist after transforms(), even with no site data.

    With no site sources, site_hierarchy is empty and _graph_edges_init + _edge_replication
    produce zero replication rows — but the table itself must be created so convert can
    read it without a separate existence check.
    """
    con = duckdb.connect(":memory:")
    transforms(con, schema="sccm")
    # Must not raise — table must exist.
    edges = con.execute("SELECT start_id, end_id, kind FROM sccm.graph_edges").fetchall()
    assert edges == [], f"Expected empty graph_edges with no site data; got {edges}"


def test_transforms_spike_edge_absent():
    """The SCCM_Spike edge kind must never appear in graph_edges."""
    con = duckdb.connect(":memory:")
    transforms(con, schema="sccm")
    spike_edges = con.execute(
        "SELECT * FROM sccm.graph_edges WHERE kind = 'SCCM_Spike'"
    ).fetchall()
    assert spike_edges == [], f"Stage-0 spike edges still present: {spike_edges}"
