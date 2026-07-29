# src/openhound_sccm/graph_edges_test.py
"""Tests for _graph_edges_init + _edge_replication: the SCCM_AdminsReplicatedTo replication-edge builder.

Seeds a three-site hierarchy (CAS type 4, PS1 type 2 / parent CAS, SS1 type 1
/ parent PS1), runs transforms(), and asserts the expected edge rows are present
and the forbidden row (SS1 -> PS1) is absent.
"""
import duckdb

from openhound_sccm.transforms import transforms


def _seed(con: duckdb.DuckDBPyConnection) -> None:
    """Minimal tables for site_hierarchy + graph_edges to build from."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # Three-site hierarchy: CAS (4), PS1 (2, parent CAS), SS1 (1, parent PS1)
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES "
        "('CAS', NULL, 4), "
        "('PS1', 'CAS', 2), "
        "('SS1', 'PS1', 1)"
        ") AS t(site_code, parent_site_code, site_type)"
    )


def _graph_edges_rows(con: duckdb.DuckDBPyConnection) -> set[tuple[str, str, str]]:
    """Return all graph_edges rows as a set of (start_id, end_id, kind) triples."""
    return set(con.execute("SELECT start_id, end_id, kind FROM sccm.graph_edges").fetchall())


def test_cas_primary_edges_are_bidirectional():
    """CAS(4) <-> Primary(2): two rows, one in each direction."""
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    rows = _graph_edges_rows(con)
    assert ("CAS", "PS1", "SCCM_AdminsReplicatedTo") in rows, "Expected CAS->PS1 edge"
    assert ("PS1", "CAS", "SCCM_AdminsReplicatedTo") in rows, "Expected PS1->CAS edge"


def test_primary_secondary_edge_is_one_way():
    """Primary(2) -> Secondary(1): one row (parent -> child only)."""
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    rows = _graph_edges_rows(con)
    assert ("PS1", "SS1", "SCCM_AdminsReplicatedTo") in rows, "Expected PS1->SS1 edge"
    assert ("SS1", "PS1", "SCCM_AdminsReplicatedTo") not in rows, "Should NOT have SS1->PS1 edge"


def test_no_cas_secondary_direct_edge():
    """CAS and Secondary are never directly connected — only through Primary."""
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    rows = _graph_edges_rows(con)
    # SS1's parent is PS1 (type 2), so no direct CAS<->SS1 edges expected
    assert ("CAS", "SS1", "SCCM_AdminsReplicatedTo") not in rows
    assert ("SS1", "CAS", "SCCM_AdminsReplicatedTo") not in rows


def test_graph_edges_overwrites_spike():
    """graph_edges after transforms() contains only real replication edges, not the spike."""
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    rows = _graph_edges_rows(con)
    # Spike row must be gone (Task 7 overwrites the Stage-0 spike table)
    assert ("SPIKE-1", "SPIKE-1", "SCCM_Spike") not in rows


def test_total_edge_count():
    """Exactly three edges for the three-site hierarchy: CAS->PS1, PS1->CAS, PS1->SS1."""
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    rows = _graph_edges_rows(con)
    # Only replication edges — no spike row, no phantom pair
    replication_rows = {r for r in rows if r[2] == "SCCM_AdminsReplicatedTo"}
    assert len(replication_rows) == 3, f"Expected 3 replication edges, got {len(replication_rows)}: {replication_rows}"


def test_existing_edges_carry_collection_source():
    """Every replication edge must carry collection_source=['SCCM_Invoke-PostProcessing']."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
        "(VALUES ('CAS',NULL,4),('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)"
    )
    transforms(con)
    rows = con.execute(
        "SELECT DISTINCT kind, collection_source FROM sccm.graph_edges "
        "WHERE kind='SCCM_AdminsReplicatedTo'"
    ).fetchall()
    assert rows, "Expected at least one SCCM_AdminsReplicatedTo edge"
    assert rows[0][1] == ["SCCM_Invoke-PostProcessing"], (
        f"Expected ['SCCM_Invoke-PostProcessing'], got {rows[0][1]}"
    )
