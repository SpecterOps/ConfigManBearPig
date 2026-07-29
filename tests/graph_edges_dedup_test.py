import duckdb
from openhound_sccm.transforms import transforms, _graph_edges_dedup, _graph_edges_init


def test_graph_edges_deduplicated_across_sources():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    # the SAME admin in BOTH adminservice and wmi -> _edge_is_mapped_to would insert twice
    row = "SELECT 'MAYYHEM\\a' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group"
    con.execute(f"CREATE TABLE sccm.adminservice_admins AS {row}")
    con.execute(f"CREATE TABLE sccm.wmi_admins AS {row}")
    transforms(con)
    cnt = con.execute("SELECT count(*) FROM sccm.graph_edges "
                      "WHERE kind='SCCM_IsMappedTo' AND end_id='MAYYHEM\\A@CAS'").fetchone()[0]
    assert cnt == 1   # deduped, not 2


def test_graph_edges_dedup_merges_collection_source_from_different_sources():
    """Two rows with the same (start, end, kind) but different collection_source tags
    should collapse into one row whose collection_source is the union of both tags."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # Use _graph_edges_init so the schema stays current (includes Stage 6 coercion columns).
    _graph_edges_init(con, "sccm")
    # Same triple, two different source tags.
    con.execute(
        "INSERT INTO sccm.graph_edges (start_id, end_id, kind, collection_source) VALUES "
        "('A', 'B', 'MemberOf', ['AdminService-SMS_R_System']), "
        "('A', 'B', 'MemberOf', ['WMI-SMS_R_System'])"
    )
    _graph_edges_dedup(con, "sccm")

    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source FROM sccm.graph_edges "
        "WHERE start_id='A' AND end_id='B' AND kind='MemberOf'"
    ).fetchall()

    # Exactly one row after dedup.
    assert len(rows) == 1, f"Expected 1 row, got {len(rows)}"

    merged_sources = sorted(rows[0][3])
    assert merged_sources == ["AdminService-SMS_R_System", "WMI-SMS_R_System"], (
        f"Expected both source tags merged, got {merged_sources}"
    )


def test_graph_edges_dedup_deduplicates_identical_collection_source_tags():
    """Two rows with the same (start, end, kind) AND the same collection_source tag
    should collapse into one row with a single copy of that tag (no duplicates)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA sccm")
    # Use _graph_edges_init so the schema stays current (includes Stage 6 coercion columns).
    _graph_edges_init(con, "sccm")
    # Same triple AND same source tag inserted twice.
    con.execute(
        "INSERT INTO sccm.graph_edges (start_id, end_id, kind, collection_source) VALUES "
        "('A', 'B', 'MemberOf', ['AdminService-SMS_R_System']), "
        "('A', 'B', 'MemberOf', ['AdminService-SMS_R_System'])"
    )
    _graph_edges_dedup(con, "sccm")

    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source FROM sccm.graph_edges "
        "WHERE start_id='A' AND end_id='B' AND kind='MemberOf'"
    ).fetchall()

    # Exactly one row after dedup.
    assert len(rows) == 1, f"Expected 1 row, got {len(rows)}"

    merged_sources = rows[0][3]
    assert merged_sources == ["AdminService-SMS_R_System"], (
        f"Expected single tag, got {merged_sources}"
    )
