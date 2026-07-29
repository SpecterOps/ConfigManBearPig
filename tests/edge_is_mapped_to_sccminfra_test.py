# src/openhound_sccm/edge_is_mapped_to_sccminfra_test.py
"""CMBP parity: SCCM_IsMappedTo edges carry SCCMInfra = true (ps1:7807), every other
edge kind leaves it unset. Covers the full path: builder -> dedup -> split -> the
GraphEdge model's emitted OpenGraph property.
"""
import duckdb

from openhound_sccm.graph import SCCMEdgeProperties
from openhound_sccm.kinds.edges import SCCM_HAS_MEMBER, SCCM_IS_MAPPED_TO
from openhound_sccm.models.graph_edge import GraphEdge
from openhound_sccm.transforms import (
    _graph_edges_dedup,
    _graph_edges_init,
    _graph_edges_split,
    transforms,
)


def test_edge_is_mapped_to_sets_sccm_infra_true():
    """The builder itself: every SCCM_IsMappedTo row it inserts gets sccm_infra = true."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\sccmadmin', 'S-1-5-21-1-2-3-1110', false)) "
                "AS t(logon_name, admin_sid, is_group)")
    transforms(con)
    rows = con.execute(
        "SELECT sccm_infra FROM sccm.graph_edges WHERE kind = ?", [SCCM_IS_MAPPED_TO]
    ).fetchall()
    assert rows == [(True,)]


def _seed_mixed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _graph_edges_init(con, "sccm")
    con.execute(
        "INSERT INTO sccm.graph_edges BY NAME "
        "SELECT 'S-1-5-21-1-2-3-1110' AS start_id, 'MAYYHEM\\SCCMADMIN@CAS' AS end_id, "
        f"  '{SCCM_IS_MAPPED_TO}' AS kind, ['AdminService-SMS_Admin'] AS collection_source, "
        "  true AS sccm_infra "
        "UNION ALL "
        "SELECT 'S-1-5-21-1-2-3-1110', 'MAYYHEM\\SCCMADMIN@CAS', "
        f"  '{SCCM_IS_MAPPED_TO}', ['WMI-SMS_Admin'], true "
        "UNION ALL "
        f"SELECT 'PS1', 'GUID:dev1', '{SCCM_HAS_MEMBER}', ['x'], NULL"
    )


def test_dedup_collapses_duplicate_is_mapped_to_rows_keeping_true_and_null_elsewhere():
    con = duckdb.connect(":memory:")
    _seed_mixed(con)
    _graph_edges_dedup(con, "sccm")
    mapped = con.execute(
        f"SELECT sccm_infra FROM sccm.graph_edges WHERE kind = '{SCCM_IS_MAPPED_TO}'"
    ).fetchall()
    assert mapped == [(True,)]  # the two admin-source duplicates collapse to one row
    other = con.execute(
        f"SELECT sccm_infra FROM sccm.graph_edges WHERE kind = '{SCCM_HAS_MEMBER}'"
    ).fetchone()
    assert other == (None,)  # non-IsMappedTo kinds are untouched


def test_sccm_infra_survives_split_into_both_payloads():
    con = duckdb.connect(":memory:")
    _seed_mixed(con)
    _graph_edges_dedup(con, "sccm")
    # AuthUsers SID + a group node land the IsMappedTo row in the AD payload;
    # HasMember's ends have no node table match, so it lands in the SCCM-only payload.
    con.execute("CREATE TABLE sccm.node_computer AS SELECT NULL::VARCHAR AS sid WHERE false")
    con.execute("CREATE TABLE sccm.node_user AS SELECT NULL::VARCHAR AS sid WHERE false")
    con.execute(
        "CREATE TABLE sccm.node_group AS SELECT 'S-1-5-21-1-2-3-1110'::VARCHAR AS sid"
    )
    con.execute("CREATE TABLE sccm.node_backfill AS SELECT NULL::VARCHAR AS id WHERE false")
    _graph_edges_split(con, "sccm")

    ad_cols = [d[0] for d in con.execute("DESCRIBE sccm.graph_edges_ad").fetchall()]
    sccm_cols = [d[0] for d in con.execute("DESCRIBE sccm.graph_edges_sccm").fetchall()]
    assert "sccm_infra" in ad_cols
    assert "sccm_infra" in sccm_cols

    ad_row = con.execute(
        f"SELECT sccm_infra FROM sccm.graph_edges_ad WHERE kind = '{SCCM_IS_MAPPED_TO}'"
    ).fetchone()
    assert ad_row == (True,)
    sccm_row = con.execute(
        f"SELECT sccm_infra FROM sccm.graph_edges_sccm WHERE kind = '{SCCM_HAS_MEMBER}'"
    ).fetchone()
    assert sccm_row == (None,)


def test_graph_edge_model_emits_sccminfra_true_for_is_mapped_to():
    row = GraphEdge(
        start_id="S-1-5-21-1-2-3-1110",
        end_id="MAYYHEM\\SCCMADMIN@CAS",
        kind=SCCM_IS_MAPPED_TO,
        collection_source=["AdminService-SMS_Admin"],
        sccm_infra=True,
    )
    edge = next(iter(row.edges))
    assert isinstance(edge.properties, SCCMEdgeProperties)
    assert edge.properties.SCCMInfra is True


def test_graph_edge_model_leaves_sccminfra_unset_for_other_kinds():
    row = GraphEdge(
        start_id="PS1", end_id="GUID:dev1", kind=SCCM_HAS_MEMBER,
        collection_source=["AdminService-SMS_FullCollectionMembership"],
    )
    edge = next(iter(row.edges))
    assert edge.properties.SCCMInfra is None
