import json
import duckdb
import pytest
from openhound_sccm.convert_pipeline import emit_hybrid_edges_from_duckdb
from openhound_sccm.lookup import SCCMLookup
from openhound_sccm.main import _emit_split_graph


def _seed_db(tmp_path):
    """A lookup DB with one SCCM node (node_site), one AD node (node_computer),
    and split edge tables already built (one AD-touching, one SCCM-only)."""
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")

    # AD node: node_computer (only the columns ComputerNode reads).
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'HOST1' AS name, 'host1.lab' AS dnshostname, "
        "'HOST1$' AS sam_account_name, ['SMS Provider'] AS site_system_roles, "
        "['7@PS1'] AS resource_ids, true AS sccm_infra, 'GUID:abc' AS sms_unique_identifier, "
        "true AS smb_signing_required, false AS sccm_has_client_remote_control_spn, "
        "false AS network_boot_server, NULL AS disable_loopback_check, "
        "NULL AS restrict_receiving_ntlm_traffic, NULL AS sccm_client_certificate_required, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    # SCCM node: node_site (only the columns SCCMSite reads to produce an id + kind).
    con.execute(
        "CREATE TABLE sccm.node_site AS SELECT "
        "'PS1' AS site_code, 'CAS' AS root_site_code, 'CAS' AS parent_site_code, "
        "2 AS site_type"  # 2 = Primary Site (integer, as node_site stores it)
    )
    # MSSQL node: node_mssql_server. MSSQLServer.as_node needs only server_id to emit;
    # host_sid feeds environmentid, name is the display label (extra columns are ignored).
    con.execute(
        "CREATE TABLE sccm.node_mssql_server AS SELECT "
        "'S-1-5-21-1-2-3-9:1433' AS server_id, 'S-1-5-21-1-2-3-9' AS host_sid, 'SQL01' AS name"
    )
    # Edge tables as produced by _graph_edges_split.
    for t in (
        "graph_edges_ad",
        "graph_edges_mssql",
        "graph_edges_sccm",
        "graph_edges_hybrid",
    ):
        con.execute(
            f"CREATE TABLE sccm.{t} "
            "(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[])"
        )
    con.execute(
        "INSERT INTO sccm.graph_edges_ad VALUES "
        "('PS1','S-1-5-21-1-2-3-1104','SCCM_HasStoredAccount', ['s'])"  # site -> computer (AD)
    )
    con.execute(
        "INSERT INTO sccm.graph_edges_sccm VALUES "
        "('PS1','CAS','SCCM_Contains', ['s'])"  # site -> site (SCCM only)
    )
    con.execute(
        "INSERT INTO sccm.graph_edges_mssql VALUES "
        "('S-1-5-21-1-2-3-9:1433','sysadmin@S-1-5-21-1-2-3-9:1433','MSSQL_Contains', ['s'])"
    )
    con.execute(
        "INSERT INTO sccm.graph_edges_hybrid VALUES "
        "('S-1-5-21-1-2-3-9:1433\\CM_PS1','PS1','SCCM_AssignAllPermissions', ['s'])"
    )
    con.close()
    return str(path)


def _load(out, pattern):
    nodes, edges, docs = [], [], []
    for f in out.glob(pattern):
        doc = json.loads(f.read_text())
        docs.append((f.name, doc))
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]
    return nodes, edges, docs


def test_emit_split_writes_product_files_and_separate_hybrid_file(tmp_path):
    client = duckdb.connect(_seed_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"

    _emit_split_graph(lookup, out)

    sccm_nodes, sccm_edges, sccm_docs = _load(out, "sccm_*.json")
    ad_nodes, ad_edges, ad_docs = _load(out, "ad_*.json")

    # SCCM payload: the SCCM_Site node, the SCCM-only edge, source_kind stamped.
    assert any("SCCM_Site" in n["kinds"] for n in sccm_nodes)
    assert all("Computer" not in n["kinds"] for n in sccm_nodes)
    assert {e["kind"] for e in sccm_edges} == {"SCCM_Contains"}
    assert all(d["metadata"]["source_kind"] == "SCCM" for _, d in sccm_docs)

    # AD payload: the Computer node, the AD-touching edge, NO metadata block.
    assert any("Computer" in n["kinds"] for n in ad_nodes)
    assert all("SCCM_Site" not in n["kinds"] for n in ad_nodes)
    assert {e["kind"] for e in ad_edges} == {"SCCM_HasStoredAccount"}
    assert ad_edges[0]["properties"]["traversable"] is True
    assert all("metadata" not in d for _, d in ad_docs)

    # MSSQL payload: the MSSQL_Server node, the both-MSSQL edge, source_kind="MSSQL".
    mssql_nodes, mssql_edges, mssql_docs = _load(out, "mssql_*.json")
    assert any("MSSQL_Server" in n["kinds"] for n in mssql_nodes)
    assert {e["kind"] for e in mssql_edges} == {"MSSQL_Contains"}
    assert all(d["metadata"]["source_kind"] == "MSSQL" for _, d in mssql_docs)
    # The MSSQL node must NOT appear in the SCCM payload any more.
    assert all("MSSQL_Server" not in n["kinds"] for n in sccm_nodes)
    hybrid = json.loads((out / "hybrid_edges.json").read_text(encoding="utf-8"))
    assert "metadata" not in hybrid
    assert hybrid["graph"]["nodes"] == []
    assert len(hybrid["graph"]["edges"]) == 1
    hybrid_edge = hybrid["graph"]["edges"][0]
    assert hybrid_edge["kind"] == "SCCM_AssignAllPermissions"
    assert hybrid_edge["start"]["value"] == "S-1-5-21-1-2-3-9:1433\\CM_PS1"
    assert hybrid_edge["end"]["value"] == "PS1"
    assert hybrid_edge["properties"]["collectionSource"] == ["s"]
    assert hybrid_edge["properties"]["traversable"] is True
    assert not list(out.glob("hybrid_edges-*.json"))
    assert all(n["kinds"] == ["SCCM_Site", "SCCM"] for n in sccm_nodes)
    assert all(n["kinds"] == ["MSSQL_Server", "MSSQL"] for n in mssql_nodes)
    assert all(n["properties"]["environmentid"] == "CAS" for n in sccm_nodes)
    assert all(
        n["properties"]["environmentid"] == "S-1-5-21-1-2-3" for n in mssql_nodes
    )
    assert all(
        "environment_kind" not in n["properties"] for n in sccm_nodes + mssql_nodes
    )
    assert all("environment_kind" not in n["properties"] for n in ad_nodes)
    assert all(
        "environment_kind" not in edge["properties"]
        for edge in sccm_edges + mssql_edges + ad_edges
    )


def test_hybrid_file_keeps_more_than_one_thousand_edges_and_replaces_old_results(
    tmp_path,
):
    """One fixed filename must not lose batches or keep relationships from an older run."""
    with duckdb.connect(_seed_db(tmp_path)) as connection:
        connection.execute("DELETE FROM sccm.graph_edges_hybrid")
        connection.execute(
            "INSERT INTO sccm.graph_edges_hybrid "
            "SELECT 'database-' || value, 'PS1', 'SCCM_AssignAllPermissions', ['s'] "
            "FROM range(1001) AS generated(value)"
        )
        lookup = SCCMLookup(connection)
        output = tmp_path / "graph"
        emit_hybrid_edges_from_duckdb(lookup, output)
        file = output / "hybrid_edges.json"
        document = json.loads(file.read_text(encoding="utf-8"))
        assert len(document["graph"]["edges"]) == 1001
        assert (
            len({edge["start"]["value"] for edge in document["graph"]["edges"]}) == 1001
        )
        assert list(output.glob("*.json")) == [file]

        connection.execute("DELETE FROM sccm.graph_edges_hybrid")
        emit_hybrid_edges_from_duckdb(lookup, output)
        assert json.loads(file.read_text(encoding="utf-8")) == {
            "graph": {"nodes": [], "edges": []}
        }
        assert not list(output.glob("*.tmp"))


def test_hybrid_write_failure_preserves_previous_complete_file(
    tmp_path, monkeypatch, caplog
):
    """A failed conversion must raise, log the failure, and leave the complete file intact."""
    with duckdb.connect(_seed_db(tmp_path)) as connection:
        lookup = SCCMLookup(connection)
        output = tmp_path / "graph"
        emit_hybrid_edges_from_duckdb(lookup, output)
        file = output / "hybrid_edges.json"
        previous = file.read_bytes()

        def failed_read(table):
            raise RuntimeError("test read failure")

        monkeypatch.setattr(lookup, "table_rows", failed_read)
        with pytest.raises(RuntimeError, match="test read failure"):
            emit_hybrid_edges_from_duckdb(lookup, output)
        assert file.read_bytes() == previous
        assert "conversion is incomplete" in caplog.text
