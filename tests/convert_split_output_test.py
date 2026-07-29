import json
import duckdb
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
        "'PS1' AS site_code, 'PS1' AS root_site_code, NULL AS parent_site_code, "
        "2 AS site_type"  # 2 = Primary Site (integer, as node_site stores it)
    )
    # Edge tables as produced by _graph_edges_split.
    for t in ("graph_edges_ad", "graph_edges_sccm"):
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


def test_emit_split_writes_two_payloads(tmp_path):
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
    assert all("metadata" not in d for _, d in ad_docs)
