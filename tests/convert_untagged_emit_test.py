import json
import duckdb
from openhound_sccm.lookup import SCCMLookup
from openhound_sccm.convert_pipeline import emit_graph_from_duckdb
from openhound_sccm.models.computer import ComputerNode


def _db_with_computer(tmp_path):
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
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
    con.close()
    return str(path)


def test_untagged_emit_writes_no_metadata_and_ad_prefix(tmp_path):
    """source_kind=None must write files with NO metadata key, named by resource_prefix."""
    client = duckdb.connect(_db_with_computer(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"

    emit_graph_from_duckdb(
        lookup, out, None,
        node_specs=[("node_computer", ComputerNode)], edge_specs=[],
        resource_prefix="ad",
    )

    files = list(out.glob("ad_*.json"))
    assert files, "expected at least one output file"
    # Every file carries no metadata block (the ad_ glob already guarantees the prefix).
    for f in files:
        doc = json.loads(f.read_text())
        assert "graph" in doc
        assert "metadata" not in doc, f"AD payload must have no metadata: {f.name}"


def test_tagged_emit_still_writes_source_kind(tmp_path):
    """A real source_kind still routes through core's writer and stamps metadata."""
    client = duckdb.connect(_db_with_computer(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"

    emit_graph_from_duckdb(
        lookup, out, "SCCM",
        node_specs=[("node_computer", ComputerNode)], edge_specs=[],
        resource_prefix="sccm",
    )

    docs = [json.loads(f.read_text()) for f in out.glob("sccm_*.json")]
    assert docs, "expected sccm_-prefixed output"
    assert all(d["metadata"]["source_kind"] == "SCCM" for d in docs)
