# src/openhound_sccm/convert_integration_test.py
"""End-to-end integration test: preprocess then convert, asserting real nodes.

Seeds a minimal real raw tree:
  - one adminservice_r_system row (a domain SID + name) → becomes a Computer node
  - two adminservice_site_definitions rows (a CAS + a Primary) → become SCCM_Site
    nodes and an SCCM_AdminsReplicatedTo edge
  - one adminservice_collections row → becomes a SCCM_Collection node
  - one adminservice_admins row (a user) → becomes a SCCM_AdminUser node and a
    SCCM_IsMappedTo edge (admin_sid → SCCM_AdminUser node)
  - one adminservice_client_devices row → becomes a SCCM_ClientDevice node and a
    SCCM_HasClient edge (site_code → smsid)

Runs preprocess then convert as subprocesses (matching real user invocation),
then reads the output graph files and asserts Stage 1 and Stage 2 nodes/edges.
"""
import gzip
import json
import subprocess
import sys
from pathlib import Path

# Seeded values used in assertions below.
_COMPUTER_SID = "S-1-5-21-10-20-30-1104"
_SITE_CODE_CAS = "CAS"
_SITE_CODE_PRIMARY = "PS1"

# Stage 2 seeded values.
# Collection node id = upper(collection_id)@root_site_code (root = CAS here).
_COLLECTION_ID = "SMS00001"
_COLLECTION_NODE_ID = f"{_COLLECTION_ID}@{_SITE_CODE_CAS}"

# AdminUser node id = upper(logon_name)@root_site_code.
# The logon_name uses a single backslash (DOMAIN\user); in Python source that is \\.
_ADMIN_LOGON = "MAYYHEM\\sccm-admin"
_ADMIN_SID = "S-1-5-21-10-20-30-1200"
_ADMIN_NODE_ID = f"{_ADMIN_LOGON.upper()}@{_SITE_CODE_CAS}"

# ClientDevice node id = upper(smsid).
_CLIENT_SMSID = "GUID:client-seed-01"
_CLIENT_NODE_ID = _CLIENT_SMSID.upper()


def _seed_raw(raw: Path) -> None:
    """Write a minimal real raw tree that preprocess can consume.

    Column names are the clean snake_case names the post-Task-3 collectors emit.
    Each table dir gets one gzipped JSONL file with one data row.
    """
    # --- adminservice_r_system: one computer with a real domain SID ---
    r_sys_dir = raw / "sccm" / "adminservice_r_system"
    r_sys_dir.mkdir(parents=True)
    with gzip.open(r_sys_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(
            json.dumps({
                "sid": _COMPUTER_SID,
                "name": "DESKTOP-SEED",
                "obsolete": False,
                "resource_id": 42,
                "source_site_code": _SITE_CODE_PRIMARY,
                "system_roles": "SMS Provider",
                "sms_unique_identifier": "GUID:seed-test",
            }) + "\n"
        )

    # --- adminservice_site_definitions: CAS + Primary so hierarchy + nodes fire ---
    site_def_dir = raw / "sccm" / "adminservice_site_definitions"
    site_def_dir.mkdir(parents=True)
    with gzip.open(site_def_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        # DLT skips null-valued fields when inferring schema — use placeholder
        # non-null strings so it creates site_guid/sql_server_name/sql_database_name
        # columns in DuckDB. Without them the _node_site INSERT fails silently via
        # _safe() (BinderException on the missing column reference), leaving node_site
        # empty and producing no SCCM_Site nodes in convert.
        # CAS has no parent; Primary's parent is CAS.
        fh.write(json.dumps({
            "site_code": _SITE_CODE_CAS,
            "parent_site_code": None,
            "site_type": 4,
            "site_guid": "00000000-0000-0000-0000-000000000000",
            "sql_server_name": "SQLSRV",
            "sql_database_name": "CM_CAS",
        }) + "\n")
        fh.write(json.dumps({
            "site_code": _SITE_CODE_PRIMARY,
            "parent_site_code": _SITE_CODE_CAS,
            "site_type": 2,
            "site_guid": "11111111-1111-1111-1111-111111111111",
            "sql_server_name": "SQLSRV",
            "sql_database_name": "CM_PS1",
        }) + "\n")

    # --- adminservice_collections: one collection -> SCCM_Collection node ---
    # collection_type=2 (Device collection). source_site_code is not used by the
    # transform but is included so DLT infers a schema with all expected columns.
    coll_dir = raw / "sccm" / "adminservice_collections"
    coll_dir.mkdir(parents=True)
    with gzip.open(coll_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "collection_id": _COLLECTION_ID,
            "name": "All Systems",
            "collection_type": 2,
            "source_site_code": _SITE_CODE_CAS,
        }) + "\n")

    # --- adminservice_admins: one user admin -> SCCM_AdminUser node + SCCM_IsMappedTo edge ---
    # _edge_is_mapped_to: start = upper(admin_sid), end = upper(logon_name)@root.
    # admin_sid is supplied directly so the coalesce picks it without needing a
    # principal_by_name hit. is_group=false so the row also feeds node_user (sccm_infra=True).
    admins_dir = raw / "sccm" / "adminservice_admins"
    admins_dir.mkdir(parents=True)
    with gzip.open(admins_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "logon_name": _ADMIN_LOGON,
            "admin_sid": _ADMIN_SID,
            "is_group": False,
        }) + "\n")

    # --- adminservice_client_devices: one real client -> SCCM_ClientDevice node + SCCM_HasClient edge ---
    # Requires is_client=True and is_obsolete=False to pass the node_client_device filter.
    # resource_id is included so DLT infers the column and the resource_id_str computation
    # binds without a BinderException.
    client_dir = raw / "sccm" / "adminservice_client_devices"
    client_dir.mkdir(parents=True)
    with gzip.open(client_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "smsid": _CLIENT_SMSID,
            "name": "CLIENT-SEED",
            "resource_id": 101,
            "site_code": _SITE_CODE_PRIMARY,
            "is_client": True,
            "is_obsolete": False,
        }) + "\n")


def test_preprocess_then_convert_emits_real_nodes(tmp_path):
    """Preprocess + convert on real seeded data must emit Stage 1 and Stage 2 nodes/edges
    and must NOT emit the Stage-0 spike (SPIKE-1 / SCCM_Spike).

    Stage 1 (pre-existing): Computer + SCCM_Site.
    Stage 2 (new): SCCM_Collection, SCCM_AdminUser, SCCM_IsMappedTo, SCCM_HasClient.
    """
    raw = tmp_path / "raw"
    _seed_raw(raw)
    db = tmp_path / "lookup.duckdb"
    graph = tmp_path / "graph"

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "openhound", *args],
            capture_output=True,
            text=True,
        )

    # --- preprocess ---
    pre = run("preprocess", "sccm", str(raw), str(db))
    assert pre.returncode == 0, (
        f"preprocess failed (rc={pre.returncode}):\n{pre.stderr}"
    )

    # --- convert ---
    conv = run("convert", "sccm", str(raw / "sccm"), str(graph), "--lookup-file", str(db))
    assert conv.returncode == 0, (
        f"convert failed (rc={conv.returncode}):\n{conv.stderr}"
    )

    # --- collect all graph output ---
    nodes, edges = [], []
    for f in graph.glob("*.json"):
        doc = json.loads(f.read_text())
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]

    node_ids = [n["id"] for n in nodes]
    node_kinds = [kind for n in nodes for kind in n.get("kinds", [])]
    edge_kinds = [e["kind"] for e in edges]

    # --- Stage 1 assertions (unchanged) ---

    # Computer node from the seeded adminservice_r_system row must appear.
    assert _COMPUTER_SID in node_ids, (
        f"Expected Computer node {_COMPUTER_SID!r} in output; got node ids: {node_ids}"
    )

    # SCCM_Site node for at least the CAS must appear (site definitions were seeded).
    assert _SITE_CODE_CAS in node_ids, (
        f"Expected SCCM_Site node {_SITE_CODE_CAS!r} in output; got node ids: {node_ids}"
    )

    # Kinds sanity checks.
    assert "Computer" in node_kinds, f"No Computer kind in output; kinds seen: {node_kinds}"
    assert "SCCM_Site" in node_kinds, f"No SCCM_Site kind in output; kinds seen: {node_kinds}"

    # The Stage-0 spike must be gone.
    assert "SPIKE-1" not in node_ids, "Stage-0 spike node SPIKE-1 is still present in output"
    assert "SCCM_Spike" not in edge_kinds, "Stage-0 spike edge SCCM_Spike is still present in output"

    # --- Stage 2 assertions ---

    # SCCM_Collection node from the seeded adminservice_collections row must appear.
    # id = upper(collection_id)@root_site_code; root is CAS (site_type=4).
    assert _COLLECTION_NODE_ID in node_ids, (
        f"Expected SCCM_Collection node {_COLLECTION_NODE_ID!r} in output; "
        f"got node ids: {node_ids}"
    )
    assert "SCCM_Collection" in node_kinds, (
        f"No SCCM_Collection kind in output; kinds seen: {node_kinds}"
    )

    # SCCM_AdminUser node from the seeded adminservice_admins row must appear.
    # id = upper(logon_name)@root_site_code.
    assert _ADMIN_NODE_ID in node_ids, (
        f"Expected SCCM_AdminUser node {_ADMIN_NODE_ID!r} in output; "
        f"got node ids: {node_ids}"
    )
    assert "SCCM_AdminUser" in node_kinds, (
        f"No SCCM_AdminUser kind in output; kinds seen: {node_kinds}"
    )

    # SCCM_IsMappedTo edge: admin_sid -> SCCM_AdminUser node (one per seeded admin).
    assert "SCCM_IsMappedTo" in edge_kinds, (
        f"No SCCM_IsMappedTo edge in output; edge kinds seen: {edge_kinds}"
    )

    # SCCM_HasClient edge: site_code -> smsid (from the seeded client device).
    assert "SCCM_HasClient" in edge_kinds, (
        f"No SCCM_HasClient edge in output; edge kinds seen: {edge_kinds}"
    )
