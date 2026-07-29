"""End-to-end: authored help content lands on edges (SCCM_AdminsReplicatedTo and
SCCM_HasClient) and is pruned from unauthored kinds -- verified against a real
unauthored-kind edge (HasSession), not just asserted over an empty set.

The pruning check is dynamic against EDGE_HELP: any emitted edge whose kind has no
authored block must carry none of the five help keys. HasSession is used as the
guaranteed unauthored edge because BloodHound documents it natively, so it is
permanently excluded from EDGE_HELP and cannot drift into it the way a PENDING kind can."""
import gzip
import json
import subprocess
import sys
from pathlib import Path

from openhound_sccm.edge_help import EDGE_HELP
from openhound_sccm.kinds import edges as ek

_HELP_KEYS = ("general", "windowsAbuse", "linuxAbuse", "opsec", "references")

_SITE_CODE_CAS = "CAS"
_SITE_CODE_PRIMARY = "PS1"
_CLIENT_SMSID = "GUID:edge-help-seed-01"
_HOST_SID = "S-1-5-21-10-20-30-1104"
_SESSION_USER_SID = "S-1-5-21-10-20-30-1300"


def _seed_raw(raw: Path) -> None:
    """Seed a minimal raw tree producing three edge kinds:

    - two site definitions (CAS parent of PS1)  -> SCCM_AdminsReplicatedTo (authored)
    - one real client device (site_code->smsid) -> SCCM_HasClient          (authored)
    - one RemoteRegistry logged-on user         -> HasSession              (never authored)

    HasSession is one of the kinds BloodHound documents natively, so it is permanently
    excluded from EDGE_HELP -- a stable unauthored-kind edge for the "no leaked help keys"
    assertion below (it cannot drift into EDGE_HELP the way a PENDING kind can).
    """
    site_def_dir = raw / "sccm" / "adminservice_site_definitions"
    site_def_dir.mkdir(parents=True)
    with gzip.open(site_def_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
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

    # --- adminservice_client_devices: one real client -> SCCM_HasClient edge (authored) ---
    # Requires is_client=True and is_obsolete=False to pass the node_client_device filter.
    client_dir = raw / "sccm" / "adminservice_client_devices"
    client_dir.mkdir(parents=True)
    with gzip.open(client_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "smsid": _CLIENT_SMSID,
            "name": "CLIENT-EDGE-HELP-SEED",
            "resource_id": 101,
            "site_code": _SITE_CODE_PRIMARY,
            "is_client": True,
            "is_obsolete": False,
        }) + "\n")

    # --- remoteregistry_users: one logged-on user -> HasSession edge (never authored) ---
    # _edge_has_session: start = upper(host_object_sid), end = upper(object_sid). Endpoints are
    # matched by id, so the SIDs need not resolve to seeded nodes for the edge to be emitted.
    rr_users_dir = raw / "sccm" / "remoteregistry_users"
    rr_users_dir.mkdir(parents=True)
    with gzip.open(rr_users_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "host_object_sid": _HOST_SID,
            "object_sid": _SESSION_USER_SID,
        }) + "\n")


def test_help_content_emitted_on_authored_edges_and_pruned_elsewhere(tmp_path):
    raw = tmp_path / "raw"
    _seed_raw(raw)
    db = tmp_path / "lookup.duckdb"
    graph = tmp_path / "graph"

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "openhound", *args], capture_output=True, text=True
        )

    pre = run("preprocess", "sccm", str(raw), str(db))
    assert pre.returncode == 0, f"preprocess failed:\n{pre.stderr}"
    conv = run("convert", "sccm", str(raw / "sccm"), str(graph), "--lookup-file", str(db))
    assert conv.returncode == 0, f"convert failed:\n{conv.stderr}"

    edges = []
    for f in graph.glob("*.json"):
        edges += json.loads(f.read_text())["graph"]["edges"]

    kinds = [e["kind"] for e in edges]

    # --- Authored kind 1: SCCM_AdminsReplicatedTo carries all five help keys with real content ---
    replicated = [e for e in edges if e["kind"] == ek.SCCM_ADMINS_REPLICATED_TO]
    assert replicated, f"No SCCM_AdminsReplicatedTo edge emitted; kinds: {kinds}"
    props = replicated[0]["properties"]
    for key in _HELP_KEYS:
        assert key in props, f"Expected help key {key!r} on SCCM_AdminsReplicatedTo; got {sorted(props)}"
    assert "replicated" in props["general"].lower()
    assert isinstance(props["references"], list) and props["references"][0].startswith("http")

    # --- Authored kind 2: SCCM_HasClient carries its help content end-to-end ---
    has_client = [e for e in edges if e["kind"] == ek.SCCM_HAS_CLIENT]
    assert has_client, f"seed did not produce the expected SCCM_HasClient edge; kinds: {kinds}"
    client_props = has_client[0]["properties"]
    assert "client device" in client_props["general"].lower()
    assert "SharpSCCM" in client_props["windowsAbuse"]
    assert "sccmhunter" in client_props["linuxAbuse"]

    # --- Unauthored kind: HasSession (BloodHound-native, permanently excluded from EDGE_HELP)
    #     must exist so the pruning check below is not vacuous, and must carry none of the
    #     five help keys. ---
    assert ek.HAS_SESSION in kinds, (
        f"seed did not produce the expected unauthored-kind edge HasSession; kinds: {kinds}"
    )
    unauthored = [e for e in edges if e["kind"] not in EDGE_HELP]
    assert unauthored, f"no unauthored-kind edge emitted to prove pruning; kinds: {kinds}"
    for e in unauthored:
        leaked = [k for k in _HELP_KEYS if k in e["properties"]]
        assert not leaked, f"Unauthored kind {e['kind']!r} leaked help keys {leaked}"
