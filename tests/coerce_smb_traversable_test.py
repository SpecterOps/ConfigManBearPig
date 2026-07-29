"""Task 6 guard tests: `SCCM_CoerceAndRelayToSMB` traversability + deterministic
possible-client-device ids.

Audited (2026-07-27) before this task started, per the plan: both halves were
ALREADY correct in the current code --
  - `SCCM_CoerceAndRelayToSMB` is already in `TRAVERSABLE_EDGE_KINDS`
    (kinds/edges.py), with an inline comment explaining the CMBP kind-name-mismatch
    bug this avoids ([[sccm-stage6-relay-decisions]]): CMBP's own allow-list named
    "CoerceAndRelayNTLMtoSMB", but the function that builds the edge emits it under
    a different name, so CMBP's port left the SMB relay silently non-traversable.
  - `_node_client_device_possible` already mints a deterministic id
    (`upper(object_sid) || '@' || root`), not CMBP's random GUID.
So no production change was needed for this task -- these are guard tests only,
pinning both facts against regression.
"""
import duckdb

from openhound_sccm.kinds.edges import SCCM_COERCE_AND_RELAY_TO_SMB, TRAVERSABLE_EDGE_KINDS
from openhound_sccm.models.graph_edge import GraphEdge
from openhound_sccm.transforms import transforms


def _seed_possible_client(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.collection_settings AS "
        "SELECT false AS disable_possible_edges, false AS enable_bad_opsec"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'WS09' AS name"
    )


def test_possible_client_ids_are_deterministic_across_reruns():
    def run():
        con = duckdb.connect()
        _seed_possible_client(con)
        transforms(con)
        return con.execute("SELECT smsid FROM sccm.node_client_device").fetchone()[0]

    id1 = run()
    id2 = run()
    assert id1 == id2 == "S-1-5-21-1-2-3-1104@PS1"


def test_coerce_and_relay_to_smb_kind_is_in_traversable_allowlist():
    assert SCCM_COERCE_AND_RELAY_TO_SMB in TRAVERSABLE_EDGE_KINDS


def test_coerce_and_relay_to_smb_edge_is_traversable_end_to_end():
    # Confirms the allow-list membership above actually reaches the emitted edge's
    # `traversable` property (GraphEdge.edges computes it from the allow-list).
    e = list(GraphEdge(start_id="A", end_id="B", kind=SCCM_COERCE_AND_RELAY_TO_SMB).edges)[0]
    assert e.properties.traversable is True
