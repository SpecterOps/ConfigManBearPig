"""Task 5: provenance tags on the Tier-B SCCM edges.

`SCCM_AssignAllPermissions`, `SCCM_LocalAdminRequired`, `SCCM_CoerceAndRelayToAdminService`
and `SCCM_CoerceAndRelayToSMB` are unconditionally assumption-derived (they template a
permission/relay conclusion from role topology, never read out of an ACL) -- so they
carry `assumed=true`/`assumptionBasis`/an `Assumed-*` collectionSource tag on every row,
regardless of `--disable-possible-edges` (design spec §7 ruling, 2026-07-28: these
builders' gates are measured evidence, not a topology guess, so they stay flag-independent
-- the stamp is unconditional, not flag-gated). `_edge_replication` stays unmarked; it is
confirmed hierarchy topology, not an assumption.
"""
import duckdb

from openhound_sccm.transforms import (
    ASSIGN_ALL_PERMISSIONS_SOURCE,
    COERCE_RELAY_SOURCE,
    LOCAL_ADMIN_REQUIRED_SOURCE,
    _edge_coerce_relay_adminservice,
    _edge_coerce_relay_smb,
    _edge_replication,
    _graph_edges_init,
    transforms,
)

SCHEMA = "sccm"


def test_assign_all_permissions_is_stamped_assumed():
    con = duckdb.connect(":memory:")
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.adminservice_site_definitions_computers AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'SMSPROV' AS name, "
        "'[\"SMS Provider@PS1\"]' AS sccm_site_system_roles, true AS sccm_infra"
    )
    transforms(con)
    row = con.execute(
        f"SELECT assumed, assumption_basis, collection_source FROM {SCHEMA}.graph_edges "
        f"WHERE kind = 'SCCM_AssignAllPermissions'"
    ).fetchone()
    assert row[0] is True
    assert row[1]
    assert ASSIGN_ALL_PERMISSIONS_SOURCE in row[2]


def test_local_admin_required_is_stamped_assumed():
    con = duckdb.connect(":memory:")
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-100', 'SITESRV', '[\"SMS Site Server@PS1\"]', true), "
        "('S-1-5-21-1-2-3-200', 'MP', '[\"SMS Management Point@PS1\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    row = con.execute(
        f"SELECT assumed, assumption_basis, collection_source FROM {SCHEMA}.graph_edges "
        f"WHERE kind = 'SCCM_LocalAdminRequired'"
    ).fetchone()
    assert row[0] is True
    assert row[1]
    assert LOCAL_ADMIN_REQUIRED_SOURCE in row[2]


def test_coerce_relay_adminservice_is_stamped_assumed():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_computer AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1001','PROV01.mayyhem.com',['SMS Provider@PS1'], NULL), "
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, restrict_receiving_ntlm_traffic)"
    )
    _graph_edges_init(con, SCHEMA)
    _edge_coerce_relay_adminservice(con, SCHEMA)
    row = con.execute(
        f"SELECT assumed, assumption_basis, collection_source FROM {SCHEMA}.graph_edges"
    ).fetchone()
    assert row[0] is True
    assert row[1]
    assert COERCE_RELAY_SOURCE in row[2]
    assert "Post-processing" in row[2]  # existing tag preserved, not replaced (Task 3)


def test_coerce_relay_smb_is_stamped_assumed():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_computer AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-7001','DP01.mayyhem.com',['SMS Distribution Point@PS1'],"
        " false, ['SMB-Negotiate'], NULL), "
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'],"
        " true, [], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, smb_signing_required, "
        "smb_signing_source, restrict_receiving_ntlm_traffic)"
    )
    _graph_edges_init(con, SCHEMA)
    _edge_coerce_relay_smb(con, SCHEMA)
    row = con.execute(
        f"SELECT assumed, assumption_basis, collection_source FROM {SCHEMA}.graph_edges"
    ).fetchone()
    assert row[0] is True
    assert row[1]
    assert COERCE_RELAY_SOURCE in row[2]
    assert "SMB-Negotiate" in row[2]  # existing tag preserved, not replaced (Task 3)


def test_replication_stays_unmarked_confirmed_topology():
    # SCCM_AdminsReplicatedTo is confirmed hierarchy topology, not an assumption --
    # it must NOT get the assumed stamp.
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.site_hierarchy AS SELECT * FROM (VALUES "
        "('CAS', NULL, 4), ('PS1', 'CAS', 2)) AS t(site_code, parent_site_code, site_type)"
    )
    _graph_edges_init(con, SCHEMA)
    _edge_replication(con, SCHEMA)
    row = con.execute(
        f"SELECT assumed FROM {SCHEMA}.graph_edges WHERE kind = 'SCCM_AdminsReplicatedTo'"
    ).fetchone()
    assert row[0] is None
