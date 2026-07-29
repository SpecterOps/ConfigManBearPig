# tests/edge_all_permissions_test.py
import duckdb
from openhound_sccm.transforms import transforms


def _seed_hierarchy(con: duckdb.DuckDBPyConnection) -> None:
    """Seed a CAS->PS1->SEC hierarchy with the Full Administrator role and both global collections."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
        "(VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) AS t(site_code,parent_site_code,site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_security_roles AS "
        "SELECT 'SMS0001R' AS role_id, 'Full Administrator' AS role_name"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_collections AS SELECT * FROM (VALUES "
        "('SMS00001','All Systems',2),('SMS00004','All Users and User Groups',1)) AS t(collection_id,name,collection_type)"
    )


def test_all_permissions_requires_both_collections():
    """Admin with SMS0001R + both SMS00001 and SMS00004 -> AllPermissions to CAS and PS1, not SEC."""
    con = duckdb.connect(":memory:")
    _seed_hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS "
        "SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
        "'All Systems, All Users and User Groups' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names"
    )
    transforms(con)
    ends = sorted(r[0] for r in con.execute(
        "SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AllPermissions' AND start_id='MAYYHEM\\ADM@CAS'"
    ).fetchall())
    assert ends == ["CAS", "PS1"]


def test_all_permissions_missing_all_systems_no_edge():
    """Admin with SMS0001R and ONLY SMS00004 (not SMS00001) must NOT get AllPermissions.
    Both collections are required — this is the crux of the builder."""
    con = duckdb.connect(":memory:")
    _seed_hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS "
        "SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
        "'All Users and User Groups' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names"
    )
    transforms(con)
    rows = con.execute(
        "SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AllPermissions' AND start_id='MAYYHEM\\ADM@CAS'"
    ).fetchall()
    assert rows == [], "AllPermissions must NOT be granted with only SMS00004 assigned"


def test_all_permissions_missing_all_users_no_edge():
    """Admin with SMS0001R and ONLY SMS00001 (not SMS00004) must NOT get AllPermissions.
    Both collections are required — this is the crux of the builder."""
    con = duckdb.connect(":memory:")
    _seed_hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS "
        "SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
        "'All Systems' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names"
    )
    transforms(con)
    rows = con.execute(
        "SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AllPermissions' AND start_id='MAYYHEM\\ADM@CAS'"
    ).fetchall()
    assert rows == [], "AllPermissions must NOT be granted with only SMS00001 assigned"


def test_all_permissions_secondary_excluded():
    """AllPermissions edges must not target secondary sites (site_type=1)."""
    con = duckdb.connect(":memory:")
    _seed_hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS "
        "SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group, "
        "'All Systems, All Users and User Groups' AS collection_names, 'SMS0001R' AS roles, NULL AS role_names"
    )
    transforms(con)
    rows = con.execute(
        "SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AllPermissions' AND end_id='SEC'"
    ).fetchall()
    assert rows == [], "AllPermissions must NOT target secondary sites"
