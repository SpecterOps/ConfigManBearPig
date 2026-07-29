import duckdb
from openhound_sccm.transforms import transforms


def test_assign_all_permissions_from_sms_provider():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) AS t(site_code,parent_site_code,site_type)")
    # a computer with an SMS Provider site-system role (system_roles arrives as JSON-array text)
    con.execute("CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT "
                "'S-1-5-21-1-2-3-1104' AS object_sid, 'SMSPROV' AS name, '[\"SMS Provider@PS1\"]' AS sccm_site_system_roles, true AS sccm_infra")
    transforms(con)
    ends = sorted(r[0] for r in con.execute("SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AssignAllPermissions'").fetchall())
    assert ends == ["CAS", "PS1"]


def test_assign_all_permissions_no_edge_without_sms_provider_role():
    """A computer with no SMS Provider role should produce no SCCM_AssignAllPermissions edges."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) AS t(site_code,parent_site_code,site_type)")
    # computer with a different role — not an SMS Provider
    con.execute("CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT "
                "'S-1-5-21-1-2-3-1105' AS object_sid, 'DPSERVER' AS name, '[\"SMS Distribution Point@PS1\"]' AS sccm_site_system_roles, true AS sccm_infra")
    transforms(con)
    rows = con.execute("SELECT count(*) FROM sccm.graph_edges WHERE kind='SCCM_AssignAllPermissions'").fetchone()[0]
    assert rows == 0
