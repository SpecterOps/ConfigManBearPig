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


# --- con-edee: a site of UNKNOWN type is not a takeover target ---------------
#
# The non-secondary filter was `coalesce(site_type, 0) != 1`, which reads an
# unknown type as "not a secondary" and therefore as a valid target. At low
# privilege that is exactly backwards: a site discovered only by bare site code
# (mayyhem's SEC secondary, found via SMB share comments) has site_type NULL, so
# every SMS Provider gained a spurious "can assign all permissions" edge to it --
# 12 edges where the lab has 8. Claiming hierarchy takeover over a site whose type
# was never established is a false positive in an attack-path tool, so an unknown
# type must EXCLUDE the site rather than include it.

def test_assign_all_permissions_skips_a_site_of_unknown_type():
    """A site whose type was never learned is not asserted as a target."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # CAS + PS1 typed by a privileged source; SEC known only as a bare site code,
    # exactly as a low-privilege run discovers it.
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4),('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.smb_sites AS SELECT * FROM "
                "(VALUES ('SMB-Shares','SEC')) AS t(source,site_code)")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT "
                "'S-1-5-21-1-2-3-1104' AS object_sid, 'SMSPROV' AS name, "
                "'[\"SMS Provider@PS1\"]' AS sccm_site_system_roles, true AS sccm_infra")
    transforms(con)
    ends = sorted(r[0] for r in con.execute(
        "SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AssignAllPermissions'").fetchall())
    assert ends == ["CAS", "PS1"], f"SEC (unknown type) must not be a target, got {ends}"


def test_assign_all_permissions_still_skips_a_known_secondary():
    """The original behaviour is preserved when the type IS known."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT "
                "'S-1-5-21-1-2-3-1104' AS object_sid, 'SMSPROV' AS name, "
                "'[\"SMS Provider@PS1\"]' AS sccm_site_system_roles, true AS sccm_infra")
    transforms(con)
    ends = sorted(r[0] for r in con.execute(
        "SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AssignAllPermissions'").fetchall())
    assert ends == ["CAS", "PS1"]


# --- con-edee follow-up: the DATABASE arm had the same fail-open bug -----------
#
# con-edee replaced `coalesce(site_type, 0) != 1` in five builders, but missed
# `_edge_mssql_db_assign_all` -- the arm that starts at a site DATABASE rather than
# at an SMS Provider computer. Its docstring claimed the filter "drops secondary-site
# databases (e.g. CM_SEC)", but `coalesce(NULL, 0) != 1` reads an UNKNOWN type as
# non-secondary, so a secondary discovered only by bare site code passed straight
# through. It stayed dormant only because a low-privilege run never built a site
# database for SEC; the moment one exists, CM_SEC claims hierarchy takeover over its
# own site. A secondary holds a partial replica with no RBAC tables, so that edge is
# always a false positive.

def _con_with_sec_site_database():
    """SEC known ONLY as a bare site code (type NULL) but WITH a site database.

    This is the low-privilege shape: `adminservice_site_definitions` never mentions
    SEC (that source is admin-gated), so its type is unknown, while the host carrying
    'SMS SQL Server@SEC' makes it a confirmed site database.
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4),('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.smb_sites AS SELECT * FROM "
                "(VALUES ('SMB-Shares','SEC')) AS t(source,site_code)")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
                "('S-1-5-21-1-2-3-1104','SMSPROV','[\"SMS Provider@PS1\"]',true),"
                "('S-1-5-21-1-2-3-1113','SECSQL','[\"SMS SQL Server@SEC\"]',true)"
                ") AS t(object_sid,name,sccm_site_system_roles,sccm_infra)")
    return con


def test_secondary_site_database_never_assigns_all_permissions():
    """A site DB for a site of unknown type must not claim takeover of that site."""
    con = _con_with_sec_site_database()
    transforms(con)
    # Guard against a vacuous pass: the SEC database must actually have been built,
    # otherwise this asserts nothing about the filter.
    sec_dbs = con.execute(
        "SELECT count(*) FROM sccm.node_mssql_database WHERE upper(sccm_site) = 'SEC'"
    ).fetchone()[0]
    assert sec_dbs > 0, "fixture no longer builds a SEC site database; test is vacuous"

    ends = sorted({r[0] for r in con.execute(
        "SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AssignAllPermissions'").fetchall()})
    assert "SEC" not in ends, f"secondary/unknown-type site claimed as a target: {ends}"


def test_known_secondary_site_database_never_assigns_all_permissions():
    """Same rule when the type IS known to be Secondary (site_type = 1)."""
    con = _con_with_sec_site_database()
    con.execute("DROP TABLE sccm.adminservice_site_definitions")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS',NULL,4),('PS1','CAS',2),('SEC','PS1',1)) "
                "AS t(site_code,parent_site_code,site_type)")
    transforms(con)
    ends = sorted({r[0] for r in con.execute(
        "SELECT end_id FROM sccm.graph_edges WHERE kind='SCCM_AssignAllPermissions'").fetchall()})
    assert "SEC" not in ends, f"known secondary claimed as a target: {ends}"
