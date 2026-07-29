# src/openhound_sccm/node_security_role_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_node_security_role_one_row_per_id():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS000AR' AS role_id, "
                "'Full Administrator' AS role_name, 'desc' AS role_description, true AS is_built_in, "
                "false AS is_sec_admin_role")
    transforms(con)
    r = con.execute("SELECT role_id, role_name, root_site_code FROM sccm.node_security_role").fetchone()
    assert r == ("SMS000AR", "Full Administrator", "CAS")


def test_node_security_role_audit_scalars():
    """Audit fields from ROLE_COLUMNS land in node_security_role after transforms."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute(
        "CREATE TABLE sccm.adminservice_security_roles AS SELECT "
        "'SMS0001R' AS role_id, 'Full Administrator' AS role_name, "
        "'CAS' AS source_site, 'admin@x' AS created_by, '2024-01-01' AS created_date, "
        "'mod@x' AS last_modified_by, '2024-06-01' AS last_modified_date"
    )
    transforms(con)
    r = con.execute(
        "SELECT site_code, created_by, created_date, last_modified_by, last_modified_date "
        "FROM sccm.node_security_role WHERE role_id='SMS0001R'"
    ).fetchone()
    assert r == ("CAS", "admin@x", "2024-01-01", "mod@x", "2024-06-01")


def test_node_security_role_members_admin_ids():
    """members = upper(logon_name)@root for each admin assigned to the role."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT "
                "'SMS0001R' AS role_id, 'Full Administrator' AS role_name, 'admin@x' AS created_by")
    # Use a parameter to insert the logon_name so backslash escaping is unambiguous.
    con.execute("CREATE TABLE sccm.adminservice_admins (logon_name VARCHAR, admin_sid VARCHAR, "
                "is_group BOOLEAN, roles VARCHAR, role_names VARCHAR)")
    con.execute("INSERT INTO sccm.adminservice_admins VALUES (?, ?, ?, ?, ?)",
                ["MAYYHEM\\adm", "S-1-5-21-1-2-3-1110", False, "SMS0001R", None])
    transforms(con)
    r = con.execute(
        "SELECT created_by, members FROM sccm.node_security_role WHERE role_id='SMS0001R'"
    ).fetchone()
    assert r[0] == "admin@x"
    assert r[1] == ["MAYYHEM\\ADM@CAS"]


def test_node_security_role_members_role_name_fallback():
    """When roles is empty, role_names resolves via role_by_name to populate members."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT "
                "'SMS0002R' AS role_id, 'Read-Only Analyst' AS role_name")
    # Use a parameter to insert the logon_name so backslash escaping is unambiguous.
    # roles is NULL; role_names carries the role name as a JSON array.
    con.execute("CREATE TABLE sccm.adminservice_admins (logon_name VARCHAR, admin_sid VARCHAR, "
                "is_group BOOLEAN, roles VARCHAR, role_names VARCHAR)")
    con.execute("INSERT INTO sccm.adminservice_admins VALUES (?, ?, ?, ?, ?)",
                ["MAYYHEM\\reader", "S-1-5-21-1-2-3-1111", False, None, '["Read-Only Analyst"]'])
    transforms(con)
    r = con.execute(
        "SELECT members FROM sccm.node_security_role WHERE role_id='SMS0002R'"
    ).fetchone()
    assert r[0] == ["MAYYHEM\\READER@CAS"]


def test_node_security_role_members_empty_when_no_admins():
    """A role with no admins assigned gets an empty members list."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT "
                "'SMS000AR' AS role_id, 'OSD Manager' AS role_name")
    transforms(con)
    r = con.execute(
        "SELECT members FROM sccm.node_security_role WHERE role_id='SMS000AR'"
    ).fetchone()
    assert r[0] == []
