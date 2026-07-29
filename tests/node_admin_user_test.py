# src/openhound_sccm/node_admin_user_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_node_admin_user_one_row_per_logon():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    # same admin replicated from two sites -> one node (dedup on upper(logon_name))
    # Use single backslash in the SQL literal ('MAYYHEM\sccmadmin') so DuckDB stores
    # one backslash — matching the assertion below. Python \\  -> SQL \ -> stored \.
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\sccmadmin','S-1-5-21-1-2-3-1110','adm', false, 1), "
                "('MAYYHEM\\sccmadmin','S-1-5-21-1-2-3-1110','adm', false, 1)) "
                "AS t(logon_name, admin_sid, display_name, is_group, account_type)")
    transforms(con)
    rows = con.execute("SELECT logon_name, admin_sid, root_site_code FROM sccm.node_admin_user").fetchall()
    assert rows == [("MAYYHEM\\sccmadmin", "S-1-5-21-1-2-3-1110", "CAS")]


def test_node_admin_user_audit_scalars():
    """Audit fields from ADMIN_COLUMNS land in node_admin_user after transforms."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS SELECT "
        "'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, "
        "false AS is_group, 'adm disp' AS display_name, 'CAS' AS source_site, "
        "'admin@x' AS created_by, '2024-01-01' AS created_date, "
        "'mod@x' AS last_modified_by, '2024-06-01' AS last_modified_date"
    )
    transforms(con)
    r = con.execute(
        "SELECT display_name, source_site_code, created_by, created_date, "
        "last_modified_by, last_modified_date "
        "FROM sccm.node_admin_user"
    ).fetchone()
    assert r == ("adm disp", "CAS", "admin@x", "2024-01-01", "mod@x", "2024-06-01")


def test_node_admin_user_assignment_lists():
    """collection_ids, role_ids, member_of are resolved from raw admin rows."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT "
                "'SMS00001' AS collection_id, 'All Systems' AS name, "
                "2 AS collection_type, 'CAS' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT "
                "'SMS0001R' AS role_id, 'Full Administrator' AS role_name")
    # Use a parameter insert so the backslash in MAYYHEM\adm is unambiguous.
    con.execute("CREATE TABLE sccm.adminservice_admins "
                "(logon_name VARCHAR, admin_sid VARCHAR, is_group BOOLEAN, "
                "display_name VARCHAR, source_site VARCHAR, "
                "collection_names VARCHAR, roles VARCHAR, role_names VARCHAR)")
    con.execute("INSERT INTO sccm.adminservice_admins VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ["MAYYHEM\\adm", "S-1-5-21-1-2-3-1110", False,
                 "adm disp", "CAS", "All Systems", "SMS0001R", None])
    transforms(con)
    r = con.execute(
        "SELECT display_name, source_site_code, collection_ids, role_ids, member_of "
        "FROM sccm.node_admin_user"
    ).fetchone()
    assert r[0] == "adm disp"
    assert r[1] == "CAS"
    assert r[2] == ["SMS00001@CAS"]    # collection node id
    assert r[3] == ["SMS0001R"]        # raw role id
    assert r[4] == ["SMS0001R@CAS"]    # role node id


def test_node_admin_user_member_of_role_name_fallback():
    """When roles is empty, role_names resolves via role_by_name for member_of."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT "
                "'SMS0002R' AS role_id, 'Read-Only Analyst' AS role_name")
    con.execute("CREATE TABLE sccm.adminservice_admins "
                "(logon_name VARCHAR, admin_sid VARCHAR, is_group BOOLEAN, "
                "roles VARCHAR, role_names VARCHAR)")
    con.execute("INSERT INTO sccm.adminservice_admins VALUES (?, ?, ?, ?, ?)",
                ["MAYYHEM\\reader", "S-1-5-21-1-2-3-1111", False,
                 None, '["Read-Only Analyst"]'])
    transforms(con)
    r = con.execute(
        "SELECT role_ids, member_of FROM sccm.node_admin_user"
    ).fetchone()
    # roles was NULL, so role_ids is empty; member_of populated via role_names fallback
    assert r[0] == []
    assert r[1] == ["SMS0002R@CAS"]


def test_node_admin_user_empty_lists_when_no_assignments():
    """An admin with no roles or collection assignments gets empty list fields."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_admins "
                "(logon_name VARCHAR, admin_sid VARCHAR, is_group BOOLEAN)")
    con.execute("INSERT INTO sccm.adminservice_admins VALUES (?, ?, ?)",
                ["MAYYHEM\\noperms", "S-1-5-21-1-2-3-1200", False])
    transforms(con)
    r = con.execute(
        "SELECT collection_ids, role_ids, member_of FROM sccm.node_admin_user"
    ).fetchone()
    assert r[0] == []
    assert r[1] == []
    assert r[2] == []
