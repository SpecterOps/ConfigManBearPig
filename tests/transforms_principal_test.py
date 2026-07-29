# src/openhound_sccm/transforms_principal_test.py
import duckdb
from openhound_sccm.transforms import transforms


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'HOST1' AS name, 'S-1-5-21-1-2-3-1104' AS sid")
    con.execute("CREATE TABLE sccm.adminservice_r_user   AS SELECT 'alice' AS name, 's-1-5-21-1-2-3-1106' AS sid")
    # two-site hierarchy: CAS 'CAS' (type 4), Primary 'PS1' (type 2, parent CAS)
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS "
                "SELECT * FROM (VALUES ('CAS', NULL, 4), ('PS1', 'CAS', 2)) AS t(site_code, parent_site_code, site_type)")


def test_principal_by_name_unions_and_uppercases():
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    rows = dict(con.execute("SELECT name, sid FROM sccm.principal_by_name ORDER BY name").fetchall())
    assert rows == {"HOST1": "S-1-5-21-1-2-3-1104", "alice": "S-1-5-21-1-2-3-1106"}


def test_root_site_code_resolves_to_cas():
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    roots = dict(con.execute("SELECT site_code, root_site_code FROM sccm.site_hierarchy ORDER BY site_code").fetchall())
    assert roots == {"CAS": "CAS", "PS1": "CAS"}


def test_principal_by_name_includes_user_groups():
    """SMS_R_UserGroup rows (unique_usergroup_name + SID) must land in
    principal_by_name so security_group_name memberships resolve to group SIDs
    offline, replacing CMBP's per-name live AD lookup."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_user_group AS SELECT "
        "'mayyhem\\Domain Users' AS unique_usergroup_name, 'S-1-5-21-1-2-3-513' AS sid"
    )
    con.execute(
        "CREATE TABLE sccm.wmi_user_group AS SELECT "
        "'mayyhem\\Domain Admins' AS unique_usergroup_name, 's-1-5-21-1-2-3-512' AS sid"
    )
    transforms(con)
    rows = dict(con.execute("SELECT name, sid FROM sccm.principal_by_name").fetchall())
    assert rows.get("mayyhem\\Domain Users") == "S-1-5-21-1-2-3-513", rows
    # SID uppercased like every other principal_by_name source.
    assert rows.get("mayyhem\\Domain Admins") == "S-1-5-21-1-2-3-512", rows
