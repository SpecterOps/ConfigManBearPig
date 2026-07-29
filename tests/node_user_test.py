# src/openhound_sccm/node_user_test.py
"""Tests for the node_user coalesce transform in transforms.py.

Each test seeds a minimal DuckDB schema that mimics one or more source tables,
runs the full transforms() call, and then asserts properties of the resulting
node_user table — one row per unique SID.
"""
import duckdb
from openhound_sccm.transforms import transforms


def test_node_user_one_row_per_sid():
    """r_user rows with the same SID from a single source should collapse to one row."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
        "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code"
    )
    transforms(con)
    rows = con.execute(
        "SELECT sid, name, list_sort(resource_ids) FROM sccm.node_user"
    ).fetchall()
    assert rows == [("S-1-5-21-1-2-3-1106", "alice", ["9@PS1"])]


def test_node_user_unions_r_user_and_remoteregistry():
    """The same SID from adminservice_r_user and remoteregistry_users should merge
    into one row; resource_ids come only from r_user (remoteregistry has none)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
        "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code"
    )
    # remoteregistry_users uses object_sid (clean snake_case column from Task-3 fix)
    con.execute(
        "CREATE TABLE sccm.remoteregistry_users AS SELECT "
        "'S-1-5-21-1-2-3-1106' AS object_sid, 'alice' AS sam_account_name"
    )
    transforms(con)
    rows = con.execute("SELECT sid, name, list_sort(resource_ids) FROM sccm.node_user").fetchall()
    assert len(rows) == 1
    sid, name, rids = rows[0]
    assert sid == "S-1-5-21-1-2-3-1106"
    assert rids == ["9@PS1"]


def test_node_user_sccm_infra_from_admins():
    """A user sourced from adminservice_admins (is_group=false) should have
    sccm_infra=True, even if that SID also appears in r_user without that flag."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT 'svc_sccm' AS name, "
        "'S-1-5-21-1-2-3-1500' AS sid, 42 AS resource_id, 'PS1' AS source_site_code"
    )
    # admin entry marks this user as an SCCM admin (is_group=false -> user)
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS SELECT "
        "'LAB\\\\svc_sccm' AS logon_name, 'S-1-5-21-1-2-3-1500' AS admin_sid, false AS is_group"
    )
    transforms(con)
    rows = con.execute("SELECT sid, sccm_infra FROM sccm.node_user").fetchall()
    assert len(rows) == 1
    sid, infra = rows[0]
    assert sid == "S-1-5-21-1-2-3-1500"
    assert infra is True


def test_node_user_stored_in_sccm_site_from_reserved_accounts():
    """A user in adminservice_reserved_accounts should have stored_in_sccm_site
    set to the site_code of the record that produced it."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # reserved_accounts uses object_sid (clean snake_case)
    con.execute(
        "CREATE TABLE sccm.adminservice_reserved_accounts AS SELECT "
        "'S-1-5-21-1-2-3-2000' AS object_sid, 'naa_account' AS name, 'PS1' AS site_code"
    )
    transforms(con)
    rows = con.execute("SELECT sid, stored_in_sccm_site FROM sccm.node_user").fetchall()
    assert len(rows) == 1
    sid, site = rows[0]
    assert sid == "S-1-5-21-1-2-3-2000"
    assert site == "PS1"


def test_node_user_uppercases_sid():
    """SIDs in any casing should be normalised to uppercase in node_user."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT 'bob' AS name, "
        "'s-1-5-21-1-2-3-1200' AS sid, NULL AS resource_id, 'PS1' AS source_site_code"
    )
    transforms(con)
    rows = con.execute("SELECT sid FROM sccm.node_user").fetchall()
    assert rows == [("S-1-5-21-1-2-3-1200",)]


def test_node_user_carries_ad_attrs():
    """adminservice_r_user rows with distinguished_name and user_principal_name
    must surface those columns in node_user after the coalesce."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS sid, 'alice' AS name, "
        "5 AS resource_id, 'CAS' AS source_site_code, "
        "'CN=alice,DC=lab' AS distinguished_name, 'alice@lab' AS user_principal_name"
    )
    transforms(con)
    r = con.execute(
        "SELECT distinguished_name, user_principal_name FROM sccm.node_user "
        "WHERE sid='S-1-5-21-1-2-3-1200'"
    ).fetchone()
    assert r == ("CN=alice,DC=lab", "alice@lab")


def test_node_user_sam_account_name_from_user_name():
    """SMS_R_User.UserName (raw column user_name) is the bare SAM (e.g. 'sqlsccmsvc');
    node_user must surface it as sam_account_name.

    Regression guard: without this, User nodes carry no samAccountName, so every edge
    keyed on the User endpoint by samAccountName fails — the SQL service account
    (HasSession, MSSQL_GetTGS/GetAdminTGS/ServiceAccountFor) and AD users alike.
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT "
        "'S-1-5-21-1-2-3-1116' AS sid, 'mayyhem\\svc (svc)' AS name, "
        "NULL AS resource_id, 'PS1' AS source_site_code, 'sqlsccmsvc' AS user_name"
    )
    transforms(con)
    r = con.execute(
        "SELECT sam_account_name FROM sccm.node_user WHERE sid='S-1-5-21-1-2-3-1116'"
    ).fetchone()
    assert r is not None
    assert r[0] == "sqlsccmsvc"


def test_node_user_sam_account_name_from_remoteregistry():
    """remoteregistry_users carries the bare SAM directly; it must reach node_user.sam_account_name."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.remoteregistry_users AS SELECT "
        "'S-1-5-21-1-2-3-1301' AS object_sid, 'localsvc' AS sam_account_name"
    )
    transforms(con)
    r = con.execute(
        "SELECT sam_account_name FROM sccm.node_user WHERE sid='S-1-5-21-1-2-3-1301'"
    ).fetchone()
    assert r is not None
    assert r[0] == "localsvc"


def test_node_user_ad_attrs_any_value_coalesce():
    """When both adminservice_r_user and wmi_r_user have the same SID,
    any_value picks one non-null distinguished_name (idempotent)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT "
        "'S-1-5-21-1-2-3-1300' AS sid, 'carol' AS name, "
        "6 AS resource_id, 'PS1' AS source_site_code, "
        "'CN=carol,DC=lab' AS distinguished_name, 'carol@lab' AS user_principal_name"
    )
    con.execute(
        "CREATE TABLE sccm.wmi_r_user AS SELECT "
        "'S-1-5-21-1-2-3-1300' AS sid, 'carol' AS name, "
        "6 AS resource_id, 'PS1' AS source_site_code, "
        "'CN=carol,DC=lab' AS distinguished_name, 'carol@lab' AS user_principal_name"
    )
    transforms(con)
    rows = con.execute("SELECT sid FROM sccm.node_user").fetchall()
    assert len(rows) == 1
    r = con.execute(
        "SELECT distinguished_name, user_principal_name FROM sccm.node_user "
        "WHERE sid='S-1-5-21-1-2-3-1300'"
    ).fetchone()
    assert r == ("CN=carol,DC=lab", "carol@lab")
