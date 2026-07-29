import duckdb
from openhound_sccm.transforms import transforms


def _ps1_sql_and_provider(con):
    """PS1 with SQL host SQL01 (-1200) and an SMS Provider host PROV (-1300, a sysadmin computer).

    The provider is seeded in BOTH adminservice_site_definitions_computers (role + dnshostname)
    AND ldap_cmrc_devices (sam_account_name) per the Phase E fixture note — node_computer takes
    sam from LDAP/HTTP, not from adminservice_r_system.
    """
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1'), "
        "('S-1-5-21-1-2-3-1300', 'PROV.lab.local', 'SMS Provider@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1300', 'PROV', 'PROV$', 'PROV.lab.local')"
        ") AS t(object_sid, name, sam_account_name, dns_host_name)"
    )


def test_login_id_and_name_from_computer_own_domain():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    row = con.execute(
        "SELECT login_id, login_name, server_id, sysadmin_computer_sid FROM sccm.node_mssql_login"
    ).fetchone()
    assert row == ("LAB\\PROV$@S-1-5-21-1-2-3-1200:1433", "LAB\\PROV$",
                   "S-1-5-21-1-2-3-1200:1433", "S-1-5-21-1-2-3-1300")


def test_sql_host_is_not_its_own_login():
    """The SQL host must NOT become a login on itself, even when it ALSO holds a Site Server
    role and has a samAccountName (CMBP :1920 — the only thing excluding it is sid != host)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    # SQL host -1200 ALSO tagged Site Server, and given a sam — it must STILL be excluded.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS SQL Server@PS1'), "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab.local', 'SMS Site Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01', 'SQL01$', 'SQL01.lab.local')"
        ") AS t(object_sid, name, sam_account_name, dns_host_name)"
    )
    transforms(con)
    n = con.execute("SELECT count(*) FROM sccm.node_mssql_login").fetchone()[0]
    assert n == 0


def test_database_user_id_and_login_linkage():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    row = con.execute(
        "SELECT dbuser_id, dbuser_name, login_id, database_id, database FROM sccm.node_mssql_database_user"
    ).fetchone()
    assert row == (
        "LAB\\PROV$@S-1-5-21-1-2-3-1200:1433\\CM_PS1", "LAB\\PROV$",
        "LAB\\PROV$@S-1-5-21-1-2-3-1200:1433",
        "S-1-5-21-1-2-3-1200:1433\\CM_PS1", "CM_PS1",
    )
