import duckdb
from openhound_sccm.transforms import transforms


def _ps1_sql_and_provider(con):
    """PS1 with SQL host SQL01 (-1200) + SMS Provider PROV (-1300). See the Phase E fixture note:
    the provider's sam comes from ldap_cmrc_devices, its role from site_definitions_computers."""
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


def _edges(con, kind):
    return con.execute("SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = ?", [kind]).fetchall()


def test_membership_edges():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    srv = "S-1-5-21-1-2-3-1200:1433"
    login = "LAB\\PROV$@" + srv
    db = srv + "\\CM_PS1"
    dbuser = "LAB\\PROV$@" + db
    assert (login, "sysadmin@" + srv) in _edges(con, "MSSQL_MemberOf")
    assert (srv, login) in _edges(con, "MSSQL_Contains")
    assert ("S-1-5-21-1-2-3-1300", login) in _edges(con, "MSSQL_HasLogin")   # computer -> login
    assert (login, dbuser) in _edges(con, "MSSQL_IsMappedTo")
    assert (dbuser, "db_owner@" + db) in _edges(con, "MSSQL_MemberOf")
    assert (db, dbuser) in _edges(con, "MSSQL_Contains")
