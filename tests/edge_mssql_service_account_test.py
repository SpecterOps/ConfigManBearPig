import duckdb
from openhound_sccm.transforms import transforms


def _ps1_sql_with_svc_acct(con):
    """SQL host SQL01 with a domain service account svc_sql (SID ...-1400, has a node)."""
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
    # site_systems carries the SQL service logon account name; principal_by_name resolves it.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_systems AS SELECT "
        "'PS1' AS site_code, 'LAB\\svc_sql' AS sql_server_service_logon_account"
    )
    # r_user gives svc_sql a node_user row + a (name, SID) pair for principal_by_name.
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1400', 'LAB\\svc_sql', 16777240, 'PS1', false)"
        ") AS t(sid, name, resource_id, source_site_code, obsolete)"
    )
    # provider sam (Phase E fixture note): node_computer takes sam from LDAP/HTTP, not r_system.
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1300', 'PROV', 'PROV$', 'PROV.lab.local')"
        ") AS t(object_sid, name, sam_account_name, dns_host_name)"
    )


def _edges(con, kind):
    return con.execute("SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = ?", [kind]).fetchall()


def test_service_account_edges():
    con = duckdb.connect(":memory:")
    _ps1_sql_with_svc_acct(con)
    transforms(con)
    srv = "S-1-5-21-1-2-3-1200:1433"
    login = "LAB\\PROV$@" + srv
    acct = "S-1-5-21-1-2-3-1400"
    assert (acct, login) in _edges(con, "MSSQL_GetTGS")            # service acct -> each login
    assert (acct, srv) in _edges(con, "MSSQL_ServiceAccountFor")   # acct != host
    assert (acct, srv) in _edges(con, "MSSQL_GetAdminTGS")
