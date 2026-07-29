import duckdb
from openhound_sccm.transforms import transforms


def _ps1_with_sql(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab', 'SMS SQL Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )


def test_database_node_id_and_name():
    con = duckdb.connect(":memory:")
    _ps1_with_sql(con)
    transforms(con)
    row = con.execute(
        "SELECT database_id, server_id, name, sccm_site, sql_server FROM sccm.node_mssql_database"
    ).fetchone()
    assert row == ("S-1-5-21-1-2-3-1200:1433\\CM_PS1", "S-1-5-21-1-2-3-1200:1433",
                   "CM_PS1", "PS1", "SQL01.lab")
