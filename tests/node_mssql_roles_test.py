"""Tests for MSSQL server-role and (later) database-role node transforms.

F1 covers sysadmin ServerRole; F2 will append db_owner DatabaseRole tests.
"""
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


def test_sysadmin_role_id_and_members_populated():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    row = con.execute(
        "SELECT role_id, name, members FROM sccm.node_mssql_server_role "
        "WHERE server_id = 'S-1-5-21-1-2-3-1200:1433'"
    ).fetchone()
    assert row[0] == "sysadmin@S-1-5-21-1-2-3-1200:1433"
    assert row[1] == "sysadmin"
    assert "LAB\\PROV$@S-1-5-21-1-2-3-1200:1433" in row[2]   # members fixed (CMBP scope bug)


def test_db_owner_role_id_and_members_populated():
    con = duckdb.connect(":memory:")
    _ps1_sql_and_provider(con)
    transforms(con)
    row = con.execute(
        "SELECT role_id, name, database, members FROM sccm.node_mssql_database_role "
        "WHERE database_id = 'S-1-5-21-1-2-3-1200:1433\\CM_PS1'"
    ).fetchone()
    assert row[0] == "db_owner@S-1-5-21-1-2-3-1200:1433\\CM_PS1"
    assert row[1] == "db_owner"
    assert row[2] == "CM_PS1"
    assert "LAB\\PROV$@S-1-5-21-1-2-3-1200:1433\\CM_PS1" in row[3]
