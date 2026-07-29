import duckdb
from openhound_sccm.transforms import transforms


def _standalone_primary(con):
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_sql_server_temp_built_from_role_rows():
    """One _mssql_sql_servers row per (site, SQL host), from the 'SMS SQL Server@<site>' role."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab', 'SMS SQL Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    transforms(con)
    rows = con.execute(
        "SELECT host_sid, dns_host_name, site_code FROM sccm._mssql_sql_servers"
    ).fetchall()
    assert rows == [("S-1-5-21-1-2-3-1200", "SQL01.lab", "PS1")]


def test_sccm_server_merges_epa_scan():
    """The SCCM site DB and its EPA-scan row collapse to ONE server node keyed host:port."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1200', 'SQL01.lab', 'SMS SQL Server@PS1')"
        ") AS t(object_sid, dns_host_name, sccm_site_system_roles)"
    )
    con.execute(
        "CREATE TABLE sccm.mssql_server_instances AS SELECT "
        "'MSSQL-ScanForEPA' AS source, true AS force_encryption, 'Required' AS extended_protection, "
        "false AS strict_encryption, 'SQL01.lab' AS name, 'S-1-5-21-1-2-3-1200' AS domain_computer_sid, "
        "1433 AS port"
    )
    transforms(con)
    rows = con.execute(
        "SELECT server_id, sccm_site, sccm_infra, force_encryption, extended_protection, strict_encryption "
        "FROM sccm.node_mssql_server WHERE host_sid = 'S-1-5-21-1-2-3-1200'"
    ).fetchall()
    assert len(rows) == 1
    sid, site, infra, fe, ep, se = rows[0]
    assert sid == "S-1-5-21-1-2-3-1200:1433"
    assert site == "PS1" and infra is True
    assert fe is True and ep == "Required" and se is False
    db = con.execute("SELECT databases FROM sccm.node_mssql_server WHERE host_sid='S-1-5-21-1-2-3-1200'").fetchone()[0]
    assert "CM_PS1" in db


def test_non_sccm_server_kept_as_bare_node():
    """A scan-only SQL server (no SCCM site) still produces a server node; sccm_site is NULL."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.mssql_server_instances AS SELECT "
        "'MSSQL-ScanForEPA' AS source, NULL AS force_encryption, 'Off' AS extended_protection, "
        "NULL AS strict_encryption, 'OTHER.lab' AS name, 'S-1-5-21-1-2-3-9999' AS domain_computer_sid, "
        "1433 AS port"
    )
    transforms(con)
    row = con.execute(
        "SELECT server_id, sccm_site, sccm_infra FROM sccm.node_mssql_server "
        "WHERE host_sid = 'S-1-5-21-1-2-3-9999'"
    ).fetchone()
    assert row == ("S-1-5-21-1-2-3-9999:1433", None, False)


def test_registry_only_server_kept_with_string_port():
    """A registry-discovered SQL server survives even though its port is a VARCHAR.

    Regression for the arm-3 coalesce: the remote registry stores TcpPort as a
    REG_SZ string, so dlt types the port column VARCHAR. Coalescing it against an
    integer literal (1433) is a DuckDB type mix that safe_execute swallows,
    silently dropping every registry-only server. The port default must be a
    string, matching the arm-1 idiom.
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.remoteregistry_mssql_servers AS SELECT "
        "'S-1-5-21-1-2-3-7777' AS domain_computer_sid, '1433' AS port, 'REGSQL.lab' AS name, "
        "true AS force_encryption, 'On' AS extended_protection, 'MSSQLSERVER' AS instance_names"
    )
    transforms(con)
    row = con.execute(
        "SELECT server_id, sccm_site, sccm_infra, instance_names FROM sccm.node_mssql_server "
        "WHERE host_sid = 'S-1-5-21-1-2-3-7777'"
    ).fetchone()
    assert row is not None, "registry-only server was dropped (arm-3 coalesce failed)"
    sid, site, infra, instances = row
    assert sid == "S-1-5-21-1-2-3-7777:1433"
    assert site is None and infra is False
    assert instances == ["MSSQLSERVER"]
