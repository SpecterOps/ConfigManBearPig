# src/openhound_sccm/site_system_roles_test.py
"""Tests for transforms._derive_site_system_roles (SCCM_Site.siteSystemRoles, CMBP
parity, ps1:1851-1897).

Column names match the real node_site / node_computer coalesce tables produced by
transforms._node_site / transforms._node_computer (site_code, site_type, dnshostname,
site_system_roles) -- not the raw per-source column names (dns_host_name,
sccm_site_system_roles) they're built from. site_type defaults to a non-secondary
value (2 = Primary) in fixtures that aren't specifically testing the Secondary Site
gate, matching the site_type INTEGER column node_site actually carries.
"""
import duckdb

from openhound_sccm.transforms import _derive_site_system_roles


def test_site_system_roles_aggregation():
    """A computer's "<role>@<site>" entry lands on the matching site as
    "<dnsHostName>: <role>@<site>"; a role for a different site is excluded."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.node_site (site_code VARCHAR, site_type INTEGER)")
    con.execute("INSERT INTO sccm.node_site VALUES ('PS1', 2)")
    con.execute(
        "CREATE TABLE sccm.node_computer (dnshostname VARCHAR, site_system_roles VARCHAR[])"
    )
    con.execute(
        "INSERT INTO sccm.node_computer VALUES "
        "('ps1-mp.corp.local', ['SMS Management Point@PS1']),"
        "('other.corp.local', ['SMS Site System@CAS'])"
    )
    out = _derive_site_system_roles(con, "sccm")
    assert out["PS1"] == ["ps1-mp.corp.local: SMS Management Point@PS1"]


def test_site_system_roles_multiple_computers_and_roles():
    """Multiple site systems and multiple roles on one computer all aggregate onto
    the site; a computer with no roles for the site contributes nothing."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.node_site (site_code VARCHAR, site_type INTEGER)")
    con.execute("INSERT INTO sccm.node_site VALUES ('CAS', 4)")
    con.execute(
        "CREATE TABLE sccm.node_computer (dnshostname VARCHAR, site_system_roles VARCHAR[])"
    )
    con.execute(
        "INSERT INTO sccm.node_computer VALUES "
        "('srv1.corp.local', ['SMS Site Server@CAS', 'SMS SQL Server@CAS']),"
        "('srv2.corp.local', ['SMS Management Point@CAS']),"
        "('irrelevant.corp.local', [])"
    )
    out = _derive_site_system_roles(con, "sccm")
    assert set(out["CAS"]) == {
        "srv1.corp.local: SMS Site Server@CAS",
        "srv1.corp.local: SMS SQL Server@CAS",
        "srv2.corp.local: SMS Management Point@CAS",
    }


def test_site_system_roles_defaults_to_empty_list():
    """A site with no matching site-system computers gets an empty list, not NULL,
    and the node_site table keeps its one-row-per-site_code shape (no duplicate rows)."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.node_site (site_code VARCHAR, site_type INTEGER)")
    con.execute("INSERT INTO sccm.node_site VALUES ('PS1', NULL)")
    con.execute(
        "CREATE TABLE sccm.node_computer (dnshostname VARCHAR, site_system_roles VARCHAR[])"
    )
    con.execute(
        "INSERT INTO sccm.node_computer VALUES ('other.corp.local', ['SMS Site System@CAS'])"
    )
    out = _derive_site_system_roles(con, "sccm")
    assert out["PS1"] == []
    rows = con.execute("SELECT site_code FROM sccm.node_site").fetchall()
    assert rows == [("PS1",)]


def test_site_system_roles_excludes_secondary_site():
    """CMBP only attributes siteSystemRoles to a site when it is NOT a Secondary
    Site (Type -ne "Secondary Site", ps1:1861-1865). A node_site row with
    site_type = 1 (Secondary) must get an empty siteSystemRoles list even though a
    computer's role suffix matches its site_code."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.node_site (site_code VARCHAR, site_type INTEGER)")
    con.execute("INSERT INTO sccm.node_site VALUES ('SEC', 1)")
    con.execute(
        "CREATE TABLE sccm.node_computer (dnshostname VARCHAR, site_system_roles VARCHAR[])"
    )
    con.execute(
        "INSERT INTO sccm.node_computer VALUES "
        "('sec-srv.corp.local', ['SMS Site Server@SEC'])"
    )
    out = _derive_site_system_roles(con, "sccm")
    assert out["SEC"] == []
