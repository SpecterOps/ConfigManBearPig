"""A CONFIRMED secondary site's database, and the parent primary's sysadmin on it.

Microsoft's secondary-site prerequisites
(learn.microsoft.com/intune/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites#bkmk_secondary)
say three things this module pins:

  1. "The database server must ... be run on the secondary site server." A secondary's
     database is never remote, so identifying the secondary site server identifies its
     database host.
  2. "Add the computer account of the parent primary site to the Administrators group on
     the secondary site server."
  3. The parent primary's computer account "needs sysadmin permissions on the instance of
     SQL Server on the secondary site server", and must keep them after setup.

@_Mayyhem additionally lab-tested the SQL Express path (which setup installs for a
secondary when no instance pre-exists) and found BUILTIN\\Administrators is a sysadmin
there by default -- which reaches the parent primary via (2) rather than (3). Either way
the parent primary's computer account ends up sysadmin, so THAT is what we emit; the
broader "every local admin is a sysadmin" claim is Express-only and is deliberately NOT
emitted here (con-e2f1).

DELIBERATELY NOT EMITTED, and pinned so by the negative tests below:
  * the secondary-site GRANTS, when secondary-ness was not POSITIVELY established. A site
    discovered only by bare code (an SMB share comment) has site_type NULL, and a
    low-privilege run cannot tell a secondary from an uncollected primary. @_Mayyhem's
    ruling 2026-08-01: "Don't infer/create the nodes/relationships we aren't certain about
    when we can't confirm a site is secondary via LDAP or privileged AdminService/WMI
    collection." Note this withholds the GRANTS only -- everything actually observed is
    still emitted, so a low-privilege run keeps the SCCM_Site node for SEC, ps1-sec as an
    MSSQL_Server, and its 'SMS Site Server@SEC' role ("just emit what can be confirmed or
    positively inferred").
  * a login for the secondary site server's OWN machine account. Because the database is
    co-located, that principal authenticates locally as NT AUTHORITY\\SYSTEM and never
    over the network, and NTLM cannot be reflected back to the same host -- so it is a
    node with no traversable edge.
  * SCCM_AssignAllPermissions from a secondary's database: a secondary holds a partial
    replica with no RBAC tables (see edge_assign_all_permissions_test.py).
"""
import duckdb

from openhound_sccm.transforms import transforms

SEC_SERVER_SID = "S-1-5-21-1-2-3-1113"      # ps1-sec: SEC's site server AND its DB host
PSS_SID = "S-1-5-21-1-2-3-1112"             # ps1-pss: the PS1 parent primary site server
PSV_SID = "S-1-5-21-1-2-3-1111"             # ps1-psv: PS1's passive site server


def _seed(con, sec_row):
    """sec_row: the SEC tuple for adminservice_site_definitions, or None to omit it."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    rows = ["('CAS',NULL,4)", "('PS1','CAS',2)"]
    if sec_row:
        rows.append(sec_row)
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES "
                + ",".join(rows) + ") AS t(site_code,parent_site_code,site_type)")
    # SEC is always discoverable as a bare site code -- that is what an SMB share comment
    # gives a low-privilege run, and it must not by itself be enough.
    con.execute("CREATE TABLE sccm.smb_sites AS SELECT * FROM "
                "(VALUES ('SMB-Shares','SEC')) AS t(source,site_code)")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        f"('{PSS_SID}','PS1-PSS','ps1-pss.mayyhem.com','PS1-PSS$','[\"SMS Site Server@PS1\"]',true),"
        f"('{PSV_SID}','PS1-PSV','ps1-psv.mayyhem.com','PS1-PSV$','[\"SMS Site Server@PS1\"]',true),"
        f"('{SEC_SERVER_SID}','PS1-SEC','ps1-sec.mayyhem.com','PS1-SEC$',"
        f"  '[\"SMS Site Server@SEC\",\"SMS SQL Server@SEC\"]',true)"
        ") AS t(object_sid,name,dns_host_name,sam_account_name,sccm_site_system_roles,sccm_infra)")
    return con


def _logins_on_sec(con):
    return sorted(r[0] for r in con.execute(
        "SELECT login_name FROM sccm.node_mssql_login WHERE upper(sccm_site) = 'SEC'"
    ).fetchall())


def test_confirmed_secondary_grants_parent_primary_site_servers_sysadmin():
    """site_type=1 + a known parent => the parent's site servers are sysadmin on its DB."""
    con = _seed(duckdb.connect(":memory:"), "('SEC','PS1',1)")
    transforms(con)
    # Not vacuous: SEC must actually have been built as a site database.
    assert con.execute(
        "SELECT count(*) FROM sccm.node_mssql_database WHERE upper(sccm_site)='SEC'"
    ).fetchone()[0] > 0, "SEC site database was not built; test proves nothing"

    logins = _logins_on_sec(con)
    assert "MAYYHEM\\PS1-PSS$" in logins, f"parent primary missing sysadmin on SEC: {logins}"


def test_passive_parent_site_server_also_gets_sysadmin():
    """The passive node carries 'SMS Site Server@PS1' too, so it is included.

    @_Mayyhem raised this as an open question -- whether a site server in passive mode
    needs the same rights for failover to work. Matching on the ROLE rather than on a
    single 'the' site server answers it without a separate rule: SharpHound's own capture
    of the mayyhem lab shows both PS1-PSS$ and PS1-PSV$ in ADMINISTRATORS@PS1-SEC.
    """
    con = _seed(duckdb.connect(":memory:"), "('SEC','PS1',1)")
    transforms(con)
    assert "MAYYHEM\\PS1-PSV$" in _logins_on_sec(con)


def test_secondary_site_server_gets_no_login_on_its_own_database():
    """Co-located Local System is not relayable, so it is not a graph principal."""
    con = _seed(duckdb.connect(":memory:"), "('SEC','PS1',1)")
    transforms(con)
    assert "MAYYHEM\\PS1-SEC$" not in _logins_on_sec(con)


def test_unconfirmed_secondary_gets_no_parent_login():
    """The core ruling: no positive confirmation of secondary-ness => emit nothing.

    SEC is present only as a bare site code from an SMB share comment, exactly as a
    low-privilege run sees it. Its type is unknown, so the parent grant must not fire --
    even though the topology happens to be identical to the confirmed case above.
    """
    con = _seed(duckdb.connect(":memory:"), None)
    transforms(con)
    logins = _logins_on_sec(con)
    assert "MAYYHEM\\PS1-PSS$" not in logins, f"inferred a grant without confirmation: {logins}"
    assert "MAYYHEM\\PS1-PSV$" not in logins


def test_primary_site_database_is_unaffected_by_the_secondary_arm():
    """A primary keeps exactly its existing same-site logins -- no parent fan-in."""
    con = _seed(duckdb.connect(":memory:"), "('SEC','PS1',1)")
    transforms(con)
    # CAS is PS1's parent; PS1 is a PRIMARY, so CAS's site server must NOT gain a login
    # on PS1's database through the secondary arm.
    ps1 = sorted(r[0] for r in con.execute(
        "SELECT login_name FROM sccm.node_mssql_login WHERE upper(sccm_site) = 'PS1'"
    ).fetchall())
    assert "MAYYHEM\\CAS-PSS$" not in ps1, f"secondary arm leaked onto a primary: {ps1}"
