# src/openhound_sccm/node_computer_test.py
"""Tests for the _node_computer coalesce in transforms.py.

Each test seeds only the tables that are relevant to what it's checking,
relying on _safe() to silently skip any missing sources.
"""
import duckdb
from openhound_sccm.transforms import transforms


def _seed_base(con):
    """Seed the minimum tables for transforms() to run without error."""
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # site_hierarchy needs at least one of these; _safe skips if absent
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT 'PS1' AS site_code, NULL AS parent_site_code, 2 AS site_type"
    )


def test_node_computer_coalesces_one_row_per_sid():
    """Two sources (r_system + smb_computers) with the same SID should produce
    exactly one node_computer row with merged roles, resource_ids, etc."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'HOST1' AS name, 'S-1-5-21-1-2-3-1104' AS sid, false AS obsolete, "
        "7 AS resource_id, 'PS1' AS source_site_code, "
        "'SMS Provider' AS system_roles, 'GUID:abc' AS sms_unique_identifier"
    )
    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'HOST1' AS name, "
        "'host1.lab' AS dns_host_name, true AS smb_signing_required, "
        "'SMS Distribution Point' AS sccm_site_system_roles, "
        "true AS sccm_infra, "
        "true AS sccm_hosts_content_library, "
        "false AS sccm_is_pxe_support_enabled"
    )

    transforms(con)

    rows = con.execute(
        "SELECT sid, name, dnshostname, sccm_infra, sms_unique_identifier, "
        "smb_signing_required, list_sort(site_system_roles), list_sort(resource_ids) "
        "FROM sccm.node_computer"
    ).fetchall()

    assert len(rows) == 1
    sid, name, dns, infra, smsid, signing, roles, rids = rows[0]
    assert sid == "S-1-5-21-1-2-3-1104"
    assert dns == "host1.lab"
    assert infra is True
    assert smsid == "GUID:abc"
    assert signing is True
    assert roles == ["SMS Distribution Point", "SMS Provider"]
    assert rids == ["7@PS1"]


def test_node_computer_sccm_has_client_remote_control_spn():
    """An ldap_cmrc_devices row should synthesize sccm_has_client_remote_control_spn=True."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'CMRC1' AS name, "
        "'cmrc1.lab' AS dns_host_name, 'CMRC1$' AS sam_account_name, "
        "true AS sccm_infra, NULL AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT sid, sccm_has_client_remote_control_spn FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1200'"
    ).fetchone()
    assert row is not None
    assert row[1] is True


def test_node_computer_disable_loopback_and_restrict_ntlm():
    """remoteregistry_computers supplies disable_loopback_check (bool) and
    restrict_receiving_ntlm_traffic (string)."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.remoteregistry_computers AS SELECT "
        "'S-1-5-21-1-2-3-1300' AS object_sid, 'RGREG1' AS name, "
        "'rgreg1.lab' AS dns_host_name, 'RGREG1$' AS sam_account_name, "
        "true AS disable_loopback_check, 'Deny_All' AS restrict_receiving_ntlm_traffic, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT sid, disable_loopback_check, restrict_receiving_ntlm_traffic "
        "FROM sccm.node_computer WHERE sid = 'S-1-5-21-1-2-3-1300'"
    ).fetchone()
    assert row is not None
    assert row[1] is True
    assert row[2] == "Deny_All"


def test_node_computer_network_boot_server():
    """ldap_network_boot_servers membership synthesizes network_boot_server=True."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.ldap_network_boot_servers AS SELECT "
        "'S-1-5-21-1-2-3-1400' AS object_sid, 'NBSRV' AS name, "
        "'nbsrv.lab' AS dns_host_name, 'NBSRV$' AS sam_account_name, "
        "true AS sccm_infra, NULL AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT sid, network_boot_server FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1400'"
    ).fetchone()
    assert row is not None
    assert row[1] is True


def test_node_computer_sccm_client_certificate_required():
    """http_management_points with client_cert_required=True sets sccm_client_certificate_required."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.http_management_points AS SELECT "
        "'S-1-5-21-1-2-3-1500' AS object_sid, 'MP1' AS name, "
        "'mp1.lab' AS dns_host_name, NULL AS sam_account_name, "
        "true AS sccm_infra, 'Management Point' AS sccm_site_system_roles, "
        "true AS client_cert_required"
    )

    transforms(con)

    row = con.execute(
        "SELECT sid, sccm_client_certificate_required FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1500'"
    ).fetchone()
    assert row is not None
    assert row[1] is True


def test_node_computer_obsolete_rows_dropped():
    """r_system rows with obsolete=True must not appear in node_computer."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'GHOST' AS name, 'S-1-5-21-1-2-3-9999' AS sid, true AS obsolete, "
        "NULL AS resource_id, NULL AS source_site_code, "
        "NULL AS system_roles, NULL AS sms_unique_identifier"
    )

    transforms(con)

    rows = con.execute("SELECT sid FROM sccm.node_computer").fetchall()
    assert all(r[0] != "S-1-5-21-1-2-3-9999" for r in rows)


def test_node_computer_distinguished_name_from_smb_computers():
    """smb_computers spreads **ad_object which includes distinguished_name;
    it must appear in node_computer after the coalesce."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1600' AS object_sid, 'SMBHOST' AS name, "
        "'smbhost.lab' AS dns_host_name, NULL AS sam_account_name, "
        "'CN=SMBHOST,OU=Computers,DC=lab,DC=local' AS distinguished_name, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )

    transforms(con)

    row = con.execute(
        "SELECT distinguished_name FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1600'"
    ).fetchone()
    assert row is not None
    assert row[0] == "CN=SMBHOST,OU=Computers,DC=lab,DC=local"


def test_node_computer_distinguished_name_from_wmi_site_definitions_computers():
    """wmi_site_definitions_computers spreads **ad_object (same as the adminservice arm),
    so distinguished_name must not be silently dropped to NULL.

    This is a regression guard for the C6 bug where the wmi arm emitted
    NULL AS distinguished_name while the adminservice arm correctly forwarded it.
    """
    con = duckdb.connect(":memory:")
    _seed_base(con)

    # Use a parameterised insert to avoid any backslash-escaping issues with the DN value.
    con.execute("CREATE TABLE sccm.wmi_site_definitions_computers ("
                "object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, "
                "distinguished_name VARCHAR, sccm_site_system_roles VARCHAR, "
                "sccm_infra BOOLEAN)")
    con.execute(
        "INSERT INTO sccm.wmi_site_definitions_computers VALUES (?, ?, ?, ?, ?, ?)",
        ["S-1-5-21-1-2-3-1800", "WMIHOST", "wmihost.lab",
         "CN=WMIHOST,OU=Computers,DC=lab,DC=local", "SMS Site Server", True],
    )

    transforms(con)

    row = con.execute(
        "SELECT distinguished_name FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1800'"
    ).fetchone()
    assert row is not None, "wmi_site_definitions_computers row not found in node_computer"
    assert row[0] == "CN=WMIHOST,OU=Computers,DC=lab,DC=local"


def test_node_computer_sam_account_name_from_remoteregistry():
    """remoteregistry_computers spreads **ad_object which includes sam_account_name; it must
    not be dropped to NULL.

    Regression guard for the MSSQL-login bug: the arm used to emit NULL AS sam_account_name,
    so a site server seen only over RemoteRegistry (e.g. a CAS-side server not in a user/LDAP
    source) ended up with a NULL account name, which the MSSQL-login inference filters out.
    """
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.remoteregistry_computers AS SELECT "
        "'S-1-5-21-1-2-3-2100' AS object_sid, 'RRHOST' AS name, "
        "'rrhost.lab' AS dns_host_name, 'RRHOST$' AS sam_account_name, "
        "false AS disable_loopback_check, NULL AS restrict_receiving_ntlm_traffic, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT sam_account_name FROM sccm.node_computer WHERE sid = 'S-1-5-21-1-2-3-2100'"
    ).fetchone()
    assert row is not None
    assert row[0] == "RRHOST$"


def test_node_computer_sam_account_name_from_site_definitions():
    """adminservice_site_definitions_computers spreads **ad_object incl. sam_account_name.

    Same regression guard as above for the site-definition arm — the source that gives the
    active site server its 'SMS Site Server@<site>' role must also forward its account name.
    """
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers ("
        "object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, sam_account_name VARCHAR, "
        "distinguished_name VARCHAR, sccm_site_system_roles VARCHAR)"
    )
    con.execute(
        "INSERT INTO sccm.adminservice_site_definitions_computers VALUES (?, ?, ?, ?, ?, ?)",
        ["S-1-5-21-1-2-3-2200", "SDCHOST", "sdchost.lab", "SDCHOST$",
         "CN=SDCHOST,DC=lab,DC=local", "SMS Site Server@CAS"],
    )

    transforms(con)

    row = con.execute(
        "SELECT sam_account_name FROM sccm.node_computer WHERE sid = 'S-1-5-21-1-2-3-2200'"
    ).fetchone()
    assert row is not None
    assert row[0] == "SDCHOST$"


def test_node_computer_site_system_roles_augmented_from_sysresuse():
    """SMS_SCI_SysResUse (adminservice_site_systems) lists every site system with role_name +
    site_code, keyed by hostname (network_os_path), not SID. node_computer must fold these in as
    'role@site' so a passive site server / SMS Provider — which SMS_SCI_SiteDefinition never
    lists — still gets 'SMS Site Server@<site>' / 'SMS Provider@<site>'. Without those suffixed
    roles the MSSQL-login inference (_node_mssql_login, mirroring CMBP ps1:1912) skips the host.
    """
    con = duckdb.connect(":memory:")
    _seed_base(con)

    # Host known via RemoteRegistry (SID + hostname), with no @site role from that source...
    con.execute(
        "CREATE TABLE sccm.remoteregistry_computers AS SELECT "
        "'S-1-5-21-1-2-3-2300' AS object_sid, 'PSV' AS name, "
        "'psv.lab' AS dns_host_name, 'PSV$' AS sam_account_name, "
        "false AS disable_loopback_check, NULL AS restrict_receiving_ntlm_traffic, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_site_system_roles"
    )
    # ...its per-site roles live only in SysResUse, keyed by network_os_path (leading '\\'), no SID.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_systems ("
        "network_os_path VARCHAR, role_name VARCHAR, site_code VARCHAR)"
    )
    con.executemany(
        "INSERT INTO sccm.adminservice_site_systems VALUES (?, ?, ?)",
        [["\\\\psv.lab", "SMS Site Server", "PS1"],
         ["\\\\psv.lab", "SMS Provider", "PS1"],
         ["\\\\PSV.LAB", "SMS Component Server", "PS1"]],
    )

    transforms(con)

    row = con.execute(
        "SELECT site_system_roles FROM sccm.node_computer WHERE sid = 'S-1-5-21-1-2-3-2300'"
    ).fetchone()
    assert row is not None
    roles = row[0]
    assert "SMS Site Server@PS1" in roles, roles
    assert "SMS Provider@PS1" in roles, roles
    assert "SMS Component Server@PS1" in roles, roles


def test_node_computer_backfills_bare_role_from_same_host_single_site():
    """A bare role ('SMS Provider') on a host that also carries an @-suffixed role
    of a DIFFERENT type gets stamped with that same site (D6: same-host evidence,
    not cross-host guessing). Mirrors ps1-sms in the live 2026-07-28 low-priv run:
    ['SMS Component Server@PS1', 'SMS Provider'] -> both entries @PS1.
    """
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-3000' AS object_sid, 'PS1-SMS' AS name, "
        "'ps1-sms.mayyhem.com' AS dns_host_name, NULL AS sam_account_name, "
        "'SMS Provider' AS sccm_site_system_roles, true AS sccm_infra, "
        "false AS smb_signing_required, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT "
        "'S-1-5-21-1-2-3-3000' AS object_sid, 'PS1-SMS' AS name, "
        "'ps1-sms.mayyhem.com' AS dns_host_name, NULL AS sam_account_name, "
        "NULL AS distinguished_name, 'SMS Component Server@PS1' AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT list_sort(site_system_roles) FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-3000'"
    ).fetchone()
    assert row is not None
    assert row[0] == ["SMS Component Server@PS1", "SMS Provider@PS1"], row


def test_node_computer_backfill_does_not_duplicate_existing_suffixed_role():
    """If '<Role>@<site>' is already present alongside the bare '<Role>', the
    backfill must not produce two entries for the same role."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-3001' AS object_sid, 'PS1-DP' AS name, "
        "'ps1-dp.mayyhem.com' AS dns_host_name, NULL AS sam_account_name, "
        "'SMS Distribution Point' AS sccm_site_system_roles, true AS sccm_infra, "
        "false AS smb_signing_required, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT "
        "'S-1-5-21-1-2-3-3001' AS object_sid, 'PS1-DP' AS name, "
        "'ps1-dp.mayyhem.com' AS dns_host_name, NULL AS sam_account_name, "
        "NULL AS distinguished_name, 'SMS Distribution Point@PS1' AS sccm_site_system_roles"
    )

    transforms(con)

    row = con.execute(
        "SELECT site_system_roles FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-3001'"
    ).fetchone()
    assert row is not None
    assert row[0] == ["SMS Distribution Point@PS1"], row


def test_node_computer_backfill_leaves_bare_role_when_sites_ambiguous():
    """When the host's other @-suffixed roles span more than one site, the bare
    role must NOT be guessed at -- it stays bare (D6: never guess across sites)."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-3002' AS object_sid, 'MULTI' AS name, "
        "'multi.mayyhem.com' AS dns_host_name, NULL AS sam_account_name, "
        "'SMS Provider' AS sccm_site_system_roles, true AS sccm_infra, "
        "false AS smb_signing_required, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers ("
        "object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, sam_account_name VARCHAR, "
        "distinguished_name VARCHAR, sccm_site_system_roles VARCHAR)"
    )
    con.executemany(
        "INSERT INTO sccm.adminservice_site_definitions_computers VALUES (?, ?, ?, ?, ?, ?)",
        [["S-1-5-21-1-2-3-3002", "MULTI", "multi.mayyhem.com", None, None, "SMS Site Server@CAS"],
         ["S-1-5-21-1-2-3-3002", "MULTI", "multi.mayyhem.com", None, None, "SMS Component Server@PS1"]],
    )

    transforms(con)

    row = con.execute(
        "SELECT list_sort(site_system_roles) FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-3002'"
    ).fetchone()
    assert row is not None
    assert "SMS Provider" in row[0], row
    assert not any(r.startswith("SMS Provider@") for r in row[0]), row


def test_node_computer_backfill_leaves_bare_role_when_no_suffixed_role_exists():
    """A host with only bare roles (no @-suffixed role to infer a site from) is
    left untouched."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-3003' AS object_sid, 'LONE' AS name, "
        "'lone.mayyhem.com' AS dns_host_name, NULL AS sam_account_name, "
        "'SMS Provider' AS sccm_site_system_roles, true AS sccm_infra, "
        "false AS smb_signing_required, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )

    transforms(con)

    row = con.execute(
        "SELECT site_system_roles FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-3003'"
    ).fetchone()
    assert row is not None
    assert row[0] == ["SMS Provider"], row


def test_node_computer_distinguished_name_any_value_wins():
    """When smb_computers and remoteregistry_computers both have distinguished_name
    for the same SID, any_value picks the first non-null (idempotent)."""
    con = duckdb.connect(":memory:")
    _seed_base(con)

    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1700' AS object_sid, 'MULTI' AS name, "
        "'multi.lab' AS dns_host_name, NULL AS sam_account_name, "
        "'CN=MULTI,OU=Computers,DC=lab,DC=local' AS distinguished_name, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    con.execute(
        "CREATE TABLE sccm.remoteregistry_computers AS SELECT "
        "'S-1-5-21-1-2-3-1700' AS object_sid, 'MULTI' AS name, "
        "'multi.lab' AS dns_host_name, NULL AS sam_account_name, "
        "'CN=MULTI,OU=Computers,DC=lab,DC=local' AS distinguished_name, "
        "false AS smb_signing_required, false AS sccm_infra, "
        "false AS disable_loopback_check, NULL AS restrict_receiving_ntlm_traffic, "
        "NULL AS sccm_site_system_roles"
    )

    transforms(con)

    rows = con.execute("SELECT sid FROM sccm.node_computer").fetchall()
    assert len(rows) == 1
    row = con.execute(
        "SELECT distinguished_name FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1700'"
    ).fetchone()
    assert row is not None
    assert row[0] == "CN=MULTI,OU=Computers,DC=lab,DC=local"
