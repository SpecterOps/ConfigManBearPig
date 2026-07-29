import duckdb
from openhound_sccm.transforms import transforms


def _hierarchy(con):
    # Standalone primary site PS1 -> root_site_code = 'PS1'.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_real_client_ad_domain_sid_resolved_from_r_system():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'GUID:ABC' AS sms_unique_identifier, "
        "16777220 AS resource_id, 'PS1' AS source_site_code, false AS obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'GUID:ABC' AS smsid, 'HOST1' AS name, 'PS1' AS site_code, "
        "16777220 AS resource_id, true AS is_client, false AS is_obsolete"
    )
    transforms(con)
    sid = con.execute(
        "SELECT ad_domain_sid FROM sccm.node_client_device WHERE smsid = 'GUID:ABC'"
    ).fetchone()[0]
    assert sid == "S-1-5-21-1-2-3-1104"


def test_possible_client_ad_domain_sid_preserved():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'HOST2' AS name"
    )
    transforms(con)
    sid = con.execute(
        "SELECT ad_domain_sid FROM sccm.node_client_device "
        "WHERE smsid = 'S-1-5-21-1-2-3-1200@PS1'"
    ).fetchone()[0]
    assert sid == "S-1-5-21-1-2-3-1200"


def test_client_device_gains_ad_attrs_from_matching_computer():
    """SCCM_ClientDevice.ad_domain_sid is the join key to the resolved Computer
    (node_computer) -- CN/DNSHostName/distinguishedName/domain/objectClass/
    samAccountName/servicePrincipalName are attributes of that underlying AD
    computer, not of the device record itself, so they must be joined in from
    node_computer rather than left unset.

    Mirrors the live 2026-07-28 low-priv run: CAS-DB is discovered via
    ldap_cmrc_devices AND probed over SMB (registered as a target by the CmRcService
    discovery, then reached in a later per-host phase), giving node_computer both
    dnshostname/sam_account_name/distinguished_name (smb_computers spreads the full
    AD object) and domain/objectClass/servicePrincipalName/cn (independently
    LDAP-resolved -> ad_props via _join_ad_props). node_client_device never
    surfaced any of these seven onto the device record itself.
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1108' AS object_sid, 'CAS-DB' AS name"
    )
    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1108' AS object_sid, 'CAS-DB' AS name, "
        "'cas-db.mayyhem.com' AS dns_host_name, 'CAS-DB$' AS sam_account_name, "
        "'CN=CAS-DB,OU=Servers,DC=mayyhem,DC=com' AS distinguished_name, "
        "false AS smb_signing_required, true AS sccm_infra, "
        "NULL AS sccm_hosts_content_library, NULL AS sccm_is_pxe_support_enabled"
    )
    # The same SID was independently LDAP-resolved (populates ad_props via
    # _derive_ad_props, joined onto node_computer by _join_ad_props).
    con.execute(
        "CREATE TABLE sccm.ldap_resolved_principals ("
        "sid VARCHAR, object_class VARCHAR[], user_account_control BIGINT, "
        "service_principal_name VARCHAR[], cn VARCHAR, sam_account_name VARCHAR, "
        "distinguished_name VARCHAR, domain VARCHAR)"
    )
    con.execute(
        "INSERT INTO sccm.ldap_resolved_principals VALUES ("
        "'S-1-5-21-1-2-3-1108', ['top', 'person', 'organizationalPerson', 'user', 'computer'], "
        "0, ['CmRcService/CAS-DB'], 'CAS-DB', 'CAS-DB$', "
        "'CN=CAS-DB,OU=Servers,DC=mayyhem,DC=com', 'MAYYHEM.COM')"
    )

    transforms(con)

    row = con.execute(
        "SELECT cn, dnshostname, distinguished_name, domain, object_class, "
        "sam_account_name, service_principal_name "
        "FROM sccm.node_client_device WHERE smsid = 'S-1-5-21-1-2-3-1108@PS1'"
    ).fetchone()
    assert row is not None
    cn, dnshostname, distinguished_name, domain, object_class, sam_account_name, spn = row
    assert cn == "CAS-DB"
    assert dnshostname == "cas-db.mayyhem.com"
    assert distinguished_name == "CN=CAS-DB,OU=Servers,DC=mayyhem,DC=com"
    assert domain == "MAYYHEM.COM"
    assert object_class == ["top", "person", "organizationalPerson", "user", "computer"]
    assert sam_account_name == "CAS-DB$"
    assert spn == ["CmRcService/CAS-DB"]
