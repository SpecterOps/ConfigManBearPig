# src/openhound_sccm/models/sccm_site_test.py
"""Tests for SCCMSite model: row -> OpenGraph node conversion."""
from openhound_sccm.models.sccm_site import SCCMSite
from openhound_sccm.kinds import nodes as nk


def test_sccm_site_as_node_id_and_kinds():
    """id = site_code; kinds = [SCCM_Site]."""
    row = {
        "site_code": "PS1",
        "root_site_code": "CAS",
        "site_type": 2,
        "site_name": "Primary",
        "server_name": "srv.lab",
    }
    node = SCCMSite(**row).as_node
    assert node.id == "PS1"
    assert node.kinds == [nk.SCCM_SITE]


def test_sccm_site_environmentid_is_root():
    """environmentid = root_site_code when present."""
    row = {"site_code": "PS1", "root_site_code": "CAS", "site_type": 2}
    node = SCCMSite(**row).as_node
    assert node.properties.environmentid == "CAS"


def test_sccm_site_environmentid_falls_back_to_site_code():
    """environmentid = site_code when root_site_code is absent."""
    row = {"site_code": "PS1", "root_site_code": None, "site_type": 2}
    node = SCCMSite(**row).as_node
    assert node.properties.environmentid == "PS1"


def test_sccm_site_type_int_to_string_mapping():
    """site_type integer maps to the correct human-readable string."""
    for int_type, expected in [(1, "Secondary Site"), (2, "Primary Site"), (4, "Central Administration Site")]:
        row = {"site_code": "X01", "root_site_code": None, "site_type": int_type}
        node = SCCMSite(**row).as_node
        assert node.properties.siteType == expected, f"site_type={int_type} should map to {expected!r}"


def test_sccm_site_unknown_type_is_none():
    """An unrecognised site_type integer maps to None (no crash)."""
    row = {"site_code": "X01", "root_site_code": None, "site_type": 99}
    node = SCCMSite(**row).as_node
    assert node.properties.siteType is None


def test_sccm_site_no_site_code_returns_none():
    """A row with no site_code cannot be keyed; as_node returns None."""
    node = SCCMSite(site_code=None).as_node
    assert node is None


def test_sccm_site_properties_use_cmbp_casing():
    """SCCM property keys mirror ConfigManBearPig.ps1 casing, not snake_case."""
    from dataclasses import asdict
    row = {"site_code": "PS1", "root_site_code": "CAS", "site_type": 2, "site_name": "Primary"}
    node = SCCMSite(**row).as_node
    props = asdict(node)["properties"]
    # CMBP-cased SCCM keys are present...
    assert "siteCode" in props
    assert "SCCMInfra" in props
    # ...and the old snake_case spellings are gone (framework base keys stay as-is).
    assert "site_code" not in props
    assert "sccm_infra" not in props


def test_sccm_site_extra_fields_ignored():
    """Extra columns from the DB are silently ignored (extra='ignore')."""
    row = {"site_code": "PS1", "root_site_code": None, "site_type": 2, "unexpected_column": "boom"}
    # Should not raise
    node = SCCMSite(**row).as_node
    assert node is not None


def test_sccm_site_build_number_and_install_dir_emitted():
    """build_number and install_dir are passed through to node properties."""
    row = {
        "site_code": "PS1",
        "root_site_code": "CAS",
        "site_type": 2,
        "build_number": "9107",
        "install_dir": r"C:\Program Files\Microsoft Configuration Manager",
    }
    node = SCCMSite(**row).as_node
    assert node.properties.buildNumber == "9107"
    assert node.properties.installDir == r"C:\Program Files\Microsoft Configuration Manager"


def test_sccm_site_sql_service_account_name_emitted():
    """sql_service_account_name is passed through to node properties."""
    row = {
        "site_code": "CAS",
        "root_site_code": "CAS",
        "site_type": 4,
        "sql_service_account_name": "MAYYHEM\\sqlsvc",
    }
    node = SCCMSite(**row).as_node
    assert node.properties.SQLServiceAccountName == "MAYYHEM\\sqlsvc"


def test_sccm_site_admin_users_and_stored_accounts_emitted():
    """admin_users and stored_accounts lists are passed through to node properties."""
    row = {
        "site_code": "CAS",
        "root_site_code": "CAS",
        "site_type": 4,
        "admin_users": ["MAYYHEM\\ADM@CAS"],
        "stored_accounts": ["S-1-5-21-1-2-3-1300"],
    }
    node = SCCMSite(**row).as_node
    assert node.properties.adminUsers == ["MAYYHEM\\ADM@CAS"]
    assert node.properties.storedAccounts == ["S-1-5-21-1-2-3-1300"]


def test_sccm_site_admin_users_defaults_to_empty_list():
    """admin_users defaults to [] when absent from the DB row."""
    row = {"site_code": "CAS", "root_site_code": "CAS", "site_type": 4}
    node = SCCMSite(**row).as_node
    assert node.properties.adminUsers == []
    assert node.properties.storedAccounts == []


def test_sccm_site_distinguished_name_and_source_forest_emitted():
    """distinguished_name and source_forest from ldap_sites are passed through."""
    row = {
        "site_code": "CAS",
        "root_site_code": "CAS",
        "site_type": 4,
        "distinguished_name": "CN=CAS,CN=SMS-Site-CAS,CN=System,DC=lab,DC=local",
        "source_forest": "lab.local",
    }
    node = SCCMSite(**row).as_node
    assert node.properties.distinguishedName == "CN=CAS,CN=SMS-Site-CAS,CN=System,DC=lab,DC=local"
    assert node.properties.sourceForest == "lab.local"


def test_sccm_site_server_and_sql_identity_props():
    """The six server-identity columns map to their CMBP-cased output properties
    (siteServerFQDN/DomainSID, SQLServerFQDN/DomainSID, SQLServiceAccountDomainSID,
    SQLServicePort)."""
    row = {
        "site_code": "PS1",
        "root_site_code": "PS1",
        "site_type": 2,
        "site_server_fqdn": "siteserver.lab.local",
        "site_server_domain_sid": "S-1-5-21-1-2-3-1001",
        "sql_server_fqdn": "sql.lab.local",
        "sql_server_domain_sid": "S-1-5-21-1-2-3-1002",
        "sql_service_account_domain_sid": "S-1-5-21-1-2-3-1500",
        "sql_service_port": "1433",
    }
    p = SCCMSite(**row).as_node.properties
    assert p.siteServerFQDN == "siteserver.lab.local"
    assert p.siteServerDomainSID == "S-1-5-21-1-2-3-1001"
    assert p.SQLServerFQDN == "sql.lab.local"
    assert p.SQLServerDomainSID == "S-1-5-21-1-2-3-1002"
    assert p.SQLServiceAccountDomainSID == "S-1-5-21-1-2-3-1500"
    assert p.SQLServicePort == "1433"
