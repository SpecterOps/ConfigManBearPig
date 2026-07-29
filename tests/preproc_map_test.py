"""Tests for _preproc_table_map() in main.py.

Verifies that the map contains only tables actually emitted by collectors,
uses the correct path pattern, and does not contain stale table names that
no collector produces.
"""
from openhound_sccm.main import _preproc_table_map


def test_all_values_match_key_path():
    """Every value must be 'sccm/<table>' — the JSONL directory DLT writes."""
    table_map = _preproc_table_map()
    for table, path in table_map.items():
        assert path == f"sccm/{table}", (
            f"Table '{table}' has path '{path}', expected 'sccm/{table}'"
        )


def test_key_real_tables_present():
    """Tables that transforms.py reads must be in the map so preproc loads them."""
    table_map = _preproc_table_map()

    # AdminService / WMI sources read by transforms.py coalesces
    assert "adminservice_r_system" in table_map
    assert "wmi_r_system" in table_map
    assert "adminservice_r_user" in table_map
    assert "wmi_r_user" in table_map
    assert "adminservice_admins" in table_map
    assert "wmi_admins" in table_map
    assert "adminservice_reserved_accounts" in table_map
    assert "wmi_reserved_accounts" in table_map
    assert "adminservice_sites" in table_map
    assert "wmi_sites" in table_map
    assert "adminservice_site_definitions" in table_map
    assert "wmi_site_definitions" in table_map
    assert "adminservice_site_definitions_computers" in table_map
    assert "wmi_site_definitions_computers" in table_map
    # SMS_R_UserGroup: maps security_group_name -> SID (feeds principal_by_name)
    assert "adminservice_user_group" in table_map
    assert "wmi_user_group" in table_map

    # LDAP sources
    assert "ldap_cmrc_devices" in table_map
    assert "ldap_network_boot_servers" in table_map
    assert "ldap_sites" in table_map
    assert "ldap_management_points_raw" in table_map
    assert "ldap_pattern_matches" in table_map
    assert "ldap_system_management_dacl" in table_map

    # RemoteRegistry sources
    assert "remoteregistry_computers" in table_map
    assert "remoteregistry_users" in table_map
    assert "remoteregistry_sites" in table_map
    assert "remoteregistry_mssql_servers" in table_map

    # SMB sources
    assert "smb_computers" in table_map
    assert "smb_sites" in table_map

    # HTTP sources
    assert "http_management_points" in table_map
    assert "http_distribution_points" in table_map
    assert "http_smsproviders" in table_map
    assert "http_site_servers" in table_map

    # MSSQL sources
    assert "mssql_server_instances" in table_map

    # DNS sources
    assert "dns_management_points" in table_map

    # Local sources
    assert "local_wmi_sms_authority" in table_map
    assert "local_wmi_sms_lookupmp" in table_map
    assert "local_wmi_ccm_client" in table_map
    assert "local_client_logs_targets" in table_map
    # collection_settings: written at collect time to persist the --disable-possible-edges flag
    assert "collection_settings" in table_map


def test_stale_names_absent():
    """Stale table names that no collector emits must not be in the map."""
    table_map = _preproc_table_map()

    # Renamed: ldap_computers never existed; the real table is ldap_cmrc_devices
    assert "ldap_computers" not in table_map

    # These LDAP tables have no corresponding collector
    assert "ldap_users" not in table_map
    assert "ldap_groups" not in table_map
    assert "ldap_sms_providers" not in table_map
    assert "ldap_group_memberships" not in table_map

    # Typo in old map: actual resource name is ldap_system_management_dacl
    assert "ldap_system_management_acl" not in table_map

    # Old local collector names (replaced by local_wmi_* names)
    assert "local_management_points" not in table_map
    assert "local_distribution_points" not in table_map
    assert "local_naa_secrets" not in table_map

    # Old registry names (replaced by remoteregistry_*)
    assert "registry_sccm_databases" not in table_map
    assert "registry_current_users" not in table_map
    assert "registry_sccm_components" not in table_map
    assert "registry_mssql_settings" not in table_map

    # Old MSSQL name (replaced by mssql_server_instances)
    assert "mssql_epa_flags" not in table_map

    # WMI tables that no collector emits
    assert "wmi_clients" not in table_map
    assert "wmi_users_seen" not in table_map
    assert "wmi_sql_service_accounts" not in table_map

    # HTTP tables with no collector
    assert "http_naa_secrets" not in table_map
    assert "http_collection_secrets" not in table_map

    # Old SMB names (replaced by smb_computers and smb_sites)
    assert "smb_site_servers" not in table_map
    assert "smb_distribution_points" not in table_map
    assert "smb_signing_status" not in table_map

    # Derived / synthetic tables that were never collected
    assert "derived_edges" not in table_map
    assert "derived_nodes" not in table_map
    assert "dhcp_pxe_dps" not in table_map
