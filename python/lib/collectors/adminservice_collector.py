"""
AdminService collection for ConfigManBearPig.

Translated from PowerShell Invoke-AdminServiceCollection (lines 6783-8061).

Collects SCCM data from the Administration Service REST API:
- Sites (SMS_SCI_SiteDefinition)
- Stored Accounts (SMS_SCI_Reserved)
- Combined Device Resources
- SMS_R_System
- SMS_R_User
- Collections
- Collection Members
- Security Roles
- Admin Users
- Site System Roles (SMS_SCI_SysResUse)
"""

import logging
import re
import socket
import urllib3
from typing import Any, Optional

import requests
from requests_ntlm import HttpNtlmAuth

from lib.ad_resolver import ADResolver
from lib.graph import GraphStore
from lib.targets import CollectionTarget, TargetManager

logger = logging.getLogger("ConfigManBearPig")

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AdminServiceClient:
    """
    Client for the SCCM AdminService REST API.

    Uses NTLM authentication. Supports explicit credentials for proxychains.
    """

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl

        if username and password:
            self.session.auth = HttpNtlmAuth(username, password)

    def get(self, endpoint: str, params: Optional[dict] = None) -> Optional[dict[str, Any]]:
        """
        Make a GET request to the AdminService.

        Args:
            endpoint: API endpoint path (may include OData query string)
            params: Query parameters (NOTE: OData $ params should be in endpoint URL
                    to avoid URL-encoding of $ as %24)

        Returns:
            JSON response dict or None on failure
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        # Build query string manually for OData parameters to avoid
        # URL-encoding $ as %24 (which causes 400 errors)
        if params:
            odata_parts = []
            regular_params = {}
            for key, value in params.items():
                if key.startswith("$"):
                    odata_parts.append(f"{key}={value}")
                else:
                    regular_params[key] = value

            if odata_parts:
                separator = "&" if "?" in url else "?"
                url = url + separator + "&".join(odata_parts)
                params = regular_params if regular_params else None

        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                logger.warning(f"Authentication failed for {url} - insufficient privileges")
            elif response.status_code == 403:
                logger.warning(f"Access denied for {url}")
            else:
                logger.error(f"HTTP error for {url}: {e}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection failed for {url}: {e}")
            return None
        except requests.exceptions.Timeout:
            logger.error(f"Request timed out for {url}")
            return None
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
            return None

    def get_paginated(
        self,
        endpoint: str,
        top: int = 1000,
        extra_params: Optional[dict] = None,
    ) -> list[dict[str, Any]]:
        """
        Get all results from a paginated AdminService endpoint.

        Uses $top and $skip OData parameters.

        Args:
            endpoint: API endpoint path
            top: Page size
            extra_params: Additional query parameters

        Returns:
            Combined list of all results
        """
        all_results: list[dict[str, Any]] = []
        skip = 0

        while True:
            params: dict[str, Any] = {"$top": top, "$skip": skip}
            if extra_params:
                params.update(extra_params)

            response = self.get(endpoint, params=params)
            if not response:
                break

            # Extract value array from OData response
            items = response.get("value", [])
            if not items:
                break

            all_results.extend(items)
            logger.debug(f"Fetched {len(items)} items from {endpoint} (total: {len(all_results)})")

            if len(items) < top:
                break  # Last page

            skip += top

        return all_results


def invoke_adminservice_collection(
    target: CollectionTarget,
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    disable_possible_edges: bool = False,
) -> None:
    """
    Run AdminService collection against a target SMS Provider.

    Translated from PowerShell Invoke-AdminServiceCollection (lines 6783-6884).

    Args:
        target: The target SMS Provider
        ad_resolver: AD resolver
        graph: Graph store
        target_manager: Target manager
        domain: Domain name
        username: Credentials (DOMAIN\\user)
        password: Credentials
        disable_possible_edges: Flag
    """
    hostname = target.hostname
    logger.info(f"Starting AdminService collection on {hostname}...")

    # Fast port check — AdminService runs on HTTPS (443)
    try:
        with socket.create_connection((hostname, 443), timeout=3):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        logger.info(f"HTTPS port 443 not open on {hostname}, skipping AdminService collection")
        return

    # AdminService endpoint
    base_url = f"https://{hostname}/AdminService"

    client = AdminServiceClient(
        base_url=base_url,
        username=username,
        password=password,
        timeout=10,
    )

    # 1. Get this SMS Provider's site code
    site_code = _get_provider_site_code(client, graph, hostname)
    if not site_code:
        logger.warning(f"Could not determine site code for {hostname}")
        # Try to get sites directly
        site_code = _get_sites_via_adminservice(client, graph, target_manager, ad_resolver, domain)
        if not site_code:
            logger.error(f"AdminService collection failed: no site code for {hostname}")
            return
    else:
        _get_sites_via_adminservice(client, graph, target_manager, ad_resolver, domain)

    logger.info(f"Collecting from site: {site_code}")

    # 2. Get stored accounts
    _get_stored_accounts(client, graph, ad_resolver, site_code, domain)

    # 3. Get combined device resources (client devices)
    _get_combined_device_resources(client, graph, ad_resolver, site_code, domain)

    # 4. Get SMS_R_System
    _get_sms_r_system(client, graph, ad_resolver, target_manager, site_code, domain)

    # 5. Get SMS_R_User
    _get_sms_r_user(client, graph, ad_resolver, site_code, domain)

    # 6. Get collections
    _get_collections(client, graph, site_code)

    # 7. Get collection members
    _get_collection_members(client, graph, site_code)

    # 8. Get security roles
    _get_security_roles(client, graph, site_code)

    # 9. Get admin users
    _get_admin_users(client, graph, ad_resolver, site_code, domain)

    # 10. Get site system roles
    _get_site_system_roles(client, graph, ad_resolver, target_manager, site_code, domain)

    logger.info(f"AdminService collection completed for {hostname}")


def _get_provider_site_code(
    client: AdminServiceClient,
    graph: GraphStore,
    hostname: str,
) -> Optional[str]:
    """
    Get the site code for this SMS Provider.

    Translated from PowerShell Get-ThisSmsProvidersSiteViaAdminService (lines 6886-6934).
    """
    logger.info("Getting SMS Provider site code via SMS_Identification...")

    response = client.get("wmi/SMS_Identification")
    if not response:
        return None

    items = response.get("value", [])
    for item in items:
        site_code = item.get("ThisSiteCode")
        site_name = item.get("ThisSiteName", "")

        if site_code:
            logger.info(f"Identified this SMS Provider's site via AdminService: {site_code} ({site_name})")
            return site_code

    return None


def _get_sites_via_adminservice(
    client: AdminServiceClient,
    graph: GraphStore,
    target_manager: TargetManager,
    ad_resolver: ADResolver,
    domain: str,
) -> Optional[str]:
    """
    Get all sites via AdminService.

    Translated from PowerShell Get-SitesViaAdminService (lines 6936-7088).
    """
    logger.info("Getting sites via AdminService...")

    first_site_code = None

    # Get SMS_Site objects
    response = client.get("wmi/SMS_Site")
    if response:
        items = response.get("value", [])
        logger.info(f"Found {len(items)} sites")

        for item in items:
            site_code = item.get("SiteCode", "")
            site_name = item.get("SiteName", "")
            site_type = item.get("Type", 0)
            server_name = item.get("ServerName", "")
            report_to = item.get("ReportingSiteCode", "")
            version = item.get("Version", "")

            if not site_code:
                continue

            if not first_site_code:
                first_site_code = site_code

            logger.info(
                f"Site: {site_code} ({site_name}), Type: {site_type}, "
                f"Server: {server_name}, ReportsTo: {report_to}"
            )

            graph.upsert_node(
                site_code,
                ["SCCM_Site"],
                properties={
                    "collectionSource": ["AdminService-SMS_Site"],
                    "SCCMInfra": True,
                    "siteCode": site_code,
                    "siteName": site_name,
                    "siteType": site_type,
                    "serverName": server_name,
                    "reportToSite": report_to or site_code,
                    "version": version,
                    "isCAS": site_type == 4,
                },
            )

            # Add site server as target
            if server_name:
                target_manager.add_device(server_name, source="AdminService-SMS_Site")

                # Resolve and create Computer node
                ad_obj = ad_resolver.get_ad_computer(server_name)
                if ad_obj:
                    sid = ad_obj.get("SID") or ad_obj.get("objectSid")
                    if isinstance(sid, bytes):
                        sid = ad_resolver._sid_bytes_to_string(sid)
                    if sid:
                        graph.upsert_node(
                            sid,
                            ["Computer", "Base"],
                            properties={
                                "collectionSource": ["AdminService-SMS_Site"],
                                "SCCMInfra": True,
                                "SCCMSiteSystemRoles": [f"SMS Site Server@{site_code}"],
                                "dNSHostName": ad_obj.get("dNSHostName", server_name),
                                "sAMAccountName": ad_obj.get("sAMAccountName", ""),
                                "name": ad_obj.get("sAMAccountName", ""),
                            },
                            ad_object=ad_obj,
                        )

    # Also get SMS_SCI_SiteDefinition for detailed site info
    response = client.get("wmi/SMS_SCI_SiteDefinition")
    if response:
        items = response.get("value", [])
        for item in items:
            site_code = item.get("SiteCode", "")
            parent_site = item.get("ParentSiteCode", "")
            site_server = item.get("SiteServerName", "")
            sql_server = item.get("SQLServerName", "")
            sql_db = item.get("SQLDatabaseName", "")

            if site_code:
                props: dict[str, Any] = {
                    "collectionSource": ["AdminService-SMS_SCI_SiteDefinition"],
                }
                if parent_site:
                    props["reportToSite"] = parent_site
                if sql_server:
                    props["SQLServerName"] = sql_server
                    # Add SQL server as target
                    target_manager.add_device(sql_server, source="AdminService-SMS_SCI_SiteDefinition")

                    # Create/update Computer node with SMS SQL Server role
                    # Matches PowerShell lines 7022-7037
                    sql_ad_obj = ad_resolver.get_ad_computer(sql_server)
                    if sql_ad_obj:
                        sql_sid = sql_ad_obj.get("SID") or sql_ad_obj.get("objectSid")
                        if isinstance(sql_sid, bytes):
                            sql_sid = ad_resolver._sid_bytes_to_string(sql_sid)
                        if sql_sid:
                            logger.info(f"Found SQL Server for site {site_code}: {sql_server}")
                            graph.upsert_node(
                                sql_sid,
                                ["Computer", "Base"],
                                properties={
                                    "collectionSource": ["AdminService-SMS_SCI_SiteDefinition"],
                                    "SCCMInfra": True,
                                    "SCCMSiteSystemRoles": [f"SMS SQL Server@{site_code}"],
                                    "dNSHostName": sql_ad_obj.get("dNSHostName", sql_server),
                                    "sAMAccountName": sql_ad_obj.get("sAMAccountName", ""),
                                    "name": sql_ad_obj.get("sAMAccountName", ""),
                                },
                                ad_object=sql_ad_obj,
                            )
                if sql_db:
                    props["SQLDatabaseName"] = sql_db

                graph.upsert_node(site_code, ["SCCM_Site"], properties=props)

    return first_site_code


def _get_stored_accounts(
    client: AdminServiceClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> None:
    """
    Get stored accounts (Network Access Accounts, push install accounts, etc.).

    Translated from PowerShell Get-StoredAccountsViaAdminService (lines 7090-7157).

    Resolves stored account usernames via AD, creates User nodes, and creates
    SCCM_HasStoredAccount edges from the SCCM_Site to the stored account User.
    """
    logger.info("Getting stored accounts...")

    response = client.get("wmi/SMS_SCI_Reserved")
    if not response:
        return

    items = response.get("value", [])
    if not items:
        logger.info("No stored accounts found")
        return

    logger.info(f"Found {len(items)} stored account entries")

    stored_count = 0
    for item in items:
        username = item.get("UserName", "")
        item_name = item.get("ItemName", "")
        item_type = item.get("ItemType", "")
        account_site = item.get("SiteCode", site_code)

        if not username:
            if item_name:
                logger.debug(f"Stored account entry with no UserName: {item_name} (type: {item_type}, site: {account_site})")
            continue

        logger.debug(f"Stored account: {username} (type: {item_type}, site: {account_site})")

        # Resolve the stored account username via AD
        ad_obj = ad_resolver.resolve_principal(username)
        if not ad_obj:
            logger.debug(f"Could not resolve stored account {username} in AD")
            continue

        user_sid = ad_obj.get("SID") or ad_obj.get("objectSid")
        if isinstance(user_sid, bytes):
            user_sid = ad_resolver._sid_bytes_to_string(user_sid)

        if not user_sid:
            logger.warning(f"No SID found for stored account {username}")
            continue

        sam = ad_obj.get("sAMAccountName", username.split("\\")[-1] if "\\" in username else username)

        # Create User node for the stored account
        graph.upsert_node(
            user_sid,
            ["User", "Base"],
            properties={
                "collectionSource": ["AdminService-SMS_SCI_Reserved"],
                "name": sam,
                "sAMAccountName": sam,
                "storedInSCCMSite": account_site,
            },
            ad_object=ad_obj,
        )

        # Find the SCCM_Site node and create SCCM_HasStoredAccount edge
        site_node = graph.get_node(account_site)
        if site_node:
            # Update site with stored account info
            graph.upsert_node(
                account_site,
                ["SCCM_Site"],
                properties={
                    "collectionSource": ["AdminService-SMS_SCI_Reserved"],
                    "storedAccounts": [f"{sam} ({user_sid})"],
                },
            )

            graph.upsert_edge(
                account_site,
                user_sid,
                "SCCM_HasStoredAccount",
                properties={
                    "collectionSource": ["AdminService-SMS_SCI_Reserved"],
                },
            )
            stored_count += 1
            logger.info(f"Created SCCM_HasStoredAccount: {account_site} -> {sam} ({user_sid})")
        else:
            logger.debug(f"No SCCM_Site node found for site code {account_site}")

    logger.info(f"Processed {stored_count} stored accounts")


def _get_combined_device_resources(
    client: AdminServiceClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> None:
    """
    Get combined device resources (SCCM client devices).

    Translated from PowerShell Get-CombinedDeviceResourcesViaAdminService (lines 7159-7314).
    Uses pagination with $top/$skip.
    """
    logger.info("Getting combined device resources...")

    items = client.get_paginated("wmi/SMS_CombinedDeviceResources")
    if not items:
        logger.info("No combined device resources found")
        return

    logger.info(f"Found {len(items)} combined device resources")

    for item in items:
        name = item.get("Name", "")
        resource_id = item.get("ResourceID")
        sms_guid = item.get("SMSID", "")
        client_version = item.get("ClientVersion", "")
        is_client = item.get("IsClient", False)
        is_obsolete = item.get("IsObsolete", False)
        last_logon_user = item.get("LastLogonUser", "")
        current_logon_user = item.get("CurrentLogonUser", "")
        primary_user = item.get("PrimaryUser", "")
        assigned_site = item.get("SiteCode", site_code)

        if not name:
            continue

        # Skip non-client or obsolete devices (PowerShell line 7195)
        if not is_client or is_obsolete:
            continue

        # Create SCCM_ClientDevice node
        # SMSID may already include "GUID:" prefix
        if sms_guid:
            device_id = sms_guid if sms_guid.upper().startswith("GUID:") else f"GUID:{sms_guid}"
        else:
            device_id = f"RID:{resource_id}"
        device_name = f"{name.upper()}@{assigned_site or site_code}"

        props: dict[str, Any] = {
            "name": device_name,
            "collectionSource": ["AdminService-SMS_CombinedDeviceResources"],
            "siteCode": assigned_site or site_code,
            "resourceID": resource_id,
            "isClient": is_client,
            "clientVersion": client_version,
        }
        if sms_guid:
            props["smsGUID"] = sms_guid

        graph.upsert_node(device_id, ["SCCM_ClientDevice"], properties=props)

        # SCCM_HasClient: Site -> ClientDevice
        graph.upsert_edge(assigned_site or site_code, device_id, "SCCM_HasClient")

        # Resolve user relationships
        if last_logon_user:
            _create_user_edge(ad_resolver, graph, device_id, last_logon_user, "SCCM_HasADLastLogonUser", domain)

        if current_logon_user:
            _create_user_edge(ad_resolver, graph, device_id, current_logon_user, "SCCM_HasCurrentUser", domain)

        if primary_user:
            # PrimaryUser may be in "DOMAIN\user" format or just "user"
            _create_user_edge(ad_resolver, graph, device_id, primary_user, "SCCM_HasPrimaryUser", domain)


def _create_user_edge(
    ad_resolver: ADResolver,
    graph: GraphStore,
    device_id: str,
    username: str,
    edge_kind: str,
    domain: str,
) -> None:
    """Create a user node and edge from a device to the user."""
    if not username or username.lower() in ("", "unknown", "none"):
        return

    # Resolve the user to get their SID
    user_obj = ad_resolver.resolve_principal(username)
    if user_obj:
        sid = user_obj.get("SID") or user_obj.get("objectSid")
        if isinstance(sid, bytes):
            sid = ad_resolver._sid_bytes_to_string(sid)

        if sid:
            sam = user_obj.get("sAMAccountName", username.split("\\")[-1] if "\\" in username else username)
            graph.upsert_node(
                sid,
                ["User", "Base"],
                properties={
                    "sAMAccountName": sam,
                    "name": sam,
                },
                ad_object=user_obj,
            )
            graph.upsert_edge(device_id, sid, edge_kind)
            logger.debug(f"{edge_kind}: {device_id} -> {sid} ({sam})")


def _get_sms_r_system(
    client: AdminServiceClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target_manager: TargetManager,
    site_code: str,
    domain: str,
) -> None:
    """
    Get SMS_R_System resources.

    Translated from PowerShell Get-SmsRSystemViaAdminService (lines 7317-7410).

    Creates Computer nodes (resolved via AD), Group nodes from SecurityGroupName,
    with MemberOf edges between them. Also updates SCCM_ClientDevice nodes with
    AD domain SIDs.
    """
    logger.info("Getting SMS_R_System resources...")

    # Note: Do NOT use $select for SMS_R_System - the SCCM AdminService OData endpoint
    # does not return multi-valued properties (like SecurityGroupName) when $select is used.
    # PowerShell also uses $select but their WMI endpoint handles it differently.
    items = client.get_paginated("wmi/SMS_R_System")
    if not items:
        logger.info("No SMS_R_System resources found")
        return

    logger.info(f"Found {len(items)} SMS_R_System resources")

    total_systems = 0
    total_groups = 0

    for item in items:
        name = item.get("Name", "")
        resource_id = item.get("ResourceID")
        sms_guid = item.get("SMSUniqueIdentifier", "")
        is_client = item.get("Client")
        is_obsolete = item.get("Obsolete")

        if not name:
            continue

        # Resolve via AD to get domain SID (PowerShell: Resolve-PrincipalInDomain)
        # Use get_ad_computer which adds $ suffix for sAMAccountName search
        ad_obj = ad_resolver.get_ad_computer(name)
        if not ad_obj:
            logger.debug(f"No domain object found for system {name}")
            total_systems += 1
            continue

        comp_sid = ad_obj.get("SID") or ad_obj.get("objectSid")
        if isinstance(comp_sid, bytes):
            comp_sid = ad_resolver._sid_bytes_to_string(comp_sid)

        if not comp_sid:
            logger.warning(f"No domain SID found for system {name}")
            total_systems += 1
            continue

        sam = ad_obj.get("sAMAccountName", f"{name}$")
        resource_id_str = f"{resource_id}@{site_code}" if resource_id else None

        # Create/update Computer node
        graph.upsert_node(
            comp_sid,
            ["Computer", "Base"],
            properties={
                "collectionSource": ["AdminService-SMS_R_System"],
                "name": sam,
                **({"SCCMResourceIDs": [resource_id_str]} if resource_id_str else {}),
                **({"SCCMClientDeviceIdentifier": sms_guid} if sms_guid else {}),
            },
            ad_object=ad_obj,
        )

        # Create Group nodes from SecurityGroupName (PowerShell lines 7368-7380)
        security_groups = item.get("SecurityGroupName", [])
        if isinstance(security_groups, list):
            for group_name in security_groups:
                if not group_name:
                    continue
                group_obj = ad_resolver.resolve_principal(group_name)
                if not group_obj:
                    continue

                group_sid = group_obj.get("SID") or group_obj.get("objectSid")
                if isinstance(group_sid, bytes):
                    group_sid = ad_resolver._sid_bytes_to_string(group_sid)

                if group_sid:
                    group_sam = group_obj.get("sAMAccountName", group_name)
                    graph.upsert_node(
                        group_sid,
                        ["Group", "Base"],
                        properties={
                            "collectionSource": ["AdminService-SMS_R_System"],
                            "name": group_sam,
                        },
                        ad_object=group_obj,
                    )
                    graph.upsert_edge(
                        comp_sid,
                        group_sid,
                        "MemberOf",
                        properties={
                            "collectionSource": ["AdminService-SMS_R_System"],
                        },
                    )
                    total_groups += 1

        # Update SCCM_ClientDevice node if client and not obsolete
        if is_client and not is_obsolete and sms_guid:
            graph.upsert_node(
                sms_guid,
                ["SCCM_ClientDevice"],
                properties={
                    "collectionSource": ["AdminService-SMS_R_System"],
                    "ADDomainSID": comp_sid,
                },
            )
            graph.upsert_edge(
                site_code,
                sms_guid,
                "SCCM_HasClient",
                properties={
                    "collectionSource": ["AdminService-SMS_R_System"],
                },
            )

        total_systems += 1

    logger.info(f"Successfully processed {total_systems} systems and {total_groups} groups via SMS_R_System")


def _get_sms_r_user(
    client: AdminServiceClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> None:
    """
    Get SMS_R_User resources and their security group memberships.

    Translated from PowerShell Get-SmsRUserViaAdminService (lines 7412-7492).

    Creates User nodes (resolved via AD) and Group nodes from SecurityGroupName,
    with MemberOf edges between them.
    """
    logger.info("Getting SMS_R_User resources...")

    select = (
        "AADTenantID,AADUserID,DistinguishedName,FullDomainName,FullUserName,"
        "Name,ResourceID,SecurityGroupName,SID,UniqueUserName,UserName,"
        "UserPrincipalName"
    )
    items = client.get_paginated("wmi/SMS_R_User", extra_params={"$select": select})
    if not items:
        logger.info("No SMS_R_User resources found")
        return

    logger.info(f"Found {len(items)} SMS_R_User resources")

    total_users = 0
    total_groups = 0

    for item in items:
        name = item.get("Name", "")
        sid_value = item.get("SID")
        resource_id = item.get("ResourceID")

        if not name or not sid_value:
            continue

        if isinstance(sid_value, list):
            sid_value = sid_value[0] if sid_value else None

        if not sid_value:
            continue

        # Resolve user via AD (PowerShell: Resolve-PrincipalInDomain)
        user_obj = ad_resolver.resolve_principal(sid_value)
        if not user_obj:
            logger.debug(f"No domain SID found for user {name}")
            continue

        user_sid = user_obj.get("SID") or user_obj.get("objectSid")
        if isinstance(user_sid, bytes):
            user_sid = ad_resolver._sid_bytes_to_string(user_sid)

        if not user_sid:
            logger.warning(f"No domain SID found for user {name}")
            continue

        sam = user_obj.get("sAMAccountName", name)
        resource_id_str = f"{resource_id}@{site_code}" if resource_id else None

        graph.upsert_node(
            user_sid,
            ["User", "Base"],
            properties={
                "collectionSource": ["AdminService-SMS_R_User"],
                "sAMAccountName": sam,
                "name": sam,
                **({"SCCMResourceIDs": [resource_id_str]} if resource_id_str else {}),
            },
            ad_object=user_obj,
        )
        total_users += 1

        # Create Group nodes from SecurityGroupName (PowerShell lines 7462-7475)
        security_groups = item.get("SecurityGroupName", [])
        if isinstance(security_groups, list):
            for group_name in security_groups:
                if not group_name:
                    continue
                group_obj = ad_resolver.resolve_principal(group_name)
                if not group_obj:
                    continue

                group_sid = group_obj.get("SID") or group_obj.get("objectSid")
                if isinstance(group_sid, bytes):
                    group_sid = ad_resolver._sid_bytes_to_string(group_sid)

                if group_sid:
                    group_sam = group_obj.get("sAMAccountName", group_name)
                    graph.upsert_node(
                        group_sid,
                        ["Group", "Base"],
                        properties={
                            "collectionSource": ["AdminService-SMS_R_User"],
                            "sAMAccountName": group_sam,
                            "name": group_sam,
                            **({"SCCMResourceIDs": [resource_id_str]} if resource_id_str else {}),
                        },
                        ad_object=group_obj,
                    )
                    graph.upsert_edge(
                        user_sid,
                        group_sid,
                        "MemberOf",
                        properties={
                            "collectionSource": ["AdminService-SMS_R_User"],
                        },
                    )
                    total_groups += 1

    logger.info(f"Successfully processed {total_users} users and {total_groups} groups via SMS_R_User")


def _get_collections(
    client: AdminServiceClient,
    graph: GraphStore,
    site_code: str,
) -> None:
    """
    Get SCCM collections.

    Translated from PowerShell Get-CollectionsViaAdminService (lines 7494-7582).
    """
    logger.info("Getting collections...")

    items = client.get_paginated("wmi/SMS_Collection")
    if not items:
        logger.info("No collections found")
        return

    logger.info(f"Found {len(items)} collections")

    for item in items:
        collection_id = item.get("CollectionID", "")
        name = item.get("Name", "")
        coll_type = item.get("CollectionType", 0)
        member_count = item.get("MemberCount", 0)
        limiting_id = item.get("LimitToCollectionID", "")

        if not collection_id:
            continue

        node_id = f"{collection_id}@{site_code}"

        graph.upsert_node(
            node_id,
            ["SCCM_Collection"],
            properties={
                "name": f"{name}@{site_code}" if name else node_id,
                "collectionSource": ["AdminService-SMS_Collection"],
                "collectionID": collection_id,
                "collectionType": coll_type,
                "memberCount": member_count,
                "siteCode": site_code,
                "limitToCollectionID": limiting_id,
            },
        )

        # SCCM_Contains: Site -> Collection
        graph.upsert_edge(site_code, node_id, "SCCM_Contains")


def _get_collection_members(
    client: AdminServiceClient,
    graph: GraphStore,
    site_code: str,
) -> None:
    """
    Get collection members.

    Translated from PowerShell Get-CollectionMembersViaAdminService (lines 7584-7662).
    """
    logger.info("Getting collection members...")

    items = client.get_paginated("wmi/SMS_FullCollectionMembership")
    if not items:
        logger.info("No collection members found")
        return

    logger.info(f"Found {len(items)} collection memberships")

    # Group members by CollectionID to match PS Group-Object (line 7595)
    from collections import defaultdict
    collections_map: dict[str, list[dict]] = defaultdict(list)
    for item in items:
        cid = item.get("CollectionID", "")
        if cid:
            collections_map[cid].append(item)

    logger.info(f"Grouped into {len(collections_map)} collections")

    for collection_id, members in collections_map.items():
        # Use site code from first member in group (PS line 7601)
        member_site_code = members[0].get("SiteCode") or ""
        coll_node_id = f"{collection_id}@{member_site_code}"

        # Upsert collection node once per group (PS lines 7605-7610)
        graph.upsert_node(
            coll_node_id,
            ["SCCM_Collection"],
            properties={
                "collectionSource": ["AdminService-SMS_FullCollectionMembership"],
                "sourceSiteCode": member_site_code,
            },
        )

        for item in members:
            resource_id = item.get("ResourceID")
            sms_id = item.get("SMSID", "")

            if not resource_id:
                continue

            # Find matching client device
            if sms_id:
                device_id = sms_id if sms_id.upper().startswith("GUID:") else f"GUID:{sms_id}"
            else:
                device_id = f"RID:{resource_id}"

            # Verify device exists in graph
            device_node = graph.get_node(device_id)
            if not device_node:
                # Try finding by GUID prefix
                for node in graph.find_nodes_by_kind("SCCM_ClientDevice"):
                    node_props = node.get("properties", {})
                    if node_props.get("resourceID") == resource_id:
                        device_id = node.get("id")
                        device_node = node
                        break

            if device_node:
                graph.upsert_edge(coll_node_id, device_id, "SCCM_HasMember")


def _get_security_roles(
    client: AdminServiceClient,
    graph: GraphStore,
    site_code: str,
) -> None:
    """
    Get security roles.

    Translated from PowerShell Get-SecurityRolesViaAdminService (lines 7664-7752).
    """
    logger.info("Getting security roles...")

    items = client.get_paginated("wmi/SMS_Role")
    if not items:
        logger.info("No security roles found")
        return

    logger.info(f"Found {len(items)} security roles")

    for item in items:
        role_id = item.get("RoleID", "")
        role_name = item.get("RoleName", "")
        description = item.get("RoleDescription", "")

        if not role_id:
            continue

        node_id = f"{role_id}@{site_code}"

        graph.upsert_node(
            node_id,
            ["SCCM_SecurityRole"],
            properties={
                "name": f"{role_name}@{site_code}" if role_name else node_id,
                "collectionSource": ["AdminService-SMS_Role"],
                "roleID": role_id,
                "roleName": role_name,
                "description": description,
                "siteCode": site_code,
            },
        )


def _get_admin_users(
    client: AdminServiceClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> None:
    """
    Get admin users.

    Translated from PowerShell Get-AdminUsersViaAdminService (lines 7754-7904).

    NOTE: Permissions, Roles, Categories are lazy properties on SMS_Admin
    and return empty arrays in list queries. We use RoleNames and CollectionNames
    (non-lazy) to look up security role and collection nodes by name, matching
    the PowerShell fallback behavior (lines 7864-7888).
    """
    logger.info("Getting admin users...")

    items = client.get_paginated("wmi/SMS_Admin")
    if not items:
        logger.info("No admin users found")
        return

    logger.info(f"Found {len(items)} admin users")

    for item in items:
        admin_id_raw = item.get("AdminID")
        logon_name = item.get("LogonName", "")
        display_name = item.get("DisplayName", "")
        admin_sid = item.get("AdminSid", "")
        role_names = item.get("RoleNames", [])  # Non-lazy, always populated
        collection_names = item.get("CollectionNames", [])  # Non-lazy, always populated
        is_group = item.get("AccountType", 0) == 1
        source_site = item.get("SourceSite", site_code)

        if isinstance(role_names, str):
            role_names = [r.strip() for r in role_names.split(",")]
        if isinstance(collection_names, str):
            collection_names = [c.strip() for c in collection_names.split(",")]

        # Normalize logon name
        logon_lower = logon_name.lower().strip()
        node_id = f"{logon_lower}@{site_code}"

        # Determine if all instances from CategoryNames
        is_all_instances = False
        scope_names = item.get("CategoryNames", [])
        if isinstance(scope_names, list):
            is_all_instances = "All Systems" in scope_names or "All" in scope_names

        # Create admin user node (initial - collectionIDs and securityRoles populated below)
        graph.upsert_node(
            node_id,
            ["SCCM_AdminUser"],
            properties={
                "name": f"{logon_name}@{site_code}",
                "collectionSource": ["AdminService-SMS_Admin"],
                "logonName": logon_name,
                "displayName": display_name,
                "adminSid": admin_sid,
                "collectionIDs": [],
                "securityRoles": [],
                "memberOf": [],
                "isGroup": is_group,
                "isAllInstances": is_all_instances,
                "siteCode": site_code,
                "SCCMInfra": True,
                "sourceSiteCode": source_site,
            },
        )

        # Resolve CollectionNames to collection node IDs and create SCCM_IsAssigned edges
        # (PowerShell lines 7816-7833)
        resolved_collection_ids = []
        for coll_name in (collection_names or []):
            coll_name = coll_name.strip()
            if not coll_name:
                continue
            # Find collection node by name matching @site_code
            # Collection names in graph are stored as "Name@SiteCode" (e.g., "All Systems@PS1")
            matched_coll = None
            for coll_node in graph.find_nodes_by_kind("SCCM_Collection"):
                coll_id = coll_node.get("id", "")
                coll_props = coll_node.get("properties", {})
                coll_node_name = coll_props.get("name", "")
                # Strip @SiteCode suffix from stored name for comparison
                coll_name_base = coll_node_name.split("@")[0] if "@" in coll_node_name else coll_node_name
                if (coll_name_base == coll_name and coll_id.endswith(f"@{site_code}")):
                    matched_coll = coll_node
                    break
            if matched_coll:
                coll_id = matched_coll.get("id")
                resolved_collection_ids.append(coll_id)
                graph.upsert_edge(node_id, coll_id, "SCCM_IsAssigned",
                                  properties={"collectionSource": ["AdminService-SMS_Admin"]})
                # Add collection ID to admin user's collectionIDs
                graph.upsert_node(node_id, ["SCCM_AdminUser"],
                                  properties={"collectionIDs": [coll_id]})
                logger.debug(f"Admin {node_id} assigned to collection {coll_id}")
            else:
                logger.warning(f"No collection node found for '{coll_name}' in site {site_code}")

        # Resolve RoleNames to security role node IDs and create SCCM_IsAssigned edges
        # (PowerShell lines 7864-7888 - fallback to RoleNames since Roles is lazy/empty)
        resolved_role_ids = []
        for role_name in (role_names or []):
            role_name = role_name.strip()
            if not role_name:
                continue
            # Find role node by roleName property matching @site_code
            matched_role = None
            for role_node in graph.find_nodes_by_kind("SCCM_SecurityRole"):
                role_id = role_node.get("id", "")
                role_props = role_node.get("properties", {})
                role_node_name = role_props.get("roleName", "")
                if (role_node_name == role_name and role_id.endswith(f"@{site_code}")):
                    matched_role = role_node
                    break
            if matched_role:
                role_id = matched_role.get("id")
                resolved_role_ids.append(role_id)
                graph.upsert_edge(node_id, role_id, "SCCM_IsAssigned",
                                  properties={"collectionSource": ["AdminService-SMS_Admin"]})
                # Add role to admin user's securityRoles and memberOf
                graph.upsert_node(node_id, ["SCCM_AdminUser"],
                                  properties={
                                      "securityRoles": [role_id],
                                      "memberOf": [f"{role_id} ({role_name})"],
                                  })
                # Add admin user to role's members
                graph.upsert_node(role_id, ["SCCM_SecurityRole"],
                                  properties={"members": [node_id]})
                logger.debug(f"Admin {node_id} assigned to role {role_id} ({role_name})")
            else:
                logger.warning(f"No role node found for '{role_name}' in site {site_code}")

        # Create SCCM_IsMappedTo: User/Group -> SCCM_AdminUser
        if admin_sid:
            # Resolve the SID to see if it's a user or group
            ad_obj = ad_resolver.resolve_principal(admin_sid)
            if ad_obj:
                resolved_sid = ad_obj.get("SID") or ad_obj.get("objectSid")
                if isinstance(resolved_sid, bytes):
                    resolved_sid = ad_resolver._sid_bytes_to_string(resolved_sid)

                if resolved_sid:
                    kinds = ["Group", "Base"] if is_group else ["User", "Base"]
                    sam = ad_obj.get("sAMAccountName", logon_name.split("\\")[-1])
                    graph.upsert_node(
                        resolved_sid,
                        kinds,
                        properties={
                            "sAMAccountName": sam,
                            "name": sam,
                            "SCCMInfra": True,
                        },
                        ad_object=ad_obj,
                    )
                    graph.upsert_edge(resolved_sid, node_id, "SCCM_IsMappedTo",
                                      properties={"collectionSource": ["AdminService-SMS_Admin"],
                                                   "SCCMInfra": True})
            else:
                logger.warning(f"No domain object found for admin user {node_id}")
        else:
            logger.warning(f"No domain SID found for admin user {node_id}")


def _get_site_system_roles(
    client: AdminServiceClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target_manager: TargetManager,
    site_code: str,
    domain: str,
) -> None:
    """
    Get site system roles.

    Translated from PowerShell Get-SiteSystemRolesViaAdminService (lines 7906-8061).
    """
    logger.info("Getting site system roles...")

    items = client.get_paginated("wmi/SMS_SCI_SysResUse")
    if not items:
        logger.info("No site system roles found")
        return

    logger.info(f"Found {len(items)} site system role entries")

    # Track roles per server
    server_roles: dict[str, list[str]] = {}
    server_sites: dict[str, str] = {}
    server_props_map: dict[str, dict[str, Any]] = {}

    for item in items:
        server_name = item.get("ServerName", "") or item.get("NetworkOSPath", "").replace("\\", "")
        role_name = item.get("RoleName", "")
        role_site = item.get("SiteCode", site_code)

        if not server_name or not role_name:
            continue

        api_site = item.get("SiteCode")
        logger.debug(
            f"  SysResUse: {server_name} role={role_name} "
            f"api_SiteCode={api_site} resolved={role_site} (param={site_code})"
        )

        # Normalize server name (may include domain)
        server_key = server_name.lower()

        if server_key not in server_roles:
            server_roles[server_key] = []
        server_roles[server_key].append(f"{role_name}@{role_site}")
        server_sites[server_key] = role_site

        # Extract service account info from embedded properties
        # PS looks for "SQL Server Service Logon Account" in Props.Value2
        props_list = item.get("Props", [])
        if isinstance(props_list, list):
            for prop in props_list:
                if isinstance(prop, dict):
                    prop_name = prop.get("PropertyName", "")
                    prop_value = prop.get("Value1", "") or prop.get("Value2", "")
                    if prop_name and prop_value:
                        if server_key not in server_props_map:
                            server_props_map[server_key] = {}
                        server_props_map[server_key][prop_name] = prop_value
                    # Specifically capture the SQL service account (Value2)
                    if prop_name == "SQL Server Service Logon Account":
                        val2 = prop.get("Value2", "")
                        if val2:
                            if server_key not in server_props_map:
                                server_props_map[server_key] = {}
                            server_props_map[server_key]["_SQLServiceAccount"] = val2

    # Create/update computer nodes for each server
    for server_key, roles in server_roles.items():
        server_name = server_key
        role_site = server_sites.get(server_key, site_code)

        logger.info(f"Server: {server_name} -> Roles: {', '.join(roles)}")

        # Add as collection target
        target_manager.add_device(server_name, source="AdminService-SMS_SCI_SysResUse")

        # Resolve AD object
        ad_obj = ad_resolver.get_ad_computer(server_name)
        if ad_obj:
            sid = ad_obj.get("SID") or ad_obj.get("objectSid")
            if isinstance(sid, bytes):
                sid = ad_resolver._sid_bytes_to_string(sid)

            if sid:
                node_props: dict[str, Any] = {
                    "collectionSource": ["AdminService-SMS_SCI_SysResUse"],
                    "SCCMInfra": True,
                    "SCCMSiteSystemRoles": roles,
                    "dNSHostName": ad_obj.get("dNSHostName", server_name),
                    "sAMAccountName": ad_obj.get("sAMAccountName", ""),
                    "name": ad_obj.get("sAMAccountName", ""),
                }

                # Check for service account in props
                extra_props = server_props_map.get(server_key, {})
                service_account_name = extra_props.get("_SQLServiceAccount")
                generic_svc = extra_props.get("ServiceAccount") or extra_props.get("Username")
                if generic_svc:
                    node_props["SCCMServiceAccount"] = generic_svc

                graph.upsert_node(
                    sid,
                    ["Computer", "Base"],
                    properties=node_props,
                    ad_object=ad_obj,
                )

                # Handle SQL service account (PS lines 7966-8019)
                if service_account_name:
                    sa_obj = ad_resolver.resolve_principal(service_account_name, domain)
                    if sa_obj:
                        sa_sid = sa_obj.get("SID") or sa_obj.get("objectSid")
                        if isinstance(sa_sid, bytes):
                            sa_sid = ad_resolver._sid_bytes_to_string(sa_sid)
                        if sa_sid:
                            sa_type = sa_obj.get("type", "User")
                            sa_kinds = ["User", "Base"] if sa_type == "User" else ["Computer", "Base"]
                            graph.upsert_node(
                                sa_sid,
                                sa_kinds,
                                properties={
                                    "collectionSource": ["AdminService-SMS_SCI_SysResUse"],
                                    "SCCMInfra": True,
                                },
                                ad_object=sa_obj,
                            )
                            # Update site node with service account
                            graph.upsert_node(
                                role_site,
                                ["SCCM_Site"],
                                properties={
                                    "collectionSource": ["AdminService-SMS_SCI_SysResUse"],
                                    "SQLServiceAccountDomainSID": sa_sid,
                                    "SQLServiceAccountName": sa_obj.get("sAMAccountName", service_account_name),
                                },
                            )
                            # Update MSSQL_Server node with service account
                            mssql_server_id = f"{sid}:1433"
                            graph.upsert_node(
                                mssql_server_id,
                                ["MSSQL_Server"],
                                properties={
                                    "collectionSource": ["AdminService-SMS_SCI_SysResUse"],
                                    "SCCMInfra": True,
                                    "SQLServiceAccountDomainSID": sa_sid,
                                    "SQLServiceAccountName": sa_obj.get("sAMAccountName", service_account_name),
                                },
                            )
                            # Create edges if service account != computer (dedicated account)
                            if sa_sid != sid:
                                # HasSession: computer -> service account
                                graph.upsert_edge(sid, sa_sid, "HasSession", properties={
                                    "collectionSource": ["AdminService-SMS_SCI_SysResUse"],
                                })
                                # MSSQL_ServiceAccountFor: service account -> MSSQL_Server
                                graph.upsert_edge(sa_sid, mssql_server_id, "MSSQL_ServiceAccountFor", properties={
                                    "collectionSource": ["AdminService-SMS_SCI_SysResUse"],
                                })
                                # MSSQL_GetAdminTGS: service account -> MSSQL_Server
                                graph.upsert_edge(sa_sid, mssql_server_id, "MSSQL_GetAdminTGS", properties={
                                    "collectionSource": ["AdminService-SMS_SCI_SysResUse"],
                                })
                    else:
                        logger.debug(f"No domain object found for SQL service account {service_account_name}, likely a local account")

                # Check for SQL Server role and create MSSQL_Server node
                has_sql_role = any("SQL Server" in r for r in roles)
                if has_sql_role:
                    # Create MSSQL_Server node (PS line 7997 / 8034-8040)
                    mssql_sid = f"{sid}:1433"
                    graph.upsert_node(
                        mssql_sid,
                        ["MSSQL_Server"],
                        properties={
                            "collectionSource": ["AdminService-SMS_SCI_SysResUse"],
                            "SCCMInfra": True,
                        },
                    )
                    # Extract SQL server and DB name
                    sql_info = extra_props.get("SQLServerName", server_name)
                    sql_db = extra_props.get("DatabaseName", "")
                    if sql_db:
                        node_props["SQLDatabaseName"] = sql_db
                        # Update site node with SQL info
                        graph.upsert_node(
                            role_site,
                            ["SCCM_Site"],
                            properties={
                                "SQLServerName": sql_info,
                                "SQLDatabaseName": sql_db,
                            },
                        )
