"""
WMI collection for ConfigManBearPig.

Translated from PowerShell Invoke-SmsProviderWmiCollection (lines 8063-8600).
Uses impacket DCOM/WMI to query SCCM SMS Provider WMI classes.
Produces the same nodes/edges as AdminService collection.

WMI classes queried:
- SMS_ProviderLocation (site code discovery)
- SMS_Site (basic site info)
- SMS_SCI_SiteDefinition (detailed site info with GUID)
- SMS_SCI_Reserved (stored accounts / NAA)
- SMS_CombinedDeviceResources / SMS_R_System (client devices)
- SMS_R_User (user resources)
- SMS_Collection (collections)
- SMS_FullCollectionMembership (collection members)
- SMS_Role (security roles)
- SMS_Admin (admin users)
- SMS_SCI_SysResUse (site system roles)
"""

import logging
import socket
from collections import defaultdict
from typing import Any, Optional

from lib.ad_resolver import ADResolver
from lib.graph import GraphStore
from lib.targets import CollectionTarget, TargetManager

logger = logging.getLogger("ConfigManBearPig")


def _parse_wmi_bool(value: Any) -> bool:
    """Parse a boolean value from WMI, which may return strings, ints, or bools."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    if isinstance(value, int):
        return value != 0
    return False


def _extract_embedded_props(props_raw: Any) -> dict[str, dict[str, str]]:
    """
    Extract embedded properties from WMI SMS_EmbeddedProperty array.

    impacket DCOM returns embedded objects as ENCODING_UNIT instances
    (raw CIM binary). This function handles:
    - list of dicts (simple case)
    - list of impacket ENCODING_UNIT objects (decoded from raw bytes)

    Returns:
        Dict mapping PropertyName -> {"Value1": ..., "Value2": ...}
    """
    import re

    result: dict[str, dict[str, str]] = {}

    if props_raw is None:
        return result

    items = props_raw if isinstance(props_raw, list) else [props_raw]

    for prop in items:
        try:
            if isinstance(prop, dict):
                pn = prop.get("PropertyName", "")
                if pn:
                    result[pn] = {
                        "Value1": str(prop.get("Value1", "") or ""),
                        "Value2": str(prop.get("Value2", "") or ""),
                    }
            elif hasattr(prop, "getData"):
                # impacket ENCODING_UNIT — extract from raw binary
                raw = prop.getData()
                # Extract readable ASCII strings (the embedded property values)
                strings = [s.decode("ascii", errors="ignore")
                           for s in re.findall(b"[\\x20-\\x7e]{3,}", raw)]

                # The SMS_EmbeddedProperty structure stores:
                #   class definition strings first, then instance data.
                # Instance data appears after the last "SMS_EmbeddedProperty" marker.
                # The pattern is: PropertyName, Value2 (both as trailing strings)
                last_marker = -1
                for i, s in enumerate(strings):
                    if s == "SMS_EmbeddedProperty":
                        last_marker = i

                if last_marker >= 0 and last_marker + 1 < len(strings):
                    # Strings after the last marker are the instance values
                    instance_strings = strings[last_marker + 1:]
                    if len(instance_strings) >= 1:
                        pn = instance_strings[0]
                        v2 = instance_strings[1] if len(instance_strings) >= 2 else ""
                        result[pn] = {"Value1": "", "Value2": v2}
        except Exception:
            continue

    return result


# Try to import impacket for DCOM WMI
try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi as impacket_wmi
    from impacket.dcerpc.v5.dtypes import NULL

    HAS_IMPACKET_WMI = True
except ImportError:
    HAS_IMPACKET_WMI = False


class WMIClient:
    """
    Client for SCCM WMI queries via impacket DCOM.

    Connects to a remote WMI namespace and executes WQL queries.
    """

    def __init__(
        self,
        target: str,
        username: str,
        password: str,
        domain: str,
    ):
        self.target = target
        self.domain = domain
        self.dcom: Any = None
        self._wmi_services: Any = None

        # Parse DOMAIN\user or user@domain format
        self._user = username
        self._password = password
        self._auth_domain = domain
        if "\\" in username:
            self._auth_domain, self._user = username.split("\\", 1)
        elif "@" in username:
            self._user, self._auth_domain = username.split("@", 1)

    def connect(self, namespace: str) -> bool:
        """
        Establish DCOM WMI connection to the given namespace.

        Args:
            namespace: WMI namespace (e.g., "root\\SMS\\site_PS1")

        Returns:
            True if connected successfully
        """
        try:
            self.dcom = DCOMConnection(
                self.target,
                username=self._user,
                password=self._password,
                domain=self._auth_domain,
            )

            iInterface = self.dcom.CoCreateInstanceEx(
                impacket_wmi.CLSID_WbemLevel1Login,
                impacket_wmi.IID_IWbemLevel1Login,
            )
            iWbemLevel1Login = impacket_wmi.IWbemLevel1Login(iInterface)
            self._wmi_services = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
            iWbemLevel1Login.RemRelease()
            return True
        except Exception as e:
            logger.warning(f"WMI connection to {self.target} namespace {namespace} failed: {e}")
            self.disconnect()
            return False

    def query(self, wql: str) -> list[dict[str, Any]]:
        """
        Execute a WQL query and return results as list of property dicts.

        Args:
            wql: WQL query string

        Returns:
            List of dicts mapping property names to values
        """
        if not self._wmi_services:
            raise RuntimeError("Not connected to WMI")

        results: list[dict[str, Any]] = []
        try:
            enum = self._wmi_services.ExecQuery(wql)
        except Exception as e:
            logger.warning(f"WMI query failed [{wql[:80]}...]: {e}")
            return results

        while True:
            try:
                objects = enum.Next(0xFFFFFFFF, 1)
            except Exception:
                break

            if not objects:
                break

            for obj in objects:
                try:
                    props = obj.getProperties()
                    record: dict[str, Any] = {}
                    for name, prop_data in props.items():
                        record[name] = prop_data.get("value")
                    results.append(record)
                except Exception as e:
                    logger.debug(f"Failed to parse WMI object properties: {e}")

        return results

    def disconnect(self) -> None:
        """Clean up DCOM connection."""
        if self.dcom:
            try:
                self.dcom.disconnect()
            except Exception:
                pass
            self.dcom = None
            self._wmi_services = None


def invoke_wmi_collection(
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
    Run WMI collection against a target SMS Provider.

    Translated from PowerShell Invoke-SmsProviderWmiCollection (lines 8063-8208).
    Queries the same WMI classes as AdminService and produces identical nodes/edges.

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

    if not HAS_IMPACKET_WMI:
        logger.error("impacket DCOM/WMI modules not available. Install impacket>=0.11.0")
        return

    if not username or not password:
        logger.warning("WMI collection requires explicit credentials (-u/-p)")
        return

    logger.info(f"Starting WMI collection on {hostname}...")

    # Fast port check - DCOM uses TCP 135
    try:
        with socket.create_connection((hostname, 135), timeout=3):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        logger.info(f"DCOM port 135 not open on {hostname}, skipping WMI collection")
        return

    # Step 1: Discover site code(s)
    site_codes = _discover_site_codes(hostname, username, password, domain, graph)
    if not site_codes:
        logger.warning(f"No SCCM site codes discovered on {hostname}")
        return

    # Step 2: Collect from each site
    for site_code in site_codes:
        namespace = f"root\\SMS\\site_{site_code}"
        logger.info(f"Connecting to WMI namespace: {namespace} on {hostname}")

        client = WMIClient(hostname, username, password, domain)
        if not client.connect(namespace):
            logger.warning(f"Could not connect to WMI namespace {namespace} on {hostname}")
            continue

        # Probe query to verify the namespace is actually responsive
        probe = client.query("SELECT SiteCode FROM SMS_Site WHERE SiteCode = '{}'".format(site_code))
        if not probe:
            logger.warning(
                f"WMI namespace {namespace} connected but queries are failing on {hostname}, "
                f"skipping WMI collections for site {site_code}"
            )
            client.disconnect()
            continue

        try:
            collections_ok = 0
            collections_total = 0

            # Sites
            collections_total += 1
            if _get_sites_via_wmi(client, graph, target_manager, ad_resolver, domain, site_code):
                collections_ok += 1

            # Stored accounts (SMS_SCI_Reserved)
            collections_total += 1
            if _get_stored_accounts_via_wmi(client, graph, ad_resolver, site_code, domain):
                collections_ok += 1

            # Combined device resources
            collections_total += 1
            if _get_combined_device_resources_via_wmi(client, graph, ad_resolver, site_code, domain):
                collections_ok += 1

            # SMS_R_System
            collections_total += 1
            if _get_sms_r_system_via_wmi(client, graph, ad_resolver, target_manager, site_code, domain):
                collections_ok += 1

            # SMS_R_User
            collections_total += 1
            if _get_sms_r_user_via_wmi(client, graph, ad_resolver, site_code, domain):
                collections_ok += 1

            # Collections
            collections_total += 1
            if _get_collections_via_wmi(client, graph, site_code):
                collections_ok += 1

            # Collection members
            collections_total += 1
            if _get_collection_members_via_wmi(client, graph, site_code):
                collections_ok += 1

            # Security roles
            collections_total += 1
            if _get_security_roles_via_wmi(client, graph, site_code):
                collections_ok += 1

            # Admin users
            collections_total += 1
            if _get_admin_users_via_wmi(client, graph, ad_resolver, site_code, domain):
                collections_ok += 1

            # Site system roles
            collections_total += 1
            if _get_site_system_roles_via_wmi(client, graph, ad_resolver, target_manager, site_code, domain):
                collections_ok += 1

            if collections_ok > 0:
                logger.info(
                    f"WMI collection successful on {hostname} for site {site_code} "
                    f"({collections_ok}/{collections_total} collections succeeded)"
                )
                break  # Success - don't try other site codes
            else:
                logger.warning(
                    f"WMI collection failed for site {site_code} on {hostname} "
                    f"(0/{collections_total} succeeded)"
                )
        finally:
            client.disconnect()

    logger.info(f"WMI collection completed for {hostname}")


def _discover_site_codes(
    hostname: str,
    username: str,
    password: str,
    domain: str,
    graph: GraphStore,
) -> list[str]:
    """
    Discover SCCM site codes from the SMS Provider.

    Tries: 1) graph (from prior phases), 2) WMI SMS_ProviderLocation query.
    """
    # Check graph for previously discovered sites
    site_codes: list[str] = []
    for node in graph.find_nodes_by_kind("SCCM_Site"):
        sc = node.get("properties", {}).get("siteCode")
        if sc and sc not in site_codes:
            site_codes.append(sc)

    if site_codes:
        logger.info(f"Found site codes from graph: {', '.join(site_codes)}")
        return site_codes

    # Query root\SMS for SMS_ProviderLocation
    logger.info(f"Discovering site codes via WMI on {hostname}...")
    client = WMIClient(hostname, username, password, domain)
    try:
        if not client.connect("root\\SMS"):
            logger.warning("Could not connect to root\\SMS namespace")
            return []

        providers = client.query("SELECT SiteCode, ProviderForLocalSite FROM SMS_ProviderLocation")
        for p in providers:
            sc = p.get("SiteCode")
            if sc and sc not in site_codes:
                site_codes.append(sc)
                logger.info(f"Discovered site code via WMI: {sc}")

        if not site_codes:
            logger.warning("No SMS_ProviderLocation entries found")

        return site_codes
    finally:
        client.disconnect()


def _get_sites_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    target_manager: TargetManager,
    ad_resolver: ADResolver,
    domain: str,
    site_code: str,
) -> bool:
    """
    Get sites via WMI: SMS_Site + SMS_SCI_SiteDefinition.

    Mirrors AdminService _get_sites_via_adminservice.
    """
    try:
        logger.info("Getting sites via WMI...")

        # Query SMS_Site for basic site info
        sites = client.query(
            "SELECT SiteCode, SiteName, Type, ServerName, ReportingSiteCode, Version "
            "FROM SMS_Site"
        )
        logger.info(f"Found {len(sites)} sites via SMS_Site")

        for item in sites:
            sc = item.get("SiteCode", "")
            site_name = item.get("SiteName", "")
            site_type = item.get("Type", 0)
            server_name = item.get("ServerName", "")
            report_to = item.get("ReportingSiteCode", "")
            version = item.get("Version", "")

            if not sc:
                continue

            logger.info(
                f"Site: {sc} ({site_name}), Type: {site_type}, "
                f"Server: {server_name}, ReportsTo: {report_to}"
            )

            graph.upsert_node(
                sc,
                ["SCCM_Site"],
                properties={
                    "collectionSource": ["WMI-SMS_Site"],
                    "SCCMInfra": True,
                    "siteCode": sc,
                    "siteName": site_name,
                    "siteType": site_type,
                    "serverName": server_name,
                    "reportToSite": report_to or sc,
                    "version": version,
                    "isCAS": site_type == 4,
                },
            )

            if server_name:
                target_manager.add_device(server_name, source="WMI-SMS_Site")
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
                                "collectionSource": ["WMI-SMS_Site"],
                                "SCCMInfra": True,
                                "SCCMSiteSystemRoles": [f"SMS Site Server@{sc}"],
                                "dNSHostName": ad_obj.get("dNSHostName", server_name),
                                "sAMAccountName": ad_obj.get("sAMAccountName", ""),
                                "name": ad_obj.get("sAMAccountName", ""),
                            },
                            ad_object=ad_obj,
                        )

        # Query SMS_SCI_SiteDefinition for detailed site info (GUID, SQL, parent)
        site_defs = client.query(
            "SELECT SiteCode, ParentSiteCode, SiteServerName, "
            "SQLServerName, SQLDatabaseName FROM SMS_SCI_SiteDefinition"
        )
        for item in site_defs:
            sc = item.get("SiteCode", "")
            parent_site = item.get("ParentSiteCode", "")
            site_server = item.get("SiteServerName", "")
            sql_server = item.get("SQLServerName", "")
            sql_db = item.get("SQLDatabaseName", "")

            if not sc:
                continue

            props: dict[str, Any] = {
                "collectionSource": ["WMI-SMS_SCI_SiteDefinition"],
            }
            if parent_site:
                props["reportToSite"] = parent_site
            if sql_server:
                props["SQLServerName"] = sql_server
                target_manager.add_device(sql_server, source="WMI-SMS_SCI_SiteDefinition")

                sql_ad_obj = ad_resolver.get_ad_computer(sql_server)
                if sql_ad_obj:
                    sql_sid = sql_ad_obj.get("SID") or sql_ad_obj.get("objectSid")
                    if isinstance(sql_sid, bytes):
                        sql_sid = ad_resolver._sid_bytes_to_string(sql_sid)
                    if sql_sid:
                        logger.info(f"Found SQL Server for site {sc}: {sql_server}")
                        graph.upsert_node(
                            sql_sid,
                            ["Computer", "Base"],
                            properties={
                                "collectionSource": ["WMI-SMS_SCI_SiteDefinition"],
                                "SCCMInfra": True,
                                "SCCMSiteSystemRoles": [f"SMS SQL Server@{sc}"],
                                "dNSHostName": sql_ad_obj.get("dNSHostName", sql_server),
                                "sAMAccountName": sql_ad_obj.get("sAMAccountName", ""),
                                "name": sql_ad_obj.get("sAMAccountName", ""),
                            },
                            ad_object=sql_ad_obj,
                        )
            if sql_db:
                props["SQLDatabaseName"] = sql_db

            graph.upsert_node(sc, ["SCCM_Site"], properties=props)

        return True
    except Exception as e:
        logger.warning(f"Failed to collect sites via WMI: {e}")
        return False


def _get_stored_accounts_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> bool:
    """
    Get stored accounts via WMI (SMS_SCI_Reserved).

    Mirrors AdminService _get_stored_accounts.
    """
    try:
        logger.info("Getting stored accounts via WMI...")

        items = client.query(
            "SELECT UserName, ItemName, ItemType, SiteCode FROM SMS_SCI_Reserved"
        )
        if not items:
            logger.info("No stored accounts found via WMI")
            return True  # Not an error

        logger.info(f"Found {len(items)} stored account entries via WMI")

        stored_count = 0
        for item in items:
            username = item.get("UserName", "")
            item_name = item.get("ItemName", "")
            item_type = item.get("ItemType", "")
            account_site = item.get("SiteCode") or site_code

            if not username:
                if item_name:
                    logger.debug(
                        f"Stored account entry with no UserName: {item_name} "
                        f"(type: {item_type}, site: {account_site})"
                    )
                continue

            logger.debug(f"Stored account: {username} (type: {item_type}, site: {account_site})")

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

            sam = ad_obj.get(
                "sAMAccountName",
                username.split("\\")[-1] if "\\" in username else username,
            )

            graph.upsert_node(
                user_sid,
                ["User", "Base"],
                properties={
                    "collectionSource": ["WMI-SMS_SCI_Reserved"],
                    "name": sam,
                    "sAMAccountName": sam,
                    "storedInSCCMSite": account_site,
                },
                ad_object=ad_obj,
            )

            site_node = graph.get_node(account_site)
            if site_node:
                graph.upsert_node(
                    account_site,
                    ["SCCM_Site"],
                    properties={
                        "collectionSource": ["WMI-SMS_SCI_Reserved"],
                        "storedAccounts": [f"{sam} ({user_sid})"],
                    },
                )
                graph.upsert_edge(
                    account_site,
                    user_sid,
                    "SCCM_HasStoredAccount",
                    properties={"collectionSource": ["WMI-SMS_SCI_Reserved"]},
                )
                stored_count += 1
                logger.info(f"Created SCCM_HasStoredAccount: {account_site} -> {sam} ({user_sid})")

        logger.info(f"Processed {stored_count} stored accounts via WMI")
        return True
    except Exception as e:
        logger.warning(f"Failed to collect stored accounts via WMI: {e}")
        return False


def _get_combined_device_resources_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> bool:
    """
    Get combined device resources via WMI.

    Tries SMS_CombinedDeviceResources first, falls back to SMS_R_System.
    Mirrors AdminService _get_combined_device_resources.
    """
    try:
        logger.info("Getting combined device resources via WMI...")

        # Try SMS_CombinedDeviceResources first
        items = client.query(
            "SELECT Name, ResourceID, SMSID, ClientVersion, IsClient, IsObsolete, "
            "LastLogonUser, CurrentLogonUser, PrimaryUser, SiteCode "
            "FROM SMS_CombinedDeviceResources"
        )
        if not items:
            logger.info("SMS_CombinedDeviceResources empty, trying SMS_R_System fallback")
            items = client.query(
                "SELECT Name, ResourceID, SMSUniqueIdentifier, Client, Obsolete, "
                "ResourceDomainORWorkgroup FROM SMS_R_System"
            )
            if items:
                # Normalize field names from SMS_R_System to match CombinedDeviceResources
                for item in items:
                    item.setdefault("SMSID", item.get("SMSUniqueIdentifier", ""))
                    item.setdefault("IsClient", item.get("Client") == 1)
                    item.setdefault("IsObsolete", item.get("Obsolete") == 1)
                    item.setdefault("SiteCode", site_code)

        if not items:
            logger.info("No combined device resources found via WMI")
            return True

        logger.info(f"Found {len(items)} combined device resources via WMI")

        for item in items:
            name = item.get("Name", "")
            resource_id = item.get("ResourceID")
            sms_guid = item.get("SMSID", "")
            client_version = item.get("ClientVersion", "")
            is_client = _parse_wmi_bool(item.get("IsClient", False))
            is_obsolete = _parse_wmi_bool(item.get("IsObsolete", False))
            last_logon_user = item.get("LastLogonUser", "")
            current_logon_user = item.get("CurrentLogonUser", "")
            primary_user = item.get("PrimaryUser", "")
            assigned_site = item.get("SiteCode") or site_code

            if not name:
                continue

            if not is_client or is_obsolete:
                continue

            if sms_guid:
                device_id = sms_guid if sms_guid.upper().startswith("GUID:") else f"GUID:{sms_guid}"
            else:
                device_id = f"RID:{resource_id}"
            device_name = f"{name.upper()}@{assigned_site or site_code}"

            props: dict[str, Any] = {
                "name": device_name,
                "collectionSource": ["WMI-SMS_CombinedDeviceResources"],
                "siteCode": assigned_site or site_code,
                "resourceID": resource_id,
                "isClient": True,  # Already filtered above
                "clientVersion": client_version,
            }
            if sms_guid:
                props["smsGUID"] = sms_guid

            graph.upsert_node(device_id, ["SCCM_ClientDevice"], properties=props)
            graph.upsert_edge(assigned_site or site_code, device_id, "SCCM_HasClient")

            if last_logon_user:
                _create_user_edge(ad_resolver, graph, device_id, last_logon_user, "SCCM_HasADLastLogonUser", domain)
            if current_logon_user:
                _create_user_edge(ad_resolver, graph, device_id, current_logon_user, "SCCM_HasCurrentUser", domain)
            if primary_user:
                _create_user_edge(ad_resolver, graph, device_id, primary_user, "SCCM_HasPrimaryUser", domain)

        return True
    except Exception as e:
        logger.warning(f"Failed to collect combined device resources via WMI: {e}")
        return False


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

    user_obj = ad_resolver.resolve_principal(username)
    if user_obj:
        sid = user_obj.get("SID") or user_obj.get("objectSid")
        if isinstance(sid, bytes):
            sid = ad_resolver._sid_bytes_to_string(sid)

        if sid:
            sam = user_obj.get(
                "sAMAccountName",
                username.split("\\")[-1] if "\\" in username else username,
            )
            graph.upsert_node(
                sid,
                ["User", "Base"],
                properties={"sAMAccountName": sam, "name": sam},
                ad_object=user_obj,
            )
            graph.upsert_edge(device_id, sid, edge_kind)
            logger.debug(f"{edge_kind}: {device_id} -> {sid} ({sam})")


def _get_sms_r_system_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target_manager: TargetManager,
    site_code: str,
    domain: str,
) -> bool:
    """
    Get SMS_R_System resources via WMI.

    Mirrors AdminService _get_sms_r_system. Creates Computer nodes and
    Group nodes from SecurityGroupName with MemberOf edges.
    """
    try:
        logger.info("Getting SMS_R_System resources via WMI...")

        items = client.query(
            "SELECT Name, ResourceID, SMSUniqueIdentifier, Client, Obsolete, "
            "SecurityGroupName FROM SMS_R_System"
        )
        if not items:
            logger.info("No SMS_R_System resources found via WMI")
            return True

        logger.info(f"Found {len(items)} SMS_R_System resources via WMI")

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

            graph.upsert_node(
                comp_sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["WMI-SMS_R_System"],
                    "name": sam,
                    **({"SCCMResourceIDs": [resource_id_str]} if resource_id_str else {}),
                    **({"SCCMClientDeviceIdentifier": sms_guid} if sms_guid else {}),
                },
                ad_object=ad_obj,
            )

            # Create Group nodes from SecurityGroupName
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
                                "collectionSource": ["WMI-SMS_R_System"],
                                "name": group_sam,
                            },
                            ad_object=group_obj,
                        )
                        graph.upsert_edge(
                            comp_sid, group_sid, "MemberOf",
                            properties={"collectionSource": ["WMI-SMS_R_System"]},
                        )
                        total_groups += 1

            # Update SCCM_ClientDevice node if client and not obsolete
            if _parse_wmi_bool(is_client) and not _parse_wmi_bool(is_obsolete) and sms_guid:
                graph.upsert_node(
                    sms_guid,
                    ["SCCM_ClientDevice"],
                    properties={
                        "collectionSource": ["WMI-SMS_R_System"],
                        "ADDomainSID": comp_sid,
                    },
                )
                graph.upsert_edge(
                    site_code, sms_guid, "SCCM_HasClient",
                    properties={"collectionSource": ["WMI-SMS_R_System"]},
                )

            total_systems += 1

        logger.info(
            f"Successfully processed {total_systems} systems and {total_groups} groups "
            f"via SMS_R_System (WMI)"
        )
        return True
    except Exception as e:
        logger.warning(f"Failed to collect SMS_R_System via WMI: {e}")
        return False


def _get_sms_r_user_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> bool:
    """
    Get SMS_R_User resources via WMI.

    Mirrors AdminService _get_sms_r_user. Creates User nodes and
    Group nodes from SecurityGroupName with MemberOf edges.
    """
    try:
        logger.info("Getting SMS_R_User resources via WMI...")

        items = client.query(
            "SELECT Name, ResourceID, SID, SecurityGroupName, UniqueUserName, "
            "UserPrincipalName FROM SMS_R_User"
        )
        if not items:
            logger.info("No SMS_R_User resources found via WMI")
            return True

        logger.info(f"Found {len(items)} SMS_R_User resources via WMI")

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
                    "collectionSource": ["WMI-SMS_R_User"],
                    "sAMAccountName": sam,
                    "name": sam,
                    **({"SCCMResourceIDs": [resource_id_str]} if resource_id_str else {}),
                },
                ad_object=user_obj,
            )
            total_users += 1

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
                                "collectionSource": ["WMI-SMS_R_User"],
                                "sAMAccountName": group_sam,
                                "name": group_sam,
                            },
                            ad_object=group_obj,
                        )
                        graph.upsert_edge(
                            user_sid, group_sid, "MemberOf",
                            properties={"collectionSource": ["WMI-SMS_R_User"]},
                        )
                        total_groups += 1

        logger.info(
            f"Successfully processed {total_users} users and {total_groups} groups "
            f"via SMS_R_User (WMI)"
        )
        return True
    except Exception as e:
        logger.warning(f"Failed to collect SMS_R_User via WMI: {e}")
        return False


def _get_collections_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    site_code: str,
) -> bool:
    """
    Get SCCM collections via WMI.

    Mirrors AdminService _get_collections.
    """
    try:
        logger.info("Getting collections via WMI...")

        items = client.query(
            "SELECT CollectionID, Name, CollectionType, MemberCount, "
            "LimitToCollectionID FROM SMS_Collection"
        )
        if not items:
            logger.info("No collections found via WMI")
            return True

        logger.info(f"Found {len(items)} collections via WMI")

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
                    "collectionSource": ["WMI-SMS_Collection"],
                    "collectionID": collection_id,
                    "collectionType": coll_type,
                    "memberCount": member_count,
                    "siteCode": site_code,
                    "limitToCollectionID": limiting_id,
                },
            )

            graph.upsert_edge(site_code, node_id, "SCCM_Contains")

        return True
    except Exception as e:
        logger.warning(f"Failed to collect collections via WMI: {e}")
        return False


def _get_collection_members_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    site_code: str,
) -> bool:
    """
    Get collection members via WMI.

    Mirrors AdminService _get_collection_members.
    """
    try:
        logger.info("Getting collection members via WMI...")

        items = client.query(
            "SELECT CollectionID, ResourceID, SiteCode, SMSID "
            "FROM SMS_FullCollectionMembership"
        )
        if not items:
            logger.info("No collection members found via WMI")
            return True

        logger.info(f"Found {len(items)} collection memberships via WMI")

        # Group by CollectionID (matching PS Group-Object behavior)
        collections_map: dict[str, list[dict]] = defaultdict(list)
        for item in items:
            cid = item.get("CollectionID", "")
            if cid:
                collections_map[cid].append(item)

        logger.info(f"Grouped into {len(collections_map)} collections")

        for collection_id, members in collections_map.items():
            member_site_code = members[0].get("SiteCode") or ""
            coll_node_id = f"{collection_id}@{member_site_code}"

            graph.upsert_node(
                coll_node_id,
                ["SCCM_Collection"],
                properties={
                    "collectionSource": ["WMI-SMS_FullCollectionMembership"],
                    "sourceSiteCode": member_site_code,
                },
            )

            for item in members:
                resource_id = item.get("ResourceID")
                sms_id = item.get("SMSID", "")

                if not resource_id:
                    continue

                if sms_id:
                    device_id = sms_id if sms_id.upper().startswith("GUID:") else f"GUID:{sms_id}"
                else:
                    device_id = f"RID:{resource_id}"

                device_node = graph.get_node(device_id)
                if not device_node:
                    for node in graph.find_nodes_by_kind("SCCM_ClientDevice"):
                        node_props = node.get("properties", {})
                        if node_props.get("resourceID") == resource_id:
                            device_id = node.get("id")
                            device_node = node
                            break

                if device_node:
                    graph.upsert_edge(coll_node_id, device_id, "SCCM_HasMember")

        return True
    except Exception as e:
        logger.warning(f"Failed to collect collection members via WMI: {e}")
        return False


def _get_security_roles_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    site_code: str,
) -> bool:
    """
    Get security roles via WMI.

    Mirrors AdminService _get_security_roles.
    """
    try:
        logger.info("Getting security roles via WMI...")

        items = client.query(
            "SELECT RoleID, RoleName, RoleDescription FROM SMS_Role"
        )
        if not items:
            logger.info("No security roles found via WMI")
            return True

        logger.info(f"Found {len(items)} security roles via WMI")

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
                    "collectionSource": ["WMI-SMS_Role"],
                    "roleID": role_id,
                    "roleName": role_name,
                    "description": description,
                    "siteCode": site_code,
                },
            )

        return True
    except Exception as e:
        logger.warning(f"Failed to collect security roles via WMI: {e}")
        return False


def _get_admin_users_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> bool:
    """
    Get admin users via WMI.

    Mirrors AdminService _get_admin_users. Creates SCCM_AdminUser nodes,
    SCCM_IsAssigned edges (to roles and collections), and SCCM_IsMappedTo
    edges (from AD principal to admin user).
    """
    try:
        logger.info("Getting admin users via WMI...")

        items = client.query(
            "SELECT AdminID, LogonName, DisplayName, AdminSid, RoleNames, "
            "CollectionNames, AccountType, SourceSite, CategoryNames "
            "FROM SMS_Admin"
        )
        if not items:
            logger.info("No admin users found via WMI")
            return True

        logger.info(f"Found {len(items)} admin users via WMI")

        for item in items:
            logon_name = item.get("LogonName", "")
            display_name = item.get("DisplayName", "")
            admin_sid = item.get("AdminSid", "")
            role_names = item.get("RoleNames", [])
            collection_names = item.get("CollectionNames", [])
            is_group = item.get("AccountType", 0) == 1
            source_site = item.get("SourceSite") or site_code

            if isinstance(role_names, str):
                role_names = [r.strip() for r in role_names.split(",")]
            if isinstance(collection_names, str):
                collection_names = [c.strip() for c in collection_names.split(",")]
            if not isinstance(role_names, list):
                role_names = []
            if not isinstance(collection_names, list):
                collection_names = []

            logon_lower = logon_name.lower().strip()
            node_id = f"{logon_lower}@{site_code}"

            is_all_instances = False
            scope_names = item.get("CategoryNames", [])
            if isinstance(scope_names, list):
                is_all_instances = "All Systems" in scope_names or "All" in scope_names

            graph.upsert_node(
                node_id,
                ["SCCM_AdminUser"],
                properties={
                    "name": f"{logon_name}@{site_code}",
                    "collectionSource": ["WMI-SMS_Admin"],
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

            # Resolve CollectionNames -> collection node IDs
            for coll_name in (collection_names or []):
                coll_name = coll_name.strip()
                if not coll_name:
                    continue
                matched_coll = None
                for coll_node in graph.find_nodes_by_kind("SCCM_Collection"):
                    coll_id = coll_node.get("id", "")
                    coll_props = coll_node.get("properties", {})
                    coll_node_name = coll_props.get("name", "")
                    coll_name_base = coll_node_name.split("@")[0] if "@" in coll_node_name else coll_node_name
                    if coll_name_base == coll_name and coll_id.endswith(f"@{site_code}"):
                        matched_coll = coll_node
                        break
                if matched_coll:
                    coll_id = matched_coll.get("id")
                    graph.upsert_edge(
                        node_id, coll_id, "SCCM_IsAssigned",
                        properties={"collectionSource": ["WMI-SMS_Admin"]},
                    )
                    graph.upsert_node(
                        node_id, ["SCCM_AdminUser"],
                        properties={"collectionIDs": [coll_id]},
                    )
                    logger.debug(f"Admin {node_id} assigned to collection {coll_id}")
                else:
                    logger.warning(f"No collection node found for '{coll_name}' in site {site_code}")

            # Resolve RoleNames -> security role node IDs
            for role_name in (role_names or []):
                role_name = role_name.strip()
                if not role_name:
                    continue
                matched_role = None
                for role_node in graph.find_nodes_by_kind("SCCM_SecurityRole"):
                    role_id = role_node.get("id", "")
                    role_props = role_node.get("properties", {})
                    role_node_name = role_props.get("roleName", "")
                    if role_node_name == role_name and role_id.endswith(f"@{site_code}"):
                        matched_role = role_node
                        break
                if matched_role:
                    role_id = matched_role.get("id")
                    graph.upsert_edge(
                        node_id, role_id, "SCCM_IsAssigned",
                        properties={"collectionSource": ["WMI-SMS_Admin"]},
                    )
                    graph.upsert_node(
                        node_id, ["SCCM_AdminUser"],
                        properties={
                            "securityRoles": [role_id],
                            "memberOf": [f"{role_id} ({role_name})"],
                        },
                    )
                    graph.upsert_node(
                        role_id, ["SCCM_SecurityRole"],
                        properties={"members": [node_id]},
                    )
                    logger.debug(f"Admin {node_id} assigned to role {role_id} ({role_name})")
                else:
                    logger.warning(f"No role node found for '{role_name}' in site {site_code}")

            # Create SCCM_IsMappedTo: AD principal -> SCCM_AdminUser
            if admin_sid:
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
                        graph.upsert_edge(
                            resolved_sid, node_id, "SCCM_IsMappedTo",
                            properties={
                                "collectionSource": ["WMI-SMS_Admin"],
                                "SCCMInfra": True,
                            },
                        )
                else:
                    logger.warning(f"No domain object found for admin user {node_id}")
            else:
                logger.warning(f"No domain SID found for admin user {node_id}")

        return True
    except Exception as e:
        logger.warning(f"Failed to collect admin users via WMI: {e}")
        return False


def _get_site_system_roles_via_wmi(
    client: WMIClient,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target_manager: TargetManager,
    site_code: str,
    domain: str,
) -> bool:
    """
    Get site system roles via WMI (SMS_SCI_SysResUse).

    Mirrors AdminService _get_site_system_roles. Creates/updates Computer nodes
    with SCCMSiteSystemRoles, adds targets, handles SQL service accounts.
    """
    try:
        logger.info("Getting site system roles via WMI...")

        items = client.query(
            "SELECT ServerName, NetworkOSPath, RoleName, SiteCode, Props "
            "FROM SMS_SCI_SysResUse"
        )
        if not items:
            logger.info("No site system roles found via WMI")
            return True

        logger.info(f"Found {len(items)} site system role entries via WMI")

        # Track roles per server
        server_roles: dict[str, list[str]] = {}
        server_sites: dict[str, str] = {}
        server_props_map: dict[str, dict[str, Any]] = {}

        for item in items:
            server_name = item.get("ServerName", "") or (
                item.get("NetworkOSPath", "").replace("\\", "")
            )
            role_name = item.get("RoleName", "")
            role_site = item.get("SiteCode") or site_code

            if not server_name or not role_name:
                continue

            server_key = server_name.lower()

            if server_key not in server_roles:
                server_roles[server_key] = []
            server_roles[server_key].append(f"{role_name}@{role_site}")
            server_sites[server_key] = role_site

            # Extract embedded properties (Props array)
            # WMI returns Props as array of embedded SMS_EmbeddedProperty objects.
            # impacket may return these as CIM objects with getProperties() or as dicts.
            props_list = item.get("Props")
            if props_list is not None:
                embedded_props = _extract_embedded_props(props_list)
                for prop_name, prop_values in embedded_props.items():
                    prop_value = prop_values.get("Value1", "") or prop_values.get("Value2", "")
                    if prop_name and prop_value:
                        if server_key not in server_props_map:
                            server_props_map[server_key] = {}
                        server_props_map[server_key][prop_name] = prop_value
                    if prop_name == "SQL Server Service Logon Account":
                        val2 = prop_values.get("Value2", "")
                        if val2:
                            if server_key not in server_props_map:
                                server_props_map[server_key] = {}
                            server_props_map[server_key]["_SQLServiceAccount"] = val2

        # Create/update computer nodes for each server
        for server_key, roles in server_roles.items():
            server_name = server_key
            role_site = server_sites.get(server_key, site_code)

            logger.info(f"Server: {server_name} -> Roles: {', '.join(roles)}")

            target_manager.add_device(server_name, source="WMI-SMS_SCI_SysResUse")

            ad_obj = ad_resolver.get_ad_computer(server_name)
            if ad_obj:
                sid = ad_obj.get("SID") or ad_obj.get("objectSid")
                if isinstance(sid, bytes):
                    sid = ad_resolver._sid_bytes_to_string(sid)

                if sid:
                    node_props: dict[str, Any] = {
                        "collectionSource": ["WMI-SMS_SCI_SysResUse"],
                        "SCCMInfra": True,
                        "SCCMSiteSystemRoles": roles,
                        "dNSHostName": ad_obj.get("dNSHostName", server_name),
                        "sAMAccountName": ad_obj.get("sAMAccountName", ""),
                        "name": ad_obj.get("sAMAccountName", ""),
                    }

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

                    # Handle SQL service account
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
                                    sa_sid, sa_kinds,
                                    properties={
                                        "collectionSource": ["WMI-SMS_SCI_SysResUse"],
                                        "SCCMInfra": True,
                                    },
                                    ad_object=sa_obj,
                                )
                                graph.upsert_node(
                                    role_site, ["SCCM_Site"],
                                    properties={
                                        "collectionSource": ["WMI-SMS_SCI_SysResUse"],
                                        "SQLServiceAccountDomainSID": sa_sid,
                                        "SQLServiceAccountName": sa_obj.get(
                                            "sAMAccountName", service_account_name
                                        ),
                                    },
                                )
                                mssql_server_id = f"{sid}:1433"
                                graph.upsert_node(
                                    mssql_server_id, ["MSSQL_Server"],
                                    properties={
                                        "collectionSource": ["WMI-SMS_SCI_SysResUse"],
                                        "SCCMInfra": True,
                                        "SQLServiceAccountDomainSID": sa_sid,
                                        "SQLServiceAccountName": sa_obj.get(
                                            "sAMAccountName", service_account_name
                                        ),
                                    },
                                )
                                if sa_sid != sid:
                                    graph.upsert_edge(
                                        sid, sa_sid, "HasSession",
                                        properties={"collectionSource": ["WMI-SMS_SCI_SysResUse"]},
                                    )
                                    graph.upsert_edge(
                                        sa_sid, mssql_server_id, "MSSQL_ServiceAccountFor",
                                        properties={"collectionSource": ["WMI-SMS_SCI_SysResUse"]},
                                    )
                                    graph.upsert_edge(
                                        sa_sid, mssql_server_id, "MSSQL_GetAdminTGS",
                                        properties={"collectionSource": ["WMI-SMS_SCI_SysResUse"]},
                                    )

                    # Check for SQL Server role and create MSSQL_Server node
                    has_sql_role = any("SQL Server" in r for r in roles)
                    if has_sql_role:
                        mssql_sid = f"{sid}:1433"
                        graph.upsert_node(
                            mssql_sid, ["MSSQL_Server"],
                            properties={
                                "collectionSource": ["WMI-SMS_SCI_SysResUse"],
                                "SCCMInfra": True,
                            },
                        )
                        sql_db = extra_props.get("DatabaseName", "")
                        if sql_db:
                            node_props["SQLDatabaseName"] = sql_db
                            graph.upsert_node(
                                role_site, ["SCCM_Site"],
                                properties={
                                    "SQLServerName": extra_props.get("SQLServerName", server_name),
                                    "SQLDatabaseName": sql_db,
                                },
                            )

        return True
    except Exception as e:
        logger.warning(f"Failed to collect site system roles via WMI: {e}")
        return False
