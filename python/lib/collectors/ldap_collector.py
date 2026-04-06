"""
LDAP collection for ConfigManBearPig.

Translated from PowerShell Invoke-LDAPCollection (lines 2963-3608).

Discovers SCCM infrastructure by querying:
- System Management container for mSSMSSite and mSSMSManagementPoint objects
- Site type detection (CAS vs Primary)
- CmRcService SPNs (client detection)
- Network boot server detection
- Naming pattern analysis
- GenericAll ACLs on System Management container
"""

import logging
import re
import struct
from typing import Any, Optional

from ldap3 import SUBTREE

from lib.ad_resolver import ADResolver
from lib.graph import GraphStore
from lib.targets import TargetManager

logger = logging.getLogger("ConfigManBearPig")

# mSSMSSite object class GUID
MSSMSITE_CLASS = "mSSMSSite"
MSSMSMP_CLASS = "mSSMSManagementPoint"


def invoke_ldap_collection(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    disable_possible_edges: bool = False,
    target_site_codes: Optional[list[str]] = None,
) -> None:
    """
    Run LDAP collection phase.

    Translated from PowerShell Invoke-LDAPCollection (lines 2963-3608).

    Searches the System Management container and AD for SCCM-related objects.

    Args:
        ad_resolver: LDAP connection helper
        graph: Graph store for nodes/edges
        target_manager: Target management
        domain: Domain name
        disable_possible_edges: Flag to disable possible edges
        target_site_codes: Optional list of site codes to filter
    """
    logger.info("Starting LDAP collection...")

    base_dn = ad_resolver.base_dn
    system_mgmt_dn = f"CN=System Management,CN=System,{base_dn}"

    # 1. Search for mSSMSSite objects (SCCM site definitions)
    _collect_sites(ad_resolver, graph, target_manager, system_mgmt_dn, domain)

    # 2. Search for mSSMSManagementPoint objects
    _collect_management_points(ad_resolver, graph, target_manager, system_mgmt_dn, domain)

    # 3. Detect site types (CAS vs Primary based on mSSMSSite attributes)
    _detect_site_types(graph)

    # 4. Search for CmRcService SPNs (SCCM client detection)
    _collect_cmrc_service_spns(ad_resolver, graph, target_manager, domain, disable_possible_edges)

    # 5. Search for network boot servers (PXE-enabled DPs)
    _collect_network_boot_servers(ad_resolver, graph, target_manager, domain)

    # 6. Analyze naming patterns for site system detection
    _analyze_naming_patterns(ad_resolver, graph, target_manager, system_mgmt_dn, domain)

    # 7. System Management container ACLs
    _collect_system_mgmt_acls(ad_resolver, graph, target_manager, system_mgmt_dn, domain)

    logger.info("LDAP collection completed")


def _collect_sites(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    system_mgmt_dn: str,
    domain: str,
) -> None:
    """
    Collect mSSMSSite objects from System Management container.

    Translated from PowerShell lines 2972-3055.
    """
    logger.info("Searching for mSSMSSite objects in System Management container...")

    try:
        results = ad_resolver.get_ad_object(
            search_filter=f"(objectClass={MSSMSITE_CLASS})",
            search_base=system_mgmt_dn,
            attributes=[
                "mSSMSHealthState", "mSSMSSiteCode", "mSSMSSourceForest",
                "objectClass", "distinguishedName",
            ],
        )
    except Exception as e:
        logger.warning(f"Failed to search System Management container: {e}")
        logger.info("The System Management container may not exist or access is denied")
        return

    if not results:
        logger.warning("No mSSMSSite objects found in System Management container")
        return

    logger.info(f"Found {len(results)} mSSMSSite objects")

    for site_obj in results:
        site_code = site_obj.get("mSSMSSiteCode")
        if not site_code:
            continue

        site_code = str(site_code).strip()
        logger.info(f"Found SCCM site: {site_code}")

        # Parse health state for SiteGUID
        site_guid = None
        health_state = site_obj.get("mSSMSHealthState")
        if health_state:
            health_str = str(health_state)
            guid_match = re.search(rf"{re.escape(site_code)}\.(\{{[^}}]+\}})", health_str)
            if guid_match:
                site_guid = guid_match.group(1)

        # Create/update SCCM_Site node
        props: dict[str, Any] = {
            "collectionSource": ["LDAP-mSSMSSite"],
            "displayName": None,
            "distinguishedName": site_obj.get("distinguishedName"),
            "parentSiteCode": "Undetermined",
            "SCCMInfra": True,
            "siteCode": site_code,
            "siteGUID": site_guid,
            "siteServerDomainSID": None,
            "siteServerName": None,
            "siteType": None,
            "sourceForest": site_obj.get("mSSMSSourceForest"),
            "SQLDatabaseName": None,
            "SQLServerDomainSID": None,
            "SQLServerName": None,
            "SQLServiceAccountDomainSID": None,
            "SQLServiceAccountName": None,
        }

        graph.upsert_node(site_code, ["SCCM_Site"], properties=props)


def _collect_management_points(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    system_mgmt_dn: str,
    domain: str,
) -> None:
    """
    Collect mSSMSManagementPoint objects.

    Translated from PowerShell lines 3045-3213.
    Parses mSSMSCapabilities XML to determine site type (Primary/CAS/Secondary)
    and extract parent site codes, fallback status points, etc.
    """
    logger.info("Searching for mSSMSManagementPoint objects...")

    try:
        results = ad_resolver.get_ad_object(
            search_filter=f"(objectClass={MSSMSMP_CLASS})",
            search_base=system_mgmt_dn,
            attributes=[
                "mSSMSMPName", "mSSMSSiteCode", "mSSMSCapabilities",
            ],
        )
    except Exception as e:
        logger.warning(f"Failed to search for management points: {e}")
        return

    if not results:
        logger.info("No mSSMSManagementPoint objects found")
        return

    logger.info(f"Found {len(results)} mSSMSManagementPoint objects")

    for mp_obj in results:
        mp_hostname = mp_obj.get("mSSMSMPName")
        mp_site_code = mp_obj.get("mSSMSSiteCode", "")

        if mp_hostname:
            # Add to collection targets for subsequent phases
            mp_target = target_manager.add_device(mp_hostname, source="LDAP-mSSMSManagementPoint")
            if mp_target:
                logger.info(f"Found management point: {mp_target.hostname} (site: {mp_site_code})")

            # Create or update Computer node
            if mp_target and mp_target.ad_object:
                sid = mp_target.sid
                if sid:
                    graph.upsert_node(
                        sid,
                        ["Computer", "Base"],
                        properties={
                            "collectionSource": ["LDAP-mSSMSManagementPoint"],
                            "name": mp_target.ad_object.get("sAMAccountName", ""),
                            "SCCMSiteSystemRoles": [f"SMS Management Point@{mp_site_code}"],
                        },
                        ad_object=mp_target.ad_object,
                    )

        # Parse capabilities XML to determine site type and relationships
        source_forest = None
        command_line_site_code = None
        root_site_code = None
        capabilities_str = mp_obj.get("mSSMSCapabilities")

        if capabilities_str:
            try:
                import xml.etree.ElementTree as ET
                # Clean XML entities
                clean_xml = str(capabilities_str)
                logger.debug(f"Raw capabilities XML for {mp_hostname} (first 500 chars): {clean_xml[:500]}")
                # Fix unescaped ampersands
                clean_xml = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", clean_xml)

                root = ET.fromstring(clean_xml)

                # Extract CommandLine site code
                # PowerShell: $mSSMSCapabilities.ClientOperationalSettings.CCM.CommandLine
                # CommandLine may be an attribute of CCM, a child element, or text content
                ccm_elem = root.find(".//CCM")
                if ccm_elem is not None:
                    # Try attribute first
                    command_line = ccm_elem.get("CommandLine", "")
                    if not command_line:
                        # Try child element named CommandLine
                        cl_elem = ccm_elem.find("CommandLine")
                        if cl_elem is not None:
                            command_line = cl_elem.text or ""
                        else:
                            command_line = ccm_elem.text or ""
                    logger.debug(f"CCM CommandLine for {mp_site_code}: {command_line!r}")
                    cmd_match = re.search(r"SMSSITECODE=([A-Z0-9]{3})", command_line, re.IGNORECASE)
                    if cmd_match:
                        command_line_site_code = cmd_match.group(1)
                else:
                    logger.debug(f"No CCM element found in capabilities XML for {mp_hostname}")

                # Extract root site code
                root_elem = root.find("RootSiteCode")
                if root_elem is not None:
                    root_site_code = root_elem.text
                else:
                    # Try as child of ClientOperationalSettings (which is root)
                    root_elem = root.find(".//RootSiteCode")
                    if root_elem is not None:
                        root_site_code = root_elem.text

                # Extract source forest
                forest_elem = root.find(".//Forest")
                if forest_elem is not None:
                    source_forest = forest_elem.get("Value") or forest_elem.text

            except Exception as e:
                logger.debug(f"Failed to parse capabilities for MP {mp_hostname}: {e}")

            logger.debug(f"Parsed capabilities for {mp_site_code}: "
                         f"commandLineSiteCode={command_line_site_code!r}, "
                         f"rootSiteCode={root_site_code!r}, "
                         f"mpSiteCode={mp_site_code!r}, "
                         f"sourceForest={source_forest!r}")

            # Determine site type based on design specification (PowerShell lines 3121-3143)
            site_type = "Secondary Site"
            parent_site_code = "Undetermined"

            if command_line_site_code == mp_site_code:
                # Primary Site: CommandLine.SMSSITECODE matches this site code
                site_type = "Primary Site"
                if root_site_code and root_site_code != mp_site_code:
                    parent_site_code = root_site_code
                else:
                    parent_site_code = "None"
            elif root_site_code == mp_site_code and command_line_site_code != mp_site_code:
                # CAS: RootSiteCode matches but CommandLine doesn't
                site_type = "Central Administration Site"
                parent_site_code = "None"

            logger.debug(f"Site type for {mp_site_code}: {site_type}")

            # Update existing SCCM_Site node with MP-derived information
            graph.upsert_node(
                mp_site_code,
                ["SCCM_Site"],
                properties={
                    "collectionSource": ["LDAP-mSSMSManagementPoint"],
                    "parentSiteCode": parent_site_code,
                    "SCCMInfra": True,
                    "siteCode": mp_site_code,
                    "siteType": site_type,
                    **({"sourceForest": source_forest} if source_forest else {}),
                },
            )

            # Create parent CAS site node if we found a parent
            if parent_site_code and parent_site_code not in ("None", "Undetermined"):
                graph.upsert_node(
                    parent_site_code,
                    ["SCCM_Site"],
                    properties={
                        "collectionSource": ["LDAP-mSSMSManagementPoint"],
                        "parentSiteCode": "None",
                        "SCCMInfra": True,
                        "siteCode": parent_site_code,
                        "siteType": "Central Administration Site",
                        **({"sourceForest": source_forest} if source_forest else {}),
                    },
                )
                logger.info(f"Found central administration site: {parent_site_code}")

            # Parse for fallback status points
            if capabilities_str:
                try:
                    clean_xml = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", str(capabilities_str))
                    root = ET.fromstring(clean_xml)
                    fsp_nodes = root.findall(".//FSP/FSPServer")
                    for fsp in fsp_nodes:
                        fsp_hostname = fsp.text
                        if fsp_hostname:
                            fsp_target = target_manager.add_device(
                                fsp_hostname, source="LDAP-mSSMSManagementPoint"
                            )
                            if fsp_target:
                                logger.info(f"Found fallback status point: {fsp_target.hostname}")
                            if fsp_target and fsp_target.ad_object:
                                fsp_sid = fsp_target.sid
                                if fsp_sid:
                                    graph.upsert_node(
                                        fsp_sid,
                                        ["Computer", "Base"],
                                        properties={
                                            "collectionSource": ["LDAP-mSSMSManagementPoint"],
                                            "name": fsp_target.ad_object.get("sAMAccountName", ""),
                                            "SCCMSiteSystemRoles": [f"SMS Fallback Status Point@{mp_site_code}"],
                                        },
                                        ad_object=fsp_target.ad_object,
                                    )
                except Exception:
                    pass


def _detect_site_types(graph: GraphStore) -> None:
    """
    Detect site types from collected data.

    Site type detection is now primarily handled in _collect_management_points
    via mSSMSCapabilities XML parsing. This function performs supplementary
    detection for any sites not already classified.
    """
    logger.info("Detecting site types...")

    for site in graph.find_nodes_by_kind("SCCM_Site"):
        props = site.get("properties", {})
        # Only process sites that haven't been classified yet
        if props.get("siteType") and props["siteType"] != "Secondary Site":
            continue
        # No additional detection needed - types are set by MP capabilities parsing


def _collect_cmrc_service_spns(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    disable_possible_edges: bool = False,
) -> None:
    """
    Search for computers with CmRcService SPN (indicates SCCM client).

    Translated from PowerShell lines 3167-3240.
    """
    logger.info("Searching for CmRcService SPNs...")

    results = ad_resolver.get_ad_object(
        search_filter="(servicePrincipalName=CmRcService/*)",
        attributes=[
            "objectSid", "sAMAccountName", "dNSHostName", "distinguishedName",
            "servicePrincipalName", "objectClass",
        ],
    )

    if not results:
        logger.info("No computers with CmRcService SPN found")
        return

    logger.info(f"Found {len(results)} computers with CmRcService SPN (SCCM clients)")

    # Get the first primary site code published to AD (PowerShell line 3254)
    root_site = None
    site_nodes = graph.find_nodes_by_kind("SCCM_Site")
    if site_nodes:
        # Prefer primary site
        for sn in site_nodes:
            if sn.get("properties", {}).get("siteType") == "Primary Site":
                root_site = sn.get("id")
                break
        if not root_site and site_nodes:
            root_site = site_nodes[0].get("id")

    for obj in results:
        sid = obj.get("objectSid") or obj.get("SID")
        if isinstance(sid, bytes):
            sid = ad_resolver._sid_bytes_to_string(sid)
        sam = obj.get("sAMAccountName", "")
        fqdn = obj.get("dNSHostName", "")
        hostname = sam.rstrip("$")

        if sid:
            # Create Computer node
            graph.upsert_node(
                sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["LDAP-CmRcService"],
                    "name": obj.get("name", hostname),
                    "SCCMHasClientRemoteControlSPN": True,
                },
                ad_object=obj,
            )

            # If not disabling possible edges and we have a root site,
            # create SCCM_ClientDevice and SCCM_HasClient edge
            if not disable_possible_edges and root_site:
                import uuid
                device_id = str(uuid.uuid4())
                device_name = f"{obj.get('name', hostname)}@{root_site}"

                graph.upsert_node(
                    device_id,
                    ["SCCM_ClientDevice"],
                    properties={
                        "collectionSource": ["LDAP-CmRcService"],
                        "ADDomainSID": sid,
                        "name": device_name,
                        "siteCode": root_site,
                        "SMSID": "Not yet collected",
                    },
                    ad_object=obj,
                )

                # SCCM_HasClient: Site -> ClientDevice
                graph.upsert_edge(root_site, device_id, "SCCM_HasClient", properties={
                    "collectionSource": ["LDAP-CmRcService"],
                })


def _collect_network_boot_servers(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
) -> None:
    """
    Search for WDS/PXE enabled distribution points.

    Translated from PowerShell lines 3291-3378.
    Searches for connectionPoint objects with netbootserver attribute
    and intellimirrorSCP objects, then resolves parent computer objects.
    """
    logger.info("Searching for network boot servers (PXE-enabled DPs)...")

    base_dn = ad_resolver.base_dn
    network_boot_servers = []

    # Search for connectionPoint objects with netbootserver
    try:
        connection_points = ad_resolver.get_ad_object(
            search_filter="(&(objectClass=connectionPoint)(netbootserver=*))",
            attributes=["distinguishedName"],
        )
        for cp in connection_points:
            network_boot_servers.append({
                "distinguishedName": cp.get("distinguishedName", ""),
                "objectClass": "connectionPoint",
            })
    except Exception as e:
        logger.debug(f"connectionPoint search failed: {e}")

    # Search for intellimirrorSCP objects
    try:
        intellimirror = ad_resolver.get_ad_object(
            search_filter="(objectClass=intellimirrorSCP)",
            attributes=["distinguishedName"],
        )
        for im in intellimirror:
            network_boot_servers.append({
                "distinguishedName": im.get("distinguishedName", ""),
                "objectClass": "intellimirrorSCP",
            })
    except Exception as e:
        logger.debug(f"intellimirrorSCP search failed: {e}")

    if not network_boot_servers:
        logger.info("No network boot servers found")
        return

    logger.info(f"Found {len(network_boot_servers)} network boot server objects")

    for server in network_boot_servers:
        dn = server.get("distinguishedName", "")
        obj_class = server.get("objectClass", "")
        if not dn:
            continue

        try:
            # Extract parent DN (the computer object)
            # Remove the first CN= component to get parent
            parts = dn.split(",", 1)
            if len(parts) < 2:
                continue
            parent_dn = parts[1]

            # Resolve the parent object
            parent_obj = ad_resolver.get_ad_object(
                "(objectClass=*)",
                search_base=parent_dn,
                attributes=["dNSHostName", "objectSid", "name", "sAMAccountName"],
            )
            if not parent_obj:
                continue
            parent = parent_obj[0]

            fqdn = parent.get("dNSHostName", "")
            sid = parent.get("objectSid") or parent.get("SID")
            if isinstance(sid, bytes):
                sid = ad_resolver._sid_bytes_to_string(sid)

            if fqdn and sid:
                target = target_manager.add_device(fqdn, source=f"LDAP-{obj_class}")
                if target:
                    logger.info(f"Found network boot server: {fqdn} ({sid})")

                if target and target.ad_object:
                    graph.upsert_node(
                        sid,
                        ["Computer", "Base"],
                        properties={
                            "collectionSource": [f"LDAP-{obj_class}"],
                            "name": target.ad_object.get("sAMAccountName", ""),
                            "networkBootServer": True,
                        },
                        ad_object=target.ad_object,
                    )

        except Exception as e:
            logger.debug(f"Failed to process network boot server {dn}: {e}")


def _analyze_naming_patterns(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    system_mgmt_dn: str,
    domain: str,
) -> None:
    """
    Search for computers with SCCM-related naming patterns.

    Translated from PowerShell lines 3380-3452.
    Searches the entire domain for computers whose names match
    SCCM-related patterns (sccm, mecm, mcm, memcm, configm, cfgm, sms).
    """
    logger.info("Searching for computers with SCCM naming patterns...")

    search_patterns = ["sccm", "mecm", "mcm", "memcm", "configm", "cfgm", "sms"]

    # Build dynamic LDAP filter matching PowerShell behavior
    filter_parts = []
    for pattern in search_patterns:
        filter_parts.append(f"(samaccountname=*{pattern}*)")
        filter_parts.append(f"(description=*{pattern}*)")
        filter_parts.append(f"(name=*{pattern}*)")
        filter_parts.append(f"(cn=*{pattern}*)")
        filter_parts.append(f"(displayname=*{pattern}*)")
        filter_parts.append(f"(serviceprincipalname=*{pattern}*)")
        filter_parts.append(f"(dnshostname=*{pattern}*)")

    ldap_filter = f"(&(objectCategory=computer)(|{''.join(filter_parts)}))"

    try:
        results = ad_resolver.get_ad_object(
            search_filter=ldap_filter,
            attributes=[
                "sAMAccountName", "description", "name", "displayName",
                "servicePrincipalName", "dNSHostName", "objectClass", "objectSid",
            ],
        )
    except Exception as e:
        logger.debug(f"SCCM naming pattern search failed: {e}")
        return

    if not results:
        logger.info("No computers with SCCM naming patterns found")
        return

    logger.info(f"Found {len(results)} computers with SCCM naming patterns")

    for match in results:
        sid = match.get("objectSid") or match.get("SID")
        if isinstance(sid, bytes):
            sid = ad_resolver._sid_bytes_to_string(sid)
        hostname = match.get("dNSHostName", "")
        name = match.get("name", "")

        if sid and hostname:
            # Add to collection targets
            target = target_manager.add_device(hostname, source="LDAP-NamePattern", ad_object=match)
            if target:
                logger.info(f"Found system with SCCM naming pattern: {hostname} ({sid})")

            # Create or update Computer node
            graph.upsert_node(
                sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["LDAP-NamePattern"],
                    "name": match.get("sAMAccountName", ""),
                },
                ad_object=match,
            )
        elif not sid or not hostname:
            logger.debug(f"Missing required properties (SID or hostname): {name}")


def _collect_system_mgmt_acls(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    system_mgmt_dn: str,
    domain: str,
) -> None:
    """
    Check ACLs on the System Management container.

    Translated from PowerShell lines 3462-3608.
    Looks for GenericAll permissions which indicate site servers.
    """
    logger.info("Checking System Management container ACLs...")

    # Query the container's nTSecurityDescriptor
    # Need to use SD_FLAGS control to request DACL (0x04)
    # SD_FLAGS OID: 1.2.840.113556.1.4.801
    # BER value: SEQUENCE { INTEGER 4 } = 30 03 02 01 04
    try:
        sd_control = ("1.2.840.113556.1.4.801", True, bytes([0x30, 0x03, 0x02, 0x01, 0x04]))
        results = ad_resolver._search(
            search_filter="(objectClass=container)",
            search_base=system_mgmt_dn,
            attributes=["nTSecurityDescriptor"],
            controls=[sd_control],
        )
    except Exception as e:
        logger.debug(f"Failed to read System Management container ACLs: {e}")
        return

    if not results:
        logger.debug("Could not read System Management container ACLs")
        return

    sd_bytes = results[0].get("nTSecurityDescriptor")
    if not sd_bytes or not isinstance(sd_bytes, bytes):
        logger.debug("nTSecurityDescriptor not returned as bytes")
        return

    # Parse security descriptor and extract GenericAll ACEs
    generic_all_sids = _parse_sd_generic_all(sd_bytes)
    if not generic_all_sids:
        logger.info("No GenericAll permissions found on System Management container")
        return

    for sid_str in generic_all_sids:
        # Skip well-known SIDs like NT AUTHORITY\SYSTEM (S-1-5-18), etc.
        if sid_str.startswith("S-1-5-18") or sid_str.startswith("S-1-5-32-"):
            continue
        # Skip Domain Admins and Enterprise Admins (inherent)
        if sid_str.endswith("-512") or sid_str.endswith("-519"):
            continue

        logger.info(f"Found principal with GenericAll on System Management container: {sid_str}")

        # Resolve SID to AD object
        ad_obj = ad_resolver.resolve_principal(sid_str)
        if not ad_obj:
            logger.warning(f"Could not resolve GenericAll principal '{sid_str}' to domain object")
            continue

        obj_sid = ad_obj.get("SID") or ad_obj.get("objectSid") or sid_str
        if isinstance(obj_sid, bytes):
            obj_sid = ad_resolver._sid_bytes_to_string(obj_sid)

        sam = ad_obj.get("sAMAccountName", "")
        obj_class = ad_obj.get("objectClass", [])
        if isinstance(obj_class, str):
            obj_class = [obj_class]

        # Determine object type
        if "computer" in [c.lower() for c in obj_class]:
            graph.upsert_node(obj_sid, ["Computer", "Base"], properties={
                "collectionSource": ["LDAP-GenericAllSystemManagement"],
                "name": sam,
            }, ad_object=ad_obj)

            # Add as collection target
            dns_hostname = ad_obj.get("dNSHostName", sam.rstrip("$"))
            if dns_hostname:
                target_manager.add_device(
                    device_name=dns_hostname,
                    source="LDAP-GenericAll",
                    ad_object=ad_obj,
                )
        elif "group" in [c.lower() for c in obj_class]:
            graph.upsert_node(obj_sid, ["Group", "Base"], properties={
                "collectionSource": ["LDAP-GenericAllSystemManagement"],
                "name": sam,
            }, ad_object=ad_obj)
        elif "user" in [c.lower() for c in obj_class]:
            graph.upsert_node(obj_sid, ["User", "Base"], properties={
                "collectionSource": ["LDAP-GenericAllSystemManagement"],
                "name": sam,
            }, ad_object=ad_obj)
        else:
            graph.upsert_node(obj_sid, ["Base"], properties={
                "collectionSource": ["LDAP-GenericAllSystemManagement"],
                "name": sam,
            }, ad_object=ad_obj)


def _parse_sd_generic_all(sd_bytes: bytes) -> list[str]:
    """
    Parse a Windows SECURITY_DESCRIPTOR binary blob and return SIDs with GenericAll.

    In Active Directory, GenericAll maps to 0x000F01FF (Full Control) rather than
    the raw Windows GENERIC_ALL bit (0x10000000). The .NET ActiveDirectoryRights
    enum GenericAll = 0x000F01FF. We check for both, plus any mask that includes
    all the AD-specific rights.

    Structure reference:
    - SECURITY_DESCRIPTOR header (20 bytes for self-relative)
    - DACL at OffsetDacl
    - ACL header (8 bytes): revision, padding, size, ace_count, padding
    - Each ACE: AceType(1), AceFlags(1), AceSize(2), ACCESS_MASK(4), SID(variable)
    - ACCESS_ALLOWED_OBJECT_ACE (type 0x05) has extra: Flags(4), optional ObjectType(16),
      optional InheritedObjectType(16) before the SID
    """
    if len(sd_bytes) < 20:
        return []

    # Parse SECURITY_DESCRIPTOR header
    revision = sd_bytes[0]
    control = struct.unpack_from("<H", sd_bytes, 2)[0]
    offset_dacl = struct.unpack_from("<I", sd_bytes, 16)[0]

    if offset_dacl == 0 or offset_dacl >= len(sd_bytes):
        return []

    # Parse ACL header at offset_dacl
    acl_size = struct.unpack_from("<H", sd_bytes, offset_dacl + 2)[0]
    ace_count = struct.unpack_from("<H", sd_bytes, offset_dacl + 4)[0]

    results = []
    pos = offset_dacl + 8  # Skip ACL header

    # AD GenericAll = 0x000F01FF (DS Full Control)
    # Also check raw GENERIC_ALL = 0x10000000 in case it wasn't mapped
    AD_GENERIC_ALL = 0x000F01FF
    GENERIC_ALL = 0x10000000
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05

    for _ in range(ace_count):
        if pos + 4 > len(sd_bytes):
            break

        ace_type = sd_bytes[pos]
        ace_flags = sd_bytes[pos + 1]
        ace_size = struct.unpack_from("<H", sd_bytes, pos + 2)[0]

        if ace_size < 4 or pos + ace_size > len(sd_bytes):
            break

        if pos + 8 > len(sd_bytes):
            pos += ace_size
            continue

        access_mask = struct.unpack_from("<I", sd_bytes, pos + 4)[0]
        is_generic_all = (access_mask & GENERIC_ALL) or (access_mask & AD_GENERIC_ALL) == AD_GENERIC_ALL

        if is_generic_all:
            sid_data = None

            if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                # ACCESS_ALLOWED_ACE: header(4) + mask(4) + SID
                sid_data = sd_bytes[pos + 8:pos + ace_size]

            elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                # ACCESS_ALLOWED_OBJECT_ACE: header(4) + mask(4) + flags(4) +
                #   [ObjectType(16)] + [InheritedObjectType(16)] + SID
                if pos + 12 <= len(sd_bytes):
                    obj_flags = struct.unpack_from("<I", sd_bytes, pos + 8)[0]
                    sid_start = pos + 12
                    if obj_flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                        sid_start += 16
                    if obj_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                        sid_start += 16
                    sid_data = sd_bytes[sid_start:pos + ace_size]

            if sid_data:
                sid_str = _bytes_to_sid_string(sid_data)
                if sid_str:
                    results.append(sid_str)

        pos += ace_size

    return results


def _bytes_to_sid_string(sid_bytes: bytes) -> Optional[str]:
    """Convert raw SID bytes to string form S-1-..."""
    if len(sid_bytes) < 8:
        return None

    revision = sid_bytes[0]
    sub_authority_count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], byteorder="big")

    if len(sid_bytes) < 8 + sub_authority_count * 4:
        return None

    subs = []
    for i in range(sub_authority_count):
        offset = 8 + i * 4
        subs.append(struct.unpack_from("<I", sid_bytes, offset)[0])

    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)
