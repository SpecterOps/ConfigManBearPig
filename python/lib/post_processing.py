"""
Post-processing logic for ConfigManBearPig.

Translated from PowerShell Invoke-PostProcessing (lines 1577-1984),
Invoke-ProcessRoleAssignments (lines 1986-2101),
Add-SameHostAsEdges (lines 2261-2357),
Add-HostNodeAndEdges (lines 2359-2393),
hierarchy detection functions (lines 2395-2807),
Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer (lines 6187-6290),
Process-CoerceAndRelay* (lines 6572-6781).
"""

import logging
import re
from collections import deque
from typing import Any, Optional

from lib.graph import GraphStore

logger = logging.getLogger("ConfigManBearPig")


# Role ID to edge kind mapping (from PowerShell lines 1750-1797)
# Maps security role IDs that produce edges to client devices
ROLE_EDGE_MAP = {
    "SMS0001R": "SCCM_FullAdministrator",              # Full Administrator
    "SMS0006R": "SCCM_ComplianceSettingsManager",      # Compliance Settings Manager
    "SMS0008R": "SCCM_ApplicationAuthor",              # Application Author
    "SMS0009R": "SCCM_ApplicationAdministrator",       # Application Administrator
    "SMS000AR": "SCCM_OSDManager",                     # Operating System Deployment Manager
    "SMS000ER": "SCCM_OperationsAdministrator",        # Operations Administrator
    "SMS000FR": "SCCM_SecurityAdministrator",          # Security Administrator
}

# Roles explicitly excluded from edge creation (PowerShell lines 1811-1818)
ROLE_SKIP_SET = {
    "SMS0002R",  # Read-Only Analyst
    "SMS0003R",  # Remote Tools Operator
    "SMS0004R",  # Asset Manager
    "SMS0007R",  # Application Deployment Manager
    "SMS000BR",  # Infrastructure Administrator
    "SMS000CR",  # Software Update Manager
    "SMS000GR",  # Endpoint Protection Manager
    "SMS000HR",  # Company Resource Access Manager
}


def get_hierarchy_root(graph: GraphStore) -> Optional[str]:
    """
    Find the hierarchy root site code by looking for CAS type or site with no parent.

    Translated from PowerShell Get-HierarchyRoot (lines 2655-2700).
    """
    site_nodes = graph.find_nodes_by_kind("SCCM_Site")
    if not site_nodes:
        return None

    # Look for CAS (Central Administration Site)
    for site in site_nodes:
        props = site.get("properties", {})
        site_type = props.get("siteType")
        if site_type and str(site_type) == "4":  # CAS type
            return site.get("id")
        if props.get("isCAS"):
            return site.get("id")

    # Look for site with reportToSite as itself or empty
    for site in site_nodes:
        props = site.get("properties", {})
        report_to = props.get("reportToSite", "")
        site_code = site.get("id")
        if not report_to or report_to == site_code:
            return site_code

    # Fallback: first site
    return site_nodes[0].get("id") if site_nodes else None


def get_sites_in_hierarchy(
    graph: GraphStore,
    root_site_code: str,
    exclude_secondary: bool = False,
) -> list[str]:
    """
    BFS traversal from root to find all sites in the hierarchy.

    Translated from PowerShell Get-SitesInHierarchy (lines 2511-2597).

    Uses both parentSiteCode property AND SCCM_AdminsReplicatedTo edges
    for traversal (matching PowerShell which uses edges).
    """
    visited: set[str] = set()
    queue: deque[str] = deque([root_site_code])
    result: list[str] = []

    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        node = graph.get_node(current)
        if not node:
            continue

        if exclude_secondary:
            props = node.get("properties", {})
            st = props.get("siteType")
            if str(st) == "1":
                continue

        result.append(current)

        # Find connected sites via SCCM_AdminsReplicatedTo edges
        for edge in graph.find_edges_by_kind("SCCM_AdminsReplicatedTo"):
            start_id = edge.get("start", {}).get("value", "")
            end_id = edge.get("end", {}).get("value", "")
            if start_id == current and end_id not in visited:
                queue.append(end_id)
            elif end_id == current and start_id not in visited:
                queue.append(start_id)

        # Also find child sites by parentSiteCode
        for site in graph.find_nodes_by_kind("SCCM_Site"):
            child_code = site.get("id")
            if child_code and child_code not in visited:
                props = site.get("properties", {})
                if props.get("reportToSite") == current or props.get("parentSiteCode") == current:
                    queue.append(child_code)

    return result


def get_all_hierarchies(graph: GraphStore) -> dict[str, list[str]]:
    """
    Find all hierarchies and their member sites.

    Translated from PowerShell Get-AllHierarchies (lines 2703-2740).
    """
    site_nodes = graph.find_nodes_by_kind("SCCM_Site")
    all_sites = {s.get("id") for s in site_nodes if s.get("id")}
    assigned: set[str] = set()
    hierarchies: dict[str, list[str]] = {}

    # Try each unassigned site as a potential root
    for site_code in sorted(all_sites):
        if site_code in assigned:
            continue
        members = get_sites_in_hierarchy(graph, site_code)
        if members:
            hierarchies[site_code] = members
            assigned.update(members)

    return hierarchies


def add_root_site_codes(graph: GraphStore) -> None:
    """
    Propagate root site code to all sites in each hierarchy.

    Translated from PowerShell Add-RootSiteCodes (lines 2742-2775).
    """
    hierarchies = get_all_hierarchies(graph)

    for root_code, members in hierarchies.items():
        logger.info(f"Hierarchy root: {root_code}, members: {', '.join(members)}")
        for site_code in members:
            node = graph.get_node(site_code)
            if node:
                node.setdefault("properties", {})["rootSiteCode"] = root_code


def invoke_post_processing(
    graph: GraphStore,
    disable_possible_edges: bool = False,
    domain: str = "",
) -> None:
    """
    Run all post-processing steps on the collected graph.

    Translated from PowerShell Invoke-PostProcessing (lines 1577-1984).

    Steps:
    1. Detect hierarchy structure (root, child sites)
    2. Add SCCM_AdminsReplicatedTo edges between primary sites
    3. Update global object identifiers (rename IDs to use root site code)
    4. Add SCCM_Contains edges (all sites in hierarchy -> global objects)
    5. Process role assignments (SCCM_FullAdministrator, etc.) + SCCM_AllPermissions
    6. Add SameHostAs edges (SCCM_ClientDevice <-> Computer)
    7. Process Computer nodes: LocalAdminRequired + MSSQL sysadmin edges + SCCM_AssignAllPermissions
    8. Process relay edges: CoerceAndRelay + MSSQL_GetTGS

    Args:
        graph: Graph store with collected data
        disable_possible_edges: Skip edges that require unconfirmed assumptions
        domain: FQDN domain name (fallback for Authenticated Users group creation)
    """
    logger.info("Starting post-processing...")

    # Step 1: Detect and record hierarchy
    add_root_site_codes(graph)

    # Step 2: SCCM_AdminsReplicatedTo edges
    _add_admins_replicated_to_edges(graph)

    # Step 3: Update global object identifiers (rename IDs to root site code)
    _update_global_object_identifiers(graph)

    # Step 4: SCCM_Contains edges (all sites in hierarchy -> global objects)
    _add_contains_edges(graph)

    # Step 5: Role assignments + SCCM_AllPermissions
    _process_role_assignments_and_all_permissions(graph)

    # Step 6: SameHostAs edges
    _add_same_host_as_edges(graph)

    # Step 7: Process Computer nodes (LocalAdminRequired, MSSQL sysadmin, SCCM_AssignAllPermissions)
    _process_computer_nodes(graph)

    # Step 8: Relay edges + MSSQL_GetTGS
    _add_coerce_and_relay_edges(graph, disable_possible_edges, domain)
    _add_mssql_get_tgs_edges(graph)

    # Step 9: Secret policy edges (CRED-discovered secrets -> SCCM_ClientDevice)
    if not disable_possible_edges:
        _add_secret_policy_edges(graph)

    logger.info("Post-processing complete")


def _add_admins_replicated_to_edges(graph: GraphStore) -> None:
    """
    Add SCCM_AdminsReplicatedTo edges between primary sites in the same hierarchy.

    Translated from PowerShell lines 1596-1627.

    Rules:
    - CAS <-> Primary: bidirectional
    - Primary -> Secondary: one direction only
    - NOT between secondary sites
    """
    logger.info("Processing SCCM_AdminsReplicatedTo edges...")

    site_nodes = graph.find_nodes_by_kind("SCCM_Site")

    for site_node in site_nodes:
        site_code = site_node.get("id")
        props = site_node.get("properties", {})
        parent_site_code = props.get("parentSiteCode") or props.get("reportToSite")
        site_type = props.get("siteType", "")

        if not parent_site_code or parent_site_code in ("", "None"):
            continue

        # Find parent node
        parent_node = graph.get_node(parent_site_code)
        if not parent_node:
            continue

        parent_type = parent_node.get("properties", {}).get("siteType", "")

        # Central <-> Primary (bidirectional)
        if (str(parent_type) in ("Central Administration Site", "4") and
                str(site_type) in ("Primary Site", "2")):
            graph.upsert_edge(parent_site_code, site_code, "SCCM_AdminsReplicatedTo")
            graph.upsert_edge(site_code, parent_site_code, "SCCM_AdminsReplicatedTo")
            logger.debug(f"Added SCCM_AdminsReplicatedTo: {parent_site_code} <-> {site_code}")
        elif (str(parent_type) in ("Primary Site", "2") and
                str(site_type) in ("Central Administration Site", "4")):
            graph.upsert_edge(parent_site_code, site_code, "SCCM_AdminsReplicatedTo")
            graph.upsert_edge(site_code, parent_site_code, "SCCM_AdminsReplicatedTo")
        # Primary -> Secondary (one direction)
        elif (str(parent_type) in ("Primary Site", "2") and
                str(site_type) in ("Secondary Site", "1")):
            graph.upsert_edge(parent_site_code, site_code, "SCCM_AdminsReplicatedTo")
            logger.debug(f"Added SCCM_AdminsReplicatedTo: {parent_site_code} -> {site_code}")


def _update_global_object_identifiers(graph: GraphStore) -> None:
    """
    Rename global object IDs to use root site code instead of local site code.

    Translated from PowerShell Update-GlobalObjectIdentifiers (lines 2397-2509).

    Renames SCCM_Collection, SCCM_AdminUser, and SCCM_SecurityRole node IDs
    from @SITECODE to @ROOTSITECODE. Also updates internal property references
    (securityRoles, collectionIDs on admin users).
    """
    logger.info("Updating global object identifiers...")

    hierarchies = get_all_hierarchies(graph)
    id_pattern = re.compile(r"^(.+)@([A-Z0-9]{3})$", re.IGNORECASE)

    for root_code, members in hierarchies.items():
        global_kinds = ["SCCM_Collection", "SCCM_AdminUser", "SCCM_SecurityRole"]

        for kind in global_kinds:
            # Get current nodes (snapshot to avoid mutation during iteration)
            nodes = list(graph.find_nodes_by_kind(kind))

            for node in nodes:
                node_id = node.get("id", "")
                match = id_pattern.match(node_id)
                if not match:
                    continue

                object_base = match.group(1)
                current_site_code = match.group(2)

                # Only rename if this site is in this hierarchy and code differs from root
                if current_site_code not in members:
                    continue
                if current_site_code == root_code:
                    continue

                new_id = f"{object_base}@{root_code}"
                logger.debug(f"Renaming {kind}: {node_id} -> {new_id}")

                # Rename the node (handles merging if new_id exists)
                renamed_node = graph.rename_node(node_id, new_id)
                if not renamed_node:
                    continue

                # Update internal property references
                if kind == "SCCM_AdminUser":
                    props = renamed_node.get("properties", {})

                    # Update securityRoles array
                    roles = props.get("securityRoles", [])
                    if isinstance(roles, list):
                        updated_roles = []
                        for r in roles:
                            rm = id_pattern.match(str(r))
                            if rm and rm.group(2) in members and rm.group(2) != root_code:
                                updated_roles.append(f"{rm.group(1)}@{root_code}")
                            else:
                                updated_roles.append(r)
                        props["securityRoles"] = updated_roles

                    # Update collectionIDs array
                    coll_ids = props.get("collectionIDs", [])
                    if isinstance(coll_ids, list):
                        updated_colls = []
                        for c in coll_ids:
                            cm = id_pattern.match(str(c))
                            if cm and cm.group(2) in members and cm.group(2) != root_code:
                                updated_colls.append(f"{cm.group(1)}@{root_code}")
                            else:
                                updated_colls.append(c)
                        props["collectionIDs"] = updated_colls


def _add_contains_edges(graph: GraphStore) -> None:
    """
    Add SCCM_Contains edges from every non-secondary site in a hierarchy
    to every global object (collection, role, admin) that uses the root site code.

    Translated from PowerShell lines 1658-1690.

    PowerShell creates SCCM_Contains from EVERY primary/CAS site to EVERY
    global object in the hierarchy, not just from the object's direct site.
    """
    logger.info("Processing SCCM_Contains edges...")

    hierarchies = get_all_hierarchies(graph)

    for root_code, members in hierarchies.items():
        # Get non-secondary sites
        non_secondary_sites = []
        for sc in members:
            node = graph.get_node(sc)
            if node:
                st = node.get("properties", {}).get("siteType")
                if str(st) not in ("1", "Secondary Site"):
                    non_secondary_sites.append(sc)

        # Find global objects with root site code suffix
        for kind in ["SCCM_Collection", "SCCM_SecurityRole", "SCCM_AdminUser"]:
            for obj in graph.find_nodes_by_kind(kind):
                obj_id = obj.get("id", "")
                if obj_id.endswith(f"@{root_code}"):
                    # Create SCCM_Contains from every non-secondary site to this object
                    for site_code in non_secondary_sites:
                        graph.upsert_edge(site_code, obj_id, "SCCM_Contains")


def _process_role_assignments_and_all_permissions(graph: GraphStore) -> None:
    """
    Process security role assignments and SCCM_AllPermissions edges.

    Translated from PowerShell lines 1707-1840.

    PowerShell iterates: security role -> role.members (admin IDs) ->
    admin.collectionIds -> collection.members (resource IDs) -> SCCM_ClientDevice.

    Python equivalent: iterate security roles with root site code suffix,
    find admin users that have this role, then traverse collection membership
    to find client devices.
    """
    logger.info("Processing role assignments...")

    hierarchies = get_all_hierarchies(graph)

    for root_code, _members in hierarchies.items():
        sites_in_hierarchy = get_sites_in_hierarchy(graph, root_code, exclude_secondary=True)

        # Get security roles for this hierarchy's root site
        security_roles = [
            r for r in graph.find_nodes_by_kind("SCCM_SecurityRole")
            if r.get("id", "").endswith(f"@{root_code}")
        ]

        # Build lookup: admin user ID -> admin node
        admin_user_nodes = {
            a.get("id"): a for a in graph.find_nodes_by_kind("SCCM_AdminUser")
            if a.get("id", "").endswith(f"@{root_code}")
        }

        # Build lookup: collection ID -> list of SCCM_ClientDevice IDs (via SCCM_HasMember edges)
        collection_members: dict[str, list[str]] = {}
        for edge in graph.find_edges_by_kind("SCCM_HasMember"):
            coll_id = edge.get("start", {}).get("value", "")
            device_id = edge.get("end", {}).get("value", "")
            if coll_id and device_id:
                collection_members.setdefault(coll_id, []).append(device_id)

        # Build lookup: collection ID -> collection node (for checking collectionType and name)
        collection_nodes = {
            c.get("id"): c for c in graph.find_nodes_by_kind("SCCM_Collection")
        }

        for role_node in security_roles:
            role_id = role_node.get("id", "")
            role_base = role_id.split("@")[0] if "@" in role_id else role_id
            role_props = role_node.get("properties", {})

            edge_kind = ROLE_EDGE_MAP.get(role_base)

            logger.debug(f"Processing role assignments for {role_id} ({role_props.get('roleName', '')}) "
                         f"in hierarchy with root site {root_code}")

            # Find admin users assigned to this role
            for admin_id, admin_node in admin_user_nodes.items():
                admin_props = admin_node.get("properties", {})
                admin_roles = admin_props.get("securityRoles", [])
                if isinstance(admin_roles, str):
                    admin_roles = [admin_roles]

                if role_id not in admin_roles:
                    continue

                # Create SCCM_IsAssigned edge: admin -> role
                graph.upsert_edge(admin_id, role_id, "SCCM_IsAssigned")

                # Track if this admin is a Full Administrator with "All Systems" + "All Users and User Groups"
                is_full_admin = (role_base == "SMS0001R")
                all_systems_and_users_colls: list[str] = []

                # Get admin's collection IDs
                coll_ids = admin_props.get("collectionIDs", [])
                if isinstance(coll_ids, str):
                    coll_ids = [coll_ids]

                for coll_id in coll_ids:
                    coll_node = collection_nodes.get(coll_id)
                    if not coll_node:
                        continue

                    coll_props = coll_node.get("properties", {})
                    coll_name = coll_props.get("name", "")
                    # Strip @SITECODE suffix from collection name for comparison
                    coll_name_base = coll_name.split("@")[0] if "@" in coll_name else coll_name

                    # Track "All Systems" and "All Users and User Groups" for AllPermissions
                    if coll_name_base in ("All Systems", "All Users and User Groups"):
                        all_systems_and_users_colls.append(coll_id)

                    # Only create device edges for Device-type collections (type 2)
                    coll_type = coll_props.get("collectionType")
                    if coll_type != 2 and str(coll_type) != "2":
                        continue

                    # Find devices in this collection
                    device_ids = collection_members.get(coll_id, [])
                    for device_id in device_ids:
                        device_node = graph.get_node(device_id)
                        if not device_node:
                            continue
                        if "SCCM_ClientDevice" not in device_node.get("kinds", []):
                            continue

                        if edge_kind:
                            graph.upsert_edge(admin_id, device_id, edge_kind)
                        elif role_base not in ROLE_SKIP_SET:
                            logger.warning(
                                f"Skipping custom security role {role_id} "
                                f"({role_props.get('roleName', '')}) for edge creation"
                            )

                # SCCM_AllPermissions: Full Administrator with both "All Systems" and "All Users and User Groups"
                if is_full_admin and len(all_systems_and_users_colls) >= 2:
                    for site_code in sites_in_hierarchy:
                        graph.upsert_edge(admin_id, site_code, "SCCM_AllPermissions")
                    logger.debug(f"Added SCCM_AllPermissions for {admin_id} to {len(sites_in_hierarchy)} sites")


def _add_same_host_as_edges(graph: GraphStore) -> None:
    """
    Add bidirectional SameHostAs edges between SCCM_ClientDevice and Computer nodes.

    Translated from PowerShell Add-SameHostAsEdges (lines 2261-2357).

    Also merges duplicate SCCM_ClientDevice nodes with the same ADDomainSID
    (PowerShell lines 2264-2311). Prefers GUID: prefixed nodes as primary.
    """
    logger.info("Processing SameHostAs edges...")

    computers = graph.find_nodes_by_kind("Computer")

    # Build lookup maps for computers
    computer_by_sid: dict[str, dict[str, Any]] = {}
    computer_by_name: dict[str, dict[str, Any]] = {}
    computer_by_fqdn: dict[str, dict[str, Any]] = {}

    for comp in computers:
        comp_id = comp.get("id", "")
        props = comp.get("properties", {})
        sam = props.get("sAMAccountName", "").lower().rstrip("$")
        fqdn = props.get("dNSHostName", "").lower()
        name = props.get("name", "").lower()

        if comp_id:
            computer_by_sid[comp_id] = comp
        if sam:
            computer_by_name[sam] = comp
        if fqdn:
            computer_by_fqdn[fqdn] = comp
        if name:
            computer_by_name[name] = comp

    # Step 1: Merge duplicate SCCM_ClientDevice nodes with same ADDomainSID
    # (PowerShell lines 2264-2311)
    client_devices = graph.find_nodes_by_kind("SCCM_ClientDevice")
    devices_by_sid: dict[str, list[dict[str, Any]]] = {}
    for device in client_devices:
        ad_sid = device.get("properties", {}).get("ADDomainSID", "")
        if ad_sid:
            devices_by_sid.setdefault(ad_sid, []).append(device)

    for sid, device_list in devices_by_sid.items():
        if len(device_list) <= 1:
            continue

        # Prefer GUID: prefixed nodes
        primary = None
        for d in device_list:
            if d.get("id", "").startswith("GUID:"):
                primary = d
                break
        if not primary:
            primary = device_list[0]

        primary_id = primary.get("id")

        # Merge other devices into primary and remove them
        for dup in device_list:
            dup_id = dup.get("id")
            if dup_id == primary_id:
                continue

            logger.debug(f"Merging duplicate SCCM_ClientDevice {dup_id} into {primary_id}")
            graph.rename_node(dup_id, primary_id)

    # Step 2: Create SameHostAs edges
    # Re-fetch after dedup
    client_devices = graph.find_nodes_by_kind("SCCM_ClientDevice")

    for device in client_devices:
        device_id = device.get("id", "")
        device_props = device.get("properties", {})
        device_name = device_props.get("name", "")  # Format: HOSTNAME@SITECODE
        ad_domain_sid = device_props.get("ADDomainSID", "")

        # Try to find matching computer
        matched_computer = None

        # Match by ADDomainSID (most reliable)
        if ad_domain_sid and ad_domain_sid in computer_by_sid:
            matched_computer = computer_by_sid[ad_domain_sid]
        else:
            # Match by hostname
            hostname = device_name.split("@")[0].lower() if "@" in device_name else device_name.lower()
            if hostname in computer_by_name:
                matched_computer = computer_by_name[hostname]
            else:
                # Try FQDN match
                for fqdn, comp in computer_by_fqdn.items():
                    if fqdn.split(".")[0].lower() == hostname:
                        matched_computer = comp
                        break

        if matched_computer:
            computer_id = matched_computer.get("id", "")
            if computer_id and device_id:
                # Bidirectional SameHostAs
                graph.upsert_edge(device_id, computer_id, "SameHostAs")
                graph.upsert_edge(computer_id, device_id, "SameHostAs")
                logger.debug(f"SameHostAs: {device_id} <-> {computer_id}")


def _process_computer_nodes(graph: GraphStore) -> None:
    """
    Process Computer nodes for LocalAdminRequired, MSSQL sysadmin, and SCCM_AssignAllPermissions edges.

    Translated from PowerShell lines 1846-1945 (the Computer node processing loop).

    For each computer with site system roles:
    1. Site server -> other site systems: LocalAdminRequired
    2. Site server/SMS Provider -> site database: MSSQL sysadmin edges
    3. SMS Provider -> all primary sites in hierarchy: SCCM_AssignAllPermissions
    """
    logger.info("Processing Computer nodes for LocalAdminRequired, MSSQL sysadmin, SCCM_AssignAllPermissions...")

    computers = graph.find_nodes_by_kind("Computer")
    site_nodes = {s.get("id"): s for s in graph.find_nodes_by_kind("SCCM_Site")}

    for comp in computers:
        comp_id = comp.get("id")
        comp_props = comp.get("properties", {})
        roles = comp_props.get("SCCMSiteSystemRoles", [])
        if isinstance(roles, str):
            roles = [roles]

        if not roles:
            continue

        # Extract unique site codes from roles
        site_codes: set[str] = set()
        for role in roles:
            match = re.search(r"@([A-Z0-9]+)$", str(role), re.IGNORECASE)
            if match:
                site_codes.add(match.group(1))

        for site_code in site_codes:
            site_node = site_nodes.get(site_code)
            if not site_node:
                continue

            # Find site servers and site database servers for this site
            site_server_ids: list[str] = []
            site_db_ids: list[str] = []
            for c in computers:
                c_roles = c.get("properties", {}).get("SCCMSiteSystemRoles", [])
                if isinstance(c_roles, str):
                    c_roles = [c_roles]
                if f"SMS Site Server@{site_code}" in c_roles:
                    site_server_ids.append(c.get("id"))
                if f"SMS SQL Server@{site_code}" in c_roles:
                    site_db_ids.append(c.get("id"))

            # LocalAdminRequired: site servers -> other site system hosts
            # Note: PS processes ALL sites including secondary for LocalAdminRequired
            # because PS filters on .Type (which is null for SCCM_Site nodes), not .Properties.siteType.
            for ss_id in site_server_ids:
                if comp_id == ss_id:
                    # This IS the site server - add LocalAdminRequired to all OTHER site systems
                    for other_comp in computers:
                        other_id = other_comp.get("id")
                        if other_id == comp_id:
                            continue
                        other_roles = other_comp.get("properties", {}).get("SCCMSiteSystemRoles", [])
                        if isinstance(other_roles, str):
                            other_roles = [other_roles]
                        has_role_for_site = any(f"@{site_code}" in str(r) for r in other_roles)
                        is_site_server = f"SMS Site Server@{site_code}" in other_roles
                        if has_role_for_site and not is_site_server:
                            graph.upsert_edge(comp_id, other_id, "LocalAdminRequired")
                else:
                    # This is NOT a site server - site server needs LocalAdminRequired to this host
                    graph.upsert_edge(ss_id, comp_id, "LocalAdminRequired")

            # Skip secondary sites for MSSQL sysadmin and SCCM_AssignAllPermissions
            site_type = site_node.get("properties", {}).get("siteType", "")
            if str(site_type) in ("1", "Secondary Site"):
                continue

            # MSSQL sysadmin edges: Site Server and SMS Provider computer accounts have sysadmin on site DB
            is_site_server = f"SMS Site Server@{site_code}" in roles
            is_sms_provider = any("SMS Provider" in str(r) and f"@{site_code}" in str(r) for r in roles)

            if (is_site_server or is_sms_provider) and site_db_ids:
                for db_comp_id in site_db_ids:
                    if comp_id != db_comp_id:
                        _create_mssql_sysadmin_edges(
                            graph, site_node, db_comp_id, comp, site_code,
                        )

            # SCCM_AssignAllPermissions: SMS Provider -> all primary sites in hierarchy
            if is_sms_provider:
                sites_in_hierarchy = get_sites_in_hierarchy(graph, site_code, exclude_secondary=True)
                for sh in sites_in_hierarchy:
                    graph.upsert_edge(comp_id, sh, "SCCM_AssignAllPermissions")

    # Also add SCCM_AssignAllPermissions for MSSQL databases (CM_SITECODE)
    hierarchies = get_all_hierarchies(graph)
    for root_code, members in hierarchies.items():
        primary_sites = []
        for sc in members:
            node = site_nodes.get(sc)
            if node:
                st = node.get("properties", {}).get("siteType")
                if st is None or str(st) in ("2", "4"):
                    primary_sites.append(sc)

        for db_node in graph.find_nodes_by_kind("MSSQL_Database"):
            db_id = db_node.get("id", "")
            db_name = db_node.get("properties", {}).get("name", "")
            if db_name.startswith("CM_"):
                db_site_code = db_name[3:]
                if db_site_code in primary_sites:
                    graph.upsert_edge(db_id, db_site_code, "SCCM_AssignAllPermissions")


def _create_mssql_sysadmin_edges(
    graph: GraphStore,
    site_node: dict[str, Any],
    db_comp_id: str,
    sysadmin_comp: dict[str, Any],
    site_code: str,
) -> None:
    """
    Create MSSQL nodes and edges for a sysadmin computer account.

    Translated from PowerShell Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer (lines 6187-6290).

    Creates MSSQL_Login and MSSQL_DatabaseUser nodes for the sysadmin computer,
    plus all related edges (MSSQL_MemberOf, MSSQL_Contains, MSSQL_HasLogin, MSSQL_IsMappedTo).
    """
    site_props = site_node.get("properties", {})
    sysadmin_props = sysadmin_comp.get("properties", {})
    sysadmin_id = sysadmin_comp.get("id", "")

    # Get SQL database name and port
    sql_db_name = site_props.get("SQLDatabaseName") or f"CM_{site_code}"
    sql_port = site_props.get("sqlServicePort") or 1433

    # Build IDs matching PowerShell conventions
    server_id = f"{db_comp_id}:{sql_port}"
    database_id = f"{server_id}\\{sql_db_name}"

    # Get domain\SAMAccountName for the sysadmin computer
    # PS uses Domain.Split('.')[0] which returns lowercase (e.g., "mayyhem")
    domain = sysadmin_props.get("Domain", "")
    if domain:
        domain_prefix = domain.split(".")[0].lower()
    else:
        domain_prefix = ""
    sam = sysadmin_props.get("sAMAccountName", "")
    if not sam:
        return

    login_name = f"{domain_prefix}\\{sam}" if domain_prefix else sam
    login_id = f"{login_name}@{server_id}"
    db_user_id = f"{login_name}@{database_id}"

    logger.debug(f"Creating MSSQL sysadmin edges for {login_name} to {server_id}")

    # Create MSSQL_Login node
    graph.upsert_node(
        login_id,
        ["MSSQL_Login"],
        properties={
            "collectionSource": ["SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer"],
            "loginType": "Windows",
            "memberOfRoles": [f"sysadmin@{server_id}"],
            "name": login_name,
            "SCCMInfra": True,
            "SCCMSite": site_code,
        },
    )

    # Create MSSQL_DatabaseUser node
    graph.upsert_node(
        db_user_id,
        ["MSSQL_DatabaseUser"],
        properties={
            "collectionSource": ["SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer"],
            "database": sql_db_name,
            "memberOfRoles": [f"db_owner@{database_id}"],
            "name": login_name,
            "login": login_name,
            "SCCMInfra": True,
            "SCCMSite": site_code,
        },
    )

    # Edges
    # (MSSQL_Login) -[MSSQL_MemberOf]-> (MSSQL_ServerRole: sysadmin)
    graph.upsert_edge(login_id, f"sysadmin@{server_id}", "MSSQL_MemberOf")
    # (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_Login)
    graph.upsert_edge(server_id, login_id, "MSSQL_Contains")
    # (Computer) -[MSSQL_HasLogin]-> (MSSQL_Login)
    graph.upsert_edge(sysadmin_id, login_id, "MSSQL_HasLogin")
    # (MSSQL_Login) -[MSSQL_IsMappedTo]-> (MSSQL_DatabaseUser)
    graph.upsert_edge(login_id, db_user_id, "MSSQL_IsMappedTo")
    # (MSSQL_DatabaseUser) -[MSSQL_MemberOf]-> (MSSQL_DatabaseRole: db_owner)
    graph.upsert_edge(db_user_id, f"db_owner@{database_id}", "MSSQL_MemberOf")
    # (MSSQL_Database) -[MSSQL_Contains]-> (MSSQL_DatabaseUser)
    graph.upsert_edge(database_id, db_user_id, "MSSQL_Contains")


def _add_mssql_get_tgs_edges(graph: GraphStore) -> None:
    """
    Add MSSQL_GetTGS edges from SQL service accounts to all server logins.

    Translated from PowerShell lines 1964-1983.

    If you can compromise the SQL service account's TGT, you can get a TGS
    for any login on the server (Kerberoasting).
    """
    logger.info("Processing MSSQL_GetTGS edges...")

    site_nodes = graph.find_nodes_by_kind("SCCM_Site")
    mssql_servers = graph.find_nodes_by_kind("MSSQL_Server")

    for site in site_nodes:
        site_code = site.get("id")

        # Find MSSQL_Server nodes for this site
        for server in mssql_servers:
            server_id = server.get("id", "")
            server_props = server.get("properties", {})

            if server_props.get("sccmSite") != site_code and server_props.get("SCCMSite") != site_code:
                continue

            # Find the service account node
            service_account_sid = server_props.get("SQLServiceAccountDomainSID")
            if not service_account_sid:
                logger.debug(f"No service account SID for {server_id}, requires privileged collection")
                continue

            sa_node = graph.get_node(service_account_sid)
            if not sa_node:
                continue

            # Find all MSSQL_Login nodes for this server
            for login in graph.find_nodes_by_kind("MSSQL_Login"):
                login_id = login.get("id", "")
                if f"@{server_id}" in login_id:
                    graph.upsert_edge(service_account_sid, login_id, "MSSQL_GetTGS")

            # Also create MSSQL_GetAdminTGS if service account is Kerberoastable
            if server_props.get("servicePrincipalName"):
                for login in graph.find_nodes_by_kind("MSSQL_Login"):
                    login_id = login.get("id", "")
                    if f"@{server_id}" in login_id:
                        login_props = login.get("properties", {})
                        member_of = login_props.get("memberOfRoles", [])
                        if isinstance(member_of, str):
                            member_of = [member_of]
                        if any("sysadmin" in str(r) for r in member_of):
                            graph.upsert_edge(service_account_sid, login_id, "MSSQL_GetAdminTGS")


def _find_or_create_authenticated_users(graph: GraphStore, domain: str = "") -> Optional[str]:
    """
    Find or create the Authenticated Users group node.

    Translated from PowerShell's inline Upsert-Node for Authenticated Users
    (used in Process-CoerceAndRelay* functions).

    The ID format is: {domain}-S-1-5-11
    """
    # First try to find existing
    for group in graph.find_nodes_by_kind("Group"):
        group_id = group.get("id", "")
        if group_id.endswith("-S-1-5-11") or group_id == "S-1-5-11":
            return group_id
        props = group.get("properties", {})
        name = props.get("name", "")
        if "authenticated users" in name.lower():
            return group_id

    # Not found - create one using domain
    if domain:
        auth_users_id = f"{domain}-S-1-5-11"
        graph.upsert_node(
            auth_users_id,
            ["Group", "Base"],
            properties={
                "name": f"AUTHENTICATED USERS@{domain}",
            },
        )
        logger.info(f"Created Authenticated Users group node: {auth_users_id}")
        return auth_users_id

    # Try to infer domain from Computer nodes
    for comp in graph.find_nodes_by_kind("Computer"):
        comp_domain = comp.get("properties", {}).get("Domain", "")
        if comp_domain:
            auth_users_id = f"{comp_domain}-S-1-5-11"
            graph.upsert_node(
                auth_users_id,
                ["Group", "Base"],
                properties={
                    "name": f"AUTHENTICATED USERS@{comp_domain}",
                },
            )
            logger.info(f"Created Authenticated Users group node: {auth_users_id}")
            return auth_users_id

    logger.warning("Could not determine domain for Authenticated Users group")
    return None


def _add_coerce_and_relay_edges(
    graph: GraphStore,
    disable_possible_edges: bool = False,
    domain: str = "",
) -> None:
    """
    Add CoerceAndRelay edges.

    Translated from PowerShell Process-CoerceAndRelayToAdminService,
    Process-CoerceAndRelayToMSSQL, Process-CoerceAndRelayToSMB
    (lines 6572-6781).
    """
    logger.info("Processing CoerceAndRelay edges...")

    _process_coerce_and_relay_to_admin_service(graph, domain)
    _process_coerce_and_relay_to_mssql(graph, disable_possible_edges, domain)
    _process_coerce_and_relay_to_smb(graph, domain)


def _process_coerce_and_relay_to_admin_service(graph: GraphStore, fallback_domain: str = "") -> None:
    """
    Process CoerceAndRelayToAdminService edges.

    Translated from PowerShell Process-CoerceAndRelayToAdminService (lines 6572-6624).

    For each site, finds SMS Providers with restrictReceivingNtlmTraffic Off/null,
    and site servers. For each (site server, SMS provider) pair where they differ,
    creates a CoerceAndRelayToAdminService edge from Authenticated Users to the site.
    """
    site_nodes = graph.find_nodes_by_kind("SCCM_Site")

    for site in site_nodes:
        site_code = site.get("id")
        site_props = site.get("properties", {})

        # Skip secondary sites
        if str(site_props.get("siteType")) in ("1", "Secondary Site"):
            continue

        # Find SMS Providers with NTLM restriction Off or null
        sms_provider_comps: list[dict[str, Any]] = []
        site_server_comps: list[dict[str, Any]] = []

        for comp in graph.find_nodes_by_kind("Computer"):
            comp_props = comp.get("properties", {})
            roles = comp_props.get("SCCMSiteSystemRoles", [])
            if isinstance(roles, str):
                roles = [roles]

            ntlm_restrict = comp_props.get("restrictReceivingNtlmTraffic")
            ntlm_ok = (ntlm_restrict is None or str(ntlm_restrict).lower() == "off")

            if f"SMS Provider@{site_code}" in roles and ntlm_ok:
                sms_provider_comps.append(comp)
            if f"SMS Site Server@{site_code}" in roles:
                site_server_comps.append(comp)

        if not sms_provider_comps:
            logger.debug(f"No SMS Provider with NTLM unrestricted for site {site_code}")
            continue
        if not site_server_comps:
            logger.debug(f"No site servers found for site {site_code}")
            continue

        for sms_prov in sms_provider_comps:
            sms_id = sms_prov.get("id")
            sms_fqdn = sms_prov.get("properties", {}).get("dNSHostName", "")

            for site_srv in site_server_comps:
                srv_id = site_srv.get("id")
                srv_fqdn = site_srv.get("properties", {}).get("dNSHostName", "")
                srv_domain = site_srv.get("properties", {}).get("Domain", "")

                if sms_id == srv_id:
                    continue  # Can't relay to self

                auth_users_id = _find_or_create_authenticated_users(graph, srv_domain or fallback_domain)
                if auth_users_id:
                    graph.upsert_edge(
                        auth_users_id,
                        site_code,
                        "CoerceAndRelayToAdminService",
                        properties={
                            "collectionSource": ["Post-processing"],
                            "coercionVictimAndRelayTargetPairs": [
                                f"Coerce {srv_fqdn}, relay to {sms_fqdn}"
                            ],
                        },
                    )


def _process_coerce_and_relay_to_mssql(
    graph: GraphStore,
    disable_possible_edges: bool = False,
    fallback_domain: str = "",
) -> None:
    """
    Process CoerceAndRelayToMSSQL edges.

    Translated from PowerShell Process-CoerceAndRelayToMSSQL (lines 6626-6726).

    Finds site database servers with EPA Off/null and NTLM unrestricted,
    then creates CoerceAndRelayToMSSQL edges from Authenticated Users to
    MSSQL_Login nodes for site servers, SMS providers, and management points.
    """
    site_nodes = graph.find_nodes_by_kind("SCCM_Site")
    logger.debug(f"CoerceAndRelayToMSSQL: Processing {len(site_nodes)} sites")

    for site in site_nodes:
        site_code = site.get("id")
        site_props = site.get("properties", {})

        if str(site_props.get("siteType")) in ("1", "Secondary Site"):
            logger.debug(f"  Skipping secondary site {site_code}")
            continue

        logger.debug(f"  Processing site {site_code}")

        # Find SQL Server computers with NTLM unrestricted
        sql_server_comps: list[dict[str, Any]] = []
        for comp in graph.find_nodes_by_kind("Computer"):
            comp_props = comp.get("properties", {})
            roles = comp_props.get("SCCMSiteSystemRoles", [])
            if isinstance(roles, str):
                roles = [roles]

            if f"SMS SQL Server@{site_code}" not in roles:
                continue

            ntlm_restrict = comp_props.get("restrictReceivingNtlmTraffic")
            if ntlm_restrict is not None and str(ntlm_restrict).lower() != "off":
                logger.debug(f"  SQL Server {comp.get('id')} has NTLM restricted ({ntlm_restrict}), skipping")
                continue

            logger.debug(f"  Found SQL Server computer: {comp.get('id')} ({comp_props.get('dNSHostName', '')})")
            sql_server_comps.append(comp)

        if not sql_server_comps:
            logger.debug(f"  No SQL Server computers found for site {site_code}")
            continue

        # Find victim computers (site servers, SMS providers, management points)
        victim_comps: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for comp in graph.find_nodes_by_kind("Computer"):
            comp_props = comp.get("properties", {})
            roles = comp_props.get("SCCMSiteSystemRoles", [])
            if isinstance(roles, str):
                roles = [roles]

            is_relevant = any(
                f"@{site_code}" in str(r) and
                any(kw in str(r) for kw in ("SMS Site Server", "SMS Provider", "SMS Management Point"))
                for r in roles
            )
            if is_relevant:
                cid = comp.get("id")
                if cid not in seen_ids:
                    victim_comps.append(comp)
                    seen_ids.add(cid)

        logger.debug(f"  Found {len(victim_comps)} victim computers for site {site_code}")
        for v in victim_comps:
            logger.debug(f"    Victim: {v.get('id')} ({v.get('properties', {}).get('dNSHostName', '')})")

        for sql_comp in sql_server_comps:
            sql_comp_id = sql_comp.get("id")

            # Find MSSQL_Server node for this computer
            mssql_server = None
            for srv in graph.find_nodes_by_kind("MSSQL_Server"):
                if srv.get("id", "").startswith(f"{sql_comp_id}:"):
                    mssql_server = srv
                    break

            if not mssql_server:
                logger.debug(f"  No MSSQL_Server node found for SQL computer {sql_comp_id}")
                continue

            mssql_server_id = mssql_server.get("id", "")
            mssql_props = mssql_server.get("properties", {})

            # Check EPA - matches PowerShell logic (lines 6674-6686)
            epa = mssql_props.get("mssqlExtendedProtectionForAuthentication")
            if epa is None:
                # EPA unknown - if DisablePossibleEdges, skip; otherwise assume Off
                if disable_possible_edges:
                    logger.debug(f"  EPA unknown on {mssql_server_id}, skipping (DisablePossibleEdges)")
                    continue
                else:
                    logger.debug(f"  EPA unknown on {mssql_server_id}, assuming Off")
            elif epa is True or (isinstance(epa, str) and epa.lower() not in ("off", "0", "false", "none", "")):
                # EPA is enabled - skip
                logger.debug(f"  EPA enabled ({epa}) on {mssql_server_id}, skipping")
                continue
            else:
                logger.debug(f"  EPA disabled ({epa}) on {mssql_server_id}")

            sql_fqdn = sql_comp.get("properties", {}).get("dNSHostName", "")
            sql_port = mssql_props.get("port", 1433)

            for victim in victim_comps:
                victim_id = victim.get("id")
                if victim_id == sql_comp_id:
                    continue

                victim_props = victim.get("properties", {})
                victim_fqdn = victim_props.get("dNSHostName", "")
                victim_domain = victim_props.get("Domain", "")
                victim_sam = victim_props.get("sAMAccountName", "")
                domain_prefix = victim_domain.split(".")[0].lower() if victim_domain else ""

                # Find MSSQL_Login node for this victim computer
                # Must match the lowercase domain casing used in _create_mssql_logins_for_site
                login_name = f"{domain_prefix}\\{victim_sam}" if domain_prefix else victim_sam
                login_id = f"{login_name}@{mssql_server_id}"

                login_node = graph.get_node(login_id)
                if not login_node:
                    logger.debug(f"  No MSSQL_Login node found for {login_id}")
                    continue

                pair = f"Coerce {victim_fqdn.lower()}, relay to {sql_fqdn.lower()}:{sql_port}"
                auth_users_id = _find_or_create_authenticated_users(graph, victim_domain or fallback_domain)
                if auth_users_id:
                    logger.debug(f"  Creating CoerceAndRelayToMSSQL: {auth_users_id} -> {login_id}")
                    graph.upsert_edge(
                        auth_users_id,
                        login_id,
                        "CoerceAndRelayToMSSQL",
                        properties={
                            "coercionVictimAndRelayTargetPairs": [pair],
                        },
                    )


def _process_coerce_and_relay_to_smb(graph: GraphStore, fallback_domain: str = "") -> None:
    """
    Process CoerceAndRelaytoSMB edges.

    Translated from PowerShell Process-CoerceAndRelayToSMB (lines 6728-6781).

    For each site, finds site systems without SMB signing and NTLM unrestricted,
    then creates CoerceAndRelaytoSMB edges from Authenticated Users to those computers.
    """
    site_nodes = graph.find_nodes_by_kind("SCCM_Site")

    for site in site_nodes:
        site_code = site.get("id")
        site_props = site.get("properties", {})

        if str(site_props.get("siteType")) in ("1", "Secondary Site"):
            continue

        # Find site systems without SMB signing
        unsigned_comps: list[dict[str, Any]] = []
        site_server_comps: list[dict[str, Any]] = []

        for comp in graph.find_nodes_by_kind("Computer"):
            comp_props = comp.get("properties", {})
            roles = comp_props.get("SCCMSiteSystemRoles", [])
            if isinstance(roles, str):
                roles = [roles]

            has_role_for_site = any(f"@{site_code}" in str(r) for r in roles)
            if not has_role_for_site:
                continue

            if f"SMS Site Server@{site_code}" in roles:
                site_server_comps.append(comp)

            smb_signing = comp_props.get("SMBSigningRequired")
            if smb_signing is not True and smb_signing is not None and smb_signing is not False:
                continue

            if smb_signing is True or smb_signing is None:
                continue

            # SMB signing is False
            ntlm_restrict = comp_props.get("restrictReceivingNtlmTraffic")
            if ntlm_restrict is not None and str(ntlm_restrict).lower() != "off":
                continue

            unsigned_comps.append(comp)

        if not unsigned_comps or not site_server_comps:
            continue

        for target_comp in unsigned_comps:
            target_id = target_comp.get("id")

            for site_srv in site_server_comps:
                srv_id = site_srv.get("id")
                if target_id == srv_id:
                    continue

                srv_domain = site_srv.get("properties", {}).get("Domain", "")
                srv_fqdn = site_srv.get("properties", {}).get("dNSHostName", "")

                auth_users_id = _find_or_create_authenticated_users(graph, srv_domain or fallback_domain)
                if auth_users_id and target_id:
                    graph.upsert_edge(
                        auth_users_id,
                        target_id,
                        "CoerceAndRelayToSMB",
                        properties={
                            "coercionVictimHostnames": [srv_fqdn],
                        },
                    )


# Map discoveredSecretType values to edge kinds
_SECRET_TYPE_TO_EDGE = {
    "NAA": "SCCM_HasNetworkAccessAccount",
    "NAA_Password": "SCCM_HasNetworkAccessAccount",
    "CollectionVariable": "SCCM_HasCollectionVar",
    "TaskSequence": "SCCM_HasTaskSequence",
}


def _add_secret_policy_edges(graph: GraphStore) -> None:
    """
    Create edges from SCCM_ClientDevice nodes to CRED-discovered secret nodes.

    For each node with a discoveredSecretType property (User or SCCM_Secret),
    finds all SCCM_ClientDevice nodes in the matching site and creates the
    appropriate edge (SCCM_HasNetworkAccessAccount, SCCM_HasCollectionVar,
    or SCCM_HasTaskSequence).

    This runs after SameHostAs edges (step 6) so SCCM_ClientDevice nodes
    are fully merged. Gated by disable_possible_edges in the caller.
    """
    logger.info("Processing secret policy edges...")

    # Find all CRED-discovered secret nodes (User and SCCM_Secret kinds)
    secret_nodes: list[dict[str, Any]] = []
    for node in graph.nodes:
        props = node.get("properties", {})
        if props.get("discoveredSecretType") and props.get("discoveredInSite"):
            secret_nodes.append(node)

    if not secret_nodes:
        logger.info("No CRED-discovered secret nodes found, skipping secret policy edges")
        return

    # Group by site code
    secrets_by_site: dict[str, list[dict[str, Any]]] = {}
    for node in secret_nodes:
        site = node["properties"]["discoveredInSite"]
        secrets_by_site.setdefault(site, []).append(node)

    # Build lookup: site code -> list of SCCM_ClientDevice node IDs
    client_devices = graph.find_nodes_by_kind("SCCM_ClientDevice")
    devices_by_site: dict[str, list[str]] = {}
    for device in client_devices:
        device_site = device.get("properties", {}).get("siteCode", "")
        if device_site:
            devices_by_site.setdefault(device_site, []).append(device.get("id"))

    # Create edges
    counts: dict[str, int] = {}
    for site_code, site_secrets in secrets_by_site.items():
        device_ids = devices_by_site.get(site_code, [])
        if not device_ids:
            logger.debug(f"No SCCM_ClientDevice nodes for site {site_code}, skipping {len(site_secrets)} secret(s)")
            continue

        for secret_node in site_secrets:
            secret_id = secret_node.get("id")
            secret_type = secret_node["properties"]["discoveredSecretType"]
            edge_kind = _SECRET_TYPE_TO_EDGE.get(secret_type)
            if not edge_kind:
                logger.debug(f"Unknown secret type '{secret_type}' for node {secret_id}")
                continue

            for device_id in device_ids:
                graph.upsert_edge(
                    device_id,
                    secret_id,
                    edge_kind,
                    properties={"collectionSource": ["Post-processing"]},
                )

            counts[edge_kind] = counts.get(edge_kind, 0) + len(device_ids)

    if counts:
        parts = [f"{count} {kind}" for kind, count in sorted(counts.items())]
        logger.info(f"Added secret policy edges: {', '.join(parts)}")
    else:
        logger.info("No secret policy edges created (no matching SCCM_ClientDevice nodes)")
