"""
MSSQL collection for ConfigManBearPig.

Translated from PowerShell Invoke-MSSQLCollection (lines 6507-6781),
Get-MssqlEpaSettingsViaTDS (lines 5260-6048),
Add-MSSQLServerNodesAndEdges (lines 6050-6505).

Checks MSSQL database servers for:
- Extended Protection for Authentication (EPA) settings via TDS PRELOGIN
- Site database MSSQL server nodes and relationships
- sysadmin login detection
- Service account detection
"""

import logging
import socket
import struct
from typing import Any, Optional

from lib.ad_resolver import ADResolver
from lib.graph import GraphStore
from lib.targets import CollectionTarget, TargetManager

logger = logging.getLogger("ConfigManBearPig")

# MSSQL default port
MSSQL_PORT = 1433

# TDS PRELOGIN packet token types
TDS_PRELOGIN_VERSION = 0x00
TDS_PRELOGIN_ENCRYPTION = 0x01
TDS_PRELOGIN_INSTOPT = 0x02
TDS_PRELOGIN_THREADID = 0x03
TDS_PRELOGIN_MARS = 0x04
TDS_PRELOGIN_TERMINATOR = 0xFF


def invoke_mssql_collection(
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
    Run MSSQL collection against a target.

    Translated from PowerShell Invoke-MSSQLCollection (lines 6507-6625).

    Checks for MSSQL Server on port 1433 and collects EPA settings.
    """
    hostname = target.hostname
    logger.info(f"Starting MSSQL collection on {hostname}...")

    # Check if MSSQL is listening on port 1433
    if not _check_port(hostname, MSSQL_PORT):
        logger.info(f"MSSQL port {MSSQL_PORT} not open on {hostname}")
        return

    logger.info(f"MSSQL port {MSSQL_PORT} is open on {hostname}")

    # Get EPA settings via TDS PRELOGIN
    epa_setting = _get_epa_via_tds(hostname, MSSQL_PORT)

    # Create MSSQL_Server node
    # Use SID-based ID to match PowerShell: $SqlServerComputerNode.id:$SqlServicePort
    if target.sid:
        server_id = f"{target.sid}:{MSSQL_PORT}"
    else:
        server_id = f"{hostname}:{MSSQL_PORT}"
    fqdn = target.fqdn or hostname

    server_props: dict[str, Any] = {
        "name": f"{fqdn}:{MSSQL_PORT}",
        "collectionSource": ["MSSQL-TDS"],
        "dnsHostName": fqdn,
        "hostFQDN": fqdn,
        "port": MSSQL_PORT,
        "SQLServicePort": MSSQL_PORT,
        "SCCMInfra": True,
    }

    if epa_setting is not None:
        server_props["mssqlExtendedProtectionForAuthentication"] = epa_setting
        if epa_setting:
            logger.info(f"EPA is ENABLED on {hostname}:{MSSQL_PORT}")
        else:
            logger.info(f"EPA is DISABLED on {hostname}:{MSSQL_PORT}")
    else:
        logger.warning(f"Could not determine EPA setting on {hostname}:{MSSQL_PORT}")

    graph.upsert_node(server_id, ["MSSQL_Server"], properties=server_props)

    # Create MSSQL node structure for this server
    _add_mssql_nodes_and_edges(
        graph, ad_resolver, target, server_id, hostname, domain,
        disable_possible_edges
    )

    # MSSQL_HostFor: Computer -> MSSQL_Server
    if target.sid:
        graph.upsert_edge(target.sid, server_id, "MSSQL_HostFor")
        # MSSQL_ExecuteOnHost: MSSQL_Server -> Computer
        graph.upsert_edge(server_id, target.sid, "MSSQL_ExecuteOnHost")

    logger.info(f"MSSQL collection completed for {hostname}")


def _check_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _get_epa_via_tds(hostname: str, port: int = 1433) -> Optional[bool]:
    """
    Detect EPA setting via TDS PRELOGIN exchange.

    Translated from PowerShell Get-MssqlEpaSettingsViaTDS (lines 5260-5490).

    The TDS PRELOGIN packet exchange reveals whether the server requires
    encryption, which correlates with EPA settings.

    Returns:
        True if EPA is enabled, False if disabled, None if unknown
    """
    try:
        sock = socket.create_connection((hostname, port), timeout=5)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Cannot connect to {hostname}:{port} for TDS: {e}")
        return None

    try:
        # Build TDS PRELOGIN packet
        prelogin_payload = _build_tds_prelogin()

        # Build TDS header
        # Type 0x12 (PRELOGIN), Status 0x01 (EOM), Length, SPID, PacketID, Window
        tds_header = struct.pack(
            ">BBHHBB",
            0x12,  # Type: Pre-Login
            0x01,  # Status: End of message
            len(prelogin_payload) + 8,  # Length (header + payload)
            0,  # SPID
            1,  # PacketID
            0,  # Window
        )

        # Send TDS packet
        sock.sendall(tds_header + prelogin_payload)

        # Receive response
        response = _recv_tds_response(sock)
        if not response:
            return None

        # Parse PRELOGIN response for encryption option
        return _parse_prelogin_response(response)

    except Exception as e:
        logger.debug(f"TDS PRELOGIN exchange failed with {hostname}:{port}: {e}")
        return None
    finally:
        sock.close()


def _build_tds_prelogin() -> bytes:
    """Build a TDS PRELOGIN request payload."""
    # Options: VERSION, ENCRYPTION, INSTOPT, THREADID, MARS, TERMINATOR
    # Each option: TOKEN(1) + OFFSET(2) + LENGTH(2)
    # Followed by option data

    # Calculate offsets
    num_options = 5  # VERSION, ENCRYPTION, INSTOPT, THREADID, MARS
    option_header_size = num_options * 5 + 1  # +1 for terminator byte

    version_data = struct.pack(">BBBBH", 16, 0, 0, 1, 0)  # SQL Server 2022 compat
    encryption_data = bytes([0x00])  # 0x00 = ENCRYPT_OFF
    instopt_data = bytes([0x00])  # Default instance
    threadid_data = struct.pack(">I", 0)
    mars_data = bytes([0x00])  # MARS off

    offset = option_header_size
    options = bytearray()

    # VERSION
    options.extend(struct.pack(">BHH", TDS_PRELOGIN_VERSION, offset, len(version_data)))
    offset += len(version_data)

    # ENCRYPTION
    options.extend(struct.pack(">BHH", TDS_PRELOGIN_ENCRYPTION, offset, len(encryption_data)))
    offset += len(encryption_data)

    # INSTOPT
    options.extend(struct.pack(">BHH", TDS_PRELOGIN_INSTOPT, offset, len(instopt_data)))
    offset += len(instopt_data)

    # THREADID
    options.extend(struct.pack(">BHH", TDS_PRELOGIN_THREADID, offset, len(threadid_data)))
    offset += len(threadid_data)

    # MARS
    options.extend(struct.pack(">BHH", TDS_PRELOGIN_MARS, offset, len(mars_data)))
    offset += len(mars_data)

    # TERMINATOR
    options.extend(bytes([TDS_PRELOGIN_TERMINATOR]))

    # Combine options and data
    payload = bytes(options) + version_data + encryption_data + instopt_data + threadid_data + mars_data

    return payload


def _recv_tds_response(sock: socket.socket, timeout: float = 5.0) -> Optional[bytes]:
    """Receive a TDS response packet."""
    sock.settimeout(timeout)

    try:
        # Read TDS header (8 bytes)
        header = b""
        while len(header) < 8:
            chunk = sock.recv(8 - len(header))
            if not chunk:
                return None
            header += chunk

        # Parse header
        pkt_type = header[0]
        status = header[1]
        length = struct.unpack(">H", header[2:4])[0]

        # Read payload
        payload_length = length - 8
        payload = b""
        while len(payload) < payload_length:
            chunk = sock.recv(payload_length - len(payload))
            if not chunk:
                break
            payload += chunk

        return payload

    except socket.timeout:
        logger.debug("TDS response timeout")
        return None
    except Exception as e:
        logger.debug(f"TDS receive error: {e}")
        return None


def _parse_prelogin_response(payload: bytes) -> Optional[bool]:
    """
    Parse TDS PRELOGIN response to determine EPA/encryption setting.

    Returns True if encryption is required (EPA likely enabled),
    False if not required (EPA likely disabled).
    """
    if not payload:
        return None

    offset = 0
    encryption_value = None

    while offset < len(payload):
        token = payload[offset]
        if token == TDS_PRELOGIN_TERMINATOR:
            break

        if offset + 5 > len(payload):
            break

        data_offset = struct.unpack(">H", payload[offset + 1:offset + 3])[0]
        data_length = struct.unpack(">H", payload[offset + 3:offset + 5])[0]

        if token == TDS_PRELOGIN_ENCRYPTION:
            if data_offset + data_length <= len(payload):
                encryption_value = payload[data_offset]

        offset += 5

    if encryption_value is not None:
        # Encryption values:
        # 0x00 = ENCRYPT_OFF - no encryption required (EPA OFF)
        # 0x01 = ENCRYPT_ON - encryption required (EPA might be ON)
        # 0x02 = ENCRYPT_NOT_SUP - encryption not supported
        # 0x03 = ENCRYPT_REQ - encryption required (EPA ON)
        logger.debug(f"TDS encryption value: 0x{encryption_value:02x}")

        # EPA is enabled when encryption is required
        return encryption_value in (0x01, 0x03)

    return None


def _add_mssql_nodes_and_edges(
    graph: GraphStore,
    ad_resolver: ADResolver,
    target: CollectionTarget,
    server_id: str,
    hostname: str,
    domain: str,
    disable_possible_edges: bool = False,
) -> None:
    """
    Create MSSQL node hierarchy for a server.

    Translated from PowerShell Add-MSSQLServerNodesAndEdges (lines 6050-6350).

    Creates:
    - MSSQL_Server (already created)
    - MSSQL_Database (CM_<SiteCode>)
    - MSSQL_Login (site server computer accounts)
    - MSSQL_DatabaseUser
    - MSSQL_DatabaseRole (db_owner)
    - MSSQL_ServerRole (sysadmin)
    - Edges between them
    """
    # Find site code for this database server
    site_code = None
    for site in graph.find_nodes_by_kind("SCCM_Site"):
        props = site.get("properties", {})
        sql_server = props.get("SQLServerName", "")
        if sql_server and sql_server.lower().split(".")[0] == hostname.split(".")[0].lower():
            site_code = site.get("id")
            break

    # If sqlServerName didn't match, check if the target computer has
    # any SCCM site system role that indicates its site code
    # PS uses CollectionTarget.SiteCode set during earlier collection phases
    if not site_code:
        for comp in graph.find_nodes_by_kind("Computer"):
            comp_props = comp.get("properties", {})
            dns_name = comp_props.get("dNSHostName", "")
            if dns_name and dns_name.lower().split(".")[0] == hostname.split(".")[0].lower():
                roles = comp_props.get("SCCMSiteSystemRoles", [])
                if isinstance(roles, str):
                    roles = [roles]
                for r in roles:
                    r_str = str(r)
                    if "@" in r_str:
                        site_code = r_str.split("@")[-1]
                        break
            if site_code:
                break

    if not site_code and not disable_possible_edges:
        # Try to infer from collected sites
        sites = graph.find_nodes_by_kind("SCCM_Site")
        if len(sites) == 1:
            site_code = sites[0].get("id")
        else:
            logger.debug(f"Cannot determine site code for MSSQL server {hostname}")
            return
    elif not site_code:
        return

    fqdn = target.fqdn or hostname

    # Set SCCMSite on the MSSQL_Server node (matches PS behavior)
    graph.upsert_node(server_id, ["MSSQL_Server"], properties={"SCCMSite": site_code})

    # Skip full MSSQL hierarchy for secondary sites (matches PS line 6330)
    site_node = graph.get_node(site_code)
    if site_node:
        site_type = site_node.get("properties", {}).get("siteType", "")
        if site_type == "Secondary Site":
            logger.debug(f"Skipping MSSQL hierarchy for secondary site {site_code}")
            return

    db_name = f"CM_{site_code}"

    # sysadmin server role
    sysadmin_id = f"sysadmin@{server_id}"
    graph.upsert_node(
        sysadmin_id,
        ["MSSQL_ServerRole"],
        properties={
            "name": f"sysadmin@{server_id}",
            "collectionSource": ["MSSQL-Inferred"],
        },
    )
    # MSSQL_Contains: Server -> ServerRole
    graph.upsert_edge(server_id, sysadmin_id, "MSSQL_Contains")
    # MSSQL_ControlServer: ServerRole -> Server
    graph.upsert_edge(sysadmin_id, server_id, "MSSQL_ControlServer")

    # Bail if DisablePossibleEdges and this server wasn't confirmed via Remote Registry
    # (matches PS lines 6128-6132 / 6336-6343)
    if disable_possible_edges:
        comp_node = graph.get_node(target.sid) if target.sid else None
        comp_sources = (comp_node or {}).get("properties", {}).get("collectionSource", [])
        if isinstance(comp_sources, str):
            comp_sources = [comp_sources]
        if "RemoteRegistry-MultisiteComponentServers" not in comp_sources:
            logger.debug(
                f"Skipping MSSQL database nodes for {hostname} "
                f"(not confirmed from registry, DisablePossibleEdges is on)"
            )
            return

    # Database node
    db_id = f"{server_id}\\{db_name}"
    graph.upsert_node(
        db_id,
        ["MSSQL_Database"],
        properties={
            "name": db_name,
            "collectionSource": ["MSSQL-Inferred"],
            "siteCode": site_code,
        },
    )
    # MSSQL_Contains: Server -> Database
    graph.upsert_edge(server_id, db_id, "MSSQL_Contains")

    # db_owner role
    db_owner_id = f"db_owner@{db_id}"
    graph.upsert_node(
        db_owner_id,
        ["MSSQL_DatabaseRole"],
        properties={
            "name": f"db_owner@{db_id}",
            "collectionSource": ["MSSQL-Inferred"],
        },
    )
    # MSSQL_Contains: Database -> DatabaseRole
    graph.upsert_edge(db_id, db_owner_id, "MSSQL_Contains")
    # MSSQL_ControlDB: DatabaseRole -> Database
    graph.upsert_edge(db_owner_id, db_id, "MSSQL_ControlDB")

    # Login nodes are created by:
    # 1. Registry collector's _add_mssql_hierarchy_from_registry (for confirmed site DBs)
    # 2. Post-processing (Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer equivalent)
    # The MSSQL collector (TDS probe) does NOT create logins — it only creates the base hierarchy.

    # Service account detection
    _detect_service_account(graph, ad_resolver, server_id, hostname, domain)


def _create_mssql_logins_for_site(
    graph: GraphStore,
    ad_resolver: ADResolver,
    server_id: str,
    db_id: str,
    db_owner_id: str,
    sysadmin_id: str,
    site_code: str,
    domain: str,
) -> None:
    """Create MSSQL login/user/role membership for site server computer accounts."""
    for comp in graph.find_nodes_by_kind("Computer"):
        comp_props = comp.get("properties", {})
        roles = comp_props.get("SCCMSiteSystemRoles", [])
        if isinstance(roles, str):
            roles = [roles]

        # Check if this computer has a relevant role for this site
        has_relevant_role = False
        for role in roles:
            role_str = str(role)
            if f"@{site_code}" in role_str:
                if any(r in role_str for r in ["Site Server", "SMS Provider", "Passive"]):
                    has_relevant_role = True
                    break

        if not has_relevant_role:
            continue

        comp_id = comp.get("id", "")
        sam = comp_props.get("sAMAccountName", "")
        if not sam:
            continue

        # Use lowercase domain prefix to match PowerShell behavior
        # PS: $Domain.Split('.')[0] returns lowercase (e.g., "mayyhem")
        domain_prefix = domain.split(".")[0].lower()
        login_name = f"{domain_prefix}\\{sam}"
        login_id = f"{login_name}@{server_id}"

        # MSSQL_Login node
        graph.upsert_node(
            login_id,
            ["MSSQL_Login"],
            properties={
                "name": login_id,
                "collectionSource": ["MSSQL-Inferred"],
                "loginName": login_name,
            },
        )

        # MSSQL_Contains: Server -> Login
        graph.upsert_edge(server_id, login_id, "MSSQL_Contains")

        # MSSQL_HasLogin: Computer -> Login
        graph.upsert_edge(comp_id, login_id, "MSSQL_HasLogin")

        # MSSQL_MemberOf: Login -> sysadmin
        graph.upsert_edge(login_id, sysadmin_id, "MSSQL_MemberOf")

        # Database user
        db_user_id = f"{login_name}@{db_id}"
        graph.upsert_node(
            db_user_id,
            ["MSSQL_DatabaseUser"],
            properties={
                "name": db_user_id,
                "collectionSource": ["MSSQL-Inferred"],
            },
        )

        # MSSQL_Contains: Database -> DatabaseUser
        graph.upsert_edge(db_id, db_user_id, "MSSQL_Contains")

        # MSSQL_IsMappedTo: Login -> DatabaseUser
        graph.upsert_edge(login_id, db_user_id, "MSSQL_IsMappedTo")

        # MSSQL_MemberOf: DatabaseUser -> db_owner
        graph.upsert_edge(db_user_id, db_owner_id, "MSSQL_MemberOf")


def _detect_service_account(
    graph: GraphStore,
    ad_resolver: ADResolver,
    server_id: str,
    hostname: str,
    domain: str,
) -> None:
    """
    Detect MSSQL service account from SPN or known patterns.

    Translated from PowerShell service account detection in MSSQL collection.
    """
    # Look for MSSQLSvc SPN on domain computers
    results = ad_resolver.get_ad_object(
        search_filter=f"(servicePrincipalName=MSSQLSvc/{hostname}*)",
        attributes=["objectSid", "sAMAccountName", "distinguishedName", "objectClass"],
    )

    if results:
        for obj in results:
            obj_class = obj.get("objectClass", [])
            if isinstance(obj_class, str):
                obj_class = [obj_class]

            # Service account is a user (not the computer itself)
            if "user" in [c.lower() for c in obj_class] and "computer" not in [c.lower() for c in obj_class]:
                sid = obj.get("objectSid") or obj.get("SID")
                if isinstance(sid, bytes):
                    sid = ad_resolver._sid_bytes_to_string(sid)
                sam = obj.get("sAMAccountName", "")

                if sid:
                    # Create User node for service account
                    graph.upsert_node(
                        sid,
                        ["User", "Base"],
                        properties={
                            "sAMAccountName": sam,
                            "name": sam,
                            "collectionSource": ["MSSQL-SPN"],
                        },
                        ad_object=obj,
                    )

                    # MSSQL_ServiceAccountFor: User -> MSSQL_Server
                    graph.upsert_edge(sid, server_id, "MSSQL_ServiceAccountFor")

                    # MSSQL_GetAdminTGS: User -> MSSQL_Server
                    graph.upsert_edge(sid, server_id, "MSSQL_GetAdminTGS")

                    # HasSession: Computer -> User (service account has session on DB server)
                    # Find the computer hosting this MSSQL server
                    for comp in graph.find_nodes_by_kind("Computer"):
                        comp_props = comp.get("properties", {})
                        fqdn = comp_props.get("dNSHostName", "").lower()
                        if fqdn and hostname.lower().startswith(fqdn.split(".")[0]):
                            graph.upsert_edge(comp.get("id"), sid, "HasSession")
                            break

                    logger.info(f"Detected MSSQL service account: {sam} for {server_id}")

    # Also look for MSSQLSvc SPN registered on user accounts
    results2 = ad_resolver.get_ad_object(
        search_filter=f"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=MSSQLSvc/{hostname}*))",
        attributes=["objectSid", "sAMAccountName", "distinguishedName"],
    )

    if results2:
        for obj in results2:
            sid = obj.get("objectSid") or obj.get("SID")
            if isinstance(sid, bytes):
                sid = ad_resolver._sid_bytes_to_string(sid)
            sam = obj.get("sAMAccountName", "")

            if sid:
                graph.upsert_node(
                    sid,
                    ["User", "Base"],
                    properties={
                        "sAMAccountName": sam,
                        "name": sam,
                        "collectionSource": ["MSSQL-SPN"],
                    },
                    ad_object=obj,
                )
                graph.upsert_edge(sid, server_id, "MSSQL_ServiceAccountFor")
                graph.upsert_edge(sid, server_id, "MSSQL_GetAdminTGS")

                # MSSQL_GetTGS for each login on the server
                for login_node in graph.find_nodes_by_kind("MSSQL_Login"):
                    login_id = login_node.get("id", "")
                    if login_id.endswith(f"@{server_id}"):
                        graph.upsert_edge(sid, login_id, "MSSQL_GetTGS")

                logger.info(f"Detected MSSQL service account (user): {sam}")
