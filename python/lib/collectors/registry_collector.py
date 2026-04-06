"""
Remote Registry collection for ConfigManBearPig.

Translated from PowerShell Invoke-RemoteRegistryCollection (lines 4639-5046)
and Get-MssqlEpaSettingsViaRemoteRegistry (lines 2810-2961).

Collects from remote registry:
- SCCM site configuration (Component Servers, Triggers)
- Current user SID
- SMB signing settings
- MSSQL EPA settings
"""

import logging
import socket
from typing import Any, Optional

from lib.ad_resolver import ADResolver
from lib.graph import GraphStore
from lib.targets import CollectionTarget, TargetManager

logger = logging.getLogger("ConfigManBearPig")

# Try to import impacket for remote registry
try:
    from impacket.dcerpc.v5 import rrp, transport
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


# Registry key paths for SCCM
SCCM_REG_KEYS = {
    "triggers": r"SOFTWARE\Microsoft\SMS\Identification",
    "component_servers": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers",
    "multisite_components": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers",
    "current_user": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
}


def invoke_remote_registry_collection(
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
    Run Remote Registry collection against a target.

    Translated from PowerShell Invoke-RemoteRegistryCollection (lines 4639-5046).

    Requires admin privileges on the target system.
    """
    hostname = target.hostname
    logger.info(f"Starting Remote Registry collection on {hostname}...")

    if not HAS_IMPACKET:
        logger.warning("impacket not available for remote registry queries")
        return

    # Fast port check — registry uses SMB (445)
    try:
        with socket.create_connection((hostname, 445), timeout=3):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        logger.info(f"SMB port 445 not open on {hostname}, skipping Remote Registry collection")
        return

    try:
        # Connect via SMB
        conn = _connect_smb(hostname, domain, username, password)
        if not conn:
            logger.warning(f"Could not connect to {hostname} for registry queries")
            return

        # Open remote registry service
        reg_conn = _open_remote_registry(conn)
        if not reg_conn:
            logger.warning(f"Could not open remote registry on {hostname}")
            conn.logoff()
            return

        try:
            # Read SCCM identification (site code)
            site_code = _read_sccm_identification(
                reg_conn, hostname, graph, target, target_manager
            )

            # Read component servers (discovers site system servers)
            _read_component_servers(
                reg_conn, hostname, graph, ad_resolver, target,
                target_manager, domain, site_code,
            )

            # Read multisite component servers (discovers SQL database servers)
            _read_multisite_component_servers(
                reg_conn, hostname, graph, ad_resolver, target,
                target_manager, domain, site_code, disable_possible_edges,
            )

            # Read current user
            _read_current_user(reg_conn, hostname, graph, ad_resolver, target, domain)

            # Read SMB signing settings
            _read_smb_signing(reg_conn, hostname, graph, target)

            # Read MSSQL EPA settings
            _read_mssql_epa(reg_conn, hostname, graph, target)

        finally:
            try:
                reg_conn.close()
            except Exception:
                pass
            conn.logoff()

    except Exception as e:
        logger.error(f"Remote Registry collection failed for {hostname}: {e}")

    logger.info(f"Remote Registry collection completed for {hostname}")


def _connect_smb(
    hostname: str,
    domain: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> Optional["SMBConnection"]:
    """Connect to target via SMB."""
    try:
        conn = SMBConnection(hostname, hostname, timeout=5)

        domain_part = domain.split(".")[0] if domain else ""
        if username and password:
            if "\\" in username:
                domain_part, user = username.split("\\", 1)
            else:
                user = username
            conn.login(user, password, domain_part)
        else:
            conn.login("", "", domain_part)

        return conn
    except Exception as e:
        logger.debug(f"SMB connection failed to {hostname}: {e}")
        return None


def _start_remote_registry_service(conn: "SMBConnection") -> bool:
    """Start the RemoteRegistry service if it's not running.

    .NET's OpenRemoteBaseKey auto-starts the service via SCM.
    We replicate this with impacket's scmr (Service Control Manager Remote)
    to match PS behavior.
    """
    try:
        from impacket.dcerpc.v5 import scmr

        rpc_transport = transport.SMBTransport(
            conn.getRemoteHost(),
            filename=r"\svcctl",
            smb_connection=conn,
        )
        rpc_transport.connect()
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)

        resp = scmr.hROpenSCManagerW(dce)
        sc_handle = resp["lpScHandle"]

        resp = scmr.hROpenServiceW(dce, sc_handle, "RemoteRegistry")
        svc_handle = resp["lpServiceHandle"]

        try:
            resp = scmr.hRQueryServiceStatus(dce, svc_handle)
            state = resp["lpServiceStatus"]["dwCurrentState"]
            if state != scmr.SERVICE_RUNNING:
                logger.debug("RemoteRegistry service not running, starting it...")
                scmr.hRStartServiceW(dce, svc_handle)
                import time
                time.sleep(2)
                return True
        finally:
            scmr.hRCloseServiceHandle(dce, svc_handle)
            scmr.hRCloseServiceHandle(dce, sc_handle)
    except Exception as e:
        logger.debug(f"Could not start RemoteRegistry service: {e}")
    return False


def _open_remote_registry(conn: "SMBConnection") -> Optional[Any]:
    """Open remote registry service via RPC."""
    try:
        rpc_transport = transport.SMBTransport(
            conn.getRemoteHost(),
            filename=r"\winreg",
            smb_connection=conn,
        )
        rpc_transport.connect()
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        # Open HKLM
        resp = rrp.hOpenLocalMachine(dce)
        root_key = resp["phKey"]

        return _RegistryHelper(dce, root_key)
    except Exception:
        # Service might not be running — try to start it and retry
        try:
            _start_remote_registry_service(conn)
            rpc_transport = transport.SMBTransport(
                conn.getRemoteHost(),
                filename=r"\winreg",
                smb_connection=conn,
            )
            rpc_transport.connect()
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            resp = rrp.hOpenLocalMachine(dce)
            root_key = resp["phKey"]

            return _RegistryHelper(dce, root_key)
        except Exception as e:
            logger.debug(f"Remote registry open failed (even after service start): {e}")
            return None


class _RegistryHelper:
    """Helper class for reading remote registry keys."""

    def __init__(self, dce, root_key):
        self.dce = dce
        self.root_key = root_key

    def read_value(self, key_path: str, value_name: str) -> Optional[str]:
        """Read a registry value."""
        try:
            resp = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)
            sub_key = resp["phkResult"]
            try:
                resp = rrp.hBaseRegQueryValue(self.dce, sub_key, value_name)
                value = resp[1]
                if isinstance(value, bytes):
                    value = value.decode("utf-16-le")
                # Strip null terminators and whitespace
                # impacket's unpackValue for REG_SZ returns decoded strings
                # with embedded null terminators that prevent .strip() from
                # removing trailing whitespace
                result = str(value).rstrip("\x00").strip()
                return result
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub_key)
        except Exception:
            return None

    def read_dword(self, key_path: str, value_name: str) -> Optional[int]:
        """Read a DWORD registry value."""
        try:
            resp = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)
            sub_key = resp["phkResult"]
            try:
                resp = rrp.hBaseRegQueryValue(self.dce, sub_key, value_name)
                value = resp[1]
                if isinstance(value, int):
                    return value
                if isinstance(value, bytes) and len(value) >= 4:
                    import struct
                    return struct.unpack("<I", value[:4])[0]
                return int(value) if value else None
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub_key)
        except Exception:
            return None

    def enum_keys(self, key_path: str) -> Optional[list[str]]:
        """Enumerate subkeys of a registry key.

        Returns:
            List of subkey names if key exists, or None if key doesn't exist.
            This distinction matters: an empty list means the key exists but
            has no subkeys (e.g., local SQL server), while None means the key
            itself doesn't exist.
        """
        try:
            resp = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)
            sub_key = resp["phkResult"]
            try:
                keys = []
                i = 0
                while True:
                    try:
                        resp = rrp.hBaseRegEnumKey(self.dce, sub_key, i)
                        name = resp["lpNameOut"]
                        if isinstance(name, bytes):
                            name = name.decode("utf-16-le")
                        keys.append(str(name).rstrip("\x00").strip())
                        i += 1
                    except Exception:
                        break
                return keys
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub_key)
        except Exception:
            return None

    def close(self):
        """Close the registry connection."""
        try:
            rrp.hBaseRegCloseKey(self.dce, self.root_key)
            self.dce.disconnect()
        except Exception:
            pass


def _read_sccm_identification(
    reg: _RegistryHelper,
    hostname: str,
    graph: GraphStore,
    target: CollectionTarget,
    target_manager: TargetManager,
) -> Optional[str]:
    """Read SCCM site identification from registry. Returns site code or None."""
    # Read site code
    site_code = reg.read_value(
        SCCM_REG_KEYS["triggers"],
        "Site Code"
    )
    if site_code:
        site_code = site_code.strip()
        logger.info(f"Found SCCM site code in registry: {site_code}")
        graph.upsert_node(
            site_code,
            ["SCCM_Site"],
            properties={
                "collectionSource": ["RemoteRegistry-Identification"],
                "SCCMInfra": True,
                "siteCode": site_code,
            },
        )

        if target.sid:
            graph.upsert_node(
                target.sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["RemoteRegistry-Identification"],
                    "SCCMInfra": True,
                },
                ad_object=target.ad_object,
            )

    return site_code


def _read_component_servers(
    reg: _RegistryHelper,
    hostname: str,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target: CollectionTarget,
    target_manager: TargetManager,
    domain: str,
    site_code: Optional[str],
) -> None:
    """
    Discover component servers from registry and add as collection targets.

    Translated from PowerShell Invoke-RemoteRegistryCollection (lines 4753-4822).
    Reads SMS_SITE_COMPONENT_MANAGER\\Component Servers subkeys to discover
    site system servers (passive site servers, SCPs, etc.).
    """
    component_servers = reg.enum_keys(SCCM_REG_KEYS["component_servers"])
    if component_servers is None or len(component_servers) == 0:
        logger.debug(f"No component servers found on {hostname}")
        return

    for server_fqdn in component_servers:
        if not server_fqdn:
            continue

        logger.debug(f"Found component server on {hostname}: {server_fqdn}")

        # Resolve to AD object and add as collection target
        ad_obj = ad_resolver.resolve_principal(server_fqdn)
        sid = None
        if ad_obj:
            sid = ad_obj.get("SID") or ad_obj.get("objectSid")
            if isinstance(sid, bytes):
                sid = ad_resolver._sid_bytes_to_string(sid)

        target_manager.add_device(
            device_name=server_fqdn,
            source="RemoteRegistry-ComponentServer",
            ad_object=ad_obj,
        )

        # Create Computer node for component server
        if sid:
            sam = ad_obj.get("sAMAccountName", "") if ad_obj else ""
            graph.upsert_node(
                sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["RemoteRegistry-ComponentServer"],
                    "name": sam,
                    "SCCMInfra": True,
                    "SCCMSiteSystemRoles": [f"SMS Component Server@{site_code}"] if site_code else [],
                },
                ad_object=ad_obj,
            )

    # If we found component servers, this host is a site server
    if component_servers and site_code and target.sid:
        graph.upsert_node(
            target.sid,
            ["Computer", "Base"],
            properties={
                "collectionSource": ["RemoteRegistry-ComponentServer"],
                "SCCMInfra": True,
                "SCCMSiteSystemRoles": [f"SMS Site Server@{site_code}"],
            },
            ad_object=target.ad_object,
        )


def _read_multisite_component_servers(
    reg: _RegistryHelper,
    hostname: str,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target: CollectionTarget,
    target_manager: TargetManager,
    domain: str,
    site_code: Optional[str],
    disable_possible_edges: bool = False,
) -> None:
    """
    Discover SQL database servers from registry multisite component servers.

    Translated from PowerShell Invoke-RemoteRegistryCollection (lines 4824-4960).
    Reads SMS_SITE_COMPONENT_MANAGER\\Multisite Component Servers subkeys.
    If empty, the site database is local. If populated, the entries are remote SQL servers.
    Creates MSSQL node hierarchy (MSSQL_Server, Database, Login, etc.).
    """
    if not site_code:
        return

    site_node = graph.get_node(site_code)
    if not site_node:
        return

    multisite_servers = reg.enum_keys(SCCM_REG_KEYS["multisite_components"])

    if multisite_servers is None or len(multisite_servers) == 0:
        # Key doesn't exist or is empty — no SQL server info available.
        # Note: In PowerShell, the "local DB" branch ($multisiteResult.Count -eq 0) is
        # unreachable because PS treats empty arrays as falsey. We match PS behavior by
        # treating both null and empty the same way.
        logger.debug(f"No site database server found in multisite component servers on {hostname}")
        return

    # Remote SQL database servers
    if len(multisite_servers) == 1:
        logger.debug(f"Found single remote site database server: {multisite_servers[0]}")
    else:
        logger.debug(f"Found clustered site database servers: {', '.join(multisite_servers)}")

    for sql_fqdn in multisite_servers:
        if not sql_fqdn:
            continue

        # Resolve to AD computer object (these are always computer hostnames)
        ad_obj = ad_resolver.get_ad_computer(sql_fqdn)
        sql_sid = None
        if ad_obj:
            sql_sid = ad_obj.get("SID") or ad_obj.get("objectSid")
            if isinstance(sql_sid, bytes):
                sql_sid = ad_resolver._sid_bytes_to_string(sql_sid)

        # Add as collection target
        target_manager.add_device(
            device_name=sql_fqdn,
            source="RemoteRegistry-MultisiteComponentServers",
            ad_object=ad_obj,
        )

        if sql_sid:
            sam = ad_obj.get("sAMAccountName", "") if ad_obj else ""
            graph.upsert_node(
                sql_sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": ["RemoteRegistry-MultisiteComponentServers"],
                    "name": sam,
                    "SCCMInfra": True,
                    "SCCMSiteSystemRoles": [f"SMS SQL Server@{site_code}"],
                },
                ad_object=ad_obj,
            )

            # Create MSSQL hierarchy
            _add_mssql_hierarchy_from_registry(
                graph, site_node, sql_sid, ad_obj,
                sql_fqdn, site_code, disable_possible_edges,
            )


def _add_mssql_hierarchy_from_registry(
    graph: GraphStore,
    site_node: dict,
    sql_computer_sid: str,
    sql_ad_object: Optional[dict],
    sql_hostname: str,
    site_code: str,
    disable_possible_edges: bool = False,
) -> None:
    """
    Create MSSQL node hierarchy from registry-discovered SQL server.

    Translated from PowerShell Add-MSSQLServerNodesAndEdges (lines 6050-6185).
    Creates MSSQL_Server, sysadmin role, and basic edges.
    Database/login/user nodes are created if the server is confirmed as a site DB.
    """
    site_props = site_node.get("properties", {})
    site_type = site_props.get("siteType")
    if site_type and str(site_type).lower() in ("secondary site", "3"):
        logger.debug(f"Skipping MSSQL hierarchy for secondary site {site_code}")
        return

    sql_db_name = site_props.get("SQLDatabaseName") or f"CM_{site_code}"
    port = site_props.get("SQLServicePort") or 1433
    server_id = f"{sql_computer_sid}:{port}"
    source = ["RemoteRegistry-MultisiteComponentServers"]

    dns_name = ""
    if sql_ad_object:
        dns_name = sql_ad_object.get("dNSHostName", sql_hostname)
    else:
        dns_name = sql_hostname

    # MSSQL_Server node
    graph.upsert_node(server_id, ["MSSQL_Server"], properties={
        "collectionSource": source,
        "databases": [sql_db_name],
        "name": f"{dns_name}:{port}",
        "dnsHostName": dns_name,
        "SQLServicePort": port,
        "SCCMInfra": True,
        "SCCMSite": site_code,
    })

    # sysadmin server role
    sysadmin_id = f"sysadmin@{server_id}"
    graph.upsert_node(sysadmin_id, ["MSSQL_ServerRole"], properties={
        "collectionSource": source,
        "isFixedRole": True,
        "name": "sysadmin",
        "SCCMSite": site_code,
        "SQLServer": dns_name,
    })

    # Edges: Server <-> sysadmin, Computer <-> Server
    graph.upsert_edge(server_id, sysadmin_id, "MSSQL_Contains",
                       properties={"collectionSource": source})
    graph.upsert_edge(sysadmin_id, server_id, "MSSQL_ControlServer",
                       properties={"collectionSource": source})
    graph.upsert_edge(sql_computer_sid, server_id, "MSSQL_HostFor",
                       properties={"collectionSource": source})
    graph.upsert_edge(server_id, sql_computer_sid, "MSSQL_ExecuteOnHost",
                       properties={"collectionSource": source})

    # Database-level nodes require confirmed site database
    # (from RemoteRegistry-MultisiteComponentServers or without DisablePossibleEdges)
    comp_node = graph.get_node(sql_computer_sid)
    comp_sources = (comp_node or {}).get("properties", {}).get("collectionSource", [])
    is_confirmed = "RemoteRegistry-MultisiteComponentServers" in comp_sources

    if disable_possible_edges and not is_confirmed:
        logger.debug(f"Skipping MSSQL database nodes for {sql_hostname} "
                     f"(not confirmed from registry, DisablePossibleEdges is on)")
        return

    db_id = f"{server_id}\\{sql_db_name}"

    # MSSQL_Database
    graph.upsert_node(db_id, ["MSSQL_Database"], properties={
        "collectionSource": source,
        "isTrustworthy": True,
        "name": sql_db_name,
        "SCCMInfra": True,
        "SCCMSite": site_code,
        "SQLServer": dns_name,
    })

    # db_owner role
    db_owner_id = f"db_owner@{db_id}"
    graph.upsert_node(db_owner_id, ["MSSQL_DatabaseRole"], properties={
        "collectionSource": source,
        "database": sql_db_name,
        "isFixedRole": True,
        "name": "db_owner",
        "SCCMSite": site_code,
        "SQLServer": dns_name,
    })

    # Edges: Server -> Database, Database -> db_owner, db_owner -> Database (control)
    graph.upsert_edge(server_id, db_id, "MSSQL_Contains",
                       properties={"collectionSource": source})
    graph.upsert_edge(db_id, db_owner_id, "MSSQL_Contains",
                       properties={"collectionSource": source})
    graph.upsert_edge(db_owner_id, db_id, "MSSQL_ControlDB",
                       properties={"collectionSource": source})

    # SCCM_AssignAllPermissions: Database -> site
    # Note: PS calls Get-SitesInHierarchy here but at collection time
    # SCCM_AdminsReplicatedTo edges don't exist yet, so it only returns
    # the starting site. Post-processing handles broader hierarchy edges.
    graph.upsert_edge(db_id, site_code, "SCCM_AssignAllPermissions",
                       properties={"collectionSource": source})


def _read_current_user(
    reg: _RegistryHelper,
    hostname: str,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target: CollectionTarget,
    domain: str,
) -> None:
    """Read current logged-on user from registry."""
    last_user = reg.read_value(
        SCCM_REG_KEYS["current_user"],
        "LastLoggedOnSAMUser"
    )

    if last_user:
        logger.info(f"Current/last user on {hostname}: {last_user}")

        # Resolve user
        user_obj = ad_resolver.resolve_principal(last_user)
        if user_obj:
            user_sid = user_obj.get("SID") or user_obj.get("objectSid")
            if isinstance(user_sid, bytes):
                user_sid = ad_resolver._sid_bytes_to_string(user_sid)

            if user_sid and target.sid:
                sam = user_obj.get("sAMAccountName", last_user.split("\\")[-1])
                graph.upsert_node(
                    user_sid,
                    ["User", "Base"],
                    properties={
                        "sAMAccountName": sam,
                        "name": sam,
                    },
                    ad_object=user_obj,
                )
                # HasSession: Computer -> User
                graph.upsert_edge(target.sid, user_sid, "HasSession")


def _read_smb_signing(
    reg: _RegistryHelper,
    hostname: str,
    graph: GraphStore,
    target: CollectionTarget,
) -> None:
    """Read SMB signing settings from registry."""
    # Check server-side SMB signing
    require_signing = reg.read_dword(
        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "RequireSecuritySignature"
    )

    if require_signing is not None:
        signing_required = require_signing == 1
        logger.info(f"SMB signing required on {hostname}: {signing_required} (via registry)")

        if target.sid:
            graph.upsert_node(
                target.sid,
                ["Computer", "Base"],
                properties={
                    "SMBSigningRequired": signing_required,
                    "collectionSource": ["RemoteRegistry-SMBSigning"],
                },
            )


def _read_mssql_epa(
    reg: _RegistryHelper,
    hostname: str,
    graph: GraphStore,
    target: Optional[CollectionTarget] = None,
) -> None:
    """
    Read MSSQL EPA settings from registry.

    Translated from PowerShell Get-MssqlEpaSettingsViaRemoteRegistry (lines 2810-2961).
    """
    # Check for SQL Server registry key
    epa_value = reg.read_dword(
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",
        "ExtendedProtection"
    )

    if epa_value is None:
        # Try other SQL Server versions
        for version in ["15", "14", "13", "12"]:
            epa_value = reg.read_dword(
                f"SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL{version}.MSSQLSERVER\\MSSQLServer\\SuperSocketNetLib",
                "ExtendedProtection"
            )
            if epa_value is not None:
                break

    if epa_value is not None:
        # EPA values: 0=Off, 1=Allowed, 2=Required
        epa_labels = {0: "Off", 1: "Allowed", 2: "Required"}
        epa_label = epa_labels.get(epa_value, f"Unknown({epa_value})")
        logger.info(f"MSSQL EPA on {hostname}: {epa_label}")

        # Update MSSQL_Server node if it exists
        # Try SID-based ID first (preferred), then hostname-based
        server_node = None
        if target and target.sid:
            server_id = f"{target.sid}:1433"
            server_node = graph.get_node(server_id)
        if not server_node:
            server_id = f"{hostname}:1433"
            server_node = graph.get_node(server_id)
        if not server_node:
            # Search all MSSQL_Server nodes for matching hostname
            for srv in graph.find_nodes_by_kind("MSSQL_Server"):
                srv_props = srv.get("properties", {})
                if srv_props.get("dnsHostName", "").lower() == hostname.lower() or \
                   srv_props.get("hostFQDN", "").lower() == hostname.lower():
                    server_node = srv
                    break
        if server_node:
            server_node.setdefault("properties", {})["mssqlExtendedProtectionForAuthentication"] = epa_value == 0
            server_node["properties"]["mssqlEPAValue"] = epa_value
            server_node["properties"]["collectionSource"] = server_node["properties"].get("collectionSource", []) + ["RemoteRegistry-EPA"]
