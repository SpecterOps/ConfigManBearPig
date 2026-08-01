import socket
import time
from typing import Iterable, Any, Optional

from ..clients.smb import negotiated_signing_required
from ..clients.smb_sso import connect_smb
from ..context import SourceContext
from ..log_context import get_logger

logger = get_logger(__name__)


def _roles(bases: list[str], site_code: Optional[str]) -> list[str]:
    """Site-system role strings as a LIST, each suffixed ``@<site_code>`` when known.

    Always returns a list (even for a single role) so dlt types
    ``sccm_site_system_roles`` consistently across every RemoteRegistry row.
    Previously some rows emitted a bare string and others a list for the same
    column; under the freeze contract that collapsed the column to JSON-array text
    inside a VARCHAR (which the preproc role normaliser then had to parse back out).
    Mirrors smb.py's ``_role`` helper but list-valued.
    """
    suffix = f"@{site_code}" if site_code else ""
    return [f"{base}{suffix}" for base in bases]


# Registry key paths for SCCM. The two groups differ in the access they need, which is
# what makes RemoteRegistry useful at low privilege: everything that identifies the site
# and its roles is readable without local admin, and only the host-hardening values are
# gated. Keep the split when adding a key -- the README documents this distinction under
# "Privileges needed per phase".
SCCM_REG_KEYS = {
    # Readable by any authenticated AD user with SMB access to the host.
    "triggers": r"SOFTWARE\Microsoft\SMS\Triggers",
    "component_servers": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers",
    "multisite_component_servers": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers",
    "current_user": r"SOFTWARE\Microsoft\SMS\CurrentUser",
    # Require local Administrators on the target (see get_ntlm_settings /
    # get_mssql_settings, which log an error and continue when denied). The SQL Server
    # SuperSocketNetLib paths those functions build are admin-gated for the same reason.
    "lanmanserver_parameters": r"SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
    "msv10": r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
    "lsa": r"SYSTEM\CurrentControlSet\Control\Lsa"
}


# RemoteRegistry is trigger-started on modern Windows: the first \winreg pipe
# open wakes the service but races against it actually listening, so the first
# bind often returns STATUS_PIPE_NOT_AVAILABLE. Retry briefly to let the service
# finish starting -- this mirrors what the native OpenRemoteBaseKey client (used
# by the original PowerShell) does internally.
WINREG_BIND_RETRIES = 3
WINREG_BIND_RETRY_DELAY = 1.5


class _RegistryProbe:
    """Lightweight remote-registry helper used by the registry resources.

    Wraps an SMB connection + a winreg DCE/RPC binding.
    """

    def __init__(self, hostname: str, domain: str, username: Optional[str], password: Optional[str],
                 nt_hash: Optional[str] = None, kerberos_ticket: Optional[str] = None,
                 kdc_host: Optional[str] = None) -> None:
        self.hostname = hostname
        self.domain = domain
        self.username = username
        self.password = password
        self.nt_hash = nt_hash
        self.kerberos_ticket = kerberos_ticket
        self.kdc_host = kdc_host
        self.smb = None
        self.dce = None
        self.root_key = None

    def __enter__(self) -> Optional["_RegistryProbe"]:
        # Fast TCP probe to avoid 30-second SMB timeouts on dead hosts.
        logger.verbose("Probing Remote Registry on %s (port 445)", self.hostname)
        try:
            with socket.create_connection((self.hostname, 445), timeout=3):
                pass
        except (socket.timeout, ConnectionRefusedError, OSError) as ex:
            logger.verbose("SMB/445 not reachable on %s: %s", self.hostname, ex)
            return None

        try:
            from impacket.dcerpc.v5 import rrp, transport
            from impacket.nt_errors import STATUS_PIPE_NOT_AVAILABLE
            from impacket.smbconnection import SessionError
        except ImportError:
            logger.warning("impacket not installed; skipping host %s", self.hostname)
            return None

        smb = connect_smb(
            self.hostname, self.domain, self.username, self.password,
            nt_hash=self.nt_hash, kerberos_ticket=self.kerberos_ticket, kdc_host=self.kdc_host,
        )
        if smb is None:
            return None
        self.smb = smb

        # Bind to the \winreg pipe, retrying only the trigger-start race. On any
        # exit we leave self.smb set so __exit__ performs exactly one logoff --
        # logging off here too would delete the session twice and raise a
        # spurious STATUS_USER_SESSION_DELETED.
        for attempt in range(1, WINREG_BIND_RETRIES + 1):
            try:
                rpc = transport.SMBTransport(smb.getRemoteHost(), filename=r"\winreg", smb_connection=smb)
                rpc.connect()
                dce = rpc.get_dce_rpc()
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)
                resp = rrp.hOpenLocalMachine(dce)
                self.dce = dce
                self.root_key = resp["phKey"]
                logger.verbose("Remote Registry bind to %s succeeded on attempt %d", self.hostname, attempt)
                return self
            except SessionError as ex:
                # STATUS_PIPE_NOT_AVAILABLE means RemoteRegistry is still starting
                # (our open was the trigger); wait and retry. Other SMB errors
                # (access denied, service disabled, etc.) are not transient.
                if ex.getErrorCode() == STATUS_PIPE_NOT_AVAILABLE and attempt < WINREG_BIND_RETRIES:
                    logger.verbose(
                        "winreg pipe not listening yet on %s (attempt %d/%d); RemoteRegistry still starting, retrying in %.1fs",
                        self.hostname, attempt, WINREG_BIND_RETRIES, WINREG_BIND_RETRY_DELAY,
                    )
                    time.sleep(WINREG_BIND_RETRY_DELAY)
                    continue
                logger.verbose("winreg bind on %s failed: %s", self.hostname, ex)
                return None
            except Exception as ex:  # noqa: BLE001
                # Most common cause: RemoteRegistry service not running, or no perm.
                logger.verbose("winreg bind on %s failed: %s", self.hostname, ex)
                return None

        # Unreachable while WINREG_BIND_RETRIES >= 1: every path in the loop body returns,
        # and the retry branch cannot be taken on the final attempt. Explicit so the
        # contract does not depend on a constant defined elsewhere staying positive.
        logger.error("winreg bind on %s made no attempts (WINREG_BIND_RETRIES=%d)",
                     self.hostname, WINREG_BIND_RETRIES)
        return None

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            if self.dce is not None:
                logger.verbose("Disconnecting Remote Registry on %s", self.hostname)
                self.dce.disconnect()
        except Exception as ex:
            logger.error("Failed to disconnect DCE/RPC on %s: %s", self.hostname, ex)
            pass
        try:
            if self.smb is not None:
                logger.verbose("Logging off SMB on %s", self.hostname)
                self.smb.logoff()
        except Exception as ex:
            logger.error("Failed to log off SMB on %s: %s", self.hostname, ex)
            pass

    # ----- read helpers ------------------------------------------------------

    def read_value(self, key_path: str, value_name: str) -> Optional[str]:
        from impacket.dcerpc.v5 import rrp
        logger.verbose("Reading value %s under %s", value_name, key_path)
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
                if isinstance(value, bytes):
                    value = value.decode("utf-16-le", errors="replace")
                return str(value).rstrip("\x00").strip()
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except rrp.DCERPCException as ex:
            if "ERROR_FILE_NOT_FOUND" in str(ex):
                logger.verbose("DWORD value %s not found under %s on %s", value_name, key_path, self.hostname)
            else:
                logger.error("Failed to read DWORD value %s under %s on %s: %s", value_name, key_path, self.hostname, ex)
            return None
        except Exception as ex:
            logger.error("Failed to read registry value %s under %s on %s: %s", value_name, key_path, self.hostname, ex)
            return None

    def read_dword(self, key_path: str, value_name: str) -> Optional[int]:
        from impacket.dcerpc.v5 import rrp
        logger.verbose("Reading DWORD value %s under %s on %s", value_name, key_path, self.hostname)
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
                if isinstance(value, int):
                    return value
                if isinstance(value, bytes) and len(value) >= 4:
                    import struct
                    return struct.unpack("<I", value[:4])[0]
                return int(value) if value else None
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except rrp.DCERPCException as ex:
            if "ERROR_FILE_NOT_FOUND" in str(ex):
                logger.verbose("DWORD value %s not found under %s on %s", value_name, key_path, self.hostname)
            else:
                logger.error("Failed to read DWORD value %s under %s on %s: %s", value_name, key_path, self.hostname, ex)
            return None
        except Exception as ex:
            logger.error("Failed to read DWORD value %s under %s on %s: %s", value_name, key_path, self.hostname, ex)
            return None

    def enum_keys(self, key_path: str) -> Optional[list[str]]:
        from impacket.dcerpc.v5 import rrp
        logger.verbose("Enumerating subkeys under %s", key_path)
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                names: list[str] = []
                i = 0
                while True:
                    try:
                        resp = rrp.hBaseRegEnumKey(self.dce, sub, i)
                    except Exception:
                        break  # ERROR_NO_MORE_ITEMS: normal end of enumeration
                    # lpNameOut is an RRP_UNICODE_STRING wrapper; the subkey name is
                    # its Data field. Calling str() on the wrapper itself raises
                    # "__str__ returned non-string (type bytes)". Mirrors read_values().
                    name_field = resp["lpNameOut"]
                    try:
                        name = name_field["Data"]
                    except (KeyError, TypeError):
                        name = name_field
                    if isinstance(name, bytes):
                        name = name.decode("utf-16-le", errors="replace")
                    names.append(str(name).rstrip("\x00").strip())
                    i += 1
                return names
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except rrp.DCERPCException as ex:
            if "ERROR_FILE_NOT_FOUND" in str(ex):
                logger.verbose("Registry key %s not found on %s", key_path, self.hostname)
            else:
                logger.error("Failed to open registry key %s on %s: %s", key_path, self.hostname, ex)
            return None
        except Exception as ex:
            logger.verbose("Failed to enumerate subkeys under %s: %s", key_path, ex)
            return None

    def read_values(self, key_path: str) -> Optional[list[tuple[str, str]]]:
        """Return a list of ``(value_name, value_data)`` pairs under *key_path*.

        Used for keys where the *names* are unknown — e.g. SCCM's
        ``SMS\\CurrentUser`` key, which uses arbitrary value names whose
        contents are SIDs. Returns ``None`` if the key can't be opened;
        an empty list if the key exists but has no values.

        ``hBaseRegEnumValue`` returns ``lpType`` + a list-of-byte ``lpData``
        buffer; impacket's ``unpackValue(type, data)`` decodes both REG_SZ
        and REG_MULTI_SZ to a Python str. impacket's NDR layer auto-unwraps
        ``lpValueNameOut`` to the value name as a plain Python str, so we use
        it directly.
        """
        from impacket.dcerpc.v5 import rrp
        logger.verbose("Enumerating values under %s", key_path)
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                out: list[tuple[str, str]] = []
                i = 0
                while True:
                    try:
                        resp = rrp.hBaseRegEnumValue(self.dce, sub, i)
                    except Exception:
                        break  # ERROR_NO_MORE_ITEMS: normal end of enumeration
                    # impacket's NDR auto-unwraps lpValueNameOut to a Python str (the
                    # field carries a 'Data' subfield), so name_field["Data"] raises
                    # TypeError -- the str itself is the value name. Mirrors enum_keys().
                    name_field = resp["lpValueNameOut"]
                    try:
                        raw_name = name_field["Data"]
                    except (KeyError, TypeError):
                        raw_name = name_field
                    if isinstance(raw_name, bytes):
                        raw_name = raw_name.decode("utf-16-le", errors="replace")
                    name = str(raw_name).rstrip("\x00").strip()
                    # Decode the value data via impacket's helper, which
                    # handles the byte-array-of-byte-structures shape and
                    # type-specific decoding (REG_SZ → str, REG_DWORD → int).
                    try:
                        value_type = resp["lpType"]
                        raw_data = resp["lpData"]
                        decoded = rrp.unpackValue(value_type, raw_data)
                    except Exception as ex:
                        logger.error("Failed to decode value %r at index %d under %s: %s", name, i, key_path, ex)
                        decoded = ""
                    if isinstance(decoded, bytes):
                        decoded = decoded.decode("utf-16-le", errors="replace")
                    data = str(decoded).rstrip("\x00").strip()
                    out.append((name, data))
                    i += 1
                return out
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except rrp.DCERPCException as ex:
            if "ERROR_FILE_NOT_FOUND" in str(ex):
                logger.verbose("Registry key %s not found on %s", key_path, self.hostname)
            else:
                logger.error("Failed to open registry key %s on %s: %s", key_path, self.hostname, ex)
            return None
        except Exception as ex:
            logger.error("Failed to open registry key %s: %s", key_path, ex)
            return None


def collect_registry(target: str, ctx: "SourceContext") -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield one row per (host, role) discovered via remote registry.

    For each host with SMB/445 + RemoteRegistry reachable, reads SCCM_REG_KEYS.

    A successful read (even if the keys are empty) implies this host is the
    SCCM site server.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return

    logger.info("Starting Remote Registry collection on %s...", target)

    # Pass the full credential set so the SMB bind honors password, pass-the-hash
    # (--nt-hash), pass-the-ticket (--ticket), current-user SSPI, or null session.
    creds = getattr(getattr(ctx, "ad", None), "creds", None)
    with _RegistryProbe(
        target, ctx.domain, ctx.username, ctx.password,
        nt_hash=getattr(ctx, "nt_hash", None),
        kerberos_ticket=getattr(ctx, "kerberos_ticket", None),
        kdc_host=getattr(creds, "domain_controller", None),
    ) as probe:
        if probe is None:
            logger.info("Could not connect to %s for registry queries", target)
        else:
            # First because it exists on other site system roles, not just site servers
            yield from get_current_user(probe, ctx)

            # Next because it requires local Administrators privileges to collect but does not require the system to be an SCCM site server
            yield from get_ntlm_settings(probe, ctx)
            yield from get_mssql_settings(probe, ctx)
            
            # Then check for the SCCM site code, which identifies this host as an SCCM site server 
            # and is needed to interpret the component server roles. If the site code key is missing or empty, 
            # skip the remaining checks because they only exist on site servers.
        
            # HKLM\SOFTWARE\Microsoft\SMS\Triggers
            logger.verbose("Querying %s for SCCM site code", SCCM_REG_KEYS["triggers"])
            subkeys = probe.enum_keys(SCCM_REG_KEYS["triggers"])
            if subkeys and len(subkeys) > 1:
                logger.warning("Multiple site codes found under %s: %s", SCCM_REG_KEYS["triggers"], subkeys)
            site_code = subkeys[0] if subkeys else None
            if site_code:
                logger.info("Found SCCM site code: %s", site_code)
                yield "remoteregistry_sites", {
                    "source": "RemoteRegistry-Triggers",
                    "site_code": site_code,
                }
            else:
                logger.info("%s does not exist or no site code subkey found, skipping remaining Remote Registry checks", SCCM_REG_KEYS["triggers"])
                logger.info("Remote Registry collection completed for %s", target)
                return


            # HKLM\SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers
            logger.verbose("Querying %s for SCCM component servers", SCCM_REG_KEYS["component_servers"])
            subkeys = probe.enum_keys(SCCM_REG_KEYS["component_servers"])

            if subkeys:
                # Now we know this target is a site server
                # Spread every resolved AD attribute (dNSHostName, name,
                # sAMAccountName, object_sid, cn, ...) into the row, then
                # layer the registry-derived fields on top. AD `name`
                # flows through from ad_object; fall back to the raw
                # server name only when AD resolution failed (ad_object
                # is None or lacks a name).
                logger.info("Found %s, this target is a site server", SCCM_REG_KEYS["component_servers"])
                target_entry = ctx.target_hosts_by_hostname[target]
                row = {
                    **(target_entry.ad_object or {}),
                    "source": "RemoteRegistry-ComponentServers",
                    "sccm_infra": True,
                    "sccm_site_system_roles": _roles(["SMS Site Server"], site_code),
                }
                row.setdefault("name", target)
                yield "remoteregistry_computers", row

                for i, server in enumerate(subkeys):
                    logger.info("Found component server #%d: %s", i + 1, server)

                    new_target = ctx.register_target(
                        identifier=server,
                        source="RemoteRegistry-ComponentServers",
                    )

                    if new_target:
                        row = {
                            **(new_target.ad_object or {}),
                            "source": "RemoteRegistry-ComponentServers",
                            "sccm_infra": True,
                            "sccm_site_system_roles": _roles(["SMS Component Server"], site_code),
                        }
                        row.setdefault("name", server)
                        yield "remoteregistry_computers", row
                    # No else: register_target logs why it skipped (filtered host
                    # or empty name), so a None return isn't a failure here.
            else:
                logger.verbose("No component servers found under %s", SCCM_REG_KEYS["component_servers"])
            

            # HKLM\SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers
            logger.verbose("Querying %s for SCCM multisite component servers", SCCM_REG_KEYS["multisite_component_servers"])
            subkeys = probe.enum_keys(SCCM_REG_KEYS["multisite_component_servers"])

            if subkeys is None:
                # Key absent: nothing to record
                logger.verbose("No Multisite Component Servers key on %s", target)
            elif len(subkeys) == 0:
                # Key present but empty: on a standalone primary site server this
                # means the site database is local, so the host carries both the
                # SQL Server and Site Server roles.
                #
                # But a PASSIVE site server has the same empty key while the site
                # database lives elsewhere, so the SQL half is an inference, not a
                # confirmation -- taken at face value it invents a SQL server
                # (con-be15: ps1-psv, which runs no SQL, gained a spurious
                # MSSQL_Server node and inflated every dependent MSSQL count).
                #
                # We cannot settle it here: the SQL Server registry keys are
                # admin-gated (access-denied for a plain domain user) and the
                # MSSQLSvc SPN lives on the service account, not the host -- a real
                # site database running as LocalSystem has none. The 1433 probe that
                # *would* settle it belongs to the MSSQL phase, which runs after
                # RemoteRegistry. So emit the role and flag it, and let preprocess
                # decide once every source has landed (_assumed_site_dbs).
                logger.info(
                    "Multisite Component Servers is empty on %s: the site database is "
                    "local to this site server, OR this is a passive site server whose "
                    "database lives elsewhere. Emitting the SQL Server role as assumed "
                    "pending corroboration in preprocess.", target,
                )
                target_entry = ctx.target_hosts_by_hostname[target]
                row = {
                    **(target_entry.ad_object or {}),
                    "source": "RemoteRegistry-MultisiteComponentServers",
                    "sccm_infra": True,
                    "sccm_site_system_roles": _roles(["SMS SQL Server", "SMS Site Server"], site_code),
                    # Read by _assumed_site_dbs: the Site Server half is confirmed,
                    # the SQL Server half needs a live-SQL signal to survive.
                    "sql_role_assumed": True,
                }
                row.setdefault("name", target)
                yield "remoteregistry_computers", row
            else:
                # One or more remote site database servers, each a SQL Server
                if len(subkeys) == 1:
                    logger.info("Found single remote site database server: %s", subkeys[0])
                else:
                    logger.info("Found clustered remote site database servers: %s", ", ".join(subkeys))

                for server in subkeys:
                    new_target = ctx.register_target(
                        identifier=server,
                        source="RemoteRegistry-MultisiteComponentServers",
                    )
                    if new_target:
                        row = {
                            **(new_target.ad_object or {}),
                            "source": "RemoteRegistry-MultisiteComponentServers",
                            "sccm_infra": True,
                            "sccm_site_system_roles": _roles(["SMS SQL Server"], site_code),
                        }
                        row.setdefault("name", server)
                        yield "remoteregistry_computers", row
                    # No else: register_target logs why it skipped (filtered host
                    # or empty name), so a None return isn't a failure here.

    logger.info("Remote Registry collection completed for %s", target)


def get_current_user(probe: _RegistryProbe, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """
    The logged-in user's domain SID is the data of the value named "UserSID".
    Select it by name (not by enumeration position) so the sibling "Session"
    DWORD can never be mistaken for the SID — the order in which the registry
    hands back the two values is not guaranteed.
    """
    logger.verbose("Querying %s for logged-in user's domain SID", SCCM_REG_KEYS["current_user"])
    values = probe.read_values(SCCM_REG_KEYS["current_user"])

    current_user_sid = None
    if values is None:
        # read_values returns None only when the key can't be opened.
        logger.error("Error querying %s", SCCM_REG_KEYS["current_user"])
    else:
        current_user_sid = next(
            (data for name, data in values if name.lower() == "usersid" and data),
            None,
        )
        if not current_user_sid:
            # Key present but no logged-in user recorded — not an error.
            logger.verbose("No UserSID value under %s", SCCM_REG_KEYS["current_user"])

    if current_user_sid:
        logger.verbose("Found CurrentUser SID %s; resolving principal", current_user_sid)
        current_user_ad_object = ctx.resolve_principal(current_user_sid)
        if current_user_ad_object:
            logger.info("Found current user: %s (%s)", current_user_ad_object.get("sam_account_name"), current_user_sid)
            target_entry = ctx.target_hosts_by_hostname.get(probe.hostname)
            host_sid = target_entry.ad_object.get("object_sid") if (target_entry and target_entry.ad_object) else None
            if host_sid is None:
                # No resolved host AD object — HasSession can't be built for this row downstream; keep the row but log.
                logger.warning("Current-user row for %s has no host object_sid; HasSession will be dropped downstream", probe.hostname)
            row = {
                **(current_user_ad_object or {}),
                "source": "RemoteRegistry-CurrentUser",
                "host_object_sid": host_sid,
            }
            row.setdefault("object_sid", current_user_sid)
            yield "remoteregistry_users", row
        else:
            logger.warning("Failed to resolve current user SID: %s", current_user_sid)


def get_ntlm_settings(probe: _RegistryProbe, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    # NTLM/MSSQL settings are next because they require local Administrators privileges 
    # to collect but do not require the system to be an SCCM site server
    signing_required = None
    signing_source = None
    restrict_receiving_ntlm_traffic = None
    disable_loopback_check = None

    logger.verbose("Querying %s for SMB signing requirements", SCCM_REG_KEYS["lanmanserver_parameters"])
    require_signing_reg = probe.read_dword(SCCM_REG_KEYS["lanmanserver_parameters"], "RequireSecuritySignature")

    if require_signing_reg is not None:
        signing_required = require_signing_reg == 1
        signing_source = "Registry"
        logger.verbose(f"SMB signing required (registry): {signing_required}")
    else:
        # Registry value absent: fall back to the signing requirement negotiated on
        # the SMB connection we already hold open (no extra round-trip). Mirrors
        # PS1's two-tier check -- registry RequireSecuritySignature first, SMB2
        # negotiate as the fallback (Get-SMBSigningRequiredFromRegistry, 5048).
        negotiated = negotiated_signing_required(probe.smb)
        if negotiated is not None:
            signing_required = negotiated
            signing_source = "SMB-Negotiate"
            logger.verbose(f"SMB signing required (negotiate fallback): {signing_required}")
        else:
            logger.verbose("SMB signing requirement undetermined on %s (no registry value, negotiate unavailable)", probe.hostname)

    logger.verbose("Querying %s for NTLM settings", SCCM_REG_KEYS["msv10"])
    ntlm_registry_value = probe.read_dword(SCCM_REG_KEYS["msv10"], "RestrictReceivingNTLMTraffic")
    if ntlm_registry_value is not None:
        if ntlm_registry_value == 0:
            restrict_receiving_ntlm_traffic = "Off"
        elif ntlm_registry_value == 1:
            restrict_receiving_ntlm_traffic = "Deny_All"
        elif ntlm_registry_value == 2:
            restrict_receiving_ntlm_traffic = "Deny_Inbound_Explicit"
        else:
            restrict_receiving_ntlm_traffic = f"Unknown ({ntlm_registry_value})"
        logger.verbose(f"Found RestrictReceivingNTLMTraffic setting: {restrict_receiving_ntlm_traffic}")

    logger.verbose("Querying %s for LSA settings", SCCM_REG_KEYS["lsa"])
    disable_loopback_reg = probe.read_dword(SCCM_REG_KEYS["lsa"], "DisableLoopbackCheck")
    if disable_loopback_reg is not None:
        disable_loopback_check = disable_loopback_reg == 1
        logger.verbose(f"DisableLoopbackCheck is {'enabled' if disable_loopback_check else 'disabled'}")

    target_entry = ctx.target_hosts_by_hostname[probe.hostname]
    row = {
        **(target_entry.ad_object or {}),
        "source": "RemoteRegistry-NTLMSettings",
        "smb_signing_required": signing_required,
        "smb_signing_source": signing_source,
        "restrict_receiving_ntlm_traffic": restrict_receiving_ntlm_traffic,
        "disable_loopback_check": disable_loopback_check,
    }
    row.setdefault("name", target_entry.ad_object.get("name") if target_entry.ad_object else probe.hostname)
    yield "remoteregistry_computers", row


# SQL Server engine service control entries. The default instance's service is
# literally named MSSQLSERVER; a named instance is MSSQL$<InstanceName>.
MSSQL_SERVICE_KEY = r"SYSTEM\CurrentControlSet\Services\{service}"

# HKLM\...\Services\<svc>\Start. Note this is the STARTUP TYPE, not live running
# state -- only the service control manager knows that, and we are talking to the
# registry. Disabled is conclusive proof the engine is not running; Automatic only
# says it is meant to be. 0/1 (Boot/System) never apply to a SQL engine but are
# mapped for completeness rather than falling through to None.
MSSQL_START_TYPES = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}


def _mssql_service_name(instance_name: str) -> str:
    """Registry service name for a SQL Server instance.

    The default instance is registered as ``MSSQLSERVER``; every named instance is
    ``MSSQL$<InstanceName>``. ``Instance Names\\SQL`` reports the default instance
    as the literal string "MSSQLSERVER", so comparing against that name (rather
    than looking for an empty/absent one) is what distinguishes the two.
    """
    if instance_name.upper() == "MSSQLSERVER":
        return "MSSQLSERVER"
    return f"MSSQL${instance_name}"


def _read_mssql_service_state(
    probe: _RegistryProbe, instance_names: Optional[list[str]]
) -> tuple[Optional[str], Optional[str]]:
    """Return ``(startup_type, service_account)`` for the SQL Server engine.

    Read from the service control entry rather than inferred from a port probe: we
    already hold a registry connection, and a firewall can hide a perfectly healthy
    instance from 1433 while a stopped instance can still leave listening-looking
    config behind. ``ObjectName`` on the same key is the account the engine runs as.

    Only the first instance that answers is reported -- the row this feeds is one
    per host, not one per instance. Every read is best-effort: the Services hive is
    admin-gated, so a low-privilege run simply leaves these NULL rather than failing.
    """
    for instance in instance_names or ["MSSQLSERVER"]:
        key = MSSQL_SERVICE_KEY.format(service=_mssql_service_name(instance))
        start = probe.read_dword(key, "Start")
        account = probe.read_value(key, "ObjectName")
        if start is None and account is None:
            logger.verbose("No readable service control entry at %s", key)
            continue
        start_type = MSSQL_START_TYPES.get(start) if start is not None else None
        logger.info(
            "SQL Server service %s on %s: startup=%s, account=%s",
            key.rsplit("\\", 1)[-1], probe.hostname, start_type or "unknown",
            account or "unknown",
        )
        return start_type, account
    return None, None


def get_mssql_settings(probe: _RegistryProbe, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield one row per SQL instance discovered via remote registry.
    """
    # Try multiple default registry paths for MSSQL instances
    # These correspond to SQL Server versions: 2012+ (v11+) use MSSQL versions
    reg_paths = [
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2022
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2019
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2017
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2016
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2014
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2012
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.1\MSSQLServer\SuperSocketNetLib",              # Older versions / default fallback
        r"SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib"                                # Legacy path
    ]

    force_encryption = None
    extended_protection = None
    reg_path_found = None

    # Try each registry path until one succeeds
    for reg_path in reg_paths:
        if not reg_path_found:

            reg_key = probe.read_values(reg_path)
            if reg_key is not None:
                reg_path_found = reg_path
                logger.info("Found MSSQL registry key at %s", reg_path)

                # If we found a valid registry path, read the relevant values
                force_encryption_value = probe.read_dword(reg_path, "ForceEncryption")
                if force_encryption_value == 1:
                    force_encryption = "Yes"
                else:
                    force_encryption = "No"
            
                # Separate name for the raw DWORD, matching force_encryption above:
                # reusing one variable for the int and its label makes it int-or-str.
                extended_protection_value = probe.read_dword(reg_path, "ExtendedProtection")
                if extended_protection_value == 1:
                    extended_protection = "Allowed"
                elif extended_protection_value == 2:
                    extended_protection = "Required"
                else:
                    extended_protection = "Off"

    if not reg_path_found:
        logger.warning("Could not access any MSSQL registry paths on %s, tried:\n%s", probe.hostname, "\n".join(reg_paths))
        return

    logger.info("Collected EPA settings from %s: ForceEncryption=%s, ExtendedProtection=%s", probe.hostname, force_encryption, extended_protection)

    port_reg = reg_path_found + r"\Tcp\IPAll"
    port = probe.read_value(port_reg, "TcpPort")
    if port:
        logger.info("Found MSSQL TCP port: %s", port)

    instance_name_reg = r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    # read_values yields (name, data) pairs; only the names are wanted. A separate
    # variable keeps each one a single type instead of pairs-then-strings.
    instance_name_values = probe.read_values(instance_name_reg)
    instance_names: Optional[list[str]] = None
    if instance_name_values is not None:
        instance_names = [name for name, _ in instance_name_values]
        logger.info("Found MSSQL instance names: %s", ", ".join(instance_names))

    # Whether the engine is actually meant to run here, and as whom. A SQL Server
    # can be installed -- leaving every key above readable -- on a host that never
    # serves anything, which is how a passive site server acquired a spurious
    # MSSQL_Server node (con-be15). The node is still emitted; these properties are
    # what let a reader tell a live database from a dormant install.
    service_start_type, service_account_name = _read_mssql_service_state(
        probe, instance_names
    )

    target_entry = ctx.target_hosts_by_hostname[probe.hostname]

    yield "remoteregistry_mssql_servers", {
        "source": "RemoteRegistry-MSSQL",
        "force_encryption": force_encryption if force_encryption is not None else None,
        "extended_protection": extended_protection if extended_protection is not None else None,
        "name": target_entry.ad_object.get("name") if target_entry.ad_object else probe.hostname,
        "domain_computer_sid": target_entry.ad_object.get("object_sid") if target_entry.ad_object else None,
        "port": port if port else None,
        "instance_names": instance_names if instance_names else None,
        "service_start_type": service_start_type,
        "service_account_name": service_account_name,
    }