"""
Checks MSSQL database servers for:
- Extended Protection for Authentication (EPA) settings via NTLM probing
- Site database MSSQL server nodes and relationships
- sysadmin login detection
- Service account detection
"""
import logging
from typing import Any, Iterable

from ..clients.mssql_epa import test_epa
from ..context import SourceContext

logger = logging.getLogger(__name__)


def _check_port(hostname: str, port: int, timeout: float = 3.0) -> bool:
    """Check if TCP port is open on the target host."""
    import socket
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError) as ex:
        logger.debug("%s:%d unreachable: %s", hostname, port, ex)
        return False


def collect_mssql(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield one row per MSSQL host with evidence it runs SQL Server: an open
    TCP/1433 (which also lets EPA be probed), an AD-registered MSSQLSvc SPN, or both.

    EPA detection (NTLM login probes via explicit credentials or current-user SSPI)
    only runs when the port answered -- there's nothing to probe otherwise. An SPN
    is itself AD-readable proof the host runs SQL Server (design decision D2a), so a
    closed port no longer discards the host; only the ABSENCE of both signals (port
    closed AND no MSSQLSvc SPN) means there's no evidence of SQL Server at all, and
    the host is skipped. `has_mssql_spn` / `port_open` record which signal(s) fired
    so downstream builders (e.g. the MSSQL_CoerceAndRelayToMSSQL edge) can tell
    "EPA was measured and came back unclear" apart from "EPA was never measured".
    """
    if not ctx.method_enabled("MSSQL"):
        return

    logger.info("Starting MSSQL collection on %s", target)

    # Query AD for SPNs to help EPA detection select the correct service binding.
    spns = ctx.ad.get_spns(target)

    # get_spns reads the TARGET COMPUTER's own servicePrincipalName, which is empty
    # whenever SQL runs as a domain service account -- Microsoft's recommended setup and
    # the usual one for an SCCM site database, where the SPN sits on a user object. The
    # host part of MSSQLSvc/<host>:<port> names the machine running SQL no matter who
    # holds the SPN, so fall back to searching for the SPN itself. Without this, D2(a)
    # ("an MSSQLSvc SPN is enough for the host to reach the graph") silently holds only
    # for LocalSystem / NetworkService / virtual-account SQL.
    #
    # Task 13 (Tier A+): find_mssql_spn_holder also resolves WHO holds the SPN, which
    # D2(a)'s mere existence check (find_mssql_spns) deliberately doesn't need but
    # MSSQL_ServiceAccountFor/HasSession do -- the SPN is registered on the account SQL
    # actually runs as.
    service_account_sid = None
    service_account_is_computer = None
    service_account_name = None
    if not any(s.upper().startswith("MSSQLSVC/") for s in spns):
        holder = ctx.ad.find_mssql_spn_holder(target)
        if holder:
            # Merge rather than replace: the computer's own SPNs may still carry other
            # services test_epa can bind against.
            spns = list(spns) + holder["spns"]
            service_account_sid = holder.get("object_sid")
            # con-c509/con-2249: keep the NAME, not just the SID. The LDAP lookup
            # already resolved it (and logs it), but dropping it here left the account
            # with no node_user row at low privilege -- every arm of _node_user reads an
            # SCCM-privileged source -- so it degraded to a bare node_backfill stub whose
            # only property is its own SID. The MSSQL_GetTGS / MSSQL_GetAdminTGS /
            # MSSQL_ServiceAccountFor / HasSession edges pointing at it were emitted
            # correctly all along; they just pointed at an anonymous node.
            service_account_name = holder.get("sam_account_name")
            service_account_is_computer = "computer" in [
                c.lower() for c in (holder.get("object_class") or [])
            ]
            logger.info("MSSQLSvc SPN for %s is held by another principal (service account)", target)
        else:
            logger.debug("No MSSQLSvc SPN anywhere in AD for %s", target)

    # Split port or instance name from SPN if present (format is MSSQLSvc/hostname:port or MSSQLSvc/hostname\instance).
    # mssql_spn is also kept as-is (not just parsed for its port) -- it is itself
    # AD-readable proof the host runs SQL Server (D2a), used below. The match is
    # case-insensitive: SPNs are case-insensitive identifiers in AD, and
    # `setspn -A mssqlsvc/host:port ...` (lowercase) is a real, valid registration
    # -- graph presence for an SPN-only host (D2a) must not depend on how the SPN
    # happened to be cased when it was set.
    port = 1433  # Default MSSQL port
    mssql_spn = next((s for s in spns if s.upper().startswith("MSSQLSVC/")), None) if spns else None
    if mssql_spn:
        if ":" in mssql_spn:
            _, port_str = mssql_spn.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                logger.warning("Invalid port in SPN %s: %s", mssql_spn, port_str)
        elif "\\" in mssql_spn:
            # Instance name is present, but we can't determine the port without connecting to the SQL Browser service, so default to 1433.
            logger.info("SPN %s contains instance name but no port, defaulting to 1433", mssql_spn)
    elif spns:
        logger.info("No MSSQLSvc SPN found for %s, defaulting to port 1433", target)
    else:
        logger.info("No SPNs found for %s, defaulting to port 1433", target)

    port_open = _check_port(target, port)
    if not port_open:
        # An SPN is proof the host runs SQL Server, so it still belongs in the graph
        # (D2a) -- we just cannot probe EPA. Only skip entirely when there is no SPN
        # either, i.e. no evidence of SQL at all.
        if not mssql_spn:
            logger.info("MSSQL port %d closed on %s and no MSSQLSvc SPN; nothing to record", port, target)
            return
        logger.info(
            "MSSQL port %d closed on %s but an MSSQLSvc SPN exists; recording the host "
            "without EPA data", port, target,
        )
    else:
        logger.info("MSSQL port %d is open", port)

    epa_result = None
    if port_open:
        # Probe EPA enforcement using the credential ladder (explicit creds -> SSPI ->
        # ticket-only WARNING+skip -> skip). Skipped when the port is closed -- there
        # is nothing listening to probe.
        epa_result = test_epa(
            target=target,
            port=port,
            remote_name=target,
            domain=ctx.domain,
            username=ctx.username,
            password=ctx.password,
            nt_hash=ctx.nt_hash,
            kerberos_ticket=ctx.kerberos_ticket,
            spns=spns,
        )

    force_encryption = None
    extended_protection = None
    strict_encryption = None
    if epa_result:
        force_encryption = epa_result.force_encryption
        extended_protection = epa_result.extended_protection
        strict_encryption = epa_result.strict_encryption

    target_entry = ctx.target_hosts_by_hostname.get(target.lower())

    # name is the AD CN (e.g. "PS1-DB", not a DNS name); dns_host_name is the real
    # FQDN, carried separately so a consumer that needs an actual hostname (e.g. a
    # dnshostname field, or a LIKE '%.%' join) doesn't get handed the CN by mistake
    # (reviewer M2). Both fall back to the connect target when ad_object is unavailable.
    ad_object = target_entry.ad_object if target_entry and target_entry.ad_object else None
    yield "mssql_server_instances", {
        "source": "MSSQL-ScanForEPA",
        "force_encryption": force_encryption,
        "extended_protection": extended_protection,
        "strict_encryption": strict_encryption,
        "name": ad_object.get("name") if ad_object else target,
        "dns_host_name": ad_object.get("dns_host_name") if ad_object else target,
        "domain_computer_sid": ad_object.get("object_sid") if ad_object else None,
        "port": port,
        "has_mssql_spn": mssql_spn is not None,
        "port_open": port_open,
        # Task 13 (Tier A+): the MSSQLSvc SPN holder's identity, when the fallback
        # search above resolved one. NULL when the target computer's own SPN already
        # covered it (LocalSystem/NetworkService/virtual-account SQL) -- there is no
        # separate service account to report in that case.
        "service_account_sid": service_account_sid,
        "service_account_is_computer": service_account_is_computer,
        # The holder's sAMAccountName, so preproc can build a real User node for it
        # rather than a SID-only stub (con-c509 / con-2249).
        "service_account_name": service_account_name,
    }

    logger.info("MSSQL collection completed for %s:%d", target, port)
