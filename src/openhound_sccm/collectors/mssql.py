"""Keep SQL ports, registrations and protection evidence separate per instance."""

from dataclasses import dataclass, field
from collections.abc import Sequence
from typing import Any, Iterable

from openhound_collector_common.discovery.sql_server import SqlAddress, parse_sql_spn
from openhound_collector_common.proxy import active_proxy

from ..clients.mssql_epa import EPAPrereqError, EPAResult, test_epa
from ..context import SourceContext
from ..log_context import get_logger

logger = get_logger(__name__)


@dataclass
class _SqlEvidence:
    """Collected endpoint evidence before choosing any single service identity."""

    address: SqlAddress
    spns: list[str] = field(default_factory=list)
    # LDAP rows are variable-shaped at this boundary. Keep their original fields
    # in raw output; only the explicitly selected scalar identity reaches graphs.
    holders: list[dict[str, Any]] = field(default_factory=list)
    from_registry: bool = False
    is_fallback: bool = False


def _check_port(hostname: str, port: int, timeout: float = 3.0) -> bool:
    """Check one known TCP port without treating a timeout as protection evidence."""
    import socket

    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError) as error:
        logger.debug("%s:%d unreachable: %s", hostname, port, error)
        return False


def _instance_evidence(target: str, ctx: SourceContext) -> list[_SqlEvidence]:
    """Keep all host-matching registrations and registry-discovered endpoints."""
    holders = ctx.ad.find_mssql_spn_holders(target)
    spns = list(ctx.ad.get_spns(target))
    for holder in holders:
        spns.extend(holder["spns"])
    entry = ctx.target_hosts_by_hostname.get(target.lower())
    evidence = [
        _SqlEvidence(address, from_registry=True)
        for address in (entry.sql_instances if entry else [])
    ]
    host_names = {target.casefold(), target.split(".", 1)[0].casefold()}
    for spn in dict.fromkeys(spns):
        try:
            address = parse_sql_spn(spn)
        except ValueError:
            logger.warning("Ignoring an invalid SQL registration on %s", target)
            continue
        if address is None or address.host.casefold() not in host_names:
            continue  # Other services and other hosts cannot identify this endpoint.
        matched_holders = [
            holder
            for holder in holders
            if any(value.casefold() == spn.casefold() for value in holder["spns"])
        ]
        evidence.append(
            _SqlEvidence(
                SqlAddress(target, address.port, address.instance),
                [spn],
                matched_holders,
            )
        )
    if not evidence:
        logger.debug(
            "No SQL registrations or registry instances on %s; checking the conventional port only",
            target,
        )
        evidence.append(_SqlEvidence(SqlAddress(target, 1433)))
    # Names stay unresolved until Browser or SQL itself identifies their port.
    return evidence


def _merge_evidence(kept: _SqlEvidence, incoming: _SqlEvidence) -> None:
    """Combine observations already known to describe the same endpoint."""
    kept.spns = list(dict.fromkeys([*kept.spns, *incoming.spns]))
    kept.holders.extend(incoming.holders)
    kept.from_registry = kept.from_registry or incoming.from_registry
    if not kept.address.instance and incoming.address.instance:
        kept.address = incoming.address
    # Retaining an existing name needs no additional operational diagnostic.


def _resolve_endpoints(
    target: str, ctx: SourceContext
) -> tuple[list[_SqlEvidence], int]:
    """Resolve names once, then merge only evidence for the same numeric port."""
    by_address: dict[tuple[int | None, str], _SqlEvidence] = {}
    known_ports: dict[str, set[int]] = {}
    for item in _instance_evidence(target, ctx):
        address = item.address
        name = (address.instance or "").casefold()
        key = (address.port, name)
        if key in by_address:
            _merge_evidence(by_address[key], item)
        else:
            by_address[key] = item
        # Exact duplicate observations add no new endpoint or network request.
        if name and address.port is not None:
            known_ports.setdefault(name, set()).add(address.port)
        # Numeric registrations without an instance name cannot name another engine.
    endpoints: dict[tuple[int | None, str], _SqlEvidence] = {}
    failures = 0
    for item in by_address.values():
        address = item.address
        ports: Sequence[int | None] = [address.port]
        if address.port is None and address.instance:
            observed = known_ports.get(address.instance.casefold())
            if observed:
                logger.debug(
                    "Using this instance's already observed ports on %s", target
                )
                ports = sorted(observed)
            else:
                try:
                    ports = [
                        ctx.sql_browser.resolve(
                            target,
                            address.instance,
                            timeout=3,
                            proxied=active_proxy() is not None,
                        )
                    ]
                except (OSError, ValueError) as error:
                    logger.warning(
                        "SQL port is unresolved for %s\\%s: %s",
                        target,
                        address.instance,
                        error,
                    )
                    failures += 1
        # Numeric ports and bare unresolved registrations need no Browser request.
        for port in ports:
            resolved = _SqlEvidence(
                SqlAddress(target, port, address.instance),
                list(item.spns),
                list(item.holders),
                item.from_registry,
            )
            key = (
                port,
                "" if port is not None else (address.instance or "").casefold(),
            )
            if key in endpoints:
                _merge_evidence(endpoints[key], resolved)
            else:
                endpoints[key] = resolved
            # Different unknown names remain separate; known ports own their observations.
    entry = ctx.target_hosts_by_hostname.get(target.lower())
    host_identity = (
        entry.ad_object.get("object_sid") if entry and entry.ad_object else None
    )
    for item in endpoints.values():
        if item.address.port is not None:
            ctx.sql_port_fallback.remember(
                target, item.address.port, host_identity=host_identity
            )
        # Unresolved names remain raw candidates, separate from the fallback.
    if any(item.address.port is None for item in endpoints.values()):
        candidate = ctx.sql_port_fallback.claim(target, host_identity=host_identity)
        if candidate is not None:
            endpoints[(candidate.port, "")] = _SqlEvidence(candidate, is_fallback=True)
        # An existing or previously attempted 1433 endpoint needs no extra probe.
    # Fully resolved instances need no conventional-port fallback.
    return list(endpoints.values()), failures


def _probe_epa(
    target: str,
    port: int,
    spns: list[str],
    ctx: SourceContext,
    *,
    identify_instance: bool = False,
) -> tuple[EPAResult | None, bool]:
    """Return this port's measurement and whether an attempted read failed."""
    guard = getattr(ctx, "credential_guard", None)
    if guard is not None and guard.is_rejected:
        logger.warning(
            "EPA testing skipped on %s: sign-in details were already rejected", target
        )
        return None, False
    try:
        result = test_epa(
            target=target,
            port=port,
            remote_name=target,
            domain=ctx.domain,
            username=ctx.username,
            password=ctx.password,
            nt_hash=ctx.nt_hash,
            kerberos_ticket=ctx.kerberos_ticket,
            spns=spns,
            identify_instance=identify_instance,
        )
        return result, False
    except EPAPrereqError as error:
        logger.warning("EPA measurement incomplete for %s:%s: %s", target, port, error)
        return None, True


def _instance_row(
    target: str,
    item: _SqlEvidence,
    port_open: bool | None,
    result: EPAResult | None,
    ctx: SourceContext,
) -> dict[str, Any]:
    """Save original candidates while selecting a scalar identity only if unambiguous."""
    entry = ctx.target_hosts_by_hostname.get(target.lower())
    ad_object = entry.ad_object if entry and entry.ad_object else {}
    by_sid = {
        holder["object_sid"]: holder
        for holder in item.holders
        if holder.get("object_sid")
    }
    has_complete_identities = all(
        candidate.get("object_sid") for candidate in item.holders
    )
    holder = (
        next(iter(by_sid.values()))
        if len(by_sid) == 1 and has_complete_identities
        else None
    )
    if len(by_sid) > 1:
        logger.warning(
            "Conflicting SQL SPN accounts for %s:%s; retaining candidates without selecting one",
            target,
            item.address.port,
        )
    elif item.holders and not has_complete_identities:
        logger.warning(
            "SQL SPN account identity is unread for %s:%s; withholding inferred account relationships",
            target,
            item.address.port,
        )
    # No advertised account is a normal unknown, without a second warning.
    classes = (holder.get("object_class") or []) if holder else []
    # These labels describe observations already logged above, so this routine
    # classification needs no additional message for each branch.
    if result is not None:
        source = "MSSQL-ScanForEPA"
    elif item.spns:
        source = "MSSQL-SPN"
    elif item.from_registry:
        source = "RemoteRegistry-MSSQL"
    else:
        source = "MSSQL-Port"
    return {
        "source": source,
        "force_encryption": result.force_encryption if result else None,
        "extended_protection": result.extended_protection if result else None,
        "strict_encryption": result.strict_encryption if result else None,
        "epa_measured": result is not None,
        "name": ad_object.get("name") or target,
        "dns_host_name": ad_object.get("dns_host_name") or target,
        "domain_computer_sid": ad_object.get("object_sid"),
        "port": item.address.port,
        "instance_name": item.address.instance,
        "has_mssql_spn": bool(item.spns),
        "service_principal_names": item.spns,
        "port_open": port_open,
        "service_account_candidates": item.holders,
        "service_account_sid": holder.get("object_sid") if holder else None,
        "service_account_name": holder.get("sam_account_name") if holder else None,
        "service_account_is_computer": any(
            value.casefold() == "computer" for value in classes
        )
        if holder
        else None,
    }


def collect_mssql(
    target: str, ctx: SourceContext
) -> Iterable[tuple[str, dict[str, Any]]]:
    """Save independent instances before reporting any failed measurements."""
    if not ctx.method_enabled("MSSQL"):
        logger.debug("MSSQL collection was not selected for %s", target)
        return
    guard = getattr(ctx, "credential_guard", None)
    if guard is not None and guard.is_rejected:
        logger.warning("SQL collection skipped on %s: sign-in details were already rejected", target)
        return
    logger.info("Starting instance-specific MSSQL collection on %s", target)
    endpoints, failures = _resolve_endpoints(target, ctx)
    unresolved = {
        item.address.instance.casefold()
        for item in endpoints
        if item.address.port is None and item.address.instance
    }
    for item in endpoints:
        if guard is not None and guard.is_rejected:
            logger.warning("Remaining SQL endpoints skipped on %s: sign-in details were rejected", target)
            return
        # A run that has not rejected its credentials may inspect this endpoint.
        port = item.address.port
        port_open = _check_port(target, port) if port is not None else None
        if not port_open and not item.spns and not item.from_registry:
            logger.debug("No SQL endpoint evidence on %s:%s", target, port)
            continue
        # Registry inventory and SPNs remain usable without TCP reachability.
        result = None
        if port_open and port is not None:
            result, failed = _probe_epa(
                target, port, item.spns, ctx, identify_instance=item.is_fallback
            )
            failures += int(failed)
            if item.is_fallback and result is None:
                logger.warning(
                    "Fallback port %s on %s opened, but no SQL measurement "
                    "completed; retaining the unresolved names only", port, target,
                )
                continue
            if item.is_fallback and result is not None and result.instance_name:
                name = result.instance_name
                item.address = SqlAddress(target, port, name)
                if name.casefold() in unresolved:
                    logger.info(
                        "SQL confirmed %s\\%s on fallback port %s", target, name, port
                    )
                    for original in endpoints:
                        same_name = (
                            original.address.instance is not None
                            and original.address.instance.casefold() == name.casefold()
                        )
                        if original.address.port is None and same_name:
                            _merge_evidence(item, original)
                        # Other named engines cannot own this endpoint's facts.
                    unresolved.remove(name.casefold())
                    failures -= 1
                else:
                    logger.warning(
                        "Fallback port %s on %s identified %s; requested names remain unresolved",
                        port, target, name,
                    )
            # Without an authenticated identity, only the host and port are known.
        else:
            logger.verbose(
                "SQL port %s on %s was not reached; EPA is unknown", port, target
            )
        yield (
            "mssql_server_instances",
            _instance_row(target, item, port_open, result, ctx),
        )
    if failures:
        logger.error(
            "SQL facts saved for %s; %d endpoint measurements remain incomplete",
            target,
            failures,
        )
        raise EPAPrereqError(f"{failures} SQL endpoint measurements remain incomplete")
    logger.info("MSSQL collection completed on %s", target)
