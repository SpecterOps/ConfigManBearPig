"""Resolve a port only after SCCM has identified its database instance."""

from openhound_collector_common.proxy import active_proxy

from ..context import SourceContext
from ..log_context import get_logger

logger = get_logger(__name__)


def resolve_site_sql_port(
    ctx: SourceContext, host: str | None, database_name: str | None
) -> int | None:
    """Reuse this instance's registry ports, or ask Browser, without guessing.

    SCCM records a named database as instance\\database; an unqualified database
    uses the default instance. A failed read leaves graph preparation in charge
    of the explicitly marked default-port fallback.
    """
    if not host or not database_name or not ctx.method_enabled("MSSQL"):
        logger.debug("No selected SQL lookup for the incomplete site database address")
        return None
    instance = database_name.split("\\", 1)[0] if "\\" in database_name else "MSSQLSERVER"
    entry = ctx.target_hosts_by_hostname.get(host.lower())
    if entry is None:
        entry = ctx.register_target(host, source="SCCM-SiteDatabase")
        if entry is None:
            logger.warning("Site SQL port lookup skipped for excluded or unresolved host %s", host)
            return None
    # Existing entries already passed registration and the include-only list.
    ports = {
        address.port for address in (entry.sql_instances if entry else [])
        if address.instance and address.instance.casefold() == instance.casefold()
        and address.port is not None
    }
    if len(ports) == 1:
        logger.info("Site database instance %s on %s uses its collected registry port", instance, host)
        return ports.pop()
    # Several configured ports cannot choose the client's endpoint; Browser can.
    try:
        return ctx.sql_browser.resolve(
            host, instance, timeout=3, proxied=active_proxy() is not None
        )
    except (OSError, ValueError) as error:
        logger.warning("Site database port remains unresolved for %s\\%s: %s", host, instance, error)
        return None
