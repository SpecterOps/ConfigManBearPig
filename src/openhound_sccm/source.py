import logging
import pathlib
from collections.abc import Iterable
from typing import Any

import dlt
from openhound_collector_common.dlt.source_bridge import StreamBridge

from .clients.ad import ADClient, ADCredentials
from .context import SourceContext
from .main import app
from .models.raw_table import raw_table_asset
from .per_host_phases import PER_HOST_PHASES, all_table_names

from .collectors.ldap import (
    ldap_management_points_raw,
    ldap_sites,
    ldap_cmrc_devices,
    ldap_network_boot_servers,
    ldap_pattern_matches,
    ldap_system_management_dacl,
)

from .collectors.dns import dns_management_points

from .collectors.local import (
    local_wmi_sms_authority,
    local_wmi_sms_lookupmp,
    local_wmi_ccm_client,
    local_client_logs_targets,
    collection_settings,
)

logger = logging.getLogger(__name__)


def _parse_csv_option(value: str | None) -> set[str]:
    """Return a stripped set of tokens from a comma-separated CLI value."""
    return {token for raw in (value or "").split(",") if (token := raw.strip())}


def _expand_allowed_targets(names: Iterable[str]) -> set[str]:
    """Lowercase each host name and add its short-name form (text before the
    first dot), returning the allow-list set.

    ``SourceContext._is_allowed_target`` matches *lowercased* candidate names, so
    every entry must be lowercased or it can never match; adding the short name
    lets a host match whether it is later presented as an FQDN or a short name.
    ``--computers`` and ``--computer-file`` both feed this, so the two stay
    consistent (previously only the file path lowercased).
    """
    allowed: set[str] = set()
    for raw in names:
        name = raw.strip().lower()
        if name:
            allowed.add(name)
            if "." in name:
                allowed.add(name.split(".")[0])
    return allowed


# ---------------------------------------------------------------------------
# Shared per-run state — planted by collect_sccm() before each pipeline.run()
# so the SourceContext created inside source() carries the same instances.
# ---------------------------------------------------------------------------
_shared_queue = None
_shared_ad_cache = None
_shared_discovered_domains = None


def set_shared_queue(work_queue) -> None:
    """Plant (or clear) the shared phased_pipeline.WorkQueue for the next source() call."""
    global _shared_queue
    _shared_queue = work_queue


def set_shared_ad_cache(cache) -> None:
    """Plant (or clear) the shared AD resolution cache for the next source() call."""
    global _shared_ad_cache
    _shared_ad_cache = cache


def set_shared_discovered_domains(domains) -> None:
    """Plant (or clear) the shared discovered-domains set for the next source() call."""
    global _shared_discovered_domains
    _shared_discovered_domains = domains


# The SourceContext built by the most recent source() call. collect_sccm reads
# it right after the discovery pass so the per-host engine shares the SAME
# context — and therefore the same target accumulator, allow-list, caches, and
# work queue — as discovery.
_last_ctx = None


def get_last_ctx():
    """Return the SourceContext built by the most recent source() call (or None)."""
    return _last_ctx


# Discovery (once-phase) resource names, selected for the Stage-1 pass. The
# per-host emit resources (one per table in all_table_names(PER_HOST_PHASES))
# are everything else returned by source().
DISCOVERY_RESOURCE_NAMES: tuple[str, ...] = (
    "ldap_sites",
    "ldap_management_points_raw",
    "ldap_cmrc_devices",
    "ldap_network_boot_servers",
    "ldap_pattern_matches",
    "ldap_system_management_dacl",
    "dns_management_points",
    "local_wmi_sms_authority",
    "local_wmi_sms_lookupmp",
    "local_wmi_ccm_client",
    "local_client_logs_targets",
    "collection_settings",
)


# ---------------------------------------------------------------------------
# Per-run stream bridge. The per-host engine (run by collect_sccm on a
# background thread) pushes rows onto the bridge's bounded per-table queues; the
# emit resources below drain them. collect_sccm creates the bridge and plants it
# via set_bridge() just before running the emit pass, mirroring the _shared_*
# pattern above.
#
# The bridge is the shared openhound-collector-common StreamBridge: it owns the
# queues, the blocking drain, and the DONE handling, so every OpenHound collector
# shares one push->pull implementation. SCCM keeps only the app-registration glue
# (_make_emit_resource / _EMIT_RESOURCES) because its emit resources must be
# registered on ``app`` at import time (a conformance guard checks
# ``app.dlt_resources``) — earlier than any run-scoped bridge can exist. So the
# bridge is planted late and the drain below simply delegates to it.
# ---------------------------------------------------------------------------
_bridge: StreamBridge | None = None


def set_bridge(bridge: StreamBridge) -> None:
    """Plant the stream bridge whose queues the emit resources will drain."""
    global _bridge
    _bridge = bridge


def get_bridge() -> StreamBridge | None:
    """Return the currently-installed stream bridge (or None between runs)."""
    return _bridge


def clear_bridge() -> None:
    """Forget the stream bridge after the emit pass finishes."""
    global _bridge
    _bridge = None


def _drain_stream(table_name: str):
    """Yield rows from one per-table queue until quiescence.

    Delegates to the planted StreamBridge, whose drain does a *blocking* get (an
    empty queue is a wait, not an end — the resource stops only on the DONE
    marker the engine broadcasts once per-host collection reaches quiescence).
    Returns immediately when no bridge is planted, so the emit resources declared
    on ``app`` at import time are safe no-ops outside a per-host run.
    """
    bridge = get_bridge()
    if bridge is None:
        return
    yield from bridge.drain_stream(table_name)


def _make_emit_resource(table_name: str):
    """Build one DLT resource that streams a single per-host table to disk.

    Each carries ``columns=raw_table_asset(table_name)`` so convert can map the
    table to a model and the conformance tests are satisfied. A real collector's
    follow-up may replace the placeholder model with a typed one.
    """

    # parallelized=True so each emit resource drains its stream in its own
    # thread. A single-threaded round-robin extractor would block on the first
    # emit resource whose stream is momentarily empty while another stream
    # fills to capacity — a deadlock. Independent threads avoid that.
    @app.resource(name=table_name, parallelized=True, columns=raw_table_asset(table_name))
    def _emit():
        yield from _drain_stream(table_name)

    return _emit


# One emit resource per per-host table, registered once at import time.
_EMIT_RESOURCES = tuple(_make_emit_resource(table) for table in all_table_names(PER_HOST_PHASES))


def build_emit_resources(table_names=None):
    """Return freshly-bound emit resources for the per-host streaming pass.

    ``table_names=None`` (production) reuses the cached resources built once at
    import from the real ``PER_HOST_PHASES``. A caller driving the stage with a
    different phase set (e.g. integration tests using stub phases) passes that
    set's table names so the emit resources match the streams the engine writes.
    """
    if table_names is None:
        return [emit() for emit in _EMIT_RESOURCES]
    return [_make_emit_resource(table)() for table in table_names]


# ---------------------------------------------------------------------------
# Finalization resource — dumps SourceContext.resolved_principals (populated
# by resolve_principal() across BOTH the discovery stage and the per-host
# stage) to the "ldap_resolved_principals" raw table.
#
# Deliberately NOT part of DISCOVERY_RESOURCE_NAMES, NOT part of
# _EMIT_RESOURCES/build_emit_resources() (those drain per-host Phase streams;
# this table isn't produced by a Phase — resolve_principal is called from
# discovery collectors, register_target, and per-host phase code alike), and
# NOT returned from source() below. main.py::_run_per_host_stage calls it
# directly, in its own tiny pipeline.run, strictly after both the discovery
# pass and the whole per-host worker pool have finished — the only point at
# which ctx.resolved_principals is guaranteed complete. Registering it via
# @app.resource still satisfies the framework's conformance guard (it checks
# app.dlt_resources, populated at decoration/import time regardless of
# whether the resource is ever included in a source's with_resources() set).
@app.resource(
    name="ldap_resolved_principals",
    parallelized=False,
    columns=raw_table_asset("ldap_resolved_principals"),
)
def ldap_resolved_principals(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Yield every uniquely-resolved AD principal accumulated during this run.

    A thin wrapper around ctx.resolved_principals — see
    SourceContext._record_resolved_principal for how/when it's populated.
    """
    yield from list(ctx.resolved_principals.values())


@app.source(name="sccm", max_table_nesting=0)
def source(
    # These are populated by main.py from the CLI options and secrets, then passed into the SourceContext
    # Connection
    domain: str = dlt.config.value,
    domain_controller: str | None = dlt.config.value,
    username: str | None = dlt.secrets.value,
    password: str | None = dlt.secrets.value,
    nt_hash: str | None = dlt.secrets.value,
    kerberos_ticket: str | None = dlt.secrets.value,
    ldap_port: int | None = dlt.config.value,
    # Collection
    collection_methods: str | None = dlt.config.value,
    computers: str | None = dlt.config.value,
    computer_file: str | None = dlt.config.value,
    site_codes: str | None = dlt.config.value,
    # Behavior
    disable_possible_edges: bool | None = dlt.config.value,
    enable_bad_opsec: bool | None = dlt.config.value,
    threads: int | None = dlt.config.value,
    show_cleartext_passwords: bool | None = dlt.config.value,
    # DNS
    dns_resolver: str | None = dlt.config.value,
):
    # Normalize to handle None values and set defaults
    collection_methods = collection_methods or "All"
    disable_possible_edges = bool(disable_possible_edges)
    enable_bad_opsec = bool(enable_bad_opsec)
    threads = threads if threads is not None else 1
    show_cleartext_passwords = bool(show_cleartext_passwords)

    # Parse allowed targets from --computers and --computer-file. Both feed the
    # same expansion (lowercased FQDN + short-name forms) so Test-AllowedTarget
    # matching works regardless of how a discovered host is later presented.
    allowed = _expand_allowed_targets(_parse_csv_option(computers))
    if computer_file:
        p = pathlib.Path(computer_file)
        if p.exists():
            allowed |= _expand_allowed_targets(p.read_text().splitlines())
        else:
            logger.warning("Computer file not found, ignoring: %s", p)

    creds = ADCredentials(
        domain=domain,
        domain_controller=domain_controller,
        username=username,
        password=password,
        nt_hash=nt_hash,
        kerberos_ticket=kerberos_ticket,
        port=ldap_port,
    )
    ctx = SourceContext(
        ad=ADClient(creds),
        domain=domain,
        username=username,
        password=password,
        nt_hash=nt_hash,
        kerberos_ticket=kerberos_ticket,
        collection_methods=collection_methods or "All",
        allowed_targets=frozenset(allowed),
        work_queue=_shared_queue,
        ad_resolution_cache=_shared_ad_cache if _shared_ad_cache is not None else {},
        discovered_domains=_shared_discovered_domains if _shared_discovered_domains is not None else set(),
        site_codes=_parse_csv_option(site_codes) or None,
        dns_resolver=dns_resolver,
        disable_possible_edges=disable_possible_edges,
        enable_bad_opsec=enable_bad_opsec,
    )

    # Stash so collect_sccm can reuse this exact context for the per-host stage.
    global _last_ctx
    _last_ctx = ctx

    # Discovery (once) resources seed the work queue via register_target. The
    # per-host phases are NOT DLT-scheduled here; they run in collect_sccm's
    # worker pool and stream their rows through the emit resources below. Both
    # sets are returned; collect_sccm selects each stage with with_resources().
    return (
        ldap_sites(ctx),
        ldap_management_points_raw(ctx),
        ldap_cmrc_devices(ctx),
        ldap_network_boot_servers(ctx),
        ldap_pattern_matches(ctx),
        ldap_system_management_dacl(ctx),
        dns_management_points(ctx),
        local_wmi_sms_authority(ctx),
        local_wmi_sms_lookupmp(ctx),
        local_wmi_ccm_client(ctx),
        local_client_logs_targets(ctx),
        collection_settings(ctx),
        *build_emit_resources(),
    )
