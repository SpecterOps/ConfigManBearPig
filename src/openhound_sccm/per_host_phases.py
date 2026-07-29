"""The ordered SCCM per-host phases and the tables they write.

For this framework build the phases point at stub collectors; each is replaced
by a real collector in its own follow-up ticket. Phase names double as the
``--collection-methods`` gating tokens (matching ConfigManBearPig.ps1's
``$script:PhasesPerHost``), so the engine's gate is simply
``ctx.method_enabled(phase.name)``.
"""
from __future__ import annotations

from typing import Sequence

from .collectors import registry, mssql, privileged, http, smb
from .phased_pipeline import Phase

import logging
logger = logging.getLogger(__name__)

PER_HOST_PHASES: tuple[Phase, ...] = (
    Phase(
        "RemoteRegistry",(
            "remoteregistry_sites",
            "remoteregistry_computers",
            "remoteregistry_users",
            "remoteregistry_mssql_servers"
        ), registry.collect_registry,
    ),
    Phase(
        "MSSQL",(
            "mssql_server_instances",
        ), mssql.collect_mssql,
    ),
    Phase(
        "AdminService", (
            "adminservice_sites",
            "adminservice_site_definitions",
            "adminservice_site_definitions_computers",
            "adminservice_reserved_accounts",
            "adminservice_client_devices",
            "adminservice_r_system",
            "adminservice_r_user",
            "adminservice_user_group",
            "adminservice_collections",
            "adminservice_collection_members",
            "adminservice_security_roles",
            "adminservice_admins",
            "adminservice_site_systems",
        ), privileged.collect_adminservice,
    ),
    # WMI shares privileged.py's collection helpers (same collections, same
    # order) over DCOM, and runs only when AdminService could not reach the host
    # (see should_run_phase).
    Phase(
        "WMI", (
            "wmi_sites",
            "wmi_site_definitions",
            "wmi_site_definitions_computers",
            "wmi_reserved_accounts",
            "wmi_client_devices",
            "wmi_r_system",
            "wmi_r_user",
            "wmi_user_group",
            "wmi_collections",
            "wmi_collection_members",
            "wmi_security_roles",
            "wmi_admins",
            "wmi_site_systems",
        ), privileged.collect_wmi,
    ),
    # HTTP runs after WMI: unauthenticated web-endpoint role probing. Skipped once
    # AdminService or WMI has already collected the host (see should_run_phase),
    # mirroring PS1's "$script:CollectionTargets[$target]['Collected']" skip.
    Phase(
        "HTTP", (
            "http_management_points",
            "http_distribution_points",
            "http_smsproviders",
            "http_site_servers",
            "http_site_versions",
        ), http.collect_http,
    ),
    # SMB runs last: an unauthenticated SMB2-negotiate signing check plus
    # authenticated share enumeration to identify site-system roles. Skipped once
    # AdminService or WMI has already collected the host (see should_run_phase),
    # mirroring PS1's "already Collected -> skip SMB" check at 9053.
    Phase(
        "SMB", (
            "smb_computers",
            "smb_sites",
        ), smb.collect_smb,
    ),
)

def all_table_names(phases: Sequence[Phase]) -> list[str]:
    """Every table the phases may write, de-duplicated, in declaration order."""
    return list(dict.fromkeys(table for phase in phases for table in phase.streams))


def should_run_phase(target: str, phase: Phase, ctx) -> bool:
    """Engine ``should_run`` hook: method gating plus the WMI-is-a-fallback rule.

    WMI mirrors AdminService over DCOM, so it only earns its keep when
    AdminService could not be reached on this host. Skip it once AdminService has
    completed here (recorded on the shared ``TargetEntry.completed_phases``).
    This is the pipeline-native place for the gate — the same hook that already
    enforces ``--collection-methods`` — so the collector stays a plain
    "collect everything" function.
    """
    if not ctx.method_enabled(phase.name):
        return False
    if phase.name == "WMI":
        entry = ctx.target_hosts_by_hostname.get(target.lower())
        if entry is not None and "AdminService" in entry.completed_phases:
            logger.info("[%s][%s] Skipping WMI phase because AdminService already completed", target, phase.name)
            return False
    # HTTP and SMB are fallbacks: once a privileged method (AdminService or WMI)
    # has collected this host, their role probes add nothing, so skip them.
    # Mirrors PS1's "already Collected -> skip" checks (HTTP at 8617, SMB at 9053).
    if phase.name in ("HTTP", "SMB"):
        entry = ctx.target_hosts_by_hostname.get(target.lower())
        if entry is not None and ({"AdminService", "WMI"} & entry.completed_phases):
            logger.info("[%s][%s] Skipping %s phase because AdminService/WMI already collected this host", target, phase.name, phase.name)
            return False
    return True
