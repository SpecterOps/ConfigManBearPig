"""The ordered SCCM per-host phases and the tables they write.

For this framework build the phases point at stub collectors; each is replaced
by a real collector in its own follow-up ticket. Phase names double as the
``--collection-methods`` gating tokens (matching ConfigManBearPig.ps1's
``$script:PhasesPerHost``), so the engine's gate is simply
``ctx.method_enabled(phase.name)``.
"""
from __future__ import annotations

from typing import Sequence

from openhound_sccm.collectors import stubs
from openhound_sccm.phased_pipeline import Phase

PER_HOST_PHASES: tuple[Phase, ...] = (
    Phase("RemoteRegistry", ("registry_sccm_components",), stubs.stub_remote_registry),
    Phase("MSSQL", ("mssql_instances",), stubs.stub_mssql),
    Phase(
        "AdminService",
        ("adminservice_admin_users", "adminservice_client_devices"),
        stubs.stub_adminservice,
    ),
    Phase("HTTP", ("http_management_points",), stubs.stub_http),
    Phase("SMB", ("smb_signing",), stubs.stub_smb),
)


def all_table_names(phases: Sequence[Phase]) -> list[str]:
    """Every table the phases may write, de-duplicated, in declaration order."""
    return list(dict.fromkeys(table for phase in phases for table in phase.streams))
