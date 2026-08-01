"""Stub per-host phases, for tests that need the pipeline without real collectors.

The production list is ``openhound_sccm.per_host_phases.PER_HOST_PHASES`` -- 6 phases
wired to real collectors. This is its stub counterpart: the same ordered shape, but
every phase points at ``collectors/stubs.py``, so engine-level tests (ordering,
concurrency, recursion, termination) run without touching a network. Phase names
double as the ``--collection-methods`` gating tokens (matching ConfigManBearPig.ps1's
``$script:PhasesPerHost``), so the engine's gate is simply
``ctx.method_enabled(phase.name)``.

It has **5 phases, not 6**: ``collectors/stubs.py`` defines no ``stub_wmi``, because
the ``WMI`` phase arrived later with a real collector. WMI's fallback gating is
covered against the production list in ``privileged_test.py`` and ``http_test.py``.

Deliberately NOT named ``*_test.py``: this module holds no tests. ``pyproject.toml``
pins ``python_files = "*_test.py"``, and a collected module that is also imported by
name is a ``sys.modules`` collision waiting to happen.
"""
from __future__ import annotations

from openhound_sccm.collectors import stubs
from openhound_sccm.per_host_phases import all_table_names  # re-exported for importers
from openhound_sccm.phased_pipeline import Phase

__all__ = ["PER_HOST_PHASES", "all_table_names"]

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
