"""Stub per-host collectors returning deterministic test data.

These fakes let us validate the per-host pipeline framework end-to-end —
ordering, concurrency, recursion, multi-table emission, streaming, termination,
and per-host logging — before the real collectors are ported. Each is a
generator yielding ``(table_name, row)`` pairs and is replaced one-by-one by its
real counterpart (see the per-collector follow-up tickets).

Rule preserved by these stubs (and required of the real collectors): newly
discovered *machines* are registered as targets, but inventory rows (e.g. client
devices) are emitted as data and must NOT be registered as targets.
"""
from __future__ import annotations

from typing import Any, Iterable


def stub_remote_registry(target: str, ctx: Any) -> Iterable[tuple[str, dict]]:
    yield ("registry_sccm_components", {"name": target})


def stub_mssql(target: str, ctx: Any) -> Iterable[tuple[str, dict]]:
    yield ("mssql_instances", {"host": target, "instance": "MSSQLSERVER"})


def stub_adminservice(target: str, ctx: Any) -> Iterable[tuple[str, dict]]:
    # Two tables from one phase. Client devices are DATA rows, not probe targets.
    yield ("adminservice_admin_users", {"host": target, "user": f"{target}\\admin1"})
    yield ("adminservice_admin_users", {"host": target, "user": f"{target}\\admin2"})
    yield ("adminservice_client_devices", {"host": target, "device": f"{target}-dev1"})
    yield ("adminservice_client_devices", {"host": target, "device": f"{target}-dev2"})


def stub_http(target: str, ctx: Any) -> Iterable[tuple[str, dict]]:
    # Simulate discovering a new management point via HTTP enrollment. Guarded so
    # discovered hosts don't discover further hosts (recursion terminates).
    if ctx is not None and not target.endswith("-discovered"):
        ctx.register_target(f"{target}-discovered", source="STUB-HTTP")
    yield ("http_management_points", {"host": target})


def stub_smb(target: str, ctx: Any) -> Iterable[tuple[str, dict]]:
    yield ("smb_signing", {"host": target, "signing_required": True})
