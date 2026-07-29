"""Unit tests for the --dc-only recon-mode helpers in main.py."""
import pytest
import typer

from openhound_sccm.main import _resolve_dc_only_methods, _should_run_per_host
from openhound_sccm.per_host_phases import PER_HOST_PHASES


def test_dc_only_forces_ldap_dns():
    # --dc-only with no explicit -m forces the LDAP+DNS method set.
    assert _resolve_dc_only_methods(True, None) == "LDAP,DNS"


def test_dc_only_conflicts_with_explicit_methods():
    # --dc-only and -m together is a contradiction: fail fast.
    with pytest.raises(typer.BadParameter):
        _resolve_dc_only_methods(True, "AdminService")
    with pytest.raises(typer.BadParameter):
        # Even an -m that happens to match is still an explicit contradiction.
        _resolve_dc_only_methods(True, "LDAP,DNS")


def test_without_dc_only_passes_methods_through():
    # Normal runs are untouched, including the unset (None -> defaults later) case.
    assert _resolve_dc_only_methods(False, "LDAP,SMB") == "LDAP,SMB"
    assert _resolve_dc_only_methods(False, None) is None


class _StubCtx:
    """Minimal stand-in for the per-host SourceContext."""


def test_per_host_skipped_in_dc_only():
    # dc-only mode never runs Stage 2, even with a valid ctx and phases.
    assert _should_run_per_host(_StubCtx(), PER_HOST_PHASES, dc_only=True) is False


def test_per_host_runs_normally():
    assert _should_run_per_host(_StubCtx(), PER_HOST_PHASES, dc_only=False) is True


def test_per_host_skipped_when_no_ctx_or_phases():
    assert _should_run_per_host(None, PER_HOST_PHASES, dc_only=False) is False
    assert _should_run_per_host(_StubCtx(), (), dc_only=False) is False
