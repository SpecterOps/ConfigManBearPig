"""Privilege-level detection for --run-integration-tests.

The verdict is derived from COLLECTION evidence (AdminService/WMI row counts), never
from graph content: a privileged run whose builder is broken emits no SCCM-admin-only
nodes, would read as low-privilege, and would then skip the very cases that catch it.
"""
from pathlib import Path

import pytest

from openhound_sccm import main
from openhound_sccm.main import IntegrationPrivilege as P


def test_merge_row_counts_sums_overlaps():
    assert main._merge_row_counts({"a": 1, "b": 2}, {"b": 3, "c": 4}) == {"a": 1, "b": 5, "c": 4}


@pytest.mark.parametrize("counts,expected_priv,expected_rows", [
    ({}, False, 0),
    ({"ldap_sites": 12, "dns_management_points": 3}, False, 0),
    ({"adminservice_admins": 7}, True, 7),
    ({"wmi_sites": 2}, True, 2),
    ({"adminservice_admins": 7, "wmi_sites": 2}, True, 9),
    ({"adminservice_admins": 0, "wmi_sites": 0}, False, 0),
])
def test_detect_privileged(counts, expected_priv, expected_rows):
    assert main._detect_privileged(counts) == (expected_priv, expected_rows)


def test_local_wmi_tables_are_not_privileged_evidence():
    """local_wmi_* reads WMI on the COLLECTOR host -- a discovery phase any user runs.

    A substring match on "wmi_" would count these and wrongly report a plain
    domain-user collection as privileged.
    """
    counts = {"local_wmi_sms_authority": 5, "local_wmi_ccm_client": 9,
              "local_wmi_sms_lookupmp": 2}
    assert main._detect_privileged(counts) == (False, 0)


def test_high_forces_privileged_regardless_of_evidence():
    assert main._resolve_integration_privileged(P.high, {}) is True


def test_low_forces_unprivileged_regardless_of_evidence():
    assert main._resolve_integration_privileged(P.low, {"adminservice_admins": 99}) is False


@pytest.mark.parametrize("counts,expected", [
    ({"adminservice_admins": 7}, True),
    ({"ldap_sites": 12}, False),
])
def test_auto_follows_the_evidence(counts, expected):
    assert main._resolve_integration_privileged(P.auto, counts) is expected


def test_suite_passes_privileged_through(monkeypatch):
    import openhound_sccm.integration as integ
    seen = {}
    monkeypatch.setattr(integ, "run_integration_tests",
                        lambda graph_dir, **kw: seen.update(kw) or 0)
    assert main._run_integration_suite(Path("graph"), Path("r.json"), privileged=False) == 0
    assert seen["privileged"] is False
    main._run_integration_suite(Path("graph"), Path("r.json"), privileged=True)
    assert seen["privileged"] is True
