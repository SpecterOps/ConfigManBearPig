"""Tests for cve_table version->build->CVE logic."""
from openhound_sccm.cve_table import (
    ADMINSERVICE_NTLM_MIN_BUILD,
    _build_number,
    lookup_cves,
)


def test_build_number_extracts_third_dotted_field():
    assert _build_number("5.00.9135.1013") == 9135
    assert _build_number("5.0.9135.1013") == 9135
    assert _build_number("9135") == 9135
    assert _build_number("not-a-version") is None


def test_none_or_unknown_version_returns_empty():
    assert lookup_cves(None) == []
    assert lookup_cves("") == []
    assert lookup_cves("5.00.0000.0000") == []  # build not in BUILD_MAP


def test_major_version_only_reports_all_cves_for_build_conservative():
    # 2503 = build 9135. Major-version-only input -> assume base build -> all CVEs.
    result = lookup_cves("9135")
    # Every CVE whose fix KBs are all absent from an empty installed set == every CVE.
    from openhound_sccm.cve_table import CVE_MAP
    assert result == sorted(CVE_MAP)


def test_base_release_version_reports_all_cves():
    # The 2503 base release row (5.00.9135.1000 full / 5.00.9135.1001 client) has no KBs
    # installed before it -> all CVEs.
    result = lookup_cves("5.00.9135.1001")
    from openhound_sccm.cve_table import CVE_MAP
    assert result == sorted(CVE_MAP)


def test_patched_version_excludes_fixed_cves():
    # At client version 5.00.9135.1006 (2503) the walk stops at the first matching row
    # (KB33177653), so installed = {KB31909343, KB32480179, KB33177653}. KB31909343 is a
    # fix KB for CVE-2025-47178, so that CVE is patched; KB34503790 (a later row) is NOT
    # yet installed, so CVE-2025-59213 is still reported.
    result = lookup_cves("5.00.9135.1006")
    assert "CVE-2025-47178 (Auth SQLi)" not in result   # KB31909343 installed -> patched
    assert "CVE-2025-59213 (Unauth SQLi)" in result       # KB34503790 not yet installed


def test_threshold_constant_is_2509_build():
    assert ADMINSERVICE_NTLM_MIN_BUILD == 9141
