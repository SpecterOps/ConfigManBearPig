# tests/ldap_cmrc_site_code_test.py
"""Collector-side site-code selection for inferred (CmRcService-only) client devices.

A CAS publishes an mSSMSSite object like any other site, so it lands in ctx.site_codes.
Only management-point capabilities reveal which sites are Primary (ldap_management_points_raw
records them on ctx.primary_site_codes), and a CAS has no management point. The selector
must prefer a Primary so an inferred client is never stamped with the CAS site code.
"""
from openhound_sccm.collectors.ldap import _pick_client_device_site_code


def test_prefers_primary_over_cas():
    # CAS is in site_codes but must be avoided; a known Primary wins.
    assert _pick_client_device_site_code({"PS1", "PS2"}, {"CAS", "PS1", "PS2"}) == "PS1"


def test_falls_back_to_any_site_code_without_primary():
    # No primary identified yet -> best-effort first known site code (the transform is
    # the authoritative corrector; this only sets the raw collected value).
    assert _pick_client_device_site_code(None, {"CAS", "PS1"}) == "CAS"
    assert _pick_client_device_site_code(set(), {"PS1"}) == "PS1"


def test_none_when_no_sites_known():
    assert _pick_client_device_site_code(None, None) is None
    assert _pick_client_device_site_code(set(), set()) is None
