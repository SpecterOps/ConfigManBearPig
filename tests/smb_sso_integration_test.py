r"""Opt-in live-host integration test for SSPI SMB single sign-on.

Skipped unless run on a domain-joined Windows host with SSPI available AND the
opt-in env var set, so CI / non-domain machines stay green:

    $env:OH_SSO_INTEGRATION = "1"
    $env:UV_PROJECT_ENVIRONMENT = "$env:TEMP\openhound-sccm-venv"
    uv run pytest tests/test_smb_sso_integration.py -v

Override the target with OH_SSO_TEST_HOST / OH_SSO_TEST_DOMAIN.
"""
import os

import pytest

from openhound_sccm.clients import smb_sso

TARGET = os.environ.get("OH_SSO_TEST_HOST", "ps1-pss.mayyhem.com")
DOMAIN = os.environ.get("OH_SSO_TEST_DOMAIN", "mayyhem.com")

pytestmark = pytest.mark.skipif(
    not smb_sso._SSPI_NEGOTIATE_AVAILABLE or os.environ.get("OH_SSO_INTEGRATION") != "1",
    reason="Set OH_SSO_INTEGRATION=1 on a domain-joined Windows host to run.",
)


def test_sspi_negotiate_login_and_signed_op():
    """Current-user SSO connects and a signed SMB op (list shares) succeeds."""
    smb = smb_sso.connect_smb(TARGET, DOMAIN, None, None)
    assert smb is not None, "SSPI Negotiate login returned no connection"
    try:
        # A signed tree/IPC op exercises the derived SigningKey end to end.
        shares = smb.listShares()
        assert shares is not None
    finally:
        smb.close()
