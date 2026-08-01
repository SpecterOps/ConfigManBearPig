"""Opt-in live Negotiate test against a real SCCM AdminService.

Enable by setting OPENHOUND_HTTP_TEST_TARGET to an SMS-provider FQDN reachable
from this host; skipped otherwise so CI/dev stays green without lab access.

What it asserts: the auth ENGINE produces tokens the real server ACCEPTS — i.e.
the authenticated request gets **past the 401** (RESPONSE with status != 401).
It deliberately does NOT require 200: a lab AdminService whose backend service
is degraded answers 500 *after* a successful Negotiate handshake, and that still
proves the token was accepted. The transport returns whatever status the server
gives.

Env:
  OPENHOUND_HTTP_TEST_TARGET    SMS provider FQDN (required to run)
  OPENHOUND_HTTP_TEST_DOMAIN    AD domain / Kerberos realm (e.g. mayyhem.com)
  OPENHOUND_HTTP_TEST_KDC       KDC host (defaults to the domain)
  OPENHOUND_HTTP_TEST_USER      DOMAIN\\user for the explicit-cred tests
  OPENHOUND_HTTP_TEST_PASSWORD  password for the password test
  OPENHOUND_HTTP_TEST_NTHASH    NT hash for the pass-the-hash test
"""
import os
import sys

import pytest

from openhound_sccm.clients.http import ErrorClass, HttpClient
from openhound_sccm.clients.http_auth import AuthMode

TARGET = os.environ.get("OPENHOUND_HTTP_TEST_TARGET")
DOMAIN = os.environ.get("OPENHOUND_HTTP_TEST_DOMAIN", "")
KDC = os.environ.get("OPENHOUND_HTTP_TEST_KDC") or (DOMAIN or None)
USER = os.environ.get("OPENHOUND_HTTP_TEST_USER")
PASSWORD = os.environ.get("OPENHOUND_HTTP_TEST_PASSWORD")
NTHASH = os.environ.get("OPENHOUND_HTTP_TEST_NTHASH")
ENDPOINT = "wmi/SMS_Identification"

pytestmark = pytest.mark.skipif(not TARGET, reason="set OPENHOUND_HTTP_TEST_TARGET to run")


def _client(**creds):
    return HttpClient(
        base_url=f"https://{TARGET}/AdminService",
        auth=AuthMode.NEGOTIATE,
        domain=DOMAIN,
        kdc_host=KDC,
        **creds,
    )


def _assert_accepted(result):
    # Past the 401 gate => the Negotiate token was accepted. 200 (healthy) or
    # 500 (degraded backend) both prove auth succeeded; 401 means rejected.
    assert result.error_class is ErrorClass.RESPONSE, f"transport failed: {result.error_class}"
    assert result.status_code != 401, "Negotiate token was rejected (401)"


def test_sspi_current_user():
    if sys.platform != "win32":
        pytest.skip("SSPI current-user auth requires Windows")
    client = _client()  # no creds -> SSPI rung
    try:
        _assert_accepted(client.get(ENDPOINT))
    finally:
        client.close()


def test_explicit_password():
    if not (USER and PASSWORD):
        pytest.skip("set OPENHOUND_HTTP_TEST_USER + _PASSWORD")
    client = _client(username=USER, password=PASSWORD)
    try:
        _assert_accepted(client.get(ENDPOINT))
    finally:
        client.close()


def test_pass_the_hash():
    if not (USER and NTHASH):
        pytest.skip("set OPENHOUND_HTTP_TEST_USER + _NTHASH")
    client = _client(username=USER, nt_hash=NTHASH)
    try:
        _assert_accepted(client.get(ENDPOINT))
    finally:
        client.close()
