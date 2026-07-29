"""Regression tests for the NetBIOS-prefixed principal resolution crash.

Resolving a ``DOMAIN\\name`` principal where ``DOMAIN`` is a NetBIOS / single-
label name (e.g. ``MAYYHEM\\networkaccess``) used to build the LDAP search base
``DC=MAYYHEM`` — an invalid naming context. AD answered with a referral, and
ldap3's default ``auto_referrals`` chased it into ``LDAPSocketOpenError: invalid
server address``. Only the network access account and ``sccm_push`` carry a
NetBIOS prefix, so only they hit it; FQDN/SID principals build valid bases.

Two independent fixes are covered here:
  1. ``_ldap_resolve`` never searches a single-label base, falling through to the
     FQDN domain in the try-list instead.
  2. ``_open_connection`` disables ``auto_referrals`` so any stray referral comes
     back as a clean empty result rather than crashing.
"""
from openhound_sccm.clients import ad
# _open_connection / Connection / _BindAttempt now live in the shared library
# (SCCM's ADClient is a thin subclass), so patch/reference them there.
from openhound_collector_common.clients import ad as shared_ad
from openhound_sccm.context import SourceContext


class _RecordingAD:
    """Fake ADClient that records every base it is asked to search.

    Returns a match only for the valid FQDN base, mirroring a real directory
    where ``DC=MAYYHEM,DC=COM`` exists and ``DC=MAYYHEM`` does not.
    """

    base_dn = "DC=mayyhem,DC=com"

    def __init__(self):
        self.searched_bases: list[str | None] = []

    def paged_search(self, search_filter, attributes, base=None, scope=None, controls=None, size_limit=0):
        self.searched_bases.append(base)
        if base == "DC=MAYYHEM,DC=COM":
            return [{"sAMAccountName": "networkaccess", "distinguishedName": "CN=networkaccess,DC=mayyhem,DC=com"}]
        return []


def test_netbios_prefix_skips_single_label_base_and_resolves_via_fqdn():
    fake_ad = _RecordingAD()
    ctx = SourceContext(ad=fake_ad, domain="mayyhem.com")

    result = ctx.resolve_principal("MAYYHEM\\networkaccess")

    # Resolution still succeeds — via the configured FQDN fallback.
    assert result is not None
    assert result["sAMAccountName"] == "networkaccess"
    # The invalid single-label base is never searched (it triggered the crash).
    assert "DC=MAYYHEM" not in fake_ad.searched_bases
    # The valid FQDN base is what actually resolved the account.
    assert "DC=MAYYHEM,DC=COM" in fake_ad.searched_bases


def test_open_connection_disables_auto_referrals(monkeypatch):
    captured: dict = {}

    class _FakeConnection:
        def __init__(self, server, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(shared_ad, "Connection", _FakeConnection)

    client = ad.ADClient(ad.ADCredentials(domain="mayyhem.com"))
    attempt = shared_ad._BindAttempt(
        label="ldaps",
        use_ssl=True,
        port=636,
        start_tls=False,
        session_security=False,
        channel_binding=False,
        auth_mode="ntlm",
    )

    client._open_connection(host="dc01.mayyhem.com", attempt=attempt)

    assert captured.get("auto_referrals") is False
