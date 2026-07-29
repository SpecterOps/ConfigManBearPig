"""Tests for --dns-resolver flag behaviour in main.py and collectors/dns.py."""
from types import SimpleNamespace

import dns.resolver as _dns_resolver
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# _resolve_dc_via_dns
# ---------------------------------------------------------------------------

def test_resolve_dc_via_dns_uses_custom_resolver_when_provided():
    """When dns_resolver is set, Resolver(configure=False) is used with that IP."""
    from openhound_sccm.main import _resolve_dc_via_dns

    mock_resolver_instance = MagicMock()
    mock_answer = MagicMock()
    mock_answer.target.__str__ = lambda self: "dc1.corp.local."
    mock_resolver_instance.resolve.return_value = [mock_answer]

    with patch.object(_dns_resolver, "Resolver", return_value=mock_resolver_instance) as mock_cls:
        result = _resolve_dc_via_dns("corp.local", dns_resolver="192.168.1.53")

        mock_cls.assert_called_once_with(configure=False)
        assert mock_resolver_instance.nameservers == ["192.168.1.53"]
        assert result == "dc1.corp.local"


def test_resolve_dc_via_dns_uses_host_resolver_when_not_provided():
    """When dns_resolver is None, the shared make_resolver builds a host-configured
    Resolver() (no explicit nameserver) and its resolve() is used.

    (Previously this asserted the module-level dns.resolver.resolve() was called;
    _resolve_dc_via_dns now delegates resolver construction to the shared
    discovery.dns.make_resolver, which always builds a Resolver instance.)
    """
    from openhound_sccm.main import _resolve_dc_via_dns

    mock_resolver_instance = MagicMock()
    mock_answer = MagicMock()
    mock_answer.target.__str__ = lambda self: "dc1.corp.local."
    mock_resolver_instance.resolve.return_value = [mock_answer]

    with patch.object(_dns_resolver, "Resolver", return_value=mock_resolver_instance) as mock_cls:
        result = _resolve_dc_via_dns("corp.local", dns_resolver=None)

        # make_resolver(None) builds a host-configured Resolver() (no explicit nameserver).
        mock_cls.assert_called_once_with()
        assert result == "dc1.corp.local"


# ---------------------------------------------------------------------------
# _apply_env_overrides — dns_resolver → SOURCES__SCCM__DNS_RESOLVER
# ---------------------------------------------------------------------------

def test_apply_env_overrides_sets_dns_resolver(monkeypatch):
    """dns_resolver flag value propagates to the expected env var."""
    import os
    from openhound_sccm.main import _apply_env_overrides

    monkeypatch.delenv("SOURCES__SCCM__DNS_RESOLVER", raising=False)
    _apply_env_overrides({"dns_resolver": "10.0.0.53"})
    assert os.environ["SOURCES__SCCM__DNS_RESOLVER"] == "10.0.0.53"


def test_apply_env_overrides_does_not_set_dns_resolver_when_none(monkeypatch):
    """When dns_resolver is None, the env var is left untouched."""
    import os
    from openhound_sccm.main import _apply_env_overrides

    monkeypatch.delenv("SOURCES__SCCM__DNS_RESOLVER", raising=False)
    _apply_env_overrides({"dns_resolver": None})
    assert "SOURCES__SCCM__DNS_RESOLVER" not in os.environ


# ---------------------------------------------------------------------------
# dns_management_points — resolver construction
# ---------------------------------------------------------------------------

def _make_ctx(dns_resolver=None, domain_controller=None, domain="corp.local",
              site_codes=None):
    """Build a minimal mock for dns_management_points tests."""
    ctx = MagicMock()
    ctx.dns_resolver = dns_resolver
    ctx.ad.creds.domain_controller = domain_controller
    ctx.domain = domain
    ctx.site_codes = site_codes or set()
    ctx.method_enabled.return_value = True
    return ctx


def test_dns_management_points_uses_configure_false_when_dns_resolver_set():
    """When ctx.dns_resolver is set, Resolver(configure=False) is used."""
    import dns.resolver as _dns_resolver_mod
    from openhound_sccm.collectors.dns import dns_management_points

    ctx = _make_ctx(dns_resolver="192.168.1.53", site_codes={"PS1"})
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = []

    with patch.object(_dns_resolver_mod, "Resolver", return_value=mock_resolver_instance) as mock_cls:
        list(dns_management_points(ctx))

        mock_cls.assert_called_once_with(configure=False)
        assert mock_resolver_instance.nameservers == ["192.168.1.53"]


def test_dns_management_points_uses_default_resolver_when_dns_resolver_not_set():
    """When ctx.dns_resolver is None and no DC, Resolver() uses system defaults."""
    import dns.resolver as _dns_resolver_mod
    from openhound_sccm.collectors.dns import dns_management_points

    ctx = _make_ctx(dns_resolver=None, domain_controller=None, site_codes={"PS1"})
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = []

    with patch.object(_dns_resolver_mod, "Resolver", return_value=mock_resolver_instance) as mock_cls:
        list(dns_management_points(ctx))

        mock_cls.assert_called_once_with()


def _raw(resource):
    """Return the undecorated generator behind an ``@app.resource`` DltResource.

    Calling the DltResource object itself (as the two tests above do) runs it
    through dlt's own pipe/extraction iteration, which -- since this resource
    declares ``columns=raw_table_asset(...)`` with ``return_validated_models:
    True`` -- validates each yielded dict into a pydantic model instance rather
    than handing back the plain dict. Reaching the wrapped function (any level
    of the ``functools.wraps`` chain works identically; the wrapping layers are
    transparent pass-throughs) and calling it directly with a stub ctx bypasses
    that, so assertions can index the plain dict as written by the collector.
    Same technique as local_resources_state_test.py's ``_raw()``.
    """
    return resource._pipe.gen.__wrapped__


def test_dns_management_points_emits_uppercased_role_and_site_code():
    """A DNS SRV-discovered MP's role and site_code are uppercased even when
    --site-codes was passed lowercase (source.py:39 does not uppercase it) --
    matching Task 1's uppercase invariant and every other role string (review
    fix round 1, MINOR-4). Also pins the collector->transform column-name
    contract (object_sid/site_code/sccm_site_system_roles) the transform arm
    depends on (MINOR-7)."""
    import dns.resolver as _dns_resolver_mod
    from openhound_sccm.collectors.dns import dns_management_points

    ad = {"object_sid": "S-1-5-21-1-2-3-9", "dns_host_name": "mp1.corp.local", "name": "MP1"}
    ctx = _make_ctx(dns_resolver=None, site_codes={"ps1"})
    ctx.register_target = MagicMock(return_value=SimpleNamespace(ad_object=ad))

    mock_answer = MagicMock()
    mock_answer.target.__str__ = lambda self: "mp1.corp.local."
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = [mock_answer]

    with patch.object(_dns_resolver_mod, "Resolver", return_value=mock_resolver_instance):
        rows = list(_raw(dns_management_points)(ctx))

    assert len(rows) == 1
    row = rows[0]
    assert row["object_sid"] == "S-1-5-21-1-2-3-9"
    assert row["site_code"] == "PS1"
    assert row["sccm_site_system_roles"] == "SMS Management Point@PS1"
    assert row["sccm_infra"] is True


def test_dns_management_points_skips_unresolved_target_without_crashing():
    """register_target can return a target whose ad_object is None (host
    registered as a probe target but not yet resolved in AD); spreading
    **target.ad_object on that would raise TypeError. Confirms the
    `if target and target.ad_object` guard added alongside the row-emission
    change."""
    from openhound_sccm.collectors.dns import dns_management_points

    ctx = _make_ctx(dns_resolver=None, site_codes={"PS1"})
    ctx.register_target = MagicMock(return_value=SimpleNamespace(ad_object=None))

    mock_answer = MagicMock()
    mock_answer.target.__str__ = lambda self: "unresolved.corp.local."
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = [mock_answer]

    with patch.object(_dns_resolver, "Resolver", return_value=mock_resolver_instance):
        rows = list(_raw(dns_management_points)(ctx))

    assert rows == []

