"""Under a proxy, name resolution must use dnspython/TCP, never stdlib."""
import socket

from openhound_collector_common.proxy import ProxyConfig, socks_proxy_installed


def test_resolve_v4_does_not_use_stdlib_under_proxy(monkeypatch):
    from openhound_sccm.collectors import dns as dnsmod

    called = {}

    def _fake_resolve_v4_via_dns(host):
        # NOTE: `called.setdefault("host", host) or "10.0.0.9"` (as drafted in
        # the task brief) always returns `host` itself -- setdefault() returns
        # the value it just inserted, which is truthy for any real hostname, so
        # the `or` never reaches "10.0.0.9". Recording + returning explicitly
        # instead so the fake actually behaves like a stub DNS resolution.
        called["host"] = host
        return "10.0.0.9"

    monkeypatch.setattr(dnsmod, "_resolve_v4_via_dns", _fake_resolve_v4_via_dns)
    with socks_proxy_installed(ProxyConfig(host="127.0.0.1", port=9)):
        assert dnsmod._resolve_v4("mp.internal.invalid") == "10.0.0.9"
    assert called["host"] == "mp.internal.invalid"


def test_resolve_v4_uses_stdlib_when_direct(monkeypatch):
    from openhound_sccm.collectors import dns as dnsmod

    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 0))])
    # No proxy installed -> direct stdlib path.
    assert dnsmod._resolve_v4("host.example") == "10.0.0.5"


def test_resolve_ip_uses_force_tcp_resolver_under_proxy(monkeypatch):
    import openhound_sccm.context as ctxmod
    from openhound_sccm.context import SourceContext

    ctx = SourceContext.__new__(SourceContext)
    ctx.dns_resolver = "10.0.0.1"
    seen = {}
    real_make = ctxmod.make_resolver

    def _spy(server_ip=None, **kw):
        seen["force_tcp"] = kw.get("force_tcp")
        return real_make(server_ip, **kw)

    monkeypatch.setattr(ctxmod, "make_resolver", _spy)
    with socks_proxy_installed(ProxyConfig(host="127.0.0.1", port=9)):
        try:
            ctx.resolve_ip("10.0.0.5")  # may fail to resolve; we only assert the knob
        except Exception:
            pass
    assert seen.get("force_tcp") is True
