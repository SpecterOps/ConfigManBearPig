"""Offline tests for --proxy parsing and --dc/--dns validation."""
import pytest
import typer

from openhound_sccm.main import _parse_proxy_or_exit, _require_dc_or_dns_for_proxy


def test_parse_bare_host_port():
    cfg = _parse_proxy_or_exit("10.2.10.254:1080")
    assert (cfg.host, cfg.port) == ("10.2.10.254", 1080)


def test_parse_scheme_with_auth():
    cfg = _parse_proxy_or_exit("socks5://user:pass@10.2.10.254:1080")
    assert (cfg.host, cfg.port, cfg.username, cfg.password) == ("10.2.10.254", 1080, "user", "pass")


def test_parse_none_returns_none():
    assert _parse_proxy_or_exit(None) is None


def test_bad_proxy_string_exits():
    with pytest.raises(typer.Exit):
        _parse_proxy_or_exit("http://nope:3128")  # non-socks scheme


def test_proxy_requires_dc_or_dns():
    cfg = _parse_proxy_or_exit("10.2.10.254:1080")
    with pytest.raises(typer.Exit):
        _require_dc_or_dns_for_proxy({"domain_controller": None, "dns_resolver": None}, cfg)


def test_proxy_ok_with_dc():
    cfg = _parse_proxy_or_exit("10.2.10.254:1080")
    _require_dc_or_dns_for_proxy({"domain_controller": "dc.mayyhem.com", "dns_resolver": None}, cfg)


def test_proxy_ok_with_dns():
    cfg = _parse_proxy_or_exit("10.2.10.254:1080")
    _require_dc_or_dns_for_proxy({"domain_controller": None, "dns_resolver": "10.0.0.1"}, cfg)


def test_no_proxy_skips_validation():
    _require_dc_or_dns_for_proxy({"domain_controller": None, "dns_resolver": None}, None)


def test_collect_run_is_wrapped_in_socks_proxy_installed():
    import ast
    import inspect
    import textwrap
    from openhound_sccm import main as m

    tree = ast.parse(textwrap.dedent(inspect.getsource(m.collect_sccm)))

    socks_with = None
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                call = item.context_expr
                if isinstance(call, ast.Call) and getattr(call.func, "id", None) == "socks_proxy_installed":
                    socks_with = node
    assert socks_with is not None, "collect_sccm must wrap the run in socks_proxy_installed(...)"

    # It must be called with the parsed proxy_cfg.
    call = socks_with.items[0].context_expr
    assert any(getattr(a, "id", None) == "proxy_cfg" for a in call.args), \
        "socks_proxy_installed must be called with proxy_cfg"

    # Both collection stages must live INSIDE the with-block.
    inside = ast.unparse(socks_with)
    assert "with_resources" in inside, "Stage-1 discovery must run inside the proxy context"
    assert "_run_per_host_stage" in inside, "Stage-2 per-host must run inside the proxy context"
    assert "_apply_connection_context" in inside, "DC discovery must run inside the proxy context"
