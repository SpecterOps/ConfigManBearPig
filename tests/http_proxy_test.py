"""HTTP-only proxy parsing and request routing without lab dependencies."""
import os
from types import SimpleNamespace

import pytest
import requests
import typer
from typer.testing import CliRunner

from openhound_sccm.clients.http import ErrorClass, HttpClient, parse_http_proxy
from openhound_sccm.clients.http_auth import AuthMode
from openhound_sccm.main import _parse_http_proxy_or_exit, _display_cli_value, collect_sccm


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("auto", "auto"),
        ("proxy.mayyhem.com", "http://proxy.mayyhem.com:80"),
        ("proxy.mayyhem.com:8080", "http://proxy.mayyhem.com:8080"),
        ("user:pass@proxy.mayyhem.com", "http://user:pass@proxy.mayyhem.com:80"),
        ("user:pass@proxy.mayyhem.com:8080", "http://user:pass@proxy.mayyhem.com:8080"),
    ],
)
def test_parse_http_proxy(value, expected):
    assert parse_http_proxy(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "http://proxy.mayyhem.com", "proxy", "user@proxy.mayyhem.com",
     "user:@proxy.mayyhem.com", "proxy.mayyhem.com:0",
     "proxy.mayyhem.com:65536", "proxy.mayyhem.com:",
     "proxy.mayyhem.com/path", "proxy.mayyhem.com bad"],
)
def test_reject_bad_http_proxy(value):
    with pytest.raises(ValueError):
        parse_http_proxy(value)
    with pytest.raises(typer.Exit) as ex:
        _parse_http_proxy_or_exit(value)
    assert ex.value.exit_code == 2


def _capture_requests(monkeypatch):
    seen = []

    def send(self, request, **kwargs):
        seen.append((request, kwargs))
        response = requests.Response()
        response.status_code = 200
        response._content = b"ok"
        response.url = request.url
        return response

    monkeypatch.setattr(requests.Session, "send", send)
    return seen


def test_default_ignores_ambient_proxy_and_netrc(monkeypatch, tmp_path):
    monkeypatch.setenv("HTTP_PROXY", "http://ambient.mayyhem.com:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient.mayyhem.com:3128")
    netrc = tmp_path / "netrc"
    netrc.write_text("machine mp.mayyhem.com login unexpected password secret")
    monkeypatch.setenv("NETRC", str(netrc))
    seen = _capture_requests(monkeypatch)
    client = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com")
    result = client.get("/SMS_MP/.sms_aut?SMSTRC")
    assert result.error_class is ErrorClass.RESPONSE
    request, kwargs = seen[0]
    assert kwargs["proxies"] == {}
    assert "Authorization" not in request.headers


def test_explicit_proxy_covers_http_and_https(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient.mayyhem.com:3128")
    seen = _capture_requests(monkeypatch)
    client = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com",
                        http_proxy=parse_http_proxy("user:pass@proxy.mayyhem.com"))
    client.get("http://mp.mayyhem.com/SMS_MP/.sms_aut?SMSTRC")
    client.get("https://mp.mayyhem.com/SMS_MP/.sms_aut?SMSTRC")
    for request, kwargs in seen:
        assert kwargs["proxies"] == {
            "http": "http://user:pass@proxy.mayyhem.com:80",
            "https": "http://user:pass@proxy.mayyhem.com:80",
        }
        assert "Authorization" not in request.headers


def test_auto_uses_ambient_proxy_and_bypass(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.mayyhem.com:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.mayyhem.com:8080")
    monkeypatch.delenv("NO_PROXY", raising=False)
    seen = _capture_requests(monkeypatch)
    client = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com", http_proxy="auto")
    client.get("/one")
    assert seen[-1][1]["proxies"]["https"] == "http://proxy.mayyhem.com:8080"

    monkeypatch.setenv("NO_PROXY", "mp.mayyhem.com")
    client.get("/two")
    assert seen[-1][1]["proxies"] == {}


def test_auto_uses_registry_proxy_when_present(monkeypatch):
    monkeypatch.setattr("urllib.request.proxy_bypass", lambda host: False)
    monkeypatch.setattr("urllib.request.getproxies",
                        lambda: {"http": "http://registry.mayyhem.com:8080",
                                 "https": "http://registry.mayyhem.com:8080"})
    seen = _capture_requests(monkeypatch)
    client = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com", http_proxy="auto")
    client.get("/one")
    assert seen[-1][1]["proxies"]["https"] == "http://registry.mayyhem.com:8080"


def test_context_passes_http_proxy_and_cli_masks_credentials():
    ctx = SimpleNamespace(domain="mayyhem.com", ad=None,
                          http_proxy="http://user:pass@proxy.mayyhem.com:80")
    client = HttpClient.from_context(ctx, "mp.mayyhem.com", auth=AuthMode.NONE)
    assert client._http_proxy == ctx.http_proxy
    assert _display_cli_value("--http-proxy", "user:pass@proxy.mayyhem.com") == "<value>"

def test_proxy_error_log_redacts_credentials(monkeypatch):
    from unittest import mock
    from openhound_sccm.clients import http as http_module

    client = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com",
                        http_proxy=parse_http_proxy("user:secret@proxy.mayyhem.com"))
    with mock.patch.object(client._session, "get",
                           side_effect=requests.exceptions.ProxyError(
                               "failed at http://user:secret@proxy.mayyhem.com:80")), \
         mock.patch.object(http_module.logger, "verbose") as logged:
        assert client.get("/one").error_class is ErrorClass.CONNECT_FAILURE
    assert "secret" not in str(logged.call_args)
    assert "<redacted>" in str(logged.call_args)


def test_source_ignores_unscoped_http_proxy_variable(monkeypatch):
    from openhound_sccm.source import get_last_ctx, source

    monkeypatch.setenv("HTTP_PROXY", "http://ambient.mayyhem.com:3128")
    monkeypatch.delenv("SOURCES__SCCM__HTTP_PROXY_CONFIG", raising=False)
    source(domain="mayyhem.com", http_proxy=None)
    assert get_last_ctx().http_proxy is None

def test_scoped_option_does_not_hide_windows_registry_proxy(monkeypatch):
    import urllib.request

    for name in list(os.environ):
        if name.lower().endswith("_proxy"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SOURCES__SCCM__HTTP_PROXY_CONFIG", "auto")
    assert urllib.request.getproxies_environment() == {}

def test_http_and_socks_proxy_cannot_be_combined(tmp_path, monkeypatch, caplog):
    monkeypatch.delenv("SOURCES__SCCM__SOCKS_PROXY", raising=False)
    monkeypatch.delenv("SOURCES__SCCM__HTTP_PROXY_CONFIG", raising=False)
    app = typer.Typer()
    app.command()(collect_sccm)
    result = CliRunner().invoke(app, [str(tmp_path), "--proxy", "socks.mayyhem.com:1080",
                                      "--http-proxy", "proxy.mayyhem.com",
                                      "--dc", "dc.mayyhem.com"])
    assert result.exit_code == 2
    assert "--http-proxy and --proxy cannot be used together" in caplog.text

def test_http_proxy_407_warns_once_without_credentials():
    from unittest import mock
    from openhound_sccm.clients import http as http_module

    client = HttpClient(base_url="http://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com",
                        http_proxy=parse_http_proxy("user:secret@proxy.mayyhem.com"))
    response = requests.Response()
    response.status_code = 407
    response._content = b"Proxy Authentication Required"
    with mock.patch.object(client._session, "get", return_value=response), \
         mock.patch.object(http_module.logger, "warning") as warned:
        assert client.get("/one").status_code == 407
        assert client.get("/two").status_code == 407
    warned.assert_called_once()
    assert "HTTP proxy requires authentication" in str(warned.call_args)
    assert "secret" not in str(warned.call_args)


def test_https_proxy_connect_407_warns_during_negotiate(monkeypatch):
    from unittest import mock
    from openhound_sccm.clients import http as http_module
    from openhound_sccm.clients import http_auth

    monkeypatch.setattr("urllib.request.proxy_bypass", lambda host: False)
    monkeypatch.setattr("urllib.request.getproxies",
                        lambda: {"https": "http://proxy.mayyhem.com:80"})
    client = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NEGOTIATE,
                        domain="mayyhem.com", http_proxy="auto")
    proxy_error = requests.exceptions.ProxyError(
        "Tunnel connection failed: 407 Proxy Authentication Required")
    negotiator = SimpleNamespace(step=lambda token: (b"token", True))
    with mock.patch.object(client._session, "get", side_effect=proxy_error), \
         mock.patch.object(client, "_build_negotiator", return_value=negotiator), \
         mock.patch.object(http_auth, "choose_auth", return_value=["sspi"]), \
         mock.patch.object(http_auth, "sspi_negotiate_available", return_value=True), \
         mock.patch.object(http_module.logger, "warning") as warned:
        assert client.get("/AdminService/wmi/SMS_Identification").error_class is ErrorClass.CONNECT_FAILURE
    warned.assert_called_once()
    assert "HTTP proxy requires authentication" in str(warned.call_args)


def test_direct_407_does_not_claim_a_proxy_is_configured():
    from unittest import mock
    from openhound_sccm.clients import http as http_module

    client = HttpClient(base_url="http://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com")
    response = requests.Response()
    response.status_code = 407
    response._content = b""
    with mock.patch.object(client._session, "get", return_value=response), \
         mock.patch.object(http_module.logger, "warning") as warned:
        assert client.get("/one").status_code == 407
    warned.assert_not_called()

def test_failed_direct_connection_suggests_available_proxy_once(monkeypatch):
    from unittest import mock
    from openhound_sccm.clients import http as http_module

    monkeypatch.setattr("urllib.request.proxy_bypass", lambda host: False)
    monkeypatch.setattr("urllib.request.getproxies",
                        lambda: {"https": "http://user:secret@proxy.mayyhem.com:80"})
    client = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com")
    with mock.patch.object(client._session, "get",
                           side_effect=requests.exceptions.ConnectionError()), \
         mock.patch.object(http_module.logger, "warning") as warned:
        assert client.get("/one").error_class is ErrorClass.CONNECT_FAILURE
        assert client.get("/two").error_class is ErrorClass.CONNECT_FAILURE
    warned.assert_called_once()
    assert "--http-proxy auto" in str(warned.call_args)
    assert "secret" not in str(warned.call_args)


@pytest.mark.parametrize(
    ("proxy_map", "bypassed", "error"),
    [
        ({"https": "http://proxy.mayyhem.com:80"}, True,
         requests.exceptions.ConnectionError()),
        ({"http": "http://proxy.mayyhem.com:80"}, False,
         requests.exceptions.ConnectionError()),
        ({"https": "http://proxy.mayyhem.com:80"}, False,
         requests.exceptions.SSLError()),
    ],
)
def test_failed_direct_connection_does_not_suggest_inapplicable_proxy(
        monkeypatch, proxy_map, bypassed, error):
    from unittest import mock
    from openhound_sccm.clients import http as http_module

    monkeypatch.setattr("urllib.request.proxy_bypass", lambda host: bypassed)
    monkeypatch.setattr("urllib.request.getproxies", lambda: proxy_map)
    client = HttpClient(base_url="https://mp.mayyhem.com", auth=AuthMode.NONE,
                        domain="mayyhem.com")
    with mock.patch.object(client._session, "get", side_effect=error), \
         mock.patch.object(http_module.logger, "warning") as warned:
        client.get("/one")
    warned.assert_not_called()