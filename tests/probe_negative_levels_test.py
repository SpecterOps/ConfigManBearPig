"""A probe that comes back negative is a discovery result, not a fault.

Two phases spend most of their time asking hosts "are you an X?" and being told
no. Reported at WARNING that is 17 lines per low-privilege run about hosts that
are behaving perfectly normally.

The two get DIFFERENT levels, deliberately:

* AdminService (privileged.py) already logs an INFO conclusion right after the
  404 -- "<host> is not a reachable AdminService provider; skipping". The 404 is
  the evidence behind that line, so promoting it to INFO would state the same
  fact twice per host. VERBOSE.
* HTTP (http.py) has NO conclusion line -- it logs only positives between
  "Attempting HTTP collection on: X" and "HTTP collection completed for X". Drop
  its connect failure below INFO and a host that served nothing reads as a clean
  successful collection. So there the message IS the conclusion. INFO.
"""
import logging

import pytest

from openhound_sccm.clients.http import ErrorClass, HttpResult
from openhound_sccm.collectors import http as http_collector
from openhound_sccm.collectors import privileged

HTTP_LOGGER = "openhound_sccm.collectors.http"
PRIV_LOGGER = "openhound_sccm.collectors.privileged"
URL = "https://ps1-dev.mayyhem.com/AdminService/wmi/SMS_Identification"


class _FakeClient:
    """Minimal HttpClient stand-in: returns one canned result per get()."""

    def __init__(self, result):
        self.result = result

    def get(self, _path):
        return self.result


def _probe(result):
    """An _HttpProbe with only what _request touches.

    Bypasses __init__ on purpose: _request reads only self.client and writes only
    self.connection_failed, so building the real thing would drag in an HttpClient
    and a SourceContext for nothing. target is set anyway so a failure message
    stays readable if one of these tests ever regresses.
    """
    probe = http_collector._HttpProbe.__new__(http_collector._HttpProbe)
    probe.client = _FakeClient(result)
    probe.target = "ps1-dev.mayyhem.com"
    probe.connection_failed = False
    return probe


# --- D4: HTTP connect failure -------------------------------------------------

@pytest.mark.parametrize("error_class", [ErrorClass.CONNECT_FAILURE, ErrorClass.TLS_FAILURE])
def test_http_connect_failure_logs_info_not_warning(caplog, error_class):
    probe = _probe(HttpResult(status_code=None, content=None, error_class=error_class))

    with caplog.at_level(logging.DEBUG, logger=HTTP_LOGGER):
        assert probe._request(URL) is None

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    infos = [r for r in caplog.records if r.levelno == logging.INFO]
    assert infos, [r.levelname for r in caplog.records]
    assert "Unable to connect" in infos[0].getMessage()
    # The short-circuit behaviour must be untouched by a level change.
    assert probe.connection_failed is True


def test_http_connect_failure_message_does_not_repeat_the_host(caplog):
    """The [target] prefix is LogContextFilter's job; the URL already carries the host."""
    probe = _probe(HttpResult(None, None, ErrorClass.CONNECT_FAILURE))
    with caplog.at_level(logging.DEBUG, logger=HTTP_LOGGER):
        probe._request(URL)
    message = caplog.records[0].getMessage()
    assert message.count("ps1-dev.mayyhem.com") == 1, message


def test_http_success_is_returned_untouched(caplog):
    """Only the failure path changes; a real response still comes back."""
    ok = HttpResult(status_code=200, content=b"<xml/>", error_class=ErrorClass.RESPONSE)
    probe = _probe(ok)
    with caplog.at_level(logging.DEBUG, logger=HTTP_LOGGER):
        assert probe._request(URL) is ok
    assert probe.connection_failed is False


# --- D5: AdminService non-200 -------------------------------------------------

def _result(status):
    return HttpResult(status_code=status, content=b"{}", error_class=ErrorClass.RESPONSE)


def test_adminservice_404_while_probing_logs_verbose(caplog):
    """404 on the probe means "not an SMS Provider" -- a negative, not a fault."""
    client = _FakeClient(_result(404))
    with caplog.at_level(logging.DEBUG, logger=PRIV_LOGGER):
        assert privileged._http_get_value(client, "/AdminService/wmi/SMS_Identification",
                                          probing=True) is None

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("not an SMS Provider" in r.getMessage() for r in caplog.records), \
        [r.getMessage() for r in caplog.records]


@pytest.mark.parametrize("status", [401, 403, 500, 503])
def test_adminservice_non_404_while_probing_still_warns(caplog, status):
    """A provider that exists and rejected us, or broke, is a finding -- stay loud."""
    client = _FakeClient(_result(status))
    with caplog.at_level(logging.DEBUG, logger=PRIV_LOGGER):
        assert privileged._http_get_value(client, "/AdminService/wmi/SMS_Identification",
                                          probing=True) is None

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, [r.levelname for r in caplog.records]
    assert str(status) in warnings[0].getMessage()


def test_adminservice_404_when_not_probing_still_warns(caplog):
    """Past the probe the host IS a provider, so a 404 means a short collection."""
    client = _FakeClient(_result(404))
    with caplog.at_level(logging.DEBUG, logger=PRIV_LOGGER):
        assert privileged._http_get_value(client, "/AdminService/wmi/SMS_Role") is None

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, [r.levelname for r in caplog.records]
    assert "404" in warnings[0].getMessage()
