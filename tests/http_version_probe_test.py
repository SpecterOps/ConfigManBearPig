"""_HttpProbe fingerprints the SCCM version from a ccmsetup.exe body."""
from openhound_sccm.collectors.http import _extract_ccmsetup_version


def test_extracts_utf16le_version_from_binary():
    # UTF-16LE encoding of "5.00.9141.1015" embedded in surrounding bytes.
    blob = b"\x00\x01" + "5.00.9141.1015".encode("utf-16-le") + b"\xff\xfe"
    assert _extract_ccmsetup_version(blob) == "5.00.9141.1015"


def test_returns_none_when_no_version_present():
    assert _extract_ccmsetup_version(b"no version here") is None
    assert _extract_ccmsetup_version(b"") is None


def test_probe_requests_ccmsetup_with_wildcard_accept():
    # Regression (found live on ps1-mp): the shared HttpClient sends Accept: application/json,
    # which makes IIS return 406 for the BINARY ccmsetup.exe. The probe must override Accept to
    # */* so it receives the binary (200). Before the fix the probe called get() with no headers.
    from openhound_sccm.clients.http import ErrorClass, HttpResult
    from openhound_sccm.collectors.http import _HttpProbe

    captured: dict = {}

    class _FakeClient:
        def get(self, url, headers=None):
            captured["url"] = url
            captured["headers"] = headers
            return HttpResult(200, "5.00.9141.1015".encode("utf-16-le"), ErrorClass.RESPONSE)

    probe = _HttpProbe(_FakeClient(), "mp.example.com", None)
    probe.site_code = "PS1"
    rows = list(probe._probe_ccmsetup_version("http"))
    assert captured["headers"] == {"Accept": "*/*"}   # not the default application/json
    assert rows and rows[0][0] == "http_site_versions"
    assert rows[0][1]["sccm_version"] == "5.00.9141.1015"


def test_httpclient_get_forwards_custom_headers():
    # HttpClient.get() must forward a per-request headers override to the session so the
    # probe's Accept: */* actually reaches the server (overriding the session default).
    from unittest.mock import MagicMock

    from openhound_sccm.clients.http import HttpClient
    from openhound_sccm.clients.http_auth import AuthMode

    client = HttpClient(base_url="http://mp.example.com", auth=AuthMode.NONE, domain="")
    client._session = MagicMock()
    client._session.get.return_value = MagicMock(status_code=200, content=b"x")
    client.get("http://mp.example.com/CCM_Client/ccmsetup.exe", headers={"Accept": "*/*"})
    _, kwargs = client._session.get.call_args
    assert kwargs.get("headers") == {"Accept": "*/*"}


def test_picks_highest_build_among_multiple_embedded_versions():
    # A real ccmsetup.exe embeds several version strings; the first is a 5.00.0000.0000
    # placeholder. The extractor must return the highest build (the installed one), not
    # the first match. Observed on a live 2303 MP: 0000/7550/8690/9106 -> 9106.
    blob = (
        b"junk"
        + "5.00.0000.0000".encode("utf-16-le")
        + b"..."
        + "5.00.7550.0000".encode("utf-16-le")
        + b"..."
        + "5.00.9106.1000".encode("utf-16-le")
        + b"..."
        + "5.00.8690.1000".encode("utf-16-le")
    )
    assert _extract_ccmsetup_version(blob) == "5.00.9106.1000"
