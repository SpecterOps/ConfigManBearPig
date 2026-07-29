"""Regex tests for the local client-log scrape in ``collectors/local.py``.

``local_client_logs_targets()`` scans ``CCM``/``ccmsetup`` logs for UNC paths
and URLs, logs each hit at VERBOSE, and registers the *host* portion as a probe
target. These tests lock the behaviour touched by ope-8b99:

  * the "Found URL" VERBOSE line prints the WHOLE url -- scheme + host + port +
    path + query. The ported URL regex used to stop at the hostname, so its
    ``group(0)`` (the logged value) was truncated to ``scheme://host``.
  * the host handed to discovery is still the *bare* hostname (no port/path),
    proving the fix is log-accuracy only and does not change which hosts get
    probed.
  * UNC paths are already logged in full (that was never the bug); kept here as
    a contrast and a guard against an accidental UNC regression.

The resource is an ``@app.resource`` generator; ``_raw()`` reaches the
undecorated function so it runs directly against a stub context and a temp log
tree, with no DLT pipe machinery involved.
"""
import logging

from openhound_sccm.collectors import local


def _raw(resource):
    """Return the undecorated generator behind an ``@app.resource`` DltResource.

    ``@with_log_context`` wraps the body with ``functools.wraps`` (so
    ``.__wrapped__`` is the raw function) and DLT exposes that wrapper as
    ``._pipe.gen``.
    """
    return resource._pipe.gen.__wrapped__


class _Ctx:
    """Minimal SourceContext stand-in: enables the Local method, records every
    ``register_target`` call, and resolves configured hosts to an IP so the
    scrape reaches its discovery branch."""

    def __init__(self, resolve_ip=None):
        self.current_site_code = None
        self.this_computer_ad_object = None
        self._resolve_ip = resolve_ip or {}
        self.register_calls = []

    def method_enabled(self, method):
        return True

    def resolve_ip(self, host):
        return self._resolve_ip.get(host)

    def register_target(self, identifier, source, site_code=None):
        # Return None (unresolved in AD): the scrape yields nothing, but the
        # discovery call is still recorded so tests can assert on the host used.
        self.register_calls.append((identifier, source, site_code))
        return None


def _point_at_log(tmp_path, monkeypatch, *lines):
    """Write ``<SystemRoot>/CCM/Logs/test.log`` with ``lines`` and aim the
    resource at it via the ``SystemRoot`` env var. Force the Windows-only guard
    on so the test is portable to non-Windows CI."""
    log_dir = tmp_path / "CCM" / "Logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "test.log").write_text("\n".join(lines), encoding="utf-8")
    monkeypatch.setattr(local.platform, "system", lambda: "Windows")
    monkeypatch.setenv("SystemRoot", str(tmp_path))


def _messages(caplog):
    return [r.getMessage() for r in caplog.records]


FULL_URL = "https://mp.mayyhem.com:443/ccm_system/request?param=1"


def test_found_url_logs_the_full_url_not_just_the_host(tmp_path, monkeypatch, caplog):
    ctx = _Ctx(resolve_ip={"mp.mayyhem.com": "10.1.2.3"})
    _point_at_log(tmp_path, monkeypatch, f"GET {FULL_URL} 200 OK")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        list(_raw(local.local_client_logs_targets)(ctx))

    msgs = _messages(caplog)
    # The whole URL is logged (scheme + host + port + path + query).
    assert f"Found URL in test.log: {FULL_URL}" in msgs
    # Regression guard: the old truncated "scheme://host" form must not appear.
    assert "Found URL in test.log: https://mp.mayyhem.com" not in msgs


def test_url_discovery_still_uses_the_bare_hostname(tmp_path, monkeypatch, caplog):
    # The log fix must not change which host is probed: group(1) is still the
    # bare hostname with no port or path.
    ctx = _Ctx(resolve_ip={"mp.mayyhem.com": "10.1.2.3"})
    _point_at_log(tmp_path, monkeypatch, f"GET {FULL_URL} 200 OK")

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        list(_raw(local.local_client_logs_targets)(ctx))

    assert ("mp.mayyhem.com", "Local-ClientLogs", None) in ctx.register_calls


def test_found_unc_logs_the_full_path(tmp_path, monkeypatch, caplog):
    # UNC full-path logging was never broken; this contrast guards against a
    # future edit truncating it the way the URL regex was truncated.
    unc = r"\\FILESRV.mayyhem.com\SMSPKGD$\content\file.txt"
    _point_at_log(tmp_path, monkeypatch, f"Copying {unc}")
    ctx = _Ctx()

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        list(_raw(local.local_client_logs_targets)(ctx))

    assert f"Found UNC path in test.log: {unc}" in _messages(caplog)
