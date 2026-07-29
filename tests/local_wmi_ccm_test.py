"""Unit tests for ``_wmi_ccm()`` in ``collectors/local.py``.

``_wmi_ccm()`` decides whether the current host is an SCCM client before any
local collection runs. It must:

  * connect to the parent ``root`` WMI namespace first (a failure there is a
    genuine WMI problem -> ERROR),
  * enumerate ``root``'s child namespaces and only connect to ``root\\CCM``
    when ``CCM`` is present,
  * treat an absent ``CCM`` namespace as the normal non-client case -> a single
    INFO skip, never ERROR and never a traceback.

``win32com`` is faked via ``sys.modules`` so these run on any OS without
touching real WMI/DCOM (pywin32 is Windows-only and need not be importable).
"""
import logging
import sys
import types

from openhound_sccm.collectors import local


class _FakeNamespaceInstance:
    """Stand-in for a WMI ``__NAMESPACE`` instance: exposes a child-namespace ``Name``."""

    def __init__(self, name):
        self.Name = name


class _FakeService:
    """Stand-in for a connected ``SWbemServices`` object.

    Only ``InstancesOf('__NAMESPACE')`` is exercised, and only on the root service.
    """

    def __init__(self, child_namespaces=()):
        self._children = [_FakeNamespaceInstance(n) for n in child_namespaces]

    def InstancesOf(self, cls):
        assert cls == "__NAMESPACE"
        return list(self._children)


class _FakeLocator:
    """Stand-in for ``WbemScripting.SWbemLocator``.

    ``behaviors`` maps a namespace string (``'root'``, ``'root\\CCM'``) to either
    a service object to return or an ``Exception`` to raise, mirroring how
    ``ConnectServer`` succeeds or blows up per namespace.
    """

    def __init__(self, behaviors):
        self._behaviors = behaviors
        self.connected = []

    def ConnectServer(self, host, namespace):
        self.connected.append(namespace)
        result = self._behaviors[namespace]
        if isinstance(result, Exception):
            raise result
        return result


def _install(monkeypatch, behaviors):
    """Force Windows, clear the lru_cache, and make ``Dispatch`` return our locator."""
    local._wmi_ccm.cache_clear()
    monkeypatch.setattr(local.platform, "system", lambda: "Windows")
    locator = _FakeLocator(behaviors)
    fake_client = types.ModuleType("win32com.client")
    fake_client.Dispatch = lambda progid: locator
    fake_win32com = types.ModuleType("win32com")
    fake_win32com.client = fake_client
    monkeypatch.setitem(sys.modules, "win32com", fake_win32com)
    monkeypatch.setitem(sys.modules, "win32com.client", fake_client)
    return locator


def _errors(caplog):
    return [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_not_a_client_skips_quietly(monkeypatch, caplog):
    # root connects and lists namespaces, but CCM is absent -> not a client.
    root = _FakeService(child_namespaces=["cimv2", "SecurityCenter2", "RSOP"])
    locator = _install(monkeypatch, {"root": root})
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        assert local._wmi_ccm() is None
    # Never attempts the root\CCM connect, and never raises to ERROR.
    assert locator.connected == ["root"]
    assert not _errors(caplog)
    # A single INFO explains why local collection was skipped.
    assert any(
        r.levelno == logging.INFO and "SCCM client" in r.getMessage()
        for r in caplog.records
    )


def test_client_connects_to_ccm(monkeypatch):
    ccm = _FakeService()
    root = _FakeService(child_namespaces=["cimv2", "ccm"])  # case-insensitive match
    locator = _install(monkeypatch, {"root": root, "root\\CCM": ccm})
    assert local._wmi_ccm() is ccm
    assert locator.connected == ["root", "root\\CCM"]


def test_root_connect_failure_is_error(monkeypatch, caplog):
    # Cannot even reach root -> genuine WMI problem -> ERROR.
    _install(monkeypatch, {"root": OSError("RPC server unavailable")})
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        assert local._wmi_ccm() is None
    assert _errors(caplog)


def test_namespace_enumeration_failure_is_error(monkeypatch, caplog):
    class _BoomService:
        def InstancesOf(self, cls):
            raise OSError("enumeration denied")

    _install(monkeypatch, {"root": _BoomService()})
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        assert local._wmi_ccm() is None
    assert _errors(caplog)


def test_ccm_connect_failure_is_error(monkeypatch, caplog):
    # CCM present but connecting to it blows up -> still a real failure -> ERROR.
    root = _FakeService(child_namespaces=["ccm"])
    _install(monkeypatch, {"root": root, "root\\CCM": OSError("access denied")})
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        assert local._wmi_ccm() is None
    assert _errors(caplog)


def test_non_windows_returns_none(monkeypatch, caplog):
    local._wmi_ccm.cache_clear()
    monkeypatch.setattr(local.platform, "system", lambda: "Linux")
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        assert local._wmi_ccm() is None
    assert not _errors(caplog)
