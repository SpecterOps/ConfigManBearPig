"""Tests for the local collector's cross-resource state and unresolved-target
handling after moving off module-level globals.

The local resources used to share ``site_code`` / ``current_mp_ad_obj`` /
``this_computer_ad_obj`` via module globals created by whichever resource ran
first. That state now lives on ``SourceContext``. These tests confirm:

  * discovered values flow through ``ctx`` (site code, current MP, this host),
  * an MP/host that doesn't resolve in AD is skipped rather than yielded as a
    null row or crashing the enumeration (the old ``None.get()`` bug),
  * a later resource reads the ctx field safely even if the earlier resource
    never ran (no ``NameError`` from an unbound global),
  * ``get_logger`` returns a logger whose custom ``verbose`` level works.

The resources are ``@app.resource`` (DLT) generators; ``_raw`` reaches the
undecorated function so it can be driven with a stub context.
"""
import logging
import types

from openhound_sccm.collectors import local
from openhound_sccm.context import SourceContext
from openhound_sccm.log_context import get_logger


def _raw(resource):
    """Return the undecorated generator behind an ``@app.resource`` DltResource.

    ``@with_log_context`` wraps the body with ``functools.wraps`` (so
    ``.__wrapped__`` is the raw function) and DLT exposes that wrapper as
    ``._pipe.gen``. Calling the raw function with a ctx runs the resource logic
    directly, without DLT's pipe machinery.
    """
    return resource._pipe.gen.__wrapped__


class _Target:
    """Stand-in for TargetEntry: only ad_object/hostname are read here."""

    def __init__(self, ad_object, hostname="host.mayyhem.com"):
        self.ad_object = ad_object
        self.hostname = hostname


class _Svc:
    """Fake root\\CCM WMI service: ExecQuery returns canned rows per WQL."""

    def __init__(self, rows):
        self._rows = rows

    def ExecQuery(self, wql):
        return self._rows.get(wql, [])


class _Ctx:
    """Minimal SourceContext stand-in exposing only what the resources touch.

    The new per-run fields start at their SourceContext defaults (None)."""

    def __init__(self, *, targets=None, resolve=None, resolve_ip=None, site_codes=None):
        self.domain = "MAYYHEM.COM"
        self.site_codes = site_codes
        self.current_site_code = None
        self.current_mp_ad_object = None
        self.this_computer_ad_object = None
        self._targets = targets or {}
        self._resolve = resolve or {}
        self._resolve_ip = resolve_ip or {}
        self.register_calls = []

    def method_enabled(self, method):
        return True

    def register_target(self, identifier, source, site_code=None):
        self.register_calls.append((identifier, source, site_code))
        return self._targets.get(identifier)

    def resolve_principal(self, name):
        return self._resolve.get(name)

    def resolve_ip(self, host):
        return self._resolve_ip.get(host)


def _item(**props):
    return types.SimpleNamespace(**props)


# --- SMS_Authority --------------------------------------------------------

def test_sms_authority_populates_ctx_and_yields(monkeypatch):
    ad = {"dns_host_name": "mp.mayyhem.com", "object_sid": "S-1-5-21-1-2-3"}
    svc = _Svc({"SELECT * FROM SMS_Authority": [_item(CurrentManagementPoint="mp.mayyhem.com", Name="SMS:PS1")]})
    monkeypatch.setattr(local, "_wmi_ccm", lambda: svc)
    ctx = _Ctx(targets={"mp.mayyhem.com": _Target(ad)})

    rows = list(_raw(local.local_wmi_sms_authority)(ctx))

    # The yielded row now also carries the site code parsed from SMS_Authority.Name
    # (orphaned-role-sources task) -- on a Local-only run this is the sole
    # site-code source, so it must reach the row, not just ctx.
    assert rows == [{**ad, "site_code": "PS1"}]
    assert ctx.current_site_code == "PS1"
    assert ctx.site_codes == {"PS1"}  # lazily created from None
    assert ctx.current_mp_ad_object == ad
    assert ctx.register_calls == [("mp.mayyhem.com", "Local-SMS_Authority", "PS1")]


def test_sms_authority_skips_unresolved_mp_without_error(monkeypatch, caplog):
    # MP registered but not resolved in AD -> ad_object is None.
    svc = _Svc({"SELECT * FROM SMS_Authority": [_item(CurrentManagementPoint="mp.mayyhem.com", Name="SMS:PS1")]})
    monkeypatch.setattr(local, "_wmi_ccm", lambda: svc)
    ctx = _Ctx(targets={"mp.mayyhem.com": _Target(None)})

    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.local"):
        rows = list(_raw(local.local_wmi_sms_authority)(ctx))

    assert rows == []  # no null graph row
    assert ctx.current_mp_ad_object is None  # never set for an unresolved MP
    # The old code called None.get(...) here, raising AttributeError that the
    # outer except swallowed as an ERROR while aborting the enumeration.
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert ctx.current_site_code == "PS1"  # site code still captured


# --- SMS_LookupMP ---------------------------------------------------------

def test_sms_lookupmp_yields_resolved_and_uses_current_site_code(monkeypatch):
    ad = {"dns_host_name": "mp2.mayyhem.com", "object_sid": "S-1-5-21-7"}
    svc = _Svc({"SELECT * FROM SMS_LookupMP": [_item(Name="mp2.mayyhem.com")]})
    monkeypatch.setattr(local, "_wmi_ccm", lambda: svc)
    ctx = _Ctx(targets={"mp2.mayyhem.com": _Target(ad)})
    ctx.current_site_code = "PS1"  # set earlier by SMS_Authority in a real run

    rows = list(_raw(local.local_wmi_sms_lookupmp)(ctx))

    # Stamped with ctx.current_site_code for the same reason as SMS_Authority
    # above (orphaned-role-sources task).
    assert rows == [{**ad, "site_code": "PS1"}]
    assert ctx.register_calls == [("mp2.mayyhem.com", "Local-SMS_LookupMP", "PS1")]


# --- CCM_Client -----------------------------------------------------------

def test_ccm_client_reads_ctx_mp_without_nameerror(monkeypatch):
    # current_mp_ad_object was never set (SMS_Authority didn't run). The old
    # code read a module global here and would NameError; now it reads a ctx
    # field that always exists and defaults to None.
    monkeypatch.setenv("COMPUTERNAME", "TESTPC")
    monkeypatch.setenv("USERDNSDOMAIN", "mayyhem.com")
    svc = _Svc({"SELECT * FROM CCM_Client": [_item(ClientId="GUID:abc", ClientIdChangeDate=None, PreviousClientId=None)]})
    monkeypatch.setattr(local, "_wmi_ccm", lambda: svc)
    this_ad = {
        "object_sid": "S-1-5-21-9",
        "distinguished_name": "CN=TESTPC,OU=Computers,DC=mayyhem,DC=com",
        "dns_host_name": "testpc.mayyhem.com",
        "sam_account_name": "TESTPC$",
    }
    ctx = _Ctx(resolve={"TESTPC.mayyhem.com": this_ad})
    ctx.current_site_code = "PS1"

    rows = list(_raw(local.local_wmi_ccm_client)(ctx))

    assert len(rows) == 1
    row = rows[0]
    assert row["current_management_point"] is None  # unset ctx field, no NameError
    assert row["current_management_point_sid"] is None
    assert row["ad_domain_sid"] == "S-1-5-21-9"
    assert row["dns_host_name"] == "testpc.mayyhem.com"
    assert row["smsid"] == "GUID:abc"
    assert row["site_code"] == "PS1"
    assert ctx.this_computer_ad_object == this_ad


# --- SourceContext + get_logger ------------------------------------------

def test_source_context_local_fields_default_none():
    ctx = SourceContext(ad=object(), domain="MAYYHEM.COM")
    assert ctx.current_site_code is None
    assert ctx.current_mp_ad_object is None
    assert ctx.this_computer_ad_object is None


def test_get_logger_supports_verbose():
    log = get_logger("openhound_sccm.tests.getlogger")
    assert isinstance(log, logging.Logger)
    # verbose is the project's custom level; it must be callable without error.
    log.verbose("verbose line")
    log.info("info line")
