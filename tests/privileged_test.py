"""Unit tests for the merged privileged collector (collectors/privileged.py).

The ten collection helpers are transport-agnostic — they read rows from a
``fetch`` callable and label them via the ``_Run`` flavor — so they are tested
once, parameterized over both flavors. Transport plumbing (``_http_fetch`` /
``_wmi_fetch`` / the two ``_*_identify``) and the orchestrator are tested
separately with canned clients. Transport-neutral row shaping
(``_snake``/``_row``/``_prop``) is covered in ``test_sms_rows.py``.
"""
import json

import pytest

from openhound_sccm.clients.http import ErrorClass, HttpResult
from openhound_sccm.collectors import privileged as p
from openhound_sccm.models.target_entry import TargetEntry

# (flavor name, equality operator, table prefix)
FLAVORS = [("AdminService", "eq", "adminservice"), ("WMI", "=", "wmi")]


class _Ctx:
    """Minimal SourceContext stand-in (mirrors the old per-collector _Ctx)."""
    def __init__(self, enabled=True, principal=None):
        self._enabled = enabled
        self.domain = "mayyhem.com"
        self.username = self.password = self.nt_hash = self.kerberos_ticket = None
        self.ad = None
        self._principal = principal
        self.target_hosts_by_hostname = {}

    def method_enabled(self, name):
        return self._enabled

    def resolve_principal(self, name):
        return self._principal


def _run(name, eq, pages, principal=None, calls=None):
    """A _Run whose fetch reads canned rows and records (class, columns, where)."""
    def fetch(class_name, columns=None, where=None):
        if calls is not None:
            calls.append((class_name, columns, where))
        return iter(pages.get(class_name, []))
    return p._Run(fetch=fetch, name=name, eq=eq, site_code="PS1", ctx=_Ctx(principal=principal))


# --- shared helpers, parameterized over both flavors ----------------------

@pytest.mark.parametrize("name,eq,tbl", FLAVORS)
def test_sites_and_site_definition(name, eq, tbl):
    pages = {
        "SMS_Site": [{"SiteCode": "PS1", "ServerName": "ps1.mayyhem.com", "BuildNumber": "9078"}],
        "SMS_SCI_SiteDefinition": [{"SiteCode": "PS1", "Props": [
            {"PropertyName": "siteGUID", "Value1": "{G}"},
            {"PropertyName": "SQLServerFQDN", "Value1": "ps1-db.mayyhem.com"},
            {"PropertyName": "SQLServicePort", "Value": 1433}]}],
    }
    calls = []
    rows = list(p._sites(_run(name, eq, pages, principal=None, calls=calls)))
    tables = {t for t, _ in rows}
    assert tables == {f"{tbl}_sites", f"{tbl}_site_definitions"}
    site = next(r for t, r in rows if t == f"{tbl}_sites")
    assert site["source"] == f"{name}-SMS_Site" and site["build_number"] == "9078"
    assert site["source_site_code"] == "PS1"
    sdef = next(r for t, r in rows if t == f"{tbl}_site_definitions")
    assert sdef["site_guid"] == "{G}" and sdef["sql_server_fqdn"] == "ps1-db.mayyhem.com"
    assert sdef["sql_service_port"] == 1433 and "props" not in sdef
    # the one WHERE clause is built in this flavor's dialect:
    sdef_call = next(c for c in calls if c[0] == "SMS_SCI_SiteDefinition")
    assert sdef_call[2] == f"SiteCode {eq} 'PS1'"


@pytest.mark.parametrize("name,eq,tbl", FLAVORS)
def test_site_definition_emits_computer_rows_when_servers_resolve(name, eq, tbl):
    pages = {"SMS_Site": [{"SiteCode": "PS1"}],
             "SMS_SCI_SiteDefinition": [{"SiteCode": "PS1", "SiteServerName": "ps1.mayyhem.com",
                 "Props": [{"PropertyName": "SQLServerFQDN", "Value1": "ps1-db.mayyhem.com"}]}]}
    run = _run(name, eq, pages, principal={"object_sid": "S-1-5-21-1", "name": "r"})
    rows = list(p._sites(run))
    comp = [r for t, r in rows if t == f"{tbl}_site_definitions_computers"]
    assert len(comp) == 2  # site server + SQL server
    assert all(r["sccm_infra"] is True and r["source"] == f"{name}-SiteDefinition" for r in comp)


@pytest.mark.parametrize("name,eq,tbl", FLAVORS)
def test_client_devices_filter_and_labels(name, eq, tbl):
    pages = {"SMS_CombinedDeviceResources": [
        {"Name": "WS1", "IsClient": True, "IsObsolete": False, "ResourceID": 1},
        {"Name": "WS2", "IsClient": False, "IsObsolete": False, "ResourceID": 2},
        {"Name": "WS3", "IsClient": True, "IsObsolete": True, "ResourceID": 3}]}
    rows = list(p._client_devices(_run(name, eq, pages)))
    assert [r["name"] for _, r in rows] == ["WS1"]  # non-client + obsolete skipped
    assert rows[0][0] == f"{tbl}_client_devices"
    assert rows[0][1]["source"] == f"{name}-SMS_CombinedDeviceResources"


@pytest.mark.parametrize("name,eq,tbl", FLAVORS)
def test_reserved_accounts_resolve_and_skip(name, eq, tbl):
    pages = {"SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\naa", "SiteCode": "PS1"}]}
    rows = list(p._reserved_accounts(_run(name, eq, pages, principal={"object_sid": "S-7"})))
    assert rows[0][0] == f"{tbl}_reserved_accounts"
    assert rows[0][1]["source"] == f"{name}-SMS_SCI_Reserved" and rows[0][1]["sccm_infra"] is True
    assert rows[0][1]["object_sid"] == "S-7" and rows[0][1]["UserName"] == "MAYYHEM\\naa"
    # unresolvable principal -> no row
    assert list(p._reserved_accounts(_run(name, eq, pages, principal=None))) == []


@pytest.mark.parametrize("name,eq,tbl", FLAVORS)
def test_whitelisted_and_flattened_helpers(name, eq, tbl):
    pages = {
        "SMS_R_System": [{"Name": "WS1", "SID": "S-1", "SecurityGroupName": ["g1"]}],
        "SMS_R_User": [{"Name": "MAYYHEM\\u", "SID": "S-2", "UserName": "u"}],
        "SMS_Collection": [{"CollectionID": "C1", "Name": "All", "MemberCount": 42}],
        "SMS_FullCollectionMembership": [{"CollectionID": "C1", "ResourceID": 9, "SiteCode": "PS1"}],
        "SMS_Role": [{"RoleID": "R1", "RoleName": "Full Admin", "LazyJunk": "drop"}],
        "SMS_Admin": [{"AdminID": 1, "LogonName": "MAYYHEM\\a", "Roles": ["R1"], "SecretJunk": "drop"}],
        "SMS_SCI_SysResUse": [{"NetworkOSPath": "\\\\db", "SiteCode": "PS1", "RoleName": "SMS SQL Server",
            "Props": [{"PropertyName": "SQL Server Service Logon Account", "Value2": "MAYYHEM\\svc"}]}],
    }
    assert list(p._r_system(_run(name, eq, pages)))[0][0] == f"{tbl}_r_system"
    assert list(p._r_user(_run(name, eq, pages)))[0][0] == f"{tbl}_r_user"
    coll = list(p._collections(_run(name, eq, pages)))
    assert coll[0][0] == f"{tbl}_collections" and coll[0][1]["member_count"] == 42
    mem = list(p._collection_members(_run(name, eq, pages)))
    assert mem[0][0] == f"{tbl}_collection_members" and mem[0][1]["resource_id"] == 9
    role = list(p._security_roles(_run(name, eq, pages)))[0][1]
    assert role["role_name"] == "Full Admin" and "lazy_junk" not in role  # whitelist drops unlisted
    admin = list(p._admins(_run(name, eq, pages)))[0][1]
    assert admin["roles"] == ["R1"] and "secret_junk" not in admin
    ss = list(p._site_systems(_run(name, eq, pages)))[0][1]
    assert ss["sql_server_service_logon_account"] == "MAYYHEM\\svc" and "props" not in ss


# --- transport plumbing ----------------------------------------------------

class _FakeHttp:
    """Canned AdminService client; slices rows by $top/$skip like the real one."""
    def __init__(self, pages, status=200, error_class=ErrorClass.RESPONSE):
        self.pages, self.status, self.error_class, self.calls = pages, status, error_class, []

    def get(self, path):
        self.calls.append(path)
        if self.error_class is not ErrorClass.RESPONSE:
            return HttpResult(None, None, self.error_class)
        cls = path.split("wmi/", 1)[1].split("?", 1)[0]
        rows = self.pages.get(cls)
        if rows is None:
            return HttpResult(404, b"", ErrorClass.RESPONSE)
        top = _qint(path, "$top")
        skip = _qint(path, "$skip") or 0
        page = rows[skip:skip + top] if top else rows
        return HttpResult(self.status, json.dumps({"value": page}).encode(), ErrorClass.RESPONSE)

    def close(self):
        pass


def _qint(path, key):
    for part in path.replace("?", "&").split("&"):
        if part.startswith(key + "="):
            return int(part.split("=", 1)[1])
    return None


class _FakeWmi:
    """Canned generic WmiClient; query(namespace, class_name, ...) streams rows."""
    def __init__(self, pages):
        self.pages, self.queries, self.closed = pages, [], False

    def query(self, namespace, class_name, *, columns=None, where=None):
        self.queries.append((namespace, class_name))
        yield from self.pages.get(class_name, [])

    def close(self):
        self.closed = True


def test_http_identify_and_paginate():
    rows = [{"n": i} for i in range(2500)]
    fake = _FakeHttp({"SMS_Identification": [{"ThisSiteCode": "PS1"}], "SMS_R_System": rows})
    assert p._http_identify(fake) == "PS1"
    got = list(p._http_fetch(fake)("SMS_R_System", columns=("n",)))
    assert len(got) == 2500
    skips = [_qint(c, "$skip") for c in fake.calls if "SMS_R_System" in c]
    assert skips == [0, 1000, 2000]  # 3 pages: 1000, 1000, 500 (short page ends it)


def test_http_identify_aborts_when_empty():
    assert p._http_identify(_FakeHttp({"SMS_Identification": []})) is None
    assert p._http_identify(_FakeHttp({})) is None  # 404 -> None


def test_http_fetch_renders_select_and_filter():
    fake = _FakeHttp({"SMS_SCI_SiteDefinition": [{"SiteCode": "PS1"}]})
    list(p._http_fetch(fake)("SMS_SCI_SiteDefinition", columns=("SiteCode", "Props"),
                             where="SiteCode eq 'PS1'"))
    path = fake.calls[0]
    assert "$select=SiteCode,Props" in path
    assert "$filter=SiteCode eq 'PS1'" in path


def test_wmi_identify_picks_local_provider():
    fake = _FakeWmi({"SMS_ProviderLocation": [
        {"SiteCode": "AAA", "ProviderForLocalSite": False},
        {"SiteCode": "PS1", "ProviderForLocalSite": True}]})
    assert p._wmi_identify(fake) == "PS1"
    assert fake.queries[0] == ("root\\SMS", "SMS_ProviderLocation")
    # falls back to first row when none flagged local; empty -> None
    assert p._wmi_identify(_FakeWmi({"SMS_ProviderLocation": [{"SiteCode": "AAA"}]})) == "AAA"
    assert p._wmi_identify(_FakeWmi({"SMS_ProviderLocation": []})) is None


def test_wmi_fetch_passes_namespace_class_columns_where():
    fake = _FakeWmi({"SMS_Role": [{"RoleName": "Full Admin"}]})
    fetch = p._wmi_fetch(fake, "root\\SMS\\site_PS1")
    rows = list(fetch("SMS_Role", columns=("RoleName",), where="x = '1'"))
    assert rows == [{"RoleName": "Full Admin"}]
    assert fake.queries[0] == ("root\\SMS\\site_PS1", "SMS_Role")


# --- orchestrator + entry points ------------------------------------------

ALL_CLASSES = {
    "SMS_Identification": [{"ThisSiteCode": "PS1"}],
    "SMS_ProviderLocation": [{"SiteCode": "PS1", "ProviderForLocalSite": True}],
    "SMS_Site": [{"SiteCode": "PS1"}],
    "SMS_SCI_SiteDefinition": [{"SiteCode": "PS1", "Props": []}],
    "SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\naa"}],
    "SMS_CombinedDeviceResources": [{"Name": "WS1", "IsClient": True, "IsObsolete": False}],
    "SMS_R_System": [{"Name": "WS1", "SID": "S-1"}],
    "SMS_R_User": [{"Name": "u", "SID": "S-2"}],
    "SMS_Collection": [{"CollectionID": "C1", "Name": "All"}],
    "SMS_FullCollectionMembership": [{"CollectionID": "C1", "ResourceID": 1}],
    "SMS_Role": [{"RoleID": "R1", "RoleName": "Full Admin"}],
    "SMS_Admin": [{"AdminID": 1, "LogonName": "MAYYHEM\\a"}],
    "SMS_SCI_SysResUse": [{"NetworkOSPath": "\\\\ps1", "RoleName": "MP", "Props": []}],
}
EXPECT_AS = {f"adminservice_{s}" for s in ("sites", "site_definitions", "reserved_accounts",
    "client_devices", "r_system", "r_user", "collections", "collection_members",
    "security_roles", "admins", "site_systems")}


def test_collect_adminservice_order_and_marks(monkeypatch):
    fake = _FakeHttp(ALL_CLASSES)
    monkeypatch.setattr(p.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    entry = TargetEntry(hostname="ps1-sms.mayyhem.com", ad_object=None)
    ctx = _Ctx(principal={"object_sid": "S-9"})
    ctx.target_hosts_by_hostname = {"ps1-sms.mayyhem.com": entry}
    rows = list(p.collect_adminservice("ps1-sms.mayyhem.com", ctx))
    assert "wmi/SMS_Identification" in fake.calls[0]  # identification gate ran first
    assert {t for t, _ in rows} == EXPECT_AS
    assert "AdminService" in entry.completed_phases
    from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
    assert EXPECT_AS <= set(all_table_names(PER_HOST_PHASES))


def test_collect_wmi_order_and_marks(monkeypatch):
    fake = _FakeWmi(ALL_CLASSES)
    monkeypatch.setattr(p.WmiClient, "from_context", classmethod(lambda cls, ctx, target: fake))
    entry = TargetEntry(hostname="ps1-sms.mayyhem.com", ad_object=None)
    ctx = _Ctx(principal={"object_sid": "S-9"})
    ctx.target_hosts_by_hostname = {"ps1-sms.mayyhem.com": entry}
    rows = list(p.collect_wmi("ps1-sms.mayyhem.com", ctx))
    assert fake.queries[0] == ("root\\SMS", "SMS_ProviderLocation")  # identify first
    assert fake.queries[1][1] == "SMS_Site"                          # then collection order
    assert {t for t, _ in rows} == {t.replace("adminservice_", "wmi_") for t in EXPECT_AS}
    assert "WMI" in entry.completed_phases and fake.closed


def test_method_disabled_yields_nothing():
    assert list(p.collect_adminservice("h", _Ctx(enabled=False))) == []
    assert list(p.collect_wmi("h", _Ctx(enabled=False))) == []


def test_gate_failure_does_not_mark(monkeypatch):
    fake = _FakeHttp({"SMS_Identification": []})  # not a provider
    monkeypatch.setattr(p.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    entry = TargetEntry(hostname="h", ad_object=None)
    ctx = _Ctx()
    ctx.target_hosts_by_hostname = {"h": entry}
    assert list(p.collect_adminservice("h", ctx)) == []
    assert "AdminService" not in entry.completed_phases


def test_one_failing_collection_does_not_abort_rest(monkeypatch):
    # Only SMS_Site resolves; the rest 404 (empty). Sites must still emit and the
    # orchestrator must complete without raising.
    fake = _FakeHttp({"SMS_Identification": [{"ThisSiteCode": "PS1"}], "SMS_Site": [{"SiteCode": "PS1"}]})
    monkeypatch.setattr(p.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    tables = {t for t, _ in p.collect_adminservice("h", _Ctx(principal=None))}
    assert "adminservice_sites" in tables


# --- should_run_phase fallback gate (unchanged contract) ------------------

class _GateCtx:
    def __init__(self, entries, enabled=True):
        self.target_hosts_by_hostname = entries
        self._enabled = enabled

    def method_enabled(self, name):
        return self._enabled


def _wmi_phase():
    from openhound_sccm.per_host_phases import PER_HOST_PHASES
    return next(ph for ph in PER_HOST_PHASES if ph.name == "WMI")


def test_should_run_phase_skips_wmi_after_adminservice():
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None, completed_phases={"AdminService"})
    assert should_run_phase("h", _wmi_phase(), _GateCtx({"h": entry})) is False


def test_should_run_phase_runs_wmi_when_adminservice_absent():
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None)
    assert should_run_phase("h", _wmi_phase(), _GateCtx({"h": entry})) is True
