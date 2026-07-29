# Merge AdminService + WMI collectors into `privileged.py` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> **Project rule override:** Do **NOT** `git commit`. Each task's final step is a *checkpoint* (run tests, confirm green) — the project owner commits.

**Goal:** Collapse the near-identical `collectors/adminservice.py` + `collectors/wmi.py` into one `collectors/privileged.py`, and turn `clients/wmi.py` into a transport-only, SCCM-free streaming WMI client.

**Architecture:** Two thin entry points (`collect_adminservice`/`collect_wmi`) do transport-specific connect + identify, then hand a `fetch` closure + a `_Run` flavor object to one shared orchestrator and one shared set of ten collection helpers. No transport `if` lives inside a helper. The WMI client exposes a single `query(namespace, class_name, columns=, where=)` streaming iterator whose first call runs the auth ladder.

**Tech Stack:** Python, pytest, impacket (DCOM/WMI), pywin32, `requests` (HTTP/Negotiate), DLT phased pipeline.

**Spec:** `docs/superpowers/specs/2026-06-12-merge-privileged-collectors-design.md` · **Ticket:** ope-38ad

**Red-window note:** Genericizing the client (Task 1) breaks the *old* `collectors/wmi.py` and `tests/test_wmi.py`; they are deleted in Task 3. Run **targeted** tests per task; the **full** suite is the gate at Task 3 and Task 5.

---

### Task 1: Genericize `clients/wmi.py` (transport-only + streaming)

**Files:**
- Modify: `src/openhound_sccm/clients/wmi.py`
- Test: `tests/test_wmi_client.py` (rewrite ladder/query sections; keep WQL + normalization + `_build_backend` tests)

- [ ] **Step 1: Rewrite the client tests for the new surface**

Replace the `# --- ladder ---`, `# --- identify -> query ---` sections (and the `_site_code_from_providers` test) in `tests/test_wmi_client.py`. Keep `test_build_wql_*`, the `_normalize`/embedded-Props tests, `test_ladder_skips_anonymous_when_no_creds`, `test_ladder_sspi_uses_pywin32_backend`, `test_build_backend_maps_rungs_to_impacket_with_kerberos_flag`. New `FakeBackend` + tests:

```python
class FakeBackend:
    """Records connect/execquery; `open_error` simulates an auth failure on the
    first real query (impacket raises when the DCOM connection is established)."""
    def __init__(self, *, rows=None, open_error=None):
        self.rows = rows if rows is not None else []
        self.open_error = open_error
        self.connected = False
        self.queries = []
        self.closed = False
    def connect(self):
        self.connected = True
    def execquery(self, namespace, wql):
        self.queries.append((namespace, wql))
        if self.open_error:
            raise self.open_error
        return self.rows                      # the fake's "raw enumerator" is the row list
    def stream(self, raw):
        for r in raw:
            yield r
    def close(self):
        self.closed = True


def test_first_query_runs_ladder_then_streams(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: False)
    kerb = FakeBackend(open_error=OSError("kerberos down"))
    ntlm = FakeBackend(rows=[{"SiteCode": "PS1", "ProviderForLocalSite": True}])
    backends = {"kerberos": kerb, "ntlm": ntlm}
    client = _client(username="MAYYHEM\\domainadmin", password="pw")
    monkeypatch.setattr(client, "_build_backend", lambda rung: backends.get(rung))
    rows = list(client.query("root\\SMS", "SMS_ProviderLocation"))
    assert rows == [{"SiteCode": "PS1", "ProviderForLocalSite": True}]
    assert kerb.closed and ntlm.connected        # failed rung closed, winner kept
    assert client._backend is ntlm


def test_second_query_reuses_backend_and_builds_namespace_wql(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: False)
    ntlm = FakeBackend(rows=[{"SiteCode": "PS1", "ProviderForLocalSite": True}])
    client = _client(username="u", password="p")
    monkeypatch.setattr(client, "_build_backend", lambda rung: ntlm if rung == "kerberos" else None)
    list(client.query("root\\SMS", "SMS_ProviderLocation"))   # runs ladder once
    ntlm.rows = [{"RoleName": "Full Admin"}]
    rows = list(client.query("root\\SMS\\site_PS1", "SMS_Role", where="RoleName = 'x'"))
    assert rows == [{"RoleName": "Full Admin"}]
    ns, wql = ntlm.queries[-1]
    assert ns == "root\\SMS\\site_PS1"
    assert wql == "SELECT * FROM SMS_Role WHERE RoleName = 'x'"


def test_ladder_exhausted_yields_nothing(monkeypatch):
    monkeypatch.setattr(w.http_auth, "sspi_negotiate_available", lambda: False)
    dead = FakeBackend(open_error=OSError("nope"))
    client = _client(username="u", password="p")
    monkeypatch.setattr(client, "_build_backend", lambda rung: dead if rung in ("kerberos", "ntlm") else None)
    assert list(client.query("root\\SMS", "SMS_ProviderLocation")) == []
    assert client._backend is None
```

- [ ] **Step 2: Run the rewritten tests — expect FAIL**

Run: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run pytest tests/test_wmi_client.py -q`
Expected: FAIL (`query()` signature/behavior not yet changed; `execquery`/`stream` missing).

- [ ] **Step 3: Genericize the client**

In `src/openhound_sccm/clients/wmi.py`:
- Delete `_ROOT_SMS`, `identify()`, `_site_code_from_providers()`, `self._site_code`.
- Split each backend's `query(namespace, wql) -> list` into `execquery(namespace, wql) -> raw` + `stream(raw) -> Iterator[dict]`:

```python
# _ImpacketBackend
def execquery(self, namespace, wql):
    return self._services_for(namespace).ExecQuery(wql)   # raises on auth/connect failure

def stream(self, enum):
    try:
        while True:
            try:
                obj = enum.Next(0xFFFFFFFF, 1)[0]
            except Exception as ex:  # noqa: BLE001 - S_FALSE marks end of enumeration
                if "S_FALSE" in str(ex):
                    break
                raise
            yield _normalize(obj.getProperties())
    finally:
        enum.RemRelease()

# _PyWin32Backend
def execquery(self, namespace, wql):
    return self._services_for(namespace).ExecQuery(wql)

def stream(self, objset):
    for o in objset:
        yield _normalize_swbem(o)
```

- Replace `identify()`/`query()` with the lazy-ladder streaming `query`:

```python
def query(self, namespace: str, class_name: str, *, columns=None, where=None):
    """Run a WQL query against *namespace*, streaming normalized rows.

    The first query runs the auth ladder (this query is the probe) and caches the
    winning backend; later queries reuse it. Yields nothing (and logs) if the
    ladder is exhausted or the query fails."""
    wql = _build_wql(class_name, columns, where)
    try:
        raw = self._open(namespace, wql)
    except Exception as ex:  # noqa: BLE001 - one class failing must not abort the rest
        logger.warning("WMI query %s on %s failed: %s", class_name, self._target, ex)
        return
    if raw is None:
        return                                   # ladder exhausted (logged in _open)
    yield from self._backend.stream(raw)

def _open(self, namespace: str, wql: str):
    """Return a raw enumerator for (namespace, wql); run the ladder on first use."""
    if self._backend is not None:
        return self._backend.execquery(namespace, wql)
    plan = http_auth.choose_auth(
        username=self._username, password=self._password, nt_hash=self._nt_hash,
        ticket=self._kerberos_ticket, target_host=self._target,
        sspi_available=http_auth.sspi_negotiate_available(),
    )
    for rung in plan:
        backend = self._build_backend(rung)
        if backend is None:
            logger.info("WMI on %s: skipping anonymous rung (DCOM requires authentication)", self._target)
            continue
        try:
            logger.verbose("WMI auth attempt on %s via %s", self._target, rung)
            backend.connect()
            raw = backend.execquery(namespace, wql)
        except Exception as ex:  # noqa: BLE001 - this rung failed; try the next
            logger.verbose("WMI %s rung failed on %s: %s", rung, self._target, ex)
            backend.close()
            continue
        logger.info("WMI authenticated on %s via %s", self._target, rung)
        self._backend = backend
        return raw
    logger.info("WMI auth ladder exhausted on %s (%s)", self._target, plan)
    return None
```

- De-SCCM the module docstring (transport-only WMI client; namespace is the caller's concern).
- Keep `from_context`, `_build_backend`, `_load_ticket`, `_build_wql`, normalization, `close` unchanged.

- [ ] **Step 4: Run the client tests — expect PASS**

Run: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run pytest tests/test_wmi_client.py -q`
Expected: PASS.

- [ ] **Step 5: Checkpoint (no commit)** — `tests/test_wmi_client.py` green. `tests/test_wmi.py` is now expected-broken (deleted in Task 3).

---

### Task 2: Create `collectors/privileged.py` + `tests/test_privileged.py`

**Files:**
- Create: `src/openhound_sccm/collectors/privileged.py`
- Create: `tests/test_privileged.py`

- [ ] **Step 1: Write `tests/test_privileged.py` (helpers parameterized over both flavors)**

```python
"""Unit tests for the merged privileged collector (collectors/privileged.py).

The ten collection helpers are transport-agnostic — they read rows from a
`fetch` callable and label them via the `_Run` flavor — so they are tested once,
parameterized over both flavors. Transport plumbing (`_http_fetch`/`_wmi_fetch`/
identify) and the orchestrator are tested separately with canned clients."""
import json
import pytest

from openhound_sccm.clients.http import ErrorClass, HttpResult
from openhound_sccm.collectors import privileged as p
from openhound_sccm.models.target_entry import TargetEntry

FLAVORS = [("AdminService", "eq", "adminservice"), ("WMI", "=", "wmi")]


class _Ctx:
    def __init__(self, enabled=True, principal=None):
        self._enabled = enabled
        self.domain = "mayyhem.com"
        self.username = self.password = self.nt_hash = self.kerberos_ticket = None
        self.ad = None
        self._principal = principal
        self.target_hosts_by_hostname = {}
    def method_enabled(self, name): return self._enabled
    def resolve_principal(self, name): return self._principal


def _run(name, eq, pages, principal=None, calls=None):
    """A _Run whose fetch reads canned rows and records (class, columns, where)."""
    def fetch(class_name, columns=None, where=None):
        if calls is not None:
            calls.append((class_name, columns, where))
        return iter(pages.get(class_name, []))
    return p._Run(fetch=fetch, name=name, eq=eq, site_code="PS1", ctx=_Ctx(principal=principal))


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
    assert len(comp) == 2 and all(r["sccm_infra"] is True for r in comp)


@pytest.mark.parametrize("name,eq,tbl", FLAVORS)
def test_client_devices_filter_and_labels(name, eq, tbl):
    pages = {"SMS_CombinedDeviceResources": [
        {"Name": "WS1", "IsClient": True, "IsObsolete": False, "ResourceID": 1},
        {"Name": "WS2", "IsClient": False, "IsObsolete": False, "ResourceID": 2},
        {"Name": "WS3", "IsClient": True, "IsObsolete": True, "ResourceID": 3}]}
    rows = list(p._client_devices(_run(name, eq, pages)))
    assert [r["name"] for _, r in rows] == ["WS1"]
    assert rows[0][0] == f"{tbl}_client_devices"


@pytest.mark.parametrize("name,eq,tbl", FLAVORS)
def test_reserved_accounts_resolve_and_skip(name, eq, tbl):
    pages = {"SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\naa", "SiteCode": "PS1"}]}
    rows = list(p._reserved_accounts(_run(name, eq, pages, principal={"object_sid": "S-7"})))
    assert rows[0][0] == f"{tbl}_reserved_accounts" and rows[0][1]["source"] == f"{name}-SMS_SCI_Reserved"
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
    assert list(p._collections(_run(name, eq, pages)))[0][1]["member_count"] == 42
    assert list(p._collection_members(_run(name, eq, pages)))[0][1]["resource_id"] == 9
    role = list(p._security_roles(_run(name, eq, pages)))[0][1]
    assert role["role_name"] == "Full Admin" and "lazy_junk" not in role
    admin = list(p._admins(_run(name, eq, pages)))[0][1]
    assert admin["roles"] == ["R1"] and "secret_junk" not in admin
    ss = list(p._site_systems(_run(name, eq, pages)))[0][1]
    assert ss["sql_server_service_logon_account"] == "MAYYHEM\\svc" and "props" not in ss
```

(Plumbing + orchestrator tests added in Step 3's companion below.)

- [ ] **Step 2: Run helper tests — expect FAIL** (`privileged` not yet created)

Run: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run pytest tests/test_privileged.py -q`
Expected: FAIL (ModuleNotFoundError / `_Run` missing).

- [ ] **Step 3: Implement `collectors/privileged.py`**

```python
"""Privileged SCCM collect-only per-host collector (AdminService + WMI).

Both transports read the same SMS Provider classes, so they share one set of ten
collection helpers and one orchestrator. The only differences — transport, the
source-label prefix, and the table prefix — are injected via a `_Run`: a `fetch`
closure plus a flavor `name`/`eq`. Two thin entry points keep the two registered
phases (`AdminService`, `WMI`). Row shaping is in `sms_rows.py`."""
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, Optional

from ..clients.http import ErrorClass, HttpClient
from ..clients.http_auth import AuthMode
from ..clients.wmi import WmiClient
from ..context import SourceContext
from ..log_context import with_log_context
from .sms_rows import (
    _prop, _row, ADMIN_COLUMNS, COLLECTION_COLUMNS, COLLECTION_MEMBER_COLUMNS,
    DEVICE_COLUMNS, ROLE_COLUMNS, RSYSTEM_COLUMNS, RUSER_COLUMNS, SITE_COLUMNS,
    SITEDEF_COLUMNS, SYSRES_COLUMNS,
)

logger = logging.getLogger(__name__)
_BATCH = 1000


@dataclass(frozen=True)
class _Run:
    fetch: Callable[..., Iterator[dict]]   # (class_name, columns=None, where=None) -> rows
    name: str                              # "AdminService" / "WMI"
    eq: str                                # query dialect equality operator: "eq" / "="
    site_code: str
    ctx: SourceContext
    def source(self, cls: str) -> str:  return f"{self.name}-{cls}"
    def table(self, suffix: str) -> str: return f"{self.name.lower()}_{suffix}"


# --- collection helpers (PS1 order) ---------------------------------------

def _sites(run: _Run) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting all sites (SMS_Site) via %s", run.name)
    count = 0
    for site in run.fetch("SMS_Site", columns=SITE_COLUMNS):
        yield run.table("sites"), _row(run.source("SMS_Site"), run.site_code, site)
        target = site.get("SiteCode")
        if target:
            logger.verbose("  %s", target)
            yield from _site_definition(run, target)
        else:
            logger.warning("Site record missing SiteCode: %s", site)
        count += 1
    logger.info("Collected %d sites via %s", count, run.name)


def _site_definition(run: _Run, target_site: str) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting site definition for %s via %s", target_site, run.name)
    for sdef in run.fetch("SMS_SCI_SiteDefinition", columns=SITEDEF_COLUMNS,
                          where=f"SiteCode {run.eq} '{target_site}'"):
        props = sdef.get("Props")
        site_server = sdef.get("SiteServerName")
        sql_fqdn = _prop(props, "SQLServerFQDN", "Value1")
        yield run.table("site_definitions"), _row(
            run.source("SMS_SCI_SiteDefinition"), target_site, sdef, drop={"Props"},
            extra={"site_guid": _prop(props, "siteGUID", "Value1"),
                   "sql_server_fqdn": sql_fqdn,
                   "sql_service_port": _prop(props, "SQLServicePort", "Value")})
        for fqdn, role in ((site_server, "SMS Site Server"), (sql_fqdn, "SMS SQL Server")):
            if not fqdn:
                continue
            ad = run.ctx.resolve_principal(fqdn)
            if not ad:
                logger.warning("Failed to resolve %s (%s) to AD object", fqdn, role)
                continue
            row = {**ad, "source": f"{run.name}-SiteDefinition", "sccm_infra": True,
                   "sccm_site_system_roles": f"{role}@{target_site}" if target_site else role}
            row.setdefault("name", fqdn)
            yield run.table("site_definitions_computers"), row


def _reserved_accounts(run: _Run) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting stored accounts (SMS_SCI_Reserved) via %s", run.name)
    count = 0
    for account in run.fetch("SMS_SCI_Reserved"):
        ad = run.ctx.resolve_principal(account.get("UserName"))
        if not ad:
            logger.warning("Failed to resolve stored account %s to AD object", account.get("UserName"))
            continue
        row = {**ad, "source": run.source("SMS_SCI_Reserved"), "sccm_infra": True, **account}
        row.setdefault("name", account.get("UserName"))
        yield run.table("reserved_accounts"), row
        count += 1
    logger.info("Collected %d stored accounts via %s", count, run.name)


def _client_devices(run: _Run) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting client devices (SMS_CombinedDeviceResources) via %s", run.name)
    count = 0
    for device in run.fetch("SMS_CombinedDeviceResources", columns=DEVICE_COLUMNS):
        if device.get("IsClient") is False or device.get("IsObsolete") is True:
            logger.debug("Skipping device %s (IsClient=%s, IsObsolete=%s)",
                         device.get("Name"), device.get("IsClient"), device.get("IsObsolete"))
            continue
        count += 1
        yield run.table("client_devices"), _row(run.source("SMS_CombinedDeviceResources"), run.site_code, device)
    logger.info("Collected %d client devices via %s", count, run.name)


def _simple(run: _Run, cls: str, suffix: str, columns: Optional[tuple], label: str,
            *, keep: Optional[tuple] = None, extra_fn=None) -> Iterator[tuple[str, dict]]:
    """Shared body for the straight 'fetch -> _row' collections."""
    logger.verbose("Collecting %s (%s) via %s", label, cls, run.name)
    count = 0
    for obj in run.fetch(cls, columns=columns):
        extra = extra_fn(obj) if extra_fn else None
        yield run.table(suffix), _row(run.source(cls), run.site_code, obj, keep=keep, extra=extra)
        count += 1
    logger.info("Collected %d %s via %s", count, label, run.name)


def _r_system(run):        return _simple(run, "SMS_R_System", "r_system", RSYSTEM_COLUMNS, "system/group records")
def _r_user(run):          return _simple(run, "SMS_R_User", "r_user", RUSER_COLUMNS, "user/group records")
def _collections(run):     return _simple(run, "SMS_Collection", "collections", COLLECTION_COLUMNS, "collections")
def _collection_members(run): return _simple(run, "SMS_FullCollectionMembership", "collection_members", COLLECTION_MEMBER_COLUMNS, "collection memberships")
def _security_roles(run):  return _simple(run, "SMS_Role", "security_roles", None, "security roles", keep=ROLE_COLUMNS)
def _admins(run):          return _simple(run, "SMS_Admin", "admins", None, "admin users/groups", keep=ADMIN_COLUMNS)
def _site_systems(run):    return _simple(run, "SMS_SCI_SysResUse", "site_systems", None, "site system roles",
                                          keep=SYSRES_COLUMNS,
                                          extra_fn=lambda o: {"sql_server_service_logon_account":
                                              _prop(o.get("Props"), "SQL Server Service Logon Account", "Value2")})

_COLLECTIONS = (_sites, _reserved_accounts, _client_devices, _r_system, _r_user,
                _collections, _collection_members, _security_roles, _admins, _site_systems)


# --- transport adapters + identification ----------------------------------

def _http_get_value(client, path: str) -> Optional[list]:
    result = client.get(path)
    if result.error_class is ErrorClass.CONNECT_FAILURE:
        logger.verbose("AdminService GET %s failed to connect: %s", path, result.error_class.value)
        return None
    if result.error_class is not ErrorClass.RESPONSE:
        logger.warning("AdminService GET %s failed: %s", path, result.error_class.value)
        return None
    if result.status_code != 200:
        logger.warning("AdminService GET %s returned HTTP %s", path, result.status_code)
        return None
    try:
        value = json.loads(result.content or b"").get("value")
    except Exception as ex:  # noqa: BLE001 - malformed body
        logger.warning("AdminService GET %s returned invalid JSON: %s", path, ex)
        return None
    if value is None:
        logger.warning("AdminService GET %s response had no 'value' array", path)
    return value


def _http_fetch(client) -> Callable[..., Iterator[dict]]:
    def fetch(class_name, columns=None, where=None):
        path = f"/AdminService/wmi/{class_name}"
        params = []
        if columns:
            params.append("$select=" + ",".join(columns))
        if where:
            params.append("$filter=" + where)
        base = path + ("?" + "&".join(params) if params else "")
        skip = 0
        while True:
            sep = "&" if "?" in base else "?"
            value = _http_get_value(client, f"{base}{sep}$top={_BATCH}&$skip={skip}")
            if not value:
                return
            yield from value
            if len(value) < _BATCH:
                return
            skip += _BATCH
    return fetch


def _wmi_fetch(client, namespace: str) -> Callable[..., Iterator[dict]]:
    def fetch(class_name, columns=None, where=None):
        yield from client.query(namespace, class_name, columns=columns, where=where)
    return fetch


def _http_identify(client) -> Optional[str]:
    value = _http_get_value(client, "/AdminService/wmi/SMS_Identification?$select=ThisSiteCode,ThisSiteName")
    if not value:
        return None
    site_code = value[0].get("ThisSiteCode")
    if not site_code:
        logger.warning("AdminService SMS_Identification returned no site code")
        return None
    logger.info("Identified AdminService site: %s (%s)", site_code, value[0].get("ThisSiteName"))
    return site_code


def _wmi_identify(client) -> Optional[str]:
    rows = list(client.query("root\\SMS", "SMS_ProviderLocation"))
    if not rows:
        logger.info("WMI SMS_ProviderLocation returned nothing (rung exhausted or not a provider)")
        return None
    local = next((r for r in rows if r.get("ProviderForLocalSite")), rows[0])
    site_code = local.get("SiteCode")
    if not site_code:
        logger.warning("WMI SMS_ProviderLocation returned no site code")
        return None
    logger.info("Identified WMI SMS Provider site: %s", site_code)
    return site_code


# --- orchestrator + entry points ------------------------------------------

def _collect(run: _Run, target: str) -> Iterator[tuple[str, dict]]:
    for collection in _COLLECTIONS:
        try:
            yield from collection(run)
        except Exception as ex:  # noqa: BLE001 - one collection failing must not abort the rest
            logger.warning("%s %s failed on %s: %s", run.name, collection.__name__, target, ex)
    entry = run.ctx.target_hosts_by_hostname.get(target.lower())
    if entry is not None:
        entry.completed_phases.add(run.name)
        logger.verbose("Marked %s complete on %s", run.name, target)
    else:
        logger.debug("No TargetEntry for %s; phase-completion gating unavailable", target)
    logger.info("%s collection completed for %s (site %s)", run.name, target, run.site_code)


@with_log_context(phase="AdminService")
def collect_adminservice(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    if not ctx.method_enabled("AdminService"):
        return
    logger.info("Starting AdminService collection on %s...", target)
    client = HttpClient.from_context(ctx, target, auth=AuthMode.NEGOTIATE)
    try:
        site_code = _http_identify(client)
        if site_code is None:
            logger.info("%s is not a reachable AdminService provider; skipping", target)
            return
        yield from _collect(_Run(_http_fetch(client), "AdminService", "eq", site_code, ctx), target)
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("AdminService collection failed for %s: %s", target, ex)
    finally:
        client.close()


@with_log_context(phase="WMI")
def collect_wmi(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    if not ctx.method_enabled("WMI"):
        return
    logger.info("Starting WMI collection on %s...", target)
    client = WmiClient.from_context(ctx, target)
    try:
        site_code = _wmi_identify(client)
        if site_code is None:
            logger.info("%s is not a reachable SMS Provider over WMI; skipping", target)
            return
        namespace = f"root\\SMS\\site_{site_code}"
        yield from _collect(_Run(_wmi_fetch(client, namespace), "WMI", "=", site_code, ctx), target)
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("WMI collection failed for %s: %s", target, ex)
    finally:
        client.close()
```

- [ ] **Step 4: Add plumbing + orchestrator tests to `tests/test_privileged.py`**

```python
class _FakeHttp:
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
        top = _qint(path, "$top"); skip = _qint(path, "$skip") or 0
        page = rows[skip:skip + top] if top else rows
        return HttpResult(self.status, json.dumps({"value": page}).encode(), ErrorClass.RESPONSE)
    def close(self): pass

def _qint(path, key):
    for part in path.replace("?", "&").split("&"):
        if part.startswith(key + "="):
            return int(part.split("=", 1)[1])
    return None

class _FakeWmi:
    def __init__(self, pages): self.pages, self.queries, self.closed = pages, [], False
    def query(self, namespace, class_name, *, columns=None, where=None):
        self.queries.append((namespace, class_name)); yield from self.pages.get(class_name, [])
    def close(self): self.closed = True


def test_http_identify_and_paginate():
    rows = [{"n": i} for i in range(2500)]
    fake = _FakeHttp({"SMS_Identification": [{"ThisSiteCode": "PS1"}], "SMS_R_System": rows})
    assert p._http_identify(fake) == "PS1"
    got = list(p._http_fetch(fake)("SMS_R_System", columns=("n",)))
    assert len(got) == 2500
    assert [_qint(c, "$skip") for c in fake.calls if "SMS_R_System" in c] == [0, 1000, 2000]

def test_http_identify_aborts_when_empty():
    assert p._http_identify(_FakeHttp({"SMS_Identification": []})) is None
    assert p._http_identify(_FakeHttp({})) is None

def test_wmi_identify_picks_local_provider():
    fake = _FakeWmi({"SMS_ProviderLocation": [
        {"SiteCode": "AAA", "ProviderForLocalSite": False},
        {"SiteCode": "PS1", "ProviderForLocalSite": True}]})
    assert p._wmi_identify(fake) == "PS1"
    assert p._wmi_identify(_FakeWmi({"SMS_ProviderLocation": []})) is None

ALL_CLASSES = {
    "SMS_Identification": [{"ThisSiteCode": "PS1"}],
    "SMS_ProviderLocation": [{"SiteCode": "PS1", "ProviderForLocalSite": True}],
    "SMS_Site": [{"SiteCode": "PS1"}], "SMS_SCI_SiteDefinition": [{"SiteCode": "PS1", "Props": []}],
    "SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\naa"}],
    "SMS_CombinedDeviceResources": [{"Name": "WS1", "IsClient": True, "IsObsolete": False}],
    "SMS_R_System": [{"Name": "WS1", "SID": "S-1"}], "SMS_R_User": [{"Name": "u", "SID": "S-2"}],
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
    ctx = _Ctx(principal={"object_sid": "S-9"}); ctx.target_hosts_by_hostname = {"ps1-sms.mayyhem.com": entry}
    rows = list(p.collect_adminservice("ps1-sms.mayyhem.com", ctx))
    assert "wmi/SMS_Identification" in fake.calls[0]
    assert {t for t, _ in rows} == EXPECT_AS
    assert "AdminService" in entry.completed_phases
    from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
    assert EXPECT_AS <= set(all_table_names(PER_HOST_PHASES))

def test_collect_wmi_order_and_marks(monkeypatch):
    fake = _FakeWmi(ALL_CLASSES)
    monkeypatch.setattr(p.WmiClient, "from_context", classmethod(lambda cls, ctx, target: fake))
    entry = TargetEntry(hostname="ps1-sms.mayyhem.com", ad_object=None)
    ctx = _Ctx(principal={"object_sid": "S-9"}); ctx.target_hosts_by_hostname = {"ps1-sms.mayyhem.com": entry}
    rows = list(p.collect_wmi("ps1-sms.mayyhem.com", ctx))
    assert fake.queries[0] == ("root\\SMS", "SMS_ProviderLocation")  # identify first
    assert fake.queries[1][1] == "SMS_Site"                          # then collection order
    assert {t for t, _ in rows} == {t.replace("adminservice_", "wmi_") for t in EXPECT_AS}
    assert "WMI" in entry.completed_phases and fake.closed

def test_method_disabled_yields_nothing():
    assert list(p.collect_adminservice("h", _Ctx(enabled=False))) == []
    assert list(p.collect_wmi("h", _Ctx(enabled=False))) == []

def test_gate_failure_does_not_mark(monkeypatch):
    fake = _FakeHttp({"SMS_Identification": []})
    monkeypatch.setattr(p.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    entry = TargetEntry(hostname="h", ad_object=None)
    ctx = _Ctx(); ctx.target_hosts_by_hostname = {"h": entry}
    assert list(p.collect_adminservice("h", ctx)) == []
    assert "AdminService" not in entry.completed_phases

def test_one_failing_collection_does_not_abort_rest(monkeypatch):
    fake = _FakeHttp({"SMS_Identification": [{"ThisSiteCode": "PS1"}], "SMS_Site": [{"SiteCode": "PS1"}]})
    monkeypatch.setattr(p.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    tables = {t for t, _ in p.collect_adminservice("h", _Ctx(principal=None))}
    assert "adminservice_sites" in tables
```

- [ ] **Step 5: Run all of `test_privileged.py` — expect PASS**

Run: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run pytest tests/test_privileged.py -q`
Expected: PASS.

- [ ] **Step 6: Checkpoint (no commit)** — `test_privileged.py` + `test_wmi_client.py` green.

---

### Task 3: Wire phases to `privileged`; delete old collectors + tests

**Files:**
- Modify: `src/openhound_sccm/per_host_phases.py:13,47,66`
- Delete: `collectors/adminservice.py`, `collectors/wmi.py`, `tests/test_adminservice.py`, `tests/test_wmi.py`

- [ ] **Step 1: Repoint the phase registry**

In `per_host_phases.py`: change the import line to `from .collectors import registry, mssql, privileged` and set the two phase collectors to `privileged.collect_adminservice` and `privileged.collect_wmi`. Update the WMI phase comment to reference `privileged`. Leave phase names, table tuples, `all_table_names`, and `should_run_phase` unchanged.

- [ ] **Step 2: Delete the superseded modules and tests**

```bash
git rm src/openhound_sccm/collectors/adminservice.py src/openhound_sccm/collectors/wmi.py \
       tests/test_adminservice.py tests/test_wmi.py
```
(If `git rm` is undesirable pre-commit, plain file deletion is fine — owner commits.)

- [ ] **Step 3: Run the FULL suite — expect PASS**

Run: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run pytest -q`
Expected: PASS (no references to the deleted modules remain).

- [ ] **Step 4: Checkpoint (no commit)** — full suite green.

---

### Task 4: Update the debug scripts

**Files:**
- Modify: `debug_wmi_auth.py:30,49,56` (and the namespace/`len()` usage)
- Modify: `debug_per_host.py` (stale comment near line 155)

- [ ] **Step 1: `debug_wmi_auth.py` — identify via the adapter, pass a namespace, list the iterator**

Replace `client.identify()` and `client.query(cls)` usage in `_probe`:

```python
from openhound_sccm.clients.wmi import WmiClient
from openhound_sccm.collectors.privileged import _wmi_identify
...
    site = _wmi_identify(client)
    print(f"  identify() -> {site!r}")
    if site is None:
        print("  FAIL: no site code (rung exhausted or not a provider)")
        return False
    namespace = f"root\\SMS\\site_{site}"
    ok = True
    for cls in _PROBE_CLASSES:
        rows = list(client.query(namespace, cls))
        n = len(rows)
        sample = list(rows[0].keys())[:6] if rows else []
        print(f"  {cls:24} -> {n} rows; sample keys: {sample}")
        if cls == "SMS_SCI_SiteDefinition" and rows:
            props = rows[0].get("Props")
            print(f"      Props normalized -> {type(props).__name__}, "
                  f"first={props[0] if isinstance(props, list) and props else props}")
    return ok
```

- [ ] **Step 2: `debug_per_host.py` — fix the stale timing comment**

Update the comment block (around line 155) that says the marker is set "right after `_identification()` succeeds" to describe the new behavior: marked at the **end** of `collect_adminservice` (after the collection loop). Keep the surrounding debug logic unchanged.

- [ ] **Step 3: Smoke-import both scripts — expect no ImportError**

Run: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run python -c "import ast; ast.parse(open('debug_wmi_auth.py').read()); ast.parse(open('debug_per_host.py').read()); print('parse ok')"`
Expected: `parse ok`. (Live runs need lab creds — best-effort, Task 5.)

- [ ] **Step 4: Checkpoint (no commit).**

---

### Task 5: Full validation + ticket close

- [ ] **Step 1: Tests, lint, types**

```
UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run pytest -q
UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run ruff check src/
UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run mypy src/
```
Expected: pytest PASS; ruff clean (or only pre-existing warnings); mypy no new errors. Report anything skipped.

- [ ] **Step 2: Live lab validation (best-effort)** — if `ps1-sms.mayyhem.com` is reachable, run `uv run python debug_wmi_auth.py` and confirm identify + the three probe classes stream rows. Report if skipped (host often powered off).

- [ ] **Step 3: Update the ticket**

```bash
gtk add-note ope-38ad "Merged adminservice+wmi into privileged.py; genericized WmiClient (streaming, namespace-per-query, lazy ladder); end-of-collection marking for both; tests folded into test_privileged.py. pytest/ruff/mypy: <results>."
```
Leave `ope-38ad` in_progress until the owner has tested + committed (per CLAUDE.md).

---

## Self-Review

**Spec coverage:** generic client (T1), streaming both transports (T1 backends + T2 `_http_fetch`/`_wmi_fetch`), `_Run`+helpers+adapters+orchestrator (T2), where-string with `run.eq` (T2 `_site_definition` + test), end-of-collection marking (T2 `_collect` + tests), entry points keep two phases (T2 + T3), files created/modified/deleted (T2/T3/T4), tests folded (T2/T3), debug scripts (T4), validation (T5). All covered.

**Placeholder scan:** none — every code step shows full code; `<results>` in T5 is a runtime value, not a code placeholder.

**Type/name consistency:** `query(namespace, class_name, *, columns, where)`, `execquery`/`stream`, `_Run(fetch, name, eq, site_code, ctx)`, `run.source()`/`run.table()`, `_http_fetch`/`_wmi_fetch`/`_http_identify`/`_wmi_identify`, `_collect(run, target)` — consistent across T1–T4 and the spec.
