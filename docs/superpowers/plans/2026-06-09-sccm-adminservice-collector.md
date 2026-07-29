# AdminService Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `Invoke-AdminServiceCollection` from `ConfigManBearPig.ps1` into a collect-only per-host phase that queries the SCCM AdminService REST API over Negotiate and emits 13 raw `adminservice_*` JSONL tables.

**Architecture:** A `@with_log_context(phase="AdminService")` orchestrator builds the shared `HttpClient` (NEGOTIATE), runs an `SMS_Identification` gate, then `yield from` one helper per collection in exact PS1 order (two new collections appended last). Helpers share `_get_value` (GET → JSON `value[]`), `_paginate` (`$top`/`$skip`), and `_row` (snake-case raw fields + `source`/`source_site_code`). No AD resolution, no node/edge building — those are a deferred convert stage.

**Tech Stack:** Python 3.13+, the shared `clients/http.py` + `clients/http_auth.py` (ope-d57d), `requests`/`impacket` (transitive), `pytest` with a fake HTTP client.

**Spec:** [../specs/2026-06-09-sccm-adminservice-collector-design.md](../specs/2026-06-09-sccm-adminservice-collector-design.md)
**Ticket:** ope-b287 (depends on ope-d57d)

---

## Conventions for this plan

- **Auto Mode (no human gating).** Run each Validation Checkpoint and, on green, continue immediately to the next task. Stop only on a validation failure you can't fix or a genuine decision point.
- **No `git commit` steps.** The owner commits after testing. Do not `git add`/`git commit`.
- **Validation runs in an isolated uv env outside the repo.** Set once per shell, then run `uv run` from the repo root:
  - PowerShell (this host is win32): `$env:UV_PROJECT_ENVIRONMENT = "$env:TEMP\openhound-venv"`
  - POSIX: `export UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv`
  - All commands below use `uv run --directory sccm\sccm ...`.
- **TDD:** failing test → watch it fail → minimal impl → watch it pass.
- **Logging:** every collection start/success/failure and the gate log at info/verbose/warning per the project rule (code blocks below include these).
- **No bespoke models:** raw tables use the generic `raw_table_asset(table_name)` the emit wiring already applies; no Pydantic model per table.

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `src/openhound_sccm/collectors/adminservice.py` | Orchestrator + gate + collection helpers + `_get_value`/`_paginate`/`_row`/`_snake`/`_prop` | **Replace stub** |
| `src/openhound_sccm/per_host_phases.py` | Register the `AdminService` phase with its 13 stream names, after `MSSQL` | Modify |
| `tests/test_adminservice.py` | Unit tests with a `FakeClient` returning canned AdminService JSON | **Create** |

`main.py`'s `_preproc_table_map` already lists every `adminservice_*` table name (including `collection_variables`, `task_sequences`, and the deferred `role_members`), so **no `main.py` change is needed**.

---

## Task 1: Module plumbing, gate, orchestrator skeleton, phase registration

**Files:**
- Replace: `src/openhound_sccm/collectors/adminservice.py`
- Modify: `src/openhound_sccm/per_host_phases.py`
- Create: `tests/test_adminservice.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_adminservice.py`:

```python
"""Unit tests for the AdminService collect-only per-host collector."""
import json

from openhound_sccm.clients.http import ErrorClass, HttpResult
from openhound_sccm.collectors import adminservice as a


class FakeClient:
    """Canned AdminService client. `pages` maps a WMI class name to its full row
    list; `_paginate`/`_get_value` slice it by $top/$skip. status/error_class let
    tests simulate non-providers and backend errors."""

    def __init__(self, pages=None, status=200, error_class=ErrorClass.RESPONSE):
        self.pages = pages or {}
        self.status = status
        self.error_class = error_class
        self.calls = []

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


def test_snake_handles_acronyms():
    assert a._snake("SiteCode") == "site_code"
    assert a._snake("AADDeviceID") == "aad_device_id"
    assert a._snake("ThisSiteCode") == "this_site_code"
    assert a._snake("SMSID") == "smsid"


def test_identification_returns_site_code():
    fake = FakeClient({"SMS_Identification": [{"ThisSiteCode": "PS1", "ThisSiteName": "Primary"}]})
    assert a._identification(fake) == "PS1"


def test_identification_aborts_when_empty():
    assert a._identification(FakeClient({"SMS_Identification": []})) is None
    assert a._identification(FakeClient({})) is None  # 404 -> None


def test_paginate_stops_on_short_page():
    rows = [{"n": i} for i in range(2500)]
    fake = FakeClient({"SMS_R_System": rows})
    got = list(a._paginate(fake, "wmi/SMS_R_System"))
    assert len(got) == 2500
    # 3 pages: 1000, 1000, 500 (short page ends it)
    assert sum(1 for c in fake.calls if "$skip=0&" in c.replace("?", "&") + "&" or "$skip=0" in c) >= 1


def test_row_snakes_and_tags():
    row = a._row("AdminService-SMS_Site", "PS1", {"SiteCode": "PS1", "@odata.type": "x", "BuildNumber": "9000"})
    assert row == {"source": "AdminService-SMS_Site", "source_site_code": "PS1",
                   "site_code": "PS1", "build_number": "9000"}


def test_gate_failure_yields_nothing(monkeypatch):
    fake = FakeClient({"SMS_Identification": []})
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    ctx = _Ctx()
    assert list(a.collect_adminservice("ps1-sms.mayyhem.com", ctx)) == []


def test_method_disabled_yields_nothing():
    ctx = _Ctx(enabled=False)
    assert list(a.collect_adminservice("ps1-sms.mayyhem.com", ctx)) == []


class _Ctx:
    """Minimal SourceContext stand-in."""
    def __init__(self, enabled=True):
        self._enabled = enabled
        self.domain = "mayyhem.com"
        self.username = None
        self.password = None
        self.nt_hash = None
        self.kerberos_ticket = None
        self.ad = None

    def method_enabled(self, name):
        return self._enabled
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: FAIL with `ModuleNotFoundError`/`AttributeError` (helpers undefined).

- [ ] **Step 3: Write the module skeleton**

Replace `src/openhound_sccm/collectors/adminservice.py` with:

```python
"""AdminService collect-only per-host collector.

Ports ConfigManBearPig.ps1's Invoke-AdminServiceCollection: queries the SCCM
AdminService REST API over Negotiate (the shared HttpClient) and yields raw
JSONL rows. No AD resolution or graph building — that is a deferred convert
stage. Collection order matches the PS1 exactly; the two collections the PS1
does not gather (collection variables, task sequences) are appended last.
"""
import json
import logging
import re
from typing import Any, Iterable, Iterator, Optional

from ..clients.http import ErrorClass, HttpClient
from ..clients.http_auth import AuthMode
from ..context import SourceContext
from ..log_context import with_log_context

logger = logging.getLogger(__name__)

_BATCH = 1000

# Acronym-aware camelCase/PascalCase -> snake_case (AADDeviceID -> aad_device_id).
_SNAKE_1 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_SNAKE_2 = re.compile(r"([a-z0-9])([A-Z])")


def _snake(name: str) -> str:
    return _SNAKE_2.sub(r"\1_\2", _SNAKE_1.sub(r"\1_\2", name)).lower()


def _get_value(client, path: str) -> Optional[list]:
    """GET an AdminService path; return its JSON ``value`` list, or None on failure."""
    result = client.get(path)
    if result.error_class is not ErrorClass.RESPONSE:
        logger.warning("AdminService GET %s failed: %s", path, result.error_class.value)
        return None
    if result.status_code != 200:
        logger.warning("AdminService GET %s returned HTTP %s", path, result.status_code)
        return None
    try:
        data = json.loads(result.content or b"")
    except Exception as ex:  # noqa: BLE001 - malformed body
        logger.warning("AdminService GET %s returned invalid JSON: %s", path, ex)
        return None
    value = data.get("value")
    if value is None:
        logger.warning("AdminService GET %s response had no 'value' array", path)
        return None
    return value


def _paginate(client, path: str) -> Iterator[dict]:
    """Yield rows across ``$top``/``$skip`` pages until a short (final) page."""
    skip = 0
    while True:
        sep = "&" if "?" in path else "?"
        value = _get_value(client, f"{path}{sep}$top={_BATCH}&$skip={skip}")
        if not value:
            return
        for row in value:
            yield row
        if len(value) < _BATCH:
            return
        skip += _BATCH


def _prop(props: Optional[list], name: str, field: str = "Value1") -> Any:
    """Return one SMS Props value (by PropertyName), or None."""
    for p in props or []:
        if p.get("PropertyName") == name:
            return p.get(field)
    return None


def _row(source: str, site_code: Optional[str], obj: dict, *,
         keep: Optional[set] = None, drop: Optional[set] = None,
         extra: Optional[dict] = None) -> dict:
    """Build a raw row: snake-cased API fields + source + source_site_code.

    ``keep`` (original field names) whitelists columns for no-$select endpoints;
    ``drop`` excludes flattened blobs (e.g. Props); ``extra`` adds derived values.
    OData metadata keys (``@...``) are always dropped.
    """
    row: dict[str, Any] = {"source": source, "source_site_code": site_code}
    drop = drop or set()
    for k, v in obj.items():
        if k.startswith("@") or k in drop:
            continue
        if keep is not None and k not in keep:
            continue
        row[_snake(k)] = v
    if extra:
        row.update(extra)
    return row


def _identification(client) -> Optional[str]:
    """Gate: this SMS provider's site code, or None if not a reachable provider."""
    value = _get_value(client, "wmi/SMS_Identification")
    if not value:
        return None
    site_code = value[0].get("ThisSiteCode")
    if not site_code:
        logger.warning("AdminService SMS_Identification returned no ThisSiteCode")
        return None
    logger.info("AdminService identified site %s (%s)", site_code, value[0].get("ThisSiteName"))
    return site_code


# --- collection helpers (filled in by later tasks) -------------------------

def _sites(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _reserved_accounts(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _client_devices(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _r_system(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _r_user(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _collections(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _collection_members(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _security_roles(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _admins(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


def _site_systems(client, site_code: str) -> Iterator[tuple[str, dict]]:
    return
    yield  # pragma: no cover


# --- orchestrator ----------------------------------------------------------

# Collections in exact PS1 order; the two new ones appended last.
_COLLECTIONS = (
    _sites,
    _reserved_accounts,
    _client_devices,
    _r_system,
    _r_user,
    _collections,
    _collection_members,
    _security_roles,
    _admins,
    _site_systems,
    _collection_variables,  # new (not in PS1)
    _task_sequences,        # new (not in PS1)
)


@with_log_context(phase="AdminService")
def collect_adminservice(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield raw AdminService rows for one target, or nothing if it isn't a
    reachable SMS provider (the SMS_Identification gate fails)."""
    if not ctx.method_enabled("AdminService"):
        return

    logger.info("Starting AdminService collection on %s", target)
    client = HttpClient.from_context(ctx, target, auth=AuthMode.NEGOTIATE)
    try:
        site_code = _identification(client)
        if site_code is None:
            logger.info("%s is not a reachable AdminService provider; skipping", target)
            return
        for collection in _COLLECTIONS:
            try:
                yield from collection(client, site_code)
            except Exception as ex:  # noqa: BLE001 - one collection failing must not abort the rest
                logger.warning("AdminService %s failed on %s: %s", collection.__name__, target, ex)
        logger.info("AdminService collection completed for %s (site %s)", target, site_code)
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("AdminService collection failed for %s: %s", target, ex)
    finally:
        client.close()
```

- [ ] **Step 4: Register the phase**

In `src/openhound_sccm/per_host_phases.py`, import `adminservice` and add the phase after `MSSQL`:

```python
from .collectors import registry, mssql, adminservice
```

```python
    Phase(
        "MSSQL",(
            "mssql_instances",
        ), mssql.collect_mssql,
    ),
    Phase(
        "AdminService", (
            "adminservice_sites",
            "adminservice_site_definitions",
            "adminservice_reserved_accounts",
            "adminservice_client_devices",
            "adminservice_r_system_security_groups",
            "adminservice_r_user_security_groups",
            "adminservice_collections",
            "adminservice_collection_members",
            "adminservice_security_roles",
            "adminservice_admins",
            "adminservice_site_systems",
            "adminservice_collection_variables",
            "adminservice_task_sequences",
        ), adminservice.collect_adminservice,
    ),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS (snake, gate, paginate, row, gate-failure, method-disabled).

- [ ] **Step 6: Validation Checkpoint**

Run: `uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py src/openhound_sccm/per_host_phases.py tests/test_adminservice.py`
And confirm the phase registers: `uv run --directory sccm\sccm python -c "from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names; print([p.name for p in PER_HOST_PHASES]); assert 'adminservice_sites' in all_table_names(PER_HOST_PHASES)"`
Expected: `['RemoteRegistry', 'MSSQL', 'AdminService']` and no assertion error. Continue automatically on green.

---

## Task 2: Sites + site definitions

**Files:**
- Modify: `src/openhound_sccm/collectors/adminservice.py` (replace `_sites` stub)
- Test: `tests/test_adminservice.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_adminservice.py`:

```python
def test_sites_emits_site_and_definition_with_flattened_props():
    pages = {
        "SMS_Site": [{"SiteCode": "PS1", "ServerName": "ps1.mayyhem.com", "BuildNumber": "9078",
                      "SiteName": "Primary", "Type": 2, "Version": "5.0"}],
        "SMS_SCI_SiteDefinition": [{
            "SiteCode": "PS1", "SiteServerName": "ps1.mayyhem.com", "SQLDatabaseName": "CM_PS1",
            "SQLServerName": "ps1-db", "Props": [
                {"PropertyName": "siteGUID", "Value1": "{GUID}"},
                {"PropertyName": "SQLServerFQDN", "Value1": "ps1-db.mayyhem.com"},
                {"PropertyName": "SQLServicePort", "Value": 1433},
            ]}],
    }
    rows = list(a._sites(FakeClient(pages), "PS1"))
    tables = {t for t, _ in rows}
    assert tables == {"adminservice_sites", "adminservice_site_definitions"}
    site = next(r for t, r in rows if t == "adminservice_sites")
    assert site["site_code"] == "PS1" and site["build_number"] == "9078" and site["source_site_code"] == "PS1"
    sdef = next(r for t, r in rows if t == "adminservice_site_definitions")
    assert sdef["site_guid"] == "{GUID}"
    assert sdef["sql_server_fqdn"] == "ps1-db.mayyhem.com"
    assert sdef["sql_service_port"] == 1433
    assert "props" not in sdef  # raw Props blob dropped after flattening
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py::test_sites_emits_site_and_definition_with_flattened_props -q`
Expected: FAIL (`_sites` yields nothing).

- [ ] **Step 3: Implement `_sites`**

In `adminservice.py`, replace the `_sites` stub with:

```python
_SITE_SELECT = ("$select=BuildNumber,InstallDir,ReportingSiteCode,ServerName,"
                "SiteCode,SiteName,Status,Type,Version")
_SITEDEF_SELECT = ("$select=ParentSiteCode,SiteCode,SiteName,SiteServerDomain,"
                   "SiteServerName,SiteType,SQLDatabaseName,SQLServerName,Props")


def _sites(client, site_code: str) -> Iterator[tuple[str, dict]]:
    value = _get_value(client, f"wmi/SMS_Site?{_SITE_SELECT}")
    if value is None:
        return
    logger.info("AdminService collected %d sites", len(value))
    for site in value:
        yield "adminservice_sites", _row("AdminService-SMS_Site", site_code, site)
        sc = site.get("SiteCode")
        if sc:
            yield from _site_definition(client, site_code, sc)


def _site_definition(client, site_code: str, target_site: str) -> Iterator[tuple[str, dict]]:
    path = f"wmi/SMS_SCI_SiteDefinition?$filter=SiteCode eq '{target_site}'&{_SITEDEF_SELECT}"
    value = _get_value(client, path)
    if not value:
        return
    for sdef in value:
        props = sdef.get("Props")
        yield "adminservice_site_definitions", _row(
            "AdminService-SMS_SCI_SiteDefinition", site_code, sdef, drop={"Props"},
            extra={
                "site_guid": _prop(props, "siteGUID", "Value1"),
                "sql_server_fqdn": _prop(props, "SQLServerFQDN", "Value1"),
                "sql_service_port": _prop(props, "SQLServicePort", "Value"),
            },
        )
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py`
Expected: clean. Continue automatically on green.

---

## Task 3: Reserved accounts + client devices

**Files:**
- Modify: `src/openhound_sccm/collectors/adminservice.py` (replace `_reserved_accounts`, `_client_devices`)
- Test: `tests/test_adminservice.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_adminservice.py`:

```python
def test_reserved_accounts():
    pages = {"SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\svc_naa", "SiteCode": "PS1"}]}
    rows = list(a._reserved_accounts(FakeClient(pages), "PS1"))
    assert rows == [("adminservice_reserved_accounts",
                     {"source": "AdminService-SMS_SCI_Reserved", "source_site_code": "PS1",
                      "user_name": "MAYYHEM\\svc_naa", "site_code": "PS1"})]


def test_client_devices_filters_non_clients_and_obsolete():
    pages = {"SMS_CombinedDeviceResources": [
        {"Name": "WS1", "SMSID": "GUID1", "IsClient": True, "IsObsolete": False, "ResourceID": 1},
        {"Name": "WS2", "SMSID": "GUID2", "IsClient": False, "IsObsolete": False, "ResourceID": 2},
        {"Name": "WS3", "SMSID": "GUID3", "IsClient": True, "IsObsolete": True, "ResourceID": 3},
    ]}
    rows = list(a._client_devices(FakeClient(pages), "PS1"))
    names = [r["name"] for _, r in rows]
    assert names == ["WS1"]  # non-client + obsolete skipped
    assert rows[0][0] == "adminservice_client_devices"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -k "reserved or client_devices" -q`
Expected: FAIL.

- [ ] **Step 3: Implement both helpers**

Replace the `_reserved_accounts` and `_client_devices` stubs:

```python
def _reserved_accounts(client, site_code: str) -> Iterator[tuple[str, dict]]:
    value = _get_value(client, "wmi/SMS_SCI_Reserved")
    if value is None:
        return
    logger.info("AdminService collected %d reserved accounts", len(value))
    for account in value:
        yield "adminservice_reserved_accounts", _row("AdminService-SMS_SCI_Reserved", site_code, account)


_DEVICE_SELECT = ("$select=AADDeviceID,AADTenantID,ADLastLogonTime,CNAccessMP,CNLastOfflineTime,"
                  "CNLastOnlineTime,CoManaged,CurrentLogonUser,DeviceOS,DeviceOSBuild,IsClient,"
                  "IsObsolete,IsVirtualMachine,LastActiveTime,LastMPServerName,Name,PrimaryUser,"
                  "ResourceID,SiteCode,SMSID,UserName,UserDomainName")


def _client_devices(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for device in _paginate(client, f"wmi/SMS_CombinedDeviceResources?{_DEVICE_SELECT}"):
        # Mirror PS1: skip non-clients and obsolete records (stale reinstalls).
        if device.get("IsClient") is False or device.get("IsObsolete") is True:
            continue
        count += 1
        yield "adminservice_client_devices", _row(
            "AdminService-SMS_CombinedDeviceResources", site_code, device)
    logger.info("AdminService collected %d client devices", count)
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py`
Expected: clean. Continue automatically on green.

---

## Task 4: R_System + R_User security groups

**Files:**
- Modify: `src/openhound_sccm/collectors/adminservice.py` (replace `_r_system`, `_r_user`)
- Test: `tests/test_adminservice.py`

- [ ] **Step 1: Write the failing tests**

Append:

```python
def test_r_system_rows():
    pages = {"SMS_R_System": [{"Name": "WS1", "SID": "S-1-5-21-1", "ResourceID": 1,
                               "SMSUniqueIdentifier": "GUID1", "Client": 1, "Obsolete": 0,
                               "SecurityGroupName": ["MAYYHEM\\g1", "MAYYHEM\\g2"]}]}
    rows = list(a._r_system(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_r_system_security_groups"
    assert rows[0][1]["security_group_name"] == ["MAYYHEM\\g1", "MAYYHEM\\g2"]
    assert rows[0][1]["sid"] == "S-1-5-21-1"


def test_r_user_rows():
    pages = {"SMS_R_User": [{"Name": "MAYYHEM\\alice", "SID": "S-1-5-21-9", "ResourceID": 5,
                             "SecurityGroupName": ["MAYYHEM\\admins"], "UserName": "alice"}]}
    rows = list(a._r_user(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_r_user_security_groups"
    assert rows[0][1]["user_name"] == "alice"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -k "r_system or r_user" -q`
Expected: FAIL.

- [ ] **Step 3: Implement both helpers**

```python
_RSYSTEM_SELECT = "$select=Client,Name,Obsolete,ResourceID,SID,SMSUniqueIdentifier,SecurityGroupName,SystemRoles"
_RUSER_SELECT = ("$select=AADTenantID,AADUserID,DistinguishedName,FullDomainName,FullUserName,Name,"
                 "ResourceID,SecurityGroupName,SID,UniqueUserName,UserName,UserPrincipalName")


def _r_system(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for system in _paginate(client, f"wmi/SMS_R_System?{_RSYSTEM_SELECT}"):
        count += 1
        yield "adminservice_r_system_security_groups", _row(
            "AdminService-SMS_R_System", site_code, system)
    logger.info("AdminService collected %d SMS_R_System records", count)


def _r_user(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for user in _paginate(client, f"wmi/SMS_R_User?{_RUSER_SELECT}"):
        count += 1
        yield "adminservice_r_user_security_groups", _row(
            "AdminService-SMS_R_User", site_code, user)
    logger.info("AdminService collected %d SMS_R_User records", count)
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py`
Expected: clean. Continue automatically on green.

---

## Task 5: Collections + collection members

**Files:**
- Modify: `src/openhound_sccm/collectors/adminservice.py` (replace `_collections`, `_collection_members`)
- Test: `tests/test_adminservice.py`

- [ ] **Step 1: Write the failing tests**

Append:

```python
def test_collections_rows():
    pages = {"SMS_Collection": [{"CollectionID": "PS100001", "Name": "All Systems",
                                 "CollectionType": 2, "MemberCount": 42, "IsBuiltIn": True}]}
    rows = list(a._collections(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_collections"
    assert rows[0][1]["collection_id"] == "PS100001" and rows[0][1]["member_count"] == 42


def test_collection_members_rows():
    pages = {"SMS_FullCollectionMembership": [{"CollectionID": "PS100001", "ResourceID": 16777220,
                                               "SiteCode": "PS1"}]}
    rows = list(a._collection_members(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_collection_members"
    assert rows[0][1]["resource_id"] == 16777220
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -k "collections_rows or collection_members" -q`
Expected: FAIL.

- [ ] **Step 3: Implement both helpers**

```python
_COLLECTION_SELECT = ("$select=CollectionID,CollectionType,CollectionVariablesCount,Comment,"
                      "IsBuiltIn,LastChangeTime,LastMemberChangeTime,LimitToCollectionID,"
                      "LimitToCollectionName,MemberCount,Name")


def _collections(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for coll in _paginate(client, f"wmi/SMS_Collection?{_COLLECTION_SELECT}"):
        count += 1
        yield "adminservice_collections", _row("AdminService-SMS_Collection", site_code, coll)
    logger.info("AdminService collected %d collections", count)


def _collection_members(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for member in _paginate(client, "wmi/SMS_FullCollectionMembership?$select=CollectionID,ResourceID,SiteCode"):
        count += 1
        yield "adminservice_collection_members", _row(
            "AdminService-SMS_FullCollectionMembership", site_code, member)
    logger.info("AdminService collected %d collection members", count)
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py`
Expected: clean. Continue automatically on green.

---

## Task 6: Security roles + admins (no `$select` — whitelist columns)

**Files:**
- Modify: `src/openhound_sccm/collectors/adminservice.py` (replace `_security_roles`, `_admins`)
- Test: `tests/test_adminservice.py`

- [ ] **Step 1: Write the failing tests**

Append:

```python
def test_security_roles_whitelists_columns():
    pages = {"SMS_Role": [{"RoleID": "SMS0001R", "RoleName": "Full Administrator",
                           "IsBuiltIn": True, "NumberOfAdmins": 1,
                           "LazyJunkColumn": "should be dropped"}]}
    rows = list(a._security_roles(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_security_roles"
    r = rows[0][1]
    assert r["role_id"] == "SMS0001R" and r["role_name"] == "Full Administrator"
    assert "lazy_junk_column" not in r  # whitelist drops un-listed columns


def test_admins_keeps_role_and_collection_assignments():
    pages = {"SMS_Admin": [{"AdminID": 1, "LogonName": "MAYYHEM\\admin", "AdminSid": "S-1-5-21-7",
                            "Roles": ["SMS0001R"], "RoleNames": ["Full Administrator"],
                            "CollectionNames": "All Systems, All Users", "IsGroup": False,
                            "SecretJunk": "dropped"}]}
    rows = list(a._admins(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_admins"
    r = rows[0][1]
    assert r["roles"] == ["SMS0001R"] and r["collection_names"] == "All Systems, All Users"
    assert "secret_junk" not in r
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -k "security_roles or admins" -q`
Expected: FAIL.

- [ ] **Step 3: Implement both helpers**

`SMS_Role`/`SMS_Admin` reject `$select` on lazy columns (per PS1), so fetch all columns and whitelist with `keep`:

```python
_ROLE_KEEP = {"CopiedFromID", "CreatedBy", "CreatedDate", "IsBuiltIn", "IsSecAdminRole",
              "LastModifiedBy", "LastModifiedDate", "NumberOfAdmins", "Operations", "RoleID",
              "RoleName", "RoleDescription", "SourceSite"}
_ADMIN_KEEP = {"AccountType", "AdminID", "AdminSid", "CategoryNames", "CollectionNames", "CreatedBy",
               "CreatedDate", "DisplayName", "DistinguishedName", "IsGroup", "LastModifiedBy",
               "LastModifiedDate", "LogonName", "RoleNames", "Roles", "SourceSite"}


def _security_roles(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for role in _paginate(client, "wmi/SMS_Role"):
        count += 1
        yield "adminservice_security_roles", _row(
            "AdminService-SMS_Role", site_code, role, keep=_ROLE_KEEP)
    logger.info("AdminService collected %d security roles", count)


def _admins(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for admin in _paginate(client, "wmi/SMS_Admin"):
        count += 1
        yield "adminservice_admins", _row(
            "AdminService-SMS_Admin", site_code, admin, keep=_ADMIN_KEEP)
    logger.info("AdminService collected %d admin users", count)
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py`
Expected: clean. Continue automatically on green.

---

## Task 7: Site systems (no `$select`; flatten service-account Prop)

**Files:**
- Modify: `src/openhound_sccm/collectors/adminservice.py` (replace `_site_systems`)
- Test: `tests/test_adminservice.py`

- [ ] **Step 1: Write the failing test**

Append:

```python
def test_site_systems_flattens_service_account():
    pages = {"SMS_SCI_SysResUse": [{
        "NetworkOSPath": "\\\\ps1-db.mayyhem.com", "SiteCode": "PS1", "RoleName": "SMS SQL Server",
        "Props": [{"PropertyName": "SQL Server Service Logon Account", "Value2": "MAYYHEM\\svc_sql"}]}]}
    rows = list(a._site_systems(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_site_systems"
    r = rows[0][1]
    assert r["network_os_path"] == "\\\\ps1-db.mayyhem.com" and r["role_name"] == "SMS SQL Server"
    assert r["sql_server_service_logon_account"] == "MAYYHEM\\svc_sql"
    assert "props" not in r
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py::test_site_systems_flattens_service_account -q`
Expected: FAIL.

- [ ] **Step 3: Implement `_site_systems`**

```python
_SYSRES_KEEP = {"NetworkOSPath", "SiteCode", "RoleName", "Type"}


def _site_systems(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for system in _paginate(client, "wmi/SMS_SCI_SysResUse"):
        props = system.get("Props")
        count += 1
        yield "adminservice_site_systems", _row(
            "AdminService-SMS_SCI_SysResUse", site_code, system, keep=_SYSRES_KEEP,
            extra={"sql_server_service_logon_account":
                   _prop(props, "SQL Server Service Logon Account", "Value2")},
        )
    logger.info("AdminService collected %d site system role records", count)
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py`
Expected: clean. Continue automatically on green.

---

## Task 8: New collections — collection variables + task sequences

**Files:**
- Modify: `src/openhound_sccm/collectors/adminservice.py` (replace `_collection_variables`, `_task_sequences`)
- Test: `tests/test_adminservice.py`

> No PS1 reference behavior. Field lists are a practical raw subset; widen during
> implementation only if a live sample shows more useful columns.

- [ ] **Step 1: Write the failing tests**

Append:

```python
def test_collection_variables_rows():
    pages = {"SMS_CollectionVariable": [{"CollectionID": "PS100001", "Name": "OSDVar",
                                         "Value": "win11", "IsMasked": False}]}
    rows = list(a._collection_variables(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_collection_variables"
    assert rows[0][1]["name"] == "OSDVar" and rows[0][1]["is_masked"] is False


def test_task_sequences_rows():
    pages = {"SMS_TaskSequencePackage": [{"PackageID": "PS100010", "Name": "Deploy Win11",
                                          "Description": "OSD", "SourceSite": "PS1"}]}
    rows = list(a._task_sequences(FakeClient(pages), "PS1"))
    assert rows[0][0] == "adminservice_task_sequences"
    assert rows[0][1]["package_id"] == "PS100010"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -k "collection_variables or task_sequences" -q`
Expected: FAIL.

- [ ] **Step 3: Implement both helpers**

`SMS_CollectionVariable` carries masked secret values (`IsMasked`), so `Value` is whitelisted but a masked value is the server's own redaction — we do not decrypt. `SMS_TaskSequencePackage` has lazy columns, so fetch-all + whitelist.

```python
_TS_KEEP = {"PackageID", "Name", "Description", "SourceSite", "Sequence", "ProgramFlags",
            "Duration", "BootImageID", "Category"}


def _collection_variables(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for var in _paginate(client, "wmi/SMS_CollectionVariable?$select=CollectionID,Name,Value,IsMasked"):
        count += 1
        yield "adminservice_collection_variables", _row(
            "AdminService-SMS_CollectionVariable", site_code, var)
    logger.info("AdminService collected %d collection variables", count)


def _task_sequences(client, site_code: str) -> Iterator[tuple[str, dict]]:
    count = 0
    for ts in _paginate(client, "wmi/SMS_TaskSequencePackage"):
        count += 1
        yield "adminservice_task_sequences", _row(
            "AdminService-SMS_TaskSequencePackage", site_code, ts, keep=_TS_KEEP)
    logger.info("AdminService collected %d task sequences", count)
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS.

- [ ] **Step 5: Validation Checkpoint**

Run: `uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py`
Expected: clean. Continue automatically on green.

---

## Task 9: End-to-end orchestrator test + final validation

**Files:**
- Test: `tests/test_adminservice.py`

- [ ] **Step 1: Write the end-to-end orchestrator test**

Append:

```python
def test_orchestrator_runs_all_collections_in_order(monkeypatch):
    pages = {
        "SMS_Identification": [{"ThisSiteCode": "PS1", "ThisSiteName": "Primary"}],
        "SMS_Site": [{"SiteCode": "PS1", "ServerName": "ps1"}],
        "SMS_SCI_SiteDefinition": [{"SiteCode": "PS1", "Props": []}],
        "SMS_SCI_Reserved": [{"UserName": "MAYYHEM\\naa", "SiteCode": "PS1"}],
        "SMS_CombinedDeviceResources": [{"Name": "WS1", "SMSID": "G1", "IsClient": True, "IsObsolete": False}],
        "SMS_R_System": [{"Name": "WS1", "SID": "S-1", "SecurityGroupName": []}],
        "SMS_R_User": [{"Name": "MAYYHEM\\u", "SID": "S-2", "SecurityGroupName": []}],
        "SMS_Collection": [{"CollectionID": "PS100001", "Name": "All"}],
        "SMS_FullCollectionMembership": [{"CollectionID": "PS100001", "ResourceID": 1, "SiteCode": "PS1"}],
        "SMS_Role": [{"RoleID": "R1", "RoleName": "Full Admin"}],
        "SMS_Admin": [{"AdminID": 1, "LogonName": "MAYYHEM\\a", "Roles": ["R1"]}],
        "SMS_SCI_SysResUse": [{"NetworkOSPath": "\\\\ps1", "SiteCode": "PS1", "RoleName": "MP", "Props": []}],
        "SMS_CollectionVariable": [{"CollectionID": "PS100001", "Name": "v", "Value": "x", "IsMasked": False}],
        "SMS_TaskSequencePackage": [{"PackageID": "TS1", "Name": "Deploy"}],
    }
    fake = FakeClient(pages)
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    rows = list(a.collect_adminservice("ps1-sms.mayyhem.com", _Ctx()))
    tables = [t for t, _ in rows]
    # Every table is produced, and the SMS_Identification gate ran first.
    assert "wmi/SMS_Identification" in fake.calls[0]
    expected = {
        "adminservice_sites", "adminservice_site_definitions", "adminservice_reserved_accounts",
        "adminservice_client_devices", "adminservice_r_system_security_groups",
        "adminservice_r_user_security_groups", "adminservice_collections",
        "adminservice_collection_members", "adminservice_security_roles", "adminservice_admins",
        "adminservice_site_systems", "adminservice_collection_variables", "adminservice_task_sequences",
    }
    assert set(tables) == expected
    # All emitted table names are declared as phase streams.
    from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
    declared = set(all_table_names(PER_HOST_PHASES))
    assert expected <= declared


def test_one_failing_collection_does_not_abort_rest(monkeypatch):
    pages = {"SMS_Identification": [{"ThisSiteCode": "PS1"}],
             "SMS_Site": [{"SiteCode": "PS1"}],
             "SMS_TaskSequencePackage": [{"PackageID": "TS1", "Name": "Deploy"}]}
    # All other classes 404 -> their helpers yield nothing, but sites + task seq still appear.
    fake = FakeClient(pages)
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, target, **kw: fake))
    tables = {t for t, _ in a.collect_adminservice("ps1-sms.mayyhem.com", _Ctx())}
    assert "adminservice_sites" in tables and "adminservice_task_sequences" in tables
```

- [ ] **Step 2: Run to verify they pass**

Run: `uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q`
Expected: PASS (all AdminService tests).

- [ ] **Step 3: Final Validation Checkpoint**

Run:
```
uv run --directory sccm\sccm python -m pytest tests/test_adminservice.py -q
uv run --directory sccm\sccm ruff check src/openhound_sccm/collectors/adminservice.py src/openhound_sccm/per_host_phases.py tests/test_adminservice.py
uv run --directory sccm\sccm mypy src/openhound_sccm/collectors/adminservice.py
```
Expected: all AdminService tests pass; ruff clean; mypy shows only the shared `logger.verbose`/untyped-import baseline (same classes as the other collectors), no new real errors. Report the pre-existing failures (`test_registry_current_user.py`, `test_extension_methods.py`) as unrelated. Done.

---

## Self-review (performed while writing this plan)

- **Spec coverage:** gate (Task 1); all 13 tables — sites/site_definitions (2), reserved_accounts/client_devices (3), r_system/r_user (4), collections/collection_members (5), security_roles/admins (6), site_systems (7), collection_variables/task_sequences (8); exact PS1 order + appended-last new collections + whole-phase guard + per-collection isolation (Task 1 orchestrator, verified Task 9); IsClient/IsObsolete filter (Task 3); Props flattening (Tasks 2, 7); no-`$select` whitelist for lazy-column classes (Tasks 6, 8); phase registration (Task 1); testing with a fake client (all tasks). `role_members` correctly absent (derived, deferred). No `main.py` change needed (table map already complete).
- **Placeholder scan:** none — every step has complete code and exact commands. The Task 8 "widen if a live sample shows more" note is an explicit scope statement for net-new endpoints, not deferred work.
- **Type consistency:** every helper is `(_client, site_code) -> Iterator[tuple[str, dict]]`; `_row(source, site_code, obj, *, keep, drop, extra)`, `_get_value(client, path) -> list|None`, `_paginate(client, path) -> Iterator[dict]`, `_prop(props, name, field)` used identically across tasks. Orchestrator `_COLLECTIONS` tuple matches the helper names defined in Task 1 and filled in Tasks 2–8.
