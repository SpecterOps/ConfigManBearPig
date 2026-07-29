# SMS Provider WMI Fallback Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-host `WMI` collection phase that mirrors the AdminService collector over DCOM/WMI and runs only when AdminService was unreachable on that host.

**Architecture:** The SCCM AdminService REST API is a thin veneer over the SMS Provider's `root\SMS\site_<code>` WMI namespace. This collector queries that namespace directly via WMI as a fallback. It reuses the AdminService credential ladder (`choose_auth`) but realizes the rungs over WMI transports: impacket DCOM for kerberos/ntlm/ticket (incl. pass-the-hash and pass-the-ticket), pywin32 for the current-user SSPI rung; the anonymous rung is skipped (DCOM requires auth). The fallback gate is a `completed_phases` set on the shared per-host `TargetEntry`, read by a new `should_run_phase` hook (the pipeline's native phase-skip mechanism); AdminService adds `"AdminService"` after a successful identification, and the engine skips WMI when it's present.

**Tech Stack:** Python, impacket (`impacket.dcerpc.v5.dcomrt.DCOMConnection`, `impacket.dcerpc.v5.dcom.wmi`), pywin32 (`win32com.client`), pytest. impacket 0.13.1 is installed; pywin32 is installed; `python-wmi` is NOT.

---

## Design decisions (settled with the user)

1. **Shape:** Mirror the AdminService collector — same 10 collections, same order, including the AD-resolution side-rows AdminService now emits (`*_site_definitions_computers`, enriched reserved-accounts).
2. **Auth:** Reuse `clients/http_auth.choose_auth()` for credential precedence. Rung → transport: `ticket`/`kerberos`/`ntlm` → impacket DCOM; `sspi` → pywin32; `anonymous` → skip + log.
3. **Fallback gate:** `TargetEntry.completed_phases: set[str]`. AdminService adds `"AdminService"` after a successful `SMS_Identification`. `should_run_phase` (new) skips WMI when `"AdminService"` is present. WMI adds `"WMI"` on its own success.
4. **Tables:** Separate `wmi_*` tables mirroring the `adminservice_*` suffixes. The three legacy `wmi_clients`/`wmi_users_seen`/`wmi_sql_service_accounts` preproc entries belong to ticket Ope-ew5k (client-side CIM) and stay untouched.
5. **Site code / namespace:** Identification gate queries `SMS_ProviderLocation` in `root\SMS` for the site code, then queries collections in `root\SMS\site_<code>`. No PS1-style "guess every known site code" loop.
6. **Reuse:** Move `_snake`/`_row`/`_prop` and the column selections to a shared `collectors/sms_rows.py`; column selections become a single source of truth (tuples), rendered to OData `$select` for AdminService and used as WQL `SELECT` lists / `keep` whitelists for WMI.

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `src/openhound_sccm/collectors/sms_rows.py` | Create | Transport-neutral atoms: `_snake`, `_row`, `_prop`, column tuples, `odata_select()`. |
| `src/openhound_sccm/clients/wmi.py` | Create | `WmiClient`: hybrid auth ladder + per-namespace WQL query; impacket + pywin32 backends. |
| `src/openhound_sccm/collectors/wmi.py` | Create | 10 collection functions mirroring AdminService order + identify gate + orchestrator. |
| `src/openhound_sccm/models/target_entry.py` | Modify | Add `completed_phases: set[str]`. |
| `src/openhound_sccm/collectors/adminservice.py` | Modify | Import shared atoms; use shared column tuples; add `entry.completed_phases.add("AdminService")`. |
| `src/openhound_sccm/per_host_phases.py` | Modify | Add `should_run_phase`; register `WMI` phase + its streams; declare `adminservice_site_definitions_computers`. |
| `src/openhound_sccm/main.py` | Modify | Pass `should_run_phase`; add `wmi_*` tables to `_preproc_table_map`. |
| `tests/test_sms_rows.py` | Create | Unit tests for shared atoms. |
| `tests/test_adminservice.py` | Modify | Fix `(client, site_code, ctx)` signatures + new AD-resolution behavior + shared-helper import. |
| `tests/test_wmi_client.py` | Create | Auth-ladder selection + backend dispatch + row normalization (mocked transports). |
| `tests/test_wmi.py` | Create | Collection functions + identify gate + orchestrator order + completed_phases gating. |
| `README.md` | Modify | Collection Overview, `-m` methods, table reference. |

---

### Task 1: Shared `sms_rows` module

**Files:**
- Create: `src/openhound_sccm/collectors/sms_rows.py`
- Test: `tests/test_sms_rows.py`

Move `_snake`, `_row`, `_prop` verbatim from `adminservice.py`. Add column tuples (single source of truth) and `odata_select()`.

- [ ] **Step 1: Write failing tests** (`tests/test_sms_rows.py`)

```python
from openhound_sccm.collectors import sms_rows as s

def test_snake_handles_acronyms():
    assert s._snake("SiteCode") == "site_code"
    assert s._snake("AADDeviceID") == "aad_device_id"
    assert s._snake("SMSID") == "smsid"

def test_row_snakes_and_tags_and_drops_odata():
    row = s._row("WMI-SMS_Site", "PS1", {"SiteCode": "PS1", "@odata.type": "x", "BuildNumber": "9000"})
    assert row == {"source": "WMI-SMS_Site", "source_site_code": "PS1",
                   "site_code": "PS1", "build_number": "9000"}

def test_row_keep_whitelists():
    row = s._row("src", "PS1", {"RoleName": "X", "Junk": "y"}, keep=s.ROLE_COLUMNS)
    assert "role_name" in row and "junk" not in row

def test_prop_reads_named_value():
    props = [{"PropertyName": "siteGUID", "Value1": "{G}"}]
    assert s._prop(props, "siteGUID", "Value1") == "{G}"
    assert s._prop(props, "missing") is None

def test_odata_select_renders_select_clause():
    assert s.odata_select(("A", "B")) == "$select=A,B"
```

- [ ] **Step 2: Run, verify fail** — `uv run pytest tests/test_sms_rows.py -q` → ImportError.

- [ ] **Step 3: Implement `sms_rows.py`** — `_snake`/`_row`/`_prop` copied verbatim from current `adminservice.py:28-95`, plus:

```python
SITE_COLUMNS = ("BuildNumber", "InstallDir", "ReportingSiteCode", "ServerName",
                "SiteCode", "SiteName", "Status", "Type", "Version")
SITEDEF_COLUMNS = ("ParentSiteCode", "SiteCode", "SiteName", "SiteServerDomain",
                   "SiteServerName", "SiteType", "SQLDatabaseName", "SQLServerName", "Props")
DEVICE_COLUMNS = ("AADDeviceID", "AADTenantID", "ADLastLogonTime", "CNAccessMP", "CNLastOfflineTime",
                  "CNLastOnlineTime", "CoManaged", "CurrentLogonUser", "DeviceOS", "DeviceOSBuild",
                  "IsClient", "IsObsolete", "IsVirtualMachine", "LastActiveTime", "LastMPServerName",
                  "Name", "PrimaryUser", "ResourceID", "SiteCode", "SMSID", "UserName", "UserDomainName")
RSYSTEM_COLUMNS = ("Client", "Name", "Obsolete", "ResourceID", "SID", "SMSUniqueIdentifier",
                   "SecurityGroupName", "SystemRoles")
RUSER_COLUMNS = ("AADTenantID", "AADUserID", "DistinguishedName", "FullDomainName", "FullUserName",
                 "Name", "ResourceID", "SecurityGroupName", "SID", "UniqueUserName", "UserName",
                 "UserPrincipalName")
COLLECTION_COLUMNS = ("CollectionID", "CollectionType", "CollectionVariablesCount", "Comment",
                      "IsBuiltIn", "LastChangeTime", "LastMemberChangeTime", "LimitToCollectionID",
                      "LimitToCollectionName", "MemberCount", "Name")
COLLECTION_MEMBER_COLUMNS = ("CollectionID", "ResourceID", "SiteCode")
# Lazy-column classes: AdminService fetches all and whitelists; WMI does SELECT * + keep.
ROLE_COLUMNS = ("CopiedFromID", "CreatedBy", "CreatedDate", "IsBuiltIn", "IsSecAdminRole",
                "LastModifiedBy", "LastModifiedDate", "NumberOfAdmins", "Operations", "RoleID",
                "RoleName", "RoleDescription", "SourceSite")
ADMIN_COLUMNS = ("AccountType", "AdminID", "AdminSid", "CategoryNames", "CollectionNames", "CreatedBy",
                 "CreatedDate", "DisplayName", "DistinguishedName", "IsGroup", "LastModifiedBy",
                 "LastModifiedDate", "LogonName", "RoleNames", "Roles", "SourceSite")
SYSRES_COLUMNS = ("NetworkOSPath", "SiteCode", "RoleName", "Type")

def odata_select(columns) -> str:
    """Render an OData ``$select`` clause from a column tuple."""
    return "$select=" + ",".join(columns)
```

`_row`'s `keep` membership test (`k in keep`) works for tuples, so callers pass the tuples directly.

- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/test_sms_rows.py -q` → PASS.

---

### Task 2: Point AdminService at the shared module + fix its tests

**Files:**
- Modify: `src/openhound_sccm/collectors/adminservice.py`
- Modify: `tests/test_adminservice.py`

- [ ] **Step 1: Refactor `adminservice.py`.** Delete the local `_snake`/`_row`/`_prop` defs and the `_*_SELECT`/`_*_KEEP` constants. Add:

```python
from .sms_rows import (
    _snake, _row, _prop, odata_select,
    SITE_COLUMNS, SITEDEF_COLUMNS, DEVICE_COLUMNS, RSYSTEM_COLUMNS, RUSER_COLUMNS,
    COLLECTION_COLUMNS, COLLECTION_MEMBER_COLUMNS, ROLE_COLUMNS, ADMIN_COLUMNS, SYSRES_COLUMNS,
)
```

Replace query construction to render `$select` from the tuples, e.g. `query = f"?{odata_select(SITE_COLUMNS)}"`; for site_definition `query = f"?$filter=SiteCode eq '{target_site}'&{odata_select(SITEDEF_COLUMNS)}"`; collection-members `query = f"?{odata_select(COLLECTION_MEMBER_COLUMNS)}"`. Replace `keep=_ROLE_KEEP` → `keep=ROLE_COLUMNS`, `_ADMIN_KEEP` → `ADMIN_COLUMNS`, `_SYSRES_KEEP` → `SYSRES_COLUMNS`. Keep `_get_value`/`_paginate`/`_identification` in `adminservice.py` (HTTP-specific). `_snake`/`_row`/`_prop` remain importable as `adminservice._snake` etc. via the re-import.

- [ ] **Step 2: Fix `tests/test_adminservice.py`.** Update the import-level helper tests to import from `sms_rows` is optional (they still resolve via `a._snake`). The breaking changes are the new `(client, site_code, ctx)` signatures and AD-resolution behavior. Give `_Ctx` a `resolve_principal`:

```python
class _Ctx:
    def __init__(self, enabled=True, principal=None):
        self._enabled = enabled
        self.domain = "mayyhem.com"
        self.username = self.password = self.nt_hash = self.kerberos_ticket = None
        self.ad = None
        self._principal = principal
    def method_enabled(self, name): return self._enabled
    def resolve_principal(self, name): return self._principal
```

Update each direct helper call to pass a ctx:
- `a._sites(FakeClient(pages), "PS1", _Ctx())` — `resolve_principal` returns None, so only `adminservice_sites` + `adminservice_site_definitions` rows (no `_computers`); existing assertions hold.
- `a._reserved_accounts(...)`: new code only yields when `resolve_principal` is truthy. Rewrite to pass `_Ctx(principal={"object_sid": "S-1-5-21-7", "name": "svc_naa"})` and assert the enriched row carries `source`, `sccm_infra: True`, and the original account fields.
- `_client_devices`, `_r_system`, `_r_user`, `_collections`, `_collection_members`, `_security_roles`, `_admins`, `_site_systems`: add the `, _Ctx()` third arg.
- Orchestrator tests already call `collect_adminservice(...)` (unchanged signature) but monkeypatch `from_context`; they pass.

- [ ] **Step 3: Run** — `uv run pytest tests/test_adminservice.py tests/test_sms_rows.py -q` → PASS.

---

### Task 3: `TargetEntry.completed_phases` + AdminService marks itself

**Files:**
- Modify: `src/openhound_sccm/models/target_entry.py`
- Modify: `src/openhound_sccm/collectors/adminservice.py`
- Test: `tests/test_wmi.py` (gating assertions land in Task 8; a focused marker test here)

- [ ] **Step 1: Add the field.**

```python
completed_phases: set = field(default_factory=set)
```
Docstring: "Names of per-host phases that have *successfully* collected this host (e.g. ``{'AdminService'}``). Read by ``should_run_phase`` so the WMI fallback skips hosts AdminService already reached. Mirrors PS1's ``CollectionTargets[$target]['Collected'/'Method']``."

- [ ] **Step 2: Mark in `collect_adminservice`.** After `site_code = _identification(client)` succeeds (before the collection loop), look up the entry and record completion:

```python
entry = ctx.target_hosts_by_hostname.get(target.lower())
if entry is not None:
    entry.completed_phases.add("AdminService")
    logger.verbose("Marked AdminService complete on %s (site %s)", target, site_code)
else:
    logger.debug("No TargetEntry for %s; WMI-fallback gating unavailable", target)
```

- [ ] **Step 3: Test the marker** (in `tests/test_wmi.py`, see Task 8 for the file's other tests):

```python
def test_adminservice_marks_completed_phase(monkeypatch):
    from openhound_sccm.collectors import adminservice as a
    from openhound_sccm.models.target_entry import TargetEntry
    fake = FakeHttp({"SMS_Identification": [{"ThisSiteCode": "PS1"}], "SMS_Site": []})
    monkeypatch.setattr(a.HttpClient, "from_context", classmethod(lambda cls, ctx, t, **k: fake))
    entry = TargetEntry(hostname="ps1-sms.mayyhem.com", ad_object=None)
    ctx = _Ctx(); ctx.target_hosts_by_hostname = {"ps1-sms.mayyhem.com": entry}
    list(a.collect_adminservice("ps1-sms.mayyhem.com", ctx))
    assert "AdminService" in entry.completed_phases
```

- [ ] **Step 4: Run** — `uv run pytest tests/test_wmi.py::test_adminservice_marks_completed_phase -q` → PASS.

---

### Task 4: `should_run_phase` gate + phase registration + preproc tables

**Files:**
- Modify: `src/openhound_sccm/per_host_phases.py`
- Modify: `src/openhound_sccm/main.py`
- Test: `tests/test_per_host_phases.py` (extend)

- [ ] **Step 1: Add `should_run_phase` to `per_host_phases.py`.**

```python
def should_run_phase(target: str, phase: Phase, ctx) -> bool:
    """Engine ``should_run`` hook: method gating + WMI-is-a-fallback rule.

    WMI mirrors AdminService over DCOM and only earns its keep when AdminService
    could not reach this host, so skip it once AdminService has completed here.
    """
    if not ctx.method_enabled(phase.name):
        return False
    if phase.name == "WMI":
        entry = ctx.target_hosts_by_hostname.get(target.lower())
        if entry is not None and "AdminService" in entry.completed_phases:
            return False
    return True
```

- [ ] **Step 2: Register the WMI phase + streams + declare the AdminService computers stream.** Import `wmi`; add `adminservice_site_definitions_computers` to the AdminService phase streams (it is yielded but currently undeclared); add the `WMI` phase after AdminService:

```python
from .collectors import registry, mssql, adminservice, wmi
# ... AdminService phase streams gain "adminservice_site_definitions_computers" ...
    Phase(
        "WMI", (
            "wmi_sites",
            "wmi_site_definitions",
            "wmi_site_definitions_computers",
            "wmi_reserved_accounts",
            "wmi_client_devices",
            "wmi_r_system",
            "wmi_r_user",
            "wmi_collections",
            "wmi_collection_members",
            "wmi_security_roles",
            "wmi_admins",
            "wmi_site_systems",
        ), wmi.collect_wmi,
    ),
```

- [ ] **Step 3: Wire `should_run_phase` in `main.py`.** In `_run_per_host_stage`, change the import to include `should_run_phase` and pass `should_run=should_run_phase` instead of the inline lambda.

- [ ] **Step 4: Add `wmi_*` tables to `_preproc_table_map` in `main.py`** (after the `adminservice_*` block; keep the legacy `wmi_clients`/`wmi_users_seen`/`wmi_sql_service_accounts` lines): add `adminservice_site_definitions_computers`, `wmi_sites`, `wmi_site_definitions`, `wmi_site_definitions_computers`, `wmi_reserved_accounts`, `wmi_client_devices`, `wmi_r_system`, `wmi_r_user`, `wmi_collections`, `wmi_collection_members`, `wmi_security_roles`, `wmi_admins`, `wmi_site_systems`.

- [ ] **Step 5: Test the gate** (`tests/test_per_host_phases.py`):

```python
def test_should_run_phase_skips_wmi_after_adminservice():
    from openhound_sccm.per_host_phases import should_run_phase, PER_HOST_PHASES
    from openhound_sccm.models.target_entry import TargetEntry
    wmi_phase = next(p for p in PER_HOST_PHASES if p.name == "WMI")
    entry = TargetEntry(hostname="h", ad_object=None, completed_phases={"AdminService"})
    ctx = _AllCtx({"h": entry})  # method_enabled -> True; target_hosts_by_hostname set
    assert should_run_phase("h", wmi_phase, ctx) is False

def test_should_run_phase_runs_wmi_when_adminservice_absent():
    from openhound_sccm.per_host_phases import should_run_phase, PER_HOST_PHASES
    from openhound_sccm.models.target_entry import TargetEntry
    wmi_phase = next(p for p in PER_HOST_PHASES if p.name == "WMI")
    entry = TargetEntry(hostname="h", ad_object=None)  # no completed phases
    ctx = _AllCtx({"h": entry})
    assert should_run_phase("h", wmi_phase, ctx) is True
```

- [ ] **Step 6: Run** — `uv run pytest tests/test_per_host_phases.py -q` → PASS.

---

### Task 5: `WmiClient` + hybrid auth ladder (`clients/wmi.py`)

**Files:**
- Create: `src/openhound_sccm/clients/wmi.py`
- Test: `tests/test_wmi_client.py`

**Interface (the seam the collector depends on):**

```python
class WmiClient:
    @classmethod
    def from_context(cls, ctx, target: str) -> "WmiClient": ...
    def identify(self) -> Optional[str]:
        """Connect (running the auth ladder) and return this provider's site code,
        or None if no rung established a usable root\\SMS connection."""
    def query(self, class_name: str, *, columns=None, where=None) -> Optional[list[dict]]:
        """WQL ``SELECT [columns|*] FROM class_name [WHERE where]`` against
        root\\SMS\\site_<code>. Returns normalized {Name: value} dicts, or None."""
    def close(self) -> None: ...
```

**Auth ladder:** `identify()` calls `http_auth.choose_auth(username, password, nt_hash, ticket, target, sspi_available)` and walks the rungs. For each rung it builds a backend and tries to connect to `root\SMS`; the first success is cached (`self._backend`, `self._site_code`). Mapping:

| rung | backend | construction |
|---|---|---|
| `ticket` | `_ImpacketBackend(doKerberos=True, ccache=<loaded>)` | load base64 KRB-CRED → `CCache.fromKRBCRED`; pass TGT (+TGS if present for the host SPN) |
| `kerberos` | `_ImpacketBackend(doKerberos=True)` | username/password or nt_hash; `kdcHost=ctx kdc` |
| `ntlm` | `_ImpacketBackend(doKerberos=False)` | username/password or `lmhash:nthash` |
| `sspi` | `_PyWin32Backend(user=None)` | current Windows user |
| `anonymous` | — | `logger.info` "WMI requires authentication; skipping anonymous rung" and continue |

**`_ImpacketBackend`:**

```python
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL

class _ImpacketBackend:
    def __init__(self, target, domain, username, password, lmhash, nthash, *, do_kerberos, kdc_host, tgt=None, tgs=None):
        self._target = target; ...  # store
        self._dcom = None; self._services = {}  # namespace -> IWbemServices
    def connect(self):
        self._dcom = DCOMConnection(self._target, self._username, self._password, self._domain,
                                    self._lmhash, self._nthash, b"", self._tgt, self._tgs,
                                    oxidResolver=True, doKerberos=self._do_kerberos, kdcHost=self._kdc_host)
    def services(self, namespace):
        if namespace not in self._services:
            iLogin = wmi.IWbemLevel1Login(self._dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login))
            svc = iLogin.NTLMLogin("\\\\%s\\%s" % (self._target, namespace), NULL, NULL)
            iLogin.RemRelease()
            self._services[namespace] = svc
        return self._services[namespace]
    def query(self, namespace, wql):
        svc = self.services(namespace)
        it = svc.ExecQuery(wql)
        out = []
        while True:
            try:
                obj = it.Next(0xffffffff, 1)[0]
            except Exception as ex:
                if "S_FALSE" in str(ex):
                    break
                raise
            out.append(_normalize(obj.getProperties()))
        it.RemRelease()
        return out
    def close(self):
        try:
            if self._dcom: self._dcom.disconnect()
        except Exception: pass
```

**`_PyWin32Backend`:**

```python
class _PyWin32Backend:
    def __init__(self, target, username=None, password=None):
        ...
    def connect(self):
        import win32com.client
        self._locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    def services(self, namespace):
        if namespace not in self._services:
            self._services[namespace] = self._locator.ConnectServer(
                self._target, namespace, self._username or "", self._password or "")
        return self._services[namespace]
    def query(self, namespace, wql):
        return [_normalize_swbem(o) for o in self.services(namespace).ExecQuery(wql)]
    def close(self): pass
```

**Normalization (the part to unit-test hardest):**

```python
def _normalize(props) -> dict:
    """impacket getProperties() -> plain {Name: value}, recursing into embedded
    objects/arrays (SMS Props arrays become list[dict])."""
    out = {}
    for name in props:
        out[name] = _unwrap(props[name]["value"])
    return out

def _unwrap(value):
    if isinstance(value, list):
        return [_unwrap(v) for v in value]
    if hasattr(value, "getProperties"):
        return _normalize(value.getProperties())
    return value
```

pywin32 normalization mirrors it via `obj.Properties_` (`p.Name`, `p.Value`) recursing when `p.IsArray`/embedded `IDispatch`.

- [ ] **Step 1: Failing tests** (`tests/test_wmi_client.py`) — cover ladder selection and dispatch with a fake backend factory + fake impacket objects:

```python
def test_ladder_explicit_creds_tries_kerberos_then_ntlm(monkeypatch):
    """username+password -> impacket DCOM, doKerberos=True then False."""
    # inject a recording backend factory; assert order ['kerberos','ntlm'] attempted

def test_ladder_sspi_uses_pywin32(monkeypatch):
    """no creds + sspi available -> pywin32 backend constructed (user=None)."""

def test_ladder_skips_anonymous(monkeypatch):
    """no creds + no sspi -> identify() returns None, no backend constructed."""

def test_query_builds_wql_select_and_where():
    """columns + where render 'SELECT a,b FROM C WHERE x' ; None columns -> SELECT *."""

def test_normalize_unwraps_embedded_props_array():
    fake = {"SiteCode": {"value": "PS1"},
            "Props": {"value": [_FakeObj({"PropertyName": {"value": "siteGUID"}, "Value1": {"value": "{G}"}})]}}
    out = wmi_client._normalize(fake)
    assert out["SiteCode"] == "PS1"
    assert out["Props"] == [{"PropertyName": "siteGUID", "Value1": "{G}"}]
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `clients/wmi.py`** per the interface above. WQL builder: `f"SELECT {','.join(columns) if columns else '*'} FROM {class_name}" + (f" WHERE {where}" if where else "")`.
- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/test_wmi_client.py -q`.

---

### Task 6: `collectors/wmi.py` — mirror AdminService over WMI

**Files:**
- Create: `src/openhound_sccm/collectors/wmi.py`
- Test: `tests/test_wmi.py`

Structure mirrors `adminservice.py` one-to-one, swapping HTTP GET for `WmiClient.query`. Each function takes `(client, site_code, ctx)` and yields `(table, row)` with `wmi_*` table names and `"WMI-<Class>"` source labels. The identify gate uses `client.identify()`.

- WQL `where` for site_definition: `f"SiteCode = '{target_site}'"`.
- Big classes pass `columns=<TUPLE>`; lazy classes (role/admin/sysres) pass `columns=None` + `_row(keep=<TUPLE>)`.
- Device filter (`IsClient is False or IsObsolete is True`), Props flattening, and AD resolution for site servers / SQL servers / reserved accounts are copied from the AdminService equivalents (same logic, `wmi_*` table names, `WMI-*` source labels).
- Orchestrator `collect_wmi(target, ctx)`:

```python
@with_log_context(phase="WMI")
def collect_wmi(target, ctx):
    if not ctx.method_enabled("WMI"):
        return
    logger.info("Starting WMI collection on %s...", target)
    client = WmiClient.from_context(ctx, target)
    try:
        site_code = client.identify()
        if site_code is None:
            logger.info("%s is not a reachable SMS Provider over WMI; skipping", target)
            return
        for collection in _COLLECTIONS:
            try:
                yield from collection(client, site_code, ctx)
            except Exception as ex:
                logger.warning("WMI %s failed on %s: %s", collection.__name__, target, ex)
        entry = ctx.target_hosts_by_hostname.get(target.lower())
        if entry is not None:
            entry.completed_phases.add("WMI")
        logger.info("WMI collection completed for %s (site %s)", target, site_code)
    except Exception as ex:
        logger.error("WMI collection failed for %s: %s", target, ex)
    finally:
        client.close()
```

- [ ] **Step 1: Failing tests** (`tests/test_wmi.py`) with a `FakeWmi` client (maps class → row list; records WQL):

```python
class FakeWmi:
    def __init__(self, pages, site="PS1"):
        self.pages = pages; self._site = site; self.queries = []
    def identify(self): return self._site
    def query(self, class_name, *, columns=None, where=None):
        self.queries.append((class_name, columns, where))
        return self.pages.get(class_name)
    def close(self): pass
```

Tests: `_sites` emits `wmi_sites` + `wmi_site_definitions`; device filter drops non-client/obsolete; role/admin whitelist; site_systems flattens the SQL logon account from Props; orchestrator runs all collections in AdminService order, identify gate first, and adds `"WMI"` to `completed_phases`; method-disabled yields nothing; identify→None yields nothing.

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement `collectors/wmi.py`.**
- [ ] **Step 4: Run, verify pass** — `uv run pytest tests/test_wmi.py -q`.

---

### Task 7: README

**Files:** Modify `README.md`.

- [ ] Add a WMI row to Collection Overview describing it as the AdminService fallback (runs only when AdminService is unreachable), the auth ladder, and the `root\SMS\site_<code>` namespace.
- [ ] Confirm the `-m`/`--collection-methods` table lists `WMI` and note the fallback gating.
- [ ] Add the `wmi_*` raw tables to the table reference; note they mirror the `adminservice_*` set.
- [ ] No new graph nodes/edges yet (collect-only, like AdminService) — do not document nodes/edges.

---

### Task 8: Validation

**Files:** none (commands only).

- [ ] **Step 1: Full unit suite + lint.**
  `UV_PROJECT_ENVIRONMENT=/tmp/openhound-wmi-venv uv run pytest -q`
  `uv run ruff check src/`
- [ ] **Step 2: Live validation against `ps1-sms.mayyhem.com` (authorized).** Confirm DCOM/135 + WMI reachability, then run a focused live script that exercises each rung and compares WMI output to AdminService output for the same site:
  - **ntlm (explicit):** `-u MAYYHEM\domainadmin -p password`
  - **pass-the-hash:** `--nt-hash 8846f7eaee8fb117ad06bdd830b7586c`
  - **kerberos (explicit):** `-u domainadmin -p password` with KDC dc.mayyhem.com
  - **pass-the-ticket:** request a TGT for domainadmin, base64 it, pass `--ticket`
  - **sspi (current user):** no creds, on the domain-joined host
  For each: assert `identify()` returns `PS1` and at least `wmi_sites` + `wmi_admins` return rows. Report any rung that the lab environment can't exercise.
- [ ] **Step 3: Report** nodes/edges (none), pipeline changes, which validation commands ran/were skipped, and residual risks.

---

## Self-Review

- **Spec coverage:** shape (Tasks 5,6) ✓; auth ladder (Task 5) ✓; fallback gate (Tasks 3,4) ✓; separate tables (Tasks 4,6) ✓; identify gate (Tasks 5,6) ✓; shared atoms + single-source columns (Tasks 1,2) ✓; README (Task 7) ✓; live all-auth validation (Task 8) ✓.
- **Type consistency:** `WmiClient.query(class_name, *, columns=None, where=None)` used identically in Tasks 5/6; `should_run_phase(target, phase, ctx)` matches the engine's `ShouldRun` signature; `completed_phases` is a `set` everywhere.
- **Placeholder scan:** none — every code step shows concrete code or an exact command.
- **Gap watch:** AdminService currently yields `adminservice_site_definitions_computers` to an *undeclared* stream; Task 4 Step 2 declares it (fixes a latent KeyError in the AdminService phase, surfaced during planning).
