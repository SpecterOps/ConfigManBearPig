# Design: AdminService per-host collector

- **Date:** 2026-06-09
- **Status:** **Approved (not yet implemented).** Brainstorming complete; all branches resolved with the project owner. Plan: _to be written next (`writing-plans`)._ Nothing committed (per project owner).
- **Scope of change:** `sccm/sccm` only. Depends on the shared HTTP client (`ope-d57d`, `clients/http.py` + `clients/http_auth.py`).
- **Ticket:** ope-b287

## 1. Goal

Port `Invoke-AdminServiceCollection` from `ConfigManBearPig.ps1` into
[collectors/adminservice.py](../../../src/openhound_sccm/collectors/adminservice.py),
as a **collect-only** per-host phase that queries the SCCM AdminService REST API
(`https://<sms-provider>/AdminService/wmi/<class>`) and emits raw JSONL tables.

The PS1 both fetches data **and** resolves every principal to AD and builds
OpenGraph nodes/edges inline. In OpenHound those are separate stages, and the
project currently has **no convert stage** (`app.converter` is None; the existing
`registry.py`/`mssql.py` collectors emit raw tables only). This collector matches
that pattern: it emits the raw `adminservice_*` tables; AD/SID resolution and
node/edge construction are deferred to a future convert stage.

## 2. Decisions (resolved during brainstorming)

| Decision | Choice |
|---|---|
| **Pipeline scope** | **Collect-only.** Emit `adminservice_*` raw JSONL tables; defer node/edge conversion and AD resolution to a future convert stage. Matches `registry.py`/`mssql.py`. |
| **Coverage** | **14 pre-listed tables' worth of intent → 13 collected tables.** All 12 PS1-backed collections, plus two new ones (`SMS_CollectionVariable`, `SMS_TaskSequencePackage`). `adminservice_role_members` is **derived** (from `SMS_Admin`), not collected. |
| **Row shape** | **Raw AdminService fields only** (the PS1 `$select` columns, snake_cased) + `source` + `source_site_code`. **No** AD/SID resolution at collect time. |
| **Auth** | The shared `HttpClient.from_context(ctx, target, auth=AuthMode.NEGOTIATE)` over `https://<target>/AdminService`. Replaces PS1's `Invoke-WebRequest -UseDefaultCredentials`. |
| **Module shape** | Orchestrator `collect_adminservice` that `yield from`s one helper per collection, mirroring `registry.py`. Shared `_get_json` + `_paginate` helpers. |
| **Ordering** | Exact PS1 order for the 12 PS1-backed steps; the 2 new collections appended **last** (they have no PS1 position). |

### Locked assumptions

- **Phase placement:** new `AdminService` phase added to `PER_HOST_PHASES`
  **after `MSSQL`** (PS1 `$PhasesPerHost` = RemoteRegistry, MSSQL, AdminService,
  HTTP, SMB). Runs against every per-host target, gated by
  `ctx.method_enabled("AdminService")`.
- **Gate:** first call `SMS_Identification`; if `value[0].ThisSiteCode` is
  missing (not a provider / auth failed / 500), log and **return without
  yielding** — mirrors PS1's `if (-not $siteCode) { return }`. The returned site
  code becomes every row's `source_site_code`.
- **Client-device filter preserved:** `SMS_CombinedDeviceResources` rows with
  `IsClient == false` or `IsObsolete == true` are **skipped at collect time**
  (matches PS1).
- **Pagination:** collector owns the `$top=1000` / `$skip` loop; one
  `HttpClient.get` per page; stop when a page returns fewer than the batch size.
- **No new probe targets:** AdminService rows are **data**, not probe targets
  (per ticket note) — the collector never calls `register_target`.
- **`role_members` derived, not collected:** role↔admin membership lives in
  `SMS_Admin.Roles`/`.RoleNames`/`.CollectionNames`; stored raw on
  `adminservice_admins`. The `adminservice_role_members` table is a future
  convert/preproc derivation.

## 3. Architecture

### 3.1 Module: `collectors/adminservice.py`

Mirrors `registry.py`'s shape:

- **`collect_adminservice(target, ctx) -> Iterable[tuple[str, dict]]`** —
  `@with_log_context(phase="AdminService")`. Gates on
  `ctx.method_enabled("AdminService")`, builds the client, runs the
  `SMS_Identification` gate, then `yield from` each collection helper **in PS1
  order**. Wrapped so no failure crashes the per-host worker.
- **`_get_json(client, path) -> list | None`** — GET, accept only
  `ErrorClass.RESPONSE` with a 2xx status, parse JSON, return `value` (or `None`
  on any failure, logging a warning). Non-provider targets fail here cheaply.
- **`_paginate(client, path_template) -> Iterator[dict]`** — yields rows across
  `$top`/`$skip` pages until a short page; each page via `_get_json`.
- **One helper per collection** (e.g. `_sites`, `_reserved_accounts`,
  `_client_devices`, …), each yielding `(table_name, row)` tuples. A failed
  helper logs a warning and the orchestrator continues (PS1 `Success/Warning`
  parity).

### 3.2 Client usage

```python
client = HttpClient.from_context(ctx, target, auth=AuthMode.NEGOTIATE)
try:
    site_code = _identification(client)        # gate
    if site_code is None:
        return
    yield from _sites(client, site_code)
    ...
finally:
    client.close()
```

### 3.3 Phase registration

`per_host_phases.py` gains an `AdminService` `Phase` whose `streams` list the 13
table names (below); `source.py::_make_emit_resource` auto-creates an
`@app.resource(columns=raw_table_asset(table))` per stream. `main.py`'s
`_preproc_table_map` already lists most names; add
`adminservice_collection_variables` and `adminservice_task_sequences` if missing,
and keep `adminservice_role_members` listed as a future derived table.

## 4. Collected tables (13)

Order = PS1 order, new collections last. Each row also carries `source` and
`source_site_code`. Fields are the PS1 `$select` columns, snake_cased; `Props`
blobs are flattened to the named values the PS1 reads.

| # | Endpoint | Table | Key raw fields | Paged |
|---|---|---|---|---|
| gate | `SMS_Identification` | *(none)* | `ThisSiteCode`, `ThisSiteName` → `source_site_code` | no |
| 1 | `SMS_Site` | `adminservice_sites` | build_number, install_dir, reporting_site_code, server_name, site_code, site_name, status, type, version | no |
| 2 | `SMS_SCI_SiteDefinition` (per site) | `adminservice_site_definitions` | parent_site_code, site_code, site_name, site_server_domain, site_server_name, site_type, sql_database_name, sql_server_name; Props→site_guid, sql_server_fqdn, sql_service_port | no |
| 3 | `SMS_SCI_Reserved` | `adminservice_reserved_accounts` | user_name, site_code | no |
| 4 | `SMS_CombinedDeviceResources` | `adminservice_client_devices` | full `$select` (aad_device_id … user_domain_name); IsClient/IsObsolete filtered out | yes |
| 5 | `SMS_R_System` | `adminservice_r_system_security_groups` | client, name, obsolete, resource_id, sid, sms_unique_identifier, security_group_name[], system_roles[] | yes |
| 6 | `SMS_R_User` | `adminservice_r_user_security_groups` | aad_tenant_id, aad_user_id, distinguished_name, full_domain_name, full_user_name, name, resource_id, security_group_name[], sid, unique_user_name, user_name, user_principal_name | yes |
| 7 | `SMS_Collection` | `adminservice_collections` | collection_id, collection_type, collection_variables_count, comment, is_built_in, last_change_time, last_member_change_time, limit_to_collection_id, limit_to_collection_name, member_count, name | yes |
| 8 | `SMS_FullCollectionMembership` | `adminservice_collection_members` | collection_id, resource_id, site_code | yes |
| 9 | `SMS_Role` | `adminservice_security_roles` | role_id, role_name, role_description, copied_from_id, created_by, created_date, is_built_in, is_sec_admin_role, last_modified_by, last_modified_date, number_of_admins, operations, source_site | yes |
| 10 | `SMS_Admin` | `adminservice_admins` | admin_id, admin_sid, display_name, distinguished_name, is_group, last_modified_by, last_modified_date, logon_name, roles, role_names, collection_names, source_site | yes |
| 11 | `SMS_SCI_SysResUse` | `adminservice_site_systems` | network_os_path, site_code, role_name; Props→sql_server_service_logon_account | yes |
| 12 *(new)* | `SMS_CollectionVariable` | `adminservice_collection_variables` | collection_id, name, value, is_masked | yes |
| 13 *(new)* | `SMS_TaskSequencePackage` | `adminservice_task_sequences` | package_id, name, description, source_site, sequence_flags, programs | yes |

The two new endpoints (12, 13) have no PS1 reference behavior; field lists are a
practical raw subset and may be widened during implementation if a sample
response shows more useful columns.

## 5. Row shape

`{ "source": "AdminService-<Class>", "source_site_code": "<gate site code>",
<snake_cased raw fields...> }`. Arrays (`security_group_name`, `roles`,
`role_names`, `system_roles`) stored as-is. No SID/AD enrichment. `name`/server
fields kept as the raw AdminService strings for the convert stage to resolve.

## 6. Error handling & ordering

- **Gate failure or non-provider** → no rows, clean return (the common case for
  most per-host targets, which aren't SMS providers).
- **Per-collection failure** (transport non-RESPONSE, non-2xx, bad JSON) → the
  helper logs a `warning` and yields nothing; the orchestrator continues to the
  next collection (PS1 per-function `Success`/`Warning` parity).
- **Whole-phase guard** → any unexpected exception is logged at `error` and the
  phase yields nothing, never crashing the per-host worker pool.
- **Every branch logged** per the project logging rule (info per collection
  start, success counts, warnings on failure, verbose per page).
- **Order**: the 12 PS1-backed steps run in exact PS1 order; collection
  variables and task sequences run last.

## 7. Testing

Unit tests (`tests/test_adminservice.py`) with a **fake `HttpClient`** returning
canned AdminService JSON pages (pattern: `test_registry_current_user.py`'s
`FakeProbe`):

- gate aborts (no rows) when `SMS_Identification` returns empty;
- `_paginate` stops at a short page and concatenates multi-page results;
- each helper maps fields → the right `(table, row)` shape, incl. flattened
  `Props` and the client-device `IsClient/IsObsolete` filter;
- a failed single collection does not abort the remaining collections;
- a non-provider (`_get_json` → None throughout) yields nothing.

Validation (isolated uv env, per `validate-extension.md`): `uv run pytest`,
`uv run ruff check src/`, `uv run mypy src/`. Optional live check against the lab
SMS provider once its AdminService backend is healthy (see the
`sccm-http-lab-validation` notes; the lab provider currently 500s post-auth).

## 8. Out of scope (deferred)

- **Convert stage**: SCCM_Site / SCCM_Collection / SCCM_AdminUser /
  SCCM_ClientDevice / SCCM_SecurityRole nodes and the membership/assignment edges
  (`SCCM_HasMember`, `SCCM_IsAssigned`, `SCCM_HasStoredAccount`,
  `SCCM_HasClient`, `MemberOf`, etc.) the PS1 upserts.
- **AD/SID resolution** of any principal.
- **`adminservice_role_members`** derivation from `SMS_Admin`.
- The **WMI fallback** (`Invoke-SmsProviderWmiCollection`, ticket `ope-c660`).
- **`--sms-provider`** target scoping beyond existing target seeding.
- Changes to OpenHound core or the shared HTTP client.
