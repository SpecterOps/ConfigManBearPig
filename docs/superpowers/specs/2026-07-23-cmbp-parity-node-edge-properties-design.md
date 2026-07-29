# Design: CMBP-parity node/edge properties (AD props + missing SCCM props)

**Date:** 2026-07-23 · **Status:** design (approved for planning) · **Tickets:** ope-c141 (Phase A), ope-fb99 (Phase B).

## 1. Goal

A `--compare-to-zip` diff of the OpenHound SCCM collector against a ConfigManBearPig (CMBP) baseline
surfaced properties CMBP emits that OpenHound does not. Per owner decision (2026-07-23), close the
genuine gaps so OpenHound reaches CMBP parity on node/edge properties. One design, two phases:

- **Phase A (ope-c141):** populate AD-object properties on `Computer`/`User`/`Group` nodes that OpenHound
  currently omits, instead of relying on SharpHound to supply them.
- **Phase B (ope-fb99):** emit the missing SCCM-specific properties — `SCCM_ClientDevice` device
  telemetry fields, `SCCM_Site.siteSystemRoles`, and `SCCMInfra` on the `SCCM_IsMappedTo` edge.

Casing and value formats match ConfigManBearPig.ps1 verbatim (the project's SCCM-output rule).

## 2. Scope decisions (locked during brainstorming)

- **Match CMBP's property set + its LDAP/registry sources** (not a SharpHound-parity superset).
- **Phase A reaches only principals OpenHound already resolves via `resolve_principal`** — no new LDAP
  pass over the offline `principal_by_name` set. This means **partial parity, accepted**: resolved
  principals (targets, current user, admin accounts, this-computer, HTTP principals, SMC group members —
  mostly `Computer` nodes plus a handful of resolved `User`/`Group`) gain the AD props; offline-resolved
  principals (most SCCM admin users, collection/group members) stay bare. No new LDAP traffic / OPSEC cost.
- **Casing:** new properties use CMBP-exact names (`Domain`, `Enabled`, `IsDomainPrincipal`, `Type`,
  `objectClass`, `servicePrincipalName`, `CN`). Existing camelCase props (`dNSHostName`, `samAccountName`,
  `userPrincipalName`) are **left as-is** — casing variants were ruled cosmetically fine; no renames.
- **Null → pruned:** a property left null (unresolved principal, absent source field) is dropped on emit
  (convert's `_without_null_properties`), never fabricated — matching CMBP.
- **No schema change:** these are node/edge *properties*, which are not part of the OpenGraph
  `schema_SCCM.json`/`schema_MSSQL.json` kind registration.

## 3. Phase A — AD node properties (ope-c141)

### 3a. The gap (why properties are missing today)
`ctx.resolve_principal` (context.py:170) is a live, cached, multi-domain LDAP lookup already invoked
broadly (`register_target` for every discovered target; current user registry.py:471; admin accounts
privileged.py:140; this-computer local.py:192; HTTP principals http.py:208; SMC members ldap.py:645).
Three narrow gaps prevent AD props from reaching node output:
1. Its attr lists (`_ldap_resolve` context.py:259, `_ldap_resolve_dn` context.py:229) fetch
   `sAMAccountName, objectSid, dNSHostName, cn, distinguishedName, objectClass, userPrincipalName, name`
   — but **not** `userAccountControl` (needed for `Enabled`) or `servicePrincipalName`.
2. The resolved `ad_object` is consumed transiently (naming, allowed-target filtering, target
   registration) and never **persisted** to a raw table or plumbed into node properties; the
   `ad_resolution_cache` is in-memory only.
3. (Out of this spec's scope, per §2.) Offline-`principal_by_name` principals never hit `resolve_principal`.

### 3b. Collect
- Add `userAccountControl` and `servicePrincipalName` to both attr lists (context.py:229/259).
- New finalization DLT resource `ldap_resolved_principals` that, after discovery + per-host phases have
  populated `ctx.ad_resolution_cache`, yields the non-null resolved objects deduped by `objectSid`, one
  row each: `{sid, object_class, user_account_control, service_principal_name, cn, dns_host_name,
  sam_account_name, user_principal_name, distinguished_name, domain}` (snake_case raw columns per the
  DuckDB-column rule). It must drain **after** the resources that populate the cache — enforced via
  resource ordering / the per-host engine completion; a plan-level detail with a regression test.

### 3c. Preproc
New lookup/derivation over `ldap_resolved_principals`:
- `Enabled` = `NULL` if `user_account_control` absent else `(user_account_control & 2) = 0` (ACCOUNTDISABLE bit).
- `Type` = last element of `object_class`, title-cased (`computer` → `Computer`, `user` → `User`, `group` → `Group`).
- `IsDomainPrincipal` = `true` for every resolved row.
- `Domain` = the resolving domain (`domain` column).
- Carry `objectClass` (raw last-element or full, matching CMBP), `servicePrincipalName`, `CN`.
- Left-join these onto `node_computer` / `node_user` / `node_group` by SID. Nodes whose principal was
  resolved get the values; others get null (pruned).

### 3d. Graph / convert
Add to `ComputerProperties` / `UserProperties` / `GroupProperties` (graph.py), CMBP-cased, documented in
each dataclass `Attributes` docstring: `Domain`, `Enabled`, `IsDomainPrincipal`, `Type`, `objectClass`,
`servicePrincipalName`, `CN`. Convert emits them; nulls pruned.

> `disableLoopbackCheck` / `restrictReceivingNtlmTraffic` are **already** `ComputerProperties` fields
> sourced from RemoteRegistry; they showed as CMBP-only only because the id-matched computers lacked
> RemoteRegistry data. This spec does **not** change RemoteRegistry host coverage, so they stay as-is
> (their edge usage is tracked separately by ope-961c). They are not part of Phase A's LDAP work.

### 3e. Property → source (CMBP parity, from ConfigManBearPig.ps1)
| Property | Source | Derivation |
|---|---|---|
| `Type` | LDAP `objectClass` | last element, title-cased |
| `objectClass` | LDAP `objectClass` | as collected |
| `Enabled` | LDAP `userAccountControl` | `not (uac & 2)` |
| `IsDomainPrincipal` | resolution success | `true` |
| `servicePrincipalName` | LDAP `servicePrincipalName` | direct |
| `CN` | LDAP `cn` | direct |
| `Domain` | resolving domain | direct |

## 4. Phase B — SCCM node/edge properties (ope-fb99)

- **`SCCM_ClientDevice` telemetry:** emit `currentManagementPoint`, `currentManagementPointSID`,
  `previousSMSID`, `previousSMSIDChangeDate`, `userName`, `userDomainName`, `lastReportedMPServerSID`.
  Source: AdminService/WMI device resource (`SMS_R_System` / `SMS_CombinedDeviceResources`). Plan step
  pins the exact SMS class + field name per property against CMBP; extend the privileged device
  collection to carry any not already in `adminservice_client_devices` / `adminservice_r_system`, plumb
  through preproc to `SCCMClientDeviceProperties`.
- **`SCCM_Site.siteSystemRoles`:** the list of site-system roles for the site. Source: site-system /
  `SMS_SCI_SysResUse` data (likely already in raw `adminservice_site_systems`); aggregate per site and
  add to `SCCMSiteProperties`. (Distinct from the existing `Computer.SCCMSiteSystemRoles`, which is
  per-host.)
- **`SCCM_IsMappedTo.SCCMInfra`:** add `SCCMInfra = true` to the edge property bag in
  `transforms._edge_is_mapped_to` (these login→database-user mappings are SCCM infrastructure).

## 5. Testing

- **Offline unit tests** (`sccm/sccm/tests/`, run with `sccm/sccm/.venv`):
  - `userAccountControl` → `Enabled` derivation (bit-2 set/unset/absent); `objectClass` → `Type`
    title-casing; `IsDomainPrincipal` = true on resolved rows.
  - The `ldap_resolved_principals` → node-property left-join (a resolved SID populates its node's props;
    an unresolved node's props stay null).
  - `SCCM_ClientDevice` extras plumb from synthetic raw rows.
  - `SCCM_IsMappedTo` edge carries `SCCMInfra = true`.
- **Live re-validation:** `openhound collect sccm … --compare-to-zip <CMBP.zip>` — the previously-flagged
  `only_in_b` AD props (`Enabled`/`Type`/`objectClass`/`servicePrincipalName`/`CN`/`Domain`/
  `IsDomainPrincipal`) should now match **for resolved principals**, and the Phase-B SCCM props should
  match. Expected residual (by design, §2): those AD props still `only_in_b` on **offline-resolved**
  principals — documented, not a regression.

## 6. Docs

- README Node Reference: add the new `Computer`/`User`/`Group` AD props and the `SCCM_ClientDevice` /
  `SCCM_Site` props; Edge Reference: note `SCCM_IsMappedTo.SCCMInfra`.
- ARCHITECTURE.md: new subsection — *capturing AD-object attributes from the resolution cache* (the
  `ldap_resolved_principals` finalization resource and its ordering requirement) as a divergence note;
  changelog entry. No schema files change.

## 7. Out of scope / deferred

- Resolving the offline `principal_by_name` principal set (would add LDAP traffic) — deferred per §2.
- Broadening RemoteRegistry host coverage to populate `disableLoopbackCheck`/`restrictReceivingNtlmTraffic`
  on more computers — separate concern (ope-961c touches the former's edge usage).
- SharpHound-parity AD attribute superset beyond CMBP's set.

## 8. Risks / to pin during planning

- **Cache-dump ordering:** `ldap_resolved_principals` must run after everything that populates the cache;
  if resource ordering can't guarantee it, fall back to emitting resolved objects incrementally as they
  resolve. Needs a test that the raw table is non-empty after a full collect.
- **Exact SMS field names** for the `SCCM_ClientDevice` extras — confirm against CMBP + a live/cached
  AdminService row during planning (some may already be present in raw tables, needing only plumbing).
- **`objectClass` shape** — CMBP stores the multi-valued `objectClass`; confirm whether the node prop
  should carry the full list or the last element, to match CMBP's emitted value exactly.
- **`Type` for groups vs computers vs users** — verify title-casing produces CMBP's exact strings.
