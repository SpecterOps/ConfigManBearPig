# Design: low-privilege assumed nodes/edges (default possible-edges mode)

**Date:** 2026-07-23 · **Revised:** 2026-07-27 (§2.1, §4.1, D5/D6, improvements 9-11 — completeness audit
of collected-but-unread tables) · **Status:** design (approved for planning) · **Driver:** SCCM extension.

## 1. Goal

Make the **default** collection mode (possible edges ON) build the SCCM/MSSQL attack graph that
ConfigManBearPig (CMBP) produces for an operator **without AdminService access** — i.e. the common
real-world case of a non-privileged domain user. `--disable-possible-edges` keeps today's conservative,
evidence-only behavior unchanged. Where CMBP's assumptions are sloppy, tighten them; and document every
assumption so an operator can tell an *assumed* edge from a *confirmed* one.

Motivating measurement (2026-07-23 live `MAYYHEM\lowpriv` run, `sccm/tests/live-comparison/lowpriv_check/`):
CMBP emitted 106–146 edges; OpenHound emitted **9**. The gap is almost entirely families OpenHound
*collects the evidence for but discards in preprocess*, plus families CMBP fabricates by template.

## 2. The linchpin: `site_hierarchy` is starved of its low-priv sources

`_site_hierarchy` ([transforms.py:192-256](../../src/openhound_sccm/transforms.py)) INSERTs **only** from
`adminservice_site_definitions` and `wmi_site_definitions` (both AdminService/WMI-only). When those are
empty (no AdminService), `site_hierarchy` is empty, so `_root_code`/`_first_primary_code` return `None`
and every builder that joins the `nonsec` CTE (derived from `site_hierarchy`) emits **zero rows** —
regardless of what LDAP/RemoteRegistry/HTTP/SMB/DNS actually collected.

### 2.1 Full site-code source inventory (2026-07-27 audit)

The collector learns a site code in **ten** distinct ways (16 raw tables — some rows below cover a family
of sibling tables). Only two reach `site_hierarchy`. Note the asymmetry
with `_node_site`, which *does* read `ldap_sites` ([transforms.py:1245-1255](../../src/openhound_sccm/transforms.py)) —
so today a low-priv run can emit `SCCM_Site` **nodes** while the hierarchy table that gates every edge
family stays empty.

| Source table | Privilege needed | Parent/type carried | In `site_hierarchy`? |
|---|---|---|---|
| `adminservice_site_definitions` | AdminService | parent + type | **yes** |
| `wmi_site_definitions` | WMI (privileged) | parent + type | **yes** |
| `ldap_management_points_raw` ([ldap.py:300](../../src/openhound_sccm/collectors/ldap.py)) | domain user | parent + type + **true root** | no |
| `ldap_sites` — `mSSMSSite` objects ([ldap.py:194-202](../../src/openhound_sccm/collectors/ldap.py)) | domain user | `parent_site_code='Undetermined'` placeholder | no |
| `remoteregistry_sites` ([registry.py:344](../../src/openhound_sccm/collectors/registry.py)) | domain user + 445 | none | no |
| `smb_sites` ([smb.py:277-281](../../src/openhound_sccm/collectors/smb.py)) | domain user + 445 | none | no |
| `http_management_points` / `_distribution_points` / `_smsproviders` / `_site_servers` ([http.py:180-188](../../src/openhound_sccm/collectors/http.py)) | **anonymous** | none | no |
| `http_site_versions` ([http.py:419-423](../../src/openhound_sccm/collectors/http.py)) | **anonymous** | none | no |
| `dns_management_points` ([dns.py:102-110](../../src/openhound_sccm/collectors/dns.py)) | anonymous | none | no — **and not even emitted in the row** (see §4.1) |
| `local_wmi_ccm_client` ([local.py:216](../../src/openhound_sccm/collectors/local.py)) | local host | none | no |
| `local_wmi_sms_authority` / `local_wmi_sms_lookupmp` ([local.py:122,158](../../src/openhound_sccm/collectors/local.py)) | local host | none | no — **and not emitted in the row**, same defect as DNS (corrected 2026-07-27) |

> **Correction (2026-07-27, found in Task 1 review):** the first draft of this table credited
> `local_wmi_sms_authority` and `local_wmi_sms_lookupmp` with a `site_code` column. They have none. The
> site code is parsed from the `SMS:<site>` authority name into `ctx.current_site_code`
> ([local.py:102](../../src/openhound_sccm/collectors/local.py)) and passed to `register_target(...)` as a
> keyword, but both resources `yield target.ad_object` alone — exactly the `dns_management_points` defect.
> Because the column never exists, D5's discovery loop cannot reach them no matter how it is written; they
> need the same one-line collector fix, routed to §4.1 / plan Task 1b.

The richest low-priv sources are the two that carry hierarchy shape:
- **LDAP management-point capabilities** (parsed by `_parse_mp_capabilities`,
  [ldap.py:25-116](../../src/openhound_sccm/collectors/ldap.py)) yields `site_type` (Primary/CAS/Secondary),
  `parent_site_code`, and the true `root_site_code`.
- **RemoteRegistry on a site server** (low-priv-readable SMS keys) yields `site_code` plus the
  `SMS Site Server@<site>` / `SMS SQL Server@<site>` / `SMS Component Server@<site>` role tags on
  `remoteregistry_computers` ([registry.py:370,415,436](../../src/openhound_sccm/collectors/registry.py)),
  and the site database server via the "Multisite Component Servers" key.

**Fix #1 (the unlock):** feed `site_hierarchy` from **every** source in the table above (D5), not just the
two hierarchy-shaped ones. Sources without a type/parent still register the site code; the collapse step
already merges them with any typed row for the same code, so a richer source always wins. This one change
unblocks the `nonsec`-gated families for low-priv users. It is a pure improvement (data already collected)
and is *not* gated by possible-edges — a real hierarchy is a real hierarchy.

## 3. Locked decisions (from grilling)

- **D1 — Scope = Tiers A+B+C.** Default mode reproduces every CMBP-assumed family reachable without
  AdminService, plus the MSSQL template scaffolding, with the tightening below. The genuinely
  uncollectable RBAC/service-account families (Tier D, §5) stay AdminService/WMI-only.
- **D2 — Site-DB signal = RemoteRegistry-confirmed first, then `MSSQLSvc` SPN + SCCM-relatedness.**
  A host is treated as a site database server if RemoteRegistry ("Multisite Component Servers", low-priv)
  confirmed it, **or** (fallback) it has an `MSSQLSvc` SPN in AD **and** is SCCM-related (a discovered
  site system / co-located with an SMS role). This tightens CMBP's "any host reachable on 1433" and works
  even when 1433 is filtered.
  **Two separate rules, clarified 2026-07-27 — do not conflate them:**

  **(a) The SQL server itself is confirmed and unconditional.** A host with an `MSSQLSvc` SPN gets an
  `MSSQL_Server` node, a `Computer` node, and the `MSSQL_HostFor` / `MSSQL_ExecuteOnHost` edge pair —
  **in both flag modes**. The SPN is AD-readable proof that the host runs SQL Server; none of that is an
  assumption.

  **Closed 2026-07-27/28 (Task 1c, then Task 13).** `collect_mssql` first resolves SPNs via
  `ctx.ad.get_spns(target)`, which searches `(dNSHostName=<target>)` — the computer object only, which
  misses SQL running as a *domain service account* (Microsoft's recommended configuration, and the one
  CMBP's own service-account handling assumes), since that registers `MSSQLSvc/host:port` on the **user**
  object instead. Task 1c closed the existence gap this left in (a): when the computer object holds no
  `MSSQLSvc` SPN, `collect_mssql` falls back to `ADClient.find_mssql_spns` (`clients/ad.py`), which searches
  `(servicePrincipalName=MSSQLSvc/<target>*)` across the whole domain and pins the host part exactly (the
  trailing wildcard needed for the port/instance suffix would otherwise also match a longer hostname). The
  SPN is persisted (`has_mssql_spn`) independently of whether TCP/1433 answers, and `mssql_server_instances`
  now feeds a `node_computer` arm, so (a) is unconditional as written, with no dependency on which account
  SQL runs as.

  **A separate, narrower gap remained for Tier A+'s service-account edges — closed by Task 13.**
  `find_mssql_spns` (above) only proves an SPN *exists*; it discards *who holds it*. `MSSQL_ServiceAccountFor`
  and `HasSession` (§4, Tier A+) need that holder's identity, since the SPN is registered on the account SQL
  actually runs as. Task 13 added `ADClient.find_mssql_spn_holder`, sharing `find_mssql_spns`' search and
  host-pinning logic but additionally surfacing the holder's `objectSid`/`sAMAccountName`/`objectClass`,
  and threaded `service_account_sid`/`service_account_is_computer` through `collect_mssql` →
  `mssql_server_instances` → `node_mssql_server` → the low-priv arms of `_edge_mssql_service_account_spn`
  and `_edge_has_session`.

  **(b) "This is the SCCM site database" is a separate, weaker claim.** A host is a *confirmed* site
  database only via RemoteRegistry / AdminService / WMI. The `MSSQLSvc`-SPN + SCCM-relatedness fallback
  never earns the confirmed label in either mode — a co-located SQL host need not be *the* site database.
  Concretely, the fallback:
  - under `--disable-possible-edges` → produces **no** site-DB treatment at all (no `sccm_site`, no
    `sccm_infra = true`, no `CM_<site>`, no Tier-C scaffolding). The host remains a plain `MSSQL_Server`
    per (a);
  - by default (possible-ON) → produces site-DB treatment stamped **assumed** (D3: `assumed = true`,
    `assumptionBasis`, `Assumed-*` in `collectionSource`), never indistinguishable from an RR/privileged
    row.

  Conversely, a site DB that *is* confirmed (RR / AdminService / WMI) keeps its **full** scaffolding in both
  modes with no `assumed` stamp — see §7. The confirmation is what promotes the SCCM default schema from a
  guess to a consequence, so `basis` drives the provenance stamp, not just the gate.

  **Gate once, at the source:** `_assumed_site_dbs` itself drops the `SPN+SCCM` basis when the flag is set,
  so every downstream consumer inherits the filter and no builder repeats the check. Rows that survive
  carry their `basis`, which is what the provenance stamp is derived from.
- **D3 — Labeling.** Assumed nodes/edges stay **traversable** (so BloodHound pathfinding uses them), and
  carry a machine-readable provenance: `collectionSource` gains an `Assumed-<basis>` tag, plus
  `assumed = true` and a human `assumptionBasis` string. Each assumed edge kind gets an entity-panel help
  blurb (via the existing edge-help property-bag pattern, [[bloodhound-opengraph-edge-help-limit]]).
  README gets a full assumption catalog; ARCHITECTURE.md gets a new subsystem section.
- **D4 — Root anchor.** Use the true `root_site_code` from MP-capabilities to resolve the hierarchy root
  (improvement over CMBP's "first primary discovered"); keep possible-client-device attachment to the
  first **primary** site to preserve OpenHound's existing `node-clientdevice-primary-site` invariant.
  **The untyped-root fallback is partly possible-gated** (2026-07-27). When no source carried a site type,
  choosing a root among *several* untyped sites is an assumption, so `--disable-possible-edges` declines it
  and leaves `root_site_code` NULL. With exactly **one** site it is deduction, not assumption — a
  single-site hierarchy has one root and it must be that site — so that case resolves in both modes.
  This is gated more carefully than an ordinary property because the root is baked into SCCM-native node
  **ids**: `suffix = f" || '@{root}'" if root else ""`
  ([transforms.py:1583](../../src/openhound_sccm/transforms.py)) at 8 of the 13 `_root_code` call sites. A
  missing root does not suppress those builders — it mints the same objects under different ids, so the two
  flag modes would produce non-mergeable graphs. Confining the gate to the ambiguous case keeps that
  divergence to a scenario that already emits a WARNING in both modes.
- **D5 — Wire *every* site-code source into `site_hierarchy`** (2026-07-27). Not just the two
  hierarchy-shaped ones: all ten rows of the §2.1 inventory become INSERT arms. A source that knows only
  the bare code still registers the site; the existing collapse (`max(site_type)`, `any_value(parent)`)
  merges it with any richer row for the same code, so adding weak sources cannot degrade a strong one.
  Rationale: the linchpin failure is *an empty table*, and every additional source lowers the odds of that
  in a hardened environment (LDAP container locked down → SMB shares still enumerate → HTTP still answers
  anonymously). Sites are confirmed data → both flag modes.
- **D6 — Site-code attribution is per-host and never guessed** (2026-07-27). A host may only be tagged
  `<Role>@<site>` from a source that actually knows *that host's* site. Concretely: HTTP's `self.site_code`
  comes from the MPKEYINFORMATION endpoint, so it is valid for a host that is an MP (including a host that
  is *both* MP and SMS Provider). A **provider-only** host has no HTTP-knowable site code — it keeps the
  bare role until RemoteRegistry supplies one. Do **not** backfill a missing site code from "the only site
  in the hierarchy" or any similar heuristic.
  **One sanctioned exception, because it is a fact rather than a guess:** the sitesigncert probe reads an
  MP endpoint (`/SMS_MP/.sms_aut?sitesigncert`), so a valid cert response proves the probed host is an MP,
  and the site server named in that cert is by definition the site server of *that MP's* site. The probe
  therefore stamps the probed MP's hostname on its row (`mp_host`, mirroring `http_site_versions`) and the
  transform joins it to that MP's `http_management_points` row for the site code. The join keeps the
  inference visible in the data; a coalesced default would not.

## 4. Per-family build plan

Legend: **confirmed** = built from observed data; **assumed** = templated/inferred (gets provenance tag);
source abbreviations — L=LDAP, MPX=LDAP MP-capabilities XML, RR=RemoteRegistry-on-site-server (low-priv),
H=HTTP `.sms_aut`/`SMS_Identification`/sitesigncert, S=SMB shares, SPN=`MSSQLSvc` SPN, P=TCP/EPA probe.

### Tier A — LDAP-only (unblocked by Fix #1)
| Family | Source | Confirmed/Assumed | Notes |
|---|---|---|---|
| `SCCM_AdminsReplicatedTo` | site_hierarchy (L/MPX/RR) | confirmed (topology) | already built; just needs non-empty hierarchy |
| `SCCM_ClientDevice` (possible) + `SCCM_SameHostAs` + `SCCM_HasClient` | `ldap_cmrc_devices` (CmRcService SPN) | assumed | already built by `_node_client_device_possible`; only blocked by `_root_code`==None (Fix #1) and `disable_possible_edges` |

### Tier B — LDAP + RemoteRegistry/HTTP/SMB role signals (+ Fix #1)
| Family | Source | Confirmed/Assumed | Notes |
|---|---|---|---|
| site-system role tags (`SMS Site Server`/`SMS Provider`/`SMS SQL Server`/`SMS Component Server`/`SMS Management Point`/`Distribution Point`) | RR/H/S | confirmed | tagged by registry.py/http.py/smb.py into `node_computer.site_system_roles` — but **three role sources never reach the table**, see §4.1 |
| `SCCM_AssignAllPermissions` (SMS Provider host → sites; site DB → own site) | roles + site_hierarchy | assumed (structural) | needs Fix #1 |
| `SCCM_LocalAdminRequired` (site server → site systems) | roles + site_hierarchy | assumed (topology) | needs Fix #1 |
| `SCCM_CoerceAndRelayToAdminService` (SMS Site Server → SMS Provider) | roles + site_hierarchy + NTLM-restrict null/Off | assumed (relay) | needs Fix #1 |
| `SCCM_CoerceAndRelayToSMB` (site systems, SMB signing measured `false`) | roles + SMB2-negotiate signing (S, low-priv) + site_hierarchy | confirmed signing + assumed relay | needs Fix #1; **fix traversability** (§6.5) |
| `HasSession` (current-user arm) | RR current-user (low-priv) | confirmed | Already low-priv reachable via RR. **Never possible-gated** — `_edge_has_session` ([transforms.py:2798](../../src/openhound_sccm/transforms.py)) takes no flag and is called unconditionally ([transforms.py:3593](../../src/openhound_sccm/transforms.py)). An observed logon is evidence; so is the MSSQL service-account arm beside it, and the SPN-holder arm added in Tier A+. |

### Tier C — MSSQL template from an assumed/confirmed site-DB identity (D2)
| Family | Source | Confirmed/Assumed | Notes |
|---|---|---|---|
| `MSSQL_Server` + host `Computer` (+`MSSQL_HostFor`/`MSSQL_ExecuteOnHost`) | SPN/RR/P | confirmed | **Both flag modes, unconditional (D2a).** Built today from the 1433 scan, but §4.2 must land first: persist the SPN independently of the port check, and add the `node_computer` arm so the host edges don't dangle. `sccm_site` stays NULL / `sccm_infra` false unless the site-DB claim is separately earned. |
| `MSSQL_ServerRole` sysadmin, `MSSQL_Database` `CM_<site>`, `MSSQL_DatabaseRole` db_owner | SCCM default schema on the site DB (D2) | **depends on the site-DB basis** | Confirmed site DB (RR/AdminService/WMI) → **confirmed**, both modes, no stamp: the schema SCCM requires there follows from the confirmation. `SPN+SCCM` site DB → **assumed** + stamped, possible-ON only. |
| `MSSQL_Contains`/`MSSQL_ControlServer`/`MSSQL_ControlDB` | same | depends on basis | inherits the row above |
| `MSSQL_Login`/`MSSQL_DatabaseUser` (site-server machine accts) + `MSSQL_HasLogin`/`MSSQL_IsMappedTo`/`MSSQL_MemberOf` | same (machine acct is sysadmin/db_owner by SCCM requirement) | depends on basis | requires site-server/provider role (Tier B) + site-DB (D2) |
| `MSSQL_CoerceAndRelayToMSSQL` | template + EPA assume-off | assumed | EPA-off assumption honored only when possible-ON (matches existing flag semantics, [transforms.py:3056-3059](../../src/openhound_sccm/transforms.py)) |
| `SCCM_AssignAllPermissions` (site DB → its site) | template + site_hierarchy | assumed | |

### Tier A+ — confirmed low-priv additions (2026-07-23 review)

These are **confirmed** (observed/LDAP-derived), not assumed — emitted in **both** flag modes, no
provenance stamp. They correct earlier over-exclusions and wire up more already-collected data.

| Family | Source | Confirmed/Assumed | Notes |
|---|---|---|---|
| **`Container` node** (System Management) + **`GenericAll`** edges (each Full-Control principal → Container) | `ldap_system_management_dacl` (already extracts GenericAll principals, [collectors/ldap.py:521-616](../../src/openhound_sccm/collectors/ldap.py)) — **currently discarded**, no transform consumes it | confirmed | **standard BloodHound base kinds** (`Container`/`GenericAll`) — not in `schema_SCCM.json`; compose with SharpHound. Container node id = the container's `objectGUID` so it merges with SharpHound's node (add `objectGUID` to the collector's attribute list). |
| **`MemberOf`** edges (members → each Full-Control **group**) | LDAP `member` of the DACL groups, via the **recursive** `_expand_group_targets` walk which already descends nested groups ([ldap.py:618](../../src/openhound_sccm/collectors/ldap.py)) | confirmed | standard base kind; scope = the **full nested membership** the recursion already visits (a `MemberOf` per member→containing-group hop at every level), not just direct members — we already pay for the walk. BloodHound de-dupes against SharpHound. |
| **`MSSQL_ServiceAccountFor`** (svc account → server instance) + **`HasSession`** (**host computer → svc account**, unless the account IS the host computer) | `MSSQLSvc` SPN holder resolved via LDAP (the SPN is registered on the account SQL runs as) | confirmed | **Reference implementation: `mssql/mssql` extension** — [`edges/derive_ad.py:419 _service_account_edges`](../../../../mssql/mssql/src/openhound_mssql/edges/derive_ad.py) (incl. the built-in/virtual-account → host-computer rule at line 61/447) and [`collection/ad_resolve.py`](../../../../mssql/mssql/src/openhound_mssql/collection/ad_resolve.py). `collect_mssql` currently fetches SPNs for port only ([collectors/mssql.py:41-61](../../src/openhound_sccm/collectors/mssql.py)) and discards the holder — capture it. |

### 4.1 Orphaned role sources — collected, registered, never read (2026-07-27 completeness audit)

A sweep of every raw table the collector writes against every table `transforms.py` reads found four role
signals that are collected, registered in the preprocess table map, loaded into the DuckDB lookup — and
then read by nothing. All four are **confirmed** (observed evidence), so they emit in **both** flag modes
with no `assumed` stamp. Wiring them is preprocess-only except where noted.

| Signal | Source | Privilege | Why it matters |
|---|---|---|---|
| **`http_site_servers`** → `SMS Site Server@<site>` | `_sitesigncert_probe` ([http.py:216-254](../../src/openhound_sccm/collectors/http.py)) parses the MP's site-signing X.509 cert; issuer CN "Site Server" → the cert's SAN DNS name. Port of CMBP `Get-ManagementPointCertIssuer` (ps1:8918-8997) | **anonymous** — no domain creds, no null session | The **only** credential-free way to identify the Site Server. `SCCM_LocalAdminRequired`, `SCCM_CoerceAndRelayToAdminService` and `SCCM_CoerceAndRelayToSMB` all pivot on this role; without it they are unreachable when 445/winreg is blocked but 80/443 to an MP is not. Needs the D6 `mp_host` join for its site code. |
| **`ldap_management_points_raw.fsp_hostname`** → `SMS Fallback Status Point@<site>` | mSSMSCapabilities XML ([ldap.py:73-85](../../src/openhound_sccm/collectors/ldap.py)); CMBP builds the role at ps1:3204-3208 | domain user | Nothing else fingerprints an FSP — HTTP probes MP/DP/AdminService paths, SMB probes SMS shares, RR probes site-server/SQL keys. An FSP-only host gets **no** role tag, and because `_edge_local_admin_required`/`_edge_coerce_relay_smb` match any `role LIKE '%@%'`, it is silently excluded from both families even after Fix #1. |
| **`dns_management_points`** → `SMS Management Point@<site>` | SRV `_mssms_mp_<site>._tcp.<domain>` ([dns.py:102-110](../../src/openhound_sccm/collectors/dns.py)) | anonymous | The site code is **authoritative** — it is the SRV query key. But the collector passes it to `register_target(...)` and then yields `target.ad_object` alone, so the emitted row carries no site code and no role. **Requires a small collector change** (emit the fields), unlike the others. |
| **`smb_sites`** → `site_hierarchy` | SMS_* share names ([smb.py:277-281](../../src/openhound_sccm/collectors/smb.py)) | domain user + 445 | A third independent site-code signal, useful when the System Management container is locked down but share enumeration works. Listed as a follow-up on `ope-4483` when the SMB collector shipped; its sibling `smb_computers` was wired later, `smb_sites` was not. Folded into D5. |
| **`local_wmi_sms_authority`** / **`local_wmi_sms_lookupmp`** → `site_hierarchy` | `ctx.current_site_code`, parsed from the `SMS:<site>` authority name ([local.py:102](../../src/openhound_sccm/collectors/local.py)) | local host (collector runs on an SCCM client) | Found in the Task 1 review, 2026-07-27. Identical defect to `dns_management_points`: the site code is known and handed to `register_target(...)`, but both resources `yield target.ad_object` alone ([local.py:122,158](../../src/openhound_sccm/collectors/local.py)), so no `site_code` column ever exists. **Requires the same one-line collector change**, not transform wiring. On a Local-only run this is the *only* site-code source there is. |

**Verified not a gap** (checked 2026-07-27, do not re-audit):
- `ldap_pattern_matches` **does** feed the scan queue — [ldap.py:504-512](../../src/openhound_sccm/collectors/ldap.py)
  calls `ctx.register_target(...)` and only yields on success, so name-pattern hosts are probed by every
  later per-host phase and pick up real roles there. The raw table being unread by `transforms.py` is
  therefore *not* a lost signal. Residual difference from CMBP: a host matched by name alone that no
  later probe confirms gets no node here, whereas CMBP upserts one tagged `LDAP-NamePattern`. Deliberate —
  a name match is not evidence of an SCCM role, and the Computer node already exists via SharpHound.
- RemoteRegistry NTLM / `disableLoopbackCheck` / SMB-signing / EPA values are already wired as both node
  properties and edge gates in `_edge_coerce_relay_{adminservice,mssql,smb}`.
- `instance_names` is correctly property-only — a named instance's TCP port is unknowable without the SQL
  Browser service, which is not collected ([mssql.py:56-57](../../src/openhound_sccm/collectors/mssql.py)).
- `versionCVEs` is correctly a property on `SCCM_Site`, not an edge.
- Already-tracked elsewhere, not new: `disableLoopbackCheck` → NTLM-reflection relay edge (`ope-961c`),
  `SCCM_HasNetworkAccessAccount` (`ope-e10b`).
- Every `Upsert-Edge -Kind` in ConfigManBearPig.ps1 is either built in `transforms.py` or covered by a Tier
  in §4. No CMBP edge kind is both unbuilt and unplanned. The privileged `SMS_SCI_SysResUse` "SQL Server
  Service Logon Account" path (ps1:7966-8018) is already implemented at
  [transforms.py:2798-2839, 3124-3160](../../src/openhound_sccm/transforms.py) — distinct from the
  low-priv SPN-holder variant in Tier A+.

### 4.2 The `MSSQLSvc` SPN signal is collected and thrown away (2026-07-27)

D2(a) requires that every `MSSQLSvc`-SPN host reach the graph as an `MSSQL_Server` + `Computer` +
`HostFor`/`ExecuteOnHost`. Three things currently prevent that.

1. **The SPN is never persisted.** `collect_mssql` fetches `ctx.ad.get_spns(target)`
   ([mssql.py:41](../../src/openhound_sccm/collectors/mssql.py)) and uses it *only* to parse a port out of
   `MSSQLSvc/host:port`. The SPN itself is discarded, so no raw table records "this host has an MSSQLSvc
   SPN". Task 2's `_assumed_site_dbs` therefore has nothing to join for its SPN predicate.
2. **A filtered port erases the host entirely.** `if not _check_port(target, port): return`
   ([mssql.py:63-65](../../src/openhound_sccm/collectors/mssql.py)) means `mssql_server_instances` is in
   truth a *1433-is-reachable* table, not an *has-an-SPN* table. This directly contradicts D2's stated
   advantage of working "even when 1433 is filtered", and it makes the plan's suggested SPN predicate
   (`sid IN (SELECT host_sid FROM mssql_server_instances)`) silently test reachability instead.
   **Fix:** emit the row whenever the SPN exists, with the EPA/encryption fields NULL when the port is
   closed, and a boolean recording whether the port answered. EPA-gated edges must then require the EPA
   fields, not merely the row's presence.
3. **No `Computer` node for an SPN-only SQL host.** `mssql_server_instances` feeds only
   `_node_mssql_server` ([transforms.py:2380](../../src/openhound_sccm/transforms.py)), never
   `_node_computer`. Meanwhile `_edge_mssql_structural` emits `HostFor`/`ExecuteOnHost` straight off
   `node_mssql_server.host_sid` with no existence check
   ([transforms.py:3077-3083](../../src/openhound_sccm/transforms.py)) — unlike its sibling
   `_edge_mssql_service_account`, which documents an explicit "must exist as a `node_computer`/`node_user`
   row, else skip" guard ([transforms.py:3131](../../src/openhound_sccm/transforms.py)). So a SQL host not
   independently discovered as an SCCM system yields edges pointing at a node id nothing emits.
   **Fix:** add a `node_computer` arm from the MSSQL source so the host is a real Computer node.

## 5. Out of scope — Tier D (structurally uncollectable without privilege)

No AD/LDAP representation exists, and RemoteRegistry-on-site-server does not expose them, so neither tool
can derive them for a low-priv user in a hardened environment: `SCCM_FullAdministrator`,
`SCCM_AllPermissions`, `SCCM_ApplicationAdministrator`, `SCCM_IsAssigned`, `SCCM_IsMappedTo`,
`SCCM_Contains` of RBAC objects, `SCCM_HasMember`, and the SCCM admin-user/security-role/collection
nodes. These remain AdminService/WMI-gated. The default-mode README/ARCHITECTURE docs must state plainly
that these require privileged collection.

**Reclassified out of Tier D (2026-07-23 review) — all now in scope:**
- `MSSQL_ServiceAccountFor` + the `HasSession` service-account arm are **confirmed** (Tier A+, §4): the
  service account is the `MSSQLSvc` SPN holder (LDAP-readable at low priv); they need only the service
  account + server + host, no SQL login.
- `MSSQL_GetTGS`/`MSSQL_GetAdminTGS` **inherit the confidence of the login they rest on** (Tier C): they
  need a domain principal with a SQL login, which at low priv is the site-server/SMS-Provider sysadmin
  login the collector models for those roles. Off a **confirmed** site DB that login is confirmed (§7), so
  the edge is confirmed and emitted in both modes; off an `SPN+SCCM` site DB it is assumed, so the edge is
  provenance-tagged and exists only under possible-ON (where those logins exist at all). Mirrors
  `mssql/mssql` [`derive_ad.py:460-476`](../../../../mssql/mssql/src/openhound_mssql/edges/derive_ad.py).

## 6. Improvements over CMBP (recommended, folded into the plan)

1. **Fix #1** — feed `site_hierarchy` from **all ten** site-code sources (D5), not just AdminService/WMI
   (CMBP re-derives per-run; OH currently discards eight of them). Enables the whole low-priv graph, and
   survives environments where any single discovery channel is blocked.
2. **True root** from MP-capabilities `root_site_code`, not CMBP's "first primary discovered" (correct in
   multi-hierarchy environments).
3. **Site-DB signal** RR-confirmed → SPN+SCCM-related (D2), vs CMBP's 1433-only heuristic (fewer false
   positives; works with 1433 filtered).
4. **Provenance** (`assumed`/`assumptionBasis`/`Assumed-*` collectionSource) — CMBP does not distinguish
   assumed from confirmed.
5. **`SCCM_CoerceAndRelayToSMB` traversability** — CMBP emits it non-traversable due to a kind-name
   mismatch bug ([[sccm-stage6-relay-decisions]]); OpenHound emits it traversable.
6. **Deterministic possible-client-device IDs** — CMBP uses random GUIDs (documented duplicate risk); OH
   uses stable IDs and dedupes assumed vs confirmed (`_dedup_client_device`).
7. **Wire up the discarded System Management container DACL** — `ldap_system_management_dacl` is collected
   but no transform consumes it; model it as a `Container` node with `GenericAll` edges (+`MemberOf` for
   group members) using standard BloodHound kinds, exposing the "who can control SCCM via the SMC
   container" attack surface CMBP's own TODO left unbuilt.
8. **SPN-holder MSSQL service account** — resolve the `MSSQLSvc` SPN holder (LDAP) to emit
   `MSSQL_ServiceAccountFor`/`HasSession` at low privilege (reuse the `mssql/mssql` extension's logic,
   including its built-in/virtual-account → host-computer handling), instead of treating the service
   account as AdminService-only.
9. **Credential-free site-server identification** (§4.1) — wire the site-signing-certificate probe's
   `http_site_servers` rows through to `node_computer`. CMBP builds this node
   (`Get-ManagementPointCertIssuer`); OpenHound collects the evidence and drops it. This is the only
   Site Server signal that needs no credentials at all.
10. **Traceable site-code attribution** (D6) — every `<Role>@<site>` tag is sourced from something that
    knows that host's site, and the cross-host case (cert issuer) carries an `mp_host` breadcrumb so the
    inference is auditable in the raw table. CMBP tags roles with the ambient site code of the run.
11. **DNS-discovered MPs keep their site code** (§4.1) — the SRV query key is the site code, so the row
    should carry it plus the MP role instead of a bare AD object.

## 7. `--disable-possible-edges` semantics (unchanged intent, now meaningful at low priv)

The flag stays a **tightening-only** switch. When set, it removes/does-not-create the *assumed* families:
the possible client devices (+`SameHostAs`/`HasClient`), the MSSQL scaffolding **that rests on an assumed
site DB**, and `MSSQL_CoerceAndRelayToMSSQL`'s EPA-off assumption. It never removes **confirmed** data (real
site hierarchy, observed roles, the `MSSQL_Server`/`Computer`/`HostFor`/`ExecuteOnHost` set from an
`MSSQLSvc` SPN per D2a, `HasSession` in both its arms, and everything downstream of a confirmed site DB).
Fix #1 (site_hierarchy) is confirmed data and stays in both modes.

> **Ruling (Task 5, 2026-07-28): the code is right, the spec was wrong.** `SCCM_AssignAllPermissions`,
> `SCCM_LocalAdminRequired` and `SCCM_CoerceAndRelayToAdminService`/`SCCM_CoerceAndRelayToSMB` are **not**
> gated by `--disable-possible-edges`, and that is correct — this section's earlier claim that the flag
> removes them is deleted rather than implemented, for three reasons: (1) their gates are **measured
> evidence**, not a topology guess — the SMB relay's target is only ever chosen because a probe confirmed
> `smb_signing_required = false`, and the NTLM gate treats an unset `RestrictReceivingNTLMTraffic` as
> vulnerable because that IS the Windows default (0 = allow all inbound NTLM), not an assumption about it;
> (2) a live CMBP-vs-OpenHound comparison run under `--disable-possible-edges` (2026-07-28,
> `sccm/tests/live-comparison/lowpriv_check/`) shows CMBP itself emits these same three families under its
> own `-DisablePossibleEdges` switch, so gating them here would make OpenHound *stricter* than the tool it
> ports rather than matching it; (3) `edge_coerce_relay_smb_test.py::test_smb_relay_flag_keeps_null_ntlm`
> predates this plan and already pins the opposite behavior deliberately. These edges do still carry `assumed`
> provenance (D3, Task 5) — they template a permission/relay conclusion from role topology rather than
> reading it out of an ACL, which is worth flagging to an operator — but that stamp is unconditional, not
> flag-gated.

**A confirmed site DB keeps its full scaffolding (decided 2026-07-27).** Once RemoteRegistry (or
AdminService/WMI) confirms a host *is* the site database, the structure SCCM requires and defaults to on
that database is no longer a "possible" edge — it is a consequence of the confirmed fact. So
`MSSQL_Database` `CM_<site>`, the sysadmin and db_owner roles, the site-server/provider machine-account
logins and database users, and their `Contains`/`MemberOf`/`HasLogin`/`IsMappedTo`/`Control*` edges are all
emitted in **both** flag modes and carry **no** `assumed` stamp. Their `collectionSource` still records
that they were derived from the SCCM default schema rather than read out of SQL, so the provenance remains
auditable without implying doubt.

**What the flag actually removes on the MSSQL side is therefore just the *basis*.** An SPN+SCCM host is
never a confirmed site DB (D2b), so under the flag it contributes no site-DB row at all and the entire
scaffolding above simply has nothing to build from — the filter lives in `_assumed_site_dbs` and every
downstream builder inherits it without its own flag check. The one MSSQL builder that still needs the flag
directly is `MSSQL_CoerceAndRelayToMSSQL`, whose EPA-off assumption is independent of how the site DB was
identified.

## 8. Documentation (D3)

- **README** — expand the possible-edges/Assumptions section into a full catalog: one row per assumed
  family with its inference rule, data source, and false-positive caveat; a "what needs privilege"
  callout (Tier D); copy-pasteable mayyhem examples for default vs `--disable-possible-edges`.
- **ARCHITECTURE.md** — new section for the LDAP/RemoteRegistry-fed `site_hierarchy` and the
  assumption/provenance engine, plus a changelog entry; update the preprocess/convert section.
- **Entity-panel help** — per assumed edge kind, a help blurb via the edge property-bag pattern.

## 9. Testing

- **Offline transforms tests** (`sccm/sccm/tests/*_test.py`, SCCM venv): synthetic DuckDB fixtures that
  exercise (a) `site_hierarchy` populated from LDAP-MP-caps-only and from RR-only, (b) each newly-unblocked
  family emitting under possible-ON and being absent under possible-OFF, (c) provenance tags present, (d)
  the D2 site-DB signal (SPN+SCCM-related fires; arbitrary SQL host does not).
- **Integration fixtures** — extend `openhound_sccm/integration/fixtures` with low-priv-expected cases so
  `--run-integration-tests` has a low-priv baseline (distinct from the domainadmin baseline), OR document
  that the existing fixtures are the privileged baseline. (Decide during planning.)
- **Live re-validation** — re-run `lowpriv_check` (CMBP vs OpenHound, both flag states) and confirm
  OpenHound's default-mode graph now approaches CMBP's, with provenance tags and no Tier-D fabrication.

## 10. Risks

- **False positives from templated MSSQL internals** — mitigated by D2 (tighter site-DB signal) and D3
  (provenance so operators can filter). Document prominently.
- **Multi-hierarchy site-code collisions** — the true-root fix (D4) reduces but does not eliminate CMBP's
  single-hierarchy assumption (README already documents it).
- **`site_hierarchy` shape drift** — adding LDAP/RR arms must preserve the existing `site_type` INTEGER
  contract (2=Primary, 4=CAS) that root resolution depends on; MP-caps strings must map to those codes.
- **Typeless sources make the root fallback fire more often** (new with D5) — eight of the ten sources
  carry a bare site code with `site_type = NULL`. Root resolution needs a CAS(4) or a parentless Primary(2),
  so when only typeless sources ran, D4's ordered "first site code" fallback picks the root
  alphabetically — arbitrary in a multi-site hierarchy. Mitigations: the collapse keeps `max(site_type)`
  so **one** typed source anywhere rescues the whole table; `--disable-possible-edges` refuses the guess
  outright when there is more than one candidate (D4); and the logging splits by ambiguity —
  **WARNING** when there is more than one candidate, naming the chosen code (or that none was chosen), the
  full candidate list, and the fix (only LDAP MP-capabilities and AdminService/WMI carry a site type);
  **INFO** when there is exactly one site, where the pick is the only possible answer and a warning would be
  pure noise in the normal low-priv shape. Accepted risk in default mode; the alternative (no root at all)
  emits zero edges.
- **Node-id divergence between flag modes** (new with D4's gate) — in the multi-site-untyped case
  possible-OFF leaves the root NULL, so SCCM-native ids lose their `@<root>` scope and will not merge with
  a default-mode graph of the same environment. Deliberate and warned about; the alternative was asserting
  an unobserved root in evidence-only mode.
- **`ldap_sites` emits the literal string `'Undetermined'`** as `parent_site_code`
  ([ldap.py:197](../../src/openhound_sccm/collectors/ldap.py)) — a placeholder meaning "resolve this from
  mSSMSManagementPoint later". Every arm must normalize `'None'`/`'Undetermined'`/`''` to NULL or the
  parentless-Primary root test silently fails.
