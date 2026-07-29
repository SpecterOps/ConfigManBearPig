# SCCM preproc + convert — design spec

**Date:** 2026-06-16
**Revised:** 2026-06-16 — mechanism flipped from JSONL *writeback* to a convert-time *DuckDB-reading
pipeline* (Convert2-Read-DB), per review with the OpenHound author; writeback demoted to documented fallback.
**Scope:** Port the post-processing / graph-building logic of `ConfigManBearPig.ps1` (CMBP) into the
OpenHound SCCM collector's `preproc` and `convert` phases. The `collect` phase is complete and
unchanged.
**Reference tool:** `sccm/ConfigManBearPig.ps1` (CMBP) — all `:NNNN` citations are line numbers in
that file unless noted.

---

## 1. Current state (the real starting line)

`collect` is done and produces ~45 raw JSONL tables (adminservice_*, wmi_* fallback, remoteregistry_*,
mssql_server_instances, http_*, smb_*, ldap_*, dns_*, local_*). Identities that CMBP resolves inline
during collection are **already resolved to SIDs** by the collectors (LDAP/AD objects,
`adminservice_admins.AdminSid`, `r_system.SID`, `r_user.SID`, reserved/site-server/SQL-server
principals). See [privileged.py:19-21](../../../src/openhound_sccm/collectors/privileged.py#L19-L21):
device users and `SecurityGroupName[]` are deliberately left **name-only** for downstream resolution.
(Path note: links below are relative to this file under `docs/superpowers/specs/`.)

The preproc/convert side is dismantled and must be rebuilt from scratch:

- `transforms.py`, `lookup.py`, `graph.py` — **deleted**, but `main.py:32` still
  `from .transforms import transforms` and `main.py:1135` registers `@app.preproc(transformer=transforms)`,
  so the package **does not import** today.
- **No `@app.convert`** anywhere.
- `models/__init__.py` imports `from .sccm_site import SCCMSite` and describes an "11 derived edge
  models + DerivedEdges aggregator" design — **none of those files exist**.
- `kinds/edges.py` is **empty**.
- `_preproc_table_map()` ([main.py:1067](../../../src/openhound_sccm/main.py#L1067)) lists table names that
  **do not match** the real collected tables (e.g. `ldap_computers`, `registry_sccm_databases`,
  `smb_signing_status`, `mssql_epa_flags`). It is stale and must be rebuilt from the actual collect
  output.
- The README documents a previous design state that no longer exists in code.

Target graph (from CMBP): **15 node kinds + ~35 edge kinds**.

---

## 2. Locked decisions

1. **Preproc coalesces in DuckDB; convert emits via the Second Convert Pipeline with DuckDB Read (`Convert2-Read-DB`).** preproc loads raw
   JSONL into DuckDB and builds coalesced **one-row-per-entity** node tables (`node_*`) and a derived
   `graph_edges` table via set-based SQL. `convert` then runs an explicit `dlt.pipeline` that reads
   those DuckDB tables directly and emits to the `opengraph_file` destination, instantiating a trivial
   typed model per table (`row → node` / `row → edge`). **Rationale:** the framework's built-in convert
   reader only globs JSONL from the bucket, so a coalesced DuckDB table can't be iterated by it; rather
   than writing the coalesced tables back to JSONL (a filesystem side-channel that couples the
   preprocess/convert path args), we read DuckDB directly with a manual pipeline — which the OpenHound
   author confirms is the more DLT-native pattern. The coalescing itself stays SQL `GROUP BY` (the only
   construct that does true column + array union across the per-source tables). See §4. The DuckDB
   read-implementation (a custom `@dlt.resource` over the open lookup connection vs DLT's `sql_database`
   source) is **deferred to the implementation plan**, where both are prototyped against the real
   `lookup.duckdb`.
2. **Offline identity resolution, no collect changes.** preproc builds a `principal_by_name` table from
   the union of every collected `(name, SID)` pair (r_user, r_system, ldap/AD objects, admins, reserved).
   Name-only fields (device users, `SecurityGroupName[]`, SQL service account) are resolved by joining
   against it; unresolved → the edge/node is dropped (matches CMBP's drop-on-failure at
   `Resolve-PrincipalInDomain` :459-904). Logged at warning level.
   *SID format verified 2026-06-16:* AD-resolved tables carry `object_sid` (from `bytes_to_sid`,
   [ad.py:233](../../../src/openhound_sccm/clients/ad.py#L233)) and the SMS tables carry `sid`
   (snake-cased from `SMS_R_System.SID`, [sms_rows.py:78](../../../src/openhound_sccm/collectors/sms_rows.py#L78));
   both are the canonical `S-1-5-…` string, so the coalesce aliases them to one column and `GROUP BY`
   collapses the same entity. `principal_by_name` also **back-stops node identity** (not just name-only
   edge fields): the node coalescing resolves rows whose own SID is NULL (AD resolution failed) by
   `dNSHostName`/`name` *before* `GROUP BY`; rows still unresolved after that are dropped with a logged
   count (tier-3 — every emitted node is therefore SID-keyed).
3. **Active MSSQL only.** Port the two live builders (`Add-MSSQLServerNodesAndEdges` :6050-6186 and
   `Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer` :6187-6292) plus `MSSQL_GetTGS` :1965-1978,
   `MSSQL_ServiceAccountFor`/`GetAdminTGS` :8012-8016, and `MSSQL_AssignAllPermissions` (db→site)
   :6173-6180. **Skip** the decommissioned `Add-MSSQLNodesAndEdgesForPrimarySite` :6293 (call site
   commented at :6539).
4. **Faithful-but-fixed.** Bug fixes folded in (§7): compute `rootSiteCode` *first* so node IDs are
   minted final (eliminates the `@siteCode`→`@rootSiteCode` rewrite, `Update-GlobalObjectIdentifiers`
   :2397); replace O(n²)/O(n³) array scans with set-based SQL; normalize `collectionSource`/
   `CollectionSource` casing; prefer the collected SQL port over hardcoded `:1433`. Possible/inferred
   edges (coerce-and-relay, EPA/SMB-signing assumptions) preserved but clearly labeled, honoring the
   "Allowed/Required" EPA-uncertainty convention and `--disable-possible-edges`.
5. **Explicit exclusions** (dead/superseded CMBP code, not ported): the `Host` node
   (`Add-HostNodeAndEdges` :2373, unused by the main flow); the WMI graph-emit functions :8210-8600
   (they never `Upsert`; the `wmi_*` raw tables feed the same coalescing as `adminservice_*`); the
   superseded `Invoke-ProcessRoleAssignments` :1986 duplicate.

### Alternatives considered (2026-06-16 review with the OpenHound author)

Recorded so the mechanism isn't re-litigated:

- **Writeback to JSONL — demoted to documented fallback.** preproc `COPY`s each coalesced `node_*` table
  and `graph_edges` to `<bucket>/sccm/<table>/data.jsonl.gz`; convert reads them with the framework's
  filesystem reader (thin `row → node`/`row → edge` models). Fully idiomatic on the *read* side and
  leaves inspectable JSONL artifacts — but it is a filesystem side-channel: the preproc transformer must
  learn the bucket path and write into it, coupling the preprocess/convert path args (the awkwardness
  the §8 proposal flags), and it doubles IO (write + re-read the coalesced rows). The author considers
  it a last resort. **Kept as the fallback** if Convert2-Read-DB hits a wall (see §4 Stage-0 spike).
- **Multi-driver emit + BloodHound merge — rejected (scale).** One convert model per contributing raw
  table, all emitting the same node id, deduped on ingest. In the common worst case (every domain
  computer is a client), the population is found by *both* LDAP (CmRcService SPN) and privileged
  `r_system`, so each computer emits ~2× (one extra full copy of the population), with further multiples
  on per-host-probed infra. Convert2-Read-DB's one-row-per-entity coalescing is flat 1×. Same reasoning for User/Group.
- **DLT native `merge` write disposition — rejected (semantics + fit).**
  `@dlt.resource(table_name=…, write_disposition="merge", primary_key="id")` across resources. Two
  problems: (1) DLT `merge` deduplicates/replaces at the **row** level by key — it does **not**
  column-coalesce partial rows into one fat row (confirm with a 5-line spike if ever revisited), so it
  wouldn't combine the per-source fields; and (2) there is **no phase to run it** — collect can't share
  a resource across the ordered per-host phases (the original constraint) and the key isn't normalized
  yet, preproc's `PreProcessor.run` hardcodes `write_disposition="replace"` in core (no core edits), and
  convert's `opengraph_file` destination isn't relational. SQL `GROUP BY` in preproc does the true
  column + array coalesce that `merge` can't, at the right layer.

### Open design points (resolve at spec review / Stage 1)

- **Root/environment node — RESOLVED 2026-06-17 (with the BloodHound maintainer).** OpenHound's node
  model requires an `environmentid` *property* on every node (no default). **No environment *node* is
  emitted** — property only. Assignment:
  - **Base AD nodes** (Computer/User/Group): `environmentid` = the node's **AD domain SID**, derived
    per node by stripping the RID from its own SID (`S-1-5-21-A-B-C-1104` → `S-1-5-21-A-B-C`). This
    merges them with SharpHound's AD nodes of the same SID under the same domain rather than re-homing
    them. Derivation is per node, so one collect legitimately spans multiple AD domains.
  - **SCCM-native nodes** (SCCM_Site/Collection/AdminUser/SecurityRole/ClientDevice): `environmentid` =
    the hierarchy **`rootSiteCode`**.
  - **MSSQL_\*** (incl. Login/DatabaseUser/roles): `environmentid` = the **AD domain SID of the SQL
    server's domain-joined host** — *not* the SCCM environment.
  - **Well-known/builtin SIDs** (e.g. `S-1-5-32-*`, `S-1-5-11`) have no `S-1-5-21` domain SID; the
    Stage 1 plan defines their handling (proposed: SharpHound-style per-domain qualification).
  - **Documented assumption (→ README Limitations):** within one organization a site code is never
    reused, and two organizations are never loaded into the same graph — so the raw `rootSiteCode` is a
    safe SCCM environment id.
- **Edges: materialized `graph_edges` (locked).** preproc builds a single
  `graph_edges(start_id, end_id, kind, properties)` table by UNION-ing the per-edge-kind SELECTs;
  convert emits all ~35 kinds through **one** trivial edge model reading that table from DuckDB. The
  lookup-driven github-style fan-out alternative is rejected at ~35-kind scale (bespoke lookup methods
  + per-row Python fan-out scattered across ~10 models — the O(n²)/O(n³) trap of §7). This choice is
  **independent of the node-read mechanism**: `graph_edges` is just another DuckDB table the Convert2-Read-DB pipeline
  reads.

---

## 3. Node & edge inventory (the "nothing is lost" ledger)

"PS1 creation" = where CMBP creates it: **inline** (during collection via `Upsert-Node`/`Upsert-Edge`)
or **post-proc** (`Invoke-PostProcessing` :1577-1984). Every item maps to a port stage.

### Nodes (15)

| Kind | PS1 creation | Stage | Preproc table | Convert model |
|---|---|---|---|---|
| `Computer` (+`Base`) | inline (many sites) | 1 | `node_computer` | `ComputerNode` |
| `User` (+`Base`) | inline | 1 | `node_user` | `UserNode` |
| `Group` (+`Base`) | inline | 1 | `node_group` | `GroupNode` |
| `Group` (Authenticated Users, `$Domain-S-1-5-11`) | post-proc relay :6609/6708/6766 | 6 | `node_group` | `GroupNode` |
| `SCCM_Site` | inline :7043 (+LDAP/local/http/smb/registry) | 1 | `node_site` | `SCCMSite` |
| `SCCM_ClientDevice` | inline :7220 (+possible-client :3272) | 2 | `node_client_device` | `SCCMClientDevice` |
| `SCCM_Collection` | inline :7532 | 2 | `node_collection` | `SCCMCollection` |
| `SCCM_AdminUser` | inline :7767 | 2 | `node_admin_user` | `SCCMAdminUser` |
| `SCCM_SecurityRole` | inline :7700 | 2 | `node_security_role` | `SCCMSecurityRole` |
| `MSSQL_Server` | inline :6085 | 5 | `node_mssql_server` | `MSSQLServer` |
| `MSSQL_Database` | inline :6137 | 5 | `node_mssql_database` | `MSSQLDatabase` |
| `MSSQL_ServerRole` | inline :6101 | 5 | `node_mssql_server_role` | `MSSQLServerRole` |
| `MSSQL_DatabaseRole` | inline :6151 | 5 | `node_mssql_database_role` | `MSSQLDatabaseRole` |
| `MSSQL_Login` | inline :6229 | 5 | `node_mssql_login` | `MSSQLLogin` |
| `MSSQL_DatabaseUser` | inline :6245 | 5 | `node_mssql_database_user` | `MSSQLDatabaseUser` |

### Edges (~35)

| Kind | Start → End | PS1 creation | Stage |
|---|---|---|---|
| `SCCM_AdminsReplicatedTo` | Site ↔ Site | post-proc :1604-1626 | 1 |
| `SCCM_IsMappedTo` | AD principal → AdminUser | inline :7789-7804 | 2 |
| `SCCM_IsAssigned` | AdminUser → Collection/SecurityRole | inline :7819/7841/7867 | 2 |
| `SCCM_HasMember` | Collection → member | inline :7617-7629 | 2 |
| `SCCM_HasClient` | Site → ClientDevice | inline :7257/7394 | 2 |
| `SCCM_HasPrimaryUser` | ClientDevice → User | inline :7298 | 2 |
| `SCCM_HasCurrentUser` | ClientDevice → User | inline :7275 | 2 |
| `SCCM_HasADLastLogonUser` | ClientDevice → User | inline :7266 | 2 |
| `SCCM_HasStoredAccount` | Site → User/Group | inline :7147 | 2 |
| `SCCM_HasNetworkAccessAccount` | Computer → User | inline :4185 | 2 |
| `MemberOf` | Computer/User → Group | inline :7375/7470 | 2 |
| `HasSession` | Computer → User | inline :8007/5029 | 2 |
| `SCCM_Contains` | Site → Collection/Role/AdminUser | post-proc :1659-1690 | 3 |
| `SCCM_FullAdministrator` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_ApplicationAuthor` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_ApplicationAdministrator` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_ComplianceSettingsManager` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_OSDManager` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_OperationsAdministrator` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_SecurityAdministrator` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_AllPermissions` | AdminUser → Site | post-proc :1730-1837 | 3 |
| `SCCM_AssignAllPermissions` | Computer(SMS Provider) → Site | post-proc :1932-1940 | 3 |
| `SameHostAs` | Computer ↔ ClientDevice | post-proc :2261-2311 | 4 |
| `LocalAdminRequired` | Computer → Computer | post-proc :1882-1909 | 4 |
| `MSSQL_Contains` | Server→DB / DB→role etc. | inline :6110-6160 | 5 |
| `MSSQL_ControlServer` | role → Server | inline :6101-6130 | 5 |
| `MSSQL_ControlDB` | role → DB | inline :6151-6172 | 5 |
| `MSSQL_HostFor` | Server → Computer | inline :6090-6120 | 5 |
| `MSSQL_ExecuteOnHost` | Server → Computer | inline :6090-6120 | 5 |
| `MSSQL_HasLogin` | Server → Login | inline :6230-6260 | 5 |
| `MSSQL_IsMappedTo` | Login → AD principal | inline :6232-6260 | 5 |
| `MSSQL_MemberOf` | Login → role / user → dbrole | inline :6260-6286 | 5 |
| `MSSQL_ServiceAccountFor` | User(SID) → Server | inline :8012 | 5 |
| `MSSQL_GetAdminTGS` | User(SID) → Server | inline :8016 | 5 |
| `MSSQL_GetTGS` | service acct → Login | post-proc :1965-1978 | 5 |
| `MSSQL_AssignAllPermissions` | Database → Site | inline :6173-6180 | 5 |
| `CoerceAndRelayToAdminService` | Auth Users → Site | post-proc :6572-6623 | 6 |
| `CoerceAndRelayToMSSQL` | Auth Users → MSSQL_Login | post-proc :6626-6724 | 6 |
| `CoerceAndRelayToSMB` | Auth Users → Computer | post-proc :6728-6779 | 6 |

> Exact MSSQL line sub-ranges (`:6110-6286`) are approximate from analysis; the implementer confirms
> them per stage. The traversable-flag allow-list lives at CMBP :2216-2255 and feeds Stage 0's
> `seed_data` / edge declarations.

---

## 4. Preproc → convert mechanism

### Preproc (`transforms.py` + `main.py`)

1. `main.py` `preproc(ctx)` returns the corrected raw-table map (DuckDB table → JSONL path under
   `sccm/<real_table>`). No bucket-path stashing is needed — Convert2-Read-DB does not write back.
2. `transforms(con)`:
   - **Coalesce** each entity into a one-row-per-ID table (`node_computer`, `node_user`, `node_group`,
     `node_site`, `node_client_device`, `node_collection`, `node_admin_user`, `node_security_role`,
     `node_mssql_*`) via `GROUP BY` + array `UNION` — this is CMBP's `Upsert-Node` merge as SQL
     (:1444-1575). `rootSiteCode` is computed here (hierarchy BFS, CMBP :2511/2620) so SCCM object IDs
     are minted final.
     - *SID normalization in the coalesce:* alias `object_sid`/`sid` to one key (both canonical
       `S-1-5-…`, §2 Decision #2); resolve NULL-SID rows via `principal_by_name`; **drop
       `SMS_R_System` rows flagged `Obsolete`** (it keeps stale duplicate records per machine, which
       would otherwise shadow the live row in `any_value`/array unions); drop rows still without a SID
       and log the count.
   - **Lookups**: `principal_by_name`, `resource_to_sid`, `device_by_resourceid`, `site_root`,
     `sites_in_hierarchy`.
   - **Derived edges**: build `graph_edges(start_id, end_id, kind, collection_source)` by `UNION`-ing the
     per-edge-kind SELECTs (CMBP post-processing :1577-1984 + the inline edge logic). *Schema note:*
     Stage 2 reduced this to 3-col `(start_id, end_id, kind)` (its Task-C0 note dropped a free-form
     `properties JSON` column — DuckDB returns JSON as a *string*, breaking a `dict` read). **Stage 3
     re-introduces a typed `collection_source VARCHAR[]`** column (not JSON) so edge entity panels are
     populated; the dedup pass array-unions it (`GROUP BY start_id,end_id,kind`).
   - **No writeback.** Everything stays in the lookup DuckDB.

### Convert (`convert_pipeline.py` + `models/*` + `main.py`)

- `@app.convert(lookup=SCCMLookup)` runs an explicit `dlt.pipeline` (the **Convert2-Read-DB helper**) that, for each
  `node_*` table and `graph_edges`, reads rows from the lookup DuckDB and instantiates the typed model,
  emitting `as_node` / edges to the `opengraph_file` destination
  (`output_path = ctx.output_path`, `source_kind = app.source_kind`). The helper **`mkdir`s
  `output_path` first** — the destination opens files without creating the dir, and the helper runs
  before the framework would create it.
- The **DuckDB read source** is either a custom `@dlt.resource` over the open lookup connection (an
  independent cursor, so it can't clobber `self._lookup` queries) or DLT's `sql_database` source —
  chosen in the implementation plan (§2 Decision #1).
- **Node models:** typed `<PREFIX>NodeProperties` dataclass (documented `Attributes`) + `as_node`
  returning the node. No edge logic. **Edge model:** reads `graph_edges`; emits `Edge(kind=row.kind,
  start=EdgePath(row.start_id, match_by="id"), end=EdgePath(row.end_id, match_by="id"), …)`. `EdgeDef`
  declarations grouped by stage.
- The framework's `@app.convert` still expects a `(DltSource, dict)` return; return a **minimal/empty
  source** so the framework's own pipeline is a no-op (all emission happens in the Convert2-Read-DB pipeline).
  `self._lookup` remains available for any residual point resolution.
- **Output coexistence verified:** `opengraph_file` appends uniquely-numbered files
  (`{table}-{n}.json`) via a process-global counter ([destination.py:12-49](../../../.venv/Lib/site-packages/openhound/destinations/opengraph/destination.py)),
  so the Convert2-Read-DB pipeline and the framework no-op pipeline never collide.

### Validation of the mechanism (Stage 0 spike)

Prove a tiny `graph_edges` row in DuckDB round-trips through the Convert2-Read-DB pipeline into **one edge** in
`<graph>/*.json`, and one `node_*` row into **one node**. **Fallback if Convert2-Read-DB proves unworkable:**
writeback — preproc `COPY … (FORMAT JSON)` gzip into the bucket, convert reads via the framework's
filesystem reader (§2 alternatives; the
[OpenHound proposal](../../proposals/2026-06-16-convert-read-from-duckdb.md) covers the core-level
variant).

---

## 5. Files touched

| File | Role |
|---|---|
| `src/openhound_sccm/transforms.py` | recreate — coalescing + derived-edge SQL (no writeback) |
| `src/openhound_sccm/lookup.py` | recreate — `SCCMLookup(LookupManager)` cached methods + the row iterators the Convert2-Read-DB pipeline reads |
| `src/openhound_sccm/convert_pipeline.py` | **new** — the Convert2-Read-DB manual `dlt.pipeline` (read `node_*`/`graph_edges` from DuckDB → `opengraph_file`); `mkdir`s output first |
| `src/openhound_sccm/graph.py` | recreate — `SCCMNodeProperties`/`SCCMNode`/`SCCMEdgeProperties` |
| `src/openhound_sccm/kinds/edges.py` | populate — all edge-kind constants |
| `src/openhound_sccm/kinds/nodes.py` | keep (already complete) |
| `src/openhound_sccm/models/*.py` | one typed model per coalesced node table + the edge model |
| `src/openhound_sccm/models/__init__.py` | fix imports/exports to match real files |
| `src/openhound_sccm/main.py` | fix `transforms` import; rebuild `_preproc_table_map()`; register `@app.convert(lookup=SCCMLookup)` to run the Convert2-Read-DB pipeline and return a minimal source |
| `README.md` | Node/Edge Reference, preproc/convert sections, mayyhem.com examples |

---

## 6. Stages

Each stage is independently runnable and ends with **two deliverables**: the **manual validation**
block below, and a written **manual-validation harness** — a standalone doc at
`docs/superpowers/plans/<stage>-validation.md` styled as a **code tour**: a step-through of the
stage's actual code in execution order via a small in-process driver script, with exact breakpoint
locations (`file:line`), what to inspect at each stop, the expected debugger state, and the plan
detail each stop verifies — plus a black-box CLI/output smoke check. **Writing that harness is the final task of
every stage's implementation plan** (the automated `*_test.py` suite uses synthetic data; the harness
is how a human confirms real behavior). Stage 0's harness:
[`2026-06-16-sccm-preproc-convert-stage0-validation.md`](../plans/2026-06-16-sccm-preproc-convert-stage0-validation.md).
Each stage maps to gtk ticket(s). Standard test loop (collect once, reuse the raw JSONL):

```bash
# one-time: collect against the lab (or reuse an existing <raw> tree)
openhound preprocess sccm <raw> <raw>/lookup.duckdb
openhound convert sccm <raw>/sccm <graph> --lookup-file <raw>/lookup.duckdb
# then inspect <graph>/*.json for the kinds the stage adds
```

### Stage 0 — Unblock & scaffold
- **PS1:** export/seed_data structure :9523-9846; traversable allow-list :2216-2255.
- **Do:** recreate `graph.py` (base node/props/edge classes), `lookup.py` (`SCCMLookup` skeleton + the
  DuckDB row iterator), `transforms.py` (no-op transform + coalescing skeleton + the Stage-0 spike
  table), `convert_pipeline.py` (the Convert2-Read-DB helper); fix `main.py` import; rebuild `_preproc_table_map()` to
  the real collected tables; register `@app.convert` (runs the Convert2-Read-DB pipeline, returns a minimal source);
  populate `kinds/edges.py`; fix `models/__init__.py`.
- **Validate:** package imports; `openhound preprocess sccm …` and `openhound convert sccm …` both run
  to completion; the spike `graph_edges` row appears as one edge in `<graph>` via the Convert2-Read-DB pipeline (and
  one `node_*` row as one node).

### Stage 1 — Base nodes + Site + hierarchy
- **PS1:** `Upsert-Node` merge semantics :1444-1575; AdminService site emit :7043; hierarchy
  `Get-SitesInHierarchy` :2511 / `Get-HierarchyRoot` :2620; `SCCM_AdminsReplicatedTo` :1604-1626;
  identity corpus :459-1131.
- **Do:** coalesce `node_computer`/`node_user`/`node_group`/`node_site`; compute `rootSiteCode`;
  `principal_by_name`. Emit Computer/User/Group/Base + SCCM_Site; `SCCM_AdminsReplicatedTo`. Decide the
  root/environment node (§2 open point).
- **Validate:** `computer`/`user`/`group` + `SCCM_Site` nodes present with merged arrays (site-system
  roles unioned, no dup computer nodes per SID); `SCCM_AdminsReplicatedTo` matches the lab hierarchy;
  spot-check one site's `rootSiteCode`.

### Stage 2 — SCCM entities + inline edges
- **PS1:** ClientDevice :7220-7300; Collection :7532 (+HasMember :7617); AdminUser :7767 (+IsMappedTo
  :7789, IsAssigned :7819); SecurityRole :7700; HasStoredAccount :7147; Has*User :7266/7275/7298;
  HasNetworkAccessAccount :4185; MemberOf :7375/7470; HasSession :8007/5029; possible-client :3272.
- **Do:** coalesce `node_client_device`/`node_collection`/`node_admin_user`/`node_security_role`
  (IDs already `@rootSiteCode`); `resource_to_sid`, `device_by_resourceid`; build the inline edges.
- **Validate:** all four SCCM entity kinds present; spot-check an admin's `SCCM_IsMappedTo`/`IsAssigned`,
  a collection's `HasMember`, a device's `HasPrimaryUser`, a computer's `MemberOf`, against the lab.
- **Resolved 2026-06-23 (grilled with the user; implementation plan
  [`../plans/2026-06-23-sccm-preproc-convert-stage2.md`](../plans/2026-06-23-sccm-preproc-convert-stage2.md), gtk `ope-2ff3`):**
  - **Scope:** `SCCM_HasNetworkAccessAccount` is **deferred** (its NAA-secret collector is unbuilt — the spec's
    Stage-2 listing of `:4185` is dropped from this stage). `HasSession` is built from **both** the RemoteRegistry
    logged-on user (`:5029`) **and** the MSSQL service account on the site DB server
    (`adminservice_site_systems.sql_server_service_logon_account`, `:8007`) — gated to *domain* accounts.
  - **Node ids:** `SCCM_ClientDevice` = `smsid` (no site suffix); the other three = `<id>@root_site_code` minted final.
  - **Possible-client (`:3272`) moves INTO Stage 2** (was implicitly Stage 6 via `--disable-possible-edges`): emitted
    with the **deterministic** id `upper(object_sid)@root_site_code` (same `@root_site_code` convention as the other
    SCCM-native nodes; distinct from the Computer node's raw-SID id and from real client GUIDs), gated by
    `--disable-possible-edges` *and* on `root_site_code` being present (no root → skip, else the id would collapse to
    the bare SID and collide with the Computer node). `ad_domain_sid` carries the raw SID for Stage 4 SameHostAs, so
    the duplicate-vs-real-client merge (Stage 4) is unaffected by the id format.
  - **Nested groups deferred to the SharpHound merge (evidence-based):** group→group nesting is not in any collected
    SCCM table (`adminservice_user_group` has no membership column; `security_group_name` on r_system/r_user is
    direct-only — verified against the lab, e.g. it omits `BUILTIN\Administrators` for Domain Admins). `MemberOf`
    stays `principal → group`; group→group `MemberOf` is supplied by a merged SharpHound collection on the same
    SID-keyed `Group` nodes (`environmentid` = domain SID). Documented as a README assumption + Limitation. CMBP
    never built group nesting either.
  - **`--disable-possible-edges` plumbing (new mechanism, reused by Stage 6):** `collect` persists a one-row
    `collection_settings` table (`disable_possible_edges`, `enable_bad_opsec`); `preproc` reads it and skips the
    possible rows. The flag was previously a dead collect-time placeholder ([source.py:234](../../src/openhound_sccm/source.py#L234)).
  - **Traversable allow-list implemented here** (it was parked in Stage 0 but Stage 0 was plumbing-only): a
    `TRAVERSABLE_EDGE_KINDS` constant transcribed from CMBP `:2216-2249` drives `EdgeProperties.traversable`. This
    retroactively fixes Stage 1's `SCCM_AdminsReplicatedTo` (currently emitted `traversable=False`).
  - **Graph integrity (refines Decision #2's drop-on-failure):** an edge endpoint that *resolves* to an id but has
    no `node_*` row gets a **synthesised bare node** (id + kind inferred from the edge position; ambiguous →
    `Base`) plus a logged warning, rather than a dropped edge. Name→SID *resolution* failures still drop+log.
  - **One collect change beyond settings:** stamp the host computer SID onto the `remoteregistry_users` current-user
    row so `HasSession` has a start endpoint ([registry.py:471-483](../../src/openhound_sccm/collectors/registry.py#L471-L483)).

### Stage 3 — Containment + RBAC fan-out **+ full node/edge property parity**
- **PS1:** `SCCM_Contains` :1659-1690; role fan-out + role-kind mapping :1714-1827; `SCCM_AllPermissions`
  :1730-1837; `SCCM_AssignAllPermissions` (SMS Provider) :1932-1940. Node-property sources: every
  `Upsert-Node` call per kind (Collection :7532/7605; SecurityRole :7700; AdminUser :7771; ClientDevice
  :7220; base AD nodes enriched at 45+ sites via `-PSObject`).
- **Do (the 10 edges):** four edge builders appended to `graph_edges` —
  - `_edge_contains` — non-secondary sites × {collections, roles, admin users} (all `@root`).
  - `_edge_rbac_role_grants` — the 7 role edges (AdminUser→ClientDevice), reconstructed by joining the
    Stage-2 `graph_edges` rows: `SCCM_IsAssigned`(admin→role) ⋈ `SCCM_IsAssigned`(admin→Device-type
    collection) ⋈ `SCCM_HasMember`(collection→ClientDevice), with a fixed role-id→edge-kind map
    (`SMS0001R`→FullAdministrator, `SMS0008R`→ApplicationAuthor, `SMS0009R`→ApplicationAdministrator,
    `SMS0006R`→ComplianceSettingsManager, `SMS000AR`→OSDManager, `SMS000ER`→OperationsAdministrator,
    `SMS000FR`→SecurityAdministrator). Logs a count of skipped custom roles.
  - `_edge_all_permissions` — Full Administrator (`SMS0001R`) **and** assigned both `SMS00001` (All
    Systems) **and** `SMS00004` (All Users and User Groups) → every non-secondary site.
  - `_edge_assign_all_permissions` — Computer whose `site_system_roles` contains `%SMS Provider%` →
    every non-secondary site.
- **Validate:** the 7 role edges + AllPermissions + AssignAllPermissions appear; pick a Full
  Administrator and confirm `SCCM_FullAdministrator` reaches the expected devices; every edge carries a
  non-empty `collection_source`; entity panels show the ported node properties.

**Resolved 2026-06-24 (grilled with the user; gtk `ope-1950`; implementation plan
[`../plans/2026-06-24-sccm-preproc-convert-stage3.md`](../plans/2026-06-24-sccm-preproc-convert-stage3.md)):**
Stage 3 expanded well beyond the original "10 edges" into a **node/edge property-parity pass** so
BloodHound entity panels are fully populated. Three workstreams under one stage:

- **WS-1 — Edge-property infrastructure (cross-cutting, retrofits Stage 1/2 edges):** re-introduce a
  **typed `collection_source VARCHAR[]`** column on `graph_edges` (Stage 2's Task-C0 note had dropped the
  free-form `properties JSON` column because DuckDB returns JSON as a *string*; a typed array column
  avoids that bug). Every existing edge builder is tagged with its CMBP `collectionSource`; `_graph_edges_dedup`
  changes from `SELECT DISTINCT` to `GROUP BY start_id,end_id,kind` with
  `list_distinct(flatten(list(collection_source)))`; `GraphEdge` emits it via the existing
  `SCCMEdgeProperties.collection_source` (already supported — only the table had stopped carrying it).
  Future richer edge props (e.g. Stage 6 EPA status) get their own typed columns.
- **WS-2 — The 10 Stage-3 edges** (above). `TRAVERSABLE_EDGE_KINDS` is already correct (only
  `SCCM_FullAdministrator` + `SCCM_ApplicationAdministrator` traversable among the 7 role edges, per
  CMBP :2216-2249); ~10 new kind constants added to `kinds/edges.py`.
- **WS-3 — Node property parity (the bulk):** port **every** CMBP node property — including ones a
  traversable edge already encodes — for the **8 node kinds that exist today** (Computer, User, Group,
  Site, Collection, SecurityRole, AdminUser, ClientDevice). `MSSQL_*` parity is **deferred to Stage 5**
  (those node tables don't exist until then; Stage 5 builds them with full parity from birth — no
  retrofit). The plan's **first task is a systematic CMBP→port property matrix** (one pass over all
  `Upsert-Node` calls per kind) producing the authoritative gap checklist. Relationship-list properties
  (`collection.members`, `role.members`, `admin.collection_ids/member_of/role_ids`,
  `site.admin_users/site_system_roles`, `clientdevice.collection_ids/collection_names`) are built **in the
  preproc node coalesces from the raw source tables** and kept **raw/faithful to CMBP** — unresolved
  resource keys and built-in pseudo-resources **included** (e.g. `collection.members` = the literal
  `ResourceID@SiteCode` list). **No edge→node aggregation** — `graph_edges` stays the resolved/traversable
  representation; the node panels carry CMBP's raw lists. Scalars/timestamps/audit fields and resolved
  `*_sid` fields (via `principal_by_name`) fill the remaining gaps.

**Locked decisions (1–6):** (1) RBAC fan-out reconstructed from `graph_edges`, not raw tables.
(2) `SCCM_AllPermissions` "All Systems"/"All Users and User Groups" detected by well-known IDs
`SMS00001`/`SMS00004` (a code comment cites CMBP's name-match; the validation harness confirms the IDs
against the lab). (3) Port all CMBP node/edge properties for the panels, even relationship-encoding ones.
(4) Typed `collection_source` column (WS-1). (5) Full parity for all node kinds (MSSQL via Stage 5).
(6) Relationship lists built in preproc from raw tables, raw/faithful, no edge→node aggregation.

**Non-secondary site set:** the single hierarchy = all `site_hierarchy` rows; "non-secondary" excludes
only confirmed Secondary (`site_type = 1`), matching CMBP's `Type -ne "Secondary Site"` (NULL/unknown
types are included). **ARCHITECTURE.md §11c** (graph_edges columns + `GraphEdge`) is updated in the same
change as the WS-1 code.

### Stage 4 — SameHostAs + LocalAdminRequired
- **PS1:** `Add-SameHostAsEdges` :2261-2311 (incl. duplicate-client-device merge preferring the
  `GUID:`-authoritative node); `LocalAdminRequired` mesh :1882-1909.
- **Do:** derived `same_host` (+ device-dedup logic) and `local_admin_required`; append to `graph_edges`.
- **Validate:** `SameHostAs` links each ClientDevice to its Computer by `ADDomainSID`; duplicate client
  devices merged; site-server `LocalAdminRequired` mesh present.

### Stage 5 — MSSQL (active)
- **PS1:** `Add-MSSQLServerNodesAndEdges` :6050-6186; `Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer`
  :6187-6292; `MSSQL_GetTGS` :1965-1978; `ServiceAccountFor`/`GetAdminTGS` :8012-8016;
  `AssignAllPermissions` (db→site) :6173-6180. **Skip** :6293.
- **Do:** `node_mssql_*` tables + the MSSQL edges; prefer the collected SQL port over `:1433`.
- **Validate:** MSSQL_Server/Database/ServerRole/DatabaseRole/Login/DatabaseUser nodes + their edges;
  confirm a sysadmin computer's `MSSQL_*` chain and `MSSQL_AssignAllPermissions` to the site.

### Stage 6 — Coerce-and-relay (possible edges)
- **PS1:** `Process-CoerceAndRelayToAdminService` :6572-6623; `…ToMSSQL` :6626-6724; `…ToSMB`
  :6728-6779; synthetic Authenticated Users node :6609/6708/6766.
- **Do:** `relay_candidates_{adminservice,mssql,smb}` with EPA/SMB-signing/NTLM gating, the
  possible-edge default, and `--disable-possible-edges`; emit Authenticated Users group node; EPA
  labeled per the uncertainty convention.
- **Validate:** with possible edges on, the three relay edges appear from Authenticated Users; with
  `--disable-possible-edges`, they don't; EPA labels read correctly.

### Stage 7 — Docs + validation
- **Do:** rewrite README (Node Reference, Edge Reference, preproc/convert, mayyhem.com examples,
  diagrams/tables); run `references/validate-extension.md` checks (ruff/mypy/pytest in an isolated uv
  env); remove dead refs.
- **Validate:** all checks pass or are reported-skipped; README matches emitted nodes/edges exactly.

---

## 7. Bug-fix register

| CMBP quirk | Location | Port handling |
|---|---|---|
| `@siteCode`→`@rootSiteCode` ID rewrite, lockstep edge mutation, regex misfire | :2397-2504 | Compute `rootSiteCode` first in preproc; mint final IDs once. Rewrite eliminated. |
| O(n²)/O(n³) `Upsert`/RBAC scans | :1477, :1714-1827 | Set-based SQL (`GROUP BY`/joins) in preproc. |
| Edges dropped when endpoint node not yet created | :2118-2127 | preproc materializes all nodes before convert emits edges; ordering is structural. |
| `collectionSource` vs `CollectionSource` casing | :9072/4696 | Normalize to one key during coalescing. |
| Hardcoded `:1433` | :6055/7997 | Use collected SQL port where available; fall back to 1433 only if unknown. |
| EPA/SMB-signing default-to-vulnerable assumptions | :6675-6681 etc. | Preserve intent; label inferred/possible per EPA-uncertainty convention; gate with `--disable-possible-edges`. |
| `SMS_R_System` keeps obsolete duplicate records per machine | r_system collection | Filter `Obsolete` in the coalesce so a stale row can't shadow the live one (§4). |
| `bytes_to_sid` had a dead str branch + a misleading "base64/hex decode" comment | [ad.py:233](../../../src/openhound_sccm/clients/ad.py#L233) | **Fixed 2026-06-16:** the two identical `return value` branches collapsed into one honest pass-through; false comment removed. Behavior-preserving — both call sites pass bytes. |
| Dead WMI graph-emit / Host node / role-assignment dup | :8210-8600 / :2373 / :1986 | Not ported (§2 exclusions). |

---

## 8. Relationship to the convert-read-from-DuckDB proposal

Convert2-Read-DB is the **userland form** of the OpenHound proposal
([docs/proposals/2026-06-16-convert-read-from-duckdb.md](../../proposals/2026-06-16-convert-read-from-duckdb.md)):
it reads coalesced DuckDB tables at convert time **without a core change**, by running our own pipeline.
If the proposal is accepted (the framework's own convert reader gains a DuckDB mode), the manual Convert2-Read-DB
pipeline collapses into a normal convert source whose resources point at the DuckDB tables — the models
are unchanged and the explicit pipeline is deleted. Not a blocker either way; the design lives entirely
within `sccm/sccm`. The *writeback* fallback (§2 alternatives) remains the escape hatch if the manual
pipeline proves unworkable in practice.
