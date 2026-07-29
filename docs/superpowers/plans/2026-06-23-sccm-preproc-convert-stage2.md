# SCCM preproc + convert — Stage 2 (SCCM entities + inline edges) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the four SCCM-native entity nodes (`SCCM_ClientDevice`, `SCCM_Collection`, `SCCM_AdminUser`, `SCCM_SecurityRole`) and the ~9 inline edges that connect them and the Stage 1 base nodes (`SCCM_IsMappedTo`, `SCCM_IsAssigned`, `SCCM_HasMember`, `SCCM_HasClient`, `SCCM_HasPrimaryUser`/`HasCurrentUser`/`HasADLastLogonUser`, `SCCM_HasStoredAccount`, `MemberOf`, `HasSession`) — all through the existing Convert2-Read-DB pipeline.

**Architecture:** `preproc` (`transforms.py`) gains four `node_*` coalesces, four name/id lookups (`resource_to_sid`, `device_by_resourceid`, `collection_by_name`, `role_by_name`), an enriched `principal_by_name`, and many more `kind`-tagged rows UNIONed into the single `graph_edges` table. `convert` is unchanged in shape — the generic edge model (renamed `GraphEdge`) emits every `graph_edges` row regardless of kind, and four trivial node models join `NODE_SPECS`. Two small collect-side additions (a host-SID on the RemoteRegistry current-user row; a one-row `collection_settings` table) ride the re-collect. `--disable-possible-edges` is persisted at collect and applied in preproc. A final `node_backfill` pass synthesises bare nodes for any edge endpoint missing a node. No OpenHound core changes.

**Tech Stack:** Python 3.13+, `dlt`, `duckdb`, `openhound` (v0.2.x), `pytest`, `uv`.

**Tracking:** gtk `ope-2ff3`. **Baseline:** the `ope-a88e` working tree (Stage 1 hardening) is assumed present. **Re-collect:** Phase A adds two collect-side changes; there is exactly **one** user-run re-collect against the lab before real-data validation (Phase F), folding in ope-a88e's `*_user_group` work too.

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Never edit OpenHound core (`openhound/...`). (CLAUDE.md)
- **Do NOT `git commit`.** Each task ends at a **checkpoint** = `git add` (stage only); the user commits after testing. (CLAUDE.md)
- **Validate in the isolated uv env** (already synced from Stage 0/1):
  `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest <abs test path> -v`.
  Do not use/modify the repo `.venv`. (AGENTS.md)
- **Log every `if`/`else` and `try`/`except` branch** at an appropriate level, or leave a comment. (CLAUDE.md)
- **Node/edge property keys are lowercase, `_`-separated** (e.g. `sccm_collection_id`, `collection_source`). Never emit PascalCase/camelCase. (Stage 1 constraint, unchanged.)
- **Simplicity/YAGNI** — coalescing and edge derivation are set-based SQL; models stay trivial `row → node` / `row → edge`. No per-row Python fan-out.
- Tests live next to code as `<module>_test.py`.

### Locked Stage 2 decisions (grilled with the user 2026-06-23)
1. **Edge scope:** `SCCM_HasNetworkAccessAccount` is **deferred** (its NAA-secret collector is unbuilt). `HasSession` is built from **both** the RemoteRegistry logged-on user **and** the MSSQL service account on the site DB server (`adminservice_site_systems.sql_server_service_logon_account`, only when it is a *domain* account).
2. **Collect change:** stamp the host computer SID onto the `remoteregistry_users` current-user row so `HasSession` (Computer→User) has a start endpoint.
3. **Node ids:** `SCCM_ClientDevice` = `smsid` (no site suffix); `SCCM_Collection`/`SCCM_SecurityRole`/`SCCM_AdminUser` = `<collection_id|role_id|logon_name>@<root_site_code>` minted final (no `@siteCode`→`@rootSiteCode` rewrite).
4. **Possible-client:** emit in Stage 2 with a **deterministic** id `upper(object_sid)@root_site_code` (same `@root_site_code` convention as the other SCCM-native nodes; distinct from the Computer node's raw-SID id and from real client GUIDs), gated by `--disable-possible-edges` and on `root_site_code` being present.
5. **Gate plumbing:** collect writes a one-row `collection_settings` table (`disable_possible_edges`, `enable_bad_opsec`); preproc reads it and skips the possible rows when disabled. Stage 6 reuses this.
6. **Graph integrity:** for any edge endpoint id that has no node, synthesise a **bare** node keyed by that id with a **kind inferred from the edge's position**, and **log a warning**. The only ambiguous case (`SCCM_HasStoredAccount` end = User *or* Group) gets `Base` only.

### Node identity & `environmentid` (extends the Stage 1 rules)
- **SCCM-native nodes** (`SCCM_ClientDevice`, `SCCM_Collection`, `SCCM_AdminUser`, `SCCM_SecurityRole`): `environmentid` = the hierarchy **`root_site_code`** (spec §2). There is one root per graph (single-hierarchy assumption).
- **ids:** ClientDevice = `upper(smsid)`; Collection = `upper(collection_id) || '@' || root`; SecurityRole = `upper(role_id) || '@' || root`; AdminUser = `upper(logon_name) || '@' || root`.
- `root` is the single value `SELECT any_value(root_site_code) FROM {schema}.site_hierarchy` (built by Stage 1 `_site_hierarchy`).

### Source column reference (exact snake_case names as they land in DuckDB)
From `collectors/sms_rows.py` column tuples + the `_snake()` transform (acronym-aware). Use these EXACT names in coalesce SQL.

| Table | Columns used in Stage 2 |
|---|---|
| `adminservice_client_devices` / `wmi_client_devices` (`DEVICE_COLUMNS`) | `smsid`, `resource_id`, `site_code`, `name`, `is_client`, `is_obsolete`, `primary_user`, `current_logon_user`, `user_name`, `user_domain_name`, `device_os`, `device_os_build`, `is_virtual_machine`, `co_managed`, `aad_device_id`, `aad_tenant_id`, `last_mp_server_name`, `ad_last_logon_time`, `source_site_code` |
| `adminservice_collections` / `wmi_collections` (`COLLECTION_COLUMNS`) | `collection_id`, `name`, `collection_type`, `member_count`, `comment`, `is_built_in`, `last_change_time`, `last_member_change_time`, `limit_to_collection_id`, `limit_to_collection_name`, `collection_variables_count`, `source_site_code` |
| `adminservice_collection_members` / `wmi_collection_members` (`COLLECTION_MEMBER_COLUMNS`) | `collection_id`, `resource_id`, `site_code` |
| `adminservice_security_roles` / `wmi_security_roles` (`ROLE_COLUMNS`) | `role_id`, `role_name`, `role_description`, `is_built_in`, `is_sec_admin_role`, `copied_from_id`, `number_of_admins`, `operations`, `created_by`, `created_date`, `last_modified_by`, `last_modified_date`, `source_site` |
| `adminservice_admins` / `wmi_admins` (`ADMIN_COLUMNS`) | `admin_id`, `admin_sid`, `logon_name`, `display_name`, `distinguished_name`, `is_group`, `account_type`, `category_names`, `collection_names`, `role_names`, `roles`, `created_by`, `created_date`, `last_modified_by`, `last_modified_date`, `source_site` |
| `adminservice_site_systems` / `wmi_site_systems` (`SYSRES_COLUMNS` + extra) | `network_os_path`, `site_code`, `role_name`, `type`, `sql_server_service_logon_account` |
| `adminservice_r_system` / `wmi_r_system` (`RSYSTEM_COLUMNS`) | `sid`, `resource_id`, `source_site_code`, `name`, `obsolete`, `security_group_name`, `system_roles` |
| `adminservice_r_user` / `wmi_r_user` (`RUSER_COLUMNS`) | `sid`, `resource_id`, `source_site_code`, `name`, `security_group_name`, `unique_user_name`, `full_user_name`, `user_principal_name`, `distinguished_name` |
| `adminservice_user_group` / `wmi_user_group` (`USERGROUP_COLUMNS`) | `resource_id`, `sid`, `unique_usergroup_name`, `usergroup_name` |
| `remoteregistry_users` | `object_sid` (the logged-on user), **`host_object_sid`** (added in Task A1) |

---

## File Structure

| File | Responsibility |
|---|---|
| `src/openhound_sccm/collectors/registry.py` | **modify** (A1) — add `host_object_sid` to the current-user row. |
| `src/openhound_sccm/collectors/local.py` (or `source.py`) | **modify** (A2) — emit the one-row `collection_settings` resource. |
| `src/openhound_sccm/context.py` | **modify** (A2) — carry `disable_possible_edges` / `enable_bad_opsec` on `SourceContext` so the settings resource can read them. |
| `src/openhound_sccm/kinds/edges.py` | **modify** (C0+) — add all Stage 2 edge-kind constants + `TRAVERSABLE_EDGE_KINDS`. |
| `src/openhound_sccm/graph.py` | **modify** — add `SCCMEdgeProperties`, `SCCMClientDeviceProperties`, `SCCMCollectionProperties`, `SCCMAdminUserProperties`, `SCCMSecurityRoleProperties`, and `KIND_ENV_RULE` helper for backfill. |
| `src/openhound_sccm/models/graph_edge.py` | **rename** from `replication_edge.py` — generic `GraphEdge` (reads `start_id,end_id,kind,properties`; sets `traversable`). |
| `src/openhound_sccm/models/sccm_client_device.py` / `sccm_collection.py` / `sccm_admin_user.py` / `sccm_security_role.py` / `stub_node.py` | **create** — one model each. |
| `src/openhound_sccm/transforms.py` | **modify** — enrich `principal_by_name`; add four `node_*` coalesces, four lookups, all edge builders, settings gating, and `node_backfill`. |
| `src/openhound_sccm/main.py` | **modify** — grow `NODE_SPECS`; rename the edge model in `EDGE_SPECS`; add `collection_settings` to `_preproc_table_map()`. |
| `README.md` / `ARCHITECTURE.md` | **modify** (F) — Node/Edge Reference; collect-change + gating + traversable + backfill divergences. |
| `docs/superpowers/plans/2026-06-23-sccm-preproc-convert-stage2-validation.md` | **create** (F) — code-tour harness. |
| `*_test.py` next to each module | **create** — per-task tests. |

**Convert registry pattern (unchanged from Stage 1):** `main.py` owns `NODE_SPECS: list[(table, ModelClass)]` and `EDGE_SPECS`. `emit_graph_from_duckdb` instantiates `model(**row)`, injects `_lookup`, emits `asdict(as_node)` / `[asdict(e) for e in edges]`. Stage 2 grows `NODE_SPECS` by five (`node_collection`, `node_security_role`, `node_admin_user`, `node_client_device`, `node_backfill`); `EDGE_SPECS` stays `[("graph_edges", GraphEdge)]`.

---

# Phase A — Collect-side changes (ride the re-collect)

## Task A1: Stamp host SID onto the RemoteRegistry current-user row

**Why:** `HasSession` (Computer→User) needs the host computer SID; today the `remoteregistry_users` current-user row carries only the *user's* SID. See [registry.py:471-483](../../src/openhound_sccm/collectors/registry.py#L471-L483).

**Files:** Modify `src/openhound_sccm/collectors/registry.py`; create `src/openhound_sccm/collectors/registry_current_user_test.py`.

**Interfaces — Produces:** `remoteregistry_users` rows gain `host_object_sid: str | None` (the probed host's AD computer SID).

- [ ] **Step 1: Write the failing test** — drive `get_current_user` with a fake probe + ctx and assert the yielded row carries both the user SID and the host SID.

```python
# src/openhound_sccm/collectors/registry_current_user_test.py
import types
from openhound_sccm.collectors import registry


class _FakeProbe:
    hostname = "host1.lab"
    def read_values(self, _key):
        return [("UserSID", "S-1-5-21-1-2-3-1106"), ("Session", 1)]


def _fake_ctx():
    host_obj = {"name": "HOST1", "object_sid": "S-1-5-21-1-2-3-1104"}
    user_obj = {"sam_account_name": "alice", "object_sid": "S-1-5-21-1-2-3-1106"}
    ctx = types.SimpleNamespace()
    ctx.resolve_principal = lambda sid: dict(user_obj)
    ctx.target_hosts_by_hostname = {"host1.lab": types.SimpleNamespace(ad_object=host_obj)}
    return ctx


def test_current_user_row_has_host_object_sid():
    rows = list(registry.get_current_user(_FakeProbe(), _fake_ctx()))
    assert len(rows) == 1
    table, row = rows[0]
    assert table == "remoteregistry_users"
    assert row["object_sid"] == "S-1-5-21-1-2-3-1106"        # the logged-on user
    assert row["host_object_sid"] == "S-1-5-21-1-2-3-1104"   # the host it logged onto
```

- [ ] **Step 2: Run — expect failure** (`KeyError: 'host_object_sid'`).
Run: `… pytest …/collectors/registry_current_user_test.py -v`

- [ ] **Step 3: Implement** — in `get_current_user`, look up the host entry and add `host_object_sid` to the row (mirroring `get_ntlm_settings`/`get_mssql_settings`):

```python
        if current_user_ad_object:
            logger.info("Found current user: %s (%s)", current_user_ad_object.get("sam_account_name"), current_user_sid)
            target_entry = ctx.target_hosts_by_hostname.get(probe.hostname)
            host_sid = target_entry.ad_object.get("object_sid") if (target_entry and target_entry.ad_object) else None
            if host_sid is None:
                # No resolved host AD object — HasSession can't be built for this row downstream; keep the row but log.
                logger.warning("Current-user row for %s has no host object_sid; HasSession will be dropped downstream", probe.hostname)
            row = {
                **(current_user_ad_object or {}),
                "source": "RemoteRegistry-CurrentUser",
                "host_object_sid": host_sid,
            }
            row.setdefault("object_sid", current_user_sid)
            yield "remoteregistry_users", row
```

- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Checkpoint** — `git add src/openhound_sccm/collectors/registry.py src/openhound_sccm/collectors/registry_current_user_test.py`.

---

## Task A2: Persist `--disable-possible-edges` / `--enable-bad-opsec` as a `collection_settings` table

**Why:** the flags are collect-time source params but the graph is built in preproc/convert (separate runs). Persist them once so preproc can gate possible rows (Decision #5). Today `disable_possible_edges` is read in [source.py:234](../../src/openhound_sccm/source.py#L234) and used nowhere.

**Files:** Modify `src/openhound_sccm/context.py` (carry the flags), `src/openhound_sccm/source.py` (set them on ctx), `src/openhound_sccm/collectors/local.py` (emit the resource), `src/openhound_sccm/main.py` (add table to `_preproc_table_map`); create `src/openhound_sccm/collectors/collection_settings_test.py`.

**Interfaces — Produces:** a one-row table `collection_settings(disable_possible_edges BOOLEAN, enable_bad_opsec BOOLEAN)` under `sccm/collection_settings`.

- [ ] **Step 1: Write the failing test** — the resource yields exactly one row carrying both flags from ctx.

```python
# src/openhound_sccm/collectors/collection_settings_test.py
import types
from openhound_sccm.collectors.local import collection_settings_rows


def test_collection_settings_single_row():
    ctx = types.SimpleNamespace(disable_possible_edges=True, enable_bad_opsec=False)
    rows = list(collection_settings_rows(ctx))
    assert rows == [{"disable_possible_edges": True, "enable_bad_opsec": False}]
```

- [ ] **Step 2: Run — expect failure** (`ImportError`).

- [ ] **Step 3a: Carry the flags on `SourceContext`** — add two fields to the `SourceContext` dataclass in `context.py`:

```python
    disable_possible_edges: bool = False
    enable_bad_opsec: bool = False
```

- [ ] **Step 3b: Set them in `source.py`** — where `SourceContext(...)` is constructed (after the flags are normalised at [source.py:234-235](../../src/openhound_sccm/source.py#L234-L235)), pass `disable_possible_edges=disable_possible_edges, enable_bad_opsec=enable_bad_opsec`.

- [ ] **Step 3c: Emit the resource** — add to `collectors/local.py` a pure helper + an `@app.resource`. The helper is what the test calls; the resource wraps it so it runs once (not per-host):

```python
def collection_settings_rows(ctx):
    """One row capturing the collect-time behaviour flags, so preproc/convert can
    gate possible nodes/edges without re-reading the CLI (the flags are collect-time)."""
    yield {
        "disable_possible_edges": bool(getattr(ctx, "disable_possible_edges", False)),
        "enable_bad_opsec": bool(getattr(ctx, "enable_bad_opsec", False)),
    }


@app.resource(name="collection_settings", parallelized=False, columns=raw_table_asset("collection_settings"))
def collection_settings(ctx: SourceContext = None):
    # ctx is injected the same way sibling local resources receive it; emit exactly one row.
    yield from collection_settings_rows(ctx)
```
> Match the EXACT ctx-injection signature the other `local.py` `@app.resource` functions use (e.g. `local_wmi_sms_authority`). If they receive ctx differently, mirror that; the test only exercises `collection_settings_rows`.

- [ ] **Step 3d: Register in `_preproc_table_map()`** — add `"collection_settings"` to the local-discovery group in `main.py`.

- [ ] **Step 4: Run — expect PASS.** Also `python -c "import openhound_sccm.source"` to confirm the resource registers.
- [ ] **Step 5: Checkpoint** — `git add` the four changed files + the test.

> After Phase A lands, the **user runs one re-collect** against the lab. All later phases are validated with synthetic seeds (TDD) until Phase F, which uses the re-collected tree.

---

# Phase B — SCCM entity nodes

Each coalesce follows the established Stage 1 pattern: a typed staging table, `_ensure_columns` for optional source columns, per-source `INSERT … BY NAME` via `_safe`, then a `GROUP BY` collapse. Helpers `_safe`, `_ensure_columns`, `_arr` already exist in `transforms.py`. Add a module-level helper `_root_code(con, schema)` once (used by B1–B3):

```python
def _root_code(con: duckdb.DuckDBPyConnection, schema: str) -> str | None:
    """The single hierarchy root_site_code (built by _site_hierarchy). Used to mint
    SCCM-native ids final (Decision #3). None if no site data was collected."""
    try:
        row = con.execute(f"SELECT any_value(root_site_code) FROM {schema}.site_hierarchy").fetchone()
        return row[0] if row else None
    except duckdb.CatalogException:
        logger.warning("_root_code: site_hierarchy missing; SCCM-native ids will lack a root scope")
        return None
```

## Task B1: `node_collection` + `SCCMCollection` model

**Files:** Modify `transforms.py`, `graph.py`, `main.py`; create `models/sccm_collection.py`, `models/sccm_collection_test.py`, `node_collection_test.py`.

**Interfaces — Produces:** `node_collection(collection_id, name, collection_type, member_count, comment, is_built_in, limit_to_collection_id, limit_to_collection_name, collection_variables_count, root_site_code)` — one row per `upper(collection_id)`. `SCCMCollection(BaseAsset).as_node -> SCCMNode | None` (id = `collection_id@root`).

- [ ] **Step 1: Failing tests**

```python
# src/openhound_sccm/node_collection_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_collection_one_row_per_id_with_root():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4), ('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT "
                "'PS100016' AS collection_id, 'All Systems' AS name, 2 AS collection_type, "
                "42 AS member_count, false AS is_built_in, 'PS1' AS source_site_code")
    transforms(con)
    rows = con.execute("SELECT collection_id, name, member_count, root_site_code FROM sccm.node_collection").fetchall()
    assert rows == [("PS100016", "All Systems", 42, "CAS")]
```
```python
# src/openhound_sccm/models/sccm_collection_test.py
from openhound_sccm.models.sccm_collection import SCCMCollection

def test_collection_as_node():
    n = SCCMCollection(collection_id="PS100016", name="All Systems", collection_type=2,
                       member_count=42, root_site_code="CAS").as_node
    assert n.id == "PS100016@CAS"
    assert n.kinds == ["SCCM_Collection"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.sccm_collection_id == "PS100016"

def test_collection_no_id_returns_none():
    assert SCCMCollection(collection_id=None, root_site_code="CAS").as_node is None
```

- [ ] **Step 2: Run — expect failure.**

- [ ] **Step 3a: `_node_collection`** in `transforms.py` (UNION adminservice + wmi; collapse on `upper(collection_id)`; LEFT JOIN nothing — stamp root via cross join to `_root_code`):

```python
def _node_collection(con, schema):
    """One row per collection_id, coalesced from adminservice/wmi collections."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection ("
        "collection_id VARCHAR, name VARCHAR, collection_type INTEGER, member_count BIGINT, "
        "comment VARCHAR, is_built_in BOOLEAN, limit_to_collection_id VARCHAR, "
        "limit_to_collection_name VARCHAR, collection_variables_count BIGINT)"
    )
    _optional = {"name": "VARCHAR", "collection_type": "INTEGER", "member_count": "BIGINT",
                 "comment": "VARCHAR", "is_built_in": "BOOLEAN", "limit_to_collection_id": "VARCHAR",
                 "limit_to_collection_name": "VARCHAR", "collection_variables_count": "BIGINT"}
    for _src in ("adminservice_collections", "wmi_collections"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_collection<-{_src}",
              f"INSERT INTO {schema}.node_collection BY NAME "
              f"SELECT upper(collection_id) AS collection_id, name, "
              f"TRY_CAST(collection_type AS INTEGER) AS collection_type, "
              f"TRY_CAST(member_count AS BIGINT) AS member_count, comment, "
              f"is_built_in, limit_to_collection_id, limit_to_collection_name, "
              f"TRY_CAST(collection_variables_count AS BIGINT) AS collection_variables_count "
              f"FROM {schema}.{_src} WHERE collection_id IS NOT NULL")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection AS SELECT collection_id, "
        f"any_value(name) AS name, max(collection_type) AS collection_type, "
        f"max(member_count) AS member_count, any_value(comment) AS comment, "
        f"bool_or(is_built_in) AS is_built_in, any_value(limit_to_collection_id) AS limit_to_collection_id, "
        f"any_value(limit_to_collection_name) AS limit_to_collection_name, "
        f"max(collection_variables_count) AS collection_variables_count, ? AS root_site_code "
        f"FROM {schema}.node_collection GROUP BY collection_id", [root])
    logger.info("node_collection built in schema %r", schema)
```
Add `_node_collection(con, schema)` to `transforms()` (after `_node_site`, before `_graph_edges`).

- [ ] **Step 3b: `SCCMCollectionProperties`** in `graph.py`:

```python
@dataclass
class SCCMCollectionProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_collection_id: str | None = field(default=None, kw_only=True)
    sccm_collection_type: str | None = field(default=None, kw_only=True)   # "Device"/"User"
    member_count: int | None = field(default=None, kw_only=True)
    comment: str | None = field(default=None, kw_only=True)
    is_built_in: bool | None = field(default=None, kw_only=True)
    limit_to_collection_id: str | None = field(default=None, kw_only=True)
    limit_to_collection_name: str | None = field(default=None, kw_only=True)
    collection_variables_count: int | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)
```

- [ ] **Step 3c: `models/sccm_collection.py`** (collection_type 0=Device, 1=User per SCCM):

```python
# src/openhound_sccm/models/sccm_collection.py
import logging
from openhound.core.asset import BaseAsset
from pydantic import ConfigDict
from ..graph import SCCMNode, SCCMCollectionProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)
# CMBP ConfigManBearPig.ps1:1741 is the source of truth: 0 = Other, 1 = User, 2 = Device.
_COLLECTION_TYPE = {0: "Other", 1: "User", 2: "Device"}


class SCCMCollection(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    collection_id: str | None = None
    name: str | None = None
    collection_type: int | None = None
    member_count: int | None = None
    comment: str | None = None
    is_built_in: bool | None = None
    limit_to_collection_id: str | None = None
    limit_to_collection_name: str | None = None
    collection_variables_count: int | None = None
    root_site_code: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        cid = (self.collection_id or "").upper() or None
        if not cid:
            logger.warning("SCCMCollection: dropping row with no collection_id")
            return None
        root = self.root_site_code or ""
        node_id = f"{cid}@{root}" if root else cid
        display = f"{self.name}@{root}" if (self.name and root) else (self.name or node_id)
        return SCCMNode(
            id=node_id, kinds=[nk.SCCM_COLLECTION],
            properties=SCCMCollectionProperties(
                name=self.name or node_id, displayname=display, environmentid=root or cid,
                sccm_collection_id=cid,
                sccm_collection_type=_COLLECTION_TYPE.get(self.collection_type),
                member_count=self.member_count, comment=self.comment, is_built_in=self.is_built_in,
                limit_to_collection_id=self.limit_to_collection_id,
                limit_to_collection_name=self.limit_to_collection_name,
                collection_variables_count=self.collection_variables_count,
                root_site_code=self.root_site_code,
            ),
        )

    @property
    def edges(self):
        return iter(())
```

- [ ] **Step 3d:** add `("node_collection", SCCMCollection)` to `NODE_SPECS`; re-export `SCCMCollection` from `models/__init__.py`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task B2: `node_security_role` + `SCCMSecurityRole` model

**Files:** Modify `transforms.py`, `graph.py`, `main.py`; create `models/sccm_security_role.py`, `models/sccm_security_role_test.py`, `node_security_role_test.py`.

**Interfaces — Produces:** `node_security_role(role_id, role_name, role_description, is_built_in, is_sec_admin_role, copied_from_id, number_of_admins, operations, root_site_code)` — one row per `upper(role_id)`. id = `role_id@root`.

- [ ] **Step 1: Failing tests** — mirror B1: seed `adminservice_security_roles` (`role_id='SMS000AR'`, `role_name='Full Administrator'`, `is_built_in=true`) + a CAS/PS1 hierarchy; assert one `node_security_role` row with `root_site_code='CAS'`; assert `SCCMSecurityRole(...).as_node` id=`SMS000AR@CAS`, kinds `["SCCM_SecurityRole"]`, `environmentid='CAS'`, `sccm_role_name='Full Administrator'`.

```python
# src/openhound_sccm/node_security_role_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_security_role_one_row_per_id():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS000AR' AS role_id, "
                "'Full Administrator' AS role_name, 'desc' AS role_description, true AS is_built_in, "
                "false AS is_sec_admin_role")
    transforms(con)
    r = con.execute("SELECT role_id, role_name, root_site_code FROM sccm.node_security_role").fetchone()
    assert r == ("SMS000AR", "Full Administrator", "CAS")
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_node_security_role`** — UNION `adminservice_security_roles`/`wmi_security_roles`; `_ensure_columns` for `role_name, role_description, is_built_in, is_sec_admin_role, copied_from_id, number_of_admins, operations`; `INSERT … BY NAME SELECT upper(role_id) AS role_id, …`; collapse `GROUP BY role_id` with `any_value`/`bool_or`/`max(number_of_admins)`; route `operations` through `_arr` (it may arrive as comma-string or list) and array-union it; stamp `? AS root_site_code` from `_root_code`. Call from `transforms()`.
- [ ] **Step 3b: `SCCMSecurityRoleProperties`** in `graph.py` — fields: `collection_source[]`, `sccm_role_id`, `sccm_role_name`, `role_description`, `is_built_in`, `is_sec_admin_role`, `copied_from_id`, `number_of_admins int|None`, `operations list[str]`, `root_site_code`, `sccm_infra=True`.
- [ ] **Step 3c: `models/sccm_security_role.py`** — `SCCMSecurityRole(BaseAsset)` mirroring `SCCMCollection`: id = `role_id@root` (drop+warn if no role_id), kinds `[nk.SCCM_SECURITY_ROLE]`, `environmentid = root or role_id`, map fields into `SCCMSecurityRoleProperties`.
- [ ] **Step 3d:** add `("node_security_role", SCCMSecurityRole)` to `NODE_SPECS`; re-export.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task B3: `node_admin_user` + `SCCMAdminUser` model

**Note:** the admin's *AD principal* (its `admin_sid`/`logon_name`) is already a `node_user`/`node_group` from Stage 1. This task creates the distinct SCCM-native `SCCM_AdminUser` node (the RBAC object), keyed by `logon_name@root`.

**Files:** Modify `transforms.py`, `graph.py`, `main.py`; create `models/sccm_admin_user.py`, `models/sccm_admin_user_test.py`, `node_admin_user_test.py`.

**Interfaces — Produces:** `node_admin_user(logon_name, admin_id, admin_sid, display_name, distinguished_name, is_group, account_type, root_site_code)` — one row per `upper(logon_name)`. id = `logon_name@root`. (Collection/role assignment lists are NOT stored on the node; they drive the IsAssigned edges in Task C5 from the raw admins rows.)

- [ ] **Step 1: Failing tests**

```python
# src/openhound_sccm/node_admin_user_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_admin_user_one_row_per_logon():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    # same admin replicated from two sites -> one node
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\\\sccmadmin','S-1-5-21-1-2-3-1110','adm', false, 1), "
                "('MAYYHEM\\\\sccmadmin','S-1-5-21-1-2-3-1110','adm', false, 1)) "
                "AS t(logon_name, admin_sid, display_name, is_group, account_type)")
    transforms(con)
    rows = con.execute("SELECT logon_name, admin_sid, root_site_code FROM sccm.node_admin_user").fetchall()
    assert rows == [("MAYYHEM\\sccmadmin", "S-1-5-21-1-2-3-1110", "CAS")]
```
```python
# src/openhound_sccm/models/sccm_admin_user_test.py
from openhound_sccm.models.sccm_admin_user import SCCMAdminUser

def test_admin_user_as_node():
    n = SCCMAdminUser(logon_name="MAYYHEM\\sccmadmin", admin_sid="S-1-5-21-1-2-3-1110",
                      is_group=False, root_site_code="CAS").as_node
    assert n.id == "MAYYHEM\\SCCMADMIN@CAS"
    assert n.kinds == ["SCCM_AdminUser"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.is_group is False
```
> Note: id uppercases `logon_name` (the coalesce keys on `upper(logon_name)`); keep that consistent between the coalesce and `as_node`.

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_node_admin_user`** — UNION `adminservice_admins`/`wmi_admins`; `_ensure_columns` for `admin_id, admin_sid, display_name, distinguished_name, is_group, account_type`; `INSERT … BY NAME SELECT logon_name` (**original case**)`, CAST(admin_id AS VARCHAR), upper(admin_sid) AS admin_sid, …`; collapse `GROUP BY upper(logon_name)` with `any_value(logon_name)` (stores original-case logon; the model uppercases for the id), `any_value` other scalars, `bool_or(is_group)`, `max(account_type)`; stamp root. Filter `WHERE logon_name IS NOT NULL`. Call from `transforms()`. (Edge tasks C4/C5 compute `upper(logon_name)@root` from the raw admins rows, matching the node id.)
- [ ] **Step 3b: `SCCMAdminUserProperties`** in `graph.py` — fields: `collection_source[]`, `sccm_admin_id`, `admin_sid`, `distinguished_name`, `is_group bool|None`, `account_type int|None`, `root_site_code`, `sccm_infra=True`.
- [ ] **Step 3c: `models/sccm_admin_user.py`** — `SCCMAdminUser(BaseAsset)`: id = `upper(logon_name)@root` (drop+warn if no logon_name), kinds `[nk.SCCM_ADMIN_USER]`, `name=logon_name`, `environmentid = root or upper(logon_name)`.
- [ ] **Step 3d:** add `("node_admin_user", SCCMAdminUser)` to `NODE_SPECS`; re-export.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task B4: `node_client_device` (real clients) + `SCCMClientDevice` model

Possible-client rows are added in Phase E; this task does the real AdminService/WMI client devices only.

**Files:** Modify `transforms.py`, `graph.py`, `main.py`; create `models/sccm_client_device.py`, `models/sccm_client_device_test.py`, `node_client_device_test.py`.

**Interfaces — Produces:** `node_client_device(smsid, name, resource_id_str, site_code, device_os, device_os_build, is_virtual_machine, co_managed, aad_device_id, aad_tenant_id, last_mp_server_name, primary_user_name, current_logon_user_name, ad_last_logon_user_name, root_site_code, possible BOOLEAN, ad_domain_sid VARCHAR)` — one row per `upper(smsid)`. `possible=false`, `ad_domain_sid=NULL` for real clients (Phase E sets them for possible-clients). id = `upper(smsid)`. The three `*_user_name` columns are name-only here; they are resolved to SIDs for the `Has*User` edges in Task D1.

- [ ] **Step 1: Failing tests**

```python
# src/openhound_sccm/node_client_device_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_client_device_filters_and_keys_on_smsid():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT * FROM (VALUES "
                "('GUID-1','WS01', 7, 'PS1', true,  false, 'MAYYHEM\\\\alice','MAYYHEM\\\\bob','MAYYHEM\\\\carol'), "
                "('GUID-2','WS02', 8, 'PS1', false, false, NULL, NULL, NULL), "       # not a client -> dropped
                "('GUID-3','WS03', 9, 'PS1', true,  true,  NULL, NULL, NULL)) "        # obsolete -> dropped
                "AS t(smsid, name, resource_id, site_code, is_client, is_obsolete, primary_user, current_logon_user, user_name)")
    transforms(con)
    rows = con.execute("SELECT smsid, name, resource_id_str, possible FROM sccm.node_client_device ORDER BY smsid").fetchall()
    assert rows == [("GUID-1", "WS01", "7@PS1", False)]
```
```python
# src/openhound_sccm/models/sccm_client_device_test.py
from openhound_sccm.models.sccm_client_device import SCCMClientDevice

def test_client_device_as_node():
    n = SCCMClientDevice(smsid="GUID-1", name="WS01", site_code="PS1", root_site_code="CAS",
                         resource_id_str="7@PS1").as_node
    assert n.id == "GUID-1"
    assert n.kinds == ["SCCM_ClientDevice"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.smsid == "GUID-1"
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_node_client_device`** — staging table with the columns above; `_ensure_columns` for the optional device columns; per-source (`adminservice_client_devices`, `wmi_client_devices`) `INSERT … BY NAME`:

```python
        f"SELECT upper(smsid) AS smsid, name, site_code, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(site_code AS VARCHAR) END AS resource_id_str, "
        f"device_os, device_os_build, is_virtual_machine, co_managed, aad_device_id, aad_tenant_id, "
        f"last_mp_server_name, primary_user AS primary_user_name, current_logon_user AS current_logon_user_name, "
        f"user_name AS ad_last_logon_user_name, false AS possible, NULL AS ad_domain_sid "
        f"FROM {schema}.adminservice_client_devices "
        f"WHERE smsid IS NOT NULL AND coalesce(is_client, false) AND NOT coalesce(is_obsolete, false)"
```
Collapse `GROUP BY smsid` (`any_value` scalars; `bool_or` flags); stamp `? AS root_site_code`. Call from `transforms()`.

- [ ] **Step 3b: `SCCMClientDeviceProperties`** in `graph.py` — fields: `collection_source[]`, `smsid`, `sccm_resource_id`, `site_code`, `device_os`, `device_os_build`, `is_virtual_machine bool|None`, `co_managed bool|None`, `aad_device_id`, `aad_tenant_id`, `last_reported_mp_server_name`, `primary_user`, `current_logon_user`, `ad_last_logon_user`, `root_site_code`, `possible bool=False`, `sccm_infra=False`.
- [ ] **Step 3c: `models/sccm_client_device.py`** — `SCCMClientDevice(BaseAsset)`: id = `upper(smsid)` (drop+warn if none), kinds `[nk.SCCM_CLIENT_DEVICE]`, `environmentid = root_site_code or smsid`, name = `name@site_code` for display / `name` for `name`. Carry the three name-only user fields as properties (the SID-resolved edges are separate). `edges` returns `iter(())`.
- [ ] **Step 3d:** add `("node_client_device", SCCMClientDevice)` to `NODE_SPECS`; re-export.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

---

# Phase C — Generic edge model + node-local edges

## Task C0: Generalise the edge model (`GraphEdge` + traversable)

> **Implementation note (2026-06-23, applied):** the `properties JSON` column described below was **dropped** during execution. DuckDB returns a JSON column as a *string*, which breaks `GraphEdge.properties: dict` on read; and edge `collection_source` is unused for pathfinding. So `graph_edges` stays **3-col `(start_id, end_id, kind)`**, every edge builder (C0–E2) does `SELECT start_id, end_id, kind` (ignore the `NULL AS properties` shown in later tasks), and `GraphEdge` sets only `traversable` from `TRAVERSABLE_EDGE_KINDS` via `SCCMEdgeProperties(traversable=…)`. `_graph_edges` was split into `_graph_edges_init` (empty 3-col table) + `_edge_replication`.

**Files:** Rename `models/replication_edge.py` → `models/graph_edge.py`; modify `kinds/edges.py`, `graph.py`, `transforms.py` (`_graph_edges` columns), `main.py` (`EDGE_SPECS`, import), `models/__init__.py`; rename `models/replication_edge_test.py` → `models/graph_edge_test.py`.

**Interfaces — Produces:** `graph_edges(start_id, end_id, kind, properties JSON)`. `GraphEdge(BaseAsset)` emits `Edge(kind, start, end, properties=SCCMEdgeProperties(traversable=…, …))`.

- [ ] **Step 1: Add edge-kind constants** to `kinds/edges.py` (all Stage 2 kinds) + the traversable set (verbatim from CMBP :2216-2249, uncommented entries; includes future kinds so Stage 3–6 reuse it):

```python
# Stage 2 edge kinds
SCCM_IS_MAPPED_TO = "SCCM_IsMappedTo"
SCCM_IS_ASSIGNED = "SCCM_IsAssigned"
SCCM_HAS_MEMBER = "SCCM_HasMember"
SCCM_HAS_CLIENT = "SCCM_HasClient"
SCCM_HAS_PRIMARY_USER = "SCCM_HasPrimaryUser"
SCCM_HAS_CURRENT_USER = "SCCM_HasCurrentUser"
SCCM_HAS_AD_LAST_LOGON_USER = "SCCM_HasADLastLogonUser"
SCCM_HAS_STORED_ACCOUNT = "SCCM_HasStoredAccount"
MEMBER_OF = "MemberOf"
HAS_SESSION = "HasSession"

# CMBP traversable allow-list (ConfigManBearPig.ps1:2216-2249, uncommented only).
# Edges whose kind is in this set get properties.traversable = True.
TRAVERSABLE_EDGE_KINDS = frozenset({
    "AdminTo", "LocalAdminRequired",
    "CoerceAndRelayToAdminService", "CoerceAndRelayToMSSQL", "CoerceAndRelayNTLMtoSMB",
    "HasSession",
    "MSSQL_Contains", "MSSQL_ControlDB", "MSSQL_ControlServer", "MSSQL_ExecuteOnHost",
    "MSSQL_GetAdminTGS", "MSSQL_GetTGS", "MSSQL_HasLogin", "MSSQL_HostFor",
    "MSSQL_IsMappedTo", "MSSQL_MemberOf",
    "SameHostAs",
    "SCCM_AdminsReplicatedTo", "SCCM_AllPermissions", "SCCM_ApplicationAdministrator",
    "SCCM_AssignAllPermissions", "SCCM_Contains", "SCCM_FullAdministrator",
    "SCCM_HasADLastLogonUser", "SCCM_HasClient", "SCCM_HasCurrentUser",
    "SCCM_HasPrimaryUser", "SCCM_IsMappedTo",
})
```

- [ ] **Step 2: `SCCMEdgeProperties`** in `graph.py` (extends core `EdgeProperties`, which has `composed`/`traversable`):

```python
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties  # add to imports

@dataclass
class SCCMEdgeProperties(EdgeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
```

- [ ] **Step 3: Write the failing test** for the generic model (`models/graph_edge_test.py`):

```python
from dataclasses import asdict
from openhound_sccm.models.graph_edge import GraphEdge

def test_graph_edge_sets_traversable_from_allowlist():
    e = list(GraphEdge(start_id="A", end_id="B", kind="SCCM_HasClient").edges)[0]
    assert e.kind == "SCCM_HasClient"
    assert e.start.value == "A" and e.end.value == "B"
    assert e.properties.traversable is True

def test_graph_edge_non_traversable_kind():
    e = list(GraphEdge(start_id="A", end_id="B", kind="SCCM_HasMember").edges)[0]
    assert e.properties.traversable is False

def test_graph_edge_drops_incomplete_row():
    assert list(GraphEdge(start_id="A", end_id=None, kind="MemberOf").edges) == []

def test_graph_edge_reads_properties_collection_source():
    e = list(GraphEdge(start_id="A", end_id="B", kind="MemberOf",
                       properties={"collection_source": ["AdminService"]}).edges)[0]
    assert e.properties.collection_source == ["AdminService"]
```

- [ ] **Step 4: Run — expect failure.**
- [ ] **Step 5: Implement `models/graph_edge.py`** (rename + generalise):

```python
# src/openhound_sccm/models/graph_edge.py
import logging
from typing import Iterator
from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Edge, EdgePath
from pydantic import ConfigDict
from ..graph import SCCMEdgeProperties
from ..kinds.edges import TRAVERSABLE_EDGE_KINDS

logger = logging.getLogger(__name__)


class GraphEdge(BaseAsset):
    """One graph_edges row -> one OpenGraph edge of any kind. start/end are matched
    by id; traversable is set from the CMBP allow-list; collection_source rides in
    the optional properties dict."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    start_id: str | None = None
    end_id: str | None = None
    kind: str | None = None
    properties: dict | None = None

    @property
    def as_node(self) -> None:
        return None

    @property
    def edges(self) -> Iterator[Edge]:
        if not self.start_id or not self.end_id or not self.kind:
            logger.warning("GraphEdge: dropping incomplete row (start=%r end=%r kind=%r)",
                           self.start_id, self.end_id, self.kind)
            return
        props = self.properties or {}
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=SCCMEdgeProperties(
                traversable=self.kind in TRAVERSABLE_EDGE_KINDS,
                collection_source=list(props.get("collection_source") or []),
            ),
        )
```

- [ ] **Step 6: Update `_graph_edges`** in `transforms.py` to declare the table with a `properties` column and to write `SCCM_AdminsReplicatedTo` rows with `NULL AS properties` (or `{}`); update the empty-table fallbacks to the 4-column shape `(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, properties JSON)`. Later edge tasks `INSERT` into this same table. **Do not** recreate `graph_edges` per builder — Stage 1's `_graph_edges` becomes the table *initialiser*; subsequent `_edge_*` builders `INSERT` into it.

Refactor: split the current `_graph_edges` so `transforms()` calls (in order) `_graph_edges_init(con, schema)` (creates the empty 4-col table), then the per-edge builders append, e.g. `_edge_replication(con, schema)` (the existing Stage-1 self-join, now an INSERT). Keep the Stage-1 replication test green by asserting the same rows.

- [ ] **Step 7: Update `main.py`** — `from .models.graph_edge import GraphEdge`; `EDGE_SPECS = [("graph_edges", GraphEdge)]`. Update `models/__init__.py` export.
- [ ] **Step 8: Run** the graph_edge tests + the Stage-1 `graph_edges_test.py` (replication still passes, now with `traversable=True`) — expect PASS. **Step 9: Checkpoint.**

## Task C1: Stage 2 lookups (`resource_to_sid`, `device_by_resourceid`, `collection_by_name`, `role_by_name`) + `principal_by_name` enrichment

**Files:** Modify `transforms.py`; create `transforms_lookups_test.py`.

**Interfaces — Produces:** four tables keyed for edge joins, and a richer `principal_by_name`:
- `resource_to_sid(resource_key VARCHAR, sid VARCHAR)` where `resource_key = '<resource_id>@<site>'` — from r_system (computer SID), r_user (user SID), user_group (group SID).
- `device_by_resourceid(resource_key VARCHAR, smsid VARCHAR)` — from client_devices.
- `collection_by_name(name VARCHAR, collection_id VARCHAR)` — from collections (`upper(name)`).
- `role_by_name(name VARCHAR, role_id VARCHAR)` — from security_roles (`upper(role_name)`).

- [ ] **Step 1: Failing test**

```python
# src/openhound_sccm/transforms_lookups_test.py
import duckdb
from openhound_sccm.transforms import transforms

def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'WS01' AS name, "
                "'S-1-5-21-1-2-3-1104' AS sid, 7 AS resource_id, 'PS1' AS source_site_code, false AS obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'PS100016' AS collection_id, 'All Systems' AS name")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS000AR' AS role_id, 'Full Administrator' AS role_name")

def test_lookups_built():
    con = duckdb.connect(":memory:"); _seed(con); transforms(con)
    assert con.execute("SELECT sid FROM sccm.resource_to_sid WHERE resource_key='9@PS1'").fetchone()[0] == "S-1-5-21-1-2-3-1106"
    assert con.execute("SELECT smsid FROM sccm.device_by_resourceid WHERE resource_key='7@PS1'").fetchone()[0] == "GUID-1"
    assert con.execute("SELECT collection_id FROM sccm.collection_by_name WHERE name='ALL SYSTEMS'").fetchone()[0] == "PS100016"
    assert con.execute("SELECT role_id FROM sccm.role_by_name WHERE name='FULL ADMINISTRATOR'").fetchone()[0] == "SMS000AR"
```

- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_resource_to_sid`** — empty table then INSERT from r_system/wmi_r_system (`CAST(resource_id AS VARCHAR)||'@'||source_site_code`, `upper(sid)`, drop obsolete), r_user/wmi_r_user (user sid), user_group/wmi_user_group (group sid, key `resource_id@source_site_code`). `DISTINCT` at the end. Each source via `_safe`.
- [ ] **Step 3b: `_device_by_resourceid`** — from client_devices/wmi_client_devices: `resource_id@site_code -> upper(smsid)`, `WHERE smsid IS NOT NULL AND coalesce(is_client,false) AND NOT coalesce(is_obsolete,false)`.
- [ ] **Step 3c: `_collection_by_name` / `_role_by_name`** — `SELECT upper(trim(name)) AS name, upper(collection_id) ...` / `upper(trim(role_name)) AS name, upper(role_id) ...`; `DISTINCT`. (Names may not be unique; keep all rows and let the edge join fan out — log a count of names mapping to >1 id at INFO.)
- [ ] **Step 3d: Enrich `principal_by_name`** — in `_principal_by_name`, ALSO union the `DOMAIN\user` name forms so device user fields (`primary_user` etc.) and the SQL service account (`DOMAIN\svc`) resolve: from r_user/wmi_r_user add `unique_user_name`, `full_user_name`, `user_principal_name` → `sid`; keep existing sources. (These are additional `(name, sid)` rows; dedup already handles overlaps.)
- [ ] **Step 3e:** call all four lookups + the enriched principal builder from `transforms()` BEFORE the edge builders.
- [ ] **Step 4: Run — expect PASS.** (Also re-run `transforms_principal_test.py` — still green.) **Step 5: Checkpoint.**

## Task C2: `SCCM_HasClient` edge (Site → ClientDevice)

**Files:** Modify `transforms.py`; create `edge_has_client_test.py`.

**Logic (CMBP :7257/7394):** for each real client device, `start = device.site_code` (the site that has the client), `end = upper(smsid)`, `kind = SCCM_HasClient`.

- [ ] **Step 1: Failing test** — seed a `node_client_device` precursor (or seed `adminservice_client_devices` + a site) and assert `graph_edges` contains `('PS1','GUID-1','SCCM_HasClient')` after `transforms`.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: `_edge_has_client`** — append to `graph_edges` from `node_client_device` (built in B4):

```python
def _edge_has_client(con, schema):
    from .kinds.edges import SCCM_HAS_CLIENT
    _safe(con, "edge_has_client",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT site_code AS start_id, smsid AS end_id, '{SCCM_HAS_CLIENT}' AS kind, NULL AS properties "
          f"FROM {schema}.node_client_device WHERE site_code IS NOT NULL AND smsid IS NOT NULL")
```
Call from `transforms()` after `_graph_edges_init` and the node coalesces.

- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task C3: `SCCM_HasMember` edge (Collection → device/user/group)

**Files:** Modify `transforms.py`; create `edge_has_member_test.py`.

**Logic (CMBP :7617-7647):** for each `collection_members` row, `start = collection_id@root`; resolve the member by `resource_key = resource_id@site_code` — try `device_by_resourceid` (→ ClientDevice `smsid`) first, else `resource_to_sid` (→ User/Group/Computer SID). Skip built-in member IDs `2046820352`, `2046820353`, and any `resource_id` LIKE `203004%` (provisioning).

- [ ] **Step 1: Failing test** — seed a device collection with a device member (resource 7→GUID-1) and a user member (resource 9→user SID); assert two `SCCM_HasMember` edges from `PS100016@<root>`; assert a `2046820352` member is absent.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: `_edge_has_member`**:

```python
def _edge_has_member(con, schema):
    from .kinds.edges import SCCM_HAS_MEMBER
    root = _root_code(con, schema)
    _safe(con, "edge_has_member",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT (upper(cm.collection_id) || '@' || ?) AS start_id, "
          f"       coalesce(d.smsid, r.sid) AS end_id, '{SCCM_HAS_MEMBER}' AS kind, NULL AS properties "
          f"FROM {schema}.adminservice_collection_members cm "
          f"LEFT JOIN {schema}.device_by_resourceid d "
          f"  ON d.resource_key = CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR) "
          f"LEFT JOIN {schema}.resource_to_sid r "
          f"  ON r.resource_key = CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR) "
          f"WHERE cm.collection_id IS NOT NULL "
          f"  AND coalesce(d.smsid, r.sid) IS NOT NULL "
          f"  AND CAST(cm.resource_id AS VARCHAR) NOT IN ('2046820352','2046820353') "
          f"  AND CAST(cm.resource_id AS VARCHAR) NOT LIKE '203004%'", [root or ''])
    # also UNION the wmi_collection_members source with the same shape (separate _safe INSERT).
```
Add the `wmi_collection_members` variant as a second `_safe` INSERT. Call from `transforms()`.

- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task C4: `SCCM_IsMappedTo` edge (AD principal → AdminUser)

**Files:** Modify `transforms.py`; create `edge_is_mapped_to_test.py`.

**Logic (CMBP :7789-7807):** for each admin, `start =` the AD principal SID = `upper(admin_sid)` if present, else resolve `logon_name` via `principal_by_name`; `end = upper(logon_name)@root`. Drop (log) when the SID can't be determined.

- [ ] **Step 1: Failing test** — admin with `admin_sid` set → edge `(admin_sid, logon_name@root, SCCM_IsMappedTo)`; admin with only `logon_name` that resolves via principal_by_name → edge using the resolved SID.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: `_edge_is_mapped_to`** — build from `adminservice_admins`/`wmi_admins`, `COALESCE(upper(admin_sid), pbn.sid)` as start (LEFT JOIN `principal_by_name pbn ON upper(trim(logon_name)) = upper(pbn.name)`), `upper(logon_name) || '@' || root` as end, `WHERE start IS NOT NULL`. Two `_safe` INSERTs (adminservice + wmi).
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task C5: `SCCM_IsAssigned` edge (AdminUser → Collection / SecurityRole)

**Files:** Modify `transforms.py`; create `edge_is_assigned_test.py`.

**Logic (CMBP :7819/7841/7867):** from each admin row, `start = upper(logon_name)@root`:
- **→ Collection:** split `collection_names` (comma-separated names), resolve each via `collection_by_name` → `collection_id@root` end.
- **→ SecurityRole:** prefer `roles` (role-id list, via `_arr`) → `role_id@root`; if `roles` empty, fall back to `role_names` resolved via `role_by_name` → `role_id@root`.

- [ ] **Step 1: Failing test** — admin with `collection_names='All Systems'` (resolves to PS100016) and `roles=['SMS000AR']`; assert two `SCCM_IsAssigned` edges: `logon@root → PS100016@root` and `logon@root → SMS000AR@root`. Add a second admin with empty `roles` but `role_names='Full Administrator'` and assert the fallback resolves the same role id.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_edge_is_assigned_collection`** — `string_split(collection_names, ',')` UNNEST → trim → JOIN `collection_by_name` on `upper(trim(name))` → emit `(logon@root, collection_id@root, SCCM_IsAssigned)`.
- [ ] **Step 3b: `_edge_is_assigned_role`** — two arms UNIONed:
  - id arm: `unnest(_arr('roles'))` (role ids) → `(logon@root, upper(role)@root, SCCM_IsAssigned)`.
  - name-fallback arm: rows where `_arr('roles')` is empty → `string_split(role_names, ',')` UNNEST → JOIN `role_by_name` → `(logon@root, role_id@root, SCCM_IsAssigned)`.
  Guard each with `_safe`; use `len(_arr('roles')) = 0` for the fallback predicate.
- [ ] **Step 3c:** call both from `transforms()`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

---

# Phase D — Cross-entity edges

## Task D1: `SCCM_HasPrimaryUser` / `HasCurrentUser` / `HasADLastLogonUser` (ClientDevice → User)

**Files:** Modify `transforms.py`; create `edge_has_user_test.py`.

**Logic (CMBP :7266/7275/7298):** from `node_client_device`, resolve each name-only user field via `principal_by_name` (enriched in C1) to a SID; emit `start = smsid`, `end = user SID`. Drop (log) unresolved.

- [ ] **Step 1: Failing test** — seed a `node_client_device`-feeding device with `primary_user='MAYYHEM\\alice'`, and a `principal_by_name` entry (via seeding `adminservice_r_user` with `unique_user_name='MAYYHEM\\alice'`); assert `(GUID-1, alice_sid, SCCM_HasPrimaryUser)` appears. Repeat one assertion for current + ad-last-logon.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: `_edge_has_user`** — one helper, three INSERTs (one per field/kind):

```python
def _edge_has_user(con, schema):
    from .kinds.edges import SCCM_HAS_PRIMARY_USER, SCCM_HAS_CURRENT_USER, SCCM_HAS_AD_LAST_LOGON_USER
    for col, kind in (("primary_user_name", SCCM_HAS_PRIMARY_USER),
                      ("current_logon_user_name", SCCM_HAS_CURRENT_USER),
                      ("ad_last_logon_user_name", SCCM_HAS_AD_LAST_LOGON_USER)):
        _safe(con, f"edge_has_user<-{kind}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT cd.smsid AS start_id, pbn.sid AS end_id, '{kind}' AS kind, NULL AS properties "
              f"FROM {schema}.node_client_device cd "
              f"JOIN {schema}.principal_by_name pbn ON upper(trim(cd.{col})) = upper(pbn.name) "
              f"WHERE cd.smsid IS NOT NULL AND cd.{col} IS NOT NULL AND trim(cd.{col}) != ''")
```
Call from `transforms()`.

- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task D2: `MemberOf` edge (Computer/User → Group)

**Files:** Modify `transforms.py`; create `edge_member_of_test.py`.

**Logic (CMBP :7375/7470):** reuse the `security_group_name` unnest+resolve already used by `_node_group`, but emit `(resource SID, group SID)`. From r_system: `start = upper(sid)` (computer), from r_user: `start = upper(sid)` (user); `end = pbn.sid` (group). `kind = MemberOf` (not in the traversable set — BloodHound treats native MemberOf traversable via its own schema; we mirror CMBP and leave our `traversable=False`).

> **Nested groups — scope (decided 2026-06-23, evidence-based):** D2 builds ONLY the direct `principal → group` memberships SCCM records. Group→group nesting is **deliberately NOT built here** because it isn't in the collected data: `adminservice_user_group` carries no membership/parent column, and `security_group_name` on r_system/r_user is **direct-only** (verified against the lab — e.g. `mayyhem\domainadmin` lists `Domain Admins`/`Enterprise Admins` but not `BUILTIN\Administrators`, which they're nested into). Co-membership cannot reconstruct nesting. **Nested-group traversal is supplied by a merged SharpHound collection:** our `Group` nodes are SID-keyed with `environmentid` = the AD domain SID (Stage 1), so SharpHound's authoritative `MemberOf` group→group edges attach to the *same* SIDs when both datasets load into the same graph. No collect change; no AD re-enumeration here. README/ARCHITECTURE (Task F2) document this as an explicit assumption + Limitation. (CMBP itself never built group nesting either — this matches its behaviour while making the merge contract explicit.)

- [ ] **Step 1: Failing test** — seed `adminservice_r_system` (computer SID + `security_group_name=['MAYYHEM\\SCCMAdmins']`) and the group's `(name,sid)` in `principal_by_name` (via `adminservice_user_group`); assert `(computer_sid, group_sid, MemberOf)`.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: `_edge_member_of`** — four `_safe` INSERTs ({adminservice,wmi} × {r_system,r_user}) mirroring `_node_group`'s unnest/join but selecting `upper(r.sid) AS start_id, pbn.sid AS end_id, 'MemberOf' AS kind`. Reuse the `_arr('r.security_group_name')` UNNEST + `JOIN principal_by_name pbn ON upper(trim(t.gname)) = upper(pbn.name)` pattern verbatim from `_node_group`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task D3: `HasSession` edge (Computer → User) — RemoteRegistry + MSSQL service account

**Files:** Modify `transforms.py`; create `edge_has_session_test.py`.

**Logic:** two sources UNIONed into `HasSession`:
- **RemoteRegistry (CMBP :5029):** from `remoteregistry_users`, `start = upper(host_object_sid)` (added in A1), `end = upper(object_sid)` (the logged-on user). Drop rows with no `host_object_sid`.
- **MSSQL service account (CMBP :8007):** from `adminservice_site_systems`/`wmi_site_systems` where `sql_server_service_logon_account` is a **domain** account, `start =` the SQL host computer SID (resolve `network_os_path` host → SID via `node_computer` by `dnshostname`/`name`, or `principal_by_name`), `end =` the service-account SID (resolve `sql_server_service_logon_account` via `principal_by_name`). Skip local accounts (`NT AUTHORITY\*`, `LOCAL SERVICE`, `NETWORK SERVICE`, `LOCALSYSTEM`, names without a `\`).

- [ ] **Step 1: Failing tests** — (a) `remoteregistry_users` row with `host_object_sid` + `object_sid` → `(host_sid, user_sid, HasSession)`; (b) `adminservice_site_systems` with `network_os_path='\\\\SQL01.lab'`, `sql_server_service_logon_account='MAYYHEM\\svc_sql'`, plus a `node_computer` row for SQL01 and a `principal_by_name` entry for the svc account → `(sql01_sid, svc_sql_sid, HasSession)`; (c) a `NT AUTHORITY\\SYSTEM` logon account produces no edge.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_edge_has_session_registry`** — INSERT from `remoteregistry_users` (`upper(host_object_sid)`, `upper(object_sid)`), `WHERE host_object_sid IS NOT NULL AND object_sid IS NOT NULL`.
- [ ] **Step 3b: `_edge_has_session_mssql`** — normalise `network_os_path` (strip leading `\\`, take host label, lowercase) and join `node_computer` on `lower(split_part(dnshostname,'.',1)) = host` OR `lower(name) = host` to get the host SID; join `principal_by_name` on `upper(trim(sql_server_service_logon_account)) = upper(name)` for the svc SID; `WHERE sql_server_service_logon_account LIKE '%\\%' AND upper(sql_server_service_logon_account) NOT LIKE 'NT AUTHORITY\\%' AND upper(sql_server_service_logon_account) NOT IN ('LOCALSYSTEM','LOCAL SERVICE','NETWORK SERVICE')`. Two `_safe` INSERTs (adminservice + wmi site_systems).
- [ ] **Step 3c:** call both from `transforms()`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task D4: `SCCM_HasStoredAccount` edge (Site → User/Group)

**Files:** Modify `transforms.py`; create `edge_has_stored_account_test.py`.

**Logic (CMBP :7147):** from `adminservice_reserved_accounts`/`wmi_reserved_accounts`, `start = site_code`, `end = upper(object_sid)` (already AD-resolved at collection). `kind = SCCM_HasStoredAccount` (not traversable). Stage 1 already set the `stored_in_sccm_site` *property* on `node_user`; this adds the *edge*.

- [ ] **Step 1: Failing test** — seed `adminservice_reserved_accounts` (`object_sid`, `site_code='PS1'`); assert `('PS1', object_sid, SCCM_HasStoredAccount)`.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: `_edge_has_stored_account`** — two `_safe` INSERTs: `SELECT site_code AS start_id, upper(object_sid) AS end_id, 'SCCM_HasStoredAccount' AS kind, NULL AS properties … WHERE site_code IS NOT NULL AND object_sid IS NOT NULL`.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

---

# Phase E — Possible-client, gating, integrity backfill

## Task E1: Read `collection_settings` in preproc; expose a gate

**Files:** Modify `transforms.py`; create `transforms_settings_test.py`.

**Interfaces — Produces:** `transforms()` reads `collection_settings` (if present) and computes `disable_possible = bool(disable_possible_edges)`; passes it to the possible-row builders (E2). Default `False` when the table is absent (older collections).

- [ ] **Step 1: Failing test** — seed `collection_settings(disable_possible_edges=true)` + an `ldap_cmrc_devices` row; after `transforms`, assert `node_client_device` has NO `possible=true` rows. Seed with `false` (or omit table) → the possible row appears (covered fully in E2; here assert the gate value is read).
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3: helper `_read_disable_possible(con, schema) -> bool`**:

```python
def _read_disable_possible(con, schema):
    try:
        row = con.execute(f"SELECT bool_or(disable_possible_edges) FROM {schema}.collection_settings").fetchone()
        val = bool(row[0]) if row and row[0] is not None else False
    except duckdb.CatalogException:
        # Older collection without the settings table -> default to emitting possible rows.
        logger.info("collection_settings absent; possible edges/nodes enabled by default")
        val = False
    logger.info("disable_possible_edges = %s", val)
    return val
```
Call it in `transforms()` and thread the bool into `_node_client_device_possible` (E2).

- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

## Task E2: Possible-client `SCCM_ClientDevice` nodes (deterministic id, gated)

**Files:** Modify `transforms.py`, `graph.py`/`models/sccm_client_device.py` (carry `possible` + `ad_domain_sid`); create `node_client_device_possible_test.py`.

**Logic (CMBP :3272, fixed):** when NOT disabled **and `root_site_code` is present**, for each `ldap_cmrc_devices` row with an `object_sid`, INSERT a `node_client_device` row: `smsid = upper(object_sid) || '@' || root` (deterministic; follows the same `@root_site_code` convention as Collection/Role/AdminUser; distinct from the Computer node's raw-SID id and from real client GUIDs), `possible = true`, `ad_domain_sid = upper(object_sid)` (the raw computer SID, for Stage 4 SameHostAs — independent of the node-id format), `site_code = root`, `name = name`. **Gate on root:** if `_root_code` is None (no SCCM hierarchy collected), skip + log — without a root the id would collapse to the bare SID and collide with the Computer node, and a possible-client only makes sense inside a hierarchy anyway. Real-vs-possible dedup is intentionally left to Stage 4 SameHostAs (Decision #4), so no NOT-IN filter against real clients here. The `SCCM_HasClient` edge from the root site to the possible client falls out of C2's builder automatically (it reads `node_client_device`).

- [ ] **Step 1: Failing test** — `collection_settings(disable_possible_edges=false)` + a CAS hierarchy (so `root='CAS'`) + `ldap_cmrc_devices(object_sid='S-1-5-21-1-2-3-1104', name='WS09')`; assert a `node_client_device` row with `smsid='S-1-5-21-1-2-3-1104@CAS'`, `possible=true`, `ad_domain_sid='S-1-5-21-1-2-3-1104'`. Flip the flag → row absent. (Add a second assertion: with `disable_possible_edges=false` but no site hierarchy seeded → no possible row, and a skip is logged.)
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_node_client_device_possible(con, schema, disable_possible)`** — early return if `disable_possible`; compute `root = _root_code(con, schema)` and early-return + log if `root` is None; else `INSERT INTO node_client_device BY NAME SELECT upper(object_sid) || '@' || ? AS smsid, name, ? AS site_code, NULL AS resource_id_str, …, true AS possible, upper(object_sid) AS ad_domain_sid FROM ldap_cmrc_devices WHERE object_sid IS NOT NULL` (bind `root` for both `smsid` and `site_code`). Run it AFTER `_node_client_device` (so it appends) and AFTER the real-client GROUP BY (possible rows are already 1-per-id by construction; no re-collapse needed). No NOT-IN filter against real clients — dedup is Stage 4's SameHostAs merge (Decision #4), which keys on `ad_domain_sid` regardless of node-id format.
- [ ] **Step 3b:** `SCCMClientDevice` model already carries `possible`/`ad_domain_sid` (B4) — confirm `as_node` sets `properties.possible` and a `sccm_ad_domain_sid` property. Add `sccm_ad_domain_sid` to `SCCMClientDeviceProperties` if not present.
- [ ] **Step 4: Run — expect PASS** (and C2's HasClient now also covers possible clients — add an assertion). **Step 5: Checkpoint.**

## Task E3: `node_backfill` — bare nodes for edge endpoints with no node (inferred kind + warn)

**Files:** Modify `transforms.py`, `graph.py`; create `models/stub_node.py`, `models/stub_node_test.py`, `node_backfill_test.py`.

**Logic (Decision #6):** after ALL node tables and `graph_edges` are built, compute the set of node ids that exist (`node_computer.sid ∪ node_user.sid ∪ node_group.sid ∪ node_site.site_code ∪ node_client_device.smsid ∪ node_collection id ∪ node_security_role id ∪ node_admin_user id`). For each distinct `start_id`/`end_id` in `graph_edges` not in that set, emit a `node_backfill(id, kind)` row with the kind inferred from the edge position (a static `kind`→endpoint-kind map). Log a warning count.

Endpoint-kind map (from the edge schema; ambiguous → `Base`):

| Edge kind | start kind | end kind |
|---|---|---|
| `SCCM_IsMappedTo` | (User/Group — use `Base`; admin is_group not known here) | — |
| `SCCM_HasPrimaryUser`/`HasCurrentUser`/`HasADLastLogonUser` | — | `User` |
| `HasSession` | — | `User` |
| `MemberOf` | — | `Group` |
| `SCCM_HasMember` | — | `Base` (device or user) |
| `SCCM_HasStoredAccount` | — | `Base` (user or group) |

Only backfill **end** endpoints for these (the start endpoints are sites/devices/admins that always have nodes). Keep the map in `graph.py` as `BACKFILL_END_KIND: dict[str, str]`.

- [ ] **Step 1: Failing test** — build a `graph_edges` row `(smsid, 'S-1-5-21-9-9-9-1','SCCM_HasPrimaryUser')` where that user SID is in no node table; after `transforms`, assert `node_backfill` has `('S-1-5-21-9-9-9-1','User')`.
- [ ] **Step 2: Run — expect failure.**
- [ ] **Step 3a: `_node_backfill`** — build the `existing_ids` set via UNION of the node-id columns; `INSERT INTO node_backfill SELECT DISTINCT ge.end_id AS id, m.kind FROM graph_edges ge JOIN (VALUES … BACKFILL_END_KIND …) m(edge_kind, kind) ON ge.kind = m.edge_kind WHERE ge.end_id NOT IN (SELECT id FROM existing_ids)`. Log `count(*)` at WARNING. Run LAST in `transforms()`.
- [ ] **Step 3b: `StubNode` model** — `StubNode(BaseAsset)` with `id`, `kind`; `as_node` → `SCCMNode(id=id, kinds=[kind, "Base"] if kind in ("User","Group","Computer") else [kind], properties=NodeProperties(name=id, displayname=id, environmentid=domain_environment_id(id) or id))`. (For SID ids, `domain_environment_id` yields the domain SID; otherwise fall back to the id itself.)
- [ ] **Step 3c:** add `("node_backfill", StubNode)` to `NODE_SPECS` (LAST, so real nodes win on any id overlap via opengraph append semantics); re-export.
- [ ] **Step 4: Run — expect PASS. Step 5: Checkpoint.**

---

# Phase F — Docs + validation

## Task F1: `_preproc_table_map` + integration test refresh

**Files:** Modify `main.py`, `convert_integration_test.py`, `preproc_map_test.py`.

- [ ] **Step 1:** Confirm `collection_settings` is in `_preproc_table_map` (A2). Update `preproc_map_test.py` to assert it is present.
- [ ] **Step 2:** Extend `convert_integration_test.py` — seed a tiny real raw tree exercising one of each new node + one new edge (e.g. a collection + a client device + an admin + a HasClient + an IsMappedTo), run `preprocess`→`convert`, assert the new node kinds and at least one Stage 2 edge kind appear in `<graph>/*.json`.
- [ ] **Step 3: Run** the integration test + full suite (`pytest src/openhound_sccm -v`) — expect PASS. **Step 4: Checkpoint.**

## Task F2: README + ARCHITECTURE

**Files:** Modify `README.md`, `ARCHITECTURE.md`.

- [ ] **Step 1: README Node Reference** — add `SCCM_ClientDevice` (id=`smsid`; props: `sccm_resource_id`, `site_code`, `device_os`, `primary_user`/`current_logon_user`/`ad_last_logon_user`, `possible`, `sccm_ad_domain_sid`), `SCCM_Collection` (id=`collection_id@root`), `SCCM_AdminUser` (id=`logon_name@root`), `SCCM_SecurityRole` (id=`role_id@root`); all `environmentid=root_site_code`.
- [ ] **Step 2: README Edge Reference** — add the 9 Stage 2 edges with start→end and a traversable column; note `SCCM_HasNetworkAccessAccount` is **deferred** (NAA collector unbuilt). For `MemberOf`, add an **Assumption/Limitation**: only direct `principal → group` memberships are emitted (SCCM's `security_group_name` is direct-only); **group→group nesting requires merging with a SharpHound collection** (our `Group` nodes are SID-keyed with `environmentid` = the AD domain SID, so SharpHound's `MemberOf` attaches on the same SIDs). Without SharpHound, paths that depend on nested-group reachability won't resolve.
- [ ] **Step 3: README Command Line Options / Examples** — document that `--disable-possible-edges` now suppresses possible-client nodes (and Stage 6 relay edges) via the persisted `collection_settings`, applied at preproc; add a mayyhem.com copy-paste example of collect→preprocess→convert showing a Stage 2 edge.
- [ ] **Step 4: ARCHITECTURE.md** — add/extend the preproc/convert section with: the two collect-side additions (host SID on current-user row; `collection_settings`), the persist-at-collect/gate-in-preproc mechanism, the traversable allow-list, and the edge-endpoint stub backfill (a new kind of divergence — note it). Add a changelog entry.
- [ ] **Step 5: Checkpoint** (docs only).

## Task F3: Stage 2 code-tour validation harness

**Files:** Create `docs/superpowers/plans/2026-06-23-sccm-preproc-convert-stage2-validation.md`; modify `.vscode/launch.json` (with user confirmation, per the Stage 0/1 precedent).

- [ ] **Step 1:** Write a `tour_driver_stage2.py` in the Stage 0/1 code-tour style: seed a small *real* raw tree (a CAS/PS1 hierarchy, one client device with a primary user, one collection + member, one admin mapped to a role + collection, one reserved account, one site_systems SQL row, one remoteregistry current-user row, one ldap_cmrc_device, and a `collection_settings` row), load into DuckDB, run `transforms()` then `app.converter(...)` in-process. Breakpoint stops at: each `_node_*` collapse, `_resource_to_sid`/`device_by_resourceid`, `_edge_has_member` (inspect device-vs-user resolution), `_edge_is_assigned_role` (id arm vs name fallback), `_edge_has_session_mssql` (domain-account gate), `_node_client_device_possible` (deterministic id), `_node_backfill` (stub creation + warning), and `GraphEdge.edges` (traversable set). Include the expected value per stop + the black-box output check (all 4 node kinds + each Stage 2 edge kind present; possible-client present with flag on, absent with flag off).
- [ ] **Step 2:** Add a **"Debug: Stage 2 code tour"** profile to `.vscode/launch.json` (mirror the Stage 1 profile, `justMyCode: false`). **Confirm with the user before editing the repo-root launch.json.**
- [ ] **Step 3: Checkpoint.**

---

## Self-Review

**Spec coverage (Stage 2 row of §6 + the 2026-06-23 resolved decisions):** ClientDevice/Collection/AdminUser/SecurityRole coalesce + emit → B1–B4; `resource_to_sid`/`device_by_resourceid` (+`collection_by_name`/`role_by_name`) → C1; inline edges IsMappedTo/IsAssigned/HasMember/HasClient/Has*User/HasStoredAccount/MemberOf/HasSession → C2–C5, D1–D4; deferred HasNetworkAccessAccount → noted (F2); possible-client (deterministic id + gate) → E1–E2; settings persistence + collect changes → A1–A2, E1; traversable allow-list → C0; graph-integrity stub backfill → E3; README/ARCHITECTURE → F2; validation harness → F3.

**Placeholder scan:** node coalesces give exact columns + an exact test contract; edge builders give complete SQL or a precise field/join spec keyed to the established `_safe`/`_arr`/`INSERT … BY NAME` patterns (the four node coalesces are structurally identical to Stage 1's, which the implementer follows). The fiddly parts (mixed string/list `roles`/`operations`, name→id ambiguity, host-name normalisation) each carry a test that is the contract; iterate the SQL until green.

**Type consistency:** node ids — ClientDevice=`upper(smsid)`, Collection=`upper(collection_id)@root`, SecurityRole=`upper(role_id)@root`, AdminUser=`upper(logon_name)@root` — identical between each coalesce and its model's `as_node`. `_root_code` returns the single hierarchy root used by all SCCM-native id minting. `graph_edges(start_id,end_id,kind,properties)` is the only edge table; `GraphEdge` is the only edge model; `EDGE_SPECS` stays length-1. `TRAVERSABLE_EDGE_KINDS` (kinds/edges.py) is the single traversable source, consumed only by `GraphEdge`. `NODE_SPECS` grows by five with the same `(table, ModelClass)` shape; `node_backfill`/`StubNode` is appended last.

**Open risks (flagged, not placeholders):** (1) name→id resolution coverage for `primary_user`/`role_names`/SQL svc account depends on the enriched `principal_by_name` (C1 §3d) — each consuming edge test seeds the resolving source so the contract is explicit; unresolved endpoints drop+log, and any resolved-but-nodeless id is caught by E3. (2) `collection_by_name`/`role_by_name` ambiguity (duplicate names) fans out edges — acceptable per CMBP; logged. (3) the possible-client/real-client duplicate is intentionally left for Stage 4 SameHostAs (Decision #4).
