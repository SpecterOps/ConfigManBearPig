# SCCM preproc + convert — Stage 4 (SameHostAs + LocalAdminRequired + ClientDevice dedup) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the two Stage-4 edge kinds — `SameHostAs` (Computer ↔ SCCM_ClientDevice, both directions) and `LocalAdminRequired` (site-server → every other site system in the same non-secondary site) — plus CMBP's duplicate-ClientDevice merge, all as set-based SQL in `preproc`.

**Architecture:** Pure `transforms.py` changes flowing through the existing Convert2-Read-DB pipeline unchanged. The grilled decision is that the duplicate-ClientDevice merge runs **before** the edge builders, so every edge is built from the deduped node table and references only survivors — **no edge-rewrite pass** (this diverges from CMBP's literal step order but yields an identical graph and matches the spec's "materialize all nodes, then emit edges" design). A prerequisite step resolves real-client `ad_domain_sid` (the SameHostAs join key) from `SMS_R_System`, faithful to CMBP's second `Upsert-Node` at `:7388`. `main.py` `NODE_SPECS`/`EDGE_SPECS` and all `models/*` are unchanged — `GraphEdge` already emits every kind and `SCCMClientDevice` already maps `ad_domain_sid → ADDomainSID`.

**Tech Stack:** Python 3.13+, `dlt`, `duckdb`, `openhound` (v0.2.x), `pytest`, `uv`.

**Tracking:** gtk `ope-9271`. **Baseline:** the post-Stage-3 working tree (`ope-1950`) is assumed present and importing. **Spec:** [`../specs/2026-06-16-sccm-preproc-convert-design.md`](../specs/2026-06-16-sccm-preproc-convert-design.md) §6 Stage 4. **CMBP reference:** `Add-SameHostAsEdges` [ps1:2261-2323](../../../ConfigManBearPig.ps1#L2261-L2323); `LocalAdminRequired` mesh [ps1:1882-1909](../../../ConfigManBearPig.ps1#L1882-L1909); client-device `ADDomainSID` source [ps1:7388-7392](../../../ConfigManBearPig.ps1#L7388-L7392).

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Never edit OpenHound core (`openhound/...`). (CLAUDE.md)
- **Do NOT `git add` or `git commit`.** CLAUDE.md is explicit: "Don't git add or commit anything. Just write the code and I will commit/push when ready after testing." Each task ends at a **green-test checkpoint only** — run the tests, confirm pass, then stop. (This overrides the Stage-3 plan's `git add` checkpoint convention.)
- **Validate in the isolated uv env** (already synced from Stage 0–3) — never touch the repo `.venv`:
  `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest <abs test path> -v`. (AGENTS.md)
- **Log every `if`/`else` and `try`/`except` branch** at an appropriate level, or leave a comment. (CLAUDE.md)
- **Node/edge property keys are CMBP-cased on output, snake_case in DuckDB.** Stage 4 adds no new *CMBP* properties (it *populates* the already-mapped `ad_domain_sid → ADDomainSID` and adds two edge kinds); the `graph_edges` columns stay snake_case. (See [[sccm-property-casing-cmbp]].) **Phase 0 renames the port-added `possible` flag → `is_confirmed_active_client`** (snake_case, *no* CMBP equivalent — [graph.py:221](../../../src/openhound_sccm/graph.py#L221) confirms "no CMBP key") and inverts its polarity (`true` = real, `false` = inferred).
- **Tests live in `sccm/sccm/tests/` as `<name>_test.py`.** Run with the isolated-env pytest targeting `tests/`.
- **No re-collect for Stage 4** — it is preproc/convert-only and reads the existing lab raw tree. Validate against the existing `<raw>` immediately.
- **`_safe`, `_ensure_columns`, `_arr`, `_root_code`, `_read_disable_possible`** already exist in `transforms.py`; reuse them. `_safe` takes no SQL params — inline the 3-char site-code literal where needed (established Stage 2/3 pattern).
- **JSON-array-text gotcha:** role columns arrive in four physical shapes; `node_computer.site_system_roles` is already a normalised `VARCHAR[]` (built via `_arr()`), so Stage 4 reads it directly — never re-parse it.

### Locked Stage 4 decisions (grilled with the user 2026-06-29)
1. **Dedup placement:** the duplicate-ClientDevice merge runs **before** any edge builder. All edges then reference survivors; **no `graph_edges` rewrite pass exists**. Diverges from CMBP's literal sequence (merge-after-edges-then-rewrite) but produces an identical graph and avoids per-row edge mutation.
2. **`SameHostAs` `collection_source`:** `['SCCM_Invoke-PostProcessing']` (CMBP set none; the port tags it for entity-panel provenance, consistent with every other post-proc edge).
3. **Real-client `ad_domain_sid` source:** `SMS_R_System.SID` joined on `SMSUniqueIdentifier == smsid` (CMBP `:7388`), folded into `_enrich_client_device` via `coalesce(existing, resolved)` so the possible-client value already set in `_node_client_device_possible` is preserved.
4. **Dedup survivor:** per non-null `ad_domain_sid` group, prefer `possible = false` (the authoritative real client), tiebreak `smsid ASC` (deterministic); array columns unioned across the whole group; scalar columns taken from the survivor (the possible client is a strict subset, so nothing is lost). NULL-`ad_domain_sid` rows are never grouped — each is kept as its own node (and won't get `SameHostAs`, matching CMBP's "no `ADDomainSID` → no match").
5. **Neither edge is gated** by `--disable-possible-edges`. (Possible clients simply may or may not exist; the builders operate on whatever client devices survive dedup.)
6. **Excluded** (not ported): the `Host`-node logic at [ps1:2341-2373](../../../ConfigManBearPig.ps1#L2341), and the MSSQL / `SCCM_AssignAllPermissions` block at [ps1:1911-1940](../../../ConfigManBearPig.ps1#L1911) (Stage 5 / already built in Stage 3). The stale `# Merge … with the same dNSHostName` comment at `:2271` is wrong — the code matches on `ADDomainSID`; the port follows the **code**.

### Edge `collection_source` provenance tags (Stage 4)
| Edge kind | `collection_source` | CMBP line |
|---|---|---|
| `LocalAdminRequired` | `['SCCM_Invoke-PostProcessing']` | [:1892](../../../ConfigManBearPig.ps1#L1892)/[:1902](../../../ConfigManBearPig.ps1#L1902) |
| `SameHostAs` | `['SCCM_Invoke-PostProcessing']` (decision 2; CMBP set none at [:2318-2319](../../../ConfigManBearPig.ps1#L2318)) | n/a |

---

## File Structure

| File | Responsibility |
|---|---|
| `src/openhound_sccm/kinds/edges.py` | **modify** — add `SAME_HOST_AS` + `LOCAL_ADMIN_REQUIRED` constants. `TRAVERSABLE_EDGE_KINDS` already contains both string values (no change). |
| `src/openhound_sccm/transforms.py` | **modify** — (0) rename `possible` → `is_confirmed_active_client` + invert across `_node_client_device`/`_node_client_device_possible`/`_edge_has_client`; (B) resolve real-client `ad_domain_sid` inside `_enrich_client_device`; (C) new `_dedup_client_device`; (D) new `_edge_same_host`; (E) new `_edge_local_admin_required`; wire all into `transforms()`. Update stale docstrings. |
| `src/openhound_sccm/graph.py` | **modify** (Phase 0) — rename `SCCMClientDeviceProperties.possible` → `is_confirmed_active_client` ([graph.py:221](../../../src/openhound_sccm/graph.py#L221)). |
| `src/openhound_sccm/models/sccm_client_device.py` | **modify** (Phase 0 + F1) — rename the `possible` field + emission to `is_confirmed_active_client`; reword the stale module docstring (`possible`/`ad_domain_sid` are no longer "placeholders"). |
| `README.md` | **modify** — Edge Reference: add `SameHostAs` + `LocalAdminRequired` rows. |
| `ARCHITECTURE.md` | **modify** — preproc/convert section: note the client-device dedup (real+possible merge by `ad_domain_sid`, before edges) as a new preproc behavior. |
| `docs/superpowers/plans/2026-06-29-sccm-preproc-convert-stage4-validation.md` | **create** — code-tour validation harness. |
| `tests/kinds_edges_test.py` | **modify** — assert the two new constants + their traversable membership. |
| `tests/node_client_device_test.py` · `node_client_device_possible_test.py` · `sccm_client_device_test.py` | **modify** (Phase 0) — rename `possible` → `is_confirmed_active_client` in queries/asserts (inverted values); add the model property-name test. |
| `tests/enrich_client_device_ad_domain_sid_test.py` | **create** — real-client `ad_domain_sid` resolution + possible-client preservation. |
| `tests/dedup_client_device_test.py` | **create** — real+possible merge, survivor selection, array union, NULL-sid rows kept. |
| `tests/edge_same_host_test.py` | **create** — both directions; real + possible. |
| `tests/edge_local_admin_required_test.py` | **create** — site-server mesh, non-secondary filter, no self-edge, multi-site-server bidirectionality. |

**Convert registry (unchanged):** `main.py` `NODE_SPECS`/`EDGE_SPECS` are not touched — `EDGE_SPECS = [("graph_edges", GraphEdge)]` already emits `SameHostAs`/`LocalAdminRequired`, and no new node *tables* are introduced (dedup rewrites `node_client_device` in place; `ad_domain_sid` is already a column already mapped to `ADDomainSID` by [`SCCMClientDevice`](../../../src/openhound_sccm/models/sccm_client_device.py#L97)).

---

# Phase 0 — Rename the client-device confirmation flag (`possible` → `is_confirmed_active_client`)

The port-added boolean on SCCM_ClientDevice is reframed (grilled 2026-06-29): `possible` (true = inferred / CmRcService-SPN client) becomes **`is_confirmed_active_client`** (true = a confirmed, real SCCM-managed client) — the **logical inverse**. This is a pure rename + polarity flip; **no** new activity/recency computation. The `--disable-possible-edges` CLI flag and the `_node_client_device_possible` / `_read_disable_possible` "possible-edges" feature naming are a **separate concept and stay unchanged**. The dedup (Phase C) orders on this flag, so the rename lands first.

### Task 0.1: Rename + invert the column in `transforms.py`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — `_node_client_device` (col decl, real-client value, coalesce), `_node_client_device_possible` (inferred-client value), `_edge_has_client` (collection_source CASE).
- Test: `tests/node_client_device_test.py`, `tests/node_client_device_possible_test.py`

**Interfaces:**
- Produces: `node_client_device.is_confirmed_active_client` (BOOLEAN; `true` = real, `false` = inferred). Consumed by `_dedup_client_device` (Phase C) and `SCCMClientDevice` (Task 0.2). The old `possible` column no longer exists.

- [ ] **Step 1: Update the two existing tests to the new name + inverted values.**

In `tests/node_client_device_test.py`, replace lines 71-72:

```python
    rows = con.execute("SELECT smsid, name, resource_id_str, is_confirmed_active_client FROM sccm.node_client_device ORDER BY smsid").fetchall()
    assert rows == [("GUID-1", "WS01", "7@PS1", True)]
```

In `tests/node_client_device_possible_test.py`, replace the query/assert in `test_possible_client_emitted_when_enabled` (lines 18-20):

```python
    rows = con.execute("SELECT smsid, is_confirmed_active_client, ad_domain_sid, root_site_code "
                       "FROM sccm.node_client_device WHERE NOT is_confirmed_active_client").fetchall()
    assert rows == [("S-1-5-21-1-2-3-1104@CAS", False, "S-1-5-21-1-2-3-1104", "CAS")]
```

and the query in `test_possible_client_suppressed_when_disabled` (line 29):

```python
    cnt = con.execute("SELECT count(*) FROM sccm.node_client_device WHERE NOT is_confirmed_active_client").fetchone()[0]
```

(The function names and the `disable=`/`collection_settings` plumbing are the `--disable-possible-edges` *feature* — leave them as-is.)

- [ ] **Step 2: Run to verify failure**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_client_device_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_client_device_possible_test.py -v`
Expected: FAIL with a DuckDB Binder Error — column `is_confirmed_active_client` does not exist.

- [ ] **Step 3: Rename + invert in `transforms.py` (5 spots).**
  - In `_node_client_device`, the column declaration ([transforms.py:1708](../../../src/openhound_sccm/transforms.py#L1708)): `"possible BOOLEAN, ad_domain_sid VARCHAR)"` → `"is_confirmed_active_client BOOLEAN, ad_domain_sid VARCHAR)"`.
  - The real-client INSERT ([:1740](../../../src/openhound_sccm/transforms.py#L1740)): `f"false AS possible, NULL AS ad_domain_sid "` → `f"true AS is_confirmed_active_client, NULL AS ad_domain_sid "`.
  - The coalesce ([:1760](../../../src/openhound_sccm/transforms.py#L1760)): `f"bool_or(possible) AS possible, ..."` → `f"bool_or(is_confirmed_active_client) AS is_confirmed_active_client, ..."` (any-source-confirmed wins; the rest of the line is unchanged).
  - In `_node_client_device_possible`, the inferred-client INSERT ([:1788](../../../src/openhound_sccm/transforms.py#L1788)): `f"true AS possible, upper(object_sid) AS ad_domain_sid, ..."` → `f"false AS is_confirmed_active_client, upper(object_sid) AS ad_domain_sid, ..."`.
  - In `_edge_has_client`, the collection_source CASE ([:2350-2351](../../../src/openhound_sccm/transforms.py#L2350)) — swap the branches and invert the predicate (preserves: real → AdminService, inferred → LDAP):

```python
        f"CASE WHEN coalesce(is_confirmed_active_client, true) THEN ['AdminService-ClientDevices'] "
        f"     ELSE ['LDAP-CmRcService'] END AS collection_source "
```

  Update the `_edge_has_client` docstring line that says "Possible-client rows … carry site_code='root'" to refer to "inferred-client rows" (cosmetic, keeps the comment honest).

- [ ] **Step 4: Run to verify pass**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_client_device_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_client_device_possible_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_has_client_test.py -v`
Expected: PASS.

- [ ] **Step 5: Green-test checkpoint** — do NOT `git add`/`commit`.

### Task 0.2: Rename the model field + graph property

**Files:**
- Modify: `src/openhound_sccm/graph.py` — `SCCMClientDeviceProperties.possible` ([graph.py:221](../../../src/openhound_sccm/graph.py#L221)).
- Modify: `src/openhound_sccm/models/sccm_client_device.py` — field ([:46](../../../src/openhound_sccm/models/sccm_client_device.py#L46)) + emission ([:96](../../../src/openhound_sccm/models/sccm_client_device.py#L96)).
- Test: `tests/sccm_client_device_test.py`

**Interfaces:**
- Consumes: `node_client_device.is_confirmed_active_client` (Task 0.1).
- Produces: `SCCMClientDeviceProperties.is_confirmed_active_client` on the emitted node (the BloodHound entity-panel key). The old `possible` field no longer exists.

- [ ] **Step 1: Write the failing test** — append to `tests/sccm_client_device_test.py`:

```python
def test_client_device_node_exposes_is_confirmed_active_client():
    from openhound_sccm.models.sccm_client_device import SCCMClientDevice
    real = SCCMClientDevice(smsid="GUID:ABC", is_confirmed_active_client=True, root_site_code="PS1")
    inferred = SCCMClientDevice(smsid="S-1-5-21-1-2-3-1@PS1", is_confirmed_active_client=False, root_site_code="PS1")
    assert real.as_node.properties.is_confirmed_active_client is True
    assert inferred.as_node.properties.is_confirmed_active_client is False
```

- [ ] **Step 2: Run to verify failure**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/sccm_client_device_test.py::test_client_device_node_exposes_is_confirmed_active_client -v`
Expected: FAIL — `extra="ignore"` drops the unknown kwarg and `SCCMClientDeviceProperties` has no `is_confirmed_active_client` attribute (`AttributeError`).

- [ ] **Step 3: Rename the field + property.**
  - In `graph.py:221`: `possible: bool = field(default=False, kw_only=True)  # port-added (no CMBP key)` → `is_confirmed_active_client: bool = field(default=False, kw_only=True)  # port-added (no CMBP key): real SCCM client vs SPN-inferred`.
  - In `sccm_client_device.py:46`: `possible: bool = False` → `is_confirmed_active_client: bool = False`.
  - In `sccm_client_device.py:96`: `possible=self.possible,` → `is_confirmed_active_client=self.is_confirmed_active_client,`.

- [ ] **Step 4: Run to verify pass**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/sccm_client_device_test.py -v`
Expected: PASS (the new test + the existing client-device node tests).

- [ ] **Step 5: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase A — Edge-kind constants

### Task A1: Add `SAME_HOST_AS` and `LOCAL_ADMIN_REQUIRED` constants

**Files:**
- Modify: `src/openhound_sccm/kinds/edges.py`
- Test: `tests/kinds_edges_test.py`

**Interfaces:**
- Produces: `edges.SAME_HOST_AS == "SameHostAs"`, `edges.LOCAL_ADMIN_REQUIRED == "LocalAdminRequired"` (consumed by `_edge_same_host` / `_edge_local_admin_required` in Phase D/E).

- [ ] **Step 1: Write the failing test** — append to `tests/kinds_edges_test.py`:

```python
def test_stage4_edge_kind_values():
    assert ek.SAME_HOST_AS == "SameHostAs"
    assert ek.LOCAL_ADMIN_REQUIRED == "LocalAdminRequired"


def test_stage4_edges_are_traversable():
    # Both are traversable per CMBP :2216-2249 (already in the frozenset by string).
    assert ek.SAME_HOST_AS in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.LOCAL_ADMIN_REQUIRED in ek.TRAVERSABLE_EDGE_KINDS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/kinds_edges_test.py::test_stage4_edge_kind_values -v`
Expected: FAIL with `AttributeError: module 'openhound_sccm.kinds.edges' has no attribute 'SAME_HOST_AS'`

- [ ] **Step 3: Add the constants** — in `src/openhound_sccm/kinds/edges.py`, after the Stage-3 block (before the `TRAVERSABLE_EDGE_KINDS` definition):

```python
# Stage 4 edge kinds (host correlation + local-admin mesh)
SAME_HOST_AS = "SameHostAs"
LOCAL_ADMIN_REQUIRED = "LocalAdminRequired"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/kinds_edges_test.py -v`
Expected: PASS (all tests in the file, including the two new ones)

- [ ] **Step 5: Green-test checkpoint** — do NOT `git add`/`commit`. Confirm green and proceed.

---

# Phase B — Resolve real-client `ad_domain_sid` (the SameHostAs join key)

CMBP enriches the SMSID-keyed client device with `ADDomainSID = $device.SID` in a *second* `Upsert-Node` from `SMS_R_System`, keyed by `SMSUniqueIdentifier` ([ps1:7388-7392](../../../ConfigManBearPig.ps1#L7388-L7392)). The port folds this into `_enrich_client_device`: build a `smsid → SID` map from `r_system`, then `coalesce(existing ad_domain_sid, resolved)` so the possible-client value (set in `_node_client_device_possible`) is preserved and the real-client NULL is filled.

### Task B1: Resolve real-client `ad_domain_sid` from `SMS_R_System`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — `_enrich_client_device` ([transforms.py:1466](../../../src/openhound_sccm/transforms.py#L1466))
- Test: `tests/enrich_client_device_ad_domain_sid_test.py`

**Interfaces:**
- Consumes: `node_client_device` (columns incl. `smsid`, `ad_domain_sid`, `possible`, `collection_ids`, `collection_names`), `adminservice_r_system`/`wmi_r_system` (`sms_unique_identifier`, `sid`, `obsolete`).
- Produces: `node_client_device.ad_domain_sid` populated for real clients (`upper(r_system.sid)`), possible-client values unchanged. (Consumed by `_dedup_client_device` and `_edge_same_host`.)

- [ ] **Step 1: Write the failing test** — create `tests/enrich_client_device_ad_domain_sid_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _hierarchy(con):
    # Standalone primary site PS1 -> root_site_code = 'PS1'.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_real_client_ad_domain_sid_resolved_from_r_system():
    """A real client device's ad_domain_sid is filled from SMS_R_System.SID,
    matched on SMSUniqueIdentifier == smsid (CMBP :7388)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'GUID:ABC' AS sms_unique_identifier, "
        "16777220 AS resource_id, 'PS1' AS source_site_code, false AS obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'GUID:ABC' AS smsid, 'HOST1' AS name, 'PS1' AS site_code, "
        "16777220 AS resource_id, true AS is_client, false AS is_obsolete"
    )
    transforms(con)
    sid = con.execute(
        "SELECT ad_domain_sid FROM sccm.node_client_device WHERE smsid = 'GUID:ABC'"
    ).fetchone()[0]
    assert sid == "S-1-5-21-1-2-3-1104"


def test_possible_client_ad_domain_sid_preserved():
    """A possible client (no r_system match) keeps the ad_domain_sid set at creation
    (= upper(object_sid)); the r_system resolution must not overwrite it."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'HOST2' AS name"
    )
    transforms(con)
    sid = con.execute(
        "SELECT ad_domain_sid FROM sccm.node_client_device "
        "WHERE smsid = 'S-1-5-21-1-2-3-1200@PS1'"
    ).fetchone()[0]
    assert sid == "S-1-5-21-1-2-3-1200"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/enrich_client_device_ad_domain_sid_test.py -v`
Expected: `test_real_client_ad_domain_sid_resolved_from_r_system` FAILS (`ad_domain_sid` is `None`); `test_possible_client_ad_domain_sid_preserved` passes (already works).

- [ ] **Step 3: Implement** — edit `_enrich_client_device` in `src/openhound_sccm/transforms.py`. Immediately after the `_devcoll` temp-table block (just before the final `CREATE OR REPLACE TABLE … node_client_device AS SELECT d.* …`), add a `smsid → SID` map built from `r_system`:

```python
    # Real-client ADDomainSID (CMBP :7388-7392): SMS_R_System stamps the AD computer
    # SID onto the existing SMSID-keyed client device. Build a smsid -> SID map here,
    # keyed on SMSUniqueIdentifier == smsid (both uppercased). Obsolete r_system rows
    # are skipped (they keep stale duplicate machine records).
    con.execute("CREATE OR REPLACE TEMP TABLE _dev_sid (smsid VARCHAR, sid VARCHAR)")
    for _rs in ("adminservice_r_system", "wmi_r_system"):
        _ensure_columns(con, schema, _rs, {"sms_unique_identifier": "VARCHAR", "sid": "VARCHAR", "obsolete": "BOOLEAN"})
        _safe(con, f"_dev_sid<-{_rs}",
              f"INSERT INTO _dev_sid "
              f"SELECT upper(sms_unique_identifier), upper(sid) "
              f"FROM {schema}.{_rs} "
              f"WHERE sms_unique_identifier IS NOT NULL AND sid IS NOT NULL "
              f"  AND NOT coalesce(obsolete, false)")
```

Then change the final rebuild's projection from `SELECT d.*,` to a `* REPLACE` that fills only the NULL (real-client) `ad_domain_sid` from the map:

```python
    # Rebuild node_client_device with SID columns and collection list columns appended.
    # ad_domain_sid: keep the possible-client value already set; fill real-client NULLs
    # from _dev_sid (CMBP :7388). REPLACE rewrites only that one column in d.*.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS SELECT d.* REPLACE ("
        f"  coalesce(d.ad_domain_sid, "
        f"           (SELECT s.sid FROM _dev_sid s WHERE s.smsid = d.smsid LIMIT 1)) AS ad_domain_sid"
        f"), "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.primary_user_name)) LIMIT 1) AS primary_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.current_logon_user_name)) LIMIT 1) AS current_logon_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.ad_last_logon_user_name)) LIMIT 1) AS ad_last_logon_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.last_mp_server_name)) LIMIT 1) AS last_reported_mp_server_sid, "
        f"coalesce((SELECT list_distinct(array_agg(coll_id)) FROM _devcoll x WHERE x.rid_key = d.resource_id_str), "
        f"         CAST([] AS VARCHAR[])) AS collection_ids, "
        f"coalesce((SELECT list_distinct(array_agg(coll_name)) FROM _devcoll x WHERE x.rid_key = d.resource_id_str), "
        f"         CAST([] AS VARCHAR[])) AS collection_names "
        f"FROM {schema}.node_client_device d"
    )
    logger.info("node_client_device resolved SIDs (incl. ad_domain_sid) + collection lists enriched in schema %r", schema)
```

> **Note:** the only change to the original rebuild is the `d.* REPLACE (...)` wrapper and the log line; the four `*_sid` subqueries and the two collection subqueries are unchanged from the current code.

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/enrich_client_device_ad_domain_sid_test.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Regression check** — the existing client-device tests must still pass (they assert other enriched columns):

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_client_device_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_client_device_possible_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/sccm_client_device_test.py -v`
Expected: PASS

- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase C — Duplicate-ClientDevice merge (`_dedup_client_device`)

CMBP merges client devices that share an `ADDomainSID`, preferring the authoritative node, unioning array properties, and dropping the rest ([ps1:2269-2311](../../../ConfigManBearPig.ps1#L2269-L2311)). In the port the survivor is the **real** client (`possible = false`) over the possible client; because the possible client is a strict subset, the merge reduces to "keep the survivor row, union the array columns across the group." This runs **before** the edge builders (decision 1).

### Task C1: Add `_dedup_client_device` and wire it after `_enrich_client_device`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_dedup_client_device`; call it in `transforms()` immediately after `_enrich_client_device`.
- Test: `tests/dedup_client_device_test.py`

**Interfaces:**
- Consumes: `node_client_device` with `ad_domain_sid` resolved (Task B1).
- Produces: `node_client_device` collapsed to one row per non-null `ad_domain_sid` (survivor = real, arrays unioned); NULL-`ad_domain_sid` rows untouched. (Consumed by all downstream edge builders and `_edge_same_host`.)

- [ ] **Step 1: Write the failing test** — create `tests/dedup_client_device_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _standalone_primary(con):
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_real_and_possible_twin_merge_to_real():
    """A real client (smsid GUID:ABC, ad_domain_sid resolved to S-...-1104) and a
    possible client (object_sid S-...-1104) share an ad_domain_sid -> one survivor,
    the real one (possible=false)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'GUID:ABC' AS sms_unique_identifier, "
        "16777220 AS resource_id, 'PS1' AS source_site_code, false AS obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'GUID:ABC' AS smsid, 'HOST1' AS name, 'PS1' AS site_code, "
        "16777220 AS resource_id, true AS is_client, false AS is_obsolete"
    )
    # possible client for the same machine SID, found via CmRcService SPN
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'HOST1' AS name"
    )
    transforms(con)
    rows = con.execute(
        "SELECT smsid, is_confirmed_active_client FROM sccm.node_client_device "
        "WHERE ad_domain_sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "GUID:ABC"
    assert rows[0][1] is True


def test_null_ad_domain_sid_rows_are_kept_independently():
    """Two real clients with no resolvable SID (no r_system match) keep both rows —
    NULL ad_domain_sid must never collapse distinct devices."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT * FROM (VALUES "
        "('GUID:AAA', 'HOSTA', 'PS1', 1, true, false), "
        "('GUID:BBB', 'HOSTB', 'PS1', 2, true, false)"
        ") AS t(smsid, name, site_code, resource_id, is_client, is_obsolete)"
    )
    transforms(con)
    n = con.execute(
        "SELECT count(*) FROM sccm.node_client_device WHERE ad_domain_sid IS NULL"
    ).fetchone()[0]
    assert n == 2


def test_collection_arrays_union_into_survivor():
    """When a real client is the survivor, its collection_ids survive the dedup."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'GUID:ABC' AS sms_unique_identifier, "
        "16777220 AS resource_id, 'PS1' AS source_site_code, false AS obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'GUID:ABC' AS smsid, 'HOST1' AS name, 'PS1' AS site_code, "
        "16777220 AS resource_id, true AS is_client, false AS is_obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_collections AS SELECT "
        "'PS100001' AS collection_id, 'All Desktops' AS name"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_collection_members AS SELECT "
        "'PS100001' AS collection_id, 16777220 AS resource_id, 'PS1' AS site_code"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'HOST1' AS name"
    )
    transforms(con)
    coll = con.execute(
        "SELECT collection_ids FROM sccm.node_client_device "
        "WHERE ad_domain_sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchone()[0]
    assert "PS100001@PS1" in coll
```

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/dedup_client_device_test.py -v`
Expected: `test_real_and_possible_twin_merge_to_real` FAILS (`len(rows) == 2` — both the real and possible rows survive without dedup). The other two pass incidentally; all three must pass after the fix.

- [ ] **Step 3: Implement `_dedup_client_device`** — add this function to `src/openhound_sccm/transforms.py` (place it directly after `_enrich_client_device`, before `_enrich_site_lists`):

```python
def _dedup_client_device(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Collapse SCCM_ClientDevice rows that share an ad_domain_sid (CMBP ps1:2269-2311).

    CMBP merges duplicate client-device nodes found with the same ADDomainSID,
    preferring the authoritative node and unioning array properties. In the port the
    duplicate is a real client (is_confirmed_active_client=true, id=smsid) and its
    inferred twin (is_confirmed_active_client=false, id=<SID>@root) discovered via
    CmRcService SPN. The inferred row is a strict subset, so the merge keeps the real
    survivor's scalars and unions the array columns across the whole ad_domain_sid group.

    Runs BEFORE the edge builders (locked decision 1), so every edge is built from the
    deduped table and references only survivors — no graph_edges rewrite is needed.

    NULL ad_domain_sid rows (real clients whose SID could not be resolved) are never
    grouped: the composite partition key isolates each by smsid, so distinct unresolved
    devices are preserved (and simply won't get a SameHostAs edge — matches CMBP).
    """
    before = con.execute(f"SELECT count(*) FROM {schema}.node_client_device").fetchone()[0]
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS "
        f"WITH ranked AS ("
        f"  SELECT d.* EXCLUDE (collection_ids, collection_names), "
        f"    list_distinct(flatten(array_agg(d.collection_ids)  OVER w)) AS collection_ids, "
        f"    list_distinct(flatten(array_agg(d.collection_names) OVER w)) AS collection_names, "
        # Survivor = confirmed real client first (is_confirmed_active_client DESC), then lowest smsid.
        f"    row_number() OVER ("
        f"      PARTITION BY d.ad_domain_sid, (CASE WHEN d.ad_domain_sid IS NULL THEN d.smsid END) "
        f"      ORDER BY d.is_confirmed_active_client DESC, d.smsid ASC) AS _rn "
        f"  FROM {schema}.node_client_device d "
        # Same composite key: groups real+possible twins by ad_domain_sid, but isolates
        # every NULL-ad_domain_sid row by its (unique) smsid so they are never merged.
        f"  WINDOW w AS (PARTITION BY d.ad_domain_sid, (CASE WHEN d.ad_domain_sid IS NULL THEN d.smsid END))"
        f") "
        f"SELECT * EXCLUDE (_rn) FROM ranked WHERE _rn = 1"
    )
    after = con.execute(f"SELECT count(*) FROM {schema}.node_client_device").fetchone()[0]
    if before != after:
        logger.info("node_client_device dedup: merged %d duplicate client-device row(s)", before - after)
    else:
        logger.debug("node_client_device dedup: no duplicate ad_domain_sid rows found")
```

- [ ] **Step 4: Wire it into `transforms()`** — in `src/openhound_sccm/transforms.py`, in the `transforms()` body, add the call immediately after the `_enrich_client_device(con, schema)` line:

```python
    _enrich_client_device(con, schema)
    # Stage 4: collapse real+possible ClientDevice twins by ad_domain_sid BEFORE edges,
    # so every edge builder references survivors (no graph_edges rewrite needed).
    _dedup_client_device(con, schema)
    _enrich_site_lists(con, schema)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/dedup_client_device_test.py -v`
Expected: PASS (all three)

- [ ] **Step 6: Regression check** — re-run the client-device and HasClient suites (dedup now runs before `_edge_has_client`):

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_client_device_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_client_device_possible_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_has_client_test.py -v`
Expected: PASS

- [ ] **Step 7: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase D — `SameHostAs` edges (`_edge_same_host`)

Bidirectional Computer ↔ ClientDevice, joined on `node_computer.sid == node_client_device.ad_domain_sid` ([ps1:2314-2320](../../../ConfigManBearPig.ps1#L2314-L2320)). Two rows per match.

### Task D1: Add `_edge_same_host` and wire it into `transforms()`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_edge_same_host`; call it in `transforms()` after `_edge_assign_all_permissions` (before `_graph_edges_dedup`).
- Test: `tests/edge_same_host_test.py`

**Interfaces:**
- Consumes: `node_computer.sid`, deduped `node_client_device.ad_domain_sid`/`smsid`; `edges.SAME_HOST_AS`.
- Produces: `graph_edges` rows `kind='SameHostAs'` in both directions.

- [ ] **Step 1: Write the failing test** — create `tests/edge_same_host_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def _standalone_primary(con):
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_same_host_as_both_directions_for_real_client():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    # r_system gives both the Computer node (sid) and the client device's ad_domain_sid.
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, 'GUID:ABC' AS sms_unique_identifier, "
        "16777220 AS resource_id, 'PS1' AS source_site_code, false AS obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'GUID:ABC' AS smsid, 'HOST1' AS name, 'PS1' AS site_code, "
        "16777220 AS resource_id, true AS is_client, false AS is_obsolete"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SameHostAs'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-1104", "GUID:ABC") in edges
    assert ("GUID:ABC", "S-1-5-21-1-2-3-1104") in edges


def test_same_host_as_for_possible_client_without_twin():
    """A possible client with no real twin still links to its Computer node."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    # ldap_cmrc_devices creates BOTH a Computer node (sid) and a possible client device.
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'HOST2' AS name"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SameHostAs'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-1200", "S-1-5-21-1-2-3-1200@PS1") in edges
    assert ("S-1-5-21-1-2-3-1200@PS1", "S-1-5-21-1-2-3-1200") in edges


def test_same_host_as_collection_source_tagged():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _standalone_primary(con)
    con.execute(
        "CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
        "'S-1-5-21-1-2-3-1200' AS object_sid, 'HOST2' AS name"
    )
    transforms(con)
    src = con.execute(
        "SELECT collection_source FROM sccm.graph_edges WHERE kind = 'SameHostAs' LIMIT 1"
    ).fetchone()[0]
    assert src == ["SCCM_Invoke-PostProcessing"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_same_host_test.py -v`
Expected: FAIL (no `SameHostAs` rows — builder doesn't exist).

- [ ] **Step 3: Implement `_edge_same_host`** — add to `src/openhound_sccm/transforms.py` (place after `_edge_assign_all_permissions`, before `_graph_edges_dedup`):

```python
def _edge_same_host(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer <-> SCCM_ClientDevice SameHostAs, both directions (CMBP ps1:2314-2320).

    Join the Computer node id (sid) to the deduped client device's ad_domain_sid.
    Two rows per match. CMBP set no collectionSource; the port tags
    'SCCM_Invoke-PostProcessing' for entity-panel provenance (decision 2).
    """
    from .kinds.edges import SAME_HOST_AS
    _safe(con, "edge_same_host",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT computer.sid AS start_id, dev.smsid AS end_id, "
          f"'{SAME_HOST_AS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.node_computer computer "
          f"JOIN {schema}.node_client_device dev ON dev.ad_domain_sid = computer.sid "
          f"WHERE computer.sid IS NOT NULL AND dev.smsid IS NOT NULL "
          f"UNION ALL "
          f"SELECT dev.smsid AS start_id, computer.sid AS end_id, "
          f"'{SAME_HOST_AS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.node_computer computer "
          f"JOIN {schema}.node_client_device dev ON dev.ad_domain_sid = computer.sid "
          f"WHERE computer.sid IS NOT NULL AND dev.smsid IS NOT NULL")
```

- [ ] **Step 4: Wire it into `transforms()`** — add the call after `_edge_assign_all_permissions(con, schema)`:

```python
    _edge_assign_all_permissions(con, schema)
    # Stage 4 edges.
    _edge_same_host(con, schema)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_same_host_test.py -v`
Expected: PASS (all three)

- [ ] **Step 6: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase E — `LocalAdminRequired` edges (`_edge_local_admin_required`)

For each non-secondary site, every computer hosting `SMS Site Server@<site>` is local-admin on every *other* computer hosting any role at that site ([ps1:1882-1909](../../../ConfigManBearPig.ps1#L1882-L1909)). The two CMBP branches collapse to one set-based rule: **start = site-server computers; end = any site-system computer at the same site; start ≠ end.** (This includes site-server → site-server in both directions when a site has multiple site servers.)

### Task E1: Add `_edge_local_admin_required` and wire it into `transforms()`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — add `_edge_local_admin_required`; call it after `_edge_same_host`.
- Test: `tests/edge_local_admin_required_test.py`

**Interfaces:**
- Consumes: `node_computer.sid`/`site_system_roles` (a `VARCHAR[]` of `"Role@SiteCode"`), `site_hierarchy.site_code`/`site_type`; `edges.LOCAL_ADMIN_REQUIRED`.
- Produces: `graph_edges` rows `kind='LocalAdminRequired'`, site-server → other-site-system.

- [ ] **Step 1: Write the failing test** — create `tests/edge_local_admin_required_test.py`:

```python
import duckdb
from openhound_sccm.transforms import transforms


def test_site_server_is_local_admin_on_other_site_systems():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    # Site server + a management point, both site systems at PS1.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-100', 'SITESRV', '[\"SMS Site Server@PS1\"]', true), "
        "('S-1-5-21-1-2-3-200', 'MP', '[\"SMS Management Point@PS1\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'LocalAdminRequired'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-200") in edges      # site server -> MP
    assert ("S-1-5-21-1-2-3-200", "S-1-5-21-1-2-3-100") not in edges  # MP is NOT admin on the server
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-100") not in edges  # no self-edge


def test_no_local_admin_required_for_secondary_site():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2), ('SEC', 'PS1', 1)) AS t(site_code, parent_site_code, site_type)"
    )
    # A site server + DP at the SECONDARY site SEC (site_type=1) -> excluded.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-300', 'SECSRV', '[\"SMS Site Server@SEC\"]', true), "
        "('S-1-5-21-1-2-3-400', 'SECDP', '[\"SMS Distribution Point@SEC\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    n = con.execute(
        "SELECT count(*) FROM sccm.graph_edges WHERE kind = 'LocalAdminRequired'"
    ).fetchone()[0]
    assert n == 0


def test_multiple_site_servers_are_mutually_local_admin():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-100', 'SRV1', '[\"SMS Site Server@PS1\"]', true), "
        "('S-1-5-21-1-2-3-101', 'SRV2', '[\"SMS Site Server@PS1\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'LocalAdminRequired'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-101") in edges
    assert ("S-1-5-21-1-2-3-101", "S-1-5-21-1-2-3-100") in edges
```

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_local_admin_required_test.py -v`
Expected: FAIL (no `LocalAdminRequired` rows — builder doesn't exist).

- [ ] **Step 3: Implement `_edge_local_admin_required`** — add to `src/openhound_sccm/transforms.py` (after `_edge_same_host`, before `_graph_edges_dedup`):

```python
def _edge_local_admin_required(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site server -> every other site system in the same non-secondary site
    (CMBP ps1:1882-1909).

    CMBP's two branches (non-server site systems seen from the server, and the
    server iterating its peers) collapse to one set-based rule: start = computers
    hosting 'SMS Site Server@<site>'; end = computers hosting ANY role at that site;
    start != end. Site servers are thus mutually local-admin when a site has more
    than one. Sites are restricted to non-secondary (site_type != 1), matching
    CMBP's `Type -ne "Secondary Site"`.

    Site codes are extracted from the 'Role@SiteCode' strings the same way CMBP did
    (everything after the first '@'); both sides are uppercased for a robust join.
    """
    from .kinds.edges import LOCAL_ADMIN_REQUIRED
    _safe(con, "edge_local_admin_required",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"WITH roles AS ("
          f"  SELECT c.sid, role, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
          f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
          f"  WHERE c.sid IS NOT NULL AND role IS NOT NULL AND role LIKE '%@%'"
          f"), "
          f"nonsec AS ("
          f"  SELECT upper(site_code) AS site FROM {schema}.site_hierarchy "
          f"  WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL"
          f"), "
          f"site_servers AS ("
          f"  SELECT DISTINCT sid, site FROM roles WHERE role LIKE 'SMS Site Server@%' AND site != ''"
          f"), "
          f"site_systems AS ("
          f"  SELECT DISTINCT sid, site FROM roles WHERE site != ''"
          f") "
          f"SELECT ss.sid AS start_id, sys.sid AS end_id, "
          f"'{LOCAL_ADMIN_REQUIRED}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM site_servers ss "
          f"JOIN site_systems sys ON ss.site = sys.site AND ss.sid != sys.sid "
          f"JOIN nonsec n ON n.site = ss.site")
```

- [ ] **Step 4: Wire it into `transforms()`** — add the call after `_edge_same_host(con, schema)`:

```python
    _edge_same_host(con, schema)
    _edge_local_admin_required(con, schema)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_local_admin_required_test.py -v`
Expected: PASS (all three)

- [ ] **Step 6: Full-suite regression** — run the entire test suite to confirm Stage 4 broke nothing (dedup re-ordering, new edges):

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/ -q`
Expected: all pass / previously-skipped still skipped / 0 failed.

- [ ] **Step 7: Green-test checkpoint** — do NOT `git add`/`commit`.

---

# Phase F — Docs, comments, and validation harness

### Task F1: Update stale "placeholder" comments

**Files:**
- Modify: `src/openhound_sccm/transforms.py` — `_node_client_device` docstring.
- Modify: `src/openhound_sccm/models/sccm_client_device.py` — module + class docstrings.

- [ ] **Step 1:** In `_node_client_device` ([transforms.py:1690](../../../src/openhound_sccm/transforms.py#L1690)), change the line that calls `possible`/`ad_domain_sid` placeholders to reflect Stage 4 — e.g.:

```python
    """One row per smsid from adminservice/wmi client_devices (real clients only:
    is_client AND NOT is_obsolete). `is_confirmed_active_client` is True here (inferred
    rows are appended by _node_client_device_possible with it False). `ad_domain_sid`
    is NULL here and is resolved from SMS_R_System in _enrich_client_device
    (Stage 4, CMBP :7388).
    ...
```

- [ ] **Step 2:** In `models/sccm_client_device.py` ([:1-9](../../../src/openhound_sccm/models/sccm_client_device.py#L1-L9)), reword the module docstring that calls `possible`/`ad_domain_sid` "placeholder values (False/NULL)": the field is now `is_confirmed_active_client` (renamed in Phase 0) and real clients resolve `ad_domain_sid` (Phase B). (The field/emission code was already changed in Phase 0 — this step is docstring-only.)

- [ ] **Step 3: Confirm the package still imports** (docstring-only edits):

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm python -c "import openhound_sccm.transforms, openhound_sccm.models.sccm_client_device"`
Expected: no output (clean import).

### Task F2: README Edge Reference

**Files:**
- Modify: `README.md` — Edge Reference table.

- [ ] **Step 1:** Add two rows to the Edge Reference table (match the existing column layout — Edge / Start → End / Description / Traversable / Source). Example content:

```markdown
| `SameHostAs` | Computer ↔ SCCM_ClientDevice | The AD computer object and the SCCM client record for the same physical host (matched by the client device's `ADDomainSID`). Emitted in both directions. | Yes | `SCCM_Invoke-PostProcessing` |
| `LocalAdminRequired` | Computer → Computer | A site server requires local-admin rights on every other site system in the same non-secondary site. | Yes | `SCCM_Invoke-PostProcessing` |
```

- [ ] **Step 2:** If the README has a mayyhem.com worked example section for edges, add a one-line Cypher/abuse note for `LocalAdminRequired` consistent with the existing style. (Skip if the section doesn't list per-edge examples — README is code-truth; don't invent structure.)

- [ ] **Step 3:** In the SCCM_ClientDevice **Node Reference**, rename any `possible` property entry to `is_confirmed_active_client` and invert its description (`true` = a confirmed real SCCM-managed client; `false` = an inferred client seen only via a CmRcService remote-control SPN). Skip if the Node Reference doesn't list this property.

### Task F3: ARCHITECTURE.md — note the client-device dedup

**Files:**
- Modify: `ARCHITECTURE.md` — preproc/convert design section.

- [ ] **Step 1:** In the preproc/convert section (the one ARCHITECTURE.md uses for the coalesce/graph_edges design), add a short paragraph: the SCCM_ClientDevice coalesce now runs a **dedup pass** (`_dedup_client_device`) that merges a real client and its possible (CmRcService-SPN-derived) twin sharing an `ad_domain_sid`, keeping the real survivor and unioning array columns. It runs **before** the edge builders so no `graph_edges` rewrite is needed — and record this as the Stage-4 divergence from CMBP's merge-after-edges order. Add a changelog entry if the file keeps one.

- [ ] **Step 2:** Fix any `file:line` references in that section that Stage 4 shifted (the `transforms()` call order changed).

### Task F4: Validation harness (code tour)

**Files:**
- Create: `docs/superpowers/plans/2026-06-29-sccm-preproc-convert-stage4-validation.md`

- [ ] **Step 1:** Write the harness as a code-tour (same style as [`2026-06-24-sccm-preproc-convert-stage3-validation.md`](2026-06-24-sccm-preproc-convert-stage3-validation.md)). It must contain:
  - **In-process driver:** a short script that opens the existing lab `lookup.duckdb` (or runs `transforms()` on the lab raw tree) and inspects the schema.
  - **Breakpoints (exact `file:line`):**
    1. `_enrich_client_device` final rebuild ([transforms.py](../../../src/openhound_sccm/transforms.py)) — inspect a known real client's `ad_domain_sid` (should equal its host SID) and a possible client's (unchanged).
    2. `_dedup_client_device` — compare `node_client_device` row count before/after; confirm a machine that is both a real client and a CmRcService SPN target now has exactly one row (`possible = false`).
    3. `_edge_same_host` — `SELECT * FROM sccm.graph_edges WHERE kind='SameHostAs'`; confirm both directions for a sample host and `collection_source = ['SCCM_Invoke-PostProcessing']`.
    4. `_edge_local_admin_required` — confirm the site server reaches every other PS1 site system, no self-edge, secondary sites excluded.
  - **Black-box smoke check:** the standard loop —
    ```bash
    openhound preprocess sccm <raw> <raw>/lookup.duckdb
    openhound convert sccm <raw>/sccm <graph> --lookup-file <raw>/lookup.duckdb
    ```
    then grep `<graph>/*.json` for `"SameHostAs"` and `"LocalAdminRequired"` and confirm counts match the DuckDB `graph_edges` counts.
  - **What each stop verifies** (link back to this plan's tasks).

- [ ] **Step 2:** This is documentation; no test run. Confirm the file renders (no broken relative links) by spot-checking the paths.

### Task F5: Close-out

- [ ] **Step 1:** Re-run the full suite one final time:

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/ -q`
Expected: 0 failed.

- [ ] **Step 2:** Run the openhound `references/validate-extension.md` checks (ruff/mypy on the changed files) in the isolated env; report any pre-existing findings rather than fixing unrelated code (AGENTS.md surgical-changes rule).

- [ ] **Step 3:** Update gtk ticket `ope-9271` with an `add-note` summarizing what shipped (do NOT close — the user commits/closes after testing). Report to the user that Stage 4 is implementation-complete and awaiting their commit.

---

## Self-Review (completed during planning)

- **Spec coverage (§6 Stage 4):** `SameHostAs` → Phase D; duplicate-client-device merge → Phase C; `LocalAdminRequired` mesh → Phase E; the discovered `ad_domain_sid` prerequisite → Phase B; the `possible` → `is_confirmed_active_client` rename → Phase 0; validation harness → Task F4. ✔
- **Type/name consistency:** `SAME_HOST_AS`/`LOCAL_ADMIN_REQUIRED` (Task A1) are the exact names imported in `_edge_same_host`/`_edge_local_admin_required` (D/E). `_dedup_client_device` (C) consumes `ad_domain_sid` produced by B and orders on `is_confirmed_active_client` produced by Phase 0. `graph_edges` columns `(start_id, end_id, kind, collection_source)` match `_graph_edges_init`. ✔
- **No placeholders:** every code/test step shows complete content; commands include expected output. ✔
- **Decision fidelity:** dedup-before-edges (no rewrite), `SameHostAs` tagged `SCCM_Invoke-PostProcessing`, `ad_domain_sid` via `coalesce(existing, r_system.sid)`, and the pure rename+invert of `possible` → `is_confirmed_active_client` (no recency math) — all match the grilled decisions. ✔
- **Rename completeness:** `possible` (the port-added property) is renamed in `transforms.py` (5 spots), `graph.py:221`, `models/sccm_client_device.py` (field + emission), the README Node Reference, and the three Stage-2/3 tests that reference it; the separate `--disable-possible-edges` / `disable_possible_edges` / `_node_client_device_possible` feature naming is intentionally untouched. ✔
- **Excluded code not ported:** Host node (:2341-2373), MSSQL/AssignAllPermissions block (:1911-1940). ✔

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-06-29-sccm-preproc-convert-stage4.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — a fresh subagent per task with two-stage review between tasks.

**2. Inline Execution** — execute tasks in this session via `superpowers:executing-plans`, batched with checkpoints.

**Which approach?**
