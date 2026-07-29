# SCCM preproc + convert — Stage 6 (Coerce-and-relay possible edges) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three coerce-and-relay **possible edges** (`CoerceAndRelayToAdminService`, `CoerceAndRelayToMSSQL`, `CoerceAndRelayToSMB`) and the synthetic **Authenticated Users** group node in `preproc`, emitting them through the unchanged Convert2-Read-DB pipeline — porting CMBP's `Process-CoerceAndRelayToAdminService` / `…ToMSSQL` / `…ToSMB` and the synthetic Authenticated Users `Upsert-Node`.

**Architecture:** Pure `transforms.py` + `graph.py` + `models/graph_edge.py` + `kinds/edges.py` additions flowing through the existing pipeline — **no new collection, no new node model** (Authenticated Users is a `Group` emitted by the existing `GroupNode`). Each relay is a set-based join over the node tables Stages 1–5 already produced: AdminService joins SMS-Provider × Site-Server computers per site; MSSQL drives off `node_mssql_login` (which already encodes the sysadmin-computer↔server pairing); SMB joins SMB-signing-disabled site systems × Site-Server computers. The synthetic Authenticated Users node is built **lazily** — only for the domains a relay edge actually starts from — and inserted into `node_group` before `_node_backfill`/`_graph_edges_split` so it joins the AD id set and merges with SharpHound's well-known-SID node.

**Tech Stack:** Python 3.13+, `dlt`, `duckdb`, `openhound` (v0.2.x), `pydantic`, `pytest`, `uv`.

**Tracking:** gtk `ope-d820` (links `Ope-o008` "Verify CoerceAndRelayToSMB Lifecycle", `Ope-zaja` "Relay to Management Point"). **Baseline:** post-Stage-5 working tree — `transforms()` ends `… _edge_mssql_db_assign_all → _graph_edges_dedup → _node_backfill → _graph_edges_split`; `graph_edges` is `(start_id, end_id, kind, collection_source VARCHAR[])`; `main.py` uses `SCCM_NODE_SPECS`/`AD_NODE_SPECS`/`SCCM_EDGE_SPECS`/`AD_EDGE_SPECS`. **Spec:** [`../specs/2026-06-16-sccm-preproc-convert-design.md`](../specs/2026-06-16-sccm-preproc-convert-design.md) §6 Stage 6 + inventory §3. **CMBP reference:** `Process-CoerceAndRelayToAdminService` [ps1:6572-6624](../../../ConfigManBearPig.ps1#L6572-L6624); `…ToMSSQL` [ps1:6626-6726](../../../ConfigManBearPig.ps1#L6626-L6726); `…ToSMB` [ps1:6728-6781](../../../ConfigManBearPig.ps1#L6728-L6781); call site (per non-secondary site) [ps1:1948-1962](../../../ConfigManBearPig.ps1#L1948-L1962); synthetic Authenticated Users `Upsert-Node` [ps1:6609](../../../ConfigManBearPig.ps1#L6609)/[:6708](../../../ConfigManBearPig.ps1#L6708)/[:6766](../../../ConfigManBearPig.ps1#L6766); `Upsert-Edge` array-merge [ps1:2155-2158](../../../ConfigManBearPig.ps1#L2155-L2158); traversable allow-list [ps1:2216-2249](../../../ConfigManBearPig.ps1#L2216-L2249).

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Never edit OpenHound core (`openhound/...`). (CLAUDE.md)
- **Do NOT `git add` or `git commit`.** Each task ends at a **green-test checkpoint only** — run the tests, confirm pass, then stop. The user commits after testing. (CLAUDE.md, [[sdd-no-commit-harness]])
- **Validate in the isolated uv env** (already synced from Stage 0–5) — never touch the repo `.venv`:
  `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest <abs test path> -v`. (AGENTS.md)
- **Log every `if`/`else` and `try`/`except` branch** at an appropriate level, or leave a comment. (CLAUDE.md)
- **Edge/node property keys are CMBP-cased on output, snake_case in DuckDB.** New `SCCMRelayEdgeProperties` fields use **ConfigManBearPig.ps1-verbatim casing**: `coercionVictimAndRelayTargetPairs`, `coercionVictimHostnames`. DuckDB columns + model input fields stay snake_case (`coercion_victim_and_relay_target_pairs`, `coercion_victim_hostnames`, `smb_signing_source`). (See [[sccm-property-casing-cmbp]].)
- **Tests live in `sccm/sccm/tests/` as `<name>_test.py`.** Run with the isolated-env pytest targeting `tests/`.
- **No re-collect for Stage 6** — preproc/convert-only; reads the existing lab raw tree.
- **Reuse the existing helpers** in `transforms.py`: `_safe(con, label, sql)` (skips+logs missing tables; takes **no** SQL params — inline literals), `_ensure_columns`, `_arr(col)`, `_root_code`. `domain_environment_id(sid, fallback_domain_sid=None)` lives in `graph.py` and is used by the models.
- **Standard test loop** (collect once, reuse the raw JSONL):
  ```bash
  openhound preprocess sccm <raw> <raw>/lookup.duckdb
  openhound convert sccm <raw>/sccm <graph> --lookup-file <raw>/lookup.duckdb
  # then inspect <graph>/*.json for the three CoerceAndRelay* edges + the AUTHENTICATED USERS group node
  ```

### Locked Stage 6 decisions (grilled with the user 2026-06-30; see [[sccm-stage6-relay-decisions]])

1. **`--disable-possible-edges` = SURGICAL.** Default (flag off) keeps CMBP's "null NTLM/EPA ⇒ assume vulnerable ⇒ emit". With the flag, every assumption tightens to **explicitly confirmed**: NTLM literally `Off` (drop NULL), EPA literally `Off` (drop NULL/assumed), SMB-signing literally `false` (already explicit). Confirmed relay paths survive; speculative ones drop. (CMBP itself only gated the MSSQL-EPA-unknown branch — this is the faithful-but-fixed reading of the spec's Stage 6 validation, which says all three vanish under the flag.)
2. **Authenticated Users node id = `UPPER(<FQDN>)-S-1-5-11`** (SharpHound well-known-SID form, e.g. `MAYYHEM.COM-S-1-5-11`) so it merges with SharpHound-collected AD data — fixes CMBP's as-collected-case id ([ps1:6606](../../../ConfigManBearPig.ps1#L6606)). FQDN derived from the **victim** computer's `dnshostname` (first/host label stripped). `name = AUTHENTICATED USERS@<FQDN-UPPER>`, kinds `Group`+`Base`, `environmentid` = the victim's AD-domain SID (the `fallback_domain_sid`, since `S-1-5-11` has no domain SID). Built lazily — only for domains an actual relay edge starts from.
3. **SMB relay CMBP bug FIXED.** CMBP's traversable allow-list ([ps1:2221](../../../ConfigManBearPig.ps1#L2221)) names `CoerceAndRelayNTLMtoSMB`, but the function ([ps1:6775](../../../ConfigManBearPig.ps1#L6775)) emits `CoerceAndRelayToSMB` — they never match, so CMBP renders the SMB relay non-traversable. The port emits `CoerceAndRelayToSMB` AND makes it traversable, by replacing the dead `CoerceAndRelayNTLMtoSMB` string in `TRAVERSABLE_EDGE_KINDS`. (`CoerceAndRelayToAdminService`/`CoerceAndRelayToMSSQL` are already correct in the set.)
4. **Coercion-context props = port, relay-only.** Add typed `coercion_victim_and_relay_target_pairs VARCHAR[]` + `coercion_victim_hostnames VARCHAR[]` columns to `graph_edges`; array-union them in `_graph_edges_dedup` (CMBP's `Upsert-Edge` merges arrays, [ps1:2155-2158](../../../ConfigManBearPig.ps1#L2155-L2158)); carry them through `_graph_edges_split`. A relay-only `SCCMRelayEdgeProperties(SCCMEdgeProperties)` subclass surfaces `coercionVictimAndRelayTargetPairs`/`coercionVictimHostnames` on the three relay kinds **only**, so the ~33 other edges keep their current clean output.
5. **SMB relay `collectionSource` = add provenance column.** `node_computer` carries no per-source `collection_source`. Add `smb_signing_source VARCHAR[]`, set by the `smb_computers` SELECT (`['SMB-Negotiate']`) and `remoteregistry_computers` SELECT (`['RemoteRegistry-SMBSigningCheck']`), array-unioned in the final GROUP BY; the SMB relay filters it. **Cross-cutting Stage 1 change** ⇒ update the Stage 1 `node_computer` coverage + ARCHITECTURE.md. (AdminService stays the static `['Post-processing']` CMBP passes at [:1955](../../../ConfigManBearPig.ps1#L1955); MSSQL filters `node_mssql_server.collection_source` to the EPA sources, which already exist.)

### Edge inventory (the 3 edges this stage adds to `graph_edges`)

| # | Kind | Start → End | CMBP | NTLM/EPA/SMB gate (default ⇒ flag) | `collection_source` | Extra prop |
|---|---|---|---|---|---|---|
| 1 | `CoerceAndRelayToAdminService` | AuthUsers(site-server domain) → SCCM_Site | [:6615](../../../ConfigManBearPig.ps1#L6615) | provider NTLM null/Off ⇒ explicit `Off` | `['Post-processing']` | `coercionVictimAndRelayTargetPairs` |
| 2 | `CoerceAndRelayToMSSQL` | AuthUsers(sysadmin-computer domain) → MSSQL_Login | [:6717](../../../ConfigManBearPig.ps1#L6717) | host NTLM null/Off **and** server EPA null/Off ⇒ both explicit `Off` | server EPA sources | `coercionVictimAndRelayTargetPairs` |
| 3 | `CoerceAndRelayToSMB` | AuthUsers(site-server domain) → Computer (vuln. site system) | [:6775](../../../ConfigManBearPig.ps1#L6775) | target `smb_signing_required=false` (explicit) **and** NTLM null/Off ⇒ explicit `Off` | target `smb_signing_source` | `coercionVictimHostnames` |

> All three relay edges route to the **AD payload** (`graph_edges_ad`): each starts at the Authenticated Users node, which is an AD node (`node_group`). No change to `_graph_edges_split`'s routing logic is needed beyond carrying the two new columns through it.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/openhound_sccm/kinds/edges.py` | **modify** — add 3 relay edge-kind constants; fix `TRAVERSABLE_EDGE_KINDS` (`CoerceAndRelayNTLMtoSMB` → `CoerceAndRelayToSMB`). |
| `src/openhound_sccm/graph.py` | **modify** — add `SCCMRelayEdgeProperties(SCCMEdgeProperties)` with the two CMBP-cased coercion list fields. |
| `src/openhound_sccm/models/graph_edge.py` | **modify** — read the two coercion columns; emit `SCCMRelayEdgeProperties` for relay kinds, base `SCCMEdgeProperties` otherwise. |
| `src/openhound_sccm/transforms.py` | **modify** — add the `_authed_users_id` SQL helper; add `coercion_*` columns in `_graph_edges_init`; carry them in `_graph_edges_dedup`/`_graph_edges_split`; add `smb_signing_source` to `_node_computer`; add `_edge_coerce_relay_adminservice`, `_edge_coerce_relay_mssql`, `_edge_coerce_relay_smb`, `_node_authenticated_users`; wire all four into `transforms()`. |
| `README.md` | **modify** — Edge Reference (3 relay edges, possible-edge + surgical `--disable-possible-edges` note), Node Reference (synthetic Authenticated Users group), mayyhem.com examples. |
| `ARCHITECTURE.md` | **modify** — §11c graph_edges columns (+2 coercion cols, relay-only props); node_computer `smb_signing_source` provenance; Stage 6 changelog entry. |
| `docs/superpowers/plans/2026-06-30-sccm-preproc-convert-stage6-validation.md` | **create** — code-tour validation harness (final task). |
| `tests/kinds_edges_stage6_test.py` · `graph_edge_relay_props_test.py` · `graph_edges_coercion_cols_test.py` · `node_computer_smb_signing_source_test.py` · `edge_coerce_relay_adminservice_test.py` · `edge_coerce_relay_mssql_test.py` · `edge_coerce_relay_smb_test.py` · `node_authenticated_users_test.py` | **create** — per-task test suites. |

**Convert/lookup (no change):** `SCCMLookup.table_rows` is generic; `convert_pipeline.emit_graph_from_duckdb` iterates `(table, model)` specs generically. The three relay edges flow through the single `graph_edges` table → `_graph_edges_split` → `graph_edges_ad` (read by `AD_EDGE_SPECS`, untagged). The Authenticated Users node lands in `node_group` (already in `AD_NODE_SPECS`). So Stage 6 adds **no** spec entries and **no** `main.py`/`convert_pipeline.py` change.

---

# Phase A — Edge-kind constants + traversable fix

### Task A1: Add relay edge-kind constants and fix the SMB traversable bug

**Files:**
- Modify: `src/openhound_sccm/kinds/edges.py`
- Test: `tests/kinds_edges_stage6_test.py`

**Interfaces:**
- Produces: `edges.COERCE_AND_RELAY_TO_ADMIN_SERVICE == "CoerceAndRelayToAdminService"`, `COERCE_AND_RELAY_TO_MSSQL == "CoerceAndRelayToMSSQL"`, `COERCE_AND_RELAY_TO_SMB == "CoerceAndRelayToSMB"` (consumed by Phase E/F/G builders and `graph_edge.py`). `TRAVERSABLE_EDGE_KINDS` contains all three relay strings and no longer contains `"CoerceAndRelayNTLMtoSMB"`.

- [ ] **Step 1: Write the failing test** — create `tests/kinds_edges_stage6_test.py`:

```python
from openhound_sccm.kinds import edges as ek


def test_relay_edge_kind_values():
    assert ek.COERCE_AND_RELAY_TO_ADMIN_SERVICE == "CoerceAndRelayToAdminService"
    assert ek.COERCE_AND_RELAY_TO_MSSQL == "CoerceAndRelayToMSSQL"
    assert ek.COERCE_AND_RELAY_TO_SMB == "CoerceAndRelayToSMB"


def test_all_three_relays_traversable():
    # All three relay edges are real attack paths; CMBP intended them traversable
    # (the SMB one was a name-mismatch bug, ps1:2221 vs :6775 — fixed here).
    assert ek.COERCE_AND_RELAY_TO_ADMIN_SERVICE in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.COERCE_AND_RELAY_TO_MSSQL in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.COERCE_AND_RELAY_TO_SMB in ek.TRAVERSABLE_EDGE_KINDS


def test_dead_smb_allowlist_name_removed():
    # The never-matching CMBP allow-list string must be gone, else the SMB relay
    # silently reverts to non-traversable.
    assert "CoerceAndRelayNTLMtoSMB" not in ek.TRAVERSABLE_EDGE_KINDS
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/kinds_edges_stage6_test.py -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'COERCE_AND_RELAY_TO_ADMIN_SERVICE'` (and the traversable assertions fail because `CoerceAndRelayNTLMtoSMB` is still present).

- [ ] **Step 3: Add the constants.** In `src/openhound_sccm/kinds/edges.py`, after the Stage 5 block (the line `MSSQL_GET_TGS = "MSSQL_GetTGS"`) add:

```python
# Stage 6 edge kinds (coerce-and-relay possible edges).
COERCE_AND_RELAY_TO_ADMIN_SERVICE = "CoerceAndRelayToAdminService"
COERCE_AND_RELAY_TO_MSSQL = "CoerceAndRelayToMSSQL"
COERCE_AND_RELAY_TO_SMB = "CoerceAndRelayToSMB"
```

- [ ] **Step 4: Fix the traversable set.** In `src/openhound_sccm/kinds/edges.py`, inside the `TRAVERSABLE_EDGE_KINDS` frozenset, change the line

```python
    "CoerceAndRelayToAdminService", "CoerceAndRelayToMSSQL", "CoerceAndRelayNTLMtoSMB",
```

to

```python
    # CMBP's allow-list (ps1:2221) named "CoerceAndRelayNTLMtoSMB", but the function
    # (ps1:6775) emits "CoerceAndRelayToSMB" — the mismatch left the SMB relay
    # non-traversable. The port emits CoerceAndRelayToSMB and marks it traversable.
    "CoerceAndRelayToAdminService", "CoerceAndRelayToMSSQL", "CoerceAndRelayToSMB",
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/kinds_edges_stage6_test.py -v`
Expected: 3 passed.

- [ ] **Step 6: Green checkpoint (NO commit).** Stop. Report PASS + the three new constants.

---

# Phase B — Relay edge properties + graph_edges columns + GraphEdge model

### Task B1: `SCCMRelayEdgeProperties`, the two `graph_edges` columns, and relay-only emission

**Files:**
- Modify: `src/openhound_sccm/graph.py`
- Modify: `src/openhound_sccm/transforms.py` (`_graph_edges_init` only)
- Modify: `src/openhound_sccm/models/graph_edge.py`
- Test: `tests/graph_edge_relay_props_test.py`

**Interfaces:**
- Consumes: `edges.COERCE_AND_RELAY_TO_*` (Task A1); `SCCMEdgeProperties` (existing, `graph.py`).
- Produces: `graph.SCCMRelayEdgeProperties` (fields `coercionVictimAndRelayTargetPairs: list[str]`, `coercionVictimHostnames: list[str]`, plus the inherited `collectionSource`/`traversable`); `graph_edges` table gains `coercion_victim_and_relay_target_pairs VARCHAR[]` + `coercion_victim_hostnames VARCHAR[]`; `GraphEdge` reads `coercion_victim_and_relay_target_pairs` / `coercion_victim_hostnames` (consumed by Phase E/F/G via the materialized table).

- [ ] **Step 1: Write the failing test** — create `tests/graph_edge_relay_props_test.py`:

```python
from openhound_sccm.graph import SCCMEdgeProperties, SCCMRelayEdgeProperties
from openhound_sccm.kinds import edges as ek
from openhound_sccm.models.graph_edge import GraphEdge


def test_relay_kind_emits_relay_properties_with_coercion_lists():
    row = GraphEdge(
        start_id="MAYYHEM.COM-S-1-5-11",
        end_id="PS1",
        kind=ek.COERCE_AND_RELAY_TO_ADMIN_SERVICE,
        collection_source=["Post-processing"],
        coercion_victim_and_relay_target_pairs=["Coerce SS01.mayyhem.com, relay to PROV01.mayyhem.com"],
        coercion_victim_hostnames=None,
    )
    edge = next(iter(row.edges))
    assert isinstance(edge.properties, SCCMRelayEdgeProperties)
    assert edge.properties.traversable is True
    assert edge.properties.collectionSource == ["Post-processing"]
    assert edge.properties.coercionVictimAndRelayTargetPairs == [
        "Coerce SS01.mayyhem.com, relay to PROV01.mayyhem.com"
    ]
    assert edge.properties.coercionVictimHostnames == []


def test_smb_relay_carries_victim_hostnames():
    row = GraphEdge(
        start_id="MAYYHEM.COM-S-1-5-11",
        end_id="S-1-5-21-1-2-3-1104",
        kind=ek.COERCE_AND_RELAY_TO_SMB,
        collection_source=["SMB-Negotiate"],
        coercion_victim_and_relay_target_pairs=None,
        coercion_victim_hostnames=["SS01.mayyhem.com"],
    )
    edge = next(iter(row.edges))
    assert isinstance(edge.properties, SCCMRelayEdgeProperties)
    assert edge.properties.coercionVictimHostnames == ["SS01.mayyhem.com"]


def test_non_relay_kind_uses_base_properties_no_coercion_fields():
    row = GraphEdge(
        start_id="A", end_id="B", kind=ek.SCCM_HAS_MEMBER,
        collection_source=["AdminService-SMS_FullCollectionMembership"],
    )
    edge = next(iter(row.edges))
    assert isinstance(edge.properties, SCCMEdgeProperties)
    assert not isinstance(edge.properties, SCCMRelayEdgeProperties)
    assert not hasattr(edge.properties, "coercionVictimHostnames")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/graph_edge_relay_props_test.py -v`
Expected: FAIL — `ImportError: cannot import name 'SCCMRelayEdgeProperties'`.

- [ ] **Step 3: Add the relay properties dataclass.** In `src/openhound_sccm/graph.py`, immediately after the `SCCMEdgeProperties` dataclass (the one whose only field is `collectionSource`), add:

```python
@dataclass
class SCCMRelayEdgeProperties(SCCMEdgeProperties):
    # Coerce-and-relay context (CMBP Process-CoerceAndRelayTo*). ONLY the three
    # CoerceAndRelay* edge kinds carry these — every other edge keeps the lean base
    # SCCMEdgeProperties so its BloodHound panel stays uncluttered. Field names mirror
    # ConfigManBearPig.ps1 exactly (ps1:6617/6719/6777).
    coercionVictimAndRelayTargetPairs: list[str] = field(default_factory=list, kw_only=True)
    coercionVictimHostnames: list[str] = field(default_factory=list, kw_only=True)
```

- [ ] **Step 4: Add the two `graph_edges` columns.** In `src/openhound_sccm/transforms.py`, replace the body of `_graph_edges_init` so the `CREATE` carries the coercion columns:

```python
def _graph_edges_init(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Create the empty graph_edges table that every edge builder INSERTs into.
    Always runs (even with no site/edge data) so convert can read the table.

    The coercion_* columns are populated only by the Stage 6 relay builders; every
    other builder INSERTs BY NAME and leaves them NULL (dedup coalesces NULL -> [])."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges "
        f"(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[], "
        f"coercion_victim_and_relay_target_pairs VARCHAR[], coercion_victim_hostnames VARCHAR[])"
    )
```

- [ ] **Step 5: Wire the columns through `GraphEdge`.** Replace `src/openhound_sccm/models/graph_edge.py` with:

```python
# src/openhound_sccm/models/graph_edge.py
"""GraphEdge: converts any graph_edges row into an OpenGraph edge of the matching kind.

Each row in the graph_edges preproc table represents one directed relationship
between two graph nodes. This model reads those rows and emits an Edge whose
`traversable` property is set from the CMBP allow-list. The three coerce-and-relay
kinds additionally carry coercion-context lists (SCCMRelayEdgeProperties); every
other kind uses the lean base SCCMEdgeProperties. It never produces a node
(as_node returns None) because graph_edges rows are pure edge data.
"""
import logging
from typing import Iterator

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Edge, EdgePath
from pydantic import ConfigDict

from ..graph import SCCMEdgeProperties, SCCMRelayEdgeProperties
from ..kinds.edges import (
    COERCE_AND_RELAY_TO_ADMIN_SERVICE,
    COERCE_AND_RELAY_TO_MSSQL,
    COERCE_AND_RELAY_TO_SMB,
    TRAVERSABLE_EDGE_KINDS,
)

logger = logging.getLogger(__name__)

# The only edge kinds that carry coerce-and-relay context lists.
_RELAY_KINDS = frozenset({
    COERCE_AND_RELAY_TO_ADMIN_SERVICE,
    COERCE_AND_RELAY_TO_MSSQL,
    COERCE_AND_RELAY_TO_SMB,
})


class GraphEdge(BaseAsset):
    """One graph_edges row -> one OpenGraph edge of any kind. Endpoints matched by id;
    `traversable` is set from the CMBP allow-list. Never produces a node."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    start_id: str | None = None
    end_id: str | None = None
    kind: str | None = None
    collection_source: list[str] | None = None
    coercion_victim_and_relay_target_pairs: list[str] | None = None
    coercion_victim_hostnames: list[str] | None = None

    @property
    def as_node(self) -> None:
        """Graph edges never produce a node."""
        return None

    @property
    def edges(self) -> Iterator[Edge]:
        """Yield one Edge for this row.

        If start_id, end_id, or kind is missing, the row is dropped with a
        warning rather than emitting a malformed edge.
        """
        if not self.start_id or not self.end_id or not self.kind:
            logger.warning(
                "GraphEdge: dropping incomplete row (start=%r end=%r kind=%r)",
                self.start_id, self.end_id, self.kind,
            )
            return
        traversable = self.kind in TRAVERSABLE_EDGE_KINDS
        if self.kind in _RELAY_KINDS:
            # Relay edges carry the operator-facing coercion context (CMBP).
            properties = SCCMRelayEdgeProperties(
                traversable=traversable,
                collectionSource=self.collection_source or [],
                coercionVictimAndRelayTargetPairs=self.coercion_victim_and_relay_target_pairs or [],
                coercionVictimHostnames=self.coercion_victim_hostnames or [],
            )
        else:
            # Every other edge keeps the lean base properties.
            properties = SCCMEdgeProperties(
                traversable=traversable,
                collectionSource=self.collection_source or [],
            )
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=properties,
        )
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/graph_edge_relay_props_test.py -v`
Expected: 3 passed.

- [ ] **Step 7: Run the existing edge-model + convert tests to confirm no regression**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests -k "graph_edge or convert or edge_" -v`
Expected: all pass (the non-relay path is unchanged — base `SCCMEdgeProperties`, same output).

- [ ] **Step 8: Green checkpoint (NO commit).** Stop. Report PASS.

---

# Phase C — Carry coercion columns through dedup + split

### Task C1: Array-union the coercion columns in dedup; carry them in the AD/SCCM split

**Files:**
- Modify: `src/openhound_sccm/transforms.py` (`_graph_edges_dedup`, `_graph_edges_split`)
- Test: `tests/graph_edges_coercion_cols_test.py`

**Interfaces:**
- Consumes: the `graph_edges` schema from Task B1.
- Produces: `_graph_edges_dedup` array-unions both coercion columns per `(start_id, end_id, kind)`; `graph_edges_ad` and `graph_edges_sccm` both expose `coercion_victim_and_relay_target_pairs` + `coercion_victim_hostnames` (consumed by `GraphEdge` via `AD_EDGE_SPECS`/`SCCM_EDGE_SPECS`).

- [ ] **Step 1: Write the failing test** — create `tests/graph_edges_coercion_cols_test.py`:

```python
import duckdb

from openhound_sccm.transforms import _graph_edges_init, _graph_edges_dedup, _graph_edges_split


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _graph_edges_init(con, "sccm")
    # Two duplicate relay rows for the same (start,kind,end) with different pairs:
    # dedup must array-union them (mirrors CMBP Upsert-Edge merge).
    con.execute(
        "INSERT INTO sccm.graph_edges VALUES "
        "('MAYYHEM.COM-S-1-5-11','PS1','CoerceAndRelayToAdminService',"
        " ['Post-processing'], ['Coerce A, relay to X'], NULL),"
        "('MAYYHEM.COM-S-1-5-11','PS1','CoerceAndRelayToAdminService',"
        " ['Post-processing'], ['Coerce B, relay to X'], NULL),"
        # A non-relay edge with NULL coercion columns must survive as empty lists.
        "('PS1','C1','SCCM_Contains', ['SCCM_Invoke-PostProcessing'], NULL, NULL)"
    )


def test_dedup_unions_coercion_pairs_and_handles_nulls():
    con = duckdb.connect()
    _seed(con)
    _graph_edges_dedup(con, "sccm")
    rows = con.execute(
        "SELECT kind, sort(coercion_victim_and_relay_target_pairs), coercion_victim_hostnames "
        "FROM sccm.graph_edges WHERE kind = 'CoerceAndRelayToAdminService'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][1] == ["Coerce A, relay to X", "Coerce B, relay to X"]
    assert rows[0][2] == []  # NULL -> []
    nonrelay = con.execute(
        "SELECT coercion_victim_and_relay_target_pairs, coercion_victim_hostnames "
        "FROM sccm.graph_edges WHERE kind = 'SCCM_Contains'"
    ).fetchone()
    assert nonrelay == ([], [])  # NULL coalesced to [] for non-relay rows too


def test_split_carries_coercion_columns_to_ad_payload():
    con = duckdb.connect()
    _seed(con)
    _graph_edges_dedup(con, "sccm")
    # Minimal node tables so the AuthUsers start id lands in the AD id set.
    con.execute("CREATE TABLE sccm.node_computer AS SELECT NULL::VARCHAR AS sid WHERE false")
    con.execute("CREATE TABLE sccm.node_user AS SELECT NULL::VARCHAR AS sid WHERE false")
    con.execute(
        "CREATE TABLE sccm.node_group AS SELECT 'MAYYHEM.COM-S-1-5-11'::VARCHAR AS sid"
    )
    con.execute("CREATE TABLE sccm.node_backfill AS SELECT NULL::VARCHAR AS id WHERE false")
    _graph_edges_split(con, "sccm")
    ad_cols = [d[0] for d in con.execute("DESCRIBE sccm.graph_edges_ad").fetchall()]
    assert "coercion_victim_and_relay_target_pairs" in ad_cols
    assert "coercion_victim_hostnames" in ad_cols
    # The AdminService relay (AuthUsers start) is AD-routed.
    ad_kinds = [r[0] for r in con.execute("SELECT kind FROM sccm.graph_edges_ad").fetchall()]
    assert "CoerceAndRelayToAdminService" in ad_kinds
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/graph_edges_coercion_cols_test.py -v`
Expected: FAIL — dedup currently drops the coercion columns (`Binder Error: ... coercion_victim_and_relay_target_pairs` not in the rebuilt table) / split's `SELECT` doesn't include them.

- [ ] **Step 3: Update `_graph_edges_dedup`.** In `src/openhound_sccm/transforms.py`, replace the `con.execute(...)` inside `_graph_edges_dedup` with:

```python
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges AS "
        f"SELECT start_id, end_id, kind, "
        f"  coalesce(list_distinct(flatten(list(collection_source))), CAST([] AS VARCHAR[])) AS collection_source, "
        # Stage 6: array-union the coercion lists (CMBP Upsert-Edge merges arrays, ps1:2155-2158).
        # FILTER drops the NULLs that every non-relay builder leaves in these columns.
        f"  coalesce(list_distinct(flatten(list(coercion_victim_and_relay_target_pairs) "
        f"    FILTER (WHERE coercion_victim_and_relay_target_pairs IS NOT NULL))), CAST([] AS VARCHAR[])) "
        f"    AS coercion_victim_and_relay_target_pairs, "
        f"  coalesce(list_distinct(flatten(list(coercion_victim_hostnames) "
        f"    FILTER (WHERE coercion_victim_hostnames IS NOT NULL))), CAST([] AS VARCHAR[])) "
        f"    AS coercion_victim_hostnames "
        f"FROM {schema}.graph_edges "
        f"GROUP BY start_id, end_id, kind"
    )
```

- [ ] **Step 4: Update `_graph_edges_split`.** In `src/openhound_sccm/transforms.py`, in `_graph_edges_split`, extend BOTH `SELECT` lists (the `graph_edges_ad` one and the `graph_edges_sccm` one) to carry the coercion columns. Change each

```python
        f"SELECT e.start_id, e.end_id, e.kind, e.collection_source "
```

to

```python
        f"SELECT e.start_id, e.end_id, e.kind, e.collection_source, "
        f"  e.coercion_victim_and_relay_target_pairs, e.coercion_victim_hostnames "
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/graph_edges_coercion_cols_test.py -v`
Expected: 2 passed.

- [ ] **Step 6: Run the existing dedup/split tests to confirm no regression**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests -k "dedup or split or graph_edges" -v`
Expected: all pass.

- [ ] **Step 7: Green checkpoint (NO commit).** Stop. Report PASS.

---

# Phase D — node_computer SMB-signing provenance

### Task D1: Add `smb_signing_source` to `node_computer`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` (`_node_computer`)
- Test: `tests/node_computer_smb_signing_source_test.py`

**Interfaces:**
- Produces: `node_computer.smb_signing_source VARCHAR[]` — `['SMB-Negotiate']` for rows seen by the SMB negotiate probe, `['RemoteRegistry-SMBSigningCheck']` for rows seen by the remote-registry signing check, array-unioned per SID; `[]` for computers neither probe touched (consumed by the SMB relay in Phase G).

- [ ] **Step 1: Write the failing test** — create `tests/node_computer_smb_signing_source_test.py`:

```python
import duckdb

from openhound_sccm.transforms import _node_computer


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # Same SID seen by BOTH the SMB negotiate probe and the remote-registry check.
    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'SS01' AS name, "
        "'SS01.mayyhem.com' AS dns_host_name, 'CN=SS01' AS distinguished_name, "
        "false AS smb_signing_required"
    )
    con.execute(
        "CREATE TABLE sccm.remoteregistry_computers AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'SS01' AS name, "
        "'SS01.mayyhem.com' AS dns_host_name, 'CN=SS01' AS distinguished_name, "
        "false AS smb_signing_required, 'Off' AS restrict_receiving_ntlm_traffic"
    )
    # A computer only LDAP knew about -> no smb_signing_source.
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-2222' AS sid, 'WS01' AS name, NULL AS resource_id, "
        "NULL AS source_site_code, NULL AS system_roles, NULL AS sms_unique_identifier, "
        "false AS obsolete"
    )


def test_smb_signing_source_unions_both_probes():
    con = duckdb.connect()
    _seed(con)
    _node_computer(con, "sccm")
    src = con.execute(
        "SELECT sort(smb_signing_source) FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchone()[0]
    assert src == ["RemoteRegistry-SMBSigningCheck", "SMB-Negotiate"]


def test_smb_signing_source_empty_when_unprobed():
    con = duckdb.connect()
    _seed(con)
    _node_computer(con, "sccm")
    src = con.execute(
        "SELECT smb_signing_source FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-2222'"
    ).fetchone()[0]
    assert src == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_computer_smb_signing_source_test.py -v`
Expected: FAIL — `Binder Error: Referenced column "smb_signing_source" not found`.

- [ ] **Step 3: Add the staging column.** In `_node_computer`, in the `CREATE OR REPLACE TABLE {schema}.node_computer (...)` staging DDL, add the column right after the `smb_signing_required BOOLEAN, ` line:

```python
        "smb_signing_required BOOLEAN, "
        "smb_signing_source VARCHAR[], "          # which probe(s) reported signing: SMB-Negotiate / RemoteRegistry-SMBSigningCheck
```

- [ ] **Step 4: Tag the two probe sources.** In the `smb_computers` INSERT SELECT, add the tag line right after `f"smb_signing_required, "`:

```python
        f"smb_signing_required, "
        f"['SMB-Negotiate'] AS smb_signing_source, "
```

In the `remoteregistry_computers` INSERT SELECT, add right after its `f"smb_signing_required, "`:

```python
        f"smb_signing_required, "
        f"['RemoteRegistry-SMBSigningCheck'] AS smb_signing_source, "
```

(All other source SELECTs leave `smb_signing_source` unnamed; `INSERT ... BY NAME` defaults it to NULL.)

- [ ] **Step 5: Aggregate in the final GROUP BY.** In `_node_computer`'s final `CREATE OR REPLACE TABLE {schema}.node_computer AS SELECT ...` (the collapse), add this aggregate right after the `bool_or(smb_signing_required) AS smb_signing_required, ` line:

```python
        f"  bool_or(smb_signing_required) AS smb_signing_required, "
        # Array-union the probe tags; FILTER drops the NULLs other sources leave.
        f"  coalesce(list_distinct(flatten(list(smb_signing_source) "
        f"    FILTER (WHERE smb_signing_source IS NOT NULL))), CAST([] AS VARCHAR[])) AS smb_signing_source, "
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_computer_smb_signing_source_test.py -v`
Expected: 2 passed.

- [ ] **Step 7: Run the existing node_computer + Stage 1 tests to confirm no regression**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests -k "node_computer or computer or stage1 or node1" -v`
Expected: all pass (the new column is additive; `ComputerNode` ignores it via `extra="ignore"`, so the node output is unchanged).

- [ ] **Step 8: Green checkpoint (NO commit).** Stop. Report PASS. Note in the task report that `ARCHITECTURE.md` will document this cross-cutting change in Task I1.

---

# Phase E — AdminService relay builder

### Task E1: `_edge_coerce_relay_adminservice` + the `_authed_users_id` SQL helper

**Files:**
- Modify: `src/openhound_sccm/transforms.py` (add `_authed_users_id` helper + `_edge_coerce_relay_adminservice`)
- Test: `tests/edge_coerce_relay_adminservice_test.py`

**Interfaces:**
- Consumes: `edges.COERCE_AND_RELAY_TO_ADMIN_SERVICE`; `node_computer` (`sid`, `dnshostname`, `site_system_roles`, `restrict_receiving_ntlm_traffic`); `site_hierarchy` (`site_code`, `site_type`).
- Produces: `_authed_users_id(col)` -> SQL fragment `upper(regexp_replace(col, '^[^.]+\.', '')) || '-S-1-5-11'`; `_edge_coerce_relay_adminservice(con, schema, disable_possible)` INSERTs `CoerceAndRelayToAdminService` rows (start = Authenticated Users id of the site server's domain, end = non-secondary site code) with `coercion_victim_and_relay_target_pairs`.

- [ ] **Step 1: Write the failing test** — create `tests/edge_coerce_relay_adminservice_test.py`:

```python
import duckdb

from openhound_sccm.transforms import _graph_edges_init, _edge_coerce_relay_adminservice


def _seed(con, provider_ntlm):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type "
        "UNION ALL SELECT 'SEC' AS site_code, 1 AS site_type"
    )
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        # provider: SMS Provider@PS1 with given NTLM value
        "('S-1-5-21-1-2-3-1001','PROV01.mayyhem.com',['SMS Provider@PS1'], ?), "
        # site server: SMS Site Server@PS1, NTLM unknown
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'], NULL), "
        # a secondary-site system, must be ignored
        "('S-1-5-21-1-2-3-1003','SEC01.mayyhem.com',['SMS Site Server@SEC'], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, restrict_receiving_ntlm_traffic)",
        [provider_ntlm],
    )
    _graph_edges_init(con, "sccm")


def test_adminservice_relay_default_emits_with_null_ntlm():
    con = duckdb.connect()
    _seed(con, None)  # provider NTLM unknown -> assume vulnerable (default)
    _edge_coerce_relay_adminservice(con, "sccm", disable_possible=False)
    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source, "
        "coercion_victim_and_relay_target_pairs FROM sccm.graph_edges"
    ).fetchall()
    assert len(rows) == 1
    start, end, kind, csrc, pairs = rows[0]
    assert start == "MAYYHEM.COM-S-1-5-11"
    assert end == "PS1"          # non-secondary site code (raw case)
    assert kind == "CoerceAndRelayToAdminService"
    assert csrc == ["Post-processing"]
    assert pairs == ["Coerce SS01.mayyhem.com, relay to PROV01.mayyhem.com"]


def test_adminservice_relay_flag_drops_null_ntlm():
    con = duckdb.connect()
    _seed(con, None)
    _edge_coerce_relay_adminservice(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_adminservice_relay_flag_keeps_confirmed_off():
    con = duckdb.connect()
    _seed(con, "Off")  # explicitly confirmed not-restricting NTLM
    _edge_coerce_relay_adminservice(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_coerce_relay_adminservice_test.py -v`
Expected: FAIL — `ImportError: cannot import name '_edge_coerce_relay_adminservice'`.

- [ ] **Step 3: Add the `_authed_users_id` helper.** In `src/openhound_sccm/transforms.py`, next to the existing `_arr` helper, add:

```python
def _authed_users_id(dnshostname_col: str) -> str:
    """SQL fragment: the SharpHound-form Authenticated Users node id for the domain of a
    computer, derived from its dnshostname column. FQDN = dnshostname with the first
    (host) label stripped, uppercased (e.g. 'PROV01.mayyhem.com' -> 'MAYYHEM.COM-S-1-5-11').
    Always pair with a `<col> LIKE '%.%'` guard so a bare hostname can't yield a bad id."""
    return f"upper(regexp_replace({dnshostname_col}, '^[^.]+\\.', '')) || '-S-1-5-11'"
```

- [ ] **Step 4: Add the builder.** In `src/openhound_sccm/transforms.py`, add (place it after `_edge_mssql_db_assign_all`, with the other edge builders):

```python
def _edge_coerce_relay_adminservice(
    con: duckdb.DuckDBPyConnection, schema: str, disable_possible: bool
) -> None:
    """CoerceAndRelayToAdminService: Authenticated Users -> SCCM_Site (CMBP ps1:6572-6624).

    For each non-secondary site, every SMS Provider relay target is paired with every Site
    Server coercion victim (provider != site server). The relay coerces the site server and
    relays its NTLM to the provider's AdminService; the edge end is the site code (the
    SCCM_Site node id). Start = the Authenticated Users node of the SITE SERVER's domain
    (CMBP keys it off the coerced victim, ps1:6606).

    NTLM gate is on the PROVIDER (the relay target must accept NTLM): default treats
    null-or-'Off' as vulnerable; with --disable-possible-edges only explicit 'Off' qualifies
    (Stage 6 decision #1). collectionSource is the static ['Post-processing'] CMBP passes at
    ps1:1955. _safe() skips+logs if site_hierarchy / node_computer is missing."""
    from .kinds.edges import COERCE_AND_RELAY_TO_ADMIN_SERVICE
    # Default: null/Off => vulnerable. Flag: only explicit 'Off'.
    ntlm_ok = ("upper(coalesce(c.restrict_receiving_ntlm_traffic, 'OFF')) = 'OFF'"
               if not disable_possible
               else "upper(c.restrict_receiving_ntlm_traffic) = 'OFF'")
    _safe(
        con, "edge_coerce_relay_adminservice",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"WITH nonsec AS ("
        f"  SELECT site_code, upper(site_code) AS u FROM {schema}.site_hierarchy "
        f"  WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL"
        f"), "
        f"providers AS ("
        f"  SELECT c.sid, c.dnshostname, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
        f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
        f"  WHERE role LIKE 'SMS Provider@%' AND c.sid IS NOT NULL AND ({ntlm_ok})"
        f"), "
        f"servers AS ("
        f"  SELECT c.sid, c.dnshostname, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
        f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
        f"  WHERE role LIKE 'SMS Site Server@%' AND c.sid IS NOT NULL AND c.dnshostname LIKE '%.%'"
        f") "
        f"SELECT DISTINCT {_authed_users_id('srv.dnshostname')} AS start_id, "
        f"  n.site_code AS end_id, "
        f"  '{COERCE_AND_RELAY_TO_ADMIN_SERVICE}' AS kind, "
        f"  ['Post-processing'] AS collection_source, "
        f"  ['Coerce ' || coalesce(srv.dnshostname, srv.sid) || ', relay to ' "
        f"    || coalesce(prov.dnshostname, prov.sid)] AS coercion_victim_and_relay_target_pairs, "
        f"  CAST(NULL AS VARCHAR[]) AS coercion_victim_hostnames "
        f"FROM providers prov "
        f"JOIN servers srv ON srv.site = prov.site AND srv.sid != prov.sid "
        f"JOIN nonsec n ON n.u = srv.site"
    )
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_coerce_relay_adminservice_test.py -v`
Expected: 3 passed.

- [ ] **Step 6: Green checkpoint (NO commit).** Stop. Report PASS. (Wiring into `transforms()` happens in Task H1.)

---

# Phase F — MSSQL relay builder

### Task F1: `_edge_coerce_relay_mssql`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` (add `_edge_coerce_relay_mssql`)
- Test: `tests/edge_coerce_relay_mssql_test.py`

**Interfaces:**
- Consumes: `edges.COERCE_AND_RELAY_TO_MSSQL`; `node_mssql_login` (`login_id`, `server_id`, `host_sid`, `sysadmin_computer_sid`); `node_mssql_server` (`server_id`, `dns_host_name`, `name`, `port`, `extended_protection`, `collection_source`); `node_computer` (`sid`, `dnshostname`, `restrict_receiving_ntlm_traffic`); the `_authed_users_id` helper (Task E1).
- Produces: `_edge_coerce_relay_mssql(con, schema, disable_possible)` INSERTs `CoerceAndRelayToMSSQL` rows (start = Authenticated Users of the sysadmin computer's domain, end = `login_id`) with `coercion_victim_and_relay_target_pairs` and an EPA-source `collection_source`.

- [ ] **Step 1: Write the failing test** — create `tests/edge_coerce_relay_mssql_test.py`:

```python
import duckdb

from openhound_sccm.transforms import _graph_edges_init, _edge_coerce_relay_mssql


def _seed(con, host_ntlm, epa):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # SQL host computer (the site DB server) + the sysadmin victim computer.
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-5001','SQL01.mayyhem.com', ?), "       # host (site DB)
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com', NULL)"        # sysadmin victim
        ") AS t(sid, dnshostname, restrict_receiving_ntlm_traffic)",
        [host_ntlm],
    )
    con.execute(
        "CREATE TABLE sccm.node_mssql_server AS SELECT "
        "'S-1-5-21-1-2-3-5001:1433' AS server_id, 'SQL01.mayyhem.com' AS dns_host_name, "
        "'SQL01.mayyhem.com' AS name, '1433' AS port, ? AS extended_protection, "
        "['MSSQL-ScanForEPA','SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source",
        [epa],
    )
    con.execute(
        "CREATE TABLE sccm.node_mssql_login AS SELECT "
        "'MAYYHEM\\SS01$@S-1-5-21-1-2-3-5001:1433' AS login_id, "
        "'S-1-5-21-1-2-3-5001:1433' AS server_id, 'S-1-5-21-1-2-3-5001' AS host_sid, "
        "'S-1-5-21-1-2-3-1002' AS sysadmin_computer_sid"
    )
    _graph_edges_init(con, "sccm")


def test_mssql_relay_default_emits_when_epa_null():
    con = duckdb.connect()
    _seed(con, host_ntlm=None, epa=None)  # both unknown -> assume vulnerable
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=False)
    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source, "
        "coercion_victim_and_relay_target_pairs FROM sccm.graph_edges"
    ).fetchall()
    assert len(rows) == 1
    start, end, kind, csrc, pairs = rows[0]
    assert start == "MAYYHEM.COM-S-1-5-11"
    assert end == "MAYYHEM\\SS01$@S-1-5-21-1-2-3-5001:1433"
    assert kind == "CoerceAndRelayToMSSQL"
    assert csrc == ["MSSQL-ScanForEPA"]  # EPA sources only
    assert pairs == ["Coerce SS01.mayyhem.com, relay to SQL01.mayyhem.com:1433"]


def test_mssql_relay_skips_when_epa_enabled():
    con = duckdb.connect()
    _seed(con, host_ntlm="Off", epa="Required")  # EPA on -> never a relay target
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=False)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_mssql_relay_flag_drops_assumed_epa():
    con = duckdb.connect()
    _seed(con, host_ntlm="Off", epa=None)  # EPA unknown -> dropped under the flag
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_coerce_relay_mssql_test.py -v`
Expected: FAIL — `ImportError: cannot import name '_edge_coerce_relay_mssql'`.

- [ ] **Step 3: Add the builder.** In `src/openhound_sccm/transforms.py`, add after `_edge_coerce_relay_adminservice`:

```python
def _edge_coerce_relay_mssql(
    con: duckdb.DuckDBPyConnection, schema: str, disable_possible: bool
) -> None:
    """CoerceAndRelayToMSSQL: Authenticated Users -> MSSQL_Login (CMBP ps1:6626-6726).

    Driven off node_mssql_login, which already encodes the (sysadmin computer, server)
    pairing CMBP reconstructs by hand (and already excludes the SQL host as its own
    sysadmin, so 'can't relay to self' is satisfied). For each login: coerce the sysadmin
    computer and relay NTLM to the site DB server, authenticating as that login.

    Two gates (Stage 6 decision #1): the SQL HOST computer's NTLM and the SERVER's Extended
    Protection. Default treats null as vulnerable (null NTLM => assume Off; null EPA =>
    assume Off). A known EPA other than 'Off' always disqualifies the server. With
    --disable-possible-edges both must be EXPLICITLY 'Off'. collectionSource = the server's
    EPA-determination sources only (CMBP ps1:6715). _safe() skips+logs missing tables."""
    from .kinds.edges import COERCE_AND_RELAY_TO_MSSQL
    if not disable_possible:
        epa_ok = "(s.extended_protection IS NULL OR upper(s.extended_protection) = 'OFF')"
        ntlm_ok = "upper(coalesce(h.restrict_receiving_ntlm_traffic, 'OFF')) = 'OFF'"
    else:
        epa_ok = "upper(s.extended_protection) = 'OFF'"
        ntlm_ok = "upper(h.restrict_receiving_ntlm_traffic) = 'OFF'"
    _safe(
        con, "edge_coerce_relay_mssql",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"SELECT DISTINCT {_authed_users_id('v.dnshostname')} AS start_id, "
        f"  l.login_id AS end_id, "
        f"  '{COERCE_AND_RELAY_TO_MSSQL}' AS kind, "
        f"  coalesce(list_filter(s.collection_source, "
        f"    x -> x IN ('MSSQL-ScanForEPA', 'RemoteRegistry-MSSQL')), CAST([] AS VARCHAR[])) "
        f"    AS collection_source, "
        f"  ['Coerce ' || coalesce(v.dnshostname, v.sid) || ', relay to ' "
        f"    || coalesce(s.dns_host_name, s.name) || ':' || coalesce(s.port, '1433')] "
        f"    AS coercion_victim_and_relay_target_pairs, "
        f"  CAST(NULL AS VARCHAR[]) AS coercion_victim_hostnames "
        f"FROM {schema}.node_mssql_login l "
        f"JOIN {schema}.node_mssql_server s ON s.server_id = l.server_id "
        f"JOIN {schema}.node_computer h ON h.sid = l.host_sid "
        f"JOIN {schema}.node_computer v "
        f"  ON v.sid = l.sysadmin_computer_sid AND v.dnshostname LIKE '%.%' "
        f"WHERE ({epa_ok}) AND ({ntlm_ok})"
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_coerce_relay_mssql_test.py -v`
Expected: 3 passed.

- [ ] **Step 5: Green checkpoint (NO commit).** Stop. Report PASS.

---

# Phase G — SMB relay builder

### Task G1: `_edge_coerce_relay_smb`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` (add `_edge_coerce_relay_smb`)
- Test: `tests/edge_coerce_relay_smb_test.py`

**Interfaces:**
- Consumes: `edges.COERCE_AND_RELAY_TO_SMB`; `node_computer` (`sid`, `dnshostname`, `site_system_roles`, `smb_signing_required`, `restrict_receiving_ntlm_traffic`, `smb_signing_source` from Task D1); `site_hierarchy`; `_authed_users_id`.
- Produces: `_edge_coerce_relay_smb(con, schema, disable_possible)` INSERTs `CoerceAndRelayToSMB` rows (start = Authenticated Users of the site server's domain, end = the SMB-signing-disabled site-system Computer SID) with `coercion_victim_hostnames` and an SMB-source `collection_source`.

- [ ] **Step 1: Write the failing test** — create `tests/edge_coerce_relay_smb_test.py`:

```python
import duckdb

from openhound_sccm.transforms import _graph_edges_init, _edge_coerce_relay_smb


def _seed(con, target_ntlm):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type"
    )
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        # vulnerable target: a DP@PS1 with signing not required + given NTLM
        "('S-1-5-21-1-2-3-7001','DP01.mayyhem.com',['SMS Distribution Point@PS1'],"
        " false, ['SMB-Negotiate'], ?), "
        # coerced site server
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'],"
        " true, [], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, smb_signing_required, "
        "smb_signing_source, restrict_receiving_ntlm_traffic)",
        [target_ntlm],
    )
    _graph_edges_init(con, "sccm")


def test_smb_relay_default_emits():
    con = duckdb.connect()
    _seed(con, target_ntlm=None)  # NTLM unknown -> assume vulnerable
    _edge_coerce_relay_smb(con, "sccm", disable_possible=False)
    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source, coercion_victim_hostnames "
        "FROM sccm.graph_edges"
    ).fetchall()
    assert len(rows) == 1
    start, end, kind, csrc, victims = rows[0]
    assert start == "MAYYHEM.COM-S-1-5-11"
    assert end == "S-1-5-21-1-2-3-7001"          # the vulnerable site system
    assert kind == "CoerceAndRelayToSMB"
    assert csrc == ["SMB-Negotiate"]
    assert victims == ["SS01.mayyhem.com"]        # the coerced site server


def test_smb_relay_flag_drops_null_ntlm():
    con = duckdb.connect()
    _seed(con, target_ntlm=None)
    _edge_coerce_relay_smb(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_smb_relay_flag_keeps_confirmed():
    con = duckdb.connect()
    _seed(con, target_ntlm="Off")  # confirmed NTLM not restricted + signing off
    _edge_coerce_relay_smb(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_coerce_relay_smb_test.py -v`
Expected: FAIL — `ImportError: cannot import name '_edge_coerce_relay_smb'`.

- [ ] **Step 3: Add the builder.** In `src/openhound_sccm/transforms.py`, add after `_edge_coerce_relay_mssql`:

```python
def _edge_coerce_relay_smb(
    con: duckdb.DuckDBPyConnection, schema: str, disable_possible: bool
) -> None:
    """CoerceAndRelayToSMB: Authenticated Users -> Computer (CMBP ps1:6728-6781).

    The edge END is a site system whose SMB signing is NOT required (the relay target); the
    coerced victim is a Site Server in the same non-secondary site (system != server). Start
    = the Authenticated Users node of the SITE SERVER's domain (CMBP ps1:6763).

    Gates (Stage 6 decision #1): the TARGET's smb_signing_required is false (always explicit
    in CMBP) AND its NTLM is null-or-'Off' (default) / explicitly 'Off' (flag).
    collectionSource = the target's smb_signing_source filtered to the SMB-signing probes
    (CMBP ps1:6773). coercionVictimHostnames = the coerced site server's dnshostname.
    _safe() skips+logs missing tables."""
    from .kinds.edges import COERCE_AND_RELAY_TO_SMB
    ntlm_ok = ("upper(coalesce(c.restrict_receiving_ntlm_traffic, 'OFF')) = 'OFF'"
               if not disable_possible
               else "upper(c.restrict_receiving_ntlm_traffic) = 'OFF'")
    _safe(
        con, "edge_coerce_relay_smb",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"WITH nonsec AS ("
        f"  SELECT upper(site_code) AS u FROM {schema}.site_hierarchy "
        f"  WHERE coalesce(site_type, 0) != 1 AND site_code IS NOT NULL"
        f"), "
        f"targets AS ("
        f"  SELECT DISTINCT c.sid, c.smb_signing_source, "
        f"    upper(regexp_extract(role, '@(.+)$', 1)) AS site "
        f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
        f"  WHERE role LIKE '%@%' AND c.sid IS NOT NULL "
        f"    AND c.smb_signing_required = false AND ({ntlm_ok})"
        f"), "
        f"servers AS ("
        f"  SELECT DISTINCT c.sid, c.dnshostname, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
        f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
        f"  WHERE role LIKE 'SMS Site Server@%' AND c.sid IS NOT NULL AND c.dnshostname LIKE '%.%'"
        f") "
        f"SELECT DISTINCT {_authed_users_id('srv.dnshostname')} AS start_id, "
        f"  tgt.sid AS end_id, "
        f"  '{COERCE_AND_RELAY_TO_SMB}' AS kind, "
        f"  coalesce(list_filter(tgt.smb_signing_source, "
        f"    x -> x IN ('SMB-Negotiate', 'RemoteRegistry-SMBSigningCheck')), CAST([] AS VARCHAR[])) "
        f"    AS collection_source, "
        f"  CAST(NULL AS VARCHAR[]) AS coercion_victim_and_relay_target_pairs, "
        f"  [srv.dnshostname] AS coercion_victim_hostnames "
        f"FROM targets tgt "
        f"JOIN servers srv ON srv.site = tgt.site AND srv.sid != tgt.sid "
        f"JOIN nonsec n ON n.u = tgt.site"
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/edge_coerce_relay_smb_test.py -v`
Expected: 3 passed.

- [ ] **Step 5: Green checkpoint (NO commit).** Stop. Report PASS.

---

# Phase H — Authenticated Users node + transforms() integration

### Task H1: `_node_authenticated_users` + wire all four builders into `transforms()`

**Files:**
- Modify: `src/openhound_sccm/transforms.py` (add `_node_authenticated_users`; edit `transforms()`)
- Test: `tests/node_authenticated_users_test.py`

**Interfaces:**
- Consumes: `graph_edges` relay rows (Phase E/F/G); `node_computer` (`sid`, `dnshostname`); `node_group` (the final coalesce schema: `sid`, `name`, `sccm_infra`, `sccm_resource_ids`, `fallback_domain_sid`); `_read_disable_possible` (existing, called once in `transforms()`).
- Produces: `_node_authenticated_users(con, schema)` INSERTs one `node_group` row per relay-start domain (`sid = UPPER(FQDN)-S-1-5-11`, `name = AUTHENTICATED USERS@<FQDN-UPPER>`, `sccm_infra=false`, `sccm_resource_ids=[]`, `fallback_domain_sid = <domain SID>`); `transforms()` calls the three relay builders + `_node_authenticated_users` after `_edge_mssql_db_assign_all` and before `_graph_edges_dedup`.

- [ ] **Step 1: Write the failing test** — create `tests/node_authenticated_users_test.py`:

```python
import duckdb

from openhound_sccm.transforms import (
    _graph_edges_init, _edge_coerce_relay_adminservice, _node_authenticated_users,
)
from openhound_sccm.models.group import GroupNode


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type")
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-1001','PROV01.mayyhem.com',['SMS Provider@PS1'], NULL), "
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, restrict_receiving_ntlm_traffic)"
    )
    # node_group with the final coalesce columns (empty to start).
    con.execute(
        "CREATE TABLE sccm.node_group (sid VARCHAR, name VARCHAR, sccm_infra BOOLEAN, "
        "sccm_resource_ids VARCHAR[], fallback_domain_sid VARCHAR)"
    )
    _graph_edges_init(con, "sccm")
    _edge_coerce_relay_adminservice(con, "sccm", disable_possible=False)


def test_authenticated_users_node_built_for_relay_domain():
    con = duckdb.connect()
    _seed(con)
    _node_authenticated_users(con, "sccm")
    row = con.execute(
        "SELECT sid, name, sccm_infra, sccm_resource_ids, fallback_domain_sid "
        "FROM sccm.node_group WHERE sid = 'MAYYHEM.COM-S-1-5-11'"
    ).fetchone()
    assert row is not None
    sid, name, infra, rids, fallback = row
    assert name == "AUTHENTICATED USERS@MAYYHEM.COM"
    assert infra is False
    assert rids == []
    assert fallback == "S-1-5-21-1-2-3"   # domain SID stripped from a domain computer SID


def test_group_model_emits_authusers_with_domain_environmentid():
    con = duckdb.connect()
    _seed(con)
    _node_authenticated_users(con, "sccm")
    r = con.execute(
        "SELECT sid, name, sccm_infra, sccm_resource_ids, fallback_domain_sid "
        "FROM sccm.node_group WHERE sid = 'MAYYHEM.COM-S-1-5-11'"
    ).fetchone()
    node = GroupNode(
        sid=r[0], name=r[1], sccm_infra=r[2], sccm_resource_ids=r[3], fallback_domain_sid=r[4]
    ).as_node
    assert node is not None
    assert node.id == "MAYYHEM.COM-S-1-5-11"
    assert node.properties.environmentid == "S-1-5-21-1-2-3"
    assert "Group" in node.kinds and "Base" in node.kinds
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_authenticated_users_test.py -v`
Expected: FAIL — `ImportError: cannot import name '_node_authenticated_users'`.

- [ ] **Step 3: Add the node builder.** In `src/openhound_sccm/transforms.py`, add after `_edge_coerce_relay_smb`:

```python
def _node_authenticated_users(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Synthesise the Authenticated Users group node for every domain a Stage 6 relay edge
    starts from (CMBP Upsert-Node ps1:6609/6708/6766).

    id = UPPER(<FQDN>)-S-1-5-11 (SharpHound well-known-SID form, so it merges with
    SharpHound-collected AD data); name = 'AUTHENTICATED USERS@<FQDN-UPPER>'. environmentid
    is resolved by GroupNode from fallback_domain_sid — here the AD-domain SID of any
    domain-joined computer in that FQDN (S-1-5-11 has no domain part of its own).

    Lazy: only domains that actually produced a relay edge get a node — matching CMBP, where
    the node is upserted inside the relay loop. Inserted into node_group BEFORE
    _node_backfill / _graph_edges_split so the AD id set and GroupNode pick it up. The
    DISTINCT join to _domain_to_sid guarantees the edge's start id has a resolvable domain
    SID; the same domain computer that seeded the relay's start id seeds this map, so every
    relay-start id resolves."""
    from .kinds.edges import (
        COERCE_AND_RELAY_TO_ADMIN_SERVICE,
        COERCE_AND_RELAY_TO_MSSQL,
        COERCE_AND_RELAY_TO_SMB,
    )
    # UPPER(FQDN) -> AD-domain SID, from every domain-joined computer.
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _domain_to_sid AS "
        f"SELECT DISTINCT upper(regexp_replace(dnshostname, '^[^.]+\\.', '')) AS fqdn_upper, "
        f"  regexp_extract(upper(sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS domain_sid "
        f"FROM {schema}.node_computer "
        f"WHERE dnshostname LIKE '%.%' AND sid IS NOT NULL "
        f"  AND regexp_extract(upper(sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) != ''"
    )
    relay_kinds = (f"('{COERCE_AND_RELAY_TO_ADMIN_SERVICE}', "
                   f"'{COERCE_AND_RELAY_TO_MSSQL}', '{COERCE_AND_RELAY_TO_SMB}')")
    _safe(
        con, "node_group<-authenticated_users",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT DISTINCT ge.start_id AS sid, "
        f"  'AUTHENTICATED USERS@' || replace(ge.start_id, '-S-1-5-11', '') AS name, "
        f"  false AS sccm_infra, "
        f"  CAST([] AS VARCHAR[]) AS sccm_resource_ids, "
        f"  d.domain_sid AS fallback_domain_sid "
        f"FROM {schema}.graph_edges ge "
        f"JOIN _domain_to_sid d ON d.fqdn_upper = replace(ge.start_id, '-S-1-5-11', '') "
        f"WHERE ge.kind IN {relay_kinds} AND ge.start_id LIKE '%-S-1-5-11'"
    )
    n = con.execute(
        f"SELECT count(*) FROM {schema}.node_group WHERE sid LIKE '%-S-1-5-11'"
    ).fetchone()[0]
    logger.info("node_authenticated_users: %d AUTHENTICATED USERS node(s) in schema %r", n, schema)
```

- [ ] **Step 4: Wire all four builders into `transforms()`.** In `src/openhound_sccm/transforms.py`, in `transforms()`, immediately after the `_edge_mssql_db_assign_all(con, schema)` line and before `_graph_edges_dedup(con, schema)`, insert:

```python
    # Stage 6: coerce-and-relay possible edges + the synthetic Authenticated Users node.
    # disable_possible was read above (for _node_client_device_possible). The relay builders
    # gate the "assume vulnerable on null" cases on it (surgical, Stage 6 decision #1).
    # _node_authenticated_users runs AFTER the relay builders (it reads their start ids) and
    # BEFORE dedup/backfill/split (which read node_group for the AD id set).
    _edge_coerce_relay_adminservice(con, schema, disable_possible)
    _edge_coerce_relay_mssql(con, schema, disable_possible)
    _edge_coerce_relay_smb(con, schema, disable_possible)
    _node_authenticated_users(con, schema)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests/node_authenticated_users_test.py -v`
Expected: 2 passed.

- [ ] **Step 6: Run the FULL suite to confirm the wired pipeline is green end-to-end**

Run: `UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/tests -q`
Expected: all pass (Stage-5 baseline count + the new Stage-6 tests; 0 failed). If a prior whole-pipeline integration test asserts an exact edge/node count, update it to include the relay edges + AuthUsers node and note the change in the task report.

- [ ] **Step 7: Green checkpoint (NO commit).** Stop. Report PASS + the full-suite pass/fail/skip counts.

---

# Phase I — Documentation

### Task I1: README Edge/Node Reference + ARCHITECTURE.md

**Files:**
- Modify: `README.md`
- Modify: `ARCHITECTURE.md`
- (No test — verified by the code-truth review in Step 4.)

**Interfaces:** none (docs only).

- [ ] **Step 1: README — Edge Reference.** Add the three relay edges to the SCCM README Edge Reference table, matching the existing column layout. Use these code-true facts:

| Edge | Start → End | Traversable | `collectionSource` | Possible? |
|---|---|---|---|---|
| `CoerceAndRelayToAdminService` | Authenticated Users → SCCM_Site | Yes | `Post-processing` | Yes — gated by `--disable-possible-edges` (NTLM) |
| `CoerceAndRelayToMSSQL` | Authenticated Users → MSSQL_Login | Yes | `MSSQL-ScanForEPA` / `RemoteRegistry-MSSQL` | Yes — gated (NTLM + Extended Protection) |
| `CoerceAndRelayToSMB` | Authenticated Users → Computer | Yes | `SMB-Negotiate` / `RemoteRegistry-SMBSigningCheck` | Yes — gated (NTLM + SMB signing) |

Note the relay-only properties `coercionVictimAndRelayTargetPairs` (AdminService + MSSQL) and `coercionVictimHostnames` (SMB) and what they show the operator.

- [ ] **Step 2: README — Node Reference + `--disable-possible-edges` semantics.** Add a note under the `Group` node entry that a synthetic **Authenticated Users** group (`UPPER(<FQDN>)-S-1-5-11`, e.g. `MAYYHEM.COM-S-1-5-11`) is emitted as the start of every relay edge so it merges with SharpHound's well-known-SID node. In the `--disable-possible-edges` documentation, add the **surgical** Stage 6 behavior:

```markdown
With `--disable-possible-edges`, the three coerce-and-relay edges drop their
*assumed-vulnerable* cases and keep only *confirmed* ones: a relay survives only
when NTLM restriction is explicitly `Off` (not merely uncollected), the MSSQL
relay's Extended Protection is explicitly `Off`, and SMB signing is explicitly
not required. Without the flag (default), an uncollected NTLM/EPA setting is
assumed vulnerable, matching ConfigManBearPig.
```

Add a copy-pasteable mayyhem.com example showing both runs:

```bash
# default — speculative relays included
openhound preprocess sccm <raw> <raw>/lookup.duckdb
openhound convert sccm <raw>/sccm <graph> --lookup-file <raw>/lookup.duckdb

# high-confidence — only confirmed relay paths
openhound preprocess sccm <raw> <raw>/lookup.duckdb --disable-possible-edges
openhound convert sccm <raw>/sccm <graph-confirmed> --lookup-file <raw>/lookup.duckdb
```

- [ ] **Step 3: ARCHITECTURE.md.** In the preproc/convert divergence section: (a) update the §11c `graph_edges` column list to include `coercion_victim_and_relay_target_pairs VARCHAR[]` + `coercion_victim_hostnames VARCHAR[]` and note `GraphEdge` emits the relay-only `SCCMRelayEdgeProperties` subclass for the three `CoerceAndRelay*` kinds; (b) note `node_computer.smb_signing_source VARCHAR[]` (SMB-signing probe provenance, consumed by the SMB relay); (c) add a Stage 6 changelog entry summarizing the surgical `--disable-possible-edges` semantics, the lazy Authenticated Users node, and the `CoerceAndRelayToSMB` traversable bug fix. Fix any `file:line` references this change invalidates.

- [ ] **Step 4: Code-truth review.** Re-read the emitted edge kinds (`kinds/edges.py`), `SCCMRelayEdgeProperties` (`graph.py`), and the three builders. Confirm every README/ARCHITECTURE claim matches the code exactly (no edge/property the code doesn't emit; correct traversable flags; correct `collectionSource` tags). Per [[readme-code-truth-scope]], the README is code-truth for nodes/edges. Fix any mismatch.

- [ ] **Step 5: Green checkpoint (NO commit).** Stop. Report the doc sections changed + the code-truth check results.

---

# Phase J — Validation harness (final task)

### Task J1: Stage 6 manual-validation harness (code tour)

**Files:**
- Create: `docs/superpowers/plans/2026-06-30-sccm-preproc-convert-stage6-validation.md`

**Interfaces:** none (doc only).

- [ ] **Step 1: Write the harness doc** as a code tour (spec §6 style; mirror `2026-06-29-sccm-preproc-convert-stage5-validation.md`). It must contain:
  - A small in-process driver script: open the lab `lookup.duckdb`, call `transforms(con)`, then query `graph_edges_ad` for the three `CoerceAndRelay*` kinds and `node_group` for `%-S-1-5-11`.
  - Ordered breakpoints with exact `file:line` (resolve against the post-Stage-6 `transforms.py`): `_edge_coerce_relay_adminservice` (inspect the providers/servers CTE results), `_edge_coerce_relay_mssql` (inspect the EPA/NTLM gate), `_edge_coerce_relay_smb` (inspect `smb_signing_source` filtering), `_node_authenticated_users` (inspect `_domain_to_sid` + the inserted rows), `_graph_edges_dedup` (the coercion array-union), `_graph_edges_split` (relay rows land in `graph_edges_ad`). For each: what to inspect, expected debugger state, and which plan decision it verifies.
  - A black-box CLI smoke check against the lab raw tree (the Global-Constraints test loop), with the expected: three relay edges present with `traversable=true`; each carries non-empty coercion context + a real `collectionSource`; the `AUTHENTICATED USERS@<FQDN-UPPER>` group node present with `environmentid` = the lab domain SID; a second run with `--disable-possible-edges` drops the assumed-vulnerable relays and keeps only confirmed ones.

- [ ] **Step 2: Run the live black-box smoke check** against the existing lab raw tree (per the Global-Constraints loop). Record actual counts/ids observed (both default and `--disable-possible-edges`). If the lab has no relay-eligible topology (no SMS Provider/Site Server NTLM-unrestricted, no EPA-off SQL, no signing-disabled site system), note that and validate the negative case (zero relays) plus the synthetic unit-test coverage.

- [ ] **Step 3: Green checkpoint (NO commit).** Stop. Report the harness path + the live-run observations.

---

## Self-Review (run before handing off)

**1. Spec coverage (spec §6 Stage 6 + §3 inventory):**
- `Process-CoerceAndRelayToAdminService` → Task E1. ✓
- `Process-CoerceAndRelayToMSSQL` → Task F1. ✓
- `Process-CoerceAndRelayToSMB` → Task G1. ✓
- Synthetic Authenticated Users node (:6609/6708/6766) → Task H1. ✓
- EPA/SMB-signing/NTLM gating + possible-edge default + `--disable-possible-edges` → decision #1, implemented in E1/F1/G1; surgical semantics. ✓
- "EPA labeled per the uncertainty convention" → the MSSQL relay reads `extended_protection` as-collected (`Off`/`Allowed`/`Required`/`Unknown`) and only `Off`(or null-assumed) qualifies; the literal value is preserved on the `MSSQL_Server` node (Stage 5), satisfying [[feedback_epa_uncertainty_label]]. ✓
- Validate block (relays appear with possible-edges on; vanish/tighten with the flag; EPA labels read correctly) → Task J1. ✓

**2. Placeholder scan:** no "TBD"/"add error handling"/"similar to Task N"/"write tests for the above" — every code + test step carries real content. ✓

**3. Type/name consistency:** `COERCE_AND_RELAY_TO_*` constants (A1) used identically in `graph_edge.py` (B1) and the builders (E1/F1/G1/H1); `SCCMRelayEdgeProperties` field names (`coercionVictimAndRelayTargetPairs`, `coercionVictimHostnames`) match between `graph.py` (B1) and `graph_edge.py` (B1); DuckDB columns (`coercion_victim_and_relay_target_pairs`, `coercion_victim_hostnames`, `smb_signing_source`) match across `_graph_edges_init` (B1), `_graph_edges_dedup`/`_graph_edges_split` (C1), `_node_computer` (D1), and the builders; `_authed_users_id` defined in E1, reused in F1/G1; `node_mssql_login` columns (`login_id`/`server_id`/`host_sid`/`sysadmin_computer_sid`) match Stage 5's `_node_mssql_login`. ✓

**Risks to watch during execution:**
- A whole-pipeline integration test asserting an exact edge/node count will need updating once relays + AuthUsers are wired (Task H1 Step 6).
- `regexp_replace(dnshostname, '^[^.]+\.', '')` requires a dotted FQDN; the `LIKE '%.%'` guard is present in every builder + the `_domain_to_sid` map, so a bare-hostname infra computer is skipped (drop+log via the empty result) rather than producing a malformed id. CMBP's `$script:Domain` global fallback is intentionally NOT ported (no global primary domain exists in the set-based world); note this divergence in ARCHITECTURE.md (Task I1).

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-30-sccm-preproc-convert-stage6.md`. Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task (A1 → J1), two-stage review (spec-faithfulness + quality) between tasks, against the no-commit harness ([[sdd-no-commit-harness]]).

**2. Inline Execution** — execute the tasks in this session with checkpoints for review.
