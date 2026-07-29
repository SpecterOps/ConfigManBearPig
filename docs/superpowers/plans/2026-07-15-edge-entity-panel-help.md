# Per-edge Entity-Panel Help Content — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attach five entity-panel help properties (`general`, `windowsAbuse`, `linuxAbuse`, `opsec`, `references`) to every SCCM-emitted custom edge kind that BloodHound lacks native help for, with per-edge bespoke content.

**Architecture:** A per-kind content map (`edge_help.py`) holds one self-contained `EdgeHelp` block per authored kind. Five nullable help fields are added to the shared `SCCMEdgeProperties`; the existing `GraphEdge` emitter looks up the block by kind and spreads its non-`None` fields into the property bag. Edges whose kind has no block leave the fields `None`, and the existing `_without_null_properties` prune step drops them on emit — so no new pruning logic and no clutter on unrelated edges.

**Tech Stack:** Python 3, `dataclasses`, pytest, OpenHound convert pipeline, DuckDB (only via the existing convert path).

## Global Constraints

- **Only modify code under `sccm/sccm/`.** No changes to OpenHound core or the MSSQL extension. (CLAUDE.md)
- **Do NOT `git add` or commit.** Each task ends at a green checkpoint; the user commits. (CLAUDE.md + memory `sdd-no-commit-harness`)
- **Kind strings live only in `kinds/edges.py`.** Reference edge kinds via `from ..kinds import edges as ek` — never hardcode `"SCCM_..."` literals in models or the help map. (validate-extension.md)
- **Every property-dataclass field must be documented** in the class docstring's `Attributes` section. (graph-schema.md)
- **Property key casing is the output key verbatim.** Use exactly `general`, `windowsAbuse`, `linuxAbuse`, `opsec`, `references` (these mirror BloodHound's own edge-info vocabulary; there is no ConfigManBearPig precedent to match).
- **Prune relies on `None`, not empty.** Help fields default to `None` (strings) / `None` (references list) so unset keys are dropped by `_without_null_properties`; never default them to `""` or `[]`.
- **Tests go in `sccm/sccm/tests/`**, named `*_test.py` to match the existing edge tests. (CLAUDE.md)
- **Log every branch** at an appropriate level, or leave a comment where a log adds no value. (CLAUDE.md)
- Spec: `sccm/sccm/docs/superpowers/specs/2026-07-15-edge-entity-panel-help-design.md`. Ticket: **ope-aa39**.

**Scope (35 kinds).** Authored/pending set = SCCM_* (19) + CoerceAndRelay* (3) + MSSQL_* (11) + `SameHostAs` + `LocalAdminRequired`. **Excluded** (BloodHound native help): `MemberOf`, `HasSession`, `AdminTo`.

**Test command** (run from `sccm/sccm/`):
```
uv run pytest tests/<file>_test.py -v
```
Full validation (from `sccm/sccm/`): `uv run pytest`, `uv run ruff check src/`, `uv run mypy src/`. To avoid touching the local `.venv`, first set an isolated environment (bash: `export UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv`; PowerShell: `$env:UV_PROJECT_ENVIRONMENT="$env:TEMP\openhound-sccm-venv"`).

---

### Task 1: `edge_help.py` — content map, `EdgeHelp` dataclass, pending checklist

**Files:**
- Create: `sccm/sccm/src/openhound_sccm/edge_help.py`
- Test: `sccm/sccm/tests/edge_help_test.py`

**Interfaces:**
- Consumes: `openhound_sccm.kinds.edges` (kind constants).
- Produces:
  - `EdgeHelp` — frozen dataclass: `general: str`; `windowsAbuse: str | None = None`; `linuxAbuse: str | None = None`; `opsec: str | None = None`; `references: list[str] | None = None`; method `as_fields() -> dict[str, object]` returning only non-`None` fields.
  - `EDGE_HELP: dict[str, EdgeHelp]` — authored blocks, keyed by `ek.*` kind constants (starts with `SCCM_AdminsReplicatedTo` only).
  - `PENDING_HELP_KINDS: tuple[str, ...]` — the 34 scoped kinds still awaiting content.

- [ ] **Step 1: Write the failing tests**

Create `sccm/sccm/tests/edge_help_test.py`:

```python
"""Tests for the per-edge entity-panel help content map (edge_help.py)."""
from openhound_sccm.edge_help import EDGE_HELP, PENDING_HELP_KINDS, EdgeHelp
from openhound_sccm.kinds import edges as ek


def _valid_kind_strings() -> set[str]:
    """Every edge-kind string constant declared in kinds/edges.py."""
    return {
        v for name, v in vars(ek).items()
        if name.isupper() and isinstance(v, str)
    }


def test_as_fields_omits_none_sections():
    h = EdgeHelp(general="G")
    assert h.as_fields() == {"general": "G"}
    h2 = EdgeHelp(general="G", windowsAbuse="W", references=["u"])
    assert h2.as_fields() == {"general": "G", "windowsAbuse": "W", "references": ["u"]}


def test_admins_replicated_to_block_is_populated():
    block = EDGE_HELP[ek.SCCM_ADMINS_REPLICATED_TO]
    assert "replicated" in block.general.lower()
    assert block.windowsAbuse and "SharpSCCM" in block.windowsAbuse
    assert block.linuxAbuse and "sccmhunter" in block.linuxAbuse
    assert block.opsec and "EDR" in block.opsec
    assert block.references and all(r.startswith("http") for r in block.references)


def test_all_map_and_pending_keys_are_valid_edge_kinds():
    valid = _valid_kind_strings()
    unknown = (set(EDGE_HELP) | set(PENDING_HELP_KINDS)) - valid
    assert not unknown, f"Not real edge-kind constants: {unknown}"


def test_authored_and_pending_are_disjoint():
    overlap = set(EDGE_HELP) & set(PENDING_HELP_KINDS)
    assert not overlap, f"Kinds both authored and pending: {overlap}"


def test_native_help_kinds_are_excluded():
    # BloodHound ships native help for these; we must not author or list them.
    for kind in (ek.MEMBER_OF, ek.HAS_SESSION, "AdminTo"):
        assert kind not in EDGE_HELP
        assert kind not in PENDING_HELP_KINDS


def test_scope_is_complete():
    # Authored + pending must cover exactly the 35 scoped kinds.
    covered = set(EDGE_HELP) | set(PENDING_HELP_KINDS)
    assert len(covered) == 35, f"Expected 35 scoped kinds, got {len(covered)}: {sorted(covered)}"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/edge_help_test.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'openhound_sccm.edge_help'`.

- [ ] **Step 3: Create `edge_help.py`**

Create `sccm/sccm/src/openhound_sccm/edge_help.py`:

```python
"""Per-edge entity-panel help content for SCCM edges.

BloodHound renders an edge's properties in its entity panel but ships no native
help (General / Windows Abuse / Linux Abuse / OPSEC / References) for OpenGraph
custom edges. We supply that content as properties on each edge: this module maps
an edge kind to a self-contained `EdgeHelp` block, and `models/graph_edge.py`
merges the matching block into the edge's property bag.

Each block is authored independently (no shared/templated prose) so an operator
sees guidance specific to the exact edge they clicked. Kinds BloodHound already
documents natively (MemberOf, AdminTo, HasSession) are deliberately absent.
"""
from dataclasses import asdict, dataclass

from .kinds import edges as ek


@dataclass(frozen=True)
class EdgeHelp:
    """One edge kind's entity-panel help content.

    Attributes:
        general: What the edge means and why it matters (the "General" tab).
        windowsAbuse: How to abuse it from a Windows host (the "Windows Abuse" tab),
            or None if there is nothing Windows-specific to say.
        linuxAbuse: How to abuse it from a Linux host (the "Linux Abuse" tab), or None.
        opsec: Detection / operational-security considerations (the "OPSEC" tab), or None.
        references: Source URLs shown under the "References" tab, or None.
    """
    general: str
    windowsAbuse: str | None = None
    linuxAbuse: str | None = None
    opsec: str | None = None
    references: list[str] | None = None

    def as_fields(self) -> dict[str, object]:
        """Return only the non-None sections, keyed by their output property name.

        None sections are dropped here so they never reach the edge property bag;
        convert's null-pruning then keeps them off the emitted edge entirely.
        """
        return {k: v for k, v in asdict(self).items() if v is not None}


# Authored blocks, keyed by the edge-kind constants from kinds/edges.py so a renamed
# kind fails at import instead of silently dropping content. Add a block here (and
# remove the kind from PENDING_HELP_KINDS) as each one is written.
EDGE_HELP: dict[str, EdgeHelp] = {
    ek.SCCM_ADMINS_REPLICATED_TO: EdgeHelp(
        general=(
            "SCCM security roles assigned to users are replicated to every other site "
            "in the hierarchy. As a result, an administrative user created and/or granted "
            "permissions in one site will have the same permissions in every other site in "
            "the hierarchy. An attacker with control of any site gains control of every "
            "site in the hierarchy and as a result, control of every client device managed "
            "by the hierarchy."
        ),
        windowsAbuse=(
            "There is no specific abuse required to follow this attack path. As SCCM admin "
            "users are replicated between sites in the same hierarchy by design, an admin "
            "user created in any site in the hierarchy will have the same permissions in "
            "every other site in the hierarchy.\n"
            "To leverage SCCM administrative user permissions from a Windows machine, "
            "execute `SharpSCCM.exe <command> <subcommand> -sms <sms_provider_ip> "
            "-sc <site_code>` or leverage the Microsoft Configuration Manager Console "
            "software in the context of the admin user to connect to an SMS Provider for "
            "any site in the hierarchy."
        ),
        linuxAbuse=(
            "There is no specific abuse required to follow this attack path. As SCCM admin "
            "users are replicated between sites in the same hierarchy by design, an admin "
            "user created in any site in the hierarchy will have the same permissions in "
            "every other site in the hierarchy.\n"
            "To leverage SCCM administrative user permissions from a Linux machine, execute "
            "`python3 sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>` "
            "to connect to an SMS Provider for any site in the hierarchy."
        ),
        opsec=(
            "An EDR product may detect your attempt to run SharpSCCM and alert a SOC "
            "analyst. Proxying in SCCMHunter or the Configuration Manager Console software "
            "are less likely to be detected. Most actions in SCCM are logged to files in "
            "C:\\Program Files\\Microsoft Configuration Manager\\Logs. However, these logs "
            "are primarily for diagnostics/troubleshooting and it is uncommon for them to be "
            "forwarded to a SIEM. For more information, see the References tab."
        ),
        references=[
            "https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-role-based-administration",
            "https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087",
            "https://github.com/Mayyhem/SharpSCCM/wiki",
            "https://github.com/garrettfoster13/sccmhunter/wiki",
            "https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/log-file",
        ],
    ),
}


# Scoped edge kinds still awaiting authored content. As each block is written, add it
# to EDGE_HELP above and delete the kind here. Keeping unwritten kinds out of EDGE_HELP
# means no placeholder prose is ever emitted to BloodHound. The disjoint / scope tests
# in edge_help_test.py enforce that this list plus EDGE_HELP exactly covers the scope.
PENDING_HELP_KINDS: tuple[str, ...] = (
    # SCCM RBAC / topology
    ek.SCCM_IS_MAPPED_TO,
    ek.SCCM_IS_ASSIGNED,
    ek.SCCM_HAS_MEMBER,
    ek.SCCM_HAS_CLIENT,
    ek.SCCM_HAS_PRIMARY_USER,
    ek.SCCM_HAS_CURRENT_USER,
    ek.SCCM_HAS_AD_LAST_LOGON_USER,
    ek.SCCM_HAS_STORED_ACCOUNT,
    ek.SCCM_CONTAINS,
    ek.SCCM_FULL_ADMINISTRATOR,
    ek.SCCM_APPLICATION_AUTHOR,
    ek.SCCM_APPLICATION_ADMINISTRATOR,
    ek.SCCM_COMPLIANCE_SETTINGS_MANAGER,
    ek.SCCM_OSD_MANAGER,
    ek.SCCM_OPERATIONS_ADMINISTRATOR,
    ek.SCCM_SECURITY_ADMINISTRATOR,
    ek.SCCM_ALL_PERMISSIONS,
    ek.SCCM_ASSIGN_ALL_PERMISSIONS,
    # Coerce-and-relay
    ek.COERCE_AND_RELAY_TO_ADMIN_SERVICE,
    ek.COERCE_AND_RELAY_TO_MSSQL,
    ek.COERCE_AND_RELAY_TO_SMB,
    # MSSQL
    ek.MSSQL_CONTAINS,
    ek.MSSQL_CONTROL_SERVER,
    ek.MSSQL_CONTROL_DB,
    ek.MSSQL_HOST_FOR,
    ek.MSSQL_EXECUTE_ON_HOST,
    ek.MSSQL_HAS_LOGIN,
    ek.MSSQL_IS_MAPPED_TO,
    ek.MSSQL_MEMBER_OF,
    ek.MSSQL_SERVICE_ACCOUNT_FOR,
    ek.MSSQL_GET_ADMIN_TGS,
    ek.MSSQL_GET_TGS,
    # Host / local-admin
    ek.SAME_HOST_AS,
    ek.LOCAL_ADMIN_REQUIRED,
)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/edge_help_test.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Green checkpoint**

Run: `uv run ruff check src/openhound_sccm/edge_help.py` — expected: no findings.
Do **not** commit. Pause for the user to review and commit.

---

### Task 2: Emit help content on edges (`graph.py` fields + `graph_edge.py` lookup)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/graph.py` (add fields to `SCCMEdgeProperties`, ~line 48-62)
- Modify: `sccm/sccm/src/openhound_sccm/models/graph_edge.py` (import + lookup in `edges`)
- Test: `sccm/sccm/tests/edge_help_emit_test.py`

**Interfaces:**
- Consumes: `EDGE_HELP`, `EdgeHelp` from Task 1 (`openhound_sccm.edge_help`); `SCCMEdgeProperties` / `SCCMRelayEdgeProperties` from `openhound_sccm.graph`.
- Produces: edges built by `GraphEdge.edges` whose `.properties` carry `general` / `windowsAbuse` / `linuxAbuse` / `opsec` / `references` (all `str | None`, `references: list[str] | None`), populated from `EDGE_HELP` when the kind has a block and `None` otherwise.

- [ ] **Step 1: Write the failing tests**

Create `sccm/sccm/tests/edge_help_emit_test.py`:

```python
"""GraphEdge merges entity-panel help content into the edge property bag."""
from openhound_sccm import edge_help
from openhound_sccm.edge_help import EDGE_HELP, EdgeHelp
from openhound_sccm.graph import SCCMEdgeProperties, SCCMRelayEdgeProperties
from openhound_sccm.kinds import edges as ek
from openhound_sccm.models.graph_edge import GraphEdge


def _edge(kind, **kw):
    return next(iter(GraphEdge(start_id="A", end_id="B", kind=kind, **kw).edges))


def test_authored_kind_edge_carries_help():
    e = _edge(ek.SCCM_ADMINS_REPLICATED_TO)
    block = EDGE_HELP[ek.SCCM_ADMINS_REPLICATED_TO]
    assert e.properties.general == block.general
    assert e.properties.windowsAbuse == block.windowsAbuse
    assert e.properties.linuxAbuse == block.linuxAbuse
    assert e.properties.opsec == block.opsec
    assert e.properties.references == block.references


def test_excluded_kind_edge_has_no_help():
    e = _edge(ek.MEMBER_OF)
    assert e.properties.general is None
    assert e.properties.windowsAbuse is None
    assert e.properties.linuxAbuse is None
    assert e.properties.opsec is None
    assert e.properties.references is None


def test_pending_kind_edge_has_no_help_until_authored():
    # A kind still in PENDING_HELP_KINDS (no block yet) emits no help fields.
    e = _edge(ek.SCCM_IS_MAPPED_TO)
    assert e.properties.general is None
    assert e.properties.references is None


def test_relay_edge_merges_help_and_keeps_coercion(monkeypatch):
    # Inject a block for a relay kind so the test does not depend on authored content.
    # graph_edge imported EDGE_HELP by reference, so mutating this dict is visible there.
    monkeypatch.setitem(EDGE_HELP, ek.COERCE_AND_RELAY_TO_SMB, EdgeHelp(general="RELAY-GENERAL"))
    e = _edge(
        ek.COERCE_AND_RELAY_TO_SMB,
        coercion_victim_hostnames=["SS01.mayyhem.com"],
    )
    assert isinstance(e.properties, SCCMRelayEdgeProperties)
    assert e.properties.general == "RELAY-GENERAL"          # help merged in
    assert e.properties.coercionVictimHostnames == ["SS01.mayyhem.com"]  # relay context intact


def test_help_fields_optional_sections_stay_none(monkeypatch):
    # A block with only `general` leaves the other four fields None on the edge.
    monkeypatch.setitem(EDGE_HELP, ek.SCCM_CONTAINS, EdgeHelp(general="ONLY-GENERAL"))
    e = _edge(ek.SCCM_CONTAINS)
    assert e.properties.general == "ONLY-GENERAL"
    assert e.properties.windowsAbuse is None
    assert e.properties.references is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/edge_help_emit_test.py -v`
Expected: FAIL — `test_authored_kind_edge_carries_help` errors with `AttributeError: 'SCCMEdgeProperties' object has no attribute 'general'` (fields not added yet).

- [ ] **Step 3: Add the five help fields to `SCCMEdgeProperties`**

In `sccm/sccm/src/openhound_sccm/graph.py`, extend the `SCCMEdgeProperties` docstring `Attributes` section and add the fields after `collectionSource`:

```python
@dataclass
class SCCMEdgeProperties(EdgeProperties):
    """Property set carried by every edge this collector emits.

    Property names mirror ConfigManBearPig.ps1 exactly so BloodHound entity panels
    render the keys operators know from the original tool. `traversable`/`composed`
    come from the framework EdgeProperties base and already match CMBP. The five
    help fields carry entity-panel documentation (see edge_help.py); they default to
    None so edges without authored content omit them (convert prunes null values).

    Attributes:
        collectionSource: Which collection method(s) produced this edge (e.g.
            ``AdminService``, ``LDAP``, ``RemoteRegistry``), as a list of tags. An edge
            can be confirmed by more than one method, in which case the list has
            more than one entry.
        general: Entity-panel "General" text — what this edge means and why it
            matters — or None if no help content is authored for this edge kind.
        windowsAbuse: Entity-panel "Windows Abuse" text — how to abuse this edge from
            a Windows host — or None.
        linuxAbuse: Entity-panel "Linux Abuse" text — how to abuse this edge from a
            Linux host — or None.
        opsec: Entity-panel "OPSEC" text — detection / operational-security
            considerations for abusing this edge — or None.
        references: Entity-panel "References" URLs for this edge kind, or None.
    """
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    general: str | None = field(default=None, kw_only=True)
    windowsAbuse: str | None = field(default=None, kw_only=True)
    linuxAbuse: str | None = field(default=None, kw_only=True)
    opsec: str | None = field(default=None, kw_only=True)
    references: list[str] | None = field(default=None, kw_only=True)
```

`SCCMRelayEdgeProperties` subclasses `SCCMEdgeProperties`, so it inherits these fields — no change there.

- [ ] **Step 4: Wire the lookup into `GraphEdge.edges`**

In `sccm/sccm/src/openhound_sccm/models/graph_edge.py`, add the import near the other local imports:

```python
from ..edge_help import EDGE_HELP
```

Then replace the body of the `edges` property (currently at lines ~60-93) with:

```python
    @property
    def edges(self) -> Iterator[Edge]:
        """Yield one Edge for this row.

        If start_id, end_id, or kind is missing, the row is dropped with a
        warning rather than emitting a malformed edge. Entity-panel help content
        (edge_help.py) is merged into the property bag for kinds we document; other
        kinds leave the help fields None and convert prunes them on emit.
        """
        if not self.start_id or not self.end_id or not self.kind:
            logger.warning(
                "GraphEdge: dropping incomplete row (start=%r end=%r kind=%r)",
                self.start_id, self.end_id, self.kind,
            )
            return
        traversable = self.kind in self.traversable_kinds
        # Merge entity-panel help for this kind, if any is authored.
        help_block = EDGE_HELP.get(self.kind)
        if help_block:
            help_fields = help_block.as_fields()
            logger.debug("GraphEdge: attached entity-panel help for kind %r", self.kind)
        else:
            help_fields = {}
            logger.debug("GraphEdge: no entity-panel help authored for kind %r", self.kind)
        if self.kind in _RELAY_KINDS:
            # Relay edges carry the operator-facing coercion context (CMBP).
            properties = SCCMRelayEdgeProperties(
                traversable=traversable,
                collectionSource=self.collection_source or [],
                coercionVictimAndRelayTargetPairs=self.coercion_victim_and_relay_target_pairs or [],
                coercionVictimHostnames=self.coercion_victim_hostnames or [],
                **help_fields,
            )
        else:
            # Every other edge keeps the lean base properties.
            properties = SCCMEdgeProperties(
                traversable=traversable,
                collectionSource=self.collection_source or [],
                **help_fields,
            )
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=properties,
        )
```

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `uv run pytest tests/edge_help_emit_test.py -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Run the existing edge/graph tests to confirm no regression**

Run: `uv run pytest tests/graph_edge_test.py tests/graph_edge_relay_props_test.py tests/graph_edges_test.py -v`
Expected: PASS (all existing edge tests still green — help fields are additive and default None).

- [ ] **Step 7: Green checkpoint**

Run: `uv run ruff check src/openhound_sccm/graph.py src/openhound_sccm/models/graph_edge.py` — expected: no findings.
Do **not** commit. Pause for the user to review and commit.

---

### Task 3: End-to-end validation + README Edge Reference update

**Files:**
- Test: `sccm/sccm/tests/edge_help_integration_test.py`
- Modify: `sccm/sccm/README.md` (Edge Reference section)

**Interfaces:**
- Consumes: the full convert pipeline (`python -m openhound preprocess` / `convert`) and the `SCCM_AdminsReplicatedTo` block authored in Task 1; the prune behavior in `convert_pipeline.py`.
- Produces: proof that help keys appear on authored edges and are absent from unauthored/excluded edges in the emitted `*.json`, and user-facing docs.

- [ ] **Step 1: Write the failing integration test**

Create `sccm/sccm/tests/edge_help_integration_test.py`. It reuses the seeding approach from `convert_integration_test.py` (a CAS + Primary site produces a real `SCCM_AdminsReplicatedTo` edge) and asserts on the emitted JSON:

```python
"""End-to-end: help content lands on SCCM_AdminsReplicatedTo edges and is pruned elsewhere."""
import gzip
import json
import subprocess
import sys
from pathlib import Path

_SITE_CODE_CAS = "CAS"
_SITE_CODE_PRIMARY = "PS1"


def _seed_raw(raw: Path) -> None:
    """Two site definitions (CAS parent of PS1) -> one SCCM_AdminsReplicatedTo edge."""
    site_def_dir = raw / "sccm" / "adminservice_site_definitions"
    site_def_dir.mkdir(parents=True)
    with gzip.open(site_def_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "site_code": _SITE_CODE_CAS,
            "parent_site_code": None,
            "site_type": 4,
            "site_guid": "00000000-0000-0000-0000-000000000000",
            "sql_server_name": "SQLSRV",
            "sql_database_name": "CM_CAS",
        }) + "\n")
        fh.write(json.dumps({
            "site_code": _SITE_CODE_PRIMARY,
            "parent_site_code": _SITE_CODE_CAS,
            "site_type": 2,
            "site_guid": "11111111-1111-1111-1111-111111111111",
            "sql_server_name": "SQLSRV",
            "sql_database_name": "CM_PS1",
        }) + "\n")


def test_help_content_emitted_on_replicated_edge_and_pruned_elsewhere(tmp_path):
    raw = tmp_path / "raw"
    _seed_raw(raw)
    db = tmp_path / "lookup.duckdb"
    graph = tmp_path / "graph"

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "openhound", *args], capture_output=True, text=True
        )

    pre = run("preprocess", "sccm", str(raw), str(db))
    assert pre.returncode == 0, f"preprocess failed:\n{pre.stderr}"
    conv = run("convert", "sccm", str(raw / "sccm"), str(graph), "--lookup-file", str(db))
    assert conv.returncode == 0, f"convert failed:\n{conv.stderr}"

    edges = []
    for f in graph.glob("*.json"):
        edges += json.loads(f.read_text())["graph"]["edges"]

    replicated = [e for e in edges if e["kind"] == "SCCM_AdminsReplicatedTo"]
    assert replicated, f"No SCCM_AdminsReplicatedTo edge emitted; kinds: {[e['kind'] for e in edges]}"

    props = replicated[0]["properties"]
    # Authored keys present with real content.
    for key in ("general", "windowsAbuse", "linuxAbuse", "opsec", "references"):
        assert key in props, f"Expected help key {key!r} on SCCM_AdminsReplicatedTo; got {sorted(props)}"
    assert "replicated" in props["general"].lower()
    assert isinstance(props["references"], list) and props["references"][0].startswith("http")

    # An edge whose kind has no block (if any present) must not carry help keys.
    for e in edges:
        if e["kind"] not in ("SCCM_AdminsReplicatedTo",):
            assert "general" not in e["properties"], (
                f"Unauthored kind {e['kind']!r} leaked a 'general' help key"
            )
```

- [ ] **Step 2: Run the integration test to verify it fails, then passes**

Run: `uv run pytest tests/edge_help_integration_test.py -v`
Expected before Tasks 1-2 are merged: FAIL. With Tasks 1-2 in place: PASS. (If run right after Task 2, it should already PASS — that is the confirmation this task validates.)

- [ ] **Step 3: Update the README Edge Reference section**

Open `sccm/sccm/README.md`, find the **Edge Reference** section, and add a subsection documenting the help properties. Insert this after the edge table/intro:

```markdown
#### Entity-panel help properties

Edges that describe an SCCM-specific attack path carry documentation in their
property bag so BloodHound's entity panel explains the edge when you click it.
The keys mirror BloodHound's built-in edge help:

| Property | Meaning |
|---|---|
| `general` | What the edge means and why it matters. |
| `windowsAbuse` | How to abuse the edge from a Windows host. |
| `linuxAbuse` | How to abuse the edge from a Linux host. |
| `opsec` | Detection / operational-security considerations. |
| `references` | Source URLs (list of strings). |

Only sections that apply are emitted; an edge kind with no authored content carries
none of these keys. Kinds BloodHound already documents natively (`MemberOf`,
`AdminTo`, `HasSession`) are intentionally left to BloodHound's own help. The content
lives in `src/openhound_sccm/edge_help.py`; kinds still awaiting content are listed
there in `PENDING_HELP_KINDS`.

Example (`SCCM_AdminsReplicatedTo`, abbreviated):

​```json
"properties": {
  "traversable": true,
  "collectionSource": ["AdminService"],
  "general": "SCCM security roles assigned to users are replicated to every other site...",
  "windowsAbuse": "Execute SharpSCCM.exe <command> <subcommand> -sms <sms_provider_ip> -sc <site_code>...",
  "linuxAbuse": "python3 sccmhunter.py admin -u <username> -p <password> -ip <sms_provider_ip>...",
  "opsec": "An EDR product may detect your attempt to run SharpSCCM...",
  "references": ["https://posts.specterops.io/sccm-hierarchy-takeover-41929c61e087", "..."]
}
​```
```

(Remove the zero-width spaces before the inner code fences — they are only here so this plan renders; the README should use plain triple backticks.)

- [ ] **Step 4: Full validation suite**

Run from `sccm/sccm/`:
```
uv run pytest tests/edge_help_test.py tests/edge_help_emit_test.py tests/edge_help_integration_test.py -v
uv run ruff check src/
uv run mypy src/openhound_sccm/edge_help.py src/openhound_sccm/graph.py src/openhound_sccm/models/graph_edge.py
```
Expected: all pytest green; ruff clean; mypy clean for the touched files. If mypy reports pre-existing errors elsewhere, note them as out-of-scope.

- [ ] **Step 5: Green checkpoint**

Confirm the three test files pass and the README renders. Do **not** commit. Report completion to the user with: files changed, tests added, validation results, and the reminder that `PENDING_HELP_KINDS` holds the 34 kinds still needing prose.

---

## Self-Review

**Spec coverage:**
- Property bag delivery → Task 2 (fields on `SCCMEdgeProperties`, merge in `GraphEdge`). ✓
- Per-kind content map + tiny shared emit → Task 1 (`EDGE_HELP` + `as_fields()`), Task 2 (~lookup lines). ✓
- Scope: 35 included, `MemberOf`/`AdminTo`/`HasSession` excluded → Task 1 tests `test_scope_is_complete`, `test_native_help_kinds_are_excluded`. ✓
- Five flat keys, references as string list, keys mirror BloodHound vocabulary → Task 2 field definitions. ✓
- `None` defaults so unset keys prune → Task 2 fields default `None`; Task 3 integration asserts absence on unauthored kinds. ✓
- Vertical slice (`SCCM_AdminsReplicatedTo` wired + validated) + scaffold for the rest → Task 1 authored block + `PENDING_HELP_KINDS`; Task 3 end-to-end. ✓
- README Edge Reference update → Task 3 Step 3. ✓
- Cross-extension flag (MSSQL blocks stay SCCM-local) → recorded in spec; no code needed (blocks simply authored in this extension). ✓

**Placeholder scan:** The only "TODO"-adjacent content is `PENDING_HELP_KINDS`, which is the intended product deliverable (a checklist of unwritten kinds), not a plan gap. All code steps contain full code. ✓

**Type consistency:** `EdgeHelp.as_fields()` used identically in Task 1 (definition) and Task 2 (call). Field names `general`/`windowsAbuse`/`linuxAbuse`/`opsec`/`references` identical across `edge_help.py`, `SCCMEdgeProperties`, and both test files. `EDGE_HELP` / `PENDING_HELP_KINDS` names consistent throughout. ✓
