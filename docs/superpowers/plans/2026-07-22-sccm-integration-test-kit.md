# Python Integration-Test Kit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the PowerShell unit-test kit with a Python engine invoked from `collect sccm`, adding `--run-integration-tests` (assert the freshly-built graph against mayyhem fixtures) and `--compare-to-zip` (deep property-level diff of this run vs an arbitrary payload).

**Architecture:** A collector-agnostic engine lives in a new `openhound_collector_common/integration_testing/` subpackage (loader, matcher, cases, results, runner, comparator, coverage). SCCM-specific fixtures + CLI wiring live in `openhound_sccm/integration/` and `openhound_sccm/main.py`. Both flags self-chain `--run-all`, then run in-process against the convert output directory.

**Tech Stack:** Python 3.13+ (stdlib only: `json`, `zipfile`, `fnmatch`, `pathlib`, `dataclasses`, `collections`), Typer (existing CLI), pytest 9.

## Global Constraints

- **No git commits.** This repo runs the no-commit harness: each task ends at a *green checkpoint* (tests pass); the human commits. Never run `git add`/`git commit`.
- **Shared-lib edits are owner-approved for this work only** and must be **additive** — create the new `integration_testing/` subpackage; do **not** modify existing `openhound_collector_common` modules.
- **Stdlib only** in the shared engine (no new third-party deps).
- **Python:** `requires-python >=3.13,<3.15`. Modern syntax (`X | None`, `match`) is fine.
- **Edge/node kind strings** are the new schema-aligned names (`SCCM_`/`MSSQL_` prefixed); never reintroduce the old bare names or the CMBP typo `CoerceAndRelaytoSMB`.
- **Runner used by the CLI must not raise on assertion failures** — it returns a `Summary`; the CLI maps `failed > 0` to a non-zero exit.
- **Test commands** use the SCCM venv (the shared lib is an editable dep there):
  `./sccm/sccm/.venv/Scripts/python.exe -m pytest <path> -v` (run from repo root `c:\Users\domainadmin\Desktop\OpenHound`).
- **Test file naming:** shared lib → `openhound-collector-common/tests/test_*.py`; SCCM → `sccm/sccm/tests/*_test.py`.

---

## File Structure

**Shared engine (create):**
- `openhound-collector-common/src/openhound_collector_common/integration_testing/__init__.py`
- `.../integration_testing/graph.py` — `Node`, `Edge`, `Graph`, `load_graph`
- `.../integration_testing/cases.py` — `CountSpec`, `NodePattern`, `EdgeCase`, `NodeCase`
- `.../integration_testing/matcher.py` — `property_match`, `node_matches`, `edge_matches`
- `.../integration_testing/results.py` — `Result`, `Summary`, `write_results_json`, `PASS/FAIL/SKIP`
- `.../integration_testing/coverage.py` — `load_schema_kinds`, `coverage`, `report`
- `.../integration_testing/runner.py` — `run_edge_case`, `run_node_case`, `run_suite`, `Invariant`
- `.../integration_testing/compare.py` — `compare_graphs`, `ComparisonReport`, `PropDiff`
- Tests: `openhound-collector-common/tests/test_integration_graph.py`, `_matcher.py`, `_runner.py`, `_compare.py`, `_coverage.py`

**SCCM extension (create/modify):**
- `sccm/sccm/src/openhound_sccm/integration/__init__.py` — `run_integration_tests`, `compare_to_zip`
- `sccm/sccm/src/openhound_sccm/integration/fixtures/__init__.py`
- `.../integration/fixtures/edges.py` — `MAYYHEM_EDGE_CASES`
- `.../integration/fixtures/nodes.py` — `MAYYHEM_NODE_CASES`, `MAYYHEM_INVARIANTS`
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (two typer Options on `collect_sccm` + hook)
- Tests: `sccm/sccm/tests/integration_fixtures_test.py`, `integration_wiring_test.py`, `integration_cli_flags_test.py`

**Docs (modify):**
- `sccm/sccm/README.md`, `sccm/sccm/ARCHITECTURE.md`

---

## Task 1: Shared `graph.py` — model + loader

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/integration_testing/__init__.py` (empty)
- Create: `openhound-collector-common/src/openhound_collector_common/integration_testing/graph.py`
- Test: `openhound-collector-common/tests/test_integration_graph.py`

**Interfaces:**
- Produces: `Node(id:str, kinds:list[str], properties:dict)`, `Edge(kind:str, start:str, end:str, properties:dict)`, `Graph(nodes, edges)` with `.node(id)->Node|None`, `.edges_of_kind(kind)->list[Edge]`, `.nodes`, `.edges`; `load_graph(path:str|Path)->Graph` (accepts a dir of `*.json` or a `.zip`).

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_integration_graph.py
import json, zipfile
from pathlib import Path
from openhound_collector_common.integration_testing.graph import load_graph, Graph, Node, Edge

PAYLOAD_A = {"graph": {"nodes": [
    {"id": "N1", "kinds": ["SCCM_Site", "Base"], "properties": {"siteCode": "PS1"}}],
    "edges": [{"kind": "SCCM_HasClient", "start": {"value": "N1"}, "end": {"value": "N2"},
               "properties": {"traversable": True}}]}}
PAYLOAD_B = {"graph": {"nodes": [
    {"id": "N2", "kinds": ["SCCM_ClientDevice"], "properties": {}}], "edges": []}}

def _write_dir(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(PAYLOAD_A), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(PAYLOAD_B), encoding="utf-8")
    return tmp_path

def test_load_from_directory(tmp_path):
    g = load_graph(_write_dir(tmp_path))
    assert len(g.nodes) == 2 and len(g.edges) == 1
    assert g.node("N1").properties["siteCode"] == "PS1"
    assert g.edges_of_kind("SCCM_HasClient")[0].start == "N1"
    assert g.edges_of_kind("SCCM_HasClient")[0].end == "N2"

def test_load_from_zip(tmp_path):
    d = _write_dir(tmp_path)
    zp = tmp_path / "payload.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.write(d / "a.json", "a.json"); zf.write(d / "b.json", "b.json")
    g = load_graph(zp)
    assert len(g.nodes) == 2 and g.node("N2") is not None

def test_duplicate_node_id_merges(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"graph": {"nodes": [
        {"id": "X", "kinds": ["Computer"], "properties": {"a": 1, "b": None}}], "edges": []}}), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps({"graph": {"nodes": [
        {"id": "X", "kinds": ["Base"], "properties": {"b": 2}}], "edges": []}}), encoding="utf-8")
    g = load_graph(tmp_path)
    n = g.node("X")
    assert set(n.kinds) == {"Computer", "Base"} and n.properties["a"] == 1 and n.properties["b"] == 2
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_graph.py -v`
Expected: FAIL — `ModuleNotFoundError: ...integration_testing.graph`.

- [ ] **Step 3: Write the implementation**

```python
# openhound-collector-common/src/openhound_collector_common/integration_testing/graph.py
"""In-memory graph model + loader for OpenGraph node/edge JSON payloads.

Collector-agnostic: any {"graph": {"nodes": [...], "edges": [...]}} payload
(SCCM, MSSQL, or ConfigManBearPig) loads the same way. Accepts a directory of
*.json files or a .zip containing them.
"""
from __future__ import annotations

import json
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Node:
    id: str
    kinds: list[str] = field(default_factory=list)
    properties: dict = field(default_factory=dict)


@dataclass
class Edge:
    kind: str
    start: str
    end: str
    properties: dict = field(default_factory=dict)


class Graph:
    """Loaded nodes + edges with an id->Node index and a kind filter for edges."""

    def __init__(self, nodes: list[Node], edges: list[Edge]) -> None:
        self.nodes = nodes
        self.edges = edges
        self._by_id: dict[str, Node] = {}
        for n in nodes:
            existing = self._by_id.get(n.id)
            if existing is None:
                self._by_id[n.id] = n
                continue
            # Duplicate id across payloads (e.g. sccm_ + ad_): union kinds and
            # merge properties (existing non-null value wins). Keep one Node.
            for k in n.kinds:
                if k not in existing.kinds:
                    existing.kinds.append(k)
            for key, val in n.properties.items():
                if existing.properties.get(key) in (None, "", [], {}):
                    existing.properties[key] = val
            logger.debug("Graph: merged duplicate node id %r", n.id)

    def node(self, node_id: str) -> Node | None:
        return self._by_id.get(node_id)

    def edges_of_kind(self, kind: str) -> list[Edge]:
        return [e for e in self.edges if e.kind == kind]


def _iter_payload_files(path: Path) -> list[tuple[str, str]]:
    """Return (name, text) for each *.json payload in a dir or inside a zip."""
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            return [(name, zf.read(name).decode("utf-8"))
                    for name in zf.namelist() if name.lower().endswith(".json")]
    if path.is_dir():
        return [(p.name, p.read_text(encoding="utf-8")) for p in sorted(path.glob("*.json"))]
    raise ValueError(f"load_graph: {path} is neither a .zip nor a directory")


def load_graph(path: str | Path) -> Graph:
    """Load a Graph from a directory of *.json files or a .zip of them."""
    path = Path(path)
    nodes: list[Node] = []
    edges: list[Edge] = []
    files = _iter_payload_files(path)
    logger.info("load_graph: reading %d payload file(s) from %s", len(files), path)
    for _name, text in files:
        graph = (json.loads(text).get("graph") or {})
        for raw in graph.get("nodes") or []:
            nodes.append(Node(id=raw["id"], kinds=list(raw.get("kinds") or []),
                              properties=dict(raw.get("properties") or {})))
        for raw in graph.get("edges") or []:
            edges.append(Edge(kind=raw["kind"], start=raw["start"]["value"],
                              end=raw["end"]["value"], properties=dict(raw.get("properties") or {})))
    logger.info("load_graph: %d nodes, %d edges", len(nodes), len(edges))
    return Graph(nodes, edges)
```

Also create the empty package marker:
```python
# openhound-collector-common/src/openhound_collector_common/integration_testing/__init__.py
"""Collector-agnostic integration-test engine (loader, matcher, runner, comparator)."""
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_graph.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Green checkpoint** — tests green; leave uncommitted for the human.

---

## Task 2: Shared `cases.py` — typed case model

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/integration_testing/cases.py`
- Test: `openhound-collector-common/tests/test_integration_cases.py`

**Interfaces:**
- Produces: `CountSpec(exact:int|None, at_least:int|None, at_most:int|None)` with `.satisfied_by(n:int)->bool`; `NodePattern(kinds:list[str]|None, properties:dict|None)`; `EdgeCase(id, kind, description, source:NodePattern|None, target:NodePattern|None, properties:dict|None, count:CountSpec|None, negative:bool, reason:str|None)`; `NodeCase(id, description, kinds:list[str], properties:dict|None, count:CountSpec|None, negative:bool)`.

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_integration_cases.py
from openhound_collector_common.integration_testing.cases import CountSpec, NodePattern, EdgeCase, NodeCase

def test_countspec_semantics():
    assert CountSpec(exact=3).satisfied_by(3) and not CountSpec(exact=3).satisfied_by(2)
    assert CountSpec(at_least=2).satisfied_by(5) and not CountSpec(at_least=2).satisfied_by(1)
    assert CountSpec(at_most=2).satisfied_by(2) and not CountSpec(at_most=2).satisfied_by(3)
    assert CountSpec(at_least=1, at_most=3).satisfied_by(2)
    assert CountSpec().satisfied_by(999)  # no bounds => any

def test_case_defaults():
    e = EdgeCase(id="e1", kind="SCCM_HasClient", description="d")
    assert e.source is None and e.negative is False and e.count is None
    n = NodeCase(id="n1", description="d", kinds=["SCCM_Site"])
    assert n.properties is None and n.count is None
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_cases.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```python
# openhound-collector-common/src/openhound_collector_common/integration_testing/cases.py
"""Typed integration-test cases (collector-agnostic data model)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CountSpec:
    """Expected match count. None fields are unconstrained; combine at_least+at_most for a range."""
    exact: int | None = None
    at_least: int | None = None
    at_most: int | None = None

    def satisfied_by(self, n: int) -> bool:
        if self.exact is not None and n != self.exact:
            return False
        if self.at_least is not None and n < self.at_least:
            return False
        if self.at_most is not None and n > self.at_most:
            return False
        return True


@dataclass
class NodePattern:
    kinds: list[str] | None = None
    properties: dict | None = None


@dataclass
class EdgeCase:
    id: str
    kind: str
    description: str
    source: NodePattern | None = None
    target: NodePattern | None = None
    properties: dict | None = None
    count: CountSpec | None = None
    negative: bool = False
    reason: str | None = None


@dataclass
class NodeCase:
    id: str
    description: str
    kinds: list[str]
    properties: dict | None = None
    count: CountSpec | None = None
    negative: bool = False
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_cases.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Green checkpoint.**

---

## Task 3: Shared `matcher.py` — pattern matching

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/integration_testing/matcher.py`
- Test: `openhound-collector-common/tests/test_integration_matcher.py`

**Interfaces:**
- Consumes: `graph.Node/Edge/Graph`, `cases.NodePattern/EdgeCase`.
- Produces: `property_match(actual, expected)->bool`; `node_matches(node:Node, pattern:NodePattern)->bool`; `edge_matches(edge:Edge, graph:Graph, case:EdgeCase)->bool`.

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_integration_matcher.py
from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.cases import NodePattern, EdgeCase
from openhound_collector_common.integration_testing.matcher import property_match, node_matches, edge_matches

def test_property_match_branches():
    assert property_match(None, None)
    assert not property_match(None, "x") and not property_match("x", None)
    assert property_match("MAYYHEM\\PS1$@x:1433", "*:1433")     # wildcard
    assert property_match("PS1", "ps1")                          # case-insensitive exact
    assert property_match(["a", "b", "c"], ["b"])               # list subset (expected in actual)
    assert not property_match(["a"], ["z"])
    assert property_match("True", True) and property_match("0", False)  # bool coercion

def test_node_matches_kinds_and_props():
    n = Node(id="MAYYHEM.COM-S-1-5-11", kinds=["Group", "Base"], properties={})
    assert node_matches(n, NodePattern(kinds=["Group"], properties={"id": "*-S-1-5-11"}))
    assert not node_matches(n, NodePattern(kinds=["User"]))

def test_edge_matches_full():
    g = Graph(
        nodes=[Node("A", ["Group", "Base"], {}), Node("B", ["MSSQL_Login"], {})],
        edges=[Edge("MSSQL_CoerceAndRelayToMSSQL", "A", "B", {"coercionVictimAndRelayTargetPairs": ["Coerce x, relay to y:1433"]})],
    )
    case = EdgeCase(id="c", kind="MSSQL_CoerceAndRelayToMSSQL", description="d",
                    source=NodePattern(kinds=["Group"], properties={"id": "A"}),
                    target=NodePattern(kinds=["MSSQL_Login"]),
                    properties={"coercionVictimAndRelayTargetPairs": ["Coerce x, relay to y:1433"]})
    assert edge_matches(g.edges[0], g, case)
    bad = EdgeCase(id="c2", kind="MSSQL_CoerceAndRelayToMSSQL", description="d",
                   target=NodePattern(kinds=["User"]))
    assert not edge_matches(g.edges[0], g, bad)
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_matcher.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```python
# openhound-collector-common/src/openhound_collector_common/integration_testing/matcher.py
"""Wildcard/pattern matching — port of the PowerShell kit's Test-*Pattern helpers."""
from __future__ import annotations

import fnmatch

from openhound_collector_common.integration_testing.cases import EdgeCase, NodePattern
from openhound_collector_common.integration_testing.graph import Edge, Graph, Node


def property_match(actual, expected) -> bool:
    """Match one property value. Ports Test-PropertyMatch."""
    if actual is None and expected is None:
        return True
    if actual is None or expected is None:
        return False
    # Lists: every expected item must match some actual item (subset).
    if isinstance(expected, list) and isinstance(actual, list):
        return all(any(property_match(a, e) for a in actual) for e in expected)
    if isinstance(expected, list) or isinstance(actual, list):
        return False
    # Booleans: coerce the actual side ("True"/"1"/"False"/"0").
    if isinstance(expected, bool):
        if isinstance(actual, bool):
            return actual == expected
        s = str(actual).strip().lower()
        if s in ("true", "1"):
            return expected is True
        if s in ("false", "0"):
            return expected is False
        return False
    actual_s, expected_s = str(actual), str(expected)
    if "*" in expected_s or "?" in expected_s:
        return fnmatch.fnmatch(actual_s.lower(), expected_s.lower())
    return actual_s.lower() == expected_s.lower()


def _node_prop(node: Node, key: str):
    """Property lookup: node.properties[key], falling back to node.id / node.kinds."""
    if key in node.properties:
        return node.properties[key]
    if key == "id":
        return node.id
    if key == "kinds":
        return node.kinds
    return None


def node_matches(node: Node, pattern: NodePattern) -> bool:
    """Ports Test-NodePattern: kind subset (Base always satisfied) + property match."""
    if pattern.kinds:
        for k in pattern.kinds:
            if k == "Base":
                continue
            if k not in node.kinds:
                return False
    if pattern.properties:
        for key, expected in pattern.properties.items():
            if not property_match(_node_prop(node, key), expected):
                return False
    return True


def edge_matches(edge: Edge, graph: Graph, case: EdgeCase) -> bool:
    """Ports Test-EdgePattern: exact kind + endpoint nodes + edge properties."""
    if edge.kind != case.kind:
        return False
    src, tgt = graph.node(edge.start), graph.node(edge.end)
    if src is None or tgt is None:
        return False
    if case.source and not node_matches(src, case.source):
        return False
    if case.target and not node_matches(tgt, case.target):
        return False
    if case.properties:
        for key, expected in case.properties.items():
            if not property_match(edge.properties.get(key), expected):
                return False
    return True
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_matcher.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Green checkpoint.**

---

## Task 4: Shared `results.py` — result model + JSON

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/integration_testing/results.py`
- Test: `openhound-collector-common/tests/test_integration_results.py`

**Interfaces:**
- Produces: constants `PASS`, `FAIL`, `SKIP`; `Result(case_id, kind, description, outcome, detail="", matched_count=0)`; `Summary(results:list[Result])` with `.passed/.failed/.skipped` int props and `.to_dict()`; `write_results_json(summary, path)`.

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_integration_results.py
import json
from openhound_collector_common.integration_testing.results import (
    Result, Summary, write_results_json, PASS, FAIL, SKIP)

def test_summary_counts_and_dict():
    s = Summary(results=[
        Result("a", "K", "d", PASS, matched_count=2),
        Result("b", "K", "d", FAIL, "not found"),
        Result("c", "K", "d", SKIP)])
    assert (s.passed, s.failed, s.skipped) == (1, 1, 1)
    d = s.to_dict()
    assert d["passed"] == 1 and len(d["results"]) == 3 and d["results"][0]["matched_count"] == 2

def test_write_results_json(tmp_path):
    p = tmp_path / "r.json"
    write_results_json(Summary(results=[Result("a", "K", "d", PASS)]), p)
    assert json.loads(p.read_text())["results"][0]["case_id"] == "a"
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_results.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```python
# openhound-collector-common/src/openhound_collector_common/integration_testing/results.py
"""Result + Summary model and JSON serialization."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


@dataclass
class Result:
    case_id: str
    kind: str
    description: str
    outcome: str          # PASS | FAIL | SKIP
    detail: str = ""
    matched_count: int = 0


@dataclass
class Summary:
    results: list[Result] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.outcome == PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.outcome == FAIL)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.outcome == SKIP)

    def to_dict(self) -> dict:
        return {"passed": self.passed, "failed": self.failed, "skipped": self.skipped,
                "results": [asdict(r) for r in self.results]}


def write_results_json(summary: Summary, path: Path) -> None:
    Path(path).write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_results.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Green checkpoint.**

---

## Task 5: Shared `coverage.py` — schema-kind coverage

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/integration_testing/coverage.py`
- Test: `openhound-collector-common/tests/test_integration_coverage.py`

**Interfaces:**
- Consumes: `cases.EdgeCase/NodeCase`.
- Produces: `load_schema_kinds(schema_path)->tuple[set[str],set[str]]` (node_kinds, edge_kinds); `coverage(schema_path, edge_cases, node_cases)->dict` with keys `untested_edge_kinds`, `untested_node_kinds` (sorted lists); `report(schema_path, edge_cases, node_cases, log=print)->dict`.

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_integration_coverage.py
import json
from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase
from openhound_collector_common.integration_testing.coverage import coverage

def test_coverage(tmp_path):
    schema = {"node_kinds": [{"name": "SCCM_Site"}, {"name": "SCCM_Collection"}],
              "relationship_kinds": [{"name": "SCCM_HasClient"}, {"name": "SCCM_HasMember"}]}
    p = tmp_path / "schema.json"; p.write_text(json.dumps(schema), encoding="utf-8")
    cov = coverage(p, edge_cases=[EdgeCase("e", "SCCM_HasClient", "d")],
                   node_cases=[NodeCase("n", "d", ["SCCM_Site"])])
    assert cov["untested_edge_kinds"] == ["SCCM_HasMember"]
    assert cov["untested_node_kinds"] == ["SCCM_Collection"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_coverage.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```python
# openhound-collector-common/src/openhound_collector_common/integration_testing/coverage.py
"""Coverage: which schema.json kinds have no fixture test (replaces the dead Get-MissingTests)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase


def load_schema_kinds(schema_path) -> tuple[set[str], set[str]]:
    doc = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    node_kinds = {k["name"] for k in doc.get("node_kinds", [])}
    edge_kinds = {k["name"] for k in doc.get("relationship_kinds", [])}
    return node_kinds, edge_kinds


def coverage(schema_path, edge_cases: list[EdgeCase], node_cases: list[NodeCase]) -> dict:
    node_kinds, edge_kinds = load_schema_kinds(schema_path)
    covered_edge = {c.kind for c in edge_cases}
    covered_node = {k for c in node_cases for k in c.kinds}
    return {"untested_edge_kinds": sorted(edge_kinds - covered_edge),
            "untested_node_kinds": sorted(node_kinds - covered_node)}


def report(schema_path, edge_cases, node_cases, log: Callable[[str], None] = print) -> dict:
    cov = coverage(schema_path, edge_cases, node_cases)
    log("\nCoverage (schema kinds without a fixture test):")
    log(f"  Untested edge kinds: {cov['untested_edge_kinds'] or 'none'}")
    log(f"  Untested node kinds: {cov['untested_node_kinds'] or 'none'}")
    return cov
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_coverage.py -v`
Expected: PASS (1 test).

- [ ] **Step 5: Green checkpoint.**

---

## Task 6: Shared `runner.py` — verdict logic + suite

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/integration_testing/runner.py`
- Test: `openhound-collector-common/tests/test_integration_runner.py`

**Interfaces:**
- Consumes: `graph.Graph`, `cases.EdgeCase/NodeCase/NodePattern/CountSpec`, `matcher.edge_matches/node_matches`, `results.*`, `coverage.report`.
- Produces: `Invariant = Callable[[Graph], Result]`; `run_edge_case(case, graph)->Result`; `run_node_case(case, graph)->Result`; `run_suite(graph, edge_cases, node_cases, invariants=None, schema_path=None, results_path=None, log=print)->Summary`.

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_integration_runner.py
from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase, NodePattern, CountSpec
from openhound_collector_common.integration_testing.results import Result, PASS, FAIL, SKIP
from openhound_collector_common.integration_testing.runner import run_edge_case, run_node_case, run_suite

def _graph():
    return Graph(
        nodes=[Node("A", ["Group", "Base"], {}), Node("B", ["Computer", "Base"], {}),
               Node("S", ["SCCM_Site"], {"siteCode": "PS1"})],
        edges=[Edge("SCCM_CoerceAndRelayToSMB", "A", "B", {}),
               Edge("SCCM_CoerceAndRelayToSMB", "A", "B", {})])

def test_edge_default_at_least_one_passes():
    r = run_edge_case(EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d",
                               source=NodePattern(kinds=["Group"])), _graph())
    assert r.outcome == PASS and r.matched_count == 2

def test_edge_exact_count_fails():
    r = run_edge_case(EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d",
                               source=NodePattern(kinds=["Group"]), count=CountSpec(exact=1)), _graph())
    assert r.outcome == FAIL and "wrong count" in r.detail

def test_edge_no_constraints_skips():
    assert run_edge_case(EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d"), _graph()).outcome == SKIP

def test_edge_negative_passes_when_absent():
    r = run_edge_case(EdgeCase("e", "SCCM_FullAdministrator", "d",
                               source=NodePattern(kinds=["Group"]), negative=True), _graph())
    assert r.outcome == PASS

def test_node_count_at_least():
    r = run_node_case(NodeCase("n", "d", ["SCCM_Site"], count=CountSpec(at_least=1)), _graph())
    assert r.outcome == PASS and r.matched_count == 1

def test_run_suite_aggregates_and_runs_invariant(tmp_path):
    captured = []
    def inv(g): return Result("inv-1", "invariant", "always true", PASS)
    s = run_suite(_graph(),
                  edge_cases=[EdgeCase("e", "SCCM_CoerceAndRelayToSMB", "d", source=NodePattern(kinds=["Group"]))],
                  node_cases=[NodeCase("n", "d", ["SCCM_Site"])],
                  invariants=[inv], results_path=tmp_path / "r.json", log=captured.append)
    assert s.passed == 3 and s.failed == 0
    assert (tmp_path / "r.json").exists()
    assert any("Edge Test Summary" in line for line in captured)
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_runner.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```python
# openhound-collector-common/src/openhound_collector_common/integration_testing/runner.py
"""Runs edge/node cases + invariants against a Graph; prints + returns a Summary."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Callable

from openhound_collector_common.integration_testing import coverage as _coverage
from openhound_collector_common.integration_testing.cases import CountSpec, EdgeCase, NodeCase, NodePattern
from openhound_collector_common.integration_testing.graph import Graph
from openhound_collector_common.integration_testing.matcher import edge_matches, node_matches
from openhound_collector_common.integration_testing.results import (
    FAIL, PASS, SKIP, Result, Summary, write_results_json)

Invariant = Callable[[Graph], Result]


def _count_ok(spec: CountSpec | None, n: int) -> bool:
    return n >= 1 if spec is None else spec.satisfied_by(n)


def run_edge_case(case: EdgeCase, graph: Graph) -> Result:
    if not case.source and not case.target and not case.properties:
        return Result(case.id, case.kind, case.description, SKIP, "coverage placeholder")
    matches = [e for e in graph.edges_of_kind(case.kind) if edge_matches(e, graph, case)]
    n = len(matches)
    if case.negative:
        return (Result(case.id, case.kind, case.description, PASS, "correctly absent") if n == 0
                else Result(case.id, case.kind, case.description, FAIL, f"incorrectly present ({n})", n))
    if n == 0:
        return Result(case.id, case.kind, case.description, FAIL, "not found", 0)
    if not _count_ok(case.count, n):
        return Result(case.id, case.kind, case.description, FAIL, f"wrong count (found {n})", n)
    return Result(case.id, case.kind, case.description, PASS, "", n)


def run_node_case(case: NodeCase, graph: Graph) -> Result:
    pattern = NodePattern(kinds=case.kinds, properties=case.properties)
    matches = [nd for nd in graph.nodes if node_matches(nd, pattern)]
    n = len(matches)
    label = case.kinds[0] if case.kinds else "node"
    if case.negative:
        return (Result(case.id, label, case.description, PASS, "correctly absent") if n == 0
                else Result(case.id, label, case.description, FAIL, f"incorrectly present ({n})", n))
    if n == 0:
        return Result(case.id, label, case.description, FAIL, "not found", 0)
    if not _count_ok(case.count, n):
        return Result(case.id, label, case.description, FAIL, f"wrong count (found {n})", n)
    return Result(case.id, label, case.description, PASS, "", n)


def _line(r: Result) -> str:
    return f"{r.kind}: {r.description} - {r.outcome}" + (f" ({r.detail})" if r.detail else "")


def run_suite(graph: Graph, edge_cases: list[EdgeCase], node_cases: list[NodeCase],
              invariants: list[Invariant] | None = None, schema_path: Path | None = None,
              results_path: Path | None = None, log: Callable[[str], None] = print) -> Summary:
    summary = Summary()
    log(f"Total nodes found: {len(graph.nodes)}")
    log(f"Total edges found: {len(graph.edges)}")
    log("Edge types found:")
    for kind, count in sorted(Counter(e.kind for e in graph.edges).items()):
        log(f"  {kind}: {count}")

    log("\nRunning edge tests...")
    for case in edge_cases:
        r = run_edge_case(case, graph); summary.results.append(r); log(_line(r))
    log("\nRunning node tests...")
    for ncase in node_cases:
        r = run_node_case(ncase, graph); summary.results.append(r); log(_line(r))
    for inv in invariants or []:
        r = inv(graph); summary.results.append(r); log(_line(r))

    log("\nEdge Test Summary:")
    log(f"  Passed: {summary.passed}")
    log(f"  Failed: {summary.failed}")
    log(f"  Skipped: {summary.skipped}")

    if schema_path is not None:
        _coverage.report(schema_path, edge_cases, node_cases, log=log)
    if results_path is not None:
        write_results_json(summary, results_path)
    return summary
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_runner.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Green checkpoint.**

---

## Task 7: Shared `compare.py` — deep payload diff

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/integration_testing/compare.py`
- Test: `openhound-collector-common/tests/test_integration_compare.py`

**Interfaces:**
- Consumes: `graph.Graph`.
- Produces: `PropDiff(key, kind, only_in_a:dict, only_in_b:dict, changed:dict)`; `ComparisonReport(nodes_only_in_a, nodes_only_in_b, edges_only_in_a, edges_only_in_b, node_prop_diffs:list[PropDiff], edge_prop_diffs:list[PropDiff], node_kind_rollup:dict, edge_kind_rollup:dict)` with `.to_dict()` and `.render(log=print)`; `compare_graphs(a:Graph, b:Graph)->ComparisonReport`. Edge key = `"start|kind|end"`. List props compared order-insensitively.

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_integration_compare.py
from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.compare import compare_graphs

def test_compare_nodes_edges_and_rollup():
    a = Graph(
        nodes=[Node("N1", ["SCCM_Site"], {"siteCode": "PS1", "versionCVEs": ["CVE-1"], "src": ["A", "B"]}),
               Node("N2", ["SCCM_Site"], {})],
        edges=[Edge("SCCM_HasClient", "N1", "X", {"traversable": True})])
    b = Graph(
        nodes=[Node("N1", ["SCCM_Site"], {"siteCode": "CAS", "src": ["B", "A"]}),
               Node("N3", ["SCCM_Site"], {})],
        edges=[Edge("SCCM_HasClient", "N1", "Y", {"traversable": True})])
    rep = compare_graphs(a, b)
    assert rep.nodes_only_in_a == ["N2"] and rep.nodes_only_in_b == ["N3"]
    assert rep.edges_only_in_a == ["N1|SCCM_HasClient|X"]
    assert rep.edges_only_in_b == ["N1|SCCM_HasClient|Y"]
    nd = next(d for d in rep.node_prop_diffs if d.key == "N1")
    assert nd.changed["siteCode"] == ["PS1", "CAS"]          # value differs
    assert "versionCVEs" in nd.only_in_a                      # present in A only
    assert "src" not in nd.changed and "src" not in nd.only_in_a  # list order-insensitive == equal
    # by-kind rollup: versionCVEs appears on SCCM_Site in A but not B
    assert "versionCVEs" in rep.node_kind_rollup["SCCM_Site"]["only_a"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_compare.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

```python
# openhound-collector-common/src/openhound_collector_common/integration_testing/compare.py
"""Deep property-level diff between two graphs (the --compare-to-zip engine)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from openhound_collector_common.integration_testing.graph import Edge, Graph, Node


def _canon(v):
    return json.dumps(v, sort_keys=True, default=str)


def _values_equal(x, y) -> bool:
    """Scalars: exact. Lists: order-insensitive (multiset) so ordering isn't noise."""
    if isinstance(x, list) and isinstance(y, list):
        return sorted(_canon(i) for i in x) == sorted(_canon(i) for i in y)
    if isinstance(x, list) or isinstance(y, list):
        return False
    return x == y


@dataclass
class PropDiff:
    key: str          # node id, or "start|kind|end" for edges
    kind: str
    only_in_a: dict = field(default_factory=dict)
    only_in_b: dict = field(default_factory=dict)
    changed: dict = field(default_factory=dict)   # prop -> [a_val, b_val]


@dataclass
class ComparisonReport:
    nodes_only_in_a: list[str] = field(default_factory=list)
    nodes_only_in_b: list[str] = field(default_factory=list)
    edges_only_in_a: list[str] = field(default_factory=list)
    edges_only_in_b: list[str] = field(default_factory=list)
    node_prop_diffs: list[PropDiff] = field(default_factory=list)
    edge_prop_diffs: list[PropDiff] = field(default_factory=list)
    node_kind_rollup: dict = field(default_factory=dict)   # kind -> {only_a:[...], only_b:[...]}
    edge_kind_rollup: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        def pd(d: PropDiff) -> dict:
            return {"key": d.key, "kind": d.kind, "only_in_a": d.only_in_a,
                    "only_in_b": d.only_in_b, "changed": d.changed}
        return {
            "nodes_only_in_a": self.nodes_only_in_a, "nodes_only_in_b": self.nodes_only_in_b,
            "edges_only_in_a": self.edges_only_in_a, "edges_only_in_b": self.edges_only_in_b,
            "node_prop_diffs": [pd(d) for d in self.node_prop_diffs],
            "edge_prop_diffs": [pd(d) for d in self.edge_prop_diffs],
            "node_kind_rollup": self.node_kind_rollup, "edge_kind_rollup": self.edge_kind_rollup,
        }

    def render(self, log: Callable[[str], None] = print) -> None:
        log(f"Nodes only in A (current run): {len(self.nodes_only_in_a)}")
        for nid in self.nodes_only_in_a:
            log(f"  + {nid}")
        log(f"Nodes only in B (compare zip): {len(self.nodes_only_in_b)}")
        for nid in self.nodes_only_in_b:
            log(f"  - {nid}")
        log(f"Edges only in A: {len(self.edges_only_in_a)}   only in B: {len(self.edges_only_in_b)}")
        for d in self.node_prop_diffs:
            log(f"Node {d.key} [{d.kind}]: onlyA={list(d.only_in_a)} onlyB={list(d.only_in_b)} changed={d.changed}")
        for d in self.edge_prop_diffs:
            log(f"Edge {d.key}: onlyA={list(d.only_in_a)} onlyB={list(d.only_in_b)} changed={d.changed}")
        log("By-kind property rollup (node kinds):")
        for kind, roll in sorted(self.node_kind_rollup.items()):
            if roll["only_a"] or roll["only_b"]:
                log(f"  {kind}: only_in_A={roll['only_a']} only_in_B={roll['only_b']}")


def _diff_props(key: str, kind: str, a_props: dict, b_props: dict) -> PropDiff | None:
    d = PropDiff(key=key, kind=kind)
    for k, v in a_props.items():
        if k not in b_props:
            d.only_in_a[k] = v
        elif not _values_equal(v, b_props[k]):
            d.changed[k] = [v, b_props[k]]
    for k, v in b_props.items():
        if k not in a_props:
            d.only_in_b[k] = v
    return d if (d.only_in_a or d.only_in_b or d.changed) else None


def _kind_rollup(a_items, b_items, kinds_of) -> dict:
    a_props: dict[str, set] = {}
    b_props: dict[str, set] = {}
    for item, side in [(i, a_props) for i in a_items] + [(i, b_props) for i in b_items]:
        for kind in kinds_of(item):
            side.setdefault(kind, set()).update(item.properties.keys())
    roll = {}
    for kind in set(a_props) | set(b_props):
        pa, pb = a_props.get(kind, set()), b_props.get(kind, set())
        roll[kind] = {"only_a": sorted(pa - pb), "only_b": sorted(pb - pa)}
    return roll


def compare_graphs(a: Graph, b: Graph) -> ComparisonReport:
    rep = ComparisonReport()
    a_nodes = {n.id: n for n in a.nodes}
    b_nodes = {n.id: n for n in b.nodes}
    rep.nodes_only_in_a = sorted(set(a_nodes) - set(b_nodes))
    rep.nodes_only_in_b = sorted(set(b_nodes) - set(a_nodes))
    for nid in sorted(set(a_nodes) & set(b_nodes)):
        na, nb = a_nodes[nid], b_nodes[nid]
        d = _diff_props(nid, na.kinds[0] if na.kinds else "?", na.properties, nb.properties)
        if d:
            rep.node_prop_diffs.append(d)

    def ekey(e: Edge) -> str:
        return f"{e.start}|{e.kind}|{e.end}"

    a_edges = {ekey(e): e for e in a.edges}
    b_edges = {ekey(e): e for e in b.edges}
    rep.edges_only_in_a = sorted(set(a_edges) - set(b_edges))
    rep.edges_only_in_b = sorted(set(b_edges) - set(a_edges))
    for k in sorted(set(a_edges) & set(b_edges)):
        ea, eb = a_edges[k], b_edges[k]
        d = _diff_props(k, ea.kind, ea.properties, eb.properties)
        if d:
            rep.edge_prop_diffs.append(d)

    rep.node_kind_rollup = _kind_rollup(a.nodes, b.nodes, lambda n: n.kinds)
    rep.edge_kind_rollup = _kind_rollup(a.edges, b.edges, lambda e: [e.kind])
    return rep
```

> Note: the `_kind_rollup` helper's list-comprehension `side` binding is illustrative; implement it as a
> plain loop over `(a_items, a_props)` then `(b_items, b_props)` accumulating property-name sets per kind
> — the test in Step 1 pins the required behavior (`versionCVEs` in `node_kind_rollup["SCCM_Site"]["only_a"]`).

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/test_integration_compare.py -v`
Expected: PASS (1 test). If the `_kind_rollup` accumulation needs a plain-loop rewrite to satisfy the rollup assertion, do that now and re-run.

- [ ] **Step 5: Full shared-engine green checkpoint**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/ -q`
Expected: all shared-lib tests pass (pre-existing + the 6 new integration_testing files).

---

## Task 8: SCCM edge fixtures — port the 61 `$ExpectedEdges`

**Files:**
- Create: `sccm/sccm/src/openhound_sccm/integration/__init__.py` (empty for now — populated in Task 10)
- Create: `sccm/sccm/src/openhound_sccm/integration/fixtures/__init__.py`
- Create: `sccm/sccm/src/openhound_sccm/integration/fixtures/edges.py`
- Test: `sccm/sccm/tests/integration_fixtures_test.py`

**Interfaces:**
- Consumes: `cases.EdgeCase/NodePattern/CountSpec`.
- Produces: `MAYYHEM_EDGE_CASES: list[EdgeCase]`.

**Porting procedure (source of truth: `sccm/tests/live-comparison/rename_check/Invoke-ConfigManBearPigUnitTests-renamed.ps1`, the new-name kit):**
For each `$ExpectedEdges` hashtable, create one `EdgeCase`:
- `id`: stable kebab `edge-<kind-suffix>-<discriminator>` (kind-suffix = kind minus prefix, lowercased; discriminator from the Description, e.g. site/host). Must be unique.
- `kind` ← `Kind` (already the new `SCCM_`/`MSSQL_` name in the renamed kit).
- `description` ← `Description`.
- `source`/`target` ← `Source`/`Target` → `NodePattern(kinds=<Kinds>, properties=<Properties>)` (omit when the PS entry omits it).
- `properties` ← the edge-level `Properties` hashtable (e.g. `coercionVictimAndRelayTargetPairs`).
- `count` ← `CountSpec(exact=<Count>)` when `Count` is set; else `None` (default at_least 1).
- `negative`/`reason` ← `Negative`/`Reason` when present.

- [ ] **Step 1: Write the failing test (completeness + validity, not per-case)**

```python
# sccm/sccm/tests/integration_fixtures_test.py
from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES
from openhound_collector_common.integration_testing.cases import EdgeCase

def test_edge_fixture_count_matches_ps_kit():
    # The renamed PS kit has 61 $ExpectedEdges cases; the port must carry them all.
    assert len(MAYYHEM_EDGE_CASES) == 61

def test_edge_fixture_ids_unique_and_typed():
    ids = [c.id for c in MAYYHEM_EDGE_CASES]
    assert len(ids) == len(set(ids)), "duplicate fixture ids"
    assert all(isinstance(c, EdgeCase) and c.kind and c.description for c in MAYYHEM_EDGE_CASES)

def test_no_old_edge_names_or_typo():
    banned = {"SameHostAs", "LocalAdminRequired", "CoerceAndRelayToAdminService",
              "CoerceAndRelayToSMB", "CoerceAndRelayToMSSQL", "CoerceAndRelaytoSMB"}
    assert not (banned & {c.kind for c in MAYYHEM_EDGE_CASES})
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_fixtures_test.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the fixtures** (representative examples shown; port ALL 61 by the procedure above)

```python
# sccm/sccm/src/openhound_sccm/integration/fixtures/edges.py
"""mayyhem.com lab expected-edge fixtures, ported from Invoke-ConfigManBearPigUnitTests
(renamed copy). New SCCM_/MSSQL_ kind names; one EdgeCase per PS $ExpectedEdges entry."""
from __future__ import annotations

from openhound_collector_common.integration_testing.cases import CountSpec, EdgeCase, NodePattern

_AUTH_USERS = NodePattern(kinds=["Group", "Base"], properties={"id": "*-S-1-5-11"})

MAYYHEM_EDGE_CASES: list[EdgeCase] = [
    # --- MSSQL_CoerceAndRelayToMSSQL (PS lines 347-431) ---
    EdgeCase(
        id="edge-coerce-mssql-cas",
        kind="MSSQL_CoerceAndRelayToMSSQL",
        description="Authenticated Users group can coerce and relay authentication to the MSSQL service on the CAS site database server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "MAYYHEM\\CAS-PSS$@*:1433"}),
        properties={"coercionVictimAndRelayTargetPairs": ["Coerce cas-pss.mayyhem.com, relay to cas-db.mayyhem.com:1433"]},
        count=CountSpec(exact=1),
    ),
    EdgeCase(
        id="edge-coerce-mssql-ps1-pss",
        kind="MSSQL_CoerceAndRelayToMSSQL",
        description="Authenticated Users group can coerce and relay authentication to the MSSQL service on the PS1 site database server",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["MSSQL_Login"], properties={"id": "MAYYHEM\\PS1-PSS$@*:1433"}),
        properties={"coercionVictimAndRelayTargetPairs": ["Coerce ps1-pss.mayyhem.com, relay to ps1-db.mayyhem.com:1433"]},
        count=CountSpec(exact=1),
    ),
    # --- SCCM_CoerceAndRelayToSMB (PS lines 432-508) ---
    EdgeCase(
        id="edge-coerce-smb-ps1-sms",
        kind="SCCM_CoerceAndRelayToSMB",
        description="Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 SMS Provider",
        source=_AUTH_USERS,
        target=NodePattern(kinds=["Computer"]),
        # ...Properties/Count from the PS entry...
    ),
    # --- SCCM_LocalAdminRequired (PS lines 148-320, Count/Source/Target per entry) ---
    EdgeCase(
        id="edge-localadmin-cas-to-primary",
        kind="SCCM_LocalAdminRequired",
        description="The CAS primary site server has local administrator rights on ...",
        source=NodePattern(kinds=["Computer"]),
        target=NodePattern(kinds=["Computer"]),
    ),
    # ... continue for ALL 61 cases: SCCM_SameHostAs, SCCM_AdminsReplicatedTo,
    #     SCCM_AllPermissions, SCCM_ApplicationAdministrator, SCCM_AssignAllPermissions,
    #     SCCM_Contains, SCCM_FullAdministrator, SCCM_HasADLastLogonUser, SCCM_HasClient,
    #     SCCM_HasCurrentUser, SCCM_HasMember, SCCM_HasPrimaryUser, SCCM_HasStoredAccount,
    #     SCCM_IsAssigned, SCCM_IsMappedTo, MSSQL_* kinds, HasSession, MemberOf ...
]
```

Also create empty package markers:
```python
# sccm/sccm/src/openhound_sccm/integration/__init__.py
"""SCCM integration-test wiring (fixtures + CLI entry points)."""
```
```python
# sccm/sccm/src/openhound_sccm/integration/fixtures/__init__.py
```

**Porting checklist (do this to reach 61):** open the renamed kit, walk `$script:ExpectedEdges` top to bottom, and transcribe every hashtable into an `EdgeCase` by the field mapping above. Preserve `Count` exactly. Keep the `_AUTH_USERS` shared pattern for every `*-S-1-5-11` source. Do not invent constraints the PS entry lacks (a constraint-less entry stays constraint-less → it will SKIP, matching the PS kit).

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_fixtures_test.py -v`
Expected: PASS (3 tests) once all 61 are transcribed. The count test is the completeness gate.

- [ ] **Step 5: Green checkpoint.**

---

## Task 9: SCCM node fixtures + memberOf invariant

**Files:**
- Create: `sccm/sccm/src/openhound_sccm/integration/fixtures/nodes.py`
- Test: append to `sccm/sccm/tests/integration_fixtures_test.py`

**Interfaces:**
- Consumes: `cases.NodeCase/CountSpec`, `results.Result/PASS/FAIL`, `graph.Graph`.
- Produces: `MAYYHEM_NODE_CASES: list[NodeCase]`; `MAYYHEM_INVARIANTS: list[Callable[[Graph], Result]]` (the `memberOf` root-site normalization check); helper `ROOT_SITE = "CAS"`.

**Anchor counts to the validated mayyhem output** (from the 2026-07-22 parity run: 3 `SCCM_Site`, 3 `MSSQL_Server`, and the node counts observed in `sccm/tests/live-comparison/rename_check/`). Use `exact` for stable structural counts (sites) and `at_least` for growth-sensitive kinds (client devices).

- [ ] **Step 1: Write the failing test**

```python
# append to sccm/sccm/tests/integration_fixtures_test.py
from openhound_sccm.integration.fixtures.nodes import MAYYHEM_NODE_CASES, MAYYHEM_INVARIANTS
from openhound_collector_common.integration_testing.graph import Node, Graph
from openhound_collector_common.integration_testing.results import PASS, FAIL

def test_node_fixtures_present_and_cover_sccm_site():
    assert MAYYHEM_NODE_CASES, "expected at least one node case"
    assert any("SCCM_Site" in c.kinds for c in MAYYHEM_NODE_CASES)

def test_memberof_invariant_flags_non_root_site_suffix():
    inv = MAYYHEM_INVARIANTS[0]
    good = Graph(nodes=[Node("D1", ["SCCM_ClientDevice"], {"memberOf": ["ALL SYSTEMS@CAS"]})], edges=[])
    bad = Graph(nodes=[Node("D1", ["SCCM_ClientDevice"], {"memberOf": ["ALL SYSTEMS@PS1"]})], edges=[])
    assert inv(good).outcome == PASS
    assert inv(bad).outcome == FAIL
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_fixtures_test.py -v`
Expected: FAIL — `nodes` module not found.

- [ ] **Step 3: Write the implementation**

```python
# sccm/sccm/src/openhound_sccm/integration/fixtures/nodes.py
"""mayyhem.com lab node fixtures + whole-graph invariants."""
from __future__ import annotations

import re
from typing import Callable

from openhound_collector_common.integration_testing.cases import CountSpec, NodeCase
from openhound_collector_common.integration_testing.graph import Graph
from openhound_collector_common.integration_testing.results import FAIL, PASS, Result

ROOT_SITE = "CAS"

MAYYHEM_NODE_CASES: list[NodeCase] = [
    NodeCase(id="node-site-count", description="Exactly 3 SCCM sites (CAS + PS1 + secondary)",
             kinds=["SCCM_Site"], count=CountSpec(exact=3)),
    NodeCase(id="node-site-has-sitecode", description="Every SCCM_Site carries a siteCode",
             kinds=["SCCM_Site"], properties={"siteCode": "*"}, count=CountSpec(at_least=3)),
    NodeCase(id="node-mssql-server-count", description="3 MSSQL servers discovered",
             kinds=["MSSQL_Server"], count=CountSpec(exact=3)),
    NodeCase(id="node-clientdevice-present", description="At least one SCCM_ClientDevice",
             kinds=["SCCM_ClientDevice"], count=CountSpec(at_least=1)),
    # ... add one existence/count case per schema.json node kind ...
]


def _memberof_root_site_invariant(graph: Graph) -> Result:
    """All SCCM_ClientDevice.memberOf entries of the form '<name>@<3-char site>' must
    use the hierarchy root site code (ports the PS memberOf normalization check)."""
    pat = re.compile(r"^(.+)@([A-Za-z0-9]{3})$")
    bad: list[str] = []
    for node in graph.nodes:
        if "SCCM_ClientDevice" not in node.kinds:
            continue
        for entry in node.properties.get("memberOf") or []:
            m = pat.match(str(entry))
            if m and m.group(2) != ROOT_SITE:
                bad.append(f"{node.id}: {entry}")
    if bad:
        return Result("node-memberof-normalization", "invariant",
                      "SCCM_ClientDevice.memberOf entries use the root site code",
                      FAIL, f"{len(bad)} non-root entries e.g. {bad[0]}")
    return Result("node-memberof-normalization", "invariant",
                  "SCCM_ClientDevice.memberOf entries use the root site code", PASS)


MAYYHEM_INVARIANTS: list[Callable[[Graph], Result]] = [_memberof_root_site_invariant]
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_fixtures_test.py -v`
Expected: PASS (all fixture tests).

- [ ] **Step 5: Green checkpoint.**

---

## Task 10: SCCM wiring — `run_integration_tests` + `compare_to_zip`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/integration/__init__.py`
- Test: `sccm/sccm/tests/integration_wiring_test.py`

**Interfaces:**
- Consumes: shared `load_graph`, `run_suite`, `compare_graphs`; SCCM `MAYYHEM_EDGE_CASES`, `MAYYHEM_NODE_CASES`, `MAYYHEM_INVARIANTS`; the SCCM `schema.json` path.
- Produces: `SCHEMA_PATH: Path`; `run_integration_tests(graph_dir:Path, results_path:Path|None=None, log=logger.info)->int` (returns process exit code: `1` if any failure else `0`); `compare_to_zip(graph_dir:Path, zip_path:Path, out_path:Path|None=None, log=logger.info)->int` (always returns `0`).

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/integration_wiring_test.py
import json
from openhound_sccm.integration import run_integration_tests, compare_to_zip, SCHEMA_PATH

def _write_min_graph(d):
    (d / "sccm_nodes.json").write_text(json.dumps({"graph": {"nodes": [
        {"id": "CAS", "kinds": ["SCCM_Site"], "properties": {"siteCode": "CAS"}},
        {"id": "PS1", "kinds": ["SCCM_Site"], "properties": {"siteCode": "PS1"}},
        {"id": "SEC", "kinds": ["SCCM_Site"], "properties": {"siteCode": "SEC"}}], "edges": []}}), encoding="utf-8")

def test_schema_path_exists():
    assert SCHEMA_PATH.exists() and SCHEMA_PATH.name == "schema.json"

def test_run_integration_tests_returns_exit_code(tmp_path):
    _write_min_graph(tmp_path)
    rc = run_integration_tests(tmp_path, results_path=tmp_path / "res.json")
    assert rc in (0, 1)                       # runs end-to-end without raising
    assert (tmp_path / "res.json").exists()

def test_compare_to_zip_always_zero(tmp_path):
    _write_min_graph(tmp_path)
    import zipfile
    zp = tmp_path / "b.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("nodes.json", json.dumps({"graph": {"nodes": [
            {"id": "CAS", "kinds": ["SCCM_Site"], "properties": {"siteCode": "CASX"}}], "edges": []}}))
    rc = compare_to_zip(tmp_path, zp, out_path=tmp_path / "cmp.json")
    assert rc == 0 and (tmp_path / "cmp.json").exists()
    assert json.loads((tmp_path / "cmp.json").read_text())  # non-empty report
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_wiring_test.py -v`
Expected: FAIL — `run_integration_tests` not importable.

- [ ] **Step 3: Write the implementation**

```python
# sccm/sccm/src/openhound_sccm/integration/__init__.py
"""SCCM integration-test wiring: assemble mayyhem fixtures + the shared engine."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from openhound_collector_common.integration_testing.compare import compare_graphs
from openhound_collector_common.integration_testing.graph import load_graph
from openhound_collector_common.integration_testing.results import write_results_json  # noqa: F401 (re-export)
from openhound_collector_common.integration_testing.runner import run_suite

from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES
from openhound_sccm.integration.fixtures.nodes import MAYYHEM_INVARIANTS, MAYYHEM_NODE_CASES

logger = logging.getLogger(__name__)

# schema.json sits at the extension package root: src/openhound_sccm/../../schema.json
SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schema.json"


def run_integration_tests(graph_dir: Path, results_path: Path | None = None,
                          log: Callable[[str], None] = logger.info) -> int:
    graph = load_graph(graph_dir)
    summary = run_suite(graph, MAYYHEM_EDGE_CASES, MAYYHEM_NODE_CASES,
                        invariants=MAYYHEM_INVARIANTS, schema_path=SCHEMA_PATH,
                        results_path=results_path, log=log)
    return 1 if summary.failed > 0 else 0


def compare_to_zip(graph_dir: Path, zip_path: Path, out_path: Path | None = None,
                   log: Callable[[str], None] = logger.info) -> int:
    a = load_graph(graph_dir)
    b = load_graph(zip_path)
    report = compare_graphs(a, b)
    report.render(log=log)
    if out_path is not None:
        import json
        Path(out_path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return 0  # informational: never fails the process
```

> Verify `SCHEMA_PATH` resolves: `src/openhound_sccm/integration/__init__.py` → `parents[3]` is
> `sccm/sccm/`, where `schema.json` lives. If the layout differs, adjust the `parents[N]` index and
> keep the `test_schema_path_exists` assertion.

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_wiring_test.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Green checkpoint.**

---

## Task 11: CLI flags — `--run-integration-tests` / `--compare-to-zip`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (the `collect_sccm` command signature + the post-convert hook near `if run_all:`, ~lines 1014-1204)
- Test: `sccm/sccm/tests/integration_cli_flags_test.py`

**Interfaces:**
- Consumes: `openhound_sccm.integration.run_integration_tests`, `compare_to_zip`; the convert output dir from `_run_e2e_after_collect` (its `StagePaths` graph-output attribute — inspect the return type in main.py and use the graph directory field).

**Behavior:** add two `typer.Option`s in `rich_help_panel="Testing"`:
`run_integration_tests: bool` (`--run-integration-tests`) and `compare_to_zip: Optional[pathlib.Path]` (`--compare-to-zip`). At the top of the command body, if either is set, force `run_all = True`. After `_run_e2e_after_collect` returns the stage paths, resolve the graph dir; run `compare_to_zip(...)` first (if set, informational), then `run_integration_tests(...)` (if set) and `raise typer.Exit(code=rc)` with its return code.

- [ ] **Step 1: Write the failing test** (unit-level: the help panel + option exist; mirrors `collect_run_all_test.py` style)

```python
# sccm/sccm/tests/integration_cli_flags_test.py
from typer.testing import CliRunner
from openhound_sccm.main import app

runner = CliRunner()

def test_testing_flags_registered_in_help():
    result = runner.invoke(app, ["collect", "sccm", "--help"])
    assert result.exit_code == 0
    out = result.stdout
    assert "--run-integration-tests" in out
    assert "--compare-to-zip" in out
    assert "Testing" in out                     # rich_help_panel

def test_compare_to_zip_takes_a_path():
    result = runner.invoke(app, ["collect", "sccm", "--help"])
    assert "--compare-to-zip" in result.stdout
```

> If `app` is not importable this way, mirror the exact import + invocation used by
> `sccm/sccm/tests/collect_run_all_test.py` (read it first) — that test already exercises `collect sccm`.

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_cli_flags_test.py -v`
Expected: FAIL — flags not present in `--help`.

- [ ] **Step 3: Write the implementation**

Add to the `collect_sccm` signature (in the `Testing` panel, after the `Output` options):

```python
    run_integration_tests: bool = typer.Option(
        False, "--run-integration-tests", rich_help_panel="Testing",
        help="Implies --run-all, then assert the resulting graph against the built-in mayyhem "
             "lab fixtures. Prints PASS/FAIL/SKIP + summary + coverage, writes "
             "integration_results-<ts>.json, and exits non-zero if any case fails."),
    compare_to_zip: Optional[pathlib.Path] = typer.Option(
        None, "--compare-to-zip", rich_help_panel="Testing",
        help="Implies --run-all, then deep-diff this run's graph (A) against an arbitrary node/edge "
             "payload B (a CMBP zip or another OpenHound run). Reports property-level differences and "
             "writes compare-<ts>.json. Informational: always exits 0."),
```

Near the top of the command body (before the collect runs), force the chain:

```python
    if run_integration_tests or compare_to_zip is not None:
        run_all = True
```

Replace the existing `if run_all:` tail so the tests run after convert:

```python
    if run_all:
        _paths = _run_e2e_after_collect(output_path, progress)
        graph_dir = _paths.graph_dir  # adjust to the actual StagePaths field for the convert output dir
        _ts = _paths_timestamp()      # reuse the collect timestamp helper, or datetime via existing util
        if compare_to_zip is not None:
            from openhound_sccm.integration import compare_to_zip as _cmp
            _cmp(graph_dir, compare_to_zip, out_path=output_path / f"compare-{_ts}.json", log=logger.info)
        if run_integration_tests:
            from openhound_sccm.integration import run_integration_tests as _rit
            rc = _rit(graph_dir, results_path=output_path / f"integration_results-{_ts}.json", log=logger.info)
            raise typer.Exit(code=rc)
    else:
        logger.debug("--run-all not set; leaving preprocess/convert to the operator.")
```

> Read `_run_e2e_after_collect` / `StagePaths` (main.py ~1350) to use the correct attribute for the
> convert output directory, and reuse the module's existing timestamp variable (the `_ts` used for the
> collect logs) rather than calling `datetime` again. `Optional`/`pathlib` are already imported in main.py.

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_cli_flags_test.py -v`
Expected: PASS (2 tests). Also confirm no regression: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/collect_run_all_test.py -v` still passes.

- [ ] **Step 5: Green checkpoint.**

---

## Task 12: Docs — README + ARCHITECTURE

**Files:**
- Modify: `sccm/sccm/README.md` (CLI options table → new **Testing** rows; add a "Testing Changes" subsection with copy-paste mayyhem examples)
- Modify: `sccm/sccm/ARCHITECTURE.md` (new section + changelog entry)

- [ ] **Step 1: README — add Testing rows + examples**

In the Command Line Options table, add a **Testing** group:

```markdown
### Testing

| Option | Description |
|---|---|
| `--run-integration-tests` | Implies `--run-all`; asserts the collected graph against the built-in mayyhem lab fixtures. Prints PASS/FAIL/SKIP + summary + coverage, writes `integration_results-<ts>.json`, exits non-zero on any failure. |
| `--compare-to-zip <path>` | Implies `--run-all`; deep-diffs this run's graph against an arbitrary node/edge payload (a CMBP zip or another OpenHound run) down to property name/value, with a by-kind rollup. Writes `compare-<ts>.json`. Always exits 0 (informational). |

**Examples (mayyhem.com lab):**
```bash
# Assert this collection matches the known-good SCCM graph:
openhound collect sccm -d mayyhem.com --run-integration-tests

# Diff this collection against a saved CMBP or OpenHound payload:
openhound collect sccm -d mayyhem.com --compare-to-zip .\bloodhound-sccm-baseline.zip
```
```

- [ ] **Step 2: ARCHITECTURE — new section + changelog**

Add a section documenting: the shared `openhound_collector_common/integration_testing/` subpackage (loader/matcher/cases/results/runner/compare/coverage), the two collect flags as a new divergence (integration testing invoked in-process off `--run-all`), and that fixtures/coverage/wiring are SCCM-specific. Add a dated changelog row at the top of the changelog table:

```markdown
| 2026-07-22 | **Python integration-test kit + payload diff.** New shared `openhound_collector_common/integration_testing/` engine (graph loader for dir/zip, wildcard matcher, typed EdgeCase/NodeCase with exact/at_least/at_most counts, results+JSON, runner with a whole-graph invariant hook, deep comparator, schema-kind coverage). SCCM adds `openhound_sccm/integration/` fixtures (61 ported edge cases with new SCCM_/MSSQL_ names, node cases, memberOf invariant) and two `collect sccm` **Testing** flags: `--run-integration-tests` (assert vs mayyhem fixtures, non-zero exit on failure) and `--compare-to-zip` (property-level diff of this run vs an arbitrary payload, always exit 0). Both imply `--run-all`. Supersedes the PowerShell kit + `compare_results.py` for the assert/diff workflows. Shared-lib change is additive (new subpackage) so MSSQL can adopt the same engine + flags. |
```

Note in the section that the shared engine is available for the **MSSQL collector** to adopt the same flags.

- [ ] **Step 3: Consistency check**

Confirm README edge-name references and ARCHITECTURE match the code (new SCCM_/MSSQL_ names; flags spelled exactly `--run-integration-tests` / `--compare-to-zip`).

- [ ] **Step 4: Docs green checkpoint** — no tests; verify the two files render and the flag names/paths are exact.

---

## Task 13: Live validation — parity with the PowerShell kit + iterate

**Nature:** this is a validation/iteration task, not TDD. It proves the Python kit is a *faithful port*:
run against real mayyhem-lab data, it must reproduce the **same per-edge-case verdicts** the PowerShell
`Invoke-ConfigManBearPigUnitTests` kit produced on the same graph. Divergences are fixed and re-run
until they match. It also smoke-tests `--compare-to-zip` end-to-end.

**Files:**
- No `src/` changes unless a divergence forces a fixture/engine fix (then edit `integration/fixtures/edges.py`, `nodes.py`, or the relevant shared module and re-run the unit tests for that module).
- Create: `sccm/tests/live-comparison/integration_check/` for artifacts (gitignore the bulky ones like the rename_check convention).

**Baselines (already on disk from the 2026-07-22 rename parity work):**
- PowerShell-kit verdicts on OpenHound output: `sccm/tests/live-comparison/rename_check/openhound_renamed_run.log` — **55 PASS / 5 FAIL / 1 SKIP**; failing set = `SCCM_CoerceAndRelayToSMB` (ps1-psv passive), `SCCM_FullAdministrator`, `SCCM_HasCurrentUser`, `SCCM_IsAssigned`, `SCCM_IsMappedTo`.
- CMBP payload baseline zip: `sccm/tests/live-comparison/results/bloodhound-sccm-20260714-141659.zip`.

- [ ] **Step 1: Produce the graph in the CMBP-matching basis (no fresh collect required).**

The rename parity work established that reprocessing the cached live bucket is deterministic and
sufficient. Reuse it:

```bash
cd /c/Users/domainadmin/Desktop/OpenHound/sccm/sccm
mkdir -p ../tests/live-comparison/integration_check
export SOURCES__SCCM__DISABLE_POSSIBLE_EDGES=true   # match the PS-kit --DisablePossibleEdges baseline
./.venv/Scripts/openhound.exe preprocess sccm output ../tests/live-comparison/integration_check/lookup.duckdb --progress log
./.venv/Scripts/openhound.exe convert sccm output ../tests/live-comparison/integration_check/graph --lookup-file ../tests/live-comparison/integration_check/lookup.duckdb --progress log
```

If the live lab is reachable and a fresh end-to-end check is wanted instead, the equivalent one-liner is
`openhound collect sccm -d mayyhem.com --disable-possible-edges --run-integration-tests` — but prefer the
cached reprocess for a deterministic, lab-independent parity comparison.

- [ ] **Step 2: Run the Python kit against the graph.**

```bash
./.venv/Scripts/python.exe -c "import pathlib; from openhound_sccm.integration import run_integration_tests; \
  rc = run_integration_tests(pathlib.Path('../tests/live-comparison/integration_check/graph'), \
  results_path=pathlib.Path('../tests/live-comparison/integration_check/integration_results.json')); \
  print('exit', rc)"
```
Expected: it runs end-to-end, prints the summary + coverage, writes `integration_results.json`.

- [ ] **Step 3: Compare Python-kit verdicts to the PowerShell-kit verdicts.**

Map each ported edge case to its PS counterpart by `kind` + description intent and assert the Python
outcome equals the PS outcome. Concretely, confirm the Python **edge** results reproduce the PS
breakdown: the same 5 failing edge cases (`SCCM_CoerceAndRelayToSMB` passive, `SCCM_FullAdministrator`,
`SCCM_HasCurrentUser`, `SCCM_IsAssigned`, `SCCM_IsMappedTo`) and everything else PASS/SKIP as the PS kit
had. Extract the Python edge outcomes from `integration_results.json` and diff against the PS failed set
parsed from `rename_check/openhound_renamed_run.log`. Node cases + the memberOf invariant are *new*
(no PS equivalent) — verify they PASS on this known-good graph.

- [ ] **Step 4: Iterate fixes until parity.**

For every edge case whose Python verdict differs from the PS kit's:
- If the fixture was transcribed wrong (kind/source/target/properties/count mismatch vs the renamed
  `.ps1`), fix `integration/fixtures/edges.py` and re-run the fixture unit tests (Task 8) + Step 2.
- If the matcher/runner behaves differently from the PS `Test-*` logic, fix the shared module and re-run
  its unit tests (Tasks 3/6) + Step 2.
Repeat until Python edge verdicts == PS edge verdicts. For node cases that fail, decide per case: a
genuine collector gap (leave failing + note it) vs. an over-strict anchored count (relax `exact`→
`at_least` and document). **Escalate to the human** any case where the correct expectation is genuinely
ambiguous.

- [ ] **Step 5: `--compare-to-zip` live smoke.**

```bash
./.venv/Scripts/python.exe -c "import pathlib; from openhound_sccm.integration import compare_to_zip; \
  compare_to_zip(pathlib.Path('../tests/live-comparison/integration_check/graph'), \
  pathlib.Path('../tests/live-comparison/results/bloodhound-sccm-20260714-141659.zip'), \
  out_path=pathlib.Path('../tests/live-comparison/integration_check/compare_vs_cmbp.json')); print('ok')"
```
Expected: renders a report + writes `compare_vs_cmbp.json`, exit 0. Sanity-check it surfaces the expected
real differences (renamed `SCCM_`/`MSSQL_` kinds as only-in-A vs CMBP's old names; CMBP's duplicate
`SCCM_IsAssigned`/`SCCM_IsMappedTo` edges; node-count/property differences). No assertion — just confirm
the feature works and the output is sensible.

- [ ] **Step 6: Record + green checkpoint.**

Write a short `integration_check/SUMMARY.md` (Python-kit result vs PS-kit baseline, any fixes made, the
compare smoke result). Add gitignore entries for the bulky `integration_check/` artifacts
(`lookup.duckdb`, `graph/`, `*.json` results) mirroring the `rename_check/` convention. Run the full new
test set once more: `./sccm/sccm/.venv/Scripts/python.exe -m pytest openhound-collector-common/tests/ sccm/sccm/tests/integration_fixtures_test.py sccm/sccm/tests/integration_wiring_test.py sccm/sccm/tests/integration_cli_flags_test.py -q` — all green.

---

## Self-Review

**Spec coverage:**
- Two Testing flags, self-chaining --run-all, exit-code contract → Task 11. ✓
- Shared engine (graph/matcher/cases/results/runner/compare/coverage) → Tasks 1-7. ✓
- Per-instance + by-kind rollup, list order-insensitivity, matching keys (node id / start|kind|end) → Task 7. ✓
- Fixtures (61 edge cases new names, node cases, memberOf invariant, anchored counts) → Tasks 8-9. ✓
- Gap-fixes: stable IDs (cases.id, Tasks 2/8), structured JSON (results.py Task 4), coverage fix (Task 5), node assertions (Task 9), count min/max (CountSpec Task 2, verdict Task 6). ✓
- Coverage vs SCCM schema.json; MSSQL_ kinds validated against a schema → Task 5 + fixture test note (Task 8's `test_no_old_edge_names` guards names; a schema-membership assertion can be added if desired). ✓
- Docs (README Testing rows + ARCHITECTURE section/changelog) → Task 12. ✓
- Shared-lib additive, no existing-module edits → Global Constraints + Tasks 1-7 all create-only. ✓
- Live-environment validation + parity with the PowerShell `Invoke-ConfigManBearPigUnitTests` verdicts + iterate fixes → Task 13. ✓

**Placeholder scan:** Fixture Task 8 intentionally shows representative cases + a mechanical procedure + a completeness gate (`len == 61`) rather than transcribing 61 near-identical records inline; this is the correct treatment for bulk data with a hard verification. Every engine/wiring/CLI step carries complete code. No "TBD"/"add error handling"/"similar to Task N".

**Type consistency:** `EdgeCase`/`NodeCase`/`NodePattern`/`CountSpec` fields, `Result`/`Summary` shape, `load_graph`/`run_suite`/`compare_graphs`/`run_integration_tests`/`compare_to_zip` signatures are consistent across Tasks 1-11. Edge key format `"start|kind|end"` is used identically in `compare.py` and its test.

**Known implementation-time confirmations (flagged inline, not placeholders):** the `StagePaths` graph-dir attribute name and the reusable timestamp variable in `main.py` (Task 11), and the `SCHEMA_PATH` `parents[N]` index (Task 10) — each has a verification note and a test that pins correctness.
