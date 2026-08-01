# Payload Comparison as a First-Class Gate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "did my change lose anything?" a question the tooling answers on its own — a standalone `openhound-compare` command in the shared library that diffs any two OpenGraph payloads, a regression exit code on both that command and the existing `--compare-to-zip` flag, a three-way `--integration-privilege auto|high|low` flag that detects its own privilege level, and the PowerShell live-comparison drivers ported to a parameterized Python script in `dev/`.

**Architecture:** The comparison engine already exists at `openhound_collector_common/integration_testing/compare.py` and already computes every difference this work needs. Three things change in it: the argument orientation becomes `compare_graphs(baseline, candidate)` with report keys renamed to match (so a flipped meaning can never hide behind an unchanged name), a `regressions()` method classifies drops, and `render()` separates a `REGRESSIONS` block from a loud `ADDED` block. A new thin `cli.py` exposes it as the library's first console script. On the collector side, `compare_to_zip` swaps its two `load_graph` calls, both testing flags feed one combined exit code, and `--integration-lowpriv` is superseded by a three-way flag whose `auto` mode reads AdminService/WMI row counts already in scope in `collect_sccm`.

**Tech Stack:** Python 3.13+, `argparse` (stdlib — deliberately not Typer in the library), Typer (collector CLI only), `pytest` 9, `ruff`, `mypy`, `uv`.

**Design spec:** [`docs/superpowers/specs/2026-07-31-compare-and-privilege-gating-design.md`](../specs/2026-07-31-compare-and-privilege-gating-design.md)

## Global Constraints

- **Do not `git add` or commit anything.** Each task ends when its tests pass; Meatbag reviews and commits (`CLAUDE.md`: "Ask before committing each time. Never push."). **This overrides the writing-plans skill's "Commit" step** — every task ends at a green checkpoint instead.
- **Two repositories, by explicit owner authorization.** Tasks 1–5 edit the shared library `openhound-collector-common/` (a sibling checkout of this repo); Tasks 6–10 edit `ConfigManBearPig/`. The `openhound/` framework core remains **off-limits** — `CLAUDE.md` forbids it, and this plan needs nothing there.
- **Merge order is forced:** shared library lands and is released first, then this repo's floor bump, then this repo's code. This repo's CI checks out this repo alone and resolves the library from PyPI, so CMBP changes cannot go green against an unreleased library. Local development uses the sibling editable redirect the README documents, so both halves can be written together.
- **Library release is `v0.1.2`**, and **tagging/publishing is Meatbag's action, not the implementer's.** The plan stops at "tests pass locally against the editable sibling checkout." The cap in this repo stays `<0.2.0`; only the floor moves to `>=0.1.2`.
- **Orientation is fixed:** `compare_graphs(baseline, candidate)`. Baseline is what came first. A regression is something present in the baseline and missing or reduced in the candidate.
- **Regression = drops only.** Additions and ordinary value changes never fail; they are reported under `ADDED`. The six drop rules are listed in Task 2.
- **No opt-out flag.** The gate fires on both surfaces regardless of whether the payloads came from the same tool. A CMBP-vs-OpenHound parity diff exiting non-zero on a healthy run is expected and documented, not a bug to work around.
- **`requires_privilege` is a fixed field name for the duration.** Tickets `con-c542` and `con-907c` are concurrently editing `integration/fixtures/`; renaming that field would break the filter in `run_integration_tests`.
- **This work does not make a low-privilege run green and must not be described as if it does.** `con-6677` measured 36 residual failures in low-privilege mode; closing those is `con-c542`'s tagging audit. Auto-detection only removes the "operator forgot the flag" failure mode.
- **Tests live under `tests/`** and are named `*_test.py` in this repo (enforced by `[tool.pytest.ini_options] python_files = "*_test.py"` — a `test_*.py` file here is silently **not** collected). The shared library uses the opposite convention, `test_*.py`; match whichever repo you are in.
- **Write logs for every branch** (`CLAUDE.md`), at a level appropriate to the branch, or leave a comment saying why none is needed.
- **Preserve intent in comments.** Do not annotate "ported from line X".
- **Validation venv:** run tests in an isolated uv environment so neither repo's `.venv` is touched (`AGENTS.md` §5). On this Windows/PowerShell host, set once per shell:
  `$env:UV_PROJECT_ENVIRONMENT="$env:TEMP\openhound-venv"`
  Per-step commands below omit the prefix for brevity.
- **Ticket hygiene (`CLAUDE.md`):** create a `gtk` ticket per task group before starting and move it to in-progress; regenerate `.tickets/_TICKETS-BY-STATUS.md` from `gtk list` after any status change. Do not hand-edit that file. Keep tickets flat in `.tickets/` — `gtk` does not recurse. Annotate `con-6677` to record that `--integration-privilege` supersedes `--integration-lowpriv` rather than closing it as unrelated.

---

## File Structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `../openhound-collector-common/src/openhound_collector_common/integration_testing/compare.py` | Modify | Orientation flip, key rename, `Regression`, `regressions()`, `has_regressions`, reworked `render()` |
| `../openhound-collector-common/src/openhound_collector_common/integration_testing/cli.py` | **Create** | `argparse` entry point for `openhound-compare`; parsing and exit code only |
| `../openhound-collector-common/tests/test_integration_compare.py` | Modify | Orientation + renamed keys |
| `../openhound-collector-common/tests/test_integration_regressions.py` | **Create** | Each drop rule and each explicit non-rule |
| `../openhound-collector-common/tests/test_integration_cli.py` | **Create** | `main([...])` exit codes, `--json`, `-q`, bad-path handling |
| `../openhound-collector-common/pyproject.toml` | Modify | First `[project.scripts]` entry |
| `../openhound-collector-common/README.md` | Modify | Document `openhound-compare` |
| `pyproject.toml` | Modify | Floor `openhound-collector-common>=0.1.2,<0.2.0` |
| `src/openhound_sccm/integration/__init__.py` | Modify | `compare_to_zip` swaps orientation, returns 1 on regression |
| `src/openhound_sccm/main.py` | Modify | `IntegrationPrivilege` enum, `--integration-privilege` replacing `--integration-lowpriv`, `_detect_privileged`, `_resolve_integration_privileged`, `_merge_row_counts`, `_run_integration_suite(privileged=)`, combined exit code |
| `tests/integration_wiring_test.py` | Modify | `compare_to_zip` regression exit code |
| `tests/integration_cli_flags_test.py` | Modify | Replace the `--integration-lowpriv` tests with `--integration-privilege` |
| `tests/integration_privilege_test.py` | **Create** | Detection truth table incl. the `local_wmi_` trap; resolution across all three modes |
| `tests/collect_exit_code_test.py` | **Create** | Combined exit code when both testing flags are set |
| `dev/ab_matrix.py` | **Create** | Parameterized A/B matrix runner (4 cells default) |
| `dev/_ab_cmbp.py` | **Create** | `--with-cmbp` only: PowerShell subprocess + `runas /netonly` shim, isolated so the default path never imports it |
| `tests/ab_matrix_test.py` | **Create** | Cell planning, argv construction, `--clean` enforcement — no collection runs |
| `.github/workflows/ci.yml` | Modify | Add the new offline test files to the curated list |
| `README.md` | Modify | Testing rows, privilege flag, exit-code contract, **Before and after a change** subsection |
| `ARCHITECTURE.md` | Modify | Comparison-gate section + changelog entry |

**Task ordering:** Tasks 1→2→3 are sequential edits to one file. Task 4 depends on 2 (needs `has_regressions`). Task 5 is docs for 1–4. Task 6 depends on the library being importable (editable sibling). Task 7 is independent of 1–6 and may run in parallel. Task 8 depends on `openhound-compare` existing (Task 4). Task 9 documents everything and runs after 1–8. Task 10 is the final gate.

---

## Task 1: Orientation flip and key rename

**Files:**
- Modify: `../openhound-collector-common/src/openhound_collector_common/integration_testing/compare.py`
- Test: `../openhound-collector-common/tests/test_integration_compare.py`

**Interfaces:**
- Consumes: `Graph`, `Node`, `Edge` from `integration_testing.graph` (unchanged).
- Produces: `compare_graphs(baseline: Graph, candidate: Graph) -> ComparisonReport`. `ComparisonReport` fields `nodes_only_in_baseline`, `nodes_only_in_candidate`, `edges_only_in_baseline`, `edges_only_in_candidate` (all `list[str]`), `node_prop_diffs`/`edge_prop_diffs` (`list[PropDiff]`), `node_kind_rollup`/`edge_kind_rollup` (`dict[str, dict[str, list[str]]]` keyed `only_in_baseline`/`only_in_candidate`). `PropDiff` fields `key`, `kind`, `only_in_baseline: dict`, `only_in_candidate: dict`, `changed: dict[str, dict[str, object]]` where each value is `{"baseline": …, "candidate": …}`. Tasks 2, 3, 4, and 6 all depend on these exact names.

- [ ] **Step 1: Rewrite the failing test**

Replace the whole of `tests/test_integration_compare.py`:

```python
from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.compare import compare_graphs


def test_compare_nodes_edges_and_rollup():
    # baseline = what came first; candidate = what is being compared against it.
    baseline = Graph(
        nodes=[Node("N1", ["SCCM_Site"], {"siteCode": "PS1", "versionCVEs": ["CVE-1"], "src": ["A", "B"]}),
               Node("N2", ["SCCM_Site"], {})],
        edges=[Edge("SCCM_HasClient", "N1", "X", {"traversable": True})])
    candidate = Graph(
        nodes=[Node("N1", ["SCCM_Site"], {"siteCode": "CAS", "src": ["B", "A"]}),
               Node("N3", ["SCCM_Site"], {})],
        edges=[Edge("SCCM_HasClient", "N1", "Y", {"traversable": True})])
    rep = compare_graphs(baseline, candidate)

    assert rep.nodes_only_in_baseline == ["N2"]
    assert rep.nodes_only_in_candidate == ["N3"]
    assert rep.edges_only_in_baseline == ["N1|SCCM_HasClient|X"]
    assert rep.edges_only_in_candidate == ["N1|SCCM_HasClient|Y"]

    nd = next(d for d in rep.node_prop_diffs if d.key == "N1")
    assert nd.changed["siteCode"] == {"baseline": "PS1", "candidate": "CAS"}
    assert "versionCVEs" in nd.only_in_baseline          # baseline had it, candidate does not
    # list equality is order-insensitive, so a reordered list is not a difference at all
    assert "src" not in nd.changed and "src" not in nd.only_in_baseline

    assert "versionCVEs" in rep.node_kind_rollup["SCCM_Site"]["only_in_baseline"]
    assert rep.node_kind_rollup["SCCM_Site"]["only_in_candidate"] == []


def test_to_dict_uses_renamed_keys():
    baseline = Graph(nodes=[Node("N1", ["K"], {"p": 1})], edges=[])
    candidate = Graph(nodes=[], edges=[])
    d = compare_graphs(baseline, candidate).to_dict()
    assert d["nodes_only_in_baseline"] == ["N1"]
    assert d["nodes_only_in_candidate"] == []
    # the old A/B key names must be gone entirely, so stale readers fail loudly
    assert not [k for k in d if k.endswith("_a") or k.endswith("_b")]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd ../openhound-collector-common && uv run pytest tests/test_integration_compare.py -v`
Expected: FAIL — `AttributeError: 'ComparisonReport' object has no attribute 'nodes_only_in_baseline'`.

- [ ] **Step 3: Rename throughout `compare.py`**

In `PropDiff`, rename the two fields and re-comment `changed`:

```python
@dataclass
class PropDiff:
    key: str          # node id, or "start|kind|end" for edges
    kind: str
    only_in_baseline: dict = field(default_factory=dict)
    only_in_candidate: dict = field(default_factory=dict)
    changed: dict = field(default_factory=dict)   # prop -> {"baseline": v, "candidate": v}
```

In `ComparisonReport`, rename the four membership lists and update `to_dict`:

```python
@dataclass
class ComparisonReport:
    nodes_only_in_baseline: list[str] = field(default_factory=list)
    nodes_only_in_candidate: list[str] = field(default_factory=list)
    edges_only_in_baseline: list[str] = field(default_factory=list)
    edges_only_in_candidate: list[str] = field(default_factory=list)
    node_prop_diffs: list[PropDiff] = field(default_factory=list)
    edge_prop_diffs: list[PropDiff] = field(default_factory=list)
    node_kind_rollup: dict = field(default_factory=dict)   # kind -> {only_in_baseline:[...], only_in_candidate:[...]}
    edge_kind_rollup: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        def pd(d: PropDiff) -> dict:
            return {"key": d.key, "kind": d.kind, "only_in_baseline": d.only_in_baseline,
                    "only_in_candidate": d.only_in_candidate, "changed": d.changed}
        return {
            "nodes_only_in_baseline": self.nodes_only_in_baseline,
            "nodes_only_in_candidate": self.nodes_only_in_candidate,
            "edges_only_in_baseline": self.edges_only_in_baseline,
            "edges_only_in_candidate": self.edges_only_in_candidate,
            "node_prop_diffs": [pd(d) for d in self.node_prop_diffs],
            "edge_prop_diffs": [pd(d) for d in self.edge_prop_diffs],
            "node_kind_rollup": self.node_kind_rollup, "edge_kind_rollup": self.edge_kind_rollup,
        }
```

Replace `_diff_props` wholesale:

```python
def _diff_props(key: str, kind: str, baseline_props: dict, candidate_props: dict) -> PropDiff | None:
    d = PropDiff(key=key, kind=kind)
    for k, v in baseline_props.items():
        if k not in candidate_props:
            d.only_in_baseline[k] = v
        elif not _values_equal(v, candidate_props[k]):
            d.changed[k] = {"baseline": v, "candidate": candidate_props[k]}
    for k, v in candidate_props.items():
        if k not in baseline_props:
            d.only_in_candidate[k] = v
    return d if (d.only_in_baseline or d.only_in_candidate or d.changed) else None
```

Replace `_kind_rollup`'s accumulators and output keys:

```python
def _kind_rollup(baseline_items: Iterable[_Item], candidate_items: Iterable[_Item],
                 kinds_of: Callable[[_Item], list[str]]) -> dict:
    """Union of property names seen per kind, separately for each side.

    Plain accumulation loops (not comprehensions) so each side's dict is
    unambiguous: no risk of a shared/rebound variable silently pointing both
    loops at the same accumulator.
    """
    baseline_props: dict[str, set] = {}
    for item in baseline_items:
        for kind in kinds_of(item):
            baseline_props.setdefault(kind, set()).update(item.properties.keys())
    candidate_props: dict[str, set] = {}
    for item in candidate_items:
        for kind in kinds_of(item):
            candidate_props.setdefault(kind, set()).update(item.properties.keys())
    roll = {}
    for kind in set(baseline_props) | set(candidate_props):
        pb, pc = baseline_props.get(kind, set()), candidate_props.get(kind, set())
        roll[kind] = {"only_in_baseline": sorted(pb - pc), "only_in_candidate": sorted(pc - pb)}
    return roll
```

Rewrite `compare_graphs`:

```python
def compare_graphs(baseline: Graph, candidate: Graph) -> ComparisonReport:
    """Diff *candidate* against *baseline*. Baseline is what came first.

    Membership and property differences are reported in both directions; only the
    baseline-has/candidate-lacks direction counts as a regression (see regressions()).
    """
    rep = ComparisonReport()
    b_nodes = {n.id: n for n in baseline.nodes}
    c_nodes = {n.id: n for n in candidate.nodes}
    rep.nodes_only_in_baseline = sorted(set(b_nodes) - set(c_nodes))
    rep.nodes_only_in_candidate = sorted(set(c_nodes) - set(b_nodes))
    for nid in sorted(set(b_nodes) & set(c_nodes)):
        nb, nc = b_nodes[nid], c_nodes[nid]
        d = _diff_props(nid, nb.kinds[0] if nb.kinds else "?", nb.properties, nc.properties)
        if d:
            rep.node_prop_diffs.append(d)

    def ekey(e: Edge) -> str:
        return f"{e.start}|{e.kind}|{e.end}"

    b_edges = {ekey(e): e for e in baseline.edges}
    c_edges = {ekey(e): e for e in candidate.edges}
    rep.edges_only_in_baseline = sorted(set(b_edges) - set(c_edges))
    rep.edges_only_in_candidate = sorted(set(c_edges) - set(b_edges))
    for k in sorted(set(b_edges) & set(c_edges)):
        eb, ec = b_edges[k], c_edges[k]
        d = _diff_props(k, eb.kind, eb.properties, ec.properties)
        if d:
            rep.edge_prop_diffs.append(d)

    rep.node_kind_rollup = _kind_rollup(baseline.nodes, candidate.nodes, lambda n: n.kinds)
    rep.edge_kind_rollup = _kind_rollup(baseline.edges, candidate.edges, lambda e: [e.kind])
    return rep
```

Also update `render()`'s existing lines so it still runs — it is rewritten properly in Task 3, but must not reference removed attributes in the meantime. Change `self.nodes_only_in_a` → `self.nodes_only_in_baseline`, `self.nodes_only_in_b` → `self.nodes_only_in_candidate`, likewise for edges, `d.only_in_a`/`d.only_in_b` → `d.only_in_baseline`/`d.only_in_candidate`, and `roll['only_a']`/`roll['only_b']` → `roll['only_in_baseline']`/`roll['only_in_candidate']`.

- [ ] **Step 4: Run to verify it passes**

Run: `cd ../openhound-collector-common && uv run pytest tests/test_integration_compare.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Prove no stale references remain**

Run: `rg "only_in_a|only_in_b|only_a|only_b" ../openhound-collector-common/src ../openhound-collector-common/tests`
Expected: no matches. If any appear outside `compare.py`, fix them now — `runner.py` and `coverage.py` do not use these keys today, so a hit means something new.

- [ ] **Step 6: Green checkpoint.** Run `cd ../openhound-collector-common && uv run pytest tests -q` and `uv run ruff check src tests`. Both clean. **Do not commit.**

---

## Task 2: Regression detection

**Files:**
- Modify: `../openhound-collector-common/src/openhound_collector_common/integration_testing/compare.py`
- Test: `../openhound-collector-common/tests/test_integration_regressions.py` (create)

**Interfaces:**
- Consumes: `ComparisonReport` and `PropDiff` as defined in Task 1.
- Produces: `Regression` dataclass with fields `category: str`, `key: str`, `kind: str`, `detail: str`; `ComparisonReport.regressions() -> list[Regression]`; `ComparisonReport.has_regressions -> bool` (a property). Categories are exactly the strings `"node-missing"`, `"edge-missing"`, `"property-missing"`, `"property-emptied"`, `"property-shrank"`, `"kind-property-missing"`. Tasks 3, 4, and 6 depend on these.

- [ ] **Step 1: Write the failing test**

Create `tests/test_integration_regressions.py`:

```python
from openhound_collector_common.integration_testing.graph import Node, Edge, Graph
from openhound_collector_common.integration_testing.compare import compare_graphs


def _cats(baseline, candidate):
    return {r.category for r in compare_graphs(baseline, candidate).regressions()}


def test_missing_node_is_a_regression():
    b = Graph(nodes=[Node("N1", ["K"], {})], edges=[])
    c = Graph(nodes=[], edges=[])
    assert "node-missing" in _cats(b, c)
    assert compare_graphs(b, c).has_regressions is True


def test_missing_edge_is_a_regression():
    b = Graph(nodes=[], edges=[Edge("K", "S", "E", {})])
    c = Graph(nodes=[], edges=[])
    assert "edge-missing" in _cats(b, c)


def test_lost_property_is_a_regression():
    b = Graph(nodes=[Node("N1", ["K"], {"p": 1, "q": 2})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"p": 1})], edges=[])
    cats = _cats(b, c)
    assert "property-missing" in cats
    # the same loss also shows at kind granularity; both are reported
    assert "kind-property-missing" in cats


def test_property_emptied_is_a_regression():
    for empty in (None, "", [], {}):
        b = Graph(nodes=[Node("N1", ["K"], {"userName": "MAYYHEM\\bob"})], edges=[])
        c = Graph(nodes=[Node("N1", ["K"], {"userName": empty})], edges=[])
        assert "property-emptied" in _cats(b, c), f"{empty!r} should count as emptied"


def test_list_shrinking_is_a_regression():
    b = Graph(nodes=[Node("N1", ["K"], {"collectionSource": ["LDAP", "HTTP"]})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"collectionSource": ["LDAP"]})], edges=[])
    regs = compare_graphs(b, c).regressions()
    assert [r.category for r in regs].count("property-shrank") == 1
    assert "HTTP" in regs[0].detail


def test_edge_property_loss_is_a_regression():
    b = Graph(nodes=[], edges=[Edge("K", "S", "E", {"traversable": True, "why": "x"})])
    c = Graph(nodes=[], edges=[Edge("K", "S", "E", {"traversable": True})])
    assert "property-missing" in _cats(b, c)


# --- explicit non-regressions ------------------------------------------------

def test_additions_are_not_regressions():
    b = Graph(nodes=[Node("N1", ["K"], {"p": 1})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"p": 1, "new": 2}), Node("N2", ["K"], {})],
              edges=[Edge("K", "S", "E", {})])
    assert compare_graphs(b, c).regressions() == []
    assert compare_graphs(b, c).has_regressions is False


def test_ordinary_value_change_is_not_a_regression():
    b = Graph(nodes=[Node("N1", ["K"], {"siteCode": "PS1"})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"siteCode": "CAS"})], edges=[])
    assert compare_graphs(b, c).regressions() == []


def test_list_growth_and_reorder_are_not_regressions():
    b = Graph(nodes=[Node("N1", ["K"], {"src": ["A", "B"]})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"src": ["B", "A", "C"]})], edges=[])
    assert compare_graphs(b, c).regressions() == []


def test_falsy_but_present_values_are_not_emptied():
    # 0 and False are real collected values, not absence.
    b = Graph(nodes=[Node("N1", ["K"], {"count": 5, "flag": True})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"count": 0, "flag": False})], edges=[])
    assert compare_graphs(b, c).regressions() == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ../openhound-collector-common && uv run pytest tests/test_integration_regressions.py -v`
Expected: FAIL — `AttributeError: 'ComparisonReport' object has no attribute 'regressions'`.

- [ ] **Step 3: Implement the detector**

Add above `ComparisonReport` in `compare.py`:

```python
# Absence, as distinct from a falsy collected value. 0 and False are real data a
# collector legitimately emits; None/""/[]/{} are what a property looks like when
# the thing that populated it stopped working.
def _is_absent(v) -> bool:
    return v is None or (isinstance(v, (str, list, dict, tuple)) and len(v) == 0)


def _list_items_lost(baseline_v, candidate_v) -> list:
    """Items present in the baseline list and missing from the candidate list.

    Multiset difference over the canonical encoding, so duplicates are counted
    rather than collapsed and ordering is irrelevant -- consistent with
    _values_equal, which already treats lists order-insensitively.
    """
    if not (isinstance(baseline_v, list) and isinstance(candidate_v, list)):
        return []
    remaining = [_canon(i) for i in candidate_v]
    lost = []
    for item in baseline_v:
        c = _canon(item)
        if c in remaining:
            remaining.remove(c)
        else:
            lost.append(item)
    return lost


@dataclass
class Regression:
    """One way the candidate has less than the baseline."""
    category: str      # node-missing | edge-missing | property-missing |
                       # property-emptied | property-shrank | kind-property-missing
    key: str           # node id, "start|kind|end", or the kind name for rollup findings
    kind: str
    detail: str

    def __str__(self) -> str:
        where = f"{self.kind} {self.key}".strip()
        return f"{self.category:<22} {where}  {self.detail}"
```

Add to `ComparisonReport` (after `to_dict`):

```python
    def regressions(self) -> list[Regression]:
        """Every way the candidate has less than the baseline.

        Instance-level and kind-level findings both appear: losing the only
        instance carrying a property is reported once per instance AND once for
        the kind, because the two answer different questions ("which node broke?"
        versus "did this property stop being emitted at all?").
        """
        out: list[Regression] = []
        for nid in self.nodes_only_in_baseline:
            out.append(Regression("node-missing", nid, "", "in baseline, absent from candidate"))
        for ekey in self.edges_only_in_baseline:
            out.append(Regression("edge-missing", ekey, "", "in baseline, absent from candidate"))

        for diff in (*self.node_prop_diffs, *self.edge_prop_diffs):
            for prop in sorted(diff.only_in_baseline):
                out.append(Regression("property-missing", diff.key, diff.kind,
                                      f"{prop} no longer emitted"))
            for prop in sorted(diff.changed):
                pair = diff.changed[prop]
                b_val, c_val = pair["baseline"], pair["candidate"]
                if _is_absent(c_val) and not _is_absent(b_val):
                    out.append(Regression("property-emptied", diff.key, diff.kind,
                                          f"{prop}: {b_val!r} -> {c_val!r}"))
                    continue
                lost = _list_items_lost(b_val, c_val)
                if lost:
                    out.append(Regression("property-shrank", diff.key, diff.kind,
                                          f"{prop}: lost {lost!r}"))

        for rollup, what in ((self.node_kind_rollup, "node"), (self.edge_kind_rollup, "edge")):
            for kind in sorted(rollup):
                for prop in rollup[kind]["only_in_baseline"]:
                    out.append(Regression("kind-property-missing", kind, kind,
                                          f"{prop} on no {what} instance in the candidate"))
        return out

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressions())
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd ../openhound-collector-common && uv run pytest tests/test_integration_regressions.py -v`
Expected: PASS (10 tests).

- [ ] **Step 5: Green checkpoint.** `uv run pytest tests -q`, `uv run ruff check src tests`, `uv run mypy src/openhound_collector_common`. All clean. **Do not commit.**

---

## Task 3: Report rendering

**Files:**
- Modify: `../openhound-collector-common/src/openhound_collector_common/integration_testing/compare.py` — replace `render()`
- Test: `../openhound-collector-common/tests/test_integration_regressions.py` — append

**Interfaces:**
- Consumes: `regressions()` from Task 2.
- Produces: `ComparisonReport.render(log: Callable[[str], None] = print) -> None`, emitting a `REGRESSIONS` block, an `ADDED` block, and a final line beginning `RESULT:`. Task 4 and Task 6 call it.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_integration_regressions.py`:

```python
def _render(baseline, candidate):
    lines = []
    compare_graphs(baseline, candidate).render(log=lines.append)
    return "\n".join(lines)


def test_render_reports_regressions_and_additions_separately():
    b = Graph(nodes=[Node("GONE", ["K"], {}), Node("N1", ["K"], {"lost": 1})], edges=[])
    c = Graph(nodes=[Node("N1", ["K"], {"gained": 2}), Node("NEW", ["K"], {})], edges=[])
    out = _render(b, c)
    assert "REGRESSIONS" in out and "ADDED" in out
    assert "GONE" in out and "NEW" in out
    assert out.index("REGRESSIONS") < out.index("ADDED")     # failures first
    assert "RESULT:" in out.splitlines()[-1]


def test_render_clean_run_says_so():
    g = Graph(nodes=[Node("N1", ["K"], {"p": 1})], edges=[])
    out = _render(g, g)
    assert "RESULT: 0 regressions" in out
    assert "0 additions" in out
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ../openhound-collector-common && uv run pytest tests/test_integration_regressions.py -k render -v`
Expected: FAIL — the current `render()` emits neither header.

- [ ] **Step 3: Replace `render()`**

```python
    def _additions(self) -> list[str]:
        """Everything the candidate gained. Never fails a run; always shown."""
        out: list[str] = []
        for nid in self.nodes_only_in_candidate:
            out.append(f"node {nid}")
        for ekey in self.edges_only_in_candidate:
            out.append(f"edge {ekey}")
        for diff in (*self.node_prop_diffs, *self.edge_prop_diffs):
            for prop in sorted(diff.only_in_candidate):
                out.append(f"property {diff.kind} {diff.key}.{prop}")
        for rollup, what in ((self.node_kind_rollup, "node"), (self.edge_kind_rollup, "edge")):
            for kind in sorted(rollup):
                for prop in rollup[kind]["only_in_candidate"]:
                    out.append(f"property {what} kind {kind}.{prop}")
        return out

    def render(self, log: Callable[[str], None] = print) -> None:
        """Print regressions first, then additions, then a one-line verdict.

        Regressions lead because they are the only thing that changes the exit
        code; additions follow so a grown graph is still reviewed rather than
        silently accepted.
        """
        regs = self.regressions()
        bar = "=" * 72
        log(bar)
        log(f"REGRESSIONS ({len(regs)}) -- present in baseline, missing or reduced in candidate")
        log(bar)
        if regs:
            for r in regs:
                log(f"  - {r}")
        else:
            log("  (none)")

        adds = self._additions()
        log(bar)
        log(f"ADDED ({len(adds)}) -- in candidate only; review, but does not fail the run")
        log(bar)
        if adds:
            for a in adds:
                log(f"  + {a}")
        else:
            log("  (none)")

        # Changed values that are neither a loss nor an addition: reported for
        # context only, and deliberately not counted in either headline number.
        changed = sum(len(d.changed) for d in (*self.node_prop_diffs, *self.edge_prop_diffs))
        log(bar)
        log(f"RESULT: {len(regs)} regressions, {len(adds)} additions, {changed} changed values.")
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd ../openhound-collector-common && uv run pytest tests/test_integration_regressions.py -v`
Expected: PASS (12 tests).

- [ ] **Step 5: Green checkpoint.** `uv run pytest tests -q`, `uv run ruff check src tests`, `uv run mypy src/openhound_collector_common`. **Do not commit.**

---

## Task 4: The `openhound-compare` console script

**Files:**
- Create: `../openhound-collector-common/src/openhound_collector_common/integration_testing/cli.py`
- Modify: `../openhound-collector-common/pyproject.toml`
- Test: `../openhound-collector-common/tests/test_integration_cli.py` (create)

**Interfaces:**
- Consumes: `load_graph`, `compare_graphs`, `ComparisonReport.render`, `ComparisonReport.has_regressions`, `ComparisonReport.to_dict`.
- Produces: `cli.main(argv: list[str] | None = None) -> int`, returning `0` (clean), `1` (regressions), or `2` (a path that is neither a `.zip` nor a directory, or unreadable). Registered as the `openhound-compare` console script.

- [ ] **Step 1: Write the failing test**

Create `tests/test_integration_cli.py`:

```python
import json

from openhound_collector_common.integration_testing import cli


def _payload(path, nodes):
    path.write_text(json.dumps({"graph": {"nodes": nodes, "edges": []}}), encoding="utf-8")


def _dir_with(tmp_path, name, nodes):
    d = tmp_path / name
    d.mkdir()
    _payload(d / "sccm_nodes.json", nodes)
    return d


N1 = [{"id": "N1", "kinds": ["SCCM_Site"], "properties": {"siteCode": "PS1"}}]
N1_N2 = N1 + [{"id": "N2", "kinds": ["SCCM_Site"], "properties": {}}]


def test_clean_comparison_exits_zero(tmp_path, capsys):
    a = _dir_with(tmp_path, "baseline", N1)
    b = _dir_with(tmp_path, "candidate", N1)
    assert cli.main([str(a), str(b)]) == 0
    assert "RESULT: 0 regressions" in capsys.readouterr().out


def test_dropped_node_exits_one(tmp_path, capsys):
    a = _dir_with(tmp_path, "baseline", N1_N2)
    b = _dir_with(tmp_path, "candidate", N1)
    assert cli.main([str(a), str(b)]) == 1
    assert "N2" in capsys.readouterr().out


def test_added_node_exits_zero(tmp_path):
    a = _dir_with(tmp_path, "baseline", N1)
    b = _dir_with(tmp_path, "candidate", N1_N2)
    assert cli.main([str(a), str(b)]) == 0


def test_json_report_is_written(tmp_path):
    a = _dir_with(tmp_path, "baseline", N1_N2)
    b = _dir_with(tmp_path, "candidate", N1)
    out = tmp_path / "diff.json"
    assert cli.main([str(a), str(b), "--json", str(out)]) == 1
    assert json.loads(out.read_text())["nodes_only_in_baseline"] == ["N2"]


def test_quiet_suppresses_the_report_but_not_the_exit_code(tmp_path, capsys):
    a = _dir_with(tmp_path, "baseline", N1_N2)
    b = _dir_with(tmp_path, "candidate", N1)
    assert cli.main([str(a), str(b), "-q"]) == 1
    assert capsys.readouterr().out == ""


def test_bad_path_exits_two(tmp_path, capsys):
    a = _dir_with(tmp_path, "baseline", N1)
    missing = tmp_path / "nope.txt"
    missing.write_text("not a payload", encoding="utf-8")
    assert cli.main([str(a), str(missing)]) == 2
    assert "openhound-compare:" in capsys.readouterr().err
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ../openhound-collector-common && uv run pytest tests/test_integration_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'openhound_collector_common.integration_testing.cli'`.

- [ ] **Step 3: Create `cli.py`**

```python
"""Command-line entry point for ``openhound-compare``.

Deliberately argparse, not Typer: this library declares no CLI dependency, and
two positionals plus two flags do not justify imposing one on every collector
that installs it. Kept thin -- parsing and exit code only -- so the comparison
logic stays testable without spawning a subprocess.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from openhound_collector_common.integration_testing.compare import compare_graphs
from openhound_collector_common.integration_testing.graph import load_graph


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openhound-compare",
        description="Diff two OpenGraph payloads down to property name and value. "
                    "Each side may be a .zip or a directory of *.json payloads. "
                    "Exits 1 when the candidate lost anything the baseline had; "
                    "additions and ordinary value changes exit 0.",
    )
    p.add_argument("baseline", type=Path,
                   help="The payload that came first -- a saved zip or a convert output directory.")
    p.add_argument("candidate", type=Path,
                   help="The payload being compared against the baseline.")
    p.add_argument("--json", dest="json_path", type=Path, default=None,
                   help="Also write the full report as JSON to this path.")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress the console report; the exit code is unaffected.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        baseline = load_graph(args.baseline)
        candidate = load_graph(args.candidate)
    except (ValueError, OSError) as ex:
        # ValueError: load_graph rejects a path that is neither .zip nor a directory.
        # OSError: unreadable path / bad zip. Either way the operator gave us
        # something we cannot diff, which is distinct from finding a regression --
        # hence 2, so a caller can tell "broken invocation" from "found a drop".
        print(f"openhound-compare: {ex}", file=sys.stderr)
        return 2

    report = compare_graphs(baseline, candidate)
    if not args.quiet:
        report.render(log=print)
    if args.json_path is not None:
        args.json_path.write_text(json.dumps(report.to_dict(), indent=2, default=str),
                                  encoding="utf-8")
    return 1 if report.has_regressions else 0
```

- [ ] **Step 4: Register the console script**

In `../openhound-collector-common/pyproject.toml`, add immediately after the `[project.urls]` block:

```toml
# The library's first console script. `openhound compare` is not available as a
# subcommand of the framework binary: openhound/main.py builds its root Typer app
# inside TyperOverride.__init__, which loads extensions via entry points before the
# app name is bound -- so an extension cannot add_typer a new verb, and adding one
# would mean editing framework core. A console script needs neither.
[project.scripts]
openhound-compare = "openhound_collector_common.integration_testing.cli:main"
```

- [ ] **Step 5: Run to verify it passes**

Run: `cd ../openhound-collector-common && uv run pytest tests/test_integration_cli.py -v`
Expected: PASS (6 tests).

- [ ] **Step 6: Verify the installed command actually resolves**

Run: `cd ../openhound-collector-common && uv sync --group dev && uv run openhound-compare --help`
Expected: the usage block prints and exits 0. If `uv run` cannot find it, the entry point is misspelled — the module path is `openhound_collector_common.integration_testing.cli` and the callable is `main`.

- [ ] **Step 7: Green checkpoint.** `uv run pytest tests -q`, `uv run ruff check src tests`, `uv run mypy src/openhound_collector_common`. **Do not commit.**

---

## Task 5: Shared library documentation

**Files:**
- Modify: `../openhound-collector-common/README.md`

**Interfaces:** none — documentation only.

- [ ] **Step 1: Document the command**

Add a section to the shared library README (place it after the existing feature overview; match the surrounding heading level). The block below is fenced with **four** backticks because its content contains a three-backtick fence — copy the inner content, not the outer fence:

````markdown
## `openhound-compare`

Diff two OpenGraph payloads down to property name and value. Installed with this
package as a console script; no collection and no framework CLI involved.

```bash
openhound-compare BASELINE CANDIDATE [--json PATH] [-q]
```

Each side may be a `.zip` or a directory of `*.json` payloads, in any combination —
an archived baseline against a fresh `convert` output directory is the common case.

**Baseline is what came first.** A *regression* is anything present in the baseline
and missing or reduced in the candidate: a dropped node or edge, a lost property, a
property emptied to `null`/`""`/`[]`/`{}`, a list-valued property that lost items, or
a property name that no longer appears on a kind at all. Additions and ordinary value
changes are reported under `ADDED` and do not fail the run.

| Exit | Meaning |
|---|---|
| `0` | No regressions. Additions and value changes may still be reported |
| `1` | The candidate lost something the baseline had |
| `2` | A path was neither a `.zip` nor a directory, or could not be read |

There is no flag to disable the exit code. Comparing payloads from two *different*
tools will normally report regressions — each tool emits things the other does not —
so a non-zero exit there means "these differ", not "something broke".
````

- [ ] **Step 2: Verify the section landed intact**

Run: `rg -n "openhound-compare|Exit \| Meaning" ../openhound-collector-common/README.md`
Expected: the heading, the usage block, and the exit-code table are all present. Confirm the `bash` fence inside the section did not swallow the rest — the section must end with the closing paragraph about cross-tool comparison, not stop mid-table.

- [ ] **Step 3: Green checkpoint.** No tests to run. **Do not commit.** Tag/publish `v0.1.2` is **Meatbag's action** — stop here and report that the library side is ready for release.

---

## Task 6: Collector adoption — floor bump, orientation, exit codes

**Files:**
- Modify: `pyproject.toml:45`
- Modify: `src/openhound_sccm/integration/__init__.py` — `compare_to_zip` (lines 60-72)
- Modify: `src/openhound_sccm/main.py` — the testing block (lines 1384-1400)
- Test: `tests/integration_wiring_test.py`, `tests/collect_exit_code_test.py` (create)

**Interfaces:**
- Consumes: `ComparisonReport.has_regressions` and `render` from Tasks 2–3.
- Produces: `compare_to_zip(graph_dir, zip_path, out_path=None, log=logger.info) -> int` returning 1 on regression. `collect_sccm` raises `typer.Exit(code=…)` reflecting both testing flags.

- [ ] **Step 1: Bump the dependency floor**

In `pyproject.toml`, change line 45 from `"openhound-collector-common>=0.1.1,<0.2.0",` to:

```toml
    "openhound-collector-common>=0.1.2,<0.2.0",
```

Leave the surrounding comment about the `<0.2.0` cap unchanged — it still applies.

- [ ] **Step 2: Write the failing tests**

In `tests/integration_wiring_test.py`, replace `test_compare_to_zip_always_zero` with:

```python
def test_compare_to_zip_flags_a_regression(tmp_path):
    """The zip is the BASELINE. A node it has and the fresh graph lacks is a drop."""
    _write_min_graph(tmp_path)                     # graph has CAS, PS1, SEC
    zp = tmp_path / "b.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("nodes.json", json.dumps({"graph": {"nodes": [
            {"id": "CAS", "kinds": ["SCCM_Site"], "properties": {"siteCode": "CAS"}},
            {"id": "GONE", "kinds": ["SCCM_Site"], "properties": {}}], "edges": []}}))
    rc = compare_to_zip(tmp_path, zp, out_path=tmp_path / "cmp.json")
    assert rc == 1
    report = json.loads((tmp_path / "cmp.json").read_text())
    assert report["nodes_only_in_baseline"] == ["GONE"]      # the zip's node, lost
    assert "PS1" in report["nodes_only_in_candidate"]        # the graph's extras, added


def test_compare_to_zip_clean_when_candidate_only_grew(tmp_path):
    _write_min_graph(tmp_path)
    zp = tmp_path / "b.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("nodes.json", json.dumps({"graph": {"nodes": [
            {"id": "CAS", "kinds": ["SCCM_Site"], "properties": {"siteCode": "CAS"}}],
            "edges": []}}))
    assert compare_to_zip(tmp_path, zp, out_path=tmp_path / "cmp.json") == 0
```

Create `tests/collect_exit_code_test.py`:

```python
"""The collect command's combined testing exit code.

--compare-to-zip used to always return 0. Now either testing flag can fail, so
collect_sccm must surface a non-zero exit if EITHER does, while still running both
so the operator sees both reports.
"""
import pytest

from openhound_sccm import main


@pytest.mark.parametrize("rc_compare,rc_suite,expected", [
    (0, 0, 0),
    (1, 0, 1),          # compare found a regression
    (0, 1, 1),          # a fixture case failed
    (1, 1, 1),          # both
])
def test_combined_exit_code(rc_compare, rc_suite, expected):
    assert main._combined_testing_exit_code(rc_compare, rc_suite) == expected
```

- [ ] **Step 3: Run to verify they fail**

Run: `uv run pytest tests/integration_wiring_test.py tests/collect_exit_code_test.py -v`
Expected: FAIL — the wiring tests assert `rc == 1` where the current code returns 0, and `main._combined_testing_exit_code` does not exist.

- [ ] **Step 4: Swap the orientation in `compare_to_zip`**

Replace the body of `compare_to_zip` in `src/openhound_sccm/integration/__init__.py`:

```python
def compare_to_zip(graph_dir: Path, zip_path: Path, out_path: Path | None = None,
                   log: Callable[[str], None] = logger.info) -> int:
    """Diff this run's freshly-converted graph against a previously saved payload.

    The saved payload is the BASELINE -- it is what came first -- and this run's
    graph is the candidate. Returns 1 when the candidate lost something the
    baseline had, else 0.

    Comparing against a payload from a DIFFERENT tool (a CMBP zip) will normally
    return 1: each tool emits nodes, kinds and properties the other does not. That
    is a true statement about the two payloads, not a defect in this run. There is
    deliberately no flag to suppress it.
    """
    baseline = load_graph(zip_path)
    candidate = load_graph(graph_dir)
    report = compare_graphs(baseline, candidate)
    report.render(log=log)
    if out_path is not None:
        Path(out_path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        logger.debug("Comparison report written to %s", out_path)
    if report.has_regressions:
        logger.warning("Comparison: the candidate lost content the baseline had "
                       "(%d regressions)", len(report.regressions()))
        return 1
    logger.info("Comparison: no regressions against the baseline")
    return 0
```

- [ ] **Step 5: Combine the exit codes in `main.py`**

Add this helper immediately above `_run_integration_suite`:

```python
def _combined_testing_exit_code(rc_compare: int, rc_suite: int) -> int:
    """Non-zero if EITHER testing flag failed.

    Both always run so the operator gets both reports; the process then reports
    the worse of the two outcomes rather than letting one mask the other.
    """
    return 1 if (rc_compare or rc_suite) else 0
```

Replace the testing block at `main.py:1387-1400`:

```python
        graph_dir = _paths.graph_out
        rc_compare = 0
        if compare_to_zip is not None:
            from openhound_sccm.integration import compare_to_zip as _compare_to_zip
            rc_compare = _compare_to_zip(
                graph_dir, compare_to_zip,
                out_path=output_path / f"compare-{_ts}.json", log=logger.info,
            )
        rc_suite = 0
        if run_integration_tests:
            rc_suite = _run_integration_suite(
                graph_dir,
                output_path / f"integration_results-{_ts}.json",
                privileged=_resolve_integration_privileged(integration_privilege, collect_counts),
            )
        if compare_to_zip is not None or run_integration_tests:
            raise typer.Exit(code=_combined_testing_exit_code(rc_compare, rc_suite))
```

> `_resolve_integration_privileged`, `integration_privilege` and `collect_counts` are introduced in Task 7. If you are executing tasks strictly in order, use `privileged=not integration_lowpriv` here and switch it in Task 7 Step 5 — the tests in this task do not exercise that argument.

- [ ] **Step 6: Run to verify they pass**

Run: `uv run pytest tests/integration_wiring_test.py tests/collect_exit_code_test.py -v`
Expected: PASS.

- [ ] **Step 7: Green checkpoint.** `uv run pytest tests -q`, `uv run ruff check src tests`, `uv run mypy src\openhound_sccm`. **Do not commit.**

---

## Task 7: `--integration-privilege auto|high|low`

**Files:**
- Modify: `src/openhound_sccm/main.py` — remove `integration_lowpriv` (lines 1163-1171); add the enum, the flag, `_merge_row_counts`, `_detect_privileged`, `_resolve_integration_privileged`; change `_run_integration_suite`'s parameter
- Test: `tests/integration_privilege_test.py` (create), `tests/integration_cli_flags_test.py` (modify)

**Interfaces:**
- Consumes: `discovery_counts` / `per_host_counts` already computed in `collect_sccm`.
- Produces: `IntegrationPrivilege` (a `str` Enum with members `auto`, `high`, `low`); `_merge_row_counts(discovery, per_host) -> dict[str, int]`; `_detect_privileged(counts) -> tuple[bool, int]`; `_resolve_integration_privileged(choice, counts) -> bool`; `_run_integration_suite(graph_dir, results_path, privileged: bool) -> int`.

- [ ] **Step 1: Write the failing test**

Create `tests/integration_privilege_test.py`:

```python
"""Privilege-level detection for --run-integration-tests.

The verdict is derived from COLLECTION evidence (AdminService/WMI row counts), never
from graph content: a privileged run whose builder is broken emits no Tier-D nodes,
would read as low-privilege, and would then skip the very cases that catch it.
"""
from pathlib import Path

import pytest

from openhound_sccm import main
from openhound_sccm.main import IntegrationPrivilege as P


def test_merge_row_counts_sums_overlaps():
    assert main._merge_row_counts({"a": 1, "b": 2}, {"b": 3, "c": 4}) == {"a": 1, "b": 5, "c": 4}


@pytest.mark.parametrize("counts,expected_priv,expected_rows", [
    ({}, False, 0),
    ({"ldap_sites": 12, "dns_management_points": 3}, False, 0),
    ({"adminservice_admins": 7}, True, 7),
    ({"wmi_sites": 2}, True, 2),
    ({"adminservice_admins": 7, "wmi_sites": 2}, True, 9),
    ({"adminservice_admins": 0, "wmi_sites": 0}, False, 0),
])
def test_detect_privileged(counts, expected_priv, expected_rows):
    assert main._detect_privileged(counts) == (expected_priv, expected_rows)


def test_local_wmi_tables_are_not_privileged_evidence():
    """local_wmi_* reads WMI on the COLLECTOR host -- a discovery phase any user runs.

    A substring match on "wmi_" would count these and wrongly report a plain
    domain-user collection as privileged.
    """
    counts = {"local_wmi_sms_authority": 5, "local_wmi_ccm_client": 9,
              "local_wmi_sms_lookupmp": 2}
    assert main._detect_privileged(counts) == (False, 0)


def test_high_forces_privileged_regardless_of_evidence():
    assert main._resolve_integration_privileged(P.high, {}) is True


def test_low_forces_unprivileged_regardless_of_evidence():
    assert main._resolve_integration_privileged(P.low, {"adminservice_admins": 99}) is False


@pytest.mark.parametrize("counts,expected", [
    ({"adminservice_admins": 7}, True),
    ({"ldap_sites": 12}, False),
])
def test_auto_follows_the_evidence(counts, expected):
    assert main._resolve_integration_privileged(P.auto, counts) is expected


def test_suite_passes_privileged_through(monkeypatch):
    import openhound_sccm.integration as integ
    seen = {}
    monkeypatch.setattr(integ, "run_integration_tests",
                        lambda graph_dir, **kw: seen.update(kw) or 0)
    assert main._run_integration_suite(Path("graph"), Path("r.json"), privileged=False) == 0
    assert seen["privileged"] is False
    main._run_integration_suite(Path("graph"), Path("r.json"), privileged=True)
    assert seen["privileged"] is True
```

In `tests/integration_cli_flags_test.py`, replace everything from the `# --- low-privilege fixture mode (con-6677) ---` comment to the end of the file with:

```python
# --- privilege selection (con-6677, superseded by --integration-privilege) ----
#
# --integration-lowpriv was a boolean that the operator had to remember. The
# three-way flag replaces it: `low` is that boolean, `high` forces the full set for
# a partially-privileged collection, and `auto` -- the default -- reads the run's
# AdminService/WMI row counts so a forgotten flag stops producing false failures.

def test_integration_privilege_registered_in_help():
    out = _help_output()
    assert "--integration-privilege" in out
    assert "Testing" in out  # same rich_help_panel as the other testing flags


def test_superseded_boolean_flag_is_gone():
    assert "--integration-lowpriv" not in _help_output()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/integration_privilege_test.py tests/integration_cli_flags_test.py -v`
Expected: FAIL — `ImportError: cannot import name 'IntegrationPrivilege'`.

- [ ] **Step 3: Add the enum and the detection helpers**

Add the enum near the other CLI enums in `main.py` (alongside `Contract` / the progress choice type):

```python
class IntegrationPrivilege(str, Enum):
    """Which fixture set --run-integration-tests asserts.

    Describes the COLLECTION, not the fixtures. `auto` derives it from how much the
    run actually collected; the two explicit values exist for the case auto cannot
    see -- a partially-privileged run, where AdminService reached one site and not
    another, looks privileged by row count but should often be asserted as low.
    """
    auto = "auto"
    high = "high"
    low = "low"


# AdminService and WMI are the two privileged per-host transports. The prefixes are
# matched with startswith, never a substring test: local_wmi_sms_authority,
# local_wmi_sms_lookupmp and local_wmi_ccm_client are DISCOVERY resources reading
# WMI on the collector host itself, which any domain user can do.
_PRIVILEGED_TABLE_PREFIXES = ("adminservice_", "wmi_")
```

`Enum` needs importing if it is not already: add `from enum import Enum` to the stdlib import block.

Add these three functions immediately above `_run_integration_suite`:

```python
def _merge_row_counts(discovery: dict[str, int], per_host: dict[str, int]) -> dict[str, int]:
    """Combine the two collection stages' per-table row counts.

    Their table sets are disjoint today (discovery emits ldap_*/dns_*/local_*/
    collection_settings; per-host emits the rest), but sum on overlap so a future
    shared table can never silently drop rows -- same rule _log_collect_summary uses.
    """
    counts = dict(discovery)
    for table, rows in per_host.items():
        counts[table] = counts.get(table, 0) + rows
    return counts


def _detect_privileged(counts: dict[str, int]) -> tuple[bool, int]:
    """Return (privileged, rows) from this run's per-table row counts.

    Privileged means AdminService or WMI actually returned data. This measures the
    collection INPUT deliberately: inferring from the emitted graph would be
    circular, because a broken privileged builder emits nothing, would read as
    low-privilege, and would skip exactly the cases that would have caught it.
    """
    rows = sum(n for table, n in counts.items()
               if table.startswith(_PRIVILEGED_TABLE_PREFIXES))
    return rows > 0, rows


def _resolve_integration_privileged(choice: IntegrationPrivilege,
                                    counts: dict[str, int]) -> bool:
    """Resolve --integration-privilege into the boolean the harness takes."""
    if choice is IntegrationPrivilege.high:
        logger.info("Integration suite: --integration-privilege high; asserting every "
                    "case including the Tier-D RBAC families")
        return True
    if choice is IntegrationPrivilege.low:
        logger.info("Integration suite: --integration-privilege low; skipping the cases "
                    "that require AdminService/WMI collection")
        return False
    privileged, rows = _detect_privileged(counts)
    if privileged:
        logger.info("Integration suite: privileged collection detected (%d row(s) across "
                    "AdminService/WMI tables); asserting every case", rows)
    else:
        logger.info("Integration suite: low-privilege collection detected (no rows in any "
                    "AdminService/WMI table); skipping the cases that require them. "
                    "Pass --integration-privilege high to assert them anyway.")
    return privileged
```

- [ ] **Step 4: Retarget `_run_integration_suite`**

Change its signature from `lowpriv: bool` to `privileged: bool`, delete the `if lowpriv:` / `else:` logging block (the verdict is now logged by `_resolve_integration_privileged`, and logging it twice would imply two decisions), and pass the argument straight through. Update the docstring's `*lowpriv*` paragraph to describe `*privileged*` with the sense inverted — `privileged=False` is the low-privilege case. Keep the existing explanation of which families are skipped and why.

```python
def _run_integration_suite(graph_dir: pathlib.Path, results_path: pathlib.Path,
                           privileged: bool) -> int:
```

The body's final statement becomes:

```python
    from openhound_sccm.integration import run_integration_tests as _run_integration_tests
    return _run_integration_tests(
        graph_dir,
        results_path=results_path,
        log=logger.info,
        privileged=privileged,
    )
```

- [ ] **Step 5: Replace the flag and capture the counts**

Delete the whole `integration_lowpriv` option (lines 1163-1171) and put this in its place:

```python
    integration_privilege: IntegrationPrivilege = typer.Option(
        IntegrationPrivilege.auto, "--integration-privilege", rich_help_panel="Testing",
        help="Which fixture set --run-integration-tests asserts. Describes the COLLECTION, "
             "not the fixtures. 'auto' (default) decides from whether AdminService/WMI "
             "actually returned rows this run. 'low' skips the Tier-D RBAC cases "
             "(SCCM_FullAdministrator, SCCM_IsAssigned, SCCM_IsMappedTo, SCCM_AllPermissions "
             "and the SCCM_AdminUser / SCCM_SecurityRole / SCCM_Collection nodes) that need "
             "AdminService or WMI, so they cannot fail for behaving correctly. 'high' asserts "
             "every case -- use it when a partially-privileged run should be held to the full set.",
    ),
```

Then make the merged counts available to the testing block. Immediately **before** the `try:` that wraps collection, initialise:

```python
    # Captured after collection so the testing block below can derive the run's
    # privilege level. Initialised here rather than inside the try so mypy's
    # possibly-undefined check (enabled in pyproject) is satisfied on every path.
    collect_counts: dict[str, int] = {}
```

and set it right after the `_log_collect_summary(...)` call at line 1337:

```python
            collect_counts = _merge_row_counts(discovery_counts, per_host_counts)
```

Finally, in the testing block from Task 6 Step 5, the `privileged=` argument now reads as written there:

```python
                privileged=_resolve_integration_privileged(integration_privilege, collect_counts),
```

- [ ] **Step 6: Run to verify it passes**

Run: `uv run pytest tests/integration_privilege_test.py tests/integration_cli_flags_test.py -v`
Expected: PASS.

- [ ] **Step 7: Prove the old flag is gone everywhere**

Run: `rg -n "integration_lowpriv|integration-lowpriv" src tests README.md`
Expected: no matches in `src` or `tests`. `README.md` still matches — that is Task 9's work; note the line numbers now so they are easy to find.

- [ ] **Step 8: Annotate the superseded ticket**

Run `gtk` to add a note to `con-6677` recording that `--integration-privilege low` supersedes `--integration-lowpriv` and that the acceptance criteria are met by the three-way flag. Then regenerate `.tickets/_TICKETS-BY-STATUS.md` from `gtk list`. Do not hand-edit that file.

- [ ] **Step 9: Green checkpoint.** `uv run pytest tests -q`, `uv run ruff check src tests`, `uv run mypy src\openhound_sccm`. **Do not commit.**

---

## Task 8: `dev/ab_matrix.py`

**Files:**
- Create: `dev/ab_matrix.py`, `dev/_ab_cmbp.py`
- Test: `tests/ab_matrix_test.py` (create)

**Interfaces:**
- Consumes: the `openhound-compare` console script from Task 4; `openhound collect sccm` with `--clean`, `--run-all`, `--run-integration-tests`, `--disable-possible-edges`.
- Produces: `Cell` dataclass (`identity: str`, `possible_edges: bool`, `tag: str`); `plan_cells(identities) -> list[Cell]`; `collect_argv(cell, domain, dc, password, out_dir) -> list[str]`; `compare_argv(cell, baselines, out_dir) -> list[str]`; `assert_empty(path) -> None`; `main(argv=None) -> int`.

- [ ] **Step 1: Write the failing test**

Create `tests/ab_matrix_test.py`:

```python
"""Cell planning and argv construction for dev/ab_matrix.py.

dev/ is not an importable package, so the module is loaded by path. Nothing here
runs a collection -- only the pure planning functions are exercised.
"""
import importlib.util
import pathlib

import pytest

_PATH = pathlib.Path(__file__).resolve().parents[1] / "dev" / "ab_matrix.py"
_SPEC = importlib.util.spec_from_file_location("ab_matrix", _PATH)
assert _SPEC and _SPEC.loader
ab = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ab)


def test_plan_cells_is_identities_times_flag_states():
    cells = ab.plan_cells(["lowpriv", "domainadmin"])
    assert len(cells) == 4
    assert [c.tag for c in cells] == [
        "lowpriv-pe-on", "lowpriv-pe-off",
        "domainadmin-pe-on", "domainadmin-pe-off",
    ]
    assert [c.possible_edges for c in cells] == [True, False, True, False]


def test_collect_argv_always_passes_clean_and_run_all():
    cell = ab.plan_cells(["lowpriv"])[0]
    argv = ab.collect_argv(cell, "mayyhem.com", "dc.mayyhem.com", "pw", pathlib.Path("out"))
    assert "--clean" in argv            # non-negotiable: dlt APPENDS without it
    assert "--run-all" in argv
    assert "--run-integration-tests" in argv
    assert "--disable-possible-edges" not in argv        # pe-on cell


def test_collect_argv_disables_possible_edges_on_the_off_cell():
    cell = ab.plan_cells(["lowpriv"])[1]
    argv = ab.collect_argv(cell, "mayyhem.com", "dc.mayyhem.com", "pw", pathlib.Path("out"))
    assert "--disable-possible-edges" in argv


def test_collect_argv_omits_credentials_for_the_current_context():
    """password=None selects integrated auth -- how the domainadmin cell runs."""
    cell = ab.plan_cells(["domainadmin"])[0]
    argv = ab.collect_argv(cell, "mayyhem.com", "dc.mayyhem.com", None, pathlib.Path("out"))
    assert "-u" not in argv and "-p" not in argv


def test_compare_argv_puts_the_baseline_first():
    cell = ab.plan_cells(["lowpriv"])[0]
    argv = ab.compare_argv(cell, pathlib.Path("baselines"), pathlib.Path("out"))
    assert argv[0] == "openhound-compare"
    assert argv[1].endswith("lowpriv-pe-on.zip")          # baseline
    assert argv[2].endswith("graph")                       # candidate


def test_assert_empty_rejects_a_used_directory(tmp_path):
    used = tmp_path / "used"
    used.mkdir()
    (used / "stale.jsonl.gz").write_text("x", encoding="utf-8")
    with pytest.raises(SystemExit):
        ab.assert_empty(used)


def test_assert_empty_accepts_a_missing_or_empty_directory(tmp_path):
    ab.assert_empty(tmp_path / "does-not-exist")
    (tmp_path / "empty").mkdir()
    ab.assert_empty(tmp_path / "empty")
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/ab_matrix_test.py -v`
Expected: FAIL — `FileNotFoundError` for `dev/ab_matrix.py`.

- [ ] **Step 3: Create `dev/ab_matrix.py`**

```python
"""A/B matrix runner: collect the same lab under several identities and both
possible-edge states, then diff each result against its saved baseline.

Replaces the four PowerShell drivers that lived in the OpenHound monorepo under
sccm/tests/live-comparison/. Those hardcoded one desktop's absolute paths and a
literal password; this takes both as parameters and reads credentials only from the
environment.

Credentials: SCCM_LAB_PASSWORD_<IDENTITY> (uppercased), falling back to
SCCM_LAB_PASSWORD. An identity with neither runs with integrated auth as the current
logon context -- which is how the domainadmin cell is meant to run.

    uv run python dev/ab_matrix.py \
        --identity lowpriv --identity domainadmin \
        --domain mayyhem.com --dc dc.mayyhem.com \
        --baselines ./baselines --out-root ./ab-20260731

Baselines are one labelled zip per cell: baselines/<identity>-pe-on.zip and
baselines/<identity>-pe-off.zip. openhound-compare accepts a zip or a directory on
either side, so a convert output directory works equally well.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
from dataclasses import dataclass

FLAG_STATES = ((True, "pe-on"), (False, "pe-off"))


@dataclass(frozen=True)
class Cell:
    identity: str
    possible_edges: bool
    tag: str


def plan_cells(identities: list[str]) -> list[Cell]:
    """Every (identity, possible-edge state) pair, in a stable order."""
    return [Cell(identity, on, f"{identity}-{label}")
            for identity in identities
            for on, label in FLAG_STATES]


def password_for(identity: str) -> str | None:
    """Per-identity password from the environment, or None for integrated auth."""
    specific = os.environ.get(f"SCCM_LAB_PASSWORD_{identity.upper()}")
    if specific:
        return specific
    return os.environ.get("SCCM_LAB_PASSWORD") or None


def collect_argv(cell: Cell, domain: str, dc: str, password: str | None,
                 out_dir: pathlib.Path) -> list[str]:
    """The `openhound collect sccm` command line for one cell.

    --clean is not optional. Re-running into a used directory does not overwrite raw
    data: dlt appends a load package, and preprocess reads every .jsonl.gz per table,
    so the previous run's rows are unioned into this run's graph. Measured 2026-07-28:
    11 of 24 raw tables held rows from two different dates, with exit code 0 and fresh
    graph timestamps hiding it completely.
    """
    argv = ["openhound", "collect", "sccm", str(out_dir),
            "-m", "All", "-d", domain, "--dc", dc,
            "--clean", "--run-all", "--run-integration-tests"]
    if password is not None:
        argv += ["-u", cell.identity, "-p", password]
    if not cell.possible_edges:
        argv.append("--disable-possible-edges")
    return argv


def compare_argv(cell: Cell, baselines: pathlib.Path, out_dir: pathlib.Path) -> list[str]:
    """Baseline first, candidate second -- the orientation openhound-compare expects."""
    return ["openhound-compare",
            str(baselines / f"{cell.tag}.zip"),
            str(out_dir / "graph"),
            "--json", str(out_dir / "compare.json")]


def assert_empty(path: pathlib.Path) -> None:
    """Refuse to reuse a directory that already holds a collection."""
    if path.exists() and any(path.iterdir()):
        sys.exit(f"ab_matrix: {path} is not empty. Every cell needs a fresh directory -- "
                 f"reusing one unions the previous run's rows into this run's graph.")


def _run(argv: list[str], log_path: pathlib.Path) -> int:
    """Run a command, tee-ing combined output to a per-cell log. Returns its code."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as fh:
        proc = subprocess.run(argv, stdout=fh, stderr=subprocess.STDOUT, text=True)
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ab_matrix",
        description="Collect the lab under several identities and both possible-edge "
                    "states, then diff each result against its saved baseline.")
    p.add_argument("--identity", action="append", required=True, dest="identities",
                   help="Repeatable. One collection pair per identity.")
    p.add_argument("--domain", required=True)
    p.add_argument("--dc", required=True)
    p.add_argument("--baselines", type=pathlib.Path, required=True,
                   help="Directory of <identity>-<pe-on|pe-off>.zip baselines.")
    p.add_argument("--out-root", type=pathlib.Path, required=True,
                   help="Parent directory for this run's per-cell output.")
    p.add_argument("--with-cmbp", action="store_true",
                   help="Also run the deprecated ConfigManBearPig.ps1 per cell "
                        "(Windows only; adds the runas /netonly identity shim).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the planned commands and exit without running anything.")
    args = p.parse_args(argv)

    cells = plan_cells(args.identities)
    results: list[tuple[str, int, int]] = []
    worst = 0

    for cell in cells:
        out_dir = args.out_root / cell.tag
        assert_empty(out_dir)
        collect = collect_argv(cell, args.domain, args.dc,
                               password_for(cell.identity), out_dir)
        compare = compare_argv(cell, args.baselines, out_dir)

        if args.dry_run:
            # Never print the argv directly -- it carries -p <password>.
            print(f"[{cell.tag}] collect  -> {out_dir}")
            print(f"[{cell.tag}] compare  -> {' '.join(compare)}")
            continue

        if args.with_cmbp:
            from _ab_cmbp import run_cmbp          # imported only on this path
            run_cmbp(cell, args.domain, args.dc, args.out_root)

        rc_collect = _run(collect, out_dir / "_collect.log")
        rc_compare = _run(compare, out_dir / "_compare.log")
        results.append((cell.tag, rc_collect, rc_compare))
        worst = max(worst, 1 if (rc_collect or rc_compare) else 0)

    if args.dry_run:
        return 0

    print("\n===== A/B MATRIX =====")
    for tag, rc_c, rc_d in results:
        print(f"{tag:<24} collect_exit={rc_c}  compare_exit={rc_d}")
    print(f"\nWorst outcome: {worst}. compare_exit=1 means that cell lost content "
          f"its baseline had; see <cell>/compare.json.")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Create `dev/_ab_cmbp.py`**

```python
"""The --with-cmbp half of ab_matrix: drive the deprecated ConfigManBearPig.ps1.

Kept in its own module so the default 4-cell path never imports it. Windows-only --
CMBP.ps1 has no username/password parameter and authenticates as whatever context it
runs in, so a non-current identity needs the runas /netonly shim.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

CMBP = pathlib.Path(__file__).resolve().parents[1] / "powershell_deprecated" / "ConfigManBearPig.ps1"


def run_cmbp(cell, domain: str, dc: str, out_root: pathlib.Path) -> int:
    """Run CMBP.ps1 for one cell into its own empty directory.

    -MemoryThresholdPercent 100 disables CMBP's self-imposed memory guard: a lab host
    near its ceiling from hypervisor ballooning otherwise aborts before the
    AdminService/HTTP phases. A real OOM has never been observed.
    """
    if sys.platform != "win32":
        raise RuntimeError("--with-cmbp requires Windows (runas /netonly + PowerShell).")
    if not CMBP.exists():
        raise FileNotFoundError(f"CMBP.ps1 not found at {CMBP}")

    out_dir = out_root / f"cmbp-{cell.tag}"
    out_dir.mkdir(parents=True, exist_ok=True)
    ps = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(CMBP),
        "-CollectionMethods", "All", "-Domain", domain, "-DomainController", dc,
        "-MemoryThresholdPercent", "100",
        "-LogFile", str(out_dir / "cmbp.log"),
    ]
    if not cell.possible_edges:
        ps.append("-DisablePossibleEdges")
    with (out_dir / "_console.txt").open("w", encoding="utf-8") as fh:
        return subprocess.run(ps, cwd=out_dir, stdout=fh,
                              stderr=subprocess.STDOUT, text=True).returncode
```

> The `runas /netonly` shim is intentionally **not** implemented here. `runas` prompts for a password on an interactive console and cannot be driven from a pipe, which is why the original `Run-AsNetOnly.ps1` existed as a separate launcher. Run `ab_matrix.py --with-cmbp` from a shell already launched under the target identity, exactly as the old harness required. Record this in the module docstring if you extend it.

- [ ] **Step 5: Run to verify it passes**

Run: `uv run pytest tests/ab_matrix_test.py -v`
Expected: PASS (7 tests).

- [ ] **Step 6: Verify the planner end to end without collecting**

Run: `uv run python dev/ab_matrix.py --identity lowpriv --identity domainadmin --domain mayyhem.com --dc dc.mayyhem.com --baselines .\baselines --out-root .\ab-check --dry-run`
Expected: eight lines, four cells, no password printed anywhere, exit 0.

- [ ] **Step 7: Green checkpoint.** `uv run pytest tests -q`, `uv run ruff check src tests`. `dev/` is outside ruff's configured paths, so lint it explicitly once: `uv run ruff check dev\ab_matrix.py dev\_ab_cmbp.py`. **Do not commit.**

---

## Task 9: Documentation

**Files:**
- Modify: `README.md` — Testing option table (~line 612), the "Which mode matches your run?" callout (~line 618), the worked examples (~line 624), the two-flags paragraph (~line 2205), and a new subsection under Testing Changes
- Modify: `ARCHITECTURE.md` — new section + changelog entry
- Modify: `.github/workflows/ci.yml` — extend the curated test list

**Interfaces:** none — documentation and CI configuration only.

- [ ] **Step 1: Replace the Testing option rows**

In `README.md`, the Testing table currently has three rows. Replace the `--integration-lowpriv` row with the three-way flag and amend the `--compare-to-zip` row's exit-code claim:

```markdown
| Option | Description |
|---|---|
| `--run-integration-tests` | Implies `--run-all`; asserts the collected graph against the built-in mayyhem lab fixtures — build that lab with [Mayyhem/ludus_sccm](https://github.com/Mayyhem/ludus_sccm) (see [Validate against a real hierarchy](#validate-against-a-real-hierarchy)). Prints PASS/FAIL/SKIP + summary + coverage, writes `integration_results-<ts>.json`, exits non-zero on any failure. |
| `--integration-privilege <auto\|high\|low>` | Which fixture set `--run-integration-tests` asserts. Describes the **collection**, not the fixtures. `auto` (default) decides from whether AdminService/WMI actually returned rows this run. `low` skips the Tier-D RBAC cases that need them. `high` asserts every case — use it when a partially-privileged run should be held to the full set. |
| `--compare-to-zip <path>` | Implies `--run-all`; deep-diffs this run's graph against an arbitrary node/edge payload (a CMBP zip or another OpenHound run) down to property name/value, with a by-kind rollup. Writes `compare-<ts>.json`. **Exits non-zero if this run lost anything the saved payload had.** |
```

Replace the "Which mode matches your run?" callout:

```markdown
> **Which privilege mode?** Normally none — `auto` reads the run's own AdminService/WMI
> row counts and picks. Pass `--integration-privilege low` when a run reached those
> services but you know the data is unrepresentative, and `high` when a partially
> privileged run should still be held to the full fixture set.
```

Replace the worked examples:

```bash
# Assert this collection matches the known-good SCCM graph (implies --run-all).
# These credentials are a plain domain user, so AdminService/WMI never collect --
# auto detects that and skips the Tier-D cases rather than failing them:
uv run openhound collect sccm ./out -d mayyhem.com --dc dc01.mayyhem.com -u "MAYYHEM\lowpriv" -p "Passw0rd!" --run-integration-tests

# Hold a partially-privileged run to the full fixture set, including Tier D:
uv run openhound collect sccm ./out -d mayyhem.com --dc dc01.mayyhem.com -u "MAYYHEM\sccmadmin" -p "Passw0rd!" --run-integration-tests --integration-privilege high

# Diff this collection against a saved payload. The zip is the BASELINE; this run is
# the candidate. Exits non-zero if this run lost anything the zip had -- which a CMBP
# zip always will, since the two tools emit different sets:
uv run openhound collect sccm ./out -d mayyhem.com --dc dc01.mayyhem.com -u "MAYYHEM\lowpriv" -p "Passw0rd!" --compare-to-zip ./bloodhound-sccm-baseline.zip
```

- [ ] **Step 2: Add the before/after subsection**

In `README.md`, insert a new subsection between "Run the checks" and "Validate against a real hierarchy":

````markdown
## Before and after a change

`openhound-compare` ships with the shared library and diffs any two payloads — a `.zip`
or a `convert` output directory on either side — with no collection involved:

```powershell
openhound-compare .\baselines\lowpriv-pe-on.zip .\out\graph
```

The **baseline is what came first**. The command exits non-zero if the candidate lost
anything the baseline had: a dropped node or edge, a lost property, a property emptied
to null, a list-valued property that lost items, or a property name that no longer
appears on a kind. Additions and ordinary value changes are listed under `ADDED` and
exit 0. There is no flag to disable the exit code.

The strongest form of this check holds collection constant and varies only your code —
reprocess one frozen raw bucket with both versions:

```powershell
Copy-Item -Recurse .\out\sccm C:\ohcheck\sccm
# ...on the baseline code:
uv run openhound preprocess sccm C:\ohcheck C:\ohcheck\lookup.duckdb
uv run openhound convert    sccm C:\ohcheck C:\ohcheck\graph-before --lookup-file C:\ohcheck\lookup.duckdb
# ...make your change, then:
uv run openhound convert    sccm C:\ohcheck C:\ohcheck\graph-after  --lookup-file C:\ohcheck\lookup.duckdb
openhound-compare C:\ohcheck\graph-before C:\ohcheck\graph-after
```

Two *live* collections will also differ from ordinary lab churn — a decommissioned
host, an ended session — so per-instance differences there are not all regressions.
Prefer the frozen-bucket form when you want the diff to mean only your change.

For the full matrix — several identities × both possible-edge states — `dev/ab_matrix.py`
runs each cell and compares it to its baseline in one command:

```powershell
$env:SCCM_LAB_PASSWORD_LOWPRIV = "..."
uv run python dev\ab_matrix.py --identity lowpriv --identity domainadmin `
    --domain mayyhem.com --dc dc.mayyhem.com `
    --baselines .\baselines --out-root .\ab-20260731
```
````

- [ ] **Step 3: Correct the stale two-flags paragraph**

Near line 2205, the text says `--compare-to-zip` "always exits 0". Replace that sentence:

```markdown
Two flags exist for exactly this comparison, both implying `--run-all`:
`--run-integration-tests` asserts the graph against the bundled fixtures, and
`--compare-to-zip <payload>` diffs this run against a saved payload property-by-property.
Both exit non-zero on failure — for the comparison, "failure" means this run lost
something the saved payload had.
```

- [ ] **Step 4: Update `ARCHITECTURE.md`**

Add a section describing the comparison gate: the engine lives in the shared library's
`integration_testing` subpackage; `compare_graphs(baseline, candidate)` is oriented
baseline-first; the six regression rules; both the `--compare-to-zip` flag and the
`openhound-compare` console script use the same engine and the same exit-code rule; and
`openhound compare` is not a framework subcommand because extensions are imported inside
the root Typer app's constructor and cannot register a new verb. Add a matching changelog
entry with today's date.

- [ ] **Step 5: Extend the CI test list**

In `.github/workflows/ci.yml`, extend the final `pytest` invocation to include the four
new offline files:

```yaml
      - run: >
          uv run pytest tests/extension_metadata_test.py
          tests/integration_wiring_test.py tests/convert_pipeline_test.py
          tests/integration_fixtures_test.py tests/integration_privilege_test.py
          tests/collect_exit_code_test.py tests/ab_matrix_test.py
          tests/integration_cli_flags_test.py -q
```

Then update the README's matching command under "Run the checks" so the two stay in sync —
the README states that a green local run means a green pull request, which is only true if
the lists are identical.

- [ ] **Step 6: Verify the docs match the code**

Run: `rg -n "integration-lowpriv|always exits 0|Always exits 0" README.md ARCHITECTURE.md`
Expected: no matches. Any hit is a doc still describing the superseded flag or the old
exit-code contract.

- [ ] **Step 7: Green checkpoint.** Run the exact CI command from Step 5 locally. All pass. **Do not commit.**

---

## Task 10: Full verification gate

**Files:** none — verification only.

**Interfaces:** none.

- [ ] **Step 1: Shared library — full suite and static checks**

Run, from `../openhound-collector-common`:
```
uv run pytest tests -q
uv run ruff check src tests
uv run mypy src/openhound_collector_common
```
Expected: all clean. This repo's CI runs the whole `tests` directory, so a green local run is a green pull request.

- [ ] **Step 2: This repo — full offline suite**

Run: `uv run pytest tests -q`
Expected: pass or skip. Any test that fails for want of a lab, a live AdminService, or a cached DuckDB should **skip**, not fail — investigate anything that errors instead.

- [ ] **Step 3: This repo — lint and types**

Run: `uv run ruff check src tests` then `uv run mypy src\openhound_sccm`
Expected: both clean. Watch specifically for `possibly-undefined` on `collect_counts` — if it fires, the initialiser from Task 7 Step 5 is in the wrong place; it must precede the `try:`, not sit inside it.

- [ ] **Step 4: This repo — the exact CI command**

Run the curated list exactly as `.github/workflows/ci.yml` has it after Task 9 Step 5.
Expected: pass.

- [ ] **Step 5: End-to-end smoke without a lab**

Build two tiny payload directories by hand — one with an extra node — and confirm the
console script agrees with the library:

```powershell
uv run openhound-compare .\scratch\before .\scratch\after ; echo "exit=$LASTEXITCODE"
```
Expected: the `REGRESSIONS` / `ADDED` / `RESULT:` blocks print, and `exit=1` when the
after-directory is missing a node the before-directory had, `exit=0` when it only gained one.

- [ ] **Step 6: Confirm nothing was committed**

Run: `git -C . status --short` and `git -C ..\openhound-collector-common status --short`
Expected: both show modified/untracked files and **no** staged changes. Report the file
lists to Meatbag for review.

- [ ] **Step 7: Ticket hygiene**

Move this work's `gtk` tickets to their final states, add the supersession note to
`con-6677` if Task 7 Step 8 was skipped, and regenerate `.tickets/_TICKETS-BY-STATUS.md`
from `gtk list`. Leave `con-c542` and `con-907c` open — this work does not close them, and
36 low-privilege fixture failures remain theirs to fix.
