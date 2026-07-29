# Design: Python integration-test kit (`--run-integration-tests` / `--compare-to-zip`)

**Date:** 2026-07-22 · **Status:** design (approved for planning) · **Driver:** SCCM extension, with a
shared engine promoted into `openhound-collector-common`.

## 1. Goal

Replace the PowerShell unit-test kit (`powershell_deprecated/Invoke-ConfigManBearPigUnitTests.ps1`)
with a Python implementation invoked directly from the collector CLI, and add a generic payload
comparison feature. Two new flags on `collect sccm`, both in a new **Testing** help panel:

- **`--run-integration-tests`** — collect → preprocess → convert → assert the resulting graph against
  the built-in mayyhem-lab fixtures. Prints PASS/FAIL/SKIP + summary + coverage, writes a structured
  results JSON, and **exits non-zero if any case fails** (CI-gateable).
- **`--compare-to-zip <B.zip>`** — collect → … → convert, then deep-diff **this run's payload (A)**
  against an arbitrary node/edge payload **B** (a CMBP zip or another OpenHound run). Reports
  differences to property-name/value granularity, writes a diff JSON, and **always exits 0**
  (informational — it is a diff, not an assertion).

Both flags self-chain (force `run_all=True`) and run in-process after the existing
`_run_e2e_after_collect` returns the convert output directory. They are independent and composable;
when **both** are set, `--compare-to-zip` runs first (informational) and the process exit code reflects
the `--run-integration-tests` result.

## 2. Why (gaps in the current kit this addresses)

- **Position-based comparison is fragile** — `compare_results.py` aligns two runs by list index.
  Fixed by stable per-case IDs and structural (id-keyed) comparison.
- **Dead coverage report** — `Get-MissingTests` reads `$expectedEdges_*` variables that no longer
  exist. Replaced by a real diff of `schema.json` kinds vs fixture-covered kinds.
- **Exact-count only** — add `at_least` / `at_most` / `exact`.
- **Nodes barely tested** — only one hardcoded `memberOf` check. Add first-class node cases.
- **Lab-specifics and old edge names hardcoded**, CMBP typo (`CoerceAndRelaytoSMB`) baked in. The port
  uses the new `SCCM_`/`MSSQL_` names and keeps fixtures in a swappable module.
- **Zip-glob-from-CWD coupling** — read the convert output directory directly; only `--compare-to-zip`
  reads a zip (explicit path).
- **No generic payload diff** — new `--compare-to-zip` fills this, reusable across any collector.

## 3. Architecture

Collector-agnostic engine in the shared library; SCCM-specific data and wiring in the extension.

### 3a. Shared engine — `openhound_collector_common/integration_testing/`

Owner-approved shared-library change (normally read-only to extensions). No third-party deps
(stdlib `json`, `zipfile`, `fnmatch`, `pathlib`, `dataclasses`).

| Module | Responsibility |
|---|---|
| `graph.py` | `Node`, `Edge`, `Graph`; `load_graph(path)` accepts a directory (glob `*.json`) **or** a `.zip`, merges every `{graph:{nodes,edges}}` payload, extracts edge `start.value`/`end.value`, indexes nodes by `id` and edges by `kind`. Duplicate node `id` across payloads → merge property dicts (non-null wins) and union `kinds`, with a debug note. |
| `matcher.py` | Faithful port of `Test-PropertyMatch` / `Test-NodePattern` / `Test-EdgePattern`. `property_match`: both-None=True, one-None=False, list=subset (every expected item matches some actual), wildcard via `fnmatch` (case-insensitive) when expected contains `*`/`?`, bool coercion (`"True"/"1"`, `"False"/"0"`), else case-insensitive exact. `node_matches`: kinds subset (`Base` always satisfied) + property match (a `id` key resolves against `node.id`). `edge_matches`: exact kind + endpoint-by-id lookup + source/target `node_matches` + edge-property match. |
| `cases.py` | `NodePattern{kinds, properties}`; `CountSpec{exact\|at_least\|at_most}`; `EdgeCase{id, kind, description, source, target, properties, count, negative, reason}`; `NodeCase{id, description, kinds, properties, count, negative}`. Every case has a **stable `id`**. |
| `results.py` | `Result{case_id, kind, description, outcome(PASS\|FAIL\|SKIP), detail, matched_count}`, `Summary{passed, failed, skipped, results}`, JSON writer. |
| `runner.py` | `run_suite(graph, edge_cases, node_cases, invariants, schema_path) -> Summary`: runs cases, prints the human summary in the **same line shape as the PS kit** (`<kind>: <desc> - PASS/FAIL/SKIP`, totals, edge/node histograms, `Edge/Node Test Summary`), writes results JSON, returns the summary. `invariants` is an optional list of `Callable[[Graph], Result]` for cross-node/whole-graph checks that don't fit the single-case model (e.g. the `memberOf` root-site normalization); each contributes one `Result` and counts toward pass/fail. |
| `compare.py` | `compare_graphs(a, b) -> ComparisonReport` — the `--compare-to-zip` engine (see §5). |
| `coverage.py` | `coverage(schema_path, edge_cases, node_cases)` — diff `schema.json` node/edge kind names against fixture-covered kinds → untested kinds. |

### 3b. SCCM extension — `openhound_sccm/integration/` + `main.py`

| Piece | Responsibility |
|---|---|
| `integration/fixtures/edges.py` | The mayyhem `EdgeCase` list — all 61 PS `$ExpectedEdges` ported (new names, stable IDs, no CMBP typo). |
| `integration/fixtures/nodes.py` | The mayyhem `NodeCase` list — new node existence/count/property cases per `schema.json` kind, counts anchored to the validated mayyhem state (239 nodes / 419 edges); plus the `memberOf` root-site normalization as a bespoke invariant check. |
| `integration/__init__.py` | `run_integration_tests(graph_dir) -> int` and `compare_to_zip(graph_dir, zip_path) -> None`: assemble fixtures + SCCM `schema.json` + the shared engine. |
| `main.py` | Two `typer.Option`s on `collect_sccm` in `rich_help_panel="Testing"`; force `run_all=True`; after `_run_e2e_after_collect`, call the wiring. `--run-integration-tests` maps its result to the process exit code; `--compare-to-zip` always returns 0. |

## 4. `--run-integration-tests` behavior

1. Force `run_all=True`; collect → preprocess → convert as today.
2. `load_graph(convert_output_dir)` → `Graph` (A).
3. `run_suite(A, MAYYHEM_EDGE_CASES, MAYYHEM_NODE_CASES, sccm_schema_path)`.
4. Verdict per case (port of the PS logic, extended with `CountSpec`):
   - No `source`/`target`/`properties` constraints → **SKIP** (coverage placeholder).
   - `negative` → **PASS** if 0 matches, else **FAIL**.
   - positive → count matches; satisfy `CountSpec` (`exact`==n, `at_least`>=n, `at_most`<=n; default
     `at_least 1`). **PASS**/**FAIL (wrong count | not found)** with the PS-style failure diagnostics
     (same-kind edges, first mismatch reasons, examples).
   - `NodeCase` → analogous over nodes matched by kinds+properties.
5. Print summary + coverage; write `integration_results-<ts>.json`; **exit non-zero if `failed > 0`**.

## 5. `--compare-to-zip` behavior

`A` = this run's convert output dir; `B` = `load_graph(zip)`. No kind-name normalization — a literal
diff (so comparing against a CMBP zip correctly surfaces the renamed kinds as only-in-A/only-in-B).

- **Matching keys:** nodes by `id`; edges by `(start, kind, end)`.
- **Per-instance diff** (matched nodes/edges): properties **only-in-A**, **only-in-B**,
  **value-differs** (both values shown). Scalars compared exactly; **list-valued properties compared
  order-insensitively (multiset)** so `collectionSource`/`members`/`roleIDs` ordering isn't noise.
- **Membership diff:** nodes/edges **only-in-A** and **only-in-B** (by key).
- **By-kind rollup:** for each node kind and each edge kind, the union of property names seen across
  instances in A vs B → "property `versionCVEs` present on `SCCM_Site` in A but not B" (and reverse).
- **Output:** `ComparisonReport` → grouped console report + `compare_<ts>.json`. **Exit 0.**

## 6. Fixtures

- **Edges:** port every PS `$ExpectedEdges` case (source of truth: the already-renamed
  `sccm/tests/live-comparison/rename_check/Invoke-ConfigManBearPigUnitTests-renamed.ps1`) into
  `EdgeCase`s with stable kebab IDs (e.g. `edge-coerce-mssql-cas`, `edge-localadmin-cas-to-primary`).
  Preserve `Source`/`Target`/`Properties`/`Count`/`Negative`/`Reason`/`Description` intent verbatim.
- **Nodes:** new `NodeCase`s — per-kind existence + count (`SCCM_Site` exact 3, `MSSQL_Server` 3, etc.,
  anchored to the validated mayyhem output; use `at_least` where a value is lab-growth-sensitive), key
  property presence (e.g. `SCCM_Site.siteCode`), and the `memberOf` root-site invariant as a bespoke
  check (all `SCCM_ClientDevice.memberOf` entries end `@<root-site>`), reported as a named result.

## 7. Testing the kit itself

Unit tests with small synthetic graphs (no live data):
- Shared engine tests (in `openhound-collector-common`'s test suite): `graph` (dir + zip, id merge),
  `matcher` (each branch — null/list-subset/wildcard/bool/exact/kind-subset), `runner` verdicts
  (exact/at_least/at_most, negative, skip), `compare` (only-in-A/B, added/removed/changed, list
  order-insensitivity, by-kind rollup), `coverage`.
- SCCM tests (`sccm/sccm/tests/`): fixtures import/shape, IDs unique, every fixture kind exists in a
  schema (SCCM `schema.json` or the MSSQL schema for `MSSQL_*`), and a smoke run of
  `run_integration_tests` / `compare_to_zip` against a tiny fixture graph.

## 8. Docs

- **README:** new **Testing** rows in the CLI options table; a Testing-Changes section documenting
  both flags with copy-pasteable mayyhem examples.
- **ARCHITECTURE.md:** a new section for the `integration_testing` shared subpackage and the
  collect-flag divergence, plus a changelog entry. Note the shared-lib promotion so the MSSQL agent can
  adopt the same engine + add the same flags.
- The PS kit, the renamed copy, and `compare_results.py` remain as reference; the flags supersede them
  for the assert-vs-fixtures and payload-diff workflows.

## 9. Out of scope / deferred

- Env selector (`--integration-env`) — fixtures are a swappable module; add when a second lab exists.
- A `@pytest.mark.integration` wrapper — `runner.py` stays import-clean so this is trivial later.
- Folding `compare_results.py`'s position-aligned CMBP report into the flag — superseded by the
  structural comparator; the old tool stays for historical reports.

## 10. Risks / notes

- **Anchored node counts** track the lab; use `at_least` where exact counts are growth-sensitive, and
  document that count drift means "lab changed", not "collector broke".
- **Node id collisions** across `sccm_`/`ad_` payloads are merged (property union); the loader logs
  them so a genuine collision is visible.
- **`--compare-to-zip` against a CMBP zip** will show the renamed kinds and CMBP's duplicate/scaffolding
  edges as differences — expected and correct (no normalization).
- **Shared-lib blast radius:** the new subpackage is additive (no change to existing shared modules), so
  it cannot affect the MSSQL collector until MSSQL opts in.
