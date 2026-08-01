# Design: payload comparison as a first-class gate (`openhound-compare`, regression exit codes, privilege auto-detection)

**Date:** 2026-07-31 · **Status:** design (approved for planning) · **Driver:** SCCM extension, with the
comparison engine and its new CLI promoted into `openhound-collector-common`.

## 1. Goal

Make "did my change lose anything?" a question the tooling answers by itself, at both privilege levels,
without an operator remembering a flag. Four changes:

- **`openhound-compare BASELINE CANDIDATE`** — a standalone console script in the shared library that
  diffs any two OpenGraph payloads (zip or directory, in any combination) with no collection involved.
- **Regression is a failure by default.** Both the new command and the existing `--compare-to-zip` flag
  exit non-zero when the candidate has *less* than the baseline. No opt-out.
- **`--run-integration-tests` detects its own privilege level** from AdminService/WMI row counts, so a
  low-privilege collection stops reporting false failures for behaving correctly.
- **`dev/ab_matrix.py`** — the PowerShell live-comparison drivers, ported to Python, parameterized, and
  moved into this repository.

## 2. Why (gaps this addresses)

- **Comparison is welded to collection.** `--compare-to-zip` only exists as a flag on `collect sccm`, so
  diffing two payloads already on disk requires a live collection that serves no purpose.
  `parity_props_check/_compare.py` in the OpenHound monorepo is a hand-rolled local reimplementation of
  the missing entry point — evidence the gap is real.
- **A drift report cannot gate anything.** `compare_to_zip` always returns 0 by design, so the pass
  condition the 2026-07-28 privileged re-validation actually used — *"edge kinds that lost rows: 0"* —
  was checked by a human reading a summary.
- **The privilege level must be declared by hand, and a forgotten flag fails silently in the wrong
  direction.** `--integration-lowpriv` (ticket `con-6677`, landed 2026-07-31) made the low-privilege
  partition reachable, but nothing detects which mode a run needs. Omitting it on a low-privilege
  collection asserts Tier-D cases that could never have been collected, and the run reports failures
  for behaving correctly. There is also no way to force the full set when detection would say
  otherwise — the partial-privilege case.
- **`A` and `B` are not self-describing.** The report keys `only_in_a` / `only_in_b` require knowing the
  call-site argument order to interpret. This has already caused one misreading during design.
- **The drivers are unrunnable by anyone else** — absolute paths to one desktop, a literal password in
  source, a stale note about a packaging migration that has since landed, and they live in a repository
  the collector no longer belongs to.

## 3. Orientation and vocabulary (decision D1)

`compare_graphs(baseline, candidate)`. **Baseline is what came first**; candidate is what is being
compared against it. A regression is something present in the baseline and missing or reduced in the
candidate.

The existing single call site in `compare_to_zip` passes the fresh run first and the zip second, so it
swaps its two lines: the zip *is* the thing that came first.

Report keys are renamed rather than reused, because a flipped meaning under an unchanged name produces
artifacts that are silently backwards — a reader gets a confident, well-formed answer that happens to be
inverted. Renaming turns that into a `KeyError` for anything reading the old shape:

| Current | New |
|---|---|
| `nodes_only_in_a` / `nodes_only_in_b` | `nodes_only_in_candidate` / `nodes_only_in_baseline` |
| `edges_only_in_a` / `edges_only_in_b` | `edges_only_in_candidate` / `edges_only_in_baseline` |
| `PropDiff.only_in_a` / `.only_in_b` | `PropDiff.only_in_candidate` / `.only_in_baseline` |
| `changed: {prop: [a, b]}` | `changed: {prop: {baseline: …, candidate: …}}` |
| rollup `{only_a, only_b}` | rollup `{only_in_candidate, only_in_baseline}` |

Pre-existing artifacts (`compare_vs_cmbp.json`, `parity_props_check/compare_report.json`, the
`SUMMARY.md` writeups in the OpenHound monorepo) keep the `_a`/`_b` keys and are thereby
self-evidently the old format. They are historical evidence and are not rewritten.

## 4. What counts as a regression (decision D2)

Per-instance strictness, drops only. Additions never fail; they are reported loudly so nothing lands
unnoticed.

**Fails (exit 1):**

| Rule | Example |
|---|---|
| Node `id` in baseline, absent from candidate | `PS1SRV.mayyhem.com` gone |
| Edge `(start, kind, end)` in baseline, absent from candidate | `CAS\|SCCM_AdminsReplicatedTo\|PS1` gone |
| Matched instance lost a property | `only_in_baseline` non-empty for that instance |
| Property went populated → empty | `userName: "MAYYHEM\\bob"` → `null` / `""` / `[]` / `{}` |
| List-valued property shrank to a strict subset | `collectionSource: ["LDAP","HTTP"]` → `["LDAP"]` |
| Property name vanished from a kind | `SCCM_Site.versionCVEs` on no instance in the candidate |

**Passes (exit 0), reported under `ADDED`:** anything only in the candidate, any property new to an
instance or kind, and any other value change (`siteCode "PS1"` → `"CAS"`).

The list-subset rule is deliberate: a shrinking `collectionSource` is neither a missing property nor a
null, but it is lost provenance, and per-instance strictness is meaningless if it ignores content
disappearing from inside a property.

## 5. No opt-out, including cross-tool (decision D3)

The gate applies on both surfaces with no flag to disable it. A comparison finding drops exits non-zero
regardless of whether the two payloads came from the same tool.

The consequence is accepted and must be documented rather than worked around: a CMBP-vs-OpenHound
parity diff **will** exit non-zero on a healthy run, because CMBP emits nodes and kinds OpenHound does
not (160 nodes / 468 edges vs 148 / 454 on the same lab, same day, per `privileged_check/SUMMARY.md`),
uses the pre-rename edge names, and carries 34 `seed_data.json` self-loops on a node named `IgnoreMe`.

This fits existing practice: `run-openhound-both.ps1` already captures a non-zero exit from
`--run-integration-tests` without aborting, on the reasoning that a low-privilege run is *expected* to
fail cases. The exit code means "there are differences," and the operator reads the report.

Automatic same-tool detection was considered and rejected. CMBP payloads declare
`"metadata": {"source_kind": "SCCM_Base"}`; none of OpenHound's four emitted files
(`sccm_nodes-*.json`, `sccm_edges-*.json`, `ad_nodes-*.json`, `ad_edges-*.json`) carry a metadata block
at all. There is no dependable marker, and a heuristic that guesses wrong would silently skip the gate
on a real regression.

## 6. `openhound-compare` (decision D4)

The shared library gains its first `[project.scripts]` entry point. `openhound compare` as a subcommand
of the framework binary is **not** available: `openhound/main.py` builds the root Typer app via
`TyperOverride(...)`, whose `__init__` calls `CollectorManager.from_entrypoint()` → `extension.load()`.
Extensions are therefore imported *during* construction of `app`, before the name is bound, so an
extension cannot `add_typer` a new verb. Adding one means editing OpenHound core, which `CLAUDE.md`
places off-limits.

```
openhound-compare BASELINE CANDIDATE [--json PATH] [-q]
```

Both positionals accept a `.zip` or a directory; `load_graph` already branches on both and raises for
anything else. Exit 1 on regression, 0 otherwise.

`argparse`, not Typer: the library declares no CLI dependency today, and two positionals plus two flags
do not justify imposing one on every collector that installs it. The module stays thin — parsing and
exit code only — so the verdict logic is unit-testable without spawning a subprocess.

## 7. Privilege auto-detection (decision D5)

`--run-integration-tests` derives its privilege level from **collection evidence, not graph content**.
Inferring from the graph is circular: a broken privileged builder emits nothing, reads as
"low privilege," and skips precisely the cases that would have caught the breakage.

Inside `collect_sccm`, `discovery_counts` and `per_host_counts` are already both in scope and merged for
the collect summary. The verdict is:

```python
privileged = any(rows > 0 for table, rows in counts.items()
                 if table.startswith(("adminservice_", "wmi_")))
```

Prefix match, never substring: `local_wmi_sms_authority` and `local_wmi_ccm_client` are discovery
resources reading local WMI on the collector host and must not count as privileged collection.

`--integration-privilege auto|high|low` **replaces** the boolean `--integration-lowpriv` that landed
2026-07-31 under ticket `con-6677`. The three-way form is a strict superset: `low` reproduces the
boolean exactly, `high` forces the full set, and `auto` — the default — detects. Replacing rather than
supplementing avoids two flags for one concept; con-6677's acceptance criteria ("a CLI flag selects
low-privilege fixture mode, main.py passes it through, `--help` documents it, README documents it, and
a test proves the flag reaches `run_integration_tests`") remain satisfied by the superseding flag.

`high` exists for partial privilege: AdminService reaching one site but not another reads as privileged
under "any rows," and an operator who knows the collection was effectively unprivileged needs to say so.
`auto` logs its verdict and the evidence behind it at INFO.

`run_integration_tests(privileged=...)` keeps its signature, so the in-process calls documented in the
low-privilege plan continue to work unchanged. The intermediate helper `_run_integration_suite` changes
its `lowpriv: bool` parameter to `privileged: bool`, matching the function it delegates to and removing
the double negative at the call site.

**This does not by itself make a low-privilege run green, and must not be described as if it does.**
Ticket `con-6677` measured a real low-privilege lab graph at 29 pass / 43 fail / 1 skip in privileged
mode and 28 pass / 36 fail / 1 skip in low-privilege mode — the partition skips only 5 edge and 3 node
cases. Ticket `con-c542` measured 34 privilege-dependent cases against 8 tagged. Auto-detection removes
the "operator forgot the flag" failure mode and nothing else; closing the remaining 36 failures is
`con-c542`'s tagging audit, with `con-907c` rebaselining expected values on the full lab. This work
depends on neither and must not absorb either.

## 8. Exit codes (decision D6)

`--compare-to-zip` runs first, then `--run-integration-tests`; both always run so both reports are
produced. The process exits non-zero if **either** fails, and the log states which. This supersedes
the `2026-07-22` design's rule that the exit code reflects the integration tests alone, and it changes
`--compare-to-zip`'s documented always-zero contract.

## 9. `dev/ab_matrix.py` (decision D7)

The four PowerShell drivers become one parameterized Python script in `dev/`, matching that directory's
existing convention (every script there is already Python) and its rule that credentials come from the
environment, never from source.

Default run is **4 cells** — two identities × both possible-edge states — new collector only, each cell
compared against `baselines/<identity>-<flag>.zip`. `--with-cmbp` adds the **8-cell** parity matrix:
subprocess to `powershell_deprecated/ConfigManBearPig.ps1` plus the `runas /netonly` identity shim,
both confined to one module so the common path never imports them.

`--clean` is passed on every cell and the script refuses to run into a non-empty output directory.
Re-running into a used directory does not overwrite raw data — dlt appends a load package and
preprocess reads every `.jsonl.gz` per table, so the previous run's rows are unioned into this run's
graph. Measured 2026-07-28: 11 of 24 raw tables held rows from two different dates, with exit code 0
and fresh graph timestamps hiding it completely.

The parity half is retained rather than dropped because side-by-side comparison against the deprecated
PowerShell tool is still wanted occasionally, e.g. to settle a reported behavior difference.

## 10. Cross-repo sequencing

The shared library releases on its own git tag (`hatch-vcs`), and this repository's CI checks out this
repository alone and resolves the library from PyPI. So CMBP's changes cannot go green until a library
version carrying them is published:

1. Land the shared-library changes.
2. Tag and release `v0.1.2` — **Meatbag's action**, not the implementer's.
3. Raise this repo's floor to `openhound-collector-common>=0.1.2,<0.2.0`. The cap is unchanged.
4. Land the CMBP changes.
5. Documentation last, so the README describes shipped behavior rather than intent.

`v0.1.2` is a patch despite renaming the report keys, by owner decision. Defensible here: the library is
0.x and makes no API-stability promise (stated in its own dependency comment), and its only consumers
are these two collectors.

Local development uses the sibling-checkout editable redirect the README already documents, so steps 1
and 4 can be written together even though they merge in order.

## 11. Testing

Test-driven throughout. Everything below is offline — no lab, no live AdminService, no cached DuckDB.

**Shared library** (CI runs the whole `tests` directory, so new files are picked up automatically):
orientation; every renamed key; each regression rule and each explicit non-rule; `cli.py` exit codes
driven through `main([...])` rather than a subprocess.

**CMBP** (CI runs a curated list — new files must be added to both `.github/workflows/ci.yml` and the
matching README command, which are required to stay in sync): the privilege detection truth table
including the `local_wmi_` trap; `--integration-privilege` at all three values; exit-code composition
when both testing flags are set; `ab_matrix` cell planning and `--clean` enforcement, without running a
collection.

## 12. Docs

- **README** — a **Before and after a change** subsection under Testing Changes; updated Testing option
  rows; the amended exit-code contract; and the CMBP example carrying its now-expected non-zero exit
  with a sentence explaining why.
- **ARCHITECTURE.md** — a section for the comparison-gate divergence plus a changelog entry.
- **Shared library README** — the new console script.

## 13. Risks and notes

- **A patch release changes an output format.** Anything parsing `compare-<ts>.json` by the `_a`/`_b`
  keys breaks on upgrade. Only the two ad-hoc scripts in the OpenHound monorepo do, and they are not
  upgraded by this work.
- **Per-instance strictness against two live collections will fail on lab churn** — a decommissioned
  host, an ended session. The reliable before/after remains reprocessing one frozen raw bucket with old
  and new code, where the only variable is the diff. The README subsection must say so plainly.
- **The privileged verdict is only auto-derived on the collect path.** A call against a saved graph
  directory has no row counts to read and still passes `privileged=` explicitly.
- **`--with-cmbp` is Windows-only**, carrying `runas /netonly` and a PowerShell subprocess. The 4-cell
  default has neither.
- **Removing `--integration-lowpriv` touches docs written hours earlier.** The README's Testing table
  row, its "Which mode matches your run?" callout, and both worked examples all name the boolean and
  must move to `--integration-privilege low` in the same change, or the README describes a flag that no
  longer exists. `con-6677` should be annotated to record that the three-way flag supersedes it rather
  than closed as if unrelated.
- **Concurrent fixture work.** `con-c542` (tagging audit) and `con-907c` (rebaseline on the full lab)
  both edit `integration/fixtures/`. This work edits `integration/__init__.py` and `main.py` and does
  not touch the fixture case lists, so the three can proceed in parallel — but a merge that renames
  `requires_privilege` would break the filter in `run_integration_tests`, so that field name is fixed
  for the duration.
