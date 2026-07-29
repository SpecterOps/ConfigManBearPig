# `--dc-only` Flag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--dc-only` recon mode to `collect sccm` that collects only LDAP + DNS from the domain controller and skips all per-host protocol probing.

**Architecture:** `--dc-only` drives two existing levers rather than adding a new collection path: (1) it forces the already-honored `--collection-methods` value to `LDAP,DNS` (so `local_*` self-skips while `ldap_*`/`dns_*` run and the ungated `collection_settings` still fires), and (2) it flips the existing `per_host_expected` gate to `False` so the Stage-2 per-host engine (thread pool, stream bridge, emit resources) never starts. Because the per-host JSONL tables are never written, `--run-all`'s preprocess step must tolerate their absence — which the existing `_safe`/`_ensure_columns` hardening already largely provides; this plan verifies and locks it.

**Tech Stack:** Python 3, Typer (CLI), dlt (collection engine), DuckDB (preproc `transforms`), pytest.

**Ticket:** `Ope-4tdt` — DCOnly Mode (`--dc-only` flag). This plan implements it. (Duplicate `ope-3257` was created then deleted; `Ope-4tdt` is canonical and carries a 2026-07-22 note with the locked decisions.)

## Global Constraints

- **Only modify code under `sccm/sccm/`.** Do not edit `openhound/` core or `openhound-collector-common/`. If a core change seems necessary, STOP and ask Meatbag.
- **No commits.** Each task ends at a **green checkpoint**: run the tests, confirm PASS, then STOP. Meatbag reviews the diff and commits. Never `git add`/`git commit`.
- **Tests live in `sccm/sccm/tests/`.** Run them with the extension venv: from `sccm/sccm/`, `.venv/Scripts/python -m pytest tests/<file> -v`.
- **Log every branch.** Every new `if/else` and `try/except` gets a log line at the right level (error/warning/info/verbose/debug), or a comment explaining why none is needed.
- **README is code-truth.** Documented CLI surface must match the code exactly; fix any stale statement you touch.
- **Prefer readability over cleverness.** Small, focused helpers matching the existing `main.py` style (`_apply_env_overrides`, `_drop_empty_dlt_env_values`, …).
- **No new node/edge properties** are introduced, so the CMBP property-casing rule does not apply here.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `sccm/sccm/src/openhound_sccm/main.py` | CLI command `collect_sccm`, flag→env bridge, stage orchestration | Add `--dc-only` option; add two pure helpers `_resolve_dc_only_methods` and `_should_run_per_host`; wire them into `collect_sccm` |
| `sccm/sccm/tests/dc_only_flag_test.py` | Unit tests for the two helpers | Create |
| `sccm/sccm/tests/transforms_dc_only_test.py` | Integration test: full `transforms()` over a discovery-only DuckDB | Create |
| `sccm/sccm/README.md` | User-facing docs | Add `--dc-only` to CLI table + a Quick Start example + Collection Overview mention; fix stale "not gated by `--collection-methods`" line |
| `sccm/sccm/ARCHITECTURE.md` | Divergence catalogue | Add a DC-only scoping subsection + changelog entry |

---

### Task 1: Add `--dc-only` flag and wire the two behaviors

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (add helpers near `_apply_env_overrides`; add option to `collect_sccm` signature after `site_codes` ~L1081; add resolve call as first body statement, just before `_apply_log_level(verbose, debug, silent)` ~L1141; add info log before the Stage 1 discovery run; change `per_host_expected` ~L1277)

> **Current-code note (verified 2026-07-24, code drifted since planning):** `collect_sccm` is now at ~L1055 (all earlier line refs shifted ~+210). `_apply_log_level` now takes **three** args `(verbose, debug, silent)` — there is a new `--silent` flag. CLI options now carry a `rich_help_panel="..."` argument grouping them in `--help` (`Authentication`/`Collection`/`Performance`/`Output`/`BloodHound Upload`); `--dc-only` MUST use `rich_help_panel="Collection"`. There is also new BloodHound-upload machinery (`-B`, `--skip-collection`, `--upload-dir`, `resolve_credentials`, `upload_mode`) — it does not conflict with `--dc-only` (skip-collection skips collection entirely; dc-only only scopes collection when it runs). **Find every edit site by content, not by the line numbers above.**
- Test: `sccm/sccm/tests/dc_only_flag_test.py`

**Interfaces:**
- Produces:
  - `_resolve_dc_only_methods(dc_only: bool, collection_methods: Optional[str]) -> Optional[str]` — returns `collection_methods` unchanged when `dc_only` is False; returns `"LDAP,DNS"` when `dc_only` is True and `collection_methods` is None; raises `typer.BadParameter` when both are set.
  - `_should_run_per_host(ctx, phases, dc_only: bool) -> bool` — `True` only when `ctx` is not None, `phases` is truthy, and `dc_only` is False.
- Consumes: `typer` (already imported at `main.py:15`); `PER_HOST_PHASES` (already imported inside `collect_sccm`).

- [ ] **Step 1: Write the failing tests**

Create `sccm/sccm/tests/dc_only_flag_test.py`:

```python
"""Unit tests for the --dc-only recon-mode helpers in main.py."""
import pytest
import typer

from openhound_sccm.main import _resolve_dc_only_methods, _should_run_per_host
from openhound_sccm.per_host_phases import PER_HOST_PHASES


def test_dc_only_forces_ldap_dns():
    # --dc-only with no explicit -m forces the LDAP+DNS method set.
    assert _resolve_dc_only_methods(True, None) == "LDAP,DNS"


def test_dc_only_conflicts_with_explicit_methods():
    # --dc-only and -m together is a contradiction: fail fast.
    with pytest.raises(typer.BadParameter):
        _resolve_dc_only_methods(True, "AdminService")
    with pytest.raises(typer.BadParameter):
        # Even an -m that happens to match is still an explicit contradiction.
        _resolve_dc_only_methods(True, "LDAP,DNS")


def test_without_dc_only_passes_methods_through():
    # Normal runs are untouched, including the unset (None -> defaults later) case.
    assert _resolve_dc_only_methods(False, "LDAP,SMB") == "LDAP,SMB"
    assert _resolve_dc_only_methods(False, None) is None


class _StubCtx:
    """Minimal stand-in for the per-host SourceContext."""


def test_per_host_skipped_in_dc_only():
    # dc-only mode never runs Stage 2, even with a valid ctx and phases.
    assert _should_run_per_host(_StubCtx(), PER_HOST_PHASES, dc_only=True) is False


def test_per_host_runs_normally():
    assert _should_run_per_host(_StubCtx(), PER_HOST_PHASES, dc_only=False) is True


def test_per_host_skipped_when_no_ctx_or_phases():
    assert _should_run_per_host(None, PER_HOST_PHASES, dc_only=False) is False
    assert _should_run_per_host(_StubCtx(), (), dc_only=False) is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (from `sccm/sccm/`): `.venv/Scripts/python -m pytest tests/dc_only_flag_test.py -v`
Expected: FAIL with `ImportError: cannot import name '_resolve_dc_only_methods'` (and `_should_run_per_host`).

- [ ] **Step 3: Add the two helpers**

In `main.py`, next to the other flag/orchestration helpers (immediately after `_apply_env_overrides`, ~L248), add:

```python
def _resolve_dc_only_methods(dc_only: bool, collection_methods: Optional[str]) -> Optional[str]:
    """Resolve the effective --collection-methods for a run, honoring --dc-only.

    --dc-only is a recon mode: collect only LDAP + DNS from the domain controller
    and skip every per-host phase. It forces the method set to "LDAP,DNS". Because
    both flags decide *what* gets collected, passing them together is a
    contradiction we reject up front rather than silently pick a winner.
    """
    if not dc_only:
        # Normal run: leave the operator's -m (or None -> "All" later) untouched.
        return collection_methods
    if collection_methods is not None:
        # Explicit -m alongside --dc-only: the operator asked for two different scopes.
        raise typer.BadParameter(
            "--dc-only and -m/--collection-methods are mutually exclusive; "
            "--dc-only already restricts collection to LDAP + DNS."
        )
    return "LDAP,DNS"


def _should_run_per_host(ctx, phases, dc_only: bool) -> bool:
    """Whether Stage 2 (per-host probing) runs this collect.

    It runs only when discovery produced a usable context and there are phases to
    run — and never in --dc-only recon mode, which stops after LDAP + DNS discovery
    against the domain controller.
    """
    return bool(ctx is not None and phases) and not dc_only
```

- [ ] **Step 4: Add the `--dc-only` option to the `collect_sccm` signature**

In `collect_sccm`, in the `# ---- Collection ----` group, immediately after the `site_codes` option (~L1081), add (note `rich_help_panel="Collection"` to match the sibling options):

```python
    dc_only: bool = typer.Option(
        False, "--dc-only", rich_help_panel="Collection",
        help="Recon mode: collect only LDAP + DNS from the domain controller and "
             "skip all per-host probing (RemoteRegistry/MSSQL/AdminService/WMI/HTTP/SMB). "
             "Maps the SCCM attack surface from AD without touching any site system or "
             "client. Mutually exclusive with -m/--collection-methods.",
    ),
```

- [ ] **Step 5: Resolve `--dc-only` at the very top of the body (fail-fast + force methods)**

Make the resolve the **first statement** of `collect_sccm`, before `_apply_log_level(verbose, debug, silent)` (~L1141), so a conflict fails before any log file is opened and the forced value flows through the later `flag_kwargs = locals()`:

```python
    # --dc-only forces LDAP+DNS and skips per-host probing. Resolve it first so a
    # conflict with -m fails fast, and so the forced method set is picked up by the
    # locals()->flag_kwargs->env bridge below (it maps to SOURCES__SCCM__COLLECTION_METHODS).
    collection_methods = _resolve_dc_only_methods(dc_only, collection_methods)
    _apply_log_level(verbose, debug, silent)
```

(No `_FLAG_TO_ENV` entry is needed for `dc_only` — it is pure CLI orchestration, consumed only here.)

- [ ] **Step 6: Announce the mode and skip Stage 2**

(a) Just before the `# Stage 1 — discovery` comment (inside the `with socks_proxy_installed(...)` block, after `_require_domain_or_explain`), add:

```python
            if dc_only:
                logger.info(
                    "DC-only mode: collecting LDAP + DNS from the domain controller; "
                    "per-host collection skipped."
                )
```

(b) Replace the `per_host_expected` assignment (~L1277) with the helper:

```python
            per_host_expected = _should_run_per_host(per_host_ctx, PER_HOST_PHASES, dc_only)
```

- [ ] **Step 7: Run the tests to verify they pass**

Run (from `sccm/sccm/`): `.venv/Scripts/python -m pytest tests/dc_only_flag_test.py -v`
Expected: PASS (6 tests).

- [ ] **Step 8: Guard against regressing the existing CLI wiring**

Run the existing flag/method tests to confirm nothing broke:
Run: `.venv/Scripts/python -m pytest tests/test_http_cli_flags.py tests/test_extension_methods.py -v`
Expected: PASS.

- [ ] **Step 9: Green checkpoint**

Confirm Steps 7–8 PASS. STOP. Do not commit. Meatbag reviews the diff and commits.

---

### Task 2: Verify & lock `--run-all` tolerance of absent per-host tables

**Files:**
- Test: `sccm/sccm/tests/transforms_dc_only_test.py`
- Modify (only if the test reveals an unguarded read): `sccm/sccm/src/openhound_sccm/transforms.py`

**Interfaces:**
- Consumes: `openhound_sccm.transforms.transforms(con, schema="sccm")` (entry at `transforms.py:3275`), the existing `_safe`/`safe_execute` (missing-table → log-and-continue) and `_ensure_columns` (missing-column → add as NULL) hardening.

- [ ] **Step 1: Write the integration test**

Create `sccm/sccm/tests/transforms_dc_only_test.py`:

```python
"""--dc-only produces a DuckDB with only the discovery tables (ldap_*/dns_*/
collection_settings) and NONE of the per-host tables (adminservice_*, wmi_*,
smb_*, remoteregistry_*, mssql_server_instances). The full preproc transforms()
must run over that shape without raising and still emit the LDAP/DNS-discovered
entities (SharpHound-DCOnly value proposition)."""
import duckdb

from openhound_sccm.transforms import transforms


def _discovery_only_db():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("INSTALL json; LOAD json;")
    # An LDAP-discovered computer carrying the CmRcService SPN.
    con.execute("CREATE TABLE sccm.ldap_cmrc_devices (object_sid VARCHAR, name VARCHAR)")
    con.execute(
        "INSERT INTO sccm.ldap_cmrc_devices VALUES "
        "('S-1-5-21-1-2-3-1104', 'HOST1.mayyhem.com')"
    )
    # collection_settings is ungated, so it is written even in --dc-only mode.
    con.execute("CREATE TABLE sccm.collection_settings (disable_possible_edges BOOLEAN)")
    con.execute("INSERT INTO sccm.collection_settings VALUES (false)")
    return con


def test_transforms_over_dc_only_db_does_not_raise():
    con = _discovery_only_db()
    # Must complete despite every per-host table being absent.
    transforms(con, "sccm")
    con.close()


def test_transforms_over_dc_only_db_emits_discovered_host():
    con = _discovery_only_db()
    transforms(con, "sccm")
    sids = [r[0] for r in con.execute("SELECT sid FROM sccm.node_computer").fetchall()]
    con.close()
    assert "S-1-5-21-1-2-3-1104" in sids, sids
```

- [ ] **Step 2: Run the test**

Run (from `sccm/sccm/`): `.venv/Scripts/python -m pytest tests/transforms_dc_only_test.py -v`

Two outcomes:
- **PASS** → the existing `_safe`/`_ensure_columns` hardening already covers the discovery-only shape. The test now locks that as a regression guard. Skip Step 3.
- **FAIL with `duckdb.CatalogException` / `BinderException`** → the traceback names an unguarded read of a per-host table (a `con.execute(...).fetchall()`/`.fetchone()` NOT routed through `_safe`, or a coalesce missing an `_ensure_columns` guard). Proceed to Step 3.

- [ ] **Step 3 (only if Step 2 failed): Wrap the unguarded read**

For a raw catalog read that must tolerate a missing table, mirror the existing `_read_disable_possible` pattern (`transforms.py:1312-1320`):

```python
    try:
        rows = con.execute(f"SELECT ... FROM {schema}.<offending_table>").fetchall()
    except duckdb.CatalogException:
        # Absent in --dc-only collections (per-host table never written); treat as empty.
        logger.info("%s absent; skipping <builder> (dc-only or unreached hosts)", "<offending_table>")
        rows = []
```

For a coalesce SELECT that fails to bind because a source column is missing, add an `_ensure_columns(con, schema, "<table>", {...})` call before the insert, exactly as `_node_site`/`_node_computer` already do. Re-run Step 2 until PASS.

- [ ] **Step 4: Confirm no regression in the existing transforms hardening suite**

Run: `.venv/Scripts/python -m pytest tests/transforms_hardening_test.py tests/transforms_safe_fallback_test.py tests/transforms_test.py -v`
Expected: PASS.

- [ ] **Step 5: Green checkpoint**

Confirm Steps 2/4 PASS. STOP. Do not commit. Meatbag reviews the diff and commits.

---

### Task 3: Documentation (README + ARCHITECTURE)

**Files:**
- Modify: `sccm/sccm/README.md`
- Modify: `sccm/sccm/ARCHITECTURE.md`

- [ ] **Step 1: Add `--dc-only` to the README CLI options table**

In `README.md`, in the Command Line Options table, immediately after the `-m`, `--collection-methods` row (~L346), add:

```markdown
| `--dc-only` | Recon mode: collect only LDAP + DNS from the domain controller and skip all per-host probing. Mutually exclusive with `-m`/`--collection-methods`. |
```

- [ ] **Step 2: Add a Quick Start example**

In the Quick Start section, add a copy-pasteable lab example:

```markdown
**DC-only recon (map SCCM from AD without touching any host):**

```bash
openhound collect sccm -d mayyhem.com --dc-only --run-all ./out
```

Collects only LDAP + DNS from the domain controller, then preprocesses and converts
the discovery data into an OpenGraph (sites, management points, discovered computers,
and LDAP-sourced edges such as GenericAll on the System Management container).
```

- [ ] **Step 3: Mention it in Collection Overview and fix the stale gating line**

In the Collection Overview section, fix the stale sentence (~L194) that reads:

> These resources run a single time per collection and seed the per-host work queue. They are not gated by `--collection-methods` in the current build.

Replace with (code-true — `ldap.py`/`dns.py`/`local.py` all call `method_enabled`):

```markdown
These resources run a single time per collection and seed the per-host work queue.
Each is gated by `--collection-methods` (`LDAP`, `DNS`, `Local`), so `--dc-only`
(which forces `LDAP,DNS`) runs LDAP and DNS discovery while skipping local collection
and every per-host phase.
```

- [ ] **Step 4: Add the ARCHITECTURE scoping note**

In `ARCHITECTURE.md`, under §4 (Targeted collection: an include-only allow-list), append a subsection:

```markdown
### DC-only recon mode (`--dc-only`)

`--dc-only` is a second, coarser scoping control layered on the same machinery. It
does two things: (1) forces `--collection-methods` to `LDAP,DNS` so the discovery
resources self-gate (`local_*` skips; `collection_settings` still fires because it is
ungated), and (2) flips the `per_host_expected` gate off so Stage 2 — the per-host
engine, stream bridge, and emit resources — never starts. The result is a full map of
the SCCM attack surface derived from the domain controller (AD directory + DNS) with
zero connections to any site system or client. `--dc-only` and `-m/--collection-methods`
are mutually exclusive (`_resolve_dc_only_methods` in `main.py`).
```

- [ ] **Step 5: Add a changelog entry**

Append to the ARCHITECTURE.md Changelog section, matching the existing dated-entry format:

```markdown
- **2026-07-22 (Ope-4tdt):** Added `--dc-only` recon mode — forces `LDAP,DNS` and
  skips the Stage-2 per-host pass (§4). No new divergence category; it reuses the
  `--collection-methods` gate and the `per_host_expected` Stage-2 gate.
```

- [ ] **Step 6: Green checkpoint**

Re-read the changed README/ARCHITECTURE sections and confirm they match the code from Tasks 1–2 (especially: the flag name, the mutual-exclusivity, and the fixed gating line). STOP. Do not commit. Meatbag reviews and commits.

---

### Task 4: Full validation

**Files:** none (validation only).

- [ ] **Step 1: Read the extension validation checklist**

Read `sccm/sccm/.agents/skills/openhound/references/validate-extension.md` and follow its checks for a collection-behavior change.

- [ ] **Step 2: Run the targeted offline suite for this change**

Run (from `sccm/sccm/`):
`.venv/Scripts/python -m pytest tests/dc_only_flag_test.py tests/transforms_dc_only_test.py tests/test_http_cli_flags.py tests/test_extension_methods.py tests/transforms_hardening_test.py -v`
Expected: ALL PASS.

- [ ] **Step 3: Live smoke test (lab, if reachable)**

Per the lab notes, `ps1-sms` / `dc.mayyhem.com` are often powered off — check reachability first. When up, run:
`openhound collect sccm -d mayyhem.com --dc-only --run-all ./out-dconly`
Confirm from the collect log:
- LDAP and DNS resources ran; the "DC-only mode:" info line appears.
- No per-host phase ran (no `[<host>][AdminService|WMI|HTTP|SMB|...]` lines; summary shows no per-host section).
- `--run-all` completed preprocess + convert with no `CatalogException`, emitting graph files under `./out-dconly/graph/`.

- [ ] **Step 4: Negative check**

Run `openhound collect sccm -d mayyhem.com --dc-only -m AdminService ./out` and confirm it exits immediately with the mutual-exclusivity `BadParameter` message and performs no collection.

- [ ] **Step 5: Final green checkpoint + ticket close**

Confirm Steps 2/4 PASS (and Step 3 if the lab was reachable). STOP. Report results to Meatbag. On his confirmation: `gtk close Ope-4tdt` and update `TICKETS-BY-STATUS.md` (move Ope-4tdt from Open to Closed, bump counts). Meatbag commits.

---

## Self-Review

**Spec coverage** (against the four locked decisions in `Ope-4tdt`'s 2026-07-22 note):
1. *Alias + skip Stage 2* → Task 1 Steps 5 (force `LDAP,DNS`) and 6b (`per_host_expected` off). ✅
2. *Mutually exclusive with `-m`* → Task 1 Step 3 (`_resolve_dc_only_methods` raises) + Task 4 Step 4 (live negative check). ✅
3. *`--run-all` compatible; harden preprocess* → Task 2 (verify + wrap if needed) + Task 4 Step 3 (live `--run-all`). ✅
4. *Graph includes discovered hosts* → Task 2 Step 1 `test_transforms_over_dc_only_db_emits_discovered_host` + Task 4 Step 3. ✅
- *Docs (README code-truth + stale-line fix, ARCHITECTURE)* → Task 3. ✅

**Placeholder scan:** every code step shows complete code; every command shows expected output. Task 2 Step 3 is conditional on a real traceback (not a placeholder) and gives the exact pattern to apply. ✅

**Type consistency:** `_resolve_dc_only_methods(dc_only, collection_methods)` and `_should_run_per_host(ctx, phases, dc_only)` signatures are identical in the Interfaces block, the test file, and the implementation. `transforms(con, schema="sccm")` matches `transforms.py:3275`. ✅
