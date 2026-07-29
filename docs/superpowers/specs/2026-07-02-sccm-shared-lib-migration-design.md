# SCCM → `openhound-collector-common` Migration — Design Spec & Staged Roadmap

> **Status:** design/decisions locked (2026-07-02). Per-stage bite-sized TDD plans are
> authored just-in-time under `docs/superpowers/plans/` at execution time, once the merge
> (Phase 0a) has put the shared lib on the branch. This document is the master contract.

**Goal:** Make the SCCM extension consume the shared `openhound-collector-common` library for
the generic collector infrastructure the MSSQL extension already proved, delete SCCM's
duplicated copies, and complete the shared library so both extensions build and run from one
codebase — without changing SCCM's observable behavior (graph output, EPA labels, LDAP
ordering, log lines).

**Architecture:** One repo, one checkout. Both `sccm/sccm` and `mssql/mssql` depend on
`openhound-collector-common` via an *editable local path dependency*
(`../../openhound-collector-common`). The shared library holds only **stable, generic,
hard-to-get-right infrastructure**; each extension's **volatile, extension-specific glue**
stays local. Where SCCM needs more than a shared module offers, SCCM keeps a *thin local layer*
that re-exports the shared core and adds the SCCM-specific pieces.

**Tech Stack:** Python 3.13–3.14, `uv` (editable path deps), `hatchling`, `dlt`, `duckdb`,
`impacket`, `ldap3`, `pywin32`/`winkerberos` (Windows auth), `pytest`, `ruff`, `mypy`.

## Global Constraints

- **No commits by the agent.** Work runs under the SDD no-commit harness: green checkpoints
  only; the user commits. Per-task diffs/briefs/reports live in gitignored `sccm/sccm/.sdd/`.
- **SCCM agents modify only `sccm/sccm/`.** The shared library is a **read-only contract** to
  extension agents — see Governance. The two shared-lib touches this migration requires
  (recreating `graph/`, and any core-vs-local reconciliation) are explicitly user-gated,
  shared-lib-owner tasks, called out per stage.
- **Behavior parity is the bar.** SCCM output and diagnostics stay observably identical.
  Property casing stays ConfigManBearPig.ps1-verbatim; collection step order stays as in the
  PowerShell script.
- **Port every property** on nodes/edges (same casing) so entity panels stay populated.
- **Log every if/else and try/except** at an appropriate level, or leave a comment saying why not.
- **`requires-python = ">=3.13,<3.15"`.** `python-preference = "only-system"` stays (Windows
  OpenSSL Applink shim).
- **Editable path dep:** `openhound-collector-common = { path = "../../openhound-collector-common", editable = true }`.

---

## Locked decisions

- **D1 — Unify by merge into a fresh branch.** `git checkout -b integration ohsccm && git merge
  ohmssql`. Verified conflict-free (`git merge-tree`): ohmssql never touched `sccm/sccm/` after
  the Stage-4 fork, so the merge only adds `mssql/` + `openhound-collector-common/` and keeps
  ohsccm's Stage-7 SCCM and its `src/openhound/main.py` telemetry fix. `ohsccm` and `ohmssql`
  are preserved as safety copies. **The merge is the user's action** (no-commit rule).
- **D2 — Full migration scope.** SCCM adopts *every committed shared module* that maps to an
  SCCM equivalent (Category A/B below). No half-measures deferred to "later" except the two
  explicit declines (D6).
- **D3 — Recreate the missing shared `graph/` package.** The lib's README and its own
  `tests/test_graph.py`, plus mssql's `models/graph_edge.py`, all reference
  `openhound_collector_common.graph.*`, but the package source was never committed — mssql
  currently cannot import. We create `graph/graph_edge.py` (`GraphEdge`, `GraphEdgeProperties`)
  and `graph/stub_node.py` (`StubNode`, `GenericNode`) to satisfy the committed test spec,
  generalizing from SCCM's `models/stub_node.py` / `models/graph_edge.py`. This **unbreaks
  mssql** and becomes SCCM's shared base.
- **D4 — Reconciliation rule (per module).** If the shared module is a *true superset* of
  SCCM's need → adopt directly, delete the SCCM copy. If SCCM needs *more* than the shared
  module offers → SCCM keeps a thin local layer that re-exports the shared core and adds only
  the SCCM-specific extras; delete only the duplicated core.
- **D5 — Guiding principle: share stable infra, keep volatile glue local.** The shared lib =
  auth/TDS/EPA, LDAP/AD, WMI, DNS discovery, duckdb-safe, the graph base. Extension-specific,
  frequently-changing code (convert pipeline, transforms, edge rules, domain models, graph
  schema) stays local. This minimizes how often the two agents collide in shared files.
- **D6 — Declines (stay local in both extensions):**
  - `convert_pipeline.py` — never extracted; the two versions diverge on extension-specific
    features (SCCM: null-pruning, untagged-AD routing, `resource_prefix`; mssql: `edge_emitter`,
    `PROPERTY_KEY_REMAP`). A shared base would carry the leaky union of five knobs over ~130
    lines of stable boilerplate. Not worth it. → follow-up ticket only if a real third consumer
    appears.
  - `proxy/socks.py` — mssql does not exercise the shared dialer (unproven), and SCCM's
    `socks_proxy` handling already works. Leave SCCM's as-is. → follow-up ticket.
- **D7 — Run model: single checkout, one live editable-path lib, read-only governance rule.**
  No worktrees, no versioned wheel. Safety comes from Governance, not isolation.
- **D8 — Validation bar.** Unit tests + ruff + mypy gate *every* stage. Live-auth stages
  (auth, ad, wmi, mssql-EPA) additionally diff their graph output against a Phase-0 baseline in
  the lab, as the three auth identities (current-user SSPI, explicit creds, pass-the-hash).
- **D9 — impacket floor bump.** Adopting the lib raises SCCM's impacket floor `>=0.11.0` →
  `>=0.13.1`. SCCM's per-host phases use impacket internals, so this is a behavior-relevant
  change that must be validated (see Risks).

---

## Module inventory

Line counts are from the branch analysis (2026-07-02). "Shared" = `openhound-collector-common`.

### Category A — Direct adopt (shared is a proven superset; delete the SCCM copy)

| SCCM today | → Shared module | Proven by mssql? | Risk | Validation |
|---|---|---|---|---|
| inline `_safe`/`_ensure_columns`/`_arr` in `transforms.py` | `dlt/duckdb_safe.py` (`safe_execute`, `ensure_columns`, `arr_sql`) | ✅ `ensure_columns`, `safe_execute` | Low | unit |
| bridge parts of `source.py` | `dlt/source_bridge.py` (`StreamBridge`, `extract_workers_for`) | ✅ | Med | unit + collection smoke |
| inline DC/SRV discovery in `clients/ad.py`, `clients/http_auth.py`, `context.py` | `discovery/dns.py` (`make_resolver`, `resolve_dc`) | ✅ | Med | lab smoke |
| `clients/ad.py` (957) | `clients/ad.py` (1062) | ✅ `AdClient`, `LdapAuth` | **High** | lab, 3 users |
| `clients/wmi.py` (359) | `clients/wmi.py` (527) | ✅ `WmiClient`, `WmiAuth` | Med-High | lab |
| `clients/mssql_epa.py` (675, EPA detection subset) | `clients/mssql.py` (1225) EPA detection | ✅ `MssqlConnection`, `parse_target` | Med | lab — **EPA labels must match** |

### Category B — Shared core + thin SCCM local layer (SCCM needs extras)

| SCCM today | Keep local | Adopt from shared |
|---|---|---|
| `log_context.py` (610) | `trace_node/edge/property*`, host/resource-complete callbacks, `per_host_iter`, `per_pair_iter`, `cached_with_log`, `VerboseLogger`/`get_logger` (only `collectors/local.py` + `main.py` use these) | `logging/log_context`: `VERBOSE`, `target_context`, `phase_context`, `LogContextFilter`, `install_filter`, `with_log_context` — re-exported; delete duplicated core |
| `clients/http_auth.py` (357) + `clients/smb_sso.py` (278) | HTTP SPNEGO negotiators (`SspiNegotiator`/`NtlmNegotiator`/`KerberosNegotiator`, `choose_auth`, `http_spn`, `AuthMode`); SMB session-key install (`smb_login_sspi`, `connect_smb`, `_cifs_spn`) | `clients/auth`: `format_hashes`, `split_user_domain`, `split_hashes`, `ntlm_type1/3`, `EMPTY_LM_HASH`, `KerberosToken`, `SspiClient` — delete the duplicated leaf helpers |

### Category C — Recreate-in-lib then adopt

| Item | Action |
|---|---|
| shared `graph/graph_edge.py`, `graph/stub_node.py` | **Create** to the committed `test_graph.py` spec (D3). SCCM's `models/graph_edge.py` + `models/stub_node.py` become thin subclasses (as mssql's already are) — inject SCCM's `traversable_kinds` / `ad_principal_kinds` and override `environment_id_for()` with SCCM's `domain_environment_id`. |

### Category D — Decline (D6): `convert_pipeline.py`, `proxy/socks.py` — stay SCCM-local.

### Category E — Stays SCCM-local (SCCM-specific, no shared equivalent)

`collectors/*` (incl. the ADIDNS `dns.py` collection phase — distinct from `discovery/dns`),
`clients/http.py`, `clients/smb.py`, `phased_pipeline/*`, `per_host_phases.py`, `context.py`,
`graph.py`, `transforms.py` (domain transforms), `models/*` (SCCM domain models), `kinds/*`,
`lookup.py`, `cve_table.py`, `opengraph_untagged.py`, `main.py`, `extension.yaml`.

---

## Governance model (the piece that makes parallel agents safe)

Editable path dep alone means both extensions import the *same live files*; an SCCM-agent edit
to the lib could break the MSSQL agent mid-run. Safety comes from a rule, added as part of this
work:

- **Create `openhound-collector-common/AGENTS.md`** stating: this library is an owned, stable
  contract; extension agents (SCCM, MSSQL) treat it **read-only**; changes are a separate,
  user-gated *shared-lib-owner* task; changes must keep both consumers green; no
  extension-specific concepts leak in (enforces D5).
- **Update root `CLAUDE.md` / `AGENTS.md`** with the third role: alongside "SCCM agents →
  `sccm/sccm/` only" and "MSSQL agents → `mssql/mssql/` only", add "shared-lib changes are
  user-gated and must re-validate both extensions."
- **Update `sccm/sccm/ARCHITECTURE.md`** with a new "Shared-library dependency" section (per the
  cross-cutting-subsystem rule): what SCCM draws from the lib, the read-only rule, and the
  thin-local-layer pattern for `log_context`/auth.

---

## Phased roadmap

Ordered so failure is cheap early (pure-Python, unit-tested) and isolated late (one live-auth
swap at a time). Each phase ends at a green checkpoint (unit + ruff + mypy; live-auth phases add
the lab baseline diff). The user commits at each checkpoint.

### Phase 0 — Foundation (blocking; do first)
- **0a (user):** `git checkout -b integration ohsccm && git merge ohmssql`.
- **0b (shared-lib-owner task):** Create shared `graph/graph_edge.py` + `graph/stub_node.py` +
  `graph/__init__.py` to make `openhound-collector-common/tests/test_graph.py` pass. Unbreaks
  mssql's import.
- **0c:** Add the editable path dep to `sccm/sccm/pyproject.toml`; drop deps now transitive via
  the lib (`ldap3`, `winkerberos`, `pywin32`, `dnspython`, `impacket`, `cryptography`); **keep
  `requests`** (HTTP; not carried by the lib). Add the mypy `win32com` override note if still
  needed.
- **0d:** `uv sync`; run SCCM + mssql + shared-lib unit suites → all green (proves the merged
  tree imports end-to-end).
- **0e (baseline):** Capture a pre-migration SCCM graph-output baseline from a lab run (or the
  most recent known-good output) for the D8 diff. If the lab is down, record the constraint and
  gate live-auth phases on lab availability.
- **Acceptance:** merged tree imports; all three unit suites green; baseline captured or
  explicitly deferred.

### Phase 1 — `duckdb_safe` (Category A, Low)
- SCCM's `transforms.py` imports `safe_execute`/`ensure_columns`/`arr_sql` from
  `openhound_collector_common.dlt.duckdb_safe`; delete the inline copies. Verify semantics match
  SCCM's (esp. the dlt column-dropping / coalesce `BinderException` defenses noted in prior
  work). **Acceptance:** transforms unit tests green; a targeted test proves an all-NULL/absent
  column no longer breaks the coalesce SELECT.

### Phase 2 — `log_context` core + `graph/` base adoption (Category B + C, Low-Med)
- Reduce `sccm/.../log_context.py` to: `from openhound_collector_common.logging.log_context
  import *`-style re-export of the core (`VERBOSE`, contexts, filter, `install_filter`,
  `with_log_context`) + keep SCCM-only `trace_*`, callbacks, iterators, `VerboseLogger`,
  `get_logger`. Confirm `collectors/local.py` and `main.py` still resolve every symbol.
- Repoint SCCM `models/stub_node.py` + `models/graph_edge.py` to subclass the shared `graph`
  base (inject SCCM allow-lists + `environment_id_for`). **Acceptance:** log output byte-compare
  on a sample run unchanged; graph node/edge emit tests unchanged.

### Phase 3 — `source_bridge` (Category A, Med)
- Replace the push→pull emit bridge in `source.py` with `StreamBridge` /
  `extract_workers_for`. Keep SCCM's DLT resource/config wiring local. **Acceptance:** a
  multi-target collection smoke test yields the same per-target resource counts.

### Phase 4 — `discovery/dns` (Category A, Med) — *first live-auth-adjacent*
- Replace SCCM's inline DC/SRV discovery + resolver-override with `make_resolver` / `resolve_dc`
  at the call sites in `clients/ad.py`, `clients/http_auth.py`, `context.py`. Leave the ADIDNS
  `collectors/dns.py` phase untouched (different concern). **Acceptance:** DC discovery resolves
  the same DC in the lab (incl. the `--dc`-is-an-IP path); lab smoke.

### Phase 5 — auth primitives (Category B, Med) — *live-auth*
- `http_auth.py` + `smb_sso.py` import the shared leaf helpers (`format_hashes`,
  `split_user_domain`, `split_hashes`, `ntlm_type1/3`, `EMPTY_LM_HASH`); delete the dupes; keep
  the transport negotiators local. **Acceptance:** HTTP (AdminService) + SMB collection succeed
  as the 3 identities; output diff vs baseline is empty.

### Phase 6 — `clients/ad.py` (Category A, High) — *live-auth*
- Delete SCCM's `clients/ad.py`; repoint imports to `openhound_collector_common.clients.ad`
  (`AdClient`, `LdapAuth`). Verify the lockout-safe transport×bind waterfall and SID→AD-object
  resolution behave identically for SCCM's inputs. **Acceptance:** LDAP phase output diff vs
  baseline empty; no extra bind attempts (lockout-safety preserved), verified in lab as 3 users.

### Phase 7 — `clients/wmi.py` (Category A, Med-High) — *live-auth*
- Delete SCCM's `clients/wmi.py`; repoint to the shared `WmiClient` / `WmiAuth`. Verify
  `Win32_GroupUser` / `Win32_Service` enumeration returns the same objects. **Acceptance:** WMI
  phase output diff vs baseline empty in the lab.

### Phase 8 — `clients/mssql` EPA detection (Category A, Med) — *live-auth*
- Replace SCCM's `mssql_epa.py` EPA-detection usage with the shared `clients/mssql`
  (`MssqlConnection`, `parse_target`, EPA detection). **Preserve the literal "Allowed/Required"
  EPA-uncertainty labeling** SCCM emits (esp. the SSPI case). **Acceptance:** coerce-and-relay
  edges + EPA-label properties diff vs baseline empty in the lab.

### Phase 9 — Cleanup, governance docs, final validation
- Delete any now-dead SCCM code; ensure no lingering duplicate helpers. Write
  `openhound-collector-common/AGENTS.md`; update root `CLAUDE.md`/`AGENTS.md` (third role) and
  `sccm/sccm/ARCHITECTURE.md` (shared-library section). Update `sccm/sccm/README.md` if any
  user-facing behavior/requirements changed (dep list). Run a **full lab collection** and diff
  the whole graph vs the Phase-0 baseline. **Acceptance:** full-graph diff empty; docs updated;
  both extensions' unit suites + ruff + mypy green.

---

## Validation bar (D8)

- **Every phase:** `pytest` (SCCM; shared-lib suite where touched; mssql when a shared change
  could affect it), `ruff`, `mypy` — all green.
- **Live-auth phases (5–8) and Phase 9:** capture/compare the SCCM OpenGraph output against the
  Phase-0 baseline — node count, edge count, all node/edge properties, and EPA labels must be
  **identical** — run as the three identities (current-user SSPI, explicit creds,
  pass-the-hash). Lab connection facts (hosts, KDC, creds) are in the debug harness referenced
  by prior work.

## Risks & mitigations

- **R1 — impacket 0.11→0.13 (D9).** Per-host phases (SMB SSO, WMI, coercion) depend on impacket
  internals. *Mitigation:* Phases 5–8 lab-diff catch behavior shifts; if a regression traces to
  impacket, pin a compatible floor in the lib (shared-lib-owner task) after confirming both
  extensions still pass.
- **R2 — shared `ad`/`wmi`/`mssql` were generalized/extended for mssql.** A generalization may
  change an SCCM-relevant default. *Mitigation:* baseline diff per phase; where behavior differs,
  the fix is a *parameter/subclass in SCCM* or a *shared-lib-owner change* validated against both
  — never a silent behavior change.
- **R3 — lab availability.** The lab is often powered off. *Mitigation:* Phase-0 baseline
  capture; unit-testable phases (1–3) proceed regardless; live-auth phases gate on lab up.
- **R4 — recreated `graph/` must match the committed test spec exactly**, or mssql stays broken.
  *Mitigation:* `test_graph.py` is the acceptance gate for Phase 0b.
- **R5 — governance drift.** Without the AGENTS.md rule, an agent could edit the lib and break
  the other extension. *Mitigation:* Phase 9 codifies the read-only rule before parallel work
  begins in earnest.

## Follow-up tickets (out of scope here)

- Shared SOCKS5 adoption for SCCM (only if a second proven consumer appears).
- Shared `convert_pipeline` base (only if a third consumer justifies the union-of-knobs cost).

## Ticket tracking

Create a `gtk` epic "Migrate SCCM onto openhound-collector-common" with one child ticket per
phase (0–9) and the two follow-ups above, dependency-linked 0 → 1 → … → 9.
