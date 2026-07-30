# ConfigManBearPig Docs Refresh: README.md + ARCHITECTURE.md Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Repository:** This plan applies to the **standalone `ConfigManBearPig` repository** (`C:\Users\domainadmin\Desktop\ConfigManBearPig`, PyPI distribution `configmanbearpig`), **not** the OpenHound monorepo's `sccm/sccm/` copy. All paths below are relative to this repo's root.

**Goal:** Bring `README.md` (primary) and `ARCHITECTURE.md` (secondary) back into agreement with the current code, alphabetize the Node/Edge reference lists, expand every shorthand plan/stage/task reference so it names its source plan, and sort the ARCHITECTURE changelog by date — while preserving the just-added, uncommitted `# Testing Changes` section.

**Architecture (approach):** Documentation-only change — no code, no behavior. Every factual claim is verified against a named code anchor (`src/openhound_sccm/graph.py` for node/edge properties, `src/openhound_sccm/kinds/*.py` for kind names, `src/openhound_sccm/main.py` for the CLI surface, the filesystem for the file tree). README gets a full careful audit; ARCHITECTURE gets only the three requested edits (changelog sort, shorthand-reference expansion, broken-link fixes) — no independent factual re-audit of its prose.

**Tech Stack:** GitHub-Flavored Markdown, Mermaid diagrams. Verification is `grep`/`Grep` assertions, a link-existence check, and a manual render review — there is no test runner for docs.

## Global Constraints

Copied verbatim from this repo's CLAUDE.md / AGENTS.md and the design decisions grilled for this plan. They apply to **every** task.

- **Commit rule (this repo): "Ask before committing each time. Never push."** (CLAUDE.md line 32.) This is *different* from the monorepo's "never commit". Each task ends by surfacing its diff and **asking Meatbag** whether to commit; on approval, commit that task's change; **never push**. Do not batch-commit across tasks without asking.
- **Working tree already carries an uncommitted edit.** `README.md` has an unstaged change adding a new `# Testing Changes` section (setup / shared-library editing / running CI's checks / live validation) plus a `# Contributing` rewrite that points at it. **This plan is written against the working tree (that edit present) — line numbers assume it.** Do not revert or clobber that section; Task R6 reconciles with it, and Tasks R13/V1 verify its new links/anchors without rewriting its content.
- **Code-truth above all.** AGENTS.md: "The README should be true to the code above all else." When prose and code disagree, correct the prose — never change the code to match the docs.
- **Scope is exactly two files:** `README.md` and `ARCHITECTURE.md`. Do not touch code, other docs, `docs/superpowers/plans` or `specs` (the dated records), `.tickets/`, `powershell_deprecated/`, `cypher_queries/`, or the shared library (`openhound-collector-common` is a separate repo — CLAUDE.md line 59).
- **ARCHITECTURE = requested edits only:** (1) sort the changelog, (2) reference key + first-use expansion, (3) fix broken internal/code links. No line-by-line factual re-audit of its 14 sections.
- **Property casing is verbatim CMBP casing** (camelCase/PascalCase), never snake_case — the `*Properties` field names in `graph.py` ARE the output keys. Match them exactly.
- **Alphabetize within namespace group.** Node/Edge reference sections sort A–Z *inside* each of the three groups (AD base kinds, then `SCCM_*`, then `MSSQL_*`), preserving the clustering that matches the Mermaid "clustered overview" and the TOC. Combined-kind headings sort by their first-listed kind. Do **not** alphabetize the property *rows* inside a table (see recommendations).
- **Changelog: newest-first, same-date clusters ordered by dependency/causality.**
- **Reference expansion: reference-key table near the top of each doc + first-use-per-section inline expansion.** Later uses in the same section stay terse.
- **Line numbers here are as of 2026-07-30 (working tree with the Testing Changes edit) and will drift as edits land.** Always re-locate by quoted anchor text, not line number. Apply edits top-of-file to bottom-of-file within each file so drift only pushes later anchors down.
- **Don't refer to a plan/stage/decision by number alone** (CLAUDE.md) — in the docs and in commit messages, restate what it is.
- **`.gitattributes` marks `TICKETS-BY-STATUS.md` as `merge=ours`;** this plan doesn't touch it, but if you open a `gtk` ticket for this work, update `TICKETS-BY-STATUS.md` per CLAUDE.md.

---

## Reference Data (appendix used by Tasks R11 and A2)

The docs use several families of shorthand tokens. This is the authoritative mapping the reference-key tasks transcribe. **The same token string can mean different things** — disambiguating them is the whole point of "include the plan's full name". All plan paths below are confirmed present in this repo under `docs/superpowers/`.

| Token family | Where "defined" (full plan/spec name, repo-relative) | What it means |
|---|---|---|
| **Collection** `Stage 1` / `Stage 2` | `docs/superpowers/plans/2026-06-03-per-host-collection-framework.md` (tour: `docs/per-host-collection-framework-tour.md`) | The two *collection* stages: Stage 1 = once-per-run Discovery (LDAP/Local/DNS); Stage 2 = the per-host phased pipeline. Used in README "Collection Overview" and "Understanding the Codebase". |
| **Pipeline** `Stage 0`–`Stage 7` | The numbered preproc/convert plans `docs/superpowers/plans/2026-06-16-sccm-preproc-convert-stage0.md` … `2026-07-01-sccm-preproc-convert-stage7.md`, under one design spec `docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md` | The incremental port of ConfigManBearPig's post-processing into the DuckDB `preprocess` + `convert` stages (Stage 3 = RBAC fan-out, Stage 4 = host-correlation, Stage 5 = MSSQL, Stage 6 = coerce-and-relay). Used in README intro, Graph Model, and both reference intros. |
| `Stage 3 C2`/`C3`/`C4`/`C5` | `docs/superpowers/plans/2026-06-24-sccm-preproc-convert-stage3.md` + `docs/superpowers/plans/2026-06-24-stage3-property-matrix.md` | Column-parity sub-tasks *within* pipeline Stage 3 (C2 = SecurityRole audit fields, C3 = AdminUser audit fields, C4 = ClientDevice telemetry, C5 = Site SQL identity). Appear in `graph.py` comments; verify whether any leak into README/ARCHITECTURE prose. |
| `D1`–`D6`, `D2a`, `D2b` (low-priv) | `docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md` + spec `docs/superpowers/specs/2026-07-23-low-priv-assumed-edges-design.md` | Locked decisions for the low-privilege assumed-edges work. D2 = which hosts are treated as *the* site DB; D2a = resolving the `MSSQLSvc` SPN holder at low priv; D2b/D3 = the `SPN+SCCM` inference and the `assumed`/`assumptionBasis` provenance stamp; D4 = capabilities-XML-named root; D5 = `site_hierarchy` fed from every site-code source; D6 = per-host site-code attribution. **This is the `D#` family the README's MSSQL node tables (`D2a`, `D2b/D3`) and ARCHITECTURE §11l refer to.** |
| `D1`–`D11` (MSSQL extension) | The *separate MSSQL extension* repo/plan (not present here) | Decisions for a different collector — **out of scope**. Flag any `D#` in these docs that actually points there (there should be none — this is the ambiguity to catch). |
| `Task 1`–`Task 14` | `docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md` | Implementation tasks of the low-priv plan. Tasks 11–14 (Tier A+) added `Container`/`GenericAll`, nested `MemberOf`, and the `MSSQLSvc`-SPN service account. Used in ARCHITECTURE §11k/§11l. |
| `Phase A` / `Phase B` / `Task B3` | `docs/superpowers/plans/2026-07-23-cmbp-parity-node-edge-properties.md` + spec; tickets ope-c141 (Phase A) / ope-fb99 (Phase B) | The CMBP-parity property effort: Phase A = AD-object attribute capture; Phase B = extra `SCCM_Site`/`SCCM_ClientDevice` telemetry props. In ARCHITECTURE §11j and `graph.py` comments. |
| `§N` (e.g. `§7`, `§11h`, `§11l`) | Internal ARCHITECTURE section anchors | Self-navigating in-document links. **Leave as-is**; fix only if a link-check (Task A3) shows the anchor broken. |
| `ope-XXXX` / `Ope-XXXX` | The `gtk` ticket system (`.tickets/<id>.md`) | Ticket ids, not plans. Leave terse; optionally add a ticket title on first mention if cryptic. |

---

## Node Reference — target A–Z-within-group order (Task R9)

- **AD group:** `Computer` · `User` · `Group` · `Container` → **`Computer` · `Container` · `Group` · `User`**
- **SCCM group:** `SCCM_Site` · `SCCM_ClientDevice` · `SCCM_Collection` · `SCCM_AdminUser` · `SCCM_SecurityRole` → **`SCCM_AdminUser` · `SCCM_ClientDevice` · `SCCM_Collection` · `SCCM_SecurityRole` · `SCCM_Site`**
- **MSSQL group:** `MSSQL_Server` · `MSSQL_Database` · `MSSQL_ServerRole` · `MSSQL_DatabaseRole` · `MSSQL_Login` · `MSSQL_DatabaseUser` → **`MSSQL_Database` · `MSSQL_DatabaseRole` · `MSSQL_DatabaseUser` · `MSSQL_Login` · `MSSQL_Server` · `MSSQL_ServerRole`**

## Edge Reference — target A–Z-within-group order (Task R10)

Keep `Entity-panel help properties` first (preamble). Keep the two `Attack path example …` subsections last. Sort the rest A–Z inside each group. The combined heading sorts by its first kind (`SCCM_HasPrimaryUser`).

- **AD-native / base edges:** `GenericAll` · `HasSession` · `MemberOf`
- **SCCM_ edges:** `SCCM_AdminsReplicatedTo` · `SCCM_AllPermissions` · `SCCM_ApplicationAdministrator` · `SCCM_ApplicationAuthor` · `SCCM_AssignAllPermissions` · `SCCM_CoerceAndRelayToAdminService` · `SCCM_CoerceAndRelayToSMB` · `SCCM_ComplianceSettingsManager` · `SCCM_Contains` · `SCCM_FullAdministrator` · `SCCM_HasClient` · `SCCM_HasMember` · `SCCM_HasPrimaryUser / SCCM_HasCurrentUser / SCCM_HasADLastLogonUser` · `SCCM_HasStoredAccount` · `SCCM_IsAssigned` · `SCCM_IsMappedTo` · `SCCM_LocalAdminRequired` · `SCCM_OSDManager` · `SCCM_OperationsAdministrator` · `SCCM_SameHostAs` · `SCCM_SecurityAdministrator`
- **MSSQL_ edges:** `MSSQL_CoerceAndRelayToMSSQL` · `MSSQL_Contains` · `MSSQL_ControlDB` · `MSSQL_ControlServer` · `MSSQL_ExecuteOnHost` · `MSSQL_GetAdminTGS` · `MSSQL_GetTGS` · `MSSQL_HasLogin` · `MSSQL_HostFor` · `MSSQL_IsMappedTo` · `MSSQL_MemberOf` · `MSSQL_ServiceAccountFor`

> Case-insensitive sort on the string *after* the namespace prefix, so `MSSQL_CoerceAndRelayToMSSQL` precedes `MSSQL_Contains` (`Coe` < `Con`) and `SCCM_CoerceAndRelayToSMB` precedes `SCCM_ComplianceSettingsManager` (`Coe` < `Com`).

---

## Interaction with the uncommitted `# Testing Changes` section

- The new `# Testing Changes` section (README ~lines 1823–1982) and its five TOC entries (~lines 89–93) are **yours to keep** — no task rewrites them.
- The new section's `## Validate against a real hierarchy` subsection (~line 1933) documents the `dev/` scripts with correct `dev\…` paths and env-var creds. The **old** `### Debug harnesses (lab use only)` list under `# Understanding the Codebase` (~lines 1809–1815) still uses bare script names, omits two scripts, and predates the `dev/` move. **Task R6 reconciles these two so they don't duplicate or contradict.**
- The `# Contributing` rewrite already points at Testing Changes; no task edits Contributing. Task R13/V1 verify the new links (`[ci.yml](.github/workflows/ci.yml)`, the shared-library GitHub URLs) and the new `#testing-changes` / sub-anchors resolve — **without** altering the new prose.

---

## Task ordering

Do README tasks (R1–R13), then ARCHITECTURE (A1–A3), then final verification (V1). Within README, apply edits top-of-file → bottom-of-file. Task numbers are logical, not positional — follow the anchor text.

---

### Task R1: Fix the Collection Overview ASCII diagram (edges shipped)

**Files:**
- Modify: `README.md` — the fenced `text` diagram under `# Collection Overview` (anchor: the block containing `Stage 2 — Per-host phases (worker pool)` and `convert  →  OpenGraph nodes (+ edges, planned)`, ~line 261).

- [ ] **Step 1: Locate the stale claims.** Two lines are stale against the code: `convert  →  OpenGraph nodes (+ edges, planned)` (edges shipped through pipeline Stage 6 — `src/openhound_sccm/kinds/edges.py` has 38 edge kinds) and the Stage-2 box `RemoteRegistry · MSSQL  [· AdminService ...]` (there are six per-host phases now, per `src/openhound_sccm/per_host_phases.py`).

- [ ] **Step 2: Rewrite the two lines.** Convert line → `convert  →  OpenGraph nodes + edges` (drop "planned"). Stage-2 box → name the full phase set, e.g. `RemoteRegistry · MSSQL · AdminService · WMI · HTTP · SMB`. Re-pad so the ASCII box borders stay vertical.

- [ ] **Step 3: Verify.** `Grep pattern="edges, planned" path=README.md` → **no matches**. Visually confirm the box borders line up.

- [ ] **Step 4: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R2: Add the missing `samAccountName` row to the `User` node table

**Files:**
- Modify: `README.md` — the `## User` property table (anchor: the row `| `userPrincipalName` | string | ...`, ~line 876; the `## User` heading is ~line 884).
- Verify against: `src/openhound_sccm/graph.py` — `UserProperties.samAccountName` (line 265) and its docstring (lines 237–243).

- [ ] **Step 1: Confirm the drift.** `UserProperties` declares `samAccountName` (camelCase, kw-only); the README `## User` table omits it. The docstring states it's populated and load-bearing: edges keyed on a user (`HasSession`, `MSSQL_GetTGS`/`GetAdminTGS`/`ServiceAccountFor`, `SCCM_HasPrimaryUser`/`HasADLastLogonUser`/`IsMappedTo`) resolve their `User` endpoint by `samAccountName`.

- [ ] **Step 2: Add the row** immediately after the `userPrincipalName` row:
```markdown
| `samAccountName` | string | AD `sAMAccountName` of this user account (camelCase to match `Computer.samAccountName`; the LDAP attribute is normalized to camelCase). Load-bearing: edges keyed on a user (`HasSession`, `MSSQL_GetTGS`/`GetAdminTGS`/`ServiceAccountFor`, `SCCM_HasPrimaryUser`/`HasADLastLogonUser`/`IsMappedTo`) resolve their `User` endpoint by this key. |
```

- [ ] **Step 3: Verify.** `Grep pattern="samAccountName" path=README.md output_mode=count` reports ≥3 (Computer, User, SCCM_ClientDevice). Confirm the new row renders inside `## User`.

- [ ] **Step 4: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R3: Reconcile the `Group` table with `GroupProperties` (`SamAccountName`, `distinguishedName`)

**Files:**
- Modify: `README.md` — the `## Group` property table (~lines 913–940 region) and, if chosen, the Group prose below it, plus the Limitations bullet "Group DN / SAM account name".
- Verify against: `src/openhound_sccm/graph.py` — `GroupProperties.SamAccountName` (line 320), `GroupProperties.distinguishedName` (line 321); README Limitations bullet.

- [ ] **Step 1: Confirm the state.** `GroupProperties` carries `SamAccountName` (PascalCase — CMBP doesn't camelCase it for Group) and `distinguishedName`, but the README `## Group` table omits both and Limitations says they're "not yet emitted" (name-only lists, no LDAP group lookup). The fields exist on the model but are effectively always `null`.

- [ ] **Step 2: Apply the recommended fix — add both rows with an "always null today" note** (keeps parity with `Computer`/`User`, which list null-capable AD-resolution fields). After the `CN` row:
```markdown
| `SamAccountName` | string | AD `sAMAccountName` of this group (PascalCase to match CMBP's Group output — unlike `Computer`/`User`, CMBP does not camelCase this key for Group). **Always `null` today:** groups are built from name-only lists resolved to SIDs, with no LDAP group-object lookup — see [Limitations](#limitations). Present on the model for schema symmetry. |
| `distinguishedName` | string | AD distinguished name of this group. **Always `null` today** for the same reason as `SamAccountName` above. |
```
Then align the Limitations bullet wording to "carry a value only once a group-object LDAP lookup is added; the model fields exist but stay `null` today." (Acceptable alternative if Meatbag prefers a lean table: keep the two out of the table and add a one-line "see Limitations for `SamAccountName`/`distinguishedName`" pointer under the Group table. Flag the choice.)

- [ ] **Step 3: Verify.** `Grep pattern="SamAccountName" path=README.md` shows the Group entry; the Limitations bullet and the Group table no longer contradict each other.

- [ ] **Step 4: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R4: Fix the two `README-CMBP.md` references (deleted file)

**Files:**
- Modify: `README.md` — intro banner sentence "...see the PowerShell tool's reference doc, [README-CMBP.md](README-CMBP.md)." (~line 17) and the file-tree line `├── README-CMBP.md ...` (~line 1783).

- [ ] **Step 1: Confirm it's gone.** `README-CMBP.md` exists nowhere in this repo; the PowerShell predecessor now lives in `powershell_deprecated/`. Both README references dangle.

- [ ] **Step 2: Fix the intro sentence.** Replace the `README-CMBP.md` link with a live pointer, e.g.: "For the full intended model, see the original [ConfigManBearPig](https://specterops.io/blog/2026/01/13/introducing-configmanbearpig-a-bloodhound-opengraph-collector-for-sccm/) PowerShell tool, archived in [`powershell_deprecated/`](powershell_deprecated/), and the preproc/convert design spec under `docs/superpowers/specs/`."

- [ ] **Step 3: Remove the file-tree line** for `README-CMBP.md` (the tree is rebuilt in Task R6, but remove it here so no dangling reference survives if R6 is skipped).

- [ ] **Step 4: Verify.** `Grep pattern="README-CMBP" path=README.md` → **no matches**.

- [ ] **Step 5: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R5: Fix the `extension.yaml` location + link, re-verify the "boilerplate" claim

**Files:**
- Modify: `README.md` — Limitations bullet "**`extension.yaml` is boilerplate.** ... in [extension.yaml](extension.yaml) ..." (~line 418) and the file-tree line `├── extension.yaml ...` (~line 1780).
- Verify against: the real file at `src/openhound_sccm/extension.yaml`.

- [ ] **Step 1: Confirm the real location.** `extension.yaml` is at `src/openhound_sccm/extension.yaml` (moved inside the package so the wheel ships it — see `[tool.hatch.build.targets.wheel]` in `pyproject.toml`). The README file-tree places it at the repo root and the Limitations link is `[extension.yaml](extension.yaml)` — both stale.

- [ ] **Step 2: Read `src/openhound_sccm/extension.yaml`** and confirm the "credentials/parameters blocks are framework placeholders, not wired to the collector's options" claim still holds. Adjust the sentence if the file changed.

- [ ] **Step 3: Fix the link** in the Limitations bullet: `[extension.yaml](src/openhound_sccm/extension.yaml)`.

- [ ] **Step 4: Fix the file-tree location** (covered by Task R6's rebuild; ensure `extension.yaml` appears under `src/openhound_sccm/`, not the repo root).

- [ ] **Step 5: Verify.** `Grep pattern="\]\(extension\.yaml\)" path=README.md` → **no matches**.

- [ ] **Step 6: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R6: Rebuild the file tree + reconcile the Debug-harness list with `# Testing Changes`

**Files:**
- Modify: `README.md` — the fenced `text` file tree under `# Understanding the Codebase` (~lines 1778–1799) and the `### Debug harnesses (lab use only)` list (~lines 1809–1815).
- Verify against: the filesystem under `src/openhound_sccm/` and `dev/`.

- [ ] **Step 1: Fix the definite file-tree errors** (these are code-truth violations, not judgment calls):
  - `main.py` comment "collect/preprocess registration" → "collect/preprocess/convert registration" (it now hand-registers `convert sccm` via `_run_convert` + `app.converter` + `_convert_typer.command`).
  - The tree omits real, load-bearing source files: `convert_pipeline.py` (the Convert2-Read-DB convert pipeline), `edge_help.py` (entity-panel help, `PENDING_HELP_KINDS`), `opengraph_untagged.py` (untagged AD-payload destination), and the `integration/` subpackage (test-kit fixtures). Add them.
  - The `models/` line lists only `SCCMSite, SCCMClientDevice, SCCMCollection, SCCMAdminUser, SCCMSecurityRole, GraphEdge, StubNode`. The directory also has `computer.py`, `user.py`, `group.py`, `container.py`, six `mssql_*.py`, `raw_table.py`, `target_entry.py`. List them, or summarize as "AD + SCCM + MSSQL node models, `GraphEdge`, `StubNode`, `RawTable`, `TargetEntry`".
  - Remove the `README-CMBP.md` line (Task R4); move `extension.yaml` under `src/openhound_sccm/` (Task R5).

- [ ] **Step 2 (judgment call — confirm with Meatbag): whether to surface real top-level dirs.** The tree is currently a curated view (a few root files + `src/openhound_sccm/`), so it's *not* required to be a full `ls`. **Recommended:** add the operator-meaningful top-level entries `cypher_queries/` (saved BloodHound Cypher queries), `powershell_deprecated/` (the archived PowerShell predecessor — this is also where Task R4 now points), and `dev/` (developer harnesses). Leave caches, `.venv`, and dotfiles out. If Meatbag prefers the tree stay src-focused, skip this step — it is not a staleness fix.

- [ ] **Step 3: Reconcile the Debug-harness list with the new `# Testing Changes` section.** The old `### Debug harnesses (lab use only)` list names only `debug_epa_matrix.py`, `debug_per_host.py`, `spike_smb_sso.py` as bare filenames; the real `dev/` directory holds `debug_epa_matrix.py`, `debug_per_host.py`, `debug_smb_auth.py`, `debug_wmi_auth.py`, `spike_smb_sso.py`, and four `tour_driver_stage0..3.py` scripts. The new `## Validate against a real hierarchy` subsection already shows the correct `dev\debug_epa_matrix.py` invocation with env-var creds. So:
  - Update the old list to state the `dev/` location and cover the missing scripts (`debug_smb_auth.py`, `debug_wmi_auth.py`; and note the `tour_driver_stage*.py` phased-pipeline tour drivers, or point at the framework tour doc `docs/per-host-collection-framework-tour.md`).
  - Keep the *what-each-script-does* descriptions here, and add a one-line cross-reference to `# Testing Changes → Validate against a real hierarchy` for *how to run them* (env-var creds) — so the two sections complement rather than duplicate. Do not restate the run commands here.

- [ ] **Step 4: Verify.** For every filename in the rebuilt tree and harness list, confirm it exists (`Glob pattern="src/openhound_sccm/convert_pipeline.py"`, `.../edge_help.py`, `.../opengraph_untagged.py`, `Glob pattern="dev/debug_*.py"` and `dev/tour_driver_*.py`). No named file missing; no load-bearing module absent.

- [ ] **Step 5: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R7: Review the "mid-migration" / "planned" framing

**Files:**
- Modify: `README.md` — the "🚧 Work in progress" banner (~lines 9–17) and the Limitations bullets that say "planned for later stages" / "not yet ported".

- [ ] **Step 1: Establish current reality.** The graph pipeline shipped through Stage 7 (docs/validation) and the low-priv assumed-edges work is done. Genuinely unported: the **DHCP/PXE** per-host collector (accepted token, no collector) and **NAA-secret decryption** (`--enable-bad-opsec` + a dedicated collector). Those are the only in-flight items.

- [ ] **Step 2: Judgment edit (recommended — confirm with Meatbag).** Keep the banner's honesty but replace the blanket "mid-migration" with a precise statement: collect + graph pipeline complete for the implemented collection methods; remaining gaps are DHCP/PXE and NAA-secret collection. Don't overstate completeness — DHCP/NAA really are unported. Leave the "documents what the code does today" ethos.

- [ ] **Step 3: Verify.** The banner's phase list and the Limitations "not yet ported" bullet name the same remaining items (DHCP/PXE, NAA); no leftover "edges planned" language (Task R1 removed the ASCII one).

- [ ] **Step 4: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R8: Re-order the Table of Contents to match the alphabetized references

**Files:**
- Modify: `README.md` — the `# Table of Contents` Node Reference (~lines 35–49) and Edge Reference (~lines 52–88) sub-lists. Leave the new Testing Changes TOC block (~lines 89–93) untouched.

> Do this together with R9/R10 so the TOC and sections never disagree. Anchor slugs don't change (headings keep their text) — only TOC line *order* changes.

- [ ] **Step 1: Reorder the Node Reference TOC** to: `Computer`, `Container`, `Group`, `User`, `SCCM_AdminUser`, `SCCM_ClientDevice`, `SCCM_Collection`, `SCCM_SecurityRole`, `SCCM_Site`, `MSSQL_Database`, `MSSQL_DatabaseRole`, `MSSQL_DatabaseUser`, `MSSQL_Login`, `MSSQL_Server`, `MSSQL_ServerRole`.

- [ ] **Step 2: Reorder the Edge Reference TOC** to match R10's order, keeping `Entity-panel help properties` first.

- [ ] **Step 3: Verify.** Every reordered TOC link target still exists as a heading; the Testing Changes TOC entries are unchanged.

- [ ] **Step 4: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R9: Alphabetize the Node Reference sections within each namespace group

**Files:**
- Modify: `README.md` — the `# Node Reference` body (all `## <NodeKind>` subsections, ~lines 845–1274). Headings: `## Computer` 845, `## User` 884, `## Group` 913, `## Container` 941, `## SCCM_Site` 964, `## SCCM_ClientDevice` 1002, `## SCCM_Collection` 1059, `## SCCM_AdminUser` 1086, `## SCCM_SecurityRole` 1115, `## MSSQL_Server` 1146, `## MSSQL_Database` 1172, `## MSSQL_ServerRole` 1191, `## MSSQL_DatabaseRole` 1210, `## MSSQL_Login` 1230, `## MSSQL_DatabaseUser` 1252.

- [ ] **Step 1: Move whole subsections** (heading + prose + property table + trailing notes) into the "Node Reference — target order". Preserve the `---` rules separating AD/SCCM/MSSQL groups. Cut-and-paste whole blocks only — do not edit content here.

- [ ] **Step 2: Preserve property-row order inside each table** (grouped meaningfully; matches `graph.py` field order + carries grouped explanatory notes). Do not alphabetize rows.

- [ ] **Step 3: Verify.** `Grep pattern="^## " path=README.md` over the Node Reference range shows the target order; `## ` heading count unchanged (nothing dropped/duplicated).

- [ ] **Step 4: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R10: Alphabetize the Edge Reference sections within each namespace group

**Files:**
- Modify: `README.md` — the `# Edge Reference` body (all `## <EdgeKind>` subsections). Current anchors include `## SCCM_AdminsReplicatedTo` 1321 … `## MemberOf` 1375, `## GenericAll` 1389, `## HasSession` 1401 … `## MSSQL_*` 1539–1636 … `## SCCM_CoerceAndRelayToAdminService` 1653, `## MSSQL_CoerceAndRelayToMSSQL` 1675, `## SCCM_CoerceAndRelayToSMB` 1698.

- [ ] **Step 1: Keep fixed anchors.** `## Entity-panel help properties` stays **first**; the two `## Attack path example …` subsections stay **last** (current relative order). Everything between is reordered per "Edge Reference — target order".

- [ ] **Step 2: Move whole subsections.** The combined heading `## SCCM_HasPrimaryUser / SCCM_HasCurrentUser / SCCM_HasADLastLogonUser` moves as one unit (sorted by `SCCM_HasPrimaryUser`). Move any `<a name="...">` explicit anchor tags (e.g. `sccm_coerceandrelaytosmbedge`) with their subsection.

- [ ] **Step 3: Preserve the `---` group separators** between AD/SCCM/MSSQL and before the attack-path examples.

- [ ] **Step 4: Verify.** `Grep pattern="^## " path=README.md` over the Edge Reference range shows the target order, `Entity-panel help properties` first, the two attack-path examples last; heading count unchanged.

- [ ] **Step 5: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R11: Add the README reference key + first-use expansion of Stage#/D# tokens

**Files:**
- Modify: `README.md` — add a short "Reference key" note near the top (recommended: right after the intro banner, or at the head of `# Graph Model`), then expand first-uses per section.
- Uses: the "Reference Data" appendix.

- [ ] **Step 1: Inventory tokens.** `Grep pattern="\b(Stage [0-9]|Stages [0-9]|D[0-9]+[a-z]?|Task [0-9]+|Phase [AB])\b" path=README.md output_mode=content -n=true`. Expect pipeline `Stages 1–6`/`Stage 3–6` (intro, Graph Model, reference intros), collection `Stage 1`/`Stage 2` (Collection Overview, Understanding), `D2a`/`D2b` (MSSQL node tables).

- [ ] **Step 2: Add the reference key** — a compact table mapping the two `Stage` schemes and the `D#` family to their source plans (from the appendix). **Explicitly disambiguate the two `Stage` numberings:** "Stage 1/Stage 2" in Collection Overview = collection stages (per-host collection framework plan); "Stage 1–6" elsewhere = preproc/convert pipeline stages (the numbered pipeline plans).

- [ ] **Step 3: Expand first-uses per section**, e.g.:
  - First pipeline-stage mention: "…Stages 1–6 of the graph pipeline (the incremental preproc/convert port; see `docs/superpowers/plans/2026-06-*-sccm-preproc-convert-stage*.md` under the design spec `docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md`)…"
  - First `D2a`/`D2b` (in the `MSSQL_Server` table): "…the `SPN+SCCM` inference (D2a/D2b of the low-privilege assumed-edges plan, `docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md`: D2a resolves the `MSSQLSvc` SPN holder, D2b treats an SCCM-related SPN host as *the* site database)…"
  - First collection-stage mention: "Stage 1 — Discovery … / Stage 2 — Per-host phases (the two collection stages of the per-host collection framework, `docs/superpowers/plans/2026-06-03-per-host-collection-framework.md`)".
  Later uses in the same section stay terse.

- [ ] **Step 4: Verify.** Each *first* mention per section names a plan; no `D#` refers to the MSSQL-extension plan (if one does, expand it to the correct plan and flag it). `Grep` for `2026-` to confirm plan paths landed.

- [ ] **Step 5: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R12: Sweep for count/enumeration drift in the intro and reference intros

**Files:**
- Modify: `README.md` — intro banner node/edge enumerations (~line 14), Node Reference intro (~line 817 region), Edge Reference intro (~line 1255 region), Graph Model "Kinds emitted" list, and both Mermaid diagrams.
- Verify against: `src/openhound_sccm/kinds/nodes.py` (16 constants incl. `Base`; 15 documented node kinds) and `kinds/edges.py` (38 edge-kind constants).

- [ ] **Step 1: Re-confirm counts.** Node kinds documented = **15** (excluding the `Base` meta-label); edge kinds = **38**. Verify all such counts still read 15/38 after the reference reorder (reordering doesn't change counts).

- [ ] **Step 2: Decide intro/diagram order (recommended: leave as-is).** The intro banner groups edges *by stage* ("11 from Stages 1–2, 10 new from Stage 3, …") — a narrative, not a flat list; the two Mermaid diagrams are drawn in flow order. The alphabetize decision targeted the Node/Edge *reference* lists, so **do not** alphabetize these. Flag the choice for Meatbag.

- [ ] **Step 3: Verify.** `Grep pattern="node kinds|edge kinds" path=README.md output_mode=content -n=true`; every count reads 15 / 38; no stray "fourteen"/"37" outside a historical context.

- [ ] **Step 4: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task R13: README link-existence check (relative links + anchors, including the new section)

**Files:**
- Verify only (fixes fold into the owning task): `README.md`.

- [ ] **Step 1: Extract relative links.** `Grep pattern="\]\((?!https?:|#)[^)]+\)" path=README.md output_mode=content -n=true`. For each, confirm the target exists relative to the repo root (e.g. `src/openhound_sccm/main.py`, `AGENTS.md`, `.agents/...`, `pyproject.toml`, `.pre-commit-config.yaml`, and the new section's `.github/workflows/ci.yml` and `powershell_deprecated/`).

- [ ] **Step 2: Extract in-page anchors.** `Grep pattern="\]\(#" path=README.md output_mode=content` and confirm each `#slug` matches a heading slug — including the new `#testing-changes`, `#set-up-a-development-environment`, `#if-you-are-also-editing-the-shared-library`, `#run-the-checks`, `#validate-against-a-real-hierarchy`, and the reordered reference anchors (R8/R9/R10 don't change slugs).

- [ ] **Step 3: Fix any dangling target** by folding into the owning task; do **not** rewrite the new `# Testing Changes` prose — only fix a link if it's genuinely broken. Record what was fixed.

- [ ] **Step 4: Show findings + diffs and ask Meatbag whether to commit** (never push).

---

### Task A1: Sort the ARCHITECTURE.md changelog (newest-first, same-date by causality)

**Files:**
- Modify: `ARCHITECTURE.md` — the `## Changelog` table (~lines 1836–1862, 27 rows).

- [ ] **Step 1: Identify the one out-of-order row.** The `2026-07-29` "**Removed direct BloodHound CE upload**" row (~line 1841) currently sits **between** two `2026-07-24` rows. Everything else is already descending; moving that row into the `2026-07-29` cluster is the core fix.

- [ ] **Step 2: Group by date, newest first**: `2026-07-29` (×3), `2026-07-28` (×2), `2026-07-24` (×3), `2026-07-22` (×5), `2026-07-21` (×2), `2026-07-20`, `2026-07-17` (×2), `2026-07-16`, `2026-07-14`, `2026-07-01`, `2026-06-30` (×2), `2026-06-29` (×2), `2026-06-25`, `2026-06-23`.

- [ ] **Step 3: Order same-date clusters by dependency/causality** (confirm with `git log` where unclear):
  - **2026-07-29 (×3):** the two ope-60fe publishing-prep rows first and adjacent ("First green `ruff` + `mypy`" → "Adopted the published `openhound` 0.2.12"), then "**Removed direct BloodHound CE upload**" so it reads as the final state (it supersedes the `2026-07-24` "Added §15" row below).
  - **2026-07-28 (×2):** §11l built on §11k, so newest-first §11l reads before §11k; confirm against git, else keep current relative order.
  - **2026-07-24 (×3), 2026-07-22 (×5), 2026-07-21 (×2), 2026-07-17 (×2), 2026-06-30 (×2), 2026-06-29 (×2):** no hard dependency between same-date members — preserve current relative order (stable) unless git chronology dictates otherwise. (For 2026-06-30, "Stage 6" before "Stage 5" is correct newest-first.)

- [ ] **Step 4: Do NOT edit row *content*.** The struck-through "~~Added §15~~ … removed on 2026-07-29" row stays as-is (historical record). Historical counts like "14 node kinds, 37 edge kinds" in the Stage 7 row are a record of that moment — leave them.

- [ ] **Step 5: Verify.** `Grep pattern="^\| 20[0-9]{2}-" path=ARCHITECTURE.md output_mode=content` → dates monotonically non-increasing; row count unchanged (27).

- [ ] **Step 6: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task A2: Add the ARCHITECTURE.md reference key + first-use expansion

**Files:**
- Modify: `ARCHITECTURE.md` — add a "Reference key" subsection (recommended: after `## Table of Contents`, before `## The big picture`), then expand first-uses per section.
- Uses: the "Reference Data" appendix.

- [ ] **Step 1: Inventory tokens.** `Grep pattern="\b(D[0-9]+[a-z]?|Stage [0-9]|Task [0-9]+|Phase [AB]|C[2-5])\b" path=ARCHITECTURE.md output_mode=content -n=true`. Expect dense hits in §9, §11c–§11l (D2–D6, D2a/D2b, Tasks 1–14, Task B3, Stage 3–6, C4/C5, Phase A/B).

- [ ] **Step 2: Add the reference key** transcribing the appendix: the two `Stage` schemes, the low-priv `D#`/`Task#` family, the Stage-3 `C#` sub-tasks, and `Phase A/B`. **State explicitly that the `D#` tokens in this document belong to the low-privilege assumed-edges plan, NOT a separate MSSQL-extension `D1–D11` plan** — the single most important disambiguation.

- [ ] **Step 3: Expand first-uses per section**, e.g. "D6 (site-code attribution is per-host and never guessed — from the low-privilege assumed-edges plan, `docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md`)". Leave `§N` links and `ope-XXXX` ids as-is. Later uses in a section stay terse.

- [ ] **Step 4: Verify.** Spot-check the first `D#`/`Stage#`/`Task#`/`Phase` mention in §9, §11h, §11l — each names its plan. `Grep` for `2026-` to confirm plan paths landed.

- [ ] **Step 5: Show the diff and ask Meatbag whether to commit** (never push).

---

### Task A3: ARCHITECTURE.md broken-reference fixes (incl. README-CMBP + extension.yaml)

**Files:**
- Verify + fix inline: `ARCHITECTURE.md`. Known targets: the `README-CMBP.md` mention (~line 105) and the `extension.yaml` link `[extension.yaml:15-24](extension.yaml#L15-L24)` (~lines 490–491).

- [ ] **Step 1: Fix the two known broken references.**
  - `README-CMBP.md` (~line 105, prose "predecessor is the PowerShell tool **ConfigManBearPig** (`README-CMBP.md`)"): the file is gone. Re-point to the archived PowerShell tool in `powershell_deprecated/` (or drop the parenthetical `README-CMBP.md`), consistent with Task R4.
  - `extension.yaml` link (~lines 490–491): the file moved to `src/openhound_sccm/extension.yaml` — update the link target to `src/openhound_sccm/extension.yaml#L15-L24` (verify the line range still matches the current file; adjust or drop the line anchor if it doesn't).

- [ ] **Step 2: Extract remaining relative links + anchors.** `Grep pattern="\]\((?!https?:)[^)]+\)" path=ARCHITECTURE.md output_mode=content -n=true`. Check `src/openhound_sccm/...` code paths (confirm the *file* exists — don't re-audit prose), `.tickets/<id>.md` links (confirm the ticket file exists), any `.sdd/...` links (that harness dir is gitignored; if absent in a working checkout, downgrade the link to plain text rather than leaving it dangling), and in-page `#section` anchors (each matches a heading slug; the changelog re-sort doesn't change slugs).

- [ ] **Step 3: Fix each dangling target** — correct the path if the file moved, or convert to plain text if intentionally not in the repo. Don't invent content.

- [ ] **Step 4: Verify.** Re-run the Step 2 grep; every relative target resolves (or is deliberately plain text); every `#anchor` matches a heading.

- [ ] **Step 5: Show findings + diffs and ask Meatbag whether to commit** (never push).

---

### Task V1: Final whole-document verification pass

**Files:**
- Verify only: `README.md`, `ARCHITECTURE.md`.

- [ ] **Step 1: Render check.** Preview both as Markdown. Confirm: both Mermaid diagrams parse; all tables render (no broken pipes); the ASCII diagram borders line up; TOC links (including the new Testing Changes entries) jump correctly.

- [ ] **Step 2: Reference-list order check.** Node/Edge reference sections and their TOC entries are in the target A–Z-within-group order; counts read **15 node kinds / 38 edge kinds** everywhere.

- [ ] **Step 3: Changelog order check.** ARCHITECTURE changelog dates strictly non-increasing top-to-bottom; the stranded `2026-07-29` removal row now sits in the `2026-07-29` cluster.

- [ ] **Step 4: Shorthand-resolution check.** Pick five random `D#`/`Stage#`/`Task#` mentions across both docs; each traces to a named plan (via first-use expansion or the reference key).

- [ ] **Step 5: Dangling-link check.** Re-run the link greps from R13 and A3 across both files; expect zero dangling relative targets and zero unmatched anchors. Confirm the new `# Testing Changes` links/anchors still resolve and its prose is unchanged.

- [ ] **Step 6: Summarize** everything changed (factual corrections, alphabetization, reference-key/expansion, changelog sort, link fixes), show the diffs, and ask Meatbag whether to commit (never push).

---

## Self-Review (against the original request)

1. **Coverage.** (a) review docs for stale content → R1–R7, R12, R13, A3; (b) alphabetize long lists → R8, R9, R10; (c) expand shorthand references with full plan names + purpose → R11, A2 (backed by the Reference Data appendix); (d) sort change logs by date → A1; (e) bring docs up to date with code → R1–R7, R12; preserve the new `# Testing Changes` edit → the interaction section + R6/R13/V1. All covered.
2. **Placeholder scan.** No "TBD"/"handle edge cases"/"similar to Task N" — each task quotes its anchor and states the exact change.
3. **Consistency.** Node/edge target orders defined once (appendix) and referenced by R8/R9/R10; token→plan mapping defined once (Reference Data) and referenced by R11/A2; counts (15/38) and the two `Stage` schemes stated consistently.

## Other recommendations (per "make other recommendations as you see fit")

- **Property-row alphabetization:** deliberately *not* done (rows are grouped meaningfully and match `graph.py` field order + carry grouped notes). If Meatbag wants rows alphabetized too, that's a follow-up decision.
- **Intro banner + Mermaid diagrams:** recommend leaving in stage/flow order, not alphabetized (they're narrative/diagrams, not reference lists). Confirm in review.
- **File-tree completeness (Task R6 Step 2):** adding `cypher_queries/`, `powershell_deprecated/`, `dev/` to the tree is a recommended judgment call, not a staleness fix — approve or decline.
- **Track the work:** open a `gtk` ticket for this docs refresh and update `TICKETS-BY-STATUS.md` (remember `.gitattributes` marks that file `merge=ours`).

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-07-30-docs-update-readme-architecture.md` (in the ConfigManBearPig repo). Note the commit model: each task ends by showing its diff and **asking before committing**; never push. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session with checkpoints for review.

Which approach?
