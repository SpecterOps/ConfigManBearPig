# Multi-Agent Concurrency Harness — Design

**Status:** grilling complete. D1–D12 locked. Awaiting owner review before the implementation plan
is executed.
**Date:** 2026-07-29
**Scope:** how multiple Claude Code sessions and their subagents work concurrently across the
post-split ConfigManBearPig / openhound-collector-common / MSSQLHound repos without corrupting
each other's work or each other's trunk.

---

## Why this document exists

Today all agent work happens in one working tree, one session at a time. Throughput is capped by
that serialization, and the obvious fix — "run several agents at once" — is unsafe in this repo for
reasons that are specific to it rather than general. This document records what those reasons are,
what we decided to do about each, and how merge conflicts get handled once concurrency is real.

The single organising idea: **concurrency problems are never about agents, they are about shared
mutable state.** Every decision below is either isolating a piece of shared state or deciding who
resolves it when isolation is impossible.

---

## Reconnaissance findings

These are measured facts about the repo as of 2026-07-29, not assumptions. Several of them
invalidate the obvious design, so they are recorded before the decisions they constrain.

### F1 — `main` is abandoned; `integration` is the real trunk

```
integration -> ohsccm  : 34 ahead, 1 behind
integration -> ohmssql : 39 ahead, 0 behind
integration -> main    : 118 ahead, 0 behind
```

`origin/HEAD` points at `main`, so every PR opened by a human or an agent defaults to the wrong
base branch. **The owner is fixing this before the harness is implemented** (see D4), and the
post-split repos each get a clean `main` as trunk (D7), so the harness assumes a correct trunk
rather than working around a broken one.

### F2 — CI is pointed at a branch nobody uses

Both `.github/workflows/test.yml` and `.github/workflows/validate-branch.yml` trigger only on
`pull_request: branches: [main]`. Consequences:

- A PR into `integration` runs **zero** checks. Not failing checks — no checks at all, which reads
  on the PR page as "nothing to worry about."
- `validate-branch.yml` enforces `^(fix|patch|feature|minor|major)/<name>$`. The existing
  `ohsccm`, `ohmssql`, and `integration` branches all violate it, confirming F1.
- `test.yml` runs OpenHound **core** tests from the repo root. Nothing under `sccm/sccm/tests` or
  `mssql/mssql/tests` executes in CI at all.
- `.github/workflows/` is upstream-owned (`SpecterOps/openhound`). Any workflow added there would
  conflict on every upstream sync, permanently. D7 dissolves this: the post-split repos own their
  own workflows outright.

### F3 — `gh` CLI is not installed

`command -v gh` finds nothing. Agents cannot open or update pull requests until this is installed
and authenticated. This is a prerequisite, not a design decision.

### F4 — The worst merge surface is documentation, not code

| File | Lines | Longest line |
|---|---|---|
| `TICKETS-BY-STATUS.md` | 256 | **3,513 chars** |
| `sccm/sccm/README.md` | 1,645 | 2,703 chars |
| `sccm/sccm/ARCHITECTURE.md` | 1,698 | 1,914 chars |
| `CLAUDE.md` | 78 | 672 chars |

Git's 3-way merge asks "did both sides change the same *line*?" A 3,513-character line holding a
dozen semicolon-separated ticket updates means any two lanes touching any two unrelated tickets
collide on one line, and git cannot auto-resolve it because from git's view they edited the
identical unit. CLAUDE.md *mandates* updating all three files.

By contrast `.tickets/<id>.md` — 108 separate files, one per ticket — produces zero conflicts. That
is the file-per-unit pattern, and it is the model the doc files should follow.

`TICKETS-BY-STATUS.md` describes itself as **generated** (`Generated: … Reconciled: … Source of
truth: .tickets/*.md`). Merging a derived file is a category error: it can be regenerated in one
command, so any conflict there is wasted human attention.

### F5 — Editable installs leak uncommitted edits across worktrees

The mechanism is now a committed `[tool.uv.sources]` entry, which `uv sync --group dev` installs as an
editable dependency:

```toml
[tool.uv.sources]
openhound-collector-common = { path = "../openhound-collector-common", editable = true }
```

(An earlier draft of the publish plan used a `just dev` recipe that layered `uv pip install -e` on top of
`uv sync`; the task runner was deleted when the source entry was restored. The leak below is unchanged by
that — if anything it is worse, because a committed path is shared by construction rather than by a recipe
default.)

An editable install writes a *pointer* into the venv, not a copy. Every import reads
whatever is on disk at that path right now. Two lanes as siblings of one parent directory both
resolve `../openhound-collector-common` to the **same checkout**:

```
parent/
  openhound-collector-common/     <-- ONE mutable checkout
  CMBP-lane-a/  .venv -> -e ../openhound-collector-common
  CMBP-lane-b/  .venv -> -e ../openhound-collector-common
```

Lane A's *uncommitted* edit instantly changes what lane B's tests execute. This is strictly worse
than a merge conflict: a conflict is git reporting loudly that two changes disagree, whereas this
is two changes silently sharing mutable state behind git's back. There is no conflict to resolve,
no merge to review, and no diff in lane B's PR — its tests simply start failing, or worse start
passing, for reasons that exist only in another lane's working directory. Every debugging instinct
points at lane B's own code, where nothing is wrong.

**Narrowing:** a shared *read-only* checkout is safe. `-e ../OpenHound` is fine to share because
CLAUDE.md forbids writing to it. The hazard is exactly one directory: `openhound-collector-common`.
D6 addresses it.

### F6 — DuckDB and pipeline artifacts are single-writer

`sccm/sccm/` holds `lookup.duckdb`, `fix_check.duckdb`, `probe_duckdb.duckdb`, plus `output/`
(the dlt bucket) and `logs/`. DuckDB takes an **exclusive file lock**, so two `preprocess` or
`convert` runs in one tree block or error. All of these are `.gitignore`d, which is good news for
worktrees: a fresh worktree starts clean rather than inheriting a half-written bucket.

This means pipeline-*running* work cannot be parallelized inside a single tree no matter how the
agents are orchestrated — only code-*writing* work can. Worktree-per-lane resolves it by giving
each lane its own DuckDB files.

### F7 — Worktree bootstrap cost

Measured venv sizes: `sccm/sccm/.venv` 321 MB, root `.venv` 324 MB, `mssql/mssql/.venv` 162 MB,
`openhound-collector-common/.venv` 6 MB — ~813 MB total. Worktrees do **not** copy these (they are
gitignored), so each new lane must build its own.

The uv cache exists at `C:\Users\domainadmin\AppData\Local\uv\cache`, on the same NTFS volume as
the repo, so `uv sync` in a fresh worktree should mostly **hardlink** rather than copy — meaning
new lanes are considerably cheaper than 813 MB implies. **Unverified:** the `du` measurement timed
out. A real measurement of wall-clock and disk cost for one fresh lane is a prerequisite task, not
an assumption this design may rest on.

### F8 — Documentation locations are inconsistent, and the split will strand some

Three `docs/superpowers/` trees exist: the fork root (6 files, all SCCM topics), `sccm/sccm/`
(current convention, 8 specs + 8 plans), and `mssql/mssql/` (2 plans). The publish runbook
puts SCCM at the *root* of `SpecterOps/ConfigManBearPig`, and its last steps clean up the fork — so
anything under `sccm/sccm/docs/` travels into the new repo automatically, while the fork's root
`docs/` is **stranded in a repo about to be abandoned**. Those six files need relocating as part
of the cleanup; tracked separately from this work.

---

## Locked decisions

| # | Decision | Consequence |
|---|---|---|
| **D1** | A **lane** is one gtk ticket: its own worktree set, its own supervising session, its own subagents. | Maximum throughput, and it maps onto how work is already tracked. Also means multiple lanes edit the same source tree, so **real code conflicts are normal operation**, not an exception. |
| **D2** | **Serialized merge queue.** Lanes develop fully in parallel but land one at a time; a lane catches up to trunk before landing. | Conflicts are always **pairwise** (my-lane vs. new-trunk), never an N-way tangle, and each is resolved by the agent holding full context on its own change. Cost: a slow lane blocks the queue behind it. |
| **D3** | The no-agent-commits rule is **dropped**. Agents commit and push their own lane branches. **PR review in GitHub is the gate** before anything reaches trunk. | Git machinery (3-way merge, `rerere`, merge commits) becomes available — none of it can operate on uncommitted work, because uncommitted work has no identity in the object database. The owner's veto is preserved, relocated from "local commit" to "PR merge". |
| **D4** | The owner fixes the trunk/CI friction (F1, F2) **before** this harness is implemented. | The harness may assume a correct default branch and working CI rather than compensating for their absence. |
| **D5** | Conflicts are resolved by the lane's agent into a **merge commit**, plus a **written resolution report**. Both are reviewed. | The merge commit is machine-verifiable (`git show` displays exactly which side was taken, per hunk); the report is human-readable reasoning. Cross-checking them catches an agent that misdescribes its own resolution. Supersedes rebase: merging never rewrites pushed history, so no force-push and the PR stays stable while being read. |
| **D6** | **Every lane pairs** a collector worktree with its own shared-library worktree. | Kills F5 structurally rather than by discipline. Costs a second worktree and venv per lane. Two side effects: catch-up becomes **two merges in two repos kept in step**, and a lane goes green against *local* shared-library code that no released version contains — requiring an explicit pre-land check against the pinned version. |
| **D7** | Target is the **post-split** three-repo world; the publish plan is a hard prerequisite. Trunk is `main` in each repo. | No monorepo compatibility burden. Also dissolves F2's upstream-ownership problem, since each new repo owns its own workflows. The harness is unusable until the split lands. |
| **D8** | Paired PRs land **atomically as one queue slot** — shared library first, collector immediately after. | Trunk is never observed half-landed, so the next lane always merges against a coherent pair of trunks. Without this, a landed shared-library helper with no caller invites the next lane to "clean up" code that is about to be used. Cost: the owner must be present for both merges. |
| **D9** | **Full conflict prevention.** Regenerate `TICKETS-BY-STATUS.md` rather than hand-editing it; reflow `README.md`/`ARCHITECTURE.md` to one sentence per line; each ticket declares its expected file scope. | Removes most conflicts rather than making them cheaper to resolve. Addresses F4 at its root. Costs one large, boring reflow diff across ~3,300 lines. The scope declarations are also the input D11 needs. |
| **D10** | Hooks **hard-block** what is never correct: committing while `HEAD` is trunk, pushing to trunk, force-pushing a branch under review, `--no-verify`. Scope violations **warn** — except where D11's lock applies (see below). | Blocks the unrecoverable while permitting the legitimate mid-task discovery that a fix lives one layer down. |
| **D11** | **Dynamic lane count.** A lane starts whenever its ticket is ready *and* its declared file scope does not overlap an active lane. | Parallelism is bounded by genuine independence rather than an arbitrary number, and self-limits on a hot file. Requires D9's declarations to exist. Session count is unpredictable, so CPU contention needs watching (see Risks). |
| **D12** | Post-merge gate: the lane's own targeted tests, **plus** the tests belonging to the trunk change just merged, **plus** a symbol-existence check for every symbol the lane calls; plus a behavioural `transforms()` diff whenever `transforms.py` is touched. | The middle item is the only thing that catches a resolution breaking another lane's code. The symbol check catches the rename-versus-new-caller case that git merges clean. |

---

## Lane anatomy

A lane is a ticket plus the worktrees it needs. Post-split, for an SCCM ticket:

```
workspace/
  OpenHound/                        read-only, SHARED across all lanes (safe: never written)
  ConfigManBearPig/                 trunk checkout, never worked in directly
  openhound-collector-common/       trunk checkout, never worked in directly

  lane-ope-8c44/
    ConfigManBearPig/               worktree, branch feature/ope-8c44
    openhound-collector-common/     worktree, branch feature/ope-8c44
    .venv wiring: -e ../openhound-collector-common  (LANE-LOCAL, per D6)
                  -e ../../OpenHound               (shared read-only)
```

Each lane's redirection must point at that lane's own shared-library worktree, overriding the single
committed `[tool.uv.sources]` path. Getting this wrong reintroduces F5 silently — the venv keeps working,
it just executes another lane's files.

---

## Merge conflict handling

This is the part of the design the owner asked to have fleshed out in full detail, because D1
makes conflicts routine rather than rare.

### Conflict taxonomy

Not all "conflicts" are the same object, and each kind needs different handling.

| Kind | Does git flag it? | Who resolves | Notes |
|---|---|---|---|
| **Textual** | Yes, with markers | Lane agent | The easy case. Agents do this well; the lane's own agent is best positioned because it knows why its change exists. |
| **Semantic** | **No — merges clean** | Detected by tests, not by git | The dangerous case. See below. |
| **Generated-file** | Yes, but resolving is a category error | Nobody — regenerate | `TICKETS-BY-STATUS.md`. Never hand-merge a derived file. |
| **Cross-repo / pin** | No | Lane agent at pre-land check | Lane green against local shared-lib code that no published version contains (D6 side effect). |
| **Filesystem coupling** | No — not a git event at all | Prevented by D6, not resolved | F5. There is nothing to merge; the state was never in git. |

### Semantic conflicts: the case git cannot see

Git compares lines and has no concept of meaning, so two changes can merge cleanly and produce
broken code:

```
lane A:  renames  _derive_ad_props()  ->  _resolve_ad_props()
lane B:  adds a new caller of  _derive_ad_props()
git:     different lines, different files -> MERGES CLEAN, zero conflicts
result:  AttributeError at runtime
```

**A clean merge is not evidence of a correct merge.** Therefore: post-merge tests are **mandatory
even when the merge reported no conflict at all.** This is the single most important rule in this
document, because it is the one that "the merge succeeded" actively argues against.

This codebase has specific, recurring semantic-conflict classes worth naming explicitly, all drawn
from bugs that have already happened here at least once:

1. **DuckDB `coalesce` SELECT fragility.** dlt snake-cases camelCase LDAP keys and *drops* columns
   that are absent or all-NULL. A `coalesce` SELECT referencing a dropped column raises
   `BinderException` and takes the whole source with it. Two lanes editing different SQL in
   `transforms.py` merge cleanly and can jointly produce a query neither one tested.
2. **Schema / kinds desync.** `schema.json` is hand-maintained and must stay in sync with
   `kinds/edges.py` in both directions. Lane A adding an edge kind and lane B editing the schema
   merge cleanly into a desynced pair.
3. **Property-casing drift.** SCCM output node/edge properties use ConfigManBearPig.ps1-verbatim
   casing, while DuckDB columns and model input fields stay snake_case. Two lanes adding properties
   merge cleanly and ship inconsistent casing — invisible in tests, visible in BloodHound.
4. **Phase-order divergence.** CLAUDE.md requires the collector's steps to run in the exact order
   the PowerShell script uses. Two lanes each inserting a phase merge cleanly into a wrong order.

Detection measures, in order of cost:

- **Mandatory post-merge targeted test run**, clean merge or not (per the house rule: specific
  offline test files, not the full suite).
- **Run the other lane's tests too**, not only your own. That is what catches your resolution
  breaking their code.
- **Symbol-existence check**: for every symbol the lane calls that trunk touched, confirm it still
  exists. Cheap grep; catches the rename case above.
- **Behavioural diff for transform changes**: re-run `transforms()` over a copy of a live
  `lookup.duckdb` and diff the output, per the established house practice.

### Catch-up protocol (a lane preparing to land)

Executed by the lane agent when it acquires the queue slot. Both repos, shared library first,
because it is the dependency.

1. Acquire the queue slot. Only one lane holds it.
2. `git fetch origin` in **both** worktrees.
3. `git merge origin/main` in the **shared-library** worktree first.
4. `git merge origin/main` in the **collector** worktree.
5. `rerere` auto-replays any resolution already approved in another lane (see below).
6. Resolve remaining textual conflicts hunk by hunk. Escalate if any trigger below fires.
7. Write the resolution report.
8. **Re-run targeted tests — mandatory, clean merge or not.**
9. **Pin check:** confirm the lane is not green solely because of unpublished shared-library code.
10. Push both branches; both PRs update.
11. Owner reviews the merge commits, the reports, and the diffs.
12. Owner lands the pair atomically (D8), shared library then collector.
13. Release the queue slot.

### Resolution rules for agents

Constraints on *how* an agent is permitted to resolve, not merely that it may:

- **Resolve hunk by hunk.** Never `git checkout --ours`/`--theirs` on a whole file — that discards
  the other side's work wholesale while reporting success.
- **Never resolve by deletion.** Removing the other lane's code to make markers disappear is a
  silent revert of someone else's reviewed work.
- **Read, do not guess, the other side's intent.** The other lane has a gtk ticket and a PR. Read
  them before deciding.
- **Regenerate generated files**; do not merge them.
- **Never `--no-verify`.** Never force-push a branch already under review.
- **A conflict outside the ticket's declared file scope is an escalation, not a resolution.**

### Escalation triggers — the agent stops and asks

- Conflict in a file the ticket never declared it would touch.
- Both sides changed the same *logical behaviour* (not merely adjacent lines).
- Conflict in the graph contract: `schema.json`, `kinds.py`, `edges.py`. Blast radius is every
  downstream consumer, and a wrong resolution ships bad graph data rather than failing loudly.
- Tests fail after resolution and the cause is not obviously the resolution itself.
- An unusually large number of conflicted hunks in one file — signals divergence deeper than a
  merge can settle.

### `rerere` — resolutions that compound

`git rerere` records how a conflict was resolved and replays it automatically the next time the
same conflict appears. In a serialized queue this matters a great deal: lane 3 merging past lanes
1 and 2 hits near-identical collisions repeatedly.

**To verify before relying on it:** `rr-cache` is expected to live in the repo's *common* git
directory, shared by all worktrees — which would make a resolution approved in one lane replay
automatically in every other lane, for free. This has **not been tested here** and must be
confirmed with a scratch worktree before the design depends on it.

---

## Scope declarations and the lane lock

D9, D10, and D11 interact, and taken literally the first two undercut the third. D11 admits a new
lane only when its declared scope is disjoint from every active lane — but if scope violations only
*warn* (D10), a lane can drift into a file another live lane is working in, silently invalidating
the disjointness that admitted it.

The block is therefore conditional on **live contention**, not on scope alone:

| Situation | Behaviour |
|---|---|
| Edit outside declared scope, file **not** claimed by any active lane | **Warn** and log to the lane report. This is D10's legitimate case: a fix that turns out to live one layer down. |
| Edit outside declared scope, file **is** claimed by another active lane | **Hard block** and escalate. This is the guarantee D11 rests on. |

So declared scope is advisory against the *codebase* and binding against *other lanes*. A lane that
needs a file held by another lane must either wait for that lane to land or have the ticket scopes
renegotiated — which is the conflict being surfaced before any code is written, rather than at merge
time.

**Implementation note:** this requires a registry of active lanes and their claimed files that hooks
can read. The gtk ticket is the natural home for the declaration; the active-claim set is derived
from tickets currently in `in_progress`.

### A note on agent-count limits

An earlier draft of this document stated that "the harness caps concurrent agents at
`min(16, cores-2)` = 4." That figure is specific to the **Workflow tool's** per-workflow agent pool
and does **not** bound separate Claude Code sessions. Under D11 the real limits are CPU/IO
contention on 6 cores and the owner's review bandwidth, neither of which the harness enforces —
hence the contention risk below.

## How the lane lock maps onto `gtk`

The existing ticket CLI already supplies most of what D11 needs, so no new coordination store is
required:

| Need | `gtk` primitive |
|---|---|
| "Ticket's dependencies are resolved" | `gtk ready` |
| "Which lanes are active" | `gtk query` filtered to `status: in_progress` |
| Machine-readable ticket metadata | `gtk query` — emits frontmatter as JSONL |
| Recording a lane's declared scope | a frontmatter field, **or** `tags:` as fallback (see risk below) |

Two sharp edges found while checking this:

- **`gtk ready` includes `in_progress` tickets**, not only unstarted ones. The admission test must
  therefore be `ready` **and** `status == open`, or a lane will be admitted for a ticket someone is
  already working.
- **Ticket frontmatter has a fixed observed shape** (`id`, `status`, `deps`, `links`, `created`,
  `type`, `priority`, `assignee`, `tags`). Whether `gtk query` passes an unknown `scope:` field
  through is **unverified**. If it does not, declared scope goes in `tags:` as
  `scope:<path>` entries, which are free-form strings and definitely survive.

## Prerequisites

1. **Publish executed** (D7) — the split must exist first. Simplified 2026-07-29: publishing goes
   straight to `main` in each repo, so **trunk is `main` from day one** and there is no promotion step to
   wait for. An intermediate design staged the collectors on a long-lived `openhound-port` branch, which
   would have made "the split exists" insufficient; that was dropped. See
   [`2026-07-27-publishing-and-repo-split-design.md`](2026-07-27-publishing-and-repo-split-design.md).
2. Trunk/CI friction fixed (F1, F2). Delivered by the publish work, whose step 2 adds a `ci.yml` to
   ConfigManBearPig running ruff plus a **named list** of offline-safe tests on `pull_request` — what F2
   found missing. Three caveats remain this harness's problem: **`validate-branch.yml` exists nowhere**
   (it is upstream OpenHound's file and neither target repo has it), so if the `feature/<name>` pattern
   matters for lane branches, this harness adds it; that `ci.yml` gate is a hand-maintained file list
   rather than the whole suite, so confirm what it actually covers before treating it as a gate; and it
   resolves `openhound` from the published floor (`>=0.2.12`) now that the publish work deleted the dev
   group's git URL, so a lane cannot rely on CI exercising an unreleased framework commit.
3. `gh` CLI installed and authenticated (F3). Listed as a publish prerequisite, so it should already be
   done — verify rather than assume.
4. One fresh lane measured for wall-clock and disk cost (F7).
5. `rr-cache` worktree-sharing confirmed.
6. `gtk` frontmatter extensibility confirmed, or the `tags:` fallback adopted. Note that `.tickets/`
   moves to ConfigManBearPig **wholesale** rather than being split three ways (the large majority of the
   109 are SCCM), so the claim set is per-repo where it matters and the shared library simply has no lane
   tickets — track shared-library work on the collector ticket that needs it, which is what D6/D8's
   atomic-pair model already assumes.

Two items this harness must still do itself, because the publish work deliberately left them alone as
lane-only concerns: **Task 1's document reflow** (3,842 lines whose sole benefit is reducing conflicts
between concurrent lanes) and **Task 3 Step 1's `dev`-recipe parameterisation** (so a lane points at its
own shared-library worktree — the F5 fix). The one piece already delivered is
`TICKETS-BY-STATUS.md merge=ours` in `.gitattributes`, which pays for itself immediately.

## Risks

- **A slow lane blocks the queue** (D2). Mitigation: the queue orders by readiness, not by ticket
  age, and a lane that cannot go green surrenders its slot rather than holding it.
- **Local-only green** (D6). Mitigation: the pin check at step 9 of the catch-up protocol.
- **Agent resolves a conflict plausibly but wrongly.** Mitigation: D5's dual artifacts, mandatory
  post-merge tests, and the escalation triggers.
- **The harness itself is new machinery.** Its first workload should not be irreversible repo
  surgery.
- **Live-lab validation cannot be automated.** No CI runner reaches `ps1-sms` or `dc.mayyhem.com`,
  so automated gates cover the offline layer only. Lab validation remains the owner's.
- **D11 bounds lanes by independence, not by resources.** Six cores running several lanes' pytest
  and DuckDB work will contend, and nothing in the design prevents it. Mitigation: a soft advisory
  ceiling surfaced when admitting a lane, rather than a hard cap that would defeat D11's purpose.
  The owner's review bandwidth is the other unbounded input.
- **Declared scope is only as good as the declaration.** A ticket that under-declares its scope
  weakens D11's admission test without any signal. Mitigation: the warn path in the lane lock logs
  every out-of-scope edit to the lane report, so systematic under-declaration becomes visible in
  review rather than staying hidden.
