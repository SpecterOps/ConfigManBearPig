# Multi-Agent Concurrency Harness — Implementation Plan

Spec: `docs/superpowers/specs/2026-07-29-multi-agent-concurrency-design.md`
Decisions D1–D12 and findings F1–F8 are defined there and are not restated here.

---

## Global Constraints

Copy these into every task's mental checklist:

- **Post-split only (D7).** Every path below is relative to a **post-split repo root**. What is
  `sccm/sccm/` today becomes the root of `SpecterOps/ConfigManBearPig`; `openhound-collector-common/`
  becomes its own repo root. **This plan cannot start until the publish runbook (`PUBLISHING.md`) has
  been executed through its fork-cleanup step.**
- **Trunk is `main`** in each repo, with `origin/HEAD` correct and CI firing on it (D4). The owner
  fixes this first; no task here works around its absence.
- **Nothing in this plan touches OpenHound core.** The shared read-only `OpenHound/` checkout is
  never written to — that is precisely why it is safe to share across lanes (F5).
- **Every hook, script, and doc added here must work on Windows** (PowerShell primary, Git Bash
  available). Git hooks are invoked by git's own shell, so they are POSIX `sh`.
- **Logging:** every `if`/`else` and `try`/`except` in any script gets an appropriately-levelled log
  unless truly needless, in which case a comment.
- **Targeted tests only** — never the full suite.
- **Docs are code-truth.** Operator documentation ships with the task that makes it true.
- Tasks 0 and 1 are **independent of the split** and can be done at any time. Everything from
  Task 2 onward assumes post-split layout.

---

## Task ordering and why

```
Task 0  Prerequisite verification        <- independent; do first, it can invalidate later tasks
Task 1  Conflict prevention: documents   <- independent; the highest value-per-effort work here
Task 2  Ticket scope declarations        <- Tasks 4 and 7 read these
Task 3  Lane lifecycle tooling           <- Task 4's hooks are installed into what this creates
Task 4  Enforcement hooks                <- needs Task 2 (scope) + Task 3 (worktrees)
Task 5  Catch-up and merge protocol      <- needs Task 3
Task 6  Post-merge semantic gate         <- needs Task 5 (it is the gate inside the protocol)
Task 7  Lane admission                   <- needs Task 2
Task 8  Operator documentation           <- needs everything above to be true
```

---

## File Structure

**Created — each collector repo (`ConfigManBearPig`, `MSSQLHound`):**
- `.gitattributes` — per-file-kind merge strategy (Task 1).
- `scripts/lane/new-lane.sh` — create a lane's paired worktrees and wire its venv (Task 3).
- `scripts/lane/end-lane.sh` — tear a lane down, refusing if it holds unmerged work (Task 3).
- `scripts/lane/catch-up.sh` — the D2/D5/D8 catch-up protocol (Task 5).
- `scripts/lane/semantic-gate.sh` — the D12 post-merge checks (Task 6).
- `scripts/lane/admit.sh` — the D11 admission test (Task 7).
- `scripts/hooks/pre-commit`, `scripts/hooks/pre-push` — D10 enforcement, installed per worktree
  by `new-lane.sh` (Task 4).
- `scripts/tickets/regen-index.sh` — regenerate `TICKETS-BY-STATUS.md` from `.tickets/*.md` (Task 1).
- `docs/CONCURRENCY.md` — the operator runbook (Task 8).
- `docs/MERGE-CONFLICTS.md` — the agent-facing conflict runbook (Task 8).

**Modified:**
- `README.md`, `ARCHITECTURE.md` — reflowed to one sentence per line (Task 1).
- `TICKETS-BY-STATUS.md` — becomes generated output, not an authored file (Task 1).
- **Per-lane shared-library redirection** so a lane points at its **own** shared-library worktree rather
  than the fixed `../openhound-collector-common` in the committed `[tool.uv.sources]` (Task 3). This is
  the D6/F5 fix. There is no `justfile` to parameterise — the publish work deleted the task runner — so
  the mechanism is a `UV_*` environment variable or a per-worktree `uv.toml`, and choosing between them
  is this plan's design work. The verification is unchanged and is what matters: editing the shared
  library in lane A provably does not change what lane B imports.
- `CLAUDE.md` / `AGENTS.md` — the no-commit rule replaced with the D3 rule, and the grill-me path
  corrected (Task 8).

---

## Overlap with the publish work (reconciled 2026-07-29)

The publish work is a prerequisite ([design](../specs/2026-07-27-publishing-and-repo-split-design.md)),
and it was simplified to publish straight to `main` — so trunk is `main` from day one and there is no
promotion step gating this harness.

Three items of overlap, resolved as follows:

| Item | Status |
|---|---|
| **Task 0 Step 1** — install `gh` | Listed as a publish prerequisite; verify rather than repeat |
| **Task 1** — doc reflow + generated ticket index | **Stays here.** Only the `.gitattributes` line `TICKETS-BY-STATUS.md merge=ours` was taken forward, because that file is generated and its longest line is ~3,500 chars. The 3,842-line reflow was deliberately left, since its sole benefit is reducing conflicts between concurrent lanes — which is this project |
| **Task 8 Steps 4–5** — grill-me path fix, stranded root docs | **Done by the publish work**, which authors a per-repo `CLAUDE.md` (the fork-root one does not survive the split) and relocates the six orphaned specs/plans |

The two projects were kept separate on purpose. This plan's own risk list warns that *"the harness itself
is new machinery — its first workload should not be irreversible repo surgery,"* and folding it into the
publish work would make the repo split exactly that. They also carry opposite risk profiles: publishing
is externally visible and partly irreversible (PyPI filenames are immutable), while this harness is
reversible internal tooling.

---

## Task 0: Prerequisite verification

Five open assumptions. Each is cheap to test and each can invalidate a later task, so none may be
assumed.

- [x] **Step 1 — Install and authenticate `gh`** (F3). **ABSORBED** into the publish plan as a
      prerequisite (D20) — its D15 "PR the removal" needs `gh` too. Confirm with `gh auth status` and
      `gh pr list`; if it is already done, this step is a no-op.
- [ ] **Step 2 — Measure one fresh lane** (F7). Create a throwaway worktree, run the lane `dev`
      recipe, and record wall-clock time and actual disk delta. The measured venvs total ~813 MB,
      but uv should mostly hardlink from its cache on the same NTFS volume — **verify rather than
      assume.** If a lane costs minutes and hundreds of megabytes, D11's dynamic lane count needs a
      lower advisory ceiling.
- [ ] **Step 3 — Confirm `rr-cache` is shared across worktrees.** Enable `rerere`, create a
      conflict in one worktree, resolve it, then reproduce the same conflict in a second worktree of
      the same repo and check whether the resolution replays. If it does **not** share, every lane
      must be seeded with the resolution database explicitly and Task 5 changes accordingly.
- [ ] **Step 4 — Test `gtk` frontmatter extensibility.** Add `scope: ["src/x"]` to a scratch ticket
      and run `gtk query`. If the field survives, Task 2 uses it. If it is dropped, Task 2 falls
      back to `tags: [scope:src/x]`, which is free-form and definitely survives.
- [ ] **Step 5 — Confirm the admission filter.** `gtk ready` lists `in_progress` tickets as well as
      unstarted ones, so verify that `gtk ready` intersected with `status == open` yields only
      genuinely unclaimed tickets.

**Verification:** all five answers written into the spec's Prerequisites section, replacing the
"unverified" markers.

---

## Task 1: Conflict prevention — documents (D9)

The highest value-per-effort work in this plan, and independent of the split. F4 is the repo's worst
merge surface and none of it is code.

> **Step 3's `.gitattributes` line for `TICKETS-BY-STATUS.md` is already done** by the publish work —
> it pays for itself even with one developer. Steps 1 and 2 remain here. Note the reflow is **3,842
> lines**, not the ~3,300 stated below (`README.md` is 1,868 lines / 2,821 chars at its longest;
> `ARCHITECTURE.md` is 1,974), and the verification command needs fixing: `git diff --ignore-all-space`
> ignores whitespace *within* a line, not inserted newlines, so it will report every touched line.
> Compare normalized text instead — e.g. `tr '\n' ' ' | tr -s ' '` on both sides.
>
> Cheapest option for Step 1: **delete `TICKETS-BY-STATUS.md`** rather than writing a generator for it.
> It is a derived duplicate of `gtk list`.

- [ ] **Step 1 — Make `TICKETS-BY-STATUS.md` genuinely generated.** It already declares itself
      generated from `.tickets/*.md`. Write `scripts/tickets/regen-index.sh` that rebuilds it from
      `gtk query` output, and add to `.gitattributes`:
      ```
      TICKETS-BY-STATUS.md  merge=ours
      ```
      so git never attempts to merge a derived file. Regenerating after each land replaces merging.
      Update CLAUDE.md's instruction from "update the index" to "regenerate the index."
- [ ] **Step 2 — Reflow the long-line Markdown.** `README.md` (1,645 lines, longest 2,703 chars) and
      `ARCHITECTURE.md` (1,698 lines, longest 1,914 chars) go to one sentence per line. Rendered
      output is identical; git's 3-way merge starts working on them.
      **This must be a standalone commit that changes nothing but line breaks**, so it can be
      reviewed by confirming the rendered output is unchanged rather than by reading 3,300 lines.
      Verify with a whitespace-insensitive diff.
- [ ] **Step 3 — Declare merge strategies for the remaining file kinds.** Authored prose keeps the
      default 3-way merge. `merge=union` **only** for genuinely append-only lists — never prose,
      where it silently duplicates and garbles sentences instead of conflicting. Binary and
      generated artifacts get `-merge` so they conflict loudly rather than being corrupted.

**Verification:** two lanes edit different sentences of the same README paragraph and merge cleanly;
two lanes both change ticket statuses and produce no index conflict.

---

## Task 2: Ticket scope declarations (D9, D11)

- [ ] **Step 1 — Add a scope field to the ticket template**, using whichever mechanism Task 0
      Step 4 proved works. Paths are repo-relative globs, e.g.
      `scope: ["src/openhound_sccm/preprocess/**", "tests/transforms_test.py"]`.
- [ ] **Step 2 — Write the claim-set query.** A helper that emits the union of declared scopes for
      all `in_progress` tickets — the "currently claimed files" set that Tasks 4 and 7 both consume.
- [ ] **Step 3 — Backfill scope onto the open tickets** that are realistic near-term lane
      candidates. Do not backfill all 108; that is busywork.

**Verification:** the claim-set query on a known pair of in-progress tickets returns exactly their
declared paths, and the intersection test correctly reports overlap and non-overlap.

---

## Task 3: Lane lifecycle tooling (D6)

This is where F5 is either fixed or silently reintroduced.

- [ ] **Step 1 — Parameterise the `dev` recipe.** Today it hardcodes
      `uv pip install -e ../openhound-collector-common`, which resolves to a shared checkout and
      leaks uncommitted edits between lanes. It must instead install the **lane's own**
      shared-library worktree. The read-only `-e ../OpenHound` install stays shared — safe because
      it is never written.
- [ ] **Step 2 — Write `new-lane.sh <ticket-id>`.** It must:
      1. refuse if the admission test (Task 7) fails;
      2. create a worktree of the collector repo on `feature/<ticket-id>` — note the branch-name
         pattern `^(fix|patch|feature|minor|major)/<name>$` that `validate-branch.yml` enforces, so
         `lane/<id>` would be rejected but `feature/<id>` passes;
      3. create the paired shared-library worktree on the same branch name;
      4. run the lane-local `dev` recipe;
      5. install the hooks from Task 4 into **both** worktrees;
      6. assert the venv is wired to the lane-local shared library, not the shared checkout —
         a positive check, not an assumption, because the failure mode is silent;
      7. `gtk start` the ticket so it enters the claim set.
- [ ] **Step 3 — Write `end-lane.sh <ticket-id>`.** Refuse to remove a worktree holding uncommitted
      changes or unmerged commits. Report what is unmerged instead of destroying it.

**Verification:** two lanes created simultaneously; editing the shared library in lane A provably
does **not** change what lane B's tests import. This is the F5 regression test and it is the single
most important check in the plan.

---

## Task 4: Enforcement hooks (D10)

Hard-block what is never correct; warn on what is a legitimate judgement call; hard-block scope
violations **only** where another live lane holds the file.

- [ ] **Step 1 — `pre-commit`:** refuse if `HEAD` is the trunk branch. Refusing at commit time is
      what makes the trunk mistake unrecoverable-proof rather than merely detectable.
- [ ] **Step 2 — `pre-push`:** refuse pushing to trunk; refuse force-pushing a branch that has an
      open PR (that would erase commits the owner has already read).
- [ ] **Step 3 — The lane lock:** for each file being committed, if it falls outside the ticket's
      declared scope:
      - not claimed by another active lane → **warn**, and append to the lane report;
      - claimed by another active lane → **hard block**, naming the ticket holding it.
- [ ] **Step 4 — Make `--no-verify` visible.** Hooks cannot prevent their own bypass, so the value
      is in detection: the catch-up protocol re-checks the invariants the hooks enforce, so a
      bypassed hook surfaces at land time rather than never.

**Verification:** each blocked action is attempted and refused; a warn-path edit appears in the lane
report; a claimed-file edit is blocked and names the holding ticket.

---

## Task 5: Catch-up and merge protocol (D2, D5, D8)

- [ ] **Step 1 — Enable `rerere`** in both repos, per Task 0 Step 3's finding.
- [ ] **Step 2 — Write `catch-up.sh`**, implementing the spec's 13-step protocol: fetch both repos;
      merge trunk into the **shared library first** (it is the dependency), then the collector;
      let `rerere` replay known resolutions; resolve the rest; write the report; run the Task 6
      gate; run the pin check; push both branches.
- [ ] **Step 3 — Implement the pin check.** D6 means a lane can be green against local
      shared-library code that no published version contains. Verify the lane also passes against
      the pinned dependency range, so the collector is not shipped depending on code
      `>=0.1.0,<0.2.0` cannot satisfy.
- [ ] **Step 4 — Generate the resolution report** — per conflicted file: what each side wanted, what
      was chosen, and why. This is the human-readable half of D5; the merge commit is the
      machine-verifiable half, and cross-checking them catches an agent that misdescribes its own
      resolution.
- [ ] **Step 5 — Implement the queue slot.** One lane lands at a time. A lane that cannot go green
      **surrenders its slot** rather than holding it, so one stuck lane cannot block the queue.

**Verification:** two lanes deliberately conflict; the second catches up, resolves, reports, and its
merge commit shows the resolution under `git show`. Repeat the same conflict in a third lane and
confirm `rerere` replays it.

---

## Task 6: Post-merge semantic gate (D12)

The gate exists because a clean merge is not evidence of a correct merge. It therefore **runs even
when the merge reported no conflicts at all** — that is the whole point, and it is the rule that
"the merge succeeded" argues hardest against.

- [ ] **Step 1 — Run the lane's own targeted tests.**
- [ ] **Step 2 — Run the tests belonging to the trunk change just merged.** The only check that can
      catch this lane's resolution breaking another lane's feature.
- [ ] **Step 3 — Symbol-existence check.** For every symbol the lane calls that the merged trunk
      change touched, confirm it still exists. Catches the rename-versus-new-caller case that git
      merges perfectly cleanly.
- [ ] **Step 4 — Behavioural transform diff.** When `transforms.py` is touched, re-run `transforms()`
      over a copy of a live `lookup.duckdb` and diff the output, per established house practice.
      This is the only check that catches the DuckDB `coalesce` class of semantic conflict, where a
      dropped or absent column raises `BinderException` and takes an entire source with it.
- [ ] **Step 5 — Graph-contract consistency check.** Assert `schema.json` and `kinds.py`/`edges.py`
      still agree. Two lanes editing them separately merge cleanly into a desynced pair, and the
      symptom is bad graph data rather than a failing test.

**Verification:** construct each of the four semantic-conflict classes from the spec as a
deliberately clean merge, and confirm the gate catches every one.

---

## Task 7: Lane admission (D11)

- [ ] **Step 1 — Write `admit.sh <ticket-id>`:** admit only if the ticket is in `gtk ready` **and**
      its status is `open` (per Task 0 Step 5 — `gtk ready` alone includes `in_progress`), **and**
      its declared scope does not intersect the claim set.
- [ ] **Step 2 — Report refusals usefully.** On overlap, name the conflicting ticket and the
      specific paths. That turns a merge conflict into a scheduling conversation before any code is
      written, which is the entire value of D11.
- [ ] **Step 3 — Add a soft resource ceiling.** D11 bounds lanes by independence, not by CPU. Six
      cores running several lanes' pytest and DuckDB work will contend. Warn when admitting beyond
      a configurable number; do not hard-cap, which would defeat D11's purpose.

**Verification:** overlapping tickets are refused with a useful message; disjoint tickets are
admitted; the soft ceiling warns without blocking.

---

## Task 8: Operator and agent documentation (D8, and CLAUDE.md corrections)

- [ ] **Step 1 — `docs/CONCURRENCY.md`** — the owner runbook: starting and ending a lane, the
      landing sequence for an atomic pair (shared library first, collector immediately after), what
      to look for when reviewing a resolution report against its merge commit, and how to recover
      from a lane abandoned mid-flight.
- [ ] **Step 2 — `docs/MERGE-CONFLICTS.md`** — the agent-facing runbook: the conflict taxonomy, the
      resolution rules (resolve hunk by hunk; never `--ours`/`--theirs` on a whole file; never
      resolve by deleting the other side; read the other lane's ticket rather than guessing;
      regenerate generated files instead of merging them), and the escalation triggers.
- [ ] **Step 3 — Replace the no-commit rule in CLAUDE.md/AGENTS.md** with D3: agents commit and push
      their own lane branch; agents never write to trunk; PR review is the gate.
      **Note:** the publish runbook now *authors* per-repo `CLAUDE.md` and `AGENTS.md` files (the
      fork-root copies sit above the archived prefix, so they do not travel) and deliberately keeps the
      no-commit rule in them, because this is the right place to change it. So this step edits existing
      per-repo files rather than creating them.
- [x] **Step 4 — Fix the `grill-me` path.** **ABSORBED** into the publish runbook's post-move fix-ups:
      it authors the per-repo `CLAUDE.md` files, so fixing the path there is free and fixing it later
      would mean editing three repos. Context: `CLAUDE.md` lists grill-me as the highest-priority skill
      and points it at `.agents/skills/openhound/SKILL.md` — the *openhound* skill's path. grill-me is in
      fact the second front-matter block inside that same file, so every subagent fails to resolve it and
      silently improvises.
- [x] **Step 5 — Relocate the stranded root docs** (F8). **ABSORBED** into the publish runbook's
      repo-assembly step, which copies the fork root's six SCCM-topic plans and specs into the new repo.
      Doing it there rather than as a follow-up ticket matters: after the split the fork is abandoned, so a
      deferred ticket would point at files nobody maintains.

**Verification:** a fresh agent, given only CLAUDE.md and these two runbooks, can create a lane,
hit a conflict, resolve it within the rules, and land — without asking how the harness works.

---

## Self-Review

- **Task 1 is independent of everything else** and can ship immediately for real value, even if the
  rest of this plan is deferred. It is also the only task that reduces conflicts for the *current*
  single-lane workflow.
- **Task 3's verification is the linchpin.** If the F5 regression test does not exist and pass,
  every other guarantee in this plan sits on top of lanes that silently share mutable state.
- **Task 0 can invalidate Task 5.** If `rr-cache` is not shared across worktrees, resolutions do not
  compound across lanes and the protocol needs an explicit seeding step.
- **The plan does not attempt live-lab validation.** No automation reaches `ps1-sms` or
  `dc.mayyhem.com`; the gate covers the offline layer only, and lab validation stays the owner's.
- **Deliberately excluded:** GitHub merge-queue configuration, since the owner is fixing trunk and
  CI separately (D4) and the queue here is operated locally; and any change to OpenHound core.
- **Known incompleteness:** Task 2 Step 3 backfills scope onto only near-term candidate tickets, so
  admitting a lane for an un-backfilled ticket needs its scope declared first. That is a deliberate
  scoping choice, not an oversight.
