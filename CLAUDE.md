# AGENTS.md - Agent Guidance

This file should always be used as the entrypoint for agents working in this repository. Keep it generic and concise.
Project-specific standards live under `.agents/standards/` and task-specific guidance lives in the relevant skill files
under `.agents/skills/`.

## Before Editing

- Read `.agents/standards/openhound.md` before making OpenHound collector changes.
- Read `.agents/standards/workflow.md` before developing a new collector or making broad collector changes.
- Read `ARCHITECTURE.md` before touching any cross-cutting collector subsystem (the per-host phased
  pipeline, recursive discovery / target allow-list, the Windows authentication stacks under `clients/`,
  the logging/diagnostics layer, the Windows-specific fixes, or the preproc/convert design). It explains
  how and why this extension diverges from a stock OpenHound (REST-API-only) collector. **Update the
  relevant section of `ARCHITECTURE.md` in the same change** whenever you alter one of those subsystems,
  and fix any `file:line` references your change invalidates. Add a new section if you introduce a new
  category of divergence.
- **`openhound-collector-common` is a separate published package — treat it exactly like `openhound`
  core.** The Windows auth stacks, the per-target logging layer, the push→pull streaming bridge
  (`StreamBridge`), and the DNS resolver *live there*, shared with the MSSQL collector; this repo's
  `clients/*`, `log_context.py`, and `phased_pipeline/streams.py` are thin adapters/re-exports over it
  (see `ARCHITECTURE.md` → "Where this code lives"). It is declared as a capped version range in
  `[project.dependencies]`; `[tool.uv.sources]` optionally redirects it to a sibling checkout at
  `../openhound-collector-common` for local work, and that redirect never reaches the published wheel.
  Trace into the library to understand behaviour, but **do not treat editing it as part of a change
  here** — it affects both collectors and it releases on its own tag. If a task seems to need a
  shared-library change, stop and say so.
- Load the `openhound` skill from `.agents/skills/openhound/` for task-specific workflows.

## Task Skill

Use `openhound` for all OpenHound collector work. The skill routes tasks to action-specific references.

| Task                                                                                   | Skill       | Reference |
|----------------------------------------------------------------------------------------|-------------|---|
| Plan a new collector from target service requirements or API docs                      | `openhound` | `.agents/skills/openhound/references/plan-collector.md` |
| Add or modify a collected asset/model                                                  | `openhound` | `.agents/skills/openhound/references/add-asset.md` |
| Implement API collection resources, transformers, auth and DLT source wiring           | `openhound` | `.agents/skills/openhound/references/source-collection.md` |
| Define base graph node/edge dataclasses and ID generation behavior                     | `openhound` | `.agents/skills/openhound/references/graph-schema.md` |
| Add DuckDB transforms or lookup methods                                                | `openhound` | `.agents/skills/openhound/references/preproc-lookup.md` |
| Wire phase registration (collect, preproc, convert), metadata, or package entry points | `openhound` | `.agents/skills/openhound/references/register-extension.md` |
| Validate a collector before finishing                                                  | `openhound` | `.agents/skills/openhound/references/validate-extension.md` |

## General Rules

Behavioral guidelines. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

### 5. Protect User State

**Do not disturb the user's local environment or unrelated work.**

- Use an isolated uv virtual environment outside the repository for validation commands, for example `UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest`.
- Do not create, remove, rebuild, or modify the repository-local `.venv` unless explicitly asked.
- Do not revert, rewrite, or clean up unrelated worktree changes.
- Do not remove files or code that are outside the task scope unless they are made obsolete by your own changes.
- If a validation command would alter user state or require credentials/external services, report that instead of forcing it.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and
clarifying questions come before implementation rather than after mistakes.

---

# Project Conventions

Carried over from the development fork when this repository became the collector's home.

## Tickets

Work is tracked with a CLI ticket system whose files live in `.tickets/`. Run `gtk help` for the
commands. Update `TICKETS-BY-STATUS.md` after changing any ticket's status — that file is generated
from `gtk list`, so never hand-edit it as a source of truth.

`.gitattributes` marks it `merge=ours`. That attribute needs a one-time
`git config merge.ours.driver true` in each clone, because `ours` is not one of git's built-in merge
drivers and `.git/config` cannot be committed.

## Logging

Write a log line of the appropriate level (error, warning, info, verbose, debug) for every `if`/`else`
and `try`/`except` branch, unless there is genuinely nothing to say — in which case leave a comment
explaining why. A branch that silently swallows a failure is the defect this rule exists to prevent:
an AdminService read timeout once surfaced only as `Collected 0 stored accounts`, making an incomplete
graph indistinguishable from an accurate one.

## Tests

Tests live in `tests/` and stay organised there. Most of the suite is offline; a minority needs a live
SCCM hierarchy and is skipped without one.

Validate a change with the specific test files it affects rather than the whole suite — it is faster and
the failure is easier to read. Before finishing, run the four files `ci.yml` runs, since those are the
gate a pull request has to pass:

```powershell
uv run pytest tests\extension_metadata_test.py tests\integration_wiring_test.py `
    tests\convert_pipeline_test.py tests\integration_fixtures_test.py -q
uv run ruff check src tests
uv run mypy src\openhound_sccm
```

For a change to preprocess or convert, the strongest cheap check is to re-run both stages over a cached
collection bucket and diff the emitted graph — it holds collection constant so only your change moves.
`PUBLISHING.md` step 1 has the commands.

## Documentation

`README.md` is the user-facing document and is **code-truth above all else**: if the code and the README
disagree, the README is wrong. It documents the full CLI surface, but only the nodes and edges the
collector actually emits — no aspirational entries.

Update it in the same change as any user-facing behaviour, with practical, copy-pasteable examples.
Its sections are: Logo/Intro · Table of Contents · Quick Start · Collection Overview · System
Requirements · Limitations · Command Line Options · Graph Model · Node Reference · Edge Reference ·
Understanding the Codebase · Testing Changes · Contributing.

`ARCHITECTURE.md` explains how and why this collector diverges from a stock OpenHound collector, and
carries a changelog. Add an entry there for anything that changes a cross-cutting subsystem.

## Schema files

`src/openhound_sccm/schema_SCCM.json` and `schema_MSSQL.json` are **hand-maintained** and must stay in
sync with `kinds/nodes.py` and `kinds/edges.py` in both directions. Two files, deliberately: this
collector emits `MSSQL_*` kinds (site-server SQL topology) as well as `SCCM_*` ones, and the `MSSQL_*`
kinds belong to the MSSQL schema even though this collector produces them.

Both ship inside the package because they are read at runtime — `integration/__init__.py` loads
`schema_SCCM.json` for the test kit's coverage check. Any runtime data file must live inside
`src/openhound_sccm/`: a path resolved above the package works in a checkout and vanishes once
installed.
