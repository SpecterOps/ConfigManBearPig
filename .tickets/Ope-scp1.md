---
id: Ope-scp1
status: closed
deps: []
links: [ope-1f0f]
created: 2026-05-29T20:24:31Z
type: task
priority: 2
assignee: Mayyhem
tags: [sccm, audit, python, scope]
---

# Audit Variables Leaking Across Python Scopes

Audit the SCCM collector code for variables that are assigned inside branches, loops, or `try` blocks and then read later where Python's function-level scoping could preserve a stale value from a previous iteration or code path. This is especially important in collection logic that builds graph records from many entries, where one entry's value can silently bleed into the next.

## Design

Review the collector, preprocess, and convert stages for patterns such as:

- Variables assigned in an `if` / `elif` / `else` branch and used after the branch without a guaranteed reset.
- Variables assigned inside a loop and reused on the next iteration without being initialized to `None` or a fresh container at the top of the loop.
- Variables assigned inside `try` blocks and referenced after `except` / `continue` paths.
- Accumulators or temporary result objects that should be local to one record but are created outside the record loop.

Prefer restructuring code so the variable's lifetime is obvious. When restructuring would obscure the flow, explicitly initialize the variable to `None`, `{}`, or `[]` at the narrowest practical scope before it can be read.

## Acceptance Criteria

- No SCCM collector variable can retain stale per-record data across loop iterations or conditional paths.
- Any variable read after branch-local assignment is guaranteed to be initialized on every path.
- Per-record temporary values are initialized inside the per-record loop.
- Tests or focused review notes cover at least one representative collector path where stale values could affect emitted graph data.

## Notes

**2026-06-02T15:05:34Z**

Superseded by Ope-1f0f (all-encompassing code-quality pass). Variable-scope audit folded into that ticket.
