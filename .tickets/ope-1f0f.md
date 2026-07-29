---
id: ope-1f0f
status: in_progress
deps: []
links: [Ope-f3di, Ope-scp1]
created: 2026-06-02T15:05:20Z
type: task
priority: 2
---

# Code-Quality Pass: Conditional Logging, Exception Handling, Variable Scope, Linting & Cleanup -type chore -priority 2 -assignee Mayyhem -tags sccm,audit,cleanup,logging,scope,linting,best-practices -description Comprehensive code-quality pass over the entire sccm/sccm tree (collectors, context, source, and the preprocess/convert stages). Supersedes Ope-f3di (logging-branch audit) and Ope-scp1 (variable-scope audit), folding both into one cleanup effort.

Five areas to address:

1. Conditional logging: every non-trivial 'if' branch that skips a record, returns, or falls through should have an 'else'/'elif' (or inline) log statement explaining why. Use debug for optional/missing fields, warning for unexpected/degraded conditions, verbose for noisy per-entry paths. Skip pure entry guard clauses and tight inner loops that would flood output.

2. Exception handling: ensure exceptions are caught and handled at appropriate boundaries. No bare 'except:' clauses; catch specific exceptions, log them with context, and avoid swallowing errors silently. A per-record failure should log and continue rather than abort the whole collection.

3. Variable scope hygiene: variables assigned inside branches, loops, or try blocks must not leak stale values across iterations or code paths. Initialize per-record temporaries to None/{}/[] at the narrowest practical scope inside the record loop; guarantee any variable read after a branch-local assignment is initialized on every path.

4. Linting: the linter must pass cleanly on all touched files (per AGENTS.md tooling).

5. General cleanup: simplify and remove unnecessary code, improve readability per project best practices, and move logic to the preprocess/convert stages where it improves scalability and resource consumption. No backwards-compatibility constraints. -design Walk the whole sccm/sccm/src/openhound_sccm tree in a deterministic order (collectors/*.py, context.py, source.py, then preprocess and convert stages). For each file, make the five passes:

A. Conditional logging pass
- For each 'if'/'elif' block check whether the non-happy path emits a log. Add the appropriate level if not.
- logger.debug(f"...") f-strings for per-entry context; logger.warning("...", arg) percent-style for operator-visible messages (match existing style).
- Do NOT add logs to pure function-entry guard clauses (e.g. 'if not ctx.method_enabled(...)') or to tight per-entry loops where it would flood output (use verbose there).
- Known starting points carried over from Ope-f3di: ldap.py (site GUID 'if health:', 'if mp_hostname:', 'if mp_target:', 'if fsp_target:', 'if computer_dn:' bare continue, '_parse_sd_generic_all' SID extraction, 'if "," in dn:'); dns.py ('if name:' ADIDNS fallback, missing outer 'else' for 'if has_dnspython:'); context.py if/elif chains with unlogged return/continue paths.

B. Exception-handling pass
- Replace bare/over-broad excepts with specific exception types where practical.
- Ensure caught exceptions are logged with enough context to diagnose, and that per-record errors continue the loop instead of aborting.
- Remove try blocks that hide real failures.

C. Variable-scope pass (carried over from Ope-scp1)
- Variables assigned in an if/elif/else branch and used afterward without a guaranteed reset.
- Variables reused across loop iterations without being reset at the top of the loop.
- Variables assigned inside try blocks and referenced after except/continue.
- Accumulators/temp result objects that should be record-local but are created outside the record loop.
- Prefer restructuring so lifetime is obvious; otherwise initialize to None/{}/[] at the narrowest scope.

D. Linter pass
- Run the project linter/formatter (see AGENTS.md) and resolve all findings on touched files.

E. Cleanup pass
- Remove dead/unnecessary code, simplify control flow, improve naming and readability.
- Where it helps scalability/resource use, move logic into the preprocess/convert stages (per CLAUDE.md).
- Preserve the exact ordering of collector steps to match ConfigManBearPig.ps1. -acceptance - Every non-trivial 'if' branch that skips a record or exits without data emits a debug/verbose/warning log; no new info-level spam in tight loops.
- No bare 'except:' clauses; exceptions are caught specifically, logged with context, and per-record failures continue rather than abort collection.
- No SCCM variable retains stale per-record data across loop iterations or conditional paths; any variable read after branch-local assignment is initialized on every path; per-record temporaries are initialized inside the record loop.
- The linter passes cleanly on all touched files.
- Code is simplified/cleaned per best practices, with logic moved to preprocess/convert stages where it improves scalability; collector step ordering still matches ConfigManBearPig.ps1.
- Ope-f3di and Ope-scp1 are closed and referenced as superseded by this ticket.

## Notes

**2026-06-05T20:32:59Z**

Conditional-logging fix: register_target (context.py) returned None for two reasons - empty identifier or allow-list rejection - but every discovery caller logged a misleading 'Failed to register target' WARNING on the None path, duplicating the existing 'Skipping ... not in allowed targets filter' warning. Centralized the why-logging in register_target (empty -> debug, filtered -> existing warning) and removed the bogus else-warning at all ~10 call sites: dns.py x2, ldap.py x5 (incl. the inverted GenericAll site, now no unused assignment), local.py x3, registry.py x2. Also fixed register_target's wrong return annotation set[TargetEntry]|None -> Optional[TargetEntry] and updated its docstring. Net: exactly one accurate log line per skipped host. Suite: 138 passed, same 6 pre-existing baseline failures; ruff clean on changed lines.

**2026-07-21T14:03:31Z**

Umbrella for superseded-and-closed Ope-f3di (conditional-logging audit) and Ope-scp1 (variable-scope audit). Their scope must be covered here; reopened to in_progress on 2026-07-21 after status audit found only 1 of 5 cleanup areas complete.
