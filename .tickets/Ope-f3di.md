---
id: Ope-f3di
status: closed
deps: []
links: [ope-1f0f]
created: 2026-05-29T00:00:00Z
type: chore
priority: 3
assignee: Mayyhem
tags: [sccm, logging, observability]
---

# Logging Audit: Ensure All Conditional Branches Have Appropriate Log Messages

Systematically audit every `if` statement in the collector files for branches that silently skip, return, or continue without a log entry. Each non-trivial conditional path that exits or falls through should emit at least a `debug` or `warning` message so operators can tell at runtime *why* data was skipped — not just that the happy-path count was low.

## Design

Walk every `if` block in each file below. For each one, check whether the `else` / `elif` / implicit-fallthrough path has a log call. If not, add one at the appropriate level:

- `logger.debug(...)` — silently skipped because a field is missing or optional
- `logger.warning(...)` — skipped because of an unexpected/degraded condition
- `logger.verbose(...)` — noisy per-entry path that callers only want at high verbosity

**Files to audit (in order):**

1. `sccm/sccm/src/openhound_sccm/collectors/ldap.py`
   - `if health:` (site GUID extraction) — no `else` log when health string is absent
   - `if mp_hostname:` — no `else` log when mSSMSMPName is missing
   - `if mp_target:` — no `else` log when `register_target` returns `None` for an MP
   - `if fsp_target:` — no `else` log when `register_target` returns `None` for an FSP
   - `if computer_dn:` in `ldap_network_boot_servers` — bare `continue` with no log
   - `if sid_data:` / `if sid_str:` in `_parse_sd_generic_all` — no debug log when SID extraction fails for a given ACE
   - `if "," in dn:` — no debug log when dn has no comma (malformed DN)

2. `sccm/sccm/src/openhound_sccm/collectors/dns.py`
   - `if name:` in ADIDNS fallback loop — no `else` log when both `dNSHostName` and `name` are absent
   - `if has_dnspython:` — the outer `else` block is missing entirely; ADIDNS fallback runs but callers don't know the SRV path was skipped

3. `sccm/sccm/src/openhound_sccm/context.py`
   - Audit any `if`/`elif` chains where a return or continue path produces no log

**Do not** add log calls to:
- Pure guard clauses at function entry (`if not ctx.method_enabled(...)`) — those are already documented by the existing `return`
- Tight inner loops where per-iteration logging would flood output (use existing `verbose` level there)
- Library/parser helper functions where callers log the result (`_parse_sd_generic_all`, `_parse_mp_capabilities` internals)

## Acceptance Criteria

- Every non-trivial `if` branch that skips a record or exits a loop without data emits a `debug`, `verbose`, or `warning` log.
- No new `info`-level log spam in tight per-entry loops; use `debug` or `verbose` there.
- `logger.debug(f"...")` f-strings are used for per-entry context, `logger.warning("...", arg)` percent-style for operator-visible messages (matches existing style).
- Running with `--log-level DEBUG` allows an operator to trace exactly which entries were skipped and why.

## Notes

**2026-06-02T15:05:34Z**

Superseded by Ope-1f0f (all-encompassing code-quality pass). Logging-branch audit folded into that ticket.
