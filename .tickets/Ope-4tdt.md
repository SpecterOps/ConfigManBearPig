---
id: Ope-4tdt
status: closed
deps: []
links: []
created: 2026-05-28T13:30:04Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, collection, opsec]
---

# DCOnly Mode (--dc-only flag)

Add a --dc-only flag that restricts collection to Domain Controller queries (LDAP only, no remote host probing). In environments where running against hosts directly is too risky or noisy, operators want only what is available from the DC: System Management container, site objects, management point objects, computer accounts, group memberships.

## Design

Add --dc-only CLI flag to main.py. When set, force --collection-methods LDAP,DNS and skip all Phase 2/3 per-host collection. Skip TargetQueue loop entirely. Still run preproc and convert on LDAP-only data. Add startup message: DCOnly mode: collecting only from domain controller, skipping host-level probes. Preproc transforms already handle missing Phase 3 tables gracefully via CREATE TABLE IF NOT EXISTS pattern.

## Acceptance Criteria

--dc-only produces a valid graph output from LDAP data only. No TCP connections to any host other than the domain controller. Compatible with --disable-possible-edges.

## Notes

**2026-07-22T15:13:13Z**

2026-07-22 grilling refinements (design locked with Meatbag):
- Flag CONFLICT: --dc-only and -m/--collection-methods are MUTUALLY EXCLUSIVE -> fail fast with typer.BadParameter before the source is built. (-m defaults to None, so a plain --dc-only run never trips it.) --dc-only overrides a lower-precedence SOURCES__SCCM__COLLECTION_METHODS env var with a log (flags-beat-env).
- Stage-2 skip is a one-liner: force per_host_expected=False at ~main.py:1146 (the 'if per_host_expected:' gate) so _run_per_host_stage never starts the pool/bridge/emit drain; _log_collect_summary already renders correctly for no-per-host.
- collection_settings is UNGATED (local.py:233) so it still fires under -m LDAP,DNS and preproc keeps its disable_possible_edges flag. This is why forcing collection_methods=LDAP,DNS (not hand-filtering the resource list) is the clean approach: local_* self-skip, ldap_/dns_ run, collection_settings runs.
- Graph output decision: include EVERYTHING LDAP/DNS yields, incl. discovered-but-unprobed host nodes + LDAP edges (GenericAll on System Management). --computers still composes as the allow-list on discovery.
- VERIFY the ticket's 'preproc already handles missing Phase 3 tables gracefully' claim: coalesce SELECTs over absent/all-NULL columns can still throw BinderException (see memory sccm-dlt-coalesce-gotchas). Prove --run-all end-to-end against a real dc-only lookup.duckdb; harden transforms.py (except CatalogException -> empty) only where needed.
- DOCS: fix stale README line ~194 ('discovery resources are not gated by --collection-methods') — code DOES gate them (ldap.py/dns.py/local.py method_enabled) and --dc-only depends on that. Add ARCHITECTURE.md scoping subsection (method-gate + Stage-2 skip) + changelog entry.
- Superseded duplicate ope-3257 (deleted) — this ticket (Ope-4tdt) is canonical.

**2026-07-22T16:16:10Z**

Implementation plan written (writing-plans skill): docs/superpowers/plans/2026-07-22-dc-only-flag.md — 4 tasks (flag+helpers / --run-all tolerance verify+lock / docs / validation), TDD, no-commit green checkpoints.

**2026-07-31T15:34:57Z**

Status audit 2026-07-31: VERIFIED IMPLEMENTED IN CODE -> closing. Every element of the 2026-07-22 locked design is present in main.py: _resolve_dc_only_methods (main.py:321) forces LDAP,DNS and raises typer.BadParameter for the --dc-only + -m/--collection-methods conflict (main.py:335) exactly as the grilling settled; _should_run_per_host (main.py:341) returns False under --dc-only so _run_per_host_stage never starts the pool/bridge/emit drain; both are wired into collect_sccm (flag at main.py:1109, resolve at main.py:1177, per-host gate at main.py:1306, dc-only summary branch at main.py:1283). Docs done too: the stale README line claiming discovery resources are not gated by --collection-methods is gone, --dc-only appears 3x in README and 4x in ARCHITECTURE.md. Plan docs/superpowers/plans/2026-07-22-dc-only-flag.md executed.
