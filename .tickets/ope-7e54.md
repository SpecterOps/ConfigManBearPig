---
id: ope-7e54
status: closed
deps: [ope-0112]
links: []
created: 2026-06-03T19:29:20Z
type: task
priority: 2
---

# Implement RemoteRegistry per-host collector -type task -priority 2 -description Port Invoke-RemoteRegistryCollection from ConfigManBearPig.ps1 into the per-host pipeline framework (ope-0112), replacing the RemoteRegistry stub with the real collector and its table/model(s).

## Notes

**2026-06-05T18:13:58Z**

debug_per_host.py: seed hosts now register via ctx.register_target(host, source='CLI') after ctx is built (was bare wq.submit before ctx existed). This populates ctx.target_hosts_by_hostname so collect_registry's direct ctx.target_hosts_by_hostname[target] lookup (registry.py:305) resolves, simulating post-LDAP/DNS state. Seeds are now subject to the ALLOW_LIST filter, matching the real CLI flow (main.py:946-948).

**2026-06-05T18:53:58Z**

CurrentUser SID collection bug fixed (found during live test against ps1-pss.mayyhem.com).

Root causes in collectors/registry.py:
1. collect_registry selected the whole (name, data) tuple from read_values() instead of the value DATA, then passed the tuple to ctx.resolve_principal -> AttributeError: 'tuple' object has no attribute 'strip'. Now selects the value data, mirroring PS1 ($result.Values | Select-Object -Index N, ConfigManBearPig.ps1:5006-5009).
2. read_values logged false ERROR lines: impacket NDR auto-unwraps lpValueNameOut to a plain str, so name_field[Data] always raised TypeError; and normal end-of-enumeration (ERROR_NO_MORE_ITEMS) was logged at ERROR. Both now handled silently, mirroring enum_keys().
3. Latent crash: read_values returns None when the key cannot be opened, but collect_registry called len(values) -> would crash on hosts lacking the key. Now guarded.

Also applied exact PS1 parity for value counting: only values with non-empty data count (PS1 `if ($value)`), index 0 for one value / index 1 for two, warn on any other count.

Tests: sccm/sccm/tests/test_registry_current_user.py (5 cases, all pass). Pre-existing unrelated failures in test_extension_methods + test_per_host_integration confirmed present on HEAD (missing @app.convert; stub table writes) - not caused by this fix.

**2026-06-05T19:23:48Z**

Follow-up fixes after live-test review (registry.py, context.py, debug_per_host.py):

#5 Triple AD-resolution warning consolidated (context.py register_target): one failed resolution emitted 3 near-duplicate WARNINGs. Now: exception cause -> verbose; redundant using raw identifier removed; single adding target by name warning retained.

#6 Multisite Component Servers dead code fixed (registry.py): the local-DB branch (len==0) was unreachable inside `if subkeys:` and would not have emitted a row anyway (loop over empty list). Now distinguishes enum_keys None (key absent -> skip) / [] (empty -> site DB local to site server; this host gets SMS SQL Server + SMS Site Server roles) / [names] (remote SQL DB servers). Mirrors ConfigManBearPig.ps1:4854-4928 intent (PS1 itself can't reach the empty case due to PowerShell empty-array-falsy).

Resolution investigation: hosts failing AD resolution in the debug harness was NOT the target filter (allow-list was empty = allow-all; hosts were Added, not Skipped; resolution runs before filtering). Root cause: debug_per_host.py passed ad=None, so every resolve_principal hit None.paged_search. Fixed by wiring ADClient(ADCredentials(domain=DOMAIN, username, password)) into the harness -> binds as current Windows user via SSPI when no creds, like the CLI. Also de-scratched the harness docstring (it is staying) and removed stale no AD / stub phases claims.

Note: enum_keys ERROR->verbose and Triggers misleading-warning->verbose+early-return were fixed by the user directly. The early return means CurrentUser is now only collected on hosts with a site code.

Tests: tests/test_registry_current_user.py now 8 cases (5 CurrentUser + 3 multisite), all pass. Full suite: 134 passed, 6 pre-existing unrelated failures (test_extension_methods @app.convert + test_per_host_integration stubs).

**2026-06-05T19:59:38Z**

Follow-up: CurrentUser SID was still mis-selected on live host ps1-pss.mayyhem.com — resolved to "1" (the Session DWORD) instead of the domain SID.

Root cause: the prior value-count heuristic (1 value -> index 0, 2 values -> index 1; mirroring ConfigManBearPig.ps1:5006-5009) selects by enumeration POSITION. The CurrentUser key holds Session (REG_DWORD=1) + UserSID (REG_SZ=SID); the registry returned UserSID at index 0 and Session at index 1, so index-1 grabbed "1". PS1 has the same latent fragility (hashtable .Values ordering is not guaranteed).

Fix (registry.py collect_registry): select the value named "UserSID" (case-insensitive) from read_values() instead of by position. Immune to enumeration order — the sibling Session DWORD can never be chosen. Kept read_values rather than the dead read_value helper (whose except logs ERROR, wrong level for "no interactive user"). Branch logging: key-open failure -> error; key present but no UserSID -> info.

Tests (test_registry_current_user.py): replaced the count-based cases with name-based ones (9 total incl. multisite): UserSID-before-Session regression (the live bug), single UserSID, case-insensitive name match, empty UserSID data, only-Session-present, read_values None. All 9 pass.

debug_per_host.py: collapsed SEED_HOSTS + ALLOW_LIST into one COMPUTERS variable mirroring --computers (which does double duty in the CLI: main.py:716-720 seeds, source.py:213-225 builds allowed_targets). Each entry is both a seed and the allow-list, expanded to FQDN + short-name forms, lowercased. Empty -> allow-all but no seeds = no-op. Fixes the reported "harness not skipping discovered hosts" — only hosts in COMPUTERS are collected; discovered hosts outside it are rejected by register_target.

Flagged (not fixed): source.py --computers allow-list isn't lowercased (the computer_file branch is), while _is_allowed_target compares lowercased candidates -> uppercase --computers values would silently not match.

Verified the 6 pre-existing failures (test_extension_methods @app.convert + test_per_host_integration stub tables) fail identically at HEAD via git stash — not caused by this change.

**2026-06-05T20:10:33Z**

Follow-up fix (source.py): --computers allow-list now lowercased.

Bug: source.py built allowed_targets from --computers WITHOUT lowercasing (only the --computer-file branch lowercased), but SourceContext._is_allowed_target compares lowercased candidates (context.py:228) -> an uppercase --computers value silently never matched and the host was wrongly skipped.

Fix: extracted _expand_allowed_targets(names) -> set (lowercase each + add short-name form) and routed BOTH --computers and --computer-file through it, so the two branches cannot drift apart again. Added a logger.warning when a --computer-file path does not exist (was silently ignored). debug_per_host.py now reuses the same helper instead of its own inline copy.

Tests: tests/test_allowed_targets.py (3 cases: lowercases+adds short-name, strips/skips blanks, uppercase --computers still matches a lowercased target via _is_allowed_target). ruff clean on changed files; mypy source.py clean; full suite 138 passed, same 6 pre-existing unrelated failures (test_extension_methods @app.convert + test_per_host_integration stubs).
