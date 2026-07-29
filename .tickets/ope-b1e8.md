---
id: ope-b1e8
status: closed
deps: []
links: []
created: 2026-07-20T14:33:28Z
type: bug
priority: 3
tags: [sccm, cli, collect]
---

# Dead collect flag: --sms / --sms-provider accepted but ignored

The --sms / --sms-provider CLI flag on 'openhound collect sccm' is accepted and forwarded into source() but never actually read there, so it does nothing for scoping a run to a specific SMS provider. -c/--computers is what actually seeds a specific host. Found incidentally during ope-b916 live validation against ps1-sms. Either wire --sms into source()'s target seeding or remove/deprecate the flag and document -c as the scoping mechanism. Pre-existing, unrelated to the CVE feature.

## Notes

**2026-07-21T15:56:50Z**

Closed (2026-07-21): dead --sms/--sms-provider flag + its sms_provider plumbing removed from main.py, source.py, and the env-map; README + ARCHITECTURE updated to point at -c/--computers. Implemented via subagent-driven plan docs/superpowers/plans/2026-07-21-tier1-tier2-smc-abuse-and-cleanup.md (Task 1); per-task + whole-branch reviewed; green (test_sms_option_removed, ruff clean). Code pushed by user.
