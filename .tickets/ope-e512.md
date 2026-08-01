---
id: ope-e512
status: closed
deps: []
links: [Ope-txs0]
created: 2026-06-02T21:25:46Z
type: task
priority: 2
---

# Per-domain collector pipeline to rerun LDAP/DNS against discovered domains

## Notes

**2026-07-31T15:35:44Z**

Status audit 2026-07-31: CLOSED AS DUPLICATE of Ope-txs0 ('Search Other Discovered Domains via LDAP'), which is the canonical ticket -- it carries the Design and Acceptance Criteria while this one is a title-only stub with an empty body, the same pattern already applied to ope-f651 -> ope-1f49, ope-676f -> ope-4483 and ope-c660 -> ope-3f2a. Neither ticket's work is done: SourceContext.discovered_domains (context.py:54) and _build_domains_to_try (context.py:138) exist and are used, but ONLY for principal resolution inside resolve_principal (context.py:230) -- there is no second collection pass that re-runs the LDAP/DNS collectors against a newly discovered domain's System Management container. Tracking continues under Ope-txs0.
