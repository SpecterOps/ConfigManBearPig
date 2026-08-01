---
id: Ope-15m7
status: in_progress
deps: []
links: []
created: 2026-05-28T13:31:54Z
type: task
priority: 1
assignee: Mayyhem
tags: [sccm, graph, audit]
---

# Seed Nodes / Edges Audit

Audit whether all attack-path seed nodes (Authenticated Users, Everyone, Domain Computers) and their baseline edges are properly seeded in the graph, or if they rely on BloodHound pre-existing AD collection data. SCCM attack paths often originate from Authenticated Users -> coerce site server -> relay to MP. For these paths to be traversable in BloodHound, the Authenticated Users node must exist with its standard membership edges.

## Design

Determine which attack-path edges use Authenticated Users or Domain Computers as source by auditing transforms.py and all edge-emitting models. For each such source, decide: emit a minimal seed node from the SCCM extension OR document that prior AD collection is required. If seeding: implement ldap_group_memberships collector (already in preproc table map) to collect real membership. Document which graph data must be pre-existing for full attack path traversal.

## Acceptance Criteria

Clear decision documented: which nodes are seeded by SCCM extension vs. expected from AD collection. No broken/dangling edges in standalone mode. ldap_group_memberships collector implemented if seeding is chosen.

## Notes

**2026-07-31T15:37:02Z**

Status audit 2026-07-31: CORRECTLY IN PROGRESS -- partially satisfied. DONE: the Authenticated Users seed node is built, by preproc rather than by asking operators to run SharpHound first -- _node_authenticated_users (transforms.py:4853) synthesises one Group node per domain that actually produces a coerce-and-relay edge, keyed in SharpHound's well-known-SID form UPPER(FQDN)-S-1-5-11 (transforms.py:676-678) so it merges with any SharpHound-collected node, with environmentid resolved from a co-occurring domain computer because S-1-5-11 has no domain part of its own. That decision is documented (9 'Authenticated Users' references in README.md, 4 in ARCHITECTURE.md, incl. the explanatory block at README:1025), and edge-endpoint dangling is separately handled by _node_backfill. NOT DONE: the ldap_group_memberships collector named in the acceptance criteria does not exist -- zero references anywhere in src/ -- so the synthetic node carries no real membership edges; and the audit's central deliverable, a written decision covering the OTHER two seed principals the ticket names (Everyone and Domain Computers), has not been produced. Suggest narrowing this ticket to just that written decision, since the Authenticated Users half shipped with Stage 6 (ope-d820).
