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

