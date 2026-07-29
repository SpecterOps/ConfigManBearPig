---
id: ope-961c
status: open
deps: []
links: [ope-c141]
created: 2026-07-23T19:08:05Z
type: task
priority: 2
tags: [sccm, edge, relay, cred]
---

# Flesh out disableLoopbackCheck and add an NTLM-reflection relay edge

disableLoopbackCheck is a Computer property collected from RemoteRegistry (graph.py:178) but is currently referenced by no edge and no shipped query. When a coerce-and-relay-to-SMB target has the loopback check disabled AND SMB signing not required, an attacker can relay the host's own coerced NTLM auth back to itself (NTLM reflection) - strictly worse than ordinary peer relay. Flesh out disableLoopbackCheck (collection provenance + node-property usage + entity-panel help) and add a graph edge representing the NTLM-reflection / relay-to-self capability so it is queryable and traversable in BloodHound. Origin: cypher-query ideation session; the deferred rank-5 candidate 'SCCM Relay Target Vulnerable to NTLM Reflection' was a WHERE-clause workaround for the missing edge.

## Acceptance Criteria

A new or extended edge kind marks hosts where NTLM reflection is possible (disableLoopbackCheck=true AND SMBSigningRequired=false on a coerce-and-relay-to-SMB target); the edge is emitted from preproc, added to TRAVERSABLE_EDGE_KINDS if appropriate, documented in README Edge Reference + schema.json, carries edge_help content, and is surfaced by a saved cypher query.
