---
id: Ope-bmyk
status: closed
deps: [Ope-o008]
links: []
created: 2026-05-28T13:27:52Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, graph, ux]
---

# Abuse Info on Edges

Surface abuse-path information in graph output describing HOW an edge can be exploited. SCCMEdgeProperties already has composition_query and reason fields in graph.py but they are unpopulated. Operators need to understand what to do with each edge without leaving BloodHound.

## Design

Add abuse_info field to SCCMEdgeProperties in graph.py. For each edge kind, define a string describing the attack steps. Link to Misconfiguration Manager technique IDs (CRED-X, ELEVATE-X, TAKEOVER-X). Populate abuse_info at edge creation time in relevant model/transform.

## Acceptance Criteria

Each SCCM-specific edge type has a non-empty abuse_info property in graph output. Abuse info includes technique ID reference where applicable.

## Notes

**2026-07-20T19:56:58Z**

Audit second-pass (2026-07-20): DONE, closing. Abuse info ships via edge_help.py: each edge kind maps to an EdgeHelp block (general/windowsAbuse/linuxAbuse/opsec/references) merged into the edge property bag by models/graph_edge.py (EDGE_HELP.get(kind).as_fields()). PENDING_HELP_KINDS is empty; 35 of 37 kinds authored (MemberOf + HasSession intentionally omitted as BloodHound-native), with Misconfiguration Manager technique IDs (TAKEOVER-2/5/6, etc.). Tests: edge_help_test.py, edge_help_emit_test.py, edge_help_integration_test.py (13 tests). Correction: the ticket body's premise that graph.py already has composition_query/reason was never accurate; the shipped design uses EdgeHelp tabs. The separate edge composition property is tracked under ope-a214.
