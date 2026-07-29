---
id: Ope-exvi
status: open
deps: [Ope-t7kv, Ope-gqwo, Ope-padv, Ope-o6bh, Ope-0t3h, Ope-zaja]
links: []
created: 2026-05-28T13:28:04Z
type: feature
priority: 3
assignee: Mayyhem
tags: [sccm, findings, reporting]
---
# Findings / Remediations

Add a findings layer that identifies misconfiguration patterns and emits structured remediation guidance. The current pipeline is purely a graph builder with no security evaluation. Findings would be a post-convert analysis step inspecting the graph or preproc DuckDB tables to flag specific misconfigurations.

## Design

Design a findings/ module. Define a Finding dataclass: id, title, severity, description, affected_nodes, remediation, references. Implement finding detectors as DuckDB queries over preproc tables. Emit findings as a JSON report alongside graph output. Gate noisy detectors behind --enable-bad-opsec. Initial candidates: no HTTPS on MP, NAA credentials, client push enabled, automatic site-wide push, PXE DP without password, SCCM CVEs, SQL EPA not enforced.

## Acceptance Criteria

Running a full collection generates findings.json alongside graph output. Each finding includes severity, affected nodes, and remediation steps. Findings are suppressible/filterable.

