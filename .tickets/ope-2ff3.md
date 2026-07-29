---
id: ope-2ff3
status: closed
deps: []
links: []
created: 2026-06-23T21:14:07Z
type: task
priority: 1
assignee: cthompson
tags: [sccm, preproc, convert, stage2, edges, nodes]
---

# Stage 2: SCCM entities + inline edges (preproc/convert port)

Port CMBP Stage 2 (SCCM entities + inline edges) to preproc/convert: 4 entity nodes (ClientDevice/Collection/AdminUser/SecurityRole) + ~9 inline edges (IsMappedTo, IsAssigned, HasMember, HasClient, Has{Primary,Current,ADLastLogon}User, HasStoredAccount, MemberOf, HasSession). Includes 2 collect changes (host-SID on remoteregistry_users current-user row; collection_settings row), possible-client deterministic-id node + --disable-possible-edges gating in preproc, traversable allow-list, and edge-endpoint stub-node backfill. Plan: docs/superpowers/plans/2026-06-23-sccm-preproc-convert-stage2.md. Decisions grilled with user 2026-06-23. Baseline: ope-a88e working tree; one re-collect before real-data validation.
