---
id: ope-255b
status: closed
deps: []
links: [ope-7f61]
created: 2026-07-01T16:18:45Z
type: task
priority: 1
assignee: cthompson
tags: [sccm, docs, validation, stage7, preproc-convert]
---

# Stage 7: Docs + validation (preproc/convert port)

Stage 7 (final) of the CMBP->OpenHound preproc/convert port: docs reconciliation + validation. Reconcile README + ARCHITECTURE.md to code-truth (14 node kinds / 37 edge kinds); fix the stale Graph Model prose (README ~409-413 still says 8 emitted); add 3 Mermaid diagrams (full hairball + pipeline + clustered AD/SCCM/MSSQL); non-behavioral docstring/Attributes + stale-comment fixes; dead-ref sweep; run ruff/mypy/pytest in isolated uv env + structural checklist; ticket hygiene (verify+close ope-7f61 which appears already fixed). NO behavioral code changes. Plan: docs/superpowers/plans/2026-07-01-sccm-preproc-convert-stage7.md
