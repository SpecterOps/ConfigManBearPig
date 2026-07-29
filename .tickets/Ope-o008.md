---
id: Ope-o008
status: closed
deps: []
links: [ope-d820]
created: 2026-05-28T13:28:30Z
type: task
priority: 1
assignee: Mayyhem
tags: [sccm, audit, relay, smb]
---

# Verify CoerceAndRelayToSMB Lifecycle (Collection to Postprocessing)

Audit whether intermediate CoerceAndRelayToSMB data survives through to postprocessing or is dropped before the transform phase. coerce_and_relay_edges is listed in transforms.py comments but no SQL definition exists. smb_signing_status feeds the relay feasibility check but the full data path has not been validated.

## Design

Trace full data path: SMB signing status collection -> JSONL storage -> preproc table -> transform SQL -> edge emission. Confirm smb_signing_status is in preproc_table_map in main.py. Implement the coerce_and_relay_edges SQL transform in transforms.py. Verify transform runs after all SMB collection completes. Add row count logging at each stage.

## Acceptance Criteria

coerce_and_relay_edges SQL transform is implemented and correct. End-to-end test confirms edges appear when SMB signing is disabled on a site server. No data silently dropped between collection and postprocessing.

## Notes

**2026-07-01T13:39:15Z**

Satisfied by Stage 6 (ope-d820). _edge_coerce_relay_smb implements the CoerceAndRelayToSMB SQL transform (AuthUsers -> signing-disabled site system); smb_signing_required + new smb_signing_source provenance flow node_computer -> graph_edges -> graph_edges_ad -> output with no silent drop. End-to-end validated: J1 live run vs lab raw produced 4 CoerceAndRelayToSMB edges by default and 0 under disable-possible; synthetic unit tests + validation harness (2026-06-30-sccm-preproc-convert-stage6-validation.md) cover the path. Full suite 570 passed.
