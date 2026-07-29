---
id: Ope-emhc
status: open
deps: []
links: []
created: 2026-05-28T13:28:55Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, opsec]
---
# Implement --enable-bad-opsec Gating

Wire up the --enable-bad-opsec flag to gate operations that are detectable or disruptive. The flag is fully defined in the CLI and propagated into SourceContext but no code checks ctx.enable_bad_opsec. The flag help text mentions NAA decryption as an example but the gate is never evaluated.

## Design

Audit all planned/implemented collectors for operations that trigger SCCM/Windows event log entries. Gate behind --enable-bad-opsec: local CIM repository scraping (CRED-4), NAA policy decryption, PXE media download via TFTP, any enumeration generating failed-auth events. Add startup warning when a method requiring bad-opsec is requested without the flag. Document each gated operation with the event log entry it produces.

## Acceptance Criteria

Running CRED-4 without --enable-bad-opsec prints a warning and skips. With the flag, operations proceed. Each gated operation is documented.

