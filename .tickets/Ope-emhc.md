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

## Notes

**2026-07-31T15:38:01Z**

Status audit 2026-07-31: CORRECTLY OPEN -- verified that the gate is still never evaluated. --enable-bad-opsec exists end to end as a value: the CLI option (main.py:1124), the env mapping SOURCES__SCCM__ENABLE_BAD_OPSEC (main.py:157), the source() parameter and coercion (source.py:254, 263, 302), and the SourceContext field (context.py:45). But there is exactly ONE read of it in the whole tree, collectors/local.py:235, and that read does not gate anything -- it copies the value into the collection_settings row so preprocess can see what the operator asked for. No collector branches on ctx.enable_bad_opsec, so nothing is currently suppressed without the flag and nothing is unlocked with it. The flag's help text still advertises 'NAA decryption, etc.' as the example, which is the operations tracked under Ope-padv (CRED-4) and ope-e10b (SCCM_HasNetworkAccessAccount) -- neither implemented. Worth noting for release: a flag that documents itself as gating detectable operations while gating none is worse than no flag, because an operator may believe omitting it made a run quieter.
