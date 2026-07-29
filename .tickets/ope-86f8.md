---
id: ope-86f8
status: closed
deps: []
links: []
created: 2026-07-15T14:36:55Z
type: bug
priority: 1
---

# Realign coerce/relay --disable-possible-edges: NULL NTLM = Windows-default-vulnerable (match CMBP)

Under --disable-possible-edges OpenHound emitted 0 coerce/relay; CMBP (same flag) emits 9 confirmed edges. Investigation: NO generation gap - OpenHound already produced the same 9 real edges as CMBP with possible edges on (CMBP's extra 3 were edges to an 'IgnoreMe' scaffolding node + a typo'd kind CoerceAndRelaytoSMB = CMBP bugs). Sole divergence: OpenHound's flag required RestrictReceivingNTLMTraffic explicitly 'Off', but it is NULL on every host (Windows default 0 = allow all inbound NTLM = actually vulnerable). DECISION (user): treat NULL NTLM as vulnerable under the flag (match CMBP); keep primary gates strict (SMB signing=false, MSSQL EPA explicit Off). FIX: transforms.py 3 coerce builders - ntlm_ok now flag-independent. Restored exactly the 9 confirmed edges under --disable-possible-edges; recovered 8 tests, 0 blast radius. Updated 3 coerce unit tests to new semantics + added explicit-restricted-NTLM drop tests.
