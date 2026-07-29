---
id: ope-c8cc
status: closed
deps: []
links: [Ope-l6fu]
created: 2026-06-08T20:48:22Z
type: task
priority: 2
assignee: cthompson
parent: ope-3d28
tags: [sccm, mssql, epa, tds, ntlm, relay]
---

# Port MSSQLHound TestEPA network EPA scan into _get_extended_protection_settings

Port MSSQLHound TestEPA (internal/mssql/client.go:1065-1291) into _get_extended_protection_settings in collectors/mssql.py. Network EPA probe: authenticated NTLM logins with manipulated channel-binding (encrypted/strict) and service-binding (unencrypted) AV pairs to derive force_encryption (Yes/No) and extended_protection (Off/Allowed/Required/Unknown), matching registry.py's mssql_servers output vocabulary. Hybrid impl: impacket 0.13.1 core (free TDS 8.0 strict + cbt_fake_value CBT control) + tds.MSSQL subclass for service-binding control + Windows SSPI integrated-auth path (forced NTLM, SECBUFFER_CHANNEL_BINDINGS, targetspn). Auth ladder: explicit creds (password or NT-hash) -> SSPI current-user -> skip. New clients/mssql_epa.py module (mirrors smb_sso.py); collectors/mssql.py stays thin and gets its existing bugs fixed; add nt_hash to SourceContext + source func; remove dead hand-rolled PRELOGIN helpers.

## Notes

**2026-06-08T20:55:10Z**

Design locked via grilling (2026-06-08): Hybrid impl = impacket 0.13.1 core (free TDS 8.0 strict via _negotiate_encryption; cbt_fake_value drives CBT: None=correct/Normal, b''=MissingCBT, 16 garbage bytes=BogusCBT) + tds.MSSQL subclass adding service/strip_target_service for service-binding tests (BogusService='cifs', MissingService=strip). Plus a Windows SSPI integrated-auth path (forced NTLM package, channel binding via SECBUFFER_CHANNEL_BINDINGS, SPN via targetspn) reusing impacket TDS transport. Strict supported on ALL paths incl. SSPI. Auth ladder: explicit ctx creds (password or nt_hash) -> SSPI current-user -> skip. Correct SPN from ctx.ad.get_spns(target) MSSQLSvc entry, fallback MSSQLSvc/<target>. Output vocab matches registry.py: force_encryption Yes/No, extended_protection Off/Allowed/Required/Unknown. Code in new clients/mssql_epa.py; collectors/mssql.py stays thin + bugfixed; add nt_hash to SourceContext+source func (dlt.secrets); remove dead PRELOGIN helpers. Convert/edge wiring (epa_level!=Required gating) is OUT OF SCOPE (Ope-l6fu).

**2026-06-08T21:37:01Z**

Live matrix validation vs ps1-db (SQL2022): explicit-cred / pass-the-hash path = 12/12 CORRECT across all FE x FSE x EP combos incl. TDS 8.0 strict. SSPI integrated-auth path = 8/12: correctly detects Off and Required everywhere, but reports EP=Allowed as Required (4 combos). ROOT CAUSE (evidence: per-probe truth table, both CBT and service paths): impacket hand-built Type3 can OMIT the MsvAvChannelBindings/MsvAvTargetName AV pair -> Allowed server accepts the 'missing' probe. Windows SSPI ALWAYS includes the AV pair (Z(16)/empty when app supplies none) -> Allowed server treats it as present-but-wrong and rejects, identical to Required. Cannot strip post-hoc (NTProofStr HMAC + MIC computed by Windows over the AV pairs; NT hash not exposed). This is why MSSQLHound Go requires explicit creds and has no integrated-auth mode. DECISION NEEDED from user on how SSPI should report the enforced case (Allowed indistinguishable from Required).
