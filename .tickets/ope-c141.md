---
id: ope-c141
status: closed
deps: []
links: [ope-fb99, ope-961c]
created: 2026-07-23T19:20:16Z
type: task
priority: 2
tags: [sccm, graph, ldap, ad-parity]
---

# Populate all AD node properties (Computer/User/Group) to CMBP parity instead of relying on SharpHound

The OpenHound SCCM collector emits lean AD node stubs (Computer/User/Group + Base) intended to merge with SharpHound-collected nodes, so it omits AD-object attributes ConfigManBearPig.ps1 populates itself. Per owner decision (2026-07-23), OpenHound must populate ALL available AD node properties itself and NOT rely on SharpHound collection. A --compare-to-zip diff (OpenHound vs a CMBP baseline) found these present on CMBP AD nodes (Base/Computer/User/Group) but absent from OpenHound: Domain/domain, Enabled, IsDomainPrincipal, Type, objectClass, servicePrincipalName, CN, distinguishedName (Group), disableLoopbackCheck, restrictReceivingNtlmTraffic. (DNSHostName/SamAccountName/UserPrincipalName already exist on OpenHound under camelCase casing dNSHostName/samAccountName/userPrincipalName.) CMBP sources (ConfigManBearPig.ps1): Type/objectClass <- LDAP objectClass (last element; Type is title-cased e.g. computer->Computer); Enabled <- LDAP userAccountControl bit 2 (ACCOUNTDISABLE) => -not(uac -band 2); IsDomainPrincipal <- true for any AD-resolved principal; CN/DNSHostName/SamAccountName/UserPrincipalName/servicePrincipalName/distinguishedName <- direct LDAP attributes; disableLoopbackCheck/restrictReceivingNtlmTraffic <- RemoteRegistry (OpenHound already collects these per ope-961c but leaves them null on non-infra AD computers). Scope: extend LDAP collection to fetch userAccountControl + servicePrincipalName + cn + userPrincipalName + objectClass for the AD principals OpenHound resolves; derive Enabled/Type/IsDomainPrincipal/Domain; add the fields to ComputerProperties/UserProperties/GroupProperties (CMBP-exact casing per the property-casing rule); plumb through preproc/convert; update README node reference + ARCHITECTURE. Match CMBP property set + sources exactly. Needs brainstorm/spec/plan (owner chose the full cycle).

## Notes

**2026-07-24T18:03:00Z**

COMPLETE + pushed (integration). Phase A: Computer/User/Group nodes carry Domain/Enabled/IsDomainPrincipal/Type/objectClass/servicePrincipalName/CN from the per-host AD-resolution cache (ldap_resolved_principals resource + _derive_ad_props/_join_ad_props), resolved-principals-only by design. Final opus review caught + fixed a critical bug: _derive_ad_props bitwise-ANDed a VARCHAR user_account_control (binder error swallowed by _safe → all AD props NULL); fixed with TRY_CAST + hardened ad_props_derive_test to VARCHAR. Full suite 716 pass. NOTE: Phase A validated by unit tests only; a fresh privileged collect is the real end-to-end proof (cached-bucket re-validation had 0 resolved-principals rows).
