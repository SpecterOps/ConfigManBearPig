---
id: Ope-txs0
status: open
deps: []
links: []
created: 2026-05-28T13:28:42Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, ldap, multi-domain]
---
# Search Other Discovered Domains via LDAP

Extend LDAP collection to automatically search newly discovered domains, not just the initially configured domain. SourceContext._build_domains_to_try() and _shared_discovered_domains track foreign domains found during collection, but LDAP collectors only query the primary domain System Management container. In multi-forest or multi-domain environments, SCCM can span trust boundaries.

## Design

After Phase 1 LDAP completes, check ctx.discovered_domains for new domains not yet LDAP-searched. For each, spawn LDAP collection against that domains System Management container. Use the TargetQueue loop pattern for subsequent passes. Handle cross-domain auth gracefully (attempt with current credentials, fall back if unauthorized). Deduplicate site codes via ctx._emitted_site_codes.

## Acceptance Criteria

In a two-domain lab, discovery of a principal from domain B triggers LDAP collection against domain B System Management container. No duplicate SCCM_Site nodes. Graceful failure if cross-domain LDAP is rejected.

