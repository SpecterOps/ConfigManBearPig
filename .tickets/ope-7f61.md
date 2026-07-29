---
id: ope-7f61
status: closed
deps: [ope-255b]
links: [ope-255b]
created: 2026-06-29T15:57:27Z
type: chore
priority: 2
tags: [sccm, docs, readme]
---

# Fix README edge-count banner miscount (Stages 1-2 = 11, not 10)

README edge-count banner reads '10 from Stages 1-2' but 11 distinct Stage 1-2 edge kinds are actually documented (AdminsReplicatedTo, HasClient, HasMember, IsMappedTo, IsAssigned, HasPrimaryUser, HasCurrentUser, HasADLastLogonUser, HasStoredAccount, MemberOf, HasSession). Pre-existing (predates Stage 4); surfaced by the Stage 4 final review. Reconcile the count/wording so stage banners stop propagating it.
