---
id: con-907c
status: in_progress
deps: []
links: []
created: 2026-07-31T16:32:02Z
type: task
priority: 2
tags: [testing, integration, fixtures, lab]
---

# Rebaseline fixture expected values on the full lab + add host-level SEC assertions

Correct fixture expected values against a stable full-lab baseline, and add host-level SEC assertions. Distinct from the tagging ticket because these need judgement about which lab state is canonical, and should not block the mechanical tagging. Known items: (1) four MSSQL counts are each +1 because the SEC secondary site has its own site database on ps1-sec, confirmed expected by @_Mayyhem; (2) booting ps1-psv (the PS1 PASSIVE site server) fixed 1 case and broke 14 -- all MSSQL topology counts -- because the collector then correctly discovers the passive server's connection to the PS1 site database, which the fixtures were authored without; (3) edge-fulladministrator-domainadmin-client-devices expects exact=14, lab has 19 -- convert device-derived counts to at_least so adding a VM does not break CI, keep exact for topology counts where a change is a real regression signal; (4) edge-isassigned-domainadmin-full-admin-role and edge-ismappedto-sccm-domainadmin-adminuser both expect 2 'plus one dupe that BloodHound dedupes' and now find 1 -- the dupe assumption is stale; (5) add host-level SEC assertions per @_Mayyhem: 3 sites exist (CAS+PS1+SEC), ps1-sec is a PS1 CLIENT device, and ps1-sec HOSTS the SEC site systems; (6) edge-hascurrentuser-ps1-dev-domainuser's description ('requires manual addition of user device affinity') is wrong and describes HasPrimaryUser better -- fix the description, keep the case. BLOCKER: do con-3354 BEFORE editing node-site-count, or the low-privilege site loss gets blessed into the baseline.

## Acceptance Criteria

Fixture expected values match a stable full-lab baseline; device-derived counts use at_least; SEC is asserted at host level; the HasCurrentUser description is corrected; node-site-count is only touched after con-3354 is fixed.

## Notes

**2026-07-31T18:33:21Z**

@_Mayyhem's per-case value decisions (worksheet returned 2026-07-31):
- node-adminuser-count -> at_least 1, and MAYYHEM\domainadmin should itself be an SCCM_AdminUser
- node-clientdevice-count -> at_least 13
- node-collection-count -> at_least the SCCM default collection count (see con-d061)
- node-securityrole-count -> at_least the SCCM default role count
- edge-contains-sites-admin-user, edge-contains-sites-full-admin-role -> at_least 2
- edge-fulladministrator-domainadmin-client-devices -> at_least 13
- edge-isassigned-domainadmin-full-admin-role -> exact=1; dupe CONFIRMED GONE (graph shows a single SCCM_IsMappedTo for domainadmin; no code creates a duplicate -- the word survives only in these two fixture descriptions)
- edge-ismappedto-sccm-domainadmin-adminuser -> exact=1, same confirmation
- edge-controldb-db-owner-site-databases -> 3 (SEC included)
- node-mssql-server-count, edge-hostfor-servers-computers, edge-executeonhost-servers-hosts, edge-serviceaccountfor-server-instances -> should be cas-db, ps1-db, ps1-sec ONLY. The original fixtures naming ps1-psv were wrong. Blocked on con-be15 (psv has a real registry MSSQL instance, so the node is evidence-backed even if the CM_PS1 attribution is not) and the accepted PS2-PSS stale-SPN artifact.
- edge-hascurrentuser-ps1-dev-domainuser -> LEAVE AS-IS. The description is wrong (it describes HasPrimaryUser); expected to fail while ps1-dev is unbootable.
- node-mssql-database-count -> fix description: two primary sites, one secondary.
- The 4 edge-contains-ps1-* cases 'should pass as-is' -- investigate the higher count rather than raising the expectation.

**2026-07-31T20:33:25Z**

APPLIED (2026-07-31), verified against the priv6/unpriv6 graphs:
- edge-fulladministrator-domainadmin-client-devices: exact=14 -> at_least=13 (device fan-out; must survive the lab gaining a VM)
- edge-isassigned-domainadmin-full-admin-role: exact=2 -> exact=1, 'plus one dupe' dropped from the description (dupe confirmed gone)
- edge-ismappedto-sccm-domainadmin-adminuser: same
- edge-hascurrentuser-ps1-dev-domainuser: case KEPT per @_Mayyhem; the 'requires manual addition of user device affinity' caveat was wrong here and has been MOVED to edge-hasprimaryuser-ps1-dev-domainuser, where it belongs. This case now says it needs domainuser logged on when SCCM last inventoried PS1-DEV.
- node-clientdevice-count: at_least 19 -> at_least 13
- edge-contains-sites-{admin-user,full-admin-role,sms00001-collection}: exact=2 -> at_least=2
- node-mssql-server-count: description named PS1-PSV in error; the third server is PS1-SEC (the secondary's own site database). Count stays exact=3.
- node-mssql-database-count: description corrected to 'two primary sites plus the SEC secondary'.
RESULT: privileged 71 pass / 1 fail / 1 skip -- the single failure is edge-hascurrentuser, which @_Mayyhem said to leave failing while ps1-dev is unavailable. No unexplained privileged failures remain.
STILL OPEN in this ticket, all needing @_Mayyhem:
- node-adminuser-count: worksheet says 'at_least 1, and MAYYHEM\domainadmin should be an SCCM_AdminUser'. Currently at_least=3 and PASSING. Lowering to 1 weakens it, and 'domainadmin should be an SCCM_AdminUser' reads like a NEW assertion rather than a count change. Not applied.
- node-collection-count / node-securityrole-count: 'at_least SCCM default collection/role count' -- I do not know those defaults, and the collections half is entangled with con-d061. Not applied.
- SEC host-level assertions (3 sites; ps1-sec is a PS1 CLIENT; ps1-sec HOSTS the SEC site systems) are still to be added.
