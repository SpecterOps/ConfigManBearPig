---
id: con-727a
status: closed
deps: []
links: []
created: 2026-08-02T03:15:26Z
type: task
priority: 3
tags: [sccm, integration, fixtures, lab]
---

# edge-hascurrentuser-ps1-dev-domainuser fails on lab state, not code -- domainuser is not logged on to PS1-DEV

edge-hascurrentuser-ps1-dev-domainuser is the only failing case on a privileged run of current main (ab-priv-pe-on: 76 passed / 1 failed / 1 skipped). It is PRE-EXISTING and ENVIRONMENTAL, not a code regression -- it was already failing in this morning's out/priv8 run, which predates every change made today.

The case asserts exactly one SCCM_HasCurrentUser edge from client device PS1-DEV@PS1 to samAccountName domainuser. Its own description states the precondition: 'requires domainuser to be logged on to PS1-DEV when SCCM last inventoried it'. CurrentLogonUser is a point-in-time fact about who was interactively logged on at inventory time, so the case passes or fails on lab state, not on collector behaviour.

Current lab state: the graph holds 9 SCCM_HasCurrentUser edges and none originates from PS1-DEV. Eight point at DOMAINUSER from site systems (PS1-PSV, PS1-DB, PS1-PSS, PS1-DP, PS1-SMS, PS1-SEC, PS1-MP, CAS-DB) and one is PS1-DEV2 -> DOMAINADMIN. So domainuser is simply not logged on to PS1-DEV.

Ruled out as causes: the PS1-DEV@PS1 SCCM_ClientDevice node still exists and its name is byte-identical between out/priv8 and the new run, so commit 290bfcd 'Fix AD name prop' did not rename it out from under the pattern. Only the failure DETAIL changed wording, from 'not found' to 'property mismatch (9 candidates of this kind, none matched)', which is the matcher reporting more usefully now that it names how many candidates of the kind it considered.

Options: (a) log on as domainuser to PS1-DEV and let SCCM inventory it before a release run, and record that as a lab precondition in the release checklist; (b) relax the case to assert the edge KIND exists with a plausible source rather than pinning PS1-DEV specifically; (c) drop the case as untestable without lab choreography. (a) preserves the assertion's value and is cheapest if the lab is under your control.

## Acceptance Criteria

Either the mayyhem lab precondition is documented in the release checklist and a privileged run reports 0 failures, or the case is rewritten so it does not depend on a transient interactive logon.

## Notes

**2026-08-02T03:24:36Z**

DECISION (@_Mayyhem, 2026-08-01): leave the case exactly as written. No rewrite, no relaxation of the PS1-DEV / domainuser pins.

Recording the operational consequences so this is not rediscovered later:

1. A privileged run of the built-in suite reports 76 passed / 1 failed, so 'collect sccm ... --run-all --run-integration-tests' exits NON-ZERO on a healthy privileged collection. Anything that gates on that exit code -- CI, a release script, dev/ab_matrix.py's worst-outcome roll-up -- must expect 1 for the privileged cells, or the lab needs domainuser interactively logged on to PS1-DEV and re-inventoried by SCCM before the run.

2. edge-hascurrentuser-ps1-dev-domainuser is the ONLY SCCM_HasCurrentUser case in the fixture set, so while it sits red the suite provides no working assertion for that edge kind. The builder is demonstrably fine -- the current privileged graph holds 9 SCCM_HasCurrentUser edges, including PS1-DEV2 -> DOMAINADMIN from a client device -- but a regression in it would not be caught by a case that is already failing.

Closed as accepted rather than fixed. Reopen if the exit code becomes a problem for release automation.
