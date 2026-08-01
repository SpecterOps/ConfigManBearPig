---
id: con-5e71
status: closed
deps: []
links: []
created: 2026-07-31T18:32:21Z
type: feature
priority: 2
tags: [sccm, lowpriv, edges, clientdevice]
---

# Emit SCCM_ClientDevice + SameHostAs from SPN during low-priv collection

@_Mayyhem (fixture review 2026-07-31) on edge-samehostas-clientdevice-to-computer-ps1-dev and edge-samehostas-computer-to-clientdevice-ps1-dev: 'If we create SCCM_ClientDevice nodes based on SPN when --disable-possible-edges is not used, then this edge should exist.' Both currently PASS privileged and FAIL unprivileged. Related open question on edge-hasclient-ps1-site-ps1-dev (marked Unsure): 'During unprivileged without --disable-possible-edges, are we ever assigning a primary site to assumed client devices found via SPN? Maybe we should if there is only one primary site in the forest?' Partial answer from code: transforms.py:3086-3091 DOES resolve possible-client site_code to the Primary, falling back to the root site -- so the mechanism exists and the gap is elsewhere. Note ps1-dev is currently powered off but @_Mayyhem confirms that has no bearing on its SPN, so the SPN-derived path should work regardless.

## Acceptance Criteria

With possible edges enabled, a lowpriv collection emits SCCM_ClientDevice nodes for SPN-discovered hosts and the bi-directional SCCM_SameHostAs edges to their Computer nodes; the two samehostas cases pass unprivileged; the hasclient site-assignment question is resolved either way with a documented rationale.

## Notes

**2026-07-31T22:22:21Z**

FIXED, fixtures only -- no collector change was needed, which is itself the finding. sccm.node_client_device holds 20 rows privileged / 14 unprivileged and the ps1-dev row is present in BOTH; only the id FORM differs (GUID:... when confirmed via AdminService, <sid>@<site> when SPN-inferred). Three cases pinned their ClientDevice endpoint with id='GUID:*', which asserted the PRIVILEGE LEVEL rather than the relationship, so they failed at low privilege for data that was present.
Fix: edge-samehostas-clientdevice-to-computer-ps1-dev, edge-samehostas-computer-to-clientdevice-ps1-dev and edge-hasclient-ps1-site-ps1-dev now pin by name ('PS1-DEV@PS1'). The other four GUID:* pins are on requires_privilege cases a low-priv run skips, so they are safe and were left alone.
The verifier flagged that removing the id pin would DELETE the only assertion distinguishing a confirmed client from an SPN-inferred possible one, and said the follow-up should be required rather than optional. Agreed and done: new node case node-clientdevice-confirmed-has-guid-id, tagged requires_privilege, carries that assertion on its own. It exposed a modelling limit in the guard tests -- privilege there is a property of the KIND, and this is the first case where it is a property of the ASSERTION -- so the guard gained a narrow per-case escape hatch plus a second test ensuring the hatch cannot be used to silently unflag anything.
Verified: all three pass in BOTH priv6 and unpriv6; the new case passes privileged and is skipped low-priv.
