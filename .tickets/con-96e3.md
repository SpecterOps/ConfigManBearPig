---
id: con-96e3
status: open
deps: []
links: [ope-fb99]
created: 2026-10-23T23:24:16Z
type: feature
priority: 2
tags: [sccm, graph, management-point, distribution-point, tier-zero, privilege-zones, findings]
---

# Connect reported management points to clients and classify direct Tier Zero serving infrastructure

## Problem and intended outcome

A client device's reported/current or last management point is currently recorded
as properties. Add an explicit relationship starting at the management point's
computer and ending at the SCCM client device. Use that relationship as the basis
of a privilege-zone rule and corresponding BloodHound finding: management points
(MPs) and distribution points (DPs) that directly serve Tier Zero clients should
also be Tier Zero.

For example, if a Tier Zero client reports ps1-mp.mayyhem.com as its management
point, the graph should contain management-point computer -> SCCM client device.
The rule should select that management-point computer for Tier Zero. The
corresponding finding should expose a serving computer outside Tier Zero that
directly serves a Tier Zero client, subject to BloodHound's actual finding
behavior and rule evaluation order.

## Existing evidence and places to start

- `src/openhound_sccm/collectors/sms_rows.py` retains `LastMPServerName`.
- `src/openhound_sccm/graph.py` defines `lastReportedMPServerName`,
  `lastReportedMPServerSID`, `currentManagementPoint`, and
  `currentManagementPointSID` on client devices.
- `src/openhound_sccm/models/sccm_client_device.py` emits those properties.
- `ope-fb99` records the earlier client-property work.
- `extension/privilege_zone_rules/`, `extension/README.md`, and the existing
  privilege-zone tests describe and validate the current Tier Zero policy.

These are implementation starting points, not proof that every client has all
of these properties or that a last report still describes its current service.

## Proposed approach and decisions before implementation

- Build the MP -> client relationship from the reported/current or last MP
  evidence, resolving the MP to a known computer identity. Prefer existing data
  and perform reusable matching in preprocess where appropriate.
- Agree the edge name, source node kind, properties, and whether BloodHound
  should treat it as an attack-path step before changing the hand-maintained
  schemas. A service relationship alone does not establish code execution.
- Define how current and last reports are handled when they disagree, and how
  missing report times or old reports affect classification. Preserve the
  evidence source and available report time so users can understand the result.
- Recognize Tier Zero on either the SCCM client or its linked AD computer using
  the existing same-host relationship. Classify the serving computer and its
  corresponding SCCM client representation consistently with existing rules.
- Include DPs in the intended Tier Zero policy, but first identify evidence that
  a particular DP directly serves a particular client. A reported MP, shared
  site, or co-located role does not by itself prove that DP relationship. Agree
  the DP evidence and any additional relationship before implementing that part.
- Design and verify the corresponding finding alongside the rule. Explain how
  classification affects whether a finding remains visible after rules run;
  do not promise a finding based only on a successful selection query.

## Why this approach

An explicit relationship makes the observed service connection usable by rules,
findings, graph queries, and reviewers. Properties alone require each consumer
to repeat computer-name matching. Classifying every MP or DP in the same site
would not establish which infrastructure directly serves a Tier Zero client.
Keep that broader site-wide alternative outside this ticket's intended rule.

## Acceptance criteria and verification

- Emitted edges start at the resolved MP computer and end at the correct SCCM
  client device. Names with different casing or short/FQDN forms resolve
  consistently without joining unrelated computers.
- Cover matching current/last reports, conflicting reports, duplicate records,
  missing data, unresolved identities, and stale or undated evidence. Missing
  or unresolved evidence must not create an invented relationship; incomplete
  results and failed resolution are reported clearly.
- The privilege-zone rule selects MPs directly serving known Tier Zero clients,
  including clients whose Tier Zero label exists only on their AD representation.
  Include the agreed DP evidence and rule coverage, or explicitly record the
  remaining evidence gap before treating the full feature as complete.
- Negative tests exclude unrelated MPs/DPs, same-site-only associations, clients
  outside Tier Zero, and service relationships that do not meet the agreed
  evidence requirements.
- Validate the edge and rule with focused offline tests in `tests/`. Re-run
  preprocess and convert over a fixed cached collection and inspect the graph
  difference. Verify the corresponding finding in BloodHound, including behavior
  before and after privilege-zone classification. Keep active lab testing within
  the authorized mayyhem.com lab targets.
- Update the README, extension rule documentation, edge help, and relevant
  architecture sections with the approved behavior, limitations, copyable
  examples, and manual verification instructions. Keep schema declarations and
  emitted kinds aligned after owner approval of the schema design.
- Record dependencies, downstream effects, alternatives, test results, and
  review/commit commands in the implementation notes. No new dependency is
  proposed for this ticket; any later addition must be Apache 2.0 compatible.

## Scope of this ticket creation

Planning only. No collector code, schemas, rules, or findings are changed by
creating this ticket. No shared OpenHound repository changes are proposed.
