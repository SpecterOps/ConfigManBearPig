---
id: Ope-zaja
status: open
deps: [Ope-l6fu, Ope-o008]
links: [ope-d820]
created: 2026-05-28T13:31:00Z
type: feature
priority: 1
assignee: Mayyhem
tags: [sccm, http, relay, takeover]
---

# Relay to Management Point

**Deferred by the owner on 2026-11-09.** This feature is outside the current SCCM extension completion effort. Keep the ticket open for future work; this decision does not authorize implementation or active testing.

## Corrected scope

The intended technique is Garrett Foster's [I'd Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/), published July 15, 2025, with the related [mssqlkaren tool](https://github.com/garrettfoster13/mssqlkaren).

The attack coerces authentication from a remote management point and relays it to the SCCM site database's SQL service. The management point's database permissions allow policy retrieval, potentially exposing network access account, task-sequence, and collection-settings secrets. The management point supplies the relayed identity; the site database is the relay destination.

This is separate from the existing `SCCM_CoerceAndRelayToAdminService` relationship, which models site-server authentication relayed to an SMS Provider's AdminService. The ticket's previous AdminService/IIS design, placeholder `EX_RelayToMP` edge, and acceptance criteria described the wrong technique and are superseded by this scope correction.

## Before resuming

Agree what the collector should detect and model, which prerequisites can be established from collected evidence, and the graph relationships and verification required. Modelled exposure and actual secret recovery need separate decisions; secret recovery is also deferred from the current effort. No new edge name, graph schema, finding, or implementation design is approved by this note.

