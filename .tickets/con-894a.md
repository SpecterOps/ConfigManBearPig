---
id: con-894a
status: closed
deps: []
links: []
created: 2026-07-30T16:14:36Z
type: task
priority: 3
tags: [cypher, container, graph]
---

# Expose the System Management container's DN as a queryable lowercase distinguishedname property

The Container node the collector builds for the AD System Management container published only name/displayname/environmentid, folding the DN into the display name. That made the DN unqueryable on an SCCM-only graph: a filter like `WHERE c.distinguishedname STARTS WITH 'CN=System Management,CN=System,'` matched nothing unless SharpHound had also collected the same container and supplied the property.

Added ContainerProperties(NodeProperties) in graph.py carrying a lowercase `distinguishedname`, and wired models/container.py to it. Lowercase is deliberate and is the single exception to the CMBP-verbatim casing rule: ConfigManBearPig never emits a Container node (ConfigManBearPig.ps1:3454 only reads the container DACL to discover scan targets), so there is no original casing to match, while SharpHound - whose node this one merges with by objectGUID - writes AD node properties lowercase. Cypher property lookups are case-sensitive.

Also added the saved query 'SCCM Principals with Full Control of System Management Container (Possible Site Servers)' which depends on this property, and corrected the README Container section, which explicitly documented the DN as not exposed.

## Acceptance Criteria

ContainerProperties exposes distinguishedname (lowercase); the emitted node JSON carries it; DN stays null when uncaptured while display falls back to the id; tests/smc_container_test.py covers all three; README Container section documents the property and the casing exception.
