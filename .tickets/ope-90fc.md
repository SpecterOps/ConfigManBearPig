---
id: ope-90fc
status: open
deps: []
links: [ope-afc8]
created: 2026-07-15T20:47:49Z
type: task
priority: 3
---

# Collapse duplicate cross-site SCCMResourceIDs to a root/parent-site-suffixed canonical entry

In a CAS + primary hierarchy the same resource replicates across sites with the SAME ResourceID, so a Computer node's SCCMResourceIDs aggregates both '<rid>@CAS' and '<rid>@PS1' (observed on DC/WAC/HYPER-V). This is currently correct/expected multi-site behavior (CMBP aggregates the same way), not a bug -- surfaced while investigating ope-afc8.

Requested handling (per owner): when the same ResourceID is detected at more than one site, collapse to a single canonical entry keyed by the root/parent site code suffix (e.g. keep '<rid>@CAS' when CAS is the hierarchy root) instead of listing every per-site duplicate. Scope: the resource_id_str aggregation feeding node_computer.SCCMResourceIDs (transforms.py _node_computer) and any node whose id/keys embed '<rid>@<site>'. Decide dedup key (root vs immediate parent) and whether it affects edge-join resource keys. Design pass needed before implementing.
