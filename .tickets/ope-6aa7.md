---
id: ope-6aa7
status: closed
deps: []
links: []
created: 2026-06-29T19:59:31Z
type: feature
priority: 2
assignee: cthompson
tags: [sccm, convert, preproc, opengraph, ad, output]
---

# Split AD nodes/edges into a separate untagged OpenGraph file

Split convert output into two OpenGraph payloads in the same dir: SCCM-tagged (sccm_*, source_kind=SCCM) and an untagged AD payload (ad_*, NO metadata block) so BloodHound merges Computer/User/Group/backfill-stub nodes + every AD-touching edge into its native AD graph. New preproc step transforms._graph_edges_split partitions graph_edges into graph_edges_ad/graph_edges_sccm (either-endpoint-is-AD, incl. backfill stubs), runs after _node_backfill. New extension destination opengraph_file_untagged (omits metadata; core off-limits). emit_graph_from_duckdb gains resource_prefix + source_kind=None handling; NODE_SPECS/EDGE_SPECS split into SCCM_*/AD_* lists; convert runs two passes via _emit_split_graph. Always-on, no flag. Plan: sccm/sccm/docs/superpowers/plans/2026-06-29-split-ad-nodes-edges-output.md
