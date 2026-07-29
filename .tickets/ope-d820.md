---
id: ope-d820
status: closed
deps: []
links: [Ope-o008, Ope-zaja]
created: 2026-06-30T18:23:56Z
type: task
priority: 1
assignee: Mayyhem
tags: [sccm, graph, relay, preproc, convert, possible-edges]
---

# Stage 6: Coerce-and-relay possible edges (preproc/convert port)

Port CMBP's coerce-and-relay post-processing (Process-CoerceAndRelayToAdminService :6572-6624, ...ToMSSQL :6626-6726, ...ToSMB :6728-6781; synthetic Authenticated Users node :6609/6708/6766) into the SCCM preproc/convert pipeline. Three possible edges (CoerceAndRelayToAdminService AuthUsers->Site, CoerceAndRelayToMSSQL AuthUsers->MSSQL_Login, CoerceAndRelayToSMB AuthUsers->Computer) + the synthetic Authenticated Users group node. Locked decisions (grilled 2026-06-30): (1) --disable-possible-edges = SURGICAL (default assumes vulnerable on null NTLM/EPA; flag tightens to explicitly-confirmed-vulnerable); (2) AuthUsers id = UPPER(FQDN)-S-1-5-11 SharpHound-merge form, environmentid=site server domain SID; (3) fix CMBP bug: emit CoerceAndRelayToSMB + make traversable, correct TRAVERSABLE_EDGE_KINDS; (4) port coercionVictimAndRelayTargetPairs/coercionVictimHostnames via typed graph_edges VARCHAR[] cols + relay-only EdgeProperties subclass, array-unioned in dedup; (5) add smb_signing_source VARCHAR[] to node_computer for SMB relay provenance (cross-cutting Stage 1 change). Plan: sccm/sccm/docs/superpowers/plans/2026-06-30-sccm-preproc-convert-stage6.md
