---
id: ope-e10b
status: open
deps: []
links: [ope-2f15]
created: 2026-07-22T15:30:44Z
type: task
priority: 3
tags: [sccm, edge, local-collection, naa]
---

# Emit SCCM_HasNetworkAccessAccount from Local collection (NAA from client WMI)

Emit the SCCM_HasNetworkAccessAccount edge during Local collection. The Network Access Account (NAA) credential is stored in the local WMI repository (CCM_NetworkAccessAccount under root/ccm/policy/machine) on the host running the collector; recovering the plaintext requires DPAPI/SYSTEM access, which is why it sits behind the --enable-bad-opsec gate. The edge links the collector host Computer node to the User/Group principal of the stored NAA: (Computer)-[:SCCM_HasNetworkAccessAccount]->(User). schema.json already declares this relationship_kind (traversable) and the saved cypher query "SCCM CRED-3" already queries it, but no collector code emits it yet. It was deliberately deferred out of the 2026-07-22 edge-name schema-alignment change, which only renamed existing edges. Scope: add a Local-collection step that reads (and, under --enable-bad-opsec, decrypts) the NAA from WMI, resolve the principal SID, and emit the edge through the preproc/convert pipeline (respecting --disable-possible-edges). When implemented, remove the "Deferred" note in README (SCCM_HasStoredAccount section) and document it in ARCHITECTURE.
