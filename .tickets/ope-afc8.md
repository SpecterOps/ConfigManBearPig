---
id: ope-afc8
status: closed
deps: []
links: [ope-90fc]
created: 2026-07-15T20:47:31Z
type: bug
priority: 2
---

# SCCM_HasMember edge wrongly lands on Computer nodes for non-client collection members

SCCM_HasMember was drawn to Computer (AD SID) nodes for collection members that are not SCCM clients (e.g. DC/WAC/HYPER-V: present in SMS_R_System via discovery but with no client-device record). CMBP (ps1:7617-7619) resolves a member only to a User, Group, or SCCM_ClientDevice node -- never a Computer; unresolved members get no edge and log 'No node found for member' (ps1:7646).

Root cause: _edge_has_member's SID fallback used the resource_to_sid lookup, which included r_system (computers). A non-client computer member resolved to its computer SID -> edge on the Computer node.

Fix (transforms.py): renamed resource_to_sid -> principal_by_resourceid and narrowed it to r_user + user_group only (no r_system), sibling to device_by_resourceid. _edge_has_member now coalesces device smsid then user/group SID; non-client computer members get no edge, counted via an INFO diagnostic. README SCCM_HasMember End corrected from Computer to SCCM_ClientDevice.

Validated on live lab lookup.duckdb: HasMember 43->40 edges, 40 ClientDevice preserved, 3 Computer edges (DC/WAC/HYPER-V) removed, 0 non-ClientDevice targets. New regression test tests/edge_has_member_test.py::test_edge_has_member_skips_non_client_computer; 209 unit tests pass. NOTE: dual SCCMResourceIDs (X@CAS + X@PS1) on Computer nodes is expected multi-site behavior, tracked separately.

## Notes

**2026-07-20T19:56:58Z**

Audit second-pass (2026-07-20): DONE, closing. Fix committed (d0857d4): resource_to_sid renamed to principal_by_resourceid and narrowed to r_user + user_group (no r_system); _edge_has_member coalesces device smsid then user/group SID, so non-client computer members (DC/WAC/HYPER-V) get no edge. Regression test tests/edge_has_member_test.py::test_edge_has_member_skips_non_client_computer present; resource_to_sid fully removed (0 refs). Body records live validation (HasMember 43 to 40, 3 Computer edges removed). The expected multi-site dual SCCMResourceIDs behavior is tracked separately under ope-90fc.
