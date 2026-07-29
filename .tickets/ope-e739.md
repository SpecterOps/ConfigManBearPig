---
id: ope-e739
status: closed
deps: []
links: []
created: 2026-07-20T18:32:32Z
type: bug
priority: 2
tags: [sccm, possible-client, cmbp-parity, has-client]
---

# Inferred CmRcService clients attached to CAS root instead of a Primary site

Inferred (CmRcService-only) SCCM_ClientDevice nodes are attached to the hierarchy root site via SCCM_HasClient. When the root is a Central Administration Site, this produces a CAS -> client edge, which is semantically impossible (a CAS cannot own clients). ConfigManBearPig (ps1:3253-3254) deliberately attaches these to the first PRIMARY site; the port dropped that filter and used _root_code (the CAS) instead. Also, the collector's own site_code guess (ldap.py:314 sorted(ctx.site_codes)[0]) can select the CAS because a CAS publishes an mSSMSSite object too.

## Design

Two independent fixes. (1) transforms._node_client_device_possible: set site_code to _first_primary_code (MIN site_code WHERE site_type=2 in site_hierarchy), falling back to root only when no primary exists. Keep smsid=<SID>@root for id namespacing. (2) collectors/ldap.py: track ctx.primary_site_codes from MP-capabilities site_type during ldap_management_points_raw; ldap_cmrc_devices picks a Primary via _pick_client_device_site_code, falling back to any known site code. Transform is authoritative for the graph; collector fix corrects raw-data hygiene.

## Acceptance Criteria

Possible-client with CAS+Primary hierarchy attaches HasClient to the Primary, not the CAS. Degenerate CAS-only hierarchy falls back to root. Collector selects a Primary when MP data identifies one. Targeted offline tests pass. README SCCM_HasClient + ARCHITECTURE.md 11b updated.

## Notes

**2026-07-20T18:43:09Z**

Fixed + validated offline. transforms._first_primary_code + _node_client_device_possible now stamp site_code=first Primary (MIN site_type=2), fallback root. collectors/ldap.py _pick_client_device_site_code + ctx.primary_site_codes (from MP-capabilities site_type in ldap_management_points_raw). Docstrings, ARCHITECTURE.md 11b+changelog, README (SCCM_HasClient + possible-client note) updated. Tests: node_client_device_possible_test.py (rewritten: primary-attach + root-fallback + disabled), ldap_cmrc_site_code_test.py (new). Re-ran transforms() over a copy of live sccm/sccm/lookup.duckdb: HI2-PSS HasClient moved CAS -> PS1; 0 CAS-origin HasClient edges remain. 6 targeted + 22 related client-device/edge/convert tests green. ruff: only pre-existing DACL-parser warnings (untouched). Left for user live-graph re-ingest test before close.
