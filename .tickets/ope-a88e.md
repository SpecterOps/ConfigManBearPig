---
id: ope-a88e
status: closed
deps: []
links: []
created: 2026-06-23T17:30:16Z
type: task
priority: 1
assignee: cthompson
tags: [sccm, preproc, collect, group-resolution, real-data]
---

# Stage 1 hardening: SMS_R_UserGroup group resolution + node_site/node_group/role real-data fixes

Stage 1 hardening against real lab data (mayyhem.com). Reproducing 'openhound preprocess sccm' surfaced: (1) node_group UNNEST crash + 0 real groups; (2) node_site drops site_definitions (missing site_guid binder error); (3) node_computer dirty roles (smb/registry emit JSON-array TEXT in a VARCHAR). Fixes: add SMS_R_UserGroup collection (UniqueUsergroupName+SID, validated 13/13 group-name->SID) feeding principal_by_name; CAST JSON->VARCHAR[] for node_group unnest; _ensure_columns guard on node_site; harden _arr to parse JSON-text-in-VARCHAR AND fix smb.py/registry.py to emit clean role lists. TDD + README + ARCHITECTURE. No commits.

## Notes

**2026-06-23T17:59:02Z**

Implemented + validated (TDD, isolated uv env: 96 passed). Changes: (1) SMS_R_UserGroup collection - USERGROUP_COLUMNS in sms_rows.py + _user_group in privileged.py/_COLLECTIONS -> adminservice_user_group/wmi_user_group; added to _preproc_table_map; fed (unique_usergroup_name,sid) into principal_by_name. (2) _node_group UNNEST now routes security_group_name through _arr (JSON->VARCHAR[]). (3) _node_site gained _ensure_columns guard (recovers site_guid/sql_*). (4) _arr parses JSON-array-text-in-VARCHAR; registry.py _roles() always emits a list (matches smb.py). Live-validated against ps1-sms: SMS_R_UserGroup exposes SID+UniqueUsergroupName, 13/13 group names resolve, node_group 0->21 on real data; node_site recovers sql_server_name; node_computer roles clean; 0 transform errors. Added collectors/__init__.py + clients/__init__.py (were missing vs models/kinds). README + ARCHITECTURE updated. NOTE: user must RE-COLLECT to populate user_group tables (current C:\tmp\redo collection predates the collector). Pre-existing ruff/mypy noise (unused imports in main.py, logger.verbose) left for ope-1f0f.
