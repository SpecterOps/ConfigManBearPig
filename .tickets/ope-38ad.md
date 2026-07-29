---
id: ope-38ad
status: closed
deps: []
links: [ope-3f2a]
created: 2026-06-12T17:29:00Z
type: chore
priority: 2
assignee: cthompson
tags: [sccm, refactor, collectors, wmi, adminservice, dry, simplify]
---

# Merge AdminService + WMI collectors into privileged.py; genericize WmiClient

Merge collectors/adminservice.py and collectors/wmi.py into one collectors/privileged.py to remove the hand-maintained mirror duplication. One set of ten collection helpers + one orchestrator, parameterized by a small _Run object (transport fetch closure + flavor name + equality operator + site_code + ctx); two thin entry points collect_adminservice/collect_wmi keep the two registered phases. Genericize clients/wmi.py into a transport-only WMI client (remove identify/_site_code_from_providers/root\SMS coupling; new query(namespace, class_name, columns=, where=) streaming iterator with lazy auth ladder on first query). Make both transports stream (impacket/pywin32 backends become generators). Mark completed_phases at END of collection for both flavors (PS1-faithful; reverses the current adminservice mark-after-identify). Scope: production + tests (fold test_adminservice/test_wmi into test_privileged, trim test_wmi_client to the generic client) + debug scripts (debug_wmi_auth uses adapter identify; fix stale comment in debug_per_host) in one pass. Spec: sccm/sccm/docs/superpowers/specs/2026-06-12-merge-privileged-collectors-design.md

## Notes

**2026-06-12T17:56:22Z**

Implemented + validated. Merged adminservice.py+wmi.py -> collectors/privileged.py (one _Run-parameterized helper set + orchestrator, two entry points); genericized clients/wmi.py to transport-only streaming WMI (namespace-per-query, lazy auth ladder, execquery/stream backends); end-of-collection completed_phases marking for both flavors; folded tests into test_privileged.py + trimmed test_wmi_client.py; updated debug_wmi_auth.py + debug_per_host.py. Validation: pytest 256 passed/5 skipped; ruff clean on changed files; mypy clean except codebase-wide logger.verbose pattern + one resolve_principal arg-type carried verbatim from old adminservice.py:189. Live lab (ps1-sms.mayyhem.com): debug_wmi_auth.py OK across ALL rungs (sspi/password/pth/ntlm/ptt). Left in_progress pending owner commit/test.
