---
id: ope-0f66
status: closed
deps: []
links: []
created: 2026-07-01T14:50:27Z
type: task
priority: 2
tags: [sccm, local, typing, tech-debt]
---

# local.py mypy 31->0: cross-resource state on SourceContext + unresolved-target guards + typed logger

Take collectors/local.py from 31 mypy errors to 0 by fixing root causes, not suppressing. (A) Move cross-resource module globals (site_code, current_mp_ad_obj, this_computer_ad_obj) onto SourceContext as current_site_code/current_mp_ad_object/this_computer_ad_object -- removes 18 name-defined errors AND a latent NameError when an earlier local resource didn't run. (B) Guard unresolved targets ('if target and target.ad_object') across the 3 local resources -- fixes a real AttributeError (None.get in a log line aborted the whole enumeration) plus null-row yields, and clears union-attr/misc. Also rewrote the client-log localhost-skip to a prebuilt set, fixing another None.lower() crash. Lazy-init ctx.site_codes locally (mirrors ldap.py). (C) Added typed get_logger()/VerboseLogger to log_context.py so logger.verbose type-checks; added win32com mypy override in pyproject.toml for the stubless import. Tests: tests/local_resources_state_test.py (6). Verified: mypy local.py=0, ruff clean on edited files, full suite 582 passed/5 skipped.
