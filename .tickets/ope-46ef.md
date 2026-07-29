---
id: ope-46ef
status: closed
deps: []
links: []
created: 2026-06-09T14:40:21Z
type: task
priority: 2
tags: [tests, refactor]
---

# Move mssql_epa_test.py into tests/ as test_mssql_epa.py

Move src/openhound_sccm/clients/mssql_epa_test.py to tests/ and rename to test_mssql_epa.py to match the tests/ prefix convention. Absolute import is unchanged. Update README.md:391 inline-tests sentence so per_host_phases_test.py is the lone remaining inline test.
