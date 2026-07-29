---
id: ope-ff28
status: closed
deps: [ope-272f]
links: []
created: 2026-06-29T14:11:52Z
type: task
priority: 1
tags: [mssql, adapter, output, validators]
---

# Stage 8.1: MSSQLHound output adapter (convert -> validator envelope)

Stage 8.1: pure-Python output adapter (src/openhound_mssql/output_adapter.py) reshaping OpenHound convert output into the MSSQLHound envelope the existing validators read (D6/D11/sec7). to_mssqlhound_json merges mssql_*-*.json graph files, normalizes edge start/end to {value}, dedupes edges by full JSON (matches writer.go StreamingWriter); to_mssqlhound_zip wraps it for the PS1 -InputFile (.zip) validator while the bare JSON satisfies Go ReadFromFile. Property names passed verbatim (incl hyphenated CVE keys). TODO marked for Stage 7 AD metadata:{} split. Tests: tests/unit/test_output_adapter.py (13 pass, incl real convert output).
