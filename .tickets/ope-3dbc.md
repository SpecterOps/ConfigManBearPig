---
id: ope-3dbc
status: closed
deps: []
links: []
created: 2026-06-29T16:25:42Z
type: bug
priority: 1
tags: [convert, opengraph, bloodhound]
---

# Convert emits null OpenGraph properties -> BloodHound schema validation rejects file

BloodHound rejected sccm_nodes-1.json: OpenGraph schema validation failed with 'got null, want string/number/boolean/array' on 38 node properties (disableLoopbackCheck, dNSHostName, SMBSigningRequired, etc.), plus a cascading critical 'error closing graph object: expected }, got {'. Root cause: the convert emit path serializes node/edge dataclasses via asdict() + the destination's plain json.dumps, which keeps optional fields left at their None default as JSON null. BloodHound's OpenGraph property schema is anyOf[string,number,boolean,array] and rejects null, so one null sinks the whole file. The framework's Pydantic path strips None via exclude_none=True; the dataclass path did not. Fix: _without_null_properties() in convert_pipeline.py drops None-valued properties on every node and edge before emit (empty arrays kept; missing != null). Also fixed source_kind placeholder 'Kind' -> 'SCCM' in main.py so data is tagged under the real source. Tests: tests/convert_pipeline_test.py::test_emit_omits_null_properties. Docs: ARCHITECTURE.md section 10. Verify: re-upload regenerated files (or c:/tmp/redo/graph/fixed/) to confirm both the validation errors and the critical parse error clear.

## Notes

**2026-06-29T17:07:03Z**

Convert null-properties fix (convert_pipeline._without_null_properties + main.py wiring + convert_pipeline_test.py) staged alongside Stage 4 (ope-9271) in the same commit per user; MSSQL excluded.
