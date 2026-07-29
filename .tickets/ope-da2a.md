---
id: ope-da2a
status: closed
deps: []
links: []
created: 2026-06-11T16:36:10Z
type: task
priority: 3
---

# Filter debug_per_host.py to specific collectors (mirror -m)

Add COLLECTION_METHODS knob to debug_per_host.py to filter per-host phases, mirroring the -m/--collection-methods CLI flag. Wired through the same should_run=ctx.method_enabled(phase.name) gate the CLI uses in _run_per_host_stage.

## Notes

**2026-06-11T16:36:19Z**

Done. debug_per_host.py: added COLLECTION_METHODS constant, wired into SourceContext, and passed CLI-identical should_run=lambda t,p,c: c.method_enabled(p.name) to run_pipeline. Verified gating: All->3 phases, AdminService->1, RemoteRegistry,MSSQL->2. Updated docstring tips + README dev-tools line.
