---
id: Ope-pofz
status: open
deps: []
links: []
created: 2026-06-01T15:38:50Z
type: feature
priority: 2
assignee: Mayyhem
---
# Add --skip-ad-enum option to suppress AD-derived object creation

Add a CLI flag (--skip-ad-enum or similar) that prevents the creation of Computer, User, and Group objects that are derived from AD system/group discovery objects in SCCM. When this flag is set, the collector should still enumerate SCCM data but skip populating BloodHound nodes that originate from AD discovery results.

## Acceptance Criteria

- A --skip-ad-enum (or similarly named) CLI flag is accepted\n- When the flag is set, no Computer/User/Group objects are created from SCCM AD system or group discovery data\n- SCCM collection data is still gathered normally\n- Behavior is documented in --help output

