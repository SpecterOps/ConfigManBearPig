# Preserve each administrator's role assignments

## Problem and approved design

SCCM can give one administrator different collections for different roles. The
previous calculation joined that administrator's separate role and collection
lists. That could create Full Administrator access over a collection assigned
only to another role. Putting collections on a shared role node would also mix
the boundaries of different administrators.

The owner approved this arrangement:

| Information | Location |
|---|---|
| Actions a role permits | The role node's existing `operations` property |
| Collections and security scopes assigned to one administrator for one role | That administrator-to-role `SCCM_IsAssigned` edge |
| Original assignment and role-action records | Saved collection data |
| Devices covered by a supported role assignment | Existing administrator-to-device role edges, with supporting collection IDs |

The five SCCM node kinds and existing relationship kinds remain the same.
Object-panel layouts remain the same. The SCCM schema's assignment-edge help
explains the new properties. Both schema copies remain identical.

## How collection works

[privileged.py](../../src/openhound_sccm/collectors/privileged.py), through
`_complete_objects`, lists administrators and roles and then reads each one by
its native key. Live tests confirmed that normal queries leave `Permissions`
and `Operations` empty. Adding those fields to a normal query is insufficient.

AdminService reads `/AdminService/wmi/SMS_Admin(<AdminID>)` or
`/AdminService/wmi/SMS_Role('<RoleID>')`. The provider returns a single object in
its `value` array. WMI's local
[client wrapper](../../src/openhound_sccm/clients/wmi.py), `read_instance`, uses
`GetObject` for DCOM or `Get` for Windows WMI through the already authenticated
connection. DCOM object references are released after reading.

The collector checks that the returned key matches the requested object. Failed
or mismatched reads keep the summary but mark its details incomplete and log a
warning. `permissions_complete` and `operations_complete` record whether the
respective array was retrieved. Embedded records retain their original field
names and values; only the surrounding resource fields use the collector's
existing snake-case convention.

This costs one additional read per administrator and per role on each collected
provider. It adds no per-device requests. Individual reads are necessary because
the provider omits these fields from ordinary queries.

For example, an administrator's saved `permissions` array retains `RoleID`,
`RoleName`, `CategoryID`, `CategoryName`, and `CategoryTypeID`. The role's saved
`operations` array retains `ObjectTypeID` and `GrantedOperations`. These are SCCM
permission numbers, not a newly implemented interpretation of custom roles.
The existing role-node property represents each action record as a JSON string,
because graph properties cannot contain arrays of embedded objects.

## How the graph is calculated

[role_assignments.py](../../src/openhound_sccm/role_assignments.py) builds two
DuckDB tables during preprocessing:

1. `admin_role_assignments` groups original entries by administrator and role.
   `CategoryTypeID = 1` supplies collection IDs; `29` supplies security-scope IDs.
   IDs are normalized for comparison while the saved originals remain unchanged.
   Missing arrays, explicit failed reads, malformed entries, or unknown category
   types withhold the affected read's calculated access and produce a warning.
   An individually retrieved empty array is valid and grants nothing.
2. `admin_collection_permissions` follows limiting-collection descendants for
   each assignment. It retains the original assigned collection as evidence.
   Recursive `UNION` removes duplicates and terminates cycles. Membership
   expansion stays in DuckDB rather than building device lists in Python memory.

[transforms.py](../../src/openhound_sccm/transforms.py) then applies the records:

- `_edge_is_assigned` puts native `collectionIds` and `securityScopeIds` on each
  administrator-to-role edge. IDs such as `SMS00001` have no graph `@CAS` suffix.
  Administrator-to-collection edges and node lists remain useful overviews.
- `_edge_rbac_role_grants` uses each role's own collection coverage and observed
  device membership. Each resulting role edge records its supporting original
  assigned `collectionIds`. Overlapping collections can support multiple roles
  without allowing those roles to borrow each other's assignments.
- `_edge_all_permissions` retains the existing Full Administrator/global
  collection check, but requires both global collections on that exact role.
- `_graph_edges_dedup` unions evidence from duplicate observations. Missing
  evidence remains NULL; a known empty assignment remains an empty list.
  `_graph_edges_split` retains the evidence in every applicable output file.

[SCCMRoleEdgeProperties](../../src/openhound_sccm/graph.py) and
[GraphEdge](../../src/openhound_sccm/models/graph_edge.py) emit those two optional
properties only where evidence exists. Missing properties indicate unavailable
details. Security scopes remain separate from collection membership: they govern
objects such as applications and scripts, not a second list of devices.

The optional administrator Tier Zero selector now requires `SMS00001` on the
supported role's assignment edge. A separate All Systems overview edge cannot
satisfy it. The selector remains disabled by default. The synthetic test graph
includes an administrator with scoped Full Administrator and global Read-only
Analyst to catch accidental mixing.

## Alternatives considered

- **Another assignment node:** can express the same information, but introduces
  more objects, relationships, and queries. The existing assignment edge already
  identifies the administrator and role, so properties preserve the needed pairing.
- **Collections on the role node:** loses which administrator received which
  collections. The shared role node stores the role's actions instead.
- **Complete raw administrator permissions on every edge:** repeats unrelated
  assignments. Original data stays in the collection; each graph edge carries
  the assignment relevant to that relationship.
- **Guessing pairings when details are missing:** could restore false access
  claims. The collector warns and withholds those calculations instead.

No dependencies were added. No changes were made to OpenHound or the shared
library. Individual complete-object reads could eventually be useful to other
collectors; moving that capability into the shared library would require a
separate owner-approved proposal.

Microsoft documents the lazy fields on
[SMS_Admin](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/servers/configure/sms_admin-server-wmi-class)
and [SMS_Role](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/servers/configure/sms_role-server-wmi-class).
The original assignment field meanings and category numbers are documented on
[SMS_APermission](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/servers/configure/sms_apermission-server-wmi-class).

## Validation

Workstation evidence is under
`C:\Users\domainadmin\.tmp\cmbp-rbac-20261026`.

- The focused affected-file selection passed **145 tests**, covering collection,
  both WMI backends, missing details, distinct role boundaries, shared roles,
  overlapping devices, security-scope separation, inheritance/cycles, hierarchy
  access, evidence merging, conversion, schemas, and optional rule structure.
- A broader CI selection passed **160 tests**, including command wiring and the
  existing object-panel checks. After the final SQL readability cleanup and
  assignment-help updates, the relevant selection passed another **31 tests**.
  These selections overlap; the counts are separate runs, not a combined total.
- The final role-assignment regression selection passed **15 tests**, including
  the Full Administrator/Read-only split used by the live check.
- Ruff lint and mypy passed for the eight changed source files, and formatting
  checks passed for the new Python files. Source and wheel builds succeeded as
  `2.0.5.dev0`; the wheel includes the new assignment module.
- Both live transports read two administrative records and fifteen role
  definitions from `ps1-sms.mayyhem.com` (`10.10.11.54`). Every detailed array was
  retrieved. The current lab user has only CMPivot Administrator; the earlier
  screenshot's two-role configuration is no longer present. The separate
  disposable-account check below verifies a deliberately split assignment.
- Real DLT preprocessing preserved every original administrator assignment.
  The emitted role-node operation records matched the original action records.
  The ordinary split-output writer produced the live graph successfully.
- Replayed both preprocessing and conversion against the same older cached
  database with the saved before-change code and the new code. Both had **99
  nodes**. Edge counts changed from **322 to 307**: only fifteen calculated role
  or hierarchy-wide access claims were removed because the older collection had
  no detailed assignments. No other relationship triples changed.

The manual [live authorization check](../../tests/integration/role_assignment_access.ps1)
created a temporary AD account, two empty assigned collections, and an empty child
under each. Full Administrator was assigned to one parent and Read-only Analyst
to the other, with the same All object scope for both. Using that temporary
account's credentials, changing the Full Administrator child's comment succeeded.
The Read-only child's change was refused: the SMS Provider's extended status
explicitly said that account did not have modify permission. Its comment remained
unchanged. All temporary objects were removed; independent queries confirmed
zero remaining test collections, SCCM administrators, or AD accounts. No device
actions or existing account assignments were changed.

The first version of this check tried modifying a directly assigned collection.
Microsoft protects those collections from Modify/Delete, even when the role has
those actions. The corrected check uses children limited by the assigned parents,
as described in [Microsoft's collection-security documentation](https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/configure/configure-role-based-administration#configure-collections-to-manage-security).
All test objects from the earlier attempts were also removed. The provider wraps
the expected refusal in `GenericFailure`; the script checks the extended status
instead of accepting an unrelated connection or service failure as a denial.

The graph's assignment builder was also run against the actual live test's saved
permission entries. It retained exactly the Full Administrator parent on that
role and the Read-only parent on the other role, with All object scope on both.

Saved reports include `live-summary.json`, `live-validation.log`, `live-authorization.json`,
`live-authorization-model.json`,
`cached-comparison.json`, and the before/after graphs under `cached/`.
The tests do not establish every built-in role's execution prerequisites or
evaluate arbitrary custom roles. The manual check is deliberately separate from
the ordinary offline suite because it creates and removes lab objects.

The local Neo4j integration selection was not rerun: its saved test installation
had no running server or Java executable available in the checked tool locations.
Rule structure was checked offline, including its required edge property. The
new split-role fixture remains available for the existing optional integration
test. No new graph files or schema changes were uploaded to BloodHound.

### Existing release dependency issue

The isolated environment has OpenHound 0.2.12 and published shared library 0.1.4.
The original core permission tests passed against those packages. The collector's
pre-existing startup code imports `openhound_collector_common.dlt.progress`,
which is absent from that installed package and present in the local shared
checkout. Full current-working-tree conversion and broader tests therefore used
that checkout through `PYTHONPATH`, without editing or installing it. This is
evidence for the local working tree, not proof that a fresh published installation
can start. The existing release dependency mismatch requires separate resolution.

An intermediate whole-tree check found an undefined `_cli_seed_targets` call in
`main.py` while that file was being changed independently. The owner requested a
separate investigation. The function has since been restored by the ongoing work
and matches the committed implementation. Names, files, combined inputs, and no
inputs all passed direct checks. Whole-tree Ruff and mypy checks now pass again.
No edits were made to `main.py` here. See the
[separate investigation](2026-10-26-cli-seed-investigation.md).

### Approved warning correction

The owner approved correcting the warning that called CMPivot Administrator a
custom role. The message now says that the assigned role is unsupported for
device-access calculations and can be built-in or custom. The query, supported
role list, and graph calculations are unchanged. The older known omitted roles
remain quiet; unfamiliar IDs are reported without guessing their type.

Adding only CMPivot to the quiet list would hide that particular warning while
leaving future built-in roles mislabeled. Using accurate wording handles both
new built-in IDs and custom IDs without changing support.

The follow-up selection passed **27 tests**, including both actual custom-role
and CMPivot inputs, assignment boundaries, and command-line options. Whole-tree
Ruff and mypy passed (64 source files). Reprocessing the saved live snapshot
retained exactly the same **132 edges**, including all properties. Evidence is
under `C:\Users\domainadmin\.tmp\cmbp-role-warning-20261026` in
`graph-comparison.json`, `replay.log`, and `cli-investigation.json`.
No new dependency, collection request, node, relationship, or schema change was
needed for this wording correction. The shared-package mismatch remains a
separate follow-up at the owner's request.

## Manual verification

Use a fresh PowerShell window in this repository. This workstation's matching
local development environment can be selected without changing either shared
repository:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.codex\venvs\configmanbearpig-pz'
$env:PYTHONPATH = 'C:\Users\domainadmin\ConfigManBearPig\src;C:\Users\domainadmin\openhound-collector-common\src'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:RUNTIME__LOG_PATH = Join-Path $env:TEMP 'cmbp-role-review-logs'

uv run --no-sync --offline python -B -m pytest tests/role_assignments_test.py tests/privileged_permissions_test.py tests/privileged_test.py tests/wmi_client_test.py tests/edge_rbac_role_grants_test.py tests/edge_all_permissions_test.py tests/privilege_zone_rules_test.py -q
uv run --no-sync --offline python -B -m ruff check --no-cache src tests
uv run --no-sync --offline python -B -m mypy src/openhound_sccm

# Collect while signed in as the lab's domainadmin, using a new directory.
uv run --no-sync openhound collect sccm .\out-role-review --run-all

# Optional live authorization check: creates and cleans up temporary lab objects.
# Use Windows PowerShell with remote WMI access to the lab.
.\tests\integration\role_assignment_access.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -EvidencePath "$env:TEMP\cmbp-role-access.json"
```

Inspect saved administrator `permissions` and role `operations` records, then
inspect the administrator-to-role assignment edges in the emitted JSON or in a
fresh test graph. Confirm that collection IDs stay paired with their roles.
Compare each device-access edge's `collectionIds` to those original assignments.
The README includes a copyable Cypher query.

Older saved collections must be recollected: preprocessing cannot invent missing
evidence. Old graph uploads can retain stale relationships, so use a fresh test
graph or remove the older collection before comparing results. Upload the updated
SCCM schema and replace the optional administrator rule if you use it. Follow
the extension guide's existing upload instructions after reviewing the files.

## Suggested review and commit

There are substantial earlier uncommitted changes. Review this change separately
using the saved before-change copies and the paths below. Existing schema, README,
architecture, and extension files also contain earlier work; choose hunks carefully.
No staging, commits, pushes, or BloodHound uploads were performed by the agent.

```powershell
git diff -- src/openhound_sccm/collectors src/openhound_sccm/clients/wmi.py src/openhound_sccm/transforms.py src/openhound_sccm/graph.py src/openhound_sccm/models/graph_edge.py src/openhound_sccm/edge_help.py src/openhound_sccm/schema_SCCM.json README.md ARCHITECTURE.md .github/workflows/ci.yml tests

# Stage the new files after review.
git add -- src/openhound_sccm/role_assignments.py tests/role_assignments_test.py tests/privileged_permissions_test.py tests/integration/role_assignment_access.ps1 docs/changes/2026-10-26-role-assignments.md

# Select this change's hunks from tracked files, including its targeted test updates.
git add -p -- src/openhound_sccm/collectors/privileged.py src/openhound_sccm/collectors/sms_rows.py src/openhound_sccm/clients/wmi.py src/openhound_sccm/transforms.py src/openhound_sccm/graph.py src/openhound_sccm/models/graph_edge.py src/openhound_sccm/edge_help.py src/openhound_sccm/schema_SCCM.json README.md ARCHITECTURE.md .github/workflows/ci.yml tests .tickets/Ope-rhzx.md

# These extension files and the fixture were already untracked before this change.
# Review their complete contents before staging them together with the earlier work.
git add -- extension/README.md extension/schema_SCCM.json extension/privilege_zone_rules/t0-hierarchy-administrators.json tests/data/privilege_zones/graph.json
git diff --cached
git commit -m "Preserve SCCM role-specific collection assignments" -m "Retain original permissions and retrieve lazy role actions; calculate access from each role's own collections; attach assignment evidence; describe unsupported roles accurately; update the optional Tier Zero rule, documentation, and focused tests. No new dependencies or shared-library changes."
```

Committing this independently after reviewing the evidence would give the model
correction a clear checkpoint. The commit commands above are for the owner only.
