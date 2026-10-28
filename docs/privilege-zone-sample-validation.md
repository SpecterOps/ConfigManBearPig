# BloodHound privilege-zone sample validation

**Policy changed on 2026-10-22:** the collector now ships one policy with three
enabled infrastructure/computer rules and one disabled administrator rule. The
seven-rule live results below describe the earlier policy. See the
[current policy checks](#single-policy-checks-on-2026-10-22) and
[subsequent live installation](#current-policy-installed-on-2026-10-22) for this revision and
the [extension guide](../extension/README.md) for current upload instructions.

Tested on **2026-10-21**, against the BloodHound Enterprise instance reached through
the user's SSH forward on ps1-dev. The server reports version `v999.999.999`.
This is a development build; the findings below describe this instance rather
than every released BloodHound version.

**All seven corrected rules select exactly the expected objects in all four
samples.** The retest passed 28 direct query checks, 28 Zone Builder previews,
and 28 installed-rule membership checks after analysis. Each rule set was tested
independently. An additional combined-set check is described below.

The initial live run exposed three query compatibility failures that the earlier
Neo4j tests did not detect. Those failures were fixed in the rule files, with the
owner's approval, and all four archives were uploaded and tested again.
The policy, seven-file layout, and defaults are unchanged.

Focused offline and Neo4j fixture tests passed: **28 tests**, including a new
check preventing the unsupported query forms from returning. Ruff and formatting
checks passed for the updated Python test. No collector code, graph schema,
shared package, or dependency changes were needed.
The source and wheel builds passed. The source archive contains all seven final
rule files with exactly the same bytes as the tested checkout.

## What was tested

Each ZIP in `sample_data/` was uploaded separately using `start_upload`,
`upload_file`, and `end_upload` from the fork's archived
`OpenHound/bloodhound-upload/openhound_collector_common/bloodhound/client.py`.
Neither OpenHound nor collector-common was edited.

Before starting, the graph contained only BloodHound's internal `MigrationData`
object, no collected objects, and no ingest jobs. The existing 44 Tier Zero
selectors were saved for comparison. The collector's existing SCCM and MSSQL
schemas were registered without changing their files.

For each completed ingest, all seven JSON queries were sent unchanged to
`POST /api/v2/graphs/cypher`. Their complete sets of object IDs were compared
with expectations derived separately from the archives and the agreed policy.
The same queries were tested through Zone Builder's
`POST /api/v2/asset-group-tags/preview-selectors`, with `expansion: 0` to compare
the query's direct selections. Every successful preview returned exactly the
same expected object IDs as the direct graph query.

For the retest, the four managed-device rules were installed, analysis completed,
and each selector's stored member IDs were compared with the same expectations.
Those selectors were removed and analysis reset to the existing built-in rules.
The three hierarchy rules were then installed and checked in the same way. The
creation requests used the name, description, and Cypher seed format sent by
OpenHound's uploader, preserving BloodHound's default selector settings.

All temporary selectors, sample objects, and ingest history were then deleted,
and an empty graph was verified before uploading the next ZIP. Cleanup first
checked that the graph contained only IDs from that sample, allowing for
BloodHound's uppercase ID normalization. Only the selector IDs created by these
tests were removed; the original 44 selectors were left unchanged.

## Archives and ingest results

The labels below identify the full filenames in `sample_data/`.

| Label | Archive | Objects removed | Ingest result |
|---|---|---:|---|
| Privileged, possible edges | `configmanbearpig_collection_privileged_all-possible-edges_20260801_225955.zip` | 150 | All 6 files complete; no failed or partially failed files |
| Privileged, possible edges disabled | `configmanbearpig_collection_privileged_disable-possible-edges_20260801_230109.zip` | 149 | All 6 files complete; no failed or partially failed files |
| Unprivileged, possible edges | `configmanbearpig_collection_unprivileged_all-possible-edges_20260801_230258.zip` | 60 | All 6 files complete; no failed or partially failed files |
| Unprivileged, possible edges disabled | `configmanbearpig_collection_unprivileged_disable-possible-edges_20260801_230714.zip` | 46 | All 6 files complete; no failed or partially failed files |

During the initial investigation, the fourth archive once failed to report
completion within the initial wait. It was cleared and repeated successfully.
All four uploads in the final corrected-rule retest completed without failed or
partially failed files. The cause of the earlier delay was not established.

## Actual rule results

Numbers are objects selected, including separate SCCM and AD representations.
Every number below matched the expected object IDs exactly in the direct query,
Zone Builder preview, and installed selector after analysis. Each set was tested
independently so that the other set's labels did not supply additional inputs.

| Rule file, without `.json` | Privileged, possible | Privileged, disabled | Unprivileged, possible | Unprivileged, disabled |
|---|---:|---:|---:|---:|
| `t0-hierarchy-sites` | 2 | 2 | 2 | 2 |
| `t0-hierarchy-administrators` | 6 | 6 | 0 | 0 |
| `t0-managed-sites` | 2 | 2 | 2 | 0 |
| `t0-managed-administrators` | 6 | 6 | 0 | 0 |
| `t0-hierarchy-infrastructure` | 16 | 16 | 15 | 10 |
| `t0-managed-infrastructure` | 16 | 16 | 15 | 0 |
| `t0-managed-computers` | 2 | 2 | 2 | 0 |

Across four archives, **all 84 checks passed**: 28 direct queries, 28 previews,
and 28 installed memberships. This build returns HTTP 404 with
`resource not found` for an empty graph-query result; its preview API returns
HTTP 200 with an empty member list. Those confirmed empty results were counted
as successes where no objects were expected.

## Why the successful results are intended

The hierarchy site rule always selects **CAS and PS1**, while excluding SEC.
Both privileged captures select three administrators: `domainadmin`,
`networkaccess`, and `sqlsccmsvc`. Each has an SCCM administrator record and a
mapped AD user, giving six objects. The read-only analyst is excluded.
`networkaccess` qualifies through its Application Administrator assignment and
All Systems collection, independently of its name or use as a stored account.

The unprivileged captures contain no SCCM administrator records or assignments,
so both administrator selectors correctly return no objects. This describes
missing collection evidence, rather than proving that no privileged
administrators exist in the real hierarchy.

The first three samples declare PS1-DEV to be a member of Domain Admins and map
it to an SCCM client managed by PS1. BloodHound's existing analysis therefore
already gives its AD computer the `Tag_Tier_Zero` label. This supplies the managed
rules' input without adding any test seed. Both CAS and PS1 qualify because the
policy covers the whole hierarchy. The samples' group membership was used as
graph evidence; this test did not independently verify that membership in AD.

The unprivileged capture with possible edges disabled contains no SCCM client
nodes or `SCCM_HasClient` edges. The managed site rule therefore correctly selects
nothing even though the hierarchy site rule still selects CAS and PS1. Client
mapping is a required condition in the agreed design.

## Query compatibility fixes

Both original infrastructure files used `UNION`. This server rejected them with:

```text
cypher query could not be parsed: ... oC_Union rule is not supported
```

The original managed-computer file used `UNWIND [device, computer] AS n`. This
server responded with:

```text
query execution failed: array literal has no available type hints
```

Both infrastructure files now use one bounded same-host/SQL path and an optional
match from its controller to a controlled site. A result qualifies when its
controller is a computer with the exact site's site-server role, or is a computer
or database with an explicit control relationship to that site. The optional
match keeps passive site servers eligible even without such a relationship.

The managed-computer rule now matches a zero-or-one-hop same-host path to the
computer and requires the returned object to equal either the original client
or the original computer. This preserves the two representations without a list
of node values or accidentally including another client that maps to the same
computer.

Keeping `UNION` would leave valid Neo4j queries unusable on this instance.
Splitting each alternative into more rule files was considered, but the supported
forms preserve the existing seven rule names and independent sets. The fixture
and full live retest confirm the intended selections. Shared OpenHound code and
the collector's graph schema were unchanged.

The hierarchy infrastructure is six AD computers, two SQL instances, and two
site databases, plus whichever matching SCCM client representations are present.
The six hosts are CAS-PSS, CAS-DB, PS1-PSS, PS1-PSV, PS1-SMS, and PS1-DB.
The unprivileged capture with possible edges includes five of those client
representations; it lacks the CAS-PSS client representation. Disabling possible
edges in the unprivileged capture leaves the ten infrastructure objects without
client representations. MP/DP-only hosts, the secondary site's database, and
unrelated SQL objects are outside these expectations.

## Both sets enabled together

The first privileged archive was uploaded once more for an overlap check with
all seven selectors installed together. Analysis selected **37 Tier Zero objects**:
exactly the union of the original 13 objects selected by BloodHound's built-in
rules and the objects expected from the SCCM selectors. There were no missing
or unexpected object IDs.

The managed-computer selector had 14 members in this combined check, compared
with two when the managed set was tested independently. This difference is
intended: the hierarchy set qualifies the six control hosts and their six SCCM
client representations. They then satisfy the managed-computer rule alongside
the original PS1-DEV pair. All twelve additional representations already belong
to Tier Zero through the infrastructure rule, so this adds no objects outside
the expected combined zone. Rule membership counts depend on which other rules
supply Tier Zero input; the final zone membership is their union. Those seven
temporary selectors and the sample were removed afterward.

## Cleanup and retained configuration

Final checks confirmed **zero collected graph objects, zero relationships, zero
file-ingest jobs, and an idle datapipe**. Only the internal `MigrationData` object
remains, as it did at the start. All 44 original Tier Zero selector definitions
are unchanged. No sample ZIPs or logs in the repository were modified.

All four corrected-rule retest cleanup requests returned HTTP 204 and were
followed by empty-graph checks. Earlier investigation evidence is retained
separately, including the initial first-sample cleanup whose clear response was
not recorded before a transient HTTP error; separate checks verified its cleanup.

The SCCM and MSSQL schema definitions remain registered. The requested API key,
named `ConfigManBearPig PZ validation 2026-10-21`, also remains available. Its
secret is encrypted with Windows DPAPI for domainadmin at
`C:\Users\domainadmin\.codex\validation\cmbp-pz\bhe-api-key.dpapi`, outside the
repository. Neither the password nor an unencrypted token was saved to the test
results. The requested port 8080 refused connections during the retest; the
previously authorized port 80 forward still accepted the same API key and reached
the same server, so it was used. Signed requests used BloodHound's HTTP server time because
ps1-dev's clock was approximately four hours ahead; neither system clock changed.

## Evidence and manual verification

Detailed, secret-free responses, archive SHA-256 hashes, independently derived
expected IDs, and the combined `summary.json` are saved under the ignored
`out/pz-sample-validation/` directory. Temporary test helpers live outside the
repository under `.codex/validation/cmbp-pz/`. They use the existing isolated
project environment and add no package dependencies.

To repeat manually, first establish an empty test graph and register the two
existing schemas. Upload exactly one ZIP through File Ingest and wait for all
six files to complete. Paste each JSON file's `cypher` value into Explore, then
use the same query in a Zone Builder preview. Compare exact object IDs with the
saved expectations. Clear that sample's graph and ingest history, verify that
only internal graph metadata remains, and then move to the next ZIP.

Do not interpret Neo4j fixture checks as an alternative to these BloodHound
checks. The fixture remains useful for cases absent from these captures: two
hierarchies, all seven built-in roles, nested/cyclic groups, scoped and global
assignments, passive site servers, assumed paths, and deliberately unrelated
objects. Custom roles and the deferred escalation path remain excluded. These
captures cannot prove completeness when collection itself omits evidence.

The focused checks ran in the existing isolated project environment:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.codex\venvs\configmanbearpig-pz'
$env:CMBP_PZ_NEO4J_URL = 'http://127.0.0.1:18474'
uv run --locked --no-sync pytest tests\privilege_zone_rules_test.py tests\integration_privilege_zone_rules_test.py -q
uv run --locked --no-sync ruff check tests\privilege_zone_rules_test.py
uv run --locked --no-sync ruff format --check tests\privilege_zone_rules_test.py
```

Current review and commit commands are maintained in the
[extension guide](../extension/README.md#suggested-review-commit), including the
subsequent single-policy change. The custom-role ticket note is separate.
No files were staged or committed by the agent.

API references:
[official API definitions](https://github.com/SpecterOps/BloodHound/blob/main/packages/go/openapi/src/openapi.yaml),
[API authentication](https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api).

## Query comments added on 2026-10-22

All seven JSON rules now include standalone `//` comments inside their `cypher`
strings. They explain each match and condition, the supported role IDs and why
they qualify, the All Systems collection, hierarchy boundaries, assumed paths,
and duplicate removal. The Application Author prerequisite remains explicit.
Comments outside the strings would make the files invalid JSON; keeping separate
tracked query files was avoided because two sources could drift apart.

The executable query tokens and all other JSON fields were compared with their
saved originals and are unchanged. Readable copies of the commented queries were
written under the ignored `out/pz-rule-comments/` directory for local review.
The [extension guide](../extension/README.md#reading-the-query-comments) shows
how to display the authoritative JSON query as ordinary lines.

Validation passed: 40 existing offline tests, eight Neo4j graph-fixture tests,
Ruff, mypy across 63 source files, and source/wheel builds. The source archive
contains the current commented rule files. No dependencies were added.
The BloodHound forwards on ports 80 and 8080 were unreachable, so this follow-up
did not upload, replace, or clear anything in the live instance. Its commented
queries still need uploading when that connection is available; the earlier live
results above describe the same executable queries before comments were added.

## Single-policy checks on 2026-10-22

The hierarchy site and infrastructure queries are unchanged. The former
`t0-managed-computers.json` is now `t0-computers.json`, with the same executable
query and a name independent of the retired managed-device policy. The other
three managed-device selectors were removed.

`t0-hierarchy-administrators.json` now has `enabled: false`. Its query starts at
`SCCM_AdminUser` and returns only that record when a supported built-in role and
All Systems belong to the same hierarchy. It no longer returns mapped AD
identities or nested group members and does not inherit their Tier Zero labels.
Custom roles remain excluded.

Validation passed **41 tests**: 14 offline checks, seven Neo4j graph-fixture
checks, and the 20 required collector checks. The fixture administrator query
returns eight SCCM records: one per supported built-in role in the first
hierarchy and one global Full Administrator in the second. It excludes scoped,
read-only, custom-role, and cross-hierarchy assignments, all mapped AD users and
groups, and nested group members. Default rule results contain no administrator
records or role-derived AD identities. Temporarily marking a scoped
administrator's AD user T0 does not cause its SCCM record to qualify.

Ruff passed across `src` and `tests`, formatting passed for both affected test
files, and mypy passed for all 63 source files. Source and wheel builds passed.
The source archive contains exactly the four current rule files, byte-for-byte
matches of the checkout, and no retired managed-device files. No dependencies
were added. The local fixture database was verified empty before its server was
stopped.

The focused validation used the existing isolated environment, with all writable
test data and caches outside the repository's `.venv`:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.codex\venvs\configmanbearpig-pz'
$env:PYTHONPATH = 'C:\Users\domainadmin\ConfigManBearPig\src'
$env:CMBP_PZ_NEO4J_URL = 'http://127.0.0.1:18474'
uv run --no-sync --offline python -B -m pytest tests/privilege_zone_rules_test.py tests/integration_privilege_zone_rules_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py -q -p no:cacheprovider --basetemp C:\Users\domainadmin\.tmp\cmbp-pz-policy-pytest
uv run --no-sync --offline python -B -m ruff check --no-cache src tests
uv run --no-sync --offline python -B -m ruff format --check tests/privilege_zone_rules_test.py tests/integration_privilege_zone_rules_test.py
uv run --no-sync --offline python -B -m mypy --cache-dir C:\Users\domainadmin\.tmp\cmbp-pz-policy-mypy src/openhound_sccm
uv build --offline --out-dir C:\Users\domainadmin\.tmp\cmbp-pz-policy-dist
```

OpenHound 0.2.12 and the local OpenHound checkout omit `enabled` when creating or
overwriting selectors. The JSON default is therefore not evidence of a disabled
installed selector. A separate [OpenHound proposal](openhound-disabled-rules-proposal.md)
describes the fix; no shared repository was edited. Current upload instructions
copy only enabled files until that fix is approved and implemented.

No live BloodHound requests, sample uploads, deletions, rule replacements, or
analysis runs were performed for this revision. The previously restored manual
test data and selectors were not touched. The earlier live administrator result
of six objects included three AD identities and does not describe the new
SCCM-record-only query. Actual findings and revised installed memberships still
need live verification.

## Current policy installed on 2026-10-22

At the owner's request, all seven existing custom SCCM Tier Zero rules were
backed up and deleted. Their selector IDs were 80 through 86. The four current
JSON definitions, including the simplified comments, were uploaded through the
authorized SSH forward on port 80. All deletes returned HTTP 204 and all creates
returned HTTP 201. No OpenHound or collector-common code was changed.

The optional administrator rule was initially created with an empty-result
query. A successful PATCH then installed its actual query with `disabled: true`
in the same request. Readback confirmed its disable timestamp. This manual API
operation avoids relying on the uploader's ignored `enabled` flag; the separate
OpenHound implementation proposal remains pending approval.

| Current rule | Selector ID | Installed state | Members after analysis |
|---|---:|---|---:|
| `t0-computers` | 87 | Enabled | 14 |
| `t0-hierarchy-administrators` | 88 | Disabled | Not evaluated |
| `t0-hierarchy-infrastructure` | 89 | Enabled | 16 |
| `t0-hierarchy-sites` | 90 | Enabled | 2 |

All three enabled selectors' exact member IDs matched their previews. The
administrator preview selected three SCCM records and no mapped AD identities.
Its membership endpoint returned HTTP 409, `selector is disabled`, as expected
for its installed state. The saved query and descriptions match the current
files exactly.

Analysis completed and returned to idle. The final zone contains **32 objects**,
down from 37. The five removed T0 classifications are the SCCM administrator
records for domainadmin, networkaccess, and sqlsccmsvc, and the AD users for
networkaccess and sqlsccmsvc. The AD domainadmin account retains its independent
T0 classification. No `SCCM_AdminUser` record is now tagged T0.

The final inventory contains exactly four custom rules and the same 44 built-in
rules. All built-in selector definitions are byte-for-byte equivalent as decoded
JSON objects to their backups. All 149 collected object IDs and collected
properties were preserved. Only the expected classification-related
`system_tags` property changed on the five objects removed from T0.

Backups, every mutation response, previews, installed memberships, graph snapshots,
and `current-policy-installed-summary.json` are retained under the ignored
`out/pz-sample-validation/` directory. This installation used the already loaded
privileged sample with possible edges disabled. It did not upload or clear any
graph data, repeat the four-archive tests, or establish actual finding generation.
