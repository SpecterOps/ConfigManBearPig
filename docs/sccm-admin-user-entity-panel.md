# SCCM Administrative User panel

The original administrator panel design called for clickable account and audit
fields, individual named role and collection rows, and control queries. Current
BloodHound schema templates cannot fetch other objects, replace the built-in
Object Information table, hide empty accordions, or run queries on expansion.
The administrator's saved assignment arrays contain IDs rather than the related
objects' names.

The owner requested Security Roles populated from the existing `memberOf`
(Member Of) property, and Collections from `collectionIds` (Collection IDs).
Each saved full node ID gets its own plain Explore link, labelled by that ID.
The two control sections retain one query link each. Uploading the schema is
sufficient for existing data. It changes no labels, identifiers, properties,
or relationships and adds no Related Objects section.

## What appears

Object Information remains BloodHound's ordinary property table. The additional
sections follow it in this order:

| Section | Link | Query result |
|---|---|---|
| Security Roles | One link per saved ID in `memberOf`. | The `SCCM_SecurityRole` with that exact object ID. |
| Collections | One link per saved ID in `collectionIds`. | The `SCCM_Collection` with that exact object ID. |
| Inbound Object Control | Show incoming control paths | One-hop paths ending at this administrator. |
| Outbound Object Control | Show outgoing control paths | One-hop paths starting at this administrator. |

There are no tables, repeated inner headings, aggregate assignment links,
Related Objects section, or duplicate Object Information section. The saved SID,
source site, creator, modifier, and dates remain ordinary properties. A link
queries the graph only when clicked; opening an accordion runs no graph query.

The existing account labels remain unchanged. The original request to display
`LogonName@SourceSiteCode` was not applied because it would change graph data.
For example, the saved lab administrator has the stable ID
`MAYYHEM\DOMAINADMIN@CAS`, while its recorded source site is `PS1`. Neither value
is rewritten or used to invent a replacement ID.

## How the links work

The hand-maintained [packaged SCCM schema](../src/openhound_sccm/schema_SCCM.json)
defines `security_roles`, `collections`, `inbound_object_control`, and
`outbound_object_control` under `SCCM_AdminUser.info`. The
[upload copy](../extension/schema_SCCM.json) is identical. All other schema
definitions, including the existing Site panel, are preserved.

Security Roles reads only `.Properties.memberOf`; Collections reads only
`.Properties.collectionIds`. Each array is deduplicated and sorted. Empty and
whitespace-only entries are omitted. Every other entry is preserved exactly,
including its hierarchy suffix, and receives a separate link. No administrator
ID is needed to render these two sections. Missing or null arrays render no links.
The labels escape Markdown and HTML punctuation, keeping saved IDs as text.

The control templates read only `.Properties.objectid`, which BloodHound supplies
for the selected administrator. A missing, null, empty, or whitespace-only ID
produces no control link; the accordion remains. Each query's ID is preserved
exactly. The templates escape backslashes, single quotes, carriage
returns, newlines, and tabs before placing that ID in a quoted Cypher value.
`b64enc` and `urlquery` encode the query into the Explore URL, following the
existing Site panel convention. Every object lookup also specifies its expected
kind, so a different type with a similar ID is not selected.

Each role link queries `SCCM_SecurityRole.objectid`; each collection link queries
`SCCM_Collection.objectid`. There is no lookup through `SCCM_IsAssigned`, no
fallback to `roleIDs`, and no broad account-name or hierarchy lookup. A custom
role works the same way as a built-in role because the saved ID selects it
directly. In the retained lab output, `roleIDs` is empty while `memberOf` contains
`SMS0001R@CAS`; the latter supplies the Full Administrator link.

The rows reflect the arrays already saved on the administrator. Changing an
assignment elsewhere in the graph does not rewrite these arrays. Clicking a link
selects the object currently present at that full ID, even if its name changed.
An object that was not ingested or has since been removed gives an empty result.

Control queries use the same directed, single-edge pattern and kind list as
the Site panel. The list matches
[TRAVERSABLE_EDGE_KINDS](../src/openhound_sccm/kinds/edges.py). Inbound paths end at
the selected administrator; outbound paths start there. `RETURN DISTINCT path`
preserves the administrator, neighbor, and relationship. Different relationships
between the same objects remain visible. The queries have no recursive expansion
or hard-coded result limit. Inferred relationships qualify when their kind is
in the traversable set. No traversal setting or permission is changed.

## Why this approach and its limits

The [Entity Panel Content documentation](https://bloodhound.specterops.io/opengraph/developer/entity-panel-content)
defines templates over the selected object's properties. It does not provide
queries during rendering, conditional accordion removal, or custom replacements
for Object Information. Loops over existing arrays supply individual assignment
links; control relationships are queried through a single link per direction.

Adding saved names to the administrator would require changed graph data and
another ingestion. Hard-coding names for built-in role IDs would not cover custom
roles or collections. ID-labelled links therefore make the saved assignments
clickable without claiming to know names that are not stored on this record.
The earlier aggregate assignment queries were replaced at the owner's request:
they did not populate the section from its corresponding array. Duplicating audit
fields in another section would conflict with the request not to add Related
Objects. These alternatives were not selected.

An empty array can reflect incomplete collection. An empty linked-object result
can mean the target was not ingested. An empty control query can mean no matching
direct relationship was ingested. None proves that the account has no access.
Empty arrays and query results do not remove an accordion. BloodHound's own query
and display limits still apply.

The [Site spacing investigation](sccm-site-entity-panel.md#why-the-visible-gap-remains)
also applies here: BloodHound adds accordion padding and paragraph margins. The
owner chose to retain that spacing as a documented limitation. The schema does
not inject styles. The requested Stacked control-result layout remains a manual
BloodHound selection, as described in the
[Site layout notes](sccm-site-entity-panel.md#requested-stacked-layout).

There are no new runtime or test dependencies. Go remains an optional test tool
already used by the Site checks. Collection, preprocessing, conversion, models,
shared repositories, and architecture are unchanged. Two inaccurate administrator
README entries were corrected: the display-name key is `displayName`, and the
current `memberOf` output stores role node IDs while `collectionIds` stores
collection node IDs.

## Apply and manually verify

1. Upload [extension/schema_SCCM.json](../extension/schema_SCCM.json) through
   **Administration > OpenGraph Management > Upload File**.
2. Reopen the existing `MAYYHEM\DOMAINADMIN@CAS` SCCM administrator. Object
   Information should be followed by the four sections listed above. There
   should be no Related Objects section or duplicate property table.
3. Under Security Roles, expect `SMS0001R@CAS`, from `memberOf`. Follow it to
   Full Administrator. Its existing `roleIDs` array can remain empty.
4. Under Collections, expect `SMS00001@CAS` and `SMS00004@CAS`, from
   `collectionIds`. The links select All Systems and All Users and User Groups,
   respectively. There should be one link for each saved ID, without pipe borders.
5. Follow **Show incoming control paths**. The AD identity's mapping and any
   qualifying direct site containment relationships should be visible as paths.
6. Follow **Show outgoing control paths**. Any existing direct control edges,
   such as Full Administrator to clients or All Permissions to a site, should
   be visible. Longer paths and non-traversable assignment edges are excluded.
7. Reopen a Site and confirm its existing administrator/system lists and control
   links still work. The expected accordion spacing remains in both panels.

For an exact lookup of the existing lab administrator, paste this into Explore:

```cypher
MATCH (admin:SCCM_AdminUser {objectid: 'MAYYHEM\\DOMAINADMIN@CAS'})
RETURN admin
```

No collection, preprocessing, conversion, or graph upload is needed. Changing
the schema does not change account labels or the saved graph. Live BloodHound
rendering and query results still require manual verification; local template
checks do not prove the screen layout or installed-version behavior.

## Validation

[Administrator panel tests](../tests/admin_user_entity_panel_test.py) use the
shared test-only Go renderer in [conftest.py](../tests/conftest.py) and
[render_entity_panel.go](../tests/support/render_entity_panel.go). The existing
[Site tests](../tests/site_entity_panel_test.py) use that same renderer, compiled
once per test run. An absent Go installation explicitly skips rendering tests;
a configured compiler that fails is a test failure.

The checks cover section order, the absence of Related Objects, property use,
plain-link formatting, exact IDs in two hierarchies, label and query escaping,
missing control identifiers, array-only population, target types, sorting,
deduplication, empty saved arrays, one-hop control paths, and traversable-kind
agreement. The Site tests also check
that the upload and packaged schemas match. They inspect generated text and
queries, not BloodHound's visual spacing.

The array revision passes all **60 focused checks** on October 22, 2026, with
no skips: 16 administrator panel checks, 18 Site checks, six administrator model
checks, and 20 metadata, wiring, conversion, and fixture checks. Ruff passed for
all source and test files, and formatting passed for the affected Python files.
Mypy had already passed for the 63 unchanged Python source files. These checks
do not execute queries in a live BloodHound deployment.

A before-and-after schema comparison confirmed that only the two assignment
templates changed. The Site and administrator control templates are unchanged.
Hash checks confirmed that the saved models, transforms, MSSQL schemas, and graph
files were unchanged. Rendering against the retained administrator produced one
role link and two collection links matching the saved arrays. All three select
the expected existing objects and remain separate Markdown paragraphs. This
cached-data inspection was not live Cypher execution.

From this lab checkout, use the existing isolated environment:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.tmp\cmbp-traversability-venv'
$env:PYTHONPATH = "$PWD\src"
$env:RUNTIME__LOG_PATH = 'C:\Users\domainadmin\.tmp\cmbp-site-array-logs'
$env:CMBP_GO_BINARY = 'C:\Users\domainadmin\.tmp\cmbp-panel-go1.27.3\go\bin\go.exe'
$env:GOCACHE = 'C:\Users\domainadmin\.tmp\cmbp-site-table-tests\site-panel-renderer0\go-cache'
uv run --no-sync --offline python -B -m pytest tests/admin_user_entity_panel_test.py tests/site_entity_panel_test.py tests/sccm_admin_user_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py -q -p no:cacheprovider --basetemp C:\Users\domainadmin\.tmp\cmbp-admin-array-verified-tests
uv run --no-sync --offline python -B -m ruff check src tests --no-cache
uv run --no-sync --offline python -B -m ruff format --check tests/conftest.py tests/site_entity_panel_test.py tests/admin_user_entity_panel_test.py
uv run --no-sync --offline python -B -m mypy src/openhound_sccm --cache-dir C:\Users\domainadmin\.tmp\cmbp-schema-mypy-cache
uv build --offline --out-dir C:\Users\domainadmin\.tmp\cmbp-admin-array-build-20261022
```

## Suggested commit after review

Suggested message: `feat: add SCCM administrator assignment and control panels`.
The schema copies already contain earlier approved display-text and Site-panel
work. Review those together. Other working changes are
separate features; select only reviewed hunks in mixed files.

```powershell
git add -- tests/admin_user_entity_panel_test.py docs/sccm-admin-user-entity-panel.md
git add -p -- src/openhound_sccm/schema_SCCM.json README.md tests/conftest.py .github/workflows/ci.yml
# These untracked files include the earlier panel/schema work; review it together.
git add -- extension/schema_SCCM.json tests/site_entity_panel_test.py tests/support/render_entity_panel.go docs/sccm-site-entity-panel.md docs/sccm-schema-display-text.md
# extension/README.md also describes the separate privilege-zone feature;
# include it only after reviewing that work.
git diff --cached
git commit -m "feat: add SCCM administrator assignment and control panels" -m "List individual role IDs from memberOf and collection IDs from collectionIds, each linked to its exact object. Keep one-hop incoming/outgoing control links. Preserve graph data and the Site panel; omit Related Objects and duplicate information. Document schema-only deployment, retained display limits, and rendering/integration checks. Add no dependency."
```

The agent does not stage, commit, or push files.
