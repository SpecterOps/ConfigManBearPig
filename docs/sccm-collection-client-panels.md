# Collection and Client Device panels

The remaining SCCM node panels now use the existing saved properties, following
the accepted schema-only approach. This change also removes the redundant
Security Role Description accordion and turns Role Assignments into a table
with two columns. No graph data, labels, identifiers, collection, preprocessing,
conversion, shared repository, or architecture changes.

## What appears

Object Information remains BloodHound's built-in property table on every node.
The custom sections are:

| Node | Section | Contents |
|---|---|---|
| Security Role | Role Assignments | Two columns: SCCM Administrator and AD Identity, one row per saved `members` ID. |
| Collection | Members | One column without an inner heading, with a link per saved resource key in `members`. |
| Collection | Collection Assignments | Two columns, SCCM Administrators and AD Identities, containing one row of query links. |
| Client Device | Member of Collections | One column without an inner heading, with a link per saved ID in `collectionIds`. |
| Client Device | Inbound Object Control | A plain link to one-hop paths ending at the client. |
| Client Device | Outbound Object Control | A plain link to one-hop paths starting at the client. |

The saved role description stays in Object Information. There is no Description
accordion, duplicate property section, or Related Objects section. Existing site,
limiting-collection, Azure, computer, user, management-point, and audit properties
remain ordinary Object Information values. Their built-in rows cannot be turned
into custom links through this schema.

## Collection Members

The existing `members` array contains **resource keys**, such as `16777224@PS1`,
rather than object IDs. `_enrich_collection_members` in
[transforms.py](../src/openhound_sccm/transforms.py) builds those keys from the raw
resource number and site code. The
[collection model](../src/openhound_sccm/models/sccm_collection.py) copies the array
into the graph. Both remain unchanged.

The template deduplicates and sorts that array and skips empty or whitespace-only
entries. Each remaining key is the link label. Its query finds:

- `SCCM_ClientDevice` objects whose `resourceID` equals the whole key; or
- `User` and `Group` objects whose existing `SCCMResourceIDs` array contains it.

The site code stays attached to the number in both cases. There is no conversion
of a resource key into an object ID, no guessed SMSID, and no use of obsolete
`sccmresourceid`/`sccmdiscoveryagentsitecode` fields from the original design.
`RETURN DISTINCT object` returns every matching object. A key can match more than
one User/Group; the link does not silently choose one.

Raw member arrays deliberately include built-in or unresolved entries. Their
rows remain present even when no target was ingested. An empty result after a
click does not prove that the collection had no such member.

## Collection Assignments

The collection's `members` array describes its resource membership, not which
administrators are assigned to manage it. Collections do not have a saved
administrator-ID array. The template therefore
cannot list individual assigned administrator names without new graph data or a
query during rendering. The accepted Explore-link approach supplies a two-column
table with one row:

- **Show assigned administrators** queries `SCCM_AdminUser` records whose existing
  `collectionIds` contains the selected collection's full `objectid`.
- **Show AD identities** applies that same assignment check, then selects `Base`
  objects whose `objectid` matches each administrator's `adminSid`.

Both queries use the exact collection ID, including its hierarchy suffix. They
do not select every administrator merely because it shares a site, do not query
`SCCM_SameAdminsAs`, and do not need an `SCCM_IsAssigned` edge. Names appear on the
returned objects in Explore. The template reads only the selected collection's
`objectid`; the administrator properties are read by the query after a click.

A missing selected-object ID produces no table. A usable ID produces the query
links even if their result will be empty. A missing administrator SID or AD object
means no identity is returned for that record. No new assignment or mapping is
created.

## Client collections and control

The [client model](../src/openhound_sccm/models/sccm_client_device.py) already emits
`collectionIds` containing full collection node IDs, such as `SMS00001@CAS`.
Member of Collections sorts and deduplicates those IDs, skips blanks, and builds
an exact `SCCM_Collection.objectid` lookup for each. The saved full ID is the link
label, following the Administrative User panel's collection links.

The separate `collectionNames` array is independently sorted. Its elements are
not paired with IDs by position. For example, the cached PS1-MP client has All
Systems first in its ID array and All Desktop and Server Clients first in its
name array. Pairing those positions would attach the wrong name to an object.
Friendly labels would need an explicit association that is not stored here;
this change uses the existing IDs instead.

The two control sections retain the established Site/administrator query form,
with `SCCM_ClientDevice` as the selected type. They use
[TRAVERSABLE_EDGE_KINDS](../src/openhound_sccm/kinds/edges.py), stop at one edge,
and return distinct paths. Inbound paths end at the client; outbound paths start
there. Nodes and connecting relationships remain visible, including different
relationships between the same objects. There is no recursive expansion or
hard-coded result limit. Inferred relationships qualify when their kind is in
the set; traversal flags and permissions are unchanged.

## Table formatting and links

The [packaged schema](../src/openhound_sccm/schema_SCCM.json) is hand-maintained;
the [upload copy](../extension/schema_SCCM.json) is identical. Only the Security
Role, Collection, and Client Device `info` definitions change in this revision.
The Site and Administrative User panels and all other type metadata are preserved.

Array tables emit their header and separator only upon finding the first usable
entry. Header, separator, and body rows are consecutive lines, with no intervening
blank lines. Empty arrays therefore emit no orphan header. The shared table check
in [conftest.py](../tests/conftest.py) rejects extra cells and blank body lines.
The one-column Members and Member of Collections tables use an empty header
cell, so the accordion title is the only visible heading. Markdown tables still
need their header and separator lines to preserve the compact table layout;
removing those lines would turn the rows into text with visible pipe characters.
The two-column assignment tables retain their useful column headings. This
display change leaves every link and query unchanged and needs no new graph data.
Markdown/HTML punctuation is escaped in labels; literal pipes become `&#124;`
so a member name cannot accidentally create another column.

Each ID is escaped for a quoted Cypher value, including backslashes, single
quotes, carriage returns, newlines, and tabs. The templates encode queries with
`b64enc` and `urlquery` and link to the current BloodHound instance's Explore page.
Queries run after a click, not when an accordion opens. The existing Go test
helper supports the documented functions used here; no dependency was added.

The [Entity Panel Content documentation](https://bloodhound.specterops.io/opengraph/developer/entity-panel-content)
supports GitHub Flavored Markdown tables. It does not let templates fetch other
nodes during rendering, hide an empty accordion, or replace Object Information.
Empty properties leave their sections blank, but accordions remain. Missing
targets give empty query results. BloodHound's query/display limits and existing
accordion spacing still apply. Stacked remains a manual control-result layout
selection, as documented in the [Site notes](sccm-site-entity-panel.md).

Adding new name/ID pairs, administrator lists, or per-object links to the graph
would require changed data and another ingestion. Guessing those associations
would mislabel objects. Broad site-wide queries would disregard actual saved
assignments. These alternatives were not selected. Original requests for changed
object labels and clickable built-in property values remain outside the accepted
schema-only scope.

## Apply and manually verify

1. Upload [extension/schema_SCCM.json](../extension/schema_SCCM.json) through
   **Administration > OpenGraph Management > Upload File**. Reopen each node
   panel. No collection, preprocessing, conversion, or graph ingestion is needed.
2. On Full Administrator (`SMS0001R@CAS`), confirm Description is absent and
   Role Assignments has exactly two columns. The row for
   `MAYYHEM\DOMAINADMIN@CAS` links to that record and its AD identity separately.
3. On All Desktop and Server Clients (`SMSDM003@CAS`), Members should show
   individual resource keys. `16777224@PS1` selects `PS1-MP@PS1` in the retained
   graph. The raw numeric/site key is expected as the label.
4. On All Systems (`SMS00001@CAS`), follow both Collection Assignments links.
   In the retained graph, the results include `MAYYHEM\DOMAINADMIN@CAS` and
   `DOMAINADMIN@MAYYHEM.COM`, respectively.
5. On `PS1-MP@PS1`, Member of Collections lists `SMS00001@CAS` and `SMSDM003@CAS`.
   Clicking them selects All Systems and All Desktop and Server Clients.
6. Follow each client control link. The result includes the client, direct
   neighbors, and relationships; paths through intermediate objects are excluded.
7. Confirm Members and Member of Collections have no inner Member/Collection
   heading. Assignment tables should retain both column headings. All rows
   should render as cells, without literal Markdown borders.
   An empty property array should leave no table header. Empty
   accordions and the existing padding remain expected limitations.
8. Reopen a Site and an Administrative User to check their existing sections.

For an exact example lookup in Explore:

```cypher
MATCH (collection:SCCM_Collection {objectid: 'SMSDM003@CAS'})
RETURN collection
```

Live BloodHound rendering and Cypher execution remain manual checks. Local Go
and Markdown parsing checks do not establish the installed UI's behavior.

## Validation

The five panel test files render the real schema with Go's template engine.
There are **63 panel checks**: 18 Site, 16 Administrative User, eight Security
Role, 11 Collection, and 10 Client Device checks. They cover property use,
empty arrays, exact IDs and site-qualified resource keys, query direction and
types, SID lookups, escaping, table columns/continuity, one-hop paths, and
traversable-kind agreement. CI includes both new panel test files.

All **98 focused tests passed**, with no skips, on October 22, 2026. This includes
the panel checks, 15 relevant node-model checks, and 20 metadata, wiring,
conversion, and fixture checks. Ruff passed for all source/test files, formatting
passed for the four affected test files, and Mypy passed for all 63 Python source
files.

A before-and-after comparison confirmed that only the three requested node-panel
definitions changed in the SCCM schema. Hashes for the existing collector Python
files, MSSQL schemas, and graph files remained unchanged. Existing cached data
for 38 role/collection/client objects rendered as 28 valid tables with 83 links
inside them, using an already installed Markdown parser with table support enabled.
This independent check verified two-column assignment tables and one-column
membership tables rather than treating their pipe markup as paragraphs.

Cached target inspection resolved 27 member keys and 27 client-to-collection
links. Seven member-key entries were unresolved and retained as visible rows,
including keys such as `2046820352@PS1` in All Systems. All Systems and All Users
and User Groups selected the expected saved administrator and its AD identity.
These were cached-data checks, not live database queries.

The subsequent removal of the inner Member and Collection headings passed
**83 focused tests**, with no skips: all 63 panel checks and the 20 required
metadata, wiring, conversion, and fixture checks. Ruff, formatting of the two
affected test files, and Mypy also passed. A comparison with the saved schema
confirmed that only those two heading labels changed, and the upload copy is
identical. Rendering the same 38 cached objects still produced 28 valid Markdown
tables and 83 table links. All 17 populated one-column membership tables had an
empty heading cell; every link and query was unchanged. Confirm their appearance
in the installed BloodHound UI using the manual checks above.

Use the existing isolated lab environment:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.tmp\cmbp-traversability-venv'
$env:PYTHONPATH = "$PWD\src"
$env:RUNTIME__LOG_PATH = 'C:\Users\domainadmin\.tmp\cmbp-site-array-logs'
$env:CMBP_GO_BINARY = 'C:\Users\domainadmin\.tmp\cmbp-panel-go1.27.3\go\bin\go.exe'
$env:GOCACHE = 'C:\Users\domainadmin\.tmp\cmbp-site-table-tests\site-panel-renderer0\go-cache'
uv run --no-sync --offline python -B -m pytest tests/security_role_entity_panel_test.py tests/collection_entity_panel_test.py tests/client_device_entity_panel_test.py tests/admin_user_entity_panel_test.py tests/site_entity_panel_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py -q -p no:cacheprovider --basetemp C:\Users\domainadmin\.tmp\cmbp-membership-heading-tests
uv run --no-sync --offline python -B -m ruff check src tests --no-cache
uv run --no-sync --offline python -B -m ruff format --check tests/conftest.py tests/security_role_entity_panel_test.py tests/collection_entity_panel_test.py tests/client_device_entity_panel_test.py
uv run --no-sync --offline python -B -m mypy src/openhound_sccm --cache-dir C:\Users\domainadmin\.tmp\cmbp-schema-mypy-cache
uv build --offline --out-dir C:\Users\domainadmin\.tmp\cmbp-membership-heading-build-20261022
```

## Suggested commit after review

Suggested message: `feat: complete SCCM entity panels with membership tables`.
The schema and earlier panel files already contain approved display-text, Site,
and Administrative User work. Review that work together if it is still uncommitted.
Other working changes belong to separate features; select only reviewed hunks
in mixed files. Keep schema originals and upload copies identical.

```powershell
git add -- tests/collection_entity_panel_test.py tests/client_device_entity_panel_test.py tests/security_role_entity_panel_test.py docs/sccm-collection-client-panels.md docs/sccm-security-role-entity-panel.md
git add -p -- src/openhound_sccm/schema_SCCM.json README.md tests/conftest.py .github/workflows/ci.yml
git add -- extension/schema_SCCM.json docs/sccm-schema-display-text.md
# Include the earlier panel files and shared helper if still uncommitted.
git add -- tests/site_entity_panel_test.py tests/admin_user_entity_panel_test.py tests/support/render_entity_panel.go docs/sccm-site-entity-panel.md docs/sccm-admin-user-entity-panel.md
# extension/README.md also contains separate privilege-zone work; review it first.
# The Site tests need the matching MSSQL schema copy. Review/commit its existing
# original/copy changes together if that separate schema work is still uncommitted.
git diff --cached
git commit -m "feat: complete SCCM entity panels with membership tables" -m "Remove the redundant role Description accordion and use two-column role assignments. Add Collection member and assignment tables and Client Device collection tables plus one-hop control links. Omit redundant inner headings from one-column membership tables. Read existing properties and preserve graph data, labels, Site, and Administrative User panels. Document schema-only deployment and accepted UI limits; verify templates, table formatting, target matching, integration, and packaging. Add no dependency."
```

The agent does not stage, commit, or push files.
