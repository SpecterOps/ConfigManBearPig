# SCCM Site links from existing properties

The Site panel lists individual administrator and system links from the arrays
already stored on that Site. Its control sections have plain links that query
one-hop paths in Explore. No new node property or graph ingestion is required.
Object Information already lists the Site properties, so Site Details is removed.

## What appears in each section

| Accordion | Content | Click result |
|---|---|---|
| Administrative Users | One plain link per saved account. | The SCCM administrator selected by its exact `objectid`. |
| Site System Roles | One plain link per qualifying hostname. | The AD Computer selected by its name or `dNSHostName`. |
| Inbound Object Control | One plain link: Show incoming control paths. | One-hop paths ending at this Site. |
| Outbound Object Control | One plain link: Show outgoing control paths. | One-hop paths starting at this Site. |

All four sections use plain links. The administrator and system links are each
separate Markdown paragraphs, without a repeated inner heading or surrounding
pipe characters. The former table markup displayed those extra characters in
the reported BloodHound UI, so it was removed.

Template actions before a line break use Go's closing whitespace-trim marker,
`-}}`. This removes blank lines emitted by setup and loops before the first
link in each section. Deliberate blank lines between individual links remain,
keeping each link in its own Markdown paragraph. This text cleanup did not
remove the visible gap reported in BloodHound. The first attempt incorrectly
treated text whitespace as the cause of display spacing; the local template
checks did not establish that the display was fixed.

The control queries return `DISTINCT path`, keeping
the Site, neighboring node, and connecting relationship visible. Different
relationships between the same objects remain visible. There is no recursive
expansion or hard-coded result cutoff.

### Why the visible gap remains

The public BloodHound display code was checked on October 22, 2026, at commit
`480935870d981159f4d4c02d0f96ea108d8db2a2`:

- [KindInfoItems](https://github.com/SpecterOps/BloodHound/blob/480935870d981159f4d4c02d0f96ea108d8db2a2/packages/javascript/bh-shared-ui/src/components/EntityInfo/KindInfoItems.tsx)
  puts each section's Markdown inside `AccordionContent` without a spacing override.
- [AccordionContent](https://github.com/SpecterOps/BloodHound/blob/480935870d981159f4d4c02d0f96ea108d8db2a2/packages/javascript/doodle-ui/src/components/Accordion/Accordion.tsx#L57)
  wraps that content in a `p-4` container, adding padding on every side.
- [MarkdownContent](https://github.com/SpecterOps/BloodHound/blob/480935870d981159f4d4c02d0f96ea108d8db2a2/packages/javascript/bh-shared-ui/src/components/MarkdownContent.tsx#L105)
  gives each paragraph a `1rem` top and bottom margin, including a paragraph
  containing only one link.

These rules explain why trimming leading newlines does not remove the visible
gap: ordinary Markdown ignores those leading blank lines, while the display's
padding and margins remain. The supplied Enterprise instance is not reachable
from this workspace, so its exact on-screen dimensions have not been measured.
As a separate check, the templates before and after trimming were rendered for
the existing CAS, PS1, and SEC nodes. All 12 sections produced identical HTML
through a CommonMark renderer. This confirms that the earlier text change did
not change ordinary Markdown layout; it is not a live BloodHound display test.

The [Entity Panel Content documentation](https://bloodhound.specterops.io/opengraph/developer/entity-panel-content)
offers titles, ordering, and Markdown content, with no spacing setting. Injecting
styles is not a supported solution. A tight Markdown list would avoid the link's
paragraph margin, but would add bullets and retain the accordion padding, so it
does not meet the requested plain-link design. No further schema change is made
for this gap. Removing it requires a change to BloodHound's display code, outside
this collector repository. The useful scope for such a change would be custom
Entity Panel sections, preserving paragraph spacing elsewhere in BloodHound.

## Where individual names and identifiers come from

The templates use these existing fields from
[SCCMSiteProperties](../src/openhound_sccm/graph.py):

- `adminUsers` contains administrator IDs such as `MAYYHEM\DOMAINADMIN@CAS`.
  The link selects that exact ID. Its label removes the known `@CAS` hierarchy
  suffix, using `rootSiteCode` or `environmentid`; if neither root is known,
  the full saved ID remains the label. Blank entries are omitted, and repeated
  IDs are shown once, sorted by their saved names.
- `siteSystemRoles` contains entries such as
  `ps1-sms.mayyhem.com: SMS Provider@PS1`. The template extracts the hostname,
  uppercases it to match the collector's AD naming convention, and builds a
  link that queries `Computer.name` or `Computer.dNSHostName`, ignoring case.
  Repeated qualifying roles on the same hostname produce one row. Computers
  with only `SMS Site System` or `SMS Component Server` are omitted.

Labels come from the saved account names and hostnames. Custom display names
stored only on another object are unavailable to this template. These rows
reflect the Site's existing arrays; later changes elsewhere in the graph do
not rewrite those arrays. A clicked link queries the graph currently in BloodHound.

Missing or empty arrays render no links. A collected Secondary
Site has an empty `siteSystemRoles` array, so its system section stays empty.
Its saved administrator array can still provide links. Malformed role entries
without the expected `hostname: role` separator are omitted.

## How the schema templates work

The hand-maintained [packaged schema](../src/openhound_sccm/schema_SCCM.json)
contains the templates. Its [upload copy](../extension/schema_SCCM.json) is
identical. The MSSQL copies are also identical; this panel change modifies only
the SCCM Site's `info` sections.

The [Entity Panel Content documentation](https://bloodhound.specterops.io/opengraph/developer/entity-panel-content)
allows templates to loop over properties on the selected node. It does not let
them fetch neighboring objects. The administrator and system arrays therefore
supply the individual rows, while control queries run only after a click.
The former experimental `sitePanelObjects` field and its preprocessing helper
were removed. No collector, lookup, model, dependency, or shared repository
change is needed.

The documented helper list has no string-splitting function. To separate a saved
system entry safely, the template quotes it as JSON, replaces its `: ` separator
with the boundary between two JSON strings, encloses those strings in an array,
and decodes the array. For example, the result is
`["ps1-sms.mayyhem.com", "SMS Provider@PS1"]`. The first part is the hostname;
the remaining parts are joined back into the role text, preserving a colon in a
custom role. Qualifying hostnames are quoted into a JSON list, decoded,
deduplicated, and sorted. Template comments explain both JSON steps. This uses
only documented helpers and avoids depending on an unsupported split function.

Every identifier is escaped for its quoted Cypher value. Labels also escape
Markdown and HTML punctuation, including literal pipe characters within names.
`b64enc` and `urlquery` encode each query into an Explore link. There are no
aggregate links in the administrator or system sections.

Control templates read `objectid`, with the existing `siteCode` as a fallback.
Their directed one-edge queries and kind lists are unchanged by the array-row
revision. Kind lists match
[TRAVERSABLE_EDGE_KINDS](../src/openhound_sccm/kinds/edges.py); a regression check
detects drift. Inferred edges qualify when their kind is in that set. The links
do not change permissions, traversal flags, or graph contents.

## Alternatives and limits

Querying every administrator in a hierarchy or every computer's role properties
would disregard the requested Site arrays. Adding a new property would require
new graph data and violate the existing-properties requirement. The current
approach renders the individual data the Site already has. Control membership
is not stored in those arrays, so those sections keep their accepted query links.

A missing array can reflect incomplete collection. An empty query result can
also reflect missing or changed graph data. Neither proves that no access or
system exists. BloodHound's own query and display limits still apply.

## Apply and manually verify

Upload [extension/schema_SCCM.json](../extension/schema_SCCM.json) through
**Administration > OpenGraph Management > Upload File**, then reopen the Site
panel. Existing graph data works without collection, preprocess, convert, or
another graph ingestion.

For the already ingested mayyhem.com graph:

1. Select **PS1**. Object Information is followed by the four accordions above;
   Site Details is absent.
2. Administrative Users lists `MAYYHEM\DOMAINADMIN` as an individual link.
   Clicking it selects `MAYYHEM\DOMAINADMIN@CAS` alone.
3. Site System Roles lists individual computer hostnames, including
   `PS1-SMS.MAYYHEM.COM`. A computer with several qualifying roles appears once.
   Clicking a link displays the corresponding Computer. Neither object section
   repeats its title or surrounds links with pipe characters.
4. Inbound and Outbound Object Control contain only their plain links.
5. Follow **Show incoming control paths**. Collected SMS Provider computers and
   `CM_PS1` should appear with their relationships pointing to PS1. Paths through
   an intermediate administrator or client are excluded.
6. Follow **Show outgoing control paths**. It returns PS1, qualifying direct
   outgoing relationships, and their destination nodes. Different relationships
   remain visible; paths longer than one hop do not.
7. Repeat on **SEC**. Its saved administrators can appear, while its empty
   role array leaves the system section blank.

The query can be read in Explore's Cypher editor after clicking any link. Live
BloodHound rendering and query execution remain manual checks; local template
checks do not replace that verification.

### Requested Stacked layout

Stacked was requested as the default for the control results. No layout argument
has been added to the schema links. The supplied Explore URL has only the query
parameters. The public BloodHound
[GraphView source](https://github.com/SpecterOps/BloodHound/blob/480935870d981159f4d4c02d0f96ea108d8db2a2/cmd/ui/src/views/Explore/GraphView.tsx)
reads layout from the application's browser state, while
[useExploreParams](https://github.com/SpecterOps/BloodHound/blob/480935870d981159f4d4c02d0f96ea108d8db2a2/packages/javascript/bh-shared-ui/src/hooks/useExploreParams/useExploreParams.tsx)
does not expose a layout URL parameter. These references were checked on
October 22, 2026. The supplied Enterprise instance, `bhe.localhost`, could not be
resolved from this workspace, so an Enterprise-specific override could not be
verified. Choosing Stacked in BloodHound's Layout menu is the current manual
step. This collector does not modify BloodHound or browser preferences.

## Validation

The [template tests](../tests/site_entity_panel_test.py) render the actual schema
with Go's `text/template` engine. Compiler setup now lives in the shared
[test fixture](../tests/conftest.py), also used by the administrator panel checks;
the helper is compiled once per test run. They cover individual array entries, exact
administrator IDs, hostname extraction, deduplication, case handling, role
filtering, empty arrays, labels with special characters, missing Site identifiers,
plain control links, one-hop direction, returned paths, and schema-copy agreement.
They also reject reintroducing the removed property.

The text cleanup checks that links start immediately with no leading blank
lines, retains spacing between individual links, removes inner headings and
table borders, and preserves the decoded queries. These checks inspect generated
text; they do not measure the visible gap, padding, or margins in BloodHound.
Go is an optional test tool,
not a runtime dependency. Set `CMBP_GO_BINARY` or
put Go on PATH; rendering tests explicitly skip without it. The
[Go helper](../tests/support/render_entity_panel.go) implements the documented
string/list/JSON behavior used by these templates using only Go's standard
library. It is not a copy of BloodHound's renderer or query engine.

The text cleanup passed all 18 panel tests on October 22, 2026, including Go
rendering checks, with no skips. The earlier 64 focused collector and panel tests
also passed. Collector models and transforms are unchanged by this cleanup;
Mypy had already passed for all 63 source files. The final lint, formatting,
schema-copy, wheel, and source-archive checks passed as well.

The lab checks use the existing isolated environment, leaving the checkout's
normal `.venv` untouched:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.tmp\cmbp-traversability-venv'
$env:PYTHONPATH = "$PWD\src"
$env:RUNTIME__LOG_PATH = 'C:\Users\domainadmin\.tmp\cmbp-site-array-logs'
$env:CMBP_GO_BINARY = 'C:\Users\domainadmin\.tmp\cmbp-panel-go1.27.3\go\bin\go.exe'
$env:GOCACHE = 'C:\Users\domainadmin\.tmp\cmbp-site-table-tests\site-panel-renderer0\go-cache'
$env:DLT_DATA_DIR = 'C:\Users\domainadmin\.tmp\cmbp-site-array-dlt'
uv run --no-sync --offline python -B -m pytest tests/site_entity_panel_test.py -q -p no:cacheprovider --basetemp C:\Users\domainadmin\.tmp\cmbp-site-whitespace-tests
uv run --no-sync --offline python -B -m ruff check src tests --no-cache
uv run --no-sync --offline python -B -m ruff format --check tests/site_entity_panel_test.py
uv run --no-sync --offline python -B -m mypy src/openhound_sccm --cache-dir C:\Users\domainadmin\.tmp\cmbp-schema-mypy-cache
uv build --offline --out-dir C:\Users\domainadmin\.tmp\cmbp-site-whitespace-build-20261022
```

## Suggested commit after review

Suggested message: `feat: link individual SCCM Site administrators and systems`.
The schema still includes the approved display text and removal of the unused
NAA kind. Review these together. Other working changes belong to separate
features, so stage only reviewed files and hunks.

```powershell
git add -- tests/site_entity_panel_test.py tests/support/render_entity_panel.go docs/sccm-site-entity-panel.md docs/sccm-schema-display-text.md extension/schema_SCCM.json extension/schema_MSSQL.json
git add -p -- src/openhound_sccm/schema_SCCM.json README.md tests/conftest.py .github/workflows/ci.yml
# extension/README.md also contains the separate privilege-zone documentation;
# include it only after reviewing that work together.
git diff --cached
git commit -m "feat: link individual SCCM Site administrators and systems" -m "Retain approved type descriptions and remove unused NAA registration. Render plain individual links from existing Site arrays, deduplicate system hostnames, and use plain links for one-hop incoming and outgoing control paths. Remove repeated headings, table borders, and template-generated leading whitespace. Document schema-only deployment and verify templates, escaping, schema copies, and collector integration. Add no runtime dependency or graph property."
```

No files have been staged or committed by the agent. No push is performed.
