# SCCM Security Role panel

Role Assignments is a two-column Markdown table populated from the role's
existing `members` array. Its columns are **SCCM Administrator** and **AD Identity**.
The redundant Description accordion is removed; `roleDescription` remains visible
in BloodHound's built-in Object Information. No graph data, labels, identifiers,
collector code, or shared repository changes.

## How the table works

The hand-maintained [packaged SCCM schema](../src/openhound_sccm/schema_SCCM.json)
defines only `role_assignments` under `SCCM_SecurityRole.info`, at position 1.
The [upload copy](../extension/schema_SCCM.json) is identical. The template reads
only `members`, already defined in
[SCCMSecurityRoleProperties](../src/openhound_sccm/graph.py) and emitted by the
[role model](../src/openhound_sccm/models/sccm_security_role.py).

The existing `_enrich_role_members` function in
[transforms.py](../src/openhound_sccm/transforms.py) resolves administrator IDs
from collected role assignments, with a role-name fallback when raw role IDs are
absent. Each entry is a full SCCM administrator ID such as
`MAYYHEM\DOMAINADMIN@CAS`. The panel does not fetch members from neighboring nodes.

The template sorts and deduplicates these IDs, skips blank entries, and preserves
each usable ID exactly. The first column's label is that saved ID. Its query
selects the exact `SCCM_AdminUser.objectid`. The second column is labelled
**AD identity** and queries the same administrator, then the `Base` object whose
`objectid` equals its saved `adminSid`. It can return a User or Group, and does
not require an `SCCM_IsMappedTo` edge.

Both links run only when clicked. Backslashes, quotes, and control characters
are escaped for Cypher; Markdown/HTML punctuation is escaped in labels. A pipe
inside a name becomes `&#124;` so it cannot create a third column. Queries are
encoded with `b64enc` and `urlquery`, following the other panels.

A header and Markdown separator are emitted only for the first usable member.
Each body row has one newline, with no blank lines between the header, separator,
and rows. This keeps the links in one table instead of separate paragraphs.
Empty arrays, including arrays containing only whitespace, emit no table header.

## Limits and alternatives

The [Entity Panel Content documentation](https://bloodhound.specterops.io/opengraph/developer/entity-panel-content)
supports GitHub Flavored Markdown tables. Templates cannot fetch other objects
during rendering, replace Object Information, or remove an empty accordion. The
AD SID lookup therefore happens after a click. A missing administrator, SID, or
AD target gives an empty query result; the template cannot hide that link in
advance. The accordion remains visible even when its member list is empty.

The full member ID supplies both the account name and hierarchy. No
`SCCM_SameAdminsAs` query, broad site-wide administrator lookup, or guessed SID is
needed. Adding per-member SIDs and AD names to the role would require changed
graph data. The owner instead requested existing properties and a two-column
table. The earlier list layout and Description accordion are replaced.

Object Information keeps the role's description, ID, name, site, audit dates,
and flags. No duplicate property table or Related Objects section is added.
Existing root-qualified display names remain unchanged. Accordion padding and
paragraph spacing remain BloodHound's responsibility, as described in the
[Site spacing notes](sccm-site-entity-panel.md#why-the-visible-gap-remains).

## Apply and manually verify

1. Upload [extension/schema_SCCM.json](../extension/schema_SCCM.json) through
   **Administration > OpenGraph Management > Upload File**. No graph upload or
   collection is needed.
2. Reopen Full Administrator (`SMS0001R@CAS`) in the retained mayyhem.com graph.
   Object Information should be followed only by Role Assignments. Description
   should be absent; its text is still present in Object Information.
3. Confirm the table has exactly two columns and one row for
   `MAYYHEM\DOMAINADMIN@CAS`. Follow that link to the SCCM administrative record.
4. Follow **AD identity** in the second column. It should select
   `DOMAINADMIN@MAYYHEM.COM`, using the administrator's saved SID.
5. Open Read-only Analyst (`SMS0002R@CAS`) in that cached graph. Its empty
   `members` array leaves Role Assignments blank, without a lone table header.
   The accordion itself remains present.

Live BloodHound rendering and query execution remain manual checks. Local Go
and Markdown parsing checks do not replace them.

## Validation and review

[Role tests](../tests/security_role_entity_panel_test.py) render the actual schema
through the shared Go helper. The table assertion in
[conftest.py](../tests/conftest.py) checks the column headers, separator, body
columns, and uninterrupted rows. Other checks cover deduplication, empty arrays,
full IDs in different hierarchies, both queries per row, and label/query escaping.
The obsolete description tests were removed with that accordion.

The [Collection and Client Device notes](sccm-collection-client-panels.md) record
the combined validation commands, cached-data/table parsing checks, package
verification, and suggested manual commit commands for this change. No dependency
was added, and no collector phase or architecture was changed. The agent does
not stage, commit, or push files.
