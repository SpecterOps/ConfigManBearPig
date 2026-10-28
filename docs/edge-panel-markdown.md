# Markdown edge panels

## October 23 correction: upload validation and environment kind

The previous formatting missed `CM_<SiteCode>` in the `MSSQL_ControlDB` General
section. BloodHound interpreted `<SiteCode>` as raw HTML and rejected the schema.
The whole database name is now inline code, in both MSSQL schemas in this
repository, the MSSQL collector's schema, and the original `edge_help.py` text.
This preserves the visible placeholder and avoids adding or allowing HTML.
Regression checks reject HTML-like tags outside code in every authored edge panel.

The owner also requested `environment_kind: MSSQL_Server`. All three MSSQL schema
copies now use that value. Node `environmentid` values remain AD domain SIDs;
this change does not rewrite existing graphs or implement server-based grouping.
Changing those node values needs a separate decision and conversion change.

Validation reproduced exactly one rejection before the fix and zero afterward
across all five schema files, including node panels. It used the locally saved
BloodHound `markdownsanitize.go` validator in an isolated temporary Go program,
with Goldmark 1.7.13, Bluemonday 1.0.27, and x/net 0.48.0. These are verification
tools only, not new collector dependencies. The server's exact dependency versions
were not established; an actual schema upload remains the final check.

After reviewing these corrections, include `src/openhound_sccm/edge_help.py`,
`ARCHITECTURE.md`, the updated schemas, tests, README, and these notes in your
selected commit. Suggested message: `Fix Markdown schema validation and select MSSQL server environment`.
In the MSSQL repository also include `tests/unit/test_convert_environment.py`
and `ARCHITECTURE.md`. Keep the earlier stage/commit commands scoped to the work
you have reviewed; nothing has been staged, committed, or pushed.

```powershell
cd C:\Users\domainadmin\ConfigManBearPig
git add -p -- src/openhound_sccm/edge_help.py src/openhound_sccm/schema_MSSQL.json ARCHITECTURE.md README.md
git add -- extension/schema_MSSQL.json tests/edge_entity_panel_test.py docs/edge-panel-markdown.md
git commit -m "Fix Markdown schema validation and select MSSQL server environment"
cd C:\Users\domainadmin\openhound-mssql
git add -- src/openhound_mssql/schema_MSSQL.json tests/edge_entity_panel_test.py tests/unit/test_convert_environment.py README.md ARCHITECTURE.md docs/edge-panel-markdown.md
git commit -m "Fix Markdown schema validation and select MSSQL server environment"
```

The new focused runs passed 28 ConfigManBearPig tests and eight MSSQL tests.
The MSSQL run used `PYTHONPATH=src` to check the edited source rather than the
older installed wheel in the external verification environment. Ruff passed
for ConfigManBearPig's source/tests and the two affected MSSQL test files.
The new mypy runs produced no result and were stopped; the earlier successful
type check described below predates this correction. No Python interfaces changed.

The previous edge help was stored only as graph properties. BloodHound's Object
Information section lists those values, but custom formatted sections must be
declared in the extension schema. This change adds `info` entries to all 23 SCCM
and 12 MSSQL edge kinds for which `src/openhound_sccm/edge_help.py` supplies help.

Each schema entry contains static Markdown under `info.<section>.markdown.content`.
Section keys use lowercase identifiers (`windows_abuse` and `linux_abuse` for
the corresponding mixed-case help properties), as BloodHound requires. Positions 1–5 order General,
Windows Abuse, Linux Abuse, Operational Security, and References; missing authored
sections are omitted. Newlines are JSON-escaped. Separate paragraphs preserve the
authored line boundaries; standalone command examples become fenced `text` code
blocks. Numbered shell comments become step headings. Inline code stays inline.
Reference URLs become linked bullet lists. Commands and explanations come from
the existing help; no new attack techniques or dependencies were introduced.

The packaged schemas in `src/openhound_sccm/` and their downloadable copies in
`extension/` contain the same bytes. The corresponding 12 `info` entries are also
present in `../openhound-mssql/src/openhound_mssql/schema_MSSQL.json`. Other MSSQL
schema entries retain their existing content. Native BloodHound edges continue
to use BloodHound's own help.

Static Markdown was selected because this is help about an edge kind, with no
need to read individual edge properties. Dynamic templates would require graph
properties and add unnecessary rendering conditions. Reformatting properties
alone would not create the documented custom accordion sections. Existing help
properties remain available in collected graphs. Future wording edits must keep
the authored help and these static schema sections consistent across repositories.
No collection, preprocess, conversion, identifiers, or traversal settings change.

The format follows [SpecterOps' entity panel documentation](https://bloodhound.specterops.io/opengraph/developer/entity-panel-content).

## Verification

`tests/edge_entity_panel_test.py` checks complete authored-edge coverage, matching
download/package copies, section ordering, balanced code fences, preserved command
text, reference lists, and absence of unexpected dynamic templates. Run:

```powershell
uv run pytest tests/edge_entity_panel_test.py tests/edge_help_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py -q
uv run ruff check src tests
uv run mypy src/openhound_sccm
```

For visual verification, upload `extension/schema_SCCM.json` and
`extension/schema_MSSQL.json` through Administration > OpenGraph Management >
Upload File. Reopen an existing edge in Explore, such as
`SCCM_AdminsReplicatedTo`, `SCCM_CoerceAndRelayToSMB`, or `MSSQL_GetTGS`.
Check paragraph spacing, code blocks, clickable references, and omitted sections.
The tests do not replace a visual check in BloodHound or its upload validation.

Completed checks: the command above passed all 27 tests; Ruff passed across
`src` and `tests`; mypy reported no issues in all 63 source files. The MSSQL
panel test passed separately and its new test file passed that repository's
required Ruff 0.15.20. A direct comparison confirmed that all 12 shared panel
definitions match between collectors. Upload and visual verification remain
manual; no BloodHound server was changed.

## Suggested commit after review

Both repositories already contain other uncommitted work. Review the selected
changes before staging; schema files and README may include earlier work.

```powershell
cd C:\Users\domainadmin\ConfigManBearPig
git add -p -- README.md src/openhound_sccm/schema_SCCM.json src/openhound_sccm/schema_MSSQL.json
git add -- extension/schema_SCCM.json extension/schema_MSSQL.json docs/edge-panel-markdown.md tests/edge_entity_panel_test.py
git commit -m "Render custom edge help as Markdown entity panels" -m "Add ordered help sections, readable commands and linked references; document schema upload and verify authored coverage and matching schema copies. No new dependencies or collection changes."
```

Review the MSSQL repository separately and commit its schema, README, and test
changes together using `git commit -m "Add shared MSSQL edge Markdown panels"`.
Nothing was staged, committed, or pushed by the agent. Push only when you decide
the reviewed commits are ready, using `git push origin HEAD` in each repository.
