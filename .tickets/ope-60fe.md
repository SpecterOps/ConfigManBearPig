---
id: ope-60fe
status: in_progress
deps: []
links: [ope-f1ce, ope-1d06, ope-2419]
created: 2026-07-29T18:37:13Z
type: task
priority: 1
tags: [publishing, packaging, sccm]
---

# Publish ConfigManBearPig 2.0 and openhound-collector-common to PyPI

Execute PUBLISHING.md: publish openhound-collector-common 0.1.0 and configmanbearpig 2.0.0 to PyPI via Trusted Publishing, restructure SpecterOps/ConfigManBearPig around the Python collector, and unblock the MSSQL extension afterwards. Design record: docs/superpowers/specs/2026-07-27-publishing-and-repo-split-design.md. Division of labour agreed 2026-07-29: agent does all local work (edits, commits, archives, verification); user runs everything that leaves the machine (all pushes, GitHub repo/environment creation, PyPI publisher forms, both release tags).

## Acceptance Criteria

openhound-collector-common 0.1.0 and configmanbearpig 2.0.0 both installable from PyPI; 'uv tool install openhound --with configmanbearpig' then 'openhound collect sccm --help' works on a clean machine; ConfigManBearPig main has the Python collector at root with PowerShell 1.2 under powershell_deprecated/ and reachable at tag v1.2-powershell; CI green on both new repos; mssql/mssql still resolves its shared-library dependency.

## Notes

**2026-07-29T18:37:35Z**

Step 0 (pre-execution review + doc reconciliation) COMPLETE. Read PUBLISHING.md, the design record, and the MSSQL deferred plan, then verified every checkable claim against the live repos/PyPI/GitHub: openhound 0.2.12 is PyPI latest; configmanbearpig + openhound-collector-common + mssqlhound all unregistered; SpecterOps/ConfigManBearPig root is exactly the 8 documented items, zero tags, no open PRs; collector archive supplies powershell_deprecated/ + cypher_queries/ + README + LICENSE; 3 stale 'just dev' comment blocks present as described; grill-me has no SKILL.md; library has no [tool.uv]; out/ unignored; no fork-root path references to either package; fork-root vs collector plans/specs do not collide. Lab probed UP (ps1-sms 443+5985, dc 389).

Seven deltas agreed and written into PUBLISHING.md + the design record: (1) step 1 gate is now offline tests + both --help + a full live --run-all collect vs the 0.1.4 baseline; (2) scrub the literal USER/PASSWORD/NTHASH/KDC tuple from .tickets/ope-1f49.md before step 8 copies all 109 tickets to a public repo -- the 'no credentials travel' argument covered the git archive, never the Copy-Item; (3) library gets a [dependency-groups] dev + its own ci.yml, reversing the design record's 'no ci.yml in the shared library' (it rested on 'four offline tests'; there are 21 files / 108 tests, verified green); (4) NEW step 2e -- ruff has never been enforced in either package (pre-commit runs black, no ruff hook) so the runbook's own ci.yml would be red on first run: 27 collector errors (all in tests/, src/ clean) + 23 library (5 src, 18 tests), to be fixed BY HAND because --fix would delete the 7 deliberately-unused imports in test_bloodhound_exports.py and silently gut the public-API contract test; (5) merge=ours needs a per-clone 'git config merge.ours.driver true' -- 'ours' is not a built-in git merge driver, so the .gitattributes line alone is inert; (6) README fix list gains line 1798; (7) step 10's git-URL rehearsal will report version 0.0.0 because v1.2-powershell is not PEP 440 -- expected, cannot reach PyPI.

Division of labour: agent does all local work; user runs all pushes, GitHub repo/environment creation, PyPI publisher forms, and both release tags. Next: step 1.

**2026-07-29T19:02:14Z**

Step 1 (adopt openhound 0.2.12) COMPLETE -- PASS.

pyproject.toml: added 'openhound>=0.2.12' to [project.dependencies] with the no-upper-cap rationale; DELETED the dev group's 'openhound @ git+...' line (a direct git ref outranks a version range, which is how local runs and user installs diverge) and left a comment saying why it must stay absent; deleted all three stale 'just dev' comment blocks; rewrote the [tool.uv] python-preference comment to state the CONSTRAINT (no environment may download an interpreter) rather than the Windows-TLS motivation -- that mis-framing is what hid the CI interpreter failure. uv.lock now pins openhound 0.2.12 from the PyPI registry with no git source anywhere.

Gate results: 33 offline tests pass across the 7 named files; 'collect sccm --help' and 'convert sccm --help' both bind with rich panels intact (proves the Typer hand-registration and app.converter assignment survive); live --run-all against the lab completes end to end.

Framework equivalence PROVEN by reprocessing one cached bucket under both versions: identical 148 nodes / 454 edges, identical node kinds, identical node identities, identical edge triples, identical property-key population, and value-for-value identical except for element ORDER in 4 list properties. The graph JSON files even came out byte-identical in size.

Two live collects were NOT comparable and that was a trap worth recording: the pre-existing out/ baseline held 3 accumulated dlt load packages (no --clean), so its raw AdminService row counts were exactly 3x a clean run's; and the fresh run hit 5-second AdminService read timeouts on all three site servers, so SMS_SCI_Reserved returned 0 rows and dropped 2 SCCM_HasStoredAccount edges. Neither is a framework effect. PUBLISHING.md now documents comparing a cached bucket instead, plus --clean and the MAX_PATH pitfall (dlt state filenames are ~130 chars and overflow Windows' 260-char limit under a deep output dir, failing with FileNotFoundError on a file dlt just wrote).

Also fixed a pre-existing runbook defect: all three example commands used a '--site-server' flag that does not exist, including the headline example in the intro, which also omitted the required OUTPUT_PATH positional. Targets come from LDAP discovery; no target flag is needed.

TWO PRE-EXISTING BUGS FOUND, both version-independent, raised for a decision before proceeding: (1) nondeterministic array ordering in SCCM_AdminUser.collectionIds, SCCM_Site.siteSystemRoles, SCCM_CoerceAndRelayToSMB.coercionVictimHostnames, and SCCM_CoerceAndRelayToAdminService.coercionVictimAndRelayTargetPairs -- two reprocess runs of ONE clean bucket under ONE version differ (14 node / 6 edge property diffs), so graph diffing between runs is unreliable and BloodHound sees spurious property changes on re-ingest; (2) an AdminService read timeout is logged only at VERBOSE and reported as 'Collected 0 <resource>' at INFO with nothing in the issues log, so a silently incomplete graph is indistinguishable from a complete one.

**2026-07-29T21:06:03Z**

Step 2 COMPLETE (2a-2e). Both packages now green on ruff AND mypy for the first time, which the two new ci.yml files require.

2a: actions/setup-python@v5 pinning 3.13 added to BOTH release.yml files (python-preference=only-system forbids a managed download; ubuntu-latest ships 3.12).
2b: wheel entry-point + METADATA assertions added to the collector's release.yml, all before uv publish so a bad wheel aborts instead of burning an immutable version.
2c/2d: ci.yml for each package. Collector runs a curated offline test list (most of its suite needs the lab); library runs 'pytest tests' entire (all 21 files / 108 tests are offline -- verified green BEFORE writing the workflow). Library also gained its first [dependency-groups] dev + [tool.uv] python-preference, so it can stand alone as a repo.
2e: 273 mypy errors (206 collector / 67 library) + 50 ruff (27/23) -> ZERO of each. Root causes, not suppression: 88 logger.verbose fixed by routing 18 modules through the shared get_logger() (also retired 5 side-effect-only log_context imports); 85 import-untyped via ignore_missing_imports for impacket/openhound/sspi (none ship py.typed); 3 stub packages added (types-ldap3/pywin32/pyasn1) which surfaced 3 real library issues; 28 fetchone()[0] -> a _scalar() helper.

REAL BUGS found during 2e, not annotation noise: registry.py's get_current_user/get_ntlm_settings annotated Optional[list[str]]/Optional[dict] but are generators yielding (table,row); two ldap.py sites yielded a possibly-None target.ad_object into a dlt resource (fails schema validation downstream with nothing naming the host); dns.py referenced dns.resolver.NXDOMAIN in an except clause where 'dns' binds only on successful import; test_extension_methods.py had a bare try/except swallowing every exception around an unused import AND skipped test_extensions_contains_convert as 'convert phase not yet implemented' (false -- app.converter is assigned; the test passes now); test_bloodhound_exports.py asserted its public API purely by importing 8 names, 7 reading as unused, so ruff --fix would have deleted them and left a green test checking nothing.

MISSTEP worth recording: the first _scalar rewrite used a forward non-greedy regex. transforms.py has 130 con.execute( calls and only 28 with a .fetchone()[0] suffix, so the match ran across newlines from the helper's own body into the next call site and swallowed the code between. Caught by the count (29 vs the expected 28), reverted transforms.py to HEAD, redone with a paren-matching scan: exactly 28 rewritten, 102 untouched, syntax-checked before writing. Same class of hazard had already blocked a similar wrap of list_distinct(...) whose calls span adjacent Python string literals.

VERIFICATION: collector mypy 0/65 files, ruff clean, 36-test offline gate + 131 tests over every touched module. Library mypy 0/35 files, ruff clean, 108 tests. Cached-bucket reprocess proved the 28-site transforms rewrite behaviour-preserving (graph IDENTICAL). Finally a full live --run-all collect against the lab -- the only gate covering the collect-time modules touched (ldap/dns/registry/privileged + library ad/mssql/auth/proxy) -- produced 148 nodes / 454 edges, fingerprint IDENTICAL to the pre-session 0.1.4 baseline. Edge count returned to 454 (from the earlier timed-out run's 452), independently confirming the ope-1d06 timeout diagnosis.

Next: step 3 (scrub ope-1f49 creds, ignore out/, commit everything that must travel, tag pre-split-2026-07-29 -- tag push is the owner's).

**2026-07-29T22:11:22Z**

SIDE QUEST COMPLETE (ope-2419 + ope-50cc), requested before the step-3 commit: the direct BloodHound CE upload feature is out of both published packages and archived in the fork at bloodhound-upload/ (fork-root, so neither git archive prefix can carry it). 24 files preserved including cli_integration.py -- the main.py code was inline, so it is extracted verbatim with a map of where each piece sat -- plus the 2 design plans, ARCHITECTURE 15, and both removed README sections.

Owner correction applied mid-task: shipped docs must not reference the private archive, since ARCHITECTURE.md and PUBLISHING.md travel to the public repo while bloodhound-upload/ does not. The removal narrative moved to bloodhound-upload/docs/removal-record.md; the public changelog now states only the fact, and no file under sccm/sccm or openhound-collector-common mentions the archive.

Three judgement calls worth recording: (1) --disable-possible-edges was REMOVED from convert but KEPT on collect. On convert it was a no-op in all but name -- possible edges are gated during preprocess (transforms._read_disable_possible, from the collect-time value in collection_settings, optionally tightened by SOURCES__SCCM__DISABLE_POSSIBLE_EDGES), so by convert time the decision is already baked into the lookup DB and the flag's only remaining effect was flipping is_traversable in the schema the upload pushed. (2) Both schema JSON files STAY in the package: integration/__init__.py reads schema_SCCM.json at runtime for the test kit's coverage check, and schema_MSSQL.json now has no code reader but ships as a deliverable operators upload by hand -- so the 'runtime data files live inside the package' rule still has teeth and the release.yml data-file assertion is unchanged. (3) convert sccm stays hand-registered: it still carries --lookup-file/--progress, the decorator still has no flag seam, so app.converter is still assigned and openhound remains a declared dependency for that reason.

Found and fixed a THIRD pre-existing red test while sweeping (ope-50cc): edge_help_test.py::test_scope_is_complete had been failing since GenericAll became an emitted kind in the Tier A+ DACL work -- it was never added to the natively-documented exclusion alongside MemberOf/HasSession. Same root cause as the ruff/mypy debt: nothing was running the full suite.

VERIFICATION: both commands bind (collect keeps --disable-possible-edges, convert is down to --lookup-file/--progress/--help); ruff and mypy clean in BOTH packages; FULL collector suite 890 passed / 5 skipped (green for the first time this session); library 81 passed; and a live --run-all collect produced a graph fingerprint IDENTICAL to the pre-session 0.1.4 baseline (148 nodes / 454 edges). Step 3's commit is next.
