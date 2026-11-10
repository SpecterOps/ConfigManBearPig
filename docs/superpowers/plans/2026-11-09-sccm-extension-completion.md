# SCCM extension completion plan

Agreed scope and review evidence, 2026-11-09. Tracking ticket:
[SCCM extension completion](../../../.tickets/con-6f42.md).

This is the current completion plan. Where older ticket designs disagree with
the decisions below, this plan takes precedence for this effort. Inclusion means
agreed scope, not completed implementation. The owner has approved implementation,
which is underway. Current results and the approved optional-field corrections are
recorded in [the foundation change note](../../changes/2026-11-09-completion-foundation.md).
New graph schemas and finding definitions have not been changed.

## What completion means

An ordinary installation can collect the advertised SCCM data on Windows and
Linux through WSL, save usable results when some requested work fails, and clearly
report what is missing. Graph relationships must follow collected evidence.
Unread settings are unknown, not proof of safety or exposure. The README must
describe the behavior users actually receive.

The finished work includes custom-role permission analysis, client-push
configuration analysis, independent full/issues log-file switches, and SCCM
findings maintained in the separate `bhe-extensions` repository. Keep the current
built-in role shortcuts and their role-specific relationships. No broad rewrite,
secret recovery, or OpenHound core change is included.

## First: correct the confirmed defects

These findings came from reading the major collection, authentication,
preprocessing, conversion, logging, and packaging paths, with small offline
reproductions. The review did not establish live Windows/WSL or BloodHound success.
Locations below identify functions rather than line numbers that will move.

| Finding and evidence | Required result and verification |
|---|---|
| **A missing target file can remove the target restriction.** `source.py:source` ignores a nonexistent computer file; an empty `allowed_targets` in `context.py` means unrestricted targets. Constructing the source with a missing path reproduced that empty restriction without network collection. | Reject missing, unreadable, or empty explicitly supplied target files before discovery or authentication. Test these cases, including a file combined with explicit computer arguments. Supplying no restriction remains an intentional supported choice. |
| **The declared dependency minimum permits an installation that cannot start.** `pyproject.toml` permits common library 0.1.4. The installed 0.1.4 lacks imported `clients.credential_guard`, `dlt.progress`, `collection.engine`, and `graph.files`; importing the CLI without a source-path override failed on `credential_guard`. | **Owner decision: use the local common-library checkout for all development, installation, and testing for now.** This is a final release task, not a blocker for the remaining work. Once the work is complete, prepare both repositories for the owner's review and push/release process. Publish a sufficient common version before releasing the collector that requires it, then update the collector's minimum and lock file and verify fresh published-package installs on both systems. No newer published version was verified during this review. |
| **An SMB error response can look like signing is not required.** `clients/smb.py:_parse_security_mode` checks packet length/signature but not successful NEGOTIATE status/body. A constructed SMB2 error packet returned `False`. | Validate the successful NEGOTIATE header and body before reading signing bits. Error, malformed, and unrelated replies produce unknown plus a useful diagnostic, never a relay path based on signing being disabled. Test real-shaped success and error packets. |
| **A SQL protection probe timeout can look like protection is Off.** Common library `clients/mssql.py:_classify_binding` treats a failed bogus-binding probe without an untrusted-domain marker as `Off`. A fake timeout outcome reproduced this. | Apply the shared-library proposal below. Failed probes must not establish `Off` or `Allowed`. Preserve independently collected SQL facts and mark the measurement incomplete. Test both probe positions and known conclusive authentication outcomes. |
| **An incomplete AdminService read can suppress WMI fallback.** `collectors/privileged.py:_collect` catches individual read failures and still marks the phase complete. A fake required-read exception produced no rows, marked AdminService complete, and made the WMI decision skip. | Track individual read outcomes; empty successful results differ from failure. Recover missing data through the existing fallback where possible, retain successful rows, and report any remaining missing work. A successfully recovered read must not leave the run falsely incomplete. |
| **Unexpected preprocessing/conversion failures can leave a successful status.** `transforms.py:_safe` delegates to common `safe_execute`, which logs genuine SQL errors and returns. A misspelled-column statement returned normally. `lookup.py:table_rows` also returns no rows on failure; a missing required prepared table reproduced this. | Opt into propagation of genuine SQL errors. Distinguish optional raw tables that were never collected from required prepared tables that should exist. Save usable output where possible, identify failed work, and return nonzero for an unexpectedly incomplete requested result. Cover standalone stages and `--run-all`. |
| **Multiple SQL instances can be reduced to the first instance.** `collectors/mssql.py` chooses the first matching SPN and defaults to port 1433; a two-port fixture checked only the first. Registry settings/service-state helpers also take the first answer, and the AD SPN-holder lookup chooses one account. | Collect independent instance/port/account/protection facts for SCCM site SQL topology. Test named instances, nondefault ports, multiple instances/accounts on one host, and conflicting or missing evidence. Do not apply one instance's settings to another. See [SQL instance testing](../../../.tickets/ope-1172.md). |

The SMB requirement is supported by Microsoft's [successful NEGOTIATE response
rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3b29f3af-86f9-4962-8cf3-43471cb59363)
and [SMB2 error response structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d4da8b67-c180-47e3-ba7a-d24214ac4aaa).

For incomplete runs, continue independent reachable work and requested later
stages when their inputs are usable. Save raw data and usable graphs, then return
nonzero with an explanation of what remains missing. Intentional exclusions and
expected ordinary-user access limits are not failures by themselves. Keep the
existing stop-after-one-rejected-credential behavior. Reuse common
`OperationResult`, `TargetResult`, and `RunResult` where applicable rather than
inventing a second set of completion records.

## Shared-library proposal: approved

Repository: `C:\Users\domainadmin\openhound-collector-common`.
This is a proposal for three bounded changes, with their tests and documentation.
The owner approved this proposal and instructed implementation to begin after
selecting the local common-library copy for development. The approval covers
these changes, their tests, and documentation. No OpenHound core edits are proposed.

1. **Do not classify SQL EPA from an inconclusive probe.** In
   `clients/mssql.py`, require a recognized completed authentication result before
   selecting `Off` or `Allowed`. A timeout, transport error, or unrecognized
   response from either required probe raises `EPAPrereqError` with a non-secret
   explanation of which measurement failed. Retain the existing meaning of
   conclusive `Off`, `Allowed`, `Required`, and the documented ambiguous result;
   explicitly test which completed login-failure responses count as evidence.
   CMBP handles this as unknown/incomplete while retaining independent SQL facts.
2. **Allow callers to fail on genuine preprocessing errors.** Add an optional
   keyword argument, proposed as `raise_on_error=False`, to
   `dlt/duckdb_safe.py:safe_execute`. Its default preserves other callers' current
   behavior. An opting-in caller receives the original non-missing-table DuckDB
   error after it is logged. Missing source tables retain their existing handling;
   `expected_miss` remains a logging classification, not proof that every absent
   table is acceptable. CMBP separately checks that required prepared tables
   exist and handles any missing requested result through its final status.
3. **Allow full and issues log files to be disabled independently.** Add optional
   `write_full=True` and `write_issues=True` arguments to
   `logging/files.py:RunFileLogs`. Defaults preserve existing consumers. Disabled
   full logging creates neither its file nor its private spool and registers no
   full-log completion callbacks. Disabled issues logging writes no issues file
   but still counts warnings/errors through a counting-only handler. Preserve
   the current counts exposed to callers, redaction, cleanup, and repeated-close
   behavior. `owned_log_paths` lists only enabled file outputs. CMBP supplies the
   CLI choices; log-file choices never change failure status or console choices.

These belong in the common library because SQL probing, SQL error handling, and
the run-owned file handlers already live there and are also used by the MSSQL
collector. Copying them into CMBP would create two implementations to maintain.
Changing SQL-error handling for every consumer by default would impose an
unnecessary behavior change. Attaching and then muting file handlers would still
create unwanted files or spools. Treating probe failure as protection being Off
would create an unsupported attack path.

No new dependency is proposed. The EPA correction intentionally affects all
consumers; validate the MSSQL collector's relevant protection checks as well as
CMBP. The other two changes preserve default behavior. Use the local common-library
checkout for all work and checks now, including Windows and WSL installation
checks. Record the local revision and any uncommitted changes used; do not rely on
the older published package or require publication before development continues.
Use an external development environment and a local dependency override; do not
ship a sibling-directory requirement in the published collector.

After the work is complete, run each repository's required checks and prepare both
for the owner's review and push/release process. Publish the sufficient common
version before the collector release that requires it; then update CMBP's minimum
and lock file and verify installs without local overrides. Local-copy checks do
not prove a published installation works. The owner performs commit, push, and
release actions; no automatic staging, commits, or pushes are authorized.

## Included SCCM capabilities

| Work | What to build | Success evidence |
|---|---|---|
| **Custom-role permissions** ([individual permissions](../../../.tickets/Ope-rhzx.md), related [administrator assignment](../../../.tickets/ope-a214.md)) | Read actual operations and retain each role's collection/security-scope assignment. Establish device code execution and authority to grant unrestricted SCCM administration only from sufficient permission combinations. Keep built-in shortcuts and their remediation meaning. Use separate permission-based relationships with supporting roles, operations, and scope evidence. Calculate combinations in preprocessing and emit the agreed relationships during conversion. | Positive/negative cases, modified custom roles, split assignments, restricted collections, and unavailable evidence. Run Script permission for already-approved scripts alone does not prove arbitrary new code execution. Review exact permission combinations, relationship names/endpoints, evidence, and schema before implementation. |
| **Client-push settings** ([client push](../../../.tickets/Ope-0t3h.md)) | Read actual relevant configuration and configured account identities; derive only paths whose prerequisites are established. This is configuration analysis, without password recovery, triggering installation, or coercing authentication. | Positive/negative configurations and unavailable settings. At least Read-Only Analyst privileges or local administrator access to a site server is needed to check the setting in this scope. Leave a path out until settings are checked; record unassessed rather than disabled. Verify actual API/registry fields and graph design before implementation; old ticket field names and placeholder edges are not an approved contract. |
| **SCCM findings in `bhe-extensions`** | Review the drafts in `edges/`; put final SCCM-owned definitions in a separate checkout of `SpecterOps/bhe-extensions`, following that repository's format. Include findings for approved new relationships when ready. SQL/AD relationships may supply evidence but SQL/AD-owned findings are out of scope. | Import definitions into the lab BloodHound and show actual positive and negative finding generation. A successful selector query or membership alone is insufficient. Confirm repository access/layout and lab test setup first. The ignored local drafts are references, not registered findings; do not blindly publish or delete them. |
| **Log-file convenience** ([independent logs](../../../.tickets/ope-00df.md)) | Independent switches to disable full and issues files, with both enabled by default. Suggested CLI names are `--no-full-log` and `--no-issues-log`, matching today's file names. Existing `--silent` remains a console choice. | All four file-choice combinations, composed with console silence. Disabled outputs leave no file/spool; visible counts and final status remain correct. Update help and README. Shared implementation requires proposal approval. |
| **Truthful supported options** ([unused safety flag](../../../.tickets/Ope-emhc.md), [DHCP](../../../.tickets/Ope-o6bh.md)) | Remove inactive `--enable-bad-opsec` and `--show-cleartext-passwords` options and their unused settings. Remove DHCP from supported method choices and reject it before collection. Remove stale advertising of deferred functionality. | Help, environment/config handling, invalid-method errors, and ordinary commands agree with the code. No compatibility shim or replacement secret-recovery feature is required. |

Keep stable IDs, hierarchy ownership, existing collection boundaries, and current
built-in role relationships unless an individually reviewed change requires
otherwise. Hand-maintained package and extension schema copies must agree with
the emitted kinds. No new relationship name or schema is approved by this plan.

## Deferred work

Deferred means outside this completion effort, not completed or abandoned.

| Work | Existing tracking and decision |
|---|---|
| Additional System Management container rights/site takeover | [Container permissions](../../../.tickets/Ope-liu7.md). Defer new GenericWrite, WriteDACL, WriteOwner, CreateChild, and inheritance paths. |
| Client-serving management/distribution-point relationships and new Tier Zero rules | [Client-serving relationships](../../../.tickets/con-96e3.md). Defer expansion; current rule correctness remains in scope. |
| Credential/secret recovery and registration/decrypted policy or PXE media | [Secret work](../../../.tickets/Ope-t7kv.md), [local recovery](../../../.tickets/Ope-padv.md), [policy work](../../../.tickets/Ope-gqwo.md), [network access account relationship](../../../.tickets/ope-e10b.md). No passwords are recovered in this effort. |
| DHCP/PXE discovery | [DHCP](../../../.tickets/Ope-o6bh.md). Remove its unsupported advertised choice. |
| New remote client-side WMI | [Remote client WMI](../../../.tickets/Ope-ew5k.md). Existing SMS Provider fallback and local reads remain supported. |
| Management-point relay | [Corrected MP relay ticket](../../../.tickets/Ope-zaja.md). Garrett Foster's management-point identity relayed to site SQL, as described in the mssqlkaren blog technique; separate from the existing AdminService relay relationship. |
| New NTLM reflection relationship | [Reflection](../../../.tickets/ope-961c.md). |
| Parent CAS to child primary takeover | [Hierarchy takeover](../../../.tickets/con-d857.md). |
| Low-privilege secondary-site identification research | [Secondary-site research](../../../.tickets/con-0394.md). |
| Emit default collections solely from a known site | [Default collections](../../../.tickets/con-d061.md). |
| Reducing directory queries / `--skip-ad-enum` | [Directory-query options](../../../.tickets/Ope-pofz.md). Defer the whole work item. |
| More domains | One domain is sufficient; exercise the full mayyhem.com hierarchy. |

The standalone Findings/Remediations JSON-report ticket `Ope-exvi` was deleted at
the owner's request because the existing `edges/` drafts cover the findings work.
There is no separate `findings.json` deliverable.

## Order of work and acceptance

1. Review the shared proposal and resolve the exact graph/permission designs
   before edits that require those decisions. Confirm `bhe-extensions` ownership
   and the lab finding-generation setup. These are remaining decisions, not
   reasons to repeat the already agreed inclusion/deferral interview.
2. Correct target-file validation and protocol evidence, then completion/fallback
   reporting and required-table failures. Make the approved shared changes in
   separately reviewable work. Test each defect with the smallest realistic
   reproduction and the affected existing tests.
3. Complete instance-specific SCCM SQL topology and Windows/WSL installation
   checks using the local common-library copy. Keep publication and the published
   dependency minimum as final release tasks after the work is complete. Do not
   expand into a separate SQL collector feature project.
4. Implement custom permissions and client-push configuration with their reviewed
   graph designs. Preserve collected facts, derive access in preprocessing, and
   keep conversion easy to follow. Review built-in remediation descriptions.
5. Add log choices, remove inert options, and reconcile help, README, extension
   documentation, fixtures, and architecture explanations with actual behavior.
   Update cross-cutting architecture sections and affected source references in
   the same change; avoid unrelated cleanup of large files.
6. Finish SCCM finding definitions in their own repository and run the combined
   acceptance checks below. Deliver an outside-repository commit guide with
   complete commands and exact expectations, executed as written before handoff.

| Acceptance area | Required checks |
|---|---|
| Installation/platforms | For this work, fresh installs on Windows and WSL Linux using the local common-library copy, with its revision and local changes recorded; supported Python versions within the declared `>=3.13,<3.15` range; import, help, packaging, and documented commands. Exercise each supported authentication path on its supported platform. Native Windows/current-user authentication stays Windows-only. After completion and publication, separately verify published installs without local redirects before the collector release. |
| Automated checks | Affected tests, the four required CI test files, Ruff, mypy, and package/build checks supported by the project. Keep tests under `tests/` and use an external uv environment. Shared and findings repositories use their own required checks. |
| SCCM lab | Administrator and ordinary-user collection across CAS, primary, secondary, active/passive server arrangements, and distributed roles in mayyhem.com. Verify the same expected evidence on Windows and WSL for supported paths, plus named/nondefault SQL instances. Active testing stays within the authorized lab. |
| Fault handling | Invalid target files, rejected credentials, required-read failures, fallback recovery, unknown signing/EPA, genuine SQL errors, missing required prepared tables, and partial collection. Check saved output, explanation, and final status together. |
| Graph correctness | Compare preprocessing/conversion over the same cached raw bucket before/after changes; explain intended graph differences. Test positive, negative, limited-scope, and unknown-evidence cases. Match actual kinds/properties to approved schemas. |
| Findings | Load the agreed extension/schema and definitions into the lab, generate actual SCCM findings, verify expected positives and absent negatives, and record versions/evidence. |
| Usability and handoff | Copyable mayyhem.com README examples, accurate help/options and limitations, plain-English explanation of the code and alternatives, dependencies/effects, and full numbered manual checks. No staging, committing, or pushing by the agent. |

## Review baseline and remaining decisions

Review checks passed: 283 focused existing tests (84 then 199), Ruff on `src tests`,
and mypy on 63 source files. Tests used the sibling common-library source because
the installed 0.1.4 is insufficient. These are development checks, not proof of a
working published install. One pytest cleanup warning concerned access to an old
temporary directory; subsequent checks used an isolated temporary location.
No live collection, WSL run, or BloodHound finding-generation check was performed
as part of this review. The entire test suite was not run.

Decisions still needed, in dependency order:

- Exact custom-role permission routes and graph relationships, then the verified
  client-push evidence and relationship design. Review schema changes explicitly.
- `bhe-extensions` checkout/access and the lab finding-generation destination.

Implementation is underway; full acceptance remains undone. Keep relevant tickets open
or in progress until their actual checks pass; the review alone does not close
the code-quality or feature tickets.
