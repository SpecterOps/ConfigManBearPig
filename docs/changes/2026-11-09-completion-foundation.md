# SCCM completion foundation

Implementation is underway under the approved
[completion plan](../superpowers/plans/2026-11-09-sccm-extension-completion.md).
This work uses the local common-library checkout. Publishing and the dependency
minimum remain final release tasks. No graph schema or new relationship is changed.

## Problems and selected fixes

| Problem | Behavior and code |
|---|---|
| A missing or empty target file could remove the target restriction. | [`source._read_computer_file`](../../src/openhound_sccm/source.py) rejects missing, unreadable, undecodable, or empty files and accepts UTF-8/BOM. [`main._cli_seed_targets`](../../src/openhound_sccm/main.py) validates before DC/DNS discovery and reuses the seeds. Direct source construction validates too. |
| An SMB error body could be mistaken for signing being disabled. | [`clients/smb.py`](../../src/openhound_sccm/clients/smb.py) validates the session framing, fixed body length, SMB2 header size, successful status, NEGOTIATE command, server-response flag, and NEGOTIATE body structure before reading signing bits. Invalid replies remain unknown. |
| A SQL protection probe timeout could become Off or Allowed. | Common's `clients/mssql.py:_classify_binding` requires a recognized authentication outcome. CMBP's [`collect_mssql`](../../src/openhound_sccm/collectors/mssql.py) saves independent host/SPN facts with unknown protection before raising the incomplete-measurement error to the phase observer. |
| Genuine preprocessing failures and missing prepared tables could be reported as success. | [`transforms._safe`](../../src/openhound_sccm/transforms.py) opts into shared error propagation; [`SCCMLookup.table_rows`](../../src/openhound_sccm/lookup.py) raises database errors and closes its cursor. A successful empty prepared table still yields zero rows. Missing optional raw tables retain their logged skip. |
| Strict errors exposed assumptions that optional raw fields always exist. | The owner approved the related corrections on 2026-11-10. Principal and group builders prepare known alternative names, SIDs, memberships, and administrator flags with the existing typed-NULL helper. Session construction prepares RemoteRegistry SIDs and requires both. Client SID lookup casts identifiers to text before uppercasing, including an all-NULL identifier inferred as numeric. Known facts survive; unknown fields do not create memberships or sessions. |
| Partial AdminService collection could prevent WMI recovery. | [`privileged._collect`](../../src/openhound_sccm/collectors/privileged.py) records logical read outcomes, including missing role/assignment details. A failed HTTP page raises to that boundary; other collections continue. Only a complete transport gets its completion marker. |
| Ordinary phase errors could leave the command successful. | [`collection_status.py`](../../src/openhound_sccm/collection_status.py) observes existing phases and reuses common outcome records. WMI success can recover the equivalent AdminService read. Remaining failed reads appear in `collection_status_<timestamp>.json`; usable data and requested usable later stages are retained before nonzero final status. |
| Users could not independently suppress log files. | `--no-full-log` and `--no-issues-log` select common `RunFileLogs` outputs. Both default to on. Disabled full output has no spool/callbacks; disabled issues output keeps warning/error counts. Console silence and final status stay independent. |
| Inactive options and unsupported methods promised behavior they did not provide. | Removed `--enable-bad-opsec`, `--show-cleartext-passwords`, their unused settings, and obsolete metadata credentials. [`validate_collection_methods`](../../src/openhound_sccm/context.py) rejects unsupported names, including DHCP, before discovery. Help and README describe current behavior. |

## Why this approach

Ignoring a bad file would broaden collection; rejecting the input preserves the
operator's boundary. Treating failed protocol replies as disabled protection
would invent attack evidence, so they remain unknown. Existing shared probe and
logging code remains in the common library rather than being copied into CMBP.
The new SQL-error argument defaults to the previous behavior for other consumers.

The existing phase engine already continues ordinary errors and stops fatal
cleanup/cancellation errors. A local observer adds SCCM's completion policy
without changing that shared engine. Each computer's existing worker owns its
records, so no second scheduler or global error counter is needed. Read records
contain fixed labels and categories, not credentials, query text, or raw exception
messages. The completion report is diagnostics, separate from deferred findings
reports and from `bhe-extensions` finding definitions.

Keeping inactive flags would continue to mislead users. Implementing secret
recovery merely to make those flags meaningful would violate the agreed scope.
Built-in role shortcuts remain; custom-role and client-push graph changes await
their separate design decisions.

For optional fields, the existing preparation helper is the smallest correction:
it adds only named missing fields to an existing raw table, preserves collected
values and types, and does not create an absent source. Filling arbitrary fields
after every SQL error would hide spelling mistakes. Returning to swallowed errors
would again allow incomplete graphs to report success. Requiring every optional
field at collection time would reject valid sparse responses and old cached data.
The tests cover actual JSON list storage, including empty and populated lists.

## Dependencies and effects

No new dependency is added. The local shared copy supplies the approved EPA,
SQL-error, and file-choice changes. The shared EPA correction affects the SQL
collector too; the other shared changes preserve default behavior. No SQL
collector or OpenHound core source was edited. Source construction and CLI input
validation agree, while old cached raw columns can still be read as ordinary data.

Development and Windows checks used CMBP HEAD
`6c2da51b5810a8c98ef03119541e010df5359b0d` plus the uncommitted foundation changes
described here, and common HEAD `08f548ccd1969bcf91b403bd6f24c752e476419a` plus the
approved EPA, SQL-error, log-choice, graph-test ordering, and Windows-only boundary
changes, tests, and documentation. The source override
and both build commands are written out in the outside review guide. These are
local working copies, not published releases.

Partial results now have an honest failure status. Scripts calling this collector
must distinguish usable partial output from a completely successful collection.
Expected exclusions and ordinary non-provider/access-limit skips remain skips.
Fatal cleanup, output-consumer failures, and rejected credentials keep their stop
behavior. The full outcome report is written only after ordinary collection
finishes; fatal early failures remain explained by the command/logs.

## Verification so far

- Shared library: 655 tests passed, one skipped; Ruff and mypy passed on 65 files.
- SQL consumer: 13 target-collection/failure-control tests passed with the changed
  common source. Its pre-existing working-tree changes were left untouched.
- 179 combined SCCM checks passed, covering the four required CI files, ticket
  checks, optional-field regressions, bad target files, SMB reply shapes, unknown EPA with
  preserved host facts, required lookup failures, provider fallback recovery,
  partial final status with requested conversion, all log-file combinations, and
  supported method/CLI help behavior. Ruff and mypy pass on 64 source files.
- All 53 focused optional-field and neighboring checks passed. The new cases cover
  absent, empty, and populated JSON memberships through AdminService and WMI,
  unknown administrator group flags, and no invented session for a missing host SID.
- Two copies of `out/lookup.duckdb` were transformed with the original and updated
  code and converted independently. Both produced 99 nodes and 307 edges. Exact
  comparison found no difference after excluding only generated `last_seen`
  timestamps. The original cached database was not modified. Evidence is in
  `C:\Users\domainadmin\AppData\Local\Temp\sccm-completion-cache-zd2kecvr`.
- The real unauthenticated signing check returned `False` on both
  `ps1-sms.mayyhem.com` and `ps1-db.mayyhem.com`, after verifying their addresses
  are in the authorized lab. Initial sandbox-blocked attempts returned unknown;
  those are not counted as successful live checks.
- A real Windows `-m SMB -c ps1-sms.mayyhem.com --run-all` run using current-user
  authentication, both log files disabled, and `--silent` exited zero. Its target
  record is completed with zero failed reads, zero log files, and one graph ZIP.
  Output: `C:\Users\domainadmin\AppData\Local\Temp\cmbp-completion-live-verify-20261109-201303`.
- Both projects built source archives and wheels offline. Installing both local
  wheels into a fresh external Python 3.13.15 environment succeeded without
  `PYTHONPATH`; installed help exited zero and exposed both new log switches.
  That environment resolved OpenHound 0.4.2; development checks used the existing
  environment. This proves local Windows installation/help, not published or WSL
  acceptance. Environment: `C:\Users\domainadmin\AppData\Local\Temp\cmbp-local-install-20261109-201353`.

## Remaining validation and decisions

Strict SQL errors exposed missing optional names, memberships, administrator flags,
and host SIDs, plus a NULL identifier inferred as numeric. These corrections are
implemented under the owner's 2026-11-10 approval. The original group reproducer
is `tests/client_device_extras_test.py::test_client_device_extras_from_adminservice_and_local_wmi`.
A broad affected-graph run passed 389 tests and identified three remaining cases
in `node_computer_test.py` and `node_user_test.py`; all three passed after the
corrections, within the 53 focused and 179 combined checks above. This is not a
claim that the entire SCCM suite has passed.

WSL's `Microsoft-Windows-Subsystem-Linux` and `VirtualMachinePlatform` features
were enabled with the owner's approval using `Enable-WindowsOptionalFeature
-Online -FeatureName Microsoft-Windows-Subsystem-Linux,VirtualMachinePlatform
-All -NoRestart`. Windows reported `RestartNeeded: True`; separate
`Get-WindowsOptionalFeature` checks reported both features `Enabled`. Automatic
restart was suppressed; the owner restarted the VM before Linux installation
and testing.

Linux verification used WSL 3.0.5.0, its WSL 2 kernel
`6.18.58.1-microsoft-standard-WSL2`, Debian 13.5, system Python 3.13.5, and uv
0.12.21. The runtime was installed with `wsl --update --web-download`, followed by
`wsl --install -d Debian --web-download --no-launch`. Debian's `python3`,
`python3-venv`, `ca-certificates`, `curl`, and `git` packages were installed with
apt. A regular Linux account, `collector`, owns the separate environment
`/home/collector/venvs/cmbp-completion`. No project Python range or dependency
declaration was changed. Microsoft's [WSL command reference](https://learn.microsoft.com/en-us/windows/wsl/basic-commands)
and [uv's installer instructions](https://docs.astral.sh/uv/getting-started/installation/)
describe the setup commands.

The fresh environment installed the same local common 0.1.5.dev5 and collector
2.0.5.dev5 wheels as Windows, resolving OpenHound 0.4.2, DuckDB 1.5.2, and dlt
1.26.0. Imports and CLI help passed without `PYTHONPATH`; their module paths were
checked to be inside the installed environment. Test tools match the Windows
versions: pytest 9.0.3, Ruff 0.15.13, and mypy 2.1.0. The 179 affected/required SCCM
checks passed against the installed local wheels. SCCM Ruff and mypy passed.
The cached Linux graph comparison also produced 99 nodes and 307 edges, with
zero differences apart from generated `last_seen` timestamps. Its copies and
comparison log are in `/tmp/sccm-completion-cache-2ysq5s8v`.

Separate Linux CLI collections with explicit `domainadmin` and `lowpriv`
credentials, restricted to `-m SMB -c ps1-sms.mayyhem.com`, both completed with
zero failed reads, no full/issues log files, and one graph ZIP. Before each run,
the helper checked the DC and target addresses against the authorized lab
subnets. Evidence is under `/home/collector/sccm-completion-evidence`, including
`installed-versions.json`, `installed-help.txt`,
`linux-domainadmin-pvfir59r`, and `linux-lowpriv-wvy7lxaj`. These are limited SMB
and directory-authentication checks, not full provider/hierarchy acceptance.

The initial full common suite on Linux reported 653 passed, two skipped, and one failure:
`test_batches_keep_every_record_and_file_source_without_global_state` assumes
directory enumeration returns numbered parts in order. Its test helper uses
unsorted `Path.glob`. The owner approved sorting filenames in that test on
2026-11-10. The correction preserves the existing batch assertions and passes all
11 graph-file tests on Windows and Linux. Production graph writing is unchanged.
Linux-native mypy also exposed four Windows-only attribute errors in common's
`logging/console.py`, `clients/operations.py`, and `clients/windows_ldap.py`.
The owner separately approved the three-file correction on 2026-11-10.

The implemented shared change makes the Windows requirement explicit at the
three affected boundaries: use `sys.platform` for the console's existing Windows
selection in `logging/console.py`, and check for Windows immediately before native
COM cancellation in `clients/operations.py` and native LDAP socket cancellation
in `clients/windows_ldap.py`. Supported Windows calls keep their current behavior;
accidental direct use of those Windows-only cancellation calls on another system
log and raise a clear unsupported-platform error. Both collectors use these
shared helpers, so the correction belongs in common, with no new dependency or
OpenHound core change.

Explicit conditions were selected over suppressing the four errors or checking
only against Windows definitions: they describe the actual platform requirement
and allow Linux's own checks to run. Mypy documents recognized `sys.platform`
conditions in its [platform-check guidance](https://mypy.readthedocs.io/en/stable/common_issues.html#python-version-and-system-platform-checks).
Outside copies in `/home/collector/sccm-completion-evidence/platform-proposal`
were first supplied to mypy without replacing repository files and passed for
both Linux and Windows definitions. After approval and implementation, all 91
affected console, native LDAP, cancellation, and graph-file checks passed on
both platforms. Six new tests check Windows and non-Windows selections, using
inert APIs to verify the correct console flags, thread, and socket and clear
logged errors for unsupported calls. Ruff and native mypy pass on both systems;
mypy checks all 65 common source files. The final guide run also passed the full
shared suite: 661 passed and one skipped on Windows, 660 passed and two skipped
on Linux. Linux used the rebuilt local common wheel without `PYTHONPATH`; its
installed help, both SMB lab accounts, and cached graph comparison passed again.
The same guide run passed the 179 SCCM checks and source/wheel builds. Broader
hierarchy and authentication acceptance remain open.

Named/multiple SQL instance work, custom
permission/client-push features, actual BloodHound findings,
every supported authentication path, and full
administrator/ordinary-user lab acceptance remain outstanding. Fresh local-wheel
installation/help has been checked on Windows and WSL; published installs still
follow final publication.
No ticket is closed solely from these development checks. The verified foundation
checks and commit commands are supplied in the outside review guide; remaining
acceptance work stays tracked in the completion plan.
