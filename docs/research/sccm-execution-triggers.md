# Execution triggers after an SCCM deployment has finished

This follows the [permission investigation](sccm-execution-permissions.md). It
addresses a limitation in those first tests: their deployments were newly
prepared and due to execute. The administrator also accelerated client polling
and, for baselines, requested evaluation. Those results did not establish that
editing an already completed deployment would make the changed code run.

The follow-up uses the same authorized lab, with PS1-DEV for explicit-trigger
tests and a separate client, PS1-DP, for passive observation. The site version is
5.00.9128.1000. The test date is October 27, 2026.

The missing execution mechanisms were found for all four object types:

| Changed object | What actually executes it | Additional action rights in the demonstrated route |
| --- | --- | --- |
| Application | Its detection script runs during application evaluation, even while Installed. | None for the passive result; Notify Resource for the faster requested-policy/evaluation sequence. |
| Configuration item | An existing deployed baseline later evaluates its discovery script. | None for the passive result; modifying the parent baseline and Notify Resource supplied a faster sequence. |
| Package program | Its existing repeating deployment runs it again, or its deployment receives a new future deadline. | Notify Resource in the repeating test; Deploy Packages plus Notify Resource to create another deadline. |
| Task-sequence step | Its existing repeating deployment runs the sequence again, or its deployment receives a new future deadline. | Notify Resource in the repeating test; Deploy Task Sequences plus Notify Resource to create another deadline. |

All successful changed-code markers recorded SYSTEM. Object Read accompanied
Modify in this follow-up; connection/lookup rights are detailed below. A historic
deployment record alone is insufficient to establish that any command will run.

## How these tests differ

Each explicit-trigger test first waits for the original harmless deployment to
finish successfully. An application must report Installed; a baseline must
report Compliant. A package or task sequence needs its original SYSTEM marker
and an explicit successful completion record from the client.

Only then does the restricted account change code. After that boundary, the lab
administrator reads results but does not request client policy, evaluation, or
execution. Any requested SCCM action uses the restricted account's credentials.
A second, distinct SYSTEM marker proves that the changed code actually ran.

For hidden required programs, the client SDK may omit the completed program.
The test reads the exact package's persistent SCCM execution history instead:
`_ProgramID`, `_State`, `_RunStartTime`, and `SuccessOrFailureCode`. Checking the
current log file alone proved unreliable because SCCM rotates it. Two setup
attempts stopped before code modification because of those observation issues;
they are not permission-denial results.

## Application: detection supplies the execution mechanism

Changing only an installed application's installation command did not run the
changed command during the 151-second observation window. The restricted caller
successfully requested policy downloads and application evaluations, and the
client received the new revision while continuing to report Installed.

The working route changed the **detection script** instead. Detection is code
SCCM runs to decide whether an application is installed. The test script wrote a
harmless SYSTEM marker and still reported Installed. The installation command
did not need to run again.

Two execution mechanisms were demonstrated:

- **Normal client behavior:** a Modify-only account changed detection on PS1-DP
  after the original installation had completed. No notification or forced client
  action followed. The client's existing policy timer retrieved the new revision,
  and detection executed the changed code about **26 minutes 13 seconds** after
  modification.
- **Caller-requested evaluation:** a restricted account with Application Modify
  and Collection Notify Resource changed detection, then requested policy download
  and application evaluation. The second SYSTEM marker appeared after about
  **43 seconds**, with the application still reporting Installed.

The passive client's existing policy timer was 60 minutes plus random delay of
up to 60 minutes. Its log predicted the next ordinary request at 20:52 UTC; the
marker was observed at 20:52:34 UTC. The test did not change that timer. This is
an observed delay in this lab, not a guaranteed execution time.

Passive elapsed times use the observer's UTC timestamps. Explicit-trigger
comparisons time their observation window after the editor's changes and any
rescheduling/baseline revision. The first passive run's
displayed elapsed counters incorrectly added the observer's seven-hour local
offset. The retained evidence preserves those original counters separately and
recalculates the durations from the recorded modification/observation timestamps.
The helper now keeps timestamp offsets when calculating elapsed time.

The application used system-context execution and a required deployment. The
detection script was VBScript launching an inline harmless marker command, so
the result did not depend on allowing unsigned PowerShell script files. Other
application execution contexts and deployment types need their own conditions.

Microsoft describes detection as part of application evaluation.
[Application deployment evaluation](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/app-management/understand/deployment-evaluation-technical-reference)

## Configuration item: normal evaluation, or revise the parent baseline

Changing only a discovery script and requesting policy/compliance checks did not
produce the second marker in the 300-second window. The baseline remained at its
completed revision during that observation. An accepted notification alone was
not treated as execution.

The separate passive test then established a slower working mechanism. A
Modify-only account changed discovery after the baseline was already compliant.
The deployment already had a recurring evaluation schedule. Without notifications,
administrator client actions, deployment changes, or parent-baseline edits, the
changed discovery script produced a SYSTEM marker after **52 minutes 39 seconds**.
The short 300-second negative did not mean that discovery-only edits cannot run.

A faster working test used the same restricted account to:

1. Change the configuration item's discovery script.
2. Revise the parent baseline, using a description change to publish a new revision.
3. Request policy download and compliance evaluation.

The already-compliant baseline then moved from revision 2 to revision 3 and ran
the changed discovery code as SYSTEM, producing its marker after about
**44 seconds**. Remediation remained disabled.

The tested account had Configuration Item Read/Modify and Collection Notify
Resource. Configuration items and baselines both use object type 11 for these
permissions. This faster sequence requires access to **both actual objects**
within their security scopes. Collection Deploy Configuration Items was not
granted. The passive result does not require a parent edit or Notify Resource.

This proves two mechanisms, with different delays and requirements. It does not
establish that the compliance notification is necessary in addition to policy
retrieval in the faster sequence. Microsoft documents
that baseline evaluation results can be cached for 15 minutes; short waits do
not establish a universal failure.
[Monitor compliance settings](https://learn.microsoft.com/en-us/intune/configmgr/compliance/deploy-use/monitor-compliance-settings)

## The separate notification permission

The provider's `SMS_ClientOperation.InitiateClientOperation` method was tested with
three action numbers:

| Action | Meaning |
| ---: | --- |
| 8 | Download computer policy |
| 13 | Evaluate application deployments |
| 125 | Check compliance |

All three were accepted with **Collection: Notify Resource (`536870912`)**.
The provider rejected all three for the Read control, Modify Resource, and Deploy
Applications profiles. Every profile shared Collection Read/Read Resource and
Site Read for lookup and connection. Those lookup rights were not individually
minimized.

The explicit-trigger workload tests used an assigned collection containing just
PS1-DEV. They did not separately minimize the lookup rights or repeat notification
requests with a device outside the caller's assigned collection. The passive
results establish execution without needing any notification action at all.

Notification permission is separate from permission to edit an application or
configuration item. Microsoft also documents Notify Resource as the permission
for client-notification actions.
[Client notification](https://learn.microsoft.com/en-us/intune/configmgr/core/clients/manage/client-notification),
[Invoke-CMClientAction](https://learn.microsoft.com/en-us/powershell/module/configurationmanager/invoke-cmclientaction)

## Package: give the completed deployment another deadline

The completed-package test changed its command and requested policy download.
No second marker appeared in the 90-second window. Editing the command and
receiving policy did not, by themselves, repeat its completed one-time deployment.

The working caller-controlled route was:

1. Change the existing package program's command with Package Modify.
2. Set a new deadline with Collection Deploy Packages (`16384`) and allow reruns.
3. Request policy with Collection Notify Resource (`536870912`).

The changed command ran as SYSTEM about **85 seconds** into observation. The new
schedule was set two minutes into the future; SCCM's schedule has minute precision.
The client received the changed command and retained `RerunAlways` behavior.
The same rescheduling operation was rejected when the account lacked Deploy
Packages. Read/Modify on the package and Notify Resource did not replace it.

An earlier attempt set a deadline in the current minute. SCCM accepted the write,
but there was no execution in 182 seconds. The successful comparison gave the
client time to receive policy before the new deadline. This is why the test needs
both an accepted request and an independently observed marker.

## Task sequence: reschedule its deployment

Changing a command step and requesting policy did not repeat a successful
one-time task sequence during the 90-second comparison. The working route used
Task Sequence Package Read/Modify, **Collection Deploy Task Sequences
(`8388608`)**, and Notify Resource. The same restricted account changed the
step, set a new future deadline with reruns allowed, and requested policy.
The changed step then produced a second SYSTEM marker.

Without Deploy Task Sequences, the provider rejected the rescheduling operation.
The test sequence contained only one harmless command; it did not install an
operating system, change firmware, or restart the client.

The installed console needed the task-sequence **package ID and collection ID**
for `Set-CMTaskSequenceDeployment`. Earlier deployment-ID selector attempts
returned argument/lookup errors, even with the deployment permission. Those
attempts are excluded from the permission comparisons.
[Set-CMTaskSequenceDeployment](https://learn.microsoft.com/en-us/powershell/module/configurationmanager/set-cmtasksequencedeployment?view=sccm-ps)

## Existing repeating package and task-sequence deployments

Two more comparisons established the repeating schedule **before** the original
successful execution. Each deployment repeated every two minutes and allowed
reruns. After the original success, the restricted editor changed the code and
requested policy. It never changed or recreated the deployment.

Both produced changed-code SYSTEM markers without deployment rights:

| Workload | Time after modification | Object rights | Collection rights |
| --- | --- | --- | --- |
| Package | About 146 seconds | Package Read/Modify (`2:3`) | Read/Read Resource plus Notify Resource (`536875009`) |
| Task sequence | About 70 seconds | Task Sequence Package Read/Modify (`20:3`) | Read/Read Resource plus Notify Resource (`536875009`) |

An existing repeating deployment therefore supplies the execution event. The
matching Deploy permission is required for the tested **rescheduling** operation;
it is not required to wait for a schedule that already exists. These two tests
used the editor's notification permission to retrieve changed policy. They did
not separately repeat the full passive-policy wait for packages/task sequences,
so they do not establish an observed no-notification delay for those workloads.

## What this means for graph paths

An object-to-device connection needs an execution mechanism, not just a record
that the object was deployed at some point.

- An editable application detection method can execute during evaluation of an
  already-installed application. A normal policy cycle supplied a real mechanism
  in the passive test. Notify Resource supplied a faster caller-controlled route.
- A changed CI discovery script can execute through an existing recurring
  baseline evaluation. The faster tested sequence additionally modifies the
  parent baseline and requests notification; preserve access to both objects
  when describing that particular sequence.
- A completed one-time package or task sequence needs another execution event.
  The demonstrated caller-controlled route changes its deadline with the matching
  collection deployment permission, then retrieves policy with Notify Resource.
- Notify and deployment permissions apply to the target collections. Object Modify
  applies to the relevant object scopes. Rights can come from different roles held
  by the same account; a broad Read assignment does not replace a missing action.
- Execution context matters. These markers proved SYSTEM execution. A user-context
  deployment must not automatically imply control of the whole device.

This follow-up changes research tests and documentation only. Graph calculations
and schema changes remain a separate design decision.

## Exact rights and test conditions

Each explicit workload account had Site Read (`6:1`) for the native console,
Collection Read plus Read Resource (`1:4097`), and Read/Modify on the selected
object. Notification adds `536870912` to the collection's operations. Rescheduling
adds Deploy Packages (`16384`) or Deploy Task Sequences (`8388608`) on that
collection. Application is object type 31, Package is 2, Task Sequence Package is
20, and Configuration Item/baseline is 11. Modify is `2`; Read/Modify combines to
`3`. These values came from the lab's permission catalog, not role-name guesses.

The passive account had Application Read/Modify, Configuration Item Read/Modify,
Site Read, and Collection Read/Read Resource. It had **no Notify or Deploy action**.
Both passive workloads completed before either was modified. The baseline's
one-minute recurring schedule was established during setup, not by the editor.
The long observed delay demonstrates that this schedule is not a guarantee of
immediate evaluation of a changed item.

The tests deliberately used content-free harmless commands and system-context
deployments. They do not establish that access to an arbitrary content source,
a user-context deployment, an available deployment requiring a user's action, or
a completed nonrepeating deployment automatically controls every client.

There are no new dependencies, collector changes, shared-library changes, schema
changes, or new graph relationships. Windows PowerShell, the already-installed
Microsoft Configuration Manager console, native WMI, and existing lab helpers
perform the experiments. Native program flags are documented by Microsoft.
[SMS_Program](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/servers/configure/sms_program-server-wmi-class)

## Evidence and repeatable checks

The [retained trigger evidence](../../tests/integration/permissions/evidence/trigger-results.json)
contains 14 completed workload comparisons, 12 notification-permission checks,
and two passive workloads. It remains separate from the original 134-case study.
Six attempts with setup-observation or console-selector errors are retained as
excluded attempts, with their actual errors and completed cleanup. They are not
counted as permission denials.

The original-assisted approach was unsuitable for this question because an
administrator could supply the missing execution event. Accepted API calls alone
were also unsuitable because policy receipt, successful installation, and command
execution are different outcomes. Requiring the original success and a distinct
second SYSTEM marker directly answers the completed-deployment question.

Run a focused comparison from this repository in the documented lab:

```powershell
$credential = Get-Credential MAYYHEM\domainadmin
$output = Join-Path $env:TEMP ('cmbp-trigger-repeat-' + [guid]::NewGuid().ToString('N'))

# Change detection after installation, then request policy/evaluation as the editor.
.\tests\integration\permissions\execution_triggers.ps1 -Credential $credential -OutputDirectory "$output\application" -Workload Application -Profile ModifyNotify -Mechanism Notify -ApplicationChange DetectionScript

# Change discovery and revise the parent baseline, with no deployment permission.
.\tests\integration\permissions\execution_triggers.ps1 -Credential $credential -OutputDirectory "$output\baseline" -Workload ConfigurationItem -Profile ModifyNotify -Mechanism Notify -RefreshBaselineDefinition

# Reschedule a completed package. Change Profile to ModifyNotify for the denied control.
.\tests\integration\permissions\execution_triggers.ps1 -Credential $credential -OutputDirectory "$output\package" -Workload Package -Profile ModifyDeployNotify -Mechanism Reschedule -ObservationSeconds 360

# Follow an already-repeating task sequence without deployment permission.
.\tests\integration\permissions\execution_triggers.ps1 -Credential $credential -OutputDirectory "$output\task-sequence" -Workload TaskSequence -Profile ModifyNotify -Mechanism Notify -RecurringDeployment -ObservationSeconds 300

# Optional long test: no client notifications after either object is changed.
# Do not request actions on PS1-DP from another session while this runs.
.\tests\integration\permissions\passive_execution.ps1 -Credential $credential -OutputDirectory "$output\passive" -ObservationSeconds 10800

# Isolate the notification permission with four fresh-account profiles.
.\tests\integration\permissions\notification_permissions.ps1 -Credential $credential -OutputDirectory "$output\notifications"

# Inspect the result and confirm its cleanup journal is empty.
Get-Content "$output\application\results.json" -Raw
Get-Content "$output\application\cleanup-journal.json" -Raw

# Offline evidence checks; these never connect to the lab.
uv run python -m pytest tests/integration/permissions/evidence_test.py tests/integration/permissions/trigger_evidence_test.py -q
uv run ruff check tests/integration/permissions
uv run ruff format --check tests/integration/permissions
```

The workload, notification, and passive scripts all provide `Get-Help -Examples`.
`execution_helpers.ps1` is a shared helper file, not a separate experiment.
Result files and cleanup journals contain no passwords. An unfinished journal
must be resolved before that output directory can be reused.

Full scratch records and the independent final audit script remain under
`C:\Users\domainadmin\.tmp\cmbp-execution-triggers-20261027`. Each experiment removes
its own temporary definitions, deployments, collections, roles, administrators,
domain users, and markers. The independent audit then checks those ownership tags,
removes any automatically discovered copies of those exact users, withdraws
deleted client policies, removes recreated markers, and compares all 15 original
built-in role definitions. Normal audit messages and execution history remain.

Validation completed successfully:

- **52 offline evidence checks:** the original 24 plus 28 completed-deployment
  checks, including initial success, changed-code identity, permission controls,
  passive timestamps, recurrence, and cleanup.
- The four normal CI test files passed: **20 tests**. That first run printed a
  Windows temporary-directory permission error during pytest's shutdown cleanup,
  after all tests had passed. The evidence run used its own temporary directory
  and completed cleanly.
- Ruff lint passed for `src` and `tests`; both research Python files passed
  formatting checks. Mypy passed for all 63 collector source files.
- All **16 PowerShell files** parsed, and all **14 operator scripts** had working
  help examples. Research links and all empty final cleanup journals were checked.
- The independent audit recorded zero owned resources, accounts, marker files,
  or client policies remaining, and unchanged names/operations for all 15 original
  built-in roles. Its timestamp and detailed counts are retained with the evidence.

The repository-wide whitespace check reported existing trailing spaces in
`CLAUDE.md`; that unrelated file was left untouched. There are no whitespace
errors in the research changes.

### Suggested commit after manual review

Suggested message: **`test: prove SCCM execution triggers after completed deployments`**.
This includes the execution mechanisms and required actions, harmless live tests,
recorded evidence, offline evidence checks, reproduction instructions, and cleanup
verification. Collector behavior and dependencies remain unchanged.

The older research and README already contain other uncommitted work. Review the
full diff and stage only the relevant README paragraph. Nothing has been staged
or committed; no push is proposed.

```powershell
git add -- tests/integration/permissions/execution_helpers.ps1 tests/integration/permissions/execution_triggers.ps1 tests/integration/permissions/notification_permissions.ps1 tests/integration/permissions/passive_execution.ps1 tests/integration/permissions/trigger_evidence_test.py tests/integration/permissions/evidence/trigger-results.json docs/research/sccm-execution-triggers.md
git add -p -- docs/research/sccm-execution-permissions.md README.md
git diff --cached
git commit -m "test: prove SCCM execution triggers after completed deployments"
```
