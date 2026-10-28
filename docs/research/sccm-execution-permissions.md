# SCCM permissions that allow code execution or access grants

These are live results from the authorized mayyhem.com lab on October 26, 2026.
The tested primary site was PS1, running **5.00.9128.1000**. The tests used
PS1-DEV, PS1-PSS, PS1-DB, and PS1-SMS. They did not independently repeat the
experiments against the CAS or secondary site.

**The most important finding is that editing an existing deployed object is
different from creating a deployment.** An account assigned only an empty device
collection changed an application, package, task sequence, or configuration item
and obtained SYSTEM execution on PS1-DEV through its existing deployment.
The object's security scope controlled whether it could be changed. The existing
deployment controlled which devices received the changed code.

This investigation adds manual tests and recorded evidence. It does **not** change
the collector, its permission calculations, the graph schema, or emitted edges.

**Execution-trigger clarification:** the original deployment tests below used
fresh, due deployments and administrator-assisted client polling/evaluation.
They prove permission to supply code, but do not establish that modifying an
already completed deployment triggers it again. The
[completed-deployment follow-up](sccm-execution-triggers.md) tests the missing
execution mechanisms and any additional permissions. Graph paths must use those
conditions rather than treating Modify plus any deployment as sufficient.

## What reached client devices

| Permission | What the test demonstrated | Condition that matters |
| --- | --- | --- |
| Application: **Modify** | Change an existing application's installation command and run it as SYSTEM. Modify also worked without Application Read or collection permissions in the original test. | An installation command needs an installation event. The follow-up separately proves that editable detection code can run during evaluation of an already-installed application. |
| Package: **Modify** | Change an existing program command and run it as SYSTEM. | A deployment must actually run the changed program. A completed one-time deployment needs another execution event; the follow-up tests recurrence and rescheduling. Read accompanied Modify; its necessity was not separately minimized. |
| Task Sequence Package: **Modify** | Change a command step and run it as SYSTEM. | A deployment must actually run the changed step. A completed one-time deployment needs another execution event; the follow-up tests recurrence and rescheduling. Read accompanied Modify. |
| Configuration Item: **Modify** | Change a discovery script used by a deployed baseline and run it as SYSTEM. | The baseline must evaluate the changed item. The follow-up proves a later normal evaluation and a faster baseline-revision sequence. Remediation was disabled: discovery alone executed code. Read accompanied Modify. |
| Collection: **Run Script**, plus SMS Scripts: **Read** | Run an approved script as SYSTEM. | Run Script covers the target device's collection, and Read covers the approved script's object scope. This starts prepared code; it does not itself let the caller choose new script contents. |

All four existing-object modification tests succeeded **outside the editor's
assigned empty collection**. A separate package test supplied Read through the
Default scope and Modify through a different scope. The provider rejected the
write with an explicit “no modify permissions” error. Read from another role did
not widen the scope of Modify.

Four additional tests proved that one restricted account could supply its **own**
code and deploy it. For each object kind, that account had:

- Read, Create, and Modify on the application, package, task sequence, or
  configuration item.
- Read and the matching deployment permission on its one-device collection.
- Site Read for the Microsoft console connection used by these tests.

The matching collection permissions were **Deploy Applications**, **Deploy
Packages**, **Deploy Task Sequences**, and **Deploy Configuration Items**.
Every creation, command edit, and deployment in these four tests used the same
restricted account. All produced independently observed SYSTEM markers.

These are demonstrated working combinations. The tests did not establish whether
a caller could create a complete object in one raw request with Create but
without Modify. They also did not minimize every console lookup permission.

### Script execution and approval

The smallest successful Run Script account in this test had only Collection
Run Script and SMS Scripts Read. It had neither Collection Read nor Site Read.
The tested route was the provider's `AdminService.RunScript` action.

Run Script was rejected outside the account's assigned collection, even when
another role provided global collection Read. Script Read could come from a
different role and object scope than Run Script. A script outside the caller's
readable object scopes was rejected.

Creating or changing a script was a separate ability:

- SMS Scripts **Create** created a script awaiting approval.
- Requesting an already-approved state during creation did not work. Supplying a
  different author name did not work: the provider recorded the authenticated
  caller as author.
- SMS Scripts **Approve** approved another author's script. Modify alone did not.
- The provider refused self-approval, including with Create and Approve together
  or a different supplied approver name.
- The `UpdateScript` method required **Create** in this provider version. Read
  plus Modify was rejected; Read plus Create worked. Updating an approved script
  reset approval and made the caller its author. That caller could not approve
  the changed script, even with Approve.

Microsoft documents the separate author/approver requirement and the configurable
hierarchy setting. That setting was not changed during this investigation.
[Create and run scripts](https://learn.microsoft.com/en-us/intune/configmgr/apps/deploy-use/create-deploy-scripts)

## What reached the site server, database, and providers

**Site: Manage Status Filters**, tested with **Site: Read**, allowed a restricted
account to create a rule that ran a harmless command as **SYSTEM on PS1-PSS**.
Site Read alone and Site Read plus Modify were rejected for this operation.
The rule matched only a unique test component and message number; ordinary site
events could not trigger it.

This route did not use a client deployment. Microsoft documents that a status
filter can run a program on the site server.
[The status system](https://learn.microsoft.com/en-us/intune/configmgr/core/servers/manage/use-status-system)

The Default object scope worked for PS1. Manage Status Filters in a different
scope was rejected even when a separate role supplied Site Read through Default.
This is a permission on the **site object**. A device collection is not its
boundary.

A separate test ran harmless remote commands from that site-server process to
PS1-DB and PS1-SMS **without supplying credentials**. Both remote markers showed
`MAYYHEM\PS1-PSS$` with an administrator token. The site server used its existing
computer-account access. Those remote processes ran as the computer account,
rather than SYSTEM.

There is also a client-based route: Run Script produced SYSTEM markers on PS1-PSS,
PS1-DB, and PS1-SMS because those servers have SCCM clients. These are two
different reasons a path can reach the infrastructure. PS1-PSS also hosts the
second SMS Provider listed in the lab instructions.

**Unresolved minimum:** Manage Status Filters without Site Read caused a console
lookup error. That result does not prove the provider itself always requires
Read. The demonstrated working combination is Manage Status Filters plus Read.

## What could grant access

| Permission | Demonstrated ability | Important limit |
| --- | --- | --- |
| Administrative Users: **Add** | Create a new SCCM administrator entry and assign Full Administrator. This worked without an extra read-only role. | The AD principal already existed. Add could not replace an existing SCCM entry by submitting it as a new object. Using the grant for oneself may require another principal or group under one's control. |
| Administrative Users: **Modify** | Change an existing entry, including the caller's own entry, to Full Administrator. This worked without an extra read-only role. | Modify could not create a new administrator entry. |
| Security Roles: **Modify** | Replace a custom role's permissions, including a role not assigned to the caller. | Changing a role affects its existing assignments. The useful result depends on who holds that role and its assignment boundaries. |
| Security Roles: **Create** | Create a custom role containing the full permission list. | Create alone did not permit assigning it or changing an existing administrator or role. |

The grant tests also checked collection and object-scope limits:

- A grant role assigned only a narrow collection could grant Full Administrator
  within that collection, but could not grant both global collections.
- Global collection Read through another role did not widen the grant role.
- A grant role limited to Default could not grant All object scopes, even when a
  separate read-only assignment covered All.

These limits apply to the tested SCCM grant operations. They do not contain every
consequence of changing a role.

### Role modification can reach the site despite an empty collection

One account initially had only Security Roles Modify, assigned to an **empty
collection** and the **Default object scope**. It changed its own custom role to
Site Read plus Manage Status Filters, then obtained SYSTEM execution on PS1-PSS.

Role editing applies to custom role definitions generally. The resulting site
permission followed the site's object scope. Requiring a device in the account's
assigned collection would have missed this demonstrated site path.

### Role names and IDs need checking

The initial lab catalog contained these additional findings:

- **Infrastructure Administrator (`SMS000BR`)** and **Operations Administrator
  (`SMS000ER`)** included Manage Status Filters.
- **CMPivot Administrator (`SMS000IR`)** unexpectedly included Administrative
  Users Add/Modify and Security Roles Create/Modify. A fresh account assigned
  only this role successfully changed its own entry to Full Administrator and
  created another Full Administrator entry.

The CMPivot result describes **this lab's collected definition**, not a claim
about every installation's default role. The definition was captured before any
test changes. All 15 original role names and operation lists were identical
afterward.

Role IDs can remain useful shortcuts. The collected operation list should verify
what a role actually permits, including roles identified as built-in.

## Consequences for the graph model

The tests support three different calculations:

1. **Starting a new deployment or running an approved script:** check the action
   against that role assignment's device collections. Check access to the code
   object separately; another role can supply that access.
2. **Changing code in an existing deployed object:** check Modify against the
   object's security scope, then follow the object's existing deployments to
   their devices. Require an execution mechanism from the
   [completed-deployment follow-up](sccm-execution-triggers.md), such as application
   detection, recurring baseline evaluation, or another deployment deadline.
   The editor's collection list does not limit passive propagation of an object
   change. An explicit notification or deployment change has its own permission
   requirements; do not inherit those actions from object Modify.
3. **Changing a site or granting access:** check the relevant site, administrator,
   or role operation. Respect the tested grant boundaries, and account for the
   role-editing route to site execution.

For exact existing-deployment paths, the collector needs object scope memberships
and deployment targets for the relevant applications, packages, task sequences,
and configuration items. The current role-to-collection calculation cannot supply
that information. Its existing role-name relationships must not be presented as
a complete custom-permission calculation.

Deploy or Run Script alone also needs a clear condition: it starts an existing
command. The separate author-and-deploy tests establish when the caller can
supply arbitrary command contents. Adding every deployment permission as an
unconditional code-execution edge would overstate what was demonstrated.

Microsoft's role-administration documentation describes roles, collections, and
object scopes as separate parts of access control.
[Configure role-based administration](https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/configure/configure-role-based-administration)

## Exact permission values

These values came from the lab's `SMS_RbacSecuredObject` catalog. Each operation
number belongs to its object type; it is not a globally meaningful permission.
`GrantedOperations` combines the applicable operation numbers.
[SMS_RbacSecuredObject](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/servers/configure/sms_rbacsecuredobject-server-wmi-class)

| Object type | ID | Relevant operation values |
| --- | ---: | --- |
| Collection | 1 | Read `1`; Deploy Packages `16384`; Deploy Applications `1048576`; Deploy Configuration Items `4194304`; Deploy Task Sequences `8388608`; Run Script `268435456` |
| Package | 2 | Read `1`; Modify `2`; Create `1024` |
| Site | 6 | Read `1`; Modify `2`; Manage Status Filters `65536` |
| Configuration Item | 11 | Read `1`; Modify `2`; Create `1024` |
| Task Sequence Package | 20 | Read `1`; Modify `2`; Create `1024` |
| Security Role | 27 | Read `1`; Modify `2`; Create `1024` |
| Administrative User | 28 | Read `1`; Modify `2`; Add `1024` |
| Application | 31 | Read `1`; Modify `2`; Create `1024` |
| SMS Scripts | 213 | Read `1`; Modify `2`; Create `1024`; Approve `262144` |

For example, `1027` means Read plus Modify plus Create. The catalog identifies
role editing and administrator Add/Modify as operations on the whole object type.
Site Manage Status Filters and the tested library-object Modify operations are
instance permissions. This distinction is retained in the evidence catalog.

## How the tests establish the result

The [manual scripts](../../tests/integration/permissions/) create fresh temporary
AD accounts and custom roles for independent attempts. The setup account creates
test boundaries and observes results; the tested SCCM actions use the restricted
account's credentials.

Some tests load Microsoft's installed console on PS1-PSS through a setup-account
Windows session. Inside that session, the SCCM site connection explicitly uses
the restricted account. Rejected read-only controls check that it does not inherit
the setup account's SCCM privileges.

Every successful execution route required a marker with a unique identifier and
the actual executing identity. Client and site-server markers showed SYSTEM.
The infrastructure continuation also checked the site computer account's
administrator token. The setup account sometimes accelerated normal client
policy polling; it did not execute the marker command.

Applications used file detection because the lab client rejected unsigned
PowerShell detection files. Compliance discovery used VBScript to launch an
inline marker command. Classic programs used a short `whoami` command because
their command field is limited to 127 characters. UTC schedules avoided the lab
servers' different local time zones. No signing policy, clock, WinRM trust list,
or original role definition was changed.

Reading permission names alone, accepting a successful API response as execution,
or reusing an already elevated test account would not establish these boundaries.
Fresh accounts, rejected controls, and independently read markers were used
instead.

## Evidence, validation, and cleanup

The retained [results](../../tests/integration/permissions/evidence/results.json)
contain **134 completed recorded cases across 30 experiments**, including positive
controls and rejected attempts. They preserve native error details. A console
“not found” or lookup failure is not presented as proof of a provider permission
denial. The bare Manage Status Filters read requirement remains explicitly
unresolved.

The evidence also includes the [permission catalog](../../tests/integration/permissions/evidence/permission-catalog.json),
[original role permissions](../../tests/integration/permissions/evidence/builtin-role-permissions.json),
and [before/after role comparison](../../tests/integration/permissions/evidence/original-role-verification.json).
No passwords or credential objects are stored in it.

The offline [evidence checks](../../tests/integration/permissions/evidence_test.py)
verify the demonstrated execution identities, collection/scope boundaries,
approval behavior, grant limits, and unchanged original roles. They read saved
results and make no network connections. **All 24 checks passed**, as did Ruff
lint and formatting. All 12 PowerShell files parsed successfully, and all 11
operator scripts had working help examples. The recovery-journal check also
confirmed that a new run cannot overwrite a journal with unfinished cleanup.
Collector source and package dependencies are unchanged; a collector
build or broad Python regression run is not needed to exercise these manual
research scripts.

Cleanup removes temporary roles, administrators, AD accounts, collections,
definitions, deployments, scripts, and marker files. SCCM automatically discovered
ten temporary users during the investigation; their exact recorded accounts were
also removed from SCCM's discovery data. Final checks verify that experiment
client policies are withdrawn. Normal execution history and audit messages remain.
The [final independent audit](../../tests/integration/permissions/evidence/cleanup-final.json)
found zero remaining experiment objects, accounts, discovery records, or marker
files on all four hosts.

The full scratch records, including unsuccessful setup attempts, are in
`C:\Users\domainadmin\.tmp\cmbp-permission-research-20261026`. An early application
attempt without Read returned no assignment object; an invalid empty-ID journal
entry was removed only after independent queries confirmed that no assignment or
application remained. That attempt is excluded from the completed-case evidence.
The retained helpers now reject empty IDs.

### Repeat a focused experiment

These scripts are deliberately tied to the documented mayyhem.com lab and require
Windows PowerShell, lab administrator credentials, and the existing Microsoft
console on PS1-PSS. They add no Python dependency or distributed Microsoft code.

From the repository directory:

```powershell
$credential = Get-Credential MAYYHEM\domainadmin
$output = Join-Path $env:TEMP 'cmbp-permission-repeat'

# One restricted account creates its own application and deploys its marker.
.\tests\integration\permissions\applications.ps1 -Credential $credential -OutputDirectory "$output\application" -Selection author

# Edit an existing deployed task sequence from an unrelated empty collection.
.\tests\integration\permissions\packages.ps1 -Credential $credential -OutputDirectory "$output\task-sequence" -Workload TaskSequence -Selection outside

# Check Run Script's collection and object-scope boundaries.
.\tests\integration\permissions\scripts.ps1 -Credential $credential -OutputDirectory "$output\scripts" -Selection limits

# Change a custom role, then test the site-server execution route.
.\tests\integration\permissions\status_filters.ps1 -Credential $credential -OutputDirectory "$output\role-to-site" -Selection role

# Inspect an experiment's recorded outcome and cleanup journal.
Get-Content "$output\role-to-site\results.json" -Raw
Get-Content "$output\role-to-site\cleanup-journal.json" -Raw

# Offline checks of the retained evidence.
uv run python -m pytest tests/integration/permissions/evidence_test.py -q
uv run ruff check tests/integration/permissions/evidence_test.py
uv run ruff format --check tests/integration/permissions/evidence_test.py
```

Application, package, task-sequence, and configuration-item scripts also offer
separate `control`, `author`, and `outside` selections. Each output directory
contains a cleanup journal without credentials. A failed cleanup is reported as
an error and must be resolved before reusing that directory.

### Suggested commit after manual review

Suggested message: **`test: document SCCM execution and permission-grant boundaries`**.
This records the live experiments, reviewed evidence, graph-model implications,
manual reproduction steps, and cleanup checks. It changes no collector behavior
and adds no dependency.

The README already contains other work, so select only the new permission-research
paragraph when staging it. No Git action has been performed by the agent.

```powershell
git add -- tests/integration/permissions docs/research/sccm-execution-permissions.md
git add -p -- README.md
git diff --cached
git commit -m "test: document SCCM execution and permission-grant boundaries"
```
