# SCCM user and device deployment permissions

Meatbag, the tested application deployment action uses the same permission for
user and device collections. It also uses the same permission to deploy an
application configured to run as the user or as SYSTEM. Application Modify lets
an administrator change that execution setting in either direction. These
findings establish the available execution identities, subject to the conditions
below. Relationship names must still distinguish the achievable identity and
whether the principal can arrange execution or must await an existing schedule,
as agreed during model planning. This research does not change the collector or
its graph schema.

## What was tested

The mayyhem.com lab used site PS1, version **5.00.9128.1000**, and client
PS1-DEV (10.10.11.10). Experiments ran on October 28, 2026, in the client's
America/New_York timezone; the retained UTC timestamps fall on October 29.
The provider was PS1-SMS and the installed Configuration Manager console ran on
PS1-PSS. All active targets resolved inside the authorized lab networks.

Each comparison created a fresh domain account, custom SCCM role, and SCCM
administrator assignment. The native console connected using that restricted
account, even though an administrator supplied the remote Windows connection
and performed setup and observation. Denied controls used the same connection
method. Separate temporary user and device collections contained domainuser
and PS1-DEV respectively. Applications used the All security scope; collection
permissions were restricted to the particular assigned collection.

Actual execution wrote a unique identity marker in `C:\Windows\Temp`. Its command
immediately exited on any computer other than PS1-DEV. The marker recorded the
Windows SID of the process that ran it. Returning a deployment ID, accepting a
policy request, or displaying an application was insufficient to count as
execution. No distribution-point content was needed for these script applications.

Evidence and repeatable scripts:

- [Recorded results](../../tests/integration/permissions/evidence/user-deployment-results.json)
  retain 14 permission comparisons, four notification comparisons, seven successful
  execution cases, a disconnected-session observation, excluded attempts, and cleanup.
- [Experiment](../../tests/integration/permissions/user_deployments.ps1) selects
  permission, execution, or notification comparisons.
- [Helpers](../../tests/integration/permissions/user_deployment_helpers.ps1) create
  the application, request policy, operate Software Center, and observe markers.
- [Independent cleanup audit](../../tests/integration/permissions/user_deployment_audit.ps1)
  verifies both provider objects and remaining client policy.
- [Offline evidence checks](../../tests/integration/permissions/user_deployment_evidence_test.py)
  check actual identity, action order, deadline, comparisons, and cleanup.

## Permission results

These are demonstrated sufficient combinations for the native console commands.
Every supporting permission was not independently minimized.

| Action | Application permissions, object type 31 | Collection permissions, object type 1 | Result |
|---|---|---|---|
| Deploy an existing application | Read (`1`) | Read, Read Resource, Deploy Applications (`1052673`) on the target collection | Accepted for user and device collections, with both execution identities |
| Author and deploy the identity marker | Read, Create, Modify (`1027`) | Same `1052673` combination | Actual user and SYSTEM execution for both collection types |
| Change execution identity | Read, Modify (`3`) | None (`0`), with an empty collection assigned | Saved definition changed User to System and System to User |
| Read-only identity-change control | Read (`1`) | None (`0`) | Console refused the edit; saved definition stayed unchanged |
| Deploy without Deploy Applications | Read (`1`) | Read, Read Resource (`4097`) | Refused for both collection types |
| Deploy outside the assigned collection | Read (`1`) | Deploy combination on the opposite collection; separate broad Read | Refused on the target for both collection types |

Site Read (`6:1`) supported the native console in these comparisons. Application
Create without Modify was not independently tested. The no-Application-Read
control could not resolve/create the deployment through the console; it is not
an independently tested direct-provider authorization denial.

There was no separate permission for choosing user versus SYSTEM in these
tests. `Set-CMScriptDeploymentType` changed `InstallationBehaviorType` with
Application Read/Modify, and a fresh read of the application XML confirmed the
saved `ExecutionContext`. Collection permission was unnecessary for that edit.

Administrators **can still have access to one target collection and lack access
to another**, including a user collection versus a device collection. That is a
difference in assigned collections, rather than a different Deploy Applications
permission. Application security scopes also constrain which applications they
can use. Someone allowed only to deploy existing applications cannot necessarily
change their code or identity. Deployment permission alone therefore does not
establish arbitrary code execution.

## When a user-targeted application executes

Collection type chooses the recipients. The deployment type chooses the Windows
execution identity. A user-targeted application can consequently run as SYSTEM
on a client receiving that user's policy.

| Tested case | Trigger and result |
|---|---|
| Required, user collection, user identity | Policy retrieval led to automatic execution as domainuser; no Install action was requested |
| Required, user collection, SYSTEM identity | Policy retrieval led to automatic execution as `S-1-5-18` |
| Required, device collection, either identity | Both identities executed with the same author/deployment grants |
| Available, user collection, user identity | No marker during the initial 30-second observation; selecting Install in Software Center then produced domainuser's SID |
| Available, user collection, SYSTEM identity | Selecting Install in Software Center produced `S-1-5-18`, although the recipient's Windows token was not an administrator |
| Required, future deadline | No marker at 01:37:26 UTC; provider deadline was 01:38:00 UTC; SYSTEM marker appeared at 01:38:06 UTC |

Microsoft describes Required user policy as created when the deployment is
created, activated at Available Time, and enforced at Deadline. For Available
user deployments, Software Center queries available applications and creates
the deployment policy when the user selects Install. The observed behavior
matches that distinction. Ordinary policy retrieval alone did not expose the
Available user application in the client's `CCM_Application` list in our initial
observations. [Microsoft: application deployment policy for users](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/app-management/understand/user-deployment-technical-reference)

These timings are observations on an otherwise quiet lab client. Requirements,
detection results, client settings, content availability, maintenance windows,
approval settings, and user/session state can affect a real deployment. The
Required tests explicitly allowed installation outside service windows. The
applications were newly created, with unique file detection rules; this does
not establish that changing an already installed application's install command
will execute it again. That separate question is covered by the
[execution-trigger research](sccm-execution-triggers.md).

### Session state and policy retrieval

Initially domainuser and domainadmin were both logged on in disconnected
sessions. The Required user-context application received policy but remained
NotInstalled with `EvaluationState = 17`, which Microsoft defines as waiting
for an active user session. After reconnecting domainuser, a fresh user-context
case executed. A separate Required user-targeted SYSTEM case executed while
both sessions were disconnected. The user-context deployment type required a
logged-on user; the SYSTEM type allowed execution whether or not a user was
logged on. [Microsoft: client application states](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/clients/sdk/ccm_application-client-wmi-class),
[deployment type user experience](https://learn.microsoft.com/en-us/intune/configmgr/apps/deploy-use/create-applications#deployment-type-user-experience-options)

A disconnected session is still a logged-on session. These tests do not prove
that user policy reaches a device where the recipient has never logged on, or
that it executes without any recipient session. Predeployment to primary
devices and user/device affinity were not exercised.

For prompt, repeatable observations, a temporary task used the recipient's
existing limited interactive Windows token to call
`CCM_ClientUtilities.GetUserPolicy()` or `GetMachinePolicy()`. Those calls
returned zero. Required cases did not use Software Center Install. Available
cases opened the exact temporary application in Software Center and invoked its
enabled Install button using Windows UI Automation. Both user and SYSTEM marker
identities were verified independently. The test driver had administrative
rights to arrange this observation; the recipient task used `RunLevel Limited`.
[Microsoft: GetUserPolicy](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/clients/sdk/getuserpolicy-method-in-class-ccm_clientutilities)

**Recipient qualification:** domainuser's token was not a Windows administrator,
but a later audit found a preexisting SCCM **CMPivot Administrator** assignment.
The recorded role has no Application permissions, Deploy Applications, or Notify
Resource. We did not remove or change that assignment. The author/deployer
comparisons used fresh restricted accounts and remain independent of it. The
recipient-side tests should not be described as proving the complete absence of
SCCM privileges or independently minimizing recipient permissions.

### Optional immediate notification

`Invoke-CMClientAction -ActionType ClientNotificationRequestUsersPolicyNow`
succeeded on the device collection with Collection Read, Read Resource, and
**Notify Resource** (`536875009`). The Read/Read Resource control failed with an
explicit insufficient-rights error. This permission was absent from every
successful deployment actor. It accelerates policy retrieval; it is separate
from authorization to create the deployment. These experiments instead used
the recipient's ClientSDK policy request to shorten the wait.

The same console command could not resolve a user collection with either mask.
That lookup failure does not establish what every lower-level notification
method permits. [Microsoft: Invoke-CMClientAction](https://learn.microsoft.com/en-us/powershell/module/configurationmanager/invoke-cmclientaction?view=sccm-ps)

## Which computer, when, and with what rights?

The October 29 follow-up adds two-client experiments. Identifying a targeted user
is different from identifying the computer that will execute an application.
The following results distinguish actual execution from documented possibilities
and from tests whose positive control did not execute.

### A user collection does not select one computer

The collection identifies the users receiving the deployment. **A successful
installation on one computer does not consume the deployment for that user.**
The same Required application and the same assignment installed on PS1-DEV,
then PS1-DP, for the same recipient. Both SYSTEM and ordinary-user execution
were demonstrated. These were separate local installations, with the same
detection filename on each computer. Both clients subsequently reported Installed.

Rechecking user policy for at least 65 seconds after both installations left
exactly one marker on each client. The application remained detected as installed.
This is evidence against a global one-installation limit and against reinstalling
on every policy request. It is not an exhaustive test of every detection method,
dependency, supersedence setting, or future sign-in. Another eligible managed
computer can install independently; an already satisfied local detection rule
normally avoids rerunning the installer. Signing in to an arbitrary computer
does not establish that its SCCM client is eligible or receives user policy.

The recipient already had sessions on both clients. The experiment requested
user policy through the recipient's limited Windows token; it did not create a
new sign-in on the second computer. Thus it directly demonstrates independent
installation on two clients, rather than predicting where an unknown future
sign-in will occur. Microsoft supports multiple primary devices per user.
[User-based management](https://learn.microsoft.com/en-us/intune/configmgr/core/understand/fundamentals-of-managing-devices#user-based-management)

The useful evidence depends on the configuration:

| Evidence or setting | What it establishes | What it does not establish |
|---|---|---|
| User collection membership | The recipient account is targeted | A particular computer or future sign-in |
| Recent logon/current-user report | A possible client on which that user receives policy | That the session is still active or a deployment has arrived |
| Active primary-device association | SCCM's recorded primary computer or computers | That this particular application is restricted to them |
| Primary Device requirement on a deployment type | A primary-device eligibility condition for that user-targeted type | That all other requirements pass or execution has occurred |
| Required deployment with primary-device predeployment enabled | An explicit route to known primary devices without waiting for the recipient to sign in | Exclusive targeting of those devices, successful execution, or an exact execution second |
| Actual client deployment state and execution record | Evidence for that application/user/computer combination | A guarantee about other computers or future runs |

Primary Device requirements and primary-device predeployment are different
settings. The former restricts eligibility; the latter enables installation in
advance of sign-in. Predeployment is available for Required applications. The
October 29 study exercised multiple clients and attempted the primary-device
routes. Their evidence status is recorded below; a saved server association is
not by itself a successful client execution.
[Deployment requirements](https://learn.microsoft.com/en-us/intune/configmgr/apps/deploy-use/create-applications#deployment-type-requirements),
[Primary-device predeployment](https://learn.microsoft.com/en-us/intune/configmgr/apps/deploy-use/deploy-applications#deployment-settings)

To inspect primary-device associations, run this read-only command from the
Configuration Manager PowerShell console connected to PS1, for example on
PS1-PSS in this lab:

```powershell
Get-CMUserDeviceAffinity -UserName 'MAYYHEM\domainuser' |
    Select-Object ResourceName, ResourceID, IsActive, Types
```

Inspect active relationships and the primary relationship type (`Types` includes
`1`). Keep the complete set; do not select the first computer and assume it is
the destination. These associations are exposed by `SMS_UserMachineRelationship`.
[Get-CMUserDeviceAffinity](https://learn.microsoft.com/en-us/powershell/module/configurationmanager/get-cmuserdeviceaffinity),
[Association fields](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/clients/manage/sms_usermachinerelationship-server-wmi-class)

### A deadline does not establish a guaranteed execution time

Required application deployments activate at their availability time and enforce
at the deadline, once the client has policy and can perform the installation.
Available user applications normally activate when the recipient chooses Install
in Software Center. Approval may be an additional condition.
[User application deployment policy](https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/app-management/understand/user-deployment-technical-reference),
[Approval and scheduling](https://learn.microsoft.com/en-us/intune/configmgr/apps/deploy-use/deploy-applications)

Client user-policy settings also matter. Disabling user policy prevents Required
user applications from arriving. Multi-session devices have additional user-policy
settings. Do not infer policy eligibility from a logon record alone.
[Client user-policy settings](https://learn.microsoft.com/en-us/intune/configmgr/core/clients/deploy/about-client-settings#enable-user-policy-on-clients)

On the actual client, `CCM_Application` exposes deadlines, evaluation state, last
evaluation/installation times, and the next user-scheduled time. Its state can
explain a wait for content, maintenance, an active session, sign-in, or network
connectivity. These distinguish a known deployment waiting on a condition from
an execution that was actually observed. `IsMachineTarget` identifies targeting;
it must not be interpreted as the process's Windows identity.
[Client application state](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/clients/sdk/ccm_application-client-wmi-class)

### The collection type does not determine Windows privileges

For the tested script applications, inspect the applicable deployment type's
installation behavior: User, System, or System-for-device/otherwise-User. In the
last case, a user-targeted deployment uses User. An application may have multiple
deployment types with different requirements, so evaluate the appropriate type
for each computer rather than assigning the first type's settings to all targets.
[Application deployment types](https://learn.microsoft.com/en-us/intune/configmgr/apps/deploy-use/create-applications)

The existing identity-marker tests independently confirmed both the recipient's
SID and SYSTEM (`S-1-5-18`) from deployments to a user collection. Application
Read/Modify also changed the saved definition between User and System. Therefore
the current User setting is not a privilege ceiling for someone able to modify
that setting. Model the settings that person can arrange, with the corresponding
execution conditions; do not infer the maximum available access from the current
setting alone. This follow-up does not select or change relationship names.

### Other workload types have their own rules

- **Packages/programs:** read the program's administrative-versus-user run mode,
  logon condition, deadline, and rerun behavior. Do not apply application deployment
  type settings to a package.
  [Program settings](https://learn.microsoft.com/en-us/intune/configmgr/apps/deploy-use/packages-and-programs)
- **Configuration baselines/items:** Microsoft documents user-targeted baseline
  evaluation at the next sign-in on a client that has received the policy. That is
  a sign-in condition, not proof that the user will return to a particular device.
  The script's option to use logged-on-user credentials must be checked separately.
  These user-targeted CI cases were not part of the retained application tests.
  [User-targeted baseline timing](https://learn.microsoft.com/en-us/intune/configmgr/compliance/deploy-use/deploy-configuration-baselines),
  [Script identity option](https://learn.microsoft.com/en-us/intune/configmgr/compliance/deploy-use/create-custom-configuration-items-for-windows-desktop-and-server-computers-managed-with-the-client#script)
- **Standalone task-sequence deployments:** Microsoft's deployment procedure
  targets a device collection. Do not assume that application behavior for user
  collections is a standalone task-sequence targeting feature.
  [Deploy a task sequence](https://learn.microsoft.com/en-us/intune/configmgr/osd/deploy-use/deploy-a-task-sequence)

For the graph's requirement that execution will occur automatically, a user
collection plus a historical user/computer association is insufficient. Unknown
future sign-in or recipient installation must not be presented as certain
eventual execution.

### October 29 placement experiment and its limits

The manual runner is [user_placement.ps1](../../tests/integration/permissions/user_placement.ps1),
with [observation helpers](../../tests/integration/permissions/user_placement_helpers.ps1),
an [independent cleanup audit](../../tests/integration/permissions/user_placement_audit.ps1),
[retained evidence](../../tests/integration/permissions/evidence/user-placement-results.json),
and [offline checks](../../tests/integration/permissions/user_placement_evidence_test.py).
It uses PS1-DEV and PS1-DP (10.10.11.56), both client version 5.00.9128.1007.
Payloads append their nonce, computer, UTC time, and actual Windows SID to the
same local detection filename on each client. They exit without writing on any
other computer. Appending rather than overwriting makes repeated execution
visible. The recipient remains a non-administrator of Windows, with the earlier
SCCM recipient-rights caveat still applying.

| Same application and assignment | First execution on PS1-DEV, UTC | Later execution on PS1-DP, UTC | After another policy-check interval |
|---|---|---|---|
| Required, SYSTEM | 18:29:28 | 18:29:41 | One marker per computer; both Installed |
| Required, ordinary user | 18:31:47 | 18:31:57 | One marker per computer; both Installed |

The separate Primary Device requirement comparison saved an explicit
`PrimaryDevice Equals True` rule. Setup made PS1-DP an active primary device
(`Types: [1]`, administrator source `2`) while PS1-DEV remained non-primary.
Both clients received the user assignment, but neither executed during the
**362.06-second** observation. Client inspection reported NotInstalled and
evaluation state 2; the primary client's log reported NotApplicable. Its machine
policy contained no `CCM_UserAffinity` instance at the additional inspection.
These observations leave the positive control unresolved: they do not prove
that primary requirements never work or identify the underlying cause.
The planned comparison after adding a second primary was therefore not reached.

The corrected no-session predeployment comparison targeted the existing domain
account `MAYYHEM\localuser`. Neither client had a profile or user-policy namespace
for it before or after the observation, and its credentials were never passed
to either computer. Setup recorded PS1-DP as an active primary with `Types: [1]`.
The restricted author created a Required SYSTEM application and deployment.
With predeployment disabled (`OfferFlags: 0`), there was no assignment or marker
on either client over **94.48 seconds**. The same author then enabled
predeployment on the **same assignment**, and a fresh provider read verified
`OfferFlags: 1`. There was still no client assignment or marker over
**602.10 seconds**. The saved installer specified System execution, no required
logon, and no user interaction. The client was requesting machine policy, but
its policy log reported no new machine assignments and it had no
`CCM_UserAffinity` instance at the additional inspection.

This leaves primary-device policy delivery unresolved in this lab; it does not
disprove Microsoft's documented feature or establish that a longer wait would
never succeed. The second-primary no-session comparison was not reached because
the first primary did not execute. **Do not emit a confirmed automatic execution
path from these server settings alone.** The useful follow-up is to establish why
the management point did not deliver the association/deployment policy, then
repeat both primary comparisons. Device-specific approval is a separate,
documented candidate whose permissions and actual execution still need testing.

Setup added that requirement using the built-in global condition. The restricted
author's attempt to retrieve the condition did not construct a rule, so the
retained successful rule creation **does not minimize the author's requirement-
editing permissions**. Setup also changed primary associations and accelerated
machine-policy retrieval. Those actions must not be attributed to the restricted
application author, whose demonstrated application and collection masks remain
`1027` and `1052673`. No Notify Resource permission was granted to that author.

Preparation failures remain in the evidence: fresh-user discovery/limiting-
collection timing, an incorrect console parameter name, and an observer that
mistakenly read a nonexistent assignment `PreDeploy` property. The correct saved
setting is `OfferFlags` with bit `1` set. None of these preparation failures is a
permission denial or evidence against Microsoft's documented predeployment route.
[Assignment fields](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/apps/sms_applicationassignment-server-wmi-class)

### Paths with a known computer

This is a catalogue of application routes, not new emitted relationships. Each
row requires the **same principal** to control the executable application content
and to possess the required deployment or installation action. If an existing
application is already detected, changing its installation command alone does
not prove another execution. Detection, applicable deployment types, content,
logon conditions, approvals, and deadlines must support the proposed event.

| Route | How the computer is known | What causes execution | Evidence and graph treatment |
|---|---|---|---|
| Required application already delivered to a recipient's client | Actual client policy and application state identify the user/application/computer combination | A usable existing deadline or evaluation event; the application must require installation | Automatic first installation observed on two clients in both identities. An existing application still needs a demonstrated future installation or reexecution event. Read policy/state rather than infer from a historical sign-in; an installed application is insufficient. |
| New Required application deployed to a user collection | A known eligible client actually receives that user's policy | Principal creates the deployment and its deadline; normal policy delivery is still necessary | Tested author: Application Read/Create/Modify plus Read/Read Resource/Deploy Applications on the user collection, and supporting Site Read. Recipient policy requests accelerated the tests. This does not prove that the author can send a client notification. Under the agreed definition a newly arranged deadline counts as on demand, with delivery and logon conditions stated. |
| Required SYSTEM application with primary-device predeployment | All active primary associations, with Types containing 1; then machine policy/client state for the specific application | Machine policy can arrange installation without the recipient signing in | Microsoft documents this route. Do not infer success from the association alone; see the live-test status below. Creating/changing associations was setup-administrator work, not an author capability proved here. |
| Available application with a controlled installation action | The actual client on which the installation is requested | Software Center Install, or a separately validated equivalent | Earlier live tests observed both user and SYSTEM execution after Install. If another person's future click is needed, exclude a certain-execution path. Controlling a user account alone does not prove the ability to invoke an action remotely on every computer. |
| Device-specific application approval with automatic installation | The approval request explicitly identifies a ClientGUID, user, and application | SMS_UserApplicationRequest.CreateApprovedRequest with AutoInstall | Documented candidate; not executed or permission-minimized in this study. Requires the appropriate deployment, approval configuration and approval rights. Method availability alone is insufficient. |
| Deploy directly to a device collection instead | Actual device membership identifies the client | Required application deployment to that device collection | Earlier live tests observed both identities. The principal needs deployment rights on that device collection; rights on a user collection do not carry across. |

The Primary Device requirement is an eligibility restriction, not an additional
execution mechanism. A primary association, collection membership, last-logon
record, or installed application alone is not a deterministic execution path.
The same caution applies to user-targeted packages and configuration items:
their distinct execution events and identity settings need separate validation.

For a SYSTEM route the destination may be SCCM_ClientDevice and its Computer.
For ordinary-user execution, record the exact user and computer; do not let that
path inherit SYSTEM control through the existing traversable same-host edges.
The final representation of ordinary-user destinations remains a model decision.
Keep applications and deployments visible as explanatory objects, but do not
join one principal's application-editing rights to another principal's deployment
rights through a shared object. Derive the combined permission for each principal
and destination before making that complete path traversable.

The documented device-specific approval method is described in Microsoft's
[application approval process](https://learn.microsoft.com/en-us/intune/configmgr/develop/apps/application-approval-process).
It requires an existing user/group deployment. It should be a separate experiment,
not an assumed replacement for the observed Software Center action.

### Data needed to build those paths

These are proposed research inputs, not a claim that the collector already
collects them. Prefer an explicit application/user/computer record over guessing
from logon history. Server deployment reports may lag; retain their revision and
observation time. An earlier Success report identifies an installation that
already happened, not a promise that edited code will execute again.

| Question | Relevant data | Limit |
|---|---|---|
| Which users are targeted? | User collection membership, SMS_R_User identity/SID, and the assignment's TargetCollectionID | Membership supplies recipients, not computers. |
| What is deployed and when? | SMS_ApplicationAssignment: AssignedCIs, AssignmentID/AssignmentUniqueID, OfferTypeID, OfferFlags, availability/deadline and maintenance settings | PREDEPLOY is OfferFlags bit 1. A deadline does not prove client delivery. |
| What code, identity, and conditions can the principal arrange? | Application/deployment-type definition, security scopes, and effective role permissions | Check requirements, detection and dependencies for the actual type. Current User mode is mutable when the principal can change it. |
| Which primary computers are recorded? | SMS_UserMachineRelationship with IsActive and Types containing 1 | Preserve all matching computers. A usage association with empty Types is insufficient, and the server association alone did not satisfy our client test. |
| Which application/user/computer combination has reported state? | SMS_AppDeploymentAssetDetails: AssignmentID, AppCI/DTCI, UserName, MachineID/MachineName, Revision, StatusType and EnforcementState | Useful server-side evidence for a particular pair; reporting delay and old success must not become future-execution certainty. This reporting route was not independently validated against our markers. |
| What is the client actually waiting for? | Recipient-context CCM_Application and actual client assignment policy | The lab observer used local administrator access plus an existing recipient token. Adding such endpoint reads to the collector would require a separate collection design; do not assume provider credentials grant endpoint access. |
| How does a device map to an AD Computer? | The matched managed-device record and its verified AD identity | Use verified identities; a display name alone can be ambiguous. |

Microsoft documents the per-asset reporting fields in
[SMS_AppDeploymentAssetDetails](https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/apps/sms_appdeploymentassetdetails-server-wmi-class).
Its existence provides a candidate source for a known pair; it is not execution
proof by itself.

## Consequences for the graph proposal

The earlier single-`SCCM_Execute` suggestion is superseded by the agreed planning
requirement: relationship names should show access level and trigger. Application
Modify can change User to System, so evaluate the context the principal can
arrange rather than treating the current User setting as a permanent limit.
This does not remove the need to distinguish user execution, SYSTEM execution,
newly arranged deadlines, and existing scheduled events in the resulting path.

Keep these conditions when deciding which relationships are traversable:

- Require control of executable content and a usable deployment route. Merely
  reading an application or deploying a fixed existing application is insufficient.
- Respect assigned collections and application security scopes. The same
  permission name does not grant access to every collection.
- Preserve the target type. A user collection supplies user-policy recipients;
  it does not itself identify every computer where SYSTEM execution is possible.
  Evidence of the client's relationship to the user is needed for a device path.
- Treat Available-only execution as depending on recipient installation. These
  tests did not establish an automatic Available-install route without that action.
- A membership-editing relationship does not inherit application authoring or
  deployment powers. Do not share a traversable collection-to-execution path with
  every incoming membership-control edge unless each incoming capability meets
  the required conditions. A separately derived administrator-to-target execution
  relationship avoids that ambiguity at the cost of more edges.

Executing as a user demonstrates use of that user's Windows security context on
the client. These tests did not obtain passwords, reusable credentials, or a
new interactive logon, so none of those should be inferred from the marker alone.

## Approaches excluded from the conclusions

The initial observer read its output as soon as a file existed. This raced with
the task writing the file. The retained helper waits for task completion and
stops unfinished tasks before removal; timeouts from preparation are retained as
excluded attempts, not permission denials.

`CCM_RequestedAppPolicy.QueueRequestedAppPolicy` accepted requests but did not
reproduce the full Available installation flow by itself. An initial attempt
also used policy transport identifiers instead of application model identifiers.
The SYSTEM Available case includes a separately recorded actual Software Center
action; the queued request is retained as context and is not execution proof.
Calling the lower-level `SMS_Client.TriggerSchedule` was denied to the recipient
token, so the retained procedure uses the supported ClientSDK utility methods.

## Repeat and verify in the lab

Run from a Windows PowerShell session with administrative access on PS1-DEV.
The existing lab console, client, domainuser resource and interactive session
are prerequisites. No new package or dependency was added. The user-context
and Software Center cases need domainuser actively connected; reconnect that
existing session before repeating them. Do not log off existing lab sessions.
These scripts use the existing `Lab.psm1` ownership journal and cleanup helpers.

```powershell
Set-Location C:\Users\domainadmin\ConfigManBearPig
$labCredential = Get-Credential MAYYHEM\domainadmin
$investigation = Join-Path $env:TEMP ('cmbp-user-deployments-' + (Get-Date -Format yyyyMMdd-HHmmss))

# Compare user/device target permissions and both identity-change directions.
.\tests\integration\permissions\user_deployments.ps1 -Credential $labCredential -OutputDirectory (Join-Path $investigation 'permissions') -Selection Permissions

# Prove a Required user-targeted SYSTEM application executes.
.\tests\integration\permissions\user_deployments.ps1 -Credential $labCredential -OutputDirectory (Join-Path $investigation 'required-system') -Selection Execution -ExecutionCase User-InstallForSystem-Required

# Observe a future deadline, or the recipient's Software Center Install action.
.\tests\integration\permissions\user_deployments.ps1 -Credential $labCredential -OutputDirectory (Join-Path $investigation 'future') -Selection Execution -ExecutionCase User-InstallForSystem-Required -DeadlineSeconds 120
.\tests\integration\permissions\user_deployments.ps1 -Credential $labCredential -OutputDirectory (Join-Path $investigation 'available') -Selection Execution -ExecutionCase User-InstallForUser-Available

# Optional separate immediate-notification comparison.
.\tests\integration\permissions\user_deployments.ps1 -Credential $labCredential -OutputDirectory (Join-Path $investigation 'notifications') -Selection Notifications

# Run after every experiment has finished, against their common parent folder.
.\tests\integration\permissions\user_deployment_audit.ps1 -Credential $labCredential -OutputDirectory $investigation
```

Inspect each `results.json`: permission comparisons should match expectations;
successful execution cases must have `verified: true` and a nonce/SID matching
the requested marker. A missing marker is an observation, not automatically a
permission denial. The audit must report zero remaining owned objects, policies,
requests and markers, and unchanged original roles. `-Selection All` runs all
three groups; `-ExecutionCase All` runs six execution combinations.

The final independent audit at **2026-10-29 01:52:20 UTC** found zero remaining
owned roles, administrator assignments, applications, deployments, collections,
domain accounts, discovered test users, client deployment policies, requested
application entries, and markers. All 15 original built-in roles matched the
baseline. The recipient session was restored to its original disconnected state;
neither original session was logged off. Owned observer tasks/files and tracked
Software Center processes were removed. Native installation and audit history
remain. Original accounts, role assignments and groups were not changed.

Validation: **90 tests passed** across the new evidence checks, both earlier
permission/trigger evidence files, and the four repository metadata/wiring/
conversion/fixture checks. The first attempt could not import the shared graph
writer from the installed package; retrying with the existing local shared-library
source on `PYTHONPATH` passed. Neither shared repository nor the project's `.venv`
was changed. Validation used an external uv environment and the project's existing
test tools. Ruff linting passed for `src` and `tests`, formatting passed for the new
Python file, and mypy reported no issues in 63 source files. All three PowerShell
files parsed, and both runnable scripts exposed help and examples. No collector
behavior, shared-library behavior, schema, or new runtime
dependency is introduced by this research.

The exact offline validation commands used the already prepared external lab
environment. `--no-sync` preserves it and the repository environment. These
commands do not contact SCCM:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.tmp\cmbp-traversability-venv'
$env:PYTHONPATH = 'C:\Users\domainadmin\ConfigManBearPig\src;C:\Users\domainadmin\openhound-collector-common\src;C:\Users\domainadmin\ConfigManBearPig\.venv\Lib\site-packages'
uv run --no-sync --offline python -m pytest tests/integration/permissions/user_deployment_evidence_test.py tests/integration/permissions/evidence_test.py tests/integration/permissions/trigger_evidence_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py -q -p no:cacheprovider --basetemp C:\Users\domainadmin\.tmp\cmbp-user-deployments-20261028\pytest-manual
uv run --no-sync --offline python -m ruff check src tests
uv run --no-sync --offline python -m ruff format --check tests/integration/permissions/user_deployment_evidence_test.py
uv run --no-sync --offline python -m mypy src/openhound_sccm --cache-dir C:\Users\domainadmin\.tmp\cmbp-user-deployments-20261028\mypy-manual
```

## Placement cleanup and validation

The final independent audit at **2026-10-29 19:13:05 UTC** checked all **13**
managed lab clients. It found zero remaining owned roles, collections,
applications, deployments, administrator assignments, domain/discovered users,
temporary primary types, client policies, markers, or tasks. All **15** original
roles matched the baseline. The original domainuser associations matched their
saved types and sources; its PS1-DEV session was disconnected again and its
PS1-DP console session remained active. No original user was signed out.

The first audit caught two cleanup defects: an inactive owned association row
remained, and removing the temporary primary type had cleared the original
PS1-DP association's sources. The original sources `4` and `9` were restored
from the saved baseline, and the exact inactive owned record was deleted. The
helper now restores missing original sources, verifies the resulting types and
sources, and deletes an empty association only when setup created the original
record. A separate live comparison verified both preserving an existing
association with sources `[4,9]` and removing a newly created association.
The repair and that comparison are retained in the evidence. The audit was
then repeated and passed. SCCM installation and native audit history remain.

**96 offline checks passed**: ten new placement/cleanup evidence checks, the
earlier permission/trigger/user-deployment evidence checks, and the selected
metadata/wiring/conversion checks. This means the recorded observations and
collector checks agree; it does **not** turn the unresolved live primary-device
comparisons into successful executions. Ruff passed for source/tests, mypy
passed for all 63 source files, the new Python file passed formatting, and all
three placement PowerShell files parsed. The runnable scripts expose help and
examples. No collector, schema, shared-library, or runtime dependency changed.

With the same external environment variables shown above, the combined offline
check was:

```powershell
uv run --no-sync --offline python -m pytest tests/integration/permissions/user_placement_evidence_test.py tests/integration/permissions/user_deployment_evidence_test.py tests/integration/permissions/evidence_test.py tests/integration/permissions/trigger_evidence_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/convert_split_output_test.py -q -p no:cacheprovider --basetemp C:\Users\domainadmin\.tmp\cmbp-placement-final-tests
```

Use a fresh `--basetemp` directory if repeating the command. The source used for
shared-library imports was the existing local checkout, as in the earlier
research; neither shared repository nor the project's environment was edited.

## Repeat the placement comparisons

Run these only in the authorized mayyhem.com lab, from PS1-DEV. The payload can
write only on PS1-DEV and PS1-DP. Setup needs the lab administrator; the runner
creates separate restricted authors for application/deployment actions. It never
uses the no-session recipient's password. Original users are never signed out.
The existing domainuser session may be temporarily connected and then restored
to its original disconnected state. Run each selection separately so a failed
positive control does not prevent another comparison from running.

```powershell
$labCredential = Get-Credential 'MAYYHEM\domainadmin'
$placementInvestigation = Join-Path $env:TEMP ('cmbp-placement-' + (Get-Date -Format yyyyMMdd-HHmmss))
New-Item -ItemType Directory -Path $placementInvestigation -Force | Out-Null

# Save the original associations before any comparison changes them.
$originalAssociations = @(Get-WmiObject -ComputerName 'ps1-sms.mayyhem.com' -Credential $labCredential -Namespace 'root\SMS\site_PS1' -Class SMS_UserMachineRelationship -Filter "UniqueUserName='MAYYHEM\\domainuser'" |
    Where-Object { $_.ResourceID -in @(16777228,16777230) } |
    ForEach-Object { @{user=$_.UniqueUserName;resourceID=$_.ResourceID;types=@($_.Types);sources=@($_.Sources)} })
ConvertTo-Json -InputObject $originalAssociations -Depth 5 |
    Set-Content -LiteralPath (Join-Path $placementInvestigation 'original-recipient-affinities.json') -Encoding UTF8

# Same user and application, two computers, two identities, then detection checks.
.\tests\integration\permissions\user_placement.ps1 -Credential $labCredential -OutputDirectory (Join-Path $placementInvestigation 'propagation') -Selection Propagation

# This existing lab account had no profile or user policy on either test client.
# The runner checks profile absence; stop if the environment no longer meets it.
.\tests\integration\permissions\user_placement.ps1 -Credential $labCredential -OutputDirectory (Join-Path $placementInvestigation 'predeployment') -Selection Predeployment -PredeploymentRecipient 'MAYYHEM\localuser' -ObservationSeconds 600

# Separate Primary Device eligibility comparison; its positive control remains unresolved.
.\tests\integration\permissions\user_placement.ps1 -Credential $labCredential -OutputDirectory (Join-Path $placementInvestigation 'primary-requirement') -Selection PrimaryRequirement
```

Omitting `-PredeploymentRecipient` creates a fresh domain recipient and requests
user discovery. The recipient must enter All Users before it can enter the
temporary collection limited to All Users. Discovery and collection evaluation
can take longer than the bounded preparation wait; that is a setup failure,
not a deployment permission denial. No discovery settings are changed.

Every experiment uses owned cleanup journals and a `finally` cleanup block.
The independent audit uses the saved `original-recipient-affinities.json`
baseline. Run it after all selected comparisons finish, including any that
report an unresolved positive control:

```powershell
.\tests\integration\permissions\user_placement_audit.ps1 -Credential $labCredential -OutputDirectory $placementInvestigation
```

The audit checks every managed lab client, because the existing recipient uses
more clients than the two marker destinations. It removes only owned discovered
accounts, exact marker paths, and withdrawn test policies. It also checks
original role definitions, original user/device associations, and remaining
owned primary types for an existing no-session recipient. It does not remove
unrelated policies or research accounts. Native SCCM installation and audit
history remain.

## Suggested commit after review

Nothing was staged or committed. This research is a useful separate checkpoint.
Other changes were already present in the working directory; stage only the
research paragraph from README when prompted by `git add -p`.

```powershell
git add -- docs/research/sccm-user-targeted-deployments.md tests/integration/permissions/user_deployments.ps1 tests/integration/permissions/user_deployment_helpers.ps1 tests/integration/permissions/user_deployment_audit.ps1 tests/integration/permissions/user_deployment_evidence_test.py tests/integration/permissions/evidence/user-deployment-results.json
git add -p -- README.md
git diff --cached
git commit -m "test: document SCCM user-targeted execution permissions" -m "Compare deployment and identity-change rights with restricted lab administrators. Record Required/Available activation, session and deadline behavior, identity markers, and verified cleanup. Add repeatable scripts and evidence checks; 90 selected tests plus lint, type, and PowerShell checks pass. Collector behavior and dependencies are unchanged."
```

After reviewing the earlier research separately, the October 29 placement
experiments form a useful next checkpoint. They establish independent
installations on two clients and distinguish confirmed execution from unresolved
primary-device routes. They retain failed preparation attempts, explain the
graph's evidence requirements, and add no dependency or collector behavior.
Review the full document if it has not previously been committed; staging it
includes its earlier content too. Nothing was staged or committed during this
follow-up. Push the reviewed commit yourself only when you choose to publish it;
the commands below stop at a local commit.

```powershell
git add -- docs/research/sccm-user-targeted-deployments.md tests/integration/permissions/user_placement.ps1 tests/integration/permissions/user_placement_helpers.ps1 tests/integration/permissions/user_placement_audit.ps1 tests/integration/permissions/user_placement_evidence_test.py tests/integration/permissions/evidence/user-placement-results.json
git add -p -- README.md
git diff --cached
git commit -m "test: verify SCCM user deployments on multiple clients" -m "Record independent SYSTEM and user installations, local detection after policy checks, primary-device observations, excluded setup failures, and cleanup. Document known-computer execution routes and the evidence each needs. Collector, schema, shared libraries, and runtime dependencies are unchanged."
```
