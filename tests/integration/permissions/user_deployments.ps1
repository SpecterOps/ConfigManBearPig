<#
.SYNOPSIS
Compare SCCM user/device deployment permissions and execution identities.
.DESCRIPTION
Runs only in the authorized mayyhem.com lab on PS1-DEV. Uses fresh restricted
administrator accounts, temporary applications/collections, and harmless identity
markers. The existing MAYYHEM\domainuser session is the deployment recipient;
its account and privileges are not changed. User-policy retrieval and optional
installation run with that existing user's limited interactive token.
.PARAMETER Credential
Lab administrator used for setup, observation, and cleanup. Tested SCCM actions
explicitly use each restricted account through the existing lab console helper.
.PARAMETER OutputDirectory
New evidence directory. Results and ownership journals never contain passwords.
.PARAMETER Selection
Permissions compares grants and denied controls. Execution proves identities and
required/available activation. Notifications checks the optional policy-refresh
action. All performs all three groups.
.PARAMETER ObservationSeconds
Maximum wait for each expected execution marker; absence is recorded separately
from an explicit permission denial.
.PARAMETER ExecutionCase
Optionally repeat one targeting/context/purpose combination instead of all six.
.PARAMETER DeadlineSeconds
For Required deployments, seconds from creation until the deadline. The default
is already due. A positive value also records a before-deadline observation.
.EXAMPLE
.\tests\integration\permissions\user_deployments.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-user-deployments" -Selection All
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][pscredential]$Credential,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateSet('Permissions','Execution','Notifications','All')][string]$Selection='All',
    [ValidateRange(30,900)][int]$ObservationSeconds=180,
    [ValidateSet('All','User-InstallForUser-Required','User-InstallForSystem-Required',
        'Device-InstallForUser-Required','Device-InstallForSystem-Required',
        'User-InstallForUser-Available','User-InstallForSystem-Available')]
    [string]$ExecutionCase='All',
    [ValidateRange(-3600,600)][int]$DeadlineSeconds=-300
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
. (Join-Path $PSScriptRoot 'user_deployment_helpers.ps1')
if ($env:COMPUTERNAME -ne 'PS1-DEV') { throw 'Run this experiment only on PS1-DEV.' }
Write-Host 'Using the authorized PS1-DEV lab client.'
$context=New-LabContext $Credential $OutputDirectory
$site=@(Get-LabObjects $context.Scope "SELECT Version FROM SMS_Site WHERE SiteCode='PS1'")
if ($site.Count -ne 1) { throw 'Expected exactly one PS1 site version.' }
$records=[System.Collections.Generic.List[object]]::new()
$markers=[System.Collections.Generic.List[object]]::new()
$recipient='MAYYHEM\domainuser'
$recipientSID=([Security.Principal.NTAccount]::new($recipient)).Translate([Security.Principal.SecurityIdentifier]).Value
function Save-UserDeploymentResults {
    @{runTag=$context.RunTag;siteVersion=$site[0].Version;recipient=$recipient;recipientSID=$recipientSID;
        target='PS1-DEV';records=@($records.ToArray());updatedUTC=[DateTime]::UtcNow.ToString('o')} |
        ConvertTo-Json -Depth 14 | Set-Content -LiteralPath (Join-Path $context.OutputDirectory 'results.json') -Encoding UTF8
}
try {
    $users=@(Get-LabObjects $context.Scope "SELECT ResourceID,UniqueUserName FROM SMS_R_User WHERE UniqueUserName='mayyhem\\domainuser'")
    if ($users.Count -ne 1) { throw 'Expected exactly one discovered lab domainuser resource.' }
    $userCollection=New-UserDeploymentCollection $context $recipient $users[0].ResourceID
    $deviceCollection=New-LabCollection $context 'one device user comparison'
    Add-LabCollectionDevice $context $deviceCollection 16777230
    $emptyCollection=New-LabCollection $context 'empty editor scope'
    $collections=@{User=$userCollection;Device=$deviceCollection}
    $persistentCount=$context.Resources.Count
    if ($Selection -in @('Permissions','All')) {
        foreach ($targetType in @('User','Device')) {
            $targetCollection=$collections[$targetType]
            $opposite='User'
            if ($targetType -eq 'User') { $opposite='Device' }
            else { Write-Verbose 'The device negative control is assigned only the user collection.' }
            $cases=@(
                @{Name='read without deploy';App=1;Collection=4097;Allowed=$false},
                @{Name='deploy user identity';App=1;Collection=1052673;Allowed=$true;Behavior='InstallForUser'},
                @{Name='deploy system identity';App=1;Collection=1052673;Allowed=$true;Behavior='InstallForSystem'},
                @{Name='deploy without application read';App=0;Collection=1052673;Allowed=$false},
                @{Name='deploy outside assigned collection';App=1;Collection=1052673;Allowed=$false;WrongScope=$true}
            )
            foreach ($case in $cases) {
                $record=[ordered]@{group='deployment-permissions';name=$case.Name;targetType=$targetType;
                    applicationMask=$case.App;collectionMask=$case.Collection;expectedAllowed=$case.Allowed;accepted=$false}
                try {
                    $assigned=$targetCollection.CollectionID
                    if ($case.WrongScope) { $assigned=$collections[$opposite].CollectionID }
                    else { Write-Verbose 'The action is tested within the assigned collection.' }
                    $actor=New-UserDeploymentActor $context $case.App $case.Collection $assigned $case.Name -GlobalRead:([bool]$case.WrongScope)
                    $record.actor=$actor.Name;$record.assignedCollection=$assigned;$record.targetCollection=$targetCollection.CollectionID
                    $marker=New-UserDeploymentMarker;$markers.Add($marker)
                    $behavior='InstallForSystem'
                    if ($case.Behavior) { $behavior=$case.Behavior }
                    else { Write-Verbose 'The negative control uses the system-context definition.' }
                    $name=$context.RunTag+' permission '+[guid]::NewGuid().ToString('N').Substring(0,8)
                    $null=New-UserDeploymentApplication $context $Credential $name $behavior $marker 'C:\Windows\System32\cmd.exe /c exit 0'
                    $record.behavior=$behavior
                    try {
                        $assignment=New-UserDeploymentAssignment $context $actor.Credential $name $targetCollection.CollectionID
                        $record.accepted=$true;$record.assignmentID=$assignment.ID
                    }
                    catch { $record.error=Get-LabError $_;Write-Warning ($record.error | ConvertTo-Json -Compress) }
                    $record.matchesExpectation=$record.accepted -eq $case.Allowed
                }
                catch { $record.setupError=Get-LabError $_;Write-Warning ($record.setupError | ConvertTo-Json -Compress) }
                finally { Remove-LabResources $context -KeepFirst $persistentCount;$records.Add($record);Save-UserDeploymentResults }
                Write-Host ($record | ConvertTo-Json -Depth 6 -Compress)
            }
        }
        foreach ($applicationMask in @(1,3)) {
            foreach ($initialBehavior in @('InstallForUser','InstallForSystem')) {
                $changedBehavior='InstallForUser'
                if ($initialBehavior -eq 'InstallForUser') { $changedBehavior='InstallForSystem' }
                else { Write-Verbose 'Testing the reverse switch from system to user.' }
                $record=[ordered]@{group='context-permissions';applicationMask=$applicationMask;collectionMask=0;
                    initialBehavior=$initialBehavior;changedBehavior=$changedBehavior;accepted=$false}
                try {
                    $actor=New-UserDeploymentActor $context $applicationMask 0 $emptyCollection.CollectionID 'change execution identity'
                    $record.actor=$actor.Name
                    $marker=New-UserDeploymentMarker;$markers.Add($marker)
                    $name=$context.RunTag+' context '+[guid]::NewGuid().ToString('N').Substring(0,8)
                    $null=New-UserDeploymentApplication $context $Credential $name $initialBehavior $marker
                    try {
                        $null=Invoke-LabConsole $Credential $actor.Credential {
                            param($name,$behavior)
                            $logon='WhetherOrNotUserLoggedOn'
                            if ($behavior -eq 'InstallForUser') { $logon='OnlyWhenUserLoggedOn' }
                            else { Write-Verbose 'Changing this definition to SYSTEM execution.' }
                            Set-CMScriptDeploymentType -ApplicationName $name -DeploymentTypeName 'Harmless identity marker' -InstallationBehaviorType $behavior -LogonRequirementType $logon -Force
                        } @($name,$changedBehavior)
                        $record.accepted=$true
                    }
                    catch { $record.error=Get-LabError $_;Write-Warning ($record.error | ConvertTo-Json -Compress) }
                    $record.saved=Get-UserDeploymentDefinition $context $name
                }
                catch { $record.setupError=Get-LabError $_;Write-Warning ($record.setupError | ConvertTo-Json -Compress) }
                finally { Remove-LabResources $context -KeepFirst $persistentCount;$records.Add($record);Save-UserDeploymentResults }
                Write-Host ($record | ConvertTo-Json -Depth 6 -Compress)
            }
        }
    }
    else { Write-Verbose 'Skipping permission comparisons in this execution-only run.' }
    if ($Selection -in @('Notifications','All')) {
        foreach ($targetType in @('User','Device')) {
            foreach ($collectionMask in @(4097,536875009)) {
                $record=[ordered]@{group='notification-permissions';targetType=$targetType;
                    applicationMask=0;collectionMask=$collectionMask;accepted=$false}
                try {
                    $actor=New-UserDeploymentActor $context 0 $collectionMask $collections[$targetType].CollectionID 'user policy notification'
                    $record.actor=$actor.Name
                    $null=Invoke-LabConsole $Credential $actor.Credential {
                        param($collectionID)
                        Invoke-CMClientAction -CollectionId $collectionID -ActionType ClientNotificationRequestUsersPolicyNow
                    } @($collections[$targetType].CollectionID)
                    $record.accepted=$true
                }
                catch { $record.error=Get-LabError $_;Write-Warning ($record.error | ConvertTo-Json -Compress) }
                finally { Remove-LabResources $context -KeepFirst $persistentCount;$records.Add($record);Save-UserDeploymentResults }
                Write-Host ($record | ConvertTo-Json -Depth 6 -Compress)
            }
        }
    }
    else { Write-Verbose 'No separate notification comparison was selected.' }
    if ($Selection -in @('Execution','All')) {
        $cases=@(
            @{Target='User';Behavior='InstallForUser';Purpose='Required'},
            @{Target='User';Behavior='InstallForSystem';Purpose='Required'},
            @{Target='Device';Behavior='InstallForUser';Purpose='Required'},
            @{Target='Device';Behavior='InstallForSystem';Purpose='Required'},
            @{Target='User';Behavior='InstallForUser';Purpose='Available'},
            @{Target='User';Behavior='InstallForSystem';Purpose='Available'}
        )
        foreach ($case in $cases) {
            $caseName=$case.Target+'-'+$case.Behavior+'-'+$case.Purpose
            if ($ExecutionCase -ne 'All' -and $ExecutionCase -ne $caseName) {
                Write-Verbose "Not selected for this repeat: $caseName"
                continue
            }
            Write-Host "Testing $caseName"
            $context.RecipientRequests=[System.Collections.Generic.List[object]]::new()
            $record=[ordered]@{group='execution';targetType=$case.Target;behavior=$case.Behavior;purpose=$case.Purpose;
                applicationMask=1027;collectionMask=1052673;verified=$false;startedUTC=[DateTime]::UtcNow.ToString('o');sessionsBefore=@(quser)}
            try {
                $collection=$collections[$case.Target]
                $actor=New-UserDeploymentActor $context 1027 1052673 $collection.CollectionID 'author user device comparison'
                $record.actor=$actor.Name
                $marker=New-UserDeploymentMarker;$markers.Add($marker)
                $record.requestedMarker=@{nonce=$marker.Nonce;path=$marker.Path}
                $name=$context.RunTag+' execution '+[guid]::NewGuid().ToString('N').Substring(0,8)
                $record.application=New-UserDeploymentApplication $context $actor.Credential $name $case.Behavior $marker
                $assignment=New-UserDeploymentAssignment $context $actor.Credential $name $collection.CollectionID $case.Purpose $DeadlineSeconds
                $record.assignmentID=$assignment.ID;$record.assignedUTC=[DateTime]::UtcNow.ToString('o')
                $record.enforcementDeadlineUTC=$assignment.DeadlineUTC
                $policyAction='Retrieve'
                if ($case.Target -eq 'Device') { $policyAction='RetrieveMachine' }
                else { Write-Verbose 'This deployment uses user policy.' }
                Write-Host 'Policy will be requested by the non-administrator recipient through ClientSDK.'
                $record.recipientRequest=Invoke-UserDeploymentRecipient $context $recipient $name $policyAction
                if ($record.recipientRequest.error) { throw "Recipient request failed: $($record.recipientRequest.error)" }
                $record.requestedUTC=[DateTime]::UtcNow.ToString('o')
                if ($case.Purpose -eq 'Available') {
                    $record.beforeUserInstall=Wait-UserDeploymentMarker $marker 30
                    $record.recipientBeforeInstall=Invoke-UserDeploymentRecipient $context $recipient $name Inspect
                    $record.savedDefinition=Get-UserDeploymentDefinition $context $name
                    $applicationModel=$record.savedDefinition.UniqueID -replace '/[0-9]+$',''
                    $record.recipientInstall=Invoke-UserDeploymentRecipient $context $recipient $name SoftwareCenter $applicationModel
                    if ($record.recipientInstall.error) { throw "Recipient installation request failed: $($record.recipientInstall.error)" }
                    Write-Host ('Recipient installation request: '+($record.recipientInstall | ConvertTo-Json -Depth 5 -Compress))
                    $record.installRequestedUTC=[DateTime]::UtcNow.ToString('o')
                }
                else { Write-Host 'Required deployment: no recipient Install action is requested.' }
                if ($case.Purpose -eq 'Required' -and $DeadlineSeconds -gt 0) {
                    $record.beforeDeadlineMarker=Wait-UserDeploymentMarker $marker 30 $context $recipient $name -RefreshUserPolicy -PolicyAction $policyAction
                    $record.beforeDeadlineObservedUTC=[DateTime]::UtcNow.ToString('o')
                }
                # Already-due deployments have no separate future-deadline window.
                $record.marker=Wait-UserDeploymentMarker $marker $ObservationSeconds $context $recipient $name -RefreshUserPolicy -PolicyAction $policyAction
                $expectedSID=$recipientSID
                if ($case.Behavior -eq 'InstallForSystem') { $expectedSID='S-1-5-18' }
                else { Write-Verbose 'Checking the actual recipient SID, not an administrator SID.' }
                $record.expectedSID=$expectedSID
                $record.verified=$null -ne $record.marker -and $record.marker.sid -eq $expectedSID
                $record.recipientAfter=Invoke-UserDeploymentRecipient $context $recipient $name Inspect
            }
            catch { $record.error=Get-LabError $_;Write-Warning ($record.error | ConvertTo-Json -Compress) }
            finally {
                $record.additionalRecipientRequests=@($context.RecipientRequests.ToArray())
                Remove-LabResources $context -KeepFirst $persistentCount
                $records.Add($record)
                Save-UserDeploymentResults
            }
            Write-Host ($record | ConvertTo-Json -Depth 10 -Compress)
        }
    }
    else { Write-Verbose 'Skipping execution observations in this permissions-only run.' }
}
finally {
    Remove-LabResources $context
    foreach ($marker in $markers) {
        $resolved=[IO.Path]::GetFullPath($marker.Path)
        if ($resolved -notmatch '^C:\\Windows\\Temp\\cud-[a-f0-9]{32}\.json$') { throw 'Refusing to remove an unexpected marker path.' }
        if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved }
        else { Write-Verbose 'This experiment did not create that marker.' }
    }
    Save-UserDeploymentResults
}
