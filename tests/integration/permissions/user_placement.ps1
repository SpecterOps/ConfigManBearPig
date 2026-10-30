<#
.SYNOPSIS
Test user deployments on two computers and primary-device predeployment.
.DESCRIPTION
Uses PS1-DEV and PS1-DP in the mayyhem.com lab. Harmless markers record actual
execution identity and repeated installations. Fresh restricted SCCM authors
create applications; a recipient with no client profile tests predeployment. Machine
policy acceleration is explicitly performed by setup, not by those authors.
Original users are never logged off. Owned primary associations are restored.
.PARAMETER Credential
Lab administrator for setup, observation, policy acceleration, and cleanup.
.PARAMETER OutputDirectory
New investigation directory containing results and both ownership journals.
.PARAMETER ObservationSeconds
Maximum observation for each positive placement phase.
.PARAMETER Selection
Propagation, Predeployment, PrimaryRequirement, or All. Propagation compares
SYSTEM and user-context installation on two clients, including a repeat check.
.PARAMETER PredeploymentRecipient
Optional existing mayyhem.com user already discovered by SCCM. The test refuses
clients with a profile for that user. No recipient credentials are requested.
Omit this parameter to create a fresh recipient and wait for discovery.
.EXAMPLE
.\tests\integration\permissions\user_placement.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-user-placement" -Selection All
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][pscredential]$Credential,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateRange(60,900)][int]$ObservationSeconds=360,
    [ValidateSet('All','Propagation','Predeployment','PrimaryRequirement')][string]$Selection='All',
    [string]$PredeploymentRecipient=''
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
. (Join-Path $PSScriptRoot 'user_deployment_helpers.ps1')
. (Join-Path $PSScriptRoot 'user_placement_helpers.ps1')
if ($env:COMPUTERNAME -ne 'PS1-DEV') { throw 'This experiment must start on PS1-DEV.' }
Write-Host 'Testing only PS1-DEV and PS1-DP in the authorized lab.'
foreach ($address in [Net.Dns]::GetHostAddresses('ps1-dp.mayyhem.com')) {
    if ($address.ToString() -notmatch '^10\.10\.(10|11)\.[0-9]+$') { throw 'PS1-DP resolves outside the authorized lab.' }
    Write-Verbose "Verified PS1-DP address $address"
}
$context=New-LabContext $Credential $OutputDirectory
$context.PlacementAffinities=[Collections.Generic.List[object]]::new()
$records=[Collections.Generic.List[object]]::new()
$markers=[Collections.Generic.List[object]]::new()
$recipient='MAYYHEM\domainuser'
$recipientSID=([Security.Principal.NTAccount]::new($recipient)).Translate([Security.Principal.SecurityIdentifier]).Value
$targets=@('PS1-DEV','ps1-dp.mayyhem.com')
$record=[ordered]@{runTag=$context.RunTag;startedUTC=[DateTime]::UtcNow.ToString('o');records=@();cleanupComplete=$false;recipient=$recipient;recipientSID=$recipientSID;selection=$Selection;machinePolicyIsSetupAcceleration=$true}
$activatedSession=$false

function Save-PlacementResults {
    $record.records=@($records.ToArray())
    $record.updatedUTC=[DateTime]::UtcNow.ToString('o')
    $record|ConvertTo-Json -Depth 22|Set-Content -LiteralPath (Join-Path $context.OutputDirectory 'results.json') -Encoding UTF8
}

function Set-PlacementRecipientSession {
    param([ValidateSet('Connect','Disconnect')][string]$Action)
    # The known domainuser session is restored to its original disconnected
    # state at the end. No existing account is signed out or given new rights.
    $line=@(quser domainuser 2>&1|Where-Object {$_ -match '^\s*>?domainuser\s+'})
    if ($line.Count -ne 1 -or $line[0] -notmatch '\s1\s+(Disc|Active)\s') { throw 'Expected the documented domainuser session 1.' }
    $name=$context.RunTag+'-session-'+$Action
    $executable='C:\Windows\System32\tscon.exe';$arguments='1 /dest:console'
    if ($Action -eq 'Disconnect') { $executable='C:\Windows\System32\tsdiscon.exe';$arguments='1' }
    else { Write-Verbose 'Connecting the existing recipient session without a new logon.' }
    try {
        $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount
        $taskAction=New-ScheduledTaskAction -Execute $executable -Argument $arguments
        $null=Register-ScheduledTask -TaskName $name -Principal $principal -Action $taskAction
        Start-ScheduledTask -TaskName $name
        Start-Sleep -Seconds 2
        if ((Get-ScheduledTaskInfo $name).LastTaskResult -ne 0) { throw 'The owned session-state task failed.' }
    }
    finally {
        $task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if ($task) { Unregister-ScheduledTask -TaskName $name -Confirm:$false }
        # A preparation failure may happen before task registration.
    }
    return @(quser)
}

function New-PlacementCase {
    param([string]$Name, [string]$Behavior, [string]$CollectionID)
    $actor=New-UserDeploymentActor $context 1027 1052673 $CollectionID $Name
    $marker=New-PlacementMarker
    $markers.Add($marker)
    $application=New-UserDeploymentApplication $context $actor.Credential ($context.RunTag+' '+$Name) $Behavior $marker
    return @{name=$Name;behavior=$Behavior;actor=$actor;marker=$marker;application=$application}
}

try {
    Save-PlacementState $context
    $record.sessionsBefore=@(quser)
    $existing=@(Get-LabObjects $context.Scope "SELECT ResourceID FROM SMS_R_User WHERE UniqueUserName='mayyhem\\domainuser'")
    if ($existing.Count -ne 1) { throw 'Expected one discovered domainuser recipient.' }
    $userCollection=New-UserDeploymentCollection $context $recipient $existing[0].ResourceID
    $fresh=$null
    if ($Selection -in @('All','Predeployment')) {
        if ($PredeploymentRecipient) {
            if ($PredeploymentRecipient -notmatch '^MAYYHEM\\[a-zA-Z0-9_-]+$') { throw 'The recipient must be a named MAYYHEM lab user.' }
            $fresh=@{Name=$PredeploymentRecipient;Sid=([Security.Principal.NTAccount]::new($PredeploymentRecipient)).Translate([Security.Principal.SecurityIdentifier]).Value}
            Write-Verbose 'Using an existing recipient; its account and credentials remain untouched.'
        }
        else { $fresh=New-LabUser $context }
        $record.freshRecipient=@{name=$fresh.Name;sid=$fresh.Sid;credentialsPassedToClients=$false;preexisting=[bool]$PredeploymentRecipient}
        # Discovery imports the new AD recipient. It does not sign that user in
        # or change the discovery configuration.
        if (-not $PredeploymentRecipient) {
            $null=Invoke-LabConsole $Credential $Credential {Invoke-CMUserDiscovery -SiteCode PS1} @()
            Write-Host 'Requested user discovery for the fresh no-session recipient.'
        }
        else { Write-Verbose 'Existing recipients need no discovery request.' }
    }
    else { Write-Verbose 'No fresh recipient is needed for this selection.' }
    Save-PlacementResults
    if ($Selection -in @('All','Propagation','PrimaryRequirement')) {
        $line=@(quser domainuser 2>&1|Where-Object {$_ -match '^\s*>?domainuser\s+'})
        if ($line.Count -eq 1 -and $line[0] -match '\s1\s+Disc\s') {
            $record.recipientSessionConnected=Set-PlacementRecipientSession Connect
            $activatedSession=$true
        }
        else { Write-Verbose 'The existing recipient session is already active.' }
    }
    else { Write-Verbose 'No existing user session is needed for predeployment.' }

    if ($Selection -in @('All','Propagation')) {
        foreach ($behavior in @('InstallForSystem','InstallForUser')) {
            $case=New-PlacementCase ('two-client-'+$behavior) $behavior $userCollection.CollectionID
            $row=[ordered]@{name=$case.name;actor=$case.actor.Name;behavior=$behavior;application=$case.application;
                requestedMarker=@{nonce=$case.marker.Nonce;path=$case.marker.Path};applicationMask=1027;collectionMask=1052673;phases=@()}
            $records.Add($row)
            $row.assignment=New-UserDeploymentAssignment $context $case.actor.Credential $case.application.Name $userCollection.CollectionID Required
            $first=Wait-Placement $context $case.marker $recipient $recipientSID $case.application.Name @('PS1-DEV') @('PS1-DEV') User $ObservationSeconds
            $row.phases+=@{name='first-computer';result=$first}
            Save-PlacementResults
            if (-not $first.expectedObserved) { throw 'First client did not execute; no second-install conclusion is possible.' }
            $row.secondBeforeRequest=Read-PlacementClient $context 'ps1-dp.mayyhem.com' $case.marker $recipientSID $case.application.Name
            $second=Wait-Placement $context $case.marker $recipient $recipientSID $case.application.Name @('ps1-dp.mayyhem.com') @('PS1-DP') User $ObservationSeconds
            $row.phases+=@{name='second-computer-same-assignment';result=$second}
            if (-not $second.expectedObserved) { throw 'Second client execution was not observed.' }
            # Keep both local detection files present. Re-reading policy should
            # detect the application, not run its installation command repeatedly.
            $repeat=Wait-Placement $context $case.marker $recipient $recipientSID $case.application.Name $targets @() User 65
            $row.phases+=@{name='same-clients-after-success';result=$repeat}
            $row.recipientStates=@(foreach ($target in $targets) {Invoke-PlacementRecipient $context $target $recipient $case.application.Name Inspect})
            Save-PlacementResults
            Write-Host ('Completed two-client comparison: '+$behavior)
        }
    }
    else { Write-Verbose 'Propagation comparisons were not selected.' }

    if ($Selection -in @('All','Predeployment')) {
        $discovered=@()
        for ($attempt=0;$attempt -lt 200;$attempt++) {
            $discovered=@(Get-LabObjects $context.Scope "SELECT ResourceID FROM SMS_R_User WHERE UniqueUserName='$($fresh.Name.Replace('\','\\'))'")
            if ($discovered.Count -eq 1) { break }
            Write-Host 'Waiting for the fresh recipient discovery record.'
            Start-Sleep -Seconds 3
        }
        if ($discovered.Count -ne 1) { throw 'Fresh recipient was not discovered.' }
        # The discovered user must also reach the All Users limiting collection.
        # Finding a discovery record alone does not establish that membership.
        $allUsers=Get-LabObject $context.Scope 'SMS_Collection.CollectionID="SMS00002"'
        $null=$allUsers.InvokeMethod('RequestRefresh',$null,$null)
        $limitingMembership=@()
        for ($attempt=0;$attempt -lt 200;$attempt++) {
            $limitingMembership=@(Get-LabObjects $context.Scope "SELECT ResourceID FROM SMS_FullCollectionMembership WHERE CollectionID='SMS00002' AND ResourceID=$($discovered[0].ResourceID)")
            if ($limitingMembership.Count -eq 1) { break }
            if ($attempt % 10 -eq 9) {
                # Discovery can finish after the first evaluation has started.
                # Request another evaluation instead of waiting on a stale list.
                $null=$allUsers.InvokeMethod('RequestRefresh',$null,$null)
                Write-Verbose 'Requested another All Users evaluation after discovery.'
            }
            # Other attempts allow the requested evaluation time to complete.
            Write-Host 'Waiting for the fresh recipient to enter All Users.'
            Start-Sleep -Seconds 3
        }
        if ($limitingMembership.Count -ne 1) { throw 'Fresh recipient did not enter its limiting collection.' }
        $collection=New-UserDeploymentCollection $context $fresh.Name $discovered[0].ResourceID
        $case=New-PlacementCase 'no-session-predeployment' InstallForSystem $collection.CollectionID
        $row=[ordered]@{name=$case.name;actor=$case.actor.Name;behavior='InstallForSystem';recipient=$fresh.Name;recipientSID=$fresh.Sid;
            application=$case.application;requestedMarker=@{nonce=$case.marker.Nonce;path=$case.marker.Path};applicationMask=1027;collectionMask=1052673;phases=@()}
        $records.Add($row)
        $row.before=@(foreach ($target in $targets) {Read-PlacementClient $context $target $case.marker $fresh.Sid $case.application.Name})
        if (@($row.before|Where-Object recipientProfilePresent).Count) { throw 'The no-session recipient unexpectedly has a client profile.' }
        $row.firstPrimary=Set-PlacementAffinity $context $fresh.Name 16777228
        $row.assignment=New-UserDeploymentAssignment $context $case.actor.Credential $case.application.Name $collection.CollectionID Required -300 $false
        $disabled=Get-LabObject $context.Scope ('SMS_ApplicationAssignment.AssignmentID='+$row.assignment.ID)
        $row.initialOfferFlags=[uint32]$disabled.OfferFlags
        if (($row.initialOfferFlags -band 1) -ne 0) { throw 'The predeployment-disabled control unexpectedly has PREDEPLOY set.' }
        # OfferFlags bit 1 is PREDEPLOY. The provider has no PreDeploy property;
        # PreDeploy is the console command's parameter name only.
        $control=Wait-Placement $context $case.marker $fresh.Name $fresh.Sid $case.application.Name $targets @() Machine 90
        $row.phases+=@{name='predeployment-disabled-no-session';result=$control}
        Save-PlacementResults
        $null=Invoke-LabConsole $Credential $case.actor.Credential {
            param($name,$collection)
            Set-CMApplicationDeployment -ApplicationName $name -CollectionId $collection -PreDeploy $true
        } @($case.application.Name,$collection.CollectionID)
        $saved=Get-LabObject $context.Scope ('SMS_ApplicationAssignment.AssignmentID='+$row.assignment.ID)
        $row.savedOfferFlags=[uint32]$saved.OfferFlags
        $row.savedPreDeploy=($row.savedOfferFlags -band 1) -ne 0
        if (-not $row.savedPreDeploy) { throw 'The saved assignment does not enable predeployment.' }
        Write-Verbose 'The provider confirmed predeployment is enabled.'
        $row.predeploymentEnabledUTC=[DateTime]::UtcNow.ToString('o')
        Save-PlacementResults
        $first=Wait-Placement $context $case.marker $fresh.Name $fresh.Sid $case.application.Name $targets @('PS1-DP') Machine $ObservationSeconds
        $row.phases+=@{name='first-primary-no-session';result=$first}
        Save-PlacementResults
        if (-not $first.expectedObserved) { throw 'No-session primary predeployment was not observed.' }
        $row.secondPrimary=Set-PlacementAffinity $context $fresh.Name 16777230
        $row.secondPrimaryAddedUTC=[DateTime]::UtcNow.ToString('o')
        $second=Wait-Placement $context $case.marker $fresh.Name $fresh.Sid $case.application.Name $targets @('PS1-DEV') Machine $ObservationSeconds
        $row.phases+=@{name='second-primary-same-assignment-no-session';result=$second}
        Save-PlacementResults
        if (-not $second.expectedObserved) { throw 'Second primary execution was not observed.' }
    }
    else { Write-Verbose 'No-session predeployment was not selected.' }

    if ($Selection -in @('All','PrimaryRequirement')) {
        $case=New-PlacementCase 'primary-requirement' InstallForSystem $userCollection.CollectionID
        $row=[ordered]@{name=$case.name;actor=$case.actor.Name;application=$case.application;behavior='InstallForSystem';
            requestedMarker=@{nonce=$case.marker.Nonce;path=$case.marker.Path};applicationMask=1027;collectionMask=1052673;phases=@()}
        $records.Add($row)
        $row.primaryRequirement=Set-PlacementPrimaryRequirement $context $case.application.Name
        $row.firstPrimary=Set-PlacementAffinity $context $recipient 16777228
        $row.assignment=New-UserDeploymentAssignment $context $case.actor.Credential $case.application.Name $userCollection.CollectionID Required
        $row.savedDefinition=Get-UserDeploymentDefinition $context $case.application.Name
        $row.affinityPolicyAcceleration=@(foreach ($target in $targets) {Request-PlacementPolicy $context $target $recipient $case.application.Name Machine})
        $first=Wait-Placement $context $case.marker $recipient $recipientSID $case.application.Name $targets @('PS1-DP') User $ObservationSeconds
        $row.phases+=@{name='only-primary-computer';result=$first}
        $row.nonprimaryState=Invoke-PlacementRecipient $context 'PS1-DEV' $recipient $case.application.Name Inspect
        Save-PlacementResults
        if (-not $first.expectedObserved) { throw 'Primary requirement positive control did not execute.' }
        $row.secondPrimary=Set-PlacementAffinity $context $recipient 16777230
        $row.secondPrimaryAddedUTC=[DateTime]::UtcNow.ToString('o')
        $row.updatedAffinityPolicyAcceleration=@(foreach ($target in $targets) {Request-PlacementPolicy $context $target $recipient $case.application.Name Machine})
        $second=Wait-Placement $context $case.marker $recipient $recipientSID $case.application.Name $targets @('PS1-DEV') User $ObservationSeconds
        $row.phases+=@{name='new-primary-same-assignment';result=$second}
        Save-PlacementResults
        if (-not $second.expectedObserved) { throw 'Changed primary eligibility did not produce execution.' }
    }
    else { Write-Verbose 'Primary requirement comparison was not selected.' }
}
catch {
    $record.error=Get-LabError $_
    Write-Warning ($record.error|ConvertTo-Json -Compress)
    throw
}
finally {
    try { Remove-PlacementAffinities $context }
    finally {
        try { Remove-LabResources $context }
        finally {
            foreach ($target in $targets) {
                foreach ($marker in $markers) {
                    Invoke-LabDevice -Credential $Credential -ComputerName $target -ArgumentList $marker.Path -ScriptBlock {
                        param($path)
                        if ($path -notmatch '^C:\\Windows\\Temp\\cup-[a-f0-9]{32}\.jsonl$') { throw 'Invalid owned marker path.' }
                        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                        # A negative control creates no marker file.
                    }
                }
            }
            if ($activatedSession) { $record.restoredRecipientSession=Set-PlacementRecipientSession Disconnect }
            else { Write-Verbose 'Original recipient session state did not need restoration.' }
            $record.cleanupComplete=$context.Resources.Count -eq 0 -and $context.PlacementAffinities.Count -eq 0
            $record.finishedUTC=[DateTime]::UtcNow.ToString('o')
            Save-PlacementResults
        }
    }
}
