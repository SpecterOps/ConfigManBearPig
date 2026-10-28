<#
.SYNOPSIS
Test an execution mechanism after an SCCM deployment has already succeeded.
.DESCRIPTION
Setup creates a harmless original deployment and waits for confirmed success.
After that boundary, the setup account only observes. The restricted account
changes code and requests any chosen notification or reschedule. A second marker
is required to prove that the changed code ran. All resources are removed.
.PARAMETER Credential
Lab administrator for setup, read-only observation, and cleanup.
.PARAMETER OutputDirectory
Dedicated result and cleanup-journal folder. Never contains passwords.
.PARAMETER Workload
Application, Package, TaskSequence, or ConfigurationItem.
.PARAMETER Profile
Modify has object Read/Modify and collection Read/Read Resource. ModifyNotify
adds Notify Resource. ModifyDeployNotify also adds the matching Deploy action.
ReadNotify is the control with no object Modify.
.PARAMETER Mechanism
Observe waits without notifications. Notify requests actions as the restricted
account. Reschedule changes the existing deployment, then requests policy.
.PARAMETER ApplicationChange
Change the installation command, or replace detection with a harmless script.
.PARAMETER Target
PS1-DEV or the separate passive-observation client PS1-DP in the authorized lab.
.PARAMETER ObservationSeconds
How long to watch after modification. The actual elapsed time is recorded.
.PARAMETER RefreshBaselineDefinition
After changing discovery code, also revise its parent baseline using the same
restricted account. This tests a fresh baseline evaluation without a new deployment.
.PARAMETER RecurringDeployment
Establish a repeating two-minute package or task-sequence deployment before the
original successful run. The restricted editor does not change its schedule.
.EXAMPLE
.\tests\integration\permissions\execution_triggers.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-trigger-app" -Workload Application -Profile ModifyNotify -Mechanism Notify -ApplicationChange DetectionScript
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][pscredential]$Credential,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [ValidateSet('Application','Package','TaskSequence','ConfigurationItem')][string]$Workload='Application',
    [ValidateSet('Modify','ModifyNotify','ModifyDeployNotify','ReadNotify')][string]$Profile='Modify',
    [ValidateSet('Observe','Notify','Reschedule')][string]$Mechanism='Observe',
    [ValidateSet('InstallCommand','DetectionScript')][string]$ApplicationChange='InstallCommand',
    [ValidateSet('PS1-DEV','PS1-DP')][string]$Target='PS1-DEV',
    [ValidateRange(30,10800)][int]$ObservationSeconds=180,
    [switch]$RefreshBaselineDefinition,
    [switch]$RecurringDeployment
)
$ErrorActionPreference='Stop'
if($RecurringDeployment -and $Workload -notin @('Package','TaskSequence')) {
    throw 'RecurringDeployment applies only to Package and TaskSequence.'
}
# Other workloads use their own evaluation mechanisms.
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
. (Join-Path $PSScriptRoot 'execution_helpers.ps1')
$context=New-LabContext $Credential $OutputDirectory
$record=[ordered]@{ workload=$Workload;profile=$Profile;mechanism=$Mechanism;applicationChange=$ApplicationChange;target=$Target;initialSuccess=$false;modified=$false;secondMarker=$null;verified=$false;notifications=@();privilegedClientActionsAfterModification=0;refreshBaselineDefinition=[bool]$RefreshBaselineDefinition;recurringDeployment=[bool]$RecurringDeployment }
$initial=New-ExecutionMarker $Workload
$changed=New-ExecutionMarker $Workload
$record.requestedMarker=@{nonce=$changed.Nonce;path=$changed.Path}
try {
    if($Target -eq 'PS1-DP') {
        foreach($address in [Net.Dns]::GetHostAddresses('ps1-dp.mayyhem.com')) {
            if($address.ToString() -notmatch '^10\.10\.(10|11)\.[0-9]+$') { throw 'Passive client resolves outside the authorized subnets.' }
            Write-Verbose "Verified passive test address $address"
        }
    }
    $resourceID=[uint32]16777230
    if($Target -eq 'PS1-DP') { $resourceID=[uint32]16777228 }
    $record.resourceID=$resourceID
    $collection=New-LabCollection $context ('completed '+$Workload+' '+$Target)
    Add-LabCollectionDevice $context $collection $resourceID
    $record.collectionID=$collection.CollectionID
    $objectType=31; $deployPermission=1048576
    if($Workload -eq 'Package') { $objectType=2; $deployPermission=16384 }
    elseif($Workload -eq 'TaskSequence') { $objectType=20; $deployPermission=8388608 }
    elseif($Workload -eq 'ConfigurationItem') { $objectType=11; $deployPermission=4194304 }
    $objectMask=3
    if($Profile -eq 'ReadNotify') { $objectMask=1 }
    $collectionMask=4097
    if($Profile -ne 'Modify') { $collectionMask=$collectionMask -bor 536870912 }
    if($Profile -eq 'ModifyDeployNotify') { $collectionMask=$collectionMask -bor $deployPermission }
    $record.objectType=$objectType; $record.objectMask=$objectMask; $record.collectionMask=$collectionMask
    $actor=New-LabUser $context
    $role=New-LabRole $context @(
        @{ObjectTypeID=$objectType;GrantedOperations=$objectMask},
        @{ObjectTypeID=1;GrantedOperations=$collectionMask},
        @{ObjectTypeID=6;GrantedOperations=1}
    ) ('completed trigger '+$Profile)
    $null=New-LabAdmin $context $actor @(@{Role=$role.RoleID;Collections=@($collection.CollectionID);Scopes=@('SMS00ALL')})
    $record.actor=$actor.Name
    $item=New-ExecutionWorkload $context $Workload $collection $initial ([bool]$RecurringDeployment)
    $record.item=$item
    $record.original=Wait-InitialExecution $context $Target $item $initial
    $record.initialSuccess=$true
    Write-Host ('Initial deployment SUCCESS confirmed: '+($record.original.state | ConvertTo-Json -Compress))
    # Once the original run has finished, no helper may force actions locally.
    $record.attackStartedUTC=[DateTime]::UtcNow.ToString('o')
    try {
        Set-ExecutionCode $context $actor $item $changed $ApplicationChange
        $record.modified=$true
        $record.modifiedUTC=[DateTime]::UtcNow.ToString('o')
        if($RefreshBaselineDefinition) {
            if($Workload -ne 'ConfigurationItem') { throw 'Refreshing a baseline applies only to ConfigurationItem.' }
            $null=Invoke-LabConsole $Credential $actor.Credential {
                param($id,$nonce)
                Set-CMBaseline -Id $id -Description ('Restricted-account revision '+$nonce)
            } @($item.BaselineID,$changed.Nonce)
            $record.baselineRevised=$true
        }
        if($Mechanism -eq 'Reschedule') {
            Set-ExecutionReschedule $context $actor $item $collection.CollectionID
            $record.rescheduled=$true
        }
        $actorScope=New-LabScope $actor.Credential
        $watch=[Diagnostics.Stopwatch]::StartNew()
        $iteration=0
        while($watch.Elapsed.TotalSeconds -lt $ObservationSeconds) {
            $observed=Read-ExecutionMarker $Credential $Target $changed
            if($observed.nonce -eq $changed.Nonce -and $observed.sid -eq 'S-1-5-18') {
                $record.secondMarker=$observed
                $record.observedUTC=[DateTime]::UtcNow.ToString('o')
                $record.verified=$true
                break
            }
            if($Mechanism -ne 'Observe' -and $iteration % 10 -eq 0) {
                $record.notifications += Request-ExecutionNotification $actorScope $collection.CollectionID $resourceID 8
                if($Workload -eq 'Application') { $record.notifications += Request-ExecutionNotification $actorScope $collection.CollectionID $resourceID 13 }
                elseif($Workload -eq 'ConfigurationItem') { $record.notifications += Request-ExecutionNotification $actorScope $collection.CollectionID $resourceID 125 }
            }
            if($iteration % 10 -eq 0) {
                $state=Read-ExecutionState $Credential $Target $item
                Write-Host ("Post-success observation $([int]$watch.Elapsed.TotalSeconds)s: "+($state | ConvertTo-Json -Compress))
            }
            $iteration++
            Start-Sleep -Seconds 3
        }
        $record.observationSeconds=[math]::Round($watch.Elapsed.TotalSeconds,2)
        $record.finalState=Read-ExecutionState $Credential $Target $item
        if($Workload -in @('Package','TaskSequence')) {
            $record.clientDeployment=Invoke-LabDevice -Credential $Credential -ComputerName $Target -ArgumentList $item.ID -ScriptBlock {
                param($id)
                $rows=@(Get-WmiObject -Namespace root\ccm\Policy\Machine\ActualConfig -Class CCM_SoftwareDistribution | Where-Object PKG_PackageID -eq $id)
                foreach($row in $rows) {
                    $values=@{}
                    foreach($property in $row.Properties) {
                        if($property.Name -match '^(ADV|PRG|PKG)_') { $values[$property.Name]=$property.Value }
                        # Other WMI properties do not describe this deployment.
                    }
                    $values
                }
            }
        }
        if($record.verified) { Write-Host 'Changed code executed as SYSTEM after the original deployment had succeeded.' }
        else { Write-Warning 'Changed code did not execute within the recorded observation window.' }
    }
    catch {
        $record.actionError=Get-LabError $_
        Write-Warning ($record.actionError | ConvertTo-Json -Compress)
    }
}
catch {
    $record.setupError=Get-LabError $_
    Write-Warning ($record.setupError | ConvertTo-Json -Compress)
    throw
}
finally {
    try { Remove-LabResources $context }
    finally {
        foreach($marker in @($initial,$changed)) {
            Invoke-LabDevice -Credential $Credential -ComputerName $Target -ArgumentList $marker.Path -ScriptBlock {
                param($path)
                if($path -notmatch '^C:\\ProgramData\\CMBP-PermissionResearch\\[a-f0-9]{32}\.json$' -and $path -notmatch '^C:\\Windows\\Temp\\cmbp-[a-f0-9]{16}\.txt$') { throw 'Invalid experiment marker path' }
                if(Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                # A rejected or delayed action may not have created a second file.
            }
        }
        $record.cleanupComplete=$context.Resources.Count -eq 0
        $record | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
    }
}
