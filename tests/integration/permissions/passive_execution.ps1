<#
.SYNOPSIS
Observe ordinary SCCM execution after Modify-only changes, without client triggers.
.DESCRIPTION
Prepares a successfully installed app and a compliant recurring baseline on the
separate PS1-DP lab client. Both initial runs must finish before either is changed.
The restricted account then changes application detection and CI discovery code.
After that point the setup account only reads markers and client state.
.PARAMETER Credential
Administrator for initial preparation, read-only observation, and cleanup.
.PARAMETER OutputDirectory
Dedicated folder for the result, live checkpoint, and cleanup journal.
.PARAMETER ObservationSeconds
Maximum passive observation window. The default covers a normal hourly policy cycle.
.EXAMPLE
.\tests\integration\permissions\passive_execution.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-passive-execution"
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][pscredential]$Credential,
      [Parameter(Mandatory=$true)][string]$OutputDirectory,
      [ValidateRange(60,10800)][int]$ObservationSeconds=4500)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
. (Join-Path $PSScriptRoot 'execution_helpers.ps1')
$context=New-LabContext $Credential $OutputDirectory
$target='ps1-dp.mayyhem.com'
$rows=[Collections.Generic.List[object]]::new()
$record=[ordered]@{target='PS1-DP';notifications=@();privilegedClientActionsAfterModification=0;initialSuccess=$false;experiments=@();cleanupComplete=$false}
try {
    foreach($address in [Net.Dns]::GetHostAddresses($target)) {
        if($address.ToString() -notmatch '^10\.10\.(10|11)\.[0-9]+$') { throw 'Passive test target is outside the authorized lab.' }
        Write-Verbose "Verified passive address $address"
    }
    $collection=New-LabCollection $context 'passive completed objects PS1-DP'
    Add-LabCollectionDevice $context $collection 16777228
    $actor=New-LabUser $context
    $role=New-LabRole $context @(
        @{ObjectTypeID=31;GrantedOperations=3},@{ObjectTypeID=11;GrantedOperations=3},
        @{ObjectTypeID=6;GrantedOperations=1},@{ObjectTypeID=1;GrantedOperations=4097}
    ) 'Modify only with no notification permission'
    $null=New-LabAdmin $context $actor @(@{Role=$role.RoleID;Collections=@($collection.CollectionID);Scopes=@('SMS00ALL')})
    $record.actor=$actor.Name
    $record.collectionMask=4097
    foreach($workload in @('Application','ConfigurationItem')) {
        $initial=New-ExecutionMarker $workload
        $changed=New-ExecutionMarker $workload
        $row=@{workload=$workload;initialMarker=$initial;changedMarker=$changed;verified=$false;secondMarker=$null}
        $rows.Add($row)
        $row.item=New-ExecutionWorkload $context $workload $collection $initial
        $row.original=Wait-InitialExecution $context $target $row.item $initial
        Write-Host "$workload original run completed before passive modification."
    }
    $record.initialSuccess=$true
    $record.lastPrivilegedClientActionBeforeModificationUTC=[DateTime]::UtcNow.ToString('o')
    foreach($row in $rows) {
        Set-ExecutionCode $context $actor $row.item $row.changedMarker 'DetectionScript'
        $row.modifiedUTC=[DateTime]::UtcNow.ToString('o')
    }
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $iteration=0
    while($watch.Elapsed.TotalSeconds -lt $ObservationSeconds) {
        foreach($row in $rows) {
            if($row.verified) { continue }
            $observed=Read-ExecutionMarker $Credential $target $row.changedMarker
            if($observed.nonce -eq $row.changedMarker.Nonce -and $observed.sid -eq 'S-1-5-18') {
                $row.verified=$true; $row.secondMarker=$observed
                $row.observedUTC=[DateTime]::UtcNow.ToString('o')
                # Parse offsets explicitly: DateTime.Parse converts a UTC timestamp
                # to local time, which would add the observer's time-zone offset.
                $row.elapsedSinceModificationSeconds=[math]::Round(([DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($row.modifiedUTC)).TotalSeconds,2)
                Write-Host ("PASSIVE SYSTEM execution: "+$row.workload+' after '+$row.elapsedSinceModificationSeconds+' seconds')
            }
            if($iteration % 6 -eq 0) {
                $row.latestState=Read-ExecutionState $Credential $target $row.item
                Write-Host ("Passive $($row.workload) $([int]$watch.Elapsed.TotalSeconds)s: "+($row.latestState | ConvertTo-Json -Compress))
            }
        }
        $record.experiments=@($rows.ToArray())
        $record.elapsedSeconds=[math]::Round($watch.Elapsed.TotalSeconds,2)
        $record | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'checkpoint.json') -Encoding UTF8
        if(@($rows | Where-Object {-not $_.verified}).Count -eq 0) { break }
        $iteration++
        Start-Sleep -Seconds 5
    }
}
catch {
    $record.error=Get-LabError $_
    Write-Warning ($record.error | ConvertTo-Json -Compress)
    throw
}
finally {
    try { Remove-LabResources $context }
    finally {
        foreach($row in $rows) {
            foreach($marker in @($row.initialMarker,$row.changedMarker)) {
                Invoke-LabDevice -Credential $Credential -ComputerName $target -ArgumentList $marker.Path -ScriptBlock {
                    param($path)
                    if($path -notmatch '^C:\\ProgramData\\CMBP-PermissionResearch\\[a-f0-9]{32}\.json$') { throw 'Invalid passive marker cleanup path' }
                    if(Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                    # An unexecuted candidate does not create its second marker.
                }
            }
        }
        $record.experiments=@($rows.ToArray())
        $record.cleanupComplete=$context.Resources.Count -eq 0
        $record | ConvertTo-Json -Depth 18 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
    }
}
