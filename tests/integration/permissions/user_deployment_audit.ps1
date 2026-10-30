<#
.SYNOPSIS
Verify cleanup after the user/device deployment experiments.
.DESCRIPTION
Reads ownership journals and results from one investigation directory. Removes
only matching discovered test users, client requests, markers, and observer tasks.
It does not reset client policy or change original roles/accounts. Run only after
every experiment has finished. Native SCCM audit and installation history remain.
.PARAMETER Credential
Administrator of the documented mayyhem.com research lab.
.PARAMETER OutputDirectory
Investigation root containing the experiment subdirectories and their journals.
.EXAMPLE
.\tests\integration\permissions\user_deployment_audit.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-user-deployments"
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][pscredential]$Credential,
      [Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'PS1-DEV') { throw 'Run this client audit only on PS1-DEV.' }
Write-Verbose 'Auditing the documented local research client.'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
. (Join-Path $PSScriptRoot 'user_deployment_helpers.ps1')
foreach ($name in @('dc.mayyhem.com','ps1-sms.mayyhem.com')) {
    foreach ($address in [Net.Dns]::GetHostAddresses($name)) {
        if ($address.ToString() -notmatch '^10\.10\.(10|11)\.[0-9]+$') { throw 'Audit target resolves outside the authorized lab.' }
        Write-Verbose "Verified $name / $address"
    }
}
$journals=@(Get-ChildItem -LiteralPath $OutputDirectory -Filter cleanup-journal.json -Recurse |
    ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json})
if (-not $journals.Count) { throw 'No ownership journals were found.' }
Write-Verbose "Found $($journals.Count) experiment journals."
if (@($journals | Where-Object {@($_.resources).Count}).Count) { throw 'An experiment is still active or its cleanup is unfinished.' }
Write-Verbose 'Every experiment journal is empty.'
$tags=@($journals.runTag | Sort-Object -Unique)
foreach ($tag in $tags) {
    if ($tag -notmatch '^CMBP-PERM-[a-f0-9]{8}$') { throw 'Unexpected investigation ownership tag.' }
    Write-Verbose "Verified ownership tag $tag"
}
$prefixes=@($tags | ForEach-Object {'cpr'+$_.Substring(10)})
$models=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$nonces=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$clientProcesses=[Collections.Generic.HashSet[int]]::new()
foreach ($file in @(Get-ChildItem -LiteralPath $OutputDirectory -Filter results.json -Recurse)) {
    $result=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    foreach ($record in @($result.records)) {
        if ($record.application.UniqueID) { $null=$models.Add(($record.application.UniqueID -replace '/[0-9]+$','')) }
        # Permission-only cases do not have executable application models.
        if ($record.requestedMarker.nonce -match '^[a-f0-9]{32}$') { $null=$nonces.Add($record.requestedMarker.nonce) }
        # A rejected preparation may not have reached marker creation.
        if ($record.recipientInstall.softwareCenterProcess) { $null=$clientProcesses.Add([int]$record.recipientInstall.softwareCenterProcess) }
        # Required deployments never open Software Center.
    }
}
foreach ($file in @(Get-ChildItem -LiteralPath $OutputDirectory -Filter software-center-activation.json -Recurse)) {
    $record=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if ($record.softwareCenterProcess) { $null=$clientProcesses.Add([int]$record.softwareCenterProcess) }
    # An unsuccessful launch has no process ID to close.
}
function Test-InvestigationName([string]$Name) {
    foreach ($tag in $tags) {
        if ($Name.IndexOf($tag,[StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        # A name may belong to another investigation or an original lab object.
    }
    return $false
}
function Test-InvestigationAccount([string]$Name) {
    $account=($Name -split '\\')[-1]
    foreach ($prefix in $prefixes) {
        if ($account.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { return $true }
        # Other accounts are outside this cleanup's ownership.
    }
    return $false
}
$scope=New-LabScope $Credential
$counts=[ordered]@{}
foreach ($definition in @(@('roles','SMS_Role','RoleName'),@('collections','SMS_Collection','Name'),
    @('applications','SMS_ApplicationLatest','LocalizedDisplayName'),@('assignments','SMS_ApplicationAssignment','AssignmentName'))) {
    $objects=@(Get-LabObjects $scope ('SELECT * FROM '+$definition[1]))
    $counts[$definition[0]]=@($objects | Where-Object {Test-InvestigationName $_[$definition[2]]}).Count
}
$counts.administrators=@(Get-LabObjects $scope 'SELECT * FROM SMS_Admin' | Where-Object {Test-InvestigationAccount $_.LogonName}).Count
$removedDiscovery=@()
foreach ($user in @(Get-LabObjects $scope 'SELECT * FROM SMS_R_User' | Where-Object {Test-InvestigationAccount $_.UniqueUserName})) {
    $removedDiscovery+=@{name=$user.UniqueUserName;resourceID=$user.ResourceID}
    $user.Delete()
    Write-Verbose 'Removed an automatically discovered copy of a temporary test account.'
}
$counts.discoveredUsers=@(Get-LabObjects $scope 'SELECT * FROM SMS_R_User' | Where-Object {Test-InvestigationAccount $_.UniqueUserName}).Count
$directory=[DirectoryServices.DirectoryEntry]::new('LDAP://dc.mayyhem.com/CN=Users,DC=mayyhem,DC=com',$Credential.UserName,$Credential.GetNetworkCredential().Password)
try {
    $search=[DirectoryServices.DirectorySearcher]::new($directory)
    $search.Filter='(|'+(($prefixes | ForEach-Object {'(sAMAccountName='+$_+'*)'}) -join '')+')'
    $found=$search.FindAll()
    try { $counts.domainAccounts=$found.Count } finally { $found.Dispose() }
}
finally { $search.Dispose();$directory.Dispose() }
$removedRequests=@()
foreach ($request in @(Get-WmiObject -Namespace root\ccm\ClientSDK -Class CCM_RequestedAppPolicy | Where-Object {$models.Contains($_.AppId)})) {
    $removedRequests+=@{application=$request.AppId;policy=$request.PolicyId}
    $request.Delete()
}
$recipientContext=@{RunTag=$tags[0]}
$withdrawal=@(
    Invoke-UserDeploymentRecipient $recipientContext 'MAYYHEM\domainuser' '' Retrieve
    Invoke-UserDeploymentRecipient $recipientContext 'MAYYHEM\domainuser' '' RetrieveMachine
)
foreach ($request in $withdrawal) {
    if ($request.error) { throw "Policy withdrawal request failed: $($request.error)" }
    Write-Verbose 'Requested normal policy retrieval after deleting the test deployments.'
}
$userNamespace='root\ccm\Policy\S_1_5_21_2685035784_114219579_2457378813_1104\ActualConfig'
$remainingPolicies=@()
for ($attempt=0;$attempt -lt 20;$attempt++) {
    $remainingPolicies=@()
    foreach ($namespace in @('root\ccm\Policy\Machine\ActualConfig',$userNamespace)) {
        $remainingPolicies+=@(Get-WmiObject -Namespace $namespace -Class CCM_ApplicationCIAssignment |
            Where-Object {Test-InvestigationName $_.AssignmentName})
    }
    if (-not $remainingPolicies.Count) { break }
    Write-Host 'Waiting for the investigation deployment policies to be withdrawn.'
    Start-Sleep -Seconds 6
}
$removedFiles=@()
foreach ($file in @(Get-ChildItem -LiteralPath 'C:\Windows\Temp' -File)) {
    $isOwnedMarker=$file.Name -match '^cud-([a-f0-9]{32})\.json$' -and $nonces.Contains($Matches[1])
    $isOwnedObserver=(Test-InvestigationName $file.Name) -and $file.Name -match '-recipient-[a-f0-9]{8}\.json$'
    if ($isOwnedMarker -or $isOwnedObserver) {
        $resolved=[IO.Path]::GetFullPath($file.FullName)
        if ($resolved -notmatch '^C:\\Windows\\Temp\\[^\\]+$') { throw 'Unexpected observer/marker cleanup path.' }
        Remove-Item -LiteralPath $resolved
        $removedFiles+=$file.Name
    }
    # Other temporary files belong to Windows, earlier work, or another account.
}
$removedTasks=@()
foreach ($task in @(Get-ScheduledTask | Where-Object {Test-InvestigationName $_.TaskName})) {
    if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $task.TaskName;Write-Warning 'Stopped an unfinished owned observer task.' }
    # Completed observer tasks need only unregistering.
    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
    $removedTasks+=$task.TaskName
}
$closedProcesses=@()
foreach ($processID in $clientProcesses) {
    $process=Get-Process -Id $processID -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -eq 'SCClient' -and $process.SessionId -eq 1) {
        try { $process.Kill();$null=$process.WaitForExit(5000) }
        catch {
            if (-not $process.HasExited) { throw }
            Write-Verbose 'The owned single-instance Software Center launcher exited during cleanup.'
        }
        $closedProcesses+=$processID
    }
    # Software Center's single-instance launcher may have already exited.
}
$baseline=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\builtin-role-permissions.json') -Raw | ConvertFrom-Json
$rolesUnchanged=$true
foreach ($role in $baseline) {
    $current=Get-LabObject $scope ('SMS_Role.RoleID="'+$role.RoleID+'"')
    $before=@($role.Operations | ForEach-Object {"$($_.ObjectTypeID):$($_.GrantedOperations)"} | Sort-Object)
    $after=@($current.Operations | ForEach-Object {"$($_.ObjectTypeID):$($_.GrantedOperations)"} | Sort-Object)
    if ($current.RoleName -ne $role.RoleName -or @(Compare-Object $before $after).Count) { $rolesUnchanged=$false;Write-Warning "Original role differs: $($role.RoleID)" }
    # Matching roles need no per-role operational message.
}
$remainingRequests=@(Get-WmiObject -Namespace root\ccm\ClientSDK -Class CCM_RequestedAppPolicy | Where-Object {$models.Contains($_.AppId)}).Count
$audit=@{timestampUTC=[DateTime]::UtcNow.ToString('o');tags=$tags;remainingObjects=$counts;
    remainingClientPolicies=$remainingPolicies.Count;remainingClientRequests=$remainingRequests;
    remainingMarkers=@(Get-ChildItem -LiteralPath 'C:\Windows\Temp' -Filter 'cud-*.json' | Where-Object {$nonces.Contains($_.BaseName.Substring(4))}).Count;
    removedDiscoveredUsers=$removedDiscovery;removedRequests=$removedRequests;removedFiles=$removedFiles;removedTasks=$removedTasks;
    closedSoftwareCenterProcesses=$closedProcesses;originalRoleCount=$baseline.Count;originalRolesUnchanged=$rolesUnchanged;
    policyWithdrawal=$withdrawal;sessions=@(quser)}
$audit | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'cleanup-final.json') -Encoding UTF8
[pscustomobject]$audit | Select-Object timestampUTC,remainingObjects,remainingClientPolicies,remainingClientRequests,remainingMarkers,originalRoleCount,originalRolesUnchanged,sessions | ConvertTo-Json -Depth 4
if (@($counts.Values | Where-Object {$_ -ne 0}).Count -or $remainingPolicies.Count -or $remainingRequests -or $audit.remainingMarkers -or -not $rolesUnchanged) { throw 'Independent audit found unfinished cleanup or changed original roles.' }
Write-Host 'Independent investigation cleanup audit passed.'
