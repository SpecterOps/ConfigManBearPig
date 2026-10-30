<#
.SYNOPSIS
Independently verify cleanup of the user-placement experiments.
.DESCRIPTION
Run after all experiments finish. Reads their ownership journals, removes only
matching discovery records and markers, withdraws deleted test policies, checks
original primary associations and roles, and preserves original user sessions.
.PARAMETER Credential
Administrator of the authorized mayyhem.com research lab.
.PARAMETER OutputDirectory
Investigation root containing the experiment subdirectories and baseline files.
.EXAMPLE
.\tests\integration\permissions\user_placement_audit.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-user-placement"
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][pscredential]$Credential,
      [Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
. (Join-Path $PSScriptRoot 'user_deployment_helpers.ps1')
$scope=New-LabScope $Credential
$journals=@(Get-ChildItem -LiteralPath $OutputDirectory -Filter cleanup-journal.json -Recurse | ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw|ConvertFrom-Json})
if (-not $journals.Count) { throw 'No ownership journals were found.' }
if (@($journals|Where-Object {@($_.resources).Count}).Count) { throw 'An experiment has unfinished cleanup.' }
Write-Verbose 'Every provider/AD ownership journal is empty.'
foreach ($file in @(Get-ChildItem -LiteralPath $OutputDirectory -Filter placement-affinities.json -Recurse)) {
    $journal=Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json
    if (@($journal.affinities).Count) { throw 'Owned primary associations remain in a journal.' }
    Write-Verbose 'The association ownership journal is empty.'
}
$tags=@($journals.runTag|Sort-Object -Unique)
foreach ($tag in $tags) { if ($tag -notmatch '^CMBP-PERM-[a-f0-9]{8}$') { throw 'Unexpected ownership tag.' } }
$prefixes=@($tags|ForEach-Object {'cpr'+$_.Substring(10)})
function Test-PlacementOwnedName([string]$Name) {
    foreach ($tag in $tags) { if ($Name.IndexOf($tag,[StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
    return $false # Other research and original objects are outside this audit.
}
function Test-PlacementOwnedUser([string]$Name) {
    $sam=($Name -split '\\')[-1]
    foreach ($prefix in $prefixes) { if ($sam.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false # Never remove an original user or another investigation's user.
}
$counts=[ordered]@{}
foreach ($definition in @(@('roles','SMS_Role','RoleName'),@('collections','SMS_Collection','Name'),
    @('applications','SMS_ApplicationLatest','LocalizedDisplayName'),@('assignments','SMS_ApplicationAssignment','AssignmentName'))) {
    $counts[$definition[0]]=@(Get-LabObjects $scope ('SELECT * FROM '+$definition[1])|Where-Object {Test-PlacementOwnedName $_[$definition[2]]}).Count
}
$counts.administrators=@(Get-LabObjects $scope 'SELECT * FROM SMS_Admin'|Where-Object {Test-PlacementOwnedUser $_.LogonName}).Count
$counts.freshUserAffinities=@(Get-LabObjects $scope 'SELECT * FROM SMS_UserMachineRelationship'|Where-Object {Test-PlacementOwnedUser $_.UniqueUserName}).Count
$removedDiscovery=@()
foreach ($user in @(Get-LabObjects $scope 'SELECT * FROM SMS_R_User'|Where-Object {Test-PlacementOwnedUser $_.UniqueUserName})) {
    $removedDiscovery+=@{name=$user.UniqueUserName;resourceID=$user.ResourceID}
    $user.Delete()
    Write-Verbose 'Removed an automatically discovered owned recipient/actor.'
}
$counts.discoveredUsers=@(Get-LabObjects $scope 'SELECT * FROM SMS_R_User'|Where-Object {Test-PlacementOwnedUser $_.UniqueUserName}).Count
$directory=[DirectoryServices.DirectoryEntry]::new('LDAP://dc.mayyhem.com/CN=Users,DC=mayyhem,DC=com',$Credential.UserName,$Credential.GetNetworkCredential().Password)
try {
    $search=[DirectoryServices.DirectorySearcher]::new($directory)
    $search.Filter='(|'+(($prefixes|ForEach-Object {'(sAMAccountName='+$_+'*)'}) -join '')+')'
    $found=$search.FindAll()
    try { $counts.domainAccounts=$found.Count } finally { $found.Dispose() }
} finally { $search.Dispose();$directory.Dispose() }
$nonces=@();$recipientSIDs=@();$noSessionRecipients=@()
foreach ($file in @(Get-ChildItem -LiteralPath $OutputDirectory -Filter results.json -Recurse)) {
    $run=Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json
    $recipientSIDs+=@($run.recipientSID,$run.freshRecipient.sid)|Where-Object {$_}
    if ($run.freshRecipient.preexisting) { $noSessionRecipients+=$run.freshRecipient.name }
    # Fresh recipients are already covered by owned-account/affinity checks.
    $nonces+=@($run.records.requestedMarker.nonce)|Where-Object {$_}
}
$recipientSIDs=@($recipientSIDs|Sort-Object -Unique)
$counts.preexistingRecipientPrimaryTypes=0
foreach ($recipient in @($noSessionRecipients|Sort-Object -Unique)) {
    # Setup refuses any preexisting primary relationship on either test client.
    # Therefore any remaining primary type for these pairs belongs to this run.
    $relationships=@(Get-LabObjects $scope "SELECT * FROM SMS_UserMachineRelationship WHERE UniqueUserName='$($recipient.Replace('\','\\'))'")
    $counts.preexistingRecipientPrimaryTypes+=@($relationships|Where-Object {$_.ResourceID -in @(16777228,16777230) -and $_.Types -contains 1}).Count
}
$nonces=@($nonces|Sort-Object -Unique)
$recipientDefinition=(Get-Command Invoke-UserDeploymentRecipient).Definition
# Audit every managed lab client: the existing recipient uses more computers
# than the two that the payload is allowed to write on.
$managed=@(Get-LabObjects $scope 'SELECT Name FROM SMS_R_System WHERE Client=1'|ForEach-Object {$_.Name})
$clientAudits=@()
foreach ($computer in $managed) {
    $target=$computer+'.mayyhem.com'
    Write-Host "Checking withdrawn test policies on $computer"
    $clientAudits+=Invoke-LabDevice -Credential $Credential -ComputerName $target -ArgumentList $tags,$nonces,$recipientSIDs,$recipientDefinition -ScriptBlock {
        param($tags,$nonces,$sids,$recipientDefinition)
        $ErrorActionPreference='Stop'
        function Get-OwnedPolicies {
            $namespaces=@('root\ccm\Policy\Machine\ActualConfig')
            $available=@(Get-WmiObject -Namespace root\ccm\Policy -Class __NAMESPACE|Select-Object -ExpandProperty Name)
            foreach ($sid in $sids) {
                if ($available -contains $sid.Replace('-','_')) { $namespaces+='root\ccm\Policy\'+$sid.Replace('-','_')+'\ActualConfig' }
                # A fresh recipient may never have a user-policy namespace.
            }
            foreach ($namespace in $namespaces) {
                foreach ($policy in @(Get-WmiObject -Namespace $namespace -Class CCM_ApplicationCIAssignment)) {
                    foreach ($tag in $tags) { if ($policy.AssignmentName -like ('*'+$tag+'*')) { $policy } }
                    # Original and unrelated assignment names are untouched.
                }
            }
        }
        $before=@(Get-OwnedPolicies)
        if ($before.Count) {
            Set-Item Function:\Invoke-UserDeploymentRecipient ([scriptblock]::Create($recipientDefinition))
            $request=Invoke-UserDeploymentRecipient @{RunTag=$tags[0]} 'MAYYHEM\domainuser' '' Retrieve
            if ($request.error) { throw ('User-policy withdrawal failed: '+$request.error) }
            foreach ($schedule in @('{00000000-0000-0000-0000-000000000021}','{00000000-0000-0000-0000-000000000022}')) {
                $null=Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList $schedule
            }
        }
        # A client with no owned policy needs no policy request.
        $remaining=@(Get-OwnedPolicies)
        for ($attempt=0;$remaining.Count -and $attempt -lt 20;$attempt++) {
            Write-Verbose 'Waiting for ordinary policy withdrawal.'
            Start-Sleep -Seconds 4
            $remaining=@(Get-OwnedPolicies)
        }
        $removed=@()
        foreach ($nonce in $nonces) {
            if ($nonce -notmatch '^[a-f0-9]{32}$') { throw 'Invalid marker ownership nonce.' }
            $path='C:\Windows\Temp\cup-'+$nonce+'.jsonl'
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path;$removed+=$path }
            # The payload writes nothing on other computers or negative cases.
        }
        $markerCount=@(Get-ChildItem -LiteralPath 'C:\Windows\Temp' -Filter 'cup-*.jsonl'|Where-Object {$nonces -contains $_.BaseName.Substring(4)}).Count
        $ownedTasks=@(Get-ScheduledTask|Where-Object {$name=$_.TaskName;@($tags|Where-Object {$name -like ($_+'*')}).Count})
        [pscustomobject]@{computer=$env:COMPUTERNAME;policiesBefore=$before.Count;remainingPolicies=$remaining.Count;remainingMarkers=$markerCount;remainingTasks=$ownedTasks.Count;removedMarkers=$removed;sessions=@(quser 2>&1|ForEach-Object {$_|Out-String})}
    }
}
$original=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\builtin-role-permissions.json') -Raw|ConvertFrom-Json
$rolesUnchanged=$true
foreach ($role in $original) {
    $current=Get-LabObject $scope ('SMS_Role.RoleID="'+$role.RoleID+'"')
    $before=@($role.Operations|ForEach-Object {"$($_.ObjectTypeID):$($_.GrantedOperations)"}|Sort-Object)
    $after=@($current.Operations|ForEach-Object {"$($_.ObjectTypeID):$($_.GrantedOperations)"}|Sort-Object)
    if ($current.RoleName -ne $role.RoleName -or @(Compare-Object $before $after).Count) { $rolesUnchanged=$false;Write-Warning 'An original role changed.' }
    # Matching definitions need no per-role output.
}
$baseline=Get-Content -LiteralPath (Join-Path $OutputDirectory 'original-recipient-affinities.json') -Raw|ConvertFrom-Json
$affinitiesRestored=$true
foreach ($association in $baseline) {
    $current=@(Get-LabObjects $scope "SELECT * FROM SMS_UserMachineRelationship WHERE ResourceID=$($association.resourceID) AND UniqueUserName='$($association.user.Replace('\','\\'))'")
    $beforeTypes=(@($association.types|Sort-Object) -join ',')
    $afterTypes=(@($current[0].Types|Sort-Object) -join ',')
    $beforeSources=(@($association.sources|Sort-Object) -join ',')
    $afterSources=(@($current[0].Sources|Sort-Object) -join ',')
    if ($current.Count -ne 1 -or $beforeTypes -ne $afterTypes -or $beforeSources -ne $afterSources) {
        $affinitiesRestored=$false
        Write-Warning 'An original recipient association differs from the saved baseline.'
    }
    # The temporary primary type/source must be gone; original usage data remains.
}
$audit=[ordered]@{timestampUTC=[DateTime]::UtcNow.ToString('o');tags=$tags;remainingObjects=$counts;clients=$clientAudits;
    remainingClientPolicies=($clientAudits|Measure-Object remainingPolicies -Sum).Sum;
    remainingMarkers=($clientAudits|Measure-Object remainingMarkers -Sum).Sum;
    remainingTasks=($clientAudits|Measure-Object remainingTasks -Sum).Sum;
    originalRoleCount=$original.Count;originalRolesUnchanged=$rolesUnchanged;originalAffinitiesRestored=$affinitiesRestored;
    removedDiscoveredUsers=$removedDiscovery}
$audit|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $OutputDirectory 'cleanup-final.json') -Encoding UTF8
[pscustomobject]$audit|Select-Object timestampUTC,remainingObjects,remainingClientPolicies,remainingMarkers,remainingTasks,originalRoleCount,originalRolesUnchanged,originalAffinitiesRestored|ConvertTo-Json -Depth 4
if (@($counts.Values|Where-Object {$_ -ne 0}).Count -or $audit.remainingClientPolicies -or $audit.remainingMarkers -or $audit.remainingTasks -or -not $rolesUnchanged -or -not $affinitiesRestored) { throw 'Placement audit found unfinished cleanup.' }
