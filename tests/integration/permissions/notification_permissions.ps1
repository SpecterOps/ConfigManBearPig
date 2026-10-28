<#
.SYNOPSIS
Measure the permission needed for individual SCCM client-notification actions.
.DESCRIPTION
Only requests policy retrieval, application evaluation, and compliance checks on
PS1-DEV. This test does not create or change executable workload definitions.
Fresh restricted accounts are used, and temporary accounts/roles are removed.
.PARAMETER Credential
Lab administrator for preparing the one-device boundary and temporary identities.
.PARAMETER OutputDirectory
Dedicated result and cleanup-journal folder without passwords.
.EXAMPLE
.\tests\integration\permissions\notification_permissions.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-notify-permissions"
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][pscredential]$Credential,
      [Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
. (Join-Path $PSScriptRoot 'execution_helpers.ps1')
$context=New-LabContext $Credential $OutputDirectory
$results=[Collections.Generic.List[object]]::new()
try {
    $collection=New-LabCollection $context 'one-device notification permission check'
    Add-LabCollectionDevice $context $collection 16777230
    $baseCount=$context.Resources.Count
    foreach($candidate in @(
        @{name='Read control';mask=0},
        @{name='Notify Resource';mask=536870912},
        @{name='Modify Resource';mask=128},
        @{name='Deploy Applications';mask=1048576}
    )) {
        try {
            $actor=New-LabUser $context
            $role=New-LabRole $context @(
                @{ObjectTypeID=1;GrantedOperations=(4097 -bor $candidate.mask)},
                @{ObjectTypeID=6;GrantedOperations=1}
            ) ('notification '+$candidate.name)
            $null=New-LabAdmin $context $actor @(@{Role=$role.RoleID;Collections=@($collection.CollectionID);Scopes=@('SMS00ALL')})
            $scope=New-LabScope $actor.Credential
            foreach($action in @(8,13,125)) {
                Write-Host "Testing $($candidate.name), notification $action"
                $record=Request-ExecutionNotification $scope $collection.CollectionID 16777230 $action
                $record.profile=$candidate.name
                $record.collectionMask=(4097 -bor $candidate.mask)
                $record.actor=$actor.Name
                $results.Add($record)
            }
        }
        finally {
            Remove-LabResources $context -KeepFirst $baseCount
            $results.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
        }
    }
}
finally { Remove-LabResources $context }
