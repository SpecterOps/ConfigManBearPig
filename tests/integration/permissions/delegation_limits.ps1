<#
.SYNOPSIS
Test whether SCCM permission granting follows per-role collection boundaries.
.PARAMETER Credential
Lab administrator used to prepare temporary objects and observe results. Tested
SCCM actions use separate temporary accounts, except full-administrator controls.
.PARAMETER OutputDirectory
Folder for result files and the cleanup journal; passwords are never saved here.
Resolve a failed cleanup before reusing its output folder.
.EXAMPLE
.\tests\integration\permissions\delegation_limits.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-grant-limits"
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
$globalCollections = @('SMS00001','SMS00002')
$cases = @(
    @{ Name = 'all assignments narrow, request global'; ReadGlobal = $false; ActionGlobal = $false; GrantGlobal = $true; ReadAllScope = $true; ActionAllScope = $true },
    @{ Name = 'global read, narrow grant role, request global'; ReadGlobal = $true; ActionGlobal = $false; GrantGlobal = $true; ReadAllScope = $true; ActionAllScope = $true },
    @{ Name = 'narrow read, global grant role, request global'; ReadGlobal = $false; ActionGlobal = $true; GrantGlobal = $true; ReadAllScope = $true; ActionAllScope = $true },
    @{ Name = 'all assignments narrow, request same narrow'; ReadGlobal = $false; ActionGlobal = $false; GrantGlobal = $false; ReadAllScope = $true; ActionAllScope = $true },
    @{ Name = 'Default scope only, request All scope'; ReadGlobal = $true; ActionGlobal = $true; GrantGlobal = $true; ReadAllScope = $false; ActionAllScope = $false },
    @{ Name = 'All read scope, Default grant scope, request All'; ReadGlobal = $true; ActionGlobal = $true; GrantGlobal = $true; ReadAllScope = $true; ActionAllScope = $false }
)
try {
    $narrow = New-LabCollection $context 'narrow delegation boundary'
    $persistentCount = $context.Resources.Count
    foreach ($action in @('Add','Modify','Modify role then own assignment')) {
        foreach ($case in $cases) {
            Write-Host "Testing $action / $($case.Name)"
            $record = [ordered]@{ action = $action; name = $case.Name; roleChanged = $false; granted = $false; verified = $false }
            try {
                $actor = New-LabUser $context
                $operation = @{ ObjectTypeID = 28; GrantedOperations = 1024 }
                if ($action -eq 'Modify') { $operation.GrantedOperations = 2 }
                elseif ($action -eq 'Modify role then own assignment') { $operation.ObjectTypeID = 27; $operation.GrantedOperations = 2 }
                $role = New-LabRole $context @($operation) 'grant boundary'
                $readCollections = @($narrow.CollectionID)
                if ($case.ReadGlobal) { $readCollections = $globalCollections }
                $actionCollections = @($narrow.CollectionID)
                if ($case.ActionGlobal) { $actionCollections = $globalCollections }
                $readScope = @('SMS00UNA')
                if ($case.ReadAllScope) { $readScope = @('SMS00ALL') }
                $actionScope = @('SMS00UNA')
                if ($case.ActionAllScope) { $actionScope = @('SMS00ALL') }
                $admin = New-LabAdmin $context $actor @(
                    @{ Role = 'SMS0002R'; Collections = $readCollections; Scopes = $readScope },
                    @{ Role = $role.RoleID; Collections = $actionCollections; Scopes = $actionScope }
                )
                $actorScope = New-LabScope $actor.Credential
                $grantCollections = @($narrow.CollectionID)
                if ($case.GrantGlobal) { $grantCollections = $globalCollections }
                $grant = @(@{ Role = 'SMS0001R'; Collections = $grantCollections; Scopes = @('SMS00ALL') })
                $record.actor = $actor.Name
                $record.readCollections = $readCollections
                $record.actionCollections = $actionCollections
                $record.requestedCollections = $grantCollections
                $record.readScope = $readScope
                $record.actionScope = $actionScope
                try {
                    if ($action -eq 'Add') {
                        $recipient = New-LabUser $context
                        $changed = New-LabAdmin $context $recipient $grant $actorScope
                    }
                    else {
                        if ($action -eq 'Modify role then own assignment') {
                            $changedRole = Get-LabObject $actorScope $role.Path.RelativePath
                            $changedRole.Operations = ConvertTo-LabOperations $actorScope $context.FullOperations
                            $null = $changedRole.Put()
                            $savedRole = Get-LabObject $context.Scope $role.Path.RelativePath
                            $record.savedOperations = @($savedRole.Operations | ForEach-Object {
                                @{ ObjectTypeID = $_.ObjectTypeID; GrantedOperations = $_.GrantedOperations }
                            })
                            $record.roleChanged = $true
                            # A new connection observes the newly expanded role.
                            $actorScope = New-LabScope $actor.Credential
                        }
                        $changed = Get-LabObject $actorScope $admin.Path.RelativePath
                        $changed.Permissions = ConvertTo-LabAssignments $actorScope $grant
                        $null = $changed.Put()
                        $changed = Get-LabObject $context.Scope $admin.Path.RelativePath
                    }
                    $record.savedAssignments = @($changed.Permissions | ForEach-Object {
                        @{ RoleID = $_.RoleID; CategoryID = $_.CategoryID; CategoryTypeID = $_.CategoryTypeID }
                    })
                    $record.granted = $true
                    $record.verified = @($changed.Permissions | Where-Object RoleID -eq 'SMS0001R').Count -eq ($grantCollections.Count + 1)
                }
                catch {
                    $record.error = Get-LabError $_
                    Write-Warning ($record.error | ConvertTo-Json -Compress)
                }
            }
            finally {
                Remove-LabResources $context -KeepFirst $persistentCount
                $record.cleanupComplete = $context.Resources.Count -eq $persistentCount
                $results.Add($record)
                $results.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
            }
        }
    }
}
finally { Remove-LabResources $context }
