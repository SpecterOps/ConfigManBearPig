<#
.SYNOPSIS
Measure which SCCM permissions allow granting access or changing role definitions.
.DESCRIPTION
This manual test creates a different temporary domain user for every attempt.
Read-only Analyst supplies lookup access; a custom role supplies only the action
being tested. All changes are checked independently with the setup account.
Nothing is deployed to a device. Resources are removed after each attempt.
.PARAMETER Credential
Lab administrator used to prepare temporary objects and observe results. Tested
SCCM actions use separate temporary accounts, except full-administrator controls.
.PARAMETER OutputDirectory
Folder for result files and the cleanup journal; passwords are never saved here.
Resolve a failed cleanup before reusing its output folder.
.EXAMPLE
.\tests\integration\permissions\delegation.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-delegation"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][pscredential] $Credential,
    [Parameter(Mandatory = $true)][string] $OutputDirectory
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
$allCollections = @('SMS00001', 'SMS00002')
$allScopes = @('SMS00ALL')
$profiles = @(
    @{ Name = 'read-only control'; Type = 28; Mask = 1 },
    @{ Name = 'Administrative Users Add'; Type = 28; Mask = 1024 },
    @{ Name = 'Administrative Users Modify'; Type = 28; Mask = 2 },
    @{ Name = 'Security Roles Create'; Type = 27; Mask = 1024 },
    @{ Name = 'Security Roles Modify'; Type = 27; Mask = 2 }
)
$actions = @('add administrator', 'change own assignment', 'change another assignment', 'change assigned role', 'change unassigned role', 'create powerful role')
try {
    foreach ($profile in $profiles) {
        foreach ($action in $actions) {
            $resourceCount = $context.Resources.Count
            $record = [ordered]@{ profile = $profile.Name; objectType = $profile.Type; actionMask = $profile.Mask; action = $action; success = $false; verified = $false }
            Write-Host "Testing $($profile.Name): $action"
            try {
                $actor = New-LabUser $context
                $role = New-LabRole $context @(@{ ObjectTypeID = $profile.Type; GrantedOperations = $profile.Mask }) 'actor'
                $assignments = @(
                    @{ Role = 'SMS0002R'; Collections = $allCollections; Scopes = $allScopes },
                    @{ Role = $role.RoleID; Collections = $allCollections; Scopes = $allScopes }
                )
                $admin = New-LabAdmin $context $actor $assignments
                $record.actor = $actor.Name
                $record.originalRole = $role.RoleID
                $other = New-LabUser $context
                $otherAdmin = New-LabAdmin $context $other @(@{ Role = 'SMS0002R'; Collections = $allCollections; Scopes = $allScopes })
                $unassigned = New-LabRole $context @(@{ ObjectTypeID = 6; GrantedOperations = 1 }) 'unassigned target'
                $actorScope = New-LabScope $actor.Credential
                $powerfulAssignment = @(@{ Role = 'SMS0001R'; Collections = $allCollections; Scopes = $allScopes })
                # Only this block uses the temporary account's credentials.
                try {
                    switch ($action) {
                        'add administrator' {
                            # This recipient has no SCCM entry, so this tests Add.
                            $recipient = New-LabUser $context
                            $changed = New-LabAdmin $context $recipient $powerfulAssignment $actorScope
                            $record.target = $recipient.Name
                            $record.verified = @($changed.Permissions | Where-Object RoleID -eq 'SMS0001R').Count -eq 3
                        }
                        'change own assignment' {
                            $changed = Get-LabObject $actorScope $admin.Path.RelativePath
                            $changed.Permissions = ConvertTo-LabAssignments $actorScope $powerfulAssignment
                            $null = $changed.Put()
                            $saved = Get-LabObject $context.Scope $admin.Path.RelativePath
                            $record.verified = @($saved.Permissions | Where-Object RoleID -eq 'SMS0001R').Count -eq 3
                        }
                        'change another assignment' {
                            $changed = Get-LabObject $actorScope $otherAdmin.Path.RelativePath
                            $changed.Permissions = ConvertTo-LabAssignments $actorScope $powerfulAssignment
                            $null = $changed.Put()
                            $saved = Get-LabObject $context.Scope $otherAdmin.Path.RelativePath
                            $record.verified = @($saved.Permissions | Where-Object RoleID -eq 'SMS0001R').Count -eq 3
                        }
                        'change assigned role' {
                            $changed = Get-LabObject $actorScope $role.Path.RelativePath
                            $changed.Operations = ConvertTo-LabOperations $actorScope $context.FullOperations
                            $null = $changed.Put()
                            $saved = Get-LabObject $context.Scope $role.Path.RelativePath
                            $record.verified = $saved.Operations.Count -eq $context.FullOperations.Count
                        }
                        'change unassigned role' {
                            $changed = Get-LabObject $actorScope $unassigned.Path.RelativePath
                            $changed.Operations = ConvertTo-LabOperations $actorScope $context.FullOperations
                            $null = $changed.Put()
                            $saved = Get-LabObject $context.Scope $unassigned.Path.RelativePath
                            $record.verified = $saved.Operations.Count -eq $context.FullOperations.Count
                        }
                        'create powerful role' {
                            $changed = New-LabRole $context $context.FullOperations 'created by actor' $actorScope
                            $record.createdRole = $changed.RoleID
                            $record.verified = $changed.Operations.Count -eq $context.FullOperations.Count
                        }
                    }
                    $record.success = $true
                }
                catch {
                    $record.error = Get-LabError $_
                    Write-Warning ($record.error | ConvertTo-Json -Compress)
                }
            }
            finally {
                Remove-LabResources $context -KeepFirst $resourceCount
                $record.cleanupComplete = $context.Resources.Count -eq $resourceCount
                $results.Add($record)
                $results.ToArray() | ConvertTo-Json -Depth 12 |
                    Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
            }
        }
    }
}
finally { Remove-LabResources $context }
$results | ForEach-Object { [pscustomobject]$_ } | Select-Object profile, action, success, verified, cleanupComplete | Format-Table -AutoSize
