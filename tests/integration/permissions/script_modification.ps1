<#
.SYNOPSIS
Test whether changing an approved script preserves permission to execute it.
.PARAMETER Credential
Lab administrator used to prepare temporary objects and observe results. Tested
SCCM actions use separate temporary accounts, except full-administrator controls.
.PARAMETER OutputDirectory
Folder for result files and the cleanup journal; passwords are never saved here.
Resolve a failed cleanup before reusing its output folder.
.PARAMETER PermissionMasks
SMS Scripts operation values to compare. The default tests Read, Modify, Create,
and Approve combinations, including whether an edit resets approval.
.EXAMPLE
.\tests\integration\permissions\script_modification.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-script-modify"
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory,
      [uint32[]] $PermissionMasks = @(1,3,262145,262147,1025,1027,263169,263171))
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
try {
    $approver = New-LabUser $context
    $null = New-LabAdmin $context $approver @(@{ Role = 'SMS0001R'; Collections = @('SMS00001','SMS00002'); Scopes = @('SMS00ALL') })
    $approverScope = New-LabScope $approver.Credential
    $persistentCount = $context.Resources.Count
    foreach ($mask in $PermissionMasks) {
        Write-Host "Testing script Modify and approval with mask $mask"
        $record = [ordered]@{ scriptMask = $mask; updated = $false }
        try {
            $script = New-LabScript $context "Write-Output 'Original harmless script'" 'script modification'
            $null = Approve-LabScript $approverScope $script.ScriptGuid $approver.Name
            $actor = New-LabUser $context
            $role = New-LabRole $context @(@{ ObjectTypeID = 213; GrantedOperations = $mask }, @{ ObjectTypeID = 6; GrantedOperations = 1 }) 'script modification'
            $null = New-LabAdmin $context $actor @(@{ Role = $role.RoleID; Collections = @('SMS00001'); Scopes = @('SMS00ALL') })
            $actorScope = New-LabScope $actor.Credential
            $record.actor = $actor.Name
            try {
                $target = Get-LabObject $actorScope $script.Path.RelativePath
                $parameters = $target.GetMethodParameters('UpdateScript')
                $newCode = "Write-Output 'Changed harmless script'"
                $parameters.Script = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetPreamble() + [Text.Encoding]::UTF8.GetBytes($newCode))
                $parameters.ScriptVersion = '2'
                $parameters.ScriptName = $script.ScriptName
                $output = $target.InvokeMethod('UpdateScript', $parameters, $null)
                $record.updateReturn = $output.ReturnValue
                $saved = Get-LabObject $context.Scope $script.Path.RelativePath
                $record.updated = $saved.Script -eq $parameters.Script
                $record.approvalAfterChange = $saved.ApprovalState
                $record.authorAfterChange = $saved.Author
                try { $record.approvalReturn = Approve-LabScript $actorScope $script.ScriptGuid $actor.Name }
                catch {
                    $record.approvalError = Get-LabError $_
                    Write-Warning ($record.approvalError | ConvertTo-Json -Compress)
                }
                $record.finalApproval = (Get-LabObject $context.Scope $script.Path.RelativePath).ApprovalState
            }
            catch {
                $record.updateError = Get-LabError $_
                Write-Warning ($record.updateError | ConvertTo-Json -Compress)
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
finally { Remove-LabResources $context }
