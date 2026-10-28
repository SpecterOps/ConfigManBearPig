<#
.SYNOPSIS
Test script creation, approval, and the separate-author approval requirement.
.PARAMETER Credential
Lab administrator used to prepare temporary objects and observe results. Tested
SCCM actions use separate temporary accounts, except full-administrator controls.
.PARAMETER OutputDirectory
Folder for result files and the cleanup journal; passwords are never saved here.
Resolve a failed cleanup before reusing its output folder.
.EXAMPLE
.\tests\integration\permissions\script_approval.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-script-approval"
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
$cases = @(
    @{ Name = 'Read control creating script'; Mask = 1; Create = $true; ForgeAuthor = $false; ForgeApprover = $false; InitialApproval = 0 },
    @{ Name = 'Create only'; Mask = 1025; Create = $true; ForgeAuthor = $false; ForgeApprover = $false; InitialApproval = 0 },
    @{ Name = 'Create only requesting approved state'; Mask = 1025; Create = $true; ForgeAuthor = $false; ForgeApprover = $false; InitialApproval = 3 },
    @{ Name = 'Create plus Approve own script'; Mask = 263169; Create = $true; ForgeAuthor = $false; ForgeApprover = $false; InitialApproval = 0 },
    @{ Name = 'Create plus Approve forged author'; Mask = 263169; Create = $true; ForgeAuthor = $true; ForgeApprover = $false; InitialApproval = 0 },
    @{ Name = 'Create plus Approve forged approver'; Mask = 263169; Create = $true; ForgeAuthor = $false; ForgeApprover = $true; InitialApproval = 0 },
    @{ Name = 'Read control approving another script'; Mask = 1; Create = $false; ForgeAuthor = $false; ForgeApprover = $false; InitialApproval = 0 },
    @{ Name = 'Modify approving another script'; Mask = 3; Create = $false; ForgeAuthor = $false; ForgeApprover = $false; InitialApproval = 0 },
    @{ Name = 'Approve only approving another script'; Mask = 262145; Create = $false; ForgeAuthor = $false; ForgeApprover = $false; InitialApproval = 0 }
)
try {
    foreach ($case in $cases) {
        Write-Host "Testing $($case.Name)"
        $record = [ordered]@{ name = $case.Name; scriptMask = $case.Mask; created = $false; approved = $false }
        try {
            $actor = New-LabUser $context
            $role = New-LabRole $context @(
                @{ ObjectTypeID = 213; GrantedOperations = $case.Mask },
                @{ ObjectTypeID = 6; GrantedOperations = 1 }
            ) $case.Name
            $null = New-LabAdmin $context $actor @(@{ Role = $role.RoleID; Collections = @('SMS00001'); Scopes = @('SMS00ALL') })
            $actorScope = New-LabScope $actor.Credential
            $record.actor = $actor.Name
            try {
                if ($case.Create) {
                    $author = $actor.Name
                    if ($case.ForgeAuthor) { $author = $Credential.UserName }
                    $script = New-LabScript $context "Write-Output 'Harmless approval check'" $case.Name $actorScope $author $case.InitialApproval
                }
                else { $script = New-LabScript $context "Write-Output 'Harmless approval check'" $case.Name }
                $record.created = $true
                $record.savedAuthor = $script.Author
                $record.initialApproval = $script.ApprovalState
                $approver = $actor.Name
                if ($case.ForgeApprover) { $approver = $Credential.UserName }
                $record.approvalReturn = Approve-LabScript $actorScope $script.ScriptGuid $approver
            }
            catch {
                $record.error = Get-LabError $_
                Write-Warning ($record.error | ConvertTo-Json -Compress)
            }
            if ($record.created) {
                $saved = Get-LabObject $context.Scope $script.Path.RelativePath
                $record.finalApproval = $saved.ApprovalState
                $record.savedApprover = $saved.Approver
                $record.approved = $saved.ApprovalState -eq 3
            }
        }
        finally {
            Remove-LabResources $context
            $record.cleanupComplete = $context.Resources.Count -eq 0
            $results.Add($record)
            $results.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
        }
    }
}
finally { Remove-LabResources $context }
