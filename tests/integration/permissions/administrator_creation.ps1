<#
.SYNOPSIS
Check whether adding an SCCM administrator can also replace an existing entry.
.PARAMETER Credential
Lab administrator used to prepare temporary objects and observe results. Tested
SCCM actions use separate temporary accounts, except full-administrator controls.
.PARAMETER OutputDirectory
Folder for result files and the cleanup journal; passwords are never saved here.
Resolve a failed cleanup before reusing its output folder.
.EXAMPLE
.\tests\integration\permissions\administrator_creation.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-admin-creation"
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($profile in @('Add only','Modify only','CMPivot Administrator as found in this lab')) {
        foreach ($target in @('own existing entry','another existing entry','update own existing entry by key','new entry')) {
            Write-Host "Testing $profile / $target"
            $record = [ordered]@{ profile = $profile; target = $target; success = $false }
            try {
                $actor = New-LabUser $context
                $roleID = 'SMS000IR'
                if ($profile -ne 'CMPivot Administrator as found in this lab') {
                    $mask = 1024
                    if ($profile -eq 'Modify only') { $mask = 2 }
                    $roleID = (New-LabRole $context @(@{ ObjectTypeID = 28; GrantedOperations = $mask }) $profile).RoleID
                }
                $admin = New-LabAdmin $context $actor @(@{ Role = $roleID; Collections = @('SMS00001','SMS00002'); Scopes = @('SMS00ALL') })
                $recipient = $actor
                $recipientAdmin = $admin
                if ($target -eq 'another existing entry') {
                    $recipient = New-LabUser $context
                    $recipientAdmin = New-LabAdmin $context $recipient @(@{ Role = 'SMS0002R'; Collections = @('SMS00001','SMS00002'); Scopes = @('SMS00ALL') })
                }
                if ($target -eq 'new entry') { $recipient = New-LabUser $context; $recipientAdmin = $null }
                $actorScope = New-LabScope $actor.Credential
                $record.actor = $actor.Name
                try {
                    # This is a NEW instance, with no AdminID. The target SID is
                    # already registered, testing create-versus-update enforcement.
                    if ($target -eq 'update own existing entry by key') { $entry = Get-LabObject $actorScope $recipientAdmin.Path.RelativePath }
                    else { $entry = New-LabInstance $actorScope 'SMS_Admin' }
                    $entry.LogonName = $recipient.Name
                    $entry.AdminSid = $recipient.Sid
                    $entry.Permissions = ConvertTo-LabAssignments $actorScope @(@{ Role = 'SMS0001R'; Collections = @('SMS00001','SMS00002'); Scopes = @('SMS00ALL') })
                    $path = $entry.Put()
                    if ($null -eq $recipientAdmin) { Add-LabResource $context 'WMI' $path.RelativePath 'LogonName' $recipient.Name }
                    elseif ($path.RelativePath -ne $recipientAdmin.Path.RelativePath) { throw 'Unexpected second administrator entry; retain evidence for cleanup.' }
                    $saved = Get-LabObject $context.Scope $path.RelativePath
                    $record.success = @($saved.Permissions | Where-Object RoleID -eq 'SMS0001R').Count -eq 3
                }
                catch {
                    $record.error = Get-LabError $_
                    Write-Warning ($record.error | ConvertTo-Json -Compress)
                }
            }
            finally {
                Remove-LabResources $context
                $record.cleanupComplete = $context.Resources.Count -eq 0
                $results.Add($record)
                $results.ToArray() | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
            }
        }
    }
}
finally { Remove-LabResources $context }
