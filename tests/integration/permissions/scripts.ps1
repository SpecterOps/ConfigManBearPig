<#
.SYNOPSIS
Test the individual permissions behind SCCM Run Scripts.
.DESCRIPTION
Uses fresh temporary accounts, custom roles, and a harmless SYSTEM marker.
Read-only setup work and marker observation use the supplied lab administrator.
Every tested action uses the temporary account. All objects are removed.
.PARAMETER Credential
Lab administrator used to prepare temporary objects and observe results. Tested
SCCM actions use separate temporary accounts, except full-administrator controls.
.PARAMETER OutputDirectory
Folder for result files and the cleanup journal; passwords are never saved here.
Resolve a failed cleanup before reusing its output folder.
.PARAMETER Selection
Choose a positive control, the permission comparison, or a focused scenario.
The allowed values are listed in the parameter declaration and the research report.
.EXAMPLE
.\tests\integration\permissions\scripts.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-scripts"
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory,
      [ValidateSet('basic','limits')][string] $Selection = 'basic')
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
$cases = @(
    @{ Name = 'read-only control'; Collection = 1; Script = 1; Site = 1; Target = 'PS1-DEV'; ID = 16777230 },
    @{ Name = 'Run Script with documented reads'; Collection = 268435457; Script = 1; Site = 1; Target = 'PS1-DEV'; ID = 16777230 },
    @{ Name = 'Run Script without collection Read'; Collection = 268435456; Script = 1; Site = 1; Target = 'PS1-DEV'; ID = 16777230 },
    @{ Name = 'Run Script without script Read'; Collection = 268435457; Script = 0; Site = 1; Target = 'PS1-DEV'; ID = 16777230 },
    @{ Name = 'Run Script without site Read'; Collection = 268435457; Script = 1; Site = 0; Target = 'PS1-DEV'; ID = 16777230 },
    @{ Name = 'Run Script alone'; Collection = 268435456; Script = 0; Site = 0; Target = 'PS1-DEV'; ID = 16777230 },
    @{ Name = 'Run Script on site server client'; Collection = 268435457; Script = 1; Site = 1; Target = 'PS1-PSS'; ID = 16777220 },
    @{ Name = 'Run Script on database server client'; Collection = 268435457; Script = 1; Site = 1; Target = 'PS1-DB'; ID = 16777219 },
    @{ Name = 'Run Script on SMS Provider client'; Collection = 268435457; Script = 1; Site = 1; Target = 'PS1-SMS'; ID = 16777227 }
)
try {
    if ($Selection -eq 'limits') {
        $allowed = New-LabCollection $context 'Run Script collection boundary'
        Add-LabCollectionDevice $context $allowed 16777230
        $cases = @(
            @{ Name = 'Minimal Run Script plus script Read'; Collection = 268435456; Script = 1; Site = 0; Target = 'PS1-DEV'; ID = 16777230 },
            @{ Name = 'Narrow collection inside target'; Collection = 268435456; Script = 1; Site = 0; Target = 'PS1-DEV'; ID = 16777230; Narrow = $true },
            @{ Name = 'Narrow collection outside target'; Collection = 268435456; Script = 1; Site = 0; Target = 'PS1-DB'; ID = 16777219; Narrow = $true },
            @{ Name = 'Global read with narrow Run Script outside target'; Collection = 268435456; Script = 1; Site = 0; Target = 'PS1-DB'; ID = 16777219; Narrow = $true; GlobalRead = $true },
            @{ Name = 'Run Script and script Read on separate roles and scopes'; Collection = 268435456; Script = 0; Site = 0; Target = 'PS1-DEV'; ID = 16777230; Narrow = $true; GlobalRead = $true; Scope = 'PS100046' },
            @{ Name = 'Script Read outside the script object scope'; Collection = 268435456; Script = 1; Site = 0; Target = 'PS1-DEV'; ID = 16777230; Narrow = $true; Scope = 'PS100046' }
        )
    }
    $approver = New-LabUser $context
    $null = New-LabAdmin $context $approver @(@{ Role = 'SMS0001R'; Collections = @('SMS00001','SMS00002'); Scopes = @('SMS00ALL') })
    $approverScope = New-LabScope $approver.Credential
    $persistentResources = $context.Resources.Count
    foreach ($case in $cases) {
        Write-Host "Testing $($case.Name)"
        $nonce = [guid]::NewGuid().ToString('N')
        $marker = 'C:\ProgramData\CMBP-PermissionResearch\' + $nonce + '.json'
        $record = [ordered]@{ name = $case.Name; target = $case.Target; resourceID = $case.ID; collectionMask = $case.Collection; scriptMask = $case.Script; siteMask = $case.Site; marker = $null }
        try {
            $code = @'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$result = @{ nonce = 'NONCE'; computer = $env:COMPUTERNAME; identity = $identity.Name; sid = $identity.User.Value } | ConvertTo-Json -Compress
$null = [IO.Directory]::CreateDirectory('C:\ProgramData\CMBP-PermissionResearch')
[IO.File]::WriteAllText('MARKER', $result)
Write-Output $result
'@
            $script = New-LabScript $context ($code.Replace('NONCE',$nonce).Replace('MARKER',$marker)) $case.Name
            $null = Approve-LabScript $approverScope $script.ScriptGuid $approver.Name
            $operations = [System.Collections.Generic.List[object]]::new()
            foreach ($operation in @(
                @{ ObjectTypeID = 1; GrantedOperations = $case.Collection },
                @{ ObjectTypeID = 213; GrantedOperations = $case.Script },
                @{ ObjectTypeID = 6; GrantedOperations = $case.Site }
            )) {
                if ($operation.GrantedOperations -ne 0) { $operations.Add($operation) }
                # Zero means this permission category is deliberately absent.
            }
            $role = New-LabRole $context $operations.ToArray() $case.Name
            $actor = New-LabUser $context
            $collections = @('SMS00001')
            if ($case.Narrow) { $collections = @($allowed.CollectionID) }
            $scopes = @('SMS00ALL')
            if ($case.Scope) { $scopes = @($case.Scope) }
            $assignments = @(@{ Role = $role.RoleID; Collections = $collections; Scopes = $scopes })
            if ($case.GlobalRead) {
                $readRole = New-LabRole $context @(
                    @{ ObjectTypeID = 1; GrantedOperations = 1 },
                    @{ ObjectTypeID = 213; GrantedOperations = 1 },
                    @{ ObjectTypeID = 6; GrantedOperations = 1 }
                ) 'separate global read'
                $assignments += @{ Role = $readRole.RoleID; Collections = @('SMS00001'); Scopes = @('SMS00UNA') }
            }
            $null = New-LabAdmin $context $actor $assignments
            $record.collections = $collections
            $record.scopes = $scopes
            $record.separateGlobalRead = [bool]$case.GlobalRead
            $record.actor = $actor.Name
            $record.scriptGuid = $script.ScriptGuid
            $record.run = Invoke-LabScript $actor.Credential $case.ID $script.ScriptGuid
            $polls = 1
            if ($record.run.status -eq 200) { $polls = 15 }
            else { Write-Warning "Run Script returned HTTP $($record.run.status): $($record.run.body)" }
            for ($attempt = 0; $attempt -lt $polls; $attempt++) {
                $observed = Invoke-LabDevice -ComputerName ($case.Target.ToLowerInvariant()+'.mayyhem.com') -Credential $Credential -ArgumentList $marker -ScriptBlock {
                    param($path)
                    if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw }
                    # The marker is absent when execution was denied or is still pending.
                }
                if ($observed) { $record.marker = $observed | ConvertFrom-Json; break }
                Write-Host "Waiting for $($case.Target) marker ($attempt)"
                Start-Sleep -Seconds 3
            }
            $record.verified = $record.marker.nonce -eq $nonce -and $record.marker.sid -eq 'S-1-5-18' -and $record.marker.computer -eq $case.Target
            if ($record.run.status -eq 200 -and -not $record.verified) { Write-Warning 'An accepted request produced no matching SYSTEM marker.' }
            elseif ($record.verified) { Write-Host "SYSTEM execution confirmed on $($case.Target)" }
            else { Write-Host 'No marker after the rejected request.' }
        }
        catch {
            $record.error = Get-LabError $_
            Write-Warning ($record.error | ConvertTo-Json -Compress)
        }
        finally {
            try {
                Invoke-LabDevice -ComputerName ($case.Target.ToLowerInvariant()+'.mayyhem.com') -Credential $Credential -ArgumentList $marker -ScriptBlock {
                    param($path)
                    if ($path -notmatch '^C:\\ProgramData\\CMBP-PermissionResearch\\[a-f0-9]{32}\.json$') { throw 'Invalid marker cleanup path' }
                    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                    # Rejected requests create no file to remove.
                }
            }
            finally {
                Remove-LabResources $context -KeepFirst $persistentResources
                $record.cleanupComplete = $context.Resources.Count -eq $persistentResources
                $results.Add($record)
                $results.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
            }
        }
    }
}
finally { Remove-LabResources $context }
