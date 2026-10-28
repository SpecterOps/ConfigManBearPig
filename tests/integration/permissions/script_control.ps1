<#
.SYNOPSIS
Validate a harmless SCCM script marker and the independent observation channel.
.PARAMETER Credential
Lab administrator used to prepare temporary objects and observe results. Tested
SCCM actions use separate temporary accounts, except full-administrator controls.
.PARAMETER OutputDirectory
Folder for result files and the cleanup journal; passwords are never saved here.
Resolve a failed cleanup before reusing its output folder.
.EXAMPLE
.\tests\integration\permissions\script_control.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-script-control"
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$record = [ordered]@{ runTag = $context.RunTag; target = 'PS1-DEV'; resourceID = 16777230 }
$nonce = [guid]::NewGuid().ToString('N')
$marker = 'C:\ProgramData\CMBP-PermissionResearch\' + $nonce + '.json'
$code = @'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$result = @{ nonce = 'NONCE'; computer = $env:COMPUTERNAME; identity = $identity.Name; sid = $identity.User.Value } | ConvertTo-Json -Compress
$null = [IO.Directory]::CreateDirectory('C:\ProgramData\CMBP-PermissionResearch')
[IO.File]::WriteAllText('MARKER', $result)
Write-Output $result
'@
$code = $code.Replace('NONCE', $nonce).Replace('MARKER', $marker)
try {
    $approver = New-LabUser $context
    $null = New-LabAdmin $context $approver @(@{ Role = 'SMS0001R'; Collections = @('SMS00001', 'SMS00002'); Scopes = @('SMS00ALL') })
    $script = New-LabScript $context $code 'script control'
    $record.scriptGuid = $script.ScriptGuid
    $record.initialApproval = $script.ApprovalState
    $record.approval = Approve-LabScript (New-LabScope $approver.Credential) $script.ScriptGuid $approver.Name
    $record.run = Invoke-LabScript $Credential 16777230 $script.ScriptGuid
    # Poll in short intervals; a returned operation ID alone is not proof of execution.
    $record.marker = $null
    for ($attempt = 0; $attempt -lt 18; $attempt++) {
        $observed = Invoke-LabDevice -ComputerName 'PS1-DEV' -Credential $Credential -ArgumentList $marker -ScriptBlock {
            param($path)
            if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw }
            # An absent marker is expected while the client is processing the request.
        }
        if ($observed) { $record.marker = $observed | ConvertFrom-Json; break }
        Write-Host "Waiting for the client marker ($attempt)"
        Start-Sleep -Seconds 3
    }
    $record.verified = $record.marker.nonce -eq $nonce -and $record.marker.sid -eq 'S-1-5-18'
    if (-not $record.verified) { throw 'No matching SYSTEM execution marker was observed.' }
}
finally {
    try {
        Invoke-LabDevice -ComputerName 'PS1-DEV' -Credential $Credential -ArgumentList $marker -ScriptBlock {
            param($path)
            if ($path -notmatch '^C:\\ProgramData\\CMBP-PermissionResearch\\[a-f0-9]{32}\.json$') { throw 'Invalid marker cleanup path' }
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
            # A failed deployment may never have created the marker.
        }
    }
    finally {
        Remove-LabResources $context
        $record.cleanupComplete = $context.Resources.Count -eq 0
        $record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
    }
}
$record | ConvertTo-Json -Depth 10
