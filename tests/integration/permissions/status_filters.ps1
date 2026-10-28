<#
.SYNOPSIS
Test site-server execution through SCCM status-filter permissions.
.DESCRIPTION
Each rule matches only this test's unique application component and message ID.
Its command writes a harmless identity marker. A matching synthetic status
message triggers it; no SCCM client, application, or device deployment is used.
Temporary rules, users, roles, and markers are removed in finally blocks.
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
.\tests\integration\permissions\status_filters.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-status-filters"
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory,
      [ValidateSet('basic','role','bridge','scope')][string] $Selection = 'basic')
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
$cases = @(
    @{ Name = 'Site Read control'; Mask = 1; Scope = 'SMS00ALL' },
    @{ Name = 'Site Modify'; Mask = 3; Scope = 'SMS00ALL' },
    @{ Name = 'Manage status filters with Read'; Mask = 65537; Scope = 'SMS00ALL' },
    @{ Name = 'Manage status filters alone'; Mask = 65536; Scope = 'SMS00ALL' },
    @{ Name = 'Manage status filters Default scope'; Mask = 65537; Scope = 'SMS00UNA' }
)
if ($Selection -eq 'scope') {
    $cases = @(@{ Name = 'Manage status filters outside site scope with separate Read'; Mask = 65536; Scope = 'PS100046'; SeparateRead = $true })
}
elseif ($Selection -eq 'bridge') {
    $cases = @(@{ Name = 'Status filter to site database and provider'; Mask = 65537; Scope = 'SMS00UNA'; Bridge = $true })
}
elseif ($Selection -eq 'role') {
    $cases = @(@{ Name = 'Role Modify to direct site-server execution'; Mask = 65537; Scope = 'SMS00UNA'; EditRole = $true })
}
try {
    foreach ($case in $cases) {
        Write-Host "Testing $($case.Name)"
        $nonce = [guid]::NewGuid().ToString('N')
        $component = 'CMBP_PERMISSION_' + $nonce
        $marker = 'C:\ProgramData\CMBP-PermissionResearch\' + $nonce + '.json'
        $record = [ordered]@{ name = $case.Name; siteMask = $case.Mask; scope = $case.Scope; created = $false; marker = $null }
        $baseCount = $context.Resources.Count
        try {
            $initialOperations = @(@{ ObjectTypeID = 6; GrantedOperations = $case.Mask })
            if ($case.EditRole) { $initialOperations = @(@{ ObjectTypeID = 27; GrantedOperations = 2 }) }
            $role = New-LabRole $context $initialOperations $case.Name
            $actor = New-LabUser $context
            $collections = @('SMS00001')
            if ($case.EditRole) {
                $narrow = New-LabCollection $context 'empty role-edit collection boundary'
                $collections = @($narrow.CollectionID)
            }
            $assignments = @(@{ Role = $role.RoleID; Collections = $collections; Scopes = @($case.Scope) })
            if ($case.SeparateRead) {
                $readRole = New-LabRole $context @(@{ ObjectTypeID = 6; GrantedOperations = 1 }) 'separate Default-scope site Read'
                $assignments += @{ Role = $readRole.RoleID; Collections = $collections; Scopes = @('SMS00UNA') }
            }
            $null = New-LabAdmin $context $actor $assignments
            $actorScope = New-LabScope $actor.Credential
            if ($case.EditRole) {
                $changedRole = Get-LabObject $actorScope $role.Path.RelativePath
                $changedRole.Operations = ConvertTo-LabOperations $actorScope @(@{ ObjectTypeID = 6; GrantedOperations = 65537 })
                $null = $changedRole.Put()
                $saved = Get-LabObject $context.Scope $role.Path.RelativePath
                $record.changedOperations = @($saved.Operations | ForEach-Object { @{ ObjectTypeID = $_.ObjectTypeID; GrantedOperations = $_.GrantedOperations } })
                $record.assignedCollections = $collections
                $actorScope = New-LabScope $actor.Credential
            }
            $code = @'
$i=[Security.Principal.WindowsIdentity]::GetCurrent()
$j=@{nonce='NONCE';computer=$env:COMPUTERNAME;identity=$i.Name;sid=$i.User.Value;isAdministrator=[Security.Principal.WindowsPrincipal]::new($i).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}|ConvertTo-Json -Compress
$null=[IO.Directory]::CreateDirectory('C:\ProgramData\CMBP-PermissionResearch')
[IO.File]::WriteAllText('MARKER',$j)
'@
            $payload = $code.Replace('NONCE',$nonce).Replace('MARKER',$marker)
            if ($case.Bridge) {
                $remoteCommand = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
                $bridgeCode = @'
foreach ($server in @('ps1-db.mayyhem.com','ps1-sms.mayyhem.com')) {
    try {
        $result = Invoke-WmiMethod -ComputerName $server -Namespace root\cimv2 -Class Win32_Process -Name Create -ArgumentList 'REMOTE_COMMAND' -ErrorAction Stop
        Write-Output ("Remote marker request on $server returned " + $result.ReturnValue)
    }
    catch { Write-Warning ("Remote marker request failed on $server`: " + $_.Exception.Message) }
}
'@
                $payload += [Environment]::NewLine + $bridgeCode.Replace('REMOTE_COMMAND',$remoteCommand)
            }
            $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
            $ruleName = $context.RunTag + ' ' + $nonce
            $command = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded"
            try {
                $created = Invoke-LabConsole $Credential $actor.Credential {
                    param($name, $component, $command)
                    $rule = New-CMStatusFilterRule -SiteCode 'PS1' -Name $name -ComponentName $component -MessageId 65002 -RunProgram $true -ProgramPath $command -ForwardToStatusSummarizer $true -ProcessLowerPriorityRule $true
                    [pscustomobject]@{ Name = $name; Path = $rule.SmsProviderObjectPath; Values = $rule.Values }
                } @($ruleName, $component, $command)
                Add-LabResource $context 'StatusRule' $ruleName 'SiteCode' 'PS1'
                $record.created = $created.Values -contains "Component=$component"
                $record.actor = $actor.Name
                $record.rulePath = $created.Path
            }
            catch {
                $record.error = Get-LabError $_
                Write-Warning ($record.error | ConvertTo-Json -Compress)
            }
            if ($record.created) {
                # The application context determines the status message component.
                # Using our nonce prevents ordinary lab events from matching.
                $status = [System.Management.ManagementClass]::new($actorScope, [System.Management.ManagementPath]::new('SMS_StatusMessage'), $null)
                $parameters = $status.GetMethodParameters('RaiseRawStatusMsg')
                $parameters.MessageID = [uint32]65002
                $parameters.MessageType = [uint32]256
                $parameters.ModuleName = 'SMS Server'
                $parameters.InsStrings = [string[]]@('Harmless ConfigManBearPig permission marker')
                $options = [System.Management.InvokeMethodOptions]::new()
                $options.Context.Add('ApplicationName', $component)
                $options.Context.Add('MachineName', 'ps1-dev.mayyhem.com')
                for ($attempt = 0; $attempt -lt 24; $attempt++) {
                    if ($attempt % 6 -eq 0) {
                        $output = $status.InvokeMethod('RaiseRawStatusMsg', $parameters, $options)
                        $record.triggerReturn = $output.ReturnValue
                        Write-Host "Raised the uniquely matched event ($attempt)"
                    }
                    # Repeated events allow the site-control change time to load.
                    $observed = Invoke-Command -ComputerName 'ps1-pss.mayyhem.com' -Credential $Credential -ArgumentList $marker -ScriptBlock {
                        param($path)
                        if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw }
                        # No file means the status manager has not executed the rule.
                    }
                    if ($observed) { $record.marker = $observed | ConvertFrom-Json; break }
                    Write-Host "Waiting for direct site-server execution ($attempt)"
                    Start-Sleep -Seconds 3
                }
            }
            $record.verified = $record.marker.nonce -eq $nonce -and $record.marker.sid -eq 'S-1-5-18' -and $record.marker.computer -eq 'PS1-PSS'
            if ($case.Bridge -and $record.verified) {
                $record.remoteMarkers = @()
                $siteComputerSID = [Security.Principal.NTAccount]::new('MAYYHEM\PS1-PSS$').Translate([Security.Principal.SecurityIdentifier]).Value
                $record.expectedRemoteIdentity = $siteComputerSID
                foreach ($server in @('ps1-db.mayyhem.com','ps1-sms.mayyhem.com')) {
                    $remoteMarker = $null
                    for ($poll = 0; $poll -lt 12; $poll++) {
                        $observed = Invoke-LabDevice -ComputerName $server -Credential $Credential -ArgumentList $marker -ScriptBlock {
                            param($path)
                            if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw }
                            # The outbound WMI-created process may still be starting.
                        }
                        if ($observed) { $remoteMarker = $observed | ConvertFrom-Json; break }
                        Write-Host "Waiting for site-computer access to $server ($poll)"
                        Start-Sleep -Seconds 2
                    }
                    $record.remoteMarkers += @{ server = $server; marker = $remoteMarker; verified = ($remoteMarker.nonce -eq $nonce -and $remoteMarker.sid -eq $siteComputerSID -and $remoteMarker.isAdministrator) }
                }
            }
            if ($record.verified) { Write-Host 'Direct site-server SYSTEM execution confirmed.' }
            elseif ($record.created) { Write-Warning 'Rule creation succeeded, but execution remains unconfirmed.' }
            else { Write-Host 'Rule creation was rejected.' }
        }
        finally {
            Remove-LabResources $context -KeepFirst $baseCount
            Invoke-Command -ComputerName 'ps1-pss.mayyhem.com' -Credential $Credential -ArgumentList $marker -ScriptBlock {
                param($path)
                if ($path -notmatch '^C:\\ProgramData\\CMBP-PermissionResearch\\[a-f0-9]{32}\.json$') { throw 'Invalid marker cleanup path' }
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                # Rejected rule creation leaves no marker.
            }
            if ($case.Bridge) {
                foreach ($server in @('ps1-db.mayyhem.com','ps1-sms.mayyhem.com')) {
                    Invoke-LabDevice -ComputerName $server -Credential $Credential -ArgumentList $marker -ScriptBlock {
                        param($path)
                        if ($path -notmatch '^C:\\ProgramData\\CMBP-PermissionResearch\\[a-f0-9]{32}\.json$') { throw 'Invalid marker cleanup path' }
                        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                        # A failed outbound request leaves no marker.
                    }
                }
            }
            $record.cleanupComplete = $context.Resources.Count -eq $baseCount
            $results.Add($record)
            $results.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
        }
    }
}
finally { Remove-LabResources $context }
