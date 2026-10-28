<#
.SYNOPSIS
Test configuration-item script and baseline deployment permissions on one device.
.DESCRIPTION
The discovery script writes only an identity marker and reports Compliant.
There is no remediation command or change to client settings. VBScript launches
the inline marker so the test does not depend on unsigned PowerShell file policy.
All objects, temporary users, and markers are removed.
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
.\tests\integration\permissions\configuration_items.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-ci" -Selection control
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory,
      [ValidateSet('control','permissions','author','outside')][string] $Selection = 'permissions')
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
$cases = @(
    @{ Name = 'Configuration item Read control modifying'; ObjectMask = 1; CollectionMask = 1; Modify = $true },
    @{ Name = 'Configuration item Modify'; ObjectMask = 3; CollectionMask = 1; Modify = $true },
    @{ Name = 'Configuration item Read control deploying'; ObjectMask = 1; CollectionMask = 1; Modify = $false },
    @{ Name = 'Deploy Configuration Items plus Read'; ObjectMask = 1; CollectionMask = 4194305; Modify = $false },
    @{ Name = 'Deploy Configuration Items without Read'; ObjectMask = 0; CollectionMask = 4194305; Modify = $false }
)
if ($Selection -eq 'control') { $cases = @(@{ Name = 'Full Administrator control'; Full = $true; Modify = $false }) }
if ($Selection -eq 'author') { $cases = @(@{ Name = 'Author and deploy own configuration item'; ObjectMask = 1027; CollectionMask = 4194305; Modify = $false; Own = $true }) }
if ($Selection -eq 'outside') { $cases = @(@{ Name = 'Modify configuration item deployed outside assigned collections'; ObjectMask = 3; CollectionMask = 0; Modify = $true; Outside = $true }) }
try {
    $collection = New-LabCollection $context 'one device baseline target'
    Add-LabCollectionDevice $context $collection 16777230
    $persistentCount = $context.Resources.Count
    foreach ($case in $cases) {
        Write-Host "Testing $($case.Name)"
        $marker = New-LabMarker
        $name = $context.RunTag + ' ' + $marker.Nonce.Substring(0,16)
        $ciName = $name + ' CI'
        $baselineName = $name + ' baseline'
        $record = [ordered]@{ name = $case.Name; objectMask = $case.ObjectMask; collectionMask = $case.CollectionMask; actionAccepted = $false; marker = $null }
        try {
            $actor = New-LabUser $context
            if ($case.Full) { $roleID = 'SMS0001R' }
            else {
                $operations = @(@{ ObjectTypeID = 6; GrantedOperations = 1 })
                if ($case.ObjectMask) { $operations += @{ ObjectTypeID = 11; GrantedOperations = $case.ObjectMask } }
                if ($case.CollectionMask) { $operations += @{ ObjectTypeID = 1; GrantedOperations = $case.CollectionMask } }
                $roleID = (New-LabRole $context $operations $case.Name).RoleID
            }
            $assignedCollectionID = $collection.CollectionID
            if ($case.Outside) {
                $empty = New-LabCollection $context 'empty editor collection'
                $assignedCollectionID = $empty.CollectionID
            }
            $null = New-LabAdmin $context $actor @(@{ Role = $roleID; Collections = @($assignedCollectionID); Scopes = @('SMS00ALL') })
            $record.assignedCollection = $assignedCollectionID
            $record.deploymentCollection = $collection.CollectionID
            $record.actor = $actor.Name
            $creationCredential = $Credential
            if ($case.Own) { $creationCredential = $actor.Credential }
            $ci = Invoke-LabConsole $Credential $creationCredential {
                param($name)
                $item = New-CMConfigurationItem -Name $name -CreationType WindowsOS -Description 'Harmless script discovery permission test'
                [pscustomobject]@{ ID = $item.CI_ID; Name = $item.LocalizedDisplayName }
            } @($ciName)
            Add-LabResource $context 'ConfigurationItem' $ciName 'Name' $ciName
            $discovery = 'Set shell = CreateObject("WScript.Shell")' + [Environment]::NewLine + 'result = shell.Run("' + $marker.Command + '", 0, True)' + [Environment]::NewLine + 'WScript.Echo "Compliant"'
            $initialDiscovery = $discovery
            if ($case.Modify) { $initialDiscovery = 'WScript.Echo "Compliant"' }
            $null = Invoke-LabConsole $Credential $creationCredential {
                param($id, $discovery)
                $item = Get-CMConfigurationItem -Id $id
                Add-CMComplianceSettingScript -InputObject $item -Name 'Harmless discovery' -DiscoveryScriptLanguage VBScript -DiscoveryScriptText $discovery -DataType String -RuleName 'Harmless rule' -ExpressionOperator IsEquals -ValueRule -ExpectedValue 'Compliant'
            } @($ci.ID, $initialDiscovery)
            $baseline = Invoke-LabConsole $Credential $creationCredential {
                param($name)
                $item = New-CMBaseline -Name $name -Description 'Temporary harmless permission baseline'
                [pscustomobject]@{ ID = $item.CI_ID; Name = $item.LocalizedDisplayName }
            } @($baselineName)
            Add-LabResource $context 'Baseline' $baselineName 'Name' $baselineName
            $null = Invoke-LabConsole $Credential $creationCredential {
                param($baselineID, $ciID)
                Set-CMBaseline -Id $baselineID -AddOSConfigurationItem @($ciID)
            } @($baseline.ID, $ci.ID)
            $deployCredential = $actor.Credential
            if ($case.Modify) { $deployCredential = $Credential }
            try {
                $deployment = Invoke-LabConsole $Credential $deployCredential {
                    param($id, $collectionID)
                    $schedule = New-CMSchedule -Start (Get-Date).AddMinutes(-5) -RecurCount 1 -RecurInterval Hours
                    $item = New-CMBaselineDeployment -Id $id -CollectionId $collectionID -Schedule $schedule -EnableEnforcement $false -OverrideServiceWindow $false
                    [pscustomobject]@{ ID = $item.AssignmentID; Name = $item.AssignmentName }
                } @($baseline.ID, $collection.CollectionID)
                if (-not $deployment.ID) { throw 'The console returned no baseline assignment ID; no execution is confirmed.' }
                Add-LabResource $context 'WMI' ('SMS_BaselineAssignment.AssignmentID=' + $deployment.ID) 'AssignmentName' $deployment.Name
                if ($case.Modify) {
                    $null = Invoke-LabConsole $Credential $actor.Credential {
                        param($id, $discovery)
                        $item = Get-CMConfigurationItem -Id $id
                        Set-CMComplianceSettingScript -InputObject $item -Name 'Harmless discovery' -DiscoveryScriptText $discovery
                    } @($ci.ID, $discovery)
                }
                $record.actionAccepted = $true
            }
            catch {
                $record.error = Get-LabError $_
                Write-Warning ($record.error | ConvertTo-Json -Compress)
            }
            if ($record.actionAccepted) { $record.marker = Wait-LabMarker $Credential $marker -BaselineName $baselineName }
            $record.verified = $record.marker.nonce -eq $marker.Nonce -and $record.marker.sid -eq 'S-1-5-18'
            if ($record.verified) { Write-Host 'Configuration-item discovery SYSTEM execution confirmed.' }
            elseif ($record.actionAccepted) { Write-Warning 'The accepted baseline action produced no SYSTEM marker.' }
            else { Write-Host 'The baseline action was rejected.' }
        }
        finally {
            Remove-LabResources $context -KeepFirst $persistentCount
            Remove-LabMarker $Credential $marker
            $record.cleanupComplete = $context.Resources.Count -eq $persistentCount
            $results.Add($record)
            $results.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
        }
    }
}
finally { Remove-LabResources $context }
