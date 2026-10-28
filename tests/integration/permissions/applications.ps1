<#
.SYNOPSIS
Test the permissions to change and deploy a harmless SCCM application.
.DESCRIPTION
Each case uses a fresh account and an application limited to one test device.
No software or content is installed: the command only writes an identity marker.
The setup account may ask the client to poll sooner; it never runs the marker.
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
.\tests\integration\permissions\applications.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-applications"
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory,
      [ValidateSet('control','modify','deploy','author','outside','all')][string] $Selection = 'all')
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
$cases = @(
    @{ Name = 'Application Read control'; Group = 'modify'; AppMask = 1; CollectionMask = 1; Modify = $true },
    @{ Name = 'Application Modify with Read'; Group = 'modify'; AppMask = 3; CollectionMask = 1; Modify = $true },
    @{ Name = 'Application Modify alone'; Group = 'modify'; AppMask = 2; CollectionMask = 0; Modify = $true },
    @{ Name = 'Application Read without Deploy'; Group = 'deploy'; AppMask = 1; CollectionMask = 1; Modify = $false },
    @{ Name = 'Deploy Applications plus application Read'; Group = 'deploy'; AppMask = 1; CollectionMask = 1048577; Modify = $false },
    @{ Name = 'Deploy Applications without application Read'; Group = 'deploy'; AppMask = 0; CollectionMask = 1048577; Modify = $false }
)
if ($Selection -eq 'control') { $cases = @(@{ Name = 'Full Administrator control'; Group = 'control'; AppMask = 0; CollectionMask = 0; Modify = $false; Full = $true }) }
elseif ($Selection -eq 'outside') { $cases = @(@{ Name = 'Modify application deployed outside assigned collections'; AppMask = 2; CollectionMask = 0; Modify = $true; Outside = $true }) }
elseif ($Selection -eq 'author') { $cases = @(@{ Name = 'Author and deploy own application'; Group = 'author'; AppMask = 1027; CollectionMask = 1048577; Modify = $false; Own = $true }) }
elseif ($Selection -ne 'all') { $cases = @($cases | Where-Object Group -eq $Selection) }
try {
    $collection = New-LabCollection $context 'one device application target'
    Add-LabCollectionDevice $context $collection 16777230
    $persistentCount = $context.Resources.Count
    foreach ($case in $cases) {
        Write-Host "Testing $($case.Name)"
        $markerDefinition = New-LabMarker
        $nonce = $markerDefinition.Nonce
        $marker = $markerDefinition.Path
        $name = $context.RunTag + ' ' + $nonce
        $record = [ordered]@{ name = $case.Name; applicationMask = $case.AppMask; collectionMask = $case.CollectionMask; actionAccepted = $false; marker = $null }
        try {
            $command = $markerDefinition.Command
            $actor = New-LabUser $context
            if ($case.Full) { $roleID = 'SMS0001R' }
            else {
                $operations = @(@{ ObjectTypeID = 6; GrantedOperations = 1 })
                if ($case.AppMask -ne 0) { $operations += @{ ObjectTypeID = 31; GrantedOperations = $case.AppMask } }
                if ($case.CollectionMask -ne 0) { $operations += @{ ObjectTypeID = 1; GrantedOperations = $case.CollectionMask } }
                $role = New-LabRole $context $operations $case.Name
                $roleID = $role.RoleID
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
            $null = Invoke-LabConsole $Credential $creationCredential { param($name); New-CMApplication -Name $name -Description 'Temporary harmless permission test' } @($name)
            Add-LabResource $context 'Application' $name 'Name' $name
            $initialCommand = $command
            if ($case.Modify) { $initialCommand = 'C:\Windows\System32\cmd.exe /c exit 0' }
            $null = Invoke-LabConsole $Credential $creationCredential {
                param($name, $command, $marker)
                $fileName = [IO.Path]::GetFileName($marker)
                $clause = New-CMDetectionClauseFile -FileName $fileName -Path 'C:\ProgramData\CMBP-PermissionResearch' -Existence -Is64Bit
                Add-CMScriptDeploymentType -ApplicationName $name -DeploymentTypeName 'Harmless marker' -InstallCommand $command -AddDetectionClause $clause -InstallationBehaviorType InstallForSystem -LogonRequirementType WhetherOrNotUserLoggedOn -UserInteractionMode Hidden -EstimatedRuntimeMins 1 -MaximumRuntimeMins 15 -Force
            } @($name, $initialCommand, $marker)
            $deploymentCredential = $actor.Credential
            if ($case.Modify) { $deploymentCredential = $Credential }
            $deploymentAction = {
                param($name, $collectionID)
                $past = (Get-Date).AddMinutes(-5)
                $assignment = New-CMApplicationDeployment -Name $name -CollectionId $collectionID -DeployAction Install -DeployPurpose Required -AvailableDateTime $past -DeadlineDateTime $past -OverrideServiceWindow $true -RebootOutsideServiceWindow $false -UserNotification HideAll
                [pscustomobject]@{ ID = $assignment.AssignmentID; Name = $assignment.AssignmentName }
            }
            try {
                $deployment = Invoke-LabConsole $Credential $deploymentCredential $deploymentAction @($name, $collection.CollectionID)
                if (-not $deployment.ID) { throw 'The console returned no deployment ID; no assignment or execution is confirmed.' }
                Add-LabResource $context 'WMI' ("SMS_ApplicationAssignment.AssignmentID=" + $deployment.ID) 'AssignmentName' $deployment.Name
                $record.assignmentID = $deployment.ID
                if ($case.Modify) {
                    $null = Invoke-LabConsole $Credential $actor.Credential {
                        param($name, $command)
                        Set-CMScriptDeploymentType -ApplicationName $name -DeploymentTypeName 'Harmless marker' -InstallCommand $command -Force
                    } @($name, $command)
                }
                $record.actionAccepted = $true
            }
            catch {
                $record.error = Get-LabError $_
                Write-Warning ($record.error | ConvertTo-Json -Compress)
            }
            if ($record.actionAccepted) {
                for ($attempt = 0; $attempt -lt 36; $attempt++) {
                    $observed = Invoke-LabDevice -ComputerName 'PS1-DEV' -Credential $Credential -ArgumentList $marker, $attempt -ScriptBlock {
                        param($path, $attempt)
                        if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw; return }
                        if ($attempt % 4 -eq 0) {
                            foreach ($id in @('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000121')) {
                                $null = Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList ('{'+$id+'}')
                            }
                        }
                        # Asking the client to poll accelerates normal required-deployment processing.
                    }
                    if ($observed) { $record.marker = $observed | ConvertFrom-Json; break }
                    Write-Host "Waiting for application marker ($attempt)"
                    Start-Sleep -Seconds 3
                }
            }
            $record.verified = $record.marker.nonce -eq $nonce -and $record.marker.sid -eq 'S-1-5-18'
            if ($record.verified) { Write-Host 'Application SYSTEM execution confirmed.' }
            elseif ($record.actionAccepted) { Write-Warning 'Accepted application action produced no SYSTEM marker.' }
            else { Write-Host 'Application action was rejected.' }
        }
        finally {
            Remove-LabResources $context -KeepFirst $persistentCount
            Invoke-LabDevice -ComputerName 'PS1-DEV' -Credential $Credential -ArgumentList $marker -ScriptBlock {
                param($path)
                if ($path -notmatch '^C:\\ProgramData\\CMBP-PermissionResearch\\[a-f0-9]{32}\.json$') { throw 'Invalid marker cleanup path' }
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                # Rejected application actions create no file.
            }
            $record.cleanupComplete = $context.Resources.Count -eq $persistentCount
            $results.Add($record)
            $results.ToArray() | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
        }
    }
}
finally { Remove-LabResources $context }
