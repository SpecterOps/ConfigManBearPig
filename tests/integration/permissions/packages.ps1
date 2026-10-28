<#
.SYNOPSIS
Test package and task-sequence permissions with harmless one-device commands.
.DESCRIPTION
Creates no installation files, operating-system images, restart steps, or content.
The only command writes a marker containing the actual executing identity.
All actions use temporary restricted SCCM accounts and all objects are removed.
.PARAMETER Credential
Lab administrator used to prepare temporary objects and observe results. Tested
SCCM actions use separate temporary accounts, except full-administrator controls.
.PARAMETER OutputDirectory
Folder for result files and the cleanup journal; passwords are never saved here.
Resolve a failed cleanup before reusing its output folder.
.PARAMETER Selection
Choose a positive control, the permission comparison, or a focused scenario.
The allowed values are listed in the parameter declaration and the research report.
.PARAMETER Workload
Choose a classic Package or a TaskSequence containing only the harmless command.
.EXAMPLE
.\tests\integration\permissions\packages.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -OutputDirectory "$env:TEMP\cmbp-packages" -Workload Package -Selection control
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][pscredential] $Credential,
      [Parameter(Mandatory = $true)][string] $OutputDirectory,
      [ValidateSet('Package','TaskSequence')][string] $Workload = 'Package',
      [ValidateSet('control','permissions','author','outside','scope')][string] $Selection = 'permissions')
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Lab.psm1') -Force
$context = New-LabContext $Credential $OutputDirectory
$results = [System.Collections.Generic.List[object]]::new()
$objectType = 2
$deployMask = 16384
if ($Workload -eq 'TaskSequence') { $objectType = 20; $deployMask = 8388608 }
$cases = @(
    @{ Name = 'Read control changing command'; ObjectMask = 1; CollectionMask = 1; Modify = $true },
    @{ Name = 'Modify existing command'; ObjectMask = 3; CollectionMask = 1; Modify = $true },
    @{ Name = 'Read control deploying'; ObjectMask = 1; CollectionMask = 1; Modify = $false },
    @{ Name = 'Deploy plus object Read'; ObjectMask = 1; CollectionMask = ($deployMask -bor 1); Modify = $false },
    @{ Name = 'Deploy without object Read'; ObjectMask = 0; CollectionMask = ($deployMask -bor 1); Modify = $false }
)
if ($Selection -eq 'control') { $cases = @(@{ Name = 'Full Administrator control'; Full = $true; Modify = $false }) }
if ($Selection -eq 'author') { $cases = @(@{ Name = 'Author and deploy own command'; ObjectMask = 1027; CollectionMask = ($deployMask -bor 1); Modify = $false; Own = $true }) }
if ($Selection -eq 'outside') { $cases = @(@{ Name = 'Modify command deployed outside assigned collections'; ObjectMask = 3; CollectionMask = 0; Modify = $true; Outside = $true }) }
if ($Selection -eq 'scope') { $cases = @(@{ Name = 'Modify outside object scope with separate Read'; ObjectMask = 3; CollectionMask = 0; Modify = $true; Outside = $true; WrongScope = $true }) }
try {
    $collection = New-LabCollection $context 'one device package target'
    Add-LabCollectionDevice $context $collection 16777230
    $persistentCount = $context.Resources.Count
    foreach ($case in $cases) {
        Write-Host "Testing $Workload / $($case.Name)"
        $marker = New-LabMarker
        if ($Workload -eq 'Package') {
            # Classic programs permit only 127 command characters. whoami writes
            # the real identity as CSV, preceded by our nonce, without a script file.
            $marker.Path = 'C:\Windows\Temp\cmbp-' + $marker.Nonce.Substring(0,16) + '.txt'
            $marker.Format = 'WhoAmI'
            $marker.Command = 'cmd.exe /c "(echo ' + $marker.Nonce + '&whoami /user /fo csv /nh)>' + $marker.Path + '"'
            if ($marker.Command.Length -ge 128) { throw 'Classic package marker command exceeds 127 characters.' }
        }
        $name = $context.RunTag + ' ' + $marker.Nonce.Substring(0,16)
        $record = [ordered]@{ name = $case.Name; workload = $Workload; objectType = $objectType; objectMask = $case.ObjectMask; collectionMask = $case.CollectionMask; actionAccepted = $false; marker = $null }
        try {
            $actor = New-LabUser $context
            if ($case.Full) { $roleID = 'SMS0001R' }
            else {
                $operations = @(@{ ObjectTypeID = 6; GrantedOperations = 1 })
                if ($case.ObjectMask) { $operations += @{ ObjectTypeID = $objectType; GrantedOperations = $case.ObjectMask } }
                if ($case.CollectionMask) { $operations += @{ ObjectTypeID = 1; GrantedOperations = $case.CollectionMask } }
                $roleID = (New-LabRole $context $operations $case.Name).RoleID
            }
            $assignedCollectionID = $collection.CollectionID
            if ($case.Outside) {
                $empty = New-LabCollection $context 'empty editor collection'
                $assignedCollectionID = $empty.CollectionID
            }
            $assignments = @(@{ Role = $roleID; Collections = @($assignedCollectionID); Scopes = @('SMS00ALL') })
            if ($case.WrongScope) {
                $assignments = @(@{ Role = $roleID; Collections = @($assignedCollectionID); Scopes = @('PS100046') })
                $readRole = New-LabRole $context @(@{ ObjectTypeID = $objectType; GrantedOperations = 1 },@{ ObjectTypeID = 6; GrantedOperations = 1 }) 'separate Default-scope Read'
                $assignments += @{ Role = $readRole.RoleID; Collections = @($assignedCollectionID); Scopes = @('SMS00UNA') }
            }
            $null = New-LabAdmin $context $actor $assignments
            $record.assignedCollection = $assignedCollectionID
            $record.deploymentCollection = $collection.CollectionID
            $record.actor = $actor.Name
            $creationCredential = $Credential
            $creationScope = $context.Scope
            if ($case.Own) {
                $creationCredential = $actor.Credential
                $creationScope = New-LabScope $actor.Credential
            }
            $package = Invoke-LabConsole $Credential $creationCredential {
                param($name, $workload)
                if ($workload -eq 'Package') { $item = New-CMPackage -Name $name -Description 'Harmless permission test without content'; $null = $item.Get() }
                else { $item = New-CMTaskSequence -Name $name -CustomTaskSequence -Description 'One harmless marker command; no operating-system actions' }
                if (-not $item.PackageID) { throw 'Microsoft console did not return the new package ID.' }
                [pscustomobject]@{ ID = $item.PackageID; Name = $item.Name }
            } @($name, $Workload)
            if ($package -is [array]) { throw 'Unexpected extra console output while creating a package.' }
            Write-Host ("Created $Workload package " + $package.ID)
            $className = 'SMS_Package'
            if ($Workload -eq 'TaskSequence') { $className = 'SMS_TaskSequencePackage' }
            Add-LabResource $context 'WMI' ($className + '.PackageID="' + $package.ID + '"') 'Name' $name
            $command = $marker.Command
            if ($case.Modify) { $command = 'C:\Windows\System32\cmd.exe /c exit 0' }
            if ($Workload -eq 'Package') {
                $program = New-LabInstance $creationScope 'SMS_Program'
                $program.PackageID = $package.ID
                $program.ProgramName = 'Harmless marker'
                $program.CommandLine = $command
                $program.Duration = [uint32]15
                $program.SecuredTypeID = [uint32]2
                # Microsoft documents these independent flags: any Windows
                # platform, hidden window, administrator rights, no interaction, and a UNC path without a mapped drive.
                # No user-context, restart, logoff, or content flags are enabled.
                $program.ProgramFlags = [uint32](0x08000000 -bor 0x01000000 -bor 0x00008000 -bor 0x00002000 -bor 0x00100000)
                $program.WorkingDirectory = 'C:\Windows\System32'
                try { $null = $program.Put() }
                catch { Write-Warning ((Get-LabError $_) | ConvertTo-Json -Compress); throw }
            }
            else {
                $null = Invoke-LabConsole $Credential $creationCredential {
                    param($id, $command)
                    $step = New-CMTSStepRunCommandLine -Name 'Harmless marker' -CommandLine $command -DisableWow64Redirection
                    Add-CMTaskSequenceStep -TaskSequenceId $id -Step $step
                } @($package.ID, $command)
            }
            $deployCredential = $actor.Credential
            if ($case.Modify) { $deployCredential = $Credential }
            try {
                $deployment = Invoke-LabConsole $Credential $deployCredential {
                    param($id, $workload, $collectionID)
                    $past = (Get-Date).AddMinutes(-5)
                    $schedule = New-CMSchedule -Start ([DateTime]::UtcNow) -Nonrecurring -IsUtc
                    $past = [DateTime]'2020-01-01'
                    if ($workload -eq 'Package') {
                        $advert = New-CMPackageDeployment -PackageId $id -ProgramName 'Harmless marker' -StandardProgram -CollectionId $collectionID -DeployPurpose Required -Schedule @($schedule) -RerunBehavior AlwaysRerunProgram -AvailableDateTime $past -UseUtcForAvailableSchedule $true -SoftwareInstallation $true -SystemRestart $false
                    }
                    else {
                        $advert = New-CMTaskSequenceDeployment -TaskSequencePackageId $id -CollectionId $collectionID -DeployPurpose Required -Schedule @($schedule) -RerunBehavior AlwaysRerunProgram -AvailableDateTime $past -UseUtcForAvailableSchedule $true -SoftwareInstallation $true -SystemRestart $false -ShowTaskSequenceProgress $false
                    }
                    [pscustomobject]@{ ID = $advert.AdvertisementID; Name = $advert.AdvertisementName }
                } @($package.ID, $Workload, $collection.CollectionID)
                if (-not $deployment.ID) { throw 'The console returned no deployment ID; execution is unconfirmed.' }
                Add-LabResource $context 'WMI' ('SMS_Advertisement.AdvertisementID="' + $deployment.ID + '"') 'AdvertisementName' $deployment.Name
                if ($case.Modify) {
                    if ($Workload -eq 'Package') {
                        $actorScope = New-LabScope $actor.Credential
                        $path = 'SMS_Program.PackageID="' + $package.ID + '",ProgramName="Harmless marker"'
                        $program = Get-LabObject $actorScope $path
                        $program.CommandLine = $marker.Command
                        $null = $program.Put()
                    }
                    else {
                        $null = Invoke-LabConsole $Credential $actor.Credential {
                            param($id, $command)
                            Set-CMTSStepRunCommandLine -TaskSequenceId $id -StepName 'Harmless marker' -CommandLine $command
                        } @($package.ID, $marker.Command)
                    }
                }
                $record.actionAccepted = $true
            }
            catch {
                $record.error = Get-LabError $_
                Write-Warning ($record.error | ConvertTo-Json -Compress)
            }
            if ($record.actionAccepted) { $record.marker = Wait-LabMarker $Credential $marker }
            $record.verified = $record.marker.nonce -eq $marker.Nonce -and $record.marker.sid -eq 'S-1-5-18'
            if ($record.verified) { Write-Host "$Workload SYSTEM execution confirmed." }
            elseif ($record.actionAccepted) { Write-Warning 'Accepted action produced no SYSTEM marker.' }
            else { Write-Host 'The action was rejected.' }
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
