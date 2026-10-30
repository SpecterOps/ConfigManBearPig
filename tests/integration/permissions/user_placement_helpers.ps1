<#
Helpers for two-client application placement research. These are manual lab
experiments, not collector code. Loading this file does not change the lab.
#>

function New-PlacementMarker {
    $nonce = [guid]::NewGuid().ToString('N')
    $path = 'C:\Windows\Temp\cup-' + $nonce + '.jsonl'
    # Both clients use the same application and detection path. Their files are
    # separate local files. Appending lets us detect an unexpected second install.
    $body = "if(`$env:COMPUTERNAME -notin 'PS1-DEV','PS1-DP'){exit};@{nonce='$nonce';sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;computer=`$env:COMPUTERNAME;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress|Add-Content -LiteralPath '$path'"
    $command = 'powershell.exe -NoProfile -Command "' + $body + '"'
    if ($command.Length -gt 1024) { throw 'Placement marker exceeds the application command limit.' }
    Write-Verbose "Prepared two-client marker $nonce"
    return @{Nonce=$nonce;Path=$path;Command=$command}
}

function Invoke-PlacementRecipient {
    param($Context, [string]$Target, [string]$Recipient, [string]$Application,
          [ValidateSet('Retrieve','Inspect')][string]$Action='Retrieve')
    $definition = (Get-Command Invoke-UserDeploymentRecipient).Definition
    return Invoke-LabDevice -Credential $Context.Credential -ComputerName $Target -ArgumentList $definition,$Context.RunTag,$Recipient,$Application,$Action -ScriptBlock {
        param($definition,$tag,$recipient,$application,$action)
        Set-Item -Path Function:\Invoke-UserDeploymentRecipient -Value ([scriptblock]::Create($definition))
        $result = Invoke-UserDeploymentRecipient @{RunTag=$tag} $recipient $application $action
        $result | Add-Member -NotePropertyName computer -NotePropertyValue $env:COMPUTERNAME
        $result
    }
}

function Read-PlacementClient {
    param($Context, [string]$Target, $Marker, [string]$RecipientSID, [string]$Application)
    return Invoke-LabDevice -Credential $Context.Credential -ComputerName $Target -ArgumentList $Marker.Path,$Marker.Nonce,$RecipientSID,$Application -ScriptBlock {
        param($path,$nonce,$sid,$application)
        $ErrorActionPreference='Stop'
        $markers=@()
        if (Test-Path -LiteralPath $path) {
            foreach ($line in @(Get-Content -LiteralPath $path)) {
                if (-not $line.Trim()) { continue } # An empty append is not a marker.
                $marker=$line | ConvertFrom-Json
                if ($marker.nonce -ne $nonce) { throw 'Unexpected nonce in placement marker.' }
                $markers+=$marker
            }
        }
        # No file means the particular install command has not been observed.
        $namespaces=@('root\ccm\Policy\Machine\ActualConfig')
        $userNamespace='root\ccm\Policy\'+$sid.Replace('-','_')+'\ActualConfig'
        $userPolicyNamespacePresent=$false
        $policyRoot=@(Get-WmiObject -Namespace root\ccm\Policy -Class __NAMESPACE)
        if ($policyRoot.Name -contains $sid.Replace('-','_')) {
            $namespaces+=$userNamespace
            $userPolicyNamespacePresent=$true
        }
        # A recipient who never logged on may have no user-policy namespace.
        $assignments=@()
        foreach ($namespace in $namespaces) {
            $assignments+=@(Get-WmiObject -Namespace $namespace -Class CCM_ApplicationCIAssignment |
                Where-Object {$_.AssignmentName -like ('*'+$application+'*')} |
                Select-Object AssignmentID,AssignmentName,AssignmentIsMachine,StartTime,EnforcementDeadline)
        }
        [pscustomobject]@{
            computer=$env:COMPUTERNAME;observedUTC=[DateTime]::UtcNow.ToString('o')
            markers=$markers;markerCount=$markers.Count;assignments=$assignments
            recipientProfilePresent=@(Get-WmiObject Win32_UserProfile | Where-Object SID -eq $sid).Count -ne 0
            recipientUserPolicyNamespacePresent=$userPolicyNamespacePresent
            sessions=@(quser 2>&1 | ForEach-Object {$_ | Out-String})
        }
    }
}

function Request-PlacementPolicy {
    param($Context, [string]$Target, [string]$Recipient, [string]$Application,
          [ValidateSet('User','Machine')][string]$Kind)
    if ($Kind -eq 'User') {
        $result=Invoke-PlacementRecipient $Context $Target $Recipient $Application Retrieve
        if ($result.error) { throw ('Recipient policy request failed: '+$result.error) }
        Write-Verbose "Recipient requested user policy on $Target"
        return $result
    }
    Write-Verbose "Setup administrator accelerates ordinary machine policy on $Target"
    # This is test acceleration, not evidence that the restricted author has
    # Notify Resource or local administrator access to the receiving computer.
    return Invoke-LabDevice -Credential $Context.Credential -ComputerName $Target -ScriptBlock {
        $results=@()
        foreach ($schedule in @('{00000000-0000-0000-0000-000000000021}','{00000000-0000-0000-0000-000000000022}')) {
            $results+=Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList $schedule |
                Select-Object ReturnValue
        }
        [pscustomobject]@{computer=$env:COMPUTERNAME;identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;kind='setup administrator machine-policy acceleration';utc=[DateTime]::UtcNow.ToString('o');requests=$results}
    }
}

function Wait-Placement {
    param($Context, $Marker, [string]$Recipient, [string]$RecipientSID,
          [string]$Application, [string[]]$Targets, [string[]]$ExpectedComputers,
          [ValidateSet('User','Machine')][string]$PolicyKind='User', [int]$Seconds=180)
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $nextRequest=0
    $requests=[Collections.Generic.List[object]]::new()
    do {
        if ($watch.Elapsed.TotalSeconds -ge $nextRequest) {
            foreach ($target in $Targets) { $requests.Add((Request-PlacementPolicy $Context $target $Recipient $Application $PolicyKind)) }
            $nextRequest=$watch.Elapsed.TotalSeconds+25
        }
        $clients=@(foreach ($target in $Targets) {Read-PlacementClient $Context $target $Marker $RecipientSID $Application})
        $satisfied=$ExpectedComputers.Count -gt 0
        foreach ($computer in $ExpectedComputers) {
            if (@($clients | Where-Object {$_.computer -eq $computer -and $_.markerCount -gt 0}).Count -ne 1) { $satisfied=$false }
            # Other clients are negative controls and do not satisfy this target.
        }
        if ($satisfied) { break }
        Write-Host ('Waiting for '+$Application+': '+(($clients|ForEach-Object {$_.computer+'='+$_.markerCount}) -join ', '))
        Start-Sleep -Seconds 5
    } while ($watch.Elapsed.TotalSeconds -lt $Seconds)
    return @{clients=$clients;requests=@($requests.ToArray());elapsedSeconds=[math]::Round($watch.Elapsed.TotalSeconds,2);expectedObserved=$satisfied}
}

function Set-PlacementPrimaryRequirement {
    param($Context, [string]$Application)
    # The built-in global condition is read during setup. This experiment tests
    # where the requirement allows execution, not the rights to author a rule.
    # The restricted actor still authors the application and its deployment.
    return Invoke-LabConsole $Context.Credential $Context.Credential {
        param($name)
        $condition=Get-CMGlobalCondition -Name 'Primary device' -DisableWildcardHandling
        if (-not $condition) { throw 'Setup could not read the built-in Primary device condition.' }
        $rule=New-CMRequirementRuleBooleanValue -InputObject $condition -Value $true
        if (-not $rule) { throw 'Setup could not construct the Primary device requirement.' }
        Set-CMScriptDeploymentType -ApplicationName $name -DeploymentTypeName 'Harmless identity marker' -AddRequirement $rule -Force
        $application=Get-CMApplication -Name $name -DisableWildcardHandling
        $definition=[xml]$application.SDMPackageXML
        $rules=@($definition.SelectNodes("//*[local-name()='Rule']") | Where-Object {$_.OuterXml -match 'PrimaryDevice'} | ForEach-Object OuterXml)
        if (-not $rules.Count) { throw 'The saved application does not contain the expected Primary Device rule.' }
        [pscustomobject]@{hasPrimaryDeviceRequirement=$true;rules=$rules;addedBySetupAdministrator=$true}
    } @($Application)
}

function Set-PlacementAffinity {
    param($Context, [string]$User, [uint32]$ResourceID)
    $previous=@(Get-LabObjects $Context.Scope "SELECT * FROM SMS_UserMachineRelationship WHERE ResourceID=$ResourceID AND UniqueUserName='$($User.Replace('\','\\'))'")
    if (@($previous | Where-Object {$_.Types -contains 1}).Count) { throw 'Refusing to replace an existing primary-device association.' }
    Write-Verbose "Adding an owned primary association for $User / $ResourceID"
    $class=[Management.ManagementClass]::new($Context.Scope,[Management.ManagementPath]::new('SMS_UserMachineRelationship'),$null)
    $parameters=$class.GetMethodParameters('CreateRelationship')
    $parameters.MachineResourceId=$ResourceID;$parameters.UserAccountName=$User
    $parameters.SourceId=[uint32]2;$parameters.TypeId=[uint32]1
    $output=$class.InvokeMethod('CreateRelationship',$parameters,$null)
    if ($output.ReturnValue -ne 0) { throw 'Creating the owned primary-device association failed.' }
    # Record which parts existed so cleanup preserves an original usage link.
    $entry=@{user=$User;resourceID=$ResourceID;originalRelationshipExists=$previous.Count -gt 0;originalSources=@($previous | ForEach-Object Sources);originalTypes=@($previous | ForEach-Object Types)}
    # Track cleanup before writing additional evidence. A failed evidence write
    # must still leave the association available to the finally cleanup block.
    $Context.PlacementAffinities.Add($entry)
    Save-PlacementState $Context
    $baselinePath=Join-Path $Context.OutputDirectory 'affinity-baselines.json'
    $baseline=@()
    if (Test-Path -LiteralPath $baselinePath) { $baseline=@(Get-Content -LiteralPath $baselinePath -Raw|ConvertFrom-Json) }
    # Unlike the cleanup journal, this keeps the original values after cleanup
    # so another observer can check that no temporary primary type/source remains.
    $baseline+=$entry
    ConvertTo-Json -InputObject $baseline -Depth 6|Set-Content -LiteralPath $baselinePath -Encoding UTF8
    return @(Get-LabObjects $Context.Scope "SELECT * FROM SMS_UserMachineRelationship WHERE ResourceID=$ResourceID AND UniqueUserName='$($User.Replace('\','\\'))'" |
        ForEach-Object {[pscustomobject]@{user=$_.UniqueUserName;resourceID=$_.ResourceID;computer=$_.ResourceName;active=$_.IsActive;types=$_.Types;sources=$_.Sources}})
}

function Save-PlacementState {
    param($Context)
    @{runTag=$Context.RunTag;affinities=@($Context.PlacementAffinities.ToArray())} |
        ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $Context.OutputDirectory 'placement-affinities.json') -Encoding UTF8
}

function Remove-PlacementAffinities {
    param($Context)
    foreach ($entry in @($Context.PlacementAffinities.ToArray())) {
        $rows=@(Get-LabObjects $Context.Scope "SELECT * FROM SMS_UserMachineRelationship WHERE ResourceID=$($entry.resourceID) AND UniqueUserName='$($entry.user.Replace('\','\\'))'")
        foreach ($row in $rows) {
            if ($entry.originalTypes -notcontains 1 -and $row.Types -contains 1) {
                $parameters=$row.GetMethodParameters('RemoveType');$parameters.TypeId=[uint32]1
                $output=$row.InvokeMethod('RemoveType',$parameters,$null)
                if ($output.ReturnValue -ne 0) { throw 'Owned primary-device type could not be removed.' }
            }
            # An original primary relationship was refused before setup.
            if ($entry.originalSources -notcontains 2 -and $row.Sources -contains 2) {
                $parameters=$row.GetMethodParameters('RemoveSource');$parameters.SourceId=[uint32]2
                $output=$row.InvokeMethod('RemoveSource',$parameters,$null)
                if ($output.ReturnValue -ne 0) { throw 'Owned affinity source could not be removed.' }
            }
            # The provider can clear source entries when the last primary type
            # is removed. Restore saved sources explicitly instead of assuming
            # RemoveType/RemoveSource preserve them.
            $row.Get()
            foreach ($source in $entry.originalSources) {
                if ($row.Sources -notcontains $source) {
                    $parameters=$row.GetMethodParameters('AddSource');$parameters.SourceId=[uint32]$source
                    $output=$row.InvokeMethod('AddSource',$parameters,$null)
                    if ($output.ReturnValue -ne 0) { throw 'Restoring an original affinity source failed.' }
                    Write-Verbose "Restored original affinity source $source"
                    $row.Get()
                }
                # Sources still present need no update.
            }
            if (-not $entry.originalRelationshipExists -and -not @($row.Types).Count -and -not @($row.Sources).Count) {
                $row.Delete()
                Write-Verbose 'Removed the empty association created by setup.'
            }
            # Existing relationships remain, including an originally empty one.
        }
        $restored=@(Get-LabObjects $Context.Scope "SELECT * FROM SMS_UserMachineRelationship WHERE ResourceID=$($entry.resourceID) AND UniqueUserName='$($entry.user.Replace('\','\\'))'")
        $actualTypes=(@($restored|ForEach-Object Types|Sort-Object -Unique) -join ',')
        $actualSources=(@($restored|ForEach-Object Sources|Sort-Object -Unique) -join ',')
        if ($actualTypes -ne (@($entry.originalTypes|Sort-Object -Unique) -join ',') -or $actualSources -ne (@($entry.originalSources|Sort-Object -Unique) -join ',')) {
            throw 'Primary association cleanup did not restore the original types and sources.'
        }
        Write-Verbose 'Verified original affinity types and sources after cleanup.'
        $Context.PlacementAffinities.Remove($entry) | Out-Null
        Save-PlacementState $Context
    }
}
