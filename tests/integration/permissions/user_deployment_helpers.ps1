<#
Helpers for the user-versus-device deployment experiment. Loading this file does
not contact SCCM or change the lab. Lab.psm1 owns temporary SCCM objects/accounts.
#>

function New-UserDeploymentMarker {
    param([string]$Target = 'PS1-DEV')
    $nonce = [guid]::NewGuid().ToString('N')
    $path = 'C:\Windows\Temp\cud-' + $nonce + '.json'
    # The payload uses short names to fit SCCM's 1024-character command limit.
    # It writes only an identity marker, and does nothing on other lab devices.
    $code = "if(`$env:COMPUTERNAME -ne '$Target'){exit 0};@{nonce='$nonce';sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}|ConvertTo-Json|Set-Content -LiteralPath '$path'"
    $command = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    if ($command.Length -gt 1024) { throw 'Identity marker exceeds the SCCM command limit.' }
    Write-Verbose "Prepared marker $nonce for $Target"
    return @{Nonce = $nonce; Path = $path; Command = $command}
}

function New-UserDeploymentCollection {
    param($Context, [string]$Recipient, [uint32]$ResourceID)
    $collection = New-LabInstance $Context.Scope 'SMS_Collection'
    $collection.Name = $Context.RunTag + ' one user'
    $collection.Comment = 'Temporary user-targeted identity marker experiment'
    $collection.CollectionType = 1
    $collection.RefreshType = 1
    $collection.LimitToCollectionID = 'SMS00002'
    $path = $collection.Put()
    Add-LabResource $Context 'WMI' $path.RelativePath 'Name' $collection.Name
    $collection = Get-LabObject $Context.Scope $path.RelativePath
    $rule = New-LabInstance $Context.Scope 'SMS_CollectionRuleDirect'
    $rule.ResourceClassName = 'SMS_R_User'
    $rule.ResourceID = $ResourceID
    $rule.RuleName = $Recipient
    $parameters = $collection.GetMethodParameters('AddMembershipRule')
    $parameters.collectionRule = $rule
    $result = $collection.InvokeMethod('AddMembershipRule', $parameters, $null)
    if ($result.ReturnValue -ne 0) { throw "User membership failed: $($result.ReturnValue)" }
    $null = $collection.InvokeMethod('RequestRefresh', $null, $null)
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $members = @(Get-LabObjects $Context.Scope "SELECT ResourceID FROM SMS_FullCollectionMembership WHERE CollectionID='$($collection.CollectionID)' AND ResourceID=$ResourceID")
        if ($members.Count -eq 1) { return $collection }
        Write-Verbose 'Waiting for the user collection to evaluate.'
        Start-Sleep -Seconds 2
    }
    throw 'The temporary user collection never acquired its intended recipient.'
}

function New-UserDeploymentActor {
    param($Context, [uint32]$ApplicationMask, [uint32]$CollectionMask,
          [string]$CollectionID, [string]$Label, [switch]$GlobalRead)
    $actor = New-LabUser $Context
    $operations = @(@{ObjectTypeID = 6; GrantedOperations = 1})
    if ($ApplicationMask) { $operations += @{ObjectTypeID = 31; GrantedOperations = $ApplicationMask} }
    else { Write-Verbose 'This negative control has no application permissions.' }
    if ($CollectionMask) { $operations += @{ObjectTypeID = 1; GrantedOperations = $CollectionMask} }
    else { Write-Verbose 'The editor has no collection actions.' }
    $role = New-LabRole $Context $operations $Label
    $assignments = @(@{Role = $role.RoleID; Collections = @($CollectionID); Scopes = @('SMS00ALL')})
    if ($GlobalRead) {
        $readRole = New-LabRole $Context @(@{ObjectTypeID = 1; GrantedOperations = 4097}) 'global read control'
        $assignments += @{Role = $readRole.RoleID; Collections = @('SMS00001','SMS00002'); Scopes = @('SMS00ALL')}
    }
    else { Write-Verbose 'No separate global Read assignment is added.' }
    $null = New-LabAdmin $Context $actor $assignments
    return $actor
}

function New-UserDeploymentApplication {
    param($Context, [pscredential]$ActorCredential, [string]$Name,
          [string]$Behavior, $Marker, [string]$Command = '')
    $created = Invoke-LabConsole $Context.Credential $ActorCredential {
        param($name)
        $application = New-CMApplication -Name $name -Description 'Harmless user/device deployment research'
        [pscustomobject]@{ID = $application.CI_ID; UniqueID = $application.CI_UniqueID}
    } @($Name)
    Add-LabResource $Context 'Application' $Name 'Name' $Name
    if (-not $Command) { $Command = $Marker.Command }
    else { Write-Verbose 'Using the harmless initial command before a restricted editor changes it.' }
    $null = Invoke-LabConsole $Context.Credential $ActorCredential {
        param($name, $command, $path, $behavior)
        $clause = New-CMDetectionClauseFile -FileName ([IO.Path]::GetFileName($path)) -Path 'C:\Windows\Temp' -Existence -Is64Bit
        $logon = 'WhetherOrNotUserLoggedOn'
        if ($behavior -eq 'InstallForUser') { $logon = 'OnlyWhenUserLoggedOn' }
        else { Write-Verbose 'SYSTEM installation may run without a logged-on user.' }
        Add-CMScriptDeploymentType -ApplicationName $name -DeploymentTypeName 'Harmless identity marker' -InstallCommand $command -AddDetectionClause $clause -InstallationBehaviorType $behavior -LogonRequirementType $logon -UserInteractionMode Hidden -EstimatedRuntimeMins 1 -MaximumRuntimeMins 15 -Force
    } @($Name, $Command, $Marker.Path, $Behavior)
    return @{ID = $created.ID; UniqueID = $created.UniqueID; Name = $Name}
}

function New-UserDeploymentAssignment {
    param($Context, [pscredential]$ActorCredential, [string]$Name,
          [string]$CollectionID, [string]$Purpose = 'Required',
          [int]$DeadlineSeconds = -300, [bool]$PreDeploy = $false)
    $assignment = Invoke-LabConsole $Context.Credential $ActorCredential {
        param($name, $collectionID, $purpose, $seconds, $preDeploy)
        $settings = @{Name = $name; CollectionId = $collectionID; DeployAction = 'Install';
            DeployPurpose = $purpose; AvailableDateTime = (Get-Date).AddMinutes(-5);
            PreDeploy = $preDeploy; UserNotification = 'DisplayAll'}
        if ($purpose -eq 'Required') {
            $settings.DeadlineDateTime = (Get-Date).AddSeconds($seconds)
            $settings.OverrideServiceWindow = $true
            $settings.RebootOutsideServiceWindow = $false
        }
        else { Write-Verbose 'Available deployments have no enforcement deadline.' }
        $created = New-CMApplicationDeployment @settings
        [pscustomobject]@{ID = $created.AssignmentID; Name = $created.AssignmentName}
    } @($Name, $CollectionID, $Purpose, $DeadlineSeconds, $PreDeploy)
    if (-not $assignment.ID) { throw 'No assignment ID was returned; deployment is unconfirmed.' }
    Add-LabResource $Context 'WMI' ('SMS_ApplicationAssignment.AssignmentID=' + $assignment.ID) 'AssignmentName' $assignment.Name
    $saved = Get-LabObject $Context.Scope ('SMS_ApplicationAssignment.AssignmentID=' + $assignment.ID)
    $deadlineUTC = $null
    if ($saved.EnforcementDeadline) {
        if (-not $saved.UseGMTTimes) { throw 'The deadline comparison expects the lab deployment to use UTC.' }
        Write-Verbose 'Reading the actual UTC deadline saved by the provider.'
        $deadlineUTC = [DateTime]::ParseExact($saved.EnforcementDeadline.Substring(0,14),'yyyyMMddHHmmss',
            [Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime().ToString('o')
    }
    else { Write-Verbose 'This available deployment has no enforcement deadline.' }
    return @{ID = $assignment.ID; Name = $assignment.Name; DeadlineUTC = $deadlineUTC}
}

function Get-UserDeploymentDefinition {
    param($Context, [string]$Name)
    return Invoke-LabConsole $Context.Credential $Context.Credential {
        param($name)
        $application = Get-CMApplication -Name $name -DisableWildcardHandling
        $definition = [xml]$application.SDMPackageXML
        [pscustomobject]@{Name = $name; Contexts = @($definition.SelectNodes("//*[local-name()='ExecutionContext']") | ForEach-Object InnerText);
            Version = $application.SDMPackageVersion; UniqueID = $application.CI_UniqueID}
    } @($Name)
}

function Invoke-UserDeploymentRecipient {
    param($Context, [string]$Recipient, [string]$ApplicationName,
          [ValidateSet('Retrieve','RetrieveMachine','Inspect','SoftwareCenter')][string]$Action,
          [string]$ApplicationID='')
    # InteractiveToken uses the already logged-on lab user. It needs no password
    # and does not grant the user administrative rights. This simulates a normal
    # client policy request or Software Center installation by the recipient.
    $taskName = $Context.RunTag + '-recipient-' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $resultPath = 'C:\Windows\Temp\' + $taskName + '.json'
    $body = @'
$ErrorActionPreference='Stop'
$result=[ordered]@{identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;action='ACTION';utc=[DateTime]::UtcNow.ToString('o')}
try {
    if('ACTION' -eq 'Retrieve') {
        # ClientSDK exposes the supported user policy request. The lower-level
        # SMS_Client.TriggerSchedule method requires administrative access here.
        $r=Invoke-WmiMethod -Namespace root\ccm\ClientSDK -Class CCM_ClientUtilities -Name GetUserPolicy
        $result.policyRequest=@{returnValue=$r.ReturnValue}
    }
    elseif('ACTION' -eq 'RetrieveMachine') {
        $r=Invoke-WmiMethod -Namespace root\ccm\ClientSDK -Class CCM_ClientUtilities -Name GetMachinePolicy
        $result.policyRequest=@{returnValue=$r.ReturnValue}
    }
    elseif('ACTION' -eq 'SoftwareCenter') {
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
        $process=Start-Process -FilePath 'C:\Windows\CCM\ClientUX\SCClient.exe' -ArgumentList 'softwarecenter:SoftwareID=APPLICATIONID' -WindowStyle Hidden -PassThru
        $result.softwareCenterProcess=$process.Id
        for($attempt=0;$attempt -lt 45;$attempt++) {
            $roots=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,[Windows.Automation.Condition]::TrueCondition)
            foreach($root in $roots) {
                if($root.Current.Name -eq 'Software Center') {
                    $names=@($root.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition) | ForEach-Object {$_.Current.Name})
                    $buttons=@($root.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ControlTypeProperty,[Windows.Automation.ControlType]::Button)))
                    $result.softwareCenter=@{names=$names;buttons=@($buttons | ForEach-Object {$_.Current.Name})}
                    if($names -contains 'APPLICATION') {
                        $button=@($buttons | Where-Object {$_.Current.Name -eq 'Install' -and $_.Current.IsEnabled})
                        if($button.Count -eq 1) {
                            $button[0].GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke()
                            $result.install=@{invoked=$true;application='APPLICATION'}
                            break
                        }
                    }
                }
            }
            if($result.install){break}
            Start-Sleep -Seconds 1
        }
        if(-not $result.install){throw 'Software Center did not expose an enabled Install button for the exact temporary application.'}
    }
    # Inspect deliberately does not force policy retrieval.
    if('ACTION' -eq 'Inspect') {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $result.groupSIDs=@($identity.Groups | ForEach-Object Value)
        $result.isWindowsAdministrator=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $apps=@(Get-WmiObject -Namespace root\ccm\ClientSDK -Class CCM_Application | Where-Object Name -eq 'APPLICATION')
        $result.applications=@($apps | Select-Object Name,Id,Revision,IsMachineTarget,InstallState,EvaluationState,AllowedActions)
    }
    # A policy request returns independently of the slower application enumeration.
    # Other actions have already completed their explicit policy/UI operation.
} catch {$result.error=$_.Exception.Message}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath 'RESULT'
'@
    $body = $body.Replace('APPLICATIONID',$ApplicationID)
    $body = $body.Replace('ACTION',$Action).Replace('APPLICATION',$ApplicationName).Replace('RESULT',$resultPath)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    try {
        $principal = New-ScheduledTaskPrincipal -UserId $Recipient -LogonType Interactive -RunLevel Limited
        $taskAction = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -WindowStyle Hidden -EncodedCommand ' + $encoded)
        $null = Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $principal
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 90; $attempt++) {
            $state = Get-ScheduledTask -TaskName $taskName
            if ((Test-Path -LiteralPath $resultPath) -and $state.State -ne 'Running') {
                # Task completion closes the output file before the observer reads
                # it. File existence alone races with Set-Content's open handle.
                return Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
            }
            Write-Verbose 'Waiting for the recipient task to finish.'
            Start-Sleep -Seconds 1
        }
        $state = Get-ScheduledTaskInfo -TaskName $taskName
        throw "Recipient action did not finish: $($state.LastTaskResult)"
    }
    finally {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            if ($task.State -eq 'Running') {
                Write-Warning 'Stopping an unfinished recipient observation task before removing it.'
                Stop-ScheduledTask -TaskName $taskName
            }
            # A completed task has no remaining process to stop.
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        else { Write-Verbose 'No recipient task was registered.' }
        if (Test-Path -LiteralPath $resultPath) { Remove-Item -LiteralPath $resultPath }
        else { Write-Verbose 'No recipient result file was created.' }
    }
}

function Wait-UserDeploymentMarker {
    param($Marker, [int]$Seconds, $Context, [string]$Recipient,
          [string]$ApplicationName, [switch]$RefreshUserPolicy,
          [ValidateSet('Retrieve','RetrieveMachine')][string]$PolicyAction='Retrieve')
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $nextRequest = 15
    while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
        if (Test-Path -LiteralPath $Marker.Path) {
            $observed = Get-Content -LiteralPath $Marker.Path -Raw | ConvertFrom-Json
            if ($observed.nonce -ne $Marker.Nonce) { throw 'Marker nonce does not match this experiment.' }
            return @{nonce = $observed.nonce; sid = $observed.sid;
                writtenUTC = (Get-Item -LiteralPath $Marker.Path).LastWriteTimeUtc.ToString('o'); elapsedSeconds = [math]::Round($watch.Elapsed.TotalSeconds,1)}
        }
        Write-Verbose 'No execution marker yet.'
        if ($RefreshUserPolicy -and $watch.Elapsed.TotalSeconds -ge $nextRequest) {
            $request = Invoke-UserDeploymentRecipient $Context $Recipient $ApplicationName $PolicyAction
            $Context.RecipientRequests.Add($request)
            if ($request.error) { throw "Recipient policy refresh failed: $($request.error)" }
            Write-Host 'The non-administrator recipient requested policy again after site processing.'
            $nextRequest = $watch.Elapsed.TotalSeconds + 20
        }
        # Ordinary observation does not request any client action.
        Start-Sleep -Seconds 2
    }
    Write-Warning "No marker appeared during the $Seconds-second observation."
    return $null
}
