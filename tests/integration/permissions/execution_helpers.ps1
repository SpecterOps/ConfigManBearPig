<#
Dot-sourced helpers for completed-deployment trigger experiments.
These functions do not start an experiment when this file is loaded.
Only Wait-InitialExecution may request privileged client actions. Later observers
only read state; every requested SCCM trigger uses the restricted actor's scope.
#>

function New-ExecutionMarker {
    param([string] $Workload)
    $marker = New-LabMarker
    if ($Workload -eq 'Package') {
        $marker.Path = 'C:\Windows\Temp\cmbp-' + $marker.Nonce.Substring(0,16) + '.txt'
        $marker.Format = 'WhoAmI'
        $marker.Command = 'cmd.exe /c "(echo ' + $marker.Nonce + '&whoami /user /fo csv /nh)>' + $marker.Path + '"'
        if ($marker.Command.Length -ge 128) { throw 'Package marker command exceeds 127 characters.' }
    }
    return $marker
}

function Read-ExecutionMarker {
    param([pscredential] $Credential, [string] $Target, $Marker)
    $text = Invoke-LabDevice -Credential $Credential -ComputerName $Target -ArgumentList $Marker.Path -ScriptBlock {
        param($path)
        if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw }
        # An absent marker is the expected result before the tested code runs.
    }
    if (-not $text) { return $null }
    if ($Marker.Format -eq 'WhoAmI') {
        $lines = @($text -split '[\r\n]+' | Where-Object { $_.Trim() })
        $identity = $lines[1] | ConvertFrom-Csv -Header Identity,SID
        return @{ nonce = $lines[0].Trim(); sid = $identity.SID; identity = $identity.Identity; computer = $Target }
    }
    return $text | ConvertFrom-Json
}

function Read-ExecutionState {
    param([pscredential] $Credential, [string] $Target, $Item)
    return Invoke-LabDevice -Credential $Credential -ComputerName $Target -ArgumentList $Item.Workload, $Item.Name, $Item.ID, $Item.AssignmentID -ScriptBlock {
        param($workload, $name, $id, $assignment)
        if ($workload -eq 'Application') {
            $item = @(Get-WmiObject -Namespace root\ccm\ClientSDK -Class CCM_Application | Where-Object Name -eq $name)
            if ($item.Count -eq 1) { return @{ installState=$item[0].InstallState; evaluationState=$item[0].EvaluationState; revision=$item[0].Revision; lastInstallTime=$item[0].LastInstallTime; lastEvalTime=$item[0].LastEvalTime } }
        }
        elseif ($workload -eq 'ConfigurationItem') {
            $item = @(Get-WmiObject -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration | Where-Object DisplayName -eq ($name+' baseline'))
            if ($item.Count -eq 1) { return @{ compliance=$item[0].LastComplianceStatus; status=$item[0].Status; version=$item[0].Version; lastEvalTime=$item[0].LastEvalTime } }
        }
        else {
            $item = @(Get-WmiObject -Namespace root\ccm\ClientSDK -Class CCM_Program | Where-Object PackageID -eq $id)
            if ($item.Count -eq 1) { return @{ lastRunStatus=$item[0].LastRunStatus; lastExitCode=$item[0].LastExitCode; lastRunTime=$item[0].LastRunTime; evaluationState=$item[0].EvaluationState; repeatRunBehavior=$item[0].RepeatRunBehavior } }
            # Completed hidden programs have persistent history even when the
            # user-facing SDK omits them and their execution log has rotated.
            $historyRoot='HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution\Execution History\System\'+$id
            $programName='Completed marker'
            if($workload -eq 'TaskSequence') { $programName='*' }
            if(Test-Path -LiteralPath $historyRoot) {
                $history=@(Get-ChildItem -LiteralPath $historyRoot | ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath } | Where-Object {$_._ProgramID -eq $programName} | Sort-Object _RunStartTime -Descending | Select-Object -First 1)
                if($history.Count -eq 1) { return @{lastRunStatus=$history[0]._State;lastExitCode=$history[0].SuccessOrFailureCode;lastRunTime=$history[0]._RunStartTime;completionSource='SCCM execution history';historyKey=$history[0].PSChildName} }
            }
            # Hidden required programs may not be listed by the user-facing SDK.
            # Require the client's explicit success event for this exact temporary
            # advertisement and package; the marker alone is not completion proof.
            $match='Raised Program Success Event for Ad:'+$assignment+', Package:'+$id+','
            $success=@(Select-String -LiteralPath 'C:\Windows\CCM\Logs\execmgr.log' -SimpleMatch $match | Select-Object -Last 1)
            if($success.Count -eq 1) { return @{lastRunStatus='Success';lastExitCode=0;completionSource='execmgr.log';completionEvent=$success[0].Line} }
        }
        # Missing client state means the initial policy has not arrived yet.
        return @{ notPresent=$true }
    }
}

function New-ExecutionWorkload {
    param($Context, [string] $Workload, $Collection, $InitialMarker, [bool] $RecurringDeployment=$false)
    $name = $Context.RunTag + ' trigger ' + $InitialMarker.Nonce.Substring(0,8)
    $item = @{ Workload=$Workload; Name=$name; ID=''; AssignmentID=''; BaselineID='' }
    if ($Workload -eq 'Application') {
        $created = Invoke-LabConsole $Context.Credential $Context.Credential {
            param($name)
            $application=New-CMApplication -Name $name -Description 'Completed deployment trigger experiment'
            [pscustomobject]@{ ID=$application.CI_ID }
        } @($name)
        Add-LabResource $Context 'Application' $name 'Name' $name
        $item.ID=$created.ID
        $null=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($name,$command,$path)
            $clause=New-CMDetectionClauseFile -FileName ([IO.Path]::GetFileName($path)) -Path 'C:\ProgramData\CMBP-PermissionResearch' -Existence -Is64Bit
            Add-CMScriptDeploymentType -ApplicationName $name -DeploymentTypeName 'Completed marker' -InstallCommand $command -AddDetectionClause $clause -InstallationBehaviorType InstallForSystem -LogonRequirementType WhetherOrNotUserLoggedOn -UserInteractionMode Hidden -MaximumRuntimeMins 15 -Force
        } @($name,$InitialMarker.Command,$InitialMarker.Path)
        $assignment=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($name,$collection)
            $past=[DateTime]'2020-01-01'
            $a=New-CMApplicationDeployment -Name $name -CollectionId $collection -DeployAction Install -DeployPurpose Required -AvailableDateTime $past -DeadlineDateTime $past -OverrideServiceWindow $true -RebootOutsideServiceWindow $false -UserNotification HideAll
            [pscustomobject]@{ ID=$a.AssignmentID; Name=$a.AssignmentName }
        } @($name,$Collection.CollectionID)
        $item.AssignmentID=$assignment.ID
        Add-LabResource $Context 'WMI' ('SMS_ApplicationAssignment.AssignmentID='+$assignment.ID) 'AssignmentName' $assignment.Name
    }
    elseif ($Workload -eq 'ConfigurationItem') {
        $created=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($name)
            $c=New-CMConfigurationItem -Name ($name+' CI') -CreationType WindowsOS
            [pscustomobject]@{ ID=$c.CI_ID }
        } @($name)
        Add-LabResource $Context 'ConfigurationItem' ($name+' CI') 'Name' ($name+' CI')
        $item.ID=$created.ID
        $discovery='Set shell=CreateObject("WScript.Shell")'+[Environment]::NewLine+'result=shell.Run("'+$InitialMarker.Command+'",0,True)'+[Environment]::NewLine+'WScript.Echo "Compliant"'
        $null=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($id,$code)
            $c=Get-CMConfigurationItem -Id $id
            Add-CMComplianceSettingScript -InputObject $c -Name 'Completed discovery' -DiscoveryScriptLanguage VBScript -DiscoveryScriptText $code -DataType String -RuleName 'Compliant marker' -ExpressionOperator IsEquals -ValueRule -ExpectedValue Compliant
        } @($item.ID,$discovery)
        $baseline=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($name)
            $b=New-CMBaseline -Name ($name+' baseline')
            [pscustomobject]@{ ID=$b.CI_ID }
        } @($name)
        Add-LabResource $Context 'Baseline' ($name+' baseline') 'Name' ($name+' baseline')
        $item.BaselineID=$baseline.ID
        $null=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($baseline,$ci)
            Set-CMBaseline -Id $baseline -AddOSConfigurationItem @($ci)
        } @($baseline.ID,$item.ID)
        $assignment=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($baseline,$collection)
            # The recurring schedule is established before the initial successful
            # evaluation and is not changed by a Modify-only attacker.
            $schedule=New-CMSchedule -Start ([DateTime]::UtcNow) -IsUtc -RecurCount 1 -RecurInterval Minutes
            $a=New-CMBaselineDeployment -Id $baseline -CollectionId $collection -Schedule $schedule -EnableEnforcement $false
            [pscustomobject]@{ ID=$a.AssignmentID; Name=$a.AssignmentName }
        } @($baseline.ID,$Collection.CollectionID)
        $item.AssignmentID=$assignment.ID
        Add-LabResource $Context 'WMI' ('SMS_BaselineAssignment.AssignmentID='+$assignment.ID) 'AssignmentName' $assignment.Name
    }
    else {
        $created=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($name,$workload)
            if($workload -eq 'Package') { $p=New-CMPackage -Name $name }
            else { $p=New-CMTaskSequence -Name $name -CustomTaskSequence -Description 'Only a harmless marker command' }
            [pscustomobject]@{ ID=$p.PackageID }
        } @($name,$Workload)
        $item.ID=$created.ID
        $className='SMS_Package'
        if($Workload -eq 'TaskSequence') { $className='SMS_TaskSequencePackage' }
        Add-LabResource $Context 'WMI' ($className+'.PackageID="'+$item.ID+'"') 'Name' $name
        if($Workload -eq 'Package') {
            $p=New-LabInstance $Context.Scope 'SMS_Program'
            $p.PackageID=$item.ID; $p.ProgramName='Completed marker'; $p.CommandLine=$InitialMarker.Command
            $p.Duration=[uint32]15; $p.SecuredTypeID=[uint32]2
            # Native SMS_Program settings: run on this platform, hide the window,
            # use administrator context, require no interaction, and avoid a
            # mapped drive. No restart or logoff flag is enabled.
            $anyPlatform=0x08000000
            $hideWindow=0x01000000
            $administratorContext=0x00008000
            $unattended=0x00002000
            $useUncPath=0x00100000
            $p.ProgramFlags=[uint32]($anyPlatform -bor $hideWindow -bor $administratorContext -bor $unattended -bor $useUncPath)
            $p.WorkingDirectory='C:\Windows\System32'
            $null=$p.Put()
        }
        else {
            $null=Invoke-LabConsole $Context.Credential $Context.Credential {
                param($id,$command)
                $step=New-CMTSStepRunCommandLine -Name 'Completed marker' -CommandLine $command -DisableWow64Redirection
                Add-CMTaskSequenceStep -TaskSequenceId $id -Step $step
            } @($item.ID,$InitialMarker.Command)
        }
        $assignment=Invoke-LabConsole $Context.Credential $Context.Credential {
            param($id,$workload,$collection,$recurring)
            $schedule=New-CMSchedule -Start ([DateTime]::UtcNow) -Nonrecurring -IsUtc
            if($recurring) {
                # This repeating schedule exists before the original successful
                # run. The restricted editor will not create or change it.
                $schedule=New-CMSchedule -Start ([DateTime]::UtcNow) -IsUtc -RecurCount 2 -RecurInterval Minutes
            }
            # The usual comparison starts with a single completed deadline.
            $past=[DateTime]'2020-01-01'
            if($workload -eq 'Package') {
                $a=New-CMPackageDeployment -PackageId $id -ProgramName 'Completed marker' -StandardProgram -CollectionId $collection -DeployPurpose Required -Schedule @($schedule) -RerunBehavior AlwaysRerunProgram -AvailableDateTime $past -UseUtcForAvailableSchedule $true -SoftwareInstallation $true -SystemRestart $false
            }
            else {
                $a=New-CMTaskSequenceDeployment -TaskSequencePackageId $id -CollectionId $collection -DeployPurpose Required -Schedule @($schedule) -RerunBehavior AlwaysRerunProgram -AvailableDateTime $past -UseUtcForAvailableSchedule $true -SoftwareInstallation $true -SystemRestart $false -ShowTaskSequenceProgress $false
            }
            [pscustomobject]@{ ID=$a.AdvertisementID; Name=$a.AdvertisementName }
        } @($item.ID,$Workload,$Collection.CollectionID,$RecurringDeployment)
        $item.AssignmentID=$assignment.ID
        Add-LabResource $Context 'WMI' ('SMS_Advertisement.AdvertisementID="'+$assignment.ID+'"') 'AdvertisementName' $assignment.Name
    }
    if(-not $item.ID -or -not $item.AssignmentID) { throw 'Setup returned an empty object or assignment ID.' }
    return $item
}

function Wait-InitialExecution {
    param($Context,[string]$Target,$Item,$Marker)
    for($attempt=0;$attempt -lt 80;$attempt++) {
        $observed=Read-ExecutionMarker $Context.Credential $Target $Marker
        $state=Read-ExecutionState $Context.Credential $Target $Item
        $completed=$false
        if($Item.Workload -eq 'Application') { $completed=$state.installState -eq 'Installed' }
        elseif($Item.Workload -eq 'ConfigurationItem') { $completed=$state.compliance -eq 1 }
        else { $completed=($state.lastRunStatus -match 'Success|Succeeded') -and $state.lastExitCode -eq 0 }
        if($observed.nonce -eq $Marker.Nonce -and $observed.sid -eq 'S-1-5-18' -and $completed) { return @{ marker=$observed; state=$state; completedUTC=[DateTime]::UtcNow.ToString('o') } }
        if($attempt % 4 -eq 0) {
            $null=Invoke-LabDevice -Credential $Context.Credential -ComputerName $Target -ArgumentList $Item.Workload,$Item.Name -ScriptBlock {
                param($workload,$name)
                foreach($schedule in @('{00000000-0000-0000-0000-000000000021}','{00000000-0000-0000-0000-000000000022}','{00000000-0000-0000-0000-000000000121}')) {
                    $null=Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList $schedule
                }
                if($workload -eq 'ConfigurationItem') {
                    foreach($b in @(Get-WmiObject -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration | Where-Object DisplayName -eq ($name+' baseline'))) {
                        $class=[wmiclass]'root\ccm\dcm:SMS_DesiredConfiguration'
                        $p=$class.GetMethodParameters('TriggerEvaluation'); $p.Name=$b.Name; $p.Version=$b.Version; $p.IsMachineTarget=$true; $p.IsEnforced=$true
                        $null=$class.InvokeMethod('TriggerEvaluation',$p,$null)
                    }
                }
            }
        }
        Write-Host ('Waiting for initial SUCCESS before testing modification: '+($state | ConvertTo-Json -Compress))
        Start-Sleep -Seconds 3
    }
    throw 'Initial deployment did not reach a confirmed successful/compliant state.'
}

function Set-ExecutionCode {
    param($Context,$Actor,$Item,$Marker,[string]$Change)
    if($Item.Workload -eq 'Package') {
        $scope=New-LabScope $Actor.Credential
        $program=Get-LabObject $scope ('SMS_Program.PackageID="'+$Item.ID+'",ProgramName="Completed marker"')
        $program.CommandLine=$Marker.Command
        $null=$program.Put()
        return
    }
    $null=Invoke-LabConsole $Context.Credential $Actor.Credential {
        param($workload,$name,$id,$command,$change)
        if($workload -eq 'Application') {
            if($change -eq 'DetectionScript') {
                $code='Set shell=CreateObject("WScript.Shell")'+[Environment]::NewLine+'result=shell.Run("'+$command+'",0,True)'+[Environment]::NewLine+'WScript.Echo "Installed"'
                Set-CMScriptDeploymentType -ApplicationName $name -DeploymentTypeName 'Completed marker' -ScriptLanguage VBScript -ScriptText $code -Force
            }
            else { Set-CMScriptDeploymentType -ApplicationName $name -DeploymentTypeName 'Completed marker' -InstallCommand $command -Force }
        }
        elseif($workload -eq 'TaskSequence') { Set-CMTSStepRunCommandLine -TaskSequenceId $id -StepName 'Completed marker' -CommandLine $command }
        else {
            $code='Set shell=CreateObject("WScript.Shell")'+[Environment]::NewLine+'result=shell.Run("'+$command+'",0,True)'+[Environment]::NewLine+'WScript.Echo "Compliant"'
            $c=Get-CMConfigurationItem -Id $id
            Set-CMComplianceSettingScript -InputObject $c -Name 'Completed discovery' -DiscoveryScriptText $code
        }
    } @($Item.Workload,$Item.Name,$Item.ID,$Marker.Command,$Change)
}

function Request-ExecutionNotification {
    param($Scope,[string]$CollectionID,[uint32]$ResourceID,[uint32]$Action)
    try {
        $class=[System.Management.ManagementClass]::new($Scope,[System.Management.ManagementPath]::new('SMS_ClientOperation'),$null)
        $p=$class.GetMethodParameters('InitiateClientOperation')
        $p.Type=$Action; $p.TargetCollectionID=$CollectionID; $p.TargetResourceIDs=[uint32[]]@($ResourceID); $p.RandomizationWindow=[uint32]0
        $out=$class.InvokeMethod('InitiateClientOperation',$p,$null)
        $values=@{}; foreach($property in $out.Properties) { $values[$property.Name]=$property.Value }
        return @{ action=$Action; accepted=($out.ReturnValue -eq 0); response=$values; utc=[DateTime]::UtcNow.ToString('o') }
    }
    catch {
        $errorDetails=Get-LabError $_
        Write-Warning ($errorDetails | ConvertTo-Json -Compress)
        return @{ action=$Action; accepted=$false; error=$errorDetails; utc=[DateTime]::UtcNow.ToString('o') }
    }
}

function Set-ExecutionReschedule {
    param($Context,$Actor,$Item,[string]$CollectionID)
    $null=Invoke-LabConsole $Context.Credential $Actor.Credential {
        param($workload,$id,$baseline,$collection)
        # Give the client time to receive the revised policy before its deadline.
        # A deadline rounded into the already-completed minute is ambiguous.
        $schedule=New-CMSchedule -Start ([DateTime]::UtcNow.AddMinutes(2)) -Nonrecurring -IsUtc
        if($workload -eq 'Package') { Set-CMPackageDeployment -PackageId $id -StandardProgramName 'Completed marker' -CollectionId $collection -Schedule @($schedule) -RerunBehavior AlwaysRerunProgram }
        elseif($workload -eq 'TaskSequence') { Set-CMTaskSequenceDeployment -TaskSequencePackageId $id -CollectionId $collection -Schedule @($schedule) -RerunBehavior AlwaysRerunProgram }
        elseif($workload -eq 'ConfigurationItem') { Set-CMBaselineDeployment -BaselineId $baseline -CollectionId $collection -Schedule $schedule }
        else { throw 'Application rescheduling is not part of this experiment.' }
    } @($Item.Workload,$Item.ID,$Item.BaselineID,$CollectionID)
}
