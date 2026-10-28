<#
Helpers for temporary SCCM permission experiments in the mayyhem.com lab.
Credentials stay in memory. The cleanup journal contains names and object paths,
never passwords. Every experiment must remove its resources in a finally block.
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Management
Add-Type -AssemblyName System.DirectoryServices

function New-LabScope {
    param([System.Management.Automation.PSCredential] $Credential)
    $options = [System.Management.ConnectionOptions]::new()
    $options.Username = $Credential.UserName
    $options.SecurePassword = $Credential.Password
    $options.Authentication = [System.Management.AuthenticationLevel]::PacketPrivacy
    $options.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
    $options.Timeout = [TimeSpan]::FromSeconds(30)
    $scope = [System.Management.ManagementScope]::new('\\ps1-sms.mayyhem.com\root\SMS\site_PS1', $options)
    $scope.Connect()
    return $scope
}

function New-LabInstance {
    param($Scope, [string] $ClassName)
    $class = [System.Management.ManagementClass]::new($Scope, [System.Management.ManagementPath]::new($ClassName), $null)
    return $class.CreateInstance()
}

function Get-LabObject {
    param($Scope, [string] $Path)
    $object = [System.Management.ManagementObject]::new($Scope, [System.Management.ManagementPath]::new($Path), $null)
    $object.Get()
    return $object
}

function Get-LabObjects {
    param($Scope, [string] $Query)
    $search = [System.Management.ManagementObjectSearcher]::new($Scope, [System.Management.ObjectQuery]::new($Query))
    return @($search.Get())
}

function Save-LabJournal {
    param($Context)
    @{ runTag = $Context.RunTag; resources = @($Context.Resources.ToArray()) } |
        ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $Context.OutputDirectory 'cleanup-journal.json') -Encoding UTF8
}

function Add-LabResource {
    param($Context, [string] $Kind, [string] $Path, [string] $Property, [string] $Expected)
    if ($Kind -eq 'WMI' -and $Path -match '=\s*$') {
        throw 'The provider returned no resource ID; no cleanup entry or successful action can be recorded.'
    }
    $Context.Resources.Add(@{ kind = $Kind; path = $Path; property = $Property; expected = $Expected })
    Save-LabJournal $Context
}

function New-LabContext {
    param([System.Management.Automation.PSCredential] $Credential, [string] $OutputDirectory)
    $journalPath = Join-Path $OutputDirectory 'cleanup-journal.json'
    if (Test-Path -LiteralPath $journalPath) {
        $previous = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
        if (@($previous.resources).Count -ne 0) {
            throw "Resolve the existing cleanup journal before reusing this output directory: $journalPath"
        }
        Write-Verbose 'The previous experiment journal contains no remaining resources.'
    }
    # A new output directory has no previous resources to recover.
    foreach ($hostName in @('dc.mayyhem.com', 'ps1-sms.mayyhem.com', 'ps1-pss.mayyhem.com', 'ps1-db.mayyhem.com')) {
        foreach ($address in [System.Net.Dns]::GetHostAddresses($hostName)) {
            if ($address.ToString() -notmatch '^10\.10\.(10|11)\.[0-9]+$') {
                throw "Lab name resolves outside the authorized subnets: $hostName ($address)"
            }
            Write-Verbose "Verified authorized lab address $address"
        }
    }
    $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetFullPath($OutputDirectory))
    $context = @{
        Credential = $Credential
        Scope = New-LabScope $Credential
        OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
        RunTag = 'CMBP-PERM-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        Resources = [System.Collections.Generic.List[object]]::new()
        NextUser = 0
    }
    $fullRole = Get-LabObject $context.Scope 'SMS_Role.RoleID="SMS0001R"'
    $context.FullOperations = @($fullRole.Operations | ForEach-Object {
        @{ ObjectTypeID = [uint32]$_.ObjectTypeID; GrantedOperations = [uint32]$_.GrantedOperations }
    })
    Save-LabJournal $context
    return $context
}

function New-LabUser {
    param($Context)
    $Context.NextUser++
    $sam = 'cpr' + $Context.RunTag.Substring(10) + $Context.NextUser.ToString('0000')
    $container = [System.DirectoryServices.DirectoryEntry]::new(
        'LDAP://dc.mayyhem.com/CN=Users,DC=mayyhem,DC=com',
        $Context.Credential.UserName, $Context.Credential.GetNetworkCredential().Password)
    $user = $container.Children.Add("CN=$sam", 'user')
    try {
        $user.Properties['sAMAccountName'].Value = $sam
        $user.Properties['userPrincipalName'].Value = "$sam@mayyhem.com"
        $user.CommitChanges()
        Add-LabResource $Context 'ADUser' "CN=$sam,CN=Users,DC=mayyhem,DC=com" 'sAMAccountName' $sam
        $password = [guid]::NewGuid().ToString('N') + 'aA!1'
        $null = $user.Invoke('SetPassword', @($password))
        $user.Properties['userAccountControl'].Value = 512
        $user.CommitChanges()
        $user.RefreshCache(@('objectSid'))
        $sid = [System.Security.Principal.SecurityIdentifier]::new($user.Properties['objectSid'].Value, 0).Value
        $secret = ConvertTo-SecureString $password -AsPlainText -Force
        return @{
            Name = "MAYYHEM\$sam"; Sid = $sid
            Credential = [System.Management.Automation.PSCredential]::new("MAYYHEM\$sam", $secret)
        }
    }
    finally {
        $user.Dispose()
        $container.Dispose()
    }
}

function ConvertTo-LabOperations {
    param($Scope, [object[]] $Operations)
    $result = [System.Collections.Generic.List[System.Management.ManagementBaseObject]]::new()
    foreach ($operation in $Operations) {
        $entry = New-LabInstance $Scope 'SMS_ARoleOperation'
        $entry.ObjectTypeID = [uint32]$operation.ObjectTypeID
        $entry.GrantedOperations = [uint32]$operation.GrantedOperations
        $result.Add($entry)
    }
    return ,$result.ToArray()
}

function New-LabRole {
    param($Context, [object[]] $Operations, [string] $Label, $Scope = $Context.Scope)
    $role = New-LabInstance $Scope 'SMS_Role'
    $role.RoleName = $Context.RunTag + ' ' + $Label + ' ' + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $role.RoleDescription = 'Temporary custom role for permission validation; remove after the experiment.'
    $role.Operations = ConvertTo-LabOperations $Scope $Operations
    $path = $role.Put()
    Add-LabResource $Context 'WMI' $path.RelativePath 'RoleName' $role.RoleName
    return Get-LabObject $Context.Scope $path.RelativePath
}

function ConvertTo-LabAssignments {
    param($Scope, [object[]] $Assignments)
    $result = [System.Collections.Generic.List[System.Management.ManagementBaseObject]]::new()
    foreach ($assignment in $Assignments) {
        $categories = @($assignment.Collections | ForEach-Object { @{ ID = $_; Type = 1 } }) +
            @($assignment.Scopes | ForEach-Object { @{ ID = $_; Type = 29 } })
        foreach ($category in $categories) {
            # Each entry binds one role to either a collection or an object scope.
            $entry = New-LabInstance $Scope 'SMS_APermission'
            $entry.RoleID = $assignment.Role
            $entry.CategoryID = $category.ID
            $entry.CategoryTypeID = [uint32]$category.Type
            $result.Add($entry)
        }
    }
    return ,$result.ToArray()
}

function New-LabAdmin {
    param($Context, $User, [object[]] $Assignments, $Scope = $Context.Scope)
    $admin = New-LabInstance $Scope 'SMS_Admin'
    $admin.LogonName = $User.Name
    $admin.AdminSid = $User.Sid
    $admin.Permissions = ConvertTo-LabAssignments $Scope $Assignments
    $path = $admin.Put()
    Add-LabResource $Context 'WMI' $path.RelativePath 'LogonName' $User.Name
    return Get-LabObject $Context.Scope $path.RelativePath
}

function New-LabCollection {
    param($Context, [string] $Label, [string] $Limit = 'SMS00001')
    $collection = New-LabInstance $Context.Scope 'SMS_Collection'
    $collection.Name = $Context.RunTag + ' ' + $Label
    $collection.Comment = 'Temporary permission experiment collection'
    $collection.CollectionType = 2
    $collection.RefreshType = 1
    $collection.LimitToCollectionID = $Limit
    $path = $collection.Put()
    Add-LabResource $Context 'WMI' $path.RelativePath 'Name' $collection.Name
    return Get-LabObject $Context.Scope $path.RelativePath
}

function Add-LabCollectionDevice {
    param($Context, $Collection, [uint32] $ResourceID)
    $rule = New-LabInstance $Context.Scope 'SMS_CollectionRuleDirect'
    $rule.ResourceClassName = 'SMS_R_System'
    $rule.ResourceID = $ResourceID
    $rule.RuleName = 'Temporary permission test device'
    $parameters = $Collection.GetMethodParameters('AddMembershipRule')
    $parameters.collectionRule = $rule
    $output = $Collection.InvokeMethod('AddMembershipRule', $parameters, $null)
    if ($output.ReturnValue -ne 0) { throw "AddMembershipRule returned $($output.ReturnValue)" }
    $null = $Collection.InvokeMethod('RequestRefresh', $null, $null)
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        # WMI's PowerShell adapter returns a null Count for a single object.
        # Explicitly keep the query result as an array before checking its size.
        $members = @(Get-LabObjects $Context.Scope "SELECT ResourceID FROM SMS_FullCollectionMembership WHERE CollectionID='$($Collection.CollectionID)' AND ResourceID=$ResourceID")
        if ($members.Count -eq 1) { return }
        Write-Verbose "Waiting for collection $($Collection.CollectionID) to contain resource $ResourceID"
        Start-Sleep -Seconds 2
    }
    throw "Collection membership did not become available: $($Collection.CollectionID) / $ResourceID"
}

function Get-LabError {
    param($ErrorRecord)
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception.InnerException) { $exception = $exception.InnerException }
    $result = @{ type = $exception.GetType().FullName; message = $exception.Message }
    if ($exception -is [System.Management.ManagementException]) {
        $result.code = $exception.ErrorCode.ToString()
        if ($null -ne $exception.ErrorInformation) {
            $result.providerDescription = $exception.ErrorInformation['Description']
            $result.providerErrorCode = $exception.ErrorInformation['ErrorCode']
        }
        # No extended status means only the ordinary WMI error is available.
    }
    # Other exception types have no SMS Provider status to record.
    return $result
}

function New-LabHttpClient {
    param([pscredential] $Credential)
    Add-Type -AssemblyName System.Net.Http
    if (-not ('CmbpLabCertificate' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Security;
public static class CmbpLabCertificate {
 public static void Install() { ServicePointManager.ServerCertificateValidationCallback = Validate; }
 private static bool Validate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Security.Cryptography.X509Certificates.X509Chain chain, SslPolicyErrors errors) {
  var request = sender as HttpWebRequest;
  return errors == SslPolicyErrors.None || (request != null && request.RequestUri.Host == "ps1-sms.mayyhem.com");
 }
}
'@
    }
    # Only this provider's lab certificate is accepted. DNS is checked by the context.
    [CmbpLabCertificate]::Install()
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.Credentials = $Credential.GetNetworkCredential()
    $handler.UseProxy = $false
    return [Net.Http.HttpClient]::new($handler)
}

function Invoke-LabScript {
    param([pscredential] $Credential, [uint32] $ResourceID, [string] $ScriptGuid)
    $client = New-LabHttpClient $Credential
    try {
        $json = @{ ScriptGuid = $ScriptGuid } | ConvertTo-Json -Compress
        $content = [Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
        try {
            $uri = "https://ps1-sms.mayyhem.com/AdminService/v1.0/Device($ResourceID)/AdminService.RunScript"
            $response = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
            return @{ status = [int]$response.StatusCode; body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
        }
        finally { $content.Dispose() }
    }
    finally { $client.Dispose() }
}

function Invoke-LabConsole {
    param([pscredential] $Credential, [pscredential] $ActorCredential, [scriptblock] $Body, [object[]] $Arguments = @())
    # The administrator opens a Windows session only to load Microsoft's console
    # library. The SCCM connection explicitly uses the account under test. Denial
    # controls verify that this connection does not inherit administrator access.
    return Invoke-Command -ComputerName 'ps1-pss.mayyhem.com' -Credential $Credential -ArgumentList $ActorCredential, $Body.ToString(), $Arguments -ScriptBlock {
        param($actor, $bodyText, $bodyArguments)
        $ErrorActionPreference = 'Stop'
        Import-Module 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin\ConfigurationManager.psd1' -ErrorAction SilentlyContinue
        $null = New-PSDrive -Name 'CMBP' -PSProvider CMSite -Root 'ps1-sms.mayyhem.com' -Credential $actor
        Set-Location CMBP:
        & ([scriptblock]::Create($bodyText)) @bodyArguments
    }
}

function Invoke-LabDevice {
    param([pscredential] $Credential, [string] $ComputerName, [scriptblock] $ScriptBlock, [object[]] $ArgumentList = @())
    if ($ComputerName -in @('PS1-DEV', 'ps1-dev.mayyhem.com', '10.10.11.10')) {
        # Windows resolves its own computer name to ::1. Observe this known lab
        # device locally instead of opening a connection to a loopback address.
        $addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress)
        if ($env:COMPUTERNAME -ne 'PS1-DEV' -or $addresses -notcontains '10.10.11.10') {
            throw 'Local observation requires the documented PS1-DEV lab computer.'
        }
        return & $ScriptBlock @ArgumentList
    }
    foreach ($address in [Net.Dns]::GetHostAddresses($ComputerName)) {
        if ($address.ToString() -notmatch '^10\.10\.(10|11)\.[0-9]+$') { throw "Unauthorized device address: $ComputerName / $address" }
        Write-Verbose "Verified device address $address"
    }
    return Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function New-LabMarker {
    # The short variable names inside the marker payload keep its encoded command
    # below SCCM's 1024-character application limit. i is the Windows identity;
    # d is the dedicated marker directory. The surrounding test uses full names.
    $nonce = [guid]::NewGuid().ToString('N')
    $path = 'C:\ProgramData\CMBP-PermissionResearch\' + $nonce + '.json'
    $code = @'
$i=[Security.Principal.WindowsIdentity]::GetCurrent()
$d='C:\ProgramData\CMBP-PermissionResearch'
$null=[IO.Directory]::CreateDirectory($d)
@{nonce='NONCE';computer=$env:COMPUTERNAME;sid=$i.User.Value}|ConvertTo-Json|Set-Content -LiteralPath ($d+'\NONCE.json')
'@
    $code = $code.Replace('NONCE',$nonce)
    $command = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    if ($command.Length -gt 1024) { throw 'The harmless marker command is too long for an application.' }
    return @{ Nonce = $nonce; Path = $path; Code = $code; Command = $command }
}

function Wait-LabMarker {
    param([pscredential] $Credential, $Marker, [string] $BaselineName = '', [int] $Polls = 36)
    for ($attempt = 0; $attempt -lt $Polls; $attempt++) {
        $observed = Invoke-LabDevice $Credential 'PS1-DEV' -ArgumentList $Marker.Path, $attempt, $BaselineName -ScriptBlock {
            param($path, $attempt, $baselineName)
            if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw; return }
            if ($attempt % 4 -eq 0) {
                foreach ($id in @('{00000000-0000-0000-0000-000000000021}','{00000000-0000-0000-0000-000000000022}')) {
                    $null = Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name TriggerSchedule -ArgumentList $id
                }
                if ($baselineName) {
                    $baselines = @(Get-WmiObject -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration | Where-Object DisplayName -eq $baselineName)
                    foreach ($baseline in $baselines) {
                        $class = [wmiclass]'root\ccm\dcm:SMS_DesiredConfiguration'
                        $parameters = $class.GetMethodParameters('TriggerEvaluation')
                        $parameters.Name = $baseline.Name
                        $parameters.Version = $baseline.Version
                        $parameters.IsMachineTarget = $true
                        $parameters.IsEnforced = $true
                        $null = $class.InvokeMethod('TriggerEvaluation', $parameters, $null)
                    }
                }
                # The setup account only accelerates normal client policy processing.
            }
        }
        if ($observed) {
            if ($Marker.Format -eq 'WhoAmI') {
                $lines = @($observed -split '[\r\n]+' | Where-Object { $_.Trim() })
                $identity = $lines[1] | ConvertFrom-Csv -Header Identity,SID
                return [pscustomobject]@{ nonce = $lines[0].Trim(); identity = $identity.Identity; sid = $identity.SID; computer = 'PS1-DEV' }
            }
            return $observed | ConvertFrom-Json
        }
        Write-Host "Waiting for the harmless client marker ($attempt)"
        Start-Sleep -Seconds 3
    }
    Write-Warning 'No matching execution marker appeared within the observation period.'
    return $null
}

function Remove-LabMarker {
    param([pscredential] $Credential, $Marker)
    Invoke-LabDevice $Credential 'PS1-DEV' -ArgumentList $Marker.Path -ScriptBlock {
        param($path)
        if ($path -notmatch '^C:\\ProgramData\\CMBP-PermissionResearch\\[a-f0-9]{32}\.json$' -and $path -notmatch '^C:\\Windows\\Temp\\cmbp-[a-f0-9]{16}\.txt$') { throw 'Invalid marker cleanup path' }
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
        # A rejected action creates no file to remove.
    }
}

function New-LabScript {
    param($Context, [string] $Code, [string] $Label, $Scope = $Context.Scope, [string] $Author = $Context.Credential.UserName, [uint32] $ApprovalState = 0)
    $class = [System.Management.ManagementClass]::new($Scope, [System.Management.ManagementPath]::new('SMS_Scripts'), $null)
    $parameters = $class.GetMethodParameters('CreateScripts')
    $guid = [guid]::NewGuid().ToString().ToUpperInvariant()
    $name = $Context.RunTag + ' ' + $Label
    $parameters.ScriptGuid = $guid
    $parameters.ScriptName = $name
    $parameters.ScriptDescription = 'Temporary harmless permission marker'
    $parameters.Author = $Author
    $parameters.ApprovalState = $ApprovalState
    # Native SCCM stores script text as base64 of UTF-8 with its byte-order mark.
    $bytes = [Text.Encoding]::UTF8.GetPreamble() + [Text.Encoding]::UTF8.GetBytes($Code)
    $parameters.Script = [Convert]::ToBase64String($bytes)
    $parameters.ScriptType = [uint32]0
    $parameters.ScriptVersion = '1'
    $parameters.Timeout = [uint32]60
    $output = $class.InvokeMethod('CreateScripts', $parameters, $null)
    if ($output.ReturnValue -ne 0) { throw "CreateScripts returned $($output.ReturnValue)" }
    $path = 'SMS_Scripts.ScriptGuid="' + $guid + '"'
    Add-LabResource $Context 'WMI' $path 'ScriptName' $name
    return Get-LabObject $Context.Scope $path
}

function Approve-LabScript {
    param($Scope, [string] $Guid, [string] $Approver)
    $script = Get-LabObject $Scope ('SMS_Scripts.ScriptGuid="' + $Guid + '"')
    $parameters = $script.GetMethodParameters('UpdateApprovalState')
    $parameters.ApprovalState = '3'
    $parameters.Approver = $Approver
    $parameters.Comment = 'Approve only the temporary harmless permission marker'
    $result = $script.InvokeMethod('UpdateApprovalState', $parameters, $null)
    if ($result.ReturnValue -ne 0) { throw "UpdateApprovalState returned $($result.ReturnValue)" }
    return $result.ReturnValue
}

function Remove-LabResources {
    param($Context, [int] $KeepFirst = 0)
    $failures = [System.Collections.Generic.List[string]]::new()
    for ($index = $Context.Resources.Count - 1; $index -ge $KeepFirst; $index--) {
        $resource = $Context.Resources[$index]
        try {
            if ($resource.kind -in @('ConfigurationItem', 'Baseline')) {
                $null = Invoke-LabConsole $Context.Credential $Context.Credential {
                    param($name, $kind)
                    if ($kind -eq 'Baseline') {
                        $items = @(Get-CMBaseline -Name $name -Fast -DisableWildcardHandling)
                        if ($items.Count -ne 1) { throw "Expected exactly one temporary baseline: $name" }
                        Remove-CMBaseline -Name $name -Force -DisableWildcardHandling
                    }
                    else {
                        $items = @(Get-CMConfigurationItem -Name $name -Fast -DisableWildcardHandling)
                        if ($items.Count -ne 1) { throw "Expected exactly one temporary configuration item: $name" }
                        Remove-CMConfigurationItem -Name $name -Force -DisableWildcardHandling
                    }
                } @($resource.path, $resource.kind)
            }
            elseif ($resource.kind -eq 'Application') {
                $null = Invoke-LabConsole $Context.Credential $Context.Credential {
                    param($name)
                    $apps = @(Get-CMApplication -Name $name -Fast -DisableWildcardHandling)
                    if ($apps.Count -ne 1) { throw "Expected exactly one temporary application: $name" }
                    Remove-CMApplication -Name $name -Force -DisableWildcardHandling
                } @($resource.path)
            }
            elseif ($resource.kind -eq 'StatusRule') {
                $null = Invoke-LabConsole $Context.Credential $Context.Credential {
                    param($name, $site)
                    $rules = @(Get-CMStatusFilterRule -SiteCode $site -Name $name -DisableWildcardHandling)
                    if ($rules.Count -ne 1) { throw "Expected exactly one temporary status rule: $name" }
                    Remove-CMStatusFilterRule -SiteCode $site -Name $name -Force -DisableWildcardHandling
                } @($resource.path, $resource.expected)
            }
            elseif ($resource.kind -eq 'WMI') {
                $object = Get-LabObject $Context.Scope $resource.path
                if ($object[$resource.property] -ne $resource.expected) {
                    throw "Cleanup identity mismatch at $($resource.path)"
                }
                $object.Delete()
            }
            else {
                $object = [System.DirectoryServices.DirectoryEntry]::new(
                    ('LDAP://dc.mayyhem.com/' + $resource.path),
                    $Context.Credential.UserName, $Context.Credential.GetNetworkCredential().Password)
                try {
                    if ($object.Properties[$resource.property].Value -ne $resource.expected) {
                        throw "Cleanup identity mismatch at $($resource.path)"
                    }
                    # DirectoryEntry's PowerShell adapter exposes LDAP's string
                    # "parent" property. psbase selects the .NET parent object.
                    $parent = $object.psbase.Parent
                    try { $parent.Children.Remove($object) } finally { $parent.Dispose() }
                }
                finally { $object.Dispose() }
            }
            $Context.Resources.RemoveAt($index)
            Save-LabJournal $Context
            Write-Verbose "Removed temporary resource $($resource.path)"
        }
        catch {
            $failures.Add("$($resource.path): $($_.Exception.Message)")
            Write-Warning "Cleanup failed for $($resource.path): $($_.Exception.Message)"
        }
    }
    if ($failures.Count -gt 0) { throw ($failures -join [Environment]::NewLine) }
    Write-Verbose 'All requested experiment resources were removed.'
}

Export-ModuleMember -Function *-Lab*
