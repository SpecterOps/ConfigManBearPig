<#
.SYNOPSIS
Check different SCCM role assignments in the mayyhem.com development lab.
.DESCRIPTION
Creates one temporary AD account, two empty assigned device collections, and an
empty child under each. The account receives Full Administrator on one parent
and Read-only Analyst on the other. Changing the first child's comment must
succeed; changing the second must be denied. SCCM protects directly assigned
collections from modification, so the test uses their children. A finally block
removes all test objects. No device action is run.
This manual integration check requires Windows PowerShell and lab administrator
credentials. It never runs as part of the ordinary offline Python test suite.
.EXAMPLE
.\tests\integration\role_assignment_access.ps1 -Credential (Get-Credential MAYYHEM\domainadmin) -EvidencePath "$env:TEMP\cmbp-role-access.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.PSCredential] $Credential,
    [string] $EvidencePath = (Join-Path $env:TEMP 'cmbp-role-access.json')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Management
Add-Type -AssemblyName System.DirectoryServices

# This test is intentionally restricted to the owner's development lab.
foreach ($hostName in @('dc.mayyhem.com', 'ps1-sms.mayyhem.com')) {
    $addresses = [System.Net.Dns]::GetHostAddresses($hostName)
    foreach ($address in $addresses) {
        if ($address.ToString() -notmatch '^10\.10\.(10|11)\.[0-9]+$') {
            throw "Refusing a lab name that resolves outside the authorized subnets: $hostName"
        }
        Write-Verbose "Verified lab address $address for $hostName"
    }
}

function New-ProviderScope {
    param([string] $UserName, [string] $Password)
    $options = [System.Management.ConnectionOptions]::new()
    $options.Username = $UserName
    $options.Password = $Password
    $options.Authentication = [System.Management.AuthenticationLevel]::PacketPrivacy
    $options.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
    $scope = [System.Management.ManagementScope]::new('\\ps1-sms.mayyhem.com\root\SMS\site_PS1', $options)
    $scope.Connect()
    return $scope
}

function New-ProviderInstance {
    param([System.Management.ManagementScope] $Scope, [string] $ClassName)
    $class = [System.Management.ManagementClass]::new($Scope, [System.Management.ManagementPath]::new($ClassName), $null)
    return $class.CreateInstance()
}

function Read-ProviderObject {
    param([System.Management.ManagementScope] $Scope, [System.Management.ManagementPath] $Path)
    $object = [System.Management.ManagementObject]::new($Scope, $Path, $null)
    $object.Get()
    return $object
}

$administratorScope = New-ProviderScope $Credential.UserName ($Credential.GetNetworkCredential().Password)
$testName = 'cmbprbac' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$testLogon = "MAYYHEM\$testName"
$testPassword = [guid]::NewGuid().ToString('N') + 'aA!1'
$usersContainer = [System.DirectoryServices.DirectoryEntry]::new(
    'LDAP://dc.mayyhem.com/CN=Users,DC=mayyhem,DC=com',
    $Credential.UserName, $Credential.GetNetworkCredential().Password
)
$temporaryUser = $null
$hasCreatedUser = $false
$administratorPath = $null
$collectionPaths = [System.Collections.Generic.List[System.Management.ManagementPath]]::new()
$report = [ordered]@{ testAccount = $testLogon; allowedChange = $false; deniedChange = $false; cleanupComplete = $false }
$failure = $null

try {
    $temporaryUser = $usersContainer.Children.Add("CN=$testName", 'user')
    $temporaryUser.Properties['sAMAccountName'].Value = $testName
    $temporaryUser.Properties['userPrincipalName'].Value = "$testName@mayyhem.com"
    $temporaryUser.CommitChanges()
    $hasCreatedUser = $true
    $null = $temporaryUser.Invoke('SetPassword', @($testPassword))
    $temporaryUser.Properties['userAccountControl'].Value = 512
    $temporaryUser.CommitChanges()
    $temporaryUser.RefreshCache(@('objectSid'))
    $testSid = [System.Security.Principal.SecurityIdentifier]::new($temporaryUser.Properties['objectSid'].Value, 0).Value

    foreach ($label in @('Full Administrator', 'Read-only Analyst')) {
        $collection = New-ProviderInstance $administratorScope 'SMS_Collection'
        $collection.Name = "CMBP role check $testName $label"
        $collection.Comment = 'Temporary empty collection for role assignment verification'
        $collection.CollectionType = 2
        $collection.RefreshType = 1
        $collection.LimitToCollectionID = 'SMS00001'
        $collectionPaths.Add($collection.Put())
    }
    $allowedParent = Read-ProviderObject $administratorScope $collectionPaths[0]
    $deniedParent = Read-ProviderObject $administratorScope $collectionPaths[1]
    $report.assignedAllowedCollection = $allowedParent.CollectionID
    $report.assignedDeniedCollection = $deniedParent.CollectionID
    foreach ($parentCollection in @($allowedParent, $deniedParent)) {
        $child = New-ProviderInstance $administratorScope 'SMS_Collection'
        $child.Name = "CMBP role check $testName child of $($parentCollection.CollectionID)"
        $child.Comment = 'Temporary empty child collection for role assignment verification'
        $child.CollectionType = 2
        $child.RefreshType = 1
        $child.LimitToCollectionID = $parentCollection.CollectionID
        $collectionPaths.Add($child.Put())
    }
    $report.allowedCollection = (Read-ProviderObject $administratorScope $collectionPaths[2]).CollectionID
    $report.deniedCollection = (Read-ProviderObject $administratorScope $collectionPaths[3]).CollectionID

    $permissions = [System.Collections.Generic.List[System.Management.ManagementBaseObject]]::new()
    foreach ($assignment in @(
        @{ Role = 'SMS0001R'; Collection = $allowedParent.CollectionID },
        @{ Role = 'SMS0002R'; Collection = $deniedParent.CollectionID }
    )) {
        # Each role gets its own collection entry. Both can use All object scopes;
        # this keeps the test focused on collection boundaries.
        foreach ($category in @(
            @{ ID = $assignment.Collection; Type = 1 },
            @{ ID = 'SMS00ALL'; Type = 29 }
        )) {
            $permission = New-ProviderInstance $administratorScope 'SMS_APermission'
            $permission.RoleID = $assignment.Role
            $permission.CategoryID = $category.ID
            $permission.CategoryTypeID = $category.Type
            $permissions.Add($permission)
        }
    }
    $administrator = New-ProviderInstance $administratorScope 'SMS_Admin'
    $administrator.LogonName = $testLogon
    $administrator.AdminSid = $testSid
    $administrator.Permissions = $permissions.ToArray()
    $administratorPath = $administrator.Put()
    $savedAdministrator = Read-ProviderObject $administratorScope $administratorPath
    $report.permissions = @($savedAdministrator.Permissions | ForEach-Object {
        @{ RoleID = $_.RoleID; CategoryID = $_.CategoryID; CategoryTypeID = $_.CategoryTypeID }
    })

    $testScope = New-ProviderScope $testLogon $testPassword
    $allowed = Read-ProviderObject $testScope $collectionPaths[2]
    $allowed.Comment = 'Allowed change verified by the temporary account'
    $null = $allowed.Put()
    $report.allowedChange = $true

    $denied = Read-ProviderObject $testScope $collectionPaths[3]
    $originalComment = $denied.Comment
    try {
        $denied.Comment = 'This change must be denied'
        $null = $denied.Put()
    }
    catch {
        $errorDetails = $_.Exception.ToString()
        $underlyingError = $_.Exception
        while ($null -ne $underlyingError.InnerException) {
            $underlyingError = $underlyingError.InnerException
        }
        if ($underlyingError -is [System.Management.ManagementException] -and $null -ne $underlyingError.ErrorInformation) {
            $providerDetails = @($underlyingError.ErrorInformation.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
            $errorDetails += " Provider details: $providerDetails"
        }
        if ($errorDetails -notmatch 'AccessDenied|Access is denied|0x80041003|0x80070005|not authorized|does not have (modify )?permission|2147942405') {
            throw "The second change failed for an unexpected reason: $errorDetails"
        }
        $report.deniedChange = $true
        # SMS Provider wraps this refusal in GenericFailure. Its extended status
        # gives the actual reason; do not mistake a transport error for a denial.
        $report.denial = $underlyingError.Message
        if ($null -ne $underlyingError.ErrorInformation) {
            $report.denial = $underlyingError.ErrorInformation['Description']
            $report.providerErrorCode = $underlyingError.ErrorInformation['ErrorCode']
        }
    }
    if (-not $report.deniedChange) {
        throw 'The account could change the collection assigned only to Read-only Analyst.'
    }
    $checkDenied = Read-ProviderObject $administratorScope $collectionPaths[3]
    if ($checkDenied.Comment -ne $originalComment) {
        throw 'The collection assigned only to Read-only Analyst was changed.'
    }
    $report.deniedCollectionUnchanged = $true
}
catch {
    $failure = $_
    $report.failure = $_.Exception.Message
}
finally {
    # Remove only object paths created by this invocation, in dependency order.
    # Continue after a cleanup failure so it cannot strand the other resources.
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $administratorPath) {
        try {
            (Read-ProviderObject $administratorScope $administratorPath).Delete()
        }
        catch {
            $cleanupFailures.Add("Administrator $administratorPath : $($_.Exception.Message)")
            Write-Warning "Could not remove temporary administrator $administratorPath"
        }
    }
    # Remove children before their limiting parents.
    for ($index = $collectionPaths.Count - 1; $index -ge 0; $index--) {
        $path = $collectionPaths[$index]
        try {
            (Read-ProviderObject $administratorScope $path).Delete()
        }
        catch {
            $cleanupFailures.Add("Collection $path : $($_.Exception.Message)")
            Write-Warning "Could not remove temporary collection $path"
        }
    }
    if ($hasCreatedUser) {
        try {
            $usersContainer.Children.Remove($temporaryUser)
        }
        catch {
            $cleanupFailures.Add("AD account $testLogon : $($_.Exception.Message)")
            Write-Warning "Could not remove temporary AD account $testLogon"
        }
    }
    if ($null -ne $temporaryUser) {
        $temporaryUser.Dispose()
    }
    $usersContainer.Dispose()
    $report.cleanupComplete = ($cleanupFailures.Count -eq 0)
    $report.cleanupFailures = $cleanupFailures.ToArray()
    $testPassword = $null
    $parent = Split-Path -Parent ([System.IO.Path]::GetFullPath($EvidencePath))
    $null = [System.IO.Directory]::CreateDirectory($parent)
    $report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
    $report | ConvertTo-Json -Depth 6
}
if (-not $report.cleanupComplete) {
    throw 'Test cleanup was incomplete; inspect cleanupFailures in the saved evidence.'
}
if ($null -ne $failure) {
    throw $failure
}
