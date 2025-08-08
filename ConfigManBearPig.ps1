<#
.SYNOPSIS
ConfigManBearPig: PowerShell collector for adding SCCM attack paths to BloodHound with OpenGraph

.DESCRIPTION
Author: Chris Thompson (@_Mayyhem) at SpecterOps

Purpose:
    Collects BloodHound OpenGraph compatible SCCM data following the exact collection methodology:
    1. LDAP (identify targets in System Management container)
    2. Local (data available when running on an SCCM client)
    3. DNS (management points published to DNS)
    4. Remote Registry (on targets identified in previous phases)
    5. AdminService (on targets identified in previous phases)
    6. WMI (if AdminService collection fails)
    7. HTTP (fallback method)
    8. SMB (fallback method)
      
System Requirements:
    - PowerShell 4.0 or higher
    - Active Directory domain context with line of sight to a domain controller
    - Various permissions based on collection methods used

.PARAMETER Help
Display usage information

.PARAMETER CollectionMethods
Collection methods to use (comma-separated):
    - All (default): All SCCM collection methods
    - LDAP
    - Local
    - DNS
    - RemoteRegistry
    - AdminService
    - WMI
    - HTTP
    - SMB

.PARAMETER ComputerFile
Specify the path to a file containing computer targets (limits to Remote Registry, AdminService, HTTP, SMB)

.PARAMETER SMSProvider
Specify a specific SMS Provider to collect from (limits to AdminService, WMI)

.PARAMETER SiteCodes
Specify site codes to use for DNS collection (file path or comma-separated string):
    - File: Path to file containing site codes (one per line)
    - String: Comma-separated site codes (e.g., "PS1,CAS,PS2")

Increases success rate of querying of DNS for management point records for the specified sites (when LDAP/Local collection fail to identify a site code or to supplement discovered site codes)

.PARAMETER OutputFormat
Supported values:
    - Zip (default): OpenGraph implementation, outputs .zip containing .json file
    - JSON: OpenGraph implementation, outputs uncompressed .json file
    - StdOut: OpenGraph implementation, outputs JSON to console (can be piped to BHOperator)

.PARAMETER TempDir
Specify the path to a temporary directory where .json files will be stored before being zipped

.PARAMETER ZipDir
Specify the path to a directory where the final .zip file will be stored (default: current directory)

.PARAMETER Domain
Specify a domain to use for LDAP queries and name resolution

.PARAMETER Credential
Specify a PSCredential object for authentication

.PARAMETER SkipPostProcessing
Skip post-processing edge creation (creates only direct edges from collection)

.PARAMETER Verbose
Enable verbose output

#>

[CmdletBinding()]
param(
    [switch]$Help,
    
    [string]$CollectionMethods = "All",
    
    [string]$ComputerFile,
    
    [string]$SMSProvider,

    [string]$SiteCodes,
    
    [string]$OutputFormat = "Zip",
    
    [string]$TempDir,
    
    [string]$ZipDir,
    
    [string]$Domain = $env:USERDNSDOMAIN,
    
    [PSCredential]$Credential,
    
    [switch]$SkipPostProcessing,

    [switch]$Version
)

# Display help text
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    return
}

# Script version information
$script:ScriptVersion = "1.0"
$script:ScriptName = "ConfigManBearPig"

if ($Version) {
    Write-Host "$script:ScriptName version $script:ScriptVersion" -ForegroundColor Green
    return
}

# Collection phases to run
$collectionMethods = $CollectionMethods -split "," | ForEach-Object { $_.Trim().ToUpper() }
$enableLDAP = $false
$enableLocal = $false
$enableDNS = $false
$enableRemoteRegistry = $false
$enableAdminService = $false
$enableWMI = $false
$enableHTTP = $false
$enableSMB = $false

# Process each specified method
foreach ($method in $collectionMethods) {
    switch ($method) {
        "ALL" {
            $enableLDAP = $true
            $enableLocal = $true
            $enableDNS = $true
            $enableRemoteRegistry = $true
            $enableAdminService = $true
            $enableWMI = $true
            $enableHTTP = $true
            $enableSMB = $true
        }
        "LDAP" { $enableLDAP = $true }
        "LOCAL" { $enableLocal = $true }
        "DNS" { $enableDNS = $true }
        "REMOTEREGISTRY" { $enableRemoteRegistry = $true }
        "ADMINSERVICE" { $enableAdminService = $true }
        "WMI" { $enableWMI = $true }
        "HTTP" { $enableHTTP = $true }
        "SMB" { $enableSMB = $true }
        default {
            Write-LogMessage Error "Unknown collection method: $method"
        }
    }
}

# Parse SiteCodes parameter
$script:TargetSiteCodes = @()
if ($SiteCodes) {
    if (Test-Path $SiteCodes) {
        # File containing site codes
        try {
            $script:TargetSiteCodes = Get-Content $SiteCodes | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
            Write-LogMessage Info "Loaded $($script:TargetSiteCodes.Count) site codes from file: $SiteCodes"
        } catch {
            Write-LogMessage Error "Failed to read site codes file: $_"
            return
        }
    } else {
        # Comma-separated string
        $script:TargetSiteCodes = $SiteCodes -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        Write-LogMessage Info "Targeting site codes: $($script:TargetSiteCodes -join ', ')"
    }
}

# Global variables
$script:CollectionTargets = @{}
$script:Sites = @()
$script:ClientDevices = @()
$script:Computers = @()
$script:Collections = @()
$script:SecurityRoles = @()
$script:AdminUsers = @()
$script:SiteSystemRoles = @()
$script:OutputFiles = @()
$script:Domain = $Domain

# Initialize output structures
$script:Nodes = @()
$script:Edges = @()

# Disable certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

#region Helper Functions

function Write-LogMessage {
    param(
        [string]$Level = "Info",
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        "Info" { "White" }
        "Important" { "Cyan" }
        "Verbose" { "Magenta" }
        "Debug" { "DarkYellow" }
        default { "White" }
    }
    
    if ($Level -eq "Verbose" -and $VerbosePreference -eq 'SilentlyContinue') {
        return
    } elseif ($Level -eq "Debug" -and $DebugPreference -eq 'SilentlyContinue') {
        return
    } else {
        Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    }
}

function Invoke-HttpRequest {
    param(
        [string]$Uri,
        [int]$TimeoutSec = 3,
        [switch]$UseDefaultCredentials = $false
    )
    
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Method = "GET"
    $request.Timeout = $TimeoutSec * 1000

    if ($UseDefaultCredentials) {
        $request.UseDefaultCredentials = $true
    }
    
    try {
        $response = $request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        
        $result = [PSCustomObject]@{
            StatusCode = [int]$response.StatusCode
            Content = $content
        }
        
        $reader.Close()
        $stream.Close()
        $response.Close()
        
        return $result
        
    } catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($webResponse) {
            $statusCode = [int]$webResponse.StatusCode
            return [PSCustomObject]@{
                StatusCode = $statusCode
                Content = $null
            }
        }
        throw
    }
}

function Test-AdminPrivileges {
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DomainController {
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $dc = Get-ADDomainController -Discover -Domain $script:Domain -ErrorAction SilentlyContinue
            return $dc.HostName[0]
        } else {
            # Fallback using .NET
            $context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new("Domain", $script:Domain)
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
            return $domain.FindDomainController().Name
        }
    } catch {
        Write-LogMessage Warning "Failed to find domain controller: $_"
        return $null
    }
}

function Add-Node {
    param(
        [string]$Id,
        [string[]]$Kinds,
        [hashtable]$Properties = @{},  # Default to empty hashtable, not null
        [PSObject]$PSObject = $null
    )
   
    # Start with provided properties
    $finalProperties = if ($Properties) { $Properties.Clone() } else { @{} }
    
    # If PSObject is provided, add its properties automatically
    if ($PSObject) {        
        # Add all non-null object properties except SID, which is already the Id
        $PSObject.PSObject.Properties | ForEach-Object {
            if ($null -ne $_.Value `
                -and $_.Name -ne "SID" `
                -and $_.Name -ne "ObjectSid" `
                -and -not $finalProperties.ContainsKey($_.Name)) {

                    $finalProperties[$_.Name] = $_.Value
            }
        }
    }
   
    # Check if node already exists and merge properties if it does
    $existingNode = $script:Nodes | Where-Object { $_.id -eq $Id }
    if ($existingNode) {
        # Track which properties are being added/updated
        $addedProperties = @()
        $updatedProperties = @()
        
        # Merge new properties into existing node
        foreach ($key in $finalProperties.Keys) {
            if ($null -ne $finalProperties[$key]) {
                if ($existingNode.properties.ContainsKey($key)) {
                    $oldValue = $existingNode.properties[$key]
                    $newValue = $finalProperties[$key]
                    
                    # Special handling for arrays - merge them
                    if ($oldValue -is [Array] -and $newValue -is [Array]) {
                        # Combine and deduplicate arrays
                        $mergedArray = @($oldValue + $newValue | Select-Object -Unique)
                        $existingNode.properties[$key] = $mergedArray
                        
                        # Update logging to show merge
                        $addedItems = $newValue | Where-Object { $_ -notin $oldValue }
                        if ($addedItems.Count -gt 0) {
                            $updatedProperties += "$key`: Added [$($addedItems -join ', ')] to existing [$($oldValue -join ', ')]"
                        }
                    } else {
                        # Non-array properties - check if different and replace
                        if ($oldValue -ne $newValue) {
                            $updatedProperties += "$key`: '$oldValue' -> '$newValue'"
                        }
                        $existingNode.properties[$key] = $newValue
                    }
                } else {
                    # New property being added
                    $valueStr = if ($finalProperties[$key] -is [Array]) { 
                        "[$($finalProperties[$key] -join ', ')]" 
                    } else { 
                        "'$($finalProperties[$key])'" 
                    }
                    $addedProperties += "$key`: $valueStr"
                    $existingNode.properties[$key] = $finalProperties[$key]
                }
            }
        }
        
        # Create verbose message showing what was added/updated
        $changes = @()
        if ($addedProperties.Count -gt 0) {
            $changes += "`n    Added:`n        $($addedProperties -join "`n        ")"
        }
        if ($updatedProperties.Count -gt 0) {
            $changes += "`n    Updated:`n        $($updatedProperties -join "`n        ")"
        }
        
        if ($changes.Count -gt 0) {
            Write-LogMessage Verbose "Found existing node: $($existingNode.properties.Name) ($Id)$changes"
        } else {
            Write-LogMessage Verbose "Found existing node: $($existingNode.properties.Name) ($Id)`nNo new properties"
        }
    } else {
        # Filter out null properties and create new node
        $cleanProperties = @{}
        foreach ($key in $finalProperties.Keys) {  # Use $finalProperties, not $Properties
            if ($null -ne $finalProperties[$key]) {
                $cleanProperties[$key] = $finalProperties[$key]
            }
        }
       
        $node = [PSCustomObject]@{
            id = $Id
            kinds = $Kinds
            properties = $cleanProperties
        }
       
        $script:Nodes += $node
        Write-LogMessage Verbose "Added $($Kinds[0]) node: $Id (node count: $($script:Nodes.Count))"
    }
   
    # Auto-create Host nodes and SameHostAs edges for Computer/ClientDevice pairs
    if ($Kinds -contains "Computer" -or $Kinds -contains "SCCM_ClientDevice") {
        Create-HostNodeIfNeeded -NodeId $Id -NodeKinds $Kinds -NodeProperties $finalProperties  # Use $finalProperties
    }
}

# Helper function to add edges during collection and processing
function Add-Edge {
    param(
        [string]$Start,
        [string]$Kind,
        [string]$End,
        [hashtable]$Properties = @{}
    )
    
    # Filter out null properties
    $cleanProperties = @{}
    foreach ($key in $Properties.Keys) {
        if ($null -ne $Properties[$key]) {
            $cleanProperties[$key] = $Properties[$key]
        }
    }

    # Create new edge
    $edge = [PSCustomObject]@{
        start = $Start
        kind = $Kind
        end = $End
        properties = $cleanProperties
    }
    
    $script:Edges += $edge
    Write-LogMessage Verbose "Added edge: $Start --[$Kind]-> $End (edge count: $($script:Edges.Count))"
}

function Create-HostNodeIfNeeded {
    param(
        [string]$NodeId,
        [string[]]$NodeKinds,
        [hashtable]$NodeProperties
    )
    
    if ($NodeKinds -contains "Computer") {
        # Look for SCCM_ClientDevice with ADDomainSID matching this Computer's ID
        $matchingClient = $script:Nodes | Where-Object { 
            $_.kinds -contains "SCCM_ClientDevice" -and 
            $_.properties.ADDomainSID -eq $NodeId 
        }
        
        if ($matchingClient) {
            Create-HostAndEdges -ComputerSid $NodeId -ClientDeviceId $matchingClient.id -Hostname $NodeProperties.dnshostname
        }
        
    } elseif ($NodeKinds -contains "SCCM_ClientDevice" -and $NodeProperties.ADDomainSID) {
        # Look for Computer with ID matching this ClientDevice's ADDomainSID
        $matchingComputer = $script:Nodes | Where-Object { 
            $_.kinds -contains "Computer" -and 
            $_.id -eq $NodeProperties.ADDomainSID 
        }
        
        if ($matchingComputer) {
            Create-HostAndEdges -ComputerSid $NodeProperties.ADDomainSID -ClientDeviceId $NodeId -Hostname $NodeProperties.DNSHostName
        }
    }
}

function Create-HostAndEdges {
    param(
        [string]$ComputerSid,
        [string]$ClientDeviceId, 
        [string]$Hostname
    )
    
    # Check if Host node already exists for this Computer SID
    if ($script:Nodes | Where-Object { $_.kinds -contains "Host" -and $_.properties.Computer -eq $ComputerSid }) {
        return  # Host already exists
    }
    
    # Generate Host node ID: dnshostname_GUID
    $hostGuid = [System.Guid]::NewGuid().ToString()
    $hostId = "${Hostname}_${hostGuid}"
    
    # Create Host node
    $script:Nodes += [PSCustomObject]@{
        id = $hostId
        kinds = @("Host")
        properties = @{
            Computer = $ComputerSid
            SCCM_ClientDevice = $ClientDeviceId
        }
    }
    
    # Create all four SameHostAs edges
    $edgesToCreate = @(
        @{Start = $ComputerSid; End = $hostId},      # Computer -> Host
        @{Start = $hostId; End = $ComputerSid},      # Host -> Computer
        @{Start = $ClientDeviceId; End = $hostId},   # ClientDevice -> Host
        @{Start = $hostId; End = $ClientDeviceId}    # Host -> ClientDevice
    )
    
    foreach ($edge in $edgesToCreate) {
        $script:Edges += [PSCustomObject]@{
            start = $edge.Start
            end = $edge.End
            kind = "SameHostAs"
        }
    }
    
    Write-LogMessage Verbose "Created Host node $hostId and SameHostAs edges for Computer: $ComputerSid"
}

#endregion

#region Domain Resolution Functions

# Initialize AD module availability at script level
$script:ADModuleAvailable = $false

function Get-ForestRoot {
    try {
        if ($script:ADModuleAvailable) {
            $rootDSE = Get-ADRootDSE -ErrorAction Stop
            return $rootDSE.rootDomainNamingContext
        } else {
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            return $rootDSE.Properties["rootDomainNamingContext"][0] 
        }
    } catch {
        Write-LogMessage Warning "Failed to retrieve forest root: $_"
    }
    return $null
}

function Get-ActiveDirectoryObject {
    param (
        [string]$Name = $null,
        [string]$Sid = $null,
        [string]$Domain = $script:Domain,
        [string[]]$Properties = @("objectSid", "DNSHostName", "distinguishedName", "samAccountName", "userPrincipalName", "objectClass")
    )
   
    if ([string]::IsNullOrWhiteSpace($Name) -and [string]::IsNullOrWhiteSpace($Sid)) { 
        return $null 
    }
    
    $searchValue = if ($Sid) { $Sid } else { $Name }
    $isSearchBySid = -not [string]::IsNullOrWhiteSpace($Sid)
    
    if ($script:ADModuleAvailable) {
        try {
            $serverParam = @{}
            if ($Domain -and $Domain -ne $env:USERDOMAIN -and $Domain -ne $env:USERDNSDOMAIN) {
                $serverParam.Server = $Domain
            }
            
            if ($isSearchBySid) {
                # Search by SID
                try {
                    $adObject = Get-ADObject -Filter "objectSid -eq '$Sid'" @serverParam -Properties $Properties -ErrorAction Stop
                    if ($adObject) {
                        # Determine object type from objectClass
                        $objectType = switch -Regex ($adObject.objectClass[-1]) {
                            "computer" { "Computer" }
                            "user" { "User" }
                            "group" { "Group" }
                            default { $adObject.objectClass[-1] }
                        }
                        
                        return [PSCustomObject]@{
                            Name = if ($adObject.DNSHostName) { $adObject.DNSHostName } elseif ($adObject.samAccountName) { "$Domain\$($adObject.samAccountName)" } else { "$Domain\$($adObject.Name)" }
                            SID = $adObject.objectSid.Value
                            Domain = $Domain
                            Type = $objectType
                            DNSHostName = $adObject.DNSHostName
                            DistinguishedName = $adObject.DistinguishedName
                            SamAccountName = $adObject.samAccountName
                            UserPrincipalName = $adObject.userPrincipalName
                            ObjectClass = $adObject.objectClass
                            Enabled = if ($adObject.PSObject.Properties.Name -contains "Enabled") { $adObject.Enabled } else { $null }
                            IsDomainPrincipal = $true
                        }
                    }
                } catch {
                    Write-LogMessage Verbose "Failed to resolve SID '$Sid' using Get-ADObject: $_"
                }
            } else {
                # Search by Name - try different search filters in priority order
                $searchFilters = @(
                    "DNSHostName -eq '$Name'",           # FQDN match
                    "samAccountName -eq '$Name'",        # SAM account name
                    "userPrincipalName -eq '$Name'",     # UPN for users
                    "Name -eq '$Name'"                   # Display name
                )
                
                # If name doesn't contain dot and doesn't end with $, try computer account format
                if ($Name -notcontains '.' -and $Name -notlike '*$') {
                    $searchFilters += "samAccountName -eq '$Name$'"
                }
                
                foreach ($filter in $searchFilters) {
                    try {
                        $adObject = Get-ADObject -Filter $filter @serverParam -Properties $Properties -ErrorAction Stop
                        if ($adObject) {
                            # Determine object type from objectClass
                            $objectType = switch -Regex ($adObject.objectClass[-1]) {
                                "computer" { "Computer" }
                                "user" { "User" }
                                "group" { "Group" }
                                default { $adObject.objectClass[-1] }
                            }
                            
                            return [PSCustomObject]@{
                                Name = if ($adObject.DNSHostName) { $adObject.DNSHostName } elseif ($adObject.samAccountName) { "$Domain\$($adObject.samAccountName)" } else { "$Domain\$($adObject.Name)" }
                                SID = if ($adObject.objectSid) { $adObject.objectSid.Value } else { $null }
                                Domain = $Domain
                                Type = $objectType
                                DNSHostName = $adObject.DNSHostName
                                DistinguishedName = $adObject.DistinguishedName
                                SamAccountName = $adObject.samAccountName
                                UserPrincipalName = $adObject.userPrincipalName
                                ObjectClass = $adObject.objectClass
                                Enabled = if ($adObject.PSObject.Properties.Name -contains "Enabled") { $adObject.Enabled } else { $null }
                                IsDomainPrincipal = $true
                            }
                        }
                    } catch { 
                        # Continue to next filter
                        continue 
                    }
                }
            }
        } catch {
            Write-LogMessage Verbose "Failed to resolve '$searchValue' using Get-ADObject: $_"
        }
    }

    # Try DirectoryServices .NET fallback
    Write-LogMessage Debug "Trying DirectoryServices for '$searchValue' in domain '$Domain'"
    
    try {
        $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
        $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($domainObj.Name)")
        
        if ($isSearchBySid) {
            # Search by SID - convert SID string to binary format for LDAP
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $sidBytes = New-Object byte[] $sidObj.BinaryLength
            $sidObj.GetBinaryForm($sidBytes, 0)
            $sidHex = ($sidBytes | ForEach-Object { '\' + $_.ToString('x2') }) -join ''
            $searcher.Filter = "(objectSid=$sidHex)"
        } else {
            # Search by Name
            $searcher.Filter = "(|(samAccountName=$Name)(cn=$Name)(dNSHostName=$Name))"
        }
        
        $searcher.PropertiesToLoad.AddRange(@("objectSid", "objectClass", "distinguishedName", "dNSHostName", "samAccountName", "cn"))
        
        $result = $searcher.FindOne()
        if ($result) {
            $sidBytes = $result.Properties["objectsid"][0]
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
            
            $objectClass = $result.Properties["objectclass"]
            $objectType = if ($objectClass -contains "computer") { "Computer" }
                            elseif ($objectClass -contains "user") { "User" } 
                            elseif ($objectClass -contains "group") { "Group" }
                            else { "Object" }
            
            $resolvedName = if ($result.Properties["samaccountname"].Count -gt 0) { $result.Properties["samaccountname"][0] } else { $result.Properties["cn"][0] }
            $dnsHostName = if ($result.Properties["dnshostname"].Count -gt 0) { $result.Properties["dnshostname"][0] } else { $null }
            
            return [PSCustomObject]@{
                Name = if ($dnsHostName) { $dnsHostName } else { "$Domain\$resolvedName" }
                SID = $sid
                Domain = $Domain
                Type = $objectType
                DNSHostName = $dnsHostName
                DistinguishedName = $result.Properties["distinguishedname"][0]
                SamAccountName = $resolvedName
                UserPrincipalName = $null
                ObjectClass = $objectClass
                Enabled = $null
                IsDomainPrincipal = $true
            }
        }
    } catch {
        Write-LogMessage Warning "DirectorySearcher failed for '$searchValue' in domain '$Domain': $_"
    }
    
    # Try NTAccount translation as last resort
    try {
        Write-LogMessage Verbose "Attempting NTAccount translation for '$searchValue' in domain '$Domain'"
        
        if ($isSearchBySid -or $Name -match "^S-\d+-\d+") {
            # SID to name translation
            $sidValue = if ($isSearchBySid) { $Sid } else { $Name }
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
            $resolvedName = $sid.Translate([System.Security.Principal.NTAccount]).Value
            
            return [PSCustomObject]@{
                Name = $resolvedName
                SID = $sidValue
                Domain = $Domain
                Type = "Unknown"
                DNSHostName = $null
                DistinguishedName = $null
                SamAccountName = $null
                UserPrincipalName = $null
                ObjectClass = $null
                Enabled = $null
                IsDomainPrincipal = $true
            }
        } else {
            # Name to SID translation
            $ntAccount = New-Object System.Security.Principal.NTAccount($Domain, $Name)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
            
            return [PSCustomObject]@{
                Name = "$Domain\$Name"
                SID = $sid.Value
                Domain = $Domain
                Type = "Unknown"
                DNSHostName = $null
                DistinguishedName = $null
                SamAccountName = $Name
                UserPrincipalName = $null
                ObjectClass = $null
                Enabled = $null
                IsDomainPrincipal = $true
            }
        }
    } catch {
        Write-LogMessage Verbose "NTAccount translation failed for '$searchValue' in domain '$Domain': $_"
    }
    
    # Return failure
    return $null
}

#endregion

#region LDAP Collection

function Invoke-LDAPCollection {
    Write-LogMessage Info "Starting LDAP collection..."
    
    try {
        if (-not $script:Domain) {
            Write-LogMessage Warning "No domain specified for LDAP collection"
            return
        }
        
        # Build domain DN
        $domainDN = ($script:Domain -split '\.') -replace '^', 'DC=' -join ','
        $systemManagementDN = "CN=System Management,CN=System,$domainDN"
        
        Write-LogMessage Info "Searching System Management container: $systemManagementDN"
        
        # Get forest root using our resolution function
        $forestRoot = Get-ForestRoot
        if ($forestRoot) {
            Write-LogMessage Verbose "Found forest root: $forestRoot"
        }
        
        # Get all mSSMSSite objects (Primary sites)
        Write-LogMessage Info "Collecting mSSMSSite objects..."
        $mSSMSSiteObjects = @()
        
        if ($script:ADModuleAvailable) {
            $mSSMSSiteObjects = Get-ADObject -LDAPFilter "(objectClass=mSSMSSite)" -SearchBase $systemManagementDN -Properties mSSMSHealthState, mSSMSSiteCode, mSSMSSourceForest, objectClass, distinguishedName -ErrorAction SilentlyContinue
        } else {
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$systemManagementDN")
                $searcher.Filter = "(objectClass=mSSMSSite)"
                $searcher.PropertiesToLoad.AddRange(@("mSSMSHealthState", "mSSMSSiteCode", "mSSMSSourceForest", "objectClass", "distinguishedName"))
                
                $results = $searcher.FindAll()
                foreach ($result in $results) {
                    $mSSMSSiteObjects += [PSCustomObject]@{
                        DistinguishedName = $result.Properties["distinguishedName"][0]
                        mSSMSHealthState = $result.Properties["mSSMSHealthState"][0]
                        mSSMSSiteCode = $result.Properties["mSSMSSiteCode"][0]
                        mSSMSSourceForest = $result.Properties["mSSMSSourceForest"][0]
                    }
                }
            } catch {
                Write-LogMessage Warning "DirectorySearcher failed for mSSMSSite objects: $_"
            }
        }
        
        foreach ($mSSMSSiteObj in $mSSMSSiteObjects) {
            $siteCode = $mSSMSSiteObj.mSSMSSiteCode

            Write-LogMessage Success "Found site: $siteCode"
            
            # Parse health state for SiteGUID
            $siteGuid = $null
            if ($mSSMSSiteObj.mSSMSHealthState) {
                if ($mSSMSSiteObj.mSSMSHealthState -match "$siteCode\.(\{[^}]+\})") {
                    $siteGuid = $matches[1]
                }
            }
            
            # Use only site code as ObjectIdentifier for LDAP collection
            $objectIdentifier = $siteCode
            
            # Create/update SCCM_Site node
            Add-Node -Id $objectIdentifier -Kinds @("SCCM_Site") -Properties @{
                CollectionSource = @("LDAP-mSSMSSite")
                Name = $null
                DistinguishedName = $mSSMSSiteObj.DistinguishedName
                ParentSiteCode = $null # Will be determined by mSSMSManagementPoint
                ParentSiteGUID = $null # Will be determined by mSSMSManagementPoint
                ParentSiteIdentifier = $null # Will be determined by mSSMSManagementPoint
                SiteCode = $siteCode
                SiteGUID = $siteGuid
                SiteName = $null
                SiteServerDomain = $null
                SiteServerName = $null
                SiteServerObjectIdentifier = $null
                SiteType = $null # Will be determined by mSSMSManagementPoint
                SourceForest = $mSSMSSiteObj.mSSMSSourceForest
                SQLDatabaseName = $null
                SQLServerName = $null
                SQLServerObjectIdentifier = $null
                SQLServiceAccount = $null
                SQLServiceAccountObjectIdentifier = $null
            }
        }
        
        # Get all mSSMSManagementPoint objects
        Write-LogMessage Info "Collecting mSSMSManagementPoint objects..."
        $mSSMSManagementPoints = @()
        
        if ($script:ADModuleAvailable) {
            $mSSMSManagementPoints = Get-ADObject -LDAPFilter "(ObjectClass=mSSMSManagementPoint)" -SearchBase $systemManagementDN -Properties mSSMSMPName, mSSMSSiteCode, mSSMSCapabilities -ErrorAction SilentlyContinue
        } else {
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$systemManagementDN")
                $searcher.Filter = "(ObjectClass=mSSMSManagementPoint)"
                $searcher.PropertiesToLoad.AddRange(@("mSSMSMPName", "mSSMSSiteCode", "mSSMSCapabilities"))
                
                $results = $searcher.FindAll()
                foreach ($result in $results) {
                    $mSSMSManagementPoints += [PSCustomObject]@{
                        mSSMSMPName = $result.Properties["mSSMSMPName"][0]
                        mSSMSSiteCode = $result.Properties["mSSMSSiteCode"][0]
                        mSSMSCapabilities = $result.Properties["mSSMSCapabilities"][0]
                    }
                }
            } catch {
                Write-LogMessage Warning "DirectorySearcher failed for mSSMSManagementPoint objects: $_"
            }
        }
        
        foreach ($mSSMSManagementPoint in $mSSMSManagementPoints) {
            $mpHostname = $mSSMSManagementPoint.mSSMSMPName
            $mpSiteCode = $mSSMSManagementPoint.mSSMSSiteCode
            
            # Add to collection targets for subsequent phases
            if ($mpHostname) {
                $mpTarget = Add-DeviceToTargets -DeviceName $mpHostname -Source "LDAP-mSSMSManagementPoint"
                if ($mpTarget -and $mpTarget.IsNew) {
                    Write-LogMessage Success "Found management point: $($mpTarget.Hostname) (site: $mpSiteCode)"
                }
                # Create or update Computer node
                if ($mpTarget.ADObject) {
                    Add-Node -Id $mpTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $mpTarget.ADObject -Properties @{
                        CollectionSource = @("LDAP-mSSMSManagementPoint")
                        SCCM_SiteSystemRoles = @("SMS Management Point@$mpSiteCode")
                    }
                }
            }
            
            $sourceForest = $null
            $commandLineSiteCode = $null
            $rootSiteCode = $null

            # Parse capabilities to determine site relationships and extract SourceForest
            if ($mSSMSManagementPoint.mSSMSCapabilities) {
                try {
                    # Clean XML entities
                    $cleanXml = $mSSMSManagementPoint.mSSMSCapabilities -replace '&(?!amp;|lt;|gt;|quot;|apos;)', '&amp;'
                    [xml]$mSSMSCapabilities = $cleanXml

                    # Extract CommandLine site code
                    $commandLine = $mSSMSCapabilities.ClientOperationalSettings.CCM.CommandLine
                    if ($commandLine -match "SMSSITECODE=([A-Z0-9]{3})") {
                        $commandLineSiteCode = $matches[1]
                    }

                    # Extract root site code
                    $rootSiteCode = $mSSMSCapabilities.ClientOperationalSettings.RootSiteCode

                    # Extract source forest
                    $forestElement = $mSSMSCapabilities.ClientOperationalSettings.Forest
                    if ($forestElement) {
                        $sourceForest = $forestElement.Value
                    }
                } catch {
                    Write-LogMessage Error "Failed to parse capabilities for MP $mpHostname`: $_"
                    $mSSMSCapabilities = $null
                }
                    
                # Determine site type based on design specification
                $siteType = "Secondary Site"  # Default assumption
                $parentSiteCode = $null
                $parentSiteIdentifier = $null

                # Check if this MP's CommandLine site code matches the site code we're analyzing
                if ($commandLineSiteCode -eq $mpSiteCode) {
                    # Primary Site: mSSMSManagementPoint exists where CommandLine.SMSSITECODE = this site code
                    $siteType = "Primary Site"
                    
                    # Check if there's a different root site code (indicates hierarchy)
                    if ($rootSiteCode -and $rootSiteCode -ne $mpSiteCode) {
                        $parentSiteCode = $rootSiteCode
                        $parentSiteIdentifier = $rootSiteCode
                    } else {
                        $parentSiteCode = "None"
                        $parentSiteIdentifier = "None"
                    }
                }
                elseif ($rootSiteCode -eq $mpSiteCode -and $commandLineSiteCode -ne $mpSiteCode) {
                    # Central Administration Site: mSSMSManagementPoint exists where RootSiteCode = this site code
                    # but CommandLine.SMSSITECODE is different
                    $siteType = "Central Administration Site"
                    $parentSiteCode = "None"
                    $parentSiteIdentifier = "None"
                }
                # If neither condition above is met, it remains "Secondary Site"
                
                # Update existing SCCM_Site node with MP-derived information
                $existingSiteNode = $script:Nodes | Where-Object { $_.id -eq $mpSiteCode }
                if ($existingSiteNode) {
                    $existingSiteNode.properties.SiteType = $siteType
                    $existingSiteNode.properties.ParentSiteCode = $parentSiteCode
                    $existingSiteNode.properties.ParentSiteIdentifier = $parentSiteIdentifier
                    if ($sourceForest) {
                        $existingSiteNode.properties.SourceForest = $sourceForest
                    }
                    
                    # Add MP as collection source
                    if ($existingSiteNode.properties.CollectionSource -notcontains "LDAP-mSSMSManagementPoint") {
                        $existingSiteNode.properties.CollectionSource += "LDAP-mSSMSManagementPoint"
                    }
                    
                    Write-LogMessage Verbose "Updated site type for $($mpSiteCode): $siteType"
                }
                
                # Create parent CAS site node if it doesn't exist and we found one
                if ($parentSiteCode -and $parentSiteCode -ne "None") {
                    $existingParentSite = $script:Nodes | Where-Object { $_.id -eq $parentSiteCode }
                    if (-not $existingParentSite) {
                        Add-Node -Id $parentSiteCode -Kinds @("SCCM_Site") -Properties @{
                            CollectionSource = @("LDAP-mSSMSManagementPoint")
                            Name = $parentSiteCode
                            DistinguishedName = $null
                            ParentSiteCode = "None"
                            ParentSiteGUID = $null
                            ParentSiteIdentifier = "None"
                            SiteCode = $parentSiteCode
                            SiteGUID = $null
                            SiteName = $null
                            SiteServerDomain = $null
                            SiteServerName = $null
                            SiteServerObjectIdentifier = $null
                            SiteType = "Central Administration Site"
                            SourceForest = $sourceForest
                            SQLDatabaseName = $null
                            SQLServerName = $null
                            SQLServerObjectIdentifier = $null
                            SQLServiceAccount = $null
                            SQLServiceAccountObjectIdentifier = $null
                        }
                        
                        Write-LogMessage Success "Found central administration site: $parentSiteCode"
                    }
                }
                
                # Parse for fallback status points and create Computer nodes
                if ($fspNodes = $capabilities.ClientOperationalSettings.FSP) {
                    $fspNodes = $capabilities.ClientOperationalSettings.FSP.SelectNodes("FSPServer")
                    foreach ($fsp in $fspNodes) {
                        $fspHostname = $fsp.InnerText
                        $fspTarget = Add-DeviceToTargets -DeviceName $fspHostname -Source "LDAP-mSSMSManagementPoint"
        
                        if ($fspTarget -and $fspTarget.IsNew) {
                            Write-LogMessage Success "Found fallback status point: $($fspTarget.Hostname)"                          
                        }
                        # Create or update Computer node
                        if ($fspTarget.ADObject) {
                            Add-Node -Id $fspTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $fspTarget.ADObject -Properties @{
                                CollectionSource = @("LDAP-mSSMSManagementPoint")
                                SCCM_SiteSystemRoles = @("SMS Fallback Status Point@$siteCode")
                            }
                        }
                    }
                }
            }
        }
        
        # Get computers with CmRcService SPN (possible client devices)
        Write-LogMessage Info "Collecting computers with Remote Control SPN..."
        $remoteControlSystems = @()

        if ($script:ADModuleAvailable) {
            $remoteControlSystems = Get-ADObject -LDAPFilter "(servicePrincipalName=CmRcService/*)" -Properties DNSHostName, DistinguishedName, ObjectClass, ServicePrincipalName, ObjectSid, CN, Name -ErrorAction SilentlyContinue
        } else {
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
                $searcher.Filter = "(servicePrincipalName=CmRcService/*)"
                $searcher.PropertiesToLoad.AddRange(@("dNSHostName", "distinguishedName", "objectClass", "servicePrincipalName", "objectSid", "cn", "name"))
            
                $results = $searcher.FindAll()
                foreach ($result in $results) {
                    $sidBytes = $result.Properties["objectsid"][0]
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                
                    $remoteControlSystems += [PSCustomObject]@{
                        Name = $result.Properties["name"][0]
                        CN = $result.Properties["cn"][0]
                        DistinguishedName = $result.Properties["distinguishedname"][0]
                        DNSHostName = $result.Properties["dnshostname"][0]
                        DOmain = $result.Properties["domain"]
                        ObjectClass = $result.Properties["objectclass"]
                        ObjectSid = @{ Value = $sid.Value }
                        ServicePrincipalName = $result.Properties["serviceprincipalname"]
                    }
                }
            } catch {
                Write-LogMessage Warning "DirectorySearcher failed for CmRcService SPN objects: $_"
            }
        }

        foreach ($system in $remoteControlSystems) {

            Write-LogMessage Success "Found computer with Remote Control SPN: $($system.DNSHostName)"

            # Create Computer node for these systems
            if ($system.ObjectSid) {
                Add-Node -Id $system.ObjectSid.Value -Kinds @("Computer", "Base") -PSObject $system -Properties @{
                    CollectionSource = @("LDAP-CmRcService")
                    SCCM_HasClientRemoteControlSPN = $true
                }
            }
        }
        
        # Get systems with WDS/PXE enabled (possible distribution points)
        Write-LogMessage Info "Collecting network boot servers..."
        $networkBootServers = @()

        if ($script:ADModuleAvailable) {
            # Search for both connectionPoint with netbootserver and intellimirrorSCP objects
            $connectionPoints = Get-ADObject -LDAPFilter "(&(objectclass=connectionPoint)(netbootserver=*))" -SearchBase $domainDN -Properties netbootserver, DistinguishedName -ErrorAction SilentlyContinue
            $intellimirrorObjects = Get-ADObject -LDAPFilter "(objectclass=intellimirrorSCP)" -SearchBase $domainDN -Properties DistinguishedName -ErrorAction SilentlyContinue
            
            # Combine both result sets
            $networkBootServers = @($connectionPoints) + @($intellimirrorObjects)
        } else {
            try {
                # Search for connectionPoint objects with netbootserver
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
                $searcher.Filter = "(&(objectclass=connectionPoint)(netbootserver=*))"
                $searcher.PropertiesToLoad.Add("distinguishedName")
                
                $results = $searcher.FindAll()
                foreach ($result in $results) {
                    $networkBootServers += [PSCustomObject]@{
                        DistinguishedName = $result.Properties["distinguishedname"][0]
                        ObjectClass = "connectionPoint"
                    }
                }
                
                # Search for intellimirrorSCP objects
                $searcher.Filter = "(objectclass=intellimirrorSCP)"
                $searcher.PropertiesToLoad.Clear()
                $searcher.PropertiesToLoad.Add("distinguishedName")
                
                $results = $searcher.FindAll()
                foreach ($result in $results) {
                    $networkBootServers += [PSCustomObject]@{
                        DistinguishedName = $result.Properties["distinguishedname"][0]
                        ObjectClass = "intellimirrorSCP"
                    }
                }
            } catch {
                Write-LogMessage Warning "DirectorySearcher failed for network boot servers: $_"
            }
        }

        foreach ($server in $networkBootServers) {
            try {
                # Extract everything after the first comma to get parent DN (the computer object)
                $parentDN = $server.DistinguishedName -replace '^[^,]+,', ''
                
                $parentObject = $null
                if ($script:ADModuleAvailable) {
                    $parentObject = Get-ADObject -Identity $parentDN -Properties DNSHostName, ObjectSid, Name -ErrorAction SilentlyContinue
                } else {
                    $parentEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$parentDN")
                    if ($parentEntry.Properties["dNSHostName"].Count -gt 0) {
                        $parentObject = [PSCustomObject]@{
                            DNSHostName = $parentEntry.Properties["dNSHostName"][0]
                            ObjectSid = if ($parentEntry.Properties["objectSid"].Count -gt 0) { 
                                (New-Object System.Security.Principal.SecurityIdentifier($parentEntry.Properties["objectSid"][0], 0)).Value 
                            } else { $null }
                            Name = if ($parentEntry.Properties["name"].Count -gt 0) { $parentEntry.Properties["name"][0] } else { $null }
                        }
                    }
                    $parentEntry.Dispose()
                }
                
                if ($parentObject -and $parentObject.DNSHostName -and $parentObject.ObjectSid) {
                    # Add to targets for subsequent collection phases
                    $collectionTarget = Add-DeviceToTargets -DeviceName $parentObject.DNSHostName -Source "LDAP-$($server.ObjectClass)"
                    if ($collectionTarget -and $collectionTarget.IsNew) {
                        Write-LogMessage Success "Found network boot server: $($parentObject.DNSHostName) ($($parentObject.ObjectSid))"
                    }

                    # Create or update Computer node
                    if ($collectionTarget.ADObject) {
                        
                        Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                            CollectionSource = @("LDAP-$($server.ObjectClass)")
                            NetworkBootServer = $true
                        }
                    }
                }
                
            } catch {
                Write-LogMessage Error "Failed to process network boot server $($server.DistinguishedName): $_"
            }
        }
        
        # Search for computers with SCCM-related naming patterns
        Write-LogMessage Info "Searching for computers with SCCM naming patterns..."
        $searchPatterns = @("sccm", "mecm", "mcm", "memcm", "configm", "cfgm", "sms")

        # Build dynamic LDAP filter
        $ldapFilter = "(&(objectCategory=computer)(|"
        foreach ($pattern in $searchPatterns) {
            $ldapFilter += "(samaccountname=*$pattern*)"
            $ldapFilter += "(description=*$pattern*)"
            $ldapFilter += "(name=*$pattern*)"
            $ldapFilter += "(cn=*$pattern*)"
            $ldapFilter += "(displayname=*$pattern*)"
            $ldapFilter += "(serviceprincipalname=*$pattern*)"
            $ldapFilter += "(dnshostname=*$pattern*)"
        }
        $ldapFilter += "))"

        $patternMatches = @()
        if ($script:ADModuleAvailable) {
            $patternMatches = Get-ADObject -LDAPFilter $ldapFilter -SearchBase $domainDN -Properties samaccountname, description, name, displayname, serviceprincipalname, dnshostname, objectClass, objectSid -ErrorAction SilentlyContinue
        } else {
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
                $searcher.Filter = $ldapFilter
                $searcher.PropertiesToLoad.AddRange(@("samaccountname", "description", "name", "displayname", "serviceprincipalname", "dnshostname", "objectClass", "objectSid"))
                
                $results = $searcher.FindAll()
                foreach ($result in $results) {
                    $patternMatches += [PSCustomObject]@{
                        samaccountname = if ($result.Properties["samaccountname"].Count -gt 0) { $result.Properties["samaccountname"][0] } else { $null }
                        description = if ($result.Properties["description"].Count -gt 0) { $result.Properties["description"][0] } else { $null }
                        name = if ($result.Properties["name"].Count -gt 0) { $result.Properties["name"][0] } else { $null }
                        displayname = if ($result.Properties["displayname"].Count -gt 0) { $result.Properties["displayname"][0] } else { $null }
                        serviceprincipalname = $result.Properties["serviceprincipalname"]
                        dnshostname = if ($result.Properties["dnshostname"].Count -gt 0) { $result.Properties["dnshostname"][0] } else { $null }
                        objectClass = $result.Properties["objectclass"]
                        objectSid = if ($result.Properties["objectsid"].Count -gt 0) {
                            $sidBytes = $result.Properties["objectsid"][0]
                            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                            @{ Value = $sid.Value }
                        } else { $null }
                    }
                }
                $searcher.Dispose()
            } catch {
                Write-LogMessage Error "DirectorySearcher failed for SCCM naming patterns: $_"
            }
        }

        foreach ($match in $patternMatches) {
            if ($match.objectSid -and $match.objectSid.Value -and $match.dnshostname) {
                $hostname = $match.dnshostname
                $objectSid = $match.objectSid.Value

                # Add to collection targets for subsequent collection phases
                $collectionTarget = Add-DeviceToTargets -DeviceName $hostname -Source "LDAP-NamePattern"
                if ($collectionTarget -and $collectionTarget.IsNew) {
                    Write-LogMessage Success "Found system with SCCM naming pattern: $hostname ($objectSid)"
                }
                
                # Create or update Computer node
                if ($collectionTarget.ADObject) {

                    Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                        CollectionSource = @("LDAP-NamePattern")
                    }
                
                }
            } else {
                Write-LogMessage Warning "Missing required properties (SID or hostname): $($match.name)"
            }
        }
                
        # Get accounts with GenericAll on System Management container
        Write-LogMessage Info "Checking permissions on System Management container..."
        try {
            if ($script:ADModuleAvailable) {
                $acl = Get-Acl -Path "AD:\$systemManagementDN"
                $genericAllAccounts = $acl.Access | Where-Object {
                    $_.AccessControlType -eq "Allow" -and
                    $_.ActiveDirectoryRights -eq "GenericAll"
                    $_.IdentityReference -notlike "NT AUTHORITY\*"
                }
                
                foreach ($account in $genericAllAccounts) {
                    Write-LogMessage Success "Found principal with GenericAll on System Management container: $($account.IdentityReference)"
                    
                    # Extract account name (remove domain prefix and potentially $ suffix)
                    $identityRef = $account.IdentityReference.ToString()
                    $accountName = $identityRef -replace '.*\\', ''
                    
                    # Handle computer accounts (ending with $) vs user/group accounts
                    $isComputerAccount = $accountName -match '\$$'
                    if ($isComputerAccount) {
                        $accountName = $accountName -replace '\$$', ''
                    }
                    
                    # Resolve to AD Object
                    $adObject = Get-ActiveDirectoryObject -Name $accountName -Domain $script:Domain
                    
                    if ($adObject -and $adObject.SID) {
                        Write-LogMessage Verbose "Resolved principal to $($adObject.Type): $($adObject.Name) ($($adObject.SID))"
                        
                        # Create appropriate node based on object type
                        switch ($adObject.Type) {
                            "Computer" {                                
                                Add-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                                    CollectionSource = @("LDAP-GenericAllSystemManagement")
                                }
                                
                                # Add to collection targets for subsequent collection phases
                                if ($adObject.DNSHostName) {
                                    $null = Add-DeviceToTargets -DeviceName $adObject.DNSHostName -Source "LDAP-GenericAll"
                                } else {
                                    Write-LogMessage Warning "Cannot add computer $($adObject.Name) to targets - no FQDN available"
                                }
                            }
                            
                            "User" {
                                Add-Node -Id $adObject.SID -Kinds @("User", "Base") -PSObject $adObject -Properties @{
                                    CollectionSource = @("LDAP-GenericAllSystemManagement")
                                }
                            }
                            
                            "Group" {                              
                                Add-Node -Id $adObject.SID -Kinds @("Group", "Base") -PSObject $adObject -Properties @{
                                    CollectionSource = @("LDAP-GenericAllSystemManagement")
                                }
                            }
                            
                            default {
                                # Handle unknown object types
                                Add-Node -Id $adObject.SID -Kinds @($adObject.Type, "Base") -PSObject $adObject -Properties @{
                                    CollectionSource = @("LDAP-GenericAllSystemManagement")
                                }
                                Write-LogMessage Warning "Created node for unknown object type '$($adObject.Type)': $($adObject.Name)"
                            }
                        }
                    } else {
                        Write-LogMessage Warning "Could not resolve GenericAll account '$accountName' to domain object"
                    }
                }
            } else {
                # Try using .NET DirectoryServices to check ACL
                try {
                    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$systemManagementDN")
                    $ntSecurityDescriptor = $directoryEntry.ObjectSecurity
                    $accessRules = $ntSecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
                    
                    foreach ($rule in $accessRules) {
                        if ($rule.AccessControlType -eq "Allow" -and
                            $rule.ActiveDirectoryRights -match "GenericAll" -and
                            $rule.IdentityReference -notlike "NT AUTHORITY\*")  {
                            
                            Write-LogMessage Success "Found principal with GenericAll on System Management container: $($rule.IdentityReference)"
                            
                            # Extract account name (remove domain prefix and potentially $ suffix)
                            $identityRef = $rule.IdentityReference.ToString()
                            $accountName = $identityRef -replace '.*\\', ''
                            
                            # Handle computer accounts (ending with $) vs user/group accounts
                            $isComputerAccount = $accountName -match '\$$'
                            if ($isComputerAccount) {
                                $accountName = $accountName -replace '\$$', ''
                            }
                            
                            # Resolve using our new generic function
                            $adObject = Get-ActiveDirectoryObject -Name $accountName -Domain $script:Domain
                            
                            if ($adObject -and $adObject.SID) {
                                Write-LogMessage Verbose "Resolved principal to $($adObject.Type): $($adObject.Name) ($($adObject.SID))"
                                
                                # Create appropriate node based on object type (same switch logic as above)
                                switch ($adObject.Type) {
                                    "Computer" {
                                        Add-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                                            CollectionSource = @("LDAP-GenericAllSystemManagement")
                                        }
                                        
                                        # Add to collection targets for subsequent collection phases
                                        if ($adObject.DNSHostName) {
                                            $null = Add-DeviceToTargets -DeviceName $adObject.DNSHostName -Source "LDAP-GenericAll"
                                        } else {
                                            Write-LogMessage Warning "Cannot add computer $($adObject.Name) to targets - no FQDN available"
                                        }
                                    }
                                    
                                    "User" {
                                        Add-Node -Id $adObject.SID -Kinds @("User", "Base") -PSObject $adObject -Properties @{
                                            CollectionSource = @("LDAP-GenericAllSystemManagement")
                                        }
                                    }
                                    
                                    "Group" {
                                        Add-Node -Id $adObject.SID -Kinds @("Group", "Base") -PSObject $adObject -Properties @{
                                            CollectionSource = @("LDAP-GenericAllSystemManagement")
                                        }
                                    }
                                }
                            } else {
                                Write-LogMessage Warning "Could not resolve principal '$accountName' to domain object"
                            }
                        }
                    }
                    $directoryEntry.Dispose()
                } catch {
                    Write-LogMessage Error "DirectoryServices ACL check failed: $_"
                }
            }
        } catch {
            Write-LogMessage Error "Failed to check System Management container permissions: $_"
        }
        
        # Report what was collected
        Write-LogMessage Success "LDAP collection completed"
        Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCM_SiteSystemRoles } | ForEach-Object { "$($_.Properties.Name) ($($_.Properties.SCCM_SiteSystemRoles -join ', '))" }) -join "`n    ")"
        Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
    } catch {
        Write-LogMessage "LDAP collection failed: $_" -Level "Error"
    }
}

#endregion

#region Local Collection

function Invoke-LocalCollection {
    Write-LogMessage Info "Starting Local collection..."
    
    try {
        # Check if running on SCCM client by testing WMI namespaces
        $ccmNamespaceExists = $false
        try {
            Get-WmiObject -Namespace "root\CCM" -Class "__Namespace" -ErrorAction Stop | Out-Null
            $ccmNamespaceExists = $true
        } catch {
            Write-LogMessage Warning "SCCM client WMI namespace not detected on local machine"
            return
        }
        
        if (-not $ccmNamespaceExists) {
            Write-LogMessage Warning "SCCM client not detected on local machine"
            return
        }
        
        Write-LogMessage Success "SCCM client detected on local machine"
        
        # Get current management point and site code from SMS_Authority
        Write-LogMessage Info "Querying SMS_Authority for current management point and site code..."
        $smsAuthority = Get-WmiObject -Namespace "root\CCM" -Class "SMS_Authority" -Property CurrentManagementPoint, Name -ErrorAction SilentlyContinue
        
        $siteCode = $null
        $currentMP = $null
        
        if ($smsAuthority) {
            $currentMP = $smsAuthority.CurrentManagementPoint
            # Extract site code from Name property (format: "SMS:PS1")
            if ($smsAuthority.Name -match "SMS:([A-Z0-9]{3})") {
                $siteCode = $matches[1]
                Write-LogMessage Verbose "Site code in SMS_Authority: $siteCode"
                Write-LogMessage Verbose "Current management point: $currentMP"
            }
        }
        
        # Create or update Site object if site code found
        if ($siteCode) {
            Add-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                "CollectionSource" = "Local-SMS_Authority"
                "SiteCode" = $siteCode
                "SiteType" = 2  # Primary (clients can only be joined to primary sites)
            }
        }
        
        # Get additional management points from SMS_LookupMP
        Write-LogMessage Info "Querying SMS_LookupMP for additional management points..."
        $lookupMPs = Get-WmiObject -Namespace "root\CCM" -Class "SMS_LookupMP" -Property Name -ErrorAction SilentlyContinue
        
        $allManagementPoints = @()
        if ($currentMP) { $allManagementPoints += $currentMP }
        
        foreach ($mp in $lookupMPs) {
            if ($mp.Name -and $mp.Name -notin $allManagementPoints) {
                $allManagementPoints += $mp.Name
            }
        }
        
        # Add management points to collection targets and site system roles
        foreach ($mpHostname in $allManagementPoints) {
            if ($mpHostname) {
                # Add to collection targets for subsequent phases
                $mp = Add-DeviceToTargets -DeviceName $mpHostname -Source "Local-SMS_LookupMP"
                if ($mp -and $mp.IsNew) {
                    Write-LogMessage Success "Found management point: $mpHostname"
                }
                
                if ($mp.ADObject) {
                    Add-Node -Id $mp.ADObject.SID -Kinds @("Computer", "Base") -PSObject $mp.ADObject -Properties @{
                        CollectionSource = @("Local-SMS_LookupMP")
                        SCCM_SiteSystemRoles = @("SMS Management Point@$siteCode")
                    }
                }
            }
        }
        
        # Get client settings from CCM_Client
        Write-LogMessage Info "Querying CCM_Client for client information..."
        $ccmClient = Get-WmiObject -Namespace "root\CCM" -Class "CCM_Client" -ErrorAction SilentlyContinue

        $clientId = $null
        $clientIdChangeDate = $null
        $previousClientId = $null

        if ($ccmClient) {
            $clientId = $ccmClient.ClientId
            $clientIdChangeDate = $ccmClient.ClientIdChangeDate
            $previousClientId = $ccmClient.PreviousClientId
            
            Write-LogMessage Verbose "Found client ID (SMSID): $clientId"
            Write-LogMessage Verbose "Client ID change date: $clientIdChangeDate"
        }

        # Create ClientDevice object for the local machine
        if ($siteCode -and $clientId) {
            # Get local computer information
            $computerName = $env:COMPUTERNAME
            $domainName = $env:USERDNSDOMAIN
            $fqdn = if ($domainName) { "$computerName.$domainName" } else { $computerName }
            
            # Add to collection targets using established pattern
            $localTarget = Add-DeviceToTargets -DeviceName $fqdn -Source "Local-CCM_Client"
            if ($localTarget -and $localTarget.IsNew) {
                Write-LogMessage Success "Found local client device: $fqdn (SMSID: $clientId)"
            }
            
            # Resolve current management point SID
            $currentMPSid = $null
            if ($currentMP -and $localTarget.ADObject) {
                $mpObject = Get-ActiveDirectoryObject -Name $currentMP -Domain $script:Domain
                $currentMPSid = $mpObject.SID
            }
            
            # Create SCCM_ClientDevice node
            Add-Node -Id $clientId -Kinds @("SCCM_ClientDevice") -Properties @{
                CollectionSource = @("Local-CCM_Client")
                ADDomainSID = if ($localTarget.ADObject) { $localTarget.ADObject.SID } else { $null }
                CurrentManagementPoint = $currentMP
                CurrentManagementPointSID = $currentMPSid
                DistinguishedName = if ($localTarget.ADObject) { $localTarget.ADObject.DistinguishedName } else { $null }
                DNSHostName = if ($localTarget.ADObject) { $localTarget.ADObject.DNSHostName } else { $null }
                SiteCode = $siteCode
                SMSID = $clientId
            }
            
            # Also create/update the Computer node for the system running the collector
            Add-Node -Id $localTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $localTarget.ADObject -Properties @{
                CollectionSource = @("Local-CCM_Client")
            }
        }
        
        # Search SCCM client log data for UNC paths and URLs that are likely to be SCCM components
        Write-LogMessage Info "Searching SCCM client logs for additional SCCM components..."
        try {
            $logPaths = @(
                "$env:WINDIR\CCM\Logs\*.log",
                "$env:WINDIR\CCMSetup\Logs\*.log"
            )
            
            $uncPaths = @()
            $additionalComponents = @{}
            
            foreach ($logPath in $logPaths) {
                if (Test-Path $logPath) {
                    $logFiles = Get-ChildItem -Path $logPath -ErrorAction SilentlyContinue
                    foreach ($logFile in $logFiles) {
                        try {
                            Write-LogMessage "$logFile" -Level Verbose
                            $content = Get-Content -Path $logFile.FullName -ErrorAction SilentlyContinue
                            
                            # Look for UNC paths and URLs that might be SCCM components
                            $uncMatches = $content | Select-String -Pattern "(\\\\([a-zA-Z0-9\-_\s]{2,15})(\.[a-zA-Z0-9\-_\s]{1,64}){0,3})(\\[^\\\/:\*\?`"<>\|;]{1,64})+(\\)?" -AllMatches
                            $urlMatches = $content | Select-String -Pattern "(?<Protocol>\w+):\/\/(?<Domain>[\w@][\w.:@]+)\/?[\w\.?=%&=\-@/$,]*" -AllMatches
        
                            # Process UNC paths
                            foreach ($match in $uncMatches) {
                                foreach ($matchGroup in $match.Matches) {
                                    $uncPath = $matchGroup.Value.Trim()
                                    Write-LogMessage "Found UNC path: $uncPath" -Level Debug
                                    
                                    # Extract hostname from UNC path
                                    if ($uncPath -match "^\\\\([^\\]+)") {
                                        $hostname = $matches[1].Trim()
                                        
                                        # Skip localhost references and current machine
                                        if ($hostname -notin @("localhost", "127.0.0.1", $env:COMPUTERNAME, $env:COMPUTERNAME.ToLower())) {
                                            # Resolve hostname to IP address then check for RFC1918
                                            $shouldAdd = $false
                                            try {
                                                $resolvedIPs = [System.Net.Dns]::GetHostAddresses($hostname)
                                                foreach ($ip in $resolvedIPs) {
                                                    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                                                        $bytes = $ip.GetAddressBytes()
                                                        # Check RFC1918 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                                                        $isRFC1918 = ($bytes[0] -eq 10) -or 
                                                                     ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                                                                     ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
                                                        if ($isRFC1918) {
                                                            $shouldAdd = $true
                                                            break
                                                        } else {
                                                            Write-LogMessage Debug "Host resolved to non-RFC1918 IP address: $hostname ($($ip.IPAddressToString))"
                                                        }
                                                    }
                                                }
                                            } catch {
                                                # DNS resolution failed
                                                Write-LogMessage Debug "Failed to resolve hostname $hostname from UNC path: $_"
                                            }
                                            
                                            # Only add if resolves to RFC1918 private IP
                                            if ($shouldAdd) {
                                                $uncPaths += $uncPath
                                                
                                                # Add unique hostnames to additional components
                                                if (-not $additionalComponents.ContainsKey($hostname)) {
                                                    Write-LogMessage Verbose "Found host: $hostname ($($ip.IPAddressToString))"

                                                    $additionalComponents[$hostname] = @{
                                                        "Hostname" = $hostname
                                                        "UNCPaths" = @($uncPath)
                                                        "URLs" = @()
                                                        "Source" = "Local-LogFile-$($logFile.Name)"
                                                        "LogFile" = $logFile.FullName
                                                    }
                                                } else {
                                                    # Add UNC path if not already present
                                                    if ($uncPath -notin $additionalComponents[$hostname].UNCPaths) {
                                                        $additionalComponents[$hostname].UNCPaths += $uncPath
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
        
                            # Process URLs
                            foreach ($match in $urlMatches) {
                                foreach ($matchGroup in $match.Matches) {
                                    $fullUrl = $matchGroup.Value.Trim()
                                    Write-LogMessage Debug "Found URL: $fullUrl"
                                    
                                    # Extract just the domain/hostname portion using named capture group
                                    if ($fullUrl -match "^https?://([^/@:]+)") {
                                        $hostname = $matches[1].Trim()
                                        
                                        # Skip localhost references and current machine
                                        if ($hostname -notin @("localhost", "127.0.0.1", $env:COMPUTERNAME, $env:COMPUTERNAME.ToLower())) {
                                            # Resolve hostname to IP address then check for RFC1918
                                            $shouldAdd = $false
                                            try {
                                                $resolvedIPs = [System.Net.Dns]::GetHostAddresses($hostname)
                                                foreach ($ip in $resolvedIPs) {
                                                    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                                                        $bytes = $ip.GetAddressBytes()
                                                        # Check RFC1918 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                                                        $isRFC1918 = ($bytes[0] -eq 10) -or 
                                                                     ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
                                                                     ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
                                                        if ($isRFC1918) {
                                                            $shouldAdd = $true
                                                            break
                                                        } else {
                                                            Write-LogMessage Debug "Host resolved to non-RFC1918 IP address: $hostname ($($ip.IPAddressToString))"
                                                        }
                                                    }
                                                }
                                            } catch {
                                                # DNS resolution failed
                                                Write-LogMessage Debug "Failed to resolve hostname $hostname from URL: $_"
                                            }
                                            
                                            # Only add if resolves to RFC1918 private IP
                                            if ($shouldAdd) {

                                                # Add unique hostnames to additional components
                                                if (-not $additionalComponents.ContainsKey($hostname)) {
                                                    Write-LogMessage Verbose "Found host: $hostname ($($ip.IPAddressToString))"

                                                    $additionalComponents[$hostname] = @{
                                                        "Hostname" = $hostname
                                                        "UNCPaths" = @()
                                                        "URLs" = @($fullUrl)
                                                        "Source" = "Local-LogFile-$($logFile.Name)"
                                                        "LogFile" = $logFile.FullName
                                                    }
                                                } else {
                                                    # Add URL if not already present
                                                    if ($fullUrl -notin $additionalComponents[$hostname].URLs) {
                                                        $additionalComponents[$hostname].URLs += $fullUrl
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            
                        } catch {
                            Write-LogMessage Error "Failed to search log file $($logFile.FullName): $_"
                        }
                    }
                }
            }
            
            # Add discovered components to collection targets
            foreach ($component in $additionalComponents.Values) {
                $hostname = $component.Hostname
                $compTarget = Add-DeviceToTargets -DeviceName $hostname -Source $component.Source
                if ($compTarget -and $compTarget.IsNew) {
                    Write-LogMessage Success "Discovered potential SCCM component from logs: $hostname"
                }
            }
            
            if ($additionalComponents.Count -eq 0) {
                Write-LogMessage Info "No additional SCCM components discovered in client logs"
            }
            
        } catch {
            Write-LogMessage Error "Failed to search client logs: $_"
        }
        
        # Report what was collected
        Write-LogMessage Success "Local collection completed" -Level "Success"
        Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCM_SiteSystemRoles } | ForEach-Object { "$($_.Properties.Name) ($($_.Properties.SCCM_SiteSystemRoles -join ', '))" }) -join "`n    ")"
        Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
    } catch {
        Write-LogMessage Error "Local collection failed: $_"
    }
}

#endregion

#region DNS Collection

function Invoke-DNSCollection {
    Write-LogMessage Info "Starting DNS collection..."
    
    try {
        if (-not $script:Domain) {
            Write-LogMessage Warning "No domain specified for DNS collection"
            return
        }
        
        # Collect site codes from previous phases and user-specified targets
        $siteCodesForDNS = @()
        
        # Add site codes from LDAP/Local collection
        foreach ($site in $script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }) {
            if ($site.Properties.SiteCode -and $siteCodesForDNS -notcontains $site.Properties.SiteCode) {
                $siteCodesForDNS += $site.Properties.SiteCode
            }
        }
        
        # Add user-specified site codes
        if ($script:TargetSiteCodes) {
            foreach ($siteCode in $script:TargetSiteCodes) {
                if ($siteCodesForDNS -notcontains $siteCode) {
                    $siteCodesForDNS += $siteCode
                }
            }
        }
        
        if ($siteCodesForDNS.Count -eq 0) {
            Write-LogMessage Warning "No site codes available for DNS collection. Use -SiteCodes parameter or run LDAP/Local collection first."
            return
        }
        
        Write-LogMessage Info "Performing DNS collection for site codes: $($siteCodesForDNS -join ', ')"
        
        # Try ADIDNS dump approach first (if available)
        $adidnsRecords = @()
        try {
            Write-LogMessage Info "Attempting ADIDNS SRV record enumeration..."
            
            # Try to use Resolve-DnsName to get all SRV records (requires appropriate DNS configuration)
            try {
                # Get all discovered site codes for targeted SRV queries
                $targetSiteCodes = @()
                if ($script:TargetSiteCodes) {
                    $targetSiteCodes += $script:TargetSiteCodes
                }
                if ($script:Sites) {
                    $targetSiteCodes += $script:Sites | ForEach-Object { $_.SiteCode }
                }
                # Remove duplicates and empty values
                $targetSiteCodes = $targetSiteCodes | Where-Object { $_ } | Sort-Object -Unique

                # Query SCCM-specific SRV records
                $sccmSrvRecords = @()
                foreach ($siteCode in $targetSiteCodes) {
                    try {
                        $srvName = "_mssms_mp_$siteCode._tcp.$script:Domain"
                        Write-LogMessage Verbose "Querying SRV record: $srvName"
                        $records = Resolve-DnsName -Name $srvName -Type SRV -DnsOnly -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        if ($records) {
                            $sccmSrvRecords += $records
                            Write-LogMessage Verbose "Found $($records.Count) SRV records for $srvName"
                        }
                    } catch {
                        Write-LogMessage Warning "Failed to query SRV record $srvName`: $_"
                    }
                }

                foreach ($record in $sccmSrvRecords) {
                    if ($record.Name -match "_mssms_mp_([A-Z0-9]{3})\._tcp\.$($script:Domain.Replace('.', '\.'))" -and $record.NameTarget) {
                        $siteCodeFromDNS = $matches[1]
                        $managementPointFQDN = $record.NameTarget
                        
                        # Enhanced resolution using AD helper functions
                        try {
                            $adObject = Get-ActiveDirectoryObject -Name $managementPointFQDN -Domain $script:Domain
                            if ($adObject) {
                                $adidnsRecords += @{
                                    "FQDN" = $managementPointFQDN
                                    "SiteCode" = $siteCodeFromDNS
                                    "ADObject" = $adObject
                                    "Priority" = $record.Priority
                                    "Weight" = $record.Weight
                                    "Port" = $record.Port
                                }
                                Write-LogMessage Success "Found management point $managementPointFQDN for site $siteCodeFromDNS"
                            } else {
                                Write-LogMessage Warning "Failed to resolve $managementPointFQDN to AD object"
                            }
                        } catch {
                            Write-LogMessage Error "ADIDNS: Error resolving $managementPointFQDN`: $_"
                        }
                    }
                }
            } catch {
                Write-LogMessage Error "ADIDNS enumeration failed: $_"
            }
        } catch {
            Write-LogMessage Error "ADIDNS collection failed: $_"
        }
        
        # Targeted DNS queries for each site code
        $dnsDiscoveredMPs = @()
        foreach ($siteCode in $siteCodesForDNS) {
            try {
                $srvRecordName = "_mssms_mp_$($siteCode.ToLower())._tcp.$script:Domain"
                Write-LogMessage Info "Querying DNS for: $srvRecordName"
                
                $srvRecords = Resolve-DnsName -Name $srvRecordName -Type SRV -DnsOnly -ErrorAction SilentlyContinue
                
                foreach ($record in $srvRecords) {
                    if ($record.NameTarget) {
                        $managementPointFQDN = $record.NameTarget
                        
                        # Enhanced resolution using AD helper functions
                        try {
                            $adObject = Get-ActiveDirectoryObject -Name $managementPointFQDN -Domain $script:Domain
                            if ($adObject) {
                                # Check for RFC-1918 IP space
                                $ipAddresses = @()
                                try {
                                    $ipResolve = Resolve-DnsName -Name $managementPointFQDN -Type A -DnsOnly -ErrorAction SilentlyContinue
                                    $ipAddresses = $ipResolve | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }
                                } catch {
                                    Write-LogMessage Error "Failed to resolve IP for $managementPointFQDN`: $_"
                                }
                                
                                # Check if any IP is in RFC-1918 space
                                $isRFC1918 = $false
                                foreach ($ip in $ipAddresses) {
                                    try {
                                        $ipObj = [System.Net.IPAddress]::Parse($ip)
                                        $ipBytes = $ipObj.GetAddressBytes()
                                        if (($ipBytes[0] -eq 10) -or 
                                            ($ipBytes[0] -eq 172 -and $ipBytes[1] -ge 16 -and $ipBytes[1] -le 31) -or
                                            ($ipBytes[0] -eq 192 -and $ipBytes[1] -eq 168)) {
                                            $isRFC1918 = $true
                                            break
                                        }
                                    } catch {
                                        Write-LogMessage Error "Failed to parse IP address $ip"
                                    }
                                }
                                
                                if ($isRFC1918 -or $ipAddresses.Count -eq 0) {
                                    $dnsDiscoveredMPs += @{
                                        "FQDN" = $managementPointFQDN
                                        "SiteCode" = $siteCode
                                        "ADObject" = $adObject
                                        "Priority" = $record.Priority
                                        "Weight" = $record.Weight
                                        "Port" = $record.Port
                                        "IPAddresses" = $ipAddresses
                                    }
                                } else {
                                    Write-LogMessage Verbose "Skipping $managementPointFQDN (not in RFC-1918 space)"
                                }
                            } else {
                                Write-LogMessage Warning "Failed to resolve $managementPointFQDN to AD object"
                            }
                        } catch {
                            Write-LogMessage Error "Error resolving $managementPointFQDN`: $_"
                        }
                    }
                }
            } catch {
                Write-LogMessagen Error "Failed to query DNS for site $siteCode`: $_"
            }
        }
        
        # Combine and deduplicate all discovered management points
        $allDiscoveredMPs = @()
        $processedFQDNs = @()
        
        # Process ADIDNS records
        foreach ($mp in $adidnsRecords) {
            if ($processedFQDNs -notcontains $mp.FQDN) {
                $allDiscoveredMPs += $mp
                $processedFQDNs += $mp.FQDN
            }
        }
        
        # Process targeted DNS records
        foreach ($mp in $dnsDiscoveredMPs) {
            if ($processedFQDNs -notcontains $mp.FQDN) {
                $allDiscoveredMPs += $mp
                $processedFQDNs += $mp.FQDN
            }
        }
        
        # Add discovered management points to targets and create site system roles
        foreach ($mp in $allDiscoveredMPs) {
            $fqdn = $mp.FQDN
            $siteCode = $mp.SiteCode
            $adObject = $mp.ADObject

            $collectionTarget = Add-DeviceToTargets -DeviceName $fqdn -Source "DNS"
            if ($collectionTarget -and $collectionTarget.IsNew) {
                Write-LogMessage Success "Found management point $fqdn for site $siteCode"
            }

            # Create or update Computer node
            if ($adObject) {
                Add-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                    CollectionSource = @("DNS")
                    SCCM_SiteSystemRoles = @("SMS Management Point@$siteCode")
                }
            } else {
                Write-LogMessage Warning "Cannot create Computer node for $fqdn - missing AD object or SID"
            }
        }
        
        # Report what was collected
        Write-LogMessage Success "DNS collection completed"
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCM_SiteSystemRoles } | ForEach-Object { "$($_.Properties.Name) ($($_.Properties.SCCM_SiteSystemRoles -join ', '))" }) -join "`n    ")"
        Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
    } catch {
        Write-LogMessage Error "DNS collection failed: $_"
    }
}

#endregion

#region Remote Registry Collection

function Remove-TimedOutJob {
    param([System.Management.Automation.Job]$Job, [string]$Target)
    
    if (Get-Job $Job -ErrorAction SilentlyContinue) {
        try {
            Stop-Job $Job -PassThru -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue
        } catch {
            Write-LogMessage Error "Job cleanup failed for $Target"
        }
    }
}
function Invoke-RemoteRegistryCollection {
    param($Targets)
    
    Write-LogMessage Info "Starting Remote Registry collection..."
    
    if (-not $Targets -or $Targets.Count -eq 0) {
        Write-LogMessage Warning "No targets provided for Remote Registry collection"
        return
    }
    
    foreach ($collectionTarget in $Targets) {
        try {
            $target = $collectionTarget.Hostname
            Write-LogMessage Info "Attempting Remote Registry collection on: $($target)"
            
            $regConnectionSuccessful = $false
            $siteCode = $null
            
            # Connect to remote registry with timeout - Job 1
            $timeoutSeconds = 3
            $registryConnectionCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $reg.Close()
                    return $true
                } catch {
                    return $false
                }
            }
            
            $j1 = Start-Job -ScriptBlock $registryConnectionCode -ArgumentList $target
            $connectionSuccess = $false
            
            if (Wait-Job $j1 -Timeout $timeoutSeconds) { 
                $connectionSuccess = Receive-Job $j1 
            } else {
                Write-LogMessage Warning "Remote Registry connection timed out for $target after $timeoutSeconds seconds"
                Remove-TimedOutJob $j1 $target
            }

            if (-not $connectionSuccess) {
                Write-LogMessage Warning "Remote Registry connection failed for $target"
                continue
            }
            
            Write-LogMessage Success "Remote Registry connection successful: $target"
            $regConnectionSuccessful = $true
            
            # Query 1: Get site code from Triggers subkey - Job 2
            $triggersCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $subkeyName = "SOFTWARE\Microsoft\SMS\Triggers"
                    Write-LogMessage Verbose "Querying $subkeyName"
                    $triggersKey = $reg.OpenSubKey($subkeyName)
                    $result = $null
                    if ($triggersKey) {
                        $result = $triggersKey.GetSubKeyNames()
                        $triggersKey.Close()
                    }
                    $reg.Close()
                    return $result
                } catch {
                    return $null
                }
            }
            
            $j2 = Start-Job -ScriptBlock $triggersCode -ArgumentList $target
            $triggersResult = $null
            
            if (Wait-Job $j2 -Timeout $timeoutSeconds) { 
                $triggersResult = Receive-Job $j2 
            } else {
                Write-LogMessage Warning "Triggers registry query timed out for $target"
                Remove-TimedOutJob $j2 $target
            }
            
            if ($triggersResult -and $triggersResult.Count -eq 1) {
                $siteCode = $triggersResult
                Write-LogMessage Success "Found site code from triggers: $siteCode"
            } elseif ($triggersResult -and $triggersResult.Count -gt 1) {
                Write-LogMessage Warning "Multiple site codes found under triggers key on $target`: $($triggersResult -join ', ')"
                $siteCode = $triggersResult[0] # Use first one
            } else {
                Write-LogMessage Info "No site code found in triggers on $target"
            }
            
            # Query 2: Get component servers - Job 3
            $componentCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $subkeyName = "SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers"
                    Write-LogMessage Verbose "Querying $subkeyName"
                    $componentKey = $reg.OpenSubKey($subkeyName)
                    $result = $null
                    if ($componentKey) {
                        $result = $componentKey.GetSubKeyNames()
                        $componentKey.Close()
                    }
                    $reg.Close()
                    return $result
                } catch {
                    return $null
                }
            }
            
            $j3 = Start-Job -ScriptBlock $componentCode -ArgumentList $target
            $componentResult = $null
            
            if (Wait-Job $j3 -Timeout $timeoutSeconds) { 
                $componentResult = Receive-Job $j3 
            } else {
                Write-LogMessage Warning "Component servers registry query timed out for $target"
                Remove-TimedOutJob $j3 $target
            }

            # Process component servers
            if ($componentResult) {
                foreach ($componentServerFQDN in $componentResult) {
                    $collectionTarget = Add-DeviceToTargets -DeviceName $componentServerFQDN -Source "RemoteRegistry-ComponentServer"
                    if ($collectionTarget -and $collectionTarget.IsNew){
                        Write-LogMessage Success "Found component server: $componentServerFQDN"
                    }
                    # Add site system role to Computer node
                    if ($collectionTarget.ADObject) {
                        Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                            CollectionSource = @("RemoteRegistry-ComponentServer")
                            SCCM_SiteSystemRoles = @("SMS Component Server@$siteCode")
                        }
                    }
                }
            }
            
            # Query 3: Get site database servers - Job 4
            $multisiteCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $subkeyName = "SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers"
                    Write-LogMessage Verbose "Querying $subkeyName"
                    $multisiteKey = $reg.OpenSubKey($subkeyName)
                    $result = $null
                    if ($multisiteKey) {
                        $result = $multisiteKey.GetSubKeyNames()
                        $multisiteKey.Close()
                    }
                    $reg.Close()
                    return $result
                } catch {
                    return $null
                }
            }
            
            $j4 = Start-Job -ScriptBlock $multisiteCode -ArgumentList $target
            $multisiteResult = $null
            
            if (Wait-Job $j4 -Timeout $timeoutSeconds) { 
                $multisiteResult = Receive-Job $j4 
            } else {
                Write-LogMessage Warning "Multisite servers registry query timed out for $target"
                Remove-TimedOutJob $j4 $target
            }
            
            # Process SQL servers
            if ($multisiteResult -ne $null -and $multisiteResult.Count -eq 0) {
                # Site database is local to the site server
                Write-LogMessage Info "Site database is local to the site server: $target"

                # Add site system roles to Computer node
                if ($target.ADObject) {
                    Add-Node -Id $target.ADObject.SID -Kinds @("Computer", "Base") -PSObject $target.ADObject -Properties @{
                        CollectionSource = @("RemoteRegistry-MultisiteComponentServers")
                        SCCM_SiteSystemRoles = @("SMS SQL Server@$siteCode", "SMS Site Server@$siteCode")
                    }
                }
            } elseif ($multisiteResult.Count -eq 1) {
                # Single site database server
                $sqlServerFQDN = $multisiteResult
                $collectionTarget = Add-DeviceToTargets -DeviceName $sqlServerFQDN -Source "RemoteRegistry-MultisiteComponentServers"
                if ($collectionTarget -and $collectionTarget.IsNew){
                    Write-LogMessage Success "Found site database server: $sqlServerFQDN"
                }
                # Add site system roles to Computer node
                if ($collectionTarget -and $collectionTarget.ADObject) {
                    Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                        CollectionSource = @("RemoteRegistry-MultisiteComponentServers")
                        SCCM_SiteSystemRoles = @("SMS SQL Server@$siteCode")
                    }
                }

            } elseif ($multisiteResult.Count -gt 1) {
                # Multiple SQL servers (clustered)
                Write-LogMessage Verbose "Found clustered site database servers: $($multisiteResult -join ', ')"
                foreach ($sqlServerFQDN in $multisiteResult) {

                    $collectionTarget = Add-DeviceToTargets -DeviceName $sqlServerFQDN -Source "RemoteRegistry-MultisiteComponentServers"
                    if ($collectionTarget -and $collectionTarget.IsNew){
                        Write-LogMessage Success "Found site database server: $sqlServerFQDN"
                    }

                    # Add site system roles to each Computer node
                    if ($collectionTarget -and $collectionTarget.ADObject) {
                        Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                            CollectionSource = @("RemoteRegistry-MultisiteComponentServers")
                            SCCM_SiteSystemRoles = @("SMS SQL Server@$siteCode")
                        }
                    }
                }
            }
            
            # Query 4: Get current user SID(s) - Job 5
            $currentUserCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $subkeyName = "SOFTWARE\Microsoft\SMS\CurrentUser"
                    Write-LogMessage Verbose "Querying $subkeyName"
                    $currentUserKey = $reg.OpenSubKey($subkeyName)
                    $result = @{}
                    if ($currentUserKey) {
                        $valueNames = $currentUserKey.GetValueNames()
                        foreach ($valueName in $valueNames) {
                            $value = $currentUserKey.GetValue($valueName)
                            if ($value) {
                                $result[$valueName] = $value
                            }
                        }
                        $currentUserKey.Close()
                    }
                    $reg.Close()
                    return $result
                } catch {
                    return @{}
                }
            }
            
            $j5 = Start-Job -ScriptBlock $currentUserCode -ArgumentList $target
            $currentUserResult = $null
            
            if (Wait-Job $j5 -Timeout $timeoutSeconds) { 
                $currentUserResult = Receive-Job $j5 
            } else {
                Write-LogMessage Warning "Current user registry query timed out for $target"
                Remove-TimedOutJob $j5 $target
            }
            
            # Process current user SIDs
            $currentUserSid = $null
            if ($currentUserResult -and $currentUserResult.Count -eq 0) {
                Write-LogMessage Info "No values found in CurrentUser subkey on $target"
            } elseif ($currentUserResult -and $currentUserResult.Count -eq 2) {
                $currentUserSid = $currentUserResult.Values | Select-Object -Index 1
                Write-LogMessage Verbose "Found CurrentUser $currentUserSid on $target"
                # Resolve SID to AD object
                try {
                    $userADObject = Get-ActiveDirectoryObject -Sid $currentUserSid -Domain $script:Domain

                    if ($userADObject) {
                        Write-LogMessage Success "Found current user: $($userADObject.Name) ($currentUserSid)"
                        
                        # Create User node for current user
                        Add-Node -Id $currentUserSid -Kinds @("User", "Base") -PSObject $userADObject -Properties @{
                            CollectionSource = @("RemoteRegistry-CurrentUser")
                        }

                        # Create Computer -[HasSession]-> User edge
                        Add-Edge -Start $target.ADObject.SID -Kind "HasSession" -End $currentUserSid -Properties @{
                            CollectionSource = @("RemoteRegistry-CurrentUser")
                        }
                    } else {
                        Write-LogMessage Warning "Failed to resolve current user SID $sid"
                    }
                } catch {
                    Write-LogMessage Error "Error resolving current user SID $sid`: $_"
                }
            }
            
            Write-LogMessage Success "Remote Registry collection completed for $target"
        } catch {
            Write-LogMessage Error "Remote Registry collection failed for $target`: $_"
        }
    }
    
    Write-LogMessage Success "Remote Registry collection completed"
    Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
    Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCM_SiteSystemRoles } | ForEach-Object { "$($_.Properties.Name) ($($_.Properties.SCCM_SiteSystemRoles -join ', '))" }) -join "`n    ")"
    Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
}

#endregion

#region AdminService Collection

function Invoke-AdminServiceCollection {
    param(
        $CollectionTarget
    )
    
    $Target = $CollectionTarget.Hostname
    Write-LogMessage Info "Attempting AdminService collection on: $Target"
    
    # Construct base AdminService URL
    $baseUrl = "https://$Target/AdminService"
    
    # Test AdminService connectivity first
    if (-not (Test-AdminServiceConnectivity -Target $Target -BaseUrl $baseUrl)) {
        Write-LogMessage "AdminService connectivity test failed for $Target" -Level "Warning"
        return $false
    }
    
    # Attempt collection - AdminService will auto-detect the site code
    $collectionsAttempted = 0
    $collectionsSuccessful = 0
    
    try {
        # Collection 1: Sites (SMS_Site) - this will tell us which site we're collecting from
        $detectedSiteCode = $null
        if (Get-SCCMSitesViaAdminService -Target $Target -BaseUrl $baseUrl -DetectedSiteCodeRef ([ref]$detectedSiteCode)) {
            $collectionsSuccessful++
            Write-LogMessage "Successfully collected Sites via AdminService (detected site: $detectedSiteCode)" -Level "Success"
        } else {
            Write-LogMessage "Failed to collect Sites via AdminService" -Level "Warning"
        }
        $collectionsAttempted++
        
        # Use detected site code for remaining collections, fallback to provided SiteCode
        $currentSiteCode = if ($detectedSiteCode) { $detectedSiteCode } else { $SiteCode }
        
        # Collection 2: Collections (SMS_Collection)
        if (Get-SCCMCollectionsViaAdminService -Target $Target -BaseUrl $baseUrl -SiteCode $currentSiteCode) {
            $collectionsSuccessful++
            Write-LogMessage "Successfully collected Collections via AdminService" -Level "Success"
        } else {
            Write-LogMessage "Failed to collect Collections via AdminService" -Level "Warning"
        }
        $collectionsAttempted++
        
        # Collection 3: Collection Members (SMS_FullCollectionMembership)
        if (Get-SCCMCollectionMembersViaAdminService -Target $Target -BaseUrl $baseUrl -SiteCode $currentSiteCode) {
            $collectionsSuccessful++
            Write-LogMessage "Successfully collected Collection Members via AdminService" -Level "Success"
        } else {
            Write-LogMessage "Failed to collect Collection Members via AdminService" -Level "Warning"
        }
        $collectionsAttempted++
        
        # Collection 4: Client Devices (SMS_CombinedDeviceResources or SMS_R_System)
        if (Get-SCCMClientDevicesViaAdminService -Target $Target -BaseUrl $baseUrl -SiteCode $currentSiteCode) {
            $collectionsSuccessful++
            Write-LogMessage "Successfully collected Client Devices via AdminService" -Level "Success"
        } else {
            Write-LogMessage "Failed to collect Client Devices via AdminService" -Level "Warning"
        }
        $collectionsAttempted++
        
        # Collection 5: Security Roles (SMS_Role) - Requires Read-only Analyst or higher
        if (Get-SCCMSecurityRolesViaAdminService -Target $Target -BaseUrl $baseUrl -SiteCode $currentSiteCode) {
            $collectionsSuccessful++
            Write-LogMessage "Successfully collected Security Roles via AdminService" -Level "Success"
        } else {
            Write-LogMessage "Failed to collect Security Roles via AdminService (may require elevated privileges)" -Level "Warning"
        }
        $collectionsAttempted++
        
        # Collection 6: Administrative Users (SMS_Admin) - Requires Read-only Analyst or higher
        if (Get-SCCMAdminUsersViaAdminService -Target $Target -BaseUrl $baseUrl -SiteCode $currentSiteCode) {
            $collectionsSuccessful++
            Write-LogMessage "Successfully collected Admin Users via AdminService" -Level "Success"
        } else {
            Write-LogMessage "Failed to collect Admin Users via AdminService (may require elevated privileges)" -Level "Warning"
        }
        $collectionsAttempted++
        
        # Collection 7: Site System Roles (SMS_SystemResourceList)
        if (Get-SCCMSiteSystemRolesViaAdminService -Target $Target -BaseUrl $baseUrl -SiteCode $currentSiteCode) {
            $collectionsSuccessful++
            Write-LogMessage "Successfully collected Site System Roles via AdminService" -Level "Success"
        } else {
            Write-LogMessage "Failed to collect Site System Roles via AdminService" -Level "Warning"
        }
        $collectionsAttempted++
        
        Write-LogMessage "AdminService collection completed: $collectionsSuccessful/$collectionsAttempted successful" -Level "Info"
        
        if ($collectionsSuccessful -gt 0) {
            # Mark target as successfully collected
            if (-not $script:CollectionTargets.ContainsKey($Target)) {
                $script:CollectionTargets[$Target] = @{}
            }
            $script:CollectionTargets[$Target]["Collected"] = $true
            $script:CollectionTargets[$Target]["Method"] = "AdminService"
            $script:CollectionTargets[$Target]["SiteCode"] = $currentSiteCode
            
            Write-LogMessage "AdminService collection successful on $Target ($collectionsSuccessful successful collections)" -Level "Success"
            return $true
        } else {
            Write-LogMessage "AdminService collection failed - no successful collections on $Target" -Level "Error"
            return $false
        }
        
    } catch {
        Write-LogMessage "AdminService collection failed on $Target`: $_" -Level "Error"
        return $false
    }
}

function Test-AdminServiceConnectivity {
    param(
        [string]$Target,
        [string]$BaseUrl
    )
    
    try {
        Write-LogMessage "Testing AdminService connectivity to $Target" -Level "Info"
        
        $response = Invoke-WebRequest -Method 'Get' -Uri "$BaseUrl/v1.0/`$metadata" -UseDefaultCredentials -TimeoutSec 3 -ErrorAction Stop
        Write-LogMessage "System responded with status code: $($response.StatusCode)"
        
        if ($response.StatusCode -eq 200){
            if ($response.Content -match "Microsoft\.ConfigurationManager"){
                Write-LogMessage "$Target was confirmed to be an SMS Provider"
            } else {
                Write-LogMessage "Could not confirm that $Target is an SMS Provider (`"Microsoft.ConfigurationManager`" not in response content)"
            }
        }


        # Test basic connectivity with a simple query
        $testUrl = "$BaseUrl/v1.0/`$metadata"
        $testResponse = Invoke-RestMethod -Uri $testUrl -Method Get -UseDefaultCredentials -TimeoutSec 30 -ErrorAction Stop
        
        # Check if response contains expected structure
        if ($testResponse -and ($testResponse.PSObject.Properties.Name -contains 'value' -or $testResponse.PSObject.Properties.Name -contains '@odata.context')) {
            Write-LogMessage "AdminService connectivity test successful for $Target" -Level "Success"
            return $true
        } else {
            Write-LogMessage "AdminService connectivity test failed - unexpected response format from $Target" -Level "Warning"
            return $false
        }
        
    } catch {
        $errorMessage = $_.Exception.Message
        
        # Check for specific error conditions
        if ($errorMessage -match "Could not establish trust relationship|SSL|certificate") {
            Write-LogMessage "AdminService SSL/Certificate error for $Target`: $errorMessage" -Level "Warning"
        } elseif ($errorMessage -match "401|Unauthorized") {
            Write-LogMessage "AdminService authentication failed for $Target`: $errorMessage" -Level "Warning"
        } elseif ($errorMessage -match "403|Forbidden") {
            Write-LogMessage "AdminService access denied for $Target`: $errorMessage" -Level "Warning"
        } elseif ($errorMessage -match "404|Not Found") {
            Write-LogMessage "AdminService endpoint not found on $Target - may not be an SMS Provider" -Level "Warning"
        } else {
            Write-LogMessage "AdminService connectivity test failed for $Target`: $errorMessage" -Level "Warning"
        }
        
        return $false
    }
}

function Get-SCCMSitesViaAdminService {
    param(
        [string]$Target,
        [string]$BaseUrl,
        [string]$SiteCode = $null,
        [ref]$DetectedSiteCodeRef = $null
    )
    
    try {
        Write-LogMessage "Collecting sites via AdminService from $Target" -Level "Info"
        
        # Query SMS_Site with specific properties as per design document
        $siteQuery = "SMS_Site?`$select=BuildNumber,InstallDir,ReportingSiteCode,RequestedStatus,ServerName,SiteCode,SiteName,Status,TimeZoneInfo,Type,Version"
        $siteUrl = "$BaseUrl/wmi/$siteQuery"
        
        $siteResponse = Invoke-RestMethod -Uri $siteUrl -Method Get -UseDefaultCredentials -TimeoutSec 120 -ErrorAction Stop
        
        if (-not $siteResponse -or -not $siteResponse.value) {
            Write-LogMessage "No sites returned from AdminService query on $Target" -Level "Warning"
            return $false
        }
        
        # Use the first site's code as the detected site code
        if ($DetectedSiteCodeRef -and $siteResponse.value.Count -gt 0) {
            $DetectedSiteCodeRef.Value = $siteResponse.value[0].SiteCode
        }
        
        foreach ($site in $siteResponse.value) {
            # Create SiteIdentifier (SiteCode.SiteGUID format or just SiteCode if no GUID available)
            $siteIdentifier = $site.SiteCode
            
            # Try to get SiteGUID from SMS_SCI_SiteDefinition
            try {
                $siteDefQuery = "SMS_SCI_SiteDefinition?`$filter=SiteCode eq '$($site.SiteCode)'&`$select=SiteCode,SiteGUID"
                $siteDefUrl = "$BaseUrl/wmi/$siteDefQuery"
                $siteDefResponse = Invoke-RestMethod -Uri $siteDefUrl -Method Get -UseDefaultCredentials -TimeoutSec 60 -ErrorAction Stop
                
                if ($siteDefResponse -and $siteDefResponse.value -and $siteDefResponse.value[0].SiteGUID) {
                    $siteIdentifier = "$($site.SiteCode).{$($siteDefResponse.value[0].SiteGUID)}"
                }
            } catch {
                Write-LogMessage "Could not retrieve SiteGUID for site $($site.SiteCode), using SiteCode only" -Level "Warning"
            }
            
            # Create site node following design document structure
            $siteNode = @{
                "ObjectIdentifier" = $siteIdentifier
                "SiteIdentifier" = $siteIdentifier
                "BuildNumber" = $site.BuildNumber
                "InstallDir" = $site.InstallDir
                "ParentSiteCode" = $site.ReportingSiteCode
                "RequestedStatus" = $site.RequestedStatus
                "SiteServerName" = $site.ServerName
                "SiteCode" = $site.SiteCode
                "SiteName" = $site.SiteName
                "Status" = $site.Status
                "TimeZoneInfo" = $site.TimeZoneInfo
                "Type" = $site.Type
                "Version" = $site.Version
            }
            
            # Add to global sites collection
            $existingSite = $script:Sites | Where-Object { $_.SiteCode -eq $site.SiteCode }
            if (-not $existingSite) {
                $script:Sites += $siteNode
                Write-LogMessage "Collected site via AdminService: $($site.SiteName) ($($site.SiteCode))" -Level "Success"
            } else {
                Write-LogMessage "Site $($site.SiteCode) already exists, skipping duplicate" -Level "Info"
            }
        }
        
        return $true
        
    } catch {
        Write-LogMessage "Failed to collect sites via AdminService from $Target`: $_" -Level "Error"
        return $false
    }
}

function Get-SCCMCollectionsViaAdminService {
    param(
        [string]$Target,
        [string]$BaseUrl,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting collections via AdminService from $Target for site $SiteCode" -Level "Info"
        
        # Query SMS_Collection with specific properties as per design document
        $collectionQuery = "SMS_Collection?`$select=CollectionID,CollectionType,CollectionVariablesCount,Comment,IsBuiltIn,LastChangeTime,LastMemberChangeTime,LimitToCollectionID,LimitToCollectionName,MemberCount,Name"
        $collectionUrl = "$BaseUrl/wmi/$collectionQuery"
        
        $collectionResponse = Invoke-RestMethod -Uri $collectionUrl -Method Get -UseDefaultCredentials -TimeoutSec 120 -ErrorAction Stop
        
        if (-not $collectionResponse -or -not $collectionResponse.value) {
            Write-LogMessage "No collections returned from AdminService query on $Target" -Level "Warning"
            return $false
        }
        
        foreach ($collection in $collectionResponse.value) {
            # Find matching site for SourceSiteIdentifier
            $sourceSiteIdentifier = $SiteCode
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $SiteCode }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $sourceSiteIdentifier = $matchingSite.SiteIdentifier
            }
            
            # Create collection node following design document structure
            $collectionNode = @{
                "ObjectIdentifier" = $collection.CollectionID
                "CollectionID" = $collection.CollectionID
                "CollectionType" = $collection.CollectionType
                "CollectionVariablesCount" = $collection.CollectionVariablesCount
                "Comment" = $collection.Comment
                "IsBuiltIn" = $collection.IsBuiltIn
                "LastChangeTime" = $collection.LastChangeTime
                "LastMemberChangeTime" = $collection.LastMemberChangeTime
                "LimitToCollectionID" = $collection.LimitToCollectionID
                "LimitToCollectionName" = $collection.LimitToCollectionName
                "MemberCount" = $collection.MemberCount
                "Members" = @()  # Will be populated by collection membership enumeration
                "Name" = $collection.Name
                "SourceSiteCode" = $SiteCode
                "SourceSiteIdentifier" = $sourceSiteIdentifier
            }
            
            # Add to global collections
            $existingCollection = $script:Collections | Where-Object { $_.CollectionID -eq $collection.CollectionID }
            if (-not $existingCollection) {
                $script:Collections += $collectionNode
                Write-LogMessage "Collected collection via AdminService: $($collection.Name) ($($collection.CollectionID))" -Level "Success"
            } else {
                Write-LogMessage "Collection $($collection.CollectionID) already exists, skipping duplicate" -Level "Info"
            }
        }
        
        return $true
        
    } catch {
        Write-LogMessage "Failed to collect collections via AdminService from $Target`: $_" -Level "Error"
        return $false
    }
}

function Get-SCCMCollectionMembersViaAdminService {
    param(
        [string]$Target,
        [string]$BaseUrl,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting collection members via AdminService from $Target for site $SiteCode" -Level "Info"
        
        # Query SMS_FullCollectionMembership as per design document
        $memberQuery = "SMS_FullCollectionMembership?`$select=CollectionID,ResourceID,SiteCode"
        $memberUrl = "$BaseUrl/wmi/$memberQuery"
        
        $memberResponse = Invoke-RestMethod -Uri $memberUrl -Method Get -UseDefaultCredentials -TimeoutSec 180 -ErrorAction Stop
        
        if (-not $memberResponse -or -not $memberResponse.value) {
            Write-LogMessage "No collection members returned from AdminService query on $Target" -Level "Warning"
            return $false
        }
        
        # Group members by collection for efficient processing
        $membersByCollection = $memberResponse.value | Group-Object -Property CollectionID
        
        foreach ($group in $membersByCollection) {
            $collectionID = $group.Name
            $collection = $script:Collections | Where-Object { $_.CollectionID -eq $collectionID }
            
            if ($collection) {
                # Update the Members array with ResourceIDs
                $collection.Members = $group.Group | ForEach-Object { $_.ResourceID }
                Write-LogMessage "Updated collection $collectionID with $($group.Count) members via AdminService" -Level "Success"
            } else {
                Write-LogMessage "Collection $collectionID not found in script collections, cannot update members" -Level "Warning"
            }
        }
        
        return $true
        
    } catch {
        Write-LogMessage "Failed to collect collection members via AdminService from $Target`: $_" -Level "Error"
        return $false
    }
}

function Get-SCCMClientDevicesViaAdminService {
    param(
        [string]$Target,
        [string]$BaseUrl,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting client devices via AdminService from $Target for site $SiteCode" -Level "Info"
        
        # Try SMS_CombinedDeviceResources first (preferred), fallback to SMS_R_System
        $deviceQueries = @(
            @{
                Class = "SMS_CombinedDeviceResources"
                Select = "ResourceID,Name,Domain,SiteCode,IsClient,Client,IsObsolete,Obsolete,LastLogonUserDomain,LastLogonUserName,SystemRoles,AADDeviceID,AADTenantID,ADDomainSID,ADLastLogonTime,ADLastLogonUser,ADLastLogonUserDomain,CurrentLogonUser,CurrentManagementPoint,CurrentManagementPointSID,DeviceOS,DeviceOSBuild,DistinguishedName,dNSHostName,IsVirtualMachine,LastActiveTime,LastOfflineTime,LastOnlineTime,LastReportedMPServerName,LastReportedMPServerSID,PrimaryUser,SMSID"
            },
            @{
                Class = "SMS_R_System"
                Select = "ResourceId,Name,ResourceDomainORWorkgroup,SMSUniqueIdentifier,Client,Obsolete,LastLogonUserName,LastLogonUserDomain,SystemRoles,AgentName,AgentSite,AgentTime,IPAddresses,IPSubnets,IPXAddresses,IPXSocketNumbers,MACAddresses,NetbiosName,NetworkAdaptersCo,OperatingSystemNameandVersion,PlatformID,ResourceNames,ResourceType,SiteCode,SNMPCommunityName,SystemContainerName,SystemGroupName,SystemOUName,TotalPhysicalMemory,User"
            }
        )
        
        $deviceCollectionSuccessful = $false
        
        foreach ($queryInfo in $deviceQueries) {
            try {
                $deviceQuery = "$($queryInfo.Class)?`$select=$($queryInfo.Select)"
                $deviceUrl = "$BaseUrl/wmi/$deviceQuery"
                
                Write-LogMessage "Attempting device collection via $($queryInfo.Class)" -Level "Info"
                $deviceResponse = Invoke-RestMethod -Uri $deviceUrl -Method Get -UseDefaultCredentials -TimeoutSec 180 -ErrorAction Stop
                
                if ($deviceResponse -and $deviceResponse.value) {
                    foreach ($device in $deviceResponse.value) {
                        # Find matching site for SourceSiteIdentifier
                        $sourceSiteIdentifier = $SiteCode
                        $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $SiteCode }
                        if ($matchingSite -and $matchingSite.SiteIdentifier) {
                            $sourceSiteIdentifier = $matchingSite.SiteIdentifier
                        }
                        
                        # Create device node - structure varies based on source class
                        $deviceNode = @{
                            "SourceSiteCode" = $SiteCode
                            "SourceSiteIdentifier" = $sourceSiteIdentifier
                        }
                        
                        if ($queryInfo.Class -eq "SMS_CombinedDeviceResources") {
                            $deviceNode["ObjectIdentifier"] = $device.SMSID
                            $deviceNode["SMSID"] = $device.SMSID
                            $deviceNode["ResourceID"] = $device.ResourceID
                            $deviceNode["Name"] = $device.Name
                            $deviceNode["Domain"] = $device.Domain
                            $deviceNode["IsClient"] = $device.IsClient
                            $deviceNode["Client"] = $device.Client
                            $deviceNode["IsObsolete"] = $device.IsObsolete
                            $deviceNode["Obsolete"] = $device.Obsolete
                            $deviceNode["LastLogonUserDomain"] = $device.LastLogonUserDomain
                            $deviceNode["LastLogonUserName"] = $device.LastLogonUserName
                            $deviceNode["SystemRoles"] = $device.SystemRoles
                            $deviceNode["AADDeviceID"] = $device.AADDeviceID
                            $deviceNode["AADTenantID"] = $device.AADTenantID
                            $deviceNode["ADDomainSID"] = $device.ADDomainSID
                            $deviceNode["ADLastLogonTime"] = $device.ADLastLogonTime
                            $deviceNode["ADLastLogonUser"] = $device.ADLastLogonUser
                            $deviceNode["ADLastLogonUserDomain"] = $device.ADLastLogonUserDomain
                            $deviceNode["CurrentLogonUser"] = $device.CurrentLogonUser
                            $deviceNode["CurrentManagementPoint"] = $device.CurrentManagementPoint
                            $deviceNode["CurrentManagementPointSID"] = $device.CurrentManagementPointSID
                            $deviceNode["DeviceOS"] = $device.DeviceOS
                            $deviceNode["DeviceOSBuild"] = $device.DeviceOSBuild
                            $deviceNode["DistinguishedName"] = $device.DistinguishedName
                            $deviceNode["dNSHostName"] = $device.dNSHostName
                            $deviceNode["IsVirtualMachine"] = $device.IsVirtualMachine
                            $deviceNode["LastActiveTime"] = $device.LastActiveTime
                            $deviceNode["LastOfflineTime"] = $device.LastOfflineTime
                            $deviceNode["LastOnlineTime"] = $device.LastOnlineTime
                            $deviceNode["LastReportedMPServerName"] = $device.LastReportedMPServerName
                            $deviceNode["LastReportedMPServerSID"] = $device.LastReportedMPServerSID
                            $deviceNode["PrimaryUser"] = $device.PrimaryUser
                        } else {
                            # SMS_R_System structure
                            $deviceNode["ObjectIdentifier"] = $device.SMSUniqueIdentifier
                            $deviceNode["SMSID"] = $device.SMSUniqueIdentifier
                            $deviceNode["ResourceID"] = $device.ResourceId
                            $deviceNode["Name"] = $device.Name
                            $deviceNode["Domain"] = $device.ResourceDomainORWorkgroup
                            $deviceNode["Client"] = $device.Client
                            $deviceNode["Obsolete"] = $device.Obsolete
                            $deviceNode["LastLogonUserName"] = $device.LastLogonUserName
                            $deviceNode["LastLogonUserDomain"] = $device.LastLogonUserDomain
                            $deviceNode["SystemRoles"] = $device.SystemRoles
                            $deviceNode["AgentName"] = $device.AgentName
                            $deviceNode["AgentSite"] = $device.AgentSite
                            $deviceNode["AgentTime"] = $device.AgentTime
                            $deviceNode["IPAddresses"] = $device.IPAddresses
                            $deviceNode["IPSubnets"] = $device.IPSubnets
                            $deviceNode["MACAddresses"] = $device.MACAddresses
                            $deviceNode["NetbiosName"] = $device.NetbiosName
                            $deviceNode["OperatingSystemNameandVersion"] = $device.OperatingSystemNameandVersion
                            $deviceNode["PlatformID"] = $device.PlatformID
                            $deviceNode["ResourceNames"] = $device.ResourceNames
                            $deviceNode["ResourceType"] = $device.ResourceType
                            $deviceNode["TotalPhysicalMemory"] = $device.TotalPhysicalMemory
                            $deviceNode["User"] = $device.User
                        }
                        
                        # Add to global client devices if not already present
                        $existingDevice = $script:ClientDevices | Where-Object { $_.ObjectIdentifier -eq $deviceNode.ObjectIdentifier }
                        if (-not $existingDevice) {
                            $script:ClientDevices += $deviceNode
                            Write-LogMessage "Collected client device via AdminService: $($deviceNode.Name)" -Level "Success"
                        }
                    }
                    
                    $deviceCollectionSuccessful = $true
                    Write-LogMessage "Successfully collected $($deviceResponse.value.Count) devices via $($queryInfo.Class)" -Level "Success"
                    break  # Success, no need to try other queries
                }
                
            } catch {
                Write-LogMessage "Failed to collect devices via $($queryInfo.Class): $_" -Level "Warning"
                continue
            }
        }
        
        return $deviceCollectionSuccessful
        
    } catch {
        Write-LogMessage "Failed to collect client devices via AdminService from $Target`: $_" -Level "Error"
        return $false
    }
}

function Get-SCCMSecurityRolesViaAdminService {
    param(
        [string]$Target,
        [string]$BaseUrl,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting security roles via AdminService from $Target for site $SiteCode" -Level "Info"
        
        # Query SMS_Role as per design document
        $roleQuery = "SMS_Role?`$select=RoleID,RoleName,RoleDescription,IsBuiltIn,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,GrantedOperations,GrantedOperationsOnTypeNames,Operations,CopiedFromID"
        $roleUrl = "$BaseUrl/wmi/$roleQuery"
        
        $roleResponse = Invoke-RestMethod -Uri $roleUrl -Method Get -UseDefaultCredentials -TimeoutSec 120 -ErrorAction Stop
        
        if (-not $roleResponse -or -not $roleResponse.value) {
            Write-LogMessage "No security roles returned from AdminService query on $Target (may require Read-only Analyst privileges or higher)" -Level "Warning"
            return $false
        }
        
        foreach ($role in $roleResponse.value) {
            # Find matching site for SourceSiteIdentifier
            $sourceSiteIdentifier = $SiteCode
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $SiteCode }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $sourceSiteIdentifier = $matchingSite.SiteIdentifier
            }
            
            # Determine if this is a security admin role (has User.Add or User.Modify permissions)
            $isSecAdminRole = $false
            if ($role.GrantedOperations -or $role.Operations) {
                $operations = @()
                if ($role.GrantedOperations) { $operations += $role.GrantedOperations }
                if ($role.Operations) { $operations += $role.Operations }
                
                $isSecAdminRole = ($operations -match "User\.Add|User\.Modify").Count -gt 0
            }
            
            # Create security role node following design document structure
            $roleNode = @{
                "ObjectIdentifier" = "$($role.RoleID)@$sourceSiteIdentifier"
                "RoleID" = $role.RoleID
                "RoleName" = $role.RoleName
                "RoleDescription" = $role.RoleDescription
                "IsBuiltIn" = $role.IsBuiltIn
                "CreatedBy" = $role.CreatedBy
                "CreatedDate" = $role.CreatedDate
                "ModifiedBy" = $role.ModifiedBy
                "ModifiedDate" = $role.ModifiedDate
                "GrantedOperations" = $role.GrantedOperations
                "GrantedOperationsOnTypeNames" = $role.GrantedOperationsOnTypeNames
                "Operations" = $role.Operations
                "CopiedFromID" = $role.CopiedFromID
                "IsSecAdminRole" = $isSecAdminRole
                "SourceSiteCode" = $SiteCode
                "SourceSiteIdentifier" = $sourceSiteIdentifier
            }
            
            # Add to global security roles
            $existingRole = $script:SecurityRoles | Where-Object { $_.ObjectIdentifier -eq $roleNode.ObjectIdentifier }
            if (-not $existingRole) {
                $script:SecurityRoles += $roleNode
                Write-LogMessage "Collected security role via AdminService: $($role.RoleName) ($($role.RoleID))" -Level "Success"
            } else {
                Write-LogMessage "Security role $($role.RoleID) already exists, skipping duplicate" -Level "Info"
            }
        }
        
        return $true
        
    } catch {
        Write-LogMessage "Failed to collect security roles via AdminService from $Target`: $_" -Level "Error"
        return $false
    }
}

function Get-SCCMAdminUsersViaAdminService {
    param(
        [string]$Target,
        [string]$BaseUrl,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting admin users via AdminService from $Target for site $SiteCode" -Level "Info"
        
        # Query SMS_Admin as per design document
        $adminQuery = "SMS_Admin?`$select=AdminID,LogonName,DistinguishedName,DisplayName,AccountType,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,Permissions,Roles,ExtendedData,TrustedForDelegation,Categories,CategoryNames,IsCovered,IsDeleted,CollectionsCount,AccountSID,SourceSite"
        $adminUrl = "$BaseUrl/wmi/$adminQuery"
        
        $adminResponse = Invoke-RestMethod -Uri $adminUrl -Method Get -UseDefaultCredentials -TimeoutSec 120 -ErrorAction Stop
        
        if (-not $adminResponse -or -not $adminResponse.value) {
            Write-LogMessage "No admin users returned from AdminService query on $Target (may require Read-only Analyst privileges or higher)" -Level "Warning"
            return $false
        }
        
        foreach ($admin in $adminResponse.value) {
            # Find matching site for SourceSiteIdentifier
            $sourceSiteIdentifier = $SiteCode
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $SiteCode }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $sourceSiteIdentifier = $matchingSite.SiteIdentifier
            }
            
            # Create admin user node following design document structure
            $adminNode = @{
                "ObjectIdentifier" = "$($admin.LogonName)@$sourceSiteIdentifier"
                "LogonName" = $admin.LogonName
                "AdminID" = $admin.AdminID
                "DistinguishedName" = $admin.DistinguishedName
                "DisplayName" = $admin.DisplayName
                "AccountType" = $admin.AccountType
                "CreatedBy" = $admin.CreatedBy
                "CreatedDate" = $admin.CreatedDate
                "ModifiedBy" = $admin.ModifiedBy
                "ModifiedDate" = $admin.ModifiedDate
                "Permissions" = $admin.Permissions
                "Roles" = $admin.Roles
                "ExtendedData" = $admin.ExtendedData
                "TrustedForDelegation" = $admin.TrustedForDelegation
                "Categories" = $admin.Categories
                "CategoryNames" = $admin.CategoryNames
                "IsCovered" = $admin.IsCovered
                "IsDeleted" = $admin.IsDeleted
                "CollectionsCount" = $admin.CollectionsCount
                "AccountSID" = $admin.AccountSID
                "SourceSite" = $admin.SourceSite
                "SourceSiteCode" = $SiteCode
                "SourceSiteIdentifier" = $sourceSiteIdentifier
            }
            
            # Add to global admin users
            $existingAdmin = $script:AdminUsers | Where-Object { $_.ObjectIdentifier -eq $adminNode.ObjectIdentifier }
            if (-not $existingAdmin) {
                $script:AdminUsers += $adminNode
                Write-LogMessage "Collected admin user via AdminService: $($admin.LogonName) ($($admin.AdminID))" -Level "Success"
            } else {
                Write-LogMessage "Admin user $($admin.LogonName) already exists, skipping duplicate" -Level "Info"
            }
        }
        
        return $true
        
    } catch {
        Write-LogMessage "Failed to collect admin users via AdminService from $Target`: $_" -Level "Error"
        return $false
    }
}

function Get-SCCMSiteSystemRolesViaAdminService {
    param(
        [string]$Target,
        [string]$BaseUrl,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting site system roles via AdminService from $Target for site $SiteCode" -Level "Info"
        
        # Query SMS_SystemResourceList as per design document
        $systemQuery = "SMS_SystemResourceList?`$select=ServerName,SiteCode,RoleName,NALPath,NALType,NetworkOSPath,InternetFacing,SslState,Props"
        $systemUrl = "$BaseUrl/wmi/$systemQuery"
        
        $systemResponse = Invoke-RestMethod -Uri $systemUrl -Method Get -UseDefaultCredentials -TimeoutSec 120 -ErrorAction Stop
        
        if (-not $systemResponse -or -not $systemResponse.value) {
            Write-LogMessage "No site system roles returned from AdminService query on $Target" -Level "Warning"
            return $false
        }
        
        # Group by NetworkOSPath and SiteCode to combine roles for same system
        $groupedSystems = $systemResponse.value | Group-Object -Property { "$($_.NetworkOSPath)_$($_.SiteCode)" }
        
        foreach ($group in $groupedSystems) {
            $firstSystem = $group.Group[0]
            
            # Find matching site for SiteIdentifier
            $siteIdentifier = $firstSystem.SiteCode
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $firstSystem.SiteCode }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $siteIdentifier = $matchingSite.SiteIdentifier
            }
            
            # Collect all roles for this system
            $roles = @()
            foreach ($system in $group.Group) {
                $roleInfo = @{
                    "Name" = $system.RoleName
                    "Properties" = $system.Props
                    "SiteCode" = $system.SiteCode
                    "SiteIdentifier" = $siteIdentifier
                    "SourceForest" = $null  # Will be populated if available
                }
                $roles += $roleInfo
            }
            
            # Create site system node following design document structure
            $systemNode = @{
                "ObjectIdentifier" = $firstSystem.ServerName  # Using ServerName as ObjectIdentifier
                "dNSHostName" = $firstSystem.ServerName
                "ServerName" = $firstSystem.ServerName
                "SiteCode" = $firstSystem.SiteCode
                "NALPath" = $firstSystem.NALPath
                "NALType" = $firstSystem.NALType
                "NetworkOSPath" = $firstSystem.NetworkOSPath
                "InternetFacing" = $firstSystem.InternetFacing
                "SslState" = $firstSystem.SslState
                "Roles" = $roles
                "SiteIdentifier" = $siteIdentifier
            }
            
            # Add to global site system roles
            $existingSystem = $script:SiteSystemRoles | Where-Object { 
                $_.ServerName -eq $firstSystem.ServerName -and $_.SiteCode -eq $firstSystem.SiteCode
            }
            if (-not $existingSystem) {
                $script:SiteSystemRoles += $systemNode
                Write-LogMessage "Collected site system via AdminService: $($firstSystem.ServerName) with $($roles.Count) roles" -Level "Success"
            } else {
                Write-LogMessage "Site system $($firstSystem.ServerName) already exists, skipping duplicate" -Level "Info"
            }
        }
        
        return $true
        
    } catch {
        Write-LogMessage "Failed to collect site system roles via AdminService from $Target`: $_" -Level "Error"
        return $false
    }
}

#endregion

#region WMI Collection

function Invoke-SmsProviderWmiCollection {
    param($CollectionTargets)

    foreach ($collectionTarget in $CollectionTargets) {
        $Targets += $collectionTarget.Hostname
    }
    
    Write-LogMessage "Starting SMS Provider WMI collection..." -Level "Info"
    
    if (-not $Targets -or $Targets.Count -eq 0) {
        Write-LogMessage "No targets provided for WMI collection" -Level "Warning"
        return
    }
    
    foreach ($target in $Targets) {
        try {
            Write-LogMessage "Attempting WMI collection on: $target" -Level "Info"
            
            # Skip if already collected successfully
            if ($script:CollectionTargets[$target]["Collected"]) {
                Write-LogMessage "Target $target already collected, skipping WMI" -Level "Info"
                continue
            }
            
            # Try to determine site code from previous collection phases
            $detectedSiteCode = $null
            if ($script:CollectionTargets[$target]["SiteCode"]) {
                $detectedSiteCode = $script:CollectionTargets[$target]["SiteCode"]
            } else {
                # Try to find site code from collected sites
                $inferredSite = $script:Sites | Where-Object { 
                    $_.SiteServerName -eq $target -or 
                    $_.SiteServerName -like "*$($target.Split('.')[0])*" 
                } | Select-Object -First 1
                if ($inferredSite) {
                    $detectedSiteCode = $inferredSite.SiteCode
                }
            }
            
            # If no site code detected, try common ones or skip
            $siteCodesToTry = @()
            if ($detectedSiteCode) {
                $siteCodesToTry += $detectedSiteCode
            } else {
                # Try site codes from previously discovered sites
                $siteCodesToTry += $script:Sites | ForEach-Object { $_.SiteCode } | Sort-Object -Unique
                if ($siteCodesToTry.Count -eq 0) {
                    Write-LogMessage "No site codes available for WMI collection on $target" -Level "Warning"
                    continue
                }
            }
            
            $collectionSuccessful = $false
            
            foreach ($siteCode in $siteCodesToTry) {
                try {
                    Write-LogMessage "Trying WMI collection for site: $siteCode on $target" -Level "Info"
                    
                    # WMI namespace for the site
                    $namespace = "root\SMS\site_$siteCode"
                    
                    # Test WMI connectivity
                    try {
                        $testWmi = Get-WmiObject -ComputerName $target -Namespace $namespace -Class "SMS_ProviderLocation" -ErrorAction Stop | Select-Object -First 1
                        Write-LogMessage "WMI namespace $namespace accessible on $target" -Level "Success"
                    } catch {
                        Write-LogMessage "WMI namespace $namespace not accessible on $target`: $_" -Level "Warning"
                        continue
                    }
                    
                    # Call individual collection functions
                    $collectionsAttempted = 0
                    $collectionsSuccessful = 0
                    
                    # Sites Collection
                    if (Get-SCCMSitesViaWMI -Target $target -Namespace $namespace -SiteCode $siteCode) {
                        $collectionsSuccessful++
                    }
                    $collectionsAttempted++
                    
                    # Security Roles Collection
                    if (Get-SCCMSecurityRolesViaWMI -Target $target -Namespace $namespace -SiteCode $siteCode) {
                        $collectionsSuccessful++
                    }
                    $collectionsAttempted++
                    
                    # Administrative Users Collection
                    if (Get-SCCMAdminUsersViaWMI -Target $target -Namespace $namespace -SiteCode $siteCode) {
                        $collectionsSuccessful++
                    }
                    $collectionsAttempted++
                    
                    # Collections Collection
                    if (Get-SCCMCollectionsViaWMI -Target $target -Namespace $namespace -SiteCode $siteCode) {
                        $collectionsSuccessful++
                    }
                    $collectionsAttempted++
                    
                    # Collection Members Collection
                    if (Get-SCCMCollectionMembersViaWMI -Target $target -Namespace $namespace -SiteCode $siteCode) {
                        $collectionsSuccessful++
                    }
                    $collectionsAttempted++
                    
                    # Client Devices Collection
                    if (Get-SCCMClientDevicesViaWMI -Target $target -Namespace $namespace -SiteCode $siteCode) {
                        $collectionsSuccessful++
                    }
                    $collectionsAttempted++
                    
                    # Site System Roles Collection
                    if (Get-SCCMSiteSystemRolesViaWMI -Target $target -Namespace $namespace -SiteCode $siteCode) {
                        $collectionsSuccessful++
                    }
                    $collectionsAttempted++
                    
                    # Consider collection successful if at least one collection succeeded
                    if ($collectionsSuccessful -gt 0) {
                        $collectionSuccessful = $true
                        Write-LogMessage "WMI collection successful on $target for site $siteCode ($collectionsSuccessful/$collectionsAttempted collections succeeded)" -Level "Success"
                        break
                    } else {
                        Write-LogMessage "WMI collection failed for site $siteCode on $target (0/$collectionsAttempted collections succeeded)" -Level "Warning"
                    }
                    
                } catch {
                    Write-LogMessage "WMI collection failed for site $siteCode on $target`: $_" -Level "Warning"
                    continue
                }
            }
            
            if ($collectionSuccessful) {
                $script:CollectionTargets[$target]["Collected"] = $true
                $script:CollectionTargets[$target]["Method"] = "WMI"
                Write-LogMessage "Marked target $target as collected via WMI" -Level "Success"
            } else {
                Write-LogMessage "WMI collection failed for all site codes on $target" -Level "Warning"
            }
            
        } catch {
            Write-LogMessage "WMI collection failed for $target`: $_" -Level "Error"
        }
    }
    
    Write-LogMessage "SMS Provider WMI collection completed" -Level "Success"
}

function Get-SCCMSitesViaWMI {
    param(
        [string]$Target,
        [string]$Namespace,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting sites via WMI from $Target" -Level "Info"
        $sites = Get-WmiObject -ComputerName $Target -Namespace $Namespace -Class "SMS_SCI_SiteDefinition" -ErrorAction Stop
        
        foreach ($site in $sites) {
            # Extract SiteGUID from Props
            $siteGuid = $null
            if ($site.Props) {
                $siteGuidProp = $site.Props | Where-Object { $_.PropertyName -eq "SiteGUID" }
                if ($siteGuidProp) {
                    $siteGuid = $siteGuidProp.Value1
                }
            }
            
            # Create site identifier
            $siteIdentifier = if ($siteGuid) { "$($site.SiteCode).$siteGuid" } else { $site.SiteCode }
            
            # Check if site already exists
            $existingSite = $script:Sites | Where-Object { $_.SiteCode -eq $site.SiteCode }
            if (-not $existingSite) {
                $siteNode = @{
                    "DistinguishedName" = $null
                    "Name" = $site.SiteName
                    "ParentSiteCode" = $site.ParentSiteCode
                    "ParentSiteIdentifier" = $null
                    "SiteCode" = $site.SiteCode
                    "SiteGUID" = $siteGuid
                    "SiteIdentifier" = $siteIdentifier
                    "SiteServerDomain" = $site.SiteServerDomain
                    "SiteServerName" = $site.SiteServerName
                    "SiteType" = switch ($site.SiteType) {
                        1 { "Secondary" }
                        2 { "Primary" } 
                        4 { "CentralAdministration" }
                        default { "Unknown" }
                    }
                    "SQLDatabaseName" = $site.SQLDatabaseName
                    "SQLServerName" = $site.SQLServerName
                    "Source" = "WMI"
                }
                $script:Sites += $siteNode
                Write-LogMessage "Collected site via WMI: $($site.SiteCode)" -Level "Success"
            } else {
                # Update existing site with more complete information
                if ($siteGuid -and -not $existingSite.SiteGUID) {
                    $existingSite.SiteGUID = $siteGuid
                    $existingSite.SiteIdentifier = $siteIdentifier
                    $existingSite.Name = $site.SiteName
                    $existingSite.SiteServerDomain = $site.SiteServerDomain
                    $existingSite.SiteServerName = $site.SiteServerName
                    $existingSite.SQLDatabaseName = $site.SQLDatabaseName
                    $existingSite.SQLServerName = $site.SQLServerName
                    Write-LogMessage "Updated existing site with WMI data: $($site.SiteCode)" -Level "Success"
                }
            }
        }
        return $true
    } catch {
        Write-LogMessage "Failed to collect sites via WMI from $Target`: $_" -Level "Warning"
        return $false
    }
}

function Get-SCCMSecurityRolesViaWMI {
    param(
        [string]$Target,
        [string]$Namespace,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting security roles via WMI from $Target" -Level "Info"
        $roles = Get-WmiObject -ComputerName $Target -Namespace $Namespace -Class "SMS_Role" -ErrorAction Stop
        
        foreach ($role in $roles) {
            # Find source site identifier
            $sourceSiteIdentifier = $SiteCode
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $SiteCode }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $sourceSiteIdentifier = $matchingSite.SiteIdentifier
            }
            
            $roleNode = @{
                "ObjectIdentifier" = "$($role.RoleID)@$sourceSiteIdentifier"
                "CopiedFromID" = $role.CopiedFromID
                "CreatedBy" = $role.CreatedBy
                "CreatedDate" = $role.CreatedDate
                "Description" = $role.Description
                "IsBuiltIn" = $role.IsBuiltIn
                "IsSecAdminRole" = $role.IsSecAdminRole
                "LastModifiedBy" = $role.LastModifiedBy
                "LastModifiedDate" = $role.LastModifiedDate
                "NumberOfAdmins" = $role.NumberOfAdmins
                "Operations" = $role.Operations
                "RoleID" = $role.RoleID
                "RoleName" = $role.RoleName
                "SourceSiteCode" = $SiteCode
                "SourceSiteIdentifier" = $sourceSiteIdentifier
            }
            
            $script:SecurityRoles += $roleNode
            Write-LogMessage "Collected security role via WMI: $($role.RoleName)" -Level "Success"
        }
        return $true
    } catch {
        Write-LogMessage "Failed to collect security roles via WMI from $Target`: $_" -Level "Warning"
        return $false
    }
}

function Get-SCCMAdminUsersViaWMI {
    param(
        [string]$Target,
        [string]$Namespace,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting admin users via WMI from $Target" -Level "Info"
        $admins = Get-WmiObject -ComputerName $Target -Namespace $Namespace -Class "SMS_Admin" -ErrorAction Stop
        
        foreach ($admin in $admins) {
            # Find source site identifier
            $sourceSiteIdentifier = $admin.SourceSite
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $admin.SourceSite }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $sourceSiteIdentifier = $matchingSite.SiteIdentifier
            }
            
            $adminNode = @{
                "ObjectIdentifier" = "$($admin.LogonName)@$sourceSiteIdentifier"
                "AdminID" = $admin.AdminID
                "Categories" = $admin.Categories
                "CategoryNames" = $admin.CategoryNames
                "CollectionNames" = $admin.CollectionNames
                "CreatedBy" = $admin.CreatedBy
                "CreatedDate" = $admin.CreatedDate
                "DistinguishedName" = $admin.DistinguishedName
                "ExtensionData" = $admin.ExtensionData
                "IsCovered" = $admin.IsCovered
                "IsDeleted" = $admin.IsDeleted
                "LastModifiedBy" = $admin.LastModifiedBy
                "LastModifiedDate" = $admin.LastModifiedDate
                "LogonName" = $admin.LogonName
                "RoleNames" = $admin.RoleNames
                "SecurityScopeIDs" = $admin.Categories  # Renamed for clarity
                "SecurityScopeNames" = $admin.CategoryNames  # Renamed for clarity
                "SourceSiteCode" = $admin.SourceSite
                "SourceSiteIdentifier" = $sourceSiteIdentifier
            }
            
            $script:AdminUsers += $adminNode
            Write-LogMessage "Collected admin user via WMI: $($admin.LogonName)" -Level "Success"
        }
        return $true
    } catch {
        Write-LogMessage "Failed to collect admin users via WMI from $Target`: $_" -Level "Warning"
        return $false
    }
}

function Get-SCCMCollectionsViaWMI {
    param(
        [string]$Target,
        [string]$Namespace,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting collections via WMI from $Target" -Level "Info"
        $collections = Get-WmiObject -ComputerName $Target -Namespace $Namespace -Class "SMS_Collection" -ErrorAction Stop
        
        foreach ($collection in $collections) {
            # Find source site identifier
            $sourceSiteIdentifier = $SiteCode
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $SiteCode }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $sourceSiteIdentifier = $matchingSite.SiteIdentifier
            }
            
            $collectionNode = @{
                "ObjectIdentifier" = $collection.CollectionID
                "CollectionID" = $collection.CollectionID
                "CollectionType" = $collection.CollectionType
                "CollectionVariablesCount" = $collection.CollectionVariablesCount
                "Comment" = $collection.Comment
                "IsBuiltIn" = $collection.IsBuiltIn
                "LastChangeTime" = $collection.LastChangeTime
                "LastMemberChangeTime" = $collection.LastMemberChangeTime
                "LimitToCollectionID" = $collection.LimitToCollectionID
                "LimitToCollectionName" = $collection.LimitToCollectionName
                "MemberCount" = $collection.MemberCount
                "Members" = @()  # Will be populated by collection membership enumeration
                "Name" = $collection.Name
                "SourceSiteCode" = $SiteCode
                "SourceSiteIdentifier" = $sourceSiteIdentifier
            }
            
            $script:Collections += $collectionNode
            Write-LogMessage "Collected collection via WMI: $($collection.Name)" -Level "Success"
        }
        return $true
    } catch {
        Write-LogMessage "Failed to collect collections via WMI from $Target`: $_" -Level "Warning"
        return $false
    }
}

function Get-SCCMCollectionMembersViaWMI {
    param(
        [string]$Target,
        [string]$Namespace,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting collection members via WMI from $Target" -Level "Info"
        $members = Get-WmiObject -ComputerName $Target -Namespace $Namespace -Class "SMS_FullCollectionMembership" -Property CollectionID,ResourceID,SiteCode -ErrorAction Stop
        
        # Group members by collection
        $membersByCollection = $members | Group-Object -Property CollectionID
        
        foreach ($group in $membersByCollection) {
            $collectionID = $group.Name
            $collection = $script:Collections | Where-Object { $_.CollectionID -eq $collectionID }
            
            if ($collection) {
                $collection.Members = $group.Group | ForEach-Object {
                    $_.ResourceID
                }
                Write-LogMessage "Collected $($group.Count) members for collection $collectionID via WMI" -Level "Success"
            }
        }
        return $true
    } catch {
        Write-LogMessage "Failed to collect collection members via WMI from $Target`: $_" -Level "Warning"
        return $false
    }
}

function Get-SCCMClientDevicesViaWMI {
    param(
        [string]$Target,
        [string]$Namespace,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting client devices via WMI from $Target" -Level "Info"
        
        # Try SMS_CombinedDeviceResources first
        try {
            $devices = Get-WmiObject -ComputerName $Target -Namespace $Namespace -Class "SMS_CombinedDeviceResources" -ErrorAction Stop
        } catch {
            # Fallback to SMS_R_System
            Write-LogMessage "SMS_CombinedDeviceResources failed, trying SMS_R_System" -Level "Warning"
            $devices = Get-WmiObject -ComputerName $Target -Namespace $Namespace -Class "SMS_R_System" -ErrorAction Stop
        }
        
        foreach ($device in $devices) {
            # Filter: Only create payloads when IsClient/Client == True/1 AND IsObsolete/Obsolete == False/0
            $isClient = $device.IsClient -eq $true -or $device.Client -eq 1
            $isNotObsolete = $device.IsObsolete -eq $false -or $device.Obsolete -eq 0
            
            if (-not $isClient -or -not $isNotObsolete) {
                continue
            }
            
            # Find source site identifier
            $deviceSiteCode = if ($device.SiteCode) { $device.SiteCode } else { $SiteCode }
            $sourceSiteIdentifier = $deviceSiteCode
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $deviceSiteCode }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $sourceSiteIdentifier = $matchingSite.SiteIdentifier
            }
            
            $deviceNode = @{
                "ObjectIdentifier" = $device.ResourceID -or $device.ResourceId
                "AADDeviceID" = $device.AADDeviceID
                "AADTenantID" = $device.AADTenantID
                "ADDomainSID" = $device.ADDomainSID
                "ADLastLogonTime" = $device.ADLastLogonTime
                "ADLastLogonUser" = $device.ADLastLogonUser
                "ADLastLogonUserDomain" = $device.ADLastLogonUserDomain
                "CoManaged" = $device.CoManaged
                "CurrentLogonUser" = $device.CurrentLogonUser
                "CurrentManagementPoint" = $device.CurrentManagementPoint
                "CurrentManagementPointSID" = $device.CurrentManagementPointSID
                "DeviceOS" = $device.DeviceOS
                "DeviceOSBuild" = $device.DeviceOSBuild
                "DistinguishedName" = $device.DistinguishedName
                "dNSHostName" = $device.dNSHostName -or "$($device.Name).$($device.Domain -or $device.ResourceDomainORWorkgroup)"
                "IsVirtualMachine" = $device.IsVirtualMachine
                "LastActiveTime" = $device.LastActiveTime
                "LastOfflineTime" = $device.LastOfflineTime
                "LastOnlineTime" = $device.LastOnlineTime
                "LastReportedMPServerName" = $device.LastReportedMPServerName
                "LastReportedMPServerSID" = $device.LastReportedMPServerSID
                "PrimaryUser" = $device.PrimaryUser
                "ResourceID" = $device.ResourceID -or $device.ResourceId
                "SiteCode" = $deviceSiteCode
                "SiteGUID" = $null
                "SiteIdentifier" = $sourceSiteIdentifier
                "SMSID" = $device.SMSID -or $device.SMSUniqueIdentifier
                "Source" = "WMI"
            }
            
            $script:ClientDevices += $deviceNode
            Write-LogMessage "Collected client device via WMI: $($device.Name)" -Level "Success"
        }
        return $true
    } catch {
        Write-LogMessage "Failed to collect client devices via WMI from $Target`: $_" -Level "Warning"
        return $false
    }
}

function Get-SCCMSiteSystemRolesViaWMI {
    param(
        [string]$Target,
        [string]$Namespace,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage "Collecting site system roles via WMI from $Target" -Level "Info"
        $sysResUse = Get-WmiObject -ComputerName $Target -Namespace $Namespace -Class "SMS_SCI_SysResUse" -ErrorAction Stop
        
        # Group by NetworkOSPath and SiteCode to combine roles for each system
        $groupedSystems = $sysResUse | Group-Object { "$($_.NetworkOSPath),$($_.SiteCode)" }
        
        foreach ($group in $groupedSystems) {
            $networkOSPath = ($group.Name -split ',')[0]
            $systemSiteCode = ($group.Name -split ',')[1]
            
            # Extract hostname from NetworkOSPath (remove \\)
            $hostname = $networkOSPath -replace '^\\\\', ''
            
            # Resolve hostname to AD object
            $systemADObject = $null
            try {
                $systemADObject = Get-ActiveDirectoryObject -Name $hostname -Domain $script:Domain
            } catch {
                Write-LogMessage "Failed to resolve site system $hostname to AD object: $_" -Level "Warning"
            }
            
            # Find source site identifier
            $sourceSiteIdentifier = $systemSiteCode
            $matchingSite = $script:Sites | Where-Object { $_.SiteCode -eq $systemSiteCode }
            if ($matchingSite -and $matchingSite.SiteIdentifier) {
                $sourceSiteIdentifier = $matchingSite.SiteIdentifier
            }
            
            # Collect all roles for this system
            $systemRoles = @()
            foreach ($roleItem in $group.Group) {
                $roleName = $roleItem.RoleName
                $systemRoles += @{
                    "Name" = $roleName
                    "Properties" = @{}
                    "SiteCode" = $systemSiteCode
                    "SiteIdentifier" = $sourceSiteIdentifier
                    "SourceForest" = $null
                }
            }
            
            # Create site system entry
            $siteSystemRole = @{
                "dNSHostName" = $hostname
                "ObjectIdentifier" = if ($systemADObject) { $systemADObject.SID } else { $null }
                "Roles" = $systemRoles
                "Source" = "WMI"
                "ADObject" = $systemADObject
            }
            
            $script:SiteSystemRoles += $siteSystemRole
            Write-LogMessage "Collected site system roles via WMI: $hostname ($($systemRoles.Count) roles)" -Level "Success"
        }
        return $true
    } catch {
        Write-LogMessage "Failed to collect site system roles via WMI from $Target`: $_" -Level "Warning"
        return $false
    }
}

#endregion

#region HTTP Collection

function Invoke-HTTPCollection {
    param($Targets)
    
    Write-LogMessage Info "Starting HTTP collection..."
    
    if (-not $Targets -or $Targets.Count -eq 0) {
        Write-LogMessage Warning "No targets provided for HTTP collection"
        return
    }
    
    foreach ($targetDict in $Targets) {
        try {
            $target = $targetDict.Name
            Write-LogMessage Info "Attempting HTTP collection on: $target"
            
            # Skip if already collected successfully
            if ($script:CollectionTargets[$target]["Collected"]) {
                Write-LogMessage Warning "Target $target already collected, skipping HTTP"
                continue
            }
            
            $siteCode = $null
            $isDP = $false
            $isMP = $false
                        
            # Test Management Point HTTP endpoints (try HTTP first, then HTTPS)
            $protocols = @("http", "https")
            
            foreach ($protocol in $protocols) {

                Write-LogMessage Verbose "Trying connections via $protocol"
                try {
                    # Management Point .sms_aut endpoints
                    $mpEndpoints = @(
                        "$protocol`://$target/SMS_MP/.sms_aut?MPKEYINFORMATION", # Parse MPKEYINFORMATION response first to get site code
                        "$protocol`://$target/SMS_MP/.sms_aut?MPLIST"
                    )
                    
                    foreach ($endpoint in $mpEndpoints) {
                        # Skip if we've already discovered the MP role on this target
                        if ($isMP -ne $true) {
                            try {
                                Write-LogMessage Verbose "Testing management point endpoint: $endpoint"
                                
                                $response = Invoke-HttpRequest $endpoint
                                
                                if ($response.StatusCode -eq 200 -and $response.Content) {
                                    Write-LogMessage Success "Found management point role on $target"
                                    $isMP = $true
                                    
                                    if ($endpoint -like "*MPKEYINFORMATION*") {
                                        try {
                                            $xmlContent = [xml]$response.Content
                                            $mpKeyInfo = $xmlContent.MPKEYINFORMATION
                                            
                                            if ($mpKeyInfo) {
                                                $mpFQDN = $mpKeyInfo.FQDN
                                                $siteCode = $mpKeyInfo.SITECODE
                                                
                                                if ($mpFQDN) {
                                                    # This device is already in targets but this returns its ADObject to update the Computer node properties    
                                                    $collectionTarget = Add-DeviceToTargets -DeviceName $mpFQDN -Source "HTTP-MPKEYINFORMATION"
                                                    Write-LogMessage Success "Found site code for $mpFQDN`: $siteCode"
    
                                                    # Create or update SCCM_Site node
                                                    Add-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                                                        CollectionSource = @("HTTP-MPKEYINFORMATION")
                                                        SiteCode = $siteCode
                                                    }
                                                        

                                                }
                                            }
                                        } catch {
                                            Write-LogMessage Error "Failed to parse MPKEYINFORMATION XML response: $_"
                                        }
                                    }

                                    # Add site system role to Computer node properties
                                    if ($collectionTarget.ADObject) {
                                        Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                                            CollectionSource = @("HTTP-MPKEYINFORMATION")
                                            SCCM_SiteSystemRoles = @("SMS Management Point$(if ($siteCode) { "@$siteCode" })")
                                        }
                                    }
    
                                    # Parse MPLIST response for more management points
                                    if ($endpoint -like "*MPLIST*") {
                                        try {
                                            $xmlContent = [xml]$response.Content
                                            $mpList = $xmlContent.MPList
                                            
                                            if ($mpList -and $mpList.MP) {
                                                foreach ($mp in $mpList.MP) {
                                                    $mpFQDN = $mp.FQDN
                                                    
                                                    if ($mpFQDN) {
                                                        # There may be new systems in here and we need to start collection over for these
                                                        $collectionTarget = Add-DeviceToTargets -DeviceName $mpFQDN -Source "HTTP-MPLIST"
                                                        if ($collectionTarget -and $collectionTarget.IsNew) {
                                                            Write-LogMessage Success "Found management point: $mpFQDN"
                                                        }
    
                                                        # Add site system role to Computer node properties
                                                        if ($collectionTarget.ADObject) {
                                                            Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                                                                CollectionSource = @("HTTP-MPKEYINFORMATION")
                                                                SCCM_SiteSystemRoles = @("SMS Management Point@$siteCode")
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } catch {
                                            Write-LogMessage Error "Failed to parse MPLIST XML response: $_"
                                        }
                                    }                              
                                } else {
                                    Write-LogMessage Verbose "    Received $($response.StatusCode)"
                                }
                            } catch {
                                # Endpoint not accessible, move to next protocol
                                Write-LogMessage Verbose "Management point endpoint not accessible on $endpoint`:`n$_"
                                break
                            }
                        }
                    }
                    
                    # Test Distribution Point HTTP endpoints
                    $dpEndpoints = @(
                        "$protocol`://$target/SMS_DP_SMSPKG$"
                    )
                    
                    foreach ($endpoint in $dpEndpoints) {
                        # No need to try HTTPS if we have what we need from HTTP
                        if ($isDP -ne $true) {
                            $response = $null

                            try {
                                Write-LogMessage Verbose "Testing distribution point endpoint: $endpoint"
                                $response = Invoke-HttpRequest $endpoint
                            } catch [System.Net.WebException] {
                                # Check if it's a 401 (auth required) which still indicates DP presence
                                if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq "Unauthorized") {
                                    $isDP = $true
                                } else {
                                    Write-LogMessage Verbose "Distribution point endpoint not accessible on $endpoint`:`n$_"
                                }
                            }
    
                            # Specific response codes indicate presence of distribution point role
                            if ($response) {
                                if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 200) {
                                    $isDP = $true
                                } else {
                                    Write-LogMessage Verbose "    Received $($response.StatusCode)"
                                }
                            }
    
                            if ($isDP) {
                                Write-LogMessage Success "Found distribution point role on $target"
    
                                # This device is already in targets but this returns its ADObject to update the Computer node properties
                                $collectionTarget = Add-DeviceToTargets -DeviceName $target -Source "HTTP-SMS_DP_SMSPKG$"
    
                                # Add site system role to Computer node properties
                                if ($collectionTarget.ADObject) {
                                    Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                                        CollectionSource = @("HTTP-SMS_DP_SMSPKG$")
                                        SCCM_SiteSystemRoles = @("SMS Distribution Point$(if ($siteCode) { "@$siteCode" })") # We can't get the site code via HTTP unless the target is also a DP but might be able to later via SMB
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-LogMessage Warning "HTTP collection failed for protocol $protocol on $target`: $_"
                }
            }
        } catch {
            Write-LogMessage Warning "HTTP collection failed for $target`: $_"
        }
    }
    
    Write-LogMessage Success "HTTP collection completed"
}

#endregion

#region SMB Collection

function Invoke-SMBCollection {
    param($Targets)
    
    Write-LogMessage Info "Starting SMB collection..."
    
    if (-not $Targets -or $Targets.Count -eq 0) {
        Write-LogMessage Warning "No targets provided for SMB collection"
        return
    }

    try {
        # Define the NetAPI32 structures and functions if not already defined
        if (-not ([System.Management.Automation.PSTypeName]'NetAPI32').Type) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct SHARE_INFO_1 {
[MarshalAs(UnmanagedType.LPWStr)]
public string shi1_netname;
public uint shi1_type;
[MarshalAs(UnmanagedType.LPWStr)]
public string shi1_remark;
}

public class NetAPI32 {
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetShareEnum(
    [MarshalAs(UnmanagedType.LPWStr)] string servername,
    int level,
    out IntPtr bufptr,
    int prefmaxlen,
    out int entriesread,
    out int totalentries,
    ref int resume_handle
);

[DllImport("netapi32.dll", SetLastError = true)]
public static extern int NetApiBufferFree(IntPtr buffer);

// Error codes
public const int NERR_Success = 0;
public const int ERROR_ACCESS_DENIED = 5;
public const int ERROR_BAD_NETPATH = 53;
public const int ERROR_NETWORK_UNREACHABLE = 1231;
public const int NERR_ServerNotStarted = 2114;
}
"@
        }
        Write-LogMessage Verbose "Successfully loaded NetAPI32"
    } catch {
        Write-LogMessage Error "Failed to load NetAPI32`: $_"
        return
    }
    
    foreach ($targetDict in $Targets) {
        $target = $targetDict.Name

        # Skip if already collected successfully
        if ($script:CollectionTargets[$target]["Collected"]) {
            Write-LogMessage Info "Target $target already collected, skipping SMB"
            continue
        }
        
        # Check for SCCM-specific SMB shares using NetAPI32
        try {
            Write-LogMessage Info "Enumerating SMB shares on $target"
            
            # Use NetAPI32 to enumerate shares
            $bufPtr = [IntPtr]::Zero
            $entriesRead = 0
            $totalEntries = 0
            $resumeHandle = 0
            
            $result = [NetAPI32]::NetShareEnum(
                $target,
                1,
                [ref]$bufPtr,
                -1,
                [ref]$entriesRead,
                [ref]$totalEntries,
                [ref]$resumeHandle
            )
            
            if ($result -eq [NetAPI32]::NERR_Success -and $bufPtr -ne [IntPtr]::Zero -and $entriesRead -gt 0) {
                Write-LogMessage Verbose "Successfully enumerated SMB shares on $target"

                # Calculate the size of SHARE_INFO_1 structure
                $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][SHARE_INFO_1])

                # Initialize the target's share collection if it doesn't exist
                $shares = @()
                
                # Parse each share entry for SCCM-specific shares
                for ($i = 0; $i -lt $entriesRead; $i++) {
                    $sharePtr = [IntPtr]($bufPtr.ToInt64() + ($i * $structSize))
                    $shareInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($sharePtr, [Type][SHARE_INFO_1])
                    
                    $shareName = $shareInfo.shi1_netname
                    $shareComment = if ($shareInfo.shi1_remark) { $shareInfo.shi1_remark } else { "" }
                    Write-LogMessage Verbose "    $shareName ($shareComment)"

                    $shares += @{
                        Name = $shareName
                        Description = $shareComment
                    }
                }

                # Check share names
                $collectionSource = @()
                $siteCode = $null
                $smsSite = $shares | Where-Object { $_.Name -eq "SMS_SITE" }
                $smsSiteCode = $shares | Where-Object { $_.Name -match "^SMS_(\w+)$" }                  
                $smsDP = $shares | Where-Object { $_.Name -eq "SMS_DP$" }
                $reminst = $shares | Where-Object { $_.Name -eq "REMINST" }
                $contentLib = $shares | Where-Object { $_.Name -eq "SCCMContentLib$" }
                $smsPkgShares = $shares | Where-Object { $_.Name -match "SMSPKG" }
                $siteShares = $shares | Where-Object { $_.Description -match "SMS Site (\w+)" }

                # Check for SMS_SITE
                $isSiteServer = $false
                if ($smsSite) {
                    $collectionSource += "SMB-SMS_SITE"
                    $isSiteServer = $true

                    if ($smsSite.Description -match "SMS Site (\w+)") {
                        $siteCode = $Matches[1]
                    } else {
                        Write-LogMessage Warning "Could not determine site code from SMS_SITE share description"
                    }
                    Write-LogMessage Success "Found site server for site: $siteCode"
                }

                # Check for SMS_<sitecode>
                if (-not $isSiteServer -and $smsSiteCode) {
                    $collectionSource += "SMB-SMS_<sitecode>"
                    $isSiteServer = $true

                    if ($smsSite.Description -match "SMS Site (\w+)") {
                        $siteCode = $Matches[1]
                    } else {
                        Write-LogMessage Warning "Could not determine site code from SMS_<sitecode> share description"
                    }
                    Write-LogMessage Success "Found site server for site: $siteCode"
                }

                # Check for REMINST share (indicates PXE support)
                $isPXEEnabled = $false
                if ($reminst) {
                    $collectionSource += "SMB-REMINST"
                    Write-LogMessage Verbose "Distribution point has PXE support enabled"
                    $isPXEEnabled = $true
                }

                # Check for content library shares
                $hostsContentLib = $false
                if ($contentLib) {
                    $collectionSource += "SMB-SCCMContentLib$"
                    Write-LogMessage Verbose "Target hosts the content library (SCCMContentLib$)"
                    $hostsContentLib = $true
                }
                if ($smsPkgShares) {
                    $collectionSource += "SMB-SMSPKG$"
                    Write-LogMessage Verbose "Target hosts the legacy content library (SMSPKG$)"
                    $hostsContentLib = $true
                }

                # If for some reason we don't have the site code yet, try to find it in any share description
                if (-not $siteCode) {
                    if ($siteShares) {
                        $collectionSource += "SMB-ShareDescription"

                        foreach ($siteShare in $siteShares) {
                            if ($smsSite.Description -match "SMS Site (\w+)") {
                                $siteCode = $Matches[1]
                                Write-LogMessage Success "Found site code in share description: $siteCode"
                                break
                            }
                        } 
                    }
                }                        

                # Check for SMS_DP$ share
                $isDP = $false
                if ($smsDP) {
                    $collectionSource += @("SMB-SMS_DP$")
                    $isDP = $true

                    if ($smsDP.Description -match "SMS Site (\w+) DP") {
                        $siteCode = $Matches[1]
                    } else {
                        if (-not $smsDP.Description -contains "ConfigMgr Site Server") {
                            Write-LogMessage Warning "Could not determine site code from SMS_DP$ share description"
                        }
                    }
                    # Site code should be determined from SMS_SITE, SMS_*, or SMS_DP$ by now
                    Write-LogMessage Success "Found distribution point role for site: $siteCode"
                } 

                # Create SCCM_Site if it doesn't exist already
                if ($isDP -or $isSiteServer) {
                    if ($siteCode) {
                        Add-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                            CollectionSource = $collectionSource
                            SiteCode = $siteCode
                        }
                    } else {
                        Write-LogMessage Warning "Could not determine site code for roles"
                    }

                    # Create or update the Computer node with site system roles and properties
                    $roles = @()
                    if ($isSiteServer) {
                        $roles += "SMS Site Server$(if ($siteCode) { "@$siteCode"})"
                    }
                    if ($isDP) {
                        $roles += "SMS Distribution Point$(if ($siteCode) { "@$siteCode"})"
                    }

                    Add-Node -Id $targetDict.Value.ADObject.SID -Kinds @("Computer", "Base") -PSObject $targetDict.Value.ADObject -Properties @{
                        CollectionSource = $collectionSource
                        SCCM_HostsContentLibrary = $hostsContentLib
                        SCCM_IsPXESupportEnabled = $isPXEEnabled
                        SCCM_SiteSystemRoles = $roles
                    }
                } 
            } else {
                Write-LogMessage Warning "Failed to enumerate SMB shares on $target (access denied or not accessible)"
            }
        } catch {
            Write-LogMessage Error "SMB enumeration failed for $target`: $_"
        } finally {
            # Always free the buffer if it was allocated
            if ($bufPtr -and $bufPtr -ne [IntPtr]::Zero) {
                try {
                    [NetAPI32]::NetApiBufferFree($bufPtr) | Out-Null
                }
                catch {
                    Write-LogMessage Warning "Failed to free NetAPI buffer: $_"
                }
            }
        }
    }

    Write-LogMessage "SMB collection completed" -Level "Success"
}

#endregion

#region Post-Processing and Edge Creation

#region Ingest Processing Functions

function Process-SitesIngest {
    Write-LogMessage "Processing Sites ingest..." -Level "Info"
    
    foreach ($site in $script:Sites) {
        # 1. Create or find SCCM_Site node
        $siteNode = New-SCCMNode -ObjectIdentifier $site.SiteIdentifier -NodeType "SCCM_Site" -Properties $site
        $script:Nodes += $siteNode
        
        # 2. Create or find parent SCCM_Site if ParentSiteCode exists
        if ($site.ParentSiteCode -and $site.ParentSiteGUID) {
            $parentSiteIdentifier = "$($site.ParentSiteCode).$($site.ParentSiteGUID)"
            
            # Create parent site properties
            $parentSiteType = if ($site.SiteType -eq "Secondary Site") { "Primary Site" } else { "Central Administration Site" }
            $parentSiteProps = @{
                "SiteCode" = $site.ParentSiteCode
                "SiteGUID" = $site.ParentSiteGUID
                "SiteIdentifier" = $parentSiteIdentifier
                "SiteType" = $parentSiteType
                "SourceForest" = $site.SourceForest
            }
            
            $parentSiteNode = New-SCCMNode -ObjectIdentifier $parentSiteIdentifier -NodeType "SCCM_Site" -Properties $parentSiteProps
            $script:Nodes += $parentSiteNode
            
            # Create SCCM_SameAdminsAs edges
            # Parent to child (always)
            $edge1 = New-SCCMEdge -SourceNode $parentSiteIdentifier -TargetNode $site.SiteIdentifier -EdgeType "SCCM_SameAdminsAs"
            $script:Edges += $edge1
            
            # Child to parent (unless secondary site)
            if ($site.SiteType -ne "Secondary Site") {
                $edge2 = New-SCCMEdge -SourceNode $site.SiteIdentifier -TargetNode $parentSiteIdentifier -EdgeType "SCCM_SameAdminsAs"
                $script:Edges += $edge2
            }
        }
        
        # 3. Create/update Computer node for site server
        if ($site.Properties.SiteServerObjectIdentifier) {
            $computerProps = @{
                "Name" = $site.Properties.SiteServerName
                "Domain" = $site.Properties.SiteServerDomain
                "SCCM_SiteSystemRoles" = @("SMS Site Server@$($site.SiteIdentifier)")
            }
            $computerNode = New-SCCMNode -ObjectIdentifier $site.Properties.SiteServerObjectIdentifier -NodeType "Computer" -Properties $computerProps
            $script:Nodes += $computerNode
        }
        
        # 4. Create/update Computer node for SQL server (if different from site server)
        if ($site.Properties.SQLServerObjectIdentifier -and $site.Properties.SQLServerObjectIdentifier -ne $site.Properties.SiteServerObjectIdentifier) {
            $sqlComputerProps = @{
                "Name" = $site.Properties.SQLServerName
                "SCCM_SiteSystemRoles" = @("SMS SQL Server.$($site.SiteIdentifier)")
            }
            $sqlComputerNode = New-SCCMNode -ObjectIdentifier $site.Properties.SQLServerObjectIdentifier -NodeType "Computer" -Properties $sqlComputerProps
            $script:Nodes += $sqlComputerNode
            
            # Create AdminTo edge from site server to SQL server
            if ($site.Properties.SiteServerObjectIdentifier) {
                $adminToEdge = New-SCCMEdge -SourceNode $site.Properties.SiteServerObjectIdentifier -TargetNode $site.Properties.SQLServerObjectIdentifier -EdgeType "AdminTo"
                $script:Edges += $adminToEdge
            }
        }
    }
    
    Write-LogMessage "Sites ingest completed" -Level "Success"
}

function Process-ClientDevicesIngest {
    Write-LogMessage "Processing ClientDevices ingest..." -Level "Info"
    
    foreach ($device in $script:ClientDevices) {
        # 1. Create or find SCCM_ClientDevice node
        $deviceNode = New-SCCMNode -ObjectIdentifier $device.SMSID -NodeType "SCCM_ClientDevice" -Properties $device
        $script:Nodes += $deviceNode
        
        # 2. Create or find SCCM_Site node and create SCCM_HasClient edge
        if ($device.SiteIdentifier) {
            $siteNode = New-SCCMNode -ObjectIdentifier $device.SiteIdentifier -NodeType "SCCM_Site" -Properties @{}
            $script:Nodes += $siteNode
            
            $hasClientEdge = New-SCCMEdge -SourceNode $device.SiteIdentifier -TargetNode $device.SMSID -EdgeType "SCCM_HasClient"
            $script:Edges += $hasClientEdge
        }
        
        # 3. Create SameHostAs edges with Computer node
        if ($device.ADDomainSID) {
            # Create Host node
            $hostId = "HOST-$($device.SMSID)"
            $hostNode = New-SCCMNode -ObjectIdentifier $hostId -NodeType "Host" -Properties @{}
            $script:Nodes += $hostNode
            
            # Create Computer node
            $computerProps = @{
                "DistinguishedName" = $device.DistinguishedName
                "Name" = $device.dNSHostName
            }
            $computerNode = New-SCCMNode -ObjectIdentifier $device.ADDomainSID -NodeType "Computer" -Properties $computerProps
            $script:Nodes += $computerNode
            
            # Create SameHostAs edges (bidirectional)
            $sameHost1 = New-SCCMEdge -SourceNode $device.SMSID -TargetNode $hostId -EdgeType "SameHostAs"
            $sameHost2 = New-SCCMEdge -SourceNode $hostId -TargetNode $device.SMSID -EdgeType "SameHostAs"
            $sameHost3 = New-SCCMEdge -SourceNode $device.ADDomainSID -TargetNode $hostId -EdgeType "SameHostAs"
            $sameHost4 = New-SCCMEdge -SourceNode $hostId -TargetNode $device.ADDomainSID -EdgeType "SameHostAs"
            
            $script:Edges += $sameHost1, $sameHost2, $sameHost3, $sameHost4
        }
        
        # 4. Create SameHostAs edges with AZDevice node
        if ($device.AADDeviceID -and $device.AADTenantID) {
            # Create Host node if not already created
            $hostId = "HOST-$($device.SMSID)"
            $hostNode = New-SCCMNode -ObjectIdentifier $hostId -NodeType "Host" -Properties @{}
            $script:Nodes += $hostNode
            
            # Create AZDevice node
            $azDeviceProps = @{
                "tenantId" = $device.AADTenantID
            }
            $azDeviceNode = New-SCCMNode -ObjectIdentifier $device.AADDeviceID -NodeType "AZDevice" -Properties $azDeviceProps
            $script:Nodes += $azDeviceNode
            
            # Create SameHostAs edges (bidirectional)
            $azSameHost1 = New-SCCMEdge -SourceNode $device.SMSID -TargetNode $hostId -EdgeType "SameHostAs"
            $azSameHost2 = New-SCCMEdge -SourceNode $hostId -TargetNode $device.SMSID -EdgeType "SameHostAs"
            $azSameHost3 = New-SCCMEdge -SourceNode $device.AADDeviceID -TargetNode $hostId -EdgeType "SameHostAs"
            $azSameHost4 = New-SCCMEdge -SourceNode $hostId -TargetNode $device.AADDeviceID -EdgeType "SameHostAs"
            
            $script:Edges += $azSameHost1, $azSameHost2, $azSameHost3, $azSameHost4
        }
        
        # 5. Create SCCM_HasADLastLogonUser edge
        if ($device.ADLastLogonUserSID) {
            $lastLogonEdge = New-SCCMEdge -SourceNode $device.SMSID -TargetNode $device.ADLastLogonUserSID -EdgeType "SCCM_HasADLastLogonUser"
            $script:Edges += $lastLogonEdge
        }
        
        # 6. Create SCCM_HasCurrentUser edge
        if ($device.CurrentLogonUserSID) {
            $currentUserEdge = New-SCCMEdge -SourceNode $device.SMSID -TargetNode $device.CurrentLogonUserSID -EdgeType "SCCM_HasCurrentUser"
            $script:Edges += $currentUserEdge
        }
        
        # 7. Create SCCM_HasPrimaryUser edge
        if ($device.PrimaryUserSID) {
            $primaryUserEdge = New-SCCMEdge -SourceNode $device.SMSID -TargetNode $device.PrimaryUserSID -EdgeType "SCCM_HasPrimaryUser"
            $script:Edges += $primaryUserEdge
        }
    }
    
    Write-LogMessage "ClientDevices ingest completed" -Level "Success"
}

function Process-SecurityRolesIngest {
    Write-LogMessage "Processing SecurityRoles ingest..." -Level "Info"
    
    foreach ($role in $script:SecurityRoles) {
        # Create or find SCCM_SecurityRole node
        $roleNode = New-SCCMNode -ObjectIdentifier $role.ObjectIdentifier -NodeType "SCCM_SecurityRole" -Properties $role
        $script:Nodes += $roleNode
    }
    
    Write-LogMessage "SecurityRoles ingest completed" -Level "Success"
}

function Process-CollectionsIngest {
    Write-LogMessage "Processing Collections ingest..." -Level "Info"
    
    foreach ($collection in $script:Collections) {
        # Create or find SCCM_Collection node
        $collectionNode = New-SCCMNode -ObjectIdentifier $collection.ObjectIdentifier -NodeType "SCCM_Collection" -Properties $collection
        $script:Nodes += $collectionNode
    }
    
    Write-LogMessage "Collections ingest completed" -Level "Success"
}

function Process-AdminUsersIngest {
    Write-LogMessage "Processing AdminUsers ingest..." -Level "Info"
    
    foreach ($admin in $script:AdminUsers) {
        # 1. Create or find SCCM_AdminUser node
        $adminNode = New-SCCMNode -ObjectIdentifier $admin.ObjectIdentifier -NodeType "SCCM_AdminUser" -Properties $admin
        $script:Nodes += $adminNode
        
        # 2. Create or find domain object and create SCCM_IsMappedTo edge
        if ($admin.AdminSID) {
            $domainObjectNode = New-SCCMNode -ObjectIdentifier $admin.AdminSID -NodeType "Base" -Properties @{}
            $script:Nodes += $domainObjectNode
            
            $mappedToEdge = New-SCCMEdge -SourceNode $admin.AdminSID -TargetNode $admin.ObjectIdentifier -EdgeType "SCCM_IsMappedTo"
            $script:Edges += $mappedToEdge
        }
        
        # 3. Create SCCM_IsAssigned edges to collections
        if ($admin.CollectionNames) {
            $collectionNames = $admin.CollectionNames -split ", "
            foreach ($collectionName in $collectionNames) {
                $collection = $script:Collections | Where-Object { $_.Name -eq $collectionName.Trim() -and $_.SourceSiteIdentifier -eq $admin.SourceSiteIdentifier }
                if ($collection) {
                    $assignedToCollectionEdge = New-SCCMEdge -SourceNode $admin.ObjectIdentifier -TargetNode $collection.ObjectIdentifier -EdgeType "SCCM_IsAssigned"
                    $script:Edges += $assignedToCollectionEdge
                }
            }
        }
        
        # 4. Create SCCM_IsAssigned edges to security roles
        if ($admin.RoleIDs) {
            $roleIds = $admin.RoleIDs -split ", "
            foreach ($roleId in $roleIds) {
                $role = $script:SecurityRoles | Where-Object { $_.RoleID -eq $roleId.Trim() -and $_.SourceSiteIdentifier -eq $admin.SourceSiteIdentifier }
                if ($role) {
                    $assignedToRoleEdge = New-SCCMEdge -SourceNode $admin.ObjectIdentifier -TargetNode $role.ObjectIdentifier -EdgeType "SCCM_IsAssigned"
                    $script:Edges += $assignedToRoleEdge
                }
            }
        }
    }
    
    Write-LogMessage "AdminUsers ingest completed" -Level "Success"
}

function Process-SiteSystemRolesIngest {
    Write-LogMessage "Processing SiteSystemRoles ingest..." -Level "Info"
    
    foreach ($siteSystem in $script:SiteSystemRoles) {
        # 1. Create or find Computer node
        $computerProps = @{
            "Name" = $siteSystem.dNSHostName
            "SCCM_SiteSystemRoles" = $siteSystem.Roles
        }
        $computerNode = New-SCCMNode -ObjectIdentifier $siteSystem.ObjectIdentifier -NodeType "Computer" -Properties $computerProps
        $script:Nodes += $computerNode
        
        # 2. Create AdminTo edges from site server
        foreach ($role in $siteSystem.Roles) {
            if ($role -match "\.(.+)$") {
                $siteIdentifier = $matches[1]
                
                # Find the site server for this site
                $site = $script:Sites | Where-Object { $_.SiteIdentifier -eq $siteIdentifier }
                if ($site -and $site.Properties.SiteServerObjectIdentifier -ne $siteSystem.ObjectIdentifier) {
                    $adminToEdge = New-SCCMEdge -SourceNode $site.Properties.SiteServerObjectIdentifier -TargetNode $siteSystem.ObjectIdentifier -EdgeType "AdminTo"
                    $script:Edges += $adminToEdge
                }
            }
        }
        
        # 3. Create HasSession edge for current users
        if ($siteSystem.CurrentUser) {
            $sessionEdge = New-SCCMEdge -SourceNode $siteSystem.ObjectIdentifier -TargetNode $siteSystem.CurrentUser -EdgeType "HasSession"
            $script:Edges += $sessionEdge
        }
    }
    
    Write-LogMessage "SiteSystemRoles ingest completed" -Level "Success"
}

#endregion

#region Post-Processing Functions

function Process-HasMemberEdges {
    Write-LogMessage "Post-processing: Creating SCCM_HasMember edges..." -Level "Info"
    
    # Step 1: Identify all SCCM_Site labeled nodes
    foreach ($site in $script:Sites) {
        Write-LogMessage "Processing SCCM_HasMember for site: $($site.SiteIdentifier)" -Level "Debug"
        
        # Step 2: Get all sites connected via SCCM_SameAdminsAs (recursively)
        $connectedSiteIdentifiers = Get-ConnectedSitesRecursive -SiteIdentifier $site.SiteIdentifier
        Write-LogMessage "Found $($connectedSiteIdentifiers.Count) connected sites for $($site.SiteIdentifier)" -Level "Debug"
        
        # Step 3: Find collections whose SourceSiteIdentifier matches any connected site
        $relevantCollections = $script:Collections | Where-Object {
            $connectedSiteIdentifiers -contains $_.SourceSiteIdentifier
        }
        
        foreach ($collection in $relevantCollections) {
            Write-LogMessage "Processing collection: $($collection.Name) for site hierarchy" -Level "Debug"
            
            # Step 4: For each collection, process its members
            foreach ($member in $collection.Members) {
                # Step 5: Find ClientDevice with matching ResourceID and SiteIdentifier in connected sites
                $matchingDevice = $script:ClientDevices | Where-Object {
                    $_.ResourceID -eq $member.ResourceID -and
                    $connectedSiteIdentifiers -contains $_.SiteIdentifier
                }
                
                if ($matchingDevice) {
                    # Step 6: Create SCCM_HasMember edge
                    $hasMemberEdge = New-SCCMEdge -SourceNode $collection.ObjectIdentifier -TargetNode $matchingDevice.SMSID -EdgeType "SCCM_HasMember"
                    $script:Edges += $hasMemberEdge
                    Write-LogMessage "Created SCCM_HasMember: $($collection.Name) -> $($matchingDevice.dNSHostName)" -Level "Debug"
                }
            }
        }
    }
    
    Write-LogMessage "SCCM_HasMember edges created" -Level "Success"
}

function Process-FullAdministratorEdges {
    Write-LogMessage "Post-processing: Creating SCCM_FullAdministrator edges..." -Level "Info"
    
    # Step 1: Identify all SCCM_Site labeled nodes
    foreach ($site in $script:Sites) {
        Write-LogMessage "Processing SCCM_FullAdministrator for site: $($site.SiteIdentifier)" -Level "Debug"
        
        # Step 2: Get all sites connected via SCCM_SameAdminsAs (recursively)
        $connectedSiteIdentifiers = Get-ConnectedSitesRecursive -SiteIdentifier $site.SiteIdentifier
        
        # Step 3: Find Full Administrator security roles in connected sites
        $fullAdminRoles = $script:SecurityRoles | Where-Object {
            $connectedSiteIdentifiers -contains $_.SourceSiteIdentifier -and
            $_.RoleID -eq "SMS0001R" -and
            $_.IsBuiltIn -eq $true
        }
        
        foreach ($role in $fullAdminRoles) {
            Write-LogMessage "Processing Full Administrator role: $($role.ObjectIdentifier)" -Level "Debug"
            
            # Step 4: Find AdminUsers connected to this role via SCCM_IsAssigned edges
            $adminUsers = Find-AdminUsersConnectedToSecurityRole -SecurityRoleObjectIdentifier $role.ObjectIdentifier
            
            foreach ($admin in $adminUsers) {
                Write-LogMessage "Processing admin user: $($admin.LogonName)" -Level "Debug"
                
                # Step 5: Find Collections connected to this AdminUser via SCCM_IsAssigned edges
                $collections = Find-CollectionsConnectedToAdminUser -AdminUserObjectIdentifier $admin.ObjectIdentifier
                
                foreach ($collection in $collections) {
                    Write-LogMessage "Processing collection: $($collection.Name)" -Level "Debug"
                    
                    # Step 6: Find ClientDevices connected to this Collection via SCCM_HasMember edges
                    $devices = Find-ClientDevicesConnectedToCollection -CollectionObjectIdentifier $collection.ObjectIdentifier
                    
                    foreach ($device in $devices) {
                        # Step 7: Create SCCM_FullAdministrator edge
                        $fullAdminEdge = New-SCCMEdge -SourceNode $admin.ObjectIdentifier -TargetNode $device.SMSID -EdgeType "SCCM_FullAdministrator"
                        $script:Edges += $fullAdminEdge
                        Write-LogMessage "Created SCCM_FullAdministrator: $($admin.LogonName) -> $($device.dNSHostName)" -Level "Debug"
                    }
                }
            }
        }
    }
    
    Write-LogMessage "SCCM_FullAdministrator edges created" -Level "Success"
}

function Process-RoleSpecificEdges {
    Write-LogMessage "Post-processing: Creating role-specific edges..." -Level "Info"
    
    # Define role mappings as specified in design document
    $roleMapping = @{
        "SMS0006R" = "SCCM_ComplianceSettingsManager"
        "SMS0008R" = "SCCM_ApplicationAuthor"
        "SMS0009R" = "SCCM_ApplicationAdministrator"
        "SMS000AR" = "SCCM_OSDManager"
        "SMS000ER" = "SCCM_OperationsAdministrator"
        "SMS000FR" = "SCCM_SecurityAdministrator"
    }
    
    foreach ($roleId in $roleMapping.Keys) {
        $edgeType = $roleMapping[$roleId]
        Write-LogMessage "Processing $edgeType edges for role $roleId" -Level "Debug"
        
        # Use same recursive logic as SCCM_FullAdministrator but with different RoleID
        foreach ($site in $script:Sites) {
            $connectedSiteIdentifiers = Get-ConnectedSitesRecursive -SiteIdentifier $site.SiteIdentifier
            
            $specificRoles = $script:SecurityRoles | Where-Object {
                $connectedSiteIdentifiers -contains $_.SourceSiteIdentifier -and
                $_.RoleID -eq $roleId -and
                $_.IsBuiltIn -eq $true
            }
            
            foreach ($role in $specificRoles) {
                $adminUsers = Find-AdminUsersConnectedToSecurityRole -SecurityRoleObjectIdentifier $role.ObjectIdentifier
                
                foreach ($admin in $adminUsers) {
                    $collections = Find-CollectionsConnectedToAdminUser -AdminUserObjectIdentifier $admin.ObjectIdentifier
                    
                    foreach ($collection in $collections) {
                        $devices = Find-ClientDevicesConnectedToCollection -CollectionObjectIdentifier $collection.ObjectIdentifier
                        
                        foreach ($device in $devices) {
                            $roleEdge = New-SCCMEdge -SourceNode $admin.ObjectIdentifier -TargetNode $device.SMSID -EdgeType $edgeType
                            $script:Edges += $roleEdge
                            Write-LogMessage "Created $edgeType : $($admin.LogonName) -> $($device.dNSHostName)" -Level "Debug"
                        }
                    }
                }
            }
        }
    }
    
    Write-LogMessage "Role-specific edges created" -Level "Success"
}

function Process-AssignSpecificPermissionsEdges {
    Write-LogMessage "Post-processing: Creating SCCM_AssignSpecificPermissions edges..." -Level "Info"
    
    # Step 1: Identify all SCCM_Site labeled nodes
    foreach ($site in $script:Sites) {
        Write-LogMessage "Processing SCCM_AssignSpecificPermissions for site: $($site.SiteIdentifier)" -Level "Debug"
        
        # Step 2: Get all sites connected via SCCM_SameAdminsAs (recursively)
        $connectedSiteIdentifiers = Get-ConnectedSitesRecursive -SiteIdentifier $site.SiteIdentifier
        
        # Step 3: Find security roles with IsSecAdminRole = True in connected sites
        $secAdminRoles = $script:SecurityRoles | Where-Object {
            $connectedSiteIdentifiers -contains $_.SourceSiteIdentifier -and
            $_.IsSecAdminRole -eq $true
        }
        
        foreach ($role in $secAdminRoles) {
            Write-LogMessage "Processing security admin role: $($role.RoleName)" -Level "Debug"
            
            # Step 4: Find AdminUsers connected to this role via SCCM_IsAssigned edges
            $adminUsers = Find-AdminUsersConnectedToSecurityRole -SecurityRoleObjectIdentifier $role.ObjectIdentifier
            
            foreach ($admin in $adminUsers) {
                Write-LogMessage "Processing admin user: $($admin.LogonName)" -Level "Debug"
                
                # Step 5: Find Collections connected to this AdminUser via SCCM_IsAssigned edges
                $collections = Find-CollectionsConnectedToAdminUser -AdminUserObjectIdentifier $admin.ObjectIdentifier
                
                # Step 6: Check if both "All Systems" and "All Users and User Groups" are assigned
                $hasAllSystems = $collections | Where-Object { $_.Name -eq "All Systems" }
                $hasAllUsers = $collections | Where-Object { $_.Name -eq "All Users and User Groups" }
                
                if ($hasAllSystems -and $hasAllUsers) {
                    # Step 7a: Create SCCM_AssignAllPermissions edge to each site in hierarchy
                    foreach ($connectedSiteId in $connectedSiteIdentifiers) {
                        $connectedSite = $script:Sites | Where-Object { $_.SiteIdentifier -eq $connectedSiteId }
                        if ($connectedSite) {
                            $assignAllEdge = New-SCCMEdge -SourceNode $admin.ObjectIdentifier -TargetNode $connectedSite.SiteIdentifier -EdgeType "SCCM_AssignAllPermissions"
                            $script:Edges += $assignAllEdge
                            Write-LogMessage "Created SCCM_AssignAllPermissions: $($admin.LogonName) -> $($connectedSite.SiteCode)" -Level "Debug"
                        }
                    }
                } else {
                    # Step 7b: Create SCCM_AssignSpecificPermissions edges to client devices
                    # Only if role is not SMS0001R or SMS000FR (already covered by other edges)
                    if ($role.RoleID -ne "SMS0001R" -and $role.RoleID -ne "SMS000FR") {
                        foreach ($collection in $collections) {
                            $devices = Find-ClientDevicesConnectedToCollection -CollectionObjectIdentifier $collection.ObjectIdentifier
                            
                            foreach ($device in $devices) {
                                $assignSpecificEdge = New-SCCMEdge -SourceNode $admin.ObjectIdentifier -TargetNode $device.SMSID -EdgeType "SCCM_AssignSpecificPermissions"
                                $script:Edges += $assignSpecificEdge
                                Write-LogMessage "Created SCCM_AssignSpecificPermissions: $($admin.LogonName) -> $($device.dNSHostName)" -Level "Debug"
                            }
                        }
                    }
                }
            }
        }
    }
    
    Write-LogMessage "SCCM_AssignSpecificPermissions edges created" -Level "Success"
}

#endregion

#region Helper Functions

function Add-DeviceToTargets {
    param(
        [string]$DeviceName,
        [string]$Source
    )
    
    if ([string]::IsNullOrWhiteSpace($DeviceName)) { return $null }
    
    # Try to resolve to AD object to get canonical identifier
    $adObject = Get-ActiveDirectoryObject -Name $DeviceName -Domain $script:Domain
    
    # Use ObjectSID as deduplication key if resolved, otherwise use lowercase name
    if ($adObject -and $adObject.SID) {
        $dedupKey = $adObject.SID
        $canonicalName = if ($adObject.DNSHostName) { $adObject.DNSHostName } else { $adObject.Name }
    } else {
        $dedupKey = $DeviceName.ToLower()
        $canonicalName = $DeviceName
        Write-LogMessage Warning "Could not resolve '$DeviceName' to domain object"
        return $null
    }
    
    # Check if we already have this device
    $existingTarget = $script:CollectionTargets.Values | Where-Object { $_.DedupKey -eq $dedupKey }
    
    if ($existingTarget) {
        # Prefer FQDN: Update hostname if current input is FQDN and existing is not
        if ($DeviceName -contains '.' -and $existingTarget.Hostname -notcontains '.') {
            Write-LogMessage Verbose "Replacing NetBIOS name '$($existingTarget.Hostname)' with FQDN '$DeviceName'"
            $existingTarget.Hostname = $DeviceName
        }
        
        # Add source to existing entry
        if ($existingTarget.Source -notlike "*$Source*") {
            $existingTarget.Source += ", $Source"
        }
        
        # Return existing target
        $existingTarget.IsNew = $false
        return $existingTarget
    } else {
        # Add new target
        $script:CollectionTargets[$canonicalName] = @{
            "ADObject" = if ($adObject) { $adObject } else { $null }
            "Collected" = $false
            "DedupKey" = $dedupKey
            "Hostname" = $canonicalName
            "IsNew" = $true
            "Source" = $Source
        }
        Write-LogMessage Verbose "Added collection target: $canonicalName from $Source"
        
        # Return new target
        return $script:CollectionTargets[$canonicalName]
    }
}

function Get-SameAdminsAsSites {
    param([string]$SiteIdentifier)
    
    $relatedSites = @()
    $site = $script:Sites | Where-Object { $_.SiteIdentifier -eq $SiteIdentifier }
    
    if ($site) {
        # Find all sites with same ParentSiteCode (same hierarchy)
        $hierarchySites = $script:Sites | Where-Object { $_.ParentSiteCode -eq $site.ParentSiteCode }
        $relatedSites += $hierarchySites
        
        # Recursively find sites connected via SCCM_SameAdminsAs edges
        # This is a simplified version - full implementation would need graph traversal
        $relatedSites += $script:Sites | Where-Object { 
            $_.ParentSiteCode -eq $site.SiteCode -or 
            $_.SiteCode -eq $site.ParentSiteCode 
        }
    }
    
    return ($relatedSites | Sort-Object SiteIdentifier -Unique)
}

#endregion

#region Recursive Helper Functions

function Get-ConnectedSitesRecursive {
    param(
        [string]$SiteIdentifier,
        [hashtable]$VisitedSites = @{}
    )
    
    # Avoid infinite recursion
    if ($VisitedSites.ContainsKey($SiteIdentifier)) {
        return @()
    }
    
    $VisitedSites[$SiteIdentifier] = $true
    $connectedSites = @($SiteIdentifier)
    
    # Find all SCCM_SameAdminsAs edges FROM this site
    $outgoingEdges = $script:Edges | Where-Object {
        $_.EdgeType -eq "SCCM_SameAdminsAs" -and 
        $_.SourceNode -eq $SiteIdentifier
    }
    
    # Find all SCCM_SameAdminsAs edges TO this site  
    $incomingEdges = $script:Edges | Where-Object {
        $_.EdgeType -eq "SCCM_SameAdminsAs" -and 
        $_.TargetNode -eq $SiteIdentifier
    }
    
    # Recursively traverse outgoing edges
    foreach ($edge in $outgoingEdges) {
        $connectedSites += Get-ConnectedSitesRecursive -SiteIdentifier $edge.TargetNode -VisitedSites $VisitedSites
    }
    
    # Recursively traverse incoming edges
    foreach ($edge in $incomingEdges) {
        $connectedSites += Get-ConnectedSitesRecursive -SiteIdentifier $edge.SourceNode -VisitedSites $VisitedSites
    }
    
    return ($connectedSites | Sort-Object -Unique)
}

function Find-AdminUsersConnectedToSecurityRole {
    param([string]$SecurityRoleObjectIdentifier)
    
    $connectedAdminUsers = @()
    
    # Find SCCM_IsAssigned edges connecting AdminUsers to this SecurityRole
    $assignmentEdges = $script:Edges | Where-Object {
        $_.EdgeType -eq "SCCM_IsAssigned" -and 
        $_.TargetNode -eq $SecurityRoleObjectIdentifier
    }
    
    foreach ($edge in $assignmentEdges) {
        # Verify the source is an SCCM_AdminUser
        $adminUser = $script:AdminUsers | Where-Object { $_.ObjectIdentifier -eq $edge.SourceNode }
        if ($adminUser) {
            $connectedAdminUsers += $adminUser
        }
    }
    
    return $connectedAdminUsers
}

function Find-CollectionsConnectedToAdminUser {
    param([string]$AdminUserObjectIdentifier)
    
    $connectedCollections = @()
    
    # Find SCCM_IsAssigned edges connecting this AdminUser to Collections
    $assignmentEdges = $script:Edges | Where-Object {
        $_.EdgeType -eq "SCCM_IsAssigned" -and 
        $_.SourceNode -eq $AdminUserObjectIdentifier
    }
    
    foreach ($edge in $assignmentEdges) {
        # Verify the target is an SCCM_Collection
        $collection = $script:Collections | Where-Object { $_.ObjectIdentifier -eq $edge.TargetNode }
        if ($collection) {
            $connectedCollections += $collection
        }
    }
    
    return $connectedCollections
}

function Find-ClientDevicesConnectedToCollection {
    param([string]$CollectionObjectIdentifier)
    
    $connectedDevices = @()
    
    # Find SCCM_HasMember edges connecting this Collection to ClientDevices
    $memberEdges = $script:Edges | Where-Object {
        $_.EdgeType -eq "SCCM_HasMember" -and 
        $_.SourceNode -eq $CollectionObjectIdentifier
    }
    
    foreach ($edge in $memberEdges) {
        # Verify the target is an SCCM_ClientDevice
        $device = $script:ClientDevices | Where-Object { $_.SMSID -eq $edge.TargetNode }
        if ($device) {
            $connectedDevices += $device
        }
    }
    
    return $connectedDevices
}

#endregion

#region Main Processing Function

function Start-IngestAndPostProcessing {
    Write-LogMessage "Starting ingest and post-processing..." -Level "Info"
    
    # INGEST PHASE - Create all nodes and direct edges (no dependencies)
    Process-SitesIngest              # Creates SCCM_SameAdminsAs, AdminTo, HasSession
    Process-ClientDevicesIngest      # Creates SCCM_HasClient, SameHostAs, user relationship edges
    Process-SecurityRolesIngest      # Creates nodes only
    Process-CollectionsIngest        # Creates nodes only  
    Process-AdminUsersIngest         # Creates SCCM_IsMappedTo, SCCM_IsAssigned
    Process-SiteSystemRolesIngest    # Creates additional AdminTo edges
    
    if (-not $SkipPostProcessing) {
        # POST-PROCESSING PHASE - Create edges that depend on other edges
        Process-HasMemberEdges              # Depends on: SCCM_SameAdminsAs
        Process-FullAdministratorEdges      # Depends on: SCCM_IsAssigned + SCCM_HasMember  
        Process-RoleSpecificEdges           # Depends on: SCCM_IsAssigned + SCCM_HasMember
        Process-AssignSpecificPermissionsEdges # Depends on: SCCM_IsAssigned + SCCM_HasMember
    } else {
        Write-LogMessage "Post-processing skipped due to -SkipPostProcessing flag" -Level "Warning"
    }
    Write-LogMessage "Processing completed successfully" -Level "Success"
    Write-LogMessage "Created $($script:Nodes.Count) nodes and $($script:Edges.Count) edges" -Level "Info"
}

#endregion

#region Output Generation

function Export-BloodHoundData {
    Write-LogMessage Info "Writing BloodHound data..."

    # Create BloodHound data file using the Nodes and Edges
    $bloodhoundData = @{
        "graph" = @{
            "metadata" = @{
                "source_kind" = "SCCM_Base"
            }
            "nodes" = @($script:Nodes | ForEach-Object {
                @{
                    id = $_.id
                    kinds = $_.kinds
                    properties = $_.properties
                }
            })
            "edges" = @($script:Edges | ForEach-Object {
                @{
                    start = $_.start
                    kind = $_.kind
                    end = $_.end
                    properties = $_.properties
                }
            })
        }
    }

    $bloodhoundJson = $bloodhoundData | ConvertTo-Json -Depth 10
    if ($OutputFormat -eq "StdOut") {
        Write-Output $bloodhoundJson
        return
    }

    # Set output directory
    if (-not $TempDir) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "ConfigManBearPig-$timestamp"
    }
    
    if (-not (Test-Path $TempDir)) {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    }
    $bloodhoundFile = Join-Path $TempDir "sccm.json"
    $bloodhoundJson | Out-File -FilePath $bloodhoundFile -Encoding UTF8

    $script:OutputFiles += $bloodhoundFile
    
    if ($OutputFormat -eq "Zip") {
        # Create ZIP file
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $zipFileName = "bloodhound-sccm-$timestamp.zip"
        
        if ($ZipDir) {
            $zipPath = Join-Path $ZipDir $zipFileName
        } else {
            $zipPath = Join-Path (Get-Location).Path $zipFileName
        }
        
        try {
            if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
                Compress-Archive -Path $script:OutputFiles -DestinationPath $zipPath -CompressionLevel Optimal
            } else {
                # Fallback for older PowerShell
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::CreateFromDirectory($TempDir, $zipPath)
            }
            
            $fileInfo = Get-Item $zipPath
            Write-LogMessage Success "Created ZIP file: $zipPath"
            Write-LogMessage Info "File size: $([math]::Round($fileInfo.Length/1MB, 2)) MB"
            
        } catch {
            Write-LogMessage Error "Failed to create ZIP file: $_"
        }
    }

    # Cleanup temporary files
    try {
        Remove-Item -Path $TempDir -Recurse -Force
    } catch {
        Write-LogMessage Error "Failed to cleanup temporary directory: $_"
    }
}

#endregion

#region Main Execution Logic

function Start-SCCMCollection {
    Write-LogMessage Info "Initializing SCCM collection..."
    
    # Validate parameters
    if ($ComputerFile -and $SMSProvider) {
        Write-LogMessage Warning "Cannot specify both ComputerFile and SMSProvider"
        return
    }
    
    # Check for required modules
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Write-LogMessage Success "Active Directory module loaded"
            $script:ADModuleAvailable = $true
        } else {
            Write-LogMessage Warning "Active Directory module not available, using .NET fallback"
            try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                Add-Type -AssemblyName System.DirectoryServices
                Write-LogMessage Success "DirectoryServices fallback initialized"
            } catch {
                Write-LogMessage Error "Failed to initialize DirectoryServices fallback: $_"
            }
        }
    } catch {
        Write-LogMessage Error "Failed to load Active Directory module: $_"
    }
    
    # Determine collection strategy based on parameters
    if ($SMSProvider) {
        Write-LogMessage Info "Using SMS Provider mode: $SMSProvider"

        $collectionTarget = Add-DeviceToTargets -DeviceName $SMSProvider -Source "ScriptParameter-SMSProvider"
        
        # Only AdminService and WMI are applicable for SMS Provider mode
        if ($enableAdminService) {
            Invoke-AdminServiceCollection -CollectionTarget $collectionTarget
        }
        
        if ($enableWMI) {
            Invoke-SmsProviderWmiCollection -CollectionTargets $script:CollectionTargets
        }
        
    } elseif ($ComputerFile) {
        Write-LogMessage Info "Using ComputerFile mode: $ComputerFile"
        
        if (-not (Test-Path $ComputerFile)) {
            Write-LogMessage Warning "File not found: $ComputerFile"
            return
        }
        
        # Load targets from file
        $computerTargets = Get-Content $ComputerFile | Where-Object { $_.Trim() -ne "" }
        foreach ($target in $computerTargets) {
            # Add targets and resolve to AD objects
            Add-DeviceToTargets -DeviceName $target -Source "ScriptParameter-ComputerFile"
        }
        
        # Execute enabled methods for ComputerFile mode
        if ($enableRemoteRegistry) {
            Invoke-RemoteRegistryCollection -Targets $script:CollectionTargets
        }
        
        if ($enableAdminService) {
            foreach ($collectionTarget in $script:CollectionTargets) {
                Invoke-AdminServiceCollection -CollectionTarget $collectionTarget
            }
        }
        
        if ($enableHTTP) {
            Invoke-HTTPCollection -Targets $script:CollectionTargets
        }
        
        if ($enableSMB) {
            Invoke-SMBCollection -Targets $script:CollectionTargets
        }
        
    } else {        
        # Phase 1: LDAP - Identify targets in System Management container
        if ($enableLDAP) {
            if ($script:Domain) {
                Invoke-LDAPCollection
            } else {
                Write-LogMessage Warning "No domain specified, skipping LDAP collection"
            }
        }
        
        # Phase 2: Local - Data available when running on SCCM client
        if ($enableLocal) {
            Invoke-LocalCollection
        }
        
        # Phase 3: DNS - Management points published to DNS
        if ($enableDNS) {
            if ($script:Domain) {
                Invoke-DNSCollection
            } else {
                Write-LogMessage Warning "No domain specified, skipping DNS collection"
            }
        }
        
        if ($script:CollectionTargets.Count -eq 0 -and ($enableRemoteRegistry -or $enableAdminService -or $enableWMI -or $enableHTTP -or $enableSMB)) {
            Write-LogMessage Warning "No SCCM targets identified from LDAP/Local/DNS phases. Ensure you have appropriate permissions and are in an SCCM environment."
            return
        }
        
        if ($script:CollectionTargets.Count -gt 0) {
            Write-LogMessage Info "Identified $($script:CollectionTargets.Count) potential SCCM targets"
            
            # Phase 4: Remote Registry - On targets identified in previous phases
            if ($enableRemoteRegistry) {
                Invoke-RemoteRegistryCollection -Targets $script:CollectionTargets
            }
            
            # Phase 5: AdminService - On targets identified in previous phases
            if ($enableAdminService) {
                foreach ($collectionTarget in $script:CollectionTargets) {
                    Invoke-AdminServiceCollection -CollectionTarget $collectionTarget
                }
            }
            
            # Phase 6: WMI - If AdminService collection fails
            if ($enableWMI) {
                $uncollectedTargets = $script:CollectionTargets.Keys | Where-Object { 
                    -not $_.Value["Collected"] 
                }
                if ($uncollectedTargets.Count -gt 0) {
                    Invoke-SmsProviderWmiCollection -CollectionTargets $uncollectedTargets
                }
            }
            
            # Phase 7: HTTP - If AdminService and WMI collections fail
            if ($enableHTTP) {
                $uncollectedTargets = $script:CollectionTargets.GetEnumerator() | Where-Object { 
                    -not $_.Value["Collected"] 
                }
                if ($uncollectedTargets.Count -gt 0) {
                    Invoke-HTTPCollection -Targets $uncollectedTargets
                }
            }
            
            # Phase 8: SMB - If AdminService and WMI collections fail
            if ($enableSMB) {
                $uncollectedTargets = $script:CollectionTargets.GetEnumerator() | Where-Object { 
                    -not $_.Value["Collected"] 
                }
                if ($uncollectedTargets.Count -gt 0) {
                    Invoke-SMBCollection -Targets $uncollectedTargets
                }
            }
        }
    }
    
    # Report collection statistics
    $totalTargets = $script:CollectionTargets.Count
    $collectedTargets = ($script:CollectionTargets.Values | Where-Object { $_.Collected }).Count
    $uncollectedTargets = $totalTargets - $collectedTargets
    
    Write-LogMessage "Collection Statistics:" -Level "Info"
    Write-LogMessage "Total targets identified: $totalTargets" -Level "Info"
    Write-LogMessage "Successfully collected: $collectedTargets" -Level "Success"
    Write-LogMessage "Failed to collect: $uncollectedTargets" -Level "Warning"
    
    # Report collected data statistics
    Write-LogMessage "Data Collection Summary:" -Level "Info"
    Write-LogMessage "Sites: $($script:Sites.Count)" -Level "Info"
    Write-LogMessage "Client Devices: $($script:ClientDevices.Count)" -Level "Info"
    Write-LogMessage "Collections: $($script:Collections.Count)" -Level "Info"
    Write-LogMessage "Security Roles: $($script:SecurityRoles.Count)" -Level "Info"
    Write-LogMessage "Admin Users: $($script:AdminUsers.Count)" -Level "Info"
    Write-LogMessage "Site System Roles: $($script:SiteSystemRoles.Count)" -Level "Info"
    
    # Post-processing and edge creation
    #Invoke-PostProcessing
    
    # Report edge statistics
    Write-LogMessage "Edge Creation Summary:" -Level "Info"
    Write-LogMessage "Total nodes created: $($script:Nodes.Count)" -Level "Info"
    Write-LogMessage "Total edges created: $($script:Edges.Count)" -Level "Info"
    
    # Export data
    Export-BloodHoundData
    
    Write-LogMessage "SCCM collection completed successfully!" -Level "Success"
}

#endregion

#region Error Handling and Validation

function Test-Prerequisites {
    $issues = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 4) {
        $issues += "PowerShell 4.0 or higher is required"
    }
    
    # Check if running in domain context
    if (-not $script:Domain) {
        $issues += "No domain context detected. Specify -Domain parameter or ensure machine is domain-joined"
    }
    
    # Check permissions
    $isAdmin = Test-AdminPrivileges
    if (-not $isAdmin) {
        Write-LogMessage Warning "Not running as administrator. Some collection methods may fail."
    }
    
    # Validate ComputerFile if specified
    if ($ComputerFile -and -not (Test-Path $ComputerFile)) {
        $issues += "ComputerFile not found: $ComputerFile"
    }
    
    # Validate output directories
    if ($TempDir -and -not (Test-Path $TempDir)) {
        try {
            New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
        } catch {
            $issues += "Cannot create TempDir: $TempDir"
        }
    }
    
    if ($ZipDir -and -not (Test-Path $ZipDir)) {
        try {
            New-Item -ItemType Directory -Path $ZipDir -Force | Out-Null
        } catch {
            $issues += "Cannot create ZipDir: $ZipDir"
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-LogMessage Error "Prerequisites check failed:"
        foreach ($issue in $issues) {
            Write-LogMessage Error "- $issue"
        }
        return $false
    }
    
    Write-LogMessage Success "Prerequisites check passed"
    return $true
}

#endregion

#region Script Entry Point

# Main execution
try {
    Write-Host ("=" * 80 ) -ForegroundColor Cyan
    Write-Host "ConfigManBearPig - SCCM Data Collector for BloodHound" -ForegroundColor Cyan
    Write-Host "Version: $script:ScriptVersion" -ForegroundColor Cyan
    Write-Host "Collection Method: $CollectionMethods" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    # Test prerequisites
    if (-not (Test-Prerequisites)) {
        Write-LogMessage Error "Prerequisites check failed. Exiting."
        exit 1
    }
    
    # Start collection
    Start-SCCMCollection
    
} catch {
    Write-LogMessage Error "Critical error during execution: $_"
    Write-LogMessage Error "Stack trace: $($_.Exception.StackTrace)"
    exit 1
} finally {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "ConfigManBearPig execution completed" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

#endregion