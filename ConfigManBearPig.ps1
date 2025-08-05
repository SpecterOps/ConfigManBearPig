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
    - BloodHound (default): OpenGraph implementation, outputs .zip containing .json files
    - JSON: Single JSON file output

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
    
    [string]$OutputFormat = "BloodHound",
    
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
            Write-LogMessage "Unknown collection method: $method" -Level "Error"
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
            Write-LogMessage "Loaded $($script:TargetSiteCodes.Count) site codes from file: $SiteCodes" -Level "Info"
        } catch {
            Write-LogMessage "Failed to read site codes file: $_" -Level "Error"
            return
        }
    } else {
        # Comma-separated string
        $script:TargetSiteCodes = $SiteCodes -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        Write-LogMessage "Targeting site codes: $($script:TargetSiteCodes -join ', ')" -Level "Info"
    }
}

# Global variables
$script:CollectionTargets = @{}
$script:Sites = @()
$script:ClientDevices = @()
$script:ComputerObjects = @()
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
        [hashtable]$Properties
    )
    
    # Check if node already exists and merge properties if it does
    $existingNode = $script:Nodes | Where-Object { $_.id -eq $Id }
    if ($existingNode) {
        # Merge new properties into existing node
        foreach ($key in $Properties.Keys) {
            if ($null -ne $Properties[$key]) {
                $existingNode.properties[$key] = $Properties[$key]
            }
        }
        Write-LogMessage Verbose "Found existing node: $($existingNode.Properties.Name) ($Id)"
    } else {
        # Filter out null properties and create new node
        $cleanProperties = @{}
        foreach ($key in $Properties.Keys) {
            if ($null -ne $Properties[$key]) {
                $cleanProperties[$key] = $Properties[$key]
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
        Create-HostNodeIfNeeded -NodeId $Id -NodeKinds $Kinds -NodeProperties $Properties
    }
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
        @{Source = $ComputerSid; Target = $hostId},      # Computer -> Host
        @{Source = $hostId; Target = $ComputerSid},      # Host -> Computer
        @{Source = $ClientDeviceId; Target = $hostId},   # ClientDevice -> Host
        @{Source = $hostId; Target = $ClientDeviceId}    # Host -> ClientDevice
    )
    
    foreach ($edge in $edgesToCreate) {
        $script:Edges += [PSCustomObject]@{
            start = $edge.Source
            end = $edge.Target
            kind = "SameHostAs"
        }
    }
    
    Write-LogMessage Verbose "Created Host node $hostId and SameHostAs edges for Computer: $ComputerSid"
}

# Helper function to add edges during collection and processing
function Add-Edge {
    param(
        [string]$Source,
        [string]$Target,
        [string]$Kind,
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
        source = $Source
        target = $Target
        kind = $Kind
        properties = $cleanProperties
    }
    
    $script:Edges += $edge
    Write-LogMessage Verbose "Added $Kind edge: $Source -> $Target (edge count: $($script:Edges.Count))"
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
    Write-LogMessage Info "Starting LDAP collection phase..."
    
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
                CollectionSource = "LDAP-mSSMSSite"
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
            }
            
            $sourceForest = $null
            
            # Parse capabilities to determine site relationships and extract SourceForest
            if ($mSSMSManagementPoint.mSSMSCapabilities) {
                try {
                    try {
                        $cleanXml = $mSSMSManagementPoint.mSSMSCapabilities -replace '&(?!amp;|lt;|gt;|quot;|apos;)', '&amp;'
                        [xml]$mSSMSCapabilities = $cleanXml
                    } catch {
                        Write-Warning "Failed to parse capabilities for $($mSSMSManagementPoint.Name): $($_.Exception.Message)"
                        $mSSMSCapabilities = $null
                    }
                    $commandLine = $mSSMSCapabilities.ClientOperationalSettings.CCM.CommandLine
                    $rootSiteCode = $mSSMSCapabilities.ClientOperationalSettings.RootSiteCode
                    $forestElement = $mSSMSCapabilities.ClientOperationalSettings.Forest
                    
                    if ($forestElement) {
                        $sourceForest = $forestElement.Value
                    }
                    
                    # Update existing SCCM_Site node with MP-derived information
                    $existingSiteNode = $script:Nodes | Where-Object { $_.id -eq $mpSiteCode }
                    if ($existingSiteNode) {
                        # Determine site type based on RootSiteCode and CommandLine
                        if ($commandLine -match "SMSSITECODE=([A-Z0-9]{3})" -and $matches[1] -eq $mpSiteCode) {
                            if ($rootSiteCode -and $rootSiteCode -ne $mpSiteCode) {
                                $existingSiteNode.properties.SiteType = 2  # Primary Site
                                $existingSiteNode.properties.ParentSiteCode = $rootSiteCode
                                $existingSiteNode.properties.ParentSiteIdentifier = $rootSiteCode
                                
                                # Create CAS site node if it doesn't exist
                                $existingCAS = $script:Nodes | Where-Object { $_.id -eq $rootSiteCode }

                                if (-not $existingCAS) {
                                    Add-Node -Id $rootSiteCode -Kinds @("SCCM_Site") -Properties @{
                                        CollectionSource = "LDAP-mSSMSManagementPoint"
                                        Name = $rootSiteCode
                                        DistinguishedName = $null
                                        ParentSiteCode = "None"
                                        ParentSiteGUID = $null
                                        ParentSiteIdentifier = $null
                                        SiteCode = $rootSiteCode
                                        SiteGUID = $null
                                        SiteIdentifier = $rootSiteCode
                                        SiteName = $null
                                        SiteServerDomain = $null
                                        SiteServerName = $null
                                        SiteServerObjectIdentifier = $null
                                        SiteType = 4  # Central Administration Site
                                        SourceForest = $sourceForest
                                        SQLDatabaseName = $null
                                        SQLServerName = $null
                                        SQLServerObjectIdentifier = $null
                                        SQLServiceAccount = $null
                                        SQLServiceAccountObjectIdentifier = $null

                                    }
                                }
                            } elseif ($rootSiteCode -eq $mpSiteCode) {
                                # This is either a standalone primary or CAS
                                $existingSiteNode.properties.SiteType = 4  # Assume CAS if RootSiteCode equals SiteCode
                                $existingSiteNode.properties.ParentSiteCode = "None"
                                $existingSiteNode.properties.ParentSiteIdentifier = $null
                            }
                        } else {
                            # Secondary site case - CommandLine SMSSITECODE differs from mSSMSSiteCode
                            $existingSiteNode.properties.SiteType = 1  # Secondary Site
                            if ($commandLine -match "SMSSITECODE=([A-Z0-9]{3})") {
                                $existingSiteNode.properties.ParentSiteCode = $matches[1]
                                $existingSiteNode.properties.ParentSiteIdentifier = $matches[1]
                            }
                        }
                        
                        # Update SourceForest if found
                        if ($sourceForest -and -not $existingSiteNode.properties.SourceForest) {
                            $existingSiteNode.properties.SourceForest = $sourceForest
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
                                
                                # Create Computer node for FSP
                                if ($fspTarget.ADObject) {
                                    Add-Node -Id $fspTarget.ADObject.SID -Kinds @("Computer", "Base") -Properties @{
                                        CollectionSource = "LDAP-mSSMSManagementPoint"
                                        Name = $fspTarget.ADObject.Name
                                        DNSHostName = $fspTarget.ADObject.dNSHostName
                                        Domain =  $fspTarget.ADObject.Domain
                                        SCCM_SiteSystemRoles = @("SMS Fallback Status Point")
                                    }
                                }
                            
                            }
                        }
                    }
                } catch {
                    Write-LogMessage Warning "Failed to parse capabilities for MP $mpHostname`: $_"
                }
            }
            
            # Create Computer node for Management Point
            if ($mpTarget.ADObject) {
                Add-Node -Id $mpTarget.ADObject.SID -Kinds @("Computer", "Base") -Properties @{
                    CollectionSource = "LDAP-mSSMSManagementPoint"
                    Name = $mpTarget.ADObject.Name
                    DNSHostName = $mpTarget.ADObject.dNSHostName
                    Domain = $mpTarget.ADObject.Domain
                    SCCM_SiteSystemRoles = @("SMS Management Point")
                }
            }
        }
        
        # Get computers with CmRcService SPN (possible client devices)
        Write-LogMessage "Collecting computers with Remote Control SPN..." -Level "Info"
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
                Add-Node -Id $system.ObjectSid.Value -Kinds @("Computer", "Base") -Properties @{
                    CollectionSource = "LDAP-CmRcService"
                    Name = $system.Name
                    CN = $system.CN
                    DistinguishedName = $system.DistinguishedName
                    DNSHostnNme = $system.DNSHostName
                    Domain = $system.Domain
                    SCCM_HasClientRemoteControlSPN = $true
                    ServicePrincipalNames = $system.ServicePrincipalName
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

                    # Create Computer node
                    $computerProperties = @{
                        "CollectionSource" = "LDAP-$($server.ObjectClass)"
                        "Name" = $parentObject.DNSHostName
                        "DNSHostName" = $parentObject.DNSHostName
                        "Domain" = $domainName
                        "NetworkBootServer" = $true
                    }
                    
                    Add-Node -Id $parentObject.ObjectSid -Kinds @("Computer", "Base") -Properties $computerProperties
                }
                
            } catch {
                Write-LogMessage Warning "Failed to process network boot server $($server.DistinguishedName): $_"
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
                Write-LogMessage Warning "DirectorySearcher failed for SCCM naming patterns: $_"
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
                
                # Create Computer node
                $computerProperties = @{
                    "CollectionSource" = "LDAP-NamePattern"
                    "Name" = $hostname
                    "DNSHostName" = $hostname
                    "Domain" = $domainName
                    "SAMAccountName" = $match.samaccountname
                }
                
                # Add description if available
                if ($match.description) {
                    $computerProperties["Description"] = $match.description
                }
                
                # Add display name if available and different from hostname
                if ($match.displayname) {
                    $computerProperties["DisplayName"] = $match.displayname
                }
                
                # Process Service Principal Names if available
                if ($match.serviceprincipalname -and $match.serviceprincipalname.Count -gt 0) {
                    $spnList = @()
                    foreach ($spn in $match.serviceprincipalname) {
                        $spnList += $spn
                    }
                    $computerProperties["ServicePrincipalNames"] = $spnList
                }
                
                Add-Node -Id $objectSid -Kinds @("Computer", "Base") -Properties $computerProperties
                
            } else {
                Write-LogMessage Warning "Skipping pattern match - missing required properties (SID or hostname): $($match.name)"
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
                                $computerProperties = @{
                                    "CollectionSource" = "LDAP-GenericAllSystemManagement"
                                    "Name" = if ($adObject.DNSHostName) { $adObject.DNSHostName } else { $adObject.Name }
                                    "DNSHostName" = if ($adObject.DNSHostName) { $adObject.DNSHostName } else { $null }
                                    "Domain" = $domainName
                                    "SAMAccountName" = $adObject.SamAccountName
                                    "DistinguishedName" = $adObject.DistinguishedName
                                }
                                
                                if ($adObject.Enabled -ne $null) {
                                    $computerProperties["Enabled"] = $adObject.Enabled
                                }
                                
                                Add-Node -Id $adObject.SID -Kinds @("Computer", "Base") -Properties $computerProperties
                                
                                # Add to collection targets for subsequent collection phases
                                if ($adObject.DNSHostName) {
                                    $null = Add-DeviceToTargets -DeviceName $adObject.DNSHostName -Source "LDAP-GenericAll"
                                } else {
                                    Write-LogMessage Warning "Cannot add computer $($adObject.Name) to targets - no FQDN available"
                                }
                            }
                            
                            "User" {
                                $userProperties = @{
                                    "CollectionSource" = "LDAP-GenericAllSystemManagement"
                                    "Name" = $adObject.Name
                                    "Domain" = $domainName
                                    "SAMAccountName" = $adObject.SamAccountName
                                    "DistinguishedName" = $adObject.DistinguishedName
                                    "UserPrincipalName" = $adObject.UserPrincipalName
                                }
                                
                                if ($adObject.Enabled -ne $null) {
                                    $userProperties["Enabled"] = $adObject.Enabled
                                }
                                
                                Add-Node -Id $adObject.SID -Kinds @("User", "Base") -Properties $userProperties
                            }
                            
                            "Group" {
                                $groupProperties = @{
                                    "CollectionSource" = "LDAP-GenericAllSystemManagement"
                                    "Name" = $adObject.Name
                                    "Domain" = $domainName
                                    "SAMAccountName" = $adObject.SamAccountName
                                    "DistinguishedName" = $adObject.DistinguishedName
                                }
                                
                                Add-Node -Id $adObject.SID -Kinds @("Group", "Base") -Properties $groupProperties
                            }
                            
                            default {
                                # Handle unknown object types
                                $genericProperties = @{
                                    "CollectionSource" = "LDAP-GenericAllSystemManagement"
                                    "Name" = $adObject.Name
                                    "Domain" = $domainName
                                    "SAMAccountName" = $adObject.SamAccountName
                                    "DistinguishedName" = $adObject.DistinguishedName
                                }
                                
                                Add-Node -Id $adObject.SID -Kinds @($adObject.Type, "Base") -Properties $genericProperties
                                Write-LogMessage Verbose "Created node for unknown object type '$($adObject.Type)': $($adObject.Name)"
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
                                        # Same Computer logic as above...
                                        $computerProperties = @{
                                            "CollectionSource" = "LDAP-GenericAllSystemManagement"
                                            "Name" = if ($adObject.DNSHostName) { $adObject.DNSHostName } else { $adObject.Name }
                                            "DNSHostName" = if ($adObject.DNSHostName) { $adObject.DNSHostName } else { $null }
                                            "Domain" = $domainName
                                            "SAMAccountName" = $adObject.SamAccountName
                                            "DistinguishedName" = $adObject.DistinguishedName
                                        }
                                        
                                        if ($adObject.Enabled -ne $null) {
                                            $computerProperties["Enabled"] = $adObject.Enabled
                                        }
                                        
                                        Add-Node -Id $adObject.SID -Kinds @("Computer", "Base") -Properties $computerProperties
                                        
                                        if ($adObject.DNSHostName) {
                                            $null = Add-DeviceToTargets -DeviceName $adObject.DNSHostName -Source "LDAP-GenericAll"
                                        }
                                    }
                                    
                                    "User" {
                                        # Same User logic as above...
                                        $userProperties = @{
                                            "CollectionSource" = "LDAP-GenericAllSystemManagement"
                                            "Name" = $adObject.Name
                                            "Domain" = $domainName
                                            "SAMAccountName" = $adObject.SamAccountName
                                            "DistinguishedName" = $adObject.DistinguishedName
                                            "UserPrincipalName" = $adObject.UserPrincipalName
                                        }
                                        
                                        if ($adObject.Enabled -ne $null) {
                                            $userProperties["Enabled"] = $adObject.Enabled
                                        }
                                        
                                        Add-Node -Id $adObject.SID -Kinds @("User", "Base") -Properties $userProperties
                                    }
                                    
                                    "Group" {
                                        # Same Group logic as above...
                                        $groupProperties = @{
                                            "CollectionSource" = "LDAP-GenericAllSystemManagement"
                                            "Name" = $adObject.Name
                                            "Domain" = $domainName
                                            "SAMAccountName" = $adObject.SamAccountName
                                            "DistinguishedName" = $adObject.DistinguishedName
                                        }
                                        
                                        Add-Node -Id $adObject.SID -Kinds @("Group", "Base") -Properties $groupProperties
                                    }
                                }
                            } else {
                                Write-LogMessage Warning "Could not resolve principal '$accountName' to domain object"
                            }
                        }
                    }
                    $directoryEntry.Dispose()
                } catch {
                    Write-LogMessage Warning "DirectoryServices ACL check failed: $_"
                }
            }
        } catch {
            Write-LogMessage Warning "Failed to check System Management container permissions: $_"
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
    Write-LogMessage "Starting Local collection phase..." -Level "Info"
    
    try {
        # Check if running on SCCM client by testing WMI namespaces
        $ccmNamespaceExists = $false
        try {
            Get-WmiObject -Namespace "root\CCM" -Class "__Namespace" -ErrorAction Stop | Out-Null
            $ccmNamespaceExists = $true
        } catch {
            Write-LogMessage "SCCM client WMI namespace not detected on local machine" -Level "Warning"
            return
        }
        
        if (-not $ccmNamespaceExists) {
            Write-LogMessage "SCCM client not detected on local machine" -Level "Warning"
            return
        }
        
        Write-LogMessage "SCCM client detected on local machine" -Level "Success"
        
        # Get current management point and site code from SMS_Authority
        Write-LogMessage "Querying SMS_Authority for current management point and site code..." -Level "Info"
        $smsAuthority = Get-WmiObject -Namespace "root\CCM" -Class "SMS_Authority" -Property CurrentManagementPoint, Name -ErrorAction SilentlyContinue
        
        $siteCode = $null
        $currentMP = $null
        
        if ($smsAuthority) {
            $currentMP = $smsAuthority.CurrentManagementPoint
            # Extract site code from Name property (format: "SMS:PS1")
            if ($smsAuthority.Name -match "SMS:([A-Z0-9]{3})") {
                $siteCode = $matches[1]
                Write-LogMessage "Found site code from SMS_Authority: $siteCode" -Level "Info"
                Write-LogMessage "Current management point: $currentMP" -Level "Info"
            }
        }
        
        # Create or update Site object if site code found
        if ($siteCode) {
            $existingSite = $script:Sites | Where-Object { $_.SiteCode -eq $siteCode }
            if (-not $existingSite) {
                $siteNode = @{
                    "ObjectIdentifier" = $siteCode
                    "DistinguishedName" = $null
                    "Name" = $null
                    "SiteCode" = $siteCode
                    "SiteName" = $null
                    "SiteServerDomain" = $null
                    "SiteServerName" = $null
                    "SiteServerObjectIdentifier" = $null
                    "SQLDatabaseName" = $null
                    "SQLServerName" = $null
                    "SQLServerObjectIdentifier" = $null
                    "SQLServiceAccount" = $null
                    "SQLServiceAccountObjectIdentifier" = $null
                    "SiteType" = 2  # Primary (clients can only be joined to primary sites)
                    "SiteGUID" = $null
                    "SiteIdentifier" = $siteCode
                    "ParentSiteCode" = $null
                    "ParentSiteGUID" = $null
                    "ParentSiteIdentifier" = $null
                    "SourceForest" = $null
                    "Properties" = @{}
                    "Source" = "Local-SMS_Authority"
                }
                
                $script:Sites += $siteNode
                Write-LogMessage "Created site from local client: $siteCode" -Level "Success"
            } else {
                # Update existing site with local data
                $existingSite.SiteType = 2  # Confirm it's a primary site
                if (-not $existingSite.Source) { $existingSite.Source = "Local-SMS_Authority" }
                Write-LogMessage "Updated existing site with local data: $siteCode" -Level "Info"
            }
        }
        
        # Get additional management points from SMS_LookupMP
        Write-LogMessage "Querying SMS_LookupMP for additional management points..." -Level "Info"
        $lookupMPs = Get-WmiObject -Namespace "root\CCM" -Class "SMS_LookupMP" -Property Name -ErrorAction SilentlyContinue
        
        $allManagementPoints = @()
        if ($currentMP) { $allManagementPoints += $currentMP }
        
        foreach ($mp in $lookupMPs) {
            if ($mp.Name -and $mp.Name -notin $allManagementPoints) {
                $allManagementPoints += $mp.Name
                Write-LogMessage "Found additional management point: $($mp.Name)" -Level "Info"
            }
        }
        
        # Add management points to collection targets and site system roles
        foreach ($mpHostname in $allManagementPoints) {
            if ($mpHostname) {
                # Add to collection targets for subsequent phases
                $mp = Add-DeviceToTargets -DeviceName $mpHostname -Source "Local-SMS_LookupMP"
                if ($mp -and $mp.IsNew) {
                    Write-LogMessage "Added management point to collection targets: $mpHostname" -Level "Info"
                }
                
                $mpSid = $mp.ObjectIdentifier
                
                # Add to SiteSystemRoles
                $existingSystemRole = $script:SiteSystemRoles | Where-Object { 
                    $_.Hostname -eq $mpHostname -and $_.SiteCode -eq $siteCode 
                }
                if (-not $existingSystemRole) {
                    $systemNode = @{
                        "ObjectIdentifier" = if ($mpSid) { $mpSid } else { "$mpHostname@$siteCode" }
                        "dNSHostName" = $mpHostname
                        "Hostname" = $mpHostname
                        "NetworkOSPath" = "\\$mpHostname"
                        "SiteCode" = $siteCode
                        "Roles" = @(@{
                            "Name" = "SMS Management Point"
                            "Properties" = @{}
                            "SiteCode" = $siteCode
                            "SiteIdentifier" = $siteCode
                            "SourceForest" = $null
                        })
                        "Source" = "Local-SMS_LookupMP"
                    }
                    $script:SiteSystemRoles += $systemNode
                    Write-LogMessage "Added management point to site system roles: $mpHostname" -Level "Info"
                } else {
                    # Add role if not already present
                    $mpRole = $existingSystemRole.Roles | Where-Object { $_.Name -eq "SMS Management Point" }
                    if (-not $mpRole) {
                        $existingSystemRole.Roles += @{
                            "Name" = "SMS Management Point"
                            "Properties" = @{}
                            "SiteCode" = $siteCode
                            "SiteIdentifier" = $siteCode
                            "SourceForest" = $null
                        }
                        Write-LogMessage "Updated existing system role for: $mpHostname" -Level "Info"
                    }
                }
            }
        }
        
        # Get client settings from CCM_Client
        Write-LogMessage "Querying CCM_Client for client information..." -Level "Info"
        $ccmClient = Get-WmiObject -Namespace "root\CCM" -Class "CCM_Client" -ErrorAction SilentlyContinue
        
        $clientId = $null
        $clientIdChangeDate = $null
        $previousClientId = $null
        
        if ($ccmClient) {
            $clientId = $ccmClient.ClientId
            $clientIdChangeDate = $ccmClient.ClientIdChangeDate
            $previousClientId = $ccmClient.PreviousClientId
            
            Write-LogMessage "Found client ID (SMSID): $clientId" -Level "Info"
            Write-LogMessage "Client ID change date: $clientIdChangeDate" -Level "Info"
        }
        
        # Create ClientDevice object for the local machine
        if ($siteCode -and $clientId) {
            # Get local computer information
            $computerSystem = Get-WmiObject -Class "Win32_ComputerSystem" -ErrorAction SilentlyContinue
            $computerName = $env:COMPUTERNAME
            $domainName = $env:USERDNSDOMAIN
            $fqdn = if ($domainName) { "$computerName.$domainName" } else { $computerName }
            
            # Try to get AD computer object for SID and DN using our resolution function
            $computerObject = Resolve-DomainPrincipalSID -PrincipalName $computerName -Domain $script:Domain
            $computerSid = $computerObject.SID
            $computerDN = $computerObject.DistinguishedName
            
            # Resolve current management point SID
            $currentMPSid = $null
            if ($currentMP) {
                $mpObject = Get-ActiveDirectoryObject -Name $currentMP -Domain $script:Domain
                $currentMPSid = $mpObject.SID
            }
            
            # Check if client device already exists (using SMSID as identifier)
            $existingClient = $script:ClientDevices | Where-Object { 
                $_.SMSID -eq $clientId 
            }
            
            if (-not $existingClient) {
                $clientDevice = @{
                    "ObjectIdentifier" = $clientId  # Use SMSID as ObjectIdentifier (Primary Key)
                    "AADDeviceID" = $null
                    "AADTenantID" = $null
                    "ADDomainSID" = $computerSid
                    "ADLastLogonTime" = $null
                    "ADLastLogonUser" = $null
                    "ADLastLogonUserDomain" = $null
                    "ADLastLogonUserSID" = $null
                    "CoManaged" = $null
                    "CurrentLogonUser" = $null
                    "CurrentLogonUserSID" = $null
                    "CurrentManagementPoint" = $currentMP
                    "CurrentManagementPointSID" = $currentMPSid
                    "DeviceOS" = $null
                    "DeviceOSBuild" = $null
                    "DistinguishedName" = $computerDN
                    "dNSHostName" = $fqdn
                    "IsVirtualMachine" = $null
                    "LastActiveTime" = $null
                    "LastOfflineTime" = $null
                    "LastOnlineTime" = $null
                    "LastReportedMPServerName" = $null
                    "LastReportedMPServerSID" = $currentMPSid
                    "PrimaryUser" = $null
                    "PrimaryUserSID" = $null
                    "ResourceID" = $null  # Not available from local collection
                    "SiteCode" = $siteCode
                    "SiteGUID" = $null
                    "SiteIdentifier" = $siteCode
                    "SMSID" = $clientId
                    "Name" = $computerName
                    "Domain" = $domainName
                    "SystemRoles" = $null
                    "ADSiteName" = $null
                    "PrimaryUserName" = $null
                    "PrimaryUserDomain" = $null
                    "Source" = "Local-CCM_Client"
                }
                
                $script:ClientDevices += $clientDevice
                Write-LogMessage "Created local client device with SMSID: $clientId" -Level "Success"
            } else {
                # Update existing client with local data
                $existingClient.CurrentManagementPoint = $currentMP
                $existingClient.CurrentManagementPointSID = $currentMPSid
                $existingClient.LastReportedMPServerSID = $currentMPSid
                $existingClient.dNSHostName = $fqdn
                $existingClient.DistinguishedName = $computerDN
                $existingClient.Name = $computerName
                $existingClient.Domain = $domainName
                if ($computerSid) { $existingClient.ADDomainSID = $computerSid }
                Write-LogMessage "Updated existing client device with SMSID: $clientId" -Level "Info"
            }
        }
        
        # Search SCCM client log data for UNC paths and URLs that are likely to be SCCM components
        Write-LogMessage "Searching SCCM client logs for additional SCCM components..." -Level "Info"
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
                                                            Write-LogMessage "Host resolved to non-RFC1918 IP address: $hostname ($($ip.IPAddressToString))"  -Level Debug
                                                        }
                                                    }
                                                }
                                            } catch {
                                                # DNS resolution failed
                                                Write-LogMessage "Failed to resolve hostname $hostname from UNC path: $_" -Level "Debug"
                                            }
                                            
                                            # Only add if resolves to RFC1918 private IP
                                            if ($shouldAdd) {
                                                $uncPaths += $uncPath
                                                
                                                # Add unique hostnames to additional components
                                                if (-not $additionalComponents.ContainsKey($hostname)) {
                                                    Write-LogMessage "Found host: $hostname ($($ip.IPAddressToString))" -Level Success

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
                                    Write-LogMessage "Found URL: $fullUrl" -Level Debug
                                    
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
                                                            Write-LogMessage "Host resolved to non-RFC1918 IP address: $hostname ($($ip.IPAddressToString))"  -Level Debug
                                                        }
                                                    }
                                                }
                                            } catch {
                                                # DNS resolution failed
                                                Write-LogMessage "Failed to resolve hostname $hostname from URL: $_" -Level "Debug"
                                            }
                                            
                                            # Only add if resolves to RFC1918 private IP
                                            if ($shouldAdd) {

                                                # Add unique hostnames to additional components
                                                if (-not $additionalComponents.ContainsKey($hostname)) {
                                                    Write-LogMessage "Found host: $hostname ($($ip.IPAddressToString))" -Level Success

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
                            Write-LogMessage "Failed to search log file $($logFile.FullName): $_" -Level "Warning"
                        }
                    }
                }
            }
            
            # Add discovered components to collection targets
            foreach ($component in $additionalComponents.Values) {
                $hostname = $component.Hostname
                $compTarget = Add-DeviceToTargets -DeviceName $hostname -Source $component.Source
                if ($compTarget -and $compTarget.IsNew) {
                    Write-LogMessage "Discovered potential SCCM component from logs: $hostname" -Level "Info"
                }
            }
            
            if ($additionalComponents.Count -gt 0) {
                Write-LogMessage "Discovered $($additionalComponents.Count) potential SCCM components from client logs" -Level "Success"
                foreach ($component in $additionalComponents.Values) {
                    $pathCount = $component.UNCPaths.Count
                    $urlCount = $component.URLs.Count
                    Write-LogMessage "- $($component.Hostname) (found $pathCount UNC paths, $urlCount URLs)" -Level "Info"
                }
            } else {
                Write-LogMessage "No additional SCCM components discovered from client logs" -Level "Info"
            }
            
        } catch {
            Write-LogMessage "Failed to search client logs: $_" -Level "Error"
        }
        
        # Report what was collected
        Write-LogMessage "Local collection completed" -Level "Success"
        if ($siteCode) {
            Write-LogMessage "Site code: $siteCode" -Level "Info"
        }
        Write-LogMessage "Management points found: $($allManagementPoints.Count)" -Level "Info"
        Write-LogMessage "Client device created/updated: $(if ($clientId) { '1' } else { '0' })" -Level "Info"
        Write-LogMessage "Site system roles total: $($script:SiteSystemRoles.Count)" -Level "Info"
        
    } catch {
        Write-LogMessage "Local collection failed: $_" -Level "Error"
    }
}

#endregion

#region DNS Collection

function Invoke-DNSCollection {
    Write-LogMessage "Starting DNS collection phase..." -Level "Info"
    
    try {
        if (-not $script:Domain) {
            Write-LogMessage "No domain specified for DNS collection" -Level "Warning"
            return
        }
        
        # Collect site codes from previous phases and user-specified targets
        $siteCodesForDNS = @()
        
        # Add site codes from LDAP/Local collection
        foreach ($site in $script:Sites) {
            if ($site.SiteCode -and $siteCodesForDNS -notcontains $site.SiteCode) {
                $siteCodesForDNS += $site.SiteCode
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
            Write-LogMessage "No site codes available for DNS collection. Use -SiteCodes parameter or run LDAP/Local collection first." -Level "Warning"
            return
        }
        
        Write-LogMessage "Performing DNS collection for site codes: $($siteCodesForDNS -join ', ')" -Level "Info"
        
        # Try ADIDNS dump approach first (if available)
        $adidnsRecords = @()
        try {
            Write-LogMessage "Attempting ADIDNS SRV record enumeration..." -Level "Info"
            
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
                        Write-LogMessage "Querying SRV record: $srvName" -Level "Info"
                        $records = Resolve-DnsName -Name $srvName -Type SRV -DnsOnly -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        if ($records) {
                            $sccmSrvRecords += $records
                            Write-LogMessage "Found $($records.Count) SRV records for $srvName" -Level "Success"
                        }
                    } catch {
                        Write-LogMessage "Failed to query SRV record $srvName`: $_" -Level "Warning"
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
                                Write-LogMessage "ADIDNS: Found management point $managementPointFQDN for site $siteCodeFromDNS" -Level "Success"
                            } else {
                                Write-LogMessage "ADIDNS: Failed to resolve $managementPointFQDN to AD object" -Level "Warning"
                            }
                        } catch {
                            Write-LogMessage "ADIDNS: Error resolving $managementPointFQDN`: $_" -Level "Warning"
                        }
                    }
                }
            } catch {
                Write-LogMessage "ADIDNS enumeration failed: $_" -Level "Warning"
            }
        } catch {
            Write-LogMessage "ADIDNS collection failed: $_" -Level "Warning"
        }
        
        # Targeted DNS queries for each site code
        $dnsDiscoveredMPs = @()
        foreach ($siteCode in $siteCodesForDNS) {
            try {
                $srvRecordName = "_mssms_mp_$($siteCode.ToLower())._tcp.$script:Domain"
                Write-LogMessage "Querying DNS for: $srvRecordName" -Level "Info"
                
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
                                    Write-LogMessage "Failed to resolve IP for $managementPointFQDN`: $_" -Level "Warning"
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
                                        Write-LogMessage "Failed to parse IP address $ip" -Level "Warning"
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
                                    Write-LogMessage "DNS: Found management point $managementPointFQDN for site $siteCode" -Level "Success"
                                } else {
                                    Write-LogMessage "DNS: Skipping $managementPointFQDN (not in RFC-1918 space)" -Level "Info"
                                }
                            } else {
                                Write-LogMessage "DNS: Failed to resolve $managementPointFQDN to AD object" -Level "Warning"
                            }
                        } catch {
                            Write-LogMessage "DNS: Error resolving $managementPointFQDN`: $_" -Level "Warning"
                        }
                    }
                }
            } catch {
                Write-LogMessage "Failed to query DNS for site $siteCode`: $_" -Level "Warning"
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
                Write-LogMessage Success "DNS: Found management point $fqdn for site $siteCode"
            }
            
            # Create site system role entry
            $siteSystemRole = @{
                "dNSHostName" = $fqdn
                "ObjectIdentifier" = $adObject.SID
                "Roles" = @(
                    @{
                        "Name" = "SMS Management Point"
                        "SiteCode" = $siteCode
                        "SiteIdentifier" = $siteCode
                    }
                )
                "Source" = "DNS"
                "ADObject" = $adObject
            }
            
            $script:SiteSystemRoles += $siteSystemRole
        }
        
        # Report what was collected
        Write-LogMessage "DNS collection completed" -Level "Success"
        Write-LogMessage "Management points found via ADIDNS: $($adidnsRecords.Count)" -Level "Info"
        Write-LogMessage "Management points found via targeted DNS: $($dnsDiscoveredMPs.Count)" -Level "Info"
        Write-LogMessage "Total unique management points: $($allDiscoveredMPs.Count)" -Level "Info"        
    } catch {
        Write-LogMessage "DNS collection failed: $_" -Level "Error"
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
            Write-LogMessage "Warning: Job cleanup failed for $Target" -Level "Warning"
        }
    }
}
function Invoke-RemoteRegistryCollection {
    param([string[]]$Targets)
    
    Write-LogMessage "Starting Remote Registry collection phase..." -Level "Info"
    
    if (-not $Targets -or $Targets.Count -eq 0) {
        Write-LogMessage "No targets provided for Remote Registry collection" -Level "Warning"
        return
    }
    
    # Initialize arrays to track session data
    if (-not $script:SessionData) { $script:SessionData = @() }
    
    foreach ($target in $Targets) {
        try {
            Write-LogMessage "Attempting Remote Registry collection on: $target" -Level "Info"
            
            $regConnectionSuccessful = $false
            $siteCode = $null
            $componentServers = @()
            $siteServers = @()
            $sqlServers = @()
            $targetADObject = $null
            
            # Resolve target to AD object
            try {
                $targetADObject = Get-ActiveDirectoryObject -Name $target -Domain $script:Domain
                if ($targetADObject) {
                    Write-LogMessage "Resolved target $target to AD object: $($targetADObject.Name)" -Level "Success"
                } else {
                    Write-LogMessage "Failed to resolve target $target to AD object" -Level "Warning"
                }
            } catch {
                Write-LogMessage "Error resolving target $target to AD object: $_" -Level "Warning"
            }
            
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
                Write-LogMessage "Remote Registry connection timed out for $target after $timeoutSeconds seconds" -Level "Warning"
                Remove-TimedOutJob $j1 $target
            }

            if (-not $connectionSuccess) {
                Write-LogMessage "Remote Registry connection failed for $target" -Level "Warning"
                continue
            }
            
            Write-LogMessage "Remote Registry connection successful: $target" -Level "Success"
            $regConnectionSuccessful = $true
            
            # Query 1: Get site code from Triggers subkey - Job 2
            $triggersCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $triggersKey = $reg.OpenSubKey("SOFTWARE\Microsoft\SMS\Triggers")
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
                Write-LogMessage "Triggers registry query timed out for $target" -Level "Warning"
                Remove-TimedOutJob $j2 $target
            }
            
            if ($triggersResult -and $triggersResult.Count -eq 1) {
                $siteCode = $triggersResult
                Write-LogMessage "Found site code from triggers: $siteCode" -Level "Success"
            } elseif ($triggersResult -and $triggersResult.Count -gt 1) {
                Write-LogMessage "Multiple site codes found under triggers key on $target`: $($triggersResult -join ', ')" -Level "Warning"
                $siteCode = $triggersResult[0] # Use first one
            } else {
                Write-LogMessage "No site code found in triggers on $target" -Level "Info"
            }
            
            # Query 2: Get component servers - Job 3
            $componentCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $componentKey = $reg.OpenSubKey("SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers")
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
                Write-LogMessage "Component servers registry query timed out for $target" -Level "Warning"
                Remove-TimedOutJob $j3 $target
            }

            # Process component servers
            if ($componentResult) {
                foreach ($componentServerFQDN in $componentResult) {
                    $collectionTarget = Add-DeviceToTargets -DeviceName $componentServerFQDN -Source "RemoteRegistry-ComponentServer"
                    if ($collectionTarget -and $collectionTarget.IsNew){
                        Write-LogMessage "Found component server: $componentServerFQDN" -Level "Success"

                        $componentServers += @{
                            "FQDN" = $componentServerFQDN
                            "ObjectIdentifier" = $collectionTarget.ObjectIdentifier
                            "SiteCode" = $siteCode
                        }
                    }
                }
            }
            
            # Query 3: Get site database servers - Job 4
            $multisiteCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $multisiteKey = $reg.OpenSubKey("SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers")
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
                Write-LogMessage "Multisite servers registry query timed out for $target" -Level "Warning"
                Remove-TimedOutJob $j4 $target
            }
            
            # Process SQL servers
            if ($multisiteResult -ne $null -and $multisiteResult.Count -eq 0) {
                # Site database is local to the site server
                Write-LogMessage "Site database is local to the site server: $target" -Level "Info"
                if ($targetADObject) {
                    $sqlServers += @{
                        "FQDN" = $target
                        "ObjectIdentifier" = $targetADObject.SID
                        "SiteCode" = $siteCode
                        "Type" = "Local"
                    }
                }
            } elseif ($multisiteResult.Count -eq 1) {
                # Single site database server
                $sqlServerFQDN = $multisiteResult
                $collectionTarget = Add-DeviceToTargets -DeviceName $sqlServerFQDN -Source "RemoteRegistry-MultisiteComponentServers"
                if ($collectionTarget -and $collectionTarget.IsNew){
                    Write-LogMessage "Found site database server: $sqlServerFQDN" -Level "Success"

                    $sqlServers += @{
                        "FQDN" = $componentServerFQDN
                        "ObjectIdentifier" = $collectionTarget.ObjectIdentifier
                        "SiteCode" = $siteCode
                        "Type" = "Remote"
                    }
                }

            } elseif ($multisiteResult.Count -gt 1) {
                # Multiple SQL servers (clustered)
                Write-LogMessage "Found clustered site database servers: $($multisiteResult -join ', ')" -Level "Success"
                foreach ($sqlServerFQDN in $multisiteResult) {

                    $collectionTarget = Add-DeviceToTargets -DeviceName $sqlServerFQDN -Source "RemoteRegistry-MultisiteComponentServers"
                    if ($collectionTarget -and $collectionTarget.IsNew){
                        Write-LogMessage "Found site database server: $sqlServerFQDN" -Level "Success"
    
                        $sqlServers += @{
                            "FQDN" = $componentServerFQDN
                            "ObjectIdentifier" = $collectionTarget.ObjectIdentifier
                            "SiteCode" = $siteCode
                            "Type" = "Clustered"
                        }
                    }
                }
            }
            
            # Query 4: Get current user SID(s) - Job 5
            $currentUserCode = {
                param($target)
                try {
                    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                    $currentUserKey = $reg.OpenSubKey("SOFTWARE\Microsoft\SMS\CurrentUser")
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
                Write-LogMessage "Current user registry query timed out for $target" -Level "Warning"
                Remove-TimedOutJob $j5 $target
            }
            
            # Process current user SIDs
            $sid = $null
            if ($currentUserResult -and $currentUserResult.Count -eq 0) {
                Write-LogMessage "No values found in CurrentUser subkey on $target" -Level "Info"
            } elseif ($currentUserResult -and $currentUserResult.Count -eq 2) {
                $sid = $currentUserResult.Values | Select-Object -Index 1
                Write-LogMessage "Found CurrentUser $sid on $target" -Level "Success"
                # Resolve SID to AD object
                try {
                    $userADObject = Get-ActiveDirectoryObject -Sid $sid -Domain $script:Domain
                    if ($userADObject) {
                        $currentUserSids += @{
                            "SID" = $sid
                            "ADObject" = $userADObject
                        }
                        Write-LogMessage "Resolved current user SID $sid to: $($userADObject.Name)" -Level "Success"
                        
                        # Create session data entry for HasSession edge
                        $sessionData = @{
                            "ComputerName" = $target
                            "ComputerADObject" = $targetADObject
                            "UserSID" = $sid
                            "UserADObject" = $userADObject
                            "SessionType" = "CurrentUser"
                            "Source" = "RemoteRegistry"
                            "SiteCode" = $siteCode
                        }
                        $script:SessionData += $sessionData
                    } else {
                        Write-LogMessage "Failed to resolve current user SID $sid" -Level "Warning"
                    }
                } catch {
                    Write-LogMessage "Error resolving current user SID $sid`: $_" -Level "Warning"
                }
            }
            
            # Create SiteSystem entries based on collected data
            if ($regConnectionSuccessful) {
                # Mark target as collected
                $script:CollectionTargets[$target]["SiteCode"] = $siteCode
                $script:CollectionTargets[$target]["ObjectIdentifier"] = $targetADObject.SID
                
                # If any of the registry keys existed, this is a site server
                if ($siteCode -or $componentServers.Count -gt 0 -or $sqlServers.Count -gt 0) {
                    $siteSystemRole = @{
                        "dNSHostName" = $target
                        "ObjectIdentifier" = if ($targetADObject) { $targetADObject.SID } else { $null }
                        "Roles" = @(
                            @{
                                "Name" = "SMS Site Server"
                                "Properties" = @{}
                                "SiteCode" = $siteCode
                                "SiteIdentifier" = $siteCode
                                "SourceForest" = $null
                            }
                        )
                        "Source" = "RemoteRegistry"
                        "ADObject" = $targetADObject
                    }
                    $script:SiteSystemRoles += $siteSystemRole
                    Write-LogMessage "Created site server role for: $target" -Level "Success"
                }
                
                # Create SiteSystem entries for component servers
                foreach ($componentServer in $componentServers) {
                    $siteSystemRole = @{
                        "dNSHostName" = $componentServer.FQDN
                        "ObjectIdentifier" = $componentServer.ObjectIdentifier
                        "Roles" = @(
                            @{
                                "Name" = "SMS Component Server"
                                "Properties" = @{}
                                "SiteCode" = $componentServer.SiteCode
                                "SiteIdentifier" = $componentServer.SiteCode
                                "SourceForest" = $null
                            }
                        )
                        "Source" = "RemoteRegistry"
                    }
                    $script:SiteSystemRoles += $siteSystemRole
                }
                
                # Create SiteSystem entries for SQL servers
                foreach ($sqlServer in $sqlServers) {
                    $siteSystemRole = @{
                        "dNSHostName" = $sqlServer.FQDN
                        "ObjectIdentifier" = if ($sqlServer.ADObject) { $sqlServer.ADObject.SID } else { $null }
                        "Roles" = @(
                            @{
                                "Name" = "SMS SQL Server"
                                "Properties" = @{}
                                "SiteCode" = $sqlServer.SiteCode
                                "SiteIdentifier" = $sqlServer.SiteCode
                                "SourceForest" = $null
                            }
                        )
                        "Source" = "RemoteRegistry"
                        "ADObject" = $sqlServer.ADObject
                    }
                    $script:SiteSystemRoles += $siteSystemRole
                }
                
                Write-LogMessage "Remote Registry collection completed for $target" -Level "Success"
                Write-LogMessage "Site code: $siteCode" -Level "Info"
                Write-LogMessage "Component servers found: $($componentServers.Count)" -Level "Info"
                Write-LogMessage "SQL servers found: $($sqlServers.Count)" -Level "Info"
                Write-LogMessage "Current user: $sid" -Level "Info"
            }
        } catch {
            Write-LogMessage "Remote Registry collection failed for $target`: $_" -Level "Warning"
        }
    }
    
    Write-LogMessage "Remote Registry collection phase completed" -Level "Success"
    Write-LogMessage "Total session data entries: $($script:SessionData.Count)" -Level "Info"
    Write-LogMessage "Total site system roles from registry: $(($script:SiteSystemRoles | Where-Object { $_.Source -eq 'RemoteRegistry' }).Count)" -Level "Info"
}

#endregion

#region AdminService Collection

function Invoke-AdminServiceCollection {
    param(
        [string]$Target,
        [string]$SiteCode = $null
    )
    
    Write-LogMessage "Attempting AdminService collection on: $Target" -Level "Info"
    
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
    param([string[]]$Targets)
    
    Write-LogMessage "Starting SMS Provider WMI collection phase..." -Level "Info"
    
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
    
    Write-LogMessage "SMS Provider WMI collection phase completed" -Level "Success"
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
    param([string[]]$Targets)
    
    Write-LogMessage "Starting HTTP collection phase..." -Level "Info"
    
    if (-not $Targets -or $Targets.Count -eq 0) {
        Write-LogMessage "No targets provided for HTTP collection" -Level "Warning"
        return
    }
    
    foreach ($target in $Targets) {
        try {
            Write-LogMessage "Attempting HTTP collection on: $target" -Level "Info"
            
            # Skip if already collected successfully
            if ($script:CollectionTargets[$target]["Collected"]) {
                Write-LogMessage "Target $target already collected, skipping HTTP" -Level "Info"
                continue
            }
            
            $httpSuccessful = $false
            
            # Test Management Point HTTP endpoints (try HTTP first, then HTTPS)
            $protocols = @("http", "https")
            
            foreach ($protocol in $protocols) {
                try {
                    # Management Point .sms_aut endpoints
                    $mpEndpoints = @(
                        "$protocol`://$target/SMS_MP/.sms_aut?MPLIST",
                        "$protocol`://$target/SMS_MP/.sms_aut?MPKEYINFORMATION"
                    )
                    
                    foreach ($endpoint in $mpEndpoints) {
                        try {
                            Write-LogMessage "Testing Management Point endpoint: $endpoint" -Level "Info"
                            
                            $response = Invoke-WebRequest -Uri $endpoint -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
                            
                            if ($response.StatusCode -eq 200 -and $response.Content) {
                                Write-LogMessage "Management Point endpoint accessible: $endpoint" -Level "Success"
                                $httpSuccessful = $true
                                
                                # Parse MPLIST response for management points
                                if ($endpoint -like "*MPLIST*") {
                                    try {
                                        $xmlContent = [xml]$response.Content
                                        $mpList = $xmlContent.MPList
                                        
                                        if ($mpList -and $mpList.MP) {
                                            foreach ($mp in $mpList.MP) {
                                                $mpFQDN = $mp.FQDN
                                                $mpName = $mp.Name
                                                
                                                if ($mpFQDN) {
                                                    Write-LogMessage "Found Management Point via HTTP MPLIST: $mpFQDN" -Level "Success"
                                                    
                                                    # Resolve MP FQDN to AD object
                                                    try {
                                                        $mpADObject = Get-ActiveDirectoryObject -Name $mpFQDN -Domain $script:Domain
                                                        
                                                        # Create site system role for discovered MP
                                                        $siteSystemRole = @{
                                                            "dNSHostName" = $mpFQDN
                                                            "ObjectIdentifier" = if ($mpADObject) { $mpADObject.SID } else { $null }
                                                            "Roles" = @(
                                                                @{
                                                                    "Name" = "SMS Management Point"
                                                                    "Properties" = @{}
                                                                    "SiteCode" = $null  # Site code not available from MPLIST
                                                                    "SiteIdentifier" = $null
                                                                    "SourceForest" = $null
                                                                }
                                                            )
                                                            "Source" = "HTTP-MPLIST"
                                                            "ADObject" = $mpADObject
                                                        }
                                                        
                                                        $script:SiteSystemRoles += $siteSystemRole
                                                        
                                                        # Add to targets for subsequent collection phases
                                                        if (-not $script:CollectionTargets.ContainsKey($mpFQDN)) {
                                                            $script:CollectionTargets[$mpFQDN] = @{
                                                                "Source" = "HTTP-MPLIST"
                                                                "Hostname" = $mpFQDN
                                                                "Collected" = $false
                                                                "ADObject" = $mpADObject
                                                            }
                                                        }
                                                    } catch {
                                                        Write-LogMessage "Failed to resolve MP FQDN $mpFQDN`: $_" -Level "Warning"
                                                    }
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-LogMessage "Failed to parse MPLIST XML response: $_" -Level "Warning"
                                    }
                                }
                                
                                # Parse MPKEYINFORMATION response
                                if ($endpoint -like "*MPKEYINFORMATION*") {
                                    try {
                                        $xmlContent = [xml]$response.Content
                                        $mpKeyInfo = $xmlContent.MPKEYINFORMATION
                                        
                                        if ($mpKeyInfo) {
                                            $mpFQDN = $mpKeyInfo.FQDN
                                            $machineName = $mpKeyInfo.MACHINENAME
                                            
                                            if ($mpFQDN) {
                                                Write-LogMessage "Found Management Point via HTTP MPKEYINFORMATION: $mpFQDN" -Level "Success"
                                                
                                                # Resolve MP FQDN to AD object
                                                try {
                                                    $mpADObject = Get-ActiveDirectoryObject -Name $mpFQDN -Domain $script:Domain
                                                    
                                                    # Create site system role for discovered MP
                                                    $siteSystemRole = @{
                                                        "dNSHostName" = $mpFQDN
                                                        "ObjectIdentifier" = if ($mpADObject) { $mpADObject.SID } else { $null }
                                                        "Roles" = @(
                                                            @{
                                                                "Name" = "SMS Management Point"
                                                                "Properties" = @{}
                                                                "SiteCode" = $null  # Site code not available from MPKEYINFORMATION
                                                                "SiteIdentifier" = $null
                                                                "SourceForest" = $null
                                                            }
                                                        )
                                                        "Source" = "HTTP-MPKEYINFORMATION"
                                                        "ADObject" = $mpADObject
                                                    }
                                                    
                                                    $script:SiteSystemRoles += $siteSystemRole
                                                    
                                                    # Add to targets for subsequent collection phases
                                                    if (-not $script:CollectionTargets.ContainsKey($mpFQDN)) {
                                                        $script:CollectionTargets[$mpFQDN] = @{
                                                            "Source" = "HTTP-MPKEYINFORMATION"
                                                            "Hostname" = $mpFQDN
                                                            "Collected" = $false
                                                            "ADObject" = $mpADObject
                                                        }
                                                    }
                                                } catch {
                                                    Write-LogMessage "Failed to resolve MP FQDN $mpFQDN`: $_" -Level "Warning"
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-LogMessage "Failed to parse MPKEYINFORMATION XML response: $_" -Level "Warning"
                                    }
                                }
                            }
                        } catch {
                            # Endpoint not accessible, continue
                            Write-LogMessage "Management Point endpoint not accessible: $endpoint" -Level "Info"
                        }
                    }
                    
                    # Test Distribution Point HTTP endpoints
                    $dpEndpoints = @(
                        "$protocol`://$target/sms_dp_smspkg$"
                    )
                    
                    foreach ($endpoint in $dpEndpoints) {
                        try {
                            Write-LogMessage "Testing Distribution Point endpoint: $endpoint" -Level "Info"
                            
                            $response = Invoke-WebRequest -Uri $endpoint -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
                            
                            # Any response (including 401 auth required) indicates DP presence
                            Write-LogMessage "Distribution Point endpoint exists: $endpoint" -Level "Success"
                            $httpSuccessful = $true
                            
                            # Resolve target to AD object
                            try {
                                $targetADObject = Get-ActiveDirectoryObject -Name $target -Domain $script:Domain
                                
                                # Create site system role for discovered DP
                                $siteSystemRole = @{
                                    "dNSHostName" = $target
                                    "ObjectIdentifier" = if ($targetADObject) { $targetADObject.SID } else { $null }
                                    "Roles" = @(
                                        @{
                                            "Name" = "SMS Distribution Point"
                                            "Properties" = @{}
                                            "SiteCode" = $null  # Site code not available from HTTP endpoint
                                            "SiteIdentifier" = $null
                                            "SourceForest" = $null
                                        }
                                    )
                                    "Source" = "HTTP-DistributionPoint"
                                    "ADObject" = $targetADObject
                                }
                                
                                $script:SiteSystemRoles += $siteSystemRole
                                Write-LogMessage "Added Distribution Point role via HTTP: $target" -Level "Success"
                            } catch {
                                Write-LogMessage "Failed to resolve DP hostname $target`: $_" -Level "Warning"
                            }
                            
                        } catch [System.Net.WebException] {
                            # Check if it's a 401 (auth required) which still indicates DP presence
                            if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 401) {
                                Write-LogMessage "Distribution Point endpoint requires authentication (401): $endpoint" -Level "Success"
                                $httpSuccessful = $true
                                
                                # Resolve target to AD object
                                try {
                                    $targetADObject = Get-ActiveDirectoryObject -Name $target -Domain $script:Domain
                                    
                                    # Create site system role for discovered DP
                                    $siteSystemRole = @{
                                        "dNSHostName" = $target
                                        "ObjectIdentifier" = if ($targetADObject) { $targetADObject.SID } else { $null }
                                        "Roles" = @(
                                            @{
                                                "Name" = "SMS Distribution Point"
                                                "Properties" = @{}
                                                "SiteCode" = $null  # Site code not available from HTTP endpoint
                                                "SiteIdentifier" = $null
                                                "SourceForest" = $null
                                            }
                                        )
                                        "Source" = "HTTP-DistributionPoint-401"
                                        "ADObject" = $targetADObject
                                    }
                                    
                                    $script:SiteSystemRoles += $siteSystemRole
                                    Write-LogMessage "Added Distribution Point role via HTTP 401: $target" -Level "Success"
                                } catch {
                                    Write-LogMessage "Failed to resolve DP hostname $target`: $_" -Level "Warning"
                                }
                            } else {
                                Write-LogMessage "Distribution Point endpoint not accessible: $endpoint" -Level "Info"
                            }
                        } catch {
                            Write-LogMessage "Distribution Point endpoint not accessible: $endpoint" -Level "Info"
                        }
                    }
                    
                } catch {
                    Write-LogMessage "HTTP collection failed for protocol $protocol on $target`: $_" -Level "Warning"
                }
            }
            
            # Mark as collected if any HTTP endpoint was accessible
            if ($httpSuccessful) {
                $script:CollectionTargets[$target]["Method"] = "HTTP"
                Write-LogMessage "HTTP collection successful on $target" -Level "Success"
            } else {
                Write-LogMessage "HTTP collection failed on $target (no accessible endpoints)" -Level "Warning"
            }
            
        } catch {
            Write-LogMessage "HTTP collection failed for $target`: $_" -Level "Warning"
        }
    }
    
    Write-LogMessage "HTTP collection phase completed" -Level "Success"
}

#endregion

#region SMB Collection

function Invoke-SMBCollection {
    param([string[]]$Targets)
    
    Write-LogMessage "Starting SMB collection phase..." -Level "Info"
    
    if (-not $Targets -or $Targets.Count -eq 0) {
        Write-LogMessage "No targets provided for SMB collection" -Level "Warning"
        return
    }
    
    foreach ($target in $Targets) {
        try {
            Write-LogMessage "Attempting SMB collection on: $target" -Level "Info"
            
            # Skip if already collected successfully
            if ($script:CollectionTargets[$target]["Collected"]) {
                Write-LogMessage "Target $target already collected, skipping SMB" -Level "Info"
                continue
            }
            
            $smbSuccessful = $false
            $discoveredRoles = @()
            $siteCode = $null
            
            # Resolve target to AD object first
            $targetADObject = $null
            try {
                $targetADObject = Get-ActiveDirectoryObject -Name $target -Domain $script:Domain
            } catch {
                Write-LogMessage "Failed to resolve target $target to AD object: $_" -Level "Warning"
            }
            
            # Check for SCCM-specific SMB shares using net view
            try {
                Write-LogMessage "Enumerating SMB shares on: $target" -Level "Info"
                
                # Use net view to enumerate shares
                $netViewOutput = & net view "\\$target" /all 2>$null
                
                if ($LASTEXITCODE -eq 0 -and $netViewOutput) {
                    Write-LogMessage "Successfully enumerated SMB shares on $target" -Level "Success"
                    $smbSuccessful = $true
                    
                    # Parse net view output for SCCM-specific shares
                    foreach ($line in $netViewOutput) {
                        $line = $line.Trim()
                        
                        # Distribution Point shares
                        if ($line -match "^SMS_DP\$\s+Disk\s+(.*)") {
                            $comment = $matches[1]
                            Write-LogMessage "Found SMS_DP$ share: $comment" -Level "Success"
                            
                            # Extract site code from comment (format: "SMS Site <SITECODE> DP")
                            if ($comment -match "SMS Site (\w{3}) DP") {
                                $siteCode = $matches[1]
                                Write-LogMessage "Extracted site code from SMS_DP$ share: $siteCode" -Level "Success"
                            }
                            
                            $discoveredRoles += @{
                                "Name" = "SMS Distribution Point"
                                "Properties" = @{
                                    "IsPXESupportEnabled" = $false  # Will be updated if REMINST found
                                }
                                "SiteCode" = $siteCode
                                "SiteIdentifier" = $siteCode
                                "SourceForest" = $null
                            }
                        }
                        
                        # REMINST share indicates PXE support
                        if ($line -match "^REMINST\s+Disk") {
                            Write-LogMessage "Found REMINST share - PXE support enabled" -Level "Success"
                            
                            # Update existing DP role or create new one
                            $dpRole = $discoveredRoles | Where-Object { $_.Name -eq "SMS Distribution Point" }
                            if ($dpRole) {
                                $dpRole.Properties.IsPXESupportEnabled = $true
                            } else {
                                $discoveredRoles += @{
                                    "Name" = "SMS Distribution Point"
                                    "Properties" = @{
                                        "IsPXESupportEnabled" = $true
                                    }
                                    "SiteCode" = $siteCode
                                    "SiteIdentifier" = $siteCode
                                    "SourceForest" = $null
                                }
                            }
                        }
                        
                        # Additional DP-related shares
                        if ($line -match "^(SMSPKGC\$|SMSSIG\$|SCCMContentLib\$)\s+Disk\s+(.*)") {
                            $shareName = $matches[1]
                            $comment = $matches[2]
                            Write-LogMessage "Found DP-related share: $shareName - $comment" -Level "Success"
                            
                            # Extract site code if not already found
                            if (-not $siteCode -and $comment -match "site (\w{3})") {
                                $siteCode = $matches[1]
                                Write-LogMessage "Extracted site code from $shareName share: $siteCode" -Level "Success"
                            }
                        }
                        
                        # Site Server shares
                        if ($line -match "^SMS_SITE\s+Disk\s+(.*)") {
                            $comment = $matches[1]
                            Write-LogMessage "Found SMS_SITE share: $comment" -Level "Success"
                            
                            # Extract site code from comment (format: "SMS Site <SITECODE>")
                            if ($comment -match "SMS Site (\w{3})") {
                                $siteCode = $matches[1]
                                Write-LogMessage "Extracted site code from SMS_SITE share: $siteCode" -Level "Success"
                            }
                            
                            $discoveredRoles += @{
                                "Name" = "SMS Site Server"
                                "Properties" = @{}
                                "SiteCode" = $siteCode
                                "SiteIdentifier" = $siteCode
                                "SourceForest" = $null
                            }
                        }
                        
                        # Site-specific shares (SMS_<SITECODE>)
                        if ($line -match "^SMS_(\w{3})\s+Disk\s+(.*)") {
                            $shareCode = $matches[1]
                            $comment = $matches[2]
                            Write-LogMessage "Found site-specific share SMS_$shareCode`: $comment" -Level "Success"
                            
                            if (-not $siteCode) {
                                $siteCode = $shareCode
                                Write-LogMessage "Extracted site code from SMS_$shareCode share: $siteCode" -Level "Success"
                            }
                            
                            # Ensure Site Server role is added
                            $siteServerRole = $discoveredRoles | Where-Object { $_.Name -eq "SMS Site Server" }
                            if (-not $siteServerRole) {
                                $discoveredRoles += @{
                                    "Name" = "SMS Site Server"
                                    "Properties" = @{}
                                    "SiteCode" = $siteCode
                                    "SiteIdentifier" = $siteCode
                                    "SourceForest" = $null
                                }
                            }
                        }
                        
                        # Additional component-related shares
                        if ($line -match "^SMS_CPSC\$\s+Disk") {
                            Write-LogMessage "Found SMS_CPSC$ share - SMS Compressed Package Storage" -Level "Success"
                        }
                    }
                    
                    # Create site if discovered and doesn't exist
                    if ($siteCode) {
                        $existingSite = $script:Sites | Where-Object { $_.SiteCode -eq $siteCode }
                        if (-not $existingSite) {
                            $siteNode = @{
                                "DistinguishedName" = $null
                                "Name" = $null
                                "ParentSiteCode" = $null
                                "ParentSiteIdentifier" = $null
                                "SiteCode" = $siteCode
                                "SiteGUID" = $null
                                "SiteIdentifier" = $siteCode
                                "SiteServerDomain" = $null
                                "SiteServerName" = $null
                                "SiteType" = "Unknown"
                                "SQLDatabaseName" = $null
                                "SQLServerName" = $null
                                "Source" = "SMB-ShareComment"
                            }
                            $script:Sites += $siteNode
                            Write-LogMessage "Created site from SMB share comment: $siteCode" -Level "Success"
                        }
                    }
                    
                    # Create site system role entry if any roles were discovered
                    if ($discoveredRoles.Count -gt 0) {
                        $siteSystemRole = @{
                            "dNSHostName" = $target
                            "ObjectIdentifier" = if ($targetADObject) { $targetADObject.SID } else { $null }
                            "Roles" = $discoveredRoles
                            "Source" = "SMB"
                            "ADObject" = $targetADObject
                        }
                        
                        $script:SiteSystemRoles += $siteSystemRole
                        Write-LogMessage "Added site system roles via SMB: $target ($($discoveredRoles.Count) roles)" -Level "Success"
                    }
                } else {
                    Write-LogMessage "Failed to enumerate SMB shares on $target (access denied or not accessible)" -Level "Warning"
                }
            } catch {
                Write-LogMessage "SMB enumeration failed for $target`: $_" -Level "Warning"
            }
            
            # Additional SMB checks - try to access specific shares directly
            $directShareChecks = @(
                @{ "Share" = "SMS_SITE"; "Role" = "SMS Site Server" },
                @{ "Share" = "SMS_DP$"; "Role" = "SMS Distribution Point" },
                @{ "Share" = "SMSPKGC$"; "Role" = "SMS Distribution Point" }
            )
            
            foreach ($shareCheck in $directShareChecks) {
                try {
                    $sharePath = "\\$target\$($shareCheck.Share)"
                    $shareTest = Test-Path $sharePath -ErrorAction Stop
                    
                    if ($shareTest) {
                        Write-LogMessage "Direct share access successful: $sharePath" -Level "Success"
                        $smbSuccessful = $true
                        
                        # If we haven't already discovered this role through net view, add it
                        $existingRole = $discoveredRoles | Where-Object { $_.Name -eq $shareCheck.Role }
                        if (-not $existingRole) {
                            $newRole = @{
                                "Name" = $shareCheck.Role
                                "Properties" = @{}
                                "SiteCode" = $siteCode
                                "SiteIdentifier" = $siteCode
                                "SourceForest" = $null
                            }
                            
                            # Create site system role if we don't already have one for this target
                            $existingSiteSystem = $script:SiteSystemRoles | Where-Object { 
                                $_.dNSHostName -eq $target -and $_.Source -eq "SMB" 
                            }
                            
                            if ($existingSiteSystem) {
                                $existingSiteSystem.Roles += $newRole
                            } else {
                                $siteSystemRole = @{
                                    "dNSHostName" = $target
                                    "ObjectIdentifier" = if ($targetADObject) { $targetADObject.SID } else { $null }
                                    "Roles" = @($newRole)
                                    "Source" = "SMB-DirectAccess"
                                    "ADObject" = $targetADObject
                                }
                                
                                $script:SiteSystemRoles += $siteSystemRole
                            }
                            
                            Write-LogMessage "Added role via direct SMB share access: $($shareCheck.Role)" -Level "Success"
                        }
                    }
                } catch {
                    # Share not accessible, continue
                }
            }
            
            # Mark as collected if any SMB operation was successful
            if ($smbSuccessful) {
                $script:CollectionTargets[$target]["Method"] = "SMB"
                if ($siteCode) {
                    $script:CollectionTargets[$target]["SiteCode"] = $siteCode
                }
                Write-LogMessage "SMB collection successful on $target" -Level "Success"
            } else {
                Write-LogMessage "SMB collection failed on $target (no accessible shares)" -Level "Warning"
            }
            
        } catch {
            Write-LogMessage "SMB collection failed for $target`: $_" -Level "Warning"
        }
    }
    
    Write-LogMessage "SMB collection phase completed" -Level "Success"
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
                "SCCM_SiteSystemRoles" = @("SMS Site Server.$($site.SiteIdentifier)")
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
        # PREFER FQDN: Update hostname if current input is FQDN and existing is not
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
    Write-LogMessage "Exporting BloodHound data..." -Level "Info"
    
    if ($OutputFormat -eq "BloodHound") {
        Export-BloodHoundZip
    } else {
        Export-SingleJSON
    }

    # Set output directory
    if (-not $TempDir) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "ConfigManBearPig-$timestamp"
    }
    
    if (-not (Test-Path $TempDir)) {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    }
    
    # Create SCCM data file (keep this for compatibility)
    $sccmData = @{
        "Sites" = $script:Sites
        "ClientDevices" = $script:ClientDevices
        "Collections" = $script:Collections
        "SecurityRoles" = $script:SecurityRoles
        "AdminUsers" = $script:AdminUsers
        "SiteSystemRoles" = $script:SiteSystemRoles
    }
    
    $sccmFile = Join-Path $TempDir "sccm.json"
    $sccmData | ConvertTo-Json -Depth 10 | Out-File -FilePath $sccmFile -Encoding UTF8
    $script:OutputFiles += $sccmFile
    
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
                    start = $_.source
                    end = $_.target
                    kind = $_.kind
                    properties = $_.properties
                }
            })
        }
    }
    
    $bloodhoundFile = Join-Path $TempDir "bloodhound.json"
    $bloodhoundData | ConvertTo-Json -Depth 10 | Out-File -FilePath $bloodhoundFile -Encoding UTF8
    $script:OutputFiles += $bloodhoundFile
    
    # Create ZIP file
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $zipFileName = "sccm-bloodhound-$timestamp.zip"
    
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
        Write-LogMessage "Created ZIP file: $zipPath" -Level "Success"
        Write-LogMessage "File size: $([math]::Round($fileInfo.Length/1MB, 2)) MB" -Level "Info"
        
    } catch {
        Write-LogMessage "Failed to create ZIP file: $_" -Level "Error"
    }
    
    # Cleanup temporary files
    try {
        Remove-Item -Path $TempDir -Recurse -Force
    } catch {
        Write-LogMessage "Failed to cleanup temporary directory: $_" -Level "Warning"
    }
}

function Export-SingleJSON {
    $outputData = @{
        "sccm_data" = @{
            "Sites" = $script:Sites
            "ClientDevices" = $script:ClientDevices
            "Collections" = $script:Collections
            "SecurityRoles" = $script:SecurityRoles
            "AdminUsers" = $script:AdminUsers
            "SiteSystemRoles" = $script:SiteSystemRoles
        }
        "bloodhound_data" = @{
            "nodes" = $script:Nodes
            "edges" = $script:Edges
        }
        "meta" = @{
            "type" = "sccm"
            "version" = $script:ScriptVersion
            "collected" = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $jsonFileName = "sccm-bloodhound-$timestamp.json"
    $jsonPath = Join-Path (Get-Location).Path $jsonFileName
    
    $outputData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    $fileInfo = Get-Item $jsonPath
    Write-LogMessage "Created JSON file: $jsonPath" -Level "Success"
    Write-LogMessage "File size: $([math]::Round($fileInfo.Length/1MB, 2)) MB" -Level "Info"
}

#endregion

#region Main Execution Logic

function Start-SCCMCollection {
    Write-LogMessage "Initializing SCCM collection..." -Level "Info"
    
    # Validate parameters
    if ($ComputerFile -and $SMSProvider) {
        Write-LogMessage "Cannot specify both ComputerFile and SMSProvider" -Level "Error"
        return
    }
    
    # Check for required modules
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Write-LogMessage "Active Directory module loaded" -Level "Success"
            $script:ADModuleAvailable = $true
        } else {
            Write-LogMessage "Active Directory module not available, using .NET fallback" -Level "Warning"
            try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                Add-Type -AssemblyName System.DirectoryServices
                Write-LogMessage "DirectoryServices fallback initialized" -Level "Success"
            } catch {
                Write-LogMessage "Failed to initialize DirectoryServices fallback: $_" -Level "Error"
            }
        }
    } catch {
        Write-LogMessage "Failed to load Active Directory module: $_" -Level "Warning"
    }
    
    # Determine collection strategy based on parameters
    if ($SMSProvider) {
        Write-LogMessage "Using SMS Provider mode: $SMSProvider" -Level "Info"
        
        # Add SMS Provider to targets
        $script:CollectionTargets[$SMSProvider] = @{
            "Source" = "ScriptParameter-SMSProvider"
            "Hostname" = $SMSProvider
            "Collected" = $false
            "IsSMSProvider" = $true
        }
        
        # Only AdminService and WMI are applicable for SMS Provider mode
        if ($enableAdminService) {
            Write-LogMessage "Executing AdminService collection on SMS Provider" -Level "Info"
            Invoke-AdminServiceCollection -Target $SMSProvider
        }
        
        if ($enableWMI) {
            Write-LogMessage "Executing WMI collection on SMS Provider" -Level "Info"
            Invoke-SmsProviderWmiCollection -Targets @($SMSProvider)
        }
        
    } elseif ($ComputerFile) {
        Write-LogMessage "Using ComputerFile mode: $ComputerFile" -Level "Info"
        
        if (-not (Test-Path $ComputerFile)) {
            Write-LogMessage "ComputerFile not found: $ComputerFile" -Level "Error"
            return
        }
        
        # Load targets from file
        $computerTargets = Get-Content $ComputerFile | Where-Object { $_.Trim() -ne "" }
        foreach ($target in $computerTargets) {
            $script:CollectionTargets[$target] = @{
                "Source" = "ScriptParameter-ComputerFile"
                "Hostname" = $target
                "Collected" = $false
            }
        }
        
        # Execute enabled methods for ComputerFile mode
        if ($enableRemoteRegistry) {
            Write-LogMessage "Executing Remote Registry collection" -Level "Info"
            Invoke-RemoteRegistryCollection -Targets $computerTargets
        }
        
        if ($enableAdminService) {
            Write-LogMessage "Executing AdminService collection" -Level "Info"
            foreach ($computerTarget in $computerTargets) {
                Invoke-AdminServiceCollection -Target $computerTarget
            }
        }
        
        if ($enableHTTP) {
            Write-LogMessage "Executing HTTP collection" -Level "Info"
            Invoke-HTTPCollection -Targets $computerTargets
        }
        
        if ($enableSMB) {
            Write-LogMessage "Executing SMB collection" -Level "Info"
            Invoke-SMBCollection -Targets $computerTargets
        }
        
    } else {        
        # Phase 1: LDAP - Identify targets in System Management container
        if ($enableLDAP) {
            if ($script:Domain) {
                Invoke-LDAPCollection
            } else {
                Write-LogMessage "No domain specified, skipping LDAP collection" -Level "Warning"
            }
        }
        
        # Phase 2: Local - Data available when running on SCCM client
        if ($enableLocal) {
            Write-LogMessage "Executing Local collection phase" -Level "Info"
            Invoke-LocalCollection
        }
        
        # Phase 3: DNS - Management points published to DNS
        if ($enableDNS) {
            Write-LogMessage "Executing DNS collection phase" -Level "Info"
            if ($script:Domain) {
                Invoke-DNSCollection
            } else {
                Write-LogMessage "No domain specified, skipping DNS collection" -Level "Warning"
            }
        }
        
        # Get list of targets identified so far for subsequent phases
        $identifiedTargets = $script:CollectionTargets.Keys | Where-Object { 
            -not $script:CollectionTargets[$_]["Collected"] 
        }
        
        if ($identifiedTargets.Count -eq 0 -and ($enableRemoteRegistry -or $enableAdminService -or $enableWMI -or $enableHTTP -or $enableSMB)) {
            Write-LogMessage "No SCCM targets identified from LDAP/Local/DNS phases. Ensure you have appropriate permissions and are in an SCCM environment." -Level "Warning"
            return
        }
        
        if ($identifiedTargets.Count -gt 0) {
            Write-LogMessage "Identified $($identifiedTargets.Count) potential SCCM targets" -Level "Info"
            
            # Phase 4: Remote Registry - On targets identified in previous phases
            if ($enableRemoteRegistry) {
                Write-LogMessage "Executing Remote Registry collection phase" -Level "Info"
                Invoke-RemoteRegistryCollection -Targets $identifiedTargets
            }
            
            # Phase 5: AdminService - On targets identified in previous phases
            if ($enableAdminService) {
                Write-LogMessage "Executing AdminService collection phase" -Level "Info"
                foreach ($identifiedTarget in $identifiedTargets) {
                    Invoke-AdminServiceCollection -Target $identifiedTarget
                }
            }
            
            # Phase 6: WMI - If AdminService collection fails
            if ($enableWMI) {
                Write-LogMessage "Executing WMI collection phase" -Level "Info"
                $uncollectedTargets = $script:CollectionTargets.Keys | Where-Object { 
                    -not $script:CollectionTargets[$_]["Collected"] 
                }
                if ($uncollectedTargets.Count -gt 0) {
                    Invoke-SmsProviderWmiCollection -Targets $uncollectedTargets
                }
            }
            
            # Phase 7: HTTP - If AdminService and WMI collections fail
            if ($enableHTTP) {
                Write-LogMessage "Executing HTTP collection phase" -Level "Info"
                $uncollectedTargets = $script:CollectionTargets.Keys | Where-Object { 
                    -not $script:CollectionTargets[$_]["Collected"] 
                }
                if ($uncollectedTargets.Count -gt 0) {
                    Invoke-HTTPCollection -Targets $uncollectedTargets
                }
            }
            
            # Phase 8: SMB - If AdminService and WMI collections fail
            if ($enableSMB) {
                Write-LogMessage "Executing SMB collection phase" -Level "Info"
                $uncollectedTargets = $script:CollectionTargets.Keys | Where-Object { 
                    -not $script:CollectionTargets[$_]["Collected"] 
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
    Invoke-PostProcessing
    
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
        Write-LogMessage "Not running as administrator. Some collection methods may fail." -Level "Warning"
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
        Write-LogMessage "Prerequisites check failed:" -Level "Error"
        foreach ($issue in $issues) {
            Write-LogMessage "- $issue" -Level "Error"
        }
        return $false
    }
    
    Write-LogMessage "Prerequisites check passed" -Level "Success"
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
        Write-LogMessage "Prerequisites check failed. Exiting." -Level "Error"
        exit 1
    }
    
    # Start collection
    Start-SCCMCollection
    
} catch {
    Write-LogMessage "Critical error during execution: $_" -Level "Error"
    Write-LogMessage "Stack trace: $($_.Exception.StackTrace)" -Level "Error"
    exit 1
} finally {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "ConfigManBearPig execution completed" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

#endregion