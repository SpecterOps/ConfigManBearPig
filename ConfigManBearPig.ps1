<#
.SYNOPSIS
ConfigManBearPig: PowerShell collector for adding SCCM attack paths to BloodHound with OpenGraph

.DESCRIPTION
Author: Chris Thompson (@_Mayyhem) at SpecterOps

Purpose:
    Collects BloodHound OpenGraph compatible SCCM data following these ordered steps:
    1.  LDAP (identify sites, site servers, fallback status points, and management points in System Management container)
    2.  Local (identify management points and distribution points in logs when running this script on an SCCM client)
    3.  DNS (identify management points published to DNS)
    4.  *DHCP (identify PXE-enabled distribution points)
    5.  Remote Registry (identify site servers, site databases, and current users on targets)
    6.  MSSQL (check database servers for Extended Protection for Authentication)
    7.  AdminService (collect information from SMS Providers with privileges to query site information)
    8.  *WMI (if AdminService collection fails)
    9.  HTTP (identify management points and distribution points via exposed web services)
    10. SMB (identify site servers and distribution points via file shares)
      
System Requirements:
    - PowerShell 4.0 or higher
    - Active Directory domain context with line of sight to a domain controller
    - Various permissions based on collection methods used

Limitations:
    - You MUST include the 'MSSQL' collection method to remotely identify EPA settings on site database servers with any domain user (or 'RemoteRegistry' to collect from the registry with admin privileges on the system hosting the database).
    - SCCM hierarchies don't have their own unique identifier, so the site code for the site that data is collected from is used in the identifier for objects (e.g., SMS00001@PS1), preventing merging of objects if there are more than one hierarchy in the same graph database (e.g., both hierarchies will have the SMS00001 collection but different members), but causing duplicate objects if collecting from two sites within the same hierarchy.
    - If the same site code exists more than once in the environment (Microsoft recommends against this, so it shouldn't), the nodes and edges for those sites will be merged, causing false positives in the graph. This is not recommended within the same forest: https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/prepare-to-install-sites#bkmk_sitecodes
    - It is assumed in some cases (e.g., during DP and SMS Provider collection) that a single system does not host site system roles in more than one site. If this is the case, only one site code will be associated with that system.
    - CoerceAndRelayNTLMtoSMB collection doesn't work because post-processed AdminTo edges can't be added via OpenGraph yet, so added CoerceAndRelayToSMB edges instead
    - MSSQL collection assumes that any collection target hosting a SQL Server instance is a site database server. If there are other SQL Servers in the environment, false positives may occur.
    - I'm not a hooking expert, so if you see crashes during MSSQL collection due to the InitializeSecurityContextW hooking method that's totally vibe-coded, disable it. The hooking function doesn't work in PowerShell v7+ due to lack of support for certain APIs.

In Progress / To Do:
    - Unprivileged unit testing
    - Memory/disk usage monitoring functions
    - Entity panels
    - Get members of groups with permissions on System Management container
    - Should TAKEOVER-4 be added (not always traversable)?
    - Clean up unused post-processing and ingest functions
    - Test with SQL on non-standard port
    - Remove hardcoded port 1433 from AdminService collection
    - Relay management point computer accounts to site databases
    - Secondary site databases
    - Group and user collection members
    - DHCP collection (unauthenticated network access)
    - WMI collection (privileged, fallback if AdminService is not reachable)
    - CMPivot collection (privileged)

.PARAMETER Help
Display usage information

.PARAMETER CollectionMethods
Collection methods to use (comma-separated):
    - All (default): All SCCM collection methods
    - LDAP
    - Local
    - DNS
    - DHCP
    - RemoteRegistry
    - MSSQL
    - AdminService
    - WMI
    - HTTP
    - SMB

.PARAMETER ComputerFile
Specify the path to a file containing computer targets (limits to Remote Registry, MSSQL, AdminService, HTTP, SMB)

.PARAMETER Computers
Specify a comma-separated list of computer names or IP addresses to target (limits to Remote Registry, MSSQL, AdminService, WMI, HTTP, SMB)

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
    - CustomNodes: Outputs only custom nodes to .json file for BloodHound API

.PARAMETER FileSizeLimit
Stop enumeration after all collected files exceed this size on disk

Supported values:
    - *MB
    - *GB

.PARAMETER FileSizeUpdateInterval
Receive periodic size updates as files are being written for each server (in seconds)

.PARAMETER TempDir
Specify the path to a temporary directory where .json files will be stored before being zipped

.PARAMETER ZipDir
Specify the path to a directory where the final .zip file will be stored (default: current directory)

.PARAMETER LogFile
Specify the path to a log file to write script log to

.PARAMETER Domain
Specify a domain to use for LDAP queries and name resolution

.PARAMETER DomainController
Specify a domain controller to use for DNS and AD object resolution

.PARAMETER Credential
Specify a PSCredential object for authentication

.PARAMETER SkipPostProcessing
Skip post-processing edge creation (creates only direct edges from collection)

.PARAMETER DisablePossibleEdges
Switch/Flag:
    - Off (default): Make the following edges traversable (useful for offensive engagements but extends duration and is prone to false positive edges that may not be abusable):
        - CoerceAndRelayToMSSQL: EPA setting is assumed to be Off if the MSSQL server can't be reached
        - MSSQL_*: Assume any targeted MSSQL Server instances are site database servers, which may create false positives if MSSQL is installed on SCCM-related targets for other purposes, otherwise use Remote Registry collection to confirm
        - SameHostAs: Systems with the CmRcService SPN are treated as client devices in the root site for the forest (may be false positive if SCCM client was removed after remote control was used)
    - On: The edges above are not created or are created as non-traversable to reduce false positives at the expense of possible edges

.PARAMETER Verbose
Enable verbose output

#>

[CmdletBinding()]
param(
    [switch]$Help,
    
    [string]$CollectionMethods = "All",
    
    [string]$ComputerFile,

    [string]$Computers,
    
    [string]$SMSProvider,

    [string]$SiteCodes,
    
    [string]$OutputFormat = "Zip",

    [string]$FileSizeLimit = "1GB",
    
    [string]$FileSizeUpdateInterval = "5",
    
    [string]$TempDir,
    
    [string]$ZipDir,

    [string]$LogFile,
    
    [string]$Domain = $env:USERDNSDOMAIN,

    [string]$DomainController,
    
    [switch]$SkipPostProcessing,

    [switch]$DisablePossibleEdges,

    [switch]$Version
)

#region Logging
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
        "Verbose" { "DarkGray" }
        "Debug" { "DarkYellow" }
        default { "White" }
    }
   
    $padding = " " * (9 - $Level.Length)
    $logEntry = "[$timestamp] [$Level]$padding $Message"

    # File output
    if ($LogFile) {
        $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }

    # Only print Verbose when $VerbosePreference is set to Continue
    if ($Level -eq "Verbose" -and $VerbosePreference -ne "Continue") {
        return
    }

    Write-Host "[$timestamp] [$Level]$padding $Message" -ForegroundColor $color
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
            Write-LogMessage Error "    $issue"
        }
        return $false
    }
    
    Write-LogMessage Success "Prerequisites check passed"
    return $true
}

#endregion


#region Phase Orchestration

# Phases that run ONCE for the whole run (can add targets)
#$script:PhasesOnce    = @('LDAP','Local','DNS','DHCP')
$script:PhasesOnce    = @('LDAP','Local','DNS')

# Phases that run PER HOST
#$script:PhasesPerHost = @('RemoteRegistry','MSSQL','AdminService','WMI','HTTP','SMB')
$script:PhasesPerHost = @('RemoteRegistry','MSSQL','AdminService','HTTP','SMB')

# Canonical overall order (for selection + display)
$script:AllPhases = $script:PhasesOnce + $script:PhasesPerHost

# Map of phase -> scriptblock
#   - Once phases: { param() <do global work; may add to $script:CollectionTargets> }
#   - Per-host phases: { param($Target) <work per device> }
$script:PhaseActionsOnce = @{
    LDAP = { Invoke-LDAPCollection; }
    DHCP = { Invoke-DHCPCollection; }
    Local = { Invoke-LocalCollection; }
    DNS = { Invoke-DNSCollection; }
}

$script:PhaseActionsPerHost = @{
    RemoteRegistry = { param($Target)  Write-LogMessage Verbose "RemoteRegistry -> $($Target.Hostname) starting"; Invoke-RemoteRegistryCollection -CollectionTarget $Target; }
    MSSQL = { param($Target) Write-LogMessage Verbose "MSSQL -> $($Target.Hostname) starting"; Invoke-MSSQLCollection -CollectionTarget $Target; }
    AdminService = { param($Target)   Write-LogMessage Verbose "AdminService -> $($Target.Hostname) starting"; Invoke-AdminServiceCollection -CollectionTarget $Target; }
    WMI = { param($Target)  Write-LogMessage Verbose "WMI -> $($Target.Hostname) starting"; Invoke-WMICollection -Target $Target; }
    HTTP = { param($Target) Write-LogMessage Verbose "HTTP -> $($Target.Hostname) starting"; Invoke-HTTPCollection -CollectionTarget $Target; }
    SMB = { param($Target)  Write-LogMessage Verbose "SMB -> $($Target.Hostname) starting"; Invoke-SMBCollection -CollectionTarget $Target; }
}   

function Get-SelectedPhases {
  param([string]$Methods)

  $tokens = ($Methods -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  if (-not $tokens -or $tokens -contains 'ALL') { return $script:AllPhases }

  $wanted = @{}
  foreach ($t in $tokens) { $wanted[$t.ToUpper()] = $true }
  $script:AllPhases | Where-Object { $wanted.ContainsKey($_.ToUpper()) }
}

# Global (once) phase status
#   Values: Pending / Success / Failed
$script:GlobalPhaseStatus = @{}

function Ensure-GlobalPhaseStatus {
  param([string[]]$SelectedPhases)
  foreach ($p in ($SelectedPhases | Where-Object { $_ -in $script:PhasesOnce })) {
    if (-not $script:GlobalPhaseStatus.ContainsKey($p)) {
      $script:GlobalPhaseStatus[$p] = 'Pending'
    }
  }
}

# Per-host phase status (per device)
#   device.PhaseStatus[phase] = Pending / Success / Failed
function Ensure-PerHostPhaseStatus {
  param([string[]]$SelectedPhases)
  $perHost = $SelectedPhases | Where-Object { $_ -in $script:PhasesPerHost }

  foreach ($d in $script:CollectionTargets.Values) {
    if (-not $d.PSObject.Properties.Match('PhaseStatus')) {
      $d | Add-Member -NotePropertyName PhaseStatus -NotePropertyValue @{}
    }
    foreach ($p in $perHost) {
      if (-not $d.PhaseStatus.ContainsKey($p)) { $d.PhaseStatus[$p] = 'Pending' }
    }
  }
}

function Invoke-DiscoveryPipeline {
  param(
    [string[]]$SelectedPhases
  )

  # 1) Run ONCE phases in order (only those selected)
  Ensure-GlobalPhaseStatus -SelectedPhases $SelectedPhases

  foreach ($phase in $script:PhasesOnce) {
    if ($phase -notin $SelectedPhases) { continue }
    if ($script:GlobalPhaseStatus[$phase] -ne 'Pending') { continue }

    try {
      & $script:PhaseActionsOnce[$phase]   # no target; may add to $script:CollectionTargets
      $script:GlobalPhaseStatus[$phase] = 'Success'
    } catch {
      $script:GlobalPhaseStatus[$phase] = 'Failed'
      Write-LogMessage Error "$phase phase failed: $_"
    }
  }

  # 2) Run PER-HOST phases until none remain Pending
  while ($true) {
    Ensure-PerHostPhaseStatus -SelectedPhases $SelectedPhases

    $didWorkThisPass = $false

    foreach ($phase in $script:PhasesPerHost) {
      if ($phase -notin $SelectedPhases) { continue }

      $pending = $script:CollectionTargets.Values |
        Where-Object { $_.PhaseStatus[$phase] -eq 'Pending' }

      if (-not $pending) { continue }

      $didWorkThisPass = $true

      # Always run per-host phases serially
      foreach ($t in $pending) {
        try {
          & $script:PhaseActionsPerHost[$phase] -Target $t
          $t.PhaseStatus[$phase] = 'Success'
        } catch {
          $t.PhaseStatus[$phase] = 'Failed'
          Write-LogMessage Error "$phase phase failed on $($t.Hostname): $_"
        }
      }
    }

    if (-not $didWorkThisPass) { break }  # no pending work left for any per-host phase
  }

  Write-LogMessage Success "All selected phases completed. Once phases ran once; per-host phases ran for every discovered target."
}


#endregion

#region DNS Resolution
function Test-DnsResolution {
    param([string]$Domain)
    
    if (-not $Domain) {
        return $false
    }
        
    Write-LogMessage Verbose "Testing DNS resolution for $Domain"
    
    try {
        # Try to resolve the domain
        if ($script:DomainController) {
            Write-LogMessage Verbose "Using specified domain controller $script:DomainController for DNS resolution"
            try {
                if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
                    $dnsResult = (Resolve-DnsName -Name $Domain -Server $script:DomainController -ErrorAction Stop).IPAddress
                }                
            } catch {
                Write-LogMessage Verbose "Failed to resolve $Domain using DC $script:DomainController: $_"
            }
        }

        # Fallback to standard resolution
        if (-not $dnsResult) {
            $dnsResult = [System.Net.Dns]::GetHostAddresses($Domain)
        }
        
        if ($dnsResult -and $dnsResult.Count -gt 0) {
            return $true
        }
    } catch {
        Write-LogMessage Error "Failed to resolve domain '$Domain': $_"      
        return $false
    }
}

function Resolve-PrincipalInDomain {
    param (
        [string]$Name,
        [string]$Domain
    )
    
    # Initialize domain cache for discovered domain suffixes
    if (-not $script:DiscoveredDomains) { $script:DiscoveredDomains = @{} }
    
    # Initialize and check cache to avoid repeated lookups
    if (-not $script:ResolvedPrincipalCache) { $script:ResolvedPrincipalCache = @{} }
    
    # Extract domain suffix from FQDN if present
    $domainsToTry = @()
    if ($Name -match '\.') {
        # Name appears to be an FQDN, extract potential domain suffix
        $nameParts = $Name -split '\.'
        if ($nameParts.Count -gt 2) {
            # Try extracting domain from FQDN (everything after first part)
            $extractedDomain = ($nameParts[1..($nameParts.Count - 1)] -join '.').ToUpper()
            if ($extractedDomain -ne $Domain.ToUpper()) {
                $domainsToTry += $extractedDomain
                Write-LogMessage Verbose "Extracted domain suffix '$extractedDomain' from FQDN '$Name'"
                
                # Add to discovered domains cache
                if (-not $script:DiscoveredDomains.ContainsKey($extractedDomain)) {
                    $script:DiscoveredDomains[$extractedDomain] = $true
                    Write-LogMessage Verbose "Added '$extractedDomain' to discovered domains cache"
                }
            }
        }
    }
    
    # Add the originally specified domain
    if ($Domain) {
        $domainsToTry += $Domain
    }
    
    # Try resolution in each domain
    foreach ($domainToTry in $domainsToTry) {
        $cacheKey = ("{0}|{1}" -f $domainToTry, $Name).ToLower()
        
        # Check cache first
        if ($script:ResolvedPrincipalCache.ContainsKey($cacheKey)) {
            if ($script:ResolvedPrincipalCache[$cacheKey] -eq $null) {
                Write-LogMessage Verbose "Already tried to resolve $Name in domain $domainToTry and failed, trying next domain"
                continue
            }
            Write-LogMessage Verbose "Resolved $Name in domain $domainToTry from cache"
            return $script:ResolvedPrincipalCache[$cacheKey]
        }

        Write-LogMessage Verbose "Attempting to resolve $Name in domain $domainToTry"
        
        $adPowershellSucceeded = $false
        
        # Try Active Directory PowerShell module first
        if (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) {
            Write-LogMessage Verbose "Trying AD PowerShell module in domain $domainToTry"
            
            try {
                $adObject = $null
                
                # Set server parameter if domain is specified and different from current
                $adParams = @{ Identity = $Name }
                if ($script:DomainController) {
                    $adParams.Server = $script.DomainController
                } elseif ($domainToTry -and $domainToTry -ne $env:USERDOMAIN -and $domainToTry -ne $env:USERDNSDOMAIN) {
                    $adParams.Server = $domainToTry
                }
            
                # Try Computer first
                try {
                    $adObject = Get-ADComputer @adParams -ErrorAction Stop
                } catch {
                    # Try Computer by SID
                    try {
                        $adParams.Remove('Identity')
                        $adParams.LDAPFilter = "(objectSid=$Name)"
                        $adObject = Get-ADComputer @adParams -ErrorAction Stop
                        if (-not $adObject) { throw }
                    } catch {
                        # Try User
                        try {
                            $adParams.Remove('LDAPFilter')
                            $adParams.Identity = $Name
                            $adObject = Get-ADUser @adParams -ErrorAction Stop
                        } catch {
                            # Try User by SID
                            try {
                                $adParams.Remove('Identity')
                                $adParams.LDAPFilter = "(objectSid=$Name)"
                                $adObject = Get-ADUser @adParams -ErrorAction Stop
                                if (-not $adObject) { throw }
                            } catch {
                                # Try Group
                                try {
                                    $adParams.Remove('LDAPFilter')
                                    $adParams.Identity = $Name
                                    $adObject = Get-ADGroup @adParams -ErrorAction Stop
                                } catch {
                                    # Try Group by SID
                                    try {
                                        $adParams.Remove('Identity')
                                        $adParams.LDAPFilter = "(objectSid=$Name)"
                                        $adObject = Get-ADGroup @adParams -ErrorAction Stop
                                        if (-not $adObject) { throw }
                                    } catch {
                                        Write-LogMessage Verbose "No AD object found for '$Name' in domain '$domainToTry'"
                                    }
                                }
                            }
                        }
                    }
                }
                
                if ($adObject) {
                    $adObjectName = if ($adObject.UserPrincipalName) { $adObject.UserPrincipalName } elseif ($adObject.DNSHostName) { $adObject.DNSHostName } else { $adObject.SamAccountName }
                    $adObjectSid = $adObject.SID.ToString()
                    Write-LogMessage Verbose "Resolved '$Name' to AD principal in '$domainToTry': $adObjectName ($adObjectSid)"
                    
                    # Upper the first letter of object class to match BloodHound kind
                    $kind = if ($adObject.ObjectClass -and $adObject.ObjectClass.Length -gt 0) { 
                        $adObject.ObjectClass.Substring(0,1).ToUpper() + $adObject.ObjectClass.Substring(1).ToLower() 
                    } else { 
                        $adObject.ObjectClass 
                    }
                    
                    $adPowershellSucceeded = $true
                    $result = [PSCustomObject]@{
                        name = $adObjectName
                        distinguishedName = $adObject.DistinguishedName
                        DNSHostName = $adObject.DNSHostName
                        Domain = $domainToTry
                        Enabled = $adObject.Enabled
                        IsDomainPrincipal = $true
                        SamAccountName = $adObject.SamAccountName
                        SID = $adObject.SID.ToString()
                        UserPrincipalName = $adObject.UserPrincipalName
                        Type = $kind
                        Error = $null
                    }
                    $script:ResolvedPrincipalCache[$cacheKey] = $result
                    return $result
                }
            } catch {
                Write-LogMessage Verbose "AD PowerShell lookup failed for '$Name' in domain '$domainToTry': $_"
            }
        }

        # Try ADSISearcher approach before .NET methods (.NET does not return dNSHostName property)
        try {
            Write-LogMessage Verbose "Attempting ADSISearcher for '$Name' in domain '$domainToTry'"
            
            # Build LDAP path
            $domainDN = if ($domainToTry) {
                "DC=" + ($domainToTry -replace "\.", ",DC=")
            } else {
                $null
            }

            # Use Domain Controller in LDAP path if specified
            $ldapPath = if ($script:DomainController -and $domainDN) {
                "LDAP://$($script:DomainController)/$domainDN"
            } elseif ($domainDN) {
                "LDAP://$domainDN"
            } else {
                "LDAP://"
            }
            
            $adsiSearcher = if ($ldapPath -ne "LDAP://") {
                New-Object System.DirectoryServices.DirectorySearcher([ADSI]$ldapPath)
            } else {
                New-Object System.DirectoryServices.DirectorySearcher
            }
            
            # Try different search filters
            $searchFilters = @(
                "(samAccountName=$Name)",
                "(objectSid=$Name)",
                "(userPrincipalName=$Name)",
                "(dnsHostName=$Name)",
                "(cn=$Name)"
            )
            
            $adsiResult = $null
            foreach ($filter in $searchFilters) {
                try {
                    $adsiSearcher.Filter = $filter
                    $adsiResult = $adsiSearcher.FindOne()
                    if ($adsiResult) {
                        Write-LogMessage Verbose "Found object using ADSISearcher with filter: $filter"
                        break
                    }
                } catch {
                    Write-LogMessage Verbose "ADSISearcher filter '$filter' failed: $_"
                }
            }
            
            if ($adsiResult) {
                $props = $adsiResult.Properties
                $objectClass = if ($props["objectclass"]) { $props["objectclass"][$props["objectclass"].Count - 1] } else { "unknown" }
                $objectSid = if ($props["objectsid"]) { 
                    (New-Object System.Security.Principal.SecurityIdentifier($props["objectsid"][0], 0)).Value 
                } else { 
                    $null 
                }
                                
                $result = [PSCustomObject]@{
                    name = if ($props["userprincipalname"]) { $props["userprincipalname"][0] } elseif ($props["dnshostname"]) { $props["dnshostname"][0] } else { $props["samaccountname"][0] }
                    distinguishedName = if ($props["distinguishedname"]) { $props["distinguishedname"][0] } else { $null }
                    DNSHostName = if ($props["dnshostname"]) { $props["dnshostname"][0] } else { $null }
                    Domain = $domainToTry
                    Enabled = if ($props["useraccountcontrol"]) { 
                        -not ([int]$props["useraccountcontrol"][0] -band 2) 
                    } else { 
                        $null 
                    }
                    IsDomainPrincipal = $true
                    SamAccountName = if ($props["samaccountname"]) { $props["samaccountname"][0] } else { $null }
                    SID = $objectSid
                    UserPrincipalName = if ($props["userprincipalname"]) { $props["userprincipalname"][0] } else { $null }
                    Type = if ($objectClass -and $objectClass.Length -gt 0) { 
                        $objectClass.Substring(0,1).ToUpper() + $objectClass.Substring(1).ToLower() 
                    } else { 
                        "Unknown" 
                    }
                    Error = $null
                }
                
                $adsiSearcher.Dispose()
                $script:ResolvedPrincipalCache[$cacheKey] = $result
                return $result
            }
            
            $adsiSearcher.Dispose()
            
        } catch {
            Write-LogMessage Verbose "ADSISearcher lookup failed for '$Name' in domain '$domainToTry': $_"
        }    
        
        # Try .NET DirectoryServices AccountManagement
        if ($script:UseNetFallback -or -not (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) -or -not $adPowershellSucceeded) {
            Write-LogMessage Verbose "Attempting .NET DirectoryServices AccountManagement for '$Name' in domain '$domainToTry'"
            
            try {
                # Try AccountManagement approach
                # Use Domain Controller if specified
                if ($script:DomainController) {
                    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                        [System.DirectoryServices.AccountManagement.ContextType]::Domain, 
                        $script:DomainController
                    )
                } else {
                    $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                        [System.DirectoryServices.AccountManagement.ContextType]::Domain, 
                        $domainToTry
                    )
                }
                $principal = $null
                
                # Try as Computer
                try {
                    $principal = [System.DirectoryServices.AccountManagement.ComputerPrincipal]::FindByIdentity($context, $Name)
                    if ($principal) {
                        Write-LogMessage Verbose "Found computer principal using .NET DirectoryServices: $($principal.Name)"
                    }
                } catch {
                    Write-LogMessage Verbose "Computer lookup failed: $_"
                }
                
                # Try as User if computer lookup failed
                if (-not $principal) {
                    try {
                        $principal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($context, $Name)
                        if ($principal) {
                            Write-LogMessage Verbose "Found user principal using .NET DirectoryServices: $($principal.Name)"
                        }
                    } catch {
                        Write-LogMessage Verbose "User lookup failed: $_"
                    }
                }
                
                # Try as Group if user lookup failed
                if (-not $principal) {
                    try {
                        $principal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context, $Name)
                        if ($principal) {
                            Write-LogMessage Verbose "Found group principal using .NET DirectoryServices: $($principal.Name)"
                        }
                    } catch {
                        Write-LogMessage Verbose "Group lookup failed: $_"
                    }
                }
                
                if ($principal) {
                    $principalType = $principal.GetType().Name -replace "Principal$", ""
                    
                    $result = [PSCustomObject]@{
                        name = if ($principal.UserPrincipalName) { $principal.UserPrincipalName } else { $principal.SamAccountName }
                        distinguishedName = $principal.DistinguishedName
                        DNSHostName = $principal.dNSHostName
                        Domain = $domainToTry
                        Enabled = if ($principal.PSObject.Properties['Enabled']) { $principal.Enabled } else { $null }
                        IsDomainPrincipal = $true
                        SamAccountName = $principal.SamAccountName
                        SID = $principal.Sid.Value
                        UserPrincipalName = $principal.UserPrincipalName
                        Type = $principalType
                        Error = $null
                    }
                    
                    $context.Dispose()
                    $script:ResolvedPrincipalCache[$cacheKey] = $result
                    return $result

                } else {
                    Write-LogMessage Verbose ".NET DirectoryServices failed to resolve '$Name' in domain '$domainToTry'"
                }
                
                $context.Dispose()
                
            } catch {
                Write-LogMessage Verbose ".NET DirectoryServices failed to resolve '$Name' in domain '$domainToTry': $_"
            }
            
            # Try DirectorySearcher as final .NET attempt
            try {
                Write-LogMessage Verbose "Attempting DirectorySearcher for '$Name' in domain '$domainToTry'"
                
                Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
                
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.Filter = "(|(samAccountName=$Name)(objectSid=$Name)(userPrincipalName=$Name)(dnsHostName=$Name))"
                $null = $searcher.PropertiesToLoad.Add("samAccountName")
                $null = $searcher.PropertiesToLoad.Add("objectSid")
                $null = $searcher.PropertiesToLoad.Add("distinguishedName")
                $null = $searcher.PropertiesToLoad.Add("userPrincipalName")
                $null = $searcher.PropertiesToLoad.Add("dnsHostName")
                $null = $searcher.PropertiesToLoad.Add("objectClass")
                $null = $searcher.PropertiesToLoad.Add("userAccountControl")
                
                $result = $searcher.FindOne()
                if ($result) {
                    $objectClass = $result.Properties["objectclass"][$result.Properties["objectclass"].Count - 1]
                    $objectSid = (New-Object System.Security.Principal.SecurityIdentifier($result.Properties["objectsid"][0], 0)).Value
                    
                    Write-LogMessage Verbose "Found object using DirectorySearcher: $($result.Properties["samaccountname"][0])"
                    
                    $returnResult = [PSCustomObject]@{
                        name = if ($result.Properties["userprincipalname"].Count -gt 0) { $result.Properties["userprincipalname"][0] } elseif ($result.Properties["dnshostname"].Count -gt 0) { $result.Properties["dnshostname"][0] } else { $result.Properties["samaccountname"][0] }
                        distinguishedName = $result.Properties["distinguishedname"][0]
                        DNSHostName = if ($result.Properties["dnshostname"].Count -gt 0) { $result.Properties["dnshostname"][0] } else { $null }
                        Domain = $domainToTry
                        Enabled = if ($result.Properties["useraccountcontrol"].Count -gt 0) { 
                            -not ([int]$result.Properties["useraccountcontrol"][0] -band 2) 
                        } else { 
                            $null 
                        }
                        IsDomainPrincipal = $true
                        SamAccountName = $result.Properties["samaccountname"][0]
                        SID = $objectSid
                        UserPrincipalName = if ($result.Properties["userprincipalname"].Count -gt 0) { $result.Properties["userprincipalname"][0] } else { $null }
                        Type = $objectClass.Substring(0,1).ToUpper() + $objectClass.Substring(1).ToLower()
                        Error = $null
                    }
                    
                    $searcher.Dispose()
                    $script:ResolvedPrincipalCache[$cacheKey] = $returnResult
                    return $returnResult
                }
                
                $searcher.Dispose()
                
            } catch {
                Write-LogMessage Verbose "DirectorySearcher failed for '$Name' in domain '$domainToTry': $_"
            }
        }
        
        # Try NTAccount translation
        try {
            Write-LogMessage Verbose "Attempting NTAccount translation for '$Name' in domain '$domainToTry'"
            
            # Try direct SID lookup
            $ntAccount = New-Object System.Security.Principal.NTAccount($domainToTry, $Name)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $resolvedSid = $sid.Value
            Write-LogMessage Verbose "Resolved SID for '$Name' using NTAccount in '$domainToTry': $resolvedSid"
            
            $ntResult = [PSCustomObject]@{
                name = "$domainToTry\$Name"
                SID = $resolvedSid
                Domain = $domainToTry
                Error = $null
            }
            $script:ResolvedPrincipalCache[$cacheKey] = $ntResult
            return $ntResult
        } catch {
            Write-LogMessage Verbose "NTAccount translation failed for '$Name' in domain '$domainToTry': $_"
        }
        
        # Try SID to name translation as final attempt (if input looks like a SID)
        if ($Name -match "^S-\d+-\d+") {
            try {
                Write-LogMessage Verbose "Attempting SID to name translation for '$Name'"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($Name)
                $resolvedName = $sid.Translate([System.Security.Principal.NTAccount]).Value
                Write-LogMessage Verbose "Resolved name for SID '$Name': $resolvedName"
                
                $sidResult = [PSCustomObject]@{
                    name = $resolvedName
                    SID = $Name
                    Domain = $domainToTry
                    Error = $null
                }
                $script:ResolvedPrincipalCache[$cacheKey] = $sidResult
                return $sidResult
            } catch {
                Write-LogMessage Verbose "SID to name translation failed for '$Name': $_"
            }
        }
        
        # Mark this domain as failed in cache and continue to next domain
        Write-LogMessage Verbose "Failed to resolve '$Name' in domain '$domainToTry', trying next domain if available"
        $script:ResolvedPrincipalCache[$cacheKey] = $null
    }
    
    # All domains failed
    Write-LogMessage Verbose "Failed to resolve '$Name' in all attempted domains"
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
                            name = if ($adObject.DNSHostName) { $adObject.DNSHostName } elseif ($adObject.samAccountName) { "$Domain\$($adObject.samAccountName)" } else { "$Domain\$($adObject.Name)" }
                            SID = $adObject.objectSid.Value
                            domain = $Domain
                            type = $objectType
                            DNSHostName = $adObject.DNSHostName
                            distinguishedName = $adObject.DistinguishedName
                            samAccountName = $adObject.samAccountName
                            userPrincipalName = $adObject.userPrincipalName
                            objectClass = $adObject.objectClass
                            enabled = if ($adObject.PSObject.Properties.Name -contains "Enabled") { $adObject.Enabled } else { $null }
                            isDomainPrincipal = $true
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
                                name = if ($adObject.DNSHostName) { $adObject.DNSHostName } elseif ($adObject.samAccountName) { "$Domain\$($adObject.samAccountName)" } else { "$Domain\$($adObject.Name)" }
                                SID = if ($adObject.objectSid) { $adObject.objectSid.Value } else { $null }
                                domain = $Domain
                                type = $objectType
                                DNSHostName = $adObject.DNSHostName
                                distinguishedName = $adObject.DistinguishedName
                                samAccountName = $adObject.samAccountName
                                userPrincipalName = $adObject.userPrincipalName
                                objectClass = $adObject.objectClass
                                enabled = if ($adObject.PSObject.Properties.Name -contains "Enabled") { $adObject.Enabled } else { $null }
                                isDomainPrincipal = $true
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
    Write-LogMessage Verbose "Trying DirectoryServices for '$searchValue' in domain '$Domain'"
    
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
                name = if ($dnsHostName) { $dnsHostName } else { "$Domain\$resolvedName" }
                SID = $sid
                Domain = $Domain
                Type = $objectType
                DNSHostName = $dnsHostName
                distinguishedName = $result.Properties["distinguishedname"][0]
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
                name = $resolvedName
                SID = $sidValue
                Domain = $Domain
                Type = "Unknown"
                DNSHostName = $null
                distinguishedName = $null
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
                name = "$Domain\$Name"
                SID = $sid.Value
                Domain = $Domain
                Type = "Unknown"
                DNSHostName = $null
                distinguishedName = $null
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
        
#endregion

#region Helper Functions
function Invoke-HttpRequest {
    param(
        [string]$Uri,
        [int]$TimeoutSec = 5,
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
            IsConnectionFailure = $false
        }
        
        $reader.Close()
        $stream.Close()
        $response.Close()
        
        return $result
        
    } catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        $status = $_.Exception.Status
        # If we received an HTTP response (e.g., 401/404), it's not a connection failure
        if ($webResponse) {
            $statusCode = [int]$webResponse.StatusCode
            return [PSCustomObject]@{
                StatusCode = $statusCode
                Content = $null
                IsConnectionFailure = $false
            }
        }
        # Classify known connection-level failures where no response is available
        $isConnFail = $false
        if ($status -in @([System.Net.WebExceptionStatus]::ConnectFailure,
                          [System.Net.WebExceptionStatus]::NameResolutionFailure,
                          [System.Net.WebExceptionStatus]::Timeout,
                          [System.Net.WebExceptionStatus]::SendFailure,
                          [System.Net.WebExceptionStatus]::ReceiveFailure,
                          [System.Net.WebExceptionStatus]::TrustFailure,
                          [System.Net.WebExceptionStatus]::SecureChannelFailure)) {
            $isConnFail = $true
        }
        return [PSCustomObject]@{
            StatusCode = $null
            Content = $null
            IsConnectionFailure = $isConnFail
        }
    }
}

function Test-AdminPrivileges {
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-DeviceToTargetsA {
    param(
        [string]$DeviceName,
        [string]$Source
    )
    
    if ([string]::IsNullOrWhiteSpace($DeviceName)) { return $null }
    
    # Try to resolve to AD object to get canonical identifier
    $adObject = Resolve-PrincipalInDomain -Name $DeviceName -Domain $script:Domain
    
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
            PhaseStatus = @{
                RemoteRegistry= "Pending"
                MSSQL         = "Pending"
                AdminService  = "Pending"
                WMI           = "Pending"
                HTTP          = "Pending"
                SMB           = "Pending"
            }
        }
        Write-LogMessage Verbose "Added collection target: $canonicalName from $Source"
        
        # Return new target
        return $script:CollectionTargets[$canonicalName]
    }
}

function Test-AllowedTarget {
    param(
        [string]$DeviceName,
        $AdObject
    )

    # No filter -> allow everything
    if (-not $script:AllowedTargets -or $script:AllowedTargets.Count -eq 0) { return $true }

    $candidates = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

    if ($DeviceName) {
        [void]$candidates.Add($DeviceName.Trim())
        # If FQDN, also add short name; if short name, that's already covered
        if ($DeviceName -match '\.') {
            [void]$candidates.Add(($DeviceName -split '\.')[0])
        }
    }

    if ($AdObject) {
        if ($AdObject.DNSHostName) {
            [void]$candidates.Add($AdObject.DNSHostName)
            [void]$candidates.Add(($AdObject.DNSHostName -split '\.')[0])
        }
        if ($AdObject.Name)        { [void]$candidates.Add($AdObject.Name) }
        if ($AdObject.SamAccountName) { [void]$candidates.Add($AdObject.SamAccountName) }
    }

    foreach ($cand in $candidates) {
        if ($script:AllowedTargets.Contains($cand)) { return $true }
    }

    return $false
}

function Add-DeviceToTargets {
    param(
        [string]$DeviceName,
        [string]$Source,
        [string]$SiteCode = $null
    )

    if ([string]::IsNullOrWhiteSpace($DeviceName)) { return $null }

    # Resolve (best-effort) to enrich names + SID; don’t bail if it fails
    $adObject = $null
    try {
        $adObject = Resolve-PrincipalInDomain -Name $DeviceName -Domain $script:Domain
    } catch {
        # keep going; we handle unresolved below
    }

    # Enforce the allow-list (names/IPs). If not allowed -> skip.
    if (-not (Test-AllowedTarget -DeviceName $DeviceName -AdObject $adObject)) {
        Write-LogMessage Warning "Skipping discovered system '$DeviceName' (not in allowed targets filter)"
        return $null
    }

    # Dedup key: prefer SID if resolved; else use lowercase name
    $dedupKey = $null
    $canonicalName = $DeviceName
    if ($adObject -and $adObject.SID) {
        $dedupKey      = $adObject.SID
        $canonicalName = if ($adObject.DNSHostName) { $adObject.DNSHostName } else { $DeviceName }
    } else {
        $dedupKey = $DeviceName.ToLowerInvariant()
        if (-not ($DeviceName -match '\.')) {
            # keep short name as provided; resolution may happen later in another phase
        }
        Write-LogMessage Warning "Could not resolve '$DeviceName' to a domain object; adding by name"
    }

    # Existing target by dedup key?
    $existingTarget = $script:CollectionTargets.Values | Where-Object { $_.DedupKey -eq $dedupKey } | Select-Object -First 1
    if ($existingTarget) {
        # Prefer FQDN if we now have it
        $isExistingShort = ($existingTarget.Hostname -notmatch '\.')
        $isNewFqdn       = ($canonicalName -match '\.')
        if ($isNewFqdn -and $isExistingShort) {
            Write-LogMessage Verbose "Upgrading hostname '$($existingTarget.Hostname)' -> FQDN '$canonicalName'"
            # Change key in hashtable
            $script:CollectionTargets.Remove($existingTarget.Hostname)
            $existingTarget.Hostname = $canonicalName
            $script:CollectionTargets[$canonicalName] = $existingTarget
        }

        # Merge source tag
        if ($Source -and ($existingTarget.Source -notlike "*$Source*")) {
            $existingTarget.Source = ($existingTarget.Source, $Source) -join ", "
        }

        # Merge site code
        if ($SiteCode) {
            if (-not $existingTarget.SiteCode) {
                $existingTarget.SiteCode = $SiteCode
            } elseif ($existingTarget.SiteCode -ne $SiteCode) {
                Write-LogMessage Warning "Target '$canonicalName' already has SiteCode '$($existingTarget.SiteCode)'; cannot overwrite with '$SiteCode'"
            }
        }

        $existingTarget.IsNew = $false
        return $existingTarget
    }

    # Create a new target entry
    $target = @{
        ADObject   = $adObject
        Collected  = $false
        DedupKey   = $dedupKey
        Hostname   = $canonicalName
        IsNew      = $true
        Source     = $Source
        SiteCode    = $SiteCode
        PhaseStatus = @{
            RemoteRegistry = "Pending"
            MSSQL          = "Pending"
            AdminService   = "Pending"
            WMI            = "Pending"
            HTTP           = "Pending"
            SMB            = "Pending"
        }
    }

    $script:CollectionTargets[$canonicalName] = $target
    Write-LogMessage Verbose "Added collection target: $canonicalName from $Source"

    return $script:CollectionTargets[$canonicalName]
}

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

#endregion

#region Node and Edge Functions
$script:EdgePropertyGenerators = @{

    ############################
    ##  offensive edge kinds  ##
    #############################

    "CoerceAndRelayToAdminService" = {
    #   Source and target node types
    #       Group                   -> SCCM_Site
    #   Requirements
    #       

    }
}

function Upsert-Node {
    param(
        [string]$Id,
        [string[]]$Kinds,
        [hashtable]$Properties = @{},  # Default to empty hashtable, not null
        [PSObject]$PSObject = $null
    )

    # Start with provided properties
    $inputProperties = if ($Properties) { $Properties.Clone() } else { @{} }

    # If PSObject is provided, add its properties automatically
    if ($PSObject) {
        # Add all non-null object properties except SID, which is already the Id
        $PSObject.PSObject.Properties | ForEach-Object {
            if ($null -ne $_.Value `
                -and $_.Name -ne "SID" `
                -and $_.Name -ne "ObjectSid" `
                -and $_.Name -ne "ObjectIdentifier" `
                -and -not $inputProperties.ContainsKey($_.Name)) {
                $inputProperties[$_.Name] = $_.Value
            }
        }
    }

    # Ensure all PSObject property values are strings (prevents object serialization issues)
    foreach ($key in @($inputProperties.Keys)) {
        if ($null -ne $inputProperties[$key] -and ($inputProperties[$key] -is [PSObject] -or $inputProperties[$key].GetType().Name -eq 'PSCustomObject')) {
            $inputProperties[$key] = $inputProperties[$key].ToString()
        }
    }
       
    # Check if node already exists and merge properties if it does
    $existingNode = $script:Nodes | Where-Object { $_.id -eq $Id }

    if ($existingNode) {
        $existingProps = if ($existingNode.properties) { $existingNode.properties } else { @{} }
        # Track which properties are being added/updated
        $addedProperties = @()
        $updatedProperties = @()
        
        # Merge new properties into existing node
        foreach ($key in $inputProperties.Keys) {
            if ($null -ne $inputProperties[$key]) {
                if ($existingProps.ContainsKey($key)) {
                    $oldValue = $existingProps[$key]
                    $newValue = $inputProperties[$key]
                    
                    # Special handling for arrays - merge them
                    if ($oldValue -is [Array] -and $newValue -is [Array]) {
                        # Combine and deduplicate arrays
                        $mergedArray = @(($oldValue + $newValue) | Where-Object { $_ -ne $null } | Select-Object -Unique)
                        $existingProps[$key] = $mergedArray
                        
                        # Update logging to show merge
                        $addedItems = $newValue | Where-Object { $_ -notin $oldValue }
                        if ($addedItems.Count -gt 0) {
                            $updatedProperties += "$key`: Added [$($addedItems -join ', ')] to existing [$($oldValue -join ', ')]"
                        }
                    } elseif ($oldValue -is [Array]) {
                        # Old value is array, new is single value - add if not present
                        if ($newValue -notin $oldValue) {
                            $existingProps[$key] = @($oldValue + $newValue)
                            $updatedProperties += "$key`: Added '$newValue' to existing [$($oldValue -join ', ')]"
                        }
                    } elseif ($newValue -is [Array]) {
                        # New value is array, old is single value - add old if not present
                        if ($oldValue -notin $newValue) {
                            $existingProps[$key] = @($newValue + $oldValue)
                            $updatedProperties += "$key`: Added '$oldValue' to new [$($newValue -join ', ')]"
                        } else {
                            $existingProps[$key] = $newValue
                        }
                    } else {
                        # Non-array properties - check if different and replace
                        if ($oldValue -ne $newValue) {
                            $updatedProperties += "$key`: '$oldValue' -> '$newValue'"
                        }
                        $existingProps[$key] = $newValue
                    }
                } else {
                    # New property being added
                    $valueStr = if ($inputProperties[$key] -is [Array]) { 
                        "[$($inputProperties[$key] -join ', ')]" 
                    } else { 
                        "'$($inputProperties[$key])'" 
                    }
                    $addedProperties += "$key`: $valueStr"
                    $existingProps[$key] = $inputProperties[$key]
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
            Write-LogMessage Verbose "Found existing $($Kinds[0]) node: $Id $(if ($existingNode.Properties.samAccountName) {"($($existingNode.properties.samAccountName))"})$changes"
        } else {
            Write-LogMessage Verbose "Found existing $($Kinds[0]) node: $Id $(if ($existingNode.Properties.samAccountName) {"($($existingNode.properties.samAccountName))"})`nNo new properties"
        }

        # Replace properties with normalized/merged set
        $existingNode.properties = $existingProps
        return $existingNode

    } else {
        # Filter out null properties and create new node
        $cleanProperties = @{}
        foreach ($key in $inputProperties.Keys) {  # Use $inputProperties, not $Properties
            if ($null -ne $inputProperties[$key]) {
                $cleanProperties[$key] = $inputProperties[$key]
            }
        }
       
        $node = [PSCustomObject]@{
            id = $Id
            kinds = $Kinds
            properties = $cleanProperties
        }
       
        $script:Nodes += $node
        Write-LogMessage Verbose "Added $($Kinds[0]) node: $Id (node count: $($script:Nodes.Count))"
        return $node
    }
}

function Invoke-PostProcessing {

    Write-LogMessage Info "Starting post-processing of nodes and edges"

    $computerNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "Computer" })
    $mssqlServerNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "MSSQL_Server" })
    $sccmAdminUserNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_AdminUser" })
    $sccmClientDeviceNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_ClientDevice" })
    $sccmCollectionNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Collection" })
    $sccmSecurityRoleNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_SecurityRole" })
    $sccmSiteNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" })

    # Process SCCM_Site nodes first to identify and update root site code
    $rootSiteNodes = @()

    foreach ($sccmSiteNode in $sccmSiteNodes) {

        $rootSiteNode = $null

        # Auto-create SCCM_AdminsReplicatedTo edges for SCCM_Site nodes
        $parentSiteCode = $sccmSiteNode.Properties.parentSiteCode
        $siteType = $sccmSiteNode.Properties.siteType
        
        if ($parentSiteCode -and $parentSiteCode -ne "" -and $parentSiteCode -ne "None") {
            # Create parent-child edges per rules:
            # - Central <-> Primary (both directions)
            # - Primary -> Secondary (one direction)
            $parentCandidates = @($sccmSiteNodes | Where-Object {
                $_.kinds -contains "SCCM_Site" -and (
                    $_.id -eq $parentSiteCode -or
                    $_.Properties.siteCode -eq $parentSiteCode
                )
            })
            if ($parentCandidates -and $parentCandidates.Count -gt 0) {
                $parent = $parentCandidates[0]
                $parentType = $parent.Properties.siteType
                # Central <-> Primary
                if ( ($parentType -eq "Central Administration Site" -and $siteType -eq "Primary Site") -or
                        ($parentType -eq "Primary Site" -and $siteType -eq "Central Administration Site") ) {
                    $existsP2C = $script:Edges | Where-Object { $_.Start -eq $parent.id -and $_.End -eq $sccmSiteNode.id -and $_.Kind -eq "SCCM_AdminsReplicatedTo" }
                    if (-not $existsP2C) { Upsert-Edge -Start $parent.id -Kind "SCCM_AdminsReplicatedTo" -End $sccmSiteNode.id }
                    $existsC2P = $script:Edges | Where-Object { $_.Start -eq $sccmSiteNode.id -and $_.End -eq $parent.id -and $_.Kind -eq "SCCM_AdminsReplicatedTo" }
                    if (-not $existsC2P) { Upsert-Edge -Start $sccmSiteNode.id -Kind "SCCM_AdminsReplicatedTo" -End $parent.id }
                }
                # Primary -> Secondary only
                elseif ($parentType -eq "Primary Site" -and $siteType -eq "Secondary Site") {
                    $existsP2C = $script:Edges | Where-Object { $_.Start -eq $parent.id -and $_.End -eq $sccmSiteNode.id -and $_.Kind -eq "SCCM_AdminsReplicatedTo" }
                    if (-not $existsP2C) { Upsert-Edge -Start $parent.id -Kind "SCCM_AdminsReplicatedTo" -End $sccmSiteNode.id }
                }
            }
        }

        # Update hierarchy identifiers (root site codes) after creating SCCM_AdminsReplicatedTo edges
        try {
            # Find all sites in this hierarchy using the new edges
            $sitesInHierarchy = @(Get-SitesInHierarchy -SiteCode $sccmSiteNode.id)
            
            if ($sitesInHierarchy -and $sitesInHierarchy.Count -gt 0) {
                # sccmSiteNode.identify the root site for this hierarchy
                $rootSiteNode = Get-HierarchyRoot -SiteCode $sccmSiteNode.id
                $rootSiteCode = if ($rootSiteNode) {
                    $rootSiteNode.id
                } else { 
                    Write-LogMessage Warning "Could not determine root site code for hierarchy containing site $($sccmSiteNode.id); using current site as root"
                    $sccmSiteNode.id
                }
                
                # Update rootSiteCode for all sites in this hierarchy
                foreach ($siteInHierarchy in $sitesInHierarchy) {
                    if (-not $siteInHierarchy.properties.ContainsKey("rootSiteCode") -or $siteInHierarchy.properties.rootSiteCode -ne $rootSiteCode) {
                        $siteInHierarchy.properties.rootSiteCode = $rootSiteCode
                        $siteCode = $siteInHierarchy.id
                        Write-LogMessage Verbose "Updated rootSiteCode to '$rootSiteCode' for site $siteCode"
                    }
                }
                
                # Update global object identifiers to use root site code
                Update-GlobalObjectIdentifiers -RootSiteCode $rootSiteCode
                
                Write-LogMessage Verbose "Hierarchy with root site '$rootSiteCode' now contains $($sitesInHierarchy.Count) sites"
            }
            # Create SCCM_Contains edges from each site to global objects in this hierarchy's root site
            $sccmCollectionNodesInHierarchy = $sccmCollectionNodes | Where-Object { $_.id -like "*@$rootSiteCode" }
            foreach ($sccmCollectionNode in $sccmCollectionNodesInHierarchy) {
                foreach ($siteInHierarchy in $sitesInHierarchy) {
                        if ($siteInHierarchy.Properties.siteType -ne "Secondary Site") {
                            Upsert-Edge -Start $siteInHierarchy.id -Kind "SCCM_Contains" -End $sccmCollectionNode.id -Properties @{
                            collectionSource = @("SCCM_Invoke-PostProcessing")
                        }
                    }
                }
            }

            $sccmSecurityRoleNodesInHierarchy = $sccmSecurityRoleNodes | Where-Object { $_.id -like "*@$rootSiteCode" }
            foreach ($sccmSecurityRoleNode in $sccmSecurityRoleNodesInHierarchy) {
                foreach ($siteInHierarchy in $sitesInHierarchy) {
                    if ($siteInHierarchy.Properties.siteType -ne "Secondary Site") {
                        Upsert-Edge -Start $siteInHierarchy.Id -Kind "SCCM_Contains" -End $sccmSecurityRoleNode.id -Properties @{
                            collectionSource = @("SCCM_Invoke-PostProcessing")
                        }
                    }
                }
            }

            $sccmAdminUserNodesInHierarchy = $sccmAdminUserNodes | Where-Object { $_.id -like "*@$rootSiteCode" }
            foreach ($sccmAdminUserNode in $sccmAdminUserNodesInHierarchy) {
                foreach ($siteInHierarchy in $sitesInHierarchy) {
                    if ($siteInHierarchy.Properties.siteType -ne "Secondary Site") {
                        Upsert-Edge -Start $siteInHierarchy.Id -Kind "SCCM_Contains" -End $sccmAdminUserNode.id -Properties @{
                            collectionSource = @("SCCM_Invoke-PostProcessing")
                        }
                    }
                }
            }
        } catch {
            Write-LogMessage Warning "Failed to update root site code for site $($sccmSiteNode.id): $_"
        }

        # Collect all root site nodes to loop through for edge creation between global objects and other nodes
        if ($rootSiteNode -and -not ($rootSiteNodes | Where-Object { $_.id -eq $rootSiteNode.id })) {
            $rootSiteNodes += $rootSiteNode
        }
    }

    # Re-fetch global object nodes after updating their identifiers
    $sccmAdminUserNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_AdminUser" })
    $sccmCollectionNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Collection" })
    $sccmSecurityRoleNodes = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_SecurityRole" })

    # Process nodes that occur once in each hierarchy
    foreach ($rootSite in $rootSiteNodes) {
        $rootSiteCode = $rootSite.id
        $sitesInHierarchy = Get-SitesInHierarchy -SiteCode $rootSiteCode -ExcludeSecondarySites

        # Process security roles
        $sccmSecurityRoleNodesInHierarchy = $sccmSecurityRoleNodes | Where-Object { $_.id -like "*@$($rootSite.id)" -or $_.Properties.sourceSiteCode -eq $rootSite.id }

        foreach ($securityRoleNode in $sccmSecurityRoleNodesInHierarchy) {

            Write-LogMessage Verbose "Processing role assignments for $($securityRoleNode.id) ($($securityRoleNode.Properties.name)) in hierarchy with root site $rootSiteCode"

            foreach ($adminUserId in $securityRoleNode.Properties.members) {

                # Account for duplicate objects created during global object identifier update -- BloodHound will merge on ObjectIdentifier
                $adminUserNode = $sccmAdminUserNodes | Where-Object { $_.id -eq $adminUserId } | Select-Object -First 1

                # Track whether admin has complete control of the hierarchy
                $adminIsFullAdministrator = $securityRoleNode.id -eq "SMS0001R@$($rootSiteCode)"
                $allSystemsAllObjectsAllUsersAndUserGroups = @()

                foreach ($collectionId in $adminUserNode.Properties.collectionIds) {

                    # Account for duplicate objects created during global object identifier update -- BloodHound will merge on ObjectIdentifier
                    $collection = @($sccmCollectionNodes | Where-Object { $_.id -eq $collectionId }) | Select-Object -First 1

                    if ($collection.Properties.name -eq "All Systems" -or $collection.Properties.name -eq "All Users and User Groups") {
                        $allSystemsAllObjectsAllUsersAndUserGroups += $collectionId
                    }

                    # Process collections of Type "Device" (0 = Other, 1 = User, 2 = Device)
                    if ($collection -and $collection.Properties.collectionType -eq 2) {

                        foreach ($clientDeviceResourceId in $collection.Properties.members) {

                            # Get SMSID of client device
                            $clientDevice = $sccmClientDeviceNodes | Where-Object { $_.Properties.resourceID -eq $clientDeviceResourceId }

                            if ($clientDevice) {
                                # SMS0001R (Full Administrator)
                                if ($securityRoleNode.id -eq "SMS0001R@$($rootSiteCode)") {
                                    Upsert-Edge -Start $adminUserId -Kind "SCCM_FullAdministrator" -End $clientDevice.id -Properties @{
                                        collectionSource = @("SCCM_Invoke-PostProcessing")
                                    }
                                }

                                # SMS0008R (Application Author)
                                elseif ($securityRoleNode.id -eq "SMS0008R@$($rootSiteCode)") {
                                    Upsert-Edge -Start $adminUserId -Kind "SCCM_ApplicationAuthor" -End $clientDevice.id -Properties @{
                                        collectionSource = @("SCCM_Invoke-PostProcessing")
                                    }
                                }

                                # SMS0009R (Application Administrator)
                                elseif ($securityRoleNode.id -eq "SMS0009R@$($rootSiteCode)") {
                                    Upsert-Edge -Start $adminUserId -Kind "SCCM_ApplicationAdministrator" -End $clientDevice.id -Properties @{
                                        collectionSource = @("SCCM_Invoke-PostProcessing")
                                    }
                                }

                                # SMS0006R (Compliance Settings Manager)
                                elseif ($securityRoleNode.id -eq "SMS0006R@$($rootSiteCode)") {
                                    Upsert-Edge -Start $adminUserId -Kind "SCCM_ComplianceSettingsManager" -End $clientDevice.id -Properties @{
                                        collectionSource = @("SCCM_Invoke-PostProcessing")
                                    }
                                }

                                # SMS000AR (Operating System Deployment Manager)
                                elseif ($securityRoleNode.id -eq "SMS000AR@$($rootSiteCode)") {
                                    Upsert-Edge -Start $adminUserId -Kind "SCCM_OSDManager" -End $clientDevice.id -Properties @{
                                        collectionSource = @("SCCM_Invoke-PostProcessing")
                                    }
                                }

                                # SMS000ER (Operations Administrator)
                                elseif ($securityRoleNode.id -eq "SMS000ER@$($rootSiteCode)") {
                                    Upsert-Edge -Start $adminUserId -Kind "SCCM_OperationsAdministrator" -End $clientDevice.id -Properties @{
                                        collectionSource = @("SCCM_Invoke-PostProcessing")
                                    }
                                }

                                # SMS000FR (Security Administrator)
                                elseif ($securityRoleNode.id -eq "SMS000FR@$($rootSiteCode)") {
                                    Upsert-Edge -Start $adminUserId -Kind "SCCM_SecurityAdministrator" -End $clientDevice.id -Properties @{
                                        collectionSource = @("SCCM_Invoke-PostProcessing")
                                    }
                                }

                                # Custom Security Roles
                                else {
                                    # Skip roles we don't have traversable edges to client devices for
                                    # https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/servers/configure/sms_admin-server-wmi-class
                                    #   SMS0002R - Read-Only Analyst
                                    #   SMS0003R - Remote Tools Operator
                                    #   SMS0004R - Asset Manager
                                    #   SMS0007R - Application Deployment Manager
                                    #   SMS000BR - Infrastructure Administrator
                                    #   SMS000CR - Software Update Manager
                                    #   SMS000GR - Endpoint Protection Manager
                                    #   SMS000HR - Company Resource Access Manager
                                    if ($securityRoleNode.id -notin @(
                                        "SMS0002R@$($rootSiteCode)",
                                        "SMS0004R@$($rootSiteCode)",
                                        "SMS0007R@$($rootSiteCode)",
                                        "SMS000BR@$($rootSiteCode)",
                                        "SMS000CR@$($rootSiteCode)",
                                        "SMS000GR@$($rootSiteCode)",
                                        "SMS000HR@$($rootSiteCode)"
                                    )) {
                                        Write-LogMessage Warning "Skipping custom security role $($securityRoleNode.id) ($($securityRoleNode.Properties.name)) for edge creation"
                                    }
                                }
                            } else {
                                Write-LogMessage Verbose "Could not find SCCM_ClientDevice node for resourceID $clientDeviceResourceId in collection $($collection.id) ($($collection.Properties.name))"
                            }
                        }
                    }
                }

                # Check if admin has complete control of the hierarchy
                if ($adminIsFullAdministrator -and $allSystemsAllObjectsAllUsersAndUserGroups.Count -ge 2) {
                    foreach ($siteInHierarchy in (Get-SitesInHierarchy -SiteCode $rootSiteCode -ExcludeSecondarySites)) {
                        Upsert-Edge -Start $adminUserId -Kind "SCCM_AllPermissions" -End $siteInHierarchy.id -Properties @{
                            collectionSource = @("SCCM_Invoke-PostProcessing")
                        }
                    }
                }
            }
        }
    }

    # Create SameHostAs edges for Computer/ClientDevice pairs
    Add-SameHostAsEdges -ComputerNodes $computerNodes -ClientDeviceNodes $sccmClientDeviceNodes

    # Process Computer nodes
    foreach ($computerNode in $computerNodes) {

        Write-LogMessage Verbose "Processing $($computerNode.id) ($($computerNode.Properties.name))"

        # Process site system roles
        if ($computerNode.Properties["SCCMSiteSystemRoles"]) {

            # Extract all unique site codes from SCCMSiteSystemRoles
            $siteCodes = @($computerNode.Properties["SCCMSiteSystemRoles"] | ForEach-Object {
                if ($_ -match '@(.+)$') {
                    $matches[1]
                }
            } | Select-Object -Unique)

            # Loop through each site this computer hosts roles for
            foreach ($siteCodeForSiteSystem in $siteCodes) {

                # Find the primary site for this site system
                if ($siteCodeForSiteSystem) {
                    $primarySiteForSiteSystem = $sccmSiteNodes | Where-Object { $_.Id -eq $siteCodeForSiteSystem -and $_.Type -ne "Secondary Site" }

                    # Add AdminTo edges from site servers to all the other site systems in primary sites (temporarily LocalAdminRequired due to lack of OpenGraph support for post-processed edges)
                    if ($primarySiteForSiteSystem) {
                        $siteServerComputerNodes = @($computerNodes | Where-Object { $_.properties.SCCMSiteSystemRoles -contains "SMS Site Server@$($primarySiteForSiteSystem.Id)" })
                        $siteDatabaseComputerNodes = @($computerNodes | Where-Object { $_.properties.SCCMSiteSystemRoles -contains "SMS SQL Server@$($primarySiteForSiteSystem.Id)" })

                        if ($siteServerComputerNodes -and $siteServerComputerNodes.Count -gt 0) {
                            foreach ($siteServerComputerNode in $siteServerComputerNodes) {

                                # Don't add AdminTo edges from the site server to the site server -- the computer account may not be in the local admins group
                                if ($computerNode.Id -ne $siteServerComputerNode.Id) {
                                        Upsert-Edge -Start $siteServerComputerNode.Id -Kind "LocalAdminRequired" -End $computerNode.Id -Properties @{
                                        collectionSource = @("SCCM_Invoke-PostProcessing")
                                    }

                                # If this is a primary site server, add AdminTo edges to all the other site systems 
                                } else {
                                    $siteSystems = @($computerNodes | Where-Object { $_.properties.SCCMSiteSystemRoles -like "*@$($primarySiteForSiteSystem.Id)" -and $_.properties.SCCMSiteSystemRoles -notlike "*SMS Site Server@$($primarySiteForSiteSystem.Id)*" })
                                    if ($siteSystems -and $siteSystems.Count -gt 0) {
                                        foreach ($siteSystem in $siteSystems) {
                                            if ($computerNode.Id -ne $siteSystem.Id) {
                                                    Upsert-Edge -Start $computerNode.Id -Kind "LocalAdminRequired" -End $siteSystem.Id -Properties @{
                                                    collectionSource = @("SCCM_Invoke-PostProcessing")
                                                }
                                            }        
                                        }
                                    }
                                }
                            }
                        }

                        # Primary site server and SMS Provider dnomain computer accounts have a MSSQL login in the site database
                        if ($computerNode.Properties["SCCMSiteSystemRoles"] -match "SMS (Site Server|Provider)@$($primarySiteForSiteSystem.Id)") {

                            if ($siteDatabaseComputerNodes -and $siteDatabaseComputerNodes.Count -gt 0) {
                                
                                # There could be multiple site database servers in a site (e.g. for high availability), so create edges to all of them
                                foreach ($siteDatabaseComputerNode in $siteDatabaseComputerNodes) {

                                    # Don't add MSSQL nodes/edges from the site database server to itself
                                    if ($computerNode.Id -ne $siteDatabaseComputerNode.Id) {

                                        Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer `
                                            -SiteNode $primarySiteForSiteSystem `
                                            -SiteDatabaseComputerNode $siteDatabaseComputerNode `
                                            -SysadminComputerNode $computerNode
                                    }
                                }
                            }
                        }

                        # If an SMS Provider domain computer account is being added, create SCCM_AssignAllPermissions edge to the site
                        if ($computerNode.Properties["SCCMSiteSystemRoles"] -like "*SMS Provider*") {

                            # Get all sites in this hierarchy
                            $sitesInHierarchy = @(Get-SitesInHierarchy -SiteCode $primarySiteForSiteSystem.Id -ExcludeSecondarySites)
                            foreach ($siteInHierarchy in $sitesInHierarchy) {
                                Upsert-Edge -Start $computerNode.Id -Kind "SCCM_AssignAllPermissions" -End $siteInHierarchy.Id -Properties @{
                                    collectionSource = @("SCCM_Invoke-PostProcessing")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    # Process Computer nodes again after site system roles are processed
    foreach ($computerNode in $computerNodes) {

        Write-LogMessage Verbose "Processing $($computerNode.id) ($($computerNode.Properties.name)) a second time"

        # Process site system roles
        if ($computerNode.Properties["SCCMSiteSystemRoles"]) {

            # Extract all unique site codes from SCCMSiteSystemRoles
            $siteCodes = @($computerNode.Properties["SCCMSiteSystemRoles"] | ForEach-Object {
                if ($_ -match '@(.+)$') {
                    $matches[1]
                }
            } | Select-Object -Unique)

            # Loop through each site this computer hosts roles for
            foreach ($siteCodeForSiteSystem in $siteCodes) {       

                # Find the primary site for this site system
                if ($siteCodeForSiteSystem) {
                    $primarySiteForSiteSystem = $sccmSiteNodes | Where-Object { $_.Id -eq $siteCodeForSiteSystem -and $_.Type -ne "Secondary Site" }

                    if ($primarySiteForSiteSystem) {

                        # Initialize the siteSystemRoles property if it doesn't exist
                        if (-not $primarySiteForSiteSystem.Properties.ContainsKey("siteSystemRoles")) {
                            $primarySiteForSiteSystem.Properties["siteSystemRoles"] = @()
                        }
                        
                        # Add the computer to the list if it's not already there
                        if ($computerNode.Properties.dNSHostName -notin $primarySiteForSiteSystem.Properties["siteSystemRoles"]) {
                            foreach ($role in $computerNode.Properties["SCCMSiteSystemRoles"] | Where-Object { $_ -like "*@$($primarySiteForSiteSystem.Id)" }) {
                                $primarySiteForSiteSystem.Properties["siteSystemRoles"] += "$($computerNode.Properties.dNSHostName): $role"
                            }
                            Write-LogMessage Verbose "Added $($computerNode.Properties.dNSHostName): $role to siteSystemRoles for site $siteCodeForSiteSystem"
                        }
                    }
                }
            }
        }
    }

    # Loop through sites again to process relay and MSSQL_GetTGS edges after MSSQL nodes are all created
    foreach ($sccmSiteNode in $sccmSiteNodes) {

        if ($sccmSiteNode.Type -ne "Secondary Site") {
            Write-LogMessage Verbose "Processing relay edges for site $($sccmSiteNode.id)"

            # Add CoerceAndRelayToAdminService edges for site servers and SMS Providers
            Process-CoerceAndRelayToAdminService -SiteCode $sccmSiteNode.Id -CollectionSource @("Post-processing")

            # Add CoerceAndRelayToMSSQL edges for site servers, site database servers, SMS Providers, and management points
            Process-CoerceAndRelayToMSSQL -SiteCode $sccmSiteNode.Id
            
            # Add CoerceAndRelayToSMB edges for all site system roles
        Process-CoerceAndRelayToSMB -SiteCode $sccmSiteNode.Id
        }
    
        # Get MSSQL_Server nodes for this site and add MSSQL_GetTGS edges from MSSQL service accounts to every server login
        $mssqlServerNodesInSite = @($mssqlServerNodes | Where-Object { $_.Properties.sccmSite -eq $sccmSiteNode.id })

        foreach ($mssqlServerNode in $mssqlServerNodesInSite) {

            # This could be a User or a Computer
            $siteDatabaseServiceAccountNode = @($script:Nodes | Where-Object { $_.id -eq $mssqlServerNode.Properties.SQLServiceAccountDomainSID })
            if ($siteDatabaseServiceAccountNode) {
                $loginNodesForMssqlServer = @($script:Nodes | Where-Object { $_.Kinds -contains "MSSQL_Login" -and $_.id -like "*@$($mssqlServerNode.id)" })

                foreach ($loginNode in $loginNodesForMssqlServer) {
                    Upsert-Edge -Start $siteDatabaseServiceAccountNode.id -Kind "MSSQL_GetTGS" -End $loginNode.Id -Properties @{
                        collectionSource = @("AdminService-SMS_SCI_SysResUse")
                    }
                }
            } else {
                Write-LogMessage Warning "Could not identify service account for $($mssqlServerNode.id), requires privileged collection (AdminService)"
            }
        }
    }
}

function Invoke-ProcessRoleAssignments {
    param(
        [PSCustomObject]$Node
    )

    # Extract commonly used fields from the node object
    $NodeId         = $Node.id
    $NodeKinds      = $Node.kinds
    $NodeProperties = $Node.properties

    # Incremental edge creation for security role assignments.
    # This is called every time one of the key kinds is upserted via Upsert-Node:
    #   - SCCM_SecurityRole
    #   - SCCM_AdminUser
    #   - SCCM_Collection
    #   - SCCM_ClientDevice

    # Only run if the node is one of the relevant SCCM kinds
    if (-not ($NodeKinds -contains "SCCM_SecurityRole" -or $NodeKinds -contains "SCCM_AdminUser" -or $NodeKinds -contains "SCCM_Collection" -or $NodeKinds -contains "SCCM_ClientDevice")) {
        return
    }

    Write-LogMessage Verbose "Incremental role assignment processing for node $NodeId (kinds: $($NodeKinds -join ', '))"

    # Identify the root site code
    $rootSiteCode = (Get-HierarchyRoot -SiteCode $NodeProperties.siteCode).id
    if (-not $rootSiteCode) {
        $rootSiteCode = (Get-HierarchyRoot -SiteCode $NodeProperties.sourceSiteCode).id
    }
    if (-not $rootSiteCode) {
        Write-LogMessage Warning "Could not determine root site code for node $NodeId; skipping role assignment processing"
        return
    }

    # Find security roles in the root site
    $securityRoles = @($script:Nodes | Where-Object {
        $_.Kinds -contains "SCCM_SecurityRole" -and
        $_.id -like "*@$($rootSiteCode)"
    })

    foreach ($securityRole in $securityRoles) {

        foreach ($adminUserId in $securityRole.Properties.members) {

            $adminUser = $script:Nodes | Where-Object { $_.id -eq $adminUserId -and $_.kinds -contains "SCCM_AdminUser" }

            foreach ($collectionId in $adminUser.Properties.collectionIds) {

                $collection = $script:Nodes | Where-Object { $_.id -eq $collectionId -and $_.kinds -contains "SCCM_Collection" }

                if ($collection) {

                    foreach ($clientDeviceResourceId in $collection.Properties.members) {

                        # Get SMSID of client device
                        $clientDevice = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_ClientDevice" -and $_.properties.resourceID -eq $clientDeviceResourceId }

                        # SMS0001R (Full Administrator)
                        if ($securityRole.Id -eq "SMS0001R@$($rootSiteCode)") {
                            Upsert-Edge -Start $adminUserId -Kind "SCCM_FullAdministrator" -End $clientDevice.id -Properties @{
                                collectionSource = $NodeProperties["collectionSource"]
                            }
                        }

                        # SMS0008R (Application Author)
                        elseif ($securityRole.Id -eq "SMS0008R@$($rootSiteCode)") {
                            Upsert-Edge -Start $adminUserId -Kind "SCCM_ApplicationAuthor" -End $clientDevice.id -Properties @{
                                collectionSource = $NodeProperties["collectionSource"]
                            }
                        }

                        # SMS0003R (Application Administrator)
                        elseif ($securityRole.Id -eq "SMS0003R@$($rootSiteCode)") {
                            Upsert-Edge -Start $adminUserId -Kind "SCCM_ApplicationAdministrator" -End $clientDevice.id -Properties @{
                                collectionSource = $NodeProperties["collectionSource"]
                            }
                        }

                        # SMS0006R (Compliance Settings Manager)
                        elseif ($securityRole.Id -eq "SMS0006R@$($rootSiteCode)") {
                            Upsert-Edge -Start $adminUserId -Kind "SCCM_ComplianceSettingsManager" -End $clientDevice.id -Properties @{
                                collectionSource = $NodeProperties["collectionSource"]
                            }
                        }

                        # SMS000AR (Operating System Deployment Manager)
                        elseif ($securityRole.Id -eq "SMS000AR@$($rootSiteCode)") {
                            Upsert-Edge -Start $adminUserId -Kind "SCCM_OSDManager" -End $clientDevice.id -Properties @{
                                collectionSource = $NodeProperties["collectionSource"]
                            }
                        }

                        # SMS000ER (Operations Administrator)
                        elseif ($securityRole.Id -eq "SMS000ER@$($rootSiteCode)") {
                            Upsert-Edge -Start $adminUserId -Kind "SCCM_OperationsAdministrator" -End $clientDevice.id -Properties @{
                                collectionSource = $NodeProperties["collectionSource"]
                            }
                        }

                        # SMS000FR (Security Administrator)
                        elseif ($securityRole.Id -eq "SMS000FR@$($rootSiteCode)") {
                            Upsert-Edge -Start $adminUserId -Kind "SCCM_SecurityAdministrator" -End $clientDevice.id -Properties @{
                                collectionSource = $NodeProperties["collectionSource"]
                            }
                        }

                        # Custom Security Roles
                        else {
                            
                        }
                    }
                }
            }
        }
    }
}

# Helper function to add edges during collection and processing
function Upsert-Edge {
    param(
        [string]$Start,
        [string]$Kind,
        [string]$End,
        [hashtable]$Properties = @{}
    )
    
    # Validate that both nodes exist
    if ([string]::IsNullOrWhiteSpace($Start) -or [string]::IsNullOrWhiteSpace($End)) {
        Write-LogMessage Warning "Cannot add edge '$Kind': start or end is null/empty"
        Write-LogMessage Warning "Start: $Start, End: $End"
        return
    }
    $startNode = $script:Nodes | Where-Object { $_.id -eq $Start }
    if (-not $startNode) {
        Write-LogMessage Warning ("Cannot add edge {0} -[{1}]-> {2}: start node not found" -f $Start, $Kind, $End)
        return
    }
    $endNode = $script:Nodes | Where-Object { $_.id -eq $End }
    if (-not $endNode) {
        Write-LogMessage Warning ("Cannot add edge {0} -[{1}]-> {2}: end node not found" -f $Start, $Kind, $End)
        return
    }

    # Check if edge already exists and merge properties if it does
    $existingEdge = $script:Edges | Where-Object { $_.start.value -eq $Start -and $_.kind -eq $Kind -and $_.end.value -eq $End }
    
    # Filter out null properties first
    $cleanProperties = @{}
    foreach ($key in $Properties.Keys) {
        if ($null -ne $Properties[$key]) {
            $cleanProperties[$key] = $Properties[$key]
        }
    }
    
    if ($existingEdge) {
        $existingProps = if ($existingEdge.properties) { $existingEdge.properties } else { @{} }
        
        # Check if properties are different - if so, merge them
        $hasNewProperties = $false
        $addedProperties = @()
        $updatedProperties = @()
        
        # Merge new properties into existing edge
        foreach ($key in $cleanProperties.Keys) {
            if ($existingProps.ContainsKey($key)) {
                $oldValue = $existingProps[$key]
                $newValue = $cleanProperties[$key]
                
                # Special handling for arrays - merge them
                if ($oldValue -is [Array] -and $newValue -is [Array]) {
                    # Combine and deduplicate arrays
                    $mergedArray = @(($oldValue + $newValue) | Where-Object { $_ -ne $null } | Select-Object -Unique)
                    $existingProps[$key] = $mergedArray
                    
                    # Update logging to show merge
                    $addedItems = $newValue | Where-Object { $_ -notin $oldValue }
                    if ($addedItems.Count -gt 0) {
                        $updatedProperties += "$key`: Added [$($addedItems -join ', ')] to existing [$($oldValue -join ', ')]"
                        $hasNewProperties = $true
                    }
                } else {
                    # Non-array properties - check if different and replace
                    if ($oldValue -ne $newValue) {
                        $updatedProperties += "$key`: '$oldValue' -> '$newValue'"
                        $hasNewProperties = $true
                    }
                    $existingProps[$key] = $newValue
                }
            } else {
                # New property being added
                $valueStr = if ($cleanProperties[$key] -is [Array]) { 
                    "[$($cleanProperties[$key] -join ', ')]" 
                } else { 
                    "'$($cleanProperties[$key])'" 
                }
                $addedProperties += "$key`: $valueStr"
                $existingProps[$key] = $cleanProperties[$key]
                $hasNewProperties = $true
            }
        }
        
        if ($hasNewProperties) {
            # Update existing edge properties
            $existingEdge.properties = $existingProps
            
            # Create verbose message showing what was added/updated
            $changes = @()
            if ($addedProperties.Count -gt 0) {
                $changes += "`n    Added:`n        $($addedProperties -join "`n        ")"
            }
            if ($updatedProperties.Count -gt 0) {
                $changes += "`n    Updated:`n        $($updatedProperties -join "`n        ")"
            }
            
            Write-LogMessage Verbose "Found existing edge $Start -[$Kind]-> $End, merged properties:$changes"
        } else {
            Write-LogMessage Verbose "Found existing edge $Start -[$Kind]-> $End with identical properties, no changes made"
        }
        
        return
    }

    # Create new edge
    $edge = @{
        start = @{ value = $Start }
        end = @{ value = $End }
        kind = $Kind
        properties = $cleanProperties
    }

    $traversableEdgeTypes = @(
        "AdminTo",
        "LocalAdminRequired",
        "CoerceAndRelayToAdminService",
        "CoerceAndRelayToMSSQL",
        "CoerceAndRelayNTLMtoSMB",
        "HasSession",
        "MSSQL_Contains",
        "MSSQL_ControlDB",
        "MSSQL_ControlServer",
        "MSSQL_ExecuteOnHost",
        "MSSQL_GetAdminTGS",
        "MSSQL_GetTGS",
        "MSSQL_HasLogin",
        "MSSQL_HostFor",
        "MSSQL_IsMappedTo",
        "MSSQL_MemberOf",
        #"MSSQL_ServiceAccountFor",
        "SameHostAs",
        "SCCM_AdminsReplicatedTo",
        "SCCM_AllPermissions",
        "SCCM_ApplicationAdministrator",
        "SCCM_AssignAllPermissions",
        #"SCCM_AssignSpecificPermissions",
        "SCCM_Contains",
        "SCCM_FullAdministrator",
        "SCCM_HasADLastLogonUser",
        "SCCM_HasClient",
        "SCCM_HasCurrentUser",
        #"SCCM_HasMember",
        "SCCM_HasPrimaryUser",
        #"SCCM_IsAssigned",
        "SCCM_IsMappedTo"
    )

    if ($traversableEdgeTypes -contains $edge.Kind) {
        $edge.properties["traversable"] = $true
    } else {
        $edge.properties["traversable"] = $false
    }
    
    $script:Edges += $edge
    Write-LogMessage Verbose "Added edge: $Start -[$Kind]-> $End (edge count: $($script:Edges.Count))"
}

function Add-SameHostAsEdges {
    param(
        [PSObject[]]$ComputerNodes,
        [PSObject[]]$ClientDeviceNodes
    )

    foreach ($computerNode in $ComputerNodes) {
        $computerId = $computerNode.Id
        $matchingClientDeviceNodes = @($ClientDeviceNodes | Where-Object { $_.Properties.ADDomainSID -eq $computerId })

        # Merge SCCM_ClientDevice nodes with the same dNSHostName
        if ($matchingClientDeviceNodes.Count -gt 1) {
            Write-LogMessage Warning "Multiple SCCM_ClientDevice nodes found with ADDomainSID $computerId; merging nodes"
            $primaryClientDeviceNode = $matchingClientDeviceNodes[0]
            for ($i = 1; $i -lt $matchingClientDeviceNodes.Count; $i++) {
                $duplicateNode = $matchingClientDeviceNodes[$i]

                # Merge properties
                foreach ($key in $duplicateNode.Properties.Keys) {
                    if ($primaryClientDeviceNode.Properties.ContainsKey($key)) {
                        # Merge arrays
                        if ($primaryClientDeviceNode.Properties[$key] -is [Array] -and $duplicateNode.Properties[$key] -is [Array]) {
                            $mergedArray = @(($primaryClientDeviceNode.Properties[$key] + $duplicateNode.Properties[$key]) | Where-Object { $_ -ne $null } | Select-Object -Unique)
                            $primaryClientDeviceNode.Properties[$key] = $mergedArray
                        }
                    } else {
                        # Add new property
                        $primaryClientDeviceNode.Properties[$key] = $duplicateNode.Properties[$key]
                    }
                }

                # Update edges to point to primary node
                foreach ($edge in $script:Edges) {
                    if ($edge.start.value -eq $duplicateNode.Id) {
                        $edge.start.value = $primaryClientDeviceNode.Id
                    }
                    if ($edge.end.value -eq $duplicateNode.Id) {
                        $edge.end.value = $primaryClientDeviceNode.Id
                    }
                }

                # Remove duplicate node
                $script:Nodes = $script:Nodes | Where-Object { $_.Id -ne $duplicateNode.Id }
                Write-LogMessage Verbose "Merged duplicate SCCM_ClientDevice node $($duplicateNode.Id) into $($primaryClientDeviceNode.Id)"
            }

            # Update matching nodes to only the primary node
            $matchingClientDeviceNodes = @($primaryClientDeviceNode)
        }

        foreach ($clientDeviceNode in $matchingClientDeviceNodes) {
            $clientDeviceId = $clientDeviceNode.Id

            # Create SameHostAs edges in both directions
            Upsert-Edge -Start $computerId -Kind "SameHostAs" -End $clientDeviceId
            Upsert-Edge -Start $clientDeviceId -Kind "SameHostAs" -End $computerId
        }
    }

}

function Add-HostNodeAndEdges{
    param(
        [string]$NodeId,
        [string[]]$NodeKinds,
        [hashtable]$NodeProperties
    )

    $matchingNode = $null   
    
    if ($NodeKinds -contains "Computer") {

        # Check if Host node already exists for this Computer SID
        if ($script:Nodes | Where-Object { $_.kinds -contains "Host" -and $_.Properties.computer -eq $NodeId }) {
            return  # Host already exists
        }

        # Look for SCCM_ClientDevice with ADDomainSID matching this Computer's ID
        $matchingNode = $script:Nodes | Where-Object { 
            $_.kinds -contains "SCCM_ClientDevice" -and 
            $_.properties.ADDomainSID -eq $NodeId 
        }
        
    } elseif ($NodeKinds -contains "SCCM_ClientDevice" -and $NodeProperties.ADDomainSID) {

        # Check if Host node already exists for this client device
        if ($script:Nodes | Where-Object { $_.kinds -contains "Host" -and $_.Properties.SCCMClientDevice -eq $NodeId }) {
            return  # Host already exists
        }
        # Look for Computer with ID matching this ClientDevice's ADDomainSID
        $matchingNode = $script:Nodes | Where-Object { 
            $_.kinds -contains "Computer" -and 
            $_.id -eq $NodeProperties.ADDomainSID
        }
    }

    if ($matchingNode) {
        # Generate Host node ID: DNSHostName_GUID
        if (-not $matchingNode.Properties.DNSHostName) {
            Write-LogMessage Warning "Cannot create Host node: DNSHostName property is missing"
            return
        }
        $hostGuid = [System.Guid]::NewGuid().ToString()
        $hostId = $matchingNode.Properties.DNSHostName
        
        $computerSid = if ($matchingNode.kinds -contains "Computer") { $matchingNode.id } else { $NodeId }
        $clientDeviceId = if ($matchingNode.kinds -contains "SCCM_ClientDevice") { $matchingNode.id } else { $NodeId }

        # Create Host node
        $null = Upsert-Node -Id $hostId -Kinds @("Host") -Properties @{
            name = $matchingNode.Properties.DNSHostName
            computer = $computerSid
            SCCMClientDevice = $clientDeviceId
        }

            # Create all four SameHostAs edges
        $edgesToCreate = @(
            @{Start = $computerSid; End = $hostId},      # Computer -> Host
            @{Start = $hostId; End = $computerSid},      # Host -> Computer
            @{Start = $clientDeviceId; End = $hostId},   # ClientDevice -> Host
            @{Start = $hostId; End = $clientDeviceId}    # Host -> ClientDevice
        )
        
        foreach ($edge in $edgesToCreate) {
            Upsert-Edge -Start $edge.Start -Kind "SameHostAs" -End $edge.End
        }
        
        Write-LogMessage Verbose "Created $computerSid <-[SameHostAs]-> $hostId <-[SameHostAs]-> $clientDeviceId nodes and edges"
    }
}

#region SCCM Hierarchy Functions

function Update-GlobalObjectIdentifiers {
    <#
    .SYNOPSIS
    Updates identifiers for globally configured SCCM objects to use root site code.
    
    .DESCRIPTION
    Updates SCCM_Collection, SCCM_AdminUser, and SCCM_SecurityRole node identifiers
    to use the root site code instead of the current site code, since these objects
    are configured at the hierarchy level.

    Don't worry about duplicates - BloodHound will merge on ObjectIdentifier.
    
    .PARAMETER RootSiteCode
    The root site code to use as the new suffix
    
    .EXAMPLE
    Update-GlobalObjectIdentifiers -RootSiteCode "CAS"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootSiteCode
    )
    
    $globalObjectKinds = @("SCCM_Collection", "SCCM_AdminUser", "SCCM_SecurityRole")

    foreach ($kind in $globalObjectKinds) {
        $globalObjects = @($script:Nodes | Where-Object { $_.kinds -contains $kind })

        foreach ($obj in $globalObjects) {
            # Check if the ID ends with a site code (format: ObjectId@SiteCode)
            if ($obj.id -match '^(.+)@([A-Z0-9]{3})$') {
                $objectBase = $matches[1]
                $currentSiteCode = $matches[2]
                $newId = "$objectBase@$RootSiteCode"

                # Only update if the site code is different
                if ($currentSiteCode -ne $RootSiteCode) {
                    Write-LogMessage Verbose "Updating $kind identifier: $($obj.id) -> $newId"

                    # Update the node ID
                    $oldId = $obj.id
                    $obj.id = $newId

                    # Update any edges that reference this node
                    $edgesToUpdate = @($script:Edges | Where-Object {
                        $_.start.value -eq $oldId -or $_.end.value -eq $oldId
                    })

                    foreach ($edge in $edgesToUpdate) {
                        if ($edge.start.value -eq $oldId) {
                            $edge.start.value = $newId
                        }
                        if ($edge.end.value -eq $oldId) {
                            $edge.end.value = $newId
                        }
                    }

                    Write-LogMessage Verbose "Updated $($edgesToUpdate.Count) edges referencing $kind $oldId"

                    # --- Also update identifiers stored in object properties ---

                    # SCCM_AdminUser.memberOf: array of SCCM_SecurityRole IDs
                    if ($kind -eq "SCCM_AdminUser" -and $obj.properties.memberOf) {
                        for ($i = 0; $i -lt $obj.properties.memberOf.Count; $i++) {
                            $memberOfId = $obj.properties.memberOf[$i]
                            if ($memberOfId -match '^(.+)@([A-Z0-9]{3})$') {
                                $memberOfBase = $matches[1]
                                $memberOfSite = $matches[2]
                                if ($memberOfSite -ne $RootSiteCode) {
                                    $newMemberOfId = "$memberOfBase@$RootSiteCode"
                                    Write-LogMessage Verbose "Updating SCCM_AdminUser.memberOf entry: $memberOfId -> $newMemberOfId"
                                    $obj.properties.memberOf[$i] = $newMemberOfId
                                }
                            }
                        }
                    }

                    # SCCM_AdminUser.collectionIds: array of SCCM_Collection IDs
                    if ($kind -eq "SCCM_AdminUser" -and $obj.properties.collectionIds) {
                        for ($i = 0; $i -lt $obj.properties.collectionIds.Count; $i++) {
                            $collectionId = $obj.properties.collectionIds[$i]
                            if ($collectionId -match '^(.+)@([A-Z0-9]{3})$') {
                                $collectionBase = $matches[1]
                                $collectionSite = $matches[2]
                                if ($collectionSite -ne $RootSiteCode) {
                                    $newCollectionId = "$collectionBase@$RootSiteCode"
                                    Write-LogMessage Verbose "Updating SCCM_AdminUser.collectionIds entry: $collectionId -> $newCollectionId"
                                    $obj.properties.collectionIds[$i] = $newCollectionId
                                }
                            }
                        }
                    }

                    # SCCM_SecurityRole.members: array of SCCM_AdminUser IDs
                    if ($kind -eq "SCCM_SecurityRole" -and $obj.properties.members) {
                        for ($i = 0; $i -lt $obj.properties.members.Count; $i++) {
                            $roleMemberId = $obj.properties.members[$i]
                            if ($roleMemberId -match '^(.+)@([A-Z0-9]{3})$') {
                                $roleMemberBase = $matches[1]
                                $roleMemberSite = $matches[2]
                                if ($roleMemberSite -ne $RootSiteCode) {
                                    $newRoleMemberId = "$roleMemberBase@$RootSiteCode"
                                    Write-LogMessage Verbose "Updating SCCM_SecurityRole.members entry: $roleMemberId -> $newRoleMemberId"
                                    $obj.properties.members[$i] = $newRoleMemberId
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

function Get-SitesInHierarchy {
    <#
    .SYNOPSIS
    Retrieves all SCCM sites that belong to the same hierarchy as the specified site.
    
    .DESCRIPTION
    Traverses SCCM_AdminsReplicatedTo edges to find all sites connected to the specified site,
    forming a complete hierarchy group. Returns all sites in the same hierarchy.
    
    .PARAMETER SiteCode
    The site code to start the hierarchy traversal from
    
    .PARAMETER SiteId  
    The site node ID to start the hierarchy traversal from
    
    .PARAMETER ExcludeSecondarySites
    When specified, excludes secondary sites from the results
    
    .EXAMPLE
    Get-SitesInHierarchy -SiteCode "PS1"
    
    .EXAMPLE
    Get-SitesInHierarchy -SiteCode "PS1" -ExcludeSecondarySites
    #>
    param(
        [Parameter(ParameterSetName="BySiteCode")]
        [string]$SiteCode,
        
        [Parameter(ParameterSetName="BySiteId")]
        [string]$SiteId,
        
        [switch]$ExcludeSecondarySites
    )
    
    # Find the starting site node
    $startSite = $null
    if ($SiteCode) {
        $startSite = $script:Nodes | Where-Object { 
            $_.kinds -contains "SCCM_Site" -and (
                $_.id -eq $SiteCode -or 
                $_.properties.siteCode -eq $SiteCode
            )
        } | Select-Object -First 1
    } elseif ($SiteId) {
        $startSite = $script:Nodes | Where-Object { 
            $_.kinds -contains "SCCM_Site" -and $_.id -eq $SiteId 
        } | Select-Object -First 1
    }
    
    if (-not $startSite) {
        Write-LogMessage Warning "Site not found: $(if($SiteCode) { $SiteCode } else { $SiteId })"
        return @()
    }
    
    # Use BFS to traverse all connected sites via SCCM_AdminsReplicatedTo edges
    $visited = @{}
    $queue = New-Object System.Collections.Queue
    $sitesInHierarchy = @()
    
    $queue.Enqueue($startSite.id)
    $visited[$startSite.id] = $true
    
    while ($queue.Count -gt 0) {
        $currentSiteId = $queue.Dequeue()
        $currentSite = $script:Nodes | Where-Object { $_.id -eq $currentSiteId } | Select-Object -First 1
        
        if ($currentSite) {
            $sitesInHierarchy += $currentSite
            
            # Find all SCCM_AdminsReplicatedTo edges from or to this site
            $sameAdminsEdges = $script:Edges | Where-Object {
                $_.kind -eq "SCCM_AdminsReplicatedTo" -and (
                    $_.start.value -eq $currentSiteId -or 
                    $_.end.value -eq $currentSiteId
                )
            }
            
            foreach ($edge in $sameAdminsEdges) {
                $connectedSiteId = if ($edge.start.value -eq $currentSiteId) { 
                    $edge.end.value 
                } else { 
                    $edge.start.value 
                }
                
                if (-not $visited.ContainsKey($connectedSiteId)) {
                    $connectedSite = $script:Nodes | Where-Object { 
                        $_.id -eq $connectedSiteId -and $_.kinds -contains "SCCM_Site" 
                    } | Select-Object -First 1
                    
                    if ($connectedSite) {
                        $visited[$connectedSiteId] = $true
                        $queue.Enqueue($connectedSiteId)
                    }
                }
            }
        }
    }
    
    # Filter out secondary sites if requested
    if ($ExcludeSecondarySites) {
        $sitesInHierarchy = @($sitesInHierarchy | Where-Object { 
            $_.properties.siteType -ne "Secondary Site" 
        })
    }
    
    # Force return as array to prevent PowerShell unwrapping single elements
    return $sitesInHierarchy
}

function Get-HierarchyRoot {
    <#
    .SYNOPSIS
    Finds the root site (CAS or primary without parent) for a given site's hierarchy.
    
    .DESCRIPTION
    Identifies the topmost site in a hierarchy - either a Central Administration Site (CAS)
    or a standalone Primary Site that has no parent.
    
    .PARAMETER SiteCode
    The site code to find the root for

    
    .EXAMPLE
    Get-HierarchyRoot -SiteCode "PS1"
    
    .EXAMPLE  
    Get-HierarchyRoot -SiteCode "PS1"
    #>
    param(
        [Parameter(ParameterSetName="BySiteCode")]
        [string]$SiteCode
    )
    
    $sitesInHierarchy = if ($SiteCode) {
        Get-SitesInHierarchy -SiteCode $SiteCode
    }
    
    if (-not $sitesInHierarchy -or $sitesInHierarchy.Count -eq 0) {
        return $null
    }
    
    # Look for CAS first
    $casSites = @($sitesInHierarchy | Where-Object { 
        $_.properties.siteType -eq "Central Administration Site" 
    })
    
    if ($casSites -and $casSites.Count -gt 0) {
        return $casSites[0]
    }
    
    # If no CAS, look for primary site with no parent or parent "None"
    $rootPrimarySites = @($sitesInHierarchy | Where-Object { 
        $_.properties.siteType -eq "Primary Site" -and (
            -not $_.properties.parentSiteCode -or 
            $_.properties.parentSiteCode -eq "" -or 
            $_.properties.parentSiteCode -eq "None"
        )
    })
    
    if ($rootPrimarySites -and $rootPrimarySites.Count -gt 0) {
        return $rootPrimarySites[0]
    }
    
    # Fallback: return the first primary site found
    $primarySites = @($sitesInHierarchy | Where-Object { 
        $_.properties.siteType -eq "Primary Site" 
    })
    
    return $(if ($primarySites -and $primarySites.Count -gt 0) { $primarySites[0] } else { $null })
}

function Get-AllHierarchies {
    <#
    .SYNOPSIS
    Groups all SCCM sites into their respective hierarchies.
    
    .DESCRIPTION
    Returns a hashtable where each key is a hierarchy identifier (root site code) 
    and each value is an array of all sites in that hierarchy.
    
    .EXAMPLE
    $hierarchies = Get-AllHierarchies
    foreach ($rootSiteCode in $hierarchies.Keys) {
        Write-Host "Hierarchy $rootSiteCode has $($hierarchies[$rootSiteCode].Count) sites"
    }
    #>
    param()
    
    $allSccmSites = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Site" }
    $processedSites = @{}
    $hierarchies = @{}
    
    foreach ($site in $allSccmSites) {
        if ($processedSites.ContainsKey($site.id)) {
            continue
        }
        
        # Get all sites in this hierarchy
        $sitesInHierarchy = Get-SitesInHierarchy -SiteCode $site.id
        
        # Find the root site for this hierarchy
        $rootSite = Get-HierarchyRoot -SiteCode $site.id
        $rootSiteCode = if ($rootSite) { 
            $rootSite.properties.siteCode -or $rootSite.id 
        } else { 
            $site.properties.siteCode -or $site.id 
        }
        
        # Store the hierarchy
        $hierarchies[$rootSiteCode] = $sitesInHierarchy
        
        # Mark all sites in this hierarchy as processed
        foreach ($siteInHierarchy in $sitesInHierarchy) {
            $processedSites[$siteInHierarchy.id] = $true
        }
    }
    
    return $hierarchies
}

function Add-RootSiteCodes {
    <#
    .SYNOPSIS
    Adds rootSiteCode properties to all SCCM_Site nodes for easier grouping.
    
    .DESCRIPTION
    Analyzes all SCCM sites and adds a rootSiteCode property to each site node,
    making it easier to group and filter sites by hierarchy.
    
    .EXAMPLE
    Add-RootSiteCodes
    #>
    param()
    
    $hierarchies = Get-AllHierarchies
    
    foreach ($rootSiteCode in $hierarchies.Keys) {
        $sitesInHierarchy = $hierarchies[$rootSiteCode]
        
        foreach ($site in $sitesInHierarchy) {
            # Add rootSiteCode property if it doesn't exist
            if (-not $site.properties.ContainsKey("rootSiteCode")) {
                $site.properties.rootSiteCode = $rootSiteCode
                Write-LogMessage Verbose "Added rootSiteCode '$rootSiteCode' to site $($site.properties.siteCode -or $site.id)"
            }
        }
    }
    
    Write-LogMessage Success "Added hierarchy identifiers (root site codes) to $($hierarchies.Keys.Count) hierarchies"
}

function Get-SitesByHierarchy {
    <#
    .SYNOPSIS
    Returns sites grouped by hierarchy, using rootSiteCode properties if available.
    
    .DESCRIPTION
    Groups SCCM sites by their rootSiteCode property. If rootSiteCode properties don't exist,
    automatically calculates hierarchies using SCCM_AdminsReplicatedTo edges.
    
    .EXAMPLE
    $hierarchies = Get-SitesByHierarchy
    foreach ($rootSiteCode in $hierarchies.Keys) {
        Write-Host "=== Hierarchy: $rootSiteCode ==="
        foreach ($site in $hierarchies[$rootSiteCode]) {
            Write-Host "  Site: $($site.properties.siteCode) ($($site.properties.siteType))"
        }
    }
    #>
    param()
    
    $allSccmSites = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Site" }
    
    # Check if rootSiteCode properties exist
    $sitesWithRootSiteCode = $allSccmSites | Where-Object { 
        $_.properties.ContainsKey("rootSiteCode") -and 
        $_.properties.rootSiteCode 
    }
    
    if ($sitesWithRootSiteCode.Count -eq $allSccmSites.Count) {
        # All sites have rootSiteCode - use existing properties
        $hierarchies = @{}
        foreach ($site in $allSccmSites) {
            $rootSiteCode = $site.properties.rootSiteCode
            if (-not $hierarchies.ContainsKey($rootSiteCode)) {
                $hierarchies[$rootSiteCode] = @()
            }
            $hierarchies[$rootSiteCode] += $site
        }
        return $hierarchies
    } else {
        # Calculate hierarchies dynamically
        Write-LogMessage Verbose "Calculating hierarchies dynamically (rootSiteCode properties missing)"
        return Get-AllHierarchies
    }
}
#endregion

#region Collection Functions
function Get-MssqlEpaSettingsViaRemoteRegistry {
    param(
        [Parameter(Mandatory = $true)][string]$SqlServerHostname,
        [string[]]$CollectionSource = @("Unknown")
    )

    try {
        Write-LogMessage Info "Collecting MSSQL EPA settings from $SqlServerHostname via Remote Registry"
        
        # Try multiple default registry paths for MSSQL instances
        # These correspond to SQL Server versions: 2012+ (v11+) use MSSQL versions
        $regPaths = @(
            "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2022
            "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2019
            "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2017
            "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2016
            "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2014
            "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2012
            "SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.1\MSSQLServer\SuperSocketNetLib",              # Older versions / default fallback
            "SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib"                                # Legacy path
        )
        
        $forceEncryption = $null
        $extendedProtection = $null
        $regPathFound = $null
        $restrictReceivingNtlmTraffic = $null
        $disableLoopbackCheck = $null

        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $SqlServerHostname)
            
            # Try each registry path until one succeeds
            foreach ($regPath in $regPaths) {
                $regKey = $reg.OpenSubKey($regPath)
                
                if ($regKey) {
                    $regPathFound = $regPath
                    Write-LogMessage Verbose "Found MSSQL registry path: $regPath"
                    
                    # Check ForceEncryption
                    $forceSetting = $regKey.GetValue("ForceEncryption")
                    if ($forceSetting -eq 1) {
                        $forceEncryption = "Yes"
                    } else {
                        $forceEncryption = "No"
                    }
                    
                    # Check ExtendedProtection
                    $epSetting = $regKey.GetValue("ExtendedProtection")
                    if ($epSetting -eq 1) {
                        $extendedProtection = "Allowed"
                    }
                    elseif ($epSetting -eq 2) {
                        $extendedProtection = "Required"
                    }
                    elseif ($epSetting -eq 0) {
                        $extendedProtection = "Off"
                    }
                    
                    $regKey.Close()
                    Write-LogMessage Success "Collected EPA settings from $SqlServerHostname`: ForceEncryption=$forceEncryption, ExtendedProtection=$extendedProtection (Path: $regPathFound)"
                    break
                }
            }
            
            if (-not $regPathFound) {
                Write-LogMessage Warning "Could not access any MSSQL registry paths on $SqlServerHostname. Tried: $($regPaths -join ', ')"
            }
            
            # Check NTLM restriction setting
            try {
                $ntlmRegPath = "SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
                $ntlmRegKey = $reg.OpenSubKey($ntlmRegPath)
                if ($ntlmRegKey) {
                    $ntlmValue = $ntlmRegKey.GetValue("RestrictReceivingNtlmTraffic")
                    if ($null -ne $ntlmValue) {
                        if ($ntlmValue -eq 0) {
                            $restrictReceivingNtlmTraffic = "Off"
                        }
                        elseif ($ntlmValue -eq 1) {
                            $restrictReceivingNtlmTraffic = "Deny_All"
                        }
                        elseif ($ntlmValue -eq 2) {
                            $restrictReceivingNtlmTraffic = "Deny_Inbound_Explicit"
                        }
                        else {
                            $restrictReceivingNtlmTraffic = "Unknown ($ntlmValue)"
                        }
                        Write-LogMessage Verbose "Found RestrictReceivingNtlmTraffic setting on $SqlServerHostname`: $restrictReceivingNtlmTraffic"
                    } else {
                        Write-LogMessage Verbose "RestrictReceivingNtlmTraffic value not found on $SqlServerHostname (default: Off)"
                        $restrictReceivingNtlmTraffic = "Off"
                    }
                    $ntlmRegKey.Close()
                } else {
                    Write-LogMessage Verbose "Could not access MSV1_0 registry path on $SqlServerHostname"
                }
            }
            catch {
                Write-LogMessage Warning "Error checking RestrictReceivingNtlmTraffic on $SqlServerHostname`: $($_.Exception.Message)"
            }

            # Check DisableLoopbackCheck setting
            try {
                $loopbackRegPath = "SYSTEM\CurrentControlSet\Control\Lsa"
                $loopbackRegKey = $reg.OpenSubKey($loopbackRegPath)
                if ($loopbackRegKey) {
                    $loopbackValue = $loopbackRegKey.GetValue("DisableLoopbackCheck")
                    if ($null -ne $loopbackValue) {
                        if ($loopbackValue -eq 0) {
                            $disableLoopbackCheck = "Enabled"
                        }
                        elseif ($loopbackValue -eq 1) {
                            $disableLoopbackCheck = "Disabled"
                        }
                        else {
                            $disableLoopbackCheck = "Unknown ($loopbackValue)"
                        }
                        Write-LogMessage Verbose "Found DisableLoopbackCheck setting on $SqlServerHostname`: $disableLoopbackCheck"
                    } else {
                        Write-LogMessage Verbose "DisableLoopbackCheck value not found on $SqlServerHostname (default: Enabled)"
                        $disableLoopbackCheck = "Enabled"
                    }
                    $loopbackRegKey.Close()
                } else {
                    Write-LogMessage Verbose "Could not access LSA registry path on $SqlServerHostname"
                }
            }
            catch {
                Write-LogMessage Warning "Error checking DisableLoopbackCheck on $SqlServerHostname`: $($_.Exception.Message)"
            }
            
            $reg.Close()
        }
        catch {
            Write-LogMessage Error "Error accessing registry on $SqlServerHostname`: $($_.Exception.Message)"
        }

        return @{
            ForceEncryption = $forceEncryption
            ExtendedProtection = $extendedProtection
            RestrictReceivingNtlmTraffic = $restrictReceivingNtlmTraffic
            DisableLoopbackCheck = $disableLoopbackCheck
            RegistryPath = $regPathFound
            CollectionSource = $CollectionSource
        }
    }
    catch {
        Write-LogMessage Error "Failed to collect MSSQL EPA settings from $SqlServerHostname`: $_"
        return $null
    }
}

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
                        distinguishedName = $result.Properties["distinguishedName"][0]
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
            
            # Create/update SCCM_Site node
            $null = Upsert-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                collectionSource = @("LDAP-mSSMSSite")
                displayName = $null
                distinguishedName = $mSSMSSiteObj.DistinguishedName
                parentSiteCode = $null # Will be determined by mSSMSManagementPoint
                SCCMInfra = $true
                siteCode = $siteCode
                siteGUID = $siteGuid
                siteServerDomainSID = $null
                siteServerName = $null
                siteType = $null # Will be determined by mSSMSManagementPoint
                sourceForest = $mSSMSSiteObj.mSSMSSourceForest
                SQLDatabaseName = $null
                SQLServerDomainSID = $null
                SQLServerName = $null
                SQLServiceAccountDomainSID = $null
                SQLServiceAccountName = $null
            }
        }
        
        # Get all mSSMSManagementPoint objects
        Write-LogMessage Info "Collecting mSSMSManagementPoint objects..."
        $mSSMSManagementPoints = @()
        
        if ($script:ADModuleAvailable) {
            $mSSMSManagementPoints = Get-ADObject -LDAPFilter "(objectClass=mSSMSManagementPoint)" -SearchBase $systemManagementDN -Properties mSSMSMPName, mSSMSSiteCode, mSSMSCapabilities -ErrorAction SilentlyContinue
        } else {
            try {
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$systemManagementDN")
                $searcher.Filter = "(objectClass=mSSMSManagementPoint)"
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
                $mpTarget = Add-DeviceToTargets -DeviceName $mpHostname -Source "LDAP-mSSMSManagementPoint" -SiteCode $mpSiteCode
                if ($mpTarget -and $mpTarget.IsNew) {
                    Write-LogMessage Success "Found management point: $($mpTarget.Hostname) (site: $mpSiteCode)"
                }
                # Create or update Computer node
                if ($mpTarget.ADObject) {
                    $null = Upsert-Node -Id $mpTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $mpTarget.ADObject -Properties @{
                        collectionSource = @("LDAP-mSSMSManagementPoint")
                        name = $mpTarget.ADObject.samAccountName
                        SCCMSiteSystemRoles = @("SMS Management Point@$mpSiteCode")
                    }
                }
            }
            
            $sourceForest = $null
            $commandLineSiteCode = $null
            $rootSiteCode = $null

            # Parse capabilities to determine site relationships and extract sourceForest
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

                # Check if this MP's CommandLine site code matches the site code we're analyzing
                if ($commandLineSiteCode -eq $mpSiteCode) {
                    # Primary Site: mSSMSManagementPoint exists where CommandLine.SMSSITECODE = this site code
                    $siteType = "Primary Site"
                    
                    # Check if there's a different root site code (indicates hierarchy)
                    if ($rootSiteCode -and $rootSiteCode -ne $mpSiteCode) {
                        $parentSiteCode = $rootSiteCode
                    } else {
                        $parentSiteCode = "None"
                    }
                }
                elseif ($rootSiteCode -eq $mpSiteCode -and $commandLineSiteCode -ne $mpSiteCode) {
                    # Central Administration Site: mSSMSManagementPoint exists where RootSiteCode = this site code
                    # but CommandLine.SMSSITECODE is different
                    $siteType = "Central Administration Site"
                    $parentSiteCode = "None"
                }
                # If neither condition above is met, it remains "Secondary Site"
                
                # Update existing SCCM_Site node with MP-derived information
                $existingSiteNode = $script:Nodes | Where-Object { $_.id -eq $mpSiteCode }
                if ($existingSiteNode) {
                    $existingSiteNode.properties.siteType = $siteType
                    $existingSiteNode.properties.parentSiteCode = $parentSiteCode
                    if ($sourceForest) {
                        $existingSiteNode.properties.sourceForest = $sourceForest
                    }
                    
                    # Add MP as collection source
                    if ($existingSiteNode.properties.collectionSource -notcontains "LDAP-mSSMSManagementPoint") {
                        $existingSiteNode.properties.collectionSource += "LDAP-mSSMSManagementPoint"
                    }
                    
                    Write-LogMessage Verbose "Updated site type for $($mpSiteCode): $siteType"
                }

                $null = Upsert-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                    collectionSource = @("LDAP-mSSMSManagementPoint")
                    parentSiteCode = $parentSiteCode
                    SCCMInfra = $true
                    siteCode = $siteCode
                    siteType = $siteType
                }

                # Create parent CAS site node if it doesn't exist and we found one
                if ($parentSiteCode -and $parentSiteCode -ne "None") {
                    $null = Upsert-Node -Id $parentSiteCode -Kinds @("SCCM_Site") -Properties @{
                        collectionSource = @("LDAP-mSSMSManagementPoint")
                        displayName = $null
                        distinguishedName = $null
                        parentSiteCode = "None"
                        SCCMInfra = $true
                        siteCode = $parentSiteCode
                        siteGUID = $null
                        siteServerDomainSID = $null
                        siteServerName = $null
                        siteType = "Central Administration Site"
                        sourceForest = $sourceForest
                        SQLDatabaseName = $null
                        SQLServerName = $null
                        SQLServerDomainSID = $null
                        SQLServiceAccountName = $null
                        SQLServiceAccountDomainSID = $null
                    }
                    Write-LogMessage Success "Found central administration site: $parentSiteCode"
                }
                
                # Parse for fallback status points and create Computer nodes
                if ($fspNodes = $capabilities.ClientOperationalSettings.FSP) {
                    $fspNodes = $capabilities.ClientOperationalSettings.FSP.SelectNodes("FSPServer")
                    foreach ($fsp in $fspNodes) {
                        $fspHostname = $fsp.InnerText
                        $fspTarget = Add-DeviceToTargets -DeviceName $fspHostname -Source "LDAP-mSSMSManagementPoint" -SiteCode $siteCode
        
                        if ($fspTarget -and $fspTarget.IsNew) {
                            Write-LogMessage Success "Found fallback status point: $($fspTarget.Hostname)"                          
                        }
                        # Create or update Computer node
                        if ($fspTarget.ADObject) {
                            $null = Upsert-Node -Id $fspTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $fspTarget.ADObject -Properties @{
                                collectionSource = @("LDAP-mSSMSManagementPoint")
                                name = $fspTarget.ADObject.samAccountName
                                SCCMSiteSystemRoles = @("SMS Fallback Status Point@$siteCode")
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
                        name = $result.Properties["name"][0]
                        CN = $result.Properties["cn"][0]
                        distinguishedName = $result.Properties["distinguishedname"][0]
                        DNSHostName = $result.Properties["dnshostname"][0]
                        domain = $result.Properties["domain"]
                        objectClass = $result.Properties["objectclass"]
                        objectSid = @{ Value = $sid.Value }
                        samAccountName = $result.Properties["samAccountName"]
                        servicePrincipalName = $result.Properties["serviceprincipalname"]
                    }
                }
            } catch {
                Write-LogMessage Warning "DirectorySearcher failed for CmRcService SPN objects: $_"
            }
        }

        if ($remoteControlSystems.Count -gt 0) {

            # Get the first primary site code published to AD -- this could very well be wrong in multi-site environments, but it should be in the same hierarchy
            $siteCode = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Site" -and $_.properties.siteType -eq "Primary Site" } | Select-Object -First 1 | ForEach-Object { $_.id }

            foreach ($system in $remoteControlSystems) {

                Write-LogMessage Success "Found computer with Remote Control SPN: $($system.DNSHostName)"

                # Create Computer node for these systems
                if ($system.ObjectSid) {
                    $null = Upsert-Node -Id $system.ObjectSid.Value -Kinds @("Computer", "Base") -PSObject $system -Properties @{
                        collectionSource = @("LDAP-CmRcService")
                        name = $system.Name
                        SCCMHasClientRemoteControlSPN = $true
                    }

                    # Make SCCM_ClientDevice node and link to Computer node if requested
                    if (-not $DisablePossibleEdges) {

                        # Generate GUID for SCCM Client node (may produce duplicates if client devices are enumerated later)
                        $sccmClientId = [Guid]::NewGuid().ToString()

                        $null = Upsert-Node -Id $sccmClientId -Kinds @("SCCM_ClientDevice") -PSObject $system -Properties @{
                            collectionSource = @("LDAP-CmRcService")
                            ADDomainSID = $system.ObjectSid.Value
                            name = "$($system.Name)@$($siteCode)"
                            siteCode = $siteCode
                            SMSID = "Not yet collected"
                        }

                        # Create edge from site to client device
                        Upsert-Edge -Start $siteCode -Kind "SCCM_HasClient" -End $sccmClientId -Properties @{
                            collectionSource = @("LDAP-CmRcService")
                        }
                    }
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
                $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
                
                $results = $searcher.FindAll()
                foreach ($result in $results) {
                    $networkBootServers += [PSCustomObject]@{
                        distinguishedName = $result.Properties["distinguishedname"][0]
                        ObjectClass = "connectionPoint"
                    }
                }
                
                # Search for intellimirrorSCP objects
                $searcher.Filter = "(objectclass=intellimirrorSCP)"
                $searcher.PropertiesToLoad.Clear()
                $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
                
                $results = $searcher.FindAll()
                foreach ($result in $results) {
                    $networkBootServers += [PSCustomObject]@{
                        distinguishedName = $result.Properties["distinguishedname"][0]
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
                            name = if ($parentEntry.Properties["name"].Count -gt 0) { $parentEntry.Properties["name"][0] } else { $null }
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
                        
                        $null = Upsert-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                            collectionSource = @("LDAP-$($server.ObjectClass)")
                            name = $collectionTarget.ADObject.samAccountName
                            networkBootServer = $true
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
                    $null = Upsert-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                        collectionSource = @("LDAP-NamePattern")
                        name = $collectionTarget.ADObject.samAccountName
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
                    $adObject = Resolve-PrincipalInDomain -Name $accountName -Domain $script:Domain
                    
                    if ($adObject -and $adObject.SID) {
                        Write-LogMessage Verbose "Resolved principal to $($adObject.Type): $($adObject.Name) ($($adObject.SID))"
                        
                        # Create appropriate node based on object type
                        switch ($adObject.Type) {
                            "Computer" {                                
                                $null = Upsert-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                                    collectionSource = @("LDAP-GenericAllSystemManagement")
                                    name = $adObject.samAccountName
                                }
                                
                                # Add to collection targets for subsequent collection phases
                                if ($adObject.DNSHostName) {
                                    $null = Add-DeviceToTargets -DeviceName $adObject.DNSHostName -Source "LDAP-GenericAll"
                                } else {
                                    $null = Add-DeviceToTargets -DeviceName $accountName -Source "LDAP-GenericAll"
                                }
                            }
                            
                            "User" {
                                $null = Upsert-Node -Id $adObject.SID -Kinds @("User", "Base") -PSObject $adObject -Properties @{
                                    collectionSource = @("LDAP-GenericAllSystemManagement")
                                    name = $adObject.samAccountName
                                }
                            }
                            
                            "Group" {                              
                                $null = Upsert-Node -Id $adObject.SID -Kinds @("Group", "Base") -PSObject $adObject -Properties @{
                                    collectionSource = @("LDAP-GenericAllSystemManagement")
                                    name = $adObject.samAccountName
                                }
                            }
                            
                            default {
                                # Handle unknown object types
                                $null = Upsert-Node -Id $adObject.SID -Kinds @($adObject.Type, "Base") -PSObject $adObject -Properties @{
                                    collectionSource = @("LDAP-GenericAllSystemManagement")
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
                            $adObject = Resolve-PrincipalInDomain -Name $accountName -Domain $script:Domain
                            
                            if ($adObject -and $adObject.SID) {
                                Write-LogMessage Verbose "Resolved principal to $($adObject.Type): $($adObject.Name) ($($adObject.SID))"
                                
                                # Create appropriate node based on object type (same switch logic as above)
                                switch ($adObject.Type) {
                                    "Computer" {
                                        $null = Upsert-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                                            collectionSource = @("LDAP-GenericAllSystemManagement")
                                            name = $adObject.samAccountName
                                        }
                                        
                                        # Add to collection targets for subsequent collection phases
                                        if ($adObject.DNSHostName) {
                                            $null = Add-DeviceToTargets -DeviceName $adObject.DNSHostName -Source "LDAP-GenericAll"
                                        } else {
                                            $null = Add-DeviceToTargets -DeviceName $accountName -Source "LDAP-GenericAll"
                                        }
                                    }
                                    
                                    "User" {
                                        $null = Upsert-Node -Id $adObject.SID -Kinds @("User", "Base") -PSObject $adObject -Properties @{
                                            collectionSource = @("LDAP-GenericAllSystemManagement")
                                            name = $adObject.samAccountName
                                        }
                                    }
                                    
                                    "Group" {
                                        $null = Upsert-Node -Id $adObject.SID -Kinds @("Group", "Base") -PSObject $adObject -Properties @{
                                            collectionSource = @("LDAP-GenericAllSystemManagement")
                                            name = $adObject.samAccountName
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
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.dNSHostName) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
        Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
    } catch {
        Write-LogMessage Error "LDAP collection failed: $_"
    }
}

function Invoke-DHCPCollection {
    Write-LogMessage Info "Starting DHCP collection..."
    try {
        # Helper: TFTP reachability test (send RRQ and accept ERROR or DATA)
        function Test-TftpReachable {
            param([string]$TftpHost, [string]$File = "pxecheck.bin", [int]$TimeoutMs = 1500)
            try {
                $udp = New-Object System.Net.Sockets.UdpClient
                $endp = New-Object System.Net.IPEndPoint(([System.Net.Dns]::GetHostAddresses($TftpHost) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1),69)
                if (-not $endp) { return $false }
                # RRQ: [0x00,0x01] + filename + 0x00 + 'octet' + 0x00
                $fn = [System.Text.Encoding]::ASCII.GetBytes($File)
                $mode = [System.Text.Encoding]::ASCII.GetBytes('octet')
                $payload = New-Object System.IO.MemoryStream
                $bw = New-Object System.IO.BinaryWriter($payload)
                $bw.Write([byte]0); $bw.Write([byte]1)
                $bw.Write($fn); $bw.Write([byte]0)
                $bw.Write($mode); $bw.Write([byte]0)
                $bw.Flush()
                $bytes = $payload.ToArray(); $bw.Dispose(); $payload.Dispose()
                [void]$udp.Send($bytes,$bytes.Length,$endp)
                $udp.Client.ReceiveTimeout = $TimeoutMs
                try { $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0); $null = $udp.Receive([ref]$remote); $udp.Close(); return $true } catch { $udp.Close(); return $false }
            } catch { return $false }
        }

        # Helper: robust option 66 decode (string or IPv4 bytes)
        function Convert-Opt66ToHost {
            param([byte[]]$Val)
            if (-not $Val) { return $null }
            if ($Val.Length -eq 4) {
                try { return (New-Object System.Net.IPAddress -ArgumentList $Val).ToString() } catch { }
            }
            try { return [System.Text.Encoding]::ASCII.GetString($Val) } catch { return $null }
        }

        # Build PXE-oriented DHCPINFORM (port 4011) and parse replies
        # 1) Get MAC
        $mac = [byte[]](0,0,0,0,0,0)
        $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' }
        foreach ($n in $nics) {
            $bytes = $n.GetPhysicalAddress().GetAddressBytes()
            if ($bytes.Length -eq 6) { $mac = $bytes; break }
        }

        # 2) Create BOOTP header (236 bytes)
        $ms = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ms)
        $rand = New-Object System.Random
        $xidBuf = New-Object byte[] 4; $rand.NextBytes($xidBuf)
        $bw.Write([byte]1)  # op
        $bw.Write([byte]1)  # htype
        $bw.Write([byte]6)  # hlen
        $bw.Write([byte]0)  # hops
        $bw.Write($xidBuf)  # xid (acceptable for our purposes)
        $bw.Write([byte[]](0,0)) # secs
        $bw.Write([byte[]](0x80,0x00)) # flags: broadcast
        $bw.Write([byte[]](0,0,0,0)) # ciaddr
        $bw.Write([byte[]](0,0,0,0)) # yiaddr
        $bw.Write([byte[]](0,0,0,0)) # siaddr
        $bw.Write([byte[]](0,0,0,0)) # giaddr
        $chaddr = New-Object byte[] 16
        [Array]::Copy($mac,0,$chaddr,0,6)
        $bw.Write($chaddr)           # chaddr
        $bw.Write((New-Object byte[] 64))  # sname
        $bw.Write((New-Object byte[] 128)) # file
        # magic cookie
        $bw.Write([byte[]](99,130,83,99))
        # options: 53=Inform, 60='PXEClient', 55=request (60,66,67)
        $bw.Write([byte]53); $bw.Write([byte]1); $bw.Write([byte]8)
        $vendor = [System.Text.Encoding]::ASCII.GetBytes('PXEClient')
        $bw.Write([byte]60); $bw.Write([byte]$vendor.Length); $bw.Write($vendor)
        $bw.Write([byte]55); $bw.Write([byte]3); $bw.Write([byte[]](60,66,67))
        $bw.Write([byte]255)  # end
        $payload = $ms.ToArray()
        $bw.Dispose(); $ms.Dispose()

        # 3) Send to broadcast:4011 and collect responses briefly
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.EnableBroadcast = $true
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast,4011)
        [void]$udp.Send($payload,$payload.Length,$remote)
        $udp.Client.ReceiveTimeout = 2000

        $responses = @()
        $start = Get-Date
        while ((Get-Date) - $start -lt [TimeSpan]::FromMilliseconds(2000)) {
            try {
                $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0)
                $buf = $udp.Receive([ref]$ep)
                if ($buf) { $responses += [PSCustomObject]@{ Data = $buf; From = $ep } }
            } catch { break }
        }
        $udp.Close()

        if (-not $responses -or $responses.Count -eq 0) {
            Write-LogMessage Info "No PXE (proxy DHCP) responses observed"
            return
        }

        foreach ($r in $responses) {
            $data = $r.Data
            if ($data.Length -lt 240) { continue }
            # siaddr (bytes 20..23)
            $si = New-Object byte[] 4; [Array]::Copy($data,20,$si,0,4)
            $siIp = (New-Object System.Net.IPAddress -ArgumentList $si).ToString()
            # file path (108..235)
            $fileBytes = @(); for ($i=108; $i -le 235 -and $i -lt $data.Length; $i++) { $fileBytes += $data[$i] }
            $fileStr = ([System.Text.Encoding]::ASCII.GetString([byte[]]$fileBytes)).Trim([char]0)
            # options start at 240
            $vendor = $null; $tftpIp = $null; $bootOpt = $null
            if ($data[236] -eq 99 -and $data[237] -eq 130 -and $data[238] -eq 83 -and $data[239] -eq 99) {
                $idx = 240
                while ($idx -lt $data.Length) {
                    $code = [int]$data[$idx]; $idx++
                    if ($code -eq 255) { break }
                    if ($code -eq 0) { continue }
                    if ($idx -ge $data.Length) { break }
                    $len = [int]$data[$idx]; $idx++
                    if ($idx + $len -gt $data.Length) { break }
                    $val = New-Object byte[] $len; [Array]::Copy($data,$idx,$val,0,$len); $idx += $len
                    switch ($code) {
                        60 { $vendor = [System.Text.Encoding]::ASCII.GetString($val) }
                        66 { $tftpIp = Convert-Opt66ToHost -Val $val }
                        67 { $bootOpt = [System.Text.Encoding]::ASCII.GetString($val) }
                    }
                }
            }

            $isPXE = $false
            if ($vendor -and $vendor -match 'PXEClient') { $isPXE = $true }
            if ($fileStr) { $isPXE = $true }
            if ($bootOpt) { $isPXE = $true }

            $hintIp = $tftpIp
            if (-not $hintIp -and $siIp -and $siIp -ne '0.0.0.0') { $hintIp = $siIp }
            if (-not $hintIp) { $hintIp = $r.From.Address.ToString() }

            $name = $hintIp
            try { $name = ([System.Net.Dns]::GetHostEntry($hintIp)).HostName } catch { }

            if ($isPXE) {
                Write-LogMessage Success ("Found PXE server hint via DHCP: $name (nextServer=$siIp tftp=$tftpIp bootfile=$fileStr vendor=$vendor)")
                $t = Add-DeviceToTargets -DeviceName $name -Source "DHCP-PXE"
                if ($t -and $t.ADObject) {
                    $bootValue = $fileStr
                    if ($bootOpt) { $bootValue = $bootOpt }
                    $tftpReachable = $null
                    if ($tftpIp) { $tftpReachable = (Test-TftpReachable -TftpHost $tftpIp -File $bootValue) }
                    $null = Upsert-Node -Id $t.ADObject.SID -Kinds @("Computer","Base") -PSObject $t.ADObject -Properties @{
                        collectionSource = @("DHCP-PXE")
                        name = $t.ADObject.samAccountName
                        networkBootServer = $true
                        isPXEServer = $true
                        pxeVendorClass = $vendor
                        pxeNextServer = $siIp
                        pxeBootFile = $bootValue
                        tftpReachable = $tftpReachable
                    }
                }
            } else {
                Write-LogMessage Verbose ("DHCP proxy responder: $name")
            }
        }

        # Also try a standard DHCPDISCOVER on port 67 to tag servers and catch any PXE hints in offers
        # Build a minimal DHCPDISCOVER (message type 1) using same BOOTP builder
        $ms2 = New-Object System.IO.MemoryStream
        $bw2 = New-Object System.IO.BinaryWriter($ms2)
        $rand2 = New-Object System.Random
        $xid2 = New-Object byte[] 4; $rand2.NextBytes($xid2)
        $bw2.Write([byte]1); $bw2.Write([byte]1); $bw2.Write([byte]6); $bw2.Write([byte]0)
        $bw2.Write($xid2); $bw2.Write([byte[]](0,0)); $bw2.Write([byte[]](0x80,0x00))
        $bw2.Write([byte[]](0,0,0,0)); $bw2.Write([byte[]](0,0,0,0)); $bw2.Write([byte[]](0,0,0,0)); $bw2.Write([byte[]](0,0,0,0))
        $c2 = New-Object byte[] 16; [Array]::Copy($mac,0,$c2,0,6); $bw2.Write($c2)
        $bw2.Write((New-Object byte[] 64)); $bw2.Write((New-Object byte[] 128))
        $bw2.Write([byte[]](99,130,83,99))
        # options: 53=Discover, 55=request params (1,3,6,15,60,66,67), 60='PXEClient'
        $bw2.Write([byte]53); $bw2.Write([byte]1); $bw2.Write([byte]1)
        $bw2.Write([byte]55); $bw2.Write([byte]7); $bw2.Write([byte[]](1,3,6,15,60,66,67))
        $v2 = [System.Text.Encoding]::ASCII.GetBytes('PXEClient'); $bw2.Write([byte]60); $bw2.Write([byte]$v2.Length); $bw2.Write($v2)
        $bw2.Write([byte]255)
        $bw2.Flush(); $discover = $ms2.ToArray(); $bw2.Dispose(); $ms2.Dispose()

        $uc = New-Object System.Net.Sockets.UdpClient
        $uc.EnableBroadcast = $true
        # Try to bind to client port 68 to receive standard DHCP offers; fall back silently if unavailable
        try {
            $uc.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket,[System.Net.Sockets.SocketOptionName]::ReuseAddress,$true)
            $uc.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,68)))
        } catch { Write-LogMessage Verbose "Could not bind to UDP 68 for DHCP offers; falling back to ephemeral port." }
        $srvEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Broadcast,67)
        [void]$uc.Send($discover,$discover.Length,$srvEP)
        $uc.Client.ReceiveTimeout = 1500
        $dhcpOffers = @()
        $st = Get-Date
        while ((Get-Date) - $st -lt [TimeSpan]::FromMilliseconds(1500)) {
            try { $rep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0); $dat = $uc.Receive([ref]$rep); if ($dat) { $dhcpOffers += [PSCustomObject]@{ Data=$dat; From=$rep } } } catch { break }
        }
        $uc.Close()

        $seen67 = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($resp in $dhcpOffers) {
            $fromIp = $resp.From.Address.ToString()
            if (-not $seen67.Add($fromIp)) { continue }
            $data = $resp.Data
            if ($data.Length -lt 240) { continue }

            # Parse minimal fields/options
            $si = New-Object byte[] 4; [Array]::Copy($data,20,$si,0,4)
            $siIp = (New-Object System.Net.IPAddress -ArgumentList $si).ToString()
            $vendor = $null; $tftp = $null; $boot = $null
            if ($data[236] -eq 99 -and $data[237] -eq 130 -and $data[238] -eq 83 -and $data[239] -eq 99) {
                $i = 240
                while ($i -lt $data.Length) {
                    $code = [int]$data[$i]; $i++
                    if ($code -eq 255) { break }
                    if ($code -eq 0) { continue }
                    if ($i -ge $data.Length) { break }
                    $len = [int]$data[$i]; $i++
                    if ($i + $len -gt $data.Length) { break }
                    $val = New-Object byte[] $len; [Array]::Copy($data,$i,$val,0,$len); $i += $len
                    switch ($code) {
                        60 { $vendor = [System.Text.Encoding]::ASCII.GetString($val) }
                        66 { $tftp = Convert-Opt66ToHost -Val $val }
                        67 { $boot = [System.Text.Encoding]::ASCII.GetString($val) }
                    }
                }
            }

            # Add/tag DHCP server and optional PXE hint if present
            $name = $fromIp; try { $name = ([System.Net.Dns]::GetHostEntry($fromIp)).HostName } catch { }
            $target = Add-DeviceToTargets -DeviceName $name -Source "DHCP-Discover"
            if ($target -and $target.ADObject) {
                $null = Upsert-Node -Id $target.ADObject.SID -Kinds @("Computer","Base") -PSObject $target.ADObject -Properties @{
                    collectionSource = @("DHCP-Discover")
                    isDHCPServer = $true
                    name = $target.ADObject.samAccountName
                }
            }

            $hasPXEHint = $false
            if ($vendor -and $vendor -match 'PXEClient') { $hasPXEHint = $true }
            if ($boot) { $hasPXEHint = $true }
            if ($siIp -and $siIp -ne '0.0.0.0') { $hasPXEHint = $true }
            if ($tftp) { $hasPXEHint = $true }

            if ($hasPXEHint) {
                $pxeHost = $tftp; if (-not $pxeHost -and $siIp -and $siIp -ne '0.0.0.0') { $pxeHost = $siIp }
                if ($pxeHost) {
                    $pxeName = $pxeHost; try { $pxeName = ([System.Net.Dns]::GetHostEntry($pxeHost)).HostName } catch { }
                    $p = Add-DeviceToTargets -DeviceName $pxeName -Source "DHCP-Discover"
                    if ($p -and $p.ADObject) {
                        $tftpReach = $null
                        if ($tftp) {
                            $rrqFile = 'pxecheck.bin'
                            if ($boot) { $rrqFile = $boot }
                            $tftpReach = (Test-TftpReachable -TftpHost $tftp -File $rrqFile)
                        }
                        $null = Upsert-Node -Id $p.ADObject.SID -Kinds @("Computer","Base") -PSObject $p.ADObject -Properties @{
                            collectionSource = @("DHCP-Discover")
                            name = $p.ADObject.samAccountName
                            networkBootServer = $true
                            isPXEServer = $true
                            pxeVendorClass = $vendor
                            pxeNextServer = $siIp
                            pxeBootFile = $boot
                            tftpReachable = $tftpReach
                        }
                    }
                }
            }
        }
        Write-LogMessage Success "DHCP collection completed"
    } catch {
        Write-LogMessage Error "DHCP collection failed: $_"
    }
}

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
        
        if ($siteCode) {
            $existingSiteNode = $script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" -and $_.Properties.siteCode -eq $siteCode }
            if (-not $existingSiteNode) {
                Write-LogMessage Success "Found site: $siteCode"
            }

            # Create or update SCCM_Site node
            $null = Upsert-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                collectionSource = "Local-SMS_Authority"
                SCCMInfra = $true
                siteCode = $siteCode
                siteType = "Primary Site"  # Primary (clients can only be joined to primary sites)
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
                $mp = Add-DeviceToTargets -DeviceName $mpHostname -Source "Local-SMS_LookupMP" -SiteCode $siteCode
                if ($mp -and $mp.IsNew) {
                    Write-LogMessage Success "Found management point: $mpHostname"
                }
                
                if ($mp.ADObject) {
                    $null = Upsert-Node -Id $mp.ADObject.SID -Kinds @("Computer", "Base") -PSObject $mp.ADObject -Properties @{
                        collectionSource = @("Local-SMS_LookupMP")
                        name = $mp.ADObject.samAccountName
                        SCCMInfra = $true
                        SCCMSiteSystemRoles = @("SMS Management Point@$siteCode")
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
            $localTarget = Add-DeviceToTargets -DeviceName $fqdn -Source "Local-CCM_Client" -SiteCode $siteCode
            if ($localTarget -and $localTarget.IsNew) {
                Write-LogMessage Success "Found local client device: $fqdn (SMSID: $clientId)"
            }
            
            # Resolve current management point SID
            $currentMPSid = $null
            if ($currentMP -and $localTarget.ADObject) {
                $mpObject = Resolve-PrincipalInDomain -Name $currentMP -Domain $script:Domain
                $currentMPSid = $mpObject.SID
            }
            
            # Create SCCM_ClientDevice node
            $null = Upsert-Node -Id $clientId -Kinds @("SCCM_ClientDevice") -Properties @{
                collectionSource = @("Local-CCM_Client")
                ADDomainSID = if ($localTarget.ADObject) { $localTarget.ADObject.SID } else { $null }
                currentManagementPoint = $currentMP
                currentManagementPointSID = $currentMPSid
                distinguishedName = if ($localTarget.ADObject) { $localTarget.ADObject.DistinguishedName } else { $null }
                DNSHostName = if ($localTarget.ADObject) { $localTarget.ADObject.DNSHostName } else { $null }
                name = if ($localTarget.ADObject) { "$($localTarget.ADObject.SamAccountName)@$siteCode" } else { $null }
                previousSMSID = if ($previousClientId) { $previousClientId } else { $null }
                previousSMSIDChangeDate = if ($clientIdChangeDate) { $clientIdChangeDate } else { $null }
                siteCode = $siteCode
                SMSID = $clientId
            }
            
            # Also create/update the Computer node for the system running the collector
            $null = Upsert-Node -Id $localTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $localTarget.ADObject -Properties @{
                collectionSource = @("Local-CCM_Client")
                name = $localTarget.ADObject.samAccountName
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
                            Write-LogMessage Verbose "$logFile"
                            $content = Get-Content -Path $logFile.FullName -ErrorAction SilentlyContinue
                            
                            # Look for UNC paths and URLs that might be SCCM components
                            $uncMatches = $content | Select-String -Pattern "(\\\\([a-zA-Z0-9\-_\s]{2,15})(\.[a-zA-Z0-9\-_\s]{1,64}){0,3})(\\[^\\\/:\*\?`"<>\|;]{1,64})+(\\)?" -AllMatches
                            $urlMatches = $content | Select-String -Pattern "(?<Protocol>\w+):\/\/(?<Domain>[\w@][\w.:@]+)\/?[\w\.?=%&=\-@/$,]*" -AllMatches
        
                            # Process UNC paths
                            foreach ($match in $uncMatches) {
                                foreach ($matchGroup in $match.Matches) {
                                    $uncPath = $matchGroup.Value.Trim()
                                    Write-LogMessage Verbose "  Found UNC path: $uncPath"
                                    
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
                                                            Write-LogMessage Verbose "    Host resolved to non-RFC1918 IP address: $hostname ($($ip.IPAddressToString))"
                                                        }
                                                    }
                                                }
                                            } catch {
                                                # DNS resolution failed
                                                Write-LogMessage Verbose "    Failed to resolve hostname $hostname from UNC path: $_"
                                            }
                                            
                                            # Only add if resolves to RFC1918 private IP
                                            if ($shouldAdd) {
                                                $uncPaths += $uncPath
                                                
                                                # Add unique hostnames to additional components
                                                if (-not $additionalComponents.ContainsKey($hostname)) {
                                                    Write-LogMessage Verbose "    Found host: $hostname ($($ip.IPAddressToString))"

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
                                    Write-LogMessage Verbose "  Found URL: $fullUrl"
                                    
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
                                                            Write-LogMessage Verbose "    Host resolved to non-RFC1918 IP address: $hostname ($($ip.IPAddressToString))"
                                                        }
                                                    }
                                                }
                                            } catch {
                                                # DNS resolution failed
                                                Write-LogMessage Verbose "    Failed to resolve hostname $hostname from URL: $_"
                                            }
                                            
                                            # Only add if resolves to RFC1918 private IP
                                            if ($shouldAdd) {

                                                # Add unique hostnames to additional components
                                                if (-not $additionalComponents.ContainsKey($hostname)) {
                                                    Write-LogMessage Verbose "    Found host: $hostname ($($ip.IPAddressToString))"

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
                            Write-LogMessage Error "  Failed to search log file $($logFile.FullName): $_"
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
        Write-LogMessage Success "Local collection completed"
        Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.dNSHostName) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
        Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
    } catch {
        Write-LogMessage Error "Local collection failed: $_"
    }
}


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

                $siteNodes = $script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }
                if ($siteNodes) {
                    $targetSiteCodes += $siteNodes | ForEach-Object { $_.Properties.SiteCode }
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
                            $adObject = Resolve-PrincipalInDomain -Name $managementPointFQDN -Domain $script:Domain
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
                            $adObject = Resolve-PrincipalInDomain -Name $managementPointFQDN -Domain $script:Domain
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

            $collectionTarget = Add-DeviceToTargets -DeviceName $fqdn -Source "DNS" -SiteCode $siteCode
            if ($collectionTarget -and $collectionTarget.IsNew) {
                Write-LogMessage Success "Found management point $fqdn for site $siteCode"
            }

            # Create or update Computer node
            if ($adObject) {
                $null = Upsert-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                    collectionSource = @("DNS")
                    name = $adObject.samAccountName
                    SCCMInfra = $true
                    SCCMSiteSystemRoles = @("SMS Management Point@$siteCode")
                }
            } else {
                Write-LogMessage Warning "Cannot create Computer node for $fqdn - missing AD object or SID"
            }
        }
        
        # Report what was collected
        Write-LogMessage Success "DNS collection completed"
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.dNSHostName) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
        Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
    } catch {
        Write-LogMessage Error "DNS collection failed: $_"
    }
}

function Invoke-RemoteRegistryCollection {
    param($CollectionTarget)
    
    try {
        $target = $CollectionTarget.Hostname

        Write-LogMessage Info "Attempting Remote Registry collection on: $($target)"
        
        $regConnectionSuccessful = $false
        $siteCode = $null
        
        # Connect to remote registry with timeout - Job 1
        $timeoutSeconds = 5
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
            return
        }
        
        Write-LogMessage Success "Remote Registry connection successful: $target"
        $regConnectionSuccessful = $true
        
        # Check SMB signing requirement
        Write-LogMessage Info "Checking SMB signing requirement on $target"
        $smbSigningResult = Get-SMBSigningRequiredFromRegistry -ComputerName $target

        if ($smbSigningResult.SigningRequired -ne $null) {
            if ($smbSigningResult.SigningRequired -eq $true) {
                Write-LogMessage Warning "SMB signing is REQUIRED on $target (detected via $($smbSigningResult.Method))"
            } elseif ($smbSigningResult.SigningRequired -eq $false) {
                Write-LogMessage Verbose "SMB signing is NOT required on $target (detected via $($smbSigningResult.Method))"
            } else {
                Write-LogMessage Verbose "Could not determine SMB signing requirement on $target`: $($smbSigningResult.Error)"
            }
            # Update Computer node property
            $null = Upsert-Node -Id $CollectionTarget.ADObject.SID -Kinds @("Computer","Base") -PSObject $CollectionTarget.ADObject -Properties @{
                SMBSigningRequired = $smbSigningResult.SigningRequired
                CollectionSource = @("RemoteRegistry-SMBSigningCheck")
            }
        }
        
        # Query 1: Get site code from Triggers subkey - Job 2
        $triggersCode = {
            param($target)
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                $subkeyName = "SOFTWARE\Microsoft\SMS\Triggers"
                $triggersKey = $reg.OpenSubKey($subkeyName)
                $result = $null
                if ($triggersKey) {
                    $result = $triggersKey.GetSubKeyNames()
                    $triggersKey.Close()
                }
                $reg.Close()
                return $result
            } catch {
                return $_ | Out-String
            }
        }
        
        Write-LogMessage Info "Querying Triggers registry key on $target for site code"
        $j2 = Start-Job -ScriptBlock $triggersCode -ArgumentList $target
        $triggersResult = $null
        
        if (Wait-Job $j2 -Timeout $timeoutSeconds) { 
            $triggersResult = Receive-Job $j2 
        } else {
            Write-LogMessage Warning "Triggers registry query timed out for $target"
            Remove-TimedOutJob $j2 $target
        }

        if ($triggersResult -and $triggersResult -like "*Exception*") {
            Write-LogMessage Error "Error querying Triggers key on $target`: $triggersResult"
        } elseif ($triggersResult -and $triggersResult.Count -eq 1) {
            $siteCode = $triggersResult
        } elseif ($triggersResult -and $triggersResult.Count -gt 1) {
            Write-LogMessage Warning "Multiple site codes found under Triggers key on $target`: $($triggersResult -join ', ')"
            $siteCode = $triggersResult[0] # Use first one
        } else {
            Write-LogMessage Verbose "No result from Triggers registry query on $target"
        }
        
        $siteNode = $null
        if ($siteCode) {
            # Only display if site code not already in nodes
            if (-not ($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" -and $_.Properties.SiteCode -eq $siteCode })) {
                Write-LogMessage Success "Found site code: $siteCode"
            }
            $siteNode = Upsert-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                collectionSource = @("RemoteRegistry")
                siteCode = $siteCode
            }
        }

        # Query 2: Get component servers - Job 3
        $componentCode = {
            param($target)
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                $subkeyName = "SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers"
                $componentKey = $reg.OpenSubKey($subkeyName)
                $result = $null
                if ($componentKey) {
                    $result = $componentKey.GetSubKeyNames()
                    $componentKey.Close()
                }
                $reg.Close()
                return $result
            } catch {
                return $_ | Out-String
            }
        }
        
        Write-LogMessage Info "Querying Components registry key on $target for SCCM component servers"
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
            if ($componentResult -and $componentResult -like "*Exception*") {
                Write-LogMessage Error "Error querying Components key on $target`: $componentResult"
            } else {
                if ($componentResult.Count -eq 0) {
                    Write-LogMessage Verbose "No component servers found on $target"
                } else {
                    foreach ($componentServerFQDN in $componentResult) {
                        $componentServer = Add-DeviceToTargets -DeviceName $componentServerFQDN -Source "RemoteRegistry-ComponentServer" -SiteCode $siteCode
                        if ($componentServer){
                            if ($componentServer.IsNew){
                                Write-LogMessage Success "Found component server: $componentServerFQDN"
                            } else {
                                Write-LogMessage Verbose "Component server already in targets: $componentServerFQDN"
                            }
                        }
                        # Add site system role to Computer node
                        if ($componentServer.ADObject) {
                            $null = Upsert-Node -Id $componentServer.ADObject.SID -Kinds @("Computer", "Base") -PSObject $componentServer.ADObject -Properties @{
                                collectionSource = @("RemoteRegistry-ComponentServer")
                                name = $componentServer.ADObject.samAccountName
                                SCCMInfra = $true
                                SCCMSiteSystemRoles = @("SMS Component Server@$siteCode")
                            }
                        }

                        # We also now know that the system we're connected to is a site server
                        if ($siteCode -and $CollectionTarget.ADObject) {
                            $null = Upsert-Node -Id $CollectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $CollectionTarget.ADObject -Properties @{
                                collectionSource = @("RemoteRegistry-ComponentServer")
                                name = $CollectionTarget.ADObject.samAccountName
                                SCCMInfra = $true
                                SCCMSiteSystemRoles = @("SMS Site Server@$siteCode")
                            }
                        }
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
                $multisiteKey = $reg.OpenSubKey($subkeyName)
                $result = $null
                if ($multisiteKey) {
                    $result = $multisiteKey.GetSubKeyNames()
                    $multisiteKey.Close()
                }
                $reg.Close()
                return $result
            } catch {
                return $_ | Out-String
            }
        }
        
        Write-LogMessage Info "Querying Multisite Component Servers registry key on $target for site database servers"
        $j4 = Start-Job -ScriptBlock $multisiteCode -ArgumentList $target
        $multisiteResult = $null
        
        if (Wait-Job $j4 -Timeout $timeoutSeconds) { 
            $multisiteResult = Receive-Job $j4 
        } else {
            Write-LogMessage Warning "Multisite servers registry query timed out for $target"
            Remove-TimedOutJob $j4 $target
        }
        
        # Process SQL servers
        if ($multisiteResult -and $multisiteResult -like "*Exception*") {
            Write-LogMessage Error "Error querying Components key on $target`: $multisiteResult"
        }
        elseif ($multisiteResult -and $multisiteResult.Count -eq 0) {
            # Site database is local to the site server
            Write-LogMessage Info "Site database is local to the site server: $target"

            # Add site system roles to Computer node
            $siteServerComputerNode = $null
            if ($target.ADObject) {
                $siteServerComputerNode = Upsert-Node -Id $target.ADObject.SID -Kinds @("Computer", "Base") -PSObject $target.ADObject -Properties @{
                    collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                    name = $target.ADObject.samAccountName
                    SCCMInfra = $true
                    SCCMSiteSystemRoles = @("SMS SQL Server@$siteCode", "SMS Site Server@$siteCode")
                }
            }

            # Add MSSQL nodes/edges for local SQL instance
            if ($siteNode -and $siteServerComputerNode) {
                Add-MSSQLServerNodesAndEdges -SiteNode $siteNode -SqlServerComputerNode $siteServerComputerNode -CollectionSource @("RemoteRegistry-MultisiteComponentServers")

                # Collect EPA settings from local SQL instance
                $epaSettings = Get-MssqlEpaSettingsViaRemoteRegistry -SqlServerHostname $CollectionTarget.Hostname -CollectionSource @("RemoteRegistry-MultisiteComponentServers")

                if ($epaSettings) {

                    # Update Computer node with EPA settings
                    $null = Upsert-Node -Id $CollectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $CollectionTarget.ADObject -Properties @{
                        collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                        disableLoopbackCheck = $epaSettings.DisableLoopbackCheck
                        name = $CollectionTarget.ADObject.samAccountName
                        SCCMInfra = $true
                        restrictReceivingNtlmTraffic = $epaSettings.RestrictReceivingNtlmTraffic
                    }

                    $portSuffix = if ($SqlServicePort) { ":$SqlServicePort" } else { ":1433" }
                    $SQLServerDomainSID = "$($CollectionTarget.ADObject.SID)$portSuffix"

                    # Update MSSQL_Server node with EPA settings
                    $null = Upsert-Node -Id $SQLServerDomainSID -Kinds @("MSSQL_Server") -Properties @{
                        collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                        extendedProtection = $epaSettings.ExtendedProtection
                        forceEncryption = $epaSettings.ForceEncryption
                    }     
                }
            }
        } elseif ($multisiteResult -and $multisiteResult.Count -gt 0) {

            if ($multisiteResult.Count -eq 1) {
                Write-LogMessage Verbose "Found single remote site database server: $($multisiteResult)"
            } elseif ($multisiteResult.Count -gt 1) {
                Write-LogMessage Verbose "Found clustered site database servers: $($multisiteResult -join ', ')"
            }

            foreach ($sqlServerFQDN in $multisiteResult) {
                $sqlServer = Add-DeviceToTargets -DeviceName $sqlServerFQDN -Source "RemoteRegistry-MultisiteComponentServers" -SiteCode $siteCode
                if ($sqlServer){
                    if ($sqlServer.IsNew){
                        Write-LogMessage Success "Found site database server: $sqlServerFQDN"
                    } else {
                        Write-LogMessage Verbose "Site database server already in targets: $sqlServerFQDN"
                    }
                }

                # Add site system roles to Computer node
                $sqlServerComputerNode = $null
                if ($sqlServer -and $sqlServer.ADObject) {
                    $sqlServerComputerNode = Upsert-Node -Id $sqlServer.ADObject.SID -Kinds @("Computer", "Base") -PSObject $sqlServer.ADObject -Properties @{
                        collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                        name = $sqlServer.ADObject.samAccountName
                        SCCMInfra = $true
                        SCCMSiteSystemRoles = @("SMS SQL Server@$siteCode")
                    }

                    # Add MSSQL nodes/edges for remote SQL instance
                    if ($siteNode -and $sqlServerComputerNode) {
                        Add-MSSQLServerNodesAndEdges -SiteNode $siteNode -SqlServerComputerNode $sqlServerComputerNode -CollectionSource @("RemoteRegistry-MultisiteComponentServers")
                    }
                    
                    # Collect EPA settings from remote SQL instance
                    $epaSettings = Get-MssqlEpaSettingsViaRemoteRegistry -SqlServerHostname $sqlServerFQDN -CollectionSource @("RemoteRegistry-MultisiteComponentServers")

                    if ($epaSettings) {
                        # Update Computer node with EPA settings
                        $null = Upsert-Node -Id $sqlServer.ADObject.SID -Kinds @("Computer", "Base") -PSObject $sqlServer.ADObject -Properties @{
                            collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                            disableLoopbackCheck = $epaSettings.DisableLoopbackCheck
                            name = $sqlServer.ADObject.samAccountName
                            SCCMInfra = $true
                            restrictReceivingNtlmTraffic = $epaSettings.RestrictReceivingNtlmTraffic
                        }

                        $portSuffix = if ($SqlServicePort) { ":$SqlServicePort" } else { ":1433" }
                        $SQLServerDomainSID = "$($sqlServer.ADObject.SID)$portSuffix"

                        # Update MSSQL_Server node with EPA settings
                        $null = Upsert-Node -Id $SQLServerDomainSID -Kinds @("MSSQL_Server") -Properties @{
                            collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                            extendedProtection = $epaSettings.ExtendedProtection
                            forceEncryption = $epaSettings.ForceEncryption
                        }
                    }
                }
            } 
        } else {
            Write-LogMessage Verbose "No site database server found in multisite component servers on $target"
        }
        
        # Query 4: Get current user SID(s) - Job 5
        $currentUserCode = {
            param($target)
            try {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $target)
                $subkeyName = "SOFTWARE\Microsoft\SMS\CurrentUser"
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
                return $_ | Out-String
            }
        }
        
        Write-LogMessage Info "Querying CurrentUser registry key on $target for logged-in user SID"
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
        if ($currentUserResult -and $currentUserResult -like "*Exception*") {
            Write-LogMessage Error "Error querying CurrentUser key on $target`: $currentUserResult"
        } elseif ($currentUserResult -and $currentUserResult.Count -eq 0) {
            Write-LogMessage Verbose "No values found in CurrentUser subkey on $target"
        } elseif ($currentUserResult -and $currentUserResult.Count -eq 1) {
            $currentUserSid = $currentUserResult.Values | Select-Object -Index 0
        } elseif ($currentUserResult -and $currentUserResult.Count -eq 2) {
            $currentUserSid = $currentUserResult.Values | Select-Object -Index 1
        } else {
            Write-LogMessage Warning "Unexpected number of values in CurrentUser subkey on $target`: $($currentUserResult.Count)"
        }

        Write-LogMessage Verbose "Found CurrentUser $currentUserSid on $target"
        # Resolve SID to AD object
        try {
            $userADObject = Resolve-PrincipalInDomain -Name $currentUserSid -Domain $script:Domain

            if ($userADObject) {
                Write-LogMessage Success "Found current user: $($userADObject.SamAccountName) ($currentUserSid)"
                
                # Create User node for current user
                $null = Upsert-Node -Id $currentUserSid -Kinds @("User", "Base") -PSObject $userADObject -Properties @{
                    collectionSource = @("RemoteRegistry-CurrentUser")
                    name = $userADObject.samAccountName
                }

                # Create Computer -[HasSession]-> User edge
                Upsert-Edge -Start $CollectionTarget.ADObject.SID -Kind "HasSession" -End $currentUserSid -Properties @{
                    collectionSource = @("RemoteRegistry-CurrentUser")
                }
            } else {
                Write-LogMessage Warning "Failed to resolve current user SID $sid"
            }
        } catch {
            Write-LogMessage Error "Error resolving current user SID $sid`: $_"
        }
        Write-LogMessage Success "Remote Registry collection completed for $target"
    } catch {
        Write-LogMessage Error "Remote Registry collection failed for $target`: $_"
    }
    
    Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
    Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.dNSHostName) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
    Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
}

function Get-SMBSigningRequiredFromRegistry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    
    $result = @{
        SigningRequired = $null
        Method = 'Unknown'
        Error = $null
    }
    
    # First attempt: Check registry values locally if applicable
    try {
        $regPath = "SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        $requireValueName = "RequireSecuritySignature"
        $enableValueName = "EnableSecuritySignature"
        
        try {
            # Try to open remote registry
            $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
            
            try {
                $regSubKey = $regKey.OpenSubKey($regPath)
                
                if ($regSubKey) {
                    $requireValue = $regSubKey.GetValue($requireValueName)
                    $enableValue = $regSubKey.GetValue($enableValueName)
                    
                    # RequireSecuritySignature takes precedence
                    if ($null -ne $requireValue) {
                        $result.SigningRequired = ([int]$requireValue -ne 0)
                        $result.Method = 'Registry'
                        Write-LogMessage Verbose "SMB Signing check for $ComputerName via registry: RequireSecuritySignature=$([int]$requireValue)"
                        return $result
                    }
                    # If RequireSecuritySignature is missing, check EnableSecuritySignature
                    elseif ($null -ne $enableValue) {
                        $enableInt = [int]$enableValue
                        if ($enableInt -eq 0) {
                            # If explicitly disabled, signing is not required
                            $result.SigningRequired = $false
                            $result.Method = 'Registry'
                            Write-LogMessage Verbose "SMB Signing check for $ComputerName via registry: EnableSecuritySignature=0 (not required)"
                            return $result
                        }
                        # If EnableSecuritySignature is 1, we can't conclusively determine, fall through to SMB negotiate
                    }
                    
                    $regSubKey.Close()
                }
            }
            finally {
                $regKey.Close()
            }
        }
        catch {
            Write-LogMessage Verbose "Could not check SMB signing via registry on $ComputerName`: $($_.Exception.Message)"
        }
    }
    catch {
        Write-LogMessage Verbose "Unexpected error during registry check: $_"
    }
}

function Get-SMBSigningRequiredViaSMBNegotiate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )
    
    $result = @{
        SigningRequired = $null
        Method = 'Unknown'
        Error = $null
    }
    
    # SMB2 negotiate based on SharpHoundCommon implementation
    try {
        Write-LogMessage Verbose "Attempting SMB2 negotiate for SMB signing check on $ComputerName"
        
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectAsync = $tcpClient.ConnectAsync($ComputerName, 445)
        
        if ($connectAsync.Wait(2000)) {  # 2 second timeout
            try {
                $networkStream = $tcpClient.GetStream()
                $networkStream.ReadTimeout = 2000
                $networkStream.WriteTimeout = 2000
                
                # Build SMB2 negotiate request following SharpHoundCommon's SMB2NegotiateRequest.cs
                # Using MemoryStream to build the packet dynamically
                $ms = New-Object System.IO.MemoryStream
                $writer = New-Object System.IO.BinaryWriter($ms)
                
                # NetBIOS header placeholder (will update length at the end)
                $writer.Write([byte]0x00)  # Message type
                $writer.Write([byte]0x00)  # Length (high byte)
                $writer.Write([byte]0x00)  # Length (middle byte)
                $writer.Write([byte]0x00)  # Length (low byte)
                
                # SMB2 Header (64 bytes)
                $writer.Write([uint32]0x424D53FE)  # Protocol ID (little-endian: 0xFE 'S' 'M' 'B')
                $writer.Write([uint16]64)          # Structure Size
                $writer.Write([uint16]0)           # Credit Charge
                $writer.Write([uint32]0)           # Status
                $writer.Write([uint16]0)           # Command (NEGOTIATE = 0)
                $writer.Write([uint16]1)           # Credits Requested
                $writer.Write([uint32]0)           # Flags
                $writer.Write([uint32]0)           # Next Command
                $writer.Write([uint64]0)           # Message ID
                $writer.Write([uint32]0)           # Reserved
                $writer.Write([uint32]0)           # Tree ID
                $writer.Write([uint64]0)           # Session ID
                $writer.Write((New-Object byte[] 16))  # Signature (16 bytes of zeros)
                
                # SMB2 NEGOTIATE Request Body
                $writer.Write([uint16]36)          # Structure Size (always 36 for NEGOTIATE)
                
                # Dialects array - we'll include multiple like SharpHoundCommon does
                $dialects = @(
                    [uint16]0x0202,  # SMB 2.0.2
                    [uint16]0x0210,  # SMB 2.1
                    [uint16]0x0300,  # SMB 3.0
                    [uint16]0x0302,  # SMB 3.0.2
                    [uint16]0x0311   # SMB 3.1.1
                )
                
                $writer.Write([uint16]$dialects.Count)  # Dialect Count
                $writer.Write([uint16]0x0002)       # Security Mode (Signing Required)
                $writer.Write([uint16]0)            # Reserved
                $writer.Write([uint32]0x000000FF)   # Capabilities (all capabilities)
                
                # Client GUID (16 bytes) - using random GUID
                $guid = [System.Guid]::NewGuid()
                $writer.Write($guid.ToByteArray())
                
                $writer.Write([uint64]0)            # Negotiate Context Offset (0 = no contexts)
                $writer.Write([uint16]0)            # Negotiate Context Count
                $writer.Write([uint16]0)            # Reserved
                
                # Write dialect list
                foreach ($dialect in $dialects) {
                    $writer.Write($dialect)
                }
                
                # Update NetBIOS header with correct length
                $fullPacket = $ms.ToArray()
                $smbLength = $fullPacket.Length - 4  # Exclude NetBIOS header itself
                $fullPacket[1] = [byte](($smbLength -shr 16) -band 0xFF)
                $fullPacket[2] = [byte](($smbLength -shr 8) -band 0xFF)
                $fullPacket[3] = [byte]($smbLength -band 0xFF)
                
                $writer.Dispose()
                $ms.Dispose()
                
                # Send the request
                $networkStream.Write($fullPacket, 0, $fullPacket.Length)
                $networkStream.Flush()
                
                # Read response
                $buffer = New-Object byte[] 1024
                $readAsync = $networkStream.ReadAsync($buffer, 0, $buffer.Length)
                
                if ($readAsync.Wait(2000)) {
                    $bytesRead = $readAsync.Result
                    
                    # Validate we have enough bytes for NetBIOS + SMB2 Header + NEGOTIATE response
                    if ($bytesRead -gt 72) {
                        # Check SMB2 protocol signature at offset 4
                        if ($buffer[4] -eq 0xFE -and $buffer[5] -eq 0x53 -and $buffer[6] -eq 0x4D -and $buffer[7] -eq 0x42) {
                            # SMB2 NEGOTIATE response structure starts at offset 68 (4 NetBIOS + 64 SMB2 header)
                            # Structure Size (2 bytes) at offset 68
                            # SecurityMode (2 bytes) at offset 70
                            $securityMode = [BitConverter]::ToUInt16($buffer, 70)
                            
                            # Check signing flags
                            $signingEnabled = ($securityMode -band 0x0001) -ne 0
                            $signingRequired = ($securityMode -band 0x0002) -ne 0
                            
                            $result.SigningRequired = $signingRequired
                            $result.Method = 'SMB2'
                            Write-LogMessage Verbose "SMB Signing check for $ComputerName via SMB2: SigningEnabled=$signingEnabled, SigningRequired=$signingRequired"
                            return $result
                        }
                    }
                }
                else {
                    Write-LogMessage Verbose "SMB2 read timeout for $ComputerName"
                }
            }
            catch {
                Write-LogMessage Verbose "SMB2 negotiate error for $ComputerName`: $($_.Exception.Message)"
            }
            finally {
                if ($networkStream) { $networkStream.Dispose() }
                if ($tcpClient) { $tcpClient.Dispose() }
            }
        }
        else {
            Write-LogMessage Verbose "Could not connect to SMB port on $ComputerName"
        }
    }
    catch {
        Write-LogMessage Verbose "SMB2 negotiate failed for $ComputerName`: $($_.Exception.Message)"
    }
    
    # If we got here, we couldn't determine via SMB2
    $result.Error = "Could not determine SMB signing requirement via SMB2"
    return $result
}

function Get-MssqlEpaSettingsViaTDS {
    # MSSQL Server Extended Protection for Authentication (EPA) Configuration Checker (Unprivileged)
    # Requires valid domain context only
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServerNameOrIP,

        [Parameter(Mandatory=$true)]
        [string]$Port,

        [Parameter(Mandatory=$true)]
        [string]$ServerString
    )

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($ServerNameOrIP, $Port)
        
        Write-LogMessage Verbose "Connected via TCP"
        $portIsOpen = $true
        
        $stream = $tcpClient.GetStream()
        
        # Build PRELOGIN packet
        $packet = New-Object System.Collections.ArrayList
        
        # TDS header (8 bytes)
        [void]$packet.Add(0x12)  # PRELOGIN packet type
        [void]$packet.Add(0x01)  # Status (EOM)
        [void]$packet.Add(0x00)  # Length high byte (will update)
        [void]$packet.Add(0x00)  # Length low byte (will update)
        [void]$packet.Add(0x00)  # SPID high
        [void]$packet.Add(0x00)  # SPID low
        [void]$packet.Add(0x01)  # Packet ID
        [void]$packet.Add(0x00)  # Window
        
        # PRELOGIN payload
        $payload = New-Object System.Collections.ArrayList
        
        # Version token
        [void]$payload.Add(0x00)  # VERSION token
        [void]$payload.Add(0x00)  # Offset high
        [void]$payload.Add(0x15)  # Offset low (21 = after 5*4 + 1 terminator)
        [void]$payload.Add(0x00)  # Length high
        [void]$payload.Add(0x06)  # Length low
        
        # Encryption token
        [void]$payload.Add(0x01)  # ENCRYPTION token
        [void]$payload.Add(0x00)  # Offset high
        [void]$payload.Add(0x1B)  # Offset low (27)
        [void]$payload.Add(0x00)  # Length high
        [void]$payload.Add(0x01)  # Length low
        
        # Instance token
        [void]$payload.Add(0x02)  # INSTOPT token
        [void]$payload.Add(0x00)  # Offset high
        [void]$payload.Add(0x1C)  # Offset low (28)
        [void]$payload.Add(0x00)  # Length high
        [void]$payload.Add(0x01)  # Length low
        
        # Thread ID token
        [void]$payload.Add(0x03)  # THREADID token
        [void]$payload.Add(0x00)  # Offset high
        [void]$payload.Add(0x1D)  # Offset low (29)
        [void]$payload.Add(0x00)  # Length high
        [void]$payload.Add(0x04)  # Length low
        
        # Terminator
        [void]$payload.Add(0xFF)
        
        # Version data (6 bytes)
        [void]$payload.Add(0x09)  # Major version
        [void]$payload.Add(0x00)  # Minor version
        [void]$payload.Add(0x00)  # Build number high
        [void]$payload.Add(0x00)  # Build number low
        [void]$payload.Add(0x00)  # Sub build high
        [void]$payload.Add(0x00)  # Sub build low
        
        # Encryption flag (1 byte)
        [void]$payload.Add(0x00)  # ENCRYPT_OFF
        
        # Instance (1 byte)
        [void]$payload.Add(0x00)
        
        # Thread ID (4 bytes)
        [void]$payload.Add(0x00)
        [void]$payload.Add(0x00)
        [void]$payload.Add(0x00)
        [void]$payload.Add(0x00)
        
        # Add payload to packet
        $payload | ForEach-Object { [void]$packet.Add($_) }
        
        # Update length in header
        $totalLen = $packet.Count
        $packet[2] = [byte](($totalLen -shr 8) -band 0xFF)
        $packet[3] = [byte]($totalLen -band 0xFF)
        
        # Convert to byte array and send
        $byteArray = [byte[]]$packet.ToArray()
        $stream.Write($byteArray, 0, $byteArray.Length)
        
        Write-LogMessage Verbose "Sent PRELOGIN packet"
        
        # Set timeout for read
        $stream.ReadTimeout = 5000  # 5 seconds
        
        # Read TDS header first
        $header = New-Object byte[] 8
        $bytesRead = $stream.Read($header, 0, 8)
        
        if ($bytesRead -ne 8) {
            Write-LogMessage Warning "Failed to receive TDS header"
            $tcpClient.Close()
            return
        }
        
        # Get payload length
        $payloadLen = (([int]$header[2] -shl 8) -bor [int]$header[3]) - 8
        
        # Read payload
        $response = New-Object byte[] $payloadLen
        $bytesRead = $stream.Read($response, 0, $payloadLen)
        
        if ($bytesRead -ne $payloadLen) {
            Write-LogMessage Warning "Failed to receive complete response"
            $tcpClient.Close()
            return
        }
        
        Write-LogMessage Verbose "Received PRELOGIN response"
        
        # Parse response
        $pos = 0
        while ($pos -lt $response.Length -and $response[$pos] -ne 0xFF) {
            if ($pos + 4 -ge $response.Length) { break }
            
            $token = $response[$pos]
            $offset = ([int]$response[$pos + 1] -shl 8) -bor [int]$response[$pos + 2]
            
            if ($token -eq 0x01 -and $offset -lt $response.Length) {  # Encryption token
                $encFlag = $response[$offset]
                # 0x00 = ENCRYPT_OFF
                # 0x01 = ENCRYPT_ON
                # 0x02 = ENCRYPT_NOT_SUP
                # 0x03 = ENCRYPT_REQ (Force Encryption)
                
                $encFlagName = switch ($encFlag) {
                    0x00 { "ENCRYPT_OFF" }
                    0x01 { "ENCRYPT_ON" }
                    0x02 { "ENCRYPT_NOT_SUP" }
                    0x03 { "ENCRYPT_REQ" }
                    default { "UNKNOWN" }
                }
                
                Write-LogMessage Verbose "Encryption flag in response: 0x$($encFlag.ToString('X2')) ($encFlagName)"
                break
            }
            $pos += 5
        }
        
        $tcpClient.Close()
        $preloginSuccess = $true
    }
    catch {
        Write-LogMessage Error "Error in TDS check: $_"
        $preloginSuccess = $false
    }

    if ($preloginSuccess) {

        $forceEncryption = 
            if ($encFlagName -eq "ENCRYPT_REQ") { "Yes" } 
            else { "No" }
            Write-LogMessage Info "Force Encryption: $forceEncryption"

    } else {
        Write-LogMessage Warning "PRELOGIN was not successful"
    }

    if ($portIsOpen) {
        try {  
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                Write-LogMessage Warning "Running in PowerShell 7+, so System.Data.SqlClient is unavailable, trying Microsoft.Data.SqlClient, may require installation"
                $sqlClientAsm = "Microsoft.Data.SqlClient"
            } else {
                $sqlClientAsm = "System.Data.SqlClient"
            }

            # This must be run remotely and will not display the correct settings if run locally on the SQL server
            Add-Type @"
using System;
using $sqlClientAsm;
using System.Runtime.InteropServices;

public class EPATester
{
    #region SSPI structs

    public struct SecBuffer
    {
        public int cbBuffer;
        public int BufferType;
        public IntPtr pvBuffer;
    }

    public struct SecBufferDesc
    {
        public uint ulVersion;
        public uint cBuffers;
        public IntPtr pBuffers;
    }

    #endregion

    #region P/Invoke for InitializeSecurityContextW

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.Winapi)]
    public static extern int InitializeSecurityContextW(
        IntPtr phCredential,
        IntPtr phContext,
        IntPtr pszTargetName,
        uint fContextReq,
        uint Reserved1,
        uint TargetDataRep,
        IntPtr pInput,
        uint Reserved2,
        IntPtr phNewContext,
        IntPtr pOutput,
        IntPtr pfContextAttr,
        IntPtr ptsExpiry);

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate int InitializeSecurityContextW_Delegate(
        IntPtr phCredential,
        IntPtr phContext,
        IntPtr pszTargetName,
        uint fContextReq,
        uint Reserved1,
        uint TargetDataRep,
        IntPtr pInput,
        uint Reserved2,
        IntPtr phNewContext,
        IntPtr pOutput,
        IntPtr pfContextAttr,
        IntPtr ptsExpiry);

    #endregion

    #region Native hook infrastructure (kernel32)

    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushInstructionCache(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        UIntPtr dwSize);

    private const int HOOK_LENGTH_X64 = 12; // mov rax, imm64; jmp rax
    private const int HOOK_LENGTH_X86 = 5;  // jmp rel32

    private static readonly object HookSync = new object();

    private static IntPtr _iscwTargetPtr = IntPtr.Zero;
    private static byte[] _iscwOriginalBytes;
    private static int _iscwPrologueLen;
    private static IntPtr _iscwTrampolinePtr = IntPtr.Zero;
    private static InitializeSecurityContextW_Delegate _iscwOriginalDelegate; // unused with unhook-call strategy
    private static Delegate _currentHookDelegate; // keep hook delegate alive
    private static bool _hookInstalled;
    private static IntPtr _emptySpn = IntPtr.Zero; // stable SPN buffer

    private static int HookLength
    {
        get { return IntPtr.Size == 8 ? HOOK_LENGTH_X64 : HOOK_LENGTH_X86; }
    }

    // Compute a safe prologue length by summing whole instruction lengths for common x64 prologue patterns
    private static int GetSafePrologueLength(IntPtr funcPtr, int minLen)
    {
        int offset = 0;
        // Read up to 64 bytes of prologue to be safe
        byte[] buf = new byte[64];
        Marshal.Copy(funcPtr, buf, 0, buf.Length);

        while (offset < buf.Length && offset < 32) // limit scanning
        {
            byte b = buf[offset];
            int len = 0;

            // Common single-byte ops
            if (b == 0x55) { len = 1; } // push rbp
            else if (b == 0x48 && offset + 2 < buf.Length && buf[offset+1] == 0x89 && buf[offset+2] == 0xE5) { len = 3; } // mov rbp,rsp
            else if (b == 0x48 && offset + 3 < buf.Length && buf[offset+1] == 0x83 && buf[offset+2] == 0xEC) { len = 4; } // sub rsp, imm8
            else if (b == 0x48 && offset + 6 < buf.Length && buf[offset+1] == 0x81 && buf[offset+2] == 0xEC) { len = 7; } // sub rsp, imm32
            else if (b == 0x48 && offset + 2 < buf.Length && buf[offset+1] == 0x8B) { len = 3; } // mov r64, r/m64 (simple)
            else if (b == 0x48 && offset + 6 < buf.Length && (buf[offset+1] == 0x8D || buf[offset+1] == 0x8B)) { len = 7; } // lea/mov RIP-rel (approx)
            else if ((b & 0xF0) == 0x50) { len = 1; } // push/pop r64
            else if (b == 0x40 || b == 0x41 || b == 0x48 || b == 0x49) { // REX prefix: try to parse next simple opcode
                // Assume next opcode is 0x89/0x8B reg/mem form => 3 bytes minimal
                len = 1; // count rex, then loop will process next
            }
            else if (b == 0xE9) { len = 5; } // jmp rel32
            else if (b == 0xEB) { len = 2; } // jmp rel8
            else if (b == 0x90) { len = 1; } // nop
            else {
                // Fallback: assume 1 byte to avoid stalling
                len = 1;
            }

            offset += len;
            if (offset >= minLen) break;
        }
        if (offset < minLen) offset = minLen; // ensure minimum
        return offset;
    }

    private static void EnsureInitializeSecurityContextHookInfrastructure()
    {
        if (_iscwTargetPtr != IntPtr.Zero && _iscwTrampolinePtr != IntPtr.Zero && _iscwOriginalDelegate != null)
            return;

        // Resolve to SspiCli.dll (secur32 often forwards this export)
        var mod = GetModuleHandle("SspiCli.dll");
        if (mod == IntPtr.Zero)
        {
            mod = LoadLibrary("SspiCli.dll");
            if (mod == IntPtr.Zero)
                throw new InvalidOperationException("Unable to load SspiCli.dll");
        }

        var target = GetProcAddress(mod, "InitializeSecurityContextW");
        if (target == IntPtr.Zero)
            throw new InvalidOperationException("Unable to locate InitializeSecurityContextW");

        _iscwTargetPtr = target;

        // Save original bytes (copy whole instructions for safe trampoline)
        _iscwPrologueLen = GetSafePrologueLength(_iscwTargetPtr, HookLength);
        _iscwOriginalBytes = new byte[_iscwPrologueLen];
        Marshal.Copy(_iscwTargetPtr, _iscwOriginalBytes, 0, _iscwPrologueLen);

        // Allocate trampoline (original bytes + jump back)
        var trampSize = (uint)(_iscwPrologueLen + (IntPtr.Size == 8 ? HOOK_LENGTH_X64 : HOOK_LENGTH_X86));
        _iscwTrampolinePtr = VirtualAlloc(
            IntPtr.Zero,
            (UIntPtr)trampSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        if (_iscwTrampolinePtr == IntPtr.Zero)
            throw new InvalidOperationException("Unable to allocate trampoline memory");

        // Copy original bytes into trampoline
        Marshal.Copy(_iscwOriginalBytes, 0, _iscwTrampolinePtr, _iscwPrologueLen);

        // Append jump back to original function (after overwritten bytes)
        var jmpBackSrc = _iscwTrampolinePtr + _iscwPrologueLen;
        var jmpBackDst = _iscwTargetPtr + _iscwPrologueLen;
        WriteJump(jmpBackSrc, jmpBackDst);

        // Create delegate that calls the trampoline (this is "original" function)
        // Trampoline delegate not required with unhook-call strategy
        _iscwOriginalDelegate = null;
    }

    private static void InstallInitializeSecurityContextHookInternal(IntPtr hookPtr)
    {
        var size = (UIntPtr)HookLength;
        uint oldProtect;
        if (!VirtualProtect(_iscwTargetPtr, size, PAGE_EXECUTE_READWRITE, out oldProtect))
            throw new InvalidOperationException("VirtualProtect failed when installing hook");

        WriteJump(_iscwTargetPtr, hookPtr);

        uint dummy;
        VirtualProtect(_iscwTargetPtr, size, oldProtect, out dummy);
        FlushInstructionCache(GetCurrentProcess(), _iscwTargetPtr, size);
    }

    private static void InstallInitializeSecurityContextHook(InitializeSecurityContextW_Delegate hookDelegate)
    {
        lock (HookSync)
        {
            EnsureInitializeSecurityContextHookInfrastructure();

            if (_hookInstalled)
                return;

            _currentHookDelegate = hookDelegate; // keep alive

            var hookPtr = Marshal.GetFunctionPointerForDelegate(hookDelegate);
            InstallInitializeSecurityContextHookInternal(hookPtr);

            _hookInstalled = true;
        }
    }

    private static void UninstallInitializeSecurityContextHookInternal()
    {
        var size = (UIntPtr)Math.Max(HookLength, _iscwOriginalBytes != null ? _iscwOriginalBytes.Length : HookLength);
        uint oldProtect;
        if (!VirtualProtect(_iscwTargetPtr, size, PAGE_EXECUTE_READWRITE, out oldProtect))
            throw new InvalidOperationException("VirtualProtect failed when uninstalling hook");

        if (_iscwOriginalBytes != null)
            Marshal.Copy(_iscwOriginalBytes, 0, _iscwTargetPtr, _iscwOriginalBytes.Length);

        uint dummy;
        VirtualProtect(_iscwTargetPtr, size, oldProtect, out dummy);
        FlushInstructionCache(GetCurrentProcess(), _iscwTargetPtr, size);
    }

    private static void UninstallInitializeSecurityContextHook()
    {
        lock (HookSync)
        {
            if (!_hookInstalled)
                return;

            UninstallInitializeSecurityContextHookInternal();

            _hookInstalled = false;
            _currentHookDelegate = null;
        }
    }

    private static void WriteJump(IntPtr src, IntPtr dst)
    {
        if (IntPtr.Size == 8)
        {
            // x64: mov rax, imm64; jmp rax   (12 bytes)
            var jmp = new byte[HOOK_LENGTH_X64];

            jmp[0] = 0x48; // REX.W
            jmp[1] = 0xB8; // mov rax, imm64
            var addrBytes = BitConverter.GetBytes(dst.ToInt64());
            Buffer.BlockCopy(addrBytes, 0, jmp, 2, 8);
            jmp[10] = 0xFF; // jmp rax
            jmp[11] = 0xE0;

            Marshal.Copy(jmp, 0, src, jmp.Length);
        }
        else
        {
            // x86: jmp rel32   (5 bytes)
            var jmp = new byte[HOOK_LENGTH_X86];
            jmp[0] = 0xE9; // jmp rel32
            int rel = dst.ToInt32() - src.ToInt32() - HOOK_LENGTH_X86;
            var relBytes = BitConverter.GetBytes(rel);
            Buffer.BlockCopy(relBytes, 0, jmp, 1, 4);
            Marshal.Copy(jmp, 0, src, jmp.Length);
        }
    }

    #endregion

    #region Hook implementations

    // Temporarily unhook, call the original function, then rehook.
    private static int CallOriginalInitializeSecurityContextW(
        IntPtr phCredential,
        IntPtr phContext,
        IntPtr pszTargetName,
        uint fContextReq,
        uint Reserved1,
        uint TargetDataRep,
        IntPtr pInput,
        uint Reserved2,
        IntPtr phNewContext,
        IntPtr pOutput,
        IntPtr pfContextAttr,
        IntPtr ptsExpiry)
    {
        // Unhook
        lock (HookSync)
        {
            if (_hookInstalled)
            {
                UninstallInitializeSecurityContextHookInternal();
                _hookInstalled = false;
            }
        }

        int ret;
        try
        {
            ret = InitializeSecurityContextW(
                phCredential,
                phContext,
                pszTargetName,
                fContextReq,
                Reserved1,
                TargetDataRep,
                pInput,
                Reserved2,
                phNewContext,
                pOutput,
                pfContextAttr,
                ptsExpiry);
        }
        finally
        {
            // Rehook
            if (_currentHookDelegate != null)
            {
                var hookPtr = Marshal.GetFunctionPointerForDelegate(_currentHookDelegate);
                lock (HookSync)
                {
                    InstallInitializeSecurityContextHookInternal(hookPtr);
                    _hookInstalled = true;
                }
            }
        }

        return ret;
    }

    public static int InitializeSecurityContextW_SBT_Hook(
        IntPtr phCredential,
        IntPtr phContext,
        IntPtr pszTargetName,
        uint fContextReq,
        uint Reserved1,
        uint TargetDataRep,
        IntPtr pInput,
        uint Reserved2,
        IntPtr phNewContext,
        IntPtr pOutput,
        IntPtr pfContextAttr,
        IntPtr ptsExpiry)
    {
        // Replace the target SPN with a stable, preallocated buffer
        if (_emptySpn == IntPtr.Zero)
        {
            // allocate once for process lifetime
            _emptySpn = Marshal.StringToHGlobalUni("empty");
        }
        if (pszTargetName != IntPtr.Zero)
        {
            pszTargetName = _emptySpn;
        }

        return CallOriginalInitializeSecurityContextW(
            phCredential,
            phContext,
            pszTargetName,
            fContextReq,
            Reserved1,
            TargetDataRep,
            pInput,
            Reserved2,
            phNewContext,
            pOutput,
            pfContextAttr,
            ptsExpiry);
    }

    public static int InitializeSecurityContextW_CBT_Hook(
        IntPtr phCredential,
        IntPtr phContext,
        IntPtr pszTargetName,
        uint fContextReq,
        uint Reserved1,
        uint TargetDataRep,
        IntPtr pInput,
        uint Reserved2,
        IntPtr phNewContext,
        IntPtr pOutput,
        IntPtr pfContextAttr,
        IntPtr ptsExpiry)
    {
        if (pInput != IntPtr.Zero)
        {
            var desc = (SecBufferDesc)Marshal.PtrToStructure(pInput, typeof(SecBufferDesc));
            if (desc.cBuffers > 0 && desc.pBuffers != IntPtr.Zero)
            {
                int secBufSize = Marshal.SizeOf(typeof(SecBuffer));
                for (uint i = 0; i < desc.cBuffers; i++)
                {
                    var ptr = new IntPtr(desc.pBuffers.ToInt64() + (i * secBufSize));
                    var buf = (SecBuffer)Marshal.PtrToStructure(ptr, typeof(SecBuffer));

                    // SECBUFFER_CHANNEL_BINDINGS = 0x0e
                    if (buf.BufferType == 0x0e && buf.pvBuffer != IntPtr.Zero && buf.cbBuffer > 0)
                    {
                        var zeroes = new byte[buf.cbBuffer];
                        Marshal.Copy(zeroes, 0, buf.pvBuffer, buf.cbBuffer);
                    }
                }
            }
        }

        return CallOriginalInitializeSecurityContextW(
            phCredential,
            phContext,
            pszTargetName,
            fContextReq,
            Reserved1,
            TargetDataRep,
            pInput,
            Reserved2,
            phNewContext,
            pOutput,
            pfContextAttr,
            ptsExpiry);
    }

    #endregion

    #region SQL connectivity helpers

    public static string TryConnectDb(string host)
    {
        using (SqlConnection conn = new SqlConnection(string.Format("Data Source={0};Integrated Security=SSPI;", host)))
        {
            try
            {
                conn.Open();
                return "success";
            }
            catch (Exception e)
            {
                if (e.Message.Contains("Login failed for"))
                    return "login failed";
                else if (e.Message.Contains("The login is from an untrusted domain"))
                    return "untrusted domain";
                else
                    return e.Message;
            }
            finally
            {
                // .NET appears to reuse SQL connections
                // We need to clear the SQL connection pool to create new connection attempts
                SqlConnection.ClearPool(conn);
            }
        }
    }

    public static string TryConnectDb_NoSb(string host)
    {
        var hookDelegate = new InitializeSecurityContextW_Delegate(InitializeSecurityContextW_SBT_Hook);
        string result;

        InstallInitializeSecurityContextHook(hookDelegate);
        try
        {
            result = TryConnectDb(host);
        }
        finally
        {
            UninstallInitializeSecurityContextHook();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();

        return result;
    }

    public static string TryConnectDb_NoCbt(string host)
    {
        var hookDelegate = new InitializeSecurityContextW_Delegate(InitializeSecurityContextW_CBT_Hook);
        string result;

        InstallInitializeSecurityContextHook(hookDelegate);
        try
        {
            result = TryConnectDb(host);
        }
        finally
        {
            UninstallInitializeSecurityContextHook();
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();

        return result;
    }

    #endregion

    #region Public EPA test wrapper

    public static EPATestResult TestEPA(string serverString)
    {
        var result = new EPATestResult
        {
            UnmodifiedConnection = TryConnectDb(serverString),
            NoSBConnection = TryConnectDb_NoSb(serverString),
            NoCBTConnection = TryConnectDb_NoCbt(serverString)
        };

        return result;
    }

    public class EPATestResult
    {
        public string PortIsOpen { get; set; }
        public string ForceEncryption { get; set; }
        public string ExtendedProtection { get; set; }
        public string UnmodifiedConnection { get; set; }
        public string NoSBConnection { get; set; }
        public string NoCBTConnection { get; set; }
    }
    
    #endregion
}
"@ -ReferencedAssemblies @(
    "System.dll",
    "System.Data.dll",
    "System.Runtime.InteropServices.dll",
    #"${sqlClientAsm}.dll",
    "System.Threading.dll",
    "System.Runtime.dll"
) -ErrorAction Stop
            # Build connection string for EPA test
            Write-LogMessage Info "Testing EPA settings for $($ServerString)"
            
            # Run the EPA test
            $epaResult = [EPATester]::TestEPA($ServerString)
            $epaResult.PortIsOpen = $portIsOpen
            $epaResult.ForceEncryption = $forceEncryption
    
            Write-LogMessage Verbose "  Unmodified connection: $($epaResult.UnmodifiedConnection)"
            Write-LogMessage Verbose "  No SB connection: $($epaResult.NoSBConnection)"
            Write-LogMessage Verbose "  No CBT connection: $($epaResult.NoCBTConnection)"
    
            # Channel binding token only considered when ForceEncryption is Yes
            # Service binding checked when ForceEncryption is No and EPA is Allowed/Required, preventing relay
            if ($epaResult.NoSBConnection -eq "untrusted domain") {
                Write-LogMessage Info "  Extended Protection: Allowed/Required (service binding)"
                $epaResult.ExtendedProtection = "Allowed/Required"
    
            # Channel binding token checked when ForceEncryption is On and EPA is Allowed/Required, preventing relay                
            } elseif ($epaResult.NoCBTConnection -eq "untrusted domain") {
                Write-LogMessage Info "  Extended Protection: Allowed/Required (channel binding)"
                $epaResult.ExtendedProtection = "Allowed/Required"
    
            # If we didn't get an "untrusted domain" message when dropping service or channel binding info, EPA is not Allowed/Required if the connection didn't fail, whether or not login failed/succeeded
            } elseif ($epaResult.UnmodifiedConnection -eq "success" -or $epaResult.UnmodifiedConnection -eq "login failed") {
                Write-LogMessage Info "  Extended Protection: Off"                
                $epaResult.ExtendedProtection = "Off"
            } else {
                Write-LogMessage Warning "There was an unexpected EPA configuration"
                $epaResult.ExtendedProtection = "Error detecting settings"
            }                 
        } catch {
            Write-LogMessage Error "EPA testing failed: $($_.Exception.Message)"
            # Create a minimal result object when an exception occurs
            $epaResult = New-Object PSObject -Property @{
                PortIsOpen = $portIsOpen
                ForceEncryption = $forceEncryption
                ExtendedProtection = "Error detecting settings"
            }
        } 
        return $epaResult
    }
}

function Add-MSSQLServerNodesAndEdges {
    param(
        [Parameter(Mandatory = $true)][PSObject]$SiteNode,
        [Parameter(Mandatory = $true)][PSObject]$SqlServerComputerNode,
        [string]$SqlDatabaseName,
        [int]$SqlServicePort = 1433,
        [string[]]$CollectionSource,
        [PSObject]$EPASettings
    )

    try {
        # Bail if this is a secondary site or if site type is not defined
        if (-not $SiteNode.Properties.siteType -or $SiteNode.Properties.siteType -eq "Secondary Site") {
            Write-LogMessage Warning "Skipping MSSQL node/edge creation for unidentified or secondary site $($SiteNode.Properties.siteCode)"
            return
        }

        # Ensure database name
        if (-not $SqlDatabaseName) {
            $SqlDatabaseName = $SiteNode.Properties.SQLDatabaseName
        }
        if (-not $SqlDatabaseName) {
            Write-LogMessage Warning "No SQL database name provided, inferring from site code $($SiteNode.Properties.siteCode)"
            $SqlDatabaseName = "CM_$($SiteNode.Properties.siteCode)"
        }

        # Ensure port
        if (-not $SqlServicePort) {
            $SqlServicePort = $SiteNode.Properties.SQLServicePort
        }
        if (-not $SqlServicePort) {
            Write-LogMessage Warning "No SQL service port provided, defaulting to 1433"
            $SqlServicePort = 1433
        }

        $siteDatabaseComputerSidAndPort = "$($SqlServerComputerNode.id):$SqlServicePort"

        # Create or update MSSQL_Server node
        $null = Upsert-Node -Id $siteDatabaseComputerSidAndPort -Kinds @("MSSQL_Server") -Properties @{
            collectionSource = @($CollectionSource)
            databases = if ($SqlDatabaseName) { @($SqlDatabaseName) } else { @() }
            extendedProtection = if ($EPASettings) { $EPASettings.ExtendedProtection } else { $null }
            forceEncryption = if ($EPASettings) { $EPASettings.ForceEncryption } else { $null }
            name = "$($SqlServerComputerNode.Properties.dNSHostName):$SqlServicePort"
            dnsHostName = $SqlServerComputerNode.Properties.dNSHostName
            SQLServicePort = $SqlServicePort
            SCCMInfra = $true
            SCCMSite = $SiteNode.Properties.siteCode
        }

        # We know the built-in sysadmin server role exists on all SQL instances
        $null = Upsert-Node -Id "sysadmin@$siteDatabaseComputerSidAndPort" -Kinds @("MSSQL_ServerRole") -Properties @{
            collectionSource = @($CollectionSource)
            isFixedRole = $true
            # We know the primary site server domain computer account is a member of the sysadmin role
            members = if ($sysadminComputerMssqlLoginId) { @($sysadminComputerMssqlLoginId) } else { @() }
            name = "sysadmin"
            SCCMSite = $SiteNode.Properties.siteCode
            SQLServer = $SqlServerComputerNode.Properties.dNSHostName
        }
        ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_ServerRole)
        Upsert-Edge -Start $siteDatabaseComputerSidAndPort -Kind "MSSQL_Contains" -End "sysadmin@$siteDatabaseComputerSidAndPort" -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_ServerRole) -[MSSQL_ControlServer]-> (MSSQL_Server)
        Upsert-Edge -Start "sysadmin@$siteDatabaseComputerSidAndPort" -Kind "MSSQL_ControlServer" -End $siteDatabaseComputerSidAndPort -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (Computer) -[MSSQL_HostFor]-> (MSSQL_Server)
        Upsert-Edge -Start $SqlServerComputerNode.id -Kind "MSSQL_HostFor" -End $siteDatabaseComputerSidAndPort -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Server) -[MSSQL_ExecuteOnHost]-> (Computer)
        Upsert-Edge -Start $siteDatabaseComputerSidAndPort -Kind "MSSQL_ExecuteOnHost" -End $SqlServerComputerNode.id -Properties @{
            collectionSource = @($CollectionSource)
        }

        # Bail if we don't know this is a site database from Remote Registry collection
        if ($DisablePossibleEdges) {
            if ($SqlServerComputerNode.properties.collectionSource -notcontains "RemoteRegistry-MultisiteComponentServers") {
                Write-LogMessage Verbose "Skipping MSSQL node/edge creation for $($SqlServerDomainObject.dNSHostName) as site database server is not known from Remote Registry collection"
                return
            }
        } else {
            Write-LogMessage Warning "Assuming that $($SqlServerComputerNode.Properties.dNSHostName) is a site database server for site $($SiteNode.Properties.siteCode) due to lack of -DisablePossibleEdges flag, may produce false positives"
        }

        $siteDatabaseId = "$($siteDatabaseComputerSidAndPort)\$($SqlDatabaseName)"

        # Create or update MSSQL_Database node
        $null = Upsert-Node -Id $siteDatabaseId -Kinds @("MSSQL_Database") -Properties @{
            collectionSource = @($CollectionSource)
            # Trustworthy attribute is required by SCCM
            isTrustworthy = $true 
            name = $SqlDatabaseName
            SCCMInfra = $true
            SCCMSite = $SiteNode.Properties.siteCode
            SQLServer = $SqlServerComputerNode.Properties.dNSHostName
        }

        # Create or update MSSQL_DatabaseRole node
        $null = Upsert-Node -Id "db_owner@$siteDatabaseId" -Kinds @("MSSQL_DatabaseRole") -Properties @{
            collectionSource = @($CollectionSource)
            database = $SqlDatabaseName
            isFixedRole = $true
            members = if ($sysadminComputerMssqlDatabaseUserId) { @($sysadminComputerMssqlDatabaseUserId) } else { @() }
            name = "db_owner"
            SCCMSite = $SiteNode.Properties.siteCode
            SQLServer = $SqlServerComputerNode.Properties.dNSHostName
        }

        ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_Database)
        Upsert-Edge -Start $siteDatabaseComputerSidAndPort -Kind "MSSQL_Contains" -End $siteDatabaseId -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Database) -[MSSQL_Contains]-> (MSSQL_DatabaseRole)
        Upsert-Edge -Start $siteDatabaseId -Kind "MSSQL_Contains" -End "db_owner@$siteDatabaseId" -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_DatabaseRole) -[MSSQL_ControlDB]-> (MSSQL_Database)
        Upsert-Edge -Start "db_owner@$siteDatabaseId" -Kind "MSSQL_ControlDB" -End $siteDatabaseId -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Database) -[SCCM_AssignAllPermissions]-> (SCCM_Site)
        # Get all primary sites in this hierarchy
        $sitesInHierarchy = Get-SitesInHierarchy -SiteCode $SiteNode.Properties.siteCode -ExcludeSecondarySites
        foreach ($siteInHierarchy in $sitesInHierarchy) {
            Upsert-Edge -Start $siteDatabaseId -Kind "SCCM_AssignAllPermissions" -End $siteInHierarchy.Id -Properties @{
                collectionSource = @($CollectionSource)
            }
        }
    } catch {
        Write-LogMessage Error "Failed to add MSSQL server nodes/edges for $($SqlServerComputerNode.Properties.dNSHostName) in site $($SiteNode.Properties.siteCode): $_"
    }

}

function Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer {
    param(
        [Parameter(Mandatory = $true)][PSObject]$SiteNode,
        [Parameter(Mandatory = $true)][PSObject]$SiteDatabaseComputerNode,
        [Parameter(Mandatory = $true)][PSObject]$SysadminComputerNode,
        [string]$SqlDatabaseName,
        [int]$SqlServicePort = 1433
    )

    Write-LogMessage Verbose "Creating MSSQL sysadmin edges for $($SysadminComputerNode.properties.dNSHostName) to site database server $($SiteDatabaseComputerNode.properties.dNSHostName)"

    try {

        # Bail if this is a secondary site or if site type is not defined
        if (-not $SiteNode.Properties.siteType -or $SiteNode.Properties.siteType -eq "Secondary Site") {
            Write-LogMessage Warning "Skipping MSSQL node/edge creation for unidentified or secondary site $($SiteNode.Properties.siteCode)"
            return
        }

        # Ensure database name
        if (-not $SqlDatabaseName) {
            $SqlDatabaseName = $SiteNode.Properties.SQLDatabaseName
        }
        if (-not $SqlDatabaseName) {
            Write-LogMessage Warning "No SQL database name provided, inferring from site code $($SiteNode.Properties.siteCode)"
            $SqlDatabaseName = "CM_$($SiteNode.Properties.siteCode)"
        }

        # Ensure port
        if (-not $SqlServicePort) {
            $SqlServicePort = $SiteNode.Properties.SQLServicePort
        }
        if (-not $SqlServicePort) {
            Write-LogMessage Warning "No SQL service port provided, defaulting to 1433"
            $SqlServicePort = 1433
        }       

        $siteDatabaseComputerSidAndPort = "$($SiteDatabaseComputerNode.id):$SqlServicePort"
        $siteDatabaseId = "$($siteDatabaseComputerSidAndPort)\$($SqlDatabaseName)"
 
        # Create nodes
        $sysadminComputerMssqlLoginName = "$($SysadminComputerNode.Properties.Domain.Split('.')[0])\$($SysadminComputerNode.Properties.samAccountName)"
        $sysadminComputerMssqlLoginId = "$sysadminComputerMssqlLoginName@$siteDatabaseComputerSidAndPort"

        # Create or update MSSQL_Login node for the sysadmin Computer
        $null = Upsert-Node -Id $sysadminComputerMssqlLoginId -Kinds @("MSSQL_Login") -Properties @{
            collectionSource = @("SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer")
            loginType = "Windows"
            # We know the primary site server is a member of the sysadmin role
            memberOfRoles = @("sysadmin@$siteDatabaseComputerSidAndPort")
            name = $sysadminComputerMssqlLoginName
            SCCMInfra = $true
            SCCMSite = $SiteNode.Properties.siteCode
            SQLServer = $SiteDatabaseComputerNode.Properties.dNSHostName
        }

        # Create or update MSSQL_DatabaseUser node for the sysadmin Computer
        $sysadminComputerMssqlDatabaseUserName = "$($SysadminComputerNode.Properties.Domain.Split('.')[0])\$($SysadminComputerNode.Properties.samAccountName)"
        $sysadminComputerMssqlDatabaseUserId = "$sysadminComputerMssqlDatabaseUserName@$siteDatabaseId"

        $null = Upsert-Node -Id $sysadminComputerMssqlDatabaseUserId -Kinds @("MSSQL_DatabaseUser") -Properties @{
            collectionSource = @("SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer")
            database = $SqlDatabaseName
            # We know the primary site server is a member of the db_owner role
            memberOfRoles = @("db_owner@$siteDatabaseId")
            name = $sysadminComputerMssqlDatabaseUserName
            login = $sysadminComputerMssqlLoginName
            SCCMInfra = $true
            SCCMSite = $SiteNode.Properties.siteCode
            SQLServer = $SiteDatabaseComputerNode.Properties.dNSHostName
        }

        # Create edges
        ## Computer level
        ### (MSSQL_Login) -[MSSQL_MemberOf]-> (MSSQL_ServerRole)
        Upsert-Edge -Start $sysadminComputerMssqlLoginId -Kind "MSSQL_MemberOf" -End "sysadmin@$siteDatabaseComputerSidAndPort" -Properties @{
            collectionSource = @("SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer")
        }
        ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_Login)
        Upsert-Edge -Start $siteDatabaseComputerSidAndPort -Kind "MSSQL_Contains" -End $sysadminComputerMssqlLoginId -Properties @{
            collectionSource = @("SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer")
        }
        ### (Computer) -[MSSQL_HasLogin]-> (MSSQL_Login)
        Upsert-Edge -Start $sysadminComputerNode.id -Kind "MSSQL_HasLogin" -End $sysadminComputerMssqlLoginId -Properties @{
            collectionSource = @("SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer")
        }

        ## Database Level
        ### (MSSQL_Login) -[MSSQL_IsMappedTo]-> (MSSQL_DatabaseUser)
        Upsert-Edge -Start $sysadminComputerMssqlLoginId -Kind "MSSQL_IsMappedTo" -End $sysadminComputerMssqlDatabaseUserId -Properties @{
            collectionSource = @("SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer")
        }
        ### (MSSQL_DatabaseUser) -[MSSQL_MemberOf]-> (MSSQL_DatabaseRole)
        Upsert-Edge -Start $sysadminComputerMssqlDatabaseUserId -Kind "MSSQL_MemberOf" -End "db_owner@$siteDatabaseId" -Properties @{
            collectionSource = @("SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer")
        }
        ### (MSSQL_Database) -[MSSQL_Contains]-> (MSSQL_DatabaseUser)
        Upsert-Edge -Start $siteDatabaseId -Kind "MSSQL_Contains" -End $sysadminComputerMssqlDatabaseUserId -Properties @{
            collectionSource = @("SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer")
        }
    } catch {
        Write-LogMessage Error "Failed to add MSSQL nodes/edges for $($SiteDatabaseComputerNode.Properties.dNSHostName) in site $($SiteNode.Properties.siteCode): $_"
    }
}

# Decommissioned function, kept for backward compatibility
function Add-MSSQLNodesAndEdgesForPrimarySite {
    param(
        [Parameter(Mandatory = $true)][string]$SiteCode,
        [Parameter(Mandatory = $true)][PSObject]$SqlServerDomainObject,
        [string]$SqlDatabaseName,
        [int]$SqlServicePort = 1433,
        [psobject]$SiteServerDomainObject,
        [string[]]$CollectionSource = @(),
        [PSObject]$EPASettings
    )

    try {

        if (-not $DisablePossibleEdges -or $SiteCode -ne "Unknown") {
            Write-LogMessage Verbose "Creating MSSQL nodes/edges for site database server $($SqlServerDomainObject.dNSHostName)"
        } else {
            Write-LogMessage Verbose "Skipping MSSQL node/edge creation for collection target without a site code"
            return
        }

        # Create or update MSSQL_Server node first
        $portSuffix = if ($SqlServicePort) { ":$SqlServicePort" } else { ":1433" }
        $SQLServerDomainSID = "$( $SqlServerDomainObject.SID )$portSuffix"
        $null = Upsert-Node -Id $SQLServerDomainSID -Kinds @("MSSQL_Server") -Properties @{
            collectionSource = @($CollectionSource)
            databases = if ($SqlDatabaseName) { @($SqlDatabaseName) } else { @() }
            extendedProtection = if ($EPASettings) { $EPASettings.ExtendedProtection } else { $null }
            forceEncryption = if ($EPASettings) { $EPASettings.ForceEncryption } else { $null }
            name = "$($SqlServerDomainObject.dNSHostName)$portSuffix"
            dnsHostName = $SqlServerDomainObject.dNSHostName
            SQLServicePort = if ($SqlServicePort) { $SqlServicePort } else { 1433 }
            SCCMInfra = if ($SiteCode -ne "Unknown") { $true } else { $false }
            SCCMSite = if ($SiteCode -ne "Unknown") { $SiteCode } else { $null }
        }

        # Bail if this is a secondary site or if site type is not defined
        $siteNode = $script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" -and $_.Properties.SiteCode -eq $SiteCode }
        if (-not $siteNode.Properties.siteType -or $siteNode.Properties.siteType -eq "Secondary Site") {
            Write-LogMessage Verbose "Skipping MSSQL node/edge creation for unidentified or secondary site $SiteCode"
            return
        }

        # Bail if we don't know this is a site database from Remote Registry collection
        if ($DisablePossibleEdges) {
            $sqlServerComputerNode = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Id -eq $SqlServerDomainObject.SID }

            if ($sqlServerComputerNode.properties.collectionSource -notcontains "RemoteRegistry-MultisiteComponentServers") {
                Write-LogMessage Verbose "Skipping MSSQL node/edge creation for $($SqlServerDomainObject.dNSHostName) as site database is not known from Remote Registry collection"
                return
            }
        }

        # Ensure database name
        if (-not $SqlDatabaseName) {
            Write-LogMessage Warning "No SQL database name provided, inferring from site code $SiteCode"
            $SqlDatabaseName = "CM_$SiteCode"
        }
        $sqlDatabaseIdentifier = "$($SQLServerDomainSID)\$($SqlDatabaseName)"

        # If we have the site server AD object, add MSSQL login and DB user
        $siteServerMssqlLogin = $null
        $siteServerMssqlDatabaseUser = $null
        if ($SiteServerDomainObject) {

            $siteServerMssqlLoginName = "$($SiteServerDomainObject.Domain.Split('.')[0])\$($SiteServerDomainObject.SamAccountName)"
            $siteServerMssqlLogin = "$siteServerMssqlLoginName@$SQLServerDomainSID"

            # Create or update MSSQL_Login node for the primary site server
            $null = Upsert-Node -Id $siteServerMssqlLogin -Kinds @("MSSQL_Login") -Properties @{
                collectionSource = @($CollectionSource)
                loginType = "Windows"
                # We know the primary site server is a member of the sysadmin role
                memberOfRoles = @("sysadmin@$SQLServerDomainSID")
                name = $siteServerMssqlLoginName
                SCCMInfra = $true
                SCCMSite = $SiteCode
                SQLServer = $SqlServerFQDN
            }

            # Create or update MSSQL_DatabaseUser node for the primary site server
            $siteServerMssqlDatabaseUserName = "$($SiteServerDomainObject.Domain.Split('.')[0])\$($SiteServerDomainObject.SamAccountName)"
            $siteServerMssqlDatabaseUser = "$siteServerMssqlDatabaseUserName@$sqlDatabaseIdentifier"

            $null = Upsert-Node -Id $siteServerMssqlDatabaseUser -Kinds @("MSSQL_DatabaseUser") -Properties @{
                collectionSource = @($CollectionSource)
                database = $SqlDatabaseName
                # We know the primary site server is a member of the db_owner role
                memberOfRoles = @("db_owner@$sqlDatabaseIdentifier")
                name = $siteServerMssqlDatabaseUserName
                login = $siteServerMssqlLoginName
                SCCMInfra = $true
                SCCMSite = $SiteCode
                SQLServer = $SqlServerFQDN
            }
        } else {
            Write-LogMessage Warning "Can't create site server MSSQL login/user nodes without resolving primary site server to AD object, will try again in post-processing"
        }

        # We know the built-in sysadmin server role exists on all SQL instances
        $null = Upsert-Node -Id "sysadmin@$SQLServerDomainSID" -Kinds @("MSSQL_ServerRole") -Properties @{
            collectionSource = @($CollectionSource)
            isFixedRole = $true
            # We know the primary site server is a member of the sysadmin role
            members = if ($SiteServerDomainObject) { @($SiteServerDomainObject.SamAccountName) } else { @() }
            name = "sysadmin"
            SCCMInfra = $true
            SCCMSite = $SiteCode
            SQLServer = $SqlServerFQDN
        }

        # Create or update MSSQL_Database node
        $null = Upsert-Node -Id $sqlDatabaseIdentifier -Kinds @("MSSQL_Database") -Properties @{
            collectionSource = @($CollectionSource)
            isTrustworthy = $true
            name = $SqlDatabaseName
            SCCMInfra = $true
            SCCMSite = $SiteCode
            SQLServer = $SqlServerFQDN
        }

        # Create or update MSSQL_DatabaseRole node
        $null = Upsert-Node -Id "db_owner@$sqlDatabaseIdentifier" -Kinds @("MSSQL_DatabaseRole") -Properties @{
            collectionSource = @($CollectionSource)
            database = $SqlDatabaseName
            isFixedRole = $true
            members = if ($SiteServerDomainObject) { @($SiteServerDomainObject.SamAccountName) } else { @() }
            name = "db_owner"
            SCCMInfra = $true
            SCCMSite = $SiteCode
            SQLServer = $SqlServerFQDN
        }

        # Create edges
        ## Computer level
        ### (Computer) -[MSSQL_HostFor]-> (MSSQL_Server)
        Upsert-Edge -Start $SqlServerDomainObject.SID -Kind "MSSQL_HostFor" -End $SQLServerDomainSID -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Server) -[MSSQL_ExecuteOnHost]-> (Computer)
        Upsert-Edge -Start $SQLServerDomainSID -Kind "MSSQL_ExecuteOnHost" -End $SqlServerDomainObject.SID -Properties @{
            collectionSource = @($CollectionSource)
        }

        ## Server level
        ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_Database)
        Upsert-Edge -Start $SQLServerDomainSID -Kind "MSSQL_Contains" -End $sqlDatabaseIdentifier -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_ServerRole)
        Upsert-Edge -Start $SQLServerDomainSID -Kind "MSSQL_Contains" -End "sysadmin@$SQLServerDomainSID" -Properties @{
            collectionSource = @($CollectionSource)
        }
        if ($siteServerMssqlLogin) {
            ### (MSSQL_Login) -[MSSQL_MemberOf]-> (MSSQL_ServerRole)
            Upsert-Edge -Start $siteServerMssqlLogin -Kind "MSSQL_MemberOf" -End "sysadmin@$SQLServerDomainSID" -Properties @{
                collectionSource = @($CollectionSource)
            }
            ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_Login)
            Upsert-Edge -Start $SQLServerDomainSID -Kind "MSSQL_Contains" -End $siteServerMssqlLogin -Properties @{
                collectionSource = @($CollectionSource)
            }
            ### (Computer) -[MSSQL_HasLogin]-> (MSSQL_Login)
            if ($SiteServerDomainObject -and $SiteServerDomainObject.SID) {
                Upsert-Edge -Start $SiteServerDomainObject.SID -Kind "MSSQL_HasLogin" -End $siteServerMssqlLogin -Properties @{
                    collectionSource = @($CollectionSource)
                }
            }
        }
        ### (MSSQL_ServerRole) -[MSSQL_ControlServer]-> (MSSQL_Server)
        Upsert-Edge -Start "sysadmin@$SQLServerDomainSID" -Kind "MSSQL_ControlServer" -End $SQLServerDomainSID -Properties @{
            collectionSource = @($CollectionSource)
        }

        ## Database Level
        ### (MSSQL_Login) -[MSSQL_IsMappedTo]-> (MSSQL_DatabaseUser)
        if ($siteServerMssqlLogin -and $siteServerMssqlDatabaseUser) {
            Upsert-Edge -Start $siteServerMssqlLogin -Kind "MSSQL_IsMappedTo" -End $siteServerMssqlDatabaseUser -Properties @{
                collectionSource = @($CollectionSource)
            }
        }
        ### (MSSQL_Database) -[MSSQL_Contains]-> (MSSQL_DatabaseRole)
        Upsert-Edge -Start $sqlDatabaseIdentifier -Kind "MSSQL_Contains" -End "db_owner@$sqlDatabaseIdentifier" -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_DatabaseUser) -[MSSQL_MemberOf]-> (MSSQL_DatabaseRole)
        if ($siteServerMssqlDatabaseUser) {
            Upsert-Edge -Start $siteServerMssqlDatabaseUser -Kind "MSSQL_MemberOf" -End "db_owner@$sqlDatabaseIdentifier" -Properties @{
                collectionSource = @($CollectionSource)
            }
        }
        ### (MSSQL_DatabaseRole) -[MSSQL_ControlDB]-> (MSSQL_Database)
        Upsert-Edge -Start "db_owner@$sqlDatabaseIdentifier" -Kind "MSSQL_ControlDB" -End $sqlDatabaseIdentifier -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Database) -[MSSQL_Contains]-> (MSSQL_DatabaseUser)
        if ($siteServerMssqlDatabaseUser) {
            Upsert-Edge -Start $sqlDatabaseIdentifier -Kind "MSSQL_Contains" -End $siteServerMssqlDatabaseUser -Properties @{
                collectionSource = @($CollectionSource)
            }
        }
        ### (MSSQL_Database) -[SCCM_AssignAllPermissions]-> (SCCM_Site)
        # Get all primary sites in this hierarchy
        $sitesInHierarchy = Get-SitesInHierarchy -SiteCode $SiteCode -ExcludeSecondarySites
        foreach ($siteInHierarchy in $sitesInHierarchy) {
            Upsert-Edge -Start $sqlDatabaseIdentifier -Kind "SCCM_AssignAllPermissions" -End $siteInHierarchy.Id -Properties @{
                collectionSource = @($CollectionSource)
            }
        }

    } catch {
        Write-LogMessage Error "Failed to add MSSQL nodes/edges for $SqlServerFQDN in site $SiteCode`: $_"
    }
}

function Invoke-MSSQLCollection {
    param(
        $CollectionTarget,
        $InstanceName = "MSSQLSERVER",
        $Port = 1433
    )
    
    $target = $CollectionTarget.Hostname
    Write-LogMessage Info "Attempting MSSQL collection on: $target"
   
    try {
        # Build the server string based on instance type
        if ($InstanceName -and $InstanceName -ne "MSSQLSERVER") {
            # Named instance - use ServerName\InstanceName format
            $serverString = "$target\$InstanceName"
        } elseif ($Port -ne 1433) {
            # Non-default port - use ServerName,Port format
            $serverString = "$target,$Port"
        } else {
            # Default instance on default port - just use ServerName
            $serverString = $target
        }

        $epaResult = Get-MssqlEpaSettingsViaTDS -ServerNameOrIP $target -Port $Port -ServerString $serverString
        if ($epaResult) {

            # If there is no SiteCode from LDAP or RemoteRegistry collection (e.g., if matched a naming pattern), set to "Unknown"
            if (-not $CollectionTarget.SiteCode) {
                Write-LogMessage Warning "No SiteCode found for CollectionTarget $target"
                $CollectionTarget.SiteCode = "Unknown"
            }

            #Add-MSSQLNodesAndEdgesForPrimarySite -SiteCode $CollectionTarget.SiteCode `
            #                              -SqlServerDomainObject $CollectionTarget.ADObject `
            #                              -SqlServicePort $Port `
            #                              -CollectionSource @("MSSQL-ScanForEPA") `
            #                              -EPASettings $epaResult

            $sqlServerComputerNode = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Id -eq $CollectionTarget.ADObject.SID }
            if (-not $sqlServerComputerNode) {
                Write-LogMessage Warning "No Computer node found for SQL Server $target with SID $($CollectionTarget.ADObject.SID), cannot add MSSQL nodes/edges"
                return
            }

            $siteNode = @($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" -and $_.Id -eq $CollectionTarget.SiteCode }) | Select-Object -First 1
            if (-not $siteNode) {
                Write-LogMessage Warning "No SCCM_Site node found for SiteCode $($CollectionTarget.SiteCode), cannot add MSSQL nodes/edges"
                return
            }

            Add-MSSQLServerNodesAndEdges `
                -SiteNode $siteNode `
                -SqlServerComputerNode $sqlServerComputerNode `
                -CollectionSource @("MSSQL-ScanForEPA") `
                -EPASettings $epaResult
            
            Write-LogMessage Success "Successfully collected EPA settings via MSSQL"
        } else {
            Write-LogMessage Warning "Failed to collect EPA settings via MSSQL"
        }
    } catch {
        Write-LogMessage Error "MSSQL collection failed for $target`: $_"
    }
}

function Process-CoerceAndRelayToAdminService {
    param(
        $SiteCode,
        [array]$CollectionSource
   )

    # Get all SMS Providers that have RestrictReceivingNtlmTraffic set to Off for the specified site code
    $smsProviderComputerNodes = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Provider@$SiteCode" -and ($null -eq $_.Properties.restrictReceivingNtlmTraffic -or $_.Properties.restrictReceivingNtlmTraffic -eq "Off" ) }
    if (-not $smsProviderComputerNodes) {
        Write-LogMessage Verbose "No SMS Provider found with RestrictReceivingNtlmTraffic set to Off in site code $SiteCode to coerce and relay to AdminService"
        return
    }

    # Get all site servers for the specified site code
    $siteServers = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Site Server@$SiteCode" }
    if ($siteServers.Count -eq 0) {
        Write-LogMessage Verbose "No site servers found for site code $SiteCode to coerce and relay to AdminService"
        return
    }

    # Get the SCCM_Site node
    $siteNode = $script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" -and $_.Id -eq $SiteCode }

    foreach ($smsProviderComputerNode in $smsProviderComputerNodes) {

        foreach ($siteServer in $siteServers) {

            # Can't relay back to the same server
            if ($smsProviderComputerNode.Id -eq $siteServer.Id) {
                Write-LogMessage Verbose "Skipping coerce and relay to AdminService edge from $(if ($siteServer.Properties.dNSHostName) { $siteServer.Properties.dNSHostName } else { $siteServer.Name }) to itself"
                continue
            }

            $computerDomain = if ($siteServer.Properties.Domain) { $siteServer.Properties.Domain.Split('.')[0] } else { $script:Domain }
            $authedUsersObjectId = "$($siteServer.Properties.Domain)`-S-1-5-11"

            # Add node for Authenticated Users so we don't get Unknown kind
            $null = Upsert-Node -Id $authedUsersObjectId `
                    -Kinds $("Group", "Base") `
                    -Properties @{
                        name = "AUTHENTICATED USERS@$($siteServer.Properties.Domain)"
                    }
            
            Upsert-Edge -Start $authedUsersObjectId -Kind "CoerceAndRelayToAdminService" -End $SiteCode -Properties @{
                collectionSource = @($CollectionSource)
                coercionVictimAndRelayTargetPairs = @("Coerce $($siteServer.Properties.dNSHostName), relay to $($smsProviderComputerNode.Properties.dNSHostName)")
                #coercionVictimHostname = $siteServer.Properties.dNSHostName
                #relayTargetHostName = $smsProviderComputerNode.Properties.dNSHostName
                #relayTargetPort = $smsProviderComputerNode.Properties.port
            }
        }
    }
}

function Process-CoerceAndRelayToMSSQL {
    param(
        $SiteCode
    )

    # Get all site databases that have EPA set to Off and RestrictReceivingNtlmTraffic set to Off for the specified site code
    $siteDatabaseComputerNodes = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS SQL Server@$SiteCode" -and ($null -eq $_.Properties.restrictReceivingNtlmTraffic -or $_.Properties.restrictReceivingNtlmTraffic -eq "Off" ) }
    if (-not $siteDatabaseComputerNodes) {
        Write-LogMessage Verbose "No site database found with RestrictReceivingNtlmTraffic set to Off in site code $SiteCode to coerce and relay to MSSQL"
        return
    }

    # Get all site servers for the specified site code
    $siteServers = @($script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Site Server@$SiteCode" })
    
    # Get all SMS Providers for the specified site code
    $smsProviders = @($script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Provider@$SiteCode" })

    # Get all management points for the specified site code
    $managementPoints = @($script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Management Point@$SiteCode" })

    # Combine all potential targets (robust against null/singleton values)
    $computersWithMssqlLogins = @()
    if ($siteServers)      { $computersWithMssqlLogins += @($siteServers) }
    if ($smsProviders)     { $computersWithMssqlLogins += @($smsProviders) }
    if ($managementPoints) { $computersWithMssqlLogins += @($managementPoints) }
    # Ensure uniqueness by node Id rather than object equality. Select-Object -Unique
    # was collapsing distinct nodes because their underlying object equality/ToString
    # made them appear identical. Sort-Object -Unique on Id preserves one instance per Id.
    if ($computersWithMssqlLogins) {
        $computersWithMssqlLogins = $computersWithMssqlLogins | Sort-Object -Property Id -Unique
    }
    if ($computersWithMssqlLogins.Count -eq 0) {
        Write-LogMessage Verbose "No site servers, SMS providers, or management points found for site code $SiteCode to coerce and relay to MSSQL"
        return
    }

    foreach ($siteDatabaseComputerNode in $siteDatabaseComputerNodes) {

        # Get the MSSQL_Server node for the site database server (ending with :port or :instancename)
        $mssqlServerNode = $script:Nodes | Where-Object { $_.Kinds -contains "MSSQL_Server" -and $_.Id -like "$($siteDatabaseComputerNode.Id):*" }

        # Check EPA settings on the site database server
        if (-not $mssqlServerNode) {
            Write-LogMessage Verbose "No MSSQL_Server node found for site database server $($siteDatabaseComputerNode.Id) to create coerce and relay to MSSQL edge"
            continue
        }

        # Bail if Extended Protection is not Off
        if (-not $mssqlServerNode.Properties.extendedProtection) {
            if (-not $DisablePossibleEdges) {
                $mssqlServerNode.Properties.extendedProtection = "Off"
            } else {
                continue
            }
        }

        if ($mssqlServerNode.Properties.extendedProtection -and $mssqlServerNode.Properties.extendedProtection -ne "Off") {
            Write-LogMessage Verbose "MSSQL server $($mssqlServerNode.Properties.name) has Extended Protection enabled ($($mssqlServerNode.Properties.extendedProtection)), skipping coerce and relay to MSSQL edge"
            continue
        }

        foreach ($computerWithMssqlLogin in $computersWithMssqlLogins) {

            # Can't relay back to the same server
            if ($siteDatabaseComputerNode.Id -eq $computerWithMssqlLogin.Id) {
                Write-LogMessage Verbose "Skipping coerce and relay to MSSQL edge from $($computerWithMssqlLogin.Properties.dNSHostName) to itself"
                continue
            }

            $computerDomain = if ($computerWithMssqlLogin.Properties.Domain) { $computerWithMssqlLogin.Properties.Domain.Split('.')[0] } else { $script:Domain }

            # Get the corresponding MSSQL login for the computer
            $mssqlLogin = $script:Nodes | Where-Object { $_.Kinds -contains "MSSQL_Login" -and $_.Id -eq "$computerDomain\$($computerWithMssqlLogin.Properties.SAMAccountName)@$($mssqlServerNode.Id)" }
            if (-not $mssqlLogin) {
                Write-LogMessage Verbose "No corresponding MSSQL login found for computer $($computerWithMssqlLogin.Properties.SAMAccountName) ($($computerWithMssqlLogin.Id)) to create coerce and relay to MSSQL edge"
                continue
            }

            $authedUsersObjectId = "$($computerWithMssqlLogin.Properties.Domain)`-S-1-5-11"

            # Add node for Authenticated Users so we don't get Unknown kind
            $null = Upsert-Node -Id $authedUsersObjectId `
                    -Kinds $("Group", "Base") `
                    -Properties @{
                        name = "AUTHENTICATED USERS@$($computerWithMssqlLogin.Properties.Domain)"
                    }

            # Get collection source from MSSQL server node EPA properties
            $collectionSource = @($mssqlServerNode.Properties["collectionSource"] | Where-Object { $_ -like "MSSQL-ScanForEPA" -or $_ -like "RemoteRegistry-MultisiteComponentServers" })
            
            Upsert-Edge -Start $authedUsersObjectId -Kind "CoerceAndRelayToMSSQL" -End $mssqlLogin.Id -Properties @{
                collectionSource = @($collectionSource)
                coercionVictimAndRelayTargetPairs = @("Coerce $($computerWithMssqlLogin.Properties.dNSHostName), relay to $($mssqlServerNode.Properties.dNSHostName)$(if ($mssqlServerNode.Properties.SQLServicePort -and $mssqlServerNode.Properties.SQLServicePort -ne 1433) { ":$($mssqlServerNode.Properties.SQLServicePort)" } else { ":1433" })")
                #coercionVictimHostname = $computerWithMssqlLogin.Properties.dNSHostName
                #relayTargetHostName = $mssqlServerNode.Properties.dNSHostName
                #relayTargetPort = $mssqlServerNode.Properties.SQLServicePort
            }
        }
    }
}

function Process-CoerceAndRelayToSMB {
    param(
        $SiteCode
    )

    # Get all site systems where SMB signing is not set to Required and RestrictReceivingNtlmTraffic set to Off for the specified site code
    $siteSystemsWithoutSmbSigning = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -like "*@$($SiteCode)" -and $_.Properties.SMBSigningRequired -eq $false -and ($null -eq $_.Properties.restrictReceivingNtlmTraffic -or $_.Properties.restrictReceivingNtlmTraffic -eq "Off" ) }

    if (-not $siteSystemsWithoutSmbSigning) {
        Write-LogMessage Verbose "No site systems found with SMB Signing not required and RestrictReceivingNtlmTraffic set to Off in site code $SiteCode to relay coerced authentication to SMB"
        return
    }

    # Get all site servers for the specified site code
    $siteServers = @($script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Site Server@$SiteCode" })
    
    if ($siteServers) {
        $siteServers = $siteServers | Sort-Object -Property Id -Unique
    }
    if ($siteServers.Count -eq 0) {
        Write-LogMessage Verbose "No site servers found for site code $SiteCode to coerce and relay to SMB on other site system roles"
        return
    }

    foreach ($siteSystemWithoutSmbSigning in $siteSystemsWithoutSmbSigning) {


        foreach ($siteServer in $siteServers) {

            # Can't relay back to the same server
            if ($siteSystemWithoutSmbSigning.Id -eq $siteServer.Id) {
                Write-LogMessage Verbose "Skipping coerce and relay to SMB edge from $($siteServer.Properties.dNSHostName) to itself"
                continue
            }

            $authedUsersObjectId = "$($siteServer.Properties.Domain)`-S-1-5-11"

            # Add node for Authenticated Users so we don't get Unknown kind
            $null = Upsert-Node -Id $authedUsersObjectId `
                    -Kinds $("Group", "Base") `
                    -Properties @{
                        name = "AUTHENTICATED USERS@$($siteServer.Properties.Domain)"
                    }

            # Get collection source from Computer node properties
            $collectionSource = @($siteSystemWithoutSmbSigning.Properties["collectionSource"] | Where-Object { $_ -like "SMB-Negotiate" -or $_ -like "RemoteRegistry-SMBSigningCheck" })
            
            Upsert-Edge -Start $authedUsersObjectId -Kind "CoerceAndRelayToSMB" -End $siteSystemWithoutSmbSigning.Id -Properties @{
                collectionSource = @($collectionSource)
                coercionVictimHostnames = @($siteServer.Properties.dNSHostName)
            }
        }
    }
}

function Invoke-AdminServiceCollection {
    param(
        $CollectionTarget
    )

    $target = $CollectionTarget.Hostname
    Write-LogMessage Info "Attempting AdminService collection on: $target"
   
    try {
        # This SMS Provider's site (SMS_Identification) - this will tell us which site we're collecting from
        $siteCode = Get-ThisSmsProvidersSiteViaAdminService -Target $target
        if (-not $siteCode) {
            return
        }

        # Sites (SMS_Site) - this will tell us all the sites in the hierarchy
        if (Get-SitesViaAdminService -Target $target) {
            Write-LogMessage Success "Successfully collected sites via AdminService (detected site: $siteCode)"
        } else {
            Write-LogMessage Warning "Failed to collect sites via AdminService"
        }
                
        # Client Devices (SMS_CombinedDeviceResources or SMS_R_System)
        if (Get-CombinedDeviceResourcesViaAdminService -Target $target -SiteCode $siteCode) {
            Write-LogMessage Success "Successfully collected combined device resources via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect combined device resources via AdminService"
        }

        if (Get-SmsRSystemViaAdminService -Target $target -SiteCode $siteCode) {
            Write-LogMessage Success "Successfully collected client devices and site systems via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect client devices and site systems via AdminService"
        }

        if (Get-SmsRUserViaAdminService -Target $target -SiteCode $siteCode) {
            Write-LogMessage Success "Successfully collected users via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect users via AdminService"
        }

        # Collections (SMS_Collection)
        if (Get-CollectionsViaAdminService -Target $target -SiteCode $siteCode) {
            Write-LogMessage Success "Successfully collected device/user collections via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect device/user collections via AdminService"
        }
        
        # Collection Members (SMS_FullCollectionMembership) - must come after collections to resolve members
        if (Get-CollectionMembersViaAdminService -Target $target -SiteCode $siteCode) {
            Write-LogMessage Success "Successfully collected collection members via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect collection members via AdminService"
        }
        
        # Security Roles (SMS_Role)
        if (Get-SecurityRolesViaAdminService -Target $target -SiteCode $siteCode) {
            Write-LogMessage Success "Successfully collected security roles via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect security roles via AdminService (may require elevated privileges)"
        }
        
        # Administrative Users (SMS_Admin) - must come after collections to resolve members
        if (Get-AdminUsersViaAdminService -Target $target -SiteCode $siteCode) {
            Write-LogMessage Success "Successfully collected admin users via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect admin users via AdminService (may require elevated privileges)"
        }
        
        # Site System Roles (SMS_SystemResourceList)
        if (Get-SiteSystemRolesViaAdminService -Target $target -SiteCode $siteCode) {
            Write-LogMessage Success "Successfully collected site system roles via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect site system roles via AdminService"
        }
        
        Write-LogMessage Info "AdminService collection completed: $collectionsSuccessful/$collectionsAttempted successful"

        Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.dNSHostName) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
        
        # Mark target as successfully collected
        if (-not $script:CollectionTargets.ContainsKey($target)) {
            $script:CollectionTargets[$target] = @{}
        }
        $script:CollectionTargets[$target]["Collected"] = $true
        $script:CollectionTargets[$target]["Method"] = "AdminService"
        $script:CollectionTargets[$target]["SiteCode"] = $detectedSiteCode
        
        Write-LogMessage Success "AdminService collection successful on $target ($collectionsSuccessful successful collections)"
        
    } catch {
        Write-LogMessage Error "AdminService collection failed for $target`: $_"
    }
}

function Get-ThisSmsProvidersSiteViaAdminService {
    param(
        [string]$Target
    )
    
    try {
        Write-LogMessage Info "Collecting this SMS Provider's site via AdminService from $Target"
        $baseUrl = "https://$Target/AdminService"
        $siteIdQuery = "SMS_Identification"
        $siteIdUrl = "$baseUrl/wmi/$siteIdQuery"
    
        try {
            $siteIdResponse = Invoke-WebRequest -Uri $siteIdUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
        } catch {
            Write-LogMessage Error "Failed to collect this site via AdminService from $Target`: $_"
            return $null
        }
    
        if (-not $siteIdResponse -or -not $siteIdResponse.Content) {
            Write-LogMessage Warning "No site identification returned from AdminService query on $Target"
            return $null
        }
    
        try {
            $siteIdResponseContent = $siteIdResponse.Content | ConvertFrom-Json
            $site = $siteIdResponseContent.value[0]
            Write-LogMessage Success "Identified this SMS Provider's site via AdminService: $($site.ThisSiteCode) ($($site.ThisSiteName))"
            return $site.ThisSiteCode
        } catch {
            Write-LogMessage Error "Failed to convert site identification response content to JSON from $Target`: $_"
            return $null
        }
    
    } catch {
        Write-LogMessage Error "Failed to collect this SMS Provider's site via AdminService from $Target`: $_"
        return $null
    }
}

function Get-SitesViaAdminService {
    param(
        [string]$Target
    )

    try {
        Write-LogMessage Info "Collecting sites via AdminService from $Target"
        $baseUrl = "https://$Target/AdminService"
        $siteQuery = "SMS_Site?`$select=BuildNumber,InstallDir,ReportingSiteCode,ServerName,SiteCode,SiteName,Status,Type,Version"
        $siteUrl = "$baseUrl/wmi/$siteQuery"
    
        try {
            $siteResponse = Invoke-WebRequest -Uri $siteUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
        } catch {
            Write-LogMessage Error "Failed to collect this site via AdminService from $Target`: $_"
            return $false
        }
    
        if (-not $siteResponse -or -not $siteResponse.Content) {
            Write-LogMessage Warning "No sites returned from AdminService query on $Target"
            return $false
        }
    
        try {
            $siteResponseContent = $siteResponse.Content | ConvertFrom-Json
            Write-LogMessage Info "Collected $($siteResponseContent.value.Count) sites via AdminService"
        } catch {
            Write-LogMessage Error "Failed to convert site response content to JSON from $Target`: $_"
            return $false
        }
    
        foreach ($site in $siteResponseContent.value) {

            # Try to get siteGUID from SMS_SCI_SiteDefinition
            $siteDefQuery = "SMS_SCI_SiteDefinition?`$filter=SiteCode eq '$($site.siteCode)'&`$select=ParentSiteCode,SiteCode,SiteName,SiteServerDomain,SiteServerName,SiteType,SQLDatabaseName,SQLServerName,Props"
            $siteDefUrl = "$baseUrl/wmi/$siteDefQuery"
    
            try {
                $siteDefResponse = Invoke-WebRequest -Uri $siteDefUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Error retrieving siteGUID for site $($site.SiteCode): $_"
            }
    
            if (-not $siteDefResponse -or -not $siteDefResponse.Content) {
                Write-LogMessage Warning "SMS_SCI_SiteDefinition not found for site $($site.SiteCode)"
            }
    
            try {
                $siteDefResponseContent = $siteDefResponse.Content | ConvertFrom-Json
                Write-LogMessage Verbose "Collected $($siteDefResponseContent.value.Count) site definitions via AdminService"
                
            } catch {
                Write-LogMessage Error "Failed to convert site definition response content to JSON from $Target`: $_"
            }
    
            $siteDef = $siteDefResponseContent.value | Where-Object { $_.SiteCode -eq $site.SiteCode }
            $siteGUID = $null
            try {
                $siteGUIDProp = $siteDef.Props | Where-Object { $_.PropertyName -eq "siteGUID" }
                if ($siteGUIDProp) {
                    $siteGUID = $siteGUIDProp.Value1
                    Write-LogMessage Verbose "Collected site GUID for site $($site.SiteCode): $($siteGUID)"
                } else {
                    Write-LogMessage Warning "siteGUID property not found in SMS_SCI_SiteDefinition for site $($site.SiteCode)"
                }
            } catch {
                Write-LogMessage Error "Failed to get site GUID for site $($site.SiteCode)`: $_"
            }

            $sqlDatabaseName = $null
            $sqlServerFQDN = $null
            $sqlServerName = $null
            $sqlServicePort = $null
            try {
                $sqlDatabaseName = $siteDef.SQLDatabaseName
                $sqlServerName = $siteDef.SQLServerName
                $sqlServerFQDN = $siteDef.Props | Where-Object { $_.PropertyName -eq "SQLServerFQDN" } | Select-Object -ExpandProperty Value1
                $sqlServicePort = $siteDef.Props | Where-Object { $_.PropertyName -eq "SQLServicePort" } | Select-Object -ExpandProperty Value
            } catch {
                Write-LogMessage Error "Failed to get SQL properties for site $($site.SiteCode)`: $_"
            }

            # Create or update the Computer node for the primary site server
            $siteServerDomainObject = Resolve-PrincipalInDomain -Name $site.ServerName -Domain $script:Domain
            if ($siteServerDomainObject) {
                Write-LogMessage Success "Found site server for site $($site.SiteCode): $($site.ServerName)"
                $siteServerComputerNode = Upsert-Node -Id $siteServerDomainObject.SID -Kinds @("Computer", "Base") -PSObject $siteServerDomainObject -Properties @{
                    collectionSource = @("AdminService-SMS_Sites", "AdminService-SMS_SCI_SiteDefinition")
                    name = $siteServerDomainObject.samAccountName
                    SCCMSiteSystemRoles = @("SMS Site Server@$($site.SiteCode)")
                    SCCMInfra = $true
                }
            } else {
                Write-LogMessage Warning "Failed to resolve primary site server $($site.ServerName) to AD object"
            }

            # Create or update MSSQL nodes and edges
            if ($sqlServerFQDN) {
                $sqlServerDomainObject = Resolve-PrincipalInDomain -Name $SqlServerFQDN -Domain $script:Domain
                if (-not $sqlServerDomainObject) {
                    Write-LogMessage Warning "Failed to resolve SQL Server $SqlServerFQDN to AD object"
                    return
                }

                Write-LogMessage Success "Found SQL Server for site $($site.SiteCode)`: $SqlServerFQDN"

                # Create or update Computer node for SQL Server
                 $siteDatabaseComputerNode = Upsert-Node -Id $sqlServerDomainObject.SID -Kinds @("Computer", "Base") -PSObject $sqlServerDomainObject -Properties @{
                    collectionSource = @("AdminService-SMS_SCI_SiteDefinition")
                    name = $sqlServerDomainObject.samAccountName
                    SCCMSiteSystemRoles = @("SMS SQL Server@$($site.SiteCode)")
                    SCCMInfra = $true
                }
            } else {
                Write-LogMessage Warning "No SQL Server FQDN found for site $($site.SiteCode)"
            }
            
            # Update SCCM_Site nodes
            $siteNode = Upsert-Node -Id $site.SiteCode -Kinds @("SCCM_Site") -Properties @{
                collectionSource = @("AdminService-SMS_Sites", "AdminService-SMS_SCI_SiteDefinition")
                buildNumber = if ($site.BuildNumber) { $site.BuildNumber } else { $null }
                displayName = if ($site.SiteName) { $site.SiteName } else { $null }
                installDir = if ($site.InstallDir) { $site.InstallDir } else { $null }
                parentSiteCode = if ($site.ReportingSiteCode) { $site.ReportingSiteCode } else { "None" }
                SCCMInfra = $true 
                siteCode = $site.SiteCode
                siteGUID = if ($siteGUID) { $siteGUID } else { $null }
                siteServerDomainSID = if ($siteServerDomainObject.SID) { $siteServerDomainObject.SID } else { $null }
                siteServerFQDN = if ($siteServerDomainObject.dNSHostName) { $siteServerDomainObject.dNSHostName } else { $null }
                siteServerName = if ($site.ServerName) { $site.ServerName } else { $null }
                siteType = if ($site.Type) { switch ($site.Type) {
                    1 { "Secondary Site" }
                    2 { "Primary Site" }
                    4 { "Central Administration Site" }
                    default { "Unknown" }
                }} else { $null }
                SQLDatabaseName = $sqlDatabaseName
                SQLServerDomainSID = if ($sqlServerDomainObject.SID) { $sqlServerDomainObject.SID } else { $null }
                SQLServerFQDN = $sqlServerFQDN
                SQLServerName = $sqlServerName
                SQLServicePort = $sqlServicePort
                version = if ($site.Version) { $site.Version } else { $null }
            }

            # Finally, add MSSQL nodes and edges for each site
            Add-MSSQLServerNodesAndEdges `
                -SiteNode $siteNode `
                -SqlServerComputerNode $siteDatabaseComputerNode `
                -CollectionSource @("AdminService-SMS_Sites", "AdminService-SMS_SCI_SiteDefinition")

            #Add-MSSQLNodesAndEdgesForPrimarySite -SiteCode $site.SiteCode `
            #                            -SqlServerDomainObject $sqlServerDomainObject `
            #                            -SqlDatabaseName $sqlDatabaseName `
            #                            -SqlServicePort $sqlServicePort `
            #                            -SiteServerDomainObject $siteServerDomainObject `
            #                            -CollectionSource @("AdminService-SMS_Sites", "AdminService-SMS_SCI_SiteDefinition")
        }
        return $true

    } catch {
        Write-LogMessage Error "Failed to collect sites via AdminService from $Target`: $_"
        return $false
    }
}

function Get-CombinedDeviceResourcesViaAdminService {
    param(
        [string]$Target,
        [string]$SiteCode
    )
    try {
        Write-LogMessage Info "Collecting combined device resources via AdminService from $Target for site $SiteCode"
        $select = "`$select=AADDeviceID,AADTenantID,ADLastLogonTime,CNAccessMP,CNLastOfflineTime,CNLastOnlineTime,CoManaged,CurrentLogonUser,DeviceOS,DeviceOSBuild,IsClient,IsObsolete,IsVirtualMachine,LastActiveTime,LastMPServerName,Name,PrimaryUser,ResourceID,SiteCode,SMSID,UserName,UserDomainName"
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            $combinedDeviceUrl = "https://$Target/AdminService/wmi/SMS_CombinedDeviceResources?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $combinedDeviceResponse = Invoke-WebRequest -Uri $combinedDeviceUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Failed to collect combined device resources via SMS_CombinedDeviceResources (skip=$skip): $_"
                return $false
            }

            if (-not $combinedDeviceResponse -or -not $combinedDeviceResponse.Content) {
                Write-LogMessage Warning "No combined device resources returned from AdminService query on $Target via SMS_CombinedDeviceResources (skip=$skip)"
                break
            }

            try {
                $combinedDeviceResponseContent = $combinedDeviceResponse.Content | ConvertFrom-Json
            } catch {
                Write-LogMessage Error "Failed to convert device response content to JSON from $Target via SMS_CombinedDeviceResources (skip=$skip)`: $_"
                return $false
            }

            if ($combinedDeviceResponseContent -and $combinedDeviceResponseContent.value) {
                foreach ($device in $combinedDeviceResponseContent.value) {
                    # Skip if not a client or obsolete, which may occur when the client is reinstalled on the same machine
                    if ($device.IsClient -eq $false -or $device.IsObsolete -eq $true) { continue }

                    $adLastLogonUserObject = $null
                    $currentLogonUserObject = $null
                    $currentManagementPointObject = $null
                    $lastReportedMPServerObject = $null
                    $primaryUserObject = $null

                    $thisClientDomainObject = Resolve-PrincipalInDomain -Name $device.Name -Domain $script:Domain
                    if ($device.UserName) { $adLastLogonUserObject = Resolve-PrincipalInDomain -Name $device.UserName -Domain $script:Domain }
                    if ($device.CurrentLogonUser) { $currentLogonUserObject = Resolve-PrincipalInDomain -Name $device.CurrentLogonUser -Domain $script:Domain }
                    if ($device.CNAccessMP) { $currentManagementPointObject = Resolve-PrincipalInDomain -Name $device.CNAccessMP -Domain $script:Domain }
                    if ($device.LastMPServerName) { $lastReportedMPServerObject = Resolve-PrincipalInDomain -Name $device.LastMPServerName -Domain $script:Domain }
                    if ($device.PrimaryUser) { $primaryUserObject = Resolve-PrincipalInDomain -Name $device.PrimaryUser -Domain $script:Domain }

                    # Create or update Computer nodes before creating SCCM_ClientDevice node to ensure we have the dNSHostname and SID for Host node creation
                    if ($thisClientDomainObject.SID) {
                        $null = Upsert-Node -Id $thisClientDomainObject.SID -Kinds @("Computer", "Base") -PSObject $thisClientDomainObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                            name = $thisClientDomainObject.samAccountName
                            SCCMResourceIDs = @("$($device.ResourceID)@$SiteCode")
                            SCCMClientDeviceIdentifier = $device.SMSUniqueIdentifier
                        }
                    }

                    $null = Upsert-Node -Id $device.SMSID -Kinds @("SCCM_ClientDevice") -Properties @{
                        collectionSource = @("AdminService-SMS_CombinedDeviceResources")
                        AADDeviceID = if ($device.AADDeviceID) { $device.AADDeviceID } else { $null }
                        AADTenantID = if ($device.AADTenantID) { $device.AADTenantID } else { $null }
                        ADLastLogonTime = if ($device.ADLastLogonTime) { $device.ADLastLogonTime } else { $null }
                        ADLastLogonUser = if ($device.UserName) { $device.UserName } else { $null }
                        ADLastLogonUserDomain = if ($device.UserDomainName) { $device.UserDomainName } else { $null }
                        ADLastLogonUserSID = if ($adLastLogonUserObject.SID) { $adLastLogonUserObject.SID } else { $null }
                        collectionIds = @()
                        collectionNames = @()
                        coManaged = if ($device.CoManaged) { $device.CoManaged } else { $null }
                        currentLogonUser = if ($device.CurrentLogonUser) { $device.CurrentLogonUser } else { $null }
                        currentLogonUserSID = if ($currentLogonUserObject.SID) { $currentLogonUserObject.SID } else { $null }
                        currentManagementPoint = if ($device.CNAccessMP) { $device.CNAccessMP } else { $null }
                        currentManagementPointSID = if ($currentManagementPointObject.SID) { $currentManagementPointObject.SID } else { $null }
                        deviceOS = if ($device.DeviceOS) { $device.DeviceOS } else { $null }
                        deviceOSBuild = if ($device.DeviceOSBuild) { $device.DeviceOSBuild } else { $null }
                        distinguishedName = if ($device.DistinguishedName) { $device.DistinguishedName } else { $null }
                        DNSHostName = $thisClientDomainObject.DNSHostName
                        domain = if ($device.FullDomainName) { $device.FullDomainName } elseif ($device.Domain) { $device.Domain } else { $null }
                        isVirtualMachine = if ($device.IsVirtualMachine) { $device.IsVirtualMachine } else { $null }
                        lastActiveTime = if ($device.LastActiveTime) { $device.LastActiveTime } else { $null }
                        lastOfflineTime = if ($device.CNLastOfflineTime) { $device.CNLastOfflineTime } else { $null }
                        lastOnlineTime = if ($device.CNLastOnlineTime) { $device.CNLastOnlineTime } else { $null }
                        lastReportedMPServerName = if ($device.LastMPServerName) { $device.LastMPServerName } else { $null }
                        lastReportedMPServerSID = if ($lastReportedMPServerObject.SID) { $lastReportedMPServerObject.SID } else { $null }
                        name = "$($device.Name)@$($device.SiteCode)"
                        primaryUser = $device.PrimaryUser
                        primaryUserSID = if ($primaryUserObject.SID) { $primaryUserObject.SID } else { $null }
                        resourceID = if ($device.ResourceID) { "$($device.ResourceID)@$($device.SiteCode)" } else { $null }
                        siteCode = if ($device.SiteCode) { $device.SiteCode } else { $null }
                        SMSID = if ($device.SMSID) { $device.SMSID } else { $null }
                        sourceSiteCode = $SiteCode
                        userName = if ($device.UserName) { $device.UserName } else { $null }
                        userDomainName = if ($device.UserDomainName) { $device.UserDomainName } else { $null }
                    }

                    Upsert-Edge -Start $device.SiteCode -Kind "SCCM_HasClient" -End $device.SMSID -Properties @{
                        collectionSource = @("AdminService-ClientDevices")
                    }

                    if ($adLastLogonUserObject.SID) {
                        $null = Upsert-Node -Id $adLastLogonUserObject.SID -Kinds @("User", "Base") -PSObject $adLastLogonUserObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                            name = $adLastLogonUserObject.samAccountName
                        }
                        Upsert-Edge -Start $device.SMSID -Kind "SCCM_HasADLastLogonUser" -End $adLastLogonUserObject.SID -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                    }
                    if ($currentLogonUserObject.SID) {
                        $null = Upsert-Node -Id $currentLogonUserObject.SID -Kinds @("User", "Base") -PSObject $currentLogonUserObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                            name = $currentLogonUserObject.samAccountName
                        }
                        Upsert-Edge -Start $device.SMSID -Kind "SCCM_HasCurrentUser" -End $currentLogonUserObject.SID -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                    }
                    if ($currentManagementPointObject.SID) {
                        $null = Upsert-Node -Id $currentManagementPointObject.SID -Kinds @("Computer", "Base") -PSObject $currentManagementPointObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                            name = $currentManagementPointObject.samAccountName
                            SCCMInfra = $true
                        }
                    }
                    if ($lastReportedMPServerObject.SID) {
                        $null = Upsert-Node -Id $lastReportedMPServerObject.SID -Kinds @("Computer", "Base") -PSObject $lastReportedMPServerObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                            name = $lastReportedMPServerObject.samAccountName
                            SCCMInfra = $true
                        }
                    }
                    if ($primaryUserObject.SID) {
                        $null = Upsert-Node -Id $primaryUserObject.SID -Kinds @("User", "Base") -PSObject $primaryUserObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                            name = $primaryUserObject.samAccountName
                        }
                        Upsert-Edge -Start $device.SMSID -Kind "SCCM_HasPrimaryUser" -End $primaryUserObject.SID -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                    }
                    $totalProcessed++
                }
            }
            $skip += $batchSize
        } while ($combinedDeviceResponseContent.value.Count -eq $batchSize)

        Write-LogMessage Success "Successfully processed $totalProcessed combined device resources via SMS_CombinedDeviceResources"
        return $true    
    } catch {
        Write-LogMessage Error "Failed to collect combined device resources via AdminService from $Target`: $_"
        return $false
    }
}

# Collect AD SIDs, roles, and security groups for clients and site systems via SMS_R_System
function Get-SmsRSystemViaAdminService {
    param(
        [string]$Target,
        [string]$SiteCode
    )

    try {
        Write-LogMessage Info "Collecting systems and groups via SMS_R_System from $Target for site $SiteCode"
        $select = "`$select=Client,Name,Obsolete,ResourceID,SID,SMSUniqueIdentifier,SecurityGroupName,SystemRoles"
        $batchSize = 1000
        $skip = 0
        $totalSystemsProcessed = 0
        $totalGroupsProcessed = 0

        do {
            $smsRSystemUrl = "https://$Target/AdminService/wmi/SMS_R_System?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $smsRSystemResponse = Invoke-WebRequest -Uri $smsRSystemUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Failed to collect systems and groups via SMS_R_System (skip=$skip): $_"
                return $false
            }
                
            if (-not $smsRSystemResponse -or -not $smsRSystemResponse.Content) {
                Write-LogMessage Warning "No systems and groups returned from AdminService query on $Target via SMS_R_System (skip=$skip)"
                break
            }
        
            try {
                $smsRSystemResponseContent = $smsRSystemResponse.Content | ConvertFrom-Json
            } catch {
                Write-LogMessage Error "Failed to convert response content to JSON from $Target via SMS_R_System (skip=$skip)`: $_"
                return $false
            }

            if ($smsRSystemResponseContent -and $smsRSystemResponseContent.value) {
                foreach ($device in $smsRSystemResponseContent.value) {

                    $thisClientDomainObject = Resolve-PrincipalInDomain -Name $device.Name -Domain $script:Domain

                    # Add or update Computer node if domain SID is not null
                    if ($thisClientDomainObject.SID) {
                        # Add or update Computer node
                        $null = Upsert-Node -Id $thisClientDomainObject.SID -Kinds @("Computer", "Base") -PSObject $thisClientDomainObject -Properties @{
                            collectionSource = @("AdminService-SMS_R_System")
                            name = $thisClientDomainObject.samAccountName
                            SCCMResourceIDs = @("$($device.ResourceID)@$SiteCode")
                            SCCMClientDeviceIdentifier = $device.SMSUniqueIdentifier
                        }

                        # Add Group nodes
                        foreach ($group in $device.SecurityGroupName) {
                            $thisGroupDomainObject = Resolve-PrincipalInDomain -Name $group -Domain $script:Domain
                            if ($thisGroupDomainObject.SID) {
                                $null = Upsert-Node -Id $thisGroupDomainObject.SID -Kinds @("Group", "Base") -PSObject $thisGroupDomainObject -Properties @{
                                    collectionSource = @("AdminService-SMS_R_System")
                                    name = $thisGroupDomainObject.samAccountName
                                }
                                Upsert-Edge -Start $thisClientDomainObject.SID -Kind "MemberOf" -End $thisGroupDomainObject.SID -Properties @{
                                    collectionSource = @("AdminService-SMS_R_System")
                                }
                                $totalGroupsProcessed++
                            }
                        }
                    } else {
                        Write-LogMessage Warning "No domain SID found for system $($device.Name)"
                    }

                    # Skip creation of SCCM_ClientDevice node if not a client or obsolete, which may occur when the client is reinstalled on the same machine
                    if ($device.Client -and -not $device.Obsolete) {

                        # Update the existing SCCM_ClientDevice node with the domain SID
                        $null = Upsert-Node -Id $device.SMSUniqueIdentifier -Kinds @("SCCM_ClientDevice") -Properties @{
                            collectionSource = @("AdminService-SMS_R_System")
                            ADDomainSID = if ($device.SID) { $device.SID } else { $null }
                        }
                        # There should already be an edge but just in case, add it again
                        Upsert-Edge -Start $SiteCode -Kind "SCCM_HasClient" -End $device.SMSUniqueIdentifier -Properties @{
                            collectionSource = @("AdminService-SMS_R_System")
                        }
                    }
                    $totalSystemsProcessed++
                }
            }
            $skip += $batchSize
        } while ($smsRSystemResponseContent.value.Count -eq $batchSize)

        Write-LogMessage Success "Successfully processed $totalSystemsProcessed systems and $totalGroupsProcessed groups via SMS_R_System"
        return $true
    } catch {
        Write-LogMessage Error "Failed to collect systems and groups via SMS_R_System from $Target`: $_"
        return $false
    }
}

function Get-SmsRUserViaAdminService {
    param(
        [string]$Target,
        [string]$SiteCode
    )

    try {
        Write-LogMessage Info "Collecting users and groups via SMS_R_User from $Target for site $SiteCode"
        $select = "`$select=AADTenantID,AADUserID,DistinguishedName,FullDomainName,FullUserName,Name,ResourceID,SecurityGroupName,SID,UniqueUserName,UserName,UserPrincipalName"
        $batchSize = 1000
        $skip = 0
        $totalUsersProcessed = 0
        $totalGroupsProcessed = 0

        do {
            $smsRUserUrl = "https://$Target/AdminService/wmi/SMS_R_User?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $smsRUserResponse = Invoke-WebRequest -Uri $smsRUserUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Failed to collect users and groups via SMS_R_User (skip=$skip): $_"
                return $false
            }
                
            if (-not $smsRUserResponse -or -not $smsRUserResponse.Content) {
                Write-LogMessage Warning "No users returned from AdminService query on $Target via SMS_R_User (skip=$skip)"
                break
            }
        
            try {
                $smsRUserResponseContent = $smsRUserResponse.Content | ConvertFrom-Json
            } catch {
                Write-LogMessage Error "Failed to convert response content to JSON from $Target via SMS_R_User (skip=$skip)`: $_"
                return $false
            }

            if ($smsRUserResponseContent -and $smsRUserResponseContent.value) {
                foreach ($user in $smsRUserResponseContent.value) {
          
                    $thisUserDomainObject = Resolve-PrincipalInDomain -Name $user.SID -Domain $script:Domain
        
                    # Create User node if domain SID is not null
                    if ($thisUserDomainObject.SID) {
        
                        $null = Upsert-Node -Id $thisUserDomainObject.SID -Kinds @("User", "Base") -PSObject $thisUserDomainObject -Properties @{
                            collectionSource = @("AdminService-SMS_R_User")
                            name = $thisUserDomainObject.samAccountName
                            SCCMResourceIDs = @("$($user.ResourceID)@$SiteCode")
                        }

                        # Add Group nodes
                        foreach ($group in $user.SecurityGroupName) {
                            $thisGroupDomainObject = Resolve-PrincipalInDomain -Name $group -Domain $script:Domain
                            if ($thisGroupDomainObject.SID) {
                                $null = Upsert-Node -Id $thisGroupDomainObject.SID -Kinds @("Group", "Base") -PSObject $thisGroupDomainObject -Properties @{
                                    collectionSource = @("AdminService-SMS_R_User")
                                    name = $thisGroupDomainObject.samAccountName
                                    SCCMResourceIDs = @("$($user.ResourceID)@$SiteCode")
                                }
                                Upsert-Edge -Start $thisUserDomainObject.SID -Kind "MemberOf" -End $thisGroupDomainObject.SID -Properties @{
                                    collectionSource = @("AdminService-SMS_R_User")
                                }
                                $totalGroupsProcessed++
                            }
                        }

                        $totalUsersProcessed++
                    } else {
                        Write-LogMessage Warning "No domain SID found for user $($user.Name)"
                    }
                }
            }
            $skip += $batchSize
        } while ($smsRUserResponseContent.value.Count -eq $batchSize)

        Write-LogMessage Success "Successfully processed $totalUsersProcessed users and $totalGroupsProcessed groups via SMS_R_User"
        return $true
    } catch {
        Write-LogMessage Error "Failed to collect users and groups via AdminService from $Target`: $_"
        return $false
    }
}

function Get-CollectionsViaAdminService {
    param(
        [string]$Target,
        [string]$SiteCode
    )

    try {
        Write-LogMessage Info "Collecting device/user collections via SMS_Collection from $Target for site $SiteCode"
        
        # Query SMS_Collection with specific properties as per design document
        $select = "`$select=CollectionID,CollectionType,CollectionVariablesCount,Comment,IsBuiltIn,LastChangeTime,LastMemberChangeTime,LimitToCollectionID,LimitToCollectionName,MemberCount,Name"
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            $collectionUrl = "https://$Target/AdminService/wmi/SMS_Collection?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $collectionResponse = Invoke-WebRequest -Uri $collectionUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Failed to collect device/user collections via SMS_Collection from $Target (skip=$skip)`: $_"
                return $false
            }
        
            if (-not $collectionResponse -or -not $collectionResponse.Content) {
                break
            }
        
            try {
                $collectionResponseContent = $collectionResponse.Content | ConvertFrom-Json
            } catch {
                Write-LogMessage Error "Failed to convert collection response content to JSON from $Target (skip=$skip)`: $_"
                return $false
            }
        
            foreach ($collection in $collectionResponseContent.value) {
                 
                 # Create collection node
                 $null = Upsert-Node -Id "$($collection.CollectionID)@$SiteCode" -Kinds @("SCCM_Collection") -Properties @{
                     collectionSource = @("AdminService-SMS_Collection")
                     collectionType = $collection.CollectionType
                     collectionVariablesCount = $collection.CollectionVariablesCount
                     comment = $collection.Comment
                     isBuiltIn = $collection.IsBuiltIn
                     lastChangeTime = $collection.LastChangeTime
                     lastMemberChangeTime = $collection.LastMemberChangeTime
                     limitToCollectionID = $collection.LimitToCollectionID
                     limitToCollectionName = $collection.LimitToCollectionName
                     memberCount = $collection.MemberCount
                     name = $collection.Name
                     sourceSiteCode = $SiteCode
                 }
                 $totalProcessed++
            }

            $skip += $batchSize
        } while ($collectionResponseContent.value.Count -eq $batchSize)

        Write-LogMessage Success "Collected $totalProcessed collections via AdminService"
        
        return $true
    } catch {
        Write-LogMessage Error "Failed to collect device/user collections via SMS_Collection from $Target`: $_"
        return $false
    }
}

function Get-CollectionMembersViaAdminService {
    param(
        [string]$Target
    )

    try {
        Write-LogMessage Info "Collecting collection members via SMS_FullCollectionMembership from $Target"
        # Query SMS_FullCollectionMembership as per design document
        $select = "`$select=CollectionID,ResourceID,SiteCode"
        $batchSize = 1000
        $skip = 0
        $totalMembers = 0

        do {
            $memberUrl = "https://$Target/AdminService/wmi/SMS_FullCollectionMembership?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $memberResponse = Invoke-WebRequest -Uri $memberUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Failed to collect collection members via SMS_FullCollectionMembership from $Target (skip=$skip)`: $_"
                return $false
            }
                
            if (-not $memberResponse -or -not $memberResponse.Content) {
                break
            }
        
            try {
                $memberResponseContent = $memberResponse.Content | ConvertFrom-Json
            } catch {
                Write-LogMessage Error "Failed to convert member response content to JSON from $Target (skip=$skip)`: $_"
                return $false
            }
        
            # Group members by collection for efficient processing
            $membersByCollection = $memberResponseContent.value | Group-Object -Property CollectionID
            Write-LogMessage Success "Collected $($memberResponseContent.value.Count) collection members for $($membersByCollection.Count) collections via AdminService (page)"
            
            foreach ($collection in $membersByCollection) {

                # Get site code from first member in group, will be set to root site code later
                $siteCode = $collection.Group[0].SiteCode
                $collectionId = "$($collection.Name)@$siteCode"

                # Update collection node with members
                $null = Upsert-Node -Id $collectionId -Kinds @("SCCM_Collection") -Properties @{
                    collectionSource = @("AdminService-SMS_FullCollectionMembership")
                    # Use member site code from response
                    members = $collection.Group | ForEach-Object { "$($_.ResourceID)@$($_.SiteCode)" }
                    sourceSiteCode = $siteCode
                }

                # Create edges for each member
                foreach ($member in $collection.Group) {
                    $memberNode = $null

                    # First get the node for the member
                    $memberUser = $script:Nodes | Where-Object { $_.kinds -contains "User" -and $_.properties.SCCMResourceIDs -contains "$($member.ResourceID)@$($member.SiteCode)" }
                    $memberGroup = $script:Nodes | Where-Object { $_.kinds -contains "Group" -and $_.properties.SCCMResourceIDs -contains "$($member.ResourceID)@$($member.SiteCode)" }
                    $memberDevice = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_ClientDevice" -and $_.properties.resourceID -eq "$($member.ResourceID)@$($member.SiteCode)" }
                    if ($memberUser) {
                        $memberNode = $memberUser
                    } elseif ($memberGroup) {
                        $memberNode = $memberGroup
                    } elseif ($memberDevice) {
                        $memberNode = $memberDevice
                    }

                    if ($memberNode) {
                        Upsert-Edge -Start $collectionId -Kind "SCCM_HasMember" -End $memberNode.Id -Properties @{
                            collectionSource = @("AdminService-SMS_FullCollectionMembership")
                        }
                        # Add collectionIds and collectionNames to SCCM_Client member nodes
                        if ($memberNode.kinds -contains "SCCM_ClientDevice") {
                            $null = Upsert-Node -Id $memberNode.Id -Kinds @("SCCM_ClientDevice") -Properties @{
                                collectionSource = @("AdminService-SMS_FullCollectionMembership")
                                collectionIds = @($collectionId)
                            }
                        }
                    } elseif ($member.ResourceID -eq '2046820352') {
                        Write-LogMessage Verbose "Skipping built-in collection member $($member.ResourceID): x86 Unknown Computer"
                    } elseif ($member.ResourceID -eq '2046820353') {
                        Write-LogMessage Verbose "Skipping built-in collection member $($member.ResourceID): x64 Unknown Computer"
                    } elseif ($member.ResourceID -like '203004*'){
                        Write-LogMessage Verbose "Skipping built-in collection member $($member.ResourceID): Provisioning Device"
                    } else {
                        Write-LogMessage Warning "No node found for member $($member.ResourceID) in $($collection.Name)"
                    }
                }
            }

            $totalMembers += $memberResponseContent.value.Count
            $skip += $batchSize
        } while ($memberResponseContent.value.Count -eq $batchSize)

        Write-LogMessage Success "Collected $totalMembers collection members via AdminService"
        
        return $true
    } catch {
        Write-LogMessage Error "Failed to collect device/user collection members in SMS_FullCollectionMembership from $Target`: $_"
        return $false
    }
}

function Get-SecurityRolesViaAdminService {
    param(
        [string]$Target,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage Info "Collecting security roles via SMS_Role from $Target for site $SiteCode"
        
        # select on lazy columns not supported for GetAll requests
        #$select = "`$select=CopiedFromID,CreatedBy,CreatedDate,IsBuiltIn,IsSecAdminRole,LastModifiedBy,LastModifiedDate,NumberOfAdmins,Operations,RoleID,RoleName,RoleDescription,SourceSite"
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            #$roleUrl = "https://$Target/AdminService/wmi/SMS_Role?$select&`$top=$batchSize&`$skip=$skip"
            $roleUrl = "https://$Target/AdminService/wmi/SMS_Role?`$top=$batchSize&`$skip=$skip"
            try {
                $roleResponse = Invoke-WebRequest -Uri $roleUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Failed to collect security roles via SMS_Role from $Target (skip=$skip)`: $_"
                return $false
            }
            
            if (-not $roleResponse -or -not $roleResponse.Content) { break }

            try {
                $roleResponseContent = $roleResponse.Content | ConvertFrom-Json
            } catch {
                Write-LogMessage Error "Failed to convert role response content to JSON from $Target (skip=$skip)`: $_"
                return $false
            }
            
            foreach ($role in $roleResponseContent.value) {
                        
                $null = Upsert-Node -Id "$($role.RoleID)@$SiteCode" -Kinds @("SCCM_SecurityRole") -Properties @{
                    collectionSource = @("AdminService-SMS_Role")
                    copiedFromID = if ($role.CopiedFromID) { $role.CopiedFromID } else { $null }
                    createdBy = if ($role.CreatedBy) { $role.CreatedBy } else { $null }
                    createdDate = if ($role.CreatedDate) { $role.CreatedDate } else { $null }
                    isBuiltIn = if ($role.IsBuiltIn) { $role.IsBuiltIn } else { $null }
                    isSecAdminRole = if ($role.IsSecAdminRole) { $role.IsSecAdminRole } else { $null }
                    lastModifiedBy = if ($role.LastModifiedBy) { $role.LastModifiedBy } else { $null }
                    lastModifiedDate = if ($role.LastModifiedDate) { $role.LastModifiedDate } else { $null }
                    members = @()
                    name = if ($role.RoleName) { $role.RoleName } else { $null }
                    numberOfAdmins = if ($role.NumberOfAdmins) { $role.NumberOfAdmins } else { $null }
                    operations = if ($role.Operations) { $role.Operations } else { $null }
                    roleID = if ($role.RoleID) { $role.RoleID } else { $null }
                    roleName = if ($role.RoleName) { $role.RoleName } else { $null }
                    roleDescription = if ($role.RoleDescription) { $role.RoleDescription } else { $null }
                    siteCode = $SiteCode
                }
                $totalProcessed++
            }

            $skip += $batchSize
        } while ($roleResponse.value.Count -eq $batchSize)

        Write-LogMessage Success "Collected $totalProcessed security roles via AdminService"        
        return $true
        
    } catch {
        Write-LogMessage Error "Failed to collect security roles via SMS_Role from $Target`: $_"
        return $false
    }
}

function Get-AdminUsersViaAdminService {
    param(
        [string]$Target,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage Info "Collecting admin users via SMS_Admin from $Target for site $SiteCode"
        # select on lazy columns not supported for GetAll requests
        #$select = "`$select=AccountType,AdminID,AdminSid,Categories,CategoryNames,CollectionNames,CreatedBy,CreatedDate,DisplayName,DistinguishedName,IsGroup,LastModifiedBy,LastModifiedDate,LogonName,RoleNames,Roles,SourceSite"
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            #$adminUrl = "https://$Target/AdminService/wmi/SMS_Admin?$select&`$top=$batchSize&`$skip=$skip"
            $adminUrl = "https://$Target/AdminService/wmi/SMS_Admin?`$top=$batchSize&`$skip=$skip"
            try {
                $adminResponse = Invoke-WebRequest -Uri $adminUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Failed to collect admin users via SMS_Admin from $Target (skip=$skip)`: $_"
                return $false
            }
            
            if (-not $adminResponse -or -not $adminResponse.Content) { break }

            try {
                $adminResponseContent = $adminResponse.Content | ConvertFrom-Json
            } catch {
                Write-LogMessage Error "Failed to convert admin response content to JSON from $Target (skip=$skip)`: $_"
                return $false
            }

            # Get hierarchy root site code for object identifier
            $rootSiteCode = (Get-HierarchyRoot -SiteCode $SiteCode).id
            
            foreach ($admin in $adminResponseContent.value) {

                $null = Upsert-Node -Id "$($admin.LogonName)@$rootSiteCode" -Kinds @("SCCM_AdminUser") -Properties @{
                    collectionSource = @("AdminService-SMS_Admin")
                    adminID = if ($admin.AdminID) { $admin.AdminID } else { $null }
                    adminSid = if ($admin.AdminSid) { $admin.AdminSid } else { $null }
                    collectionIds = @()
                    displayName = if ($admin.DisplayName) { $admin.DisplayName } else { $null }
                    distinguishedName = if ($admin.DistinguishedName) { $admin.DistinguishedName } else { $null }
                    isGroup = if ($admin.IsGroup) { $admin.IsGroup } else { $null }
                    lastModifiedBy = if ($admin.LastModifiedBy) { $admin.LastModifiedBy } else { $null }
                    lastModifiedDate = if ($admin.LastModifiedDate) { $admin.LastModifiedDate } else { $null }
                    memberOf = @()
                    name = if ($admin.LogonName) { $admin.LogonName } else { $null }
                    roleIDs = if ($admin.Roles) { $admin.Roles } else { $null }
                    SCCMInfra = $true
                    sourceSiteCode = if ($admin.SourceSite) { $admin.SourceSite } else { $SiteCode }
                }

                if ($admin.AdminSid) {
                    $adminDomainObject = Resolve-PrincipalInDomain -Name $admin.AdminSid -Domain $script:Domain
                    if ($adminDomainObject) {
                        # Check if user or group
                        if ($adminDomainObject.Type -eq "User") {
                            $kinds = @("User", "Base")
                        } else {
                            $kinds = @("Group", "Base")
                        }
                        # Create or update domain object node
                        $null = Upsert-Node -Id $adminDomainObject.SID -Kinds $kinds -PSObject $adminDomainObject -Properties @{
                            collectionSource = @("AdminService-SMS_Admin")
                            SCCMInfra = $true
                        }

                        # Create SCCM_IsMappedTo edge
                        Upsert-Edge -Start $adminDomainObject.SID -Kind "SCCM_IsMappedTo" -End "$($admin.LogonName)@$rootSiteCode" -Properties @{
                            collectionSource = @("AdminService-SMS_Admin")
                            SCCMInfra = $true
                        }
                    } else {
                        Write-LogMessage Warning "No domain object found for admin user $($admin.LogonName)@$rootSiteCode"
                    }
                } else {
                    Write-LogMessage Warning "No domain SID found for admin user $($admin.LogonName)@$rootSiteCode"
                }

                # Create SCCM_IsAssigned edges to collections this admin user is assigned
                if ($admin.CollectionNames) {
                    $collectionNames = $admin.CollectionNames -split ", "
                    foreach ($collectionName in $collectionNames) {
                        $collection = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Collection" -and $_.properties.name -eq "$collectionName" -and $_.id -like "*@$($rootSiteCode)" }
                        if ($collection) {
                            Upsert-Edge -Start "$($admin.LogonName)@$rootSiteCode" -Kind "SCCM_IsAssigned" -End $collection.Id -Properties @{
                                collectionSource = @("AdminService-SMS_Admin")
                            }
                            # Add collection to admin user's collectionIds property
                            $null = Upsert-Node -Id "$($admin.LogonName)@$rootSiteCode" -Kinds @("SCCM_AdminUser") -Properties @{
                                collectionSource = @("AdminService-SMS_Admin")
                                collectionIds = @($collection.Id)
                            }

                        } else {
                            Write-LogMessage Warning "No collection node found for $collectionName"
                        }
                    }
                }

                # Create SCCM_IsAssigned edges to security roles this admin user is assigned
                if ($admin.Roles -and $admin.Roles.Count -gt 0) {
                    $roleIDs = $admin.Roles -split ", "

                    foreach ($roleID in $roleIDs) {
                        $role = $script:Nodes | Where-Object { $_.Id -eq "$roleID@$rootSiteCode" }
                        if ($role) {
                            Upsert-Edge -Start "$($admin.LogonName)@$rootSiteCode" -Kind "SCCM_IsAssigned" -End $role.Id -Properties @{
                                collectionSource = @("AdminService-SMS_Admin")
                            }

                            # Add role to admin user's memberOf property
                            $null = Upsert-Node -Id "$($admin.LogonName)@$rootSiteCode" -Kinds @("SCCM_AdminUser") -Properties @{
                                collectionSource = @("AdminService-SMS_Admin")
                                memberOf = @($role.Id)
                            }

                            # Add admin user to role's members property
                            $null = Upsert-Node -Id $role.Id -Kinds @("SCCM_SecurityRole") -Properties @{
                                collectionSource = @("AdminService-SMS_Admin")
                                members = @("$($admin.LogonName)@$rootSiteCode")
                            }

                        } else {
                            Write-LogMessage Warning "No role node found for $roleID"
                        }
                    }
                } else {
                    # Fallback to RoleNames if RoleIDs is empty (it often is)
                    $roleNames = $admin.RoleNames -split ", "
                        foreach ($roleName in $roleNames) {
                            $role = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_SecurityRole" -and $_.properties.roleName -eq "$roleName" -and $_.id -like "*@$($rootSiteCode)" }
                            if ($role) {
                                    Upsert-Edge -Start "$($admin.LogonName)@$rootSiteCode" -Kind "SCCM_IsAssigned" -End $role.Id -Properties @{
                                        collectionSource = @("AdminService-SMS_Admin")
                                    }

                                    # Add role to admin user's memberOf property
                                    $null = Upsert-Node -Id "$($admin.LogonName)@$rootSiteCode" -Kinds @("SCCM_AdminUser") -Properties @{
                                        collectionSource = @("AdminService-SMS_Admin")
                                        memberOf = @($role.Id)
                                    }

                                    # Add admin user to role's members property
                                    $null = Upsert-Node -Id $role.Id -Kinds @("SCCM_SecurityRole") -Properties @{
                                        collectionSource = @("AdminService-SMS_Admin")
                                        members = @("$($admin.LogonName)@$rootSiteCode")
                                    }

                            } else {
                                    Write-LogMessage Warning "No role node found for $roleName"
                            }
                        }
                }
                $totalProcessed++
            }

            $skip += $batchSize
        } while ($adminResponse.value.Count -eq $batchSize)

        Write-LogMessage Success "Collected $totalProcessed admin users via SMS_Admin"
        
        return $true
        
    } catch {
        Write-LogMessage Error "Failed to collect admin users via SMS_Admin from $Target`: $_"
        return $false
    }
}

function Get-SiteSystemRolesViaAdminService {
    param(
        [string]$Target,
        [string]$SiteCode
    )
    
    try {
        Write-LogMessage Info "Collecting site system roles via SMS_SCI_SysResUse from $Target for site $SiteCode"
        
        # Batched query to SMS_SystemResourceList
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            $systemUrl = "https://$Target/AdminService/wmi/SMS_SCI_SysResUse?`$top=$batchSize&`$skip=$skip"
            try {
                $systemResponse = Invoke-WebRequest -Uri $systemUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop -UseBasicParsing
            } catch {
                Write-LogMessage Error "Failed to collect site system roles via SMS_SCI_SysResUse from $Target (skip=$skip)`: $_"
                return $false
            }
            
            if (-not $systemResponse -or -not $systemResponse.Content) { break }

            try {
                $systemResponseContent = $systemResponse.Content | ConvertFrom-Json
            } catch {
                Write-LogMessage Error "Failed to convert site system response content to JSON from $Target (skip=$skip)`: $_"
                return $false
            }
            
            if ($systemResponseContent -and $systemResponseContent.value) {

                # Group by NetworkOSPath and SiteCode to combine roles for same system (per page)
                $groupedSystems = $systemResponseContent.value | Group-Object -Property { "$(
                    $_.NetworkOSPath
                )_$(
                    $_.SiteCode
                )" }
                
                # For each system with at least one site system role
                foreach ($group in $groupedSystems) {

                    # Get site code from response to account for secondary sites
                    $siteCode = $group.Group[0].SiteCode
                    $systemName = $group.Group[0].NetworkOSPath.Replace('\', '')

                    # Resolve computer object first in case it's a site database running as LocalSystem or NetworkService
                    $computerObject = Resolve-PrincipalInDomain -Name $systemName -Domain $script:Domain

                    # Combine role names into array with site identifier suffix
                    $roleNames = @()
                    foreach ($role in $group.Group) {
                        if ($role.RoleName) {
                            if (-not $roleNames.Contains("$($role.RoleName)@$siteCode")) {
                                $roleNames += "$($role.RoleName)@$siteCode"
                            }
                        }

                        # Get service account from props
                        if ($role.Props) {
                            $serviceAccount = $role.Props | Where-Object { $_.PropertyName -eq 'SQL Server Service Logon Account' } | Select-Object -ExpandProperty Value2
                            if ($serviceAccount) {
                                $serviceAccountObject = Resolve-PrincipalInDomain -Name $serviceAccount -Domain $script:Domain
                                $kinds = @()
                                if ($serviceAccountObject) {
                                    if ($serviceAccountObject.Type -eq "User") {
                                        $kinds = @("User", "Base")
                                    } else {
                                        $kinds = @("Computer", "Base")
                                    }                    
                                } else {
                                    Write-LogMessage Verbose "No domain object found for $serviceAccount, the site database is running as a local account"
                                    $serviceAccountObject = $computerObject
                                    $kinds = @("Computer", "Base")
                                }
                                $null = Upsert-Node -Id $serviceAccountObject.SID -Kinds $kinds -PSObject $serviceAccountObject -Properties @{
                                    collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                    SCCMInfra = $true
                                }

                                # Update site node with service account for site database
                                $null = Upsert-Node -Id $siteCode -Kinds "SCCM_Site" -Properties @{
                                    collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                    SCCMInfra = $true
                                    SQLServiceAccountDomainSID = $serviceAccountObject.SID
                                    SQLServiceAccountName = $serviceAccountObject.samAccountName
                                }

                                # Update MSSQL_Server node with service account for site database
                                $null = Upsert-Node -Id "$($computerObject.SID):1433" -Kinds "MSSQL_Server" -Properties @{
                                    collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                    SCCMInfra = $true
                                    SQLServiceAccountDomainSID = $serviceAccountObject.SID
                                    SQLServiceAccountName = $serviceAccountObject.samAccountName
                                }
                                
                                # Create edges between service account and computer if not the same
                                if ($serviceAccountObject.SID -ne $computerObject.SID) {

                                    Upsert-Edge -Start $computerObject.SID -Kind "HasSession" -End $serviceAccountObject.SID -Properties @{
                                        collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                    }

                                    # To do: remove hardcoded port 1433 if possible
                                    Upsert-Edge -Start $serviceAccountObject.SID -Kind "MSSQL_ServiceAccountFor" -End "$($computerObject.SID):1433" -Properties @{
                                        collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                    }

                                    Upsert-Edge -Start $serviceAccountObject.SID -Kind "MSSQL_GetAdminTGS" -End "$($computerObject.SID):1433" -Properties @{
                                        collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                    }
                                }
                            }
                        }
                    }

                    # Create or update Computer node
                    if ($computerObject) {
                        $computerNode = Upsert-Node -Id $computerObject.SID -Kinds @("Computer", "Base") -PSObject $computerObject -Properties @{
                            collectionSource = @("AdminService-SMS_SCI_SysResUse")
                            name = $computerObject.samAccountName
                            SCCMInfra = $true
                            SCCMSiteSystemRoles = @($roleNames) 
                        }

                        # Add MSSQL nodes and edges for site database servers
                        if ($roleNames -contains "SMS SQL Server@$siteCode") {
                            $siteNode = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Site" -and $_.id -eq $siteCode }
                            if ($siteNode) {
                                Add-MSSQLServerNodesAndEdges -SiteNode $siteNode `
                                                             -SqlServerComputerNode $computerNode `
                                                             -CollectionSource "AdminService-SMS_SCI_SysResUse" `
                            }
                        }

                    } else {
                        Write-LogMessage Error "No domain object found for $systemName, but site systems require domain accounts"
                    }
                    $totalProcessed++
                }
            }

            $skip += $batchSize
        } while ($systemResponse.value.Count -eq $batchSize)

        Write-LogMessage Success "Collected $totalProcessed site system roles via SMS_SCI_SysResUse"
        
        return $true
        
    } catch {
        Write-LogMessage Error "Failed to collect site system roles via SMS_SCI_SysResUse from $Target`: $_"
        return $false
    }
}

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
                    $_.siteServerName -eq $target -or 
                    $_.siteServerName -like "*$($target.Split('.')[0])*" 
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
            # Extract siteGUID from Props
            $siteGuid = $null
            if ($site.Props) {
                $siteGuidProp = $site.Props | Where-Object { $_.PropertyName -eq "siteGUID" }
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
                    ParentSiteCode = $site.ParentSiteCode
                    "parentSiteIdentifier" = $null
                    "siteCode" = $site.SiteCode
                    "siteGUID" = $siteGuid
                    "siteIdentifier" = $siteIdentifier
                    "siteServerDomain" = $site.SiteServerDomain
                    "siteServerName" = $site.SiteServerName
                    "siteType" = switch ($site.SiteType) {
                        1 { "Secondary" }
                        2 { "Primary" } 
                        4 { "CentralAdministration" }
                        default { "Unknown" }
                    }
                    "SQLDatabaseName" = $site.SQLDatabaseName
                    "SQLServerName" = $site.SQLServerName
                    "source" = "WMI"
                }
                $script:Sites += $siteNode
                Write-LogMessage "Collected site via WMI: $($site.SiteCode)" -Level "Success"
            } else {
                # Update existing site with more complete information
                if ($siteGuid -and -not $existingSite.siteGUID) {
                    $existingSite.siteGUID = $siteGuid
                    $existingSite.SiteIdentifier = $siteIdentifier
                    $existingSite.Name = $site.SiteName
                    $existingSite.SiteServerDomain = $site.SiteServerDomain
                    $existingSite.SiteServerName = $site.siteServerName
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
                "sourceSiteCode" = $SiteCode
                "sourceSiteIdentifier" = $sourceSiteIdentifier
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
                "sourceSiteCode" = $admin.SourceSite
                "sourceSiteIdentifier" = $sourceSiteIdentifier
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
                "sourceSiteCode" = $SiteCode
                "sourceSiteIdentifier" = $sourceSiteIdentifier
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
                "siteGUID" = $null
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
                $systemADObject = Resolve-PrincipalInDomain -Name $hostname -Domain $script:Domain
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
                    "sourceForest" = $null
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

function Invoke-HTTPCollection {
    param($CollectionTarget)

    try {
        $target = $CollectionTarget.Hostname
        Write-LogMessage Info "Attempting HTTP collection on: $target"
        
        # First, attempt to detect if this MP's site signing certificate issuer indicates a Site Server
        try {
            Get-ManagementPointCertIssuer -CollectionTarget $CollectionTarget | Out-Null
        } catch {
            Write-LogMessage Verbose "sitesigncert issuer probe failed or not applicable on ${target}: $_"
        }
        
        # Skip if this target has already been fully collected by another method
        if ($script:CollectionTargets[$target] -and $script:CollectionTargets[$target]["Collected"]) {
            Write-LogMessage Warning "Target $target already collected, skipping HTTP"
            # Proactively mark HTTP phase as complete to avoid re-queuing
            try {
                $CollectionTarget.PhaseStatus["HTTP"] = 'Success'
                if ($script:CollectionTargets[$target].PhaseStatus) {
                    $script:CollectionTargets[$target].PhaseStatus["HTTP"] = 'Success'
                }
            } catch {}
            return
        }
        
        $siteCode = $null
        $isDP = $false
        $isMP = $false
        $isSMS = $false
        $connectionFailed = $false
                    
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
                            if ($response.IsConnectionFailure) {
                                Write-LogMessage Warning "Unable to connect to $target via $protocol - skipping remaining HTTP checks"
                                $connectionFailed = $true
                                break
                            }
                            
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
                                                $managementPoint = Add-DeviceToTargets -DeviceName $mpFQDN -Source "HTTP-MPKEYINFORMATION" -SiteCode $siteCode
                                                Write-LogMessage Success "Found site code for $mpFQDN`: $siteCode"

                                                # Create or update SCCM_Site node
                                                $null = Upsert-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                                                    collectionSource = @("HTTP-MPKEYINFORMATION")
                                                    SCCMInfra = $true
                                                    siteCode = $siteCode
                                                }                                                   
                                            }
                                        }
                                    } catch {
                                        Write-LogMessage Error "Failed to parse MPKEYINFORMATION XML response: $_"
                                    }
                                }

                                # Add site system role to Computer node properties
                                if ($managementPoint.ADObject) {
                                    $null = Upsert-Node -Id $managementPoint.ADObject.SID -Kinds @("Computer", "Base") -PSObject $managementPoint.ADObject -Properties @{
                                        collectionSource = @("HTTP-MPKEYINFORMATION")
                                        name = $managementPoint.ADObject.samAccountName
                                        SCCMInfra = $true
                                        SCCMSiteSystemRoles = @("SMS Management Point$(if ($siteCode) { "@$siteCode" })")
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
                                                    $managementPoint = Add-DeviceToTargets -DeviceName $mpFQDN -Source "HTTP-MPLIST" -SiteCode $siteCode
                                                    if ($managementPoint -and $managementPoint.IsNew) {
                                                        Write-LogMessage Success "Found management point: $mpFQDN"
                                                    }

                                                    # Add site system role to Computer node properties
                                                    if ($managementPoint.ADObject) {
                                                        $null = Upsert-Node -Id $managementPoint.ADObject.SID -Kinds @("Computer", "Base") -PSObject $managementPoint.ADObject -Properties @{
                                                            collectionSource = @("HTTP-MPKEYINFORMATION")
                                                            name = $managementPoint.ADObject.samAccountName
                                                            SCCMInfra = $true
                                                            SCCMSiteSystemRoles = @("SMS Management Point@$siteCode")
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
                            # Other errors (e.g., parsing issues) - continue trying other endpoints
                            Write-LogMessage Verbose "Management point endpoint error on $endpoint`: $_"
                            break
                        }
                    }
                }
                
                # Skip remaining checks if connection failed
                if ($connectionFailed) {
                    break
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
                            if ($response.IsConnectionFailure) {
                                Write-LogMessage Warning "Unable to connect to $target via $protocol - skipping remaining HTTP checks"
                                $connectionFailed = $true
                                break
                            }
                        } catch {
                            Write-LogMessage Verbose "Distribution point endpoint error on $endpoint`: $_"
                        }

                        # Specific response codes indicate presence of distribution point role
                        if ($response) {
                            # 401 (auth required) and 200 indicate DP presence
                            if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 200) {
                                $isDP = $true
                            } else {
                                Write-LogMessage Verbose "    Received $($response.StatusCode)"
                            }
                        }

                        if ($isDP) {
                            Write-LogMessage Success "Found distribution point role on $target"

                            # This device is already in targets but this returns its ADObject to update the Computer node properties
                            $distributionPoint = Add-DeviceToTargets -DeviceName $target -Source "HTTP-SMS_DP_SMSPKG$" -SiteCode $(if ($siteCode) { $siteCode })

                            # Assume site code is same as other roles discovered on this target
                            if (-not $siteCode -and $distributionPoint.SiteCode) {
                                Write-LogMessage Warning "Assuming site code is $($distributionPoint.SiteCode) for distribution point on $target based on other roles discovered"
                                $siteCode = $distributionPoint.SiteCode
                            }

                            # Add site system role to Computer node properties
                            if ($distributionPoint.ADObject) {
                                $null = Upsert-Node -Id $distributionPoint.ADObject.SID -Kinds @("Computer", "Base") -PSObject $distributionPoint.ADObject -Properties @{
                                    collectionSource = @("HTTP-SMS_DP_SMSPKG$")
                                    name = $distributionPoint.ADObject.samAccountName
                                    SCCMInfra = $true
                                    SCCMSiteSystemRoles = @("SMS Distribution Point$(if ($siteCode) { "@$siteCode" })") # We can't get the site code via HTTP unless the target is also a MP but might be able to later via SMB
                                }
                            }
                        }
                    }
                }

                # Test SMS Provider HTTP endpoints
                if ($isSMS -ne $true) {
                    $response = $null
                    $endpoint = "https://$target/AdminService/wmi/SMS_Identification"

                    try {
                        Write-LogMessage Verbose "Testing SMS Provider endpoint: $endpoint"
                        $response = Invoke-HttpRequest $endpoint
                        if ($response.IsConnectionFailure) {
                            Write-LogMessage Warning "Unable to connect to $target via HTTPS - skipping remaining HTTP checks"
                            $connectionFailed = $true
                            break
                        }
                    } catch {
                        Write-LogMessage Verbose "SMS Provider endpoint error on $endpoint`: $_"
                    }

                    # Specific response codes indicate presence of distribution point role
                    if ($response) {
                        # 401 (auth required) and 200 indicate DP presence
                        if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 200) {
                            $isSMS = $true
                        } else {
                            Write-LogMessage Verbose "    Received $($response.StatusCode)"
                        }
                    }

                    if ($isSMS) {
                        Write-LogMessage Success "Found SMS Provider role on $target"

                        # This device is already in targets but this returns its ADObject to update the Computer node properties
                        $smsProvider = Add-DeviceToTargets -DeviceName $target -Source "HTTP-SMS_Identification" -SiteCode $(if ($siteCode) { $siteCode })

                        # Assume site code is same as other roles discovered on this target
                        if (-not $siteCode -and $smsProvider.SiteCode) {
                            Write-LogMessage Warning "Assuming site code is $($smsProvider.SiteCode) for SMS Provider on $target based on other roles discovered"
                            $siteCode = $smsProvider.SiteCode
                        }

                        # Add site system role to Computer node properties
                        if ($smsProvider.ADObject) {
                            $null = Upsert-Node -Id $smsProvider.ADObject.SID -Kinds @("Computer", "Base") -PSObject $smsProvider.ADObject -Properties @{
                                collectionSource = @("HTTP-SMS_Identification")
                                name = $smsProvider.ADObject.samAccountName
                                SCCMInfra = $true
                                SCCMSiteSystemRoles = @("SMS Provider$(if ($siteCode) { "@$siteCode" })") # We can't get the site code via HTTP unless the target is also a MP but might be able to later via SMB
                            }
                        }
                    }
                    
                    # Skip remaining checks if connection failed
                    if ($connectionFailed) {
                        break
                    }
                }
            } catch {
                Write-LogMessage Warning "HTTP collection failed for protocol $protocol on $target`: $_"
            }
            
            # Skip trying the next protocol if connection failed
            if ($connectionFailed) {
                break
            }
        }
    } catch {
        Write-LogMessage Warning "HTTP collection failed for $target`: $_"
    }

    # Mark phase success when HTTP probe finished without fatal errors
    try {
        if ($CollectionTarget -and $CollectionTarget.PhaseStatus) {
            $CollectionTarget.PhaseStatus["HTTP"] = 'Success'
        }
        if ($target -and $script:CollectionTargets[$target] -and $script:CollectionTargets[$target].PhaseStatus) {
            $script:CollectionTargets[$target].PhaseStatus["HTTP"] = 'Success'
        }
    } catch {}
    Write-LogMessage Success "HTTP collection completed"
    Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
    Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.dNSHostName) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
    Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
}

function Get-ManagementPointCertIssuer {
    param(
        $CollectionTarget
    )

    try {
        $target = $CollectionTarget.Hostname
        if (-not $target) { return }

        Write-LogMessage Verbose "Probing MP site signing certificate issuer on: $target"

        $issuerCN = $null
        $siteServerHostname = $null
        $protocols = @('http','https')
        foreach ($protocol in $protocols) {
            $endpoint = "$protocol`://$target/SMS_MP/.sms_aut?sitesigncert"
            try {
                $resp = Invoke-HttpRequest $endpoint
                if ($resp -and $resp.StatusCode -eq 200 -and $resp.Content) {
                    # Extract the hex-encoded DER from the X509Certificate element content (ignore attributes like Signature)
                    $hex = $null
                    try {
                        $xml = [xml]$resp.Content
                        $certNode = $xml.SelectSingleNode('//X509Certificate')
                        if ($certNode -and $certNode.InnerText) {
                            $hex = ($certNode.InnerText).Trim()
                        }
                    } catch {
                        Write-LogMessage Verbose "Failed to parse XML from sitesigncert on ${target}: $_"
                    }

                    if ($hex -and ($hex.Length % 2 -eq 0) -and $hex.Length -ge 20) {
                        $bytes = New-Object byte[] ($hex.Length/2)
                        for ($i=0; $i -lt $bytes.Length; $i++) {
                            $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2,2),16)
                        }
                        try {
                            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
                            $issuer = $cert.Issuer
                            if ($issuer -match 'CN\s*=\s*([^,]+)') { $issuerCN = $matches[1].Trim() }
                            if (-not $issuerCN) {
                                # Fallback to simple name lookup on issuer
                                $issuerCN = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
                            }
                            Write-LogMessage Verbose "sitesigncert issuer CN: $issuerCN"

                            $siteServerHostname = $cert.DnsNameList | Where-Object { $_ -and $_ -ne "" } | Select-Object -First 1
                            if ($siteServerHostname) {
                                Write-LogMessage Verbose "sitesigncert DNS Name: $siteServerHostname"
                            }
                        } catch {
                            Write-LogMessage Verbose "Failed to parse certificate from sitesigncert on ${target}: $_"
                        }
                    } else {
                        Write-LogMessage Verbose "sitesigncert response did not contain a valid hex payload"
                    }
                }
            } catch {
                Write-LogMessage Verbose "sitesigncert endpoint not accessible via ${protocol} on ${target}: $_"
            }

            if ($issuerCN) { break }
        }

        if ($issuerCN -and ($issuerCN -match '(?i)^Site Server$' -or $issuerCN -match '(?i)Site Server') -and $siteServerHostname) {
            Write-LogMessage Success "Detected Site Server certificate issuer $siteServerHostname via sitesigncert"
            # Attach role to the computer node
            $device = Add-DeviceToTargets -DeviceName $siteServerHostname -Source "HTTP-sitesigncert"
            if ($device -and $device.ADObject -and $device.ADObject.SID) {
                $null = Upsert-Node -Id $device.ADObject.SID -Kinds @("Computer","Base") -PSObject $device.ADObject -Properties @{
                    collectionSource = @("HTTP-sitesigncert")
                    name = $device.ADObject.samAccountName
                    SCCMInfra = $true
                    SCCMSiteSystemRoles = @("SMS Site Server$(if ($CollectionTarget.SiteCode) { "@$($CollectionTarget.SiteCode)" })")
                }
            }
        }
    } catch {
        Write-LogMessage Error "Get-ManagementPointCertIssuer encountered an error: $_"
    }
}

function Invoke-SMBCollection {
    param($CollectionTarget)

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
    
    # Use canonical hostname key for CollectionTargets lookups
    $target = $CollectionTarget.Hostname

    # Skip if already collected successfully
    if ($script:CollectionTargets[$target]["Collected"]) {
        Write-LogMessage Info "Target $target already collected, skipping SMB"
        return
    }
    
    # Check SMB signing requirement
    Write-LogMessage Info "Checking SMB signing requirement on $target"
    $smbSigningResult = Get-SMBSigningRequiredViaSMBNegotiate -ComputerName $target

    if ($smbSigningResult.SigningRequired -ne $null) {
        if ($smbSigningResult.SigningRequired -eq $true) {
            Write-LogMessage Verbose "SMB signing is REQUIRED on $target (detected via $($smbSigningResult.Method))"
        } elseif ($smbSigningResult.SigningRequired -eq $false) {
            Write-LogMessage Verbose "SMB signing is NOT required on $target (detected via $($smbSigningResult.Method))"
        } else {
            Write-LogMessage Verbose "Could not determine SMB signing requirement on $target`: $($smbSigningResult.Error)"
        }
        # Update Computer node property
        $null = Upsert-Node -Id $CollectionTarget.ADObject.SID -Kinds @("Computer","Base") -PSObject $CollectionTarget.ADObject -Properties @{
            SMBSigningRequired = $smbSigningResult.SigningRequired
            CollectionSource = @("SMB-Negotiate")
        }
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
            $smsStar = $shares | Where-Object { $_.Name -match "^SMS_(\w+)$" }                  
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
            if (-not $isSiteServer -and $smsStar) {
                $collectionSource += "SMB-SMS_*"

                if ($smsSite.Description -match "SMS Site (\w+)") {
                    $isSiteServer = $true
                    $siteCode = $Matches[1]
                    Write-LogMessage Success "Found site server for site: $siteCode"
                } else {
                    Write-LogMessage Warning "Could not determine site code from SMS_* share description"
                }
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
            if ($siteCode) {
                $null = Upsert-Node -Id $siteCode -Kinds @("SCCM_Site") -Properties @{
                    collectionSource = $collectionSource
                    SCCMInfra = $true
                    siteCode = $siteCode
                }
            }
            # Create or update the Computer node with site system roles and properties
            $roles = @()
            if ($isSiteServer) {
                $roles += "SMS Site Server$(if ($siteCode) { "@$siteCode"})"
            }
            if ($isDP) {
                $roles += "SMS Distribution Point$(if ($siteCode) { "@$siteCode"})"
            }

            $null = Upsert-Node -Id $CollectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $CollectionTarget.ADObject -Properties @{
                collectionSource = $collectionSource
                name = $CollectionTarget.ADObject.samAccountName
                SCCMHostsContentLibrary = $hostsContentLib
                SCCMInfra = $true
                SCCMIsPXESupportEnabled = $isPXEEnabled
                SCCMSiteSystemRoles = if ($roles) { @($roles) } else { $null }
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

    Write-LogMessage "SMB collection completed" -Level "Success"
    Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
    Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.dNSHostName) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
    Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
}

#endregion


#region Output Generation
    
# Helper function to display current file size
function Show-CurrentFileSize {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        [string]$Context = ""
    )
    
    try {
        # Calculate cumulative size of completed files only
        $cumulativeSize = 0
        $fileCount = $script:OutputFiles.Count
        
        foreach ($file in $script:OutputFiles) {
            if (Test-Path $file) {
                $fileInfo = Get-Item $file
                $cumulativeSize += $fileInfo.Length
            }
        }
        
        # Get current file size (not included in cumulative)
        $currentFileSize = 0
        if (Test-Path $WriterObj.FilePath) {
            $fileInfo = Get-Item $WriterObj.FilePath
            $currentFileSize = $fileInfo.Length
            
            # Format current file size for display
            $currentSizeDisplay = if ($currentFileSize -ge 1GB) {
                "$([math]::Round($currentFileSize/1GB, 2)) GB"
            } elseif ($currentFileSize -ge 1MB) {
                "$([math]::Round($currentFileSize/1MB, 2)) MB"
            } elseif ($currentFileSize -ge 1KB) {
                "$([math]::Round($currentFileSize/1KB, 2)) KB"
            } else {
                "$currentFileSize bytes"
            }
        }
        
        # Format cumulative size (completed files only)
        $sizeDisplay = if ($cumulativeSize -ge 1GB) {
            "$([math]::Round($cumulativeSize/1GB, 2)) GB"
        } elseif ($cumulativeSize -ge 1MB) {
            "$([math]::Round($cumulativeSize/1MB, 2)) MB"
        } elseif ($cumulativeSize -ge 1KB) {
            "$([math]::Round($cumulativeSize/1KB, 2)) KB"
        } else {
            "$cumulativeSize bytes"
        }
        
        $contextText = if ($Context) { " ($Context)" } else { "" }
        
        # Show current file and cumulative of completed files
        if ($fileCount -gt 0) {
            Write-LogMessage Info "Current file size: $currentSizeDisplay`nCumulative file size: $sizeDisplay across $fileCount files$contextText"
        } else {
            Write-LogMessage Info "Current file size: $currentSizeDisplay"
        }
    }
    catch {
        # Silently continue if there's an error checking file size
    }
}

# Helper function to check if enough time has passed for periodic update
function Test-ShouldShowPeriodicUpdate {
    $currentTime = Get-Date
    if (-not $script:LastFileSizeCheck) {
        $script:LastFileSizeCheck = $currentTime
        return $true
    }
    $timeSinceLastCheck = ($currentTime - $script:LastFileSizeCheck).TotalSeconds
    $interval = if ($script:FileSizeCheckInterval) { $script:FileSizeCheckInterval } else { 5 }
    if ($timeSinceLastCheck -ge $interval) {
        $script:LastFileSizeCheck = $currentTime
        return $true
    }
    return $false
}

# Helper function to check file size
function Test-FileSizeLimit {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        [string]$SizeLimitString = "1GB"
    )
    
    # If we're already stopping, just return true without additional warnings
    if ($script:stopProcessing) {
        return $true
    }
    
    try {
        # Parse the size limit string
        $SizeLimitBytes = 0
        if ([string]::IsNullOrWhiteSpace($SizeLimitString)) {
            $SizeLimitBytes = 1GB
        }
        elseif ($SizeLimitString -match '^(\d+\.?\d*)\s*(GB|MB|KB|B)?$') {
            $value = [double]$matches[1]
            $unit = $matches[2]
            
            switch ($unit) {
                "GB" { $SizeLimitBytes = $value * 1GB }
                "MB" { $SizeLimitBytes = $value * 1MB }
                "KB" { $SizeLimitBytes = $value * 1KB }
                "B"  { $SizeLimitBytes = $value }
                default { $SizeLimitBytes = $value * 1GB } # Default to GB if no unit
            }
        } else {
            Write-LogMessage Warning "Invalid file size limit format: '$SizeLimitString'. Using default 1GB."
            $SizeLimitBytes = 1GB
        }
        
        # Calculate cumulative size of all completed files
        $cumulativeSize = 0
        foreach ($file in $script:OutputFiles) {
            if (Test-Path $file) {
                $fileInfo = Get-Item $file
                $cumulativeSize += $fileInfo.Length
            }
        }
        
        # Add current file being written
        if ($WriterObj.FilePath -and (Test-Path $WriterObj.FilePath)) {
            $currentFileInfo = Get-Item $WriterObj.FilePath
            $cumulativeSize += $currentFileInfo.Length
        }
        
        if ($cumulativeSize -ge $SizeLimitBytes) {
            $totalFiles = $script:OutputFiles.Count
            if ($WriterObj.FilePath -and (Test-Path $WriterObj.FilePath)) {
                $totalFiles++ # Include current file in count
            }
            Write-LogMessage Warning "Cumulative file size limit reached: $([math]::Round($cumulativeSize/1MB, 2)) MB >= $SizeLimitString"
            Write-LogMessage Warning "Total files: $totalFiles ($(($script:OutputFiles.Count)) completed + 1 in progress)"
            return $true
        }
        
        return $false
    }
    catch {
        Write-LogMessage Error "Error checking file size: $_"
        return $false
    }
}

# Memory monitoring function
function Test-MemoryUsage {
    param(
        [int]$Threshold = 80
    )
    
    $os = Get-CimInstance Win32_OperatingSystem
    $memoryUsedGB = ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB
    $totalMemoryGB = $os.TotalVisibleMemorySize / 1MB
    $percentUsed = ($memoryUsedGB / $totalMemoryGB) * 100
    
    Write-LogMessage Info "Memory usage: $([math]::Round($percentUsed, 2))% ($([math]::Round($memoryUsedGB, 2))GB / $([math]::Round($totalMemoryGB, 2))GB)"
    
    if ($percentUsed -gt $Threshold) {
        Write-LogMessage Warning "Memory usage is at $([math]::Round($percentUsed, 2))%. Threshold: $Threshold%"
        return $false
    }
    return $true
}

# Create constructor functions for streaming writers
function New-BaseStreamingWriter {
    param(
        [string]$FilePath,
        [string]$WriterType = "Base"
    )
    
    # Store the absolute path - ensure it's relative to current directory
    if ([System.IO.Path]::IsPathRooted($FilePath)) {
        $absolutePath = $FilePath
    } else {
        # Use PowerShell's current location for relative paths
        $absolutePath = Join-Path (Get-Location).Path $FilePath
    }

    try {
        # Ensure directory exists
        $directory = [System.IO.Path]::GetDirectoryName($absolutePath)
        if ($directory -and -not [System.IO.Directory]::Exists($directory)) {
            [System.IO.Directory]::CreateDirectory($directory) | Out-Null
        }
        
        # Create the file with explicit encoding
        $writer = New-Object System.IO.StreamWriter($absolutePath, $false, [System.Text.Encoding]::UTF8)
        $writer.AutoFlush = $true
        
        # Verify file was created
        if (Test-Path $absolutePath) {
            Write-LogMessage Info "Created output file: $absolutePath"
        } else {
            throw "File was not created at: $absolutePath"
        }
        
        # Return writer object with metadata
        $writerObj = New-Object PSObject -Property @{
            Writer = $writer
            FilePath = $absolutePath
            ItemCount = 0
            WriterType = $WriterType
        }
        
        return $writerObj
    }
    catch {
        Write-LogMessage Error "Failed to create output file '$absolutePath': $_"
        throw
    }
}

function Close-StreamingWriter {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj
    )
    
    try {
        if ($WriterObj.Writer) {
            $WriterObj.Writer.Flush()
            $WriterObj.Writer.Close()
            $WriterObj.Writer.Dispose()
            $WriterObj.Writer = $null
            
            # Small delay to ensure file system has caught up
            Start-Sleep -Milliseconds 100
            
            # Verify file exists and has content
            if (Test-Path $WriterObj.FilePath) {
                $fileInfo = Get-Item $WriterObj.FilePath
                Write-LogMessage Success "Output written to $($WriterObj.FilePath)"
                # Convert bytes to appropriate unit
                $fileSize = $fileInfo.Length
                if ($fileSize -ge 1MB) {
                    Write-LogMessage Info "File size: $([math]::Round($fileSize/1MB, 2)) MB"
                } elseif ($fileSize -ge 1KB) {
                    Write-LogMessage Info "File size: $([math]::Round($fileSize/1KB, 2)) KB"
                } else {
                    Write-LogMessage Info "File size: $fileSize bytes"
                }                
            } else {
                Write-LogMessage Error "File was not found after closing: $($WriterObj.FilePath)"
            }
        }
    }
    catch {
        Write-LogMessage Error "Error closing file: $_"
        Write-LogMessage Error $_.Exception.StackTrace
    }
}

function New-StreamingBloodHoundWriter {
    param(
        [string]$FilePath
    )
    
    $writerObj = New-BaseStreamingWriter -FilePath $FilePath -WriterType "BloodHound"
    
    # Add BloodHound-specific properties
    $writerObj | Add-Member -MemberType NoteProperty -Name "FirstNode" -Value $true
    $writerObj | Add-Member -MemberType NoteProperty -Name "FirstEdge" -Value $true
    $writerObj | Add-Member -MemberType NoteProperty -Name "NodeCount" -Value 0
    $writerObj | Add-Member -MemberType NoteProperty -Name "EdgeCount" -Value 0
    
    # Start JSON structure
    $writerObj.Writer.WriteLine('{')
    # Removing until deletion issue is fixed

    $writerObj.Writer.WriteLine('  "$schema": "https://raw.githubusercontent.com/MichaelGrafnetter/EntraAuthPolicyHound/refs/heads/main/bloodhound-opengraph.schema.json",')
    $writerObj.Writer.WriteLine('  "metadata": {')
    $writerObj.Writer.WriteLine('    "source_kind": "SCCM_Base"')
    $writerObj.Writer.WriteLine('  },')
    $writerObj.Writer.WriteLine('  "graph": {')
    $writerObj.Writer.WriteLine('    "nodes": [')
    $writerObj.Writer.Flush()
    
    return $writerObj
}

function Write-BloodHoundNode {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        
        [Parameter(Mandatory=$true)]
        [PSObject]$Node
    )
    
    # Skip if we're already stopping
    if ($script:stopProcessing) { return }
    
    try {
        # Check file size limit
        if (Test-FileSizeLimit -WriterObj $WriterObj -SizeLimitString $script:FileSizeLimit) {
            $script:stopProcessing = $true
            return
        }
        
        # Show file size on first node write for this file
        if ($WriterObj.NodeCount -eq 0) {
            Show-CurrentFileSize -WriterObj $WriterObj
        }
        
        # Show periodic file size update
        if (Test-ShouldShowPeriodicUpdate) {
            Show-CurrentFileSize -WriterObj $WriterObj -Context "periodic update"
        }
        
        if (-not $WriterObj.FirstNode) {
            $WriterObj.Writer.WriteLine(',')
        }
        $WriterObj.FirstNode = $false
        $WriterObj.NodeCount++
        $WriterObj.ItemCount++
        
        $json = $Node | ConvertTo-Json -Depth 10 -Compress
        $WriterObj.Writer.Write('      ' + $json)
        $WriterObj.Writer.Flush()
    }
    catch {
        Write-LogMessage Error "Error writing node: $_"
    }
}

function Write-BloodHoundEdge {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj,
        
        [Parameter(Mandatory=$true)]
        [PSObject]$Edge
    )
    
    # Skip if we're already stopping
    if ($script:stopProcessing) { return }
    
    try {
        # Check file size limit
        if (Test-FileSizeLimit -WriterObj $WriterObj -SizeLimitString $script:FileSizeLimit) {
            $script:stopProcessing = $true
            return
        }
        
        # Show periodic file size update
        if (Test-ShouldShowPeriodicUpdate) {
            Show-CurrentFileSize -WriterObj $WriterObj -Context "periodic update"
        }
        
        # If this is the first edge ever, close nodes array and start edges array
        if ($WriterObj.EdgeCount -eq 0 -and $WriterObj.NodeCount -gt 0) {
            $WriterObj.Writer.WriteLine('')  # Close last node line
            $WriterObj.Writer.WriteLine('    ],')
            $WriterObj.Writer.WriteLine('    "edges": [')
            $WriterObj.Writer.Flush()
        }
        
        # Write comma if not first edge
        if (-not $WriterObj.FirstEdge) {
            $WriterObj.Writer.WriteLine(',')
        }
        $WriterObj.FirstEdge = $false
        $WriterObj.EdgeCount++
        $WriterObj.ItemCount++
        
        $json = $Edge | ConvertTo-Json -Depth 10 -Compress
        $WriterObj.Writer.Write('      ' + $json)
        $WriterObj.Writer.Flush()
    }
    catch {
        Write-LogMessage Error "Error writing edge: $_"
    }
}

function Close-BloodHoundWriter {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject]$WriterObj
    )
    
    try {
        # If we wrote nodes but no edges, close nodes array and add empty edges array
        if ($WriterObj.NodeCount -gt 0 -and $WriterObj.EdgeCount -eq 0) {
            $WriterObj.Writer.WriteLine('')
            $WriterObj.Writer.WriteLine('    ],')
            $WriterObj.Writer.WriteLine('    "edges": [')
        }
        
        # Close the JSON structure
        if ($WriterObj.EdgeCount -gt 0 -or $WriterObj.NodeCount -gt 0) {
            $WriterObj.Writer.WriteLine('')
        }
        $WriterObj.Writer.WriteLine('    ]')
        $WriterObj.Writer.WriteLine('  }')
        $WriterObj.Writer.WriteLine('}')
        
        # Ensure everything is written
        $WriterObj.Writer.Flush()
                
        Close-StreamingWriter -WriterObj $WriterObj
    }
    catch {
        Write-LogMessage Error "Error closing BloodHound file: $_"
        Write-LogMessage Error $_.Exception.StackTrace
    }
}

function Export-BloodHoundData {
    
    # Report collection statistics
    $totalTargets = $script:CollectionTargets.Count
    $collectedTargets = ($script:CollectionTargets.Values | Where-Object { $_.Collected }).Count
    $uncollectedTargets = $totalTargets - $collectedTargets
    
    Write-LogMessage Info "Collection Statistics:"
    Write-LogMessage Info "Total targets identified: $totalTargets"
    Write-LogMessage Success "Successfully collected: $collectedTargets"
    Write-LogMessage Warning "Failed to collect: $uncollectedTargets"
    
    Write-LogMessage Info "Total nodes created: $($script:Nodes.Count)"
    Write-LogMessage Info "Total edges created: $($script:Edges.Count)"


    # Don't proceed if no nodes or edges were created
    if ($script:Nodes.Count -eq 0 -and $script:Edges.Count -eq 0) {
        Write-LogMessage Warning "No nodes or edges were created, skipping BloodHound export"
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
    $script:OutputFiles += $bloodhoundFile
    
    Write-LogMessage Info "Writing BloodHound data..."

    try {
        $serverWriter = New-StreamingBloodHoundWriter -FilePath $bloodhoundFile
        Write-LogMessage Info "Writing to file: $bloodhoundFile"
        
        # Write all nodes for this server
        foreach ($node in $script:Nodes) {
            Write-BloodHoundNode -WriterObj $serverWriter -Node $node
        }
        
        # Write all edges for this server
        foreach ($edge in $script:Edges) {
            Write-BloodHoundEdge -WriterObj $serverWriter -Edge $edge
        }
        
        Write-LogMessage Success "Wrote $(($script:Nodes).Count) nodes and $(($script:Edges).Count) edges"
        
        # Show final size before closing
        Show-CurrentFileSize -WriterObj $serverWriter -Context "finalizing"

        # Close this server's file
        Close-BloodHoundWriter -WriterObj $serverWriter
    }
    catch {
        Write-LogMessage Error "Failed to write BloodHound data to $bloodhoundFile`: $_"
        if ($serverWriter) {
            try { Close-BloodHoundWriter -WriterObj $serverWriter } catch {}
        }
    }
}

#endregion

#region Main Execution Logic
function Get-InputTargets {
    param([string[]]$Computers, [string]$ComputerFile, [string]$SMSProvider)

    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($Computers) {
        foreach ($c in ($Computers -join ',' -split ',')) {
            $n = $c.Trim(); if ($n) { [void]$set.Add($n) }
        }
    }
    if ($ComputerFile -and (Test-Path -LiteralPath $ComputerFile)) {
        foreach ($n in (Get-Content -LiteralPath $ComputerFile)) {
            $n = $n.Trim(); if ($n) { [void]$set.Add($n) }
        }
    } elseif ($ComputerFile) {
        Write-LogMessage Warning "File not found: $ComputerFile"
    }
    if ($SMSProvider) { [void]$set.Add($SMSProvider.Trim()) }

    ,$set
}

function Start-SCCMCollection {
    Write-LogMessage Info "Initializing SCCM collection..."

    # 1) Phases
    $script:SelectedPhases = Get-SelectedPhases -Methods $CollectionMethods
    Write-LogMessage Info ("Selected phases: " + ($script:SelectedPhases -join ", "))

    # 2) Inputs -> optional allow-list filter
    $inputSet   = Get-InputTargets -Computers $Computers -ComputerFile $ComputerFile -SMSProvider $SMSProvider
    $useFilter  = ($inputSet.Count -gt 0)
    
    if ($useFilter) {
        $script:AllowedTargets = $inputSet
    } else {
        $script:AllowedTargets = $null
    }

    if (-not $script:CollectionTargets) { $script:CollectionTargets = @{} }

    # 3) Seed targets (Add-DeviceToTargets handles AD resolution + filter)
    foreach ($h in $inputSet) {
        $src = if ($SMSProvider -and $h -eq $SMSProvider) { 'ScriptParameter-SMSProvider' }
               elseif ($Computers -and ($Computers -contains $h)) { 'ScriptParameter-Computers' }
               elseif ($ComputerFile) { 'ScriptParameter-ComputerFile' }
               else { 'ScriptParameter' }
        Add-DeviceToTargets -DeviceName $h -Source $src | Out-Null
    }

    # Fail if no targets after seeding and no once phases specified
    if ($script:CollectionTargets.Count -eq 0 -and -not ($script:SelectedPhases | Where-Object { $_ -in @('LDAP','Local','DNS','DHCP') } )) {
        Write-LogMessage Warning "No targets identified for collection. Discover using ""-CollectionMethods 'All|LDAP|Local|DNS|DHCP'"" or provide targets via ""-Computers"", ""-ComputerFile"", or ""-SMSProvider"" parameters."
        return
    }

    # 4) SMSProvider-only convenience (keep just AdminService/WMI unless once-phases explicitly requested)
    if ($SMSProvider) {
        $onceRequested = @('LDAP','Local','DNS','DHCP') | Where-Object { $_ -in $script:SelectedPhases }
        if (-not $onceRequested) {
            $script:SelectedPhases = @('AdminService','WMI') | Where-Object { $_ -in $script:SelectedPhases } 
            if (-not $script:SelectedPhases) { $script:SelectedPhases = @('AdminService','WMI') }
            Write-LogMessage Info ("SMS Provider mode -> phases: " + ($script:SelectedPhases -join ', '))
        }
    }

    # 5) Orchestrate (runs once-phases once; per-host phases for all targets; respects filter)
    Invoke-DiscoveryPipeline -SelectedPhases $script:SelectedPhases

    Write-LogMessage Success "SCCM collection completed."
}

#endregion


#region Script Entry Point

# Main execution
try {
    # Display help text
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Path -Detailed
        return
    }

    # Global variables
    $script:CollectionTargets = @{}
    $script:OutputFiles = @()
    $script:UseNetFallback = $false
    $script:FileSizeLimit = $FileSizeLimit
    $script:LastFileSizeCheck = Get-Date
    $script:FileSizeCheckInterval = $FileSizeUpdateInterval

    # Initialize output structures
    $script:Nodes = @()
    $script:Edges = @()

    # Script version information
    $script:ScriptVersion = "1.0"
    $script:ScriptName = "ConfigManBearPig"

    if ($Version) {
        Write-Host "$script:ScriptName version $script:ScriptVersion" -ForegroundColor Green
        return
    }

    if ($OutputFormat -eq "CustomNodes") {
        $customNodes = @{
            "custom_types" = @{
                "SCCM_Site" = @{
                    "icon" = @{
                        "color" = "#67ebf0"
                        "name" = "city"
                        "type" = "font-awesome"
                    }
                }
                "SCCM_AdminUser" = @{
                    "icon" = @{
                        "color" = "#558eea"
                        "name" = "user-gear"
                        "type" = "font-awesome"
                    }
                }
                "SCCM_SecurityRole" = @{
                    "icon" = @{
                        "color" = "#9852ed"
                        "name" = "users-gear"
                        "type" = "font-awesome"
                    }
                }
                "SCCM_Collection" = @{
                    "icon" = @{
                        "color" = "#fff82e"
                        "name" = "sitemap"
                        "type" = "font-awesome"
                    }
                }
                "SCCM_ClientDevice" = @{
                    "icon" = @{
                        "color" = "#f59b42"
                        "name" = "desktop"
                        "type" = "font-awesome"
                    }
                }
                "MSSQL_DatabaseUser" = @{
                    "icon" = @{
                        "color" = "#f5ef42"
                        "name" = "user"
                        "type" = "font-awesome"
                    }
                }
                "MSSQL_Login" = @{
                    "icon" = @{
                        "color" = "#dd42f5"
                        "name" = "user-gear"
                        "type" = "font-awesome"
                    }
                }
                "MSSQL_DatabaseRole" = @{
                    "icon" = @{
                        "color" = "#f5a142"
                        "name" = "users"
                        "type" = "font-awesome"
                    }
                }
                "MSSQL_Database" = @{
                    "icon" = @{
                        "color" = "#f54242"
                        "name" = "database"
                        "type" = "font-awesome"
                    }
                }
                "MSSQL_Server" = @{
                    "icon" = @{
                        "color" = "#42b9f5"
                        "name" = "server"
                        "type" = "font-awesome"
                    }
                }
                "MSSQL_ServerRole" = @{
                    "icon" = @{
                        "color" = "#6942f5"
                        "name" = "users-gear"
                        "type" = "font-awesome"
                    }
                }
            }
        }
        
        # Output the custom nodes JSON and exit
        $customNodes | ConvertTo-Json -Depth 10 
        $customNodes | ConvertTo-Json -Depth 10 | clip.exe
    
        # Output to clipboard
        Write-Host "All custom node types JSON copied to clipboard!" -ForegroundColor Green
        Write-Host "POST to /api/v2/custom-nodes (e.g., in API Explorer)" -ForegroundColor Green
        return
    }

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

    # Flush resolved domain name cache
    Write-LogMessage Verbose "Flushing domain principal resolution cache"
    $ResolvedPrincipalCache = @{}

    if ($Domain) {
        $script:Domain = $Domain
    } else {
        $script:Domain = $null
    }
    if ($DomainController) {
        $script:DomainController = $DomainController
    } else {
        $script:DomainController = $null
    }

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Write-LogMessage Success "Using ActiveDirectory module for name resolution"
        } catch {
            Write-LogMessage Error "Failed to load ActiveDirectory module: $_"
            return
        }
    } else {
        Write-LogMessage Verbose "ActiveDirectory module not found"
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
            Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
            Write-LogMessage Success "Using .NET DirectoryServices for name resolution"
            $script:UseNetFallback = $true
        } catch {
            Write-LogMessage Error "Failed to load .NET DirectoryServices assemblies: $_"
            return
        }
    }

    if (-not $script:Domain) {
        try {
            Write-LogMessage Verbose "No domain provided and could not find `$env:USERDNSDOMAIN, trying computer's domain"
            $script:Domain = (Get-CimInstance Win32_ComputerSystem).Domain
            Write-LogMessage Info "Using computer's domain: $script:Domain"
        } catch {
            Write-LogMessage Error "Error getting computer's domain, using `$env:USERDOMAIN: $_"
            $script:Domain = $env:USERDOMAIN
        }
    } 
    else {
        if (-not $script:DomainController) {
            Write-LogMessage Verbose "No domain controller provided, trying to find one"
            try {
                if (Get-Command -Name Get-ADDomainController -ErrorAction SilentlyContinue) {
                    $dc = Get-ADDomainController -Discover -Domain $script:Domain -ErrorAction SilentlyContinue
                    $script:DomainController = $dc.HostName[0]
                } else {
                    # Fallback using .NET
                    $context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new("Domain", $script:Domain)
                    $gotDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
                    $script:DomainController = $gotDomain.FindDomainController().Name
                }
            } catch {
                Write-LogMessage Error "Failed to find domain controller: $_"
                return
            }
            if (-not $script:DomainController) {
                Write-LogMessage Error "Failed to find domain controller"
                return
            }
            Write-LogMessage Success "Found domain controller: $script:DomainController"
        } else {
            Write-LogMessage Info "Using specified domain controller: $script:DomainController"
        }
    }
    if (Test-DnsResolution -Domain $script:Domain) {
        Write-LogMessage Success "DNS resolution successful"
    } else {
        Write-LogMessage Error "DNS resolution failed"
        return
    }
    
    # Collection phases to run
    $collectionMethodsSplit = $CollectionMethods -split "," | ForEach-Object { $_.Trim().ToUpper() }
    $enableLDAP = $false
    $enableLocal = $false
    $enableDNS = $false
    $enableDHCP = $false
    $enableRemoteRegistry = $false
    $enableMSSQL = $false
    $enableAdminService = $false
    $enableWMI = $false
    $enableHTTP = $false
    $enableSMB = $false
    
    # Process each specified method
    foreach ($method in $collectionMethodsSplit) {
        switch ($method) {
            "ALL" {
                $enableLDAP = $true
                $enableLocal = $true
                $enableDNS = $true
                $enableDHCP = $true
                $enableRemoteRegistry = $true
                $enableMSSQL = $true
                $enableAdminService = $true
                $enableWMI = $true
                $enableHTTP = $true
                $enableSMB = $true
            }
            "LDAP" { $enableLDAP = $true }
            "LOCAL" { $enableLocal = $true }
            "DNS" { $enableDNS = $true }
            "DHCP" { $enableDHCP = $true }
            "REMOTEREGISTRY" { $enableRemoteRegistry = $true }
            "MSSQL" { $enableMSSQL = $true }
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
    
    # Disable certificate validation in a cross-version way

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        # Windows PowerShell 5.1 (full .NET Framework)

        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            Add-Type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                    ServicePoint srvPoint,
                    X509Certificate certificate,
                    WebRequest request,
                    int certificateProblem) {
                    return true;
                }
            }
"@
        }

        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }

    else {
        # PowerShell 7+ (.NET Core / .NET)
        $PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
    }

    # Start collection
    Start-SCCMCollection

    # Start post-processing
    Invoke-PostProcessing

    
} catch {
    Write-LogMessage Error "Critical error during execution: $_"
    Write-LogMessage Error "Stack trace: $($_.Exception.StackTrace)"
    exit 1
} finally {
    # Always output what we can even if the script was stopped
    Export-BloodHoundData
    if ($script:OutputFiles.Count -gt 0) {
        Write-LogMessage Info "Output files created:"
        $totalSize = 0
        
        foreach ($file in $script:OutputFiles) {
            if (Test-Path $file) {
                $fileInfo = Get-Item $file
                $totalSize += $fileInfo.Length
                
                $sizeDisplay = if ($fileInfo.Length -ge 1MB) {
                    "$([math]::Round($fileInfo.Length/1MB, 2)) MB"
                } elseif ($fileInfo.Length -ge 1KB) {
                    "$([math]::Round($fileInfo.Length/1KB, 2)) KB"
                } else {
                    "$($fileInfo.Length) bytes"
                }
                
                Write-LogMessage Info "  $file - $sizeDisplay" 
            }
        }
        
        # Show total size
        $totalSizeDisplay = if ($totalSize -ge 1GB) {
            "$([math]::Round($totalSize/1GB, 2)) GB"
        } elseif ($totalSize -ge 1MB) {
            "$([math]::Round($totalSize/1MB, 2)) MB"
        } elseif ($totalSize -ge 1KB) {
            "$([math]::Round($totalSize/1KB, 2)) KB"
        } else {
            "$totalSize bytes"
        }
        
        if ($stopProcessing) {
            $foregroundColor = "Red"
        } else {
            $foregroundColor = "Green"
        }
        Write-LogMessage Info "Total size: $totalSizeDisplay across $($script:OutputFiles.Count) files"
        
        # Automatically compress if CompressOutput is specified or if there are multiple files
        if ($script:OutputFiles.Count -gt 0) {

            try {
                # Generate timestamp for unique filename
                $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                $zipFileName = "bloodhound-sccm-$timestamp.zip"
                # Always output zip to current directory
                if ($ZipDir) {
                    $zipFilePath = $ZipDir
                } else {
                    $zipFilePath = Join-Path (Get-Location).Path $zipFileName
                }

                # PowerShell version check
                if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
                    # PowerShell 5.0+ has built-in compression
                    Compress-Archive -Path $script:OutputFiles -DestinationPath $zipFilePath -CompressionLevel Optimal
                } else {
                    # For older PowerShell versions, use .NET
                    Write-LogMessage Info "Using .NET compression for PowerShell v$($PSVersionTable.PSVersion.Major)"
                    
                    # Load the required assembly
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    
                    # Create the ZIP file
                    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
                    
                    # Ensure the ZIP file doesn't already exist
                    if (Test-Path $zipFilePath) {
                        Remove-Item $zipFilePath -Force
                    }
                    
                    # Create the ZIP archive
                    $zipArchive = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'Create')
                    
                    try {
                        foreach ($file in $script:OutputFiles) {
                            if (Test-Path $file) {
                                Write-LogMessage Info "  Adding: $(Split-Path $file -Leaf)"
                                $entryName = [System.IO.Path]::GetFileName($file)
                                $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $file, $entryName, $compressionLevel)
                            }
                        }
                    }
                    finally {
                        # Always dispose of the ZIP archive
                        if ($zipArchive) {
                            $zipArchive.Dispose()
                        }
                    }
                }
                
                # Verify ZIP was created
                if (Test-Path $zipFilePath) {
                    $zipInfo = Get-Item $zipFilePath
                    $zipSizeDisplay = if ($zipInfo.Length -ge 1MB) {
                        "$([math]::Round($zipInfo.Length/1MB, 2)) MB"
                    } elseif ($zipInfo.Length -ge 1KB) {
                        "$([math]::Round($zipInfo.Length/1KB, 2)) KB"
                    } else {
                        "$($zipInfo.Length) bytes"
                    }
                    
                    Write-LogMessage Success "ZIP archive created successfully: $zipFileName ($zipSizeDisplay)"
                    
                    # Calculate compression ratio
                    if ($totalSize -gt 0) {
                        $compressionRatio = [math]::Round((1 - ($zipInfo.Length / $totalSize)) * 100, 1)
                        Write-LogMessage Info "Compression ratio: $compressionRatio% reduction"
                    }
                    
                    # Delete original files
                    Write-LogMessage Info "Deleting original files..."
                    $deletedCount = 0
                    $failedDeletes = @()
                    
                    foreach ($file in $script:OutputFiles) {
                        if (Test-Path $file) {
                            try {
                                Remove-Item $file -Force -ErrorAction Stop
                                $deletedCount++
                            } catch {
                                $failedDeletes += $file
                                Write-LogMessage Warning "Failed to delete: $(Split-Path $file -Leaf) - $_"
                            }
                        }
                    }
                    
                    if ($deletedCount -gt 0) {
                        Write-LogMessage Success "Successfully deleted $deletedCount original files"
                    }
                    
                    if ($failedDeletes.Count -gt 0) {
                        Write-LogMessage Warning "Failed to delete $($failedDeletes.Count) files. Manual cleanup required."
                    }
                    
                    # Final output location
                    $finalOutput = (Get-Item $zipFilePath).FullName
                    Write-LogMessage Success "Final output: $finalOutput"
                } else {
                    Write-Error "Failed to create ZIP archive"
                }
            } catch {
                Write-LogMessage Error "Error creating ZIP archive: $_"
                Write-LogMessage Warning "Original files have been preserved"
            }
        } 
    } else {
        Write-LogMessage Warning "No output files were created"
    }

    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "ConfigManBearPig execution completed" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}


#endregion