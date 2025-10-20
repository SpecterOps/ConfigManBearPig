<#
.SYNOPSIS
ConfigManBearPig: PowerShell collector for adding SCCM attack paths to BloodHound with OpenGraph

.DESCRIPTION
Author: Chris Thompson (@_Mayyhem) at SpecterOps

Purpose:
    Collects BloodHound OpenGraph compatible SCCM data following these ordered steps:
    1.  LDAP (identify sites, site servers, fallback status points, and management points in System Management container)
    2.  DHCP (identify PXE-enabled distribution points)
    3.  Local (identify management points and distribution points in logs when running this script on an SCCM client)
    4.  DNS (identify management points published to DNS)
    5.  Remote Registry (identify site servers, site databases, and current users on targets)
    6.  MSSQL (check database servers for Extended Protection for Authentication)
    7.  AdminService (collect information from SMS Providers with privileges to query site information)
    8.  WMI (if AdminService collection fails)
    9.  HTTP (identify management points and distribution points via exposed web services)
    10. SMB (identify site servers and management points via file shares)
      
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
    - DHCP
    - Local
    - DNS
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

.PARAMETER Domain
Specify a domain to use for LDAP queries and name resolution

.PARAMETER DomainController
Specify a domain controller to use for DNS and AD object resolution

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

    [string]$Computers,
    
    [string]$SMSProvider,

    [string]$SiteCodes,
    
    [string]$OutputFormat = "Zip",

    [string]$FileSizeLimit = "1GB",
    
    [string]$FileSizeUpdateInterval = "5",
    
    [string]$TempDir,
    
    [string]$ZipDir,
    
    [string]$Domain = $env:USERDNSDOMAIN,

    [string]$DomainController,
    
    [switch]$SkipPostProcessing,

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
        $padding = " " * (9 - $Level.Length)
        Write-Host "[$timestamp] [$Level]$padding $Message" -ForegroundColor $color
    }
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
$script:PhasesOnce    = @('LDAP','DHCP','Local','DNS')

# Phases that run PER HOST
$script:PhasesPerHost = @('RemoteRegistry','MSSQL','AdminService','WMI','HTTP','SMB')

# Canonical overall order (for selection + display)
$script:AllPhases = $script:PhasesOnce + $script:PhasesPerHost

# Map of phase -> scriptblock
#   - Once phases: { param() <do global work; may add to $script:CollectionTargets> }
#   - Per-host phases: { param($Target) <work per device> }
$script:PhaseActionsOnce = @{
    LDAP = { param()  Write-LogMessage Verbose "LDAP phase starting"; Invoke-LDAPCollection; }
    DHCP = { param()  Write-LogMessage Verbose "DHCP phase starting"; Invoke-DHCPCollection; }
    Local = { param() Write-LogMessage Verbose "Local phase starting"; Invoke-LocalCollection; }
    DNS = { param()   Write-LogMessage Verbose "DNS phase starting"; Invoke-DNSCollection; }
}

$script:PhaseActionsPerHost = @{
    RemoteRegistry = { param($Target)  Write-LogMessage Verbose "RemoteRegistry -> $($Target.Hostname)"; Invoke-RemoteRegistryCollection -CollectionTarget $Target; }
    MSSQL = { param($Target) Write-LogMessage Verbose "MSSQL -> $($Target.Hostname)"; Invoke-MSSQLCollection -CollectionTarget $Target; }
    AdminService = { param($Target)   Write-LogMessage Verbose "AdminService -> $($Target.Hostname)"; Invoke-AdminServiceCollection -CollectionTarget $Target; }
    WMI = { param($Target)  Write-LogMessage Verbose "WMI -> $($Target.Hostname)"; Invoke-WMICollection -Target $Target; }
    HTTP = { param($Target) Write-LogMessage Verbose "HTTP -> $($Target.Hostname)"; Invoke-HTTPCollection -CollectionTarget $Target; }
    SMB = { param($Target)  Write-LogMessage Verbose "SMB -> $($Target.Hostname)"; Invoke-SMBCollection -CollectionTarget $Target; }
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
    [string[]]$SelectedPhases,
    [int]$MaxParallel = 1  # 1 = serial; >1 = parallel (PowerShell 7+)
  )

  # 1) Run ONCE phases in order (only those selected)
  Ensure-GlobalPhaseStatus -SelectedPhases $SelectedPhases

  foreach ($phase in $script:PhasesOnce) {
    if ($phase -notin $SelectedPhases) { continue }
    if ($script:GlobalPhaseStatus[$phase] -ne 'Pending') { continue }

    Write-LogMessage Verbose "Once phase [$phase] starting..."
    try {
      & $script:PhaseActionsOnce[$phase]   # no target; may add to $script:CollectionTargets
      $script:GlobalPhaseStatus[$phase] = 'Success'
      Write-LogMessage Verbose "Once phase [$phase] complete."
    } catch {
      $script:GlobalPhaseStatus[$phase] = 'Failed'
      Write-LogMessage Error "Phase [$phase] failed: $_"
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
      Write-LogMessage Verbose "Per-host phase [$phase]: $($pending.Hostname.Count) target(s)"

      # Serial (Windows PowerShell or MaxParallel = 1)
      if ($MaxParallel -le 1 -or $PSVersionTable.PSEdition -ne 'Core') {
        foreach ($t in $pending) {
          try {
            & $script:PhaseActionsPerHost[$phase] -Target $t
            $t.PhaseStatus[$phase] = 'Success'
          } catch {
            $t.PhaseStatus[$phase] = 'Failed'
            Write-LogMessage Error "[$phase] failed on $($t.Hostname): $_"
          }
        }
        continue
      }

      # Parallel (PowerShell 7+)
      $pending | ForEach-Object -Parallel {
        param($phaseName, $phaseActions)
        try {
          & $phaseActions[$phaseName] -Target $_
          $_.PhaseStatus[$phaseName] = 'Success'
        } catch {
          $_.PhaseStatus[$phaseName] = 'Failed'
        }
      } -ThrottleLimit $MaxParallel -ArgumentList $phase, $using:script:PhaseActionsPerHost
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
    
    # Initialize and check cache to avoid repeated lookups
    if (-not $script:ResolvedPrincipalCache) { $script:ResolvedPrincipalCache = @{} }
    $cacheKey = ("{0}|{1}" -f $Domain, $Name).ToLower()
    if ($script:ResolvedPrincipalCache.ContainsKey($cacheKey)) {
        if ($script:ResolvedPrincipalCache[$cacheKey] -eq $null) {
            Write-LogMessage Verbose "Already tried to resolve $Name in domain $Domain and failed, skipping"
            return $null
        }
        Write-LogMessage Verbose "Resolved $Name in domain $Domain from cache"
        return $script:ResolvedPrincipalCache[$cacheKey]
    }

    Write-LogMessage Verbose "Attempting to resolve $Name in domain $Domain"
    
    $adPowershellSucceeded = $false
    
    # Try Active Directory PowerShell module first
    if (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) {
        Write-LogMessage Verbose "Trying AD PowerShell module in domain $Domain"
        
        try {
            $adObject = $null
            
            # Set server parameter if domain is specified and different from current
            $adParams = @{ Identity = $Name }
            if ($script:DomainController) {
                $adParams.Server = $script.DomainController
            } elseif ($Domain -and $Domain -ne $env:USERDOMAIN -and $Domain -ne $env:USERDNSDOMAIN) {
                $adParams.Server = $Domain
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
                                    Write-LogMessage Verbose "No AD object found for '$Name' in domain '$Domain'"
                                }
                            }
                        }
                    }
                }
            }
            
            if ($adObject) {
                $adObjectName = if ($adObject.UserPrincipalName) { $adObject.UserPrincipalName } elseif ($adObject.DNSHostName) { $adObject.DNSHostName } else { $adObject.SamAccountName }
                $adObjectSid = $adObject.SID.ToString()
                Write-LogMessage Verbose "Resolved '$Name' to AD principal in '$Domain': $adObjectName ($adObjectSid)"
                
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
                    Domain = $Domain
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
            Write-LogMessage Verbose "AD PowerShell lookup failed for '$Name' in domain '$Domain': $_"
        }
    }
    
    # Try .NET DirectoryServices AccountManagement
    if ($script:UseNetFallback -or -not (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) -or -not $adPowershellSucceeded) {
        Write-LogMessage Verbose "Attempting .NET DirectoryServices AccountManagement for '$Name' in domain '$Domain'"
        
        try {
            # Try AccountManagement approach
             # Use Domain Controller if specified
             if ($script:DomainController) {
                Write-LogMessage Verbose "Creating PrincipalContext with domain controller $script:DomainController"
                $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                    [System.DirectoryServices.AccountManagement.ContextType]::Domain, 
                    $script:DomainController
                )
            } else {
                $context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
                    [System.DirectoryServices.AccountManagement.ContextType]::Domain, 
                    $Domain
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
                    DNSHostName = if ($principal.GetType().Name -eq "ComputerPrincipal") { $principal.Name } else { $null }
                    Domain = $Domain
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
            }
            
            $context.Dispose()
            
        } catch {
            Write-LogMessage Verbose "Failed .NET DirectoryServices AccountManagement for '$Name' in domain '$Domain': $_"
        }
        
        # Try ADSISearcher approach
        try {
            Write-LogMessage Verbose "Attempting ADSISearcher for '$Name' in domain '$Domain'"
            
            # Build LDAP path
            $domainDN = if ($Domain) {
                "DC=" + ($Domain -replace "\.", ",DC=")
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
                    Domain = $Domain
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
            Write-LogMessage Verbose "ADSISearcher lookup failed for '$Name' in domain '$Domain': $_"
        }
        
        # Try DirectorySearcher as final .NET attempt
        try {
            Write-LogMessage Verbose "Attempting DirectorySearcher for '$Name' in domain '$Domain'"
            
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
                    Domain = $Domain
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
            Write-LogMessage Verbose "DirectorySearcher failed for '$Name' in domain '$Domain': $_"
        }
    }
    
    # Try NTAccount translation
    try {
        Write-LogMessage Verbose "Attempting NTAccount translation for '$Name' in domain '$Domain'"
        
        # Try direct SID lookup
        $ntAccount = New-Object System.Security.Principal.NTAccount($Domain, $Name)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        $resolvedSid = $sid.Value
        Write-LogMessage Verbose "Resolved SID for '$Name' using NTAccount in '$Domain': $resolvedSid"
        
        $ntResult = [PSCustomObject]@{
            name = "$Domain\$Name"
            SID = $resolvedSid
            Domain = $Domain
            Error = $null
        }
        $script:ResolvedPrincipalCache[$cacheKey] = $ntResult
        return $ntResult
    } catch {
        Write-LogMessage Verbose "NTAccount translation failed for '$Name' in domain '$Domain': $_"
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
                Domain = $Domain
                Error = $null
            }
            $script:ResolvedPrincipalCache[$cacheKey] = $sidResult
            return $sidResult
        } catch {
            Write-LogMessage Verbose "SID to name translation failed for '$Name': $_"
        }
    }
    
    # Return failure
    $script:ResolvedPrincipalCache[$cacheKey] = $null
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

    # No filter → allow everything
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

    # Enforce the allow-list (names/IPs). If not allowed → skip.
    if (-not (Test-AllowedTarget -DeviceName $DeviceName -AdObject $adObject)) {
        Write-LogMessage Verbose "Skipped '$DeviceName' (not in allowed targets filter)"
        return $null
    }

    # Dedup key: prefer SID if resolved; else use lowercase name
    $dedupKey = $null
    $canonicalName = $DeviceName
    if ($adObject -and $adObject.SID) {
        $dedupKey      = $adObject.SID
        $canonicalName = if ($adObject.DNSHostName) { $adObject.DNSHostName } else { $adObject.Name }
    } else {
        $dedupKey = $DeviceName.ToLowerInvariant()
        if (-not ($DeviceName -match '\.')) {
            # keep short name as provided; resolution may happen later in another phase
        }
        Write-LogMessage Warning "Could not resolve '$DeviceName' to a domain object; adding by name."
    }

    # Existing target by dedup key?
    $existingTarget = $script:CollectionTargets.Values | Where-Object { $_.DedupKey -eq $dedupKey } | Select-Object -First 1
    if ($existingTarget) {
        # Prefer FQDN if we now have it
        $isExistingShort = ($existingTarget.Hostname -notmatch '\.')
        $isNewFqdn       = ($canonicalName -match '\.')
        if ($isNewFqdn -and $isExistingShort) {
            Write-LogMessage Verbose "Upgrading hostname '$($existingTarget.Hostname)' → FQDN '$canonicalName'"
            $existingTarget.Hostname = $canonicalName
        }

        # Merge source tag
        if ($Source -and ($existingTarget.Source -notlike "*$Source*")) {
            $existingTarget.Source = ($existingTarget.Source, $Source) -join ", "
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


function Get-SameAdminsAsSites {
    param([string]$SiteIdentifier)
    
    $relatedSites = @()
    $site = $script:Sites | Where-Object { $_.siteIdentifier -eq $SiteIdentifier }
    
    if ($site) {
        # Find all sites with same parentSiteCode (same hierarchy)
        $hierarchySites = $script:Sites | Where-Object { $_.parentSiteCode -eq $site.parentSiteCode }
        $relatedSites += $hierarchySites
        
        # Recursively find sites connected via SCCM_SameAdminsAs edges
        # This is a simplified version - full implementation would need graph traversal
        $relatedSites += $script:Sites | Where-Object { 
            $_.parentSiteCode -eq $site.siteCode -or 
            $_.siteCode -eq $site.parentSiteCode 
        }
    }
    
    return ($relatedSites | Sort-Object SiteIdentifier -Unique)
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
                -and $_.Name -ne "ObjectIdentifier" `
                -and -not $finalProperties.ContainsKey($_.Name)) {
                    $finalProperties[$_.Name] = $_.Value
            }
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
        foreach ($key in $finalProperties.Keys) {
            if ($null -ne $finalProperties[$key]) {
                if ($existingProps.ContainsKey($key)) {
                    $oldValue = $existingProps[$key]
                    $newValue = $finalProperties[$key]
                    
                    # Special handling for arrays - merge them
                    if ($oldValue -is [Array] -and $newValue -is [Array]) {
                        # Combine and deduplicate arrays
                        $mergedArray = @($oldValue + $newValue | Select-Object -Unique)
                        $existingProps[$key] = $mergedArray
                        
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
                        $existingProps[$key] = $newValue
                    }
                } else {
                    # New property being added
                    $valueStr = if ($finalProperties[$key] -is [Array]) { 
                        "[$($finalProperties[$key] -join ', ')]" 
                    } else { 
                        "'$($finalProperties[$key])'" 
                    }
                    $addedProperties += "$key`: $valueStr"
                    $existingProps[$key] = $finalProperties[$key]
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
            Write-LogMessage Verbose "Found existing $($Kinds[0]) node: $($existingNode.properties.samAccountName) ($Id)$changes"
        } else {
            Write-LogMessage Verbose "Found existing $($Kinds[0]) node: $($existingNode.properties.samAccountName) ($Id)`nNo new properties"
        }

        # Replace properties with normalized/merged set
        $existingNode.properties = $existingProps
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

    ### This section is kind of like running post-processing after adding each node ###
   
    # Create Host nodes and SameHostAs edges for Computer/ClientDevice pairs
    if ($Kinds -contains "Computer" -or $Kinds -contains "SCCM_ClientDevice") {
        Add-HostNodeAndEdges -NodeId $Id -NodeKinds $Kinds -NodeProperties $finalProperties  # Use $finalProperties
    }

    if ($Kinds -contains "Computer") {
        if ($finalProperties["SCCMSiteSystemRoles"]) {

            # Get site identifier from SCCMSiteSystemRoles
            $siteIdentifier = $finalProperties["SCCMSiteSystemRoles"].Split("@")[1]
            if ($siteIdentifier) {

                # Find the primary site for this site system
                $primarySite = $script:Nodes | Where-Object { $_.Id -eq $siteIdentifier -and $_.Type -ne "Secondary Site" }
                if ($primarySite) {

                    # Add AdminTo edges from site servers to all the other site systems in primary sites
                    $siteServer = $script:Nodes | Where-Object { $_.properties.SCCMSiteSystemRoles -contains "SMS Site Server@$($primarySite.Id)"}
                    if ($siteServer) {
                        # Don't add AdminTo edges from the site server to the site server -- the computer account may not be in the local admins group
                        if ($Id -ne $siteServer.Id) {
                            Add-Edge -Start $siteServer.Id -Kind "AdminTo" -End $Id -Properties @{
                                collectionSource = $finalProperties["collectionSource"]
                            }
                        # If this is a primary site server, add AdminTo edges to all the other site systems 
                        } else {
                            $siteSystems = $script:Nodes | Where-Object { $_.properties.SCCMSiteSystemRoles -like "*@$($primarySite.Id)" -and $_.properties.SCCMSiteSystemRoles -notlike "*SMS Site Server@$($primarySite.Id)*" }
                            if ($siteSystems) {
                                foreach ($siteSystem in $siteSystems) {
                                    Add-Edge -Start $Id -Kind "AdminTo" -End $siteSystem.Id -Properties @{
                                        collectionSource = $finalProperties["collectionSource"]
                                    }            
                                }
                            }
                        }
                    }

                    # If an SMS Provider domain computer account is being added, create SCCM_AssignAllPermissionsWMI edge to the site server and a MSSQL_HasLogin edge to the site database login
                    if ($finalProperties["SCCMSiteSystemRoles"] -contains "SMS Provider@$($primarySite.Id)") {
                        Add-Edge -Start $Id -Kind "SCCM_AssignAllPermissionsWMI" -End $siteIdentifier -Properties @{
                            collectionSource = $finalProperties["collectionSource"]
                        }
                        $siteDatabaseComputerNodes = $script:Nodes | Where-Object { $_.kinds -eq "Computer" -and $_.properties.SCCMSiteSystemRoles -contains "SMS Site Database@$($primarySite.Id)" }
                        if ($siteDatabaseComputerNodes -and $siteDatabaseComputerNodes.Count -gt 0) {
                            # There could be multiple site database servers in a site (e.g. for high availability), so create edges to all of them
                            foreach ($siteDatabaseComputerNode in $siteDatabaseComputerNodes) {
                                $siteDatabaseLoginNode = $script:Nodes | Where-Object { $_.kinds -eq "MSSQL_Login" -and $_.Id -eq "$($finalProperties["name"])@$($siteDatabaseComputerNode.Id)" }
                                if ($siteDatabaseLoginNode) {
                                    Add-Edge -Start $Id -Kind "MSSQL_HasLogin" -End $siteDatabaseLoginNode.Id -Properties @{
                                        collectionSource = $finalProperties["collectionSource"]
                                    }
                                }
                            }
                        }
                    }

                    # Add CoerceAndRelayToMSSQL edges for site servers, site database servers, SMS Providers, and management points
                    if ($finalProperties["SCCMSiteSystemRoles"] -match "SMS (Site Server|SQL Server|Provider|Management Point)@$($primarySite.Id)") {
                        Process-CoerceAndRelayToMSSQL -SiteIdentifier $primarySite.Id -CollectionSource $finalProperties["collectionSource"]
                    }
                }
            }
        }
    }

    if ($Kinds -contains "MSSQL_Login" -or $Kinds -contains "MSSQL_Server") {
        $siteIdentifier = $finalProperties["SCCMSite"]
        if ($siteIdentifier) {

            # Create MSSQL_HasLogin edges from site server and SMS Provider Computer nodes to site database MSSQL_Login nodes
            $siteServerComputerNode = $script:Nodes | Where-Object { $_.kinds -eq "Computer" -and $_.properties.samAccountName -eq $($Id.Split('@')[0]) -and $_.properties.SCCMSiteSystemRoles -contains "SMS Site Server@$siteIdentifier" }
            if ($siteServerComputerNode) {
                Add-Edge -Start $Id -Kind "MSSQL_HasLogin" -End $siteServerComputerNode.Id -Properties @{
                    collectionSource = $finalProperties["collectionSource"]
                }
            }
            $smsProviderComputerNode = $script:Nodes | Where-Object { $_.kinds -eq "Computer" -and $_.properties.samAccountName -eq $($Id.Split('@')[0]) -and $_.properties.SCCMSiteSystemRoles -contains "SMS Provider@$siteIdentifier" }
            if ($smsProviderComputerNode) {
                Add-Edge -Start $Id -Kind "SCCM_AssignAllPermissionsWMI" -End $smsProviderComputerNode.Id -Properties @{
                    collectionSource = $finalProperties["collectionSource"]
                }
            }

            # Add CoerceAndRelayToMSSQL edges for site servers, site database servers, SMS Providers, and management points in this site
            Process-CoerceAndRelayToMSSQL -SiteIdentifier $siteIdentifier -CollectionSource $finalProperties["collectionSource"]
        }
    }

    if ($Kinds -contains "SCCM_Site") {

        # Create SCCM_AssignAllPermissionsWMI edges from all SMS Providers in this site to this SCCM_Site
        $smsProviderComputerNodes = $script:Nodes | Where-Object { $_.kinds -eq "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Provider@$Id" }
        if ($smsProviderComputerNodes -and $smsProviderComputerNodes.Count -gt 0) {
            foreach ($smsProviderComputerNode in $smsProviderComputerNodes) {
                Add-Edge -Start $smsProviderComputerNode.Id -Kind "SCCM_AssignAllPermissionsWMI" -End $Id -Properties @{
                    collectionSource = $finalProperties["collectionSource"]
                }
            }
        }

        # Auto-create SCCM_SameAdminsAs edges for SCCM_Site nodes
        $parentSiteCode = $finalProperties["parentSiteCode"]
        $siteType = $finalProperties["siteType"]
        
        if ($parentSiteCode -and $parentSiteCode -ne "" -and $parentSiteCode -ne "None") {
            # Create parent-child edges per rules:
            # - Central <-> Primary (both directions)
            # - Primary -> Secondary (one direction)
            $parentCandidates = $script:Nodes | Where-Object {
                $_.kinds -contains "SCCM_Site" -and (
                    $_.id -eq $parentSiteCode -or
                    $_.properties.siteCode -eq $parentSiteCode -or
                    $_.properties.siteIdentifier -eq $parentSiteCode
                )
            }
            if ($parentCandidates -and $parentCandidates.Count -gt 0) {
                $parent = $parentCandidates[0]
                $parentType = $parent.properties.siteType
                # Central <-> Primary
                if ( ($parentType -eq "Central Administration Site" -and $siteType -eq "Primary Site") -or
                        ($parentType -eq "Primary Site" -and $siteType -eq "Central Administration Site") ) {
                    $existsP2C = $script:Edges | Where-Object { $_.start -eq $parent.id -and $_.end -eq $Id -and $_.kind -eq "SCCM_SameAdminsAs" }
                    if (-not $existsP2C) { Add-Edge -Start $parent.id -Kind "SCCM_SameAdminsAs" -End $Id }
                    $existsC2P = $script:Edges | Where-Object { $_.start -eq $Id -and $_.end -eq $parent.id -and $_.kind -eq "SCCM_SameAdminsAs" }
                    if (-not $existsC2P) { Add-Edge -Start $Id -Kind "SCCM_SameAdminsAs" -End $parent.id }
                }
                # Primary -> Secondary only
                elseif ($parentType -eq "Primary Site" -and $siteType -eq "Secondary Site") {
                    $existsP2C = $script:Edges | Where-Object { $_.start -eq $parent.id -and $_.end -eq $Id -and $_.kind -eq "SCCM_SameAdminsAs" }
                    if (-not $existsP2C) { Add-Edge -Start $parent.id -Kind "SCCM_SameAdminsAs" -End $Id }
                }
            }
        }
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

    # Deduplicate: skip if identical edge already exists
    $duplicate = $script:Edges | Where-Object { $_.start.value -eq $Start -and $_.kind -eq $Kind -and $_.end.value -eq $End }
    if ($duplicate) {
        Write-LogMessage Verbose ("Skipping duplicate edge {0} -[{1}]-> {2}" -f $Start, $Kind, $End)
        return
    }

    # Filter out null properties
    $cleanProperties = @{}
    foreach ($key in $Properties.Keys) {
        if ($null -ne $Properties[$key]) {
            $cleanProperties[$key] = $Properties[$key]
        }
    }

    # Create new edge
    $edge = @{
        start = @{ value = $Start }
        end = @{ value = $End }
        kind = $Kind
        properties = $cleanProperties
    }
    
    $script:Edges += $edge
    Write-LogMessage Verbose "Added edge: $Start -[$Kind]-> $End (edge count: $($script:Edges.Count))"
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
        $hostId = "$($matchingNode.Properties.DNSHostName)_${hostGuid}"
        
        $computerSid = if ($matchingNode.kinds -contains "Computer") { $matchingNode.id } else { $NodeId }
        $clientDeviceId = if ($matchingNode.kinds -contains "SCCM_ClientDevice") { $matchingNode.id } else { $NodeId }

        # Create Host node
        Add-Node -Id $hostId -Kinds @("Host") -Properties @{
            name = "Host_$($matchingNode.Properties.DNSHostName)"
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
            Add-Edge -Start $edge.Start -Kind "SameHostAs" -End $edge.End
        }
        
        Write-LogMessage Verbose "Created $computerSid <-[SameHostAs]-> $hostId <-[SameHostAs]-> $clientDeviceId nodes and edges"
    }
}
#endregion

#region Collection Functions
function Add-AdminToEdgesForSiteServer {
    # This function should check if there are any nodes of kind Computer where SCCMSiteSystemRoles contains "SMS Site Server" for the given site
    # If such a node exists, it should create an edge of kind AdminTo to every other node of kind Computer where SCCMSiteSystemRoles is not empty and does not contain "SMS Site Server" for the same site
    param([string]$SiteIdentifier)
    $site = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Site" -and $_.Id -eq $SiteIdentifier }
    if (-not $site) { 
        Write-LogMessage Warning "Site not found for AdminTo edge creation: $SiteIdentifier"
        return  
    }
}

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
                    else {
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
            
            # Use only site code as ObjectIdentifier for LDAP collection
            $objectIdentifier = $siteCode
            
            # Create/update SCCM_Site node
            Add-Node -Id $objectIdentifier -Kinds @("SCCM_Site", "SCCM_Infra") -Properties @{
                collectionSource = @("LDAP-mSSMSSite")
                name = $null
                distinguishedName = $mSSMSSiteObj.DistinguishedName
                parentSiteCode = $null # Will be determined by mSSMSManagementPoint
                parentSiteGUID = $null # Will be determined by mSSMSManagementPoint
                parentSiteIdentifier = $null # Will be determined by mSSMSManagementPoint
                siteCode = $siteCode
                siteGUID = $siteGuid
                siteName = $null
                siteServerDomain = $null
                siteServerName = $null
                siteServerObjectIdentifier = $null
                siteType = $null # Will be determined by mSSMSManagementPoint
                sourceForest = $mSSMSSiteObj.mSSMSSourceForest
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
                $mpTarget = Add-DeviceToTargets -DeviceName $mpHostname -Source "LDAP-mSSMSManagementPoint" -SiteCode $mpSiteCode
                if ($mpTarget -and $mpTarget.IsNew) {
                    Write-LogMessage Success "Found management point: $($mpTarget.Hostname) (site: $mpSiteCode)"
                }
                # Create or update Computer node
                if ($mpTarget.ADObject) {
                    Add-Node -Id $mpTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $mpTarget.ADObject -Properties @{
                        collectionSource = @("LDAP-mSSMSManagementPoint")
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
                    $existingSiteNode.properties.siteType = $siteType
                    $existingSiteNode.properties.parentSiteCode = $parentSiteCode
                    $existingSiteNode.properties.parentSiteIdentifier = $parentSiteIdentifier
                    if ($sourceForest) {
                        $existingSiteNode.properties.sourceForest = $sourceForest
                    }
                    
                    # Add MP as collection source
                    if ($existingSiteNode.properties.collectionSource -notcontains "LDAP-mSSMSManagementPoint") {
                        $existingSiteNode.properties.collectionSource += "LDAP-mSSMSManagementPoint"
                    }
                    
                    Write-LogMessage Verbose "Updated site type for $($mpSiteCode): $siteType"
                }
                
                # Create parent CAS site node if it doesn't exist and we found one
                if ($parentSiteCode -and $parentSiteCode -ne "None") {
                    $existingParentSite = $script:Nodes | Where-Object { $_.id -eq $parentSiteCode }
                    if (-not $existingParentSite) {
                        Add-Node -Id $parentSiteCode -Kinds @("SCCM_Site", "SCCM_Infra") -Properties @{
                            collectionSource = @("LDAP-mSSMSManagementPoint")
                            name = $parentSiteCode
                            distinguishedName = $null
                            parentSiteCode = "None"
                            parentSiteGUID = $null
                            parentSiteIdentifier = "None"
                            siteCode = $parentSiteCode
                            siteGUID = $null
                            siteName = $null
                            siteServerDomain = $null
                            siteServerName = $null
                            siteServerObjectIdentifier = $null
                            siteType = "Central Administration Site"
                            sourceForest = $sourceForest
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
                        $fspTarget = Add-DeviceToTargets -DeviceName $fspHostname -Source "LDAP-mSSMSManagementPoint" -SiteCode $siteCode
        
                        if ($fspTarget -and $fspTarget.IsNew) {
                            Write-LogMessage Success "Found fallback status point: $($fspTarget.Hostname)"                          
                        }
                        # Create or update Computer node
                        if ($fspTarget.ADObject) {
                            Add-Node -Id $fspTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $fspTarget.ADObject -Properties @{
                                collectionSource = @("LDAP-mSSMSManagementPoint")
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
                        servicePrincipalName = $result.Properties["serviceprincipalname"]
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
                    collectionSource = @("LDAP-CmRcService")
                    SCCMHasClientRemoteControlSPN = $true
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
                        distinguishedName = $result.Properties["distinguishedname"][0]
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
                        
                        Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                            collectionSource = @("LDAP-$($server.ObjectClass)")
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

                    Add-Node -Id $collectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $collectionTarget.ADObject -Properties @{
                        collectionSource = @("LDAP-NamePattern")
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
                                Add-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                                    collectionSource = @("LDAP-GenericAllSystemManagement")
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
                                    collectionSource = @("LDAP-GenericAllSystemManagement")
                                }
                            }
                            
                            "Group" {                              
                                Add-Node -Id $adObject.SID -Kinds @("Group", "Base") -PSObject $adObject -Properties @{
                                    collectionSource = @("LDAP-GenericAllSystemManagement")
                                }
                            }
                            
                            default {
                                # Handle unknown object types
                                Add-Node -Id $adObject.SID -Kinds @($adObject.Type, "Base") -PSObject $adObject -Properties @{
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
                                        Add-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                                            collectionSource = @("LDAP-GenericAllSystemManagement")
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
                                            collectionSource = @("LDAP-GenericAllSystemManagement")
                                        }
                                    }
                                    
                                    "Group" {
                                        Add-Node -Id $adObject.SID -Kinds @("Group", "Base") -PSObject $adObject -Properties @{
                                            collectionSource = @("LDAP-GenericAllSystemManagement")
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
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.Name) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
        Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
    } catch {
        Write-LogMessage "LDAP collection failed: $_" -Level "Error"
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
                    Add-Node -Id $t.ADObject.SID -Kinds @("Computer","Base") -PSObject $t.ADObject -Properties @{
                        collectionSource = @("DHCP-PXE")
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
                Add-Node -Id $target.ADObject.SID -Kinds @("Computer","Base") -PSObject $target.ADObject -Properties @{
                    collectionSource = @("DHCP-Discover")
                    isDHCPServer = $true
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
                        Add-Node -Id $p.ADObject.SID -Kinds @("Computer","Base") -PSObject $p.ADObject -Properties @{
                            collectionSource = @("DHCP-Discover")
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
            Add-Node -Id $siteCode -Kinds @("SCCM_Site", "SCCM_Infra") -Properties @{
                collectionSource = "Local-SMS_Authority"
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
                    Add-Node -Id $mp.ADObject.SID -Kinds @("Computer", "Base") -PSObject $mp.ADObject -Properties @{
                        collectionSource = @("Local-SMS_LookupMP")
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
            Add-Node -Id $clientId -Kinds @("SCCM_ClientDevice") -Properties @{
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
            Add-Node -Id $localTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $localTarget.ADObject -Properties @{
                collectionSource = @("Local-CCM_Client")
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
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.Name) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
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
                Add-Node -Id $adObject.SID -Kinds @("Computer", "Base") -PSObject $adObject -Properties @{
                    collectionSource = @("DNS")
                    SCCMSiteSystemRoles = @("SMS Management Point@$siteCode")
                }
            } else {
                Write-LogMessage Warning "Cannot create Computer node for $fqdn - missing AD object or SID"
            }
        }
        
        # Report what was collected
        Write-LogMessage Success "DNS collection completed"
        Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.Name) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
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
        
        $j2 = Start-Job -ScriptBlock $triggersCode -ArgumentList $target
        $triggersResult = $null
        
        if (Wait-Job $j2 -Timeout $timeoutSeconds) { 
            $triggersResult = Receive-Job $j2 
        } else {
            Write-LogMessage Warning "Triggers registry query timed out for $target"
            Remove-TimedOutJob $j2 $target
        }

        if ($triggersResult -and $triggersResult -like "*Exception*") {
            Write-LogMessage Error "Error querying triggers key on $target`: $triggersResult"
        } elseif ($triggersResult -and $triggersResult.Count -eq 1) {
            $siteCode = $triggersResult
            Write-LogMessage Success "Found site code from triggers: $siteCode"
        } elseif ($triggersResult -and $triggersResult.Count -gt 1) {
            Write-LogMessage Warning "Multiple site codes found under triggers key on $target`: $($triggersResult -join ', ')"
            $siteCode = $triggersResult[0] # Use first one
        } else {
            Write-LogMessage Verbose "No result from triggers registry query on $target"
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
                            Add-Node -Id $componentServer.ADObject.SID -Kinds @("Computer", "Base") -PSObject $componentServer.ADObject -Properties @{
                                collectionSource = @("RemoteRegistry-ComponentServer")
                                SCCMSiteSystemRoles = @("SMS Component Server@$siteCode")
                            }
                        }

                        # We also now know that the system we're connected to is a site server
                        if ($siteCode -and $CollectionTarget.ADObject) {
                            Add-Node -Id $CollectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $CollectionTarget.ADObject -Properties @{
                                collectionSource = @("RemoteRegistry-ComponentServer")
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
            if ($target.ADObject) {
                Add-Node -Id $target.ADObject.SID -Kinds @("Computer", "Base") -PSObject $target.ADObject -Properties @{
                    collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                    SCCMSiteSystemRoles = @("SMS SQL Server@$siteCode", "SMS Site Server@$siteCode")
                }
            }

            # Add MSSQL nodes/edges for local SQL instance
            if ($CollectionTarget -and $CollectionTarget.ADObject) {
                Add-MSSQLNodesAndEdgesForSite -SiteCode $siteCode `
                                              -SiteIdentifier $siteCode `
                                              -SqlServerFQDN $CollectionTarget.Hostname `
                                              -SiteServerADObject $CollectionTarget.ADObject `
                                              -CollectionSource @("RemoteRegistry-MultisiteComponentServers")
                
                # Collect EPA settings from local SQL instance
                $epaSettings = Get-MssqlEpaSettingsViaRemoteRegistry -SqlServerHostname $CollectionTarget.Hostname -CollectionSource @("RemoteRegistry-MultisiteComponentServers")

                if ($epaSettings) {

                    # Update Computer node with EPA settings
                    Add-Node -Id $CollectionTarget.ADObject.SID -Kinds @("Computer", "Base") -PSObject $CollectionTarget.ADObject -Properties @{
                        collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                        disableLoopbackCheck = $epaSettings.DisableLoopbackCheck
                        restrictReceivingNtlmTraffic = $epaSettings.RestrictReceivingNtlmTraffic
                    }

                    $portSuffix = if ($SqlServicePort) { ":$SqlServicePort" } else { ":1433" }
                    $sqlServerObjectIdentifier = "$($CollectionTarget.ADObject.SID)$portSuffix"

                    # Update MSSQL_Server node with EPA settings
                    Add-Node -Id $sqlServerObjectIdentifier -Kinds @("MSSQL_Server") -Properties @{
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
                if ($sqlServer -and $sqlServer.ADObject) {
                    Add-Node -Id $sqlServer.ADObject.SID -Kinds @("Computer", "Base") -PSObject $sqlServer.ADObject -Properties @{
                        collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                        SCCMSiteSystemRoles = @("SMS SQL Server@$siteCode")
                    }

                    # Add MSSQL nodes/edges for remote SQL instance
                    if ($CollectionTarget -and $CollectionTarget.ADObject) {
                        Add-MSSQLNodesAndEdgesForSite -SiteCode $siteCode `
                                                    -SiteIdentifier $siteCode `
                                                    -SqlServerFQDN $sqlServerFQDN `
                                                    -SiteServerADObject $CollectionTarget.ADObject `
                                                    -CollectionSource @("RemoteRegistry-MultisiteComponentServers")
                    }
                    
                    # Collect EPA settings from remote SQL instance
                    $epaSettings = Get-MssqlEpaSettingsViaRemoteRegistry -SqlServerHostname $sqlServerFQDN -CollectionSource @("RemoteRegistry-MultisiteComponentServers")

                    if ($epaSettings) {
                        # Update Computer node with EPA settings
                        Add-Node -Id $sqlServer.ADObject.SID -Kinds @("Computer", "Base") -PSObject $sqlServer.ADObject -Properties @{
                            collectionSource = @("RemoteRegistry-MultisiteComponentServers")
                            disableLoopbackCheck = $epaSettings.DisableLoopbackCheck
                            restrictReceivingNtlmTraffic = $epaSettings.RestrictReceivingNtlmTraffic
                        }

                        $portSuffix = if ($SqlServicePort) { ":$SqlServicePort" } else { ":1433" }
                        $sqlServerObjectIdentifier = "$($sqlServer.ADObject.SID)$portSuffix"

                        # Update MSSQL_Server node with EPA settings
                        Add-Node -Id $sqlServerObjectIdentifier -Kinds @("MSSQL_Server") -Properties @{
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
        } elseif ($currentUserResult -and $currentUserResult.Count -eq 2) {
            $currentUserSid = $currentUserResult.Values | Select-Object -Index 1
            Write-LogMessage Verbose "Found CurrentUser $currentUserSid on $target"
            # Resolve SID to AD object
            try {
                $userADObject = Resolve-PrincipalInDomain -Name $currentUserSid -Domain $script:Domain

                if ($userADObject) {
                    Write-LogMessage Success "Found current user: $($userADObject.Name) ($currentUserSid)"
                    
                    # Create User node for current user
                    Add-Node -Id $currentUserSid -Kinds @("User", "Base") -PSObject $userADObject -Properties @{
                        collectionSource = @("RemoteRegistry-CurrentUser")
                    }

                    # Create Computer -[HasSession]-> User edge
                    Add-Edge -Start $CollectionTarget.ADObject.SID -Kind "HasSession" -End $currentUserSid -Properties @{
                        collectionSource = @("RemoteRegistry-CurrentUser")
                    }
                } else {
                    Write-LogMessage Warning "Failed to resolve current user SID $sid"
                }
            } catch {
                Write-LogMessage Error "Error resolving current user SID $sid`: $_"
            }
        } else {
            Write-LogMessage Warning "Unexpected number of values in CurrentUser subkey on $target`: $($currentUserResult.Count)"
        }

        # Get Extended Protection for Authentication (EPA) settings from SQL Server instance(s)

        
        Write-LogMessage Success "Remote Registry collection completed for $target"
    } catch {
        Write-LogMessage Error "Remote Registry collection failed for $target`: $_"
    }
    
    Write-LogMessage Verbose "`nSites found:`n    $(($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }).Properties.SiteCode -join "`n    ")"
    Write-LogMessage Verbose "`nSite system roles:`n    $(($script:Nodes | Where-Object { $null -ne $_.Properties.SCCMSiteSystemRoles } | ForEach-Object { "$($_.Properties.Name) ($($_.Properties.SCCMSiteSystemRoles -join ', '))" }) -join "`n    ")"
    Write-LogMessage Verbose "`nCollection targets:`n    $(($script:CollectionTargets.Keys) -join "`n    ")"
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
            # Load EasyHook first
            $EasyHookPath = Join-Path $PSScriptRoot 'EasyHook.dll'
            if (-not (Test-Path $EasyHookPath)) {
                # Try current directory if not in script root
                $EasyHookPath = Join-Path (Get-Location).Path 'EasyHook.dll'
            }
            
            if (Test-Path $EasyHookPath) {
                [Reflection.Assembly]::LoadFile($EasyHookPath) | Out-Null
                Write-LogMessage Info "Loaded EasyHook from: $EasyHookPath"
   
                # Add the EPA testing type
                # This must be run remotely and will not display the correct settings if run locally on the SQL server
                Add-Type @"
using System;
using System.Data.SqlClient;
using System.Runtime.InteropServices;
using EasyHook;

public class EPATester
{
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

    [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
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

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
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

    public static int InitializeSecurityContextW_SBT_Hook(IntPtr phCredential, IntPtr phContext, IntPtr pszTargetName, uint fContextReq, uint Reserved1,
        uint TargetDataRep, IntPtr pInput, uint Reserved2, IntPtr phNewContext, IntPtr pOutput, IntPtr pfContextAttr, IntPtr ptsExpiry)
    {
        if (pszTargetName != IntPtr.Zero)
            pszTargetName = Marshal.StringToHGlobalUni("empty");

        return InitializeSecurityContextW(phCredential, phContext, pszTargetName, fContextReq, Reserved1,
            TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
    }

    public static int InitializeSecurityContextW_CBT_Hook(IntPtr phCredential, IntPtr phContext, IntPtr pszTargetName, uint fContextReq, uint Reserved1,
        uint TargetDataRep, IntPtr pInput, uint Reserved2, IntPtr phNewContext, IntPtr pOutput, IntPtr pfContextAttr, IntPtr ptsExpiry)
    {
        if (pInput != IntPtr.Zero)
        {
            var desc = (SecBufferDesc)Marshal.PtrToStructure(pInput, typeof(SecBufferDesc));

            for (uint i = 0; i < desc.cBuffers; i++)
            {
                var ptr = new IntPtr(desc.pBuffers.ToInt64() + (i * Marshal.SizeOf(typeof(SecBuffer))));
                var buf = (SecBuffer)Marshal.PtrToStructure(ptr, typeof(SecBuffer));

                if (buf.BufferType == 0x0e /* SECBUFFER_CHANNEL_BINDINGS */)
                    Marshal.Copy(new byte[buf.cbBuffer], 0, buf.pvBuffer, buf.cbBuffer);
            }
        }

        return InitializeSecurityContextW(phCredential, phContext, pszTargetName, fContextReq, Reserved1,
            TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
    }

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
                {
                    return "login failed";
                }
                else if (e.Message.Contains("The login is from an untrusted domain"))
                {
                    return "untrusted domain";
                }
                else
                {
                    return e.Message;
                }
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
        var result = "";

        var hookDelegate = new InitializeSecurityContextW_Delegate(InitializeSecurityContextW_SBT_Hook);
        using (var hook = LocalHook.Create(LocalHook.GetProcAddress("secur32.dll", "InitializeSecurityContextW"),
            hookDelegate, null))
        {
            hook.ThreadACL.SetInclusiveACL(new int[] { 0 });

            result = TryConnectDb(host);

            hook.ThreadACL.SetExclusiveACL(new int[] { 0 });
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();

        return result;
    }

    public static string TryConnectDb_NoCbt(string host)
    {
        var result = "";

        var hookDelegate = new InitializeSecurityContextW_Delegate(InitializeSecurityContextW_CBT_Hook);
        using (var hook = LocalHook.Create(LocalHook.GetProcAddress("secur32.dll", "InitializeSecurityContextW"),
            hookDelegate, null))
        {
            hook.ThreadACL.SetInclusiveACL(new int[] { 0 });

            result = TryConnectDb(host);

            hook.ThreadACL.SetExclusiveACL(new int[] { 0 });
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();

        return result;
    }

    public static EPATestResult TestEPA(string serverString)
    {
        var result = new EPATestResult();
        
        result.UnmodifiedConnection = TryConnectDb(serverString);
        result.NoSBConnection = TryConnectDb_NoSb(serverString);
        result.NoCBTConnection = TryConnectDb_NoCbt(serverString);
        
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
}
"@ -ReferencedAssemblies @(
    "System.dll",
    "System.Data.dll",
    "System.Core.dll",
    $EasyHookPath
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
            } else {
                Write-LogMessage Warning "EasyHook.dll not found. Please ensure it's in the script directory."
                # Create a minimal result object when EasyHook.dll is not found
                $epaResult = New-Object PSObject -Property @{
                    PortIsOpen = $portIsOpen
                    ForceEncryption = $forceEncryption
                    ExtendedProtection = "EasyHook.dll not found"
                }
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

function Add-MSSQLNodesAndEdgesForSite {
    param(
        [Parameter(Mandatory = $true)][string]$SiteCode,
        [string]$SiteIdentifier,
        [Parameter(Mandatory = $true)][string]$SqlServerFQDN,
        [string]$SqlDatabaseName,
        [int]$SqlServicePort = 1433,
        [psobject]$SiteServerADObject,
        [string[]]$CollectionSource = @(),
        [PSObject]$EPASettings
    )

    try {
        if (-not $SiteIdentifier) { $SiteIdentifier = $SiteCode }

        $sqlServerDomainObject = Resolve-PrincipalInDomain -Name $SqlServerFQDN -Domain $script:Domain
        if (-not $sqlServerDomainObject) {
            Write-LogMessage Warning "Failed to resolve SQL Server $SqlServerFQDN to AD object"
            return
        }

        Write-LogMessage Success "Found SQL Server for site $SiteCode`: $SqlServerFQDN"

        # Create or update Computer node for SQL Server
        Add-Node -Id $sqlServerDomainObject.SID -Kinds @("Computer", "Base", "SCCM_Infra") -PSObject $sqlServerDomainObject -Properties @{
            collectionSource = @($CollectionSource)
            SCCMSiteSystemRoles = @("SMS SQL Server@$SiteIdentifier")
        }

        # Create or update MSSQL_Server node
        $portSuffix = if ($SqlServicePort) { ":$SqlServicePort" } else { ":1433" }
        $sqlServerObjectIdentifier = "$( $sqlServerDomainObject.SID )$portSuffix"
        Add-Node -Id $sqlServerObjectIdentifier -Kinds @("MSSQL_Server", "Base", "SCCM_Infra") -Properties @{
            collectionSource = @($CollectionSource)
            databases = if ($SqlDatabaseName) { @($SqlDatabaseName) } else { @() }
            extendedProtection = if ($EPASettings) { $EPASettings.ExtendedProtection } else { $null }
            forceEncryption = if ($EPASettings) { $EPASettings.ForceEncryption } else { $null }
            name = "$($SqlServerFQDN)$portSuffix"
            port = if ($SqlServicePort) { $SqlServicePort } else { 1433 }
            SCCMSite = $SiteIdentifier
        }

        # Ensure database name
        if (-not $SqlDatabaseName) {
            Write-LogMessage Warning "No SQL database name provided, inferring from site code $SiteCode"
            $SqlDatabaseName = "CM_$SiteCode"
        }
        $sqlDatabaseIdentifier = "$($sqlServerObjectIdentifier)\$($SqlDatabaseName)"

        # If we have the site server AD object, add MSSQL login and DB user
        $siteServerMssqlLogin = $null
        $siteServerMssqlDatabaseUser = $null
        if ($SiteServerADObject) {
            $siteServerMssqlLogin = "$($SiteServerADObject.Domain.Split('.')[0])\$($SiteServerADObject.SamAccountName)@$sqlServerObjectIdentifier"

            # Create or update MSSQL_Login node for the primary site server
            Add-Node -Id $siteServerMssqlLogin -Kinds @("MSSQL_Login", "Base", "SCCM_Infra") -Properties @{
                collectionSource = @($CollectionSource)
                loginType = "Windows"
                # We know the primary site server is a member of the sysadmin role
                memberOfRoles = @("sysadmin@$sqlServerObjectIdentifier")
                name = $SiteServerADObject.SamAccountName
                SCCMSite = $SiteIdentifier
                SQLServer = $SqlServerFQDN
            }

            # Create or update MSSQL_DatabaseUser node for the primary site server
            $siteServerMssqlDatabaseUser = "$( $SiteServerADObject.SamAccountName )@$sqlDatabaseIdentifier"
            Add-Node -Id $siteServerMssqlDatabaseUser -Kinds @("MSSQL_DatabaseUser", "Base", "SCCM_Infra") -Properties @{
                collectionSource = @($CollectionSource)
                database = $SqlDatabaseName
                # We know the primary site server is a member of the db_owner role
                memberOfRoles = @("db_owner@$sqlDatabaseIdentifier")
                name = $SiteServerADObject.SamAccountName
                login = $($script:Nodes | Where-Object { $_.Id -eq $siteServerMssqlLogin }).Properties.name
                SCCMSite = $SiteIdentifier
                SQLServer = $SqlServerFQDN
            }
        } else {
            Write-LogMessage Warning "Cannot create site server MSSQL login/user nodes without resolving primary site server to AD object"
        }

        # We know the built-in sysadmin server role exists on all SQL instances
        Add-Node -Id "sysadmin@$sqlServerObjectIdentifier" -Kinds @("MSSQL_ServerRole", "Base", "SCCM_Infra") -Properties @{
            collectionSource = @($CollectionSource)
            isFixedRole = $true
            # We know the primary site server is a member of the sysadmin role
            members = if ($SiteServerADObject) { @($SiteServerADObject.SamAccountName) } else { @() }
            name = "sysadmin"
            SCCMSite = $SiteIdentifier
            SQLServer = $SqlServerFQDN
        }

        # Create or update MSSQL_Database node
        Add-Node -Id $sqlDatabaseIdentifier -Kinds @("MSSQL_Database", "Base", "SCCM_Infra") -Properties @{
            collectionSource = @($CollectionSource)
            isTrustworthy = $true
            name = $SqlDatabaseName
            SCCMSite = $SiteIdentifier
            SQLServer = $SqlServerFQDN
        }

        # Create or update MSSQL_DatabaseRole node
        Add-Node -Id "db_owner@$sqlDatabaseIdentifier" -Kinds @("MSSQL_DatabaseRole", "Base", "SCCM_Infra") -Properties @{
            collectionSource = @($CollectionSource)
            database = $SqlDatabaseName
            isFixedRole = $true
            members = if ($SiteServerADObject) { @($SiteServerADObject.SamAccountName) } else { @() }
            name = "db_owner"
            SCCMSite = $SiteIdentifier
            SQLServer = $SqlServerFQDN
        }

        # Create edges
        ## Computer level
        ### (Computer) -[MSSQL_HostFor]-> (MSSQL_Server)
        Add-Edge -Start $sqlServerDomainObject.SID -Kind "MSSQL_HostFor" -End $sqlServerObjectIdentifier -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Server) -[MSSQL_ExecuteOnHost]-> (Computer)
        Add-Edge -Start $sqlServerObjectIdentifier -Kind "MSSQL_ExecuteOnHost" -End $sqlServerDomainObject.SID -Properties @{
            collectionSource = @($CollectionSource)
        }

        ## Server level
        ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_Database)
        Add-Edge -Start $sqlServerObjectIdentifier -Kind "MSSQL_Contains" -End $sqlDatabaseIdentifier -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_ServerRole)
        Add-Edge -Start $sqlServerObjectIdentifier -Kind "MSSQL_Contains" -End "sysadmin@$sqlServerObjectIdentifier" -Properties @{
            collectionSource = @($CollectionSource)
        }
        if ($siteServerMssqlLogin) {
            ### (MSSQL_Login) -[MSSQL_MemberOf]-> (MSSQL_ServerRole)
            Add-Edge -Start $siteServerMssqlLogin -Kind "MSSQL_MemberOf" -End "sysadmin@$sqlServerObjectIdentifier" -Properties @{
                collectionSource = @($CollectionSource)
            }
            ### (MSSQL_Server) -[MSSQL_Contains]-> (MSSQL_Login)
            Add-Edge -Start $sqlServerObjectIdentifier -Kind "MSSQL_Contains" -End $siteServerMssqlLogin -Properties @{
                collectionSource = @($CollectionSource)
            }
            ### (Computer) -[MSSQL_HasLogin]-> (MSSQL_Login)
            if ($SiteServerADObject -and $SiteServerADObject.SID) {
                Add-Edge -Start $SiteServerADObject.SID -Kind "MSSQL_HasLogin" -End $siteServerMssqlLogin -Properties @{
                    collectionSource = @($CollectionSource)
                }
            }
        }
        ### (MSSQL_ServerRole) -[MSSQL_ControlServer]-> (MSSQL_Server)
        Add-Edge -Start "sysadmin@$sqlServerObjectIdentifier" -Kind "MSSQL_ControlServer" -End $sqlServerObjectIdentifier -Properties @{
            collectionSource = @($CollectionSource)
        }

        ## Database Level
        ### (MSSQL_Login) -[MSSQL_IsMappedTo]-> (MSSQL_DatabaseUser)
        if ($siteServerMssqlLogin -and $siteServerMssqlDatabaseUser) {
            Add-Edge -Start $siteServerMssqlLogin -Kind "MSSQL_IsMappedTo" -End $siteServerMssqlDatabaseUser -Properties @{
                collectionSource = @($CollectionSource)
            }
        }
        ### (MSSQL_Database) -[MSSQL_Contains]-> (MSSQL_DatabaseRole)
        Add-Edge -Start $sqlDatabaseIdentifier -Kind "MSSQL_Contains" -End "db_owner@$sqlDatabaseIdentifier" -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_DatabaseUser) -[MSSQL_MemberOf]-> (MSSQL_DatabaseRole)
        if ($siteServerMssqlDatabaseUser) {
            Add-Edge -Start $siteServerMssqlDatabaseUser -Kind "MSSQL_MemberOf" -End "db_owner@$sqlDatabaseIdentifier" -Properties @{
                collectionSource = @($CollectionSource)
            }
        }
        ### (MSSQL_DatabaseRole) -[MSSQL_ControlDB]-> (MSSQL_Database)
        Add-Edge -Start "db_owner@$sqlDatabaseIdentifier" -Kind "MSSQL_ControlDB" -End $sqlDatabaseIdentifier -Properties @{
            collectionSource = @($CollectionSource)
        }
        ### (MSSQL_Database) -[MSSQL_Contains]-> (MSSQL_DatabaseUser)
        if ($siteServerMssqlDatabaseUser) {
            Add-Edge -Start $sqlDatabaseIdentifier -Kind "MSSQL_Contains" -End $siteServerMssqlDatabaseUser -Properties @{
                collectionSource = @($CollectionSource)
            }
        }
        ### (MSSQL_Database) -[SCCM_AssignAllPermissionsSQL]-> (SCCM_Site)
        Add-Edge -Start $sqlDatabaseIdentifier -Kind "SCCM_AssignAllPermissionsSQL" -End $SiteIdentifier -Properties @{
            collectionSource = @($CollectionSource)
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
            Write-LogMessage Success "Successfully collected EPA settings via MSSQL"

            Add-MSSQLNodesAndEdgesForSite -SiteCode $CollectionTarget.SiteCode `
                                          -SiteIdentifier $CollectionTarget.SiteCode `
                                          -SqlServerFQDN $target `
                                          -SqlServicePort $Port `
                                          -CollectionSource @("MSSQL-ScanForEPA") `
                                          -SiteServerADObject $CollectionTarget.ADObject `
                                          -EPASettings $epaResult
            return $true
        } else {
            Write-LogMessage Warning "Failed to collect EPA settings via MSSQL"
        }
    } catch {
        Write-LogMessage Error "MSSQL collection failed for $target`: $_"
        return $false
    }
}

function Process-CoerceAndRelayToMSSQL {
    param(
        $SiteIdentifier,
        $CollectionSource
   )

    # Get all site databases that have EPA set to Off and RestrictReceivingNtlmTraffic set to Off for the specified site code
    $siteDatabaseComputerNodes = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS SQL Server@$SiteIdentifier" -and ($null -eq $_.Properties.restrictReceivingNtlmTraffic -or $_.Properties.restrictReceivingNtlmTraffic -eq "Off" ) }
    if (-not $siteDatabaseComputerNodes) {
        Write-LogMessage Verbose "No site database found with RestrictReceivingNtlmTraffic set to Off in site code $SiteIdentifier to coerce and relay to MSSQL"
        return
    }

    # Get all site servers for the specified site code
    $siteServers = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Site Server@$SiteIdentifier" }
    
    # Get all SMS Providers for the specified site code
    $smsProviders = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Provider@$SiteIdentifier" }

    # Get all management points for the specified site code
    $managementPoints = $script:Nodes | Where-Object { $_.Kinds -contains "Computer" -and $_.Properties.SCCMSiteSystemRoles -contains "SMS Management Point@$SiteIdentifier" }

    # Combine all potential targets (robust against null/singleton values)
    $computersWithMssqlLogins = @()
    if ($siteServers)      { $computersWithMssqlLogins += @($siteServers) }
    if ($smsProviders)     { $computersWithMssqlLogins += @($smsProviders) }
    if ($managementPoints) { $computersWithMssqlLogins += @($managementPoints) }
    $computersWithMssqlLogins = $computersWithMssqlLogins | Select-Object -Unique
    if ($computersWithMssqlLogins.Count -eq 0) {
        Write-LogMessage Verbose "No site servers, SMS providers, or management points found for site code $SiteIdentifier to coerce and relay to MSSQL"
        return
    }

    foreach ($siteDatabaseComputerNode in $siteDatabaseComputerNodes) {

        # Get the MSSQL_Server node for the site database server (ending with :port or :instancename)
        $mssqlServerNode = $script:Nodes | Where-Object { $_.Kinds -contains "MSSQL_Server" -and $_.Id -like "$($siteDatabaseComputerNode.Id):*" }

        # Check EPA settings on the site database server
        if (-not $mssqlServerNode) {
            Write-LogMessage Warning "No MSSQL_Server node found for site database server $($siteDatabaseComputerNode.Id) to create coerce and relay to MSSQL edge"
            continue
        }

        if ($mssqlServerNode.Properties.extendedProtection -and $mssqlServerNode.Properties.extendedProtection -ne "Off") {
            Write-LogMessage Verbose "MSSQL server $($mssqlServerNode.Properties.name) has Extended Protection enabled ($($mssqlServerNode.Properties.extendedProtection)), skipping coerce and relay to MSSQL edge"
            continue
        }

        foreach ($computerWithMssqlLogin in $computersWithMssqlLogins) {

            $computerDomain = if ($computerWithMssqlLogin.Properties.Domain) { $computerWithMssqlLogin.Properties.Domain.Split('.')[0] } else { $script:Domain }

            # Get the corresponding MSSQL login for the computer
            $mssqlLogin = $script:Nodes | Where-Object { $_.Kinds -contains "MSSQL_Login" -and $_.Id -eq "$computerDomain\$($computerWithMssqlLogin.Properties.SAMAccountName)@$($mssqlServerNode.Id)" }
            if (-not $mssqlLogin) {
                Write-LogMessage Warning "No corresponding MSSQL login found for computer $($computerWithMssqlLogin.Id) to create coerce and relay to MSSQL edge"
                continue
            }

            $authedUsersObjectId = "$($computerWithMssqlLogin.Properties.Domain)`-S-1-5-11"

            # Add node for Authenticated Users so we don't get Unknown kind
            Add-Node -Id $authedUsersObjectId `
                    -Kinds $("Group", "Base") `
                    -Properties @{
                        name = "AUTHENTICATED USERS@$($computerWithMssqlLogin.Properties.Domain)"
                    }
            
            Add-Edge -Start $authedUsersObjectId -Kind "CoerceAndRelayToMSSQL" -End $mssqlLogin.Id -Properties @{
                collectionSource = @($CollectionSource)
                coercionVictimHostName = $computerWithMssqlLogin.Properties.dNSHostName
                relayTargetHostName = $mssqlServerNode.Properties.ADObject.dNSHostName
                relayTargetPort = $mssqlServerNode.Properties.port
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
        $detectedSiteCode = Get-ThisSmsProvidersSiteViaAdminService -Target $target
        if (-not $detectedSiteCode) {
            return $false
        }

        # Sites (SMS_Site) - this will tell us all the sites in the hierarchy
        if (Get-SitesViaAdminService -Target $target) {
            Write-LogMessage Success "Successfully collected sites via AdminService (detected site: $detectedSiteCode)"
        } else {
            Write-LogMessage Warning "Failed to collect sites via AdminService"
        }

        # Get the site GUID for the detected site from the nodes
        $siteGUID = ($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" -and $_.Properties.SiteCode -eq $detectedSiteCode }).Properties.siteGUID

        if (-not $siteGUID) {
            Write-LogMessage Warning "Failed to get site GUID for detected site: $detectedSiteCode"
            $siteIdentifier = $detectedSiteCode
        } else {
            Write-LogMessage Success "Found site GUID for detected site: $siteGUID"
            $siteIdentifier = "$detectedSiteCode.$siteGUID"
        }
                
        # Client Devices (SMS_CombinedDeviceResources or SMS_R_System)
        if (Get-CombinedDeviceResourcesViaAdminService -Target $target -SiteIdentifier $siteIdentifier) {
            Write-LogMessage Success "Successfully collected combined device resources via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect combined device resources via AdminService"
        }

        if (Get-SmsRSystemViaAdminService -Target $target -SiteIdentifier $siteIdentifier) {
            Write-LogMessage Success "Successfully collected client devices and site systems via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect client devices and site systems via AdminService"
        }

        if (Get-SmsRUserViaAdminService -Target $target -SiteIdentifier $siteIdentifier) {
            Write-LogMessage Success "Successfully collected users via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect users via AdminService"
        }

        # Collections (SMS_Collection)
        if (Get-CollectionsViaAdminService -Target $target -SiteIdentifier $siteIdentifier) {
            Write-LogMessage Success "Successfully collected device/user collections via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect device/user collections via AdminService"
        }
        
        # Collection Members (SMS_FullCollectionMembership) - must come after collections to resolve members
        if (Get-CollectionMembersViaAdminService -Target $target -SiteIdentifier $siteIdentifier) {
            Write-LogMessage Success "Successfully collected collection members via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect collection members via AdminService"
        }
        
        # Security Roles (SMS_Role)
        if (Get-SecurityRolesViaAdminService -Target $target -SiteIdentifier $siteIdentifier) {
            Write-LogMessage Success "Successfully collected security roles via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect security roles via AdminService (may require elevated privileges)"
        }
        
        # Administrative Users (SMS_Admin) - must come after collections to resolve members
        if (Get-AdminUsersViaAdminService -Target $target -SiteIdentifier $siteIdentifier) {
            Write-LogMessage Success "Successfully collected admin users via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect admin users via AdminService (may require elevated privileges)"
        }
        
        # Site System Roles (SMS_SystemResourceList)
        if (Get-SiteSystemRolesViaAdminService -Target $target -SiteIdentifier $siteIdentifier) {
            Write-LogMessage Success "Successfully collected site system roles via AdminService"
        } else {
            Write-LogMessage Warning "Failed to collect site system roles via AdminService"
        }
        
        Write-LogMessage Info "AdminService collection completed: $collectionsSuccessful/$collectionsAttempted successful"
        
        # Mark target as successfully collected
        if (-not $script:CollectionTargets.ContainsKey($target)) {
            $script:CollectionTargets[$target] = @{}
        }
        $script:CollectionTargets[$target]["Collected"] = $true
        $script:CollectionTargets[$target]["Method"] = "AdminService"
        $script:CollectionTargets[$target]["SiteCode"] = $detectedSiteCode
        
        Write-LogMessage Success "AdminService collection successful on $target ($collectionsSuccessful successful collections)"
        return $true
        
    } catch {
        Write-LogMessage Error "AdminService collection failed for $target`: $_"
        return $false
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
            $siteIdResponse = Invoke-WebRequest -Uri $siteIdUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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
            $siteResponse = Invoke-WebRequest -Uri $siteUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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
        
            # Create SiteIdentifier (siteCode.siteGUID format or just siteCode if no GUID available)
            $siteIdentifier = $site.siteCode
            
            # Try to get siteGUID from SMS_SCI_SiteDefinition
            $siteDefQuery = "SMS_SCI_SiteDefinition?`$filter=SiteCode eq '$($site.siteCode)'&`$select=ParentSiteCode,SiteCode,SiteName,SiteServerDomain,SiteServerName,SiteType,SQLDatabaseName,SQLServerName,Props"
            $siteDefUrl = "$baseUrl/wmi/$siteDefQuery"
    
            try {
                $siteDefResponse = Invoke-WebRequest -Uri $siteDefUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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
                    $siteIdentifier = "$($site.SiteCode).$($siteGUID)"
                    Write-LogMessage Success "Collected site GUID for site $($site.SiteCode): $($siteGUID)"
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
            
            if (-not $siteGUID) {
                Write-LogMessage Warning "Using site code only for site identifier for site $($site.SiteCode) as site GUID is not available"
            } else {
                # Delete previously collected site if it exists (we'll re-add it with updated properties)
                $existingSite = $script:Nodes | Where-Object { $_.Id -like "$($site.siteCode)*" }
                if ($existingSite) {
                    # This won't impact edges since none have been created yet
                    Write-LogMessage Verbose "Replacing site node for site code $($site.siteCode) with siteCode.siteGUID format"
                    $script:Nodes = $script:Nodes | Where-Object { $_.Id -ne $existingSite.Id }
                }
            }

            # Create or update SCCM_Site nodes
            Add-Node -Id $siteIdentifier -Kinds @("SCCM_Site", "SCCM_Infra") -Properties @{
                collectionSource = @("AdminService-SMS_Sites", "AdminService-SMS_SCI_SiteDefinition")
                buildNumber = if ($site.BuildNumber) { $site.BuildNumber } else { $null }
                installDir = if ($site.InstallDir) { $site.InstallDir } else { $null }
                parentSiteCode = if ($site.ReportingSiteCode) { $site.ReportingSiteCode } else { "None" }
                siteCode = $site.SiteCode
                siteGUID = $siteGUID
                siteName = if ($site.SiteName) { $site.SiteName } else { $null }
                siteServerName = if ($site.ServerName) { $site.ServerName } else { $null }
                SQLDatabaseName = $sqlDatabaseName
                SQLServerName = $sqlServerName
                SQLServerFQDN = $sqlServerFQDN
                SQLServicePort = $sqlServicePort
                siteType = if ($site.SiteType) { switch ($site.SiteType) {
                        1 { "Secondary Site" }
                        2 { "Primary Site" }
                        4 { "Central Administration Site" }
                        default { "Unknown" }
                    }} else { $null }
                version = if ($site.Version) { $site.Version } else { $null }
            }

            # Create or update the Computer node for the primary site server
            $siteServerDomainObject = Resolve-PrincipalInDomain -Name $site.ServerName -Domain $script:Domain
            if ($siteServerDomainObject) {
                Write-LogMessage Success "Found primary site server for site $($site.SiteCode): $($site.ServerName)"
                Add-Node -Id $siteServerDomainObject.SID -Kinds @("Computer", "Base", "SCCM_Infra") -PSObject $siteServerDomainObject -Properties @{
                    collectionSource = @("AdminService-SMS_Sites", "AdminService-SMS_SCI_SiteDefinition")
                    SCCMSiteSystemRoles = @("SMS Site Server@$siteIdentifier")
                }
            } else {
                Write-LogMessage Warning "Failed to resolve primary site server $($site.ServerName) to AD object"
            }

            # Create or update MSSQL nodes and edges
            if ($sqlServerFQDN) {

                Add-MSSQLNodesAndEdgesForSite -SiteCode $site.SiteCode `
                                              -SiteIdentifier $siteIdentifier `
                                              -SqlServerFQDN $sqlServerFQDN `
                                              -SqlDatabaseName $sqlDatabaseName `
                                              -SqlServicePort $sqlServicePort `
                                              -SiteServerADObject $siteServerDomainObject `
                                              -CollectionSource @("AdminService-SMS_Sites", "AdminService-SMS_SCI_SiteDefinition")

            } else {
                Write-LogMessage Warning "No SQL Server FQDN found for site $($site.SiteCode)"
            }
        }
    
        # Loop again to get parent site GUID from nodes array
        foreach ($site in $script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" }) {
            if ($site.ReportingSiteCode) {
                $parentSiteCode = $site.ReportingSiteCode
                $parentSiteGUID = ($script:Nodes | Where-Object { $_.Kinds -contains "SCCM_Site" -and $_.Properties.SiteCode -eq $parentSiteCode }).Properties.siteGUID
                $parentSiteIdentifier = "$($parentSiteCode).$($parentSiteGUID)"
                Write-LogMessage Success "Collected parent site GUID for site $($site.SiteCode): $($parentSiteGUID)"
    
                Add-Node -Id $site.SiteIdentifier -Kinds @("SCCM_Site", "SCCM_Infra") -Properties @{
                    collectionSource = @("AdminService-SMS_SCI_SiteDefinition")
                    parentSiteGUID = $parentSiteGUID
                    parentSiteIdentifier = $parentSiteIdentifier
                }

                # Create Site-to-Site edge
                Add-Edge -Start $site.Id -Kind "SCCM_AdminsReplicatedTo" -End $parentSiteIdentifier -Properties @{
                    collectionSource = @("AdminService-SMS_SCI_SiteDefinition")
                }
            }
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
        [string]$SiteIdentifier
    )
    try {
        Write-LogMessage Info "Collecting combined device resources via AdminService from $Target for site $SiteIdentifier"
        $select = "`$select=AADDeviceID,AADTenantID,ADLastLogonTime,CNAccessMP,CNLastOfflineTime,CNLastOnlineTime,CoManaged,CurrentLogonUser,DeviceOS,DeviceOSBuild,IsClient,IsObsolete,IsVirtualMachine,LastActiveTime,LastMPServerName,Name,PrimaryUser,ResourceID,SiteCode,SMSID,UserName,UserDomainName"
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            $combinedDeviceUrl = "https://$Target/AdminService/wmi/SMS_CombinedDeviceResources?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $combinedDeviceResponse = Invoke-WebRequest -Uri $combinedDeviceUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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
                        Add-Node -Id $thisClientDomainObject.SID -Kinds @("Computer", "Base") -PSObject $thisClientDomainObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                            SCCMResourceIDs = @("$($device.ResourceID)@$SiteIdentifier")
                            SCCMClientDeviceIdentifier = $device.SMSUniqueIdentifier
                        }
                    }

                    Add-Node -Id $device.SMSID -Kinds @("SCCM_ClientDevice") -Properties @{
                        collectionSource = @("AdminService-SMS_CombinedDeviceResources")
                        AADDeviceID = if ($device.AADDeviceID) { $device.AADDeviceID } else { $null }
                        AADTenantID = if ($device.AADTenantID) { $device.AADTenantID } else { $null }
                        ADLastLogonTime = if ($device.ADLastLogonTime) { $device.ADLastLogonTime } else { $null }
                        ADLastLogonUser = if ($device.UserName) { $device.UserName } else { $null }
                        ADLastLogonUserDomain = if ($device.UserDomainName) { $device.UserDomainName } else { $null }
                        ADLastLogonUserSID = if ($adLastLogonUserObject.SID) { $adLastLogonUserObject.SID } else { $null }
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
                        resourceID = if ($device.ResourceID) { $device.ResourceID } else { $null }
                        siteCode = if ($device.SiteCode) { $device.SiteCode } else { $null }
                        SMSID = if ($device.SMSID) { $device.SMSID } else { $null }
                        sourceSiteCode = $SiteIdentifier.Split(".")[0]
                        sourceSiteIdentifier = $SiteIdentifier
                        userName = if ($device.UserName) { $device.UserName } else { $null }
                        userDomainName = if ($device.UserDomainName) { $device.UserDomainName } else { $null }
                    }

                    Add-Edge -Start $SiteIdentifier -Kind "SCCM_HasClient" -End $device.SMSID -Properties @{
                        collectionSource = @("AdminService-ClientDevices")
                    }

                    if ($adLastLogonUserObject.SID) {
                        Add-Node -Id $adLastLogonUserObject.SID -Kinds @("User", "Base") -PSObject $adLastLogonUserObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                        Add-Edge -Start $device.SMSID -Kind "SCCM_HasADLastLogonUser" -End $adLastLogonUserObject.SID -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                    }
                    if ($currentLogonUserObject.SID) {
                        Add-Node -Id $currentLogonUserObject.SID -Kinds @("User", "Base") -PSObject $currentLogonUserObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                        Add-Edge -Start $device.SMSID -Kind "SCCM_HasCurrentUser" -End $currentLogonUserObject.SID -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                    }
                    if ($currentManagementPointObject.SID) {
                        Add-Node -Id $currentManagementPointObject.SID -Kinds @("Computer", "Base", "SCCM_Infra") -PSObject $currentManagementPointObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                    }
                    if ($lastReportedMPServerObject.SID) {
                        Add-Node -Id $lastReportedMPServerObject.SID -Kinds @("Computer", "Base", "SCCM_Infra") -PSObject $lastReportedMPServerObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                    }
                    if ($primaryUserObject.SID) {
                        Add-Node -Id $primaryUserObject.SID -Kinds @("User", "Base") -PSObject $primaryUserObject -Properties @{
                            collectionSource = @("AdminService-ClientDevices")
                        }
                        Add-Edge -Start $device.SMSID -Kind "SCCM_HasPrimaryUser" -End $primaryUserObject.SID -Properties @{
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
        [string]$SiteIdentifier
    )

    try {
        Write-LogMessage Info "Collecting systems and groups via SMS_R_System from $Target for site $SiteIdentifier"
        $select = "`$select=Client,Name,Obsolete,ResourceID,SID,SMSUniqueIdentifier,SecurityGroupName,SystemRoles"
        $batchSize = 1000
        $skip = 0
        $totalSystemsProcessed = 0
        $totalGroupsProcessed = 0

        do {
            $smsRSystemUrl = "https://$Target/AdminService/wmi/SMS_R_System?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $smsRSystemResponse = Invoke-WebRequest -Uri $smsRSystemUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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

                    $siteSystemRoles = @()
                    $siteSystemRoles += foreach ($role in $device.SystemRoles) {
                        "$role@$SiteIdentifier"
                    }

                    $thisClientDomainObject = Resolve-PrincipalInDomain -Name $device.Name -Domain $script:Domain

                    # Add or update Computer node if domain SID is not null
                    if ($thisClientDomainObject.SID) {
                        # Add or update Computer node
                        Add-Node -Id $thisClientDomainObject.SID -Kinds @("Computer", "Base") -PSObject $thisClientDomainObject -Properties @{
                            collectionSource = @("AdminService-SMS_R_System")
                            SCCMResourceIDs = @("$($device.ResourceID)@$SiteIdentifier")
                            SCCMClientDeviceIdentifier = $device.SMSUniqueIdentifier
                            SCCMSiteSystemRoles = if ($siteSystemRoles.Count -gt 0) { $siteSystemRoles } else { @() }
                        }

                        # Add Group nodes
                        foreach ($group in $device.SecurityGroupName) {
                            $thisGroupDomainObject = Resolve-PrincipalInDomain -Name $group -Domain $script:Domain
                            if ($thisGroupDomainObject.SID) {
                                Add-Node -Id $thisGroupDomainObject.SID -Kinds @("Group", "Base") -PSObject $thisGroupDomainObject -Properties @{
                                    collectionSource = @("AdminService-SMS_R_System")
                                }
                                Add-Edge -Start $thisClientDomainObject.SID -Kind "MemberOf" -End $thisGroupDomainObject.SID -Properties @{
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
                        Add-Node -Id $device.SMSUniqueIdentifier -Kinds @("SCCM_ClientDevice") -Properties @{
                            collectionSource = @("AdminService-SMS_R_System")
                            ADDomainSID = if ($device.SID) { $device.SID } else { $null }
                        }
                        # There should already be an edge but just in case, add it again
                        Add-Edge -Start $SiteIdentifier -Kind "SCCM_HasClient" -End $device.SMSUniqueIdentifier -Properties @{
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
        [string]$SiteIdentifier
    )

    try {
        Write-LogMessage Info "Collecting users and groups via SMS_R_User from $Target for site $SiteIdentifier"
        $select = "`$select=AADTenantID,AADUserID,DistinguishedName,FullDomainName,FullUserName,Name,ResourceID,SecurityGroupName,SID,UniqueUserName,UserName,UserPrincipalName"
        $batchSize = 1000
        $skip = 0
        $totalUsersProcessed = 0
        $totalGroupsProcessed = 0

        do {
            $smsRUserUrl = "https://$Target/AdminService/wmi/SMS_R_User?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $smsRUserResponse = Invoke-WebRequest -Uri $smsRUserUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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
        
                        Add-Node -Id $thisUserDomainObject.SID -Kinds @("User", "Base") -PSObject $thisUserDomainObject -Properties @{
                            collectionSource = @("AdminService-SMS_R_User")
                            SCCMResourceIDs = @("$($user.ResourceID)@$SiteIdentifier")
                        }

                        # Add Group nodes
                        foreach ($group in $user.SecurityGroupName) {
                            $thisGroupDomainObject = Resolve-PrincipalInDomain -Name $group -Domain $script:Domain
                            if ($thisGroupDomainObject.SID) {
                                Add-Node -Id $thisGroupDomainObject.SID -Kinds @("Group", "Base") -PSObject $thisGroupDomainObject -Properties @{
                                    collectionSource = @("AdminService-SMS_R_User")
                                    SCCMResourceIDs = @("$($user.ResourceID)@$SiteIdentifier")
                                }
                                Add-Edge -Start $thisUserDomainObject.SID -Kind "MemberOf" -End $thisGroupDomainObject.SID -Properties @{
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
        [string]$SiteIdentifier
    )

    try {
        Write-LogMessage Info "Collecting device/user collections via SMS_Collection from $Target for site $SiteIdentifier"
        
        # Query SMS_Collection with specific properties as per design document
        $select = "`$select=CollectionID,CollectionType,CollectionVariablesCount,Comment,IsBuiltIn,LastChangeTime,LastMemberChangeTime,LimitToCollectionID,LimitToCollectionName,MemberCount,Name"
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            $collectionUrl = "https://$Target/AdminService/wmi/SMS_Collection?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $collectionResponse = Invoke-WebRequest -Uri $collectionUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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
                 Add-Node -Id "$($collection.CollectionID)@$SiteIdentifier" -Kinds @("SCCM_Collection", "SCCM_Infra") -Properties @{
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
                     sourceSiteCode = $SiteIdentifier.Split(".")[0]
                     sourceSiteIdentifier = $SiteIdentifier
                 }

                 Add-Edge -Start $SiteIdentifier -Kind "SCCM_Contains" -End "$($collection.CollectionID)@$SiteIdentifier" -Properties @{
                     collectionSource = @("AdminService-SMS_Collection")
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
        [string]$Target,
        [string]$SiteIdentifier
    )

    try {
        Write-LogMessage "Collecting collection members via SMS_FullCollectionMembership from $Target for site $SiteIdentifier" -Level "Info"
        # Query SMS_FullCollectionMembership as per design document
        $select = "`$select=CollectionID,ResourceID,SiteCode"
        $batchSize = 1000
        $skip = 0
        $totalMembers = 0

        do {
            $memberUrl = "https://$Target/AdminService/wmi/SMS_FullCollectionMembership?$select&`$top=$batchSize&`$skip=$skip"
            try {
                $memberResponse = Invoke-WebRequest -Uri $memberUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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

                # Update collection node with members
                Add-Node -Id "$($collection.Name)@$SiteIdentifier" -Kinds @("SCCM_Collection", "SCCM_Infra") -Properties @{
                    collectionSource = @("AdminService-SMS_FullCollectionMembership")
                    members = $collection.Group | ForEach-Object { "$($_.ResourceID)@$SiteIdentifier" }
                    sourceSiteCode = $SiteIdentifier.Split(".")[0]
                    sourceSiteIdentifier = $SiteIdentifier
                }

                # Create edges for each member
                foreach ($member in $collection.Group) {
                    # First get the node for the member
                    $memberUser = $script:Nodes | Where-Object { $_.kinds -contains "User" -and $_.properties.SCCMResourceIDs -contains "$($member.ResourceID)@$SiteIdentifier" }
                    $memberGroup = $script:Nodes | Where-Object { $_.kinds -contains "Group" -and $_.properties.SCCMResourceIDs -contains "$($member.ResourceID)@$SiteIdentifier" }
                    $memberDevice = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_ClientDevice" -and $_.properties.resourceID -eq $member.ResourceID }
                    if ($memberUser) {
                        $memberNode = $memberUser
                    } elseif ($memberGroup) {
                        $memberNode = $memberGroup
                    } elseif ($memberDevice) {
                        $memberNode = $memberDevice
                    }

                    if ($memberNode) {
                        Add-Edge -Start "$($collection.Name)@$SiteIdentifier" -Kind "SCCM_HasMember" -End $memberNode.Id -Propertries @{
                            collectionSource = @("AdminService-SMS_FullCollectionMembership")
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
        [string]$SiteIdentifier
    )
    
    try {
        Write-LogMessage Info "Collecting security roles via SMS_Role from $Target for site $SiteIdentifier"
        
        # select on lazy columns not supported for GetAll requests
        #$select = "`$select=CopiedFromID,CreatedBy,CreatedDate,IsBuiltIn,IsSecAdminRole,LastModifiedBy,LastModifiedDate,NumberOfAdmins,Operations,RoleID,RoleName,RoleDescription,SourceSite"
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            #$roleUrl = "https://$Target/AdminService/wmi/SMS_Role?$select&`$top=$batchSize&`$skip=$skip"
            $roleUrl = "https://$Target/AdminService/wmi/SMS_Role?`$top=$batchSize&`$skip=$skip"
            try {
                $roleResponse = Invoke-WebRequest -Uri $roleUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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
                        
                Add-Node -Id "$($role.RoleID)@$SiteIdentifier" -Kinds @("SCCM_SecurityRole", "SCCM_Infra") -Properties @{
                    collectionSource = @("AdminService-SMS_Role")
                    copiedFromID = if ($role.CopiedFromID) { $role.CopiedFromID } else { $null }
                    createdBy = if ($role.CreatedBy) { $role.CreatedBy } else { $null }
                    createdDate = if ($role.CreatedDate) { $role.CreatedDate } else { $null }
                    isBuiltIn = if ($role.IsBuiltIn) { $role.IsBuiltIn } else { $null }
                    isSecAdminRole = if ($role.IsSecAdminRole) { $role.IsSecAdminRole } else { $null }
                    lastModifiedBy = if ($role.LastModifiedBy) { $role.LastModifiedBy } else { $null }
                    lastModifiedDate = if ($role.LastModifiedDate) { $role.LastModifiedDate } else { $null }
                    name = if ($role.RoleName) { $role.RoleName } else { $null }
                    numberOfAdmins = if ($role.NumberOfAdmins) { $role.NumberOfAdmins } else { $null }
                    operations = if ($role.Operations) { $role.Operations } else { $null }
                    roleID = if ($role.RoleID) { $role.RoleID } else { $null }
                    roleName = if ($role.RoleName) { $role.RoleName } else { $null }
                    roleDescription = if ($role.RoleDescription) { $role.RoleDescription } else { $null }
                    sourceSiteCode = $SiteIdentifier.Split(".")[0]    
                    sourceSiteIdentifier = $SiteIdentifier
                }

                # Add edges from every site in the hierarchy to every security role since they are replicated
                foreach ($site in $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Site" }) {
                    Add-Edge -Start $site.Id -Kind "SCCM_Contains" -End "$($role.RoleID)@$SiteIdentifier" -Properties @{
                        collectionSource = @("AdminService-SMS_Role")
                    }
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
        [string]$SiteIdentifier
    )
    
    try {
        Write-LogMessage Info "Collecting admin users via SMS_Admin from $Target for site $SiteIdentifier"
        # select on lazy columns not supported for GetAll requests
        #$select = "`$select=AccountType,AdminID,AdminSid,Categories,CategoryNames,CollectionNames,CreatedBy,CreatedDate,DisplayName,DistinguishedName,IsGroup,LastModifiedBy,LastModifiedDate,LogonName,RoleNames,Roles,SourceSite"
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            #$adminUrl = "https://$Target/AdminService/wmi/SMS_Admin?$select&`$top=$batchSize&`$skip=$skip"
            $adminUrl = "https://$Target/AdminService/wmi/SMS_Admin?`$top=$batchSize&`$skip=$skip"
            try {
                $adminResponse = Invoke-WebRequest -Uri $adminUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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
            
            foreach ($admin in $adminResponseContent.value) {

                Add-Node -Id "$($admin.LogonName)@$SiteIdentifier" -Kinds @("SCCM_AdminUser", "SCCM_Infra") -Properties @{
                    collectionSource = @("AdminService-SMS_Admin")
                    adminID = if ($admin.AdminID) { $admin.AdminID } else { $null }
                    adminSid = if ($admin.AdminSid) { $admin.AdminSid } else { $null }
                    collectionNames = if ($admin.CollectionNames) { $admin.CollectionNames } else { $null }
                    displayName = if ($admin.DisplayName) { $admin.DisplayName } else { $null }
                    distinguishedName = if ($admin.DistinguishedName) { $admin.DistinguishedName } else { $null }
                    isGroup = if ($admin.IsGroup) { $admin.IsGroup } else { $null }
                    lastModifiedBy = if ($admin.LastModifiedBy) { $admin.LastModifiedBy } else { $null }
                    lastModifiedDate = if ($admin.LastModifiedDate) { $admin.LastModifiedDate } else { $null }
                    name = if ($admin.LogonName) { $admin.LogonName } else { $null }
                    roleIDs = if ($admin.Roles) { $admin.Roles } else { $null }
                    sourceSiteCode = if ($admin.SourceSite) { $admin.SourceSite } else { $null }
                }

                # Add edges from every site in the hierarchy to every security role since they are replicated
                foreach ($site in $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Site" }) {
                    Add-Edge -Start $site.Id -Kind "SCCM_Contains" -End "$($admin.LogonName)@$SiteIdentifier" -Properties @{
                        collectionSource = @("AdminService-SMS_Admin")
                    }
                }

                if ($admin.AdminSid) {
                    $adminDomainObject = Resolve-PrincipalInDomain -Name $admin.AdminSid -Domain $script:Domain
                    if ($adminDomainObject) {
                        # Check if user or group
                        if ($adminDomainObject.Type -eq "User") {
                            $kinds = @("User", "Base", "SCCM_Infra")
                        } else {
                            $kinds = @("Group", "Base", "SCCM_Infra")
                        }
                        # Create or update domain object node
                        Add-Node -Id $adminDomainObject.SID -Kinds $kinds -PSObject $adminDomainObject -Properties @{
                            collectionSource = @("AdminService-SMS_Admin")
                        }

                        # Create SCCM_IsMappedTo edge
                        Add-Edge -Start $adminDomainObject.SID -Kind "SCCM_IsMappedTo" -End "$($admin.LogonName)@$SiteIdentifier" -Properties @{
                            collectionSource = @("AdminService-SMS_Admin")
                        }
                    } else {
                        Write-LogMessage Warning "No domain object found for admin user $($admin.LogonName)@$SiteIdentifier"
                    }
                } else {
                    Write-LogMessage Warning "No domain SID found for admin user $($admin.LogonName)@$SiteIdentifier"
                }

                # Create SCCM_IsAssigned edges to collections this admin user is assigned
                if ($admin.CollectionNames) {
                    $collectionNames = $admin.CollectionNames -split ", "
                    foreach ($collectionName in $collectionNames) {
                        $collection = $script:Nodes | Where-Object { $_.kinds -contains "SCCM_Collection" -and $_.properties.name -eq "$collectionName" -and $_.properties.sourceSiteIdentifier -eq $SiteIdentifier }
                        if ($collection) {
                            Add-Edge -Start "$($admin.LogonName)@$SiteIdentifier" -Kind "SCCM_IsAssigned" -End $collection.Id -Properties @{
                                collectionSource = @("AdminService-SMS_Admin")
                            }
                        } else {
                            Write-LogMessage Warning "No collection node found for $collectionName"
                        }
                    }
                }

                # Create SCCM_IsAssigned edges to security roles this admin user is assigned
                if ($admin.RoleIDs) {
                    $roleIDs = $admin.RoleIDs -split ", "
                    foreach ($roleID in $roleIDs) {
                        $role = $script:Nodes | Where-Object { $_.Id -eq "$roleID@$SiteIdentifier" }
                        if ($role) {
                            Add-Edge -Start "$($admin.LogonName)@$SiteIdentifier" -Kind "SCCM_IsAssigned" -End $role.Id -Properties @{
                                collectionSource = @("AdminService-SMS_Admin")
                            }
                        } else {
                            Write-LogMessage Warning "No role node found for $roleID"
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
        [string]$SiteIdentifier
    )
    
    try {
        Write-LogMessage Info "Collecting site system roles via SMS_SCI_SysResUse from $Target for site $SiteIdentifier"
        
        # Batched query to SMS_SystemResourceList
        $batchSize = 1000
        $skip = 0
        $totalProcessed = 0

        do {
            $systemUrl = "https://$Target/AdminService/wmi/SMS_SCI_SysResUse?`$top=$batchSize&`$skip=$skip"
            try {
                $systemResponse = Invoke-WebRequest -Uri $systemUrl -Method Get -UseDefaultCredentials -TimeoutSec 10 -ErrorAction Stop
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

                    $systemName = $group.Group[0].NetworkOSPath.Replace('\', '')

                    # Resolve computer object first in case it's a site database running as LocalSystem or NetworkService
                    $computerObject = Resolve-PrincipalInDomain -Name $systemName -Domain $script:Domain

                    # Combine role names into array with site identifier suffix
                    $roleNames = @()
                    foreach ($role in $group.Group) {
                        if ($role.RoleName) {
                            if (-not $roleNames.Contains("$($role.RoleName)@$SiteIdentifier")) {
                                $roleNames += "$($role.RoleName)@$SiteIdentifier"
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
                                        $kinds = @("User", "Base", "SCCM_Infra")
                                    } else {
                                        $kinds = @("Computer", "Base", "SCCM_Infra")
                                    }                    
                                } else {
                                    Write-LogMessage Verbose "No domain object found for $serviceAccount, the site database is running as a local account"
                                    $serviceAccountObject = $computerObject
                                    $kinds = @("Computer", "Base", "SCCM_Infra")
                                }
                                Add-Node -Id $serviceAccountObject.SID -Kinds $kinds -PSObject $serviceAccountObject -Properties @{
                                    collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                }

                                # Create edge from service account to computer if not the same
                                if ($serviceAccountObject.SID -ne $computerObject.SID) {
                                    Add-Edge -Start $serviceAccountObject.SID -Kind "HasSession" -End $computerObject.SID -Properties @{
                                        collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                    }
                                    Add-Edge -Start $computerObject.SID -Kind "MSSQL_GetAdminTGS" -End $serviceAccountObject.SID -Properties @{
                                        collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                    }
                                    # Add MSSQL_GetTGS edges from service account to every server login
                                    foreach ($login in $script:Nodes | Where-Object { $_.kinds -contains "MSSQL_Login" -and $_.properties.SCCMSite -eq $SiteIdentifier }) {
                                        Add-Edge -Start $serviceAccountObject.SID -Kind "MSSQL_GetTGS" -End $login.Id -Properties @{
                                            collectionSource = @("AdminService-SMS_SCI_SysResUse")
                                        }
                                    }
                                }
                            }
                        }
                    }

                    # Create or update Computer node
                    if ($computerObject) {
                        Add-Node -Id $computerObject.SID -Kinds @("Computer", "Base", "SCCM_Infra") -PSObject $computerObject -Properties @{
                            collectionSource = @("AdminService-SMS_SCI_SysResUse")
                            SCCMSiteSystemRoles = $roleNames
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
                                                $managementPoint = Add-DeviceToTargets -DeviceName $mpFQDN -Source "HTTP-MPKEYINFORMATION" -SiteCode $siteCode
                                                Write-LogMessage Success "Found site code for $mpFQDN`: $siteCode"

                                                # Create or update SCCM_Site node
                                                Add-Node -Id $siteCode -Kinds @("SCCM_Site", "SCCM_Infra") -Properties @{
                                                    collectionSource = @("HTTP-MPKEYINFORMATION")
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
                                    Add-Node -Id $managementPoint.ADObject.SID -Kinds @("Computer", "Base") -PSObject $managementPoint.ADObject -Properties @{
                                        collectionSource = @("HTTP-MPKEYINFORMATION")
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
                                                        Add-Node -Id $managementPoint.ADObject.SID -Kinds @("Computer", "Base") -PSObject $managementPoint.ADObject -Properties @{
                                                            collectionSource = @("HTTP-MPKEYINFORMATION")
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
                            # Endpoint not accessible, move to next protocol
                            Write-LogMessage Verbose "Management point endpoint not accessible on $endpoint`: $_"
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
                                Write-LogMessage Verbose "Distribution point endpoint not accessible on $endpoint`: $_"
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
                            $distributionPoint = Add-DeviceToTargets -DeviceName $target -Source "HTTP-SMS_DP_SMSPKG$" -SiteCode $(if ($siteCode) { "@$siteCode" })

                            # Add site system role to Computer node properties
                            if ($distributionPoint.ADObject) {
                                Add-Node -Id $distributionPoint.ADObject.SID -Kinds @("Computer", "Base") -PSObject $distributionPoint.ADObject -Properties @{
                                    collectionSource = @("HTTP-SMS_DP_SMSPKG$")
                                    SCCMSiteSystemRoles = @("SMS Distribution Point$(if ($siteCode) { "@$siteCode" })") # We can't get the site code via HTTP unless the target is also a MP but might be able to later via SMB
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

    Write-LogMessage Success "HTTP collection completed"
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
    
    $target = $CollectionTarget.Name

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
                    Add-Node -Id $siteCode -Kinds @("SCCM_Site", "SCCM_Infra") -Properties @{
                        collectionSource = $collectionSource
                        siteCode = $siteCode
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
                    collectionSource = $collectionSource
                    SCCMHostsContentLibrary = $hostsContentLib
                    SCCMIsPXESupportEnabled = $isPXEEnabled
                    SCCMSiteSystemRoles = $roles
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

    Write-LogMessage "SMB collection completed" -Level "Success"
}

#endregion

#region Processing and Edge Creation
function Process-SitesIngest {
    Write-LogMessage "Processing Sites ingest..." -Level "Info"
    
    foreach ($site in $script:Sites) {
        # 1. Create or find SCCM_Site node
        $siteNode = New-SCCMNode -ObjectIdentifier $site.SiteIdentifier -NodeType "SCCM_Site" -Properties $site
        $script:Nodes += $siteNode
        
        # 2. Create or find parent SCCM_Site if ParentSiteCode exists
        if ($site.ParentSiteCode -and $site.parentSiteGUID) {
            $parentSiteIdentifier = "$($site.ParentSiteCode).$($site.parentSiteGUID)"
            
            # Create parent site properties
            $parentSiteType = if ($site.SiteType -eq "Secondary Site") { "Primary Site" } else { "Central Administration Site" }
            $parentSiteProps = @{
                "SiteCode" = $site.ParentSiteCode
                "SiteGUID" = $site.parentSiteGUID
                "SiteIdentifier" = $parentSiteIdentifier
                "SiteType" = $parentSiteType
                "sourceForest" = $site.sourceForest
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
        if ($site.Properties.siteServerObjectIdentifier) {
            $computerProps = @{
                "Name" = $site.Properties.siteServerName
                "Domain" = $site.Properties.siteServerDomain
                "SCCMSiteSystemRoles" = @("SMS Site Server@$($site.SiteIdentifier)")
            }
            $computerNode = New-SCCMNode -ObjectIdentifier $site.Properties.siteServerObjectIdentifier -NodeType "Computer" -Properties $computerProps
            $script:Nodes += $computerNode
        }
        
        # 4. Create/update Computer node for SQL server (if different from site server)
        if ($site.Properties.SQLServerObjectIdentifier -and $site.Properties.SQLServerObjectIdentifier -ne $site.Properties.siteServerObjectIdentifier) {
            $sqlComputerProps = @{
                "Name" = $site.Properties.SQLServerName
                "SCCMSiteSystemRoles" = @("SMS SQL Server.$($site.SiteIdentifier)")
            }
            $sqlComputerNode = New-SCCMNode -ObjectIdentifier $site.Properties.SQLServerObjectIdentifier -NodeType "Computer" -Properties $sqlComputerProps
            $script:Nodes += $sqlComputerNode
            
            # Create AdminTo edge from site server to SQL server
            if ($site.Properties.siteServerObjectIdentifier) {
                $adminToEdge = New-SCCMEdge -SourceNode $site.Properties.siteServerObjectIdentifier -TargetNode $site.Properties.SQLServerObjectIdentifier -EdgeType "AdminTo"
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
                $collection = $script:Collections | Where-Object { $_.Name -eq $collectionName.Trim() -and $_.sourceSiteIdentifier -eq $admin.sourceSiteIdentifier }
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
                $role = $script:SecurityRoles | Where-Object { $_.RoleID -eq $roleId.Trim() -and $_.sourceSiteIdentifier -eq $admin.sourceSiteIdentifier }
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
            "SCCMSiteSystemRoles" = $siteSystem.Roles
        }
        $computerNode = New-SCCMNode -ObjectIdentifier $siteSystem.ObjectIdentifier -NodeType "Computer" -Properties $computerProps
        $script:Nodes += $computerNode
        
        # 2. Create AdminTo edges from site server
        foreach ($role in $siteSystem.Roles) {
            if ($role -match "\.(.+)$") {
                $siteIdentifier = $matches[1]
                
                # Find the site server for this site
                $site = $script:Sites | Where-Object { $_.SiteIdentifier -eq $siteIdentifier }
                if ($site -and $site.Properties.siteServerObjectIdentifier -ne $siteSystem.ObjectIdentifier) {
                    $adminToEdge = New-SCCMEdge -SourceNode $site.Properties.siteServerObjectIdentifier -TargetNode $siteSystem.ObjectIdentifier -EdgeType "AdminTo"
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

function Process-HasMemberEdges {
    Write-LogMessage "Post-processing: Creating SCCM_HasMember edges..." -Level "Info"
    
    # Step 1: Identify all SCCM_Site labeled nodes
    foreach ($site in $script:Sites) {
        Write-LogMessage "Processing SCCM_HasMember for site: $($site.SiteIdentifier)" -Level "Debug"
        
        # Step 2: Get all sites connected via SCCM_SameAdminsAs (recursively)
        $connectedSiteIdentifiers = Get-ConnectedSitesRecursive -SiteIdentifier $site.SiteIdentifier
        Write-LogMessage "Found $($connectedSiteIdentifiers.Count) connected sites for $($site.SiteIdentifier)" -Level "Debug"
        
        # Step 3: Find collections whose sourceSiteIdentifier matches any connected site
        $relevantCollections = $script:Collections | Where-Object {
            $connectedSiteIdentifiers -contains $_.sourceSiteIdentifier
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
            $connectedSiteIdentifiers -contains $_.sourceSiteIdentifier -and
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
                $connectedSiteIdentifiers -contains $_.sourceSiteIdentifier -and
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
            $connectedSiteIdentifiers -contains $_.sourceSiteIdentifier -and
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
    #$WriterObj.Writer.WriteLine('  "metadata": {')
    #$WriterObj.Writer.WriteLine('    "source_kind": "SCCM_Base"')
    #$WriterObj.Writer.WriteLine('  },')
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

    # 2) Inputs → optional allow-list filter
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

    # 4) SMSProvider-only convenience (keep just AdminService/WMI unless once-phases explicitly requested)
    if ($SMSProvider) {
        $onceRequested = @('LDAP','Local','DNS') | Where-Object { $_ -in $script:SelectedPhases }
        if (-not $onceRequested) {
            $script:SelectedPhases = @('AdminService','WMI') | Where-Object { $_ -in $script:SelectedPhases } 
            if (-not $script:SelectedPhases) { $script:SelectedPhases = @('AdminService','WMI') }
            Write-LogMessage Info ("SMS Provider mode → phases: " + ($script:SelectedPhases -join ', '))
        }
    }

    # 5) Orchestrate (runs once-phases once; per-host phases for all targets; respects filter)
    Invoke-DiscoveryPipeline -SelectedPhases $script:SelectedPhases -MaxParallel 8

    Write-LogMessage Success "SCCM collection completed."
}


function Start-SCCMCollectionA {
    
    Write-LogMessage Info "Initializing SCCM collection..."

    $script:SelectedPhases = Get-SelectedPhases -Methods $CollectionMethods
    Invoke-DiscoveryPipeline -SelectedPhases $script:SelectedPhases -MaxParallel 8
    return 

    # Validate parameters
    if ($ComputerFile -and $SMSProvider) {
        Write-LogMessage Warning "Cannot specify both ComputerFile and SMSProvider"
        return
    }
       
    # Determine collection strategy based on parameters
    if ($SMSProvider) {
        Write-LogMessage Info "Using SMS Provider mode: $SMSProvider"

        $collectionTarget = Add-DeviceToTargets -DeviceName $SMSProvider -Source "ScriptParameter-SMSProvider"

        if (-not $collectionTarget) {
            Write-LogMessage Error "Failed to add device to targets"
            return
        }
        
        # Only AdminService and WMI are applicable for SMS Provider mode
        if ($enableAdminService) {
            Invoke-AdminServiceCollection -CollectionTarget $collectionTarget
        }
        
        if ($enableWMI) {
            Invoke-SmsProviderWmiCollection -CollectionTarget $collectionTarget
        }
    
    } elseif ($Computers) {
        Write-LogMessage Info "Using Computers mode: $($Computers -join ', ')"
        
        foreach ($target in $Computers) {
            # Add targets and resolve to AD objects
            Add-DeviceToTargets -DeviceName $target -Source "ScriptParameter-Computers"
        }
        
        # Execute enabled methods for Computers mode
        if ($enableRemoteRegistry) {
            foreach ($collectionTarget in $@($script:CollectionTargets.Values)) {
                Invoke-RemoteRegistryCollection -Target $collectionTarget
            }
        }

        if ($enableMSSQL) {
            foreach ($collectionTarget in $@($script:CollectionTargets.Values)) {
                Invoke-MSSQLCollection -CollectionTarget $collectionTarget
            }
        }
        
        if ($enableAdminService) {
            foreach ($collectionTarget in $script:CollectionTargets.Values) {
                Invoke-AdminServiceCollection -CollectionTarget $collectionTarget
            }
        }
        
        if ($enableHTTP) {
            Invoke-HTTPCollection -Targets $script:CollectionTargets
        }
        
        if ($enableSMB) {
            Invoke-SMBCollection -Targets $script:CollectionTargets
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
            foreach ($collectionTarget in $@($script:CollectionTargets.Values)) {
                Invoke-RemoteRegistryCollection -Target $collectionTarget
            }
        }

        if ($enableMSSQL) {
            foreach ($collectionTarget in $@($script:CollectionTargets.Values)) {
                Invoke-MSSQLCollection -CollectionTarget $collectionTarget
            }
        }
        
        if ($enableAdminService) {
            foreach ($collectionTarget in $script:CollectionTargets.Values) {
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
                # Run on copy of targets to avoid modification during iteration
                Invoke-RemoteRegistryCollection -Targets @($script:CollectionTargets.Values)
            }

            # Phase 5: MSSQL - On targets identified in previous phases
            if ($enableMSSQL) {
                foreach ($collectionTarget in $script:CollectionTargets.Values) {
                    Invoke-MSSQLCollection -CollectionTarget $collectionTarget
                }
            }
            
            # Phase 6: AdminService - On targets identified in previous phases
            if ($enableAdminService) {
                foreach ($collectionTarget in $script:CollectionTargets.Values) {
                    Invoke-AdminServiceCollection -CollectionTarget $collectionTarget
                }
            }
            
            # Phase 7: WMI - If AdminService collection fails
            if ($enableWMI) {
                $uncollectedTargets = $script:CollectionTargets.Keys | Where-Object { 
                    -not $_.Value["Collected"] 
                }
                if ($uncollectedTargets.Count -gt 0) {
                    Invoke-SmsProviderWmiCollection -CollectionTargets $uncollectedTargets
                }
            }
            
            # Phase 8: HTTP - If AdminService and WMI collections fail
            if ($enableHTTP) {
                $uncollectedTargets = $script:CollectionTargets.GetEnumerator() | Where-Object { 
                    -not $_.Value["Collected"] 
                }
                if ($uncollectedTargets.Count -gt 0) {
                    Invoke-HTTPCollection -Targets $uncollectedTargets
                }
            }
            
            # Phase 9: SMB - If AdminService and WMI collections fail
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
    Write-LogMessage "SCCM collection completed successfully!" -Level "Success"
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

    if ($OutputFormat -eq "NodeGlyphs") {
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
                "Host" = @{
                    "icon" = @{
                        "color" = "#2eff4d"
                        "name" = "laptop-code"
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
            Write-LogMessage Success "ActiveDirectory module loaded"
        } catch {
            Write-LogMessage Error "Failed to load ActiveDirectory module: $_"
            return
        }
    } else {
        Write-LogMessage Warning "ActiveDirectory module not found, using .NET DirectoryServices"
        try {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
            Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
            Write-LogMessage Success "DirectoryServices fallback initialized"
            $script:UseNetFallback = $true
        } catch {
            Write-LogMessage Error "Failed to load .NET DirectoryServices assemblies: $_"
            return
        }
    }

    if (-not $script:Domain) {
        try {
            Write-LogMessage Warning "No domain provided and could not find `$env:USERDNSDOMAIN, trying computer's domain"
            $script:Domain = (Get-CimInstance Win32_ComputerSystem).Domain
            Write-LogMessage Info "Using computer's domain: $script:Domain"
        } catch {
            Write-LogMessage Error "Error getting computer's domain, using `$env:USERDOMAIN: $_"
            $script:Domain = $env:USERDOMAIN
        }
    } 
    else {
        if (-not $script:DomainController) {
            Write-LogMessage Warning "No domain controller provided, trying to find one"
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
                Write-LogMessage Warning "Failed to find domain controller: $_"
                return
            }
            if (-not $script:DomainController) {
                Write-LogMessage Error "Failed to find domain controller"
                return
            }
            Write-LogMessage Info "Using discovered domain controller: $script:DomainController"
        } else {
            Write-LogMessage Info "Using specified domain controller: $script:DomainController"
        }
    }
    if (Test-DnsResolution -Domain $script:Domain) {
        Write-LogMessage Info "DNS resolution successful"
    } else {
        Write-LogMessage Error "DNS resolution failed"
        return
    }
    
    # Collection phases to run
    $collectionMethodsSplit = $CollectionMethods -split "," | ForEach-Object { $_.Trim().ToUpper() }
    $enableLDAP = $false
    $enableDHCP = $false
    $enableLocal = $false
    $enableDNS = $false
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
                $enableDHCP = $true
                $enableLocal = $true
                $enableDNS = $true
                $enableRemoteRegistry = $true
                $enableMSSQL = $true
                $enableAdminService = $true
                $enableWMI = $true
                $enableHTTP = $true
                $enableSMB = $true
            }
            "LDAP" { $enableLDAP = $true }
            "DHCP" { $enableDHCP = $true }
            "LOCAL" { $enableLocal = $true }
            "DNS" { $enableDNS = $true }
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
    
    # Disable certificate validation
    Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # Start collection
    Start-SCCMCollection
    
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