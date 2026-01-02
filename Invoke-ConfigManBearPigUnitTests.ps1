# PowerShell SCCM Collector Unit Test Kit for BloodHound OpenGraph
#   by Chris Thompson (@_Mayyhem) at SpecterOps
#
# Required Permissions:
#   - Full Administrator security role in SCCM
#   - Local Administrator on all hosts of SCCM site system roles

[CmdletBinding()]
param(
    # Path to the enumeration script   
    [Parameter(Mandatory=$false)]
    [string]$EnumerationScript = ".\ConfigManBearPig.ps1",
    
    # Path to the output folder  
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Setup", "Test", "Teardown")]
    [string]$Action = "All",

    [Parameter(Mandatory=$false)]
    [string]$Domain = "mayyhem.com",

    # Collection method to use (default: AdminService)
    [Parameter(Mandatory=$false)]
    [string]$CollectionMethods = 'LDAP,DNS,RemoteRegistry,MSSQL,HTTP,SMB',
    #[string]$CollectionMethods = 'AdminService',

    [Parameter(Mandatory=$false)]
    [switch]$DisablePossibleEdges,

    # SMS Provider FQDN
    [Parameter(Mandatory=$false)]
    [string]$SmsProvider,# = 'cas-pss.mayyhem.com',

    [Parameter(Mandatory=$false)]
    [string]$LogFile,

    # Limit tests to a single edge type for focused debugging
    [Parameter(Mandatory=$false)]
    [string]$LimitToEdgeType,

    # Enable detailed debug output for troubleshooting test failures
    [Parameter(Mandatory=$false)]
    [switch]$ShowDebug,

    # Skip collection phase and parse the most recent ZIP file
    [Parameter(Mandatory=$false)]
    [switch]$SkipCollection
)

#region Logging Functions
function Write-TestLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Test", "Verbose")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        "Success" { Write-Host $Message -ForegroundColor Green }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error"   { Write-Host $Message -ForegroundColor Red }
        "Test"    { Write-Host $Message -ForegroundColor Cyan }
        "Verbose" { Write-Host $Message -ForegroundColor Magenta }
        default   { Write-Host $Message }
    }
    
    # File output
    if ($LogFile) {
        $logMessage | Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
}
#endregion

$script:EdgeTypes = @(
    #AdminTo,
    "LocalAdminRequired",
    "CoerceAndRelayToAdminService",
    "CoerceAndRelayToMSSQL",
    "CoerceAndRelaytoSMB",
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
    "MSSQL_ServiceAccountFor",
    "SameHostAs",
    "SCCM_AdminsReplicatedTo",
    "SCCM_AllPermissions",
    "SCCM_ApplicationAdministrator",
    "SCCM_AssignAllPermissions",
    "SCCM_AssignSpecificPermissions",
    "SCCM_Contains",
    "SCCM_FullAdministrator",
    "SCCM_HasADLastLogonUser",
    "SCCM_HasClient",
    "SCCM_HasCurrentUser",
    "SCCM_HasMember",
    "SCCM_HasPrimaryUser",
    "SCCM_IsAssigned",
    "SCCM_IsMappedTo"
)

$script:NodeTypes = @(
    "Computer",
    "Group",
    "Host",
    "User",
    "MSSQL_Database",
    "MSSQL_DatabaseRole",
    "MSSQL_DatabaseUser",
    "MSSQL_Login",
    "MSSQL_Server",
    "MSSQL_ServerRole",
    "SCCM_AdminUser",
    "SCCM_ClientDevice", 
    "SCCM_Collection",
    "SCCM_SecurityRole",
    "SCCM_Site"
)

$script:ExpectedEdges = @(

    ######################################################################################################
    # AdminTo (temporarily LocalAdminRequired due to lack of OpenGraph support for post-processed edges) #
    ######################################################################################################
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The CAS primary site server has local administrator rights on the CAS site database server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "cas-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "cas-db.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The CAS primary site server has local administrator rights on the service connection point server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "cas-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "cas-scp.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The PS1 primary site server has local administrator rights on the site database server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-db.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The PS1 primary site server has local administrator rights on the SMS Provider server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-sms.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The PS1 primary site server has local administrator rights on the management point server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-mp.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The PS1 primary site server has local administrator rights on the distribution point server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-dp.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The PS1 primary site server has local administrator rights on the passive site server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-psv.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The PS1 passive site server has local administrator rights on the primary site server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-psv.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-pss.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Count = 1
        Description = "The PS1 primary site server has local administrator rights on the content library server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-lib.$Domain"
            }
        }
    },
    @{
        Kind = "LocalAdminRequired"
        Negative = $true
        Description = "The PS2 primary site server does not have local administrator rights on the PS1 site database server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps2-pss.$Domain"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-db.$Domain"
            }
        }
    },

    ################################
    # CoerceAndRelayToAdminService #
    ################################
    @{
        Kind = "CoerceAndRelayToAdminService"
        Count = 1
        Description = "Authenticated Users group can coerce the PS1 primary site server and relay authentication to the AdminService on the PS1 SMS Provider, coerce the PS1 primary site server and relay authentication to the AdminService on the PS1 passive site server, coerce the PS1 passive site server and relay authentication to the AdminService on the PS1 primary site server, and coerce the PS1 passive site server and relay authentication to the AdminService on the PS1 SMS Provider"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "PS1"
            }
        }
        Properties = @{
            coercionVictimAndRelayTargetPairs = @("Coerce ps1-psv.mayyhem.com, relay to ps1-pss.mayyhem.com","Coerce ps1-pss.mayyhem.com, relay to ps1-psv.mayyhem.com","Coerce ps1-pss.mayyhem.com, relay to ps1-sms.mayyhem.com","Coerce ps1-psv.mayyhem.com, relay to ps1-sms.mayyhem.com")
        }
    },


    #########################
    # CoerceAndRelayToMSSQL #
    #########################
    @{
        Kind = "CoerceAndRelayToMSSQL"
        Count = 1
        Description = "Authenticated Users group can coerce and relay authentication to the MSSQL service on the CAS site database server"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "MAYYHEM\CAS-PSS$@*:1433"
            }
        }
        Properties = @{
            coercionVictimAndRelayTargetPairs = @("Coerce cas-pss.mayyhem.com, relay to cas-db.mayyhem.com:1433")
        }
    },

    @{
        Kind = "CoerceAndRelayToMSSQL"
        Count = 1
        Description = "Authenticated Users group can coerce and relay authentication to the MSSQL service on the PS1 site database server"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "MAYYHEM\PS1-PSS$@*:1433"
            }
        }
        Properties = @{
            coercionVictimAndRelayTargetPairs = @("Coerce ps1-pss.mayyhem.com, relay to ps1-db.mayyhem.com:1433")
        }
    },
    @{
        Kind = "CoerceAndRelayToMSSQL"
        Count = 1
        Description = "Authenticated Users group can coerce and relay authentication to the MSSQL service on the PS1 site database server"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "MAYYHEM\PS1-SMS$@*:1433"
            }
        }
        Properties = @{
            coercionVictimAndRelayTargetPairs = @("Coerce ps1-sms.mayyhem.com, relay to ps1-db.mayyhem.com:1433")
        }
    },
    @{
        Kind = "CoerceAndRelayToMSSQL"
        Count = 1
        Description = "Authenticated Users group can coerce and relay authentication to the MSSQL service on the PS1 site database server"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "MAYYHEM\PS1-PSV$@*:1433"
            }
        }
        Properties = @{
            coercionVictimAndRelayTargetPairs = @("Coerce ps1-psv.mayyhem.com, relay to ps1-db.mayyhem.com:1433")
        }
    },

    ###########################
    # CoerceAndRelayToSMB #
    ###########################
    @{
        Kind = "CoerceAndRelayToSMB"
        Count = 1
        Description = "Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 SMS Provider"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-sms.$Domain"
            }
        }
    },
    @{
        Kind = "CoerceAndRelayToSMB"
        Count = 1
        Description = "Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 site database server"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-db.$Domain"
            }
        }
    },
    @{
        Kind = "CoerceAndRelayToSMB"
        Count = 1
        Description = "Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 primary site server"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-pss.$Domain"
            }
        }
    },
    @{
        Kind = "CoerceAndRelayToSMB"
        Count = 1
        Description = "Authenticated Users group can coerce and relay authentication to the SMB service on the PS1 passive site server"
        Source = @{
            Kinds = @("Group", "Base")
            Properties = @{
                id = "*-S-1-5-11"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-psv.$Domain"
            }
        }
    },
    #>

    ##############
    # HasSession #
    ##############
    @{
        Kind="HasSession"
        Count = 1
        Description = "The MSSQL service account has an active session on the CAS site database server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "cas-db.$Domain"
            }
        }
        Target = @{
            Kinds = @("User", "Base")
            Properties = @{
                samAccountName = "sqlsccmsvc"
                id = "S-1-5-21-*"
            }
        }
    },
    @{
        Kind="HasSession"
        Count = 1
        Description = "The MSSQL service account has an active session on the PS1 site database server"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-db.$Domain"
            }
        }
        Target = @{
            Kinds = @("User", "Base")
            Properties = @{
                samAccountName = "sqlsccmsvc"
                id = "S-1-5-21-*"
            }
        }
    },

    ##################
    # MSSQL_Contains #
    ##################
    @{
        Kind="MSSQL_Contains"
        Count = 1
        Description = "The CAS site database MSSQL server contains the CM_<SiteCode> database"
        Source = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Database")
            Properties = @{
                name = "CM_CAS"
            }
        }
    },
    @{
        Kind="MSSQL_Contains"
        Count = 1
        Description = "The CAS site database MSSQL server contains the CAS-PSS$ login"
        Source = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
                name = "CAS-DB*"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "*cas-pss$@*:1433"
            }
        }
    },
    @{
        Kind="MSSQL_Contains"
        Count = 1
        Description = "The CAS site database contains the db_owner database role"
        Source = @{
            Kinds = @("MSSQL_Database")
            Properties = @{
                id = "*:1433\CM_CAS"
            }
        }
        Target = @{
            Kinds = @("MSSQL_DatabaseRole")
            Properties = @{
                id = "db_owner@*:1433\CM_CAS"
            }
        }
    },
    @{
        Kind="MSSQL_Contains"
        Count = 1
        Description = "The CAS site database contains the CAS-PSS$ user"
        Source = @{
            Kinds = @("MSSQL_Database")
            Properties = @{
                id = "*:1433\CM_CAS"
            }
        }
        Target = @{
            Kinds = @("MSSQL_DatabaseUser")
            Properties = @{
                id = "*cas-pss$@*:1433\CM_CAS"
            }
        }
    },
    @{
        Kind="MSSQL_Contains"
        Count = 1
        Description = "The PS1 site database MSSQL server contains the CM_<SiteCode> database"
        Source = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Database")
            Properties = @{
                name = "CM_PS1"
            }
        }
    },
    @{
        Kind="MSSQL_Contains"
        Count = 1
        Description = "The PS1 site database MSSQL server contains the PS1-PSS$ login"
        Source = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "*ps1-pss$@*:1433"
            }
        }
    },
    @{
        Kind="MSSQL_Contains"
        Count = 1
        Description = "The PS1 site database contains the db_owner database role"
        Source = @{
            Kinds = @("MSSQL_Database")
            Properties = @{
                id = "*:1433\CM_PS1"
            }
        }
        Target = @{
            Kinds = @("MSSQL_DatabaseRole")
            Properties = @{
                id = "db_owner@*:1433\CM_PS1"
            }
        }
    },
    @{
        Kind="MSSQL_Contains"
        Count = 1
        Description = "The PS1 site database contains the PS1-PSS$ user"
        Source = @{
            Kinds = @("MSSQL_Database")
            Properties = @{
                id = "*:1433\CM_PS1"
            }
        }
        Target = @{
            Kinds = @("MSSQL_DatabaseUser")
            Properties = @{
                id = "*ps1-pss$@*:1433\CM_PS1"
            }
        }
    },
    @{
        Kind="MSSQL_Contains"
        Count = 3
        Description = "The MSSQL servers contain the sysadmin server role"
        Source = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
        Target = @{
            Kinds = @("MSSQL_ServerRole")
            Properties = @{
                id = "sysadmin@*:1433"
            }
        }
    },

    ###################
    # MSSQL_ControlDB #
    ###################
    @{
        Kind="MSSQL_ControlDB"
        Count = 2
        Description = "The db_owner MSSQL database role controls the site database"
        Source = @{
            Kinds = @("MSSQL_DatabaseRole")
            Properties = @{
                id = "db_owner@*:1433\CM_*"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Database")
            Properties = @{
                id = "*:1433\CM_*"
            }
        }
    },

    #######################
    # MSSQL_ControlServer #
    #######################
    @{
        Kind="MSSQL_ControlServer"
        Count = 3
        Description = "The sysadmin MSSQL server role controls the server instance"
        Source = @{
            Kinds = @("MSSQL_ServerRole")
            Properties = @{
                id = "sysadmin@*:1433"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
    },

    #######################
    # MSSQL_ExecuteOnHost #
    #######################
    @{
        Kind="MSSQL_ExecuteOnHost"
        Count = 3
        Description = "The MSSQL server can execute commands on its host"
        Source = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
        Target = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
            }
        }
    },

    #####################
    # MSSQL_GetAdminTGS #
    #####################
    @{
        Kind="MSSQL_GetAdminTGS"
        Count = 2
        Description = "The site database MSSQL service account can request a TGS for any domain login on the server instance"
        Source = @{
            Kinds = @("User", "Base")
            Properties = @{
                samAccountName = "sqlsccmsvc"
                id = "S-1-5-21-*"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
    },

    ################
    # MSSQL_GetTGS #
    ################
    @{
        Kind="MSSQL_GetTGS"
        Count = 4
        Description = "The site database MSSQL service account can request a TGS for any domain login on the server instance (CAS-PSS, PS1-PSS, PS1-PSV, and PS1-SMS)"
        Source = @{
            Kinds = @("User", "Base")
            Properties = @{
                samAccountName = "sqlsccmsvc"
                id = "S-1-5-21-*"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "*$:1433"
            }
        }
    },

    ##################
    # MSSQL_HasLogin #
    ##################
    @{
        Kind="MSSQL_HasLogin"
        Count = 4
        Description = "The primary and passive site server and SMS Provider computers have logins on the MSSQL server instances (CAS-PSS -> CAS-DB, PS1-PSS -> PS1-DB, PS1-SMS -> PS1-DB, PS1-PSV -> PS1-DB)"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "*$:1433"
            }
        }
    },

    #################
    # MSSQL_HostFor #
    #################
    @{
        Kind="MSSQL_HostFor"
        Count = 3
        Description = "The MSSQL server computers host the MSSQL server instances"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
    },
    
    ####################
    # MSSQL_IsMappedTo #
    ####################
    @{
        Kind="MSSQL_IsMappedTo"
        Count = 4
        Description = "The primary and passive site server and SMS Provider MSSQL server logins (CAS-PSS, PS1-PSS, PS1-PSV, and PS1-SMS) are mapped to database users in the site databases"
        Source = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "*$:1433"
            }
        }
        Target = @{
            Kinds = @("MSSQL_DatabaseUser")
            Properties = @{
                id = "*$@*:1433\CM_*"
            }
        }
    },

    ##################
    # MSSQL_MemberOf #
    ##################
    @{
        Kind="MSSQL_MemberOf"
        Count = 4
        Description = "The primary and passive site server and SMS Provider MSSQL database users (CAS-PSS, PS1-PSS, PS1-PSV, and PS1-SMS) are members of the db_owner database role in the site databases"
        Source = @{
            Kinds = @("MSSQL_DatabaseUser")
            Properties = @{
                id = "*$@*:1433\CM_*"
            }
        }
        Target = @{
            Kinds = @("MSSQL_DatabaseRole")
            Properties = @{
                id = "db_owner@*:1433\CM_*"
            }
        }
    },
    @{
        Kind="MSSQL_MemberOf"
        Count =  4
        Description = "The primary and passive site server and SMS Provider MSSQL server logins (CAS-PSS, PS1-PSS, PS1-PSV, and PS1-SMS) are members of the sysadmin server role on the MSSQL server instances"
        Source = @{
            Kinds = @("MSSQL_Login")
            Properties = @{
                id = "*$:1433"
            }
        }
        Target = @{
            Kinds = @("MSSQL_ServerRole")
            Properties = @{
                id = "sysadmin@*:1433"
            }
        }
    }

    ###########################
    # MSSQL_ServiceAccountFor #
    ###########################
    @{
        Kind="MSSQL_ServiceAccountFor"
        Count = 2
        Description = "The site database MSSQL service account is the service account for the MSSQL server instances (CAS and PS1 primary and passive)"
        Source = @{
            Kinds = @("User", "Base")
            Properties = @{
                samAccountName = "sqlsccmsvc"
                id = "S-1-5-21-*"
            }
        }
        Target = @{
            Kinds = @("MSSQL_Server")
            Properties = @{
                id = "*:1433"
            }
        }
    },

    ##############
    # SameHostAs #
    ##############
    @{
        Kind="SameHostAs"
        Count = 1
        Description = "The PS1 client device is the same host as the domain joined computer (bi-directional)"
        Source = @{
            Kinds = @("SCCM_ClientDevice")
            Properties = @{
                id = "GUID:*"
            }
        }
        Target = @{
            Kinds = @("Computer")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-dev.$Domain"
            }
        }
    },
    @{
        Kind="SameHostAs"
        Count = 1
        Description = "The PS1 client device is the same host as the domain joined computer (bi-directional)"
        Source = @{
            Kinds = @("Computer")
            Properties = @{
                id = "S-1-5-21-*"
                dNSHostName = "ps1-dev.$Domain"
            }
        }
        Target = @{
            Kinds = @("SCCM_ClientDevice")
            Properties = @{
                id = "GUID:*"
            }
        }
    },

    ###########################
    # SCCM_AdminsReplicatedTo #
    ###########################
    @{
        Kind="SCCM_AdminsReplicatedTo"
        Count = 1
        Description = "The PS1 primary site has the same admins as the CAS primary site"
        Source = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "PS1"
            }
        }
        Target = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "CAS"
            }
        }
    },
    @{
        Kind="SCCM_AdminsReplicatedTo"
        Count = 1
        Description = "The PS1 primary site has the same admins as the CAS primary site (both directions)"
        Source = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "CAS"
            }
        }
        Target = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "PS1"
            }
        }
    },
    @{
        Kind="SCCM_AdminsReplicatedTo"
        Negative = $true
        Description = "Admin users in secondary sites are NOT replicated to primary sites (no replication from SEC to PS1 or CAS)"
        Source = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "SEC"
            }
        }
        Target = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "*"
            }
        }
    }

    #######################
    # SCCM_AllPermissions #
    #######################
    @{
        # SCCM admin user has all permissions in CAS and PS1
        Kind="SCCM_AllPermissions"
        Count = 2
        Description = "The Full Administrator with all collections has all permissions to all primary sites in the hierarchy"
        Source = @{
            Kinds = @("SCCM_AdminUser")
            Properties = @{
                id = "mayyhem\domainadmin@*"
            }
        }
        Target = @{
            Kinds = @("SCCM_Site")
        }
    },



    #############################
    # SCCM_AssignAllPermissions #
    #############################
    @{
        # CAS-PSS, PS1-PSS, PS1-PSV, and PS1-SMS all have this permission
        Kind="SCCM_AssignAllPermissions"
        Count = 8
        Description = "Domain computers hosting the SMS Provider role (CAS-PSS, PS1-PSS, PS1-PSV, PS1-SMS) can assign all permissions to any primary site in the hierarchy (CAS, PS1)"
        Source = @{
            Kinds = @("Computer", "Base")
            Properties = @{
                id = "S-1-5-21-*"
            }
        }
        Target = @{
            Kinds = @("SCCM_Site")
        }
    },
    @{
        Kind="SCCM_AssignAllPermissions"
        Count = 2
        Description = "SCCM primary site databases (CAS-DB\CM_CAS and PS1-DB\CM_PS1) can assign all permissions to their primary site in the hierarchy (CAS, PS1)"
        Source = @{
            Kinds = @("MSSQL_Database")
            Properties = @{
                id = "*:1433\CM_*"
            }
        }
        Target = @{
            Kinds = @("SCCM_Site")
        }
    },

    ##################################
    # SCCM_AssignSpecificPermissions #
    ##################################
    @{
        Kind="SCCM_AssignSpecificPermissions"
    },

    #################
    # SCCM_Contains #
    #################
    @{
        Kind="SCCM_Contains"
        Count = 2
        Description = "The CAS and PS1 primary sites contain an SCCM admin user"
        Source = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "*"
            }
        }
        Target = @{
            Kinds = @("SCCM_AdminUser")
            Properties = @{
                id = "mayyhem\domainadmin@*"
            }
        }
    },
    @{
        Kind="SCCM_Contains"
        Count = 2
        Description = "The CAS and PS1 primary sites contain the Full Administrator security role"
        Source = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "*"
            }
        }
        Target = @{
            Kinds = @("SCCM_SecurityRole")
            Properties = @{
                id = "SMS0001R@*"
            }
        }
    },
    @{
        Kind="SCCM_Contains"
        Count = 2
        Description = "The CAS and PS1 primary sites contain the SMS00001 collection"
        Source = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "*"
            }
        }
        Target = @{
            Kinds = @("SCCM_Collection")
            Properties = @{
                id = "SMS00001@*"
            }
        }
    },

    ##########################
    # SCCM_FullAdministrator #
    ##########################
    @{
        Kind="SCCM_FullAdministrator"
        Count = 14
        Description = "The domainadmin SCCM admin user has the Full Administrator security role over all client devices in the hierarchy"
        Source = @{
            Kinds = @("SCCM_AdminUser")
            Properties = @{
                id = "mayyhem\domainadmin@*"
            }
        }
        Target = @{
            Kinds = @("SCCM_ClientDevice")
            Properties = @{
                id = "GUID:*"
            }
        }
    },

    ###########################
    # SCCM_HasADLastLogonUser #
    ###########################
    @{
        Kind="SCCM_HasADLastLogonUser"
        Count = 1
        Description = "The PS1 client device has domainuser as the last logged on user in Active Directory"
        Source = @{
            Kinds = @("SCCM_ClientDevice")
            Properties = @{
                name = "PS1-DEV@PS1"
            }
        }
        Target = @{
            Kinds = @("User", "Base")
            Properties = @{
                samAccountName = "domainuser"
                id = "S-1-5-21-*"
            }
        }
    },

    ##################
    # SCCM_HasClient #
    ##################
    @{
        Kind="SCCM_HasClient"
        Count = 1
        Description = "PS1-DEV is a client of the PS1 site"
        Source = @{
            Kinds = @("SCCM_Site")
            Properties = @{
                id = "PS1"
            }
        }
        Target = @{
            Kinds = @("SCCM_ClientDevice")
            Properties = @{
                id = "GUID:*"
                name = "PS1-DEV@PS1"
            }
        }
    },


    #######################
    # SCCM_HasCurrentUser #
    #######################
    @{
        Kind="SCCM_HasCurrentUser"
        Count = 1
        Description = "The PS1 client device has domainuser as the current logged on user (requires manual addition of user device affinity after Ludus lab build)"
        Source = @{
            Kinds = @("SCCM_ClientDevice")
            Properties = @{
                id = "GUID:*"
                name = "PS1-DEV@PS1"
            }
        }
        Target = @{
            Kinds = @("User", "Base")
            Properties = @{
                samAccountName = "domainuser"
                id = "S-1-5-21-*"
            }
        }
    },

    ##################
    # SCCM_HasMember #
    ##################
    @{
        Kind="SCCM_HasMember"
        Count = 1
        Description = "The SMS00001 collection contains the PS1 client device"
        Source = @{
            Kinds = @("SCCM_Collection")
            Properties = @{
                id = "SMS00001@*"
            }
        }
        Target = @{
            Kinds = @("SCCM_ClientDevice")
            Properties = @{
                id = "GUID:*"
                name = "PS1-DEV@PS1"
            }
        }
    },

    #######################
    # SCCM_HasPrimaryUser #
    #######################
    @{
        Kind="SCCM_HasPrimaryUser"
        Count = 1
        Description = "The PS1 client device has domainuser as the primary user"
        Source = @{
            Kinds = @("SCCM_ClientDevice")
            Properties = @{
                id = "GUID:*"
                name = "PS1-DEV@PS1"
            }
        }
        Target = @{
            Kinds = @("User", "Base")
            Properties = @{
                samAccountName = "domainuser"
                id = "S-1-5-21-*"
            }
        }
    },

    ###################
    # SCCM_IsAssigned #
    ###################
    @{
        Kind="SCCM_IsAssigned"
        Count = 1
        Description = "The domainadmin SCCM admin user is assigned the Full Administrator security role in the CAS root site"
        Source = @{
            Kinds = @("SCCM_AdminUser")
            Properties = @{
                id = "mayyhem\domainadmin@*"
            }
        }
        Target = @{
            Kinds = @("SCCM_SecurityRole")
            Properties = @{
                id = "SMS0001R@*"  # Full Administrator role ID
            }
        }
    },

    ###################
    # SCCM_IsMappedTo #
    ###################
    @{
        Kind="SCCM_IsMappedTo"
        Count = 1
        Description = "The domainadmin user is mapped to an SCCM admin user in the CAS primary site"
        Source = @{
            Kinds = @("User", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                samAccountName = "domainadmin"
            }
        }
        Target = @{
            Kinds = @("SCCM_AdminUser")
            Properties = @{
                id = "mayyhem\domainadmin@*"
            }
        }
    },
    @{
        Kind="SCCM_IsMappedTo"
        Negative = $true
        Description = "The domainuser user is NOT mapped to an SCCM admin user in any primary site"
        Source = @{
            Kinds = @("User", "Base")
            Properties = @{
                id = "S-1-5-21-*"
                samAccountName = "domainuser"
            }
        }
        Target = @{
            Kinds = @("SCCM_AdminUser")
            Properties = @{
                id = "domainuser@*"
            }
        }
    }
)

function Test-EdgePattern {
    param(
        [PSObject]$Edge,
        [PSObject]$Nodes,
        [hashtable]$ExpectedEdge,
        [switch]$ShowDebug
    )
    
    # Check edge kind
    if ($Edge.kind -ne $ExpectedEdge.Kind) {
        return $false
    }

    # Print all edge properties for debugging in ()-[]->() format
    function Dump-EdgeProperties {
        param($Edge)
        Write-TestLog "  Testing Edge: $($Edge.start.value)-[$($Edge.kind)]->$($Edge.end.value)" -Level Verbose
        Write-TestLog "  Kind: $($Edge.kind)" -Level Verbose
        Write-TestLog "  Properties:" -Level Verbose
        foreach ($prop in $Edge.PSObject.Properties) {
            Write-TestLog "    $($prop.Name): $($prop.Value)" -Level Verbose
        }
    }

    # Find source and target nodes
    $sourceNode = $Nodes | Where-Object { $_.id -eq $Edge.start.value } | Select-Object -First 1
    $targetNode = $Nodes | Where-Object { $_.id -eq $Edge.end.value } | Select-Object -First 1
    
    if (-not $sourceNode -or -not $targetNode) {
        if ($ShowDebug) {
            Dump-EdgeProperties -Edge $Edge
            Write-TestLog "    Could not find source or target node" -Level Warning
        }
        return $false
    }
    
    # Check source node matches expected pattern
    if ($ExpectedEdge.Source) {
        if (-not (Test-NodePattern -Node $sourceNode -Expected $ExpectedEdge.Source -ShowDebug:$ShowDebug)) {
            if ($ShowDebug) {
                Dump-EdgeProperties -Edge $Edge
                Write-TestLog "    Source node doesn't match pattern" -Level Warning
            }
            return $false
        }
    }
    
    # Check target node matches expected pattern
    if ($ExpectedEdge.Target) {
        if (-not (Test-NodePattern -Node $targetNode -Expected $ExpectedEdge.Target -ShowDebug:$ShowDebug)) {
            if ($ShowDebug) {
                Dump-EdgeProperties -Edge $Edge
                Write-TestLog "    Target node doesn't match pattern" -Level Warning
            }
            return $false
        }
    }
    
    # Check edge properties if specified
    if ($ExpectedEdge.Properties) {
        foreach ($prop in $ExpectedEdge.Properties.Keys) {
            $expectedValue = $ExpectedEdge.Properties[$prop]
            $actualValue = if ($Edge.properties.$prop) { $Edge.properties.$prop } else { $Edge.$prop }
            
            if (-not (Test-PropertyMatch -Actual $actualValue -Expected $expectedValue)) {
                if ($ShowDebug) {
                    Dump-EdgeProperties -Edge $Edge
                    Write-TestLog "    Edge property '$prop' doesn't match (expected: $expectedValue, actual: $actualValue)" -Level Verbose
                }
                return $false
            }
        }
    }
    
    return $true
}


function Test-NodePattern {
    param(
        [PSObject]$Node,
        [hashtable]$Expected,
        [switch]$ShowDebug
    )

    # Print all node properties for debugging
    function Dump-NodeProperties {
        param($Node)
        Write-TestLog "  Testing Node ID: $($Node.id)" -Level Verbose
        Write-TestLog "  Kinds: $($Node.kinds -join ', ')" -Level Verbose
        Write-TestLog "  Properties:" -Level Verbose
        foreach ($prop in $Node.PSObject.Properties) {
            Write-TestLog "  $($prop.Name): $($prop.Value)" -Level Verbose
        }
    }

    # Check kinds
    if ($Expected.Kinds) {
        foreach ($expectedKind in $Expected.Kinds) {
            if ($expectedKind -eq "Base") { continue }  # Base is always present
            if ($Node.kinds -notcontains $expectedKind) {
                if ($ShowDebug) {
                    Dump-NodeProperties -Node $Node
                    Write-TestLog "    Node missing kind '$expectedKind' (has: $($Node.kinds -join ', '))" -Level Warning
                }
                return $false
            }
        }
    }
    
    # Check properties
    if ($Expected.Properties) {
        foreach ($prop in $Expected.Properties.Keys) {
            $expectedValue = $Expected.Properties[$prop]
            $actualValue = $null
            
            # Check both node properties and direct node attributes
            if ($Node.properties -and $Node.properties.PSObject.Properties[$prop]) {
                $actualValue = $Node.properties.$prop
            } elseif ($Node.PSObject.Properties[$prop]) {
                $actualValue = $Node.$prop
            }
            
            if (-not (Test-PropertyMatch -Actual $actualValue -Expected $expectedValue)) {
                if ($ShowDebug) {
                    Dump-NodeProperties -Node $Node
                    Write-TestLog "    Property '$prop' doesn't match (expected: $expectedValue, actual: $actualValue)" -Level Warning
                }
                return $false
            }
        }
    }
    
    return $true
}

function Test-PropertyMatch {
    param(
        $Actual,
        $Expected
    )
    
    # Handle null cases
    if ($null -eq $Actual -and $null -eq $Expected) { return $true }
    if ($null -eq $Actual -or $null -eq $Expected) { return $false }
    
    # Handle array comparisons
    if ($Expected -is [array] -and $Actual -is [array]) {
        # For arrays, check if all expected items are present in the actual array
        foreach ($expectedItem in $Expected) {
            $found = $false
            foreach ($actualItem in $Actual) {
                if (Test-PropertyMatch -Actual $actualItem -Expected $expectedItem) {
                    $found = $true
                    break
                }
            }
            if (-not $found) {
                return $false
            }
        }
        return $true
    }
    elseif ($Expected -is [array] -or $Actual -is [array]) {
        # One is array, one is not - no match
        return $false
    }
    
    # Convert to strings for comparison
    $actualStr = $Actual.ToString()
    $expectedStr = $Expected.ToString()
    
    # If expected contains wildcards, use pattern matching
    if ($expectedStr.Contains('*') -or $expectedStr.Contains('?')) {
        return $actualStr -like $expectedStr
    }
    
    # If expected is boolean, compare as boolean
    if ($Expected -is [bool]) {
        if ($Actual -is [bool]) {
            return $Actual -eq $Expected
        }
        # Try to convert string to boolean
        if ($actualStr -eq "True" -or $actualStr -eq "1") {
            return $Expected -eq $true
        }
        if ($actualStr -eq "False" -or $actualStr -eq "0") {
            return $Expected -eq $false
        }
    }
    
    # Otherwise use exact match (case-insensitive)
    return $actualStr -ieq $expectedStr
}

function Invoke-Collection {

    Write-TestLog "Starting collection..." -Level Info
    
    # "-CollectionMethods","'AdminService'","-SmsProvider","site-sms.aperture.local","-Verbose"
    $scriptParams = @{
        CollectionMethods = $CollectionMethods
        LogFile = $LogFile
        SmsProvider = $SmsProvider
        Verbose = $true
    }
    
    # Add switch parameters only if they are set
    if ($DisablePossibleEdges) {
        $scriptParams['DisablePossibleEdges'] = $true
    }
    
    # Run the enumeration script
    try {
        & $EnumerationScript @scriptParams 2>&1
    }
    catch {
        Write-TestLog "Error running enumeration: $_" -Level Error
        return $null
    }
    Write-TestLog "Enumeration completed successfully" -Level Info
}

# Helper function to extract and read output from ZIP
function Get-OutputFromZip {
    param(
        [string]$ZipPattern = "bloodhound-sccm*.zip"
    )
    
    # Find the most recent ZIP file
    $zipFiles = Get-ChildItem -Path . -Filter $ZipPattern | Sort-Object LastWriteTime -Descending
    if (-not $zipFiles) {
        return $null
    }
    
    $zipFile = $zipFiles[0]
    Write-TestLog "Found ZIP file: $($zipFile.FullName)" -Level Info
    
    # Create temp directory for extraction
    $tempDir = Join-Path $env:TEMP "Enum_$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    try {
        # Extract ZIP
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile.FullName, $tempDir)
        
        # Find all JSON files in the extracted content
        $jsonFiles = Get-ChildItem -Path $tempDir -Filter "*.json" -Recurse
        Write-TestLog "Found $($jsonFiles.Count) JSON files in ZIP" -Level Info
        
        # Combine all nodes and edges from all files
        $combinedOutput = @{
            graph = @{
                nodes = @()
                edges = @()
            }
        }
        
        foreach ($jsonFile in $jsonFiles) {
            Write-TestLog "Reading JSON from: $($jsonFile.Name)" -Level Info
            $content = Get-Content $jsonFile.FullName -Raw | ConvertFrom-Json
            
            # Add nodes and edges to combined output
            if ($content.graph) {
                if ($content.graph.nodes) {
                    $combinedOutput.graph.nodes += $content.graph.nodes
                }
                if ($content.graph.edges) {
                    $combinedOutput.graph.edges += $content.graph.edges
                }
            }
        }
        
        Write-TestLog "Combined output: $($combinedOutput.graph.nodes.Count) nodes, $($combinedOutput.graph.edges.Count) edges" -Level Info
        
        # Clean up temp directory
        Remove-Item $tempDir -Recurse -Force
        
        # Ask to clean up ZIP file
        #Write-TestLog "Do you want to delete the zip file with the collection results? (y/N)" -Level Warning
        #$response = Read-Host
        $response = 'N'  # Auto-confirm for cleanup
        if ($response -eq 'Y' -or $response -eq 'y') {
            Remove-Item $zipFile.FullName -Force
            Write-TestLog "Cleaned up ZIP file: $($zipFile.Name)" -Level Info
        }
        
        return $combinedOutput
    }
    catch {
        Write-TestLog "Error extracting ZIP: $_" -Level Error
        if (Test-Path $tempDir) {
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    return $null
}

function Test-Edges {
    param(
        [PSObject]$Output,
        [switch]$ShowDebug
    )

    Write-TestLog "`nTesting Edges..." -Level Test
    Write-TestLog ("=" * 30) -Level Info
    
    if (-not $Output -or -not $Output.graph -or -not $Output.graph.edges) {
        Write-TestLog "No edges found in output" -Level Error
        return @{
            Passed = @()
            Failed = @()
            Skipped = @()
        }
    }
    
    $edges = $Output.graph.edges
    $nodes = $Output.graph.nodes
    Write-TestLog "Total edges found: $($edges.Count)" -Level Info
    Write-TestLog "Total nodes found: $($nodes.Count)" -Level Info
    
    # Group edges by type for analysis
    $edgesByType = $edges | Group-Object -Property kind
    Write-TestLog "`nEdge types found:" -Level Info
    foreach ($group in $edgesByType | Sort-Object Name) {
        Write-TestLog "  $($group.Name): $($group.Count)" -Level Info
    }
    
    $testResults = @{
        Passed = @()
        Failed = @()
        Skipped = @()
    }
    
    # Combine expected and negative edges for testing
    $allTestCases = @()
    $allTestCases += $script:ExpectedEdges
    
    Write-TestLog "`nRunning edge tests..." -Level Test
    
    foreach ($testCase in $allTestCases) {
        # Filter by edge type if specified
        if ($LimitToEdgeType -and $testCase.Kind -ne $LimitToEdgeType) { 
            continue 
        }


        # If a test case has no constraints (no Source/Target/Properties), it's too loose.
        # Treat it as a coverage placeholder and skip instead of passing on kind-only matches.
        $hasConstraints = $false
        if ($testCase.Source -or $testCase.Target -or $testCase.Properties) { 
            $hasConstraints = $true 
        }
        if (-not $hasConstraints) {
            Write-TestLog "$($testCase.Kind): no Source/Target/Properties specified - SKIPPED (coverage placeholder)" -Level Warning
            $testResults.Skipped += $testCase
            continue
        }

        # Find matching edges - enable debug output for troubleshooting pattern matching
        $matchingEdges = @()
        foreach ($edge in $edges) {
            if (Test-EdgePattern -Edge $edge -Nodes $nodes -ExpectedEdge $testCase -ShowDebug:$ShowDebug) {
                $matchingEdges += $edge
            }
        }
        
        # Determine test result
        $found = $matchingEdges.Count -gt 0
        
        if ($testCase.Negative) {
            # This is a negative test - edge should NOT exist
            if (-not $found) {
                Write-TestLog "$($testCase.Kind): $($testCase.Description) - PASS (correctly absent)" -Level Success
                if ($testCase.Reason) {
                    Write-TestLog "  Reason: $($testCase.Reason)" -Level Info
                }
                $testResults.Passed += $testCase
            } else {
                Write-TestLog "$($testCase.Kind): $($testCase.Description) - FAIL (incorrectly present)" -Level Error
                Write-TestLog "  This edge should not exist: $($testCase.Reason)" -Level Error
                Write-TestLog "  Found $($matchingEdges.Count) matching edge(s)" -Level Error
                
                # Show details of the incorrect edges in requested format
                Write-TestLog "  Matching edges:" -Level Error
                foreach ($edge in $matchingEdges) {
                    Write-TestLog "    ($($edge.start.value)) -[$($edge.kind)]-> ($($edge.end.value))" -Level Error
                }
                $testResults.Failed += $testCase
            }
        } else {
            # This is a positive test - edge SHOULD exist
            if ($found) {
                # Check if expected count is specified and validate it
                if ($testCase.Count -and $matchingEdges.Count -ne $testCase.Count) {
                    Write-TestLog "$($testCase.Kind): $($testCase.Description) - FAIL (wrong count)" -Level Error
                    Write-TestLog "  Expected $($testCase.Count) matching edge(s) but found $($matchingEdges.Count)" -Level Error
                    
                    # List matching edges in requested format
                    Write-TestLog "  Matching edges:" -Level Error
                    foreach ($edge in $matchingEdges) {
                        Write-TestLog "    ($($edge.start.value)) -[$($edge.kind)]-> ($($edge.end.value))" -Level Error
                    }
                    $testResults.Failed += $testCase
                } else {
                    Write-TestLog "$($testCase.Kind): $($testCase.Description) - PASS" -Level Success
                    Write-TestLog "  Found $($matchingEdges.Count) matching edge(s)" -Level Success
                    
                    # List matching edges in requested format
                    Write-TestLog "  Matching edges:" -Level Info
                    foreach ($edge in $matchingEdges) {
                        Write-TestLog "    ($($edge.start.value)) -[$($edge.kind)]-> ($($edge.end.value))" -Level Info
                    }
                    $testResults.Passed += $testCase
                }
            } else {
                Write-TestLog "$($testCase.Kind): $($testCase.Description) - FAIL (not found)" -Level Error
                
                # Show what we were looking for in a concise format
                $sourcePattern = ""
                $targetPattern = ""
                
                if ($testCase.Source.Properties) {
                    $sourceProps = @()
                    foreach ($prop in $testCase.Source.Properties.Keys) {
                        $sourceProps += "$prop=$($testCase.Source.Properties[$prop])"
                    }
                    $sourcePattern = "Source: {$($sourceProps -join ', ')}"
                }
                
                if ($testCase.Target.Properties) {
                    $targetProps = @()
                    foreach ($prop in $testCase.Target.Properties.Keys) {
                        $targetProps += "$prop=$($testCase.Target.Properties[$prop])"
                    }
                    $targetPattern = "Target: {$($targetProps -join ', ')}"
                }
                
                if ($sourcePattern -or $targetPattern) {
                    $patterns = @($sourcePattern, $targetPattern) | Where-Object { $_ }
                    Write-TestLog "  Expected: $($patterns -join ' -> ')" -Level Error
                }
                
                # Analyze why the test failed and provide specific guidance
                $sameKindEdges = $edges | Where-Object { $_.kind -eq $testCase.Kind }
                if ($sameKindEdges.Count -gt 0) {
                    Write-TestLog "  Analysis: Found $($sameKindEdges.Count) $($testCase.Kind) edge(s) but none matched the pattern" -Level Warning
                    
                    # Analyze the mismatch reasons for better diagnostics
                    $mismatchReasons = @()
                    $checkedNodes = @{}
                    
                    foreach ($edge in ($sameKindEdges | Select-Object -First 3)) {
                        $sourceNode = $nodes | Where-Object { $_.id -eq $edge.start.value } | Select-Object -First 1
                        $targetNode = $nodes | Where-Object { $_.id -eq $edge.end.value } | Select-Object -First 1
                        
                        # Check source node mismatch
                        if ($testCase.Source -and $sourceNode -and -not $checkedNodes[$sourceNode.id]) {
                            $checkedNodes[$sourceNode.id] = $true
                            if ($testCase.Source.Properties) {
                                foreach ($prop in $testCase.Source.Properties.Keys) {
                                    $expectedValue = $testCase.Source.Properties[$prop]
                                    $actualValue = if ($sourceNode.properties.$prop) { $sourceNode.properties.$prop } else { $sourceNode.$prop }
                                    if (-not (Test-PropertyMatch -Actual $actualValue -Expected $expectedValue)) {
                                        $mismatchReasons += "Source node $($sourceNode.id): $prop = '$actualValue' (expected '$expectedValue')"
                                    }
                                }
                            }
                        }
                        
                        # Check target node mismatch
                        if ($testCase.Target -and $targetNode -and -not $checkedNodes[$targetNode.id]) {
                            $checkedNodes[$targetNode.id] = $true
                            if ($testCase.Target.Properties) {
                                foreach ($prop in $testCase.Target.Properties.Keys) {
                                    $expectedValue = $testCase.Target.Properties[$prop]
                                    $actualValue = if ($targetNode.properties.$prop) { $targetNode.properties.$prop } else { $targetNode.$prop }
                                    if (-not (Test-PropertyMatch -Actual $actualValue -Expected $expectedValue)) {
                                        $mismatchReasons += "Target node $($targetNode.id): $prop = '$actualValue' (expected '$expectedValue')"
                                    }
                                }
                            }
                        }
                    }
                    
                    # Show specific mismatch reasons
                    if ($mismatchReasons.Count -gt 0) {
                        Write-TestLog "  Common issues found:" -Level Info
                        foreach ($reason in ($mismatchReasons | Select-Object -Unique | Select-Object -First 5)) {
                            Write-TestLog "    - $reason" -Level Info
                        }
                    }
                    
                    # Show a few examples of what exists (limit to 2 for readability)
                    Write-TestLog "  Existing $($testCase.Kind) edges:" -Level Info
                    foreach ($example in ($sameKindEdges | Select-Object -First 2)) {
                        Write-TestLog "    ($($example.start.value)) -[$($example.kind)]-> ($($example.end.value))" -Level Info
                    }
                    if ($sameKindEdges.Count -gt 2) {
                        Write-TestLog "    ... and $($sameKindEdges.Count - 2) more" -Level Info
                    }
                } else {
                    Write-TestLog "  Analysis: No $($testCase.Kind) edges found in the data" -Level Warning
                    Write-TestLog "  Suggestion: Verify that the enumeration script is collecting this edge type" -Level Info
                }
                
                $testResults.Failed += $testCase
            }
        }
    }
    
    # Summary
    Write-TestLog "`nEdge Test Summary:" -Level Info
    Write-TestLog "  Passed: $($testResults.Passed.Count)" -Level Success
    Write-TestLog "  Failed: $($testResults.Failed.Count)" -Level Error
    Write-TestLog "  Skipped: $($testResults.Skipped.Count)" -Level Warning
    
    return $testResults
}

function Get-MissingTests {
    Write-TestLog "`nChecking for untested node and edge types..." -Level Info
    Write-TestLog "=" * 60 -Level Info
    
    $testedNodeTypes = @()
    $testedEdgeTypes = @()
    
    # Get all tested node types
    foreach ($nodeType in $script:NodeTypes) {
        $expectedVar = Get-Variable -Name "expectedNodes_$($nodeType.Replace('SCCM_', ''))" -Scope Script -ErrorAction SilentlyContinue
        if ($expectedVar -and $expectedVar.Value.Count -gt 0) {
            $testedNodeTypes += $nodeType
        }
    }
    
    # Get all tested edge types
    foreach ($edgeType in $script:EdgeTypes) {
        $varName = "expectedEdges_$($edgeType.Replace('SCCM_', '').Replace(' ', ''))"
        $expectedVar = Get-Variable -Name $varName -Scope Script -ErrorAction SilentlyContinue
        if ($expectedVar -and $expectedVar.Value.Count -gt 0) {
            $testedEdgeTypes += $edgeType
        }
    }
    
    # Find untested types
    $untestedNodes = $script:NodeTypes | Where-Object { $_ -notin $testedNodeTypes }
    $untestedEdges = $script:EdgeTypes | Where-Object { $_ -notin $testedEdgeTypes }
    
    if ($untestedNodes.Count -gt 0) {
        Write-TestLog "Node types without tests:" -Level Warning
        foreach ($nodeType in $untestedNodes) {
            Write-TestLog "  - $nodeType" -Level Warning
        }
    } else {
        Write-TestLog "All node types have tests defined!" -Level Success
    }
    
    if ($untestedEdges.Count -gt 0) {
        Write-TestLog "Edge types without tests:" -Level Warning
        foreach ($edgeType in $untestedEdges) {
            Write-TestLog "  - $edgeType" -Level Warning
        }
    } else {
        Write-TestLog "All edge types have tests defined!" -Level Success
    }
}

function Test-EdgeCreation {
    
}

#region Main Execution
Write-TestLog ("=" * 30) -Level Info
Write-TestLog "SCCM Collector Test Suite" -Level Info
Write-TestLog ("=" * 30) -Level Info

try {
    if ($Action -eq "All" -or $Action -eq "Setup") {
        #Invoke-Setup
    }
    if ($Action -eq "All" -or $Action -eq "Test") {
        if ($SkipCollection) {
            Write-TestLog "Skipping collection phase - parsing most recent ZIP file..." -Level Info
        } else {
            Invoke-Collection
        }
        $output = Get-OutputFromZip
        if (-not $output) {
            Write-TestLog "No output found from enumeration" -Level Error
            return $null
        }

        $testResults = Test-Edges -Output $output -ShowDebug:$ShowDebug

        # Additional node-level sanity check: SCCM_ClientDevice.memberOf normalization
        try {
            $nodes = $output.graph.nodes

            # Identify hierarchy root site code (CAS in this lab) from SCCM_Site nodes
            $siteNodes = $nodes | Where-Object { $_.kinds -contains "SCCM_Site" }
            $rootSite = $siteNodes | Where-Object { $_.id -eq "CAS" } | Select-Object -First 1
            if (-not $rootSite) {
                Write-TestLog "ClientDevice memberOf normalization check: could not find CAS root site node; skipping check" -Level Warning
            }
            else {
                $rootSiteCode = $rootSite.id  # e.g. "CAS"

                # Find SCCM client devices that have memberOf entries
                $clientDevices = $nodes | Where-Object { $_.kinds -contains "SCCM_ClientDevice" }

                foreach ($device in $clientDevices) {
                    $memberOf = $device.properties.memberOf
                    if (-not $memberOf) {
                        continue
                    }

                    $badEntries = @()
                    foreach ($entry in $memberOf) {
                        if ($entry -match '^(.+)@([A-Z0-9]{3})$') {
                            $siteCode = $Matches[2]
                            if ($siteCode -ne $rootSiteCode) {
                                $badEntries += $entry
                            }
                        }
                    }

                    if ($badEntries.Count -gt 0) {
                        Write-TestLog "ClientDevice memberOf normalization check - FAIL" -Level Error
                        Write-TestLog "  Device ID: $($device.id)" -Level Error
                        Write-TestLog "  Found non-root memberOf entries: $($badEntries -join ', ')" -Level Error
                    }
                    else {
                        Write-TestLog "ClientDevice memberOf normalization check - PASS for device $($device.id)" -Level Success
                    }
                }
            }
        }
        catch {
            Write-TestLog "Error during client device normalization check: $_" -Level Error
        }

        # Display coverage table
        Write-TestLog "Edge Type Coverage Summary:" -Level Info
        Get-MissingTests -ShowDetails
    }
} catch {
    Write-TestLog "Error during setup or test execution: $_" -Level Error
} finally {
    # Cleanup actions if needed
}

Write-TestLog "Test suite execution completed!" -Level Success

#endregion