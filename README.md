# ConfigManBearPig

<img width="256" height="384" alt="ChatGPT Image Dec 22, 2025, 01_24_18 PM" src="https://github.com/user-attachments/assets/f40c4268-431d-4dbc-9134-ed6d0e7309a0" />

A PowerShell collector for adding SCCM attack paths to [BloodHound](https://github.com/SpecterOps/BloodHound) with OpenGraph by Chris Thompson at [SpecterOps](https://x.com/SpecterOps)

Please hit me up on the [BloodHound Slack](http://ghst.ly/BHSlack) (@Mayyhem), Twitter ([@_Mayyhem](https://x.com/_Mayyhem)), or open an issue if you have any questions I can help with!

# Table of Contents

- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Limitations](#limitations)
- [Usage Info](#usage-info)
- [Command Line Options](#command-line-options)
- [Future Development](#future-development)
- [SCCM Nodes Reference](#sccm-nodes-reference)
  - [SCCM_AdminUser](#sccm_adminuser-node)
  - [SCCM_ClientDevice](#sccm_clientdevice-node)
  - [SCCM_Collection](#sccm_collection-node)
  - [SCCM_SecurityRole](#sccm_securityrole-node)
  - [SCCM_Site](#sccm_site-node)
- [SCCM Edges Reference](#sccm-edges-reference)
  - [LocalAdminRequired](#localadminrequired)
  - [CoerceAndRelayToAdminService](#coerceandrelaytoadminservice)
  - [CoerceAndRelayToMSSQL](#coerceandrelaytomssql)
  - [CoerceAndRelaytoSMB](#coerceandrelaytosmb)
  - [HasSession](#hassession)
  - [MSSQL_Contains](#mssql_contains)
  - [MSSQL_ControlDB](#mssql_controldb)
  - [MSSQL_ControlServer](#mssql_controlserver)
  - [MSSQL_ExecuteOnHost](#mssql_executeonhost)
  - [MSSQL_GetAdminTGS](#mssql_getadmintgs)
  - [MSSQL_GetTGS](#mssql_gettgs)
  - [MSSQL_HasLogin](#mssql_haslogin)
  - [MSSQL_HostFor](#mssql_hostfor)
  - [MSSQL_IsMappedTo](#mssql_ismappedto)
  - [MSSQL_MemberOf](#mssql_memberof)
  - [MSSQL_ServiceAccountFor](#mssql_serviceaccountfor)
  - [SameHostAs](#samehostas)
  - [SCCM_AdminsReplicatedTo](#sccm_adminsreplicatedto)
  - [SCCM_AllPermissions](#sccm_allpermissions)
  - [SCCM_ApplicationAdministrator](#sccm_applicationadministrator)
  - [SCCM_AssignAllPermissions](#sccm_assignallpermissions)
  - [SCCM_AssignSpecificPermissions](#sccm_assignspecificpermissions)
  - [SCCM_Contains](#sccm_contains)
  - [SCCM_FullAdministrator](#sccm_fulladministrator)
  - [SCCM_HasADLastLogonUser](#sccm_hasadlastlogonuser)
  - [SCCM_HasClient](#sccm_hasclient)
  - [SCCM_HasCurrentUser](#sccm_hascurrentuser)
  - [SCCM_HasMember](#sccm_hasmember)
  - [SCCM_HasNetworkAccessAccount](#sccm_hasnetworkaccessaccount)
  - [SCCM_HasPrimaryUser](#sccm_hasprimaryuser)
  - [SCCM_HasStoredAccount](#sccm_hasstoredaccount)
  - [SCCM_IsAssigned](#sccm_isassigned)
  - [SCCM_IsMappedTo](#sccm_ismappedto)

# Overview
Collects BloodHound OpenGraph compatible data and creates a zip in the current directory
  - Example: `sccm-bloodhound-20251020-115610.zip`

ConfigManBearPig follows these ordered steps when run without arguments:
  1.  LDAP (identify sites, site servers, fallback status points, and management points in System Management container)
  2.  Local (identify management points and distribution points in logs when running this script on an SCCM client)
  3.  DNS (identify management points published to DNS)
  4.  *DHCP (identify PXE-enabled distribution points and management points in boot media)
  5.  Remote Registry (identify site servers, site databases, and current users on targets)
  6.  MSSQL (check database servers for Extended Protection for Authentication)
  7.  AdminService (collect information from SMS Providers with privileges to query site information)
  8.  *WMI (if AdminService collection fails)
  9.  HTTP (identify management points, distribution points, and SMS Providers via exposed web services)
  10. SMB (identify site servers and distribution points via file shares)

*Work in progress

## System Requirements
  - PowerShell 4.0 or higher
  - Active Directory domain context with line of sight to a domain controller
  - Various permissions based on collection methods used

## Limitations
  - You MUST include the 'MSSQL' collection method to remotely identify EPA settings on site database servers with any domain user (or 'RemoteRegistry' to collect from the registry with admin privileges on the system hosting the database).
  - SCCM hierarchies don't have their own unique identifier, so the site code for the site that data is collected from is used in the identifier for objects (e.g., SMS00001@PS1), preventing merging of objects if there are more than one hierarchy in the same graph database (e.g., both hierarchies will have the SMS00001 collection but different members), but causing duplicate objects if collecting from two sites within the same hierarchy.
  - If the same site code exists more than once in the environment (Microsoft recommends against this, so it shouldn't), the nodes and edges for those sites will be merged, causing false positives in the graph. This is not recommended within the same forest: https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/prepare-to-install-sites#bkmk_sitecodes
  - It is assumed in some cases (e.g., during DP and SMS Provider collection) that a single system does not host site system roles in more than one site. If this is the case, only one site code will be associated with that system.
  - CoerceAndRelayNTLMtoSMB collection doesn't work because post-processed AdminTo edges can't be added via OpenGraph yet, so added CoerceAndRelayToSMB edges instead
  - MSSQL collection assumes that any collection target hosting a SQL Server instance is a site database server. If there are other SQL Servers in the environment, false positives may occur.
  - I'm not a hooking expert, so if you see crashes during MSSQL collection due to the InitializeSecurityContextW hooking method that's totally vibe-coded, disable it. The hooking function doesn't work in PowerShell v7+ due to lack of support for certain APIs.

## Usage Info
To populate the SCCM node glyphs in BloodHound, execute ConfigManBearPig.ps1 -OutputFormat CustomNodes (or copy the following) and use the API Explorer page to submit the JSON to the custom-nodes endpoint.
```
{
    "custom_types":  {
                         "SCCM_ClientDevice":  {
                                                   "icon":  {
                                                                "color":  "#f59b42",
                                                                "name":  "desktop",
                                                                "type":  "font-awesome"
                                                            }
                                               },
                         "SCCM_Collection":  {
                                                 "icon":  {
                                                              "color":  "#fff82e",
                                                              "name":  "sitemap",
                                                              "type":  "font-awesome"
                                                          }
                                             },
                         "MSSQL_Database":  {
                                                "icon":  {
                                                             "color":  "#f54242",
                                                             "name":  "database",
                                                             "type":  "font-awesome"
                                                         }
                                            },
                         "MSSQL_ServerRole":  {
                                                  "icon":  {
                                                               "color":  "#6942f5",
                                                               "name":  "users-gear",
                                                               "type":  "font-awesome"
                                                           }
                                              },
                         "SCCM_AdminUser":  {
                                                "icon":  {
                                                             "color":  "#558eea",
                                                             "name":  "user-gear",
                                                             "type":  "font-awesome"
                                                         }
                                            },
                         "MSSQL_DatabaseUser":  {
                                                    "icon":  {
                                                                 "color":  "#f5ef42",
                                                                 "name":  "user",
                                                                 "type":  "font-awesome"
                                                             }
                                                },
                         "MSSQL_DatabaseRole":  {
                                                    "icon":  {
                                                                 "color":  "#f5a142",
                                                                 "name":  "users",
                                                                 "type":  "font-awesome"
                                                             }
                                                },
                         "MSSQL_Server":  {
                                              "icon":  {
                                                           "color":  "#42b9f5",
                                                           "name":  "server",
                                                           "type":  "font-awesome"
                                                       }
                                          },
                         "MSSQL_Login":  {
                                             "icon":  {
                                                          "color":  "#dd42f5",
                                                          "name":  "user-gear",
                                                          "type":  "font-awesome"
                                                      }
                                         },
                         "SCCM_Site":  {
                                           "icon":  {
                                                        "color":  "#67ebf0",
                                                        "name":  "city", 
                                                        "type":  "font-awesome"
                                                    }
                                       },
                         "SCCM_SecurityRole":  {
                                                   "icon":  {
                                                                "color":  "#9852ed",
                                                                "name":  "users-gear",
                                                                "type":  "font-awesome"
                                                            }
                                               }
                     }
}
```

# Command Line Options
For the latest and most reliable information, please execute ConfigManBearPig with the `-Help` flag.

| Option<br>______________________________________________ | Values<br>_______________________________________________________________________________________________ |
|--------|--------|
| **-Help** `<switch>` | • Display usage information |
| **-OutputFormat** `<string>` | • **Zip**: OpenGraph implementation that collects data in separate files for each MSSQL server, then zips them up and deletes the originals. The zip can be uploaded to BloodHound by navigating to `Administration` > `File Ingest`<br>• **CustomNodes**: Generate JSON to POST to `custom-nodes` API endpoint<br> |
| **-TempDir** `<string>` | • Specify the path to a temporary directory where .json files will be stored before being zipped<br>Default: new directory created with `[System.IO.Path]::GetTempPath()` |
| **-ZipDir** `<string>` | • Specify the path to a directory where the final .zip file will be stored<br>• Default: current directory |
| **-MemoryThresholdPercent** `<uint>` | • Maximum memory allocation limit, after which the script will exit to prevent availability issues<br>• Default: `90` |
| **-Domain** `<string>` | • Specify a **domain** to use for name and SID resolution |
| **-DomainController** `<string>` | • Specify a **domain controller** FQDN/IP to use for name and SID resolution |
| **-DisablePossibleEdges** (switch) | • **Off**: Collect the following edges (useful for offensive engagements but prone to false positive edges that may not be abusable):<br>&nbsp;&nbsp;&nbsp;&nbsp;• **CoerceAndRelayToMSSQL** By default, EPA setting is assumed to be Off if the MSSQL server can't be reached<br>&nbsp;&nbsp;&nbsp;&nbsp;• **SameHostAs/SCCM_HasClient** By default, domain computers with the CmRcService SPN are assumed to be SCCM client devices<br>&nbsp;&nbsp;&nbsp;&nbsp;• **SCCM_HasNetworkAccessAccount** By default, the NAA is assumed to be an enabled account with a valid password<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_*** By default, any targeted MSSQL Server instances are assumed to be site database server<br>• **Off**: The edges above are not collected |
| **-FileSizeLimit** `<string>` | • Stop enumeration after all collected files exceed this size on disk<br> • Supports MB, GB<br> • Default: `1GB` |
| **-FileSizeUpdateInterval** `<uint>` | • Receive periodic size updates as files are being written for each server<br>• Default: `5` seconds |
| **-Version** `<switch>` | • Display version information and exit 

# SCCM Nodes Reference
## New Node Classes
### SCCM_AdminUser Node
<img width="191" height="194" alt="image" src="https://github.com/user-attachments/assets/1adc848c-3340-4c3c-920f-4fad15d5f99e" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label**: string | • Format: `<domainShortname>\<samAccountName>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `MAYYHEM\DOMAINADMIN` |
| **Object ID**: string | • Format: `<domainShortname>\<samAccountName>@<rootSiteCode>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `MAYYHEM\DOMAINADMIN@CAS` |
| **Collection Source**: List<string> | • The collection phase(s) used to populate this entity panel<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `AdminService-SMS_Admin` |
| **Admin ID**: uint | • The admin identifier in SCCM<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `16777218` |
| **Admin SID**: string | • The domain SID of the admin user<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1105` |
| **Collection IDs**: List<string> | • The collections this admin user is assigned<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `['SMS00001@CAS','SMS00004@CAS']` |
| **Admin SID**: string | • The domain SID of the admin user<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1105` |
| **Last Modified By**: string | • The admin user that last modified this admin user<br>• Format: `<domainShortname>\<samAccountName>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `MAYYHEM\DOMAINADMIN` |
| **Last Modified Date**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2025-11-26T15:52:46.24Z` |
| **Member Of**: List<string> | • The security roles this admin user is assigned<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `['SMS0001R@CAS (Full Administrator)']` |

### SCCM_ClientDevice Node
<img width="176" height="175" alt="image" src="https://github.com/user-attachments/assets/57b39743-1115-4b17-8af5-65257560a1b3" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label**: string | • Format: `<samAccountName>@<siteCode>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `dev-pc@ps1` |
| **Object ID**: string | • Format: `<smsId>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `GUID:8BCADD46-7EAD-4767-9D54-06AE64756026` |
| **Collection Source**: List<string> | |
| **AD Domain SID** | |
| **Current Management Point** | |
| **Current Management Point SID** | |
| **Distinguished Name** | |
| **DNS Hostname** | |
| **Previous SMSID** | |
| **Previous SMSID Change Date** | |
| **Site Code** | |
| **SMSID** | |

### SCCM_Collection Node
<img width="195" height="196" alt="image" src="https://github.com/user-attachments/assets/5db15cfd-c708-498c-b1f8-c727e230b7f6" />


### SCCM_SecurityRole Node
<img width="194" height="198" alt="image" src="https://github.com/user-attachments/assets/2bceaf16-0bca-4401-8fb8-0bbdeef516d4" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label** | |
| **Object ID**: string | • Format: `<roleId>@<siteCode>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1` |

### SCCM_Site Node
<img width="201" height="202" alt="image" src="https://github.com/user-attachments/assets/e50dfb9c-e213-4ecb-8da2-4087fa39f660" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label** | |
| **Object ID**: string | • Format: `<siteCode>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1` |
| **Collection Source**: List<string> | |
| **Build Number** | |
| **Display Name** | |
| **Distinguished Name** | |
| **Install Dir** | |
| **Parent Site Code** | |
| **Site Code** | |
| **Site GUID** | |
| **Site Server Domain SID** | |
| **Site Server FQDN** | |
| **Site Server Name** | |
| **Site Type** | |
| **Source Forest** | |
| **SQL Database Name** | |
| **SQL Server Domain SID** | |
| **SQL Server FQDN** | |
| **SQL Server Name** | |
| **SQL Service Port** | |
| **SQL Service Account Domain SID** | |
| **SQL Service Account Name** | |
| **Version** | |

## Updated Node Classes
### Computer
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Collection Source**: List<string> | |
| **Network Boot Server**: bool | |
| **SCCM Site System Roles**: List<string>| |
| **SCCM Has Client Remote Control SPN**: bool | |
| **** | |
| **** | |
| **** | |
| **** | |
| **** | |

### Group
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Collection Source**: List<string> | |
| **** | |
| **** | |
| **** | |
| **** | |
| **** | |

### User
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Collection Source**: List<string> | |
| **** | |
| **** | |
| **** | |
| **** | |
| **** | |
