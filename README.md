# ConfigManBearPig

<img width="256" height="384" alt="ChatGPT Image Dec 22, 2025, 01_24_18 PM" src="https://github.com/user-attachments/assets/f40c4268-431d-4dbc-9134-ed6d0e7309a0" />

A PowerShell collector for adding SCCM attack paths to [BloodHound](https://github.com/SpecterOps/BloodHound) with OpenGraph by Chris Thompson at [SpecterOps](https://x.com/SpecterOps)

Check out the introductory blog post here: https://specterops.io/blog/2026/01/13/introducing-configmanbearpig-a-bloodhound-opengraph-collector-for-sccm/

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
To populate the SCCM node glyphs in BloodHound, execute `ConfigManBearPig.ps1 -OutputFormat CustomNodes` (or copy the following) and use the API Explorer page to submit the JSON to the custom-nodes endpoint.
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
| **-Help** `<switch>` | Display usage information |
| **-CollectionMethods** `<string>` | Collection methods to use (comma-separated):<br>&nbsp;&nbsp;&nbsp;&nbsp; • **All** (default): All SCCM collection methods<br>&nbsp;&nbsp;&nbsp;&nbsp; • LDAP<br>&nbsp;&nbsp;&nbsp;&nbsp; • Local<br>&nbsp;&nbsp;&nbsp;&nbsp; • DNS<br>&nbsp;&nbsp;&nbsp;&nbsp; • DHCP<br>&nbsp;&nbsp;&nbsp;&nbsp; • RemoteRegistry<br>&nbsp;&nbsp;&nbsp;&nbsp; • MSSQL<br>&nbsp;&nbsp;&nbsp;&nbsp; • AdminService<br>&nbsp;&nbsp;&nbsp;&nbsp; • WMI<br>&nbsp;&nbsp;&nbsp;&nbsp; • HTTP<br>&nbsp;&nbsp;&nbsp;&nbsp; • SMB |
| **-ComputerFile** `<string>` | Specify the path to a file containing computer targets (limits to Remote Registry, MSSQL, AdminService, HTTP, SMB) |
| **-Computers** `<string>` | List of computer targets (comma-separated) |
| **-SMSProvider** `<string>` | Specify a specific SMS Provider to collect from (limits to AdminService, WMI) |
| **-SiteCodes** `<string>` | Specify site codes to use for DNS collection (file path or comma-separated string) |
| **-OutputFormat** `<string>` | • **Zip**: OpenGraph implementation that collects data in separate files for each MSSQL server, then zips them up and deletes the originals. The zip can be uploaded to BloodHound by navigating to `Administration` > `File Ingest`<br>• **CustomNodes**: Generate JSON to POST to `custom-nodes` API endpoint<br> |
| **-TempDir** `<string>` | Specify the path to a temporary directory where .json files will be stored before being zipped<br>Default: new directory created with `[System.IO.Path]::GetTempPath()` |
| **-ZipDir** `<string>` | Specify the path to a directory where the final .zip file will be stored<br>• Default: current directory |
| **-LogFile** `<string>` | Specify the path to a log file to write script log to |
| **-MemoryThresholdPercent** `<uint>` | Maximum memory allocation limit, after which the script will exit to prevent availability issues<br>• Default: `95` |
| **-Domain** `<string>` | Specify a **domain** to use for name and SID resolution |
| **-DomainController** `<string>` | Specify a **domain controller** FQDN/IP to use for name and SID resolution |
| **-DisablePossibleEdges** (switch) | • **Off**: Collect the following edges (useful for offensive engagements but prone to false positive edges that may not be abusable):<br>&nbsp;&nbsp;&nbsp;&nbsp;• **CoerceAndRelayToMSSQL** By default, EPA setting is assumed to be Off if the MSSQL server can't be reached<br>&nbsp;&nbsp;&nbsp;&nbsp;• **SameHostAs/SCCM_HasClient** By default, domain computers with the CmRcService SPN are assumed to be SCCM client devices<br>&nbsp;&nbsp;&nbsp;&nbsp;• **SCCM_HasNetworkAccessAccount** By default, the NAA is assumed to be an enabled account with a valid password<br>&nbsp;&nbsp;&nbsp;&nbsp;• **MSSQL_*** By default, any targeted MSSQL Server instances are assumed to be site database server<br>• **Off**: The edges above are not collected |
| **-FileSizeLimit** `<string>` | Stop enumeration after all collected files exceed this size on disk<br> • Supports MB, GB<br> • Default: `1GB` |
| **-FileSizeUpdateInterval** `<uint>` | Receive periodic size updates as files are being written for each server<br>• Default: `5` seconds |
| **-EnableBadOpsec** `<switch>` | •  **Off** (default): Do not create edges that launch cmd.exe/powershell.exe or access SYSTEM DPAPI keys on the system where ConfigManBearPig is executed (e.g., to dump and decrypt the NAA username)<br> • On: Create the edges above (WILL be detected by EDR/AV solutions) |
| **-ShowCleartextPasswords** `<switch>` | •  **Off** (default): Do not decrypt or display cleartext passwords<br> • On: Display cleartext passwords when they are discovered |
| **-Help** `<switch>` | Display usage information |
| **-Version** `<switch>` | Display version information and exit 

# Future Development
- Edge entity panels with abuse info
- altauth to allow collection when client cert is required
- Get members of groups with permissions on System Management container
- Parse task sequences and collection variables for usernames and passwords during Local collection
- Automatic client push installation detection (ELEVATE-2)
- Identify site database service account via RemoteRegistry + SPNs
- Relay management point computer accounts to site databases
- Secondary site databases
- Group and user collection members
- DHCP Collection (requires unauthenticated network access)
- WMI Collection (requires an SCCM admin account)
- CMPivot Collection (requires an SCCM admin account)

# SCCM Nodes Reference
## New Node Classes
### SCCM_AdminUser Node
<img width="191" height="194" alt="image" src="https://github.com/user-attachments/assets/1adc848c-3340-4c3c-920f-4fad15d5f99e" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label**: string | • Format: `<domainShortname>\<samAccountName>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `MAYYHEM\DOMAINADMIN` |
| **Object ID**: string | • Format: `<domainShortname>\<samAccountName>@<rootSiteCode>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `MAYYHEM\DOMAINADMIN@CAS` |
| **Collection Source**: List\<string\> | • The collection phase(s) used to populate this entity panel<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `AdminService-SMS_Admin` |
| **Admin ID**: uint | • The admin identifier in SCCM<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `16777218` |
| **Admin SID**: string | • The domain SID of the admin user<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1105` |
| **Collection IDs**: List\<string\> | • The collections this admin user is assigned<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `['SMS00001@CAS','SMS00004@CAS']` |
| **Admin SID**: string | • The domain SID of the admin user<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1105` |
| **Last Modified By**: string | • The admin user that last modified this admin user<br>• Format: `<domainShortname>\<samAccountName>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `MAYYHEM\DOMAINADMIN` |
| **Last Modified Date**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2025-11-26T15:52:46.24Z` |
| **Member Of**: List\<string\> | • The security roles this admin user is assigned<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `['SMS0001R@CAS (Full Administrator)']` |

### SCCM_ClientDevice Node
<img width="176" height="175" alt="image" src="https://github.com/user-attachments/assets/57b39743-1115-4b17-8af5-65257560a1b3" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label**: string | • Format: `<samAccountName>@<siteCode>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `ps1-dev@ps1` |
| **Object ID**: string | • Format: `<smsId>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `GUID:8BCADD46-7EAD-4767-9D54-06AE64756026` |\
| **Collection Source**: List\<string\> | • The collection phase(s) used to populate this entity panel<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `AdminService-SMS_Admin` |
| **AAD Device ID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `20ac5936-4b2f-46a7-8b70-db08ef1f99cd` |
| **AAD Tenant ID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `6c12b0b0-b2cc-4a73-8252-0b94bfca2145` |
| **AD Domain SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1119` |
| **AD Last Logon Time**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2026-01-09T02:37:28Z` |
| **AD Last Logon User**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `domainuser` |
| **AD Last Logon User Domain**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `mayyhem` |
| **AD Last Logon User SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1104` |
| **CN**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1-DEV` |
| **Collection IDs**: List\<string\> | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `['SMS00001@PS1','SMS000KM@PS1']` |
| **CoManaged**: bool | true/false |
| **Current Logon User**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `mayyhem\domainuser` |
| **Current Logon User SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1104` |
| **Current Management Point**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `ps1-mp.mayyhem.com` |
| **Current Management Point SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1118` |
| **Device OS**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `Microsoft Windows NT Workstation 10.0 (Tablet Edition)` |
| **Device OS Build**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `10.0.22621.525` |
| **Distinguished Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `CN=PS1-DEV,OU=Workstations,DC=mayyhem,DC=com` |
| **DNS Hostname**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `ps1-dev.mayyhem.com` |
| **Domain**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `10.0.22621.525` |
| **Is Virtual Machine**: bool | true/false |
| **Last Active Time**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2026-01-13T23:14:34Z` |
| **Last Offline Time**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2025-12-09T09:02:06.13Z` |
| **Last Online Time**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2026-01-13T22:50:28.293Z` |
| **Last Reported MP Server Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1-MP.MAYYHEM.COM` |
| **Last Reported MP Server SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1118` |
| **Previous SMSID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `GUID:6C25F505-E982-4A0D-8C6E-BFC74992D581` |
| **Previous SMSID Change Date**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `11/26/2025 19:32:13` |
| **Primary User**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `mayyhem\domainuser` |
| **Primary User SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1104` |
| **Resource ID**: uint | • Format: `<resourceId>@<siteCode>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `16777231@PS1` |
| **Site Code**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1` |
| **SMSID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `GUID:8BCADD46-7EAD-4767-9D54-06AE64756026` |
| **Source Site Code**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1` |
| **User Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `domainuser` |
| **User Domain Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `mayyhem` |


### SCCM_Collection Node
<img width="195" height="196" alt="image" src="https://github.com/user-attachments/assets/5db15cfd-c708-498c-b1f8-c727e230b7f6" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label**: string | • Format: `<collectionId>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `SMS00001` |
| **Object ID**: string | • Format: `<collectionId>@<siteCode>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `SMS00001@PS1` |
| **Collection Source**: List\<string\> | • The collection phase(s) used to populate this entity panel<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `AdminService-SMS_Admin` |
| **Collection Type**: uint | • 1: User Collection<br>• 2: Device Collection |
| **Collection Variables Count**: uint | Number of collection variables for this collection |
| **Comment**: string | Admin-provided comment or description |
| **Is Built In**: bool | Does the collection ship with SCCM or was it added by the organization? |
| **Last Change Time**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2026-01-13T23:14:34Z` |
| **Last Member Change Time**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2026-01-13T23:14:34Z` |
| **Member Count**: uint | Number of members in this collection |
| **Members**: List\<string\> | • Format: `<resourceId>@<siteCode>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `['16777226@PS1','16777219@PS1']` |
| **Source Site Code**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1` |


### SCCM_SecurityRole Node
<img width="194" height="198" alt="image" src="https://github.com/user-attachments/assets/2bceaf16-0bca-4401-8fb8-0bbdeef516d4" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label**: string | • Format: `<roleId>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `SMS0001R` |
| **Object ID**: string | • Format: `<roleId>@<siteCode>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `SMS0001R@PS1` |
| **Collection Source**: List\<string\> | • The collection phase(s) used to populate this entity panel<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `AdminService-SMS_Admin` |
| **Created By**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `mayyhem\domainadmin` |
| **Created Date**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2026-01-13T23:14:34Z` |
| **Is Built In**: bool | Does the security role ship with SCCM or was it added by the organization? |
| **Is Sec Admin Role**: bool | Does the security role allow assignment of any security role to users? |
| **Last Modified By**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `mayyhem\domainadmin` |
| **Last Modified Date**: datetime | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `2026-01-13T23:14:34Z` |
| **Members**: List\<string\> | • Format: `<name>@<rootSiteCode>`<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `['mayyhem\domainuser@PS1','mayyhem\domainadmin@PS1']` |
| **Number of Admins**: uint | Number of admins assigned this role |
| **Role Description**: string | Admin-provided comment or description |
| **Role ID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `SMS0001R` |
| **Role Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `Full Administrator` |
| **Site Code**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `CAS` |


### SCCM_Site Node
<img width="201" height="202" alt="image" src="https://github.com/user-attachments/assets/e50dfb9c-e213-4ecb-8da2-4087fa39f660" />

| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label** | |
| **Object ID**: string | • Format: `<siteCode>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1` |
| **Collection Source**: List\<string\> | • The collection phase(s) used to populate this entity panel<br>• Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `AdminService-SMS_Admin` |
| **Build Number**: uint | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `9106` |
| **Display Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `Primary Site One` |
| **Distinguished Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `CN=SMS-Site-PS1,CN=System Management,CN=System,DC=mayyhem,DC=com` |
| **Install Dir**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `C:\Program Files\Microsoft Configuration Manager` |
| **Parent Site Code**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `CAS` |
| **Root Site Code**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `CAS` |
| **Site Code**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1` |
| **Site GUID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `{5BBD28B5-EF88-44EB-BCC8-725ED8DA08C8}` |
| **Site Server Domain SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1112` |
| **Site Server FQDN**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `ps1-pss.mayyhem.com` |
| **Site Server Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `ps1-pss.mayyhem.com` |
| **Site System Roles**: List\<string\> | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `[ps1-mp.mayyhem.com: SMS Management Point@PS1, ps1-dp.mayyhem.com: SMS Distribution Point@PS1]` |
| **Site Type**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `Primary Site` |
| **Source Forest**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `mayyhem.com` |
| **SQL Database Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `CM_PS1` |
| **SQL Server Domain SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1109` |
| **SQL Server FQDN**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `ps1-db.mayyhem.com` |
| **SQL Server Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `ps1-db.mayyhem.com` |
| **SQL Service Port**: uint | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `1433` |
| **SQL Service Account Domain SID**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `S-1-5-21-3242052782-1287495003-4091326449-1116` |
| **SQL Service Account Name**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `sqlsccmsvc` |
| **Stored Accounts**: List\<string\> | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `[networkaccess (S-1-5-21-3242052782-1287495003-4091326449-1120), sccm_push (S-1-5-21-3242052782-1287495003-4091326449-1121)]` |
| **Version**: string | • Example:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `5.00.9106.1000` |

# SCCM Edges Reference
### LocalAdminRequired
This edge is drawn from SCCM site server `Computer` nodes to `Computer` nodes hosting site system roles in the same site because the site server's domain computer account MUST be in the local Administrators group on these systems.

This edge has no unique properties.

### CoerceAndRelayToAdminService
This edge is drawn from the `Authenticated Users` group to `SCCM_Site` nodes that have an SMS Provider that is remote from a site server.

The `Coercion Victim and Relay Target Pairs` property specifies site servers that can be coerced and remote SMS Providers that can be relayed to in order to conduct the TAKEOVER-5 attack technique.

### CoerceAndRelayToMSSQL
This edge is drawn from the `Authenticated Users` group to `MSSQL_Login` nodes that belong to an SCCM site server that is hosted remotely from the site database when the site database MSSQL server does NOT have EPA set to Required/Allowed.

The `Coercion Victim and Relay Target Pairs` property specifies site servers that can be coerced and remote site database servers that can be relayed to in order to conduct the TAKEOVER-1 attack technique.

### CoerceAndRelaytoSMB
This edge is drawn from the `Authenticated Users` group to `Computer` nodes that belong to an SCCM site database or SMS Provider that is hosted remotely from the site server when the system does NOT have SMB signing set to Required.

The `Coercion Victim Hostnames` property specifies site servers that can be coerced and remote site database and SMS Provider servers that can be relayed to in order to conduct the TAKEOVER-2, TAKEOVER-6, and TAKEOVER-7 attack techniques.

### SameHostAs
This edge is drawn between `Computer` and `SCCM_ClientDevice` nodes that represent the same machine.

This edge has no unique properties.

### SCCM_AdminsReplicatedTo
This edge is drawn between primary sites in the same hierarchy in both directions because global data, including administrative users and security roles, are replicated throughout the hierarchy. Own one site, own them all. It is also drawn from primary sites to their child secondary sites, but only in that direction.

This edge has no unique properties.

### SCCM_AllPermissions
This edge is drawn from `SCCM_AdminUser` nodes that are assigned the `All Systems` and `All Users and User Groups` collections and the `Full Administrator` security role to all `SCCM_Site` nodes in that hierarchy.

This edge has no unique properties.

### SCCM_ApplicationAdministrator
This edge is drawn from `SCCM_AdminUser` nodes that are assigned the `Application Administrator` security role and any device collection containing the target `SCCM_ClientDevice` node.

This edge has no unique properties.

### SCCM_AssignAllPermissions
This edge is drawn in two places. 

First, it is drawn from the site database `MSSQL_Database` node to the `SCCM_Site` node for the site it controls.

Second, it is drawn from the `Computer` node to the `SCCM_Site` node for each site system role that allows an attacker to compromise the hierarchy by adding an administrative user role assignment, including SMS Providers and site database servers.

This edge has no unique properties.

### SCCM_Contains
This edge is drawn from `SCCM_Site` nodes to `SCCM_AdminUser`, `SCCM_Collection`, and `SCCM_SecurityRole` nodes in the same hierarchy.

This edge has no unique properties.

### SCCM_FullAdministrator
This edge is drawn from `SCCM_AdminUser` nodes that are assigned the `Full Administrator` security role and any device collection containing the target `SCCM_ClientDevice` node.

This edge has no unique properties.

### SCCM_HasADLastLogonUser
This edge is drawn from an `SCCM_ClientDevice` node to the `User` node representing the principal who was last to log into the device according to Active Directory the last time SCCM ran Active Directory discovery.

This edge has no unique properties.

### SCCM_HasClient
This edge is drawn from an `SCCM_Site` node to ALL `SCCM_ClientDevice` nodes that are members of that primary site.

This edge has no unique properties.

### SCCM_HasCurrentUser
This edge is drawn from an `SCCM_ClientDevice` node to the `User` node representing the principal who is currently logged in according to the fast notification service that connects client devices to their management point.

This edge has no unique properties.

### SCCM_HasMember
This edge is drawn from an `SCCM_Collection` to the `SCCM_ClientDevice` nodes it contains.

This edge has no unique properties.

### SCCM_HasNetworkAccessAccount
This edge is drawn from a `Computer` node to each `User` node representing a network access account that has saved credentials on the host.

This edge has no unique properties.

### SCCM_HasPrimaryUser
This edge is drawn from an `SCCM_ClientDevice` node to the `User` node representing the principal who is the primary user according to user device affinity relationships in SCCM, which may be manually assigned by an SCCM administrator or automatically assigned when a user is logged on for >40 hours in a month.

This edge has no unique properties.

### SCCM_HasStoredAccount
This edge is drawn from an `SCCM_Site` node to each `User` node representing a credential saved in SCCM.

This edge has no unique properties.

### SCCM_IsAssigned
This edge is drawn from an `SCCM_AdminUser` node to the `SCCM_Collection` and `SCCM_SecurityRole` nodes it is assigned.

This edge has no unique properties.

### SCCM_IsMappedTo
This edge is drawn from an AD principal (i.e., a `Base` node) to the `SCCM_AdminUser` node it corresponds to in SCCM.

This edge has no unique properties.
