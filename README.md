# ConfigManBearPig

<img width="256" height="384" alt="ChatGPT Image Dec 22, 2025, 01_24_18 PM" src="https://github.com/user-attachments/assets/f40c4268-431d-4dbc-9134-ed6d0e7309a0" />

A PowerShell collector for adding SCCM attack paths to [BloodHound](https://github.com/SpecterOps/BloodHound) with OpenGraph by Chris Thompson at [SpecterOps](https://x.com/SpecterOps)

Please hit me up on the [BloodHound Slack](http://ghst.ly/BHSlack) (@Mayyhem), Twitter ([@_Mayyhem](https://x.com/_Mayyhem)), or open an issue if you have any questions I can help with!

# Table of Contents

- [Overview](#overview)
  - [System Requirements](#system-requirements)
  - [Minimum Permissions](#minimum-permissions)
  - [Recommended Permissions](#recommended-permissions)
  - [Usage Info](#usage-info)
- [Command Line Options](#command-line-options)
- [Limitations](#limitations)
- [Future Development](#future-development)
- [SCCM Graph Model](#sccm-graph-model)
- [SCCM Nodes Reference](#sccm-nodes-reference)
    - [SCCM_AdminUser](#sccm-adminuser-node)
    - [SCCM_ClientDevice](#sccm-clientdevice-node)
    - [SCCM_Collection](#sccm-collection-node)
    - [SCCM_SecurityRole](#sccm-securityrole-node)
    - [SCCM_Site](#sccm-site-node)
- [SCCM Edges Reference](#sccm-edges-reference)
  - [Edge Classes and Properties](#edge-classes-and-properties)
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

Collects BloodHound OpenGraph compatible SCCM data following these ordered steps:
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

# System Requirements
  - PowerShell 4.0 or higher
  - Active Directory domain context with line of sight to a domain controller
  - Various permissions based on collection methods used

# Limitations
  - You MUST include the 'MSSQL' collection method to remotely identify EPA settings on site database servers with any domain user (or 'RemoteRegistry' to collect from the registry with admin privileges on the system hosting the database).
  - SCCM hierarchies don't have their own unique identifier, so the site code for the site that data is collected from is used in the identifier for objects (e.g., SMS00001@PS1), preventing merging of objects if there are more than one hierarchy in the same graph database (e.g., both hierarchies will have the SMS00001 collection but different members), but causing duplicate objects if collecting from two sites within the same hierarchy.
  - If the same site code exists more than once in the environment (Microsoft recommends against this, so it shouldn't), the nodes and edges for those sites will be merged, causing false positives in the graph. This is not recommended within the same forest: https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/prepare-to-install-sites#bkmk_sitecodes
  - It is assumed in some cases (e.g., during DP and SMS Provider collection) that a single system does not host site system roles in more than one site. If this is the case, only one site code will be associated with that system.
  - CoerceAndRelayNTLMtoSMB collection doesn't work because post-processed AdminTo edges can't be added via OpenGraph yet, so added CoerceAndRelayToSMB edges instead
  - MSSQL collection assumes that any collection target hosting a SQL Server instance is a site database server. If there are other SQL Servers in the environment, false positives may occur.
  - I'm not a hooking expert, so if you see crashes during MSSQL collection due to the InitializeSecurityContextW hooking method that's totally vibe-coded, disable it. The hooking function doesn't work in PowerShell v7+ due to lack of support for certain APIs.

# SCCM Nodes Reference
## New Node Classes

### Host
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label**: string | • Format: `<dNSHostName>_<guid>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `ps1-pss.mayyhem.com_` |
| **Object ID**: string | • Format: `<smsId>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `GUID:8BCADD46-7EAD-4767-9D54-06AE64756026` |

### SCCM_AdminUser Node


### SCCM_ClientDevice Node
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

### SCCM_SecurityRole Node
| Property<br>______________________________________________ | Definition<br>_______________________________________________________________________________________________ |
|----------|------------|
| **Name/Label** | |
| **Object ID**: string | • Format: `<roleId>@<siteCode>`<br>• Examples:<br>&nbsp;&nbsp;&nbsp;&nbsp;• `PS1` |

### SCCM_Site Node
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
