# ConfigManBearPig

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
  - [SCCM_Site](#sccm_site-node)
- [SCCM Edges Reference](#sccm-edges-reference)
  - [Edge Classes and Properties](#edge-classes-and-properties)

# Overview
Collects BloodHound OpenGraph compatible data and creates a zip in the current directory
  - Example: `sccm-bloodhound-20251020-115610.zip`

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
