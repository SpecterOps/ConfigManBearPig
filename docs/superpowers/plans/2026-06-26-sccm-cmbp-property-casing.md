# SCCM property names → ConfigManBearPig.ps1 casing (ticket ope-16f5)

## Why

Earlier the SCCM port emitted node/edge **output property** names in `snake_case`. That was a
mistake: BloodHound entity panels render whatever key the OpenGraph JSON carries, and operators
expect the names they know from `ConfigManBearPig.ps1` (CMBP). This reverses that decision and makes
SCCM match the rule MSSQL already settled on (D11): **use CMBP's exact property name for every
property, verbatim — inconsistent casing and all.**

CMBP is deliberately inconsistent: LDAP-derived attributes are camelCase (`dNSHostName`,
`samAccountName`, `parentSiteCode`), SCCM-specific properties are PascalCase (`SCCMSiteSystemRoles`,
`SMBSigningRequired`, `ADDomainSID`), and a few are just one-offs (`collectionIds` vs `roleIDs`). We
mirror exactly what CMBP writes.

## What sets the output name

`convert_pipeline.py` serializes each node/edge with `dataclasses.asdict()`. **The dataclass field
name in `graph.py` is the literal JSON key.** So the rename is: rename the fields on the
`*Properties` dataclasses in `graph.py`, and update the keyword args at every construction site
(`models/*.py`). The pydantic model fields that *read DuckDB columns* stay `snake_case` (they match
the dlt-loaded column names); only the `*Properties` side changes.

## Decisions (locked with user, 2026-06-26)

- **Mirror CMBP verbatim** (not normalized to one convention).
- **Framework-mandated base fields stay as-is**: `name`, `displayname`, `environmentid`, `last_seen`
  come from `openhound.core...NodeProperties` and cannot be renamed. (CMBP also sets a `displayName`
  on Admin/Site nodes — a *different* key from the base `displayname`; we keep both, mirroring CMBP.)
- **Node/edge KIND names already match CMBP** (`Computer`, `SCCM_Site`, `SCCM_HasPrimaryUser`, …) — no
  kind changes. Edge `traversable`/`composed` already match; only edge `collection_source` →
  `collectionSource`.
- **Port-added properties (no CMBP name) → CMBP neighbor style**: `possible`, `accountType`,
  `collectionID`.
- **Consistency-extensions (CMBP names the concept on *some* node types) → reuse that name**:
  `SCCMInfra`, `rootSiteCode`, `createdBy`/`createdDate`.
- **Coin-flips → the canonical AD attribute casing CMBP actually uses**: `dNSHostName` (per
  [MS-ADTS]), `samAccountName`.
- **Add 6 missing SCCM_Site props now** (siteServerFQDN, siteServerDomainSID, SQLServerFQDN,
  SQLServerDomainSID, SQLServiceAccountDomainSID, SQLServicePort) — all derivable from
  already-collected data; **no re-collection required.**

## Complete mapping (current field → CMBP output key), verified against ConfigManBearPig.ps1

### Edge — `SCCMEdgeProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:1664 |
| traversable | `traversable` (unchanged) | ps1:2252 |
| composed | `composed` (framework base, unchanged) | — |

### `ComputerProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:3084 |
| sccm_site_system_roles | `SCCMSiteSystemRoles` | ps1:3086 |
| sccm_infra | `SCCMInfra` | ps1:7015 |
| sccm_resource_ids | `SCCMResourceIDs` | ps1:7458 |
| sccm_client_device_identifier | `SCCMClientDeviceIdentifier` | ps1:7216 |
| dnshostname | `dNSHostName` | [MS-ADTS]; ps1 read-backs 3603/4405 |
| sam_account_name | `samAccountName` | ps1:961 |
| distinguished_name | `distinguishedName` | ps1:960 |
| smb_signing_required | `SMBSigningRequired` | ps1:4695 |
| sccm_has_client_remote_control_spn | `SCCMHasClientRemoteControlSPN` | ps1:3265 |
| network_boot_server | `networkBootServer` | ps1:3370 |
| disable_loopback_check | `disableLoopbackCheck` | ps1:4885 |
| restrict_receiving_ntlm_traffic | `restrictReceivingNtlmTraffic` | ps1:4888 |
| sccm_client_certificate_required | `SCCMClientCertificateRequired` | ps1:8719 |
| sccm_hosts_content_library | `SCCMHostsContentLibrary` | ps1:9233 |
| sccm_is_pxe_support_enabled | `SCCMIsPXESupportEnabled` | ps1:9235 |

### `UserProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:7456 |
| sccm_resource_ids | `SCCMResourceIDs` | ps1:7458 |
| sccm_infra | `SCCMInfra` (port-add, consistency) | — |
| stored_in_sccm_site | `storedInSCCMSite` | ps1:7136 |
| distinguished_name | `distinguishedName` | ps1:960 |
| user_principal_name | `userPrincipalName` | ps1:962 |

### `GroupProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:7466 |
| sccm_infra | `SCCMInfra` (port-add, consistency) | — |
| sccm_resource_ids | `SCCMResourceIDs` | ps1:7468 |

### `SCCMSiteProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:7044 |
| site_code | `siteCode` | ps1:7050 |
| parent_site_code | `parentSiteCode` | ps1:7048 |
| root_site_code | `rootSiteCode` | ps1:1647 |
| site_type | `siteType` | ps1:7055 |
| site_guid | `siteGUID` | ps1:7051 |
| site_server_name | `siteServerName` | ps1:7054 |
| sql_server_name | `SQLServerName` | ps1:7064 |
| sql_database_name | `SQLDatabaseName` | ps1:7061 |
| version | `version` (unchanged) | ps1:7066 |
| build_number | `buildNumber` | ps1:7045 |
| install_dir | `installDir` | ps1:7047 |
| sql_service_account_name | `SQLServiceAccountName` | ps1:7993 |
| distinguished_name | `distinguishedName` | ps1:3028 |
| source_forest | `sourceForest` | ps1:3036 |
| admin_users | `adminUsers` | ps1:1725 |
| stored_accounts | `storedAccounts` | ps1:7143 |
| sccm_infra | `SCCMInfra` | ps1:7049 |
| **NEW** | `siteServerFQDN` | ps1:7053 |
| **NEW** | `siteServerDomainSID` | ps1:7052 |
| **NEW** | `SQLServerFQDN` | ps1:7063 |
| **NEW** | `SQLServerDomainSID` | ps1:7062 |
| **NEW** | `SQLServiceAccountDomainSID` | ps1:3040 |
| **NEW** | `SQLServicePort` | ps1:7065 |

### `SCCMCollectionProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:7533 |
| sccm_collection_id | `collectionID` (port-add) | id only in CMBP |
| sccm_collection_type | `collectionType` | ps1:7534 |
| member_count | `memberCount` | ps1:7542 |
| comment | `comment` (unchanged) | ps1:7536 |
| is_built_in | `isBuiltIn` | ps1:7537 |
| limit_to_collection_id | `limitToCollectionID` | ps1:7540 |
| limit_to_collection_name | `limitToCollectionName` | ps1:7541 |
| collection_variables_count | `collectionVariablesCount` | ps1:7535 |
| root_site_code | `rootSiteCode` (port-add, consistency) | — |
| source_site_code | `sourceSiteCode` | ps1:7544 |
| last_change_time | `lastChangeTime` | ps1:7538 |
| last_member_change_time | `lastMemberChangeTime` | ps1:7539 |
| members | `members` (unchanged) | ps1:7608 |
| sccm_infra | `SCCMInfra` (port-add, consistency) | — |

### `SCCMAdminUserProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:7772 |
| sccm_admin_id | `adminID` | ps1:7773 |
| admin_sid | `adminSid` | ps1:7774 |
| distinguished_name | `distinguishedName` | ps1:7777 |
| is_group | `isGroup` | ps1:7778 |
| account_type | `accountType` (port-add) | — |
| root_site_code | `rootSiteCode` (port-add, consistency) | — |
| display_name | `displayName` | ps1:7776 |
| source_site_code | `sourceSiteCode` | ps1:7785 |
| created_by | `createdBy` (port-add, from SecurityRole) | ps1:7703 |
| created_date | `createdDate` (port-add, from SecurityRole) | ps1:7704 |
| last_modified_by | `lastModifiedBy` | ps1:7779 |
| last_modified_date | `lastModifiedDate` | ps1:7780 |
| collection_ids | `collectionIds` | ps1:7775 |
| role_ids | `roleIDs` | ps1:7783 |
| member_of | `memberOf` | ps1:7781 |
| sccm_infra | `SCCMInfra` | ps1:7784 |

### `SCCMSecurityRoleProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:7701 |
| sccm_role_id | `roleID` | ps1:7713 |
| sccm_role_name | `roleName` | ps1:7714 |
| role_description | `roleDescription` | ps1:7715 |
| is_built_in | `isBuiltIn` | ps1:7705 |
| is_sec_admin_role | `isSecAdminRole` | ps1:7706 |
| copied_from_id | `copiedFromID` | ps1:7702 |
| number_of_admins | `numberOfAdmins` | ps1:7711 |
| operations | `operations` (unchanged) | ps1:7712 |
| root_site_code | `rootSiteCode` (port-add, consistency) | — |
| site_code | `siteCode` | ps1:7716 |
| created_by | `createdBy` | ps1:7703 |
| created_date | `createdDate` | ps1:7704 |
| last_modified_by | `lastModifiedBy` | ps1:7707 |
| last_modified_date | `lastModifiedDate` | ps1:7708 |
| members | `members` (unchanged) | ps1:7709 |
| sccm_infra | `SCCMInfra` (port-add, consistency) | — |

### `SCCMClientDeviceProperties`
| current | → CMBP | source |
|---|---|---|
| collection_source | `collectionSource` | ps1:7221 |
| smsid | `SMSID` | ps1:7251 |
| sccm_resource_id | `resourceID` | ps1:7249 |
| site_code | `siteCode` | ps1:7250 |
| device_os | `deviceOS` | ps1:7235 |
| device_os_build | `deviceOSBuild` | ps1:7236 |
| is_virtual_machine | `isVirtualMachine` | ps1:7240 |
| co_managed | `coManaged` | ps1:7230 |
| aad_device_id | `AADDeviceID` | ps1:7222 |
| aad_tenant_id | `AADTenantID` | ps1:7223 |
| last_reported_mp_server_name | `lastReportedMPServerName` | ps1:7244 |
| primary_user | `primaryUser` | ps1:7247 |
| current_logon_user | `currentLogonUser` | ps1:7231 |
| ad_last_logon_user | `ADLastLogonUser` | ps1:7225 |
| root_site_code | `rootSiteCode` (port-add, consistency) | — |
| possible | `possible` (port-add) | — |
| sccm_ad_domain_sid | `ADDomainSID` | ps1:2269 |
| ad_last_logon_time | `ADLastLogonTime` | ps1:7224 |
| ad_last_logon_user_domain | `ADLastLogonUserDomain` | ps1:7226 |
| source_site_code | `sourceSiteCode` | ps1:7252 |
| last_active_time | `lastActiveTime` | ps1:7241 |
| last_online_time | `lastOnlineTime` | ps1:7243 |
| last_offline_time | `lastOfflineTime` | ps1:7242 |
| primary_user_sid | `primaryUserSID` | ps1:7248 |
| current_logon_user_sid | `currentLogonUserSID` | ps1:7232 |
| ad_last_logon_user_sid | `ADLastLogonUserSID` | ps1:7227 |
| last_reported_mp_server_sid | `lastReportedMPServerSID` | ps1:7245 |
| collection_ids | `collectionIds` | ps1:7228 |
| collection_names | `collectionNames` | ps1:7229 |
| sccm_infra | `SCCMInfra` (port-add, consistency) | — |

## New SCCM_Site properties — derivation (transforms._node_site)

All from already-collected tables; CMBP's `*DomainSID` is the full resolved computer SID, not a domain prefix.

- `SQLServerFQDN` ← `adminservice/wmi_site_definitions.sql_server_fqdn` (already collected from
  `SMS_SCI_SiteDefinition` Props "SQLServerFQDN", `privileged.py:106-111`).
- `SQLServicePort` ← `..._site_definitions.sql_service_port` (Props "SQLServicePort",
  `privileged.py:112`).
- `siteServerDomainSID` / `siteServerFQDN` ← `*_site_definitions_computers` row whose
  `sccm_site_system_roles` = `"SMS Site Server@<site>"`: `object_sid` / `dns_host_name`.
- `SQLServerDomainSID` ← `*_site_definitions_computers` row with role `"SMS SQL Server@<site>"`:
  `object_sid`.
- `SQLServiceAccountDomainSID` ← `principal_by_name[sql_service_account_name].sid`.

## Blast radius (files)

- `src/openhound_sccm/graph.py` — rename fields on all 9 `*Properties`; add 6 site fields.
- `src/openhound_sccm/models/{computer,user,group,sccm_site,sccm_collection,sccm_admin_user,
  sccm_security_role,sccm_client_device}.py` + `graph_edge.py` — update `*Properties(...)` kwargs.
  (`stub_node.py` uses base `NodeProperties` only — no change.)
- `src/openhound_sccm/transforms.py` — `_node_site` adds the 6 columns + joins.
- `tests/` — `*_test.py` model tests: flip `node.properties.<field>` accesses to new names; **invert
  the `*_properties_lowercase_keys` assertions** (they currently enforce the old rule); add new-site-
  prop coverage; `node_site_test.py` for the 6 new columns.
- `README.md` Node/Edge Reference + `ARCHITECTURE.md` property references.

## Out of scope (surfaced; not done here)

CMBP also sets ClientDevice props the port omits (`currentManagementPoint`,
`currentManagementPointSID`, `distinguishedName`, `domain`, `userName`, `userDomainName`). Not part
of this rename — file a follow-up if wanted.
