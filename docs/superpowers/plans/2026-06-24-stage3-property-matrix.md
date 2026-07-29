# Stage-3 (ope-1950) Node Property Parity Matrix

**Authority:** This is the authoritative gap checklist for Stage-3 (WS-3) per-kind property parity tasks C1–C6.
Each deferred entry is explained in the "Deferral ledger" section at the bottom.

**Verification method:** Each port-now source column was verified directly against the collector column
tuples in `src/openhound_sccm/collectors/sms_rows.py` and the LDAP/SMB/registry collector source files.
The lab spot-check against a live `lookup.duckdb` is **deferred to Phase D** (the user runs it); the
collector tuples are the ground truth for what columns are emitted. Note: dlt drops all-NULL columns at
load, but `_ensure_columns` pre-creates optional columns in every `_node_*` coalesce so binder errors
are already handled.

**Column notation:** `TABLE.column` means the snake_cased name after `_row()` processes the raw API/WMI
object. `TUPLE.Field` means the PascalCase API field name in the named tuple constant.

---

## Computer (`node_computer`)

| CMBP property | port snake_case | classification | source column or reason |
|---|---|---|---|
| `DNSHostName` | `dnshostname` | PORT-NOW | `RSYSTEM_COLUMNS.Name` → `adminservice_r_system.name`; LDAP `ad_client.dns_host_name` via `smb_computers`, `ldap_cmrc_devices`, `ldap_network_boot_servers` (all emit `dns_host_name`) |
| `SamAccountName` | `sam_account_name` | PORT-NOW | `ldap_cmrc_devices.sam_account_name` (LDAP `samAccountName` mapped in `_ATTR_KEY_MAP`); `http_management_points.sam_account_name`; `http_distribution_points.sam_account_name`; `http_smsproviders.sam_account_name` |
| `IsPXEServer` | `sccm_is_pxe_support_enabled` | PORT-NOW | `smb_computers.sccm_is_pxe_support_enabled` (set in `smb.py` via `REMINST` share detection, already in `node_computer`) |
| `PXEVendorClass` | `pxe_vendor_class` | DEFER-NO-COLLECTOR | No DHCP/PXE collector; blocked on gtk `Ope-o6bh` / `Ope-gqwo` |
| `PXENextServer` | `pxe_next_server` | DEFER-NO-COLLECTOR | Same; blocked on gtk `Ope-o6bh` / `Ope-gqwo` |
| `PXEBootFile` | `pxe_boot_file` | DEFER-NO-COLLECTOR | Same; blocked on gtk `Ope-o6bh` / `Ope-gqwo` |
| `TFTPReachable` | `tftp_reachable` | DEFER-NO-COLLECTOR | Same; blocked on gtk `Ope-o6bh` / `Ope-gqwo` |
| `IsDHCPServer` | `is_dhcp_server` | DEFER-NO-COLLECTOR | No DHCP collector; blocked on gtk `Ope-o6bh` / `Ope-gqwo` |

**C0-verify resolution — Computer `distinguished_name`:** The AD client always emits `distinguished_name`
(from `entry.entry_dn`, `ad.py:904`) for every LDAP search result, so `ldap_cmrc_devices.distinguished_name`
is present in the raw table. However the `_node_computer` transform does **not** select it — the staging
table has no such column. This is a gap to fix in C1 (add column + select from `ldap_cmrc_devices` and
`smb_computers` which spread `**ad_object`). Classification: DEFER-NO-COLLECTOR is inaccurate here —
the data exists but the transform drops it. **Reclassified as PORT-NOW** (data available, needs WS-3 C1 wiring).

| `DistinguishedName` | `distinguished_name` | PORT-NOW | `smb_computers.distinguished_name` (primary) / `remoteregistry_computers` / `adminservice_site_definitions_computers` (all spread `**ad_object` into raw rows; present in raw tables; C1 must add column to `node_computer` staging + select it) |

**Computer port-now count: 3** (`dnshostname`, `sam_account_name`, `distinguished_name`)
**Computer deferred count: 5** (all DHCP/PXE — no collector)

---

## User (`node_user`)

| CMBP property | port snake_case | classification | source column or reason |
|---|---|---|---|
| `DistinguishedName` | `distinguished_name` | PORT-NOW | `RUSER_COLUMNS.DistinguishedName` → `adminservice_r_user.distinguished_name` (snake-cased by `_row()`; confirmed present in tuple) |
| `UserPrincipalName` | `user_principal_name` | PORT-NOW | `RUSER_COLUMNS.UserPrincipalName` → `adminservice_r_user.user_principal_name` |
| `IsNetworkAccessAccount` | `is_sccm_network_access_account` | DEFER-NO-COLLECTOR | No NAA collector; `SCCM_HasNetworkAccessAccount` edge was Stage-2-deferred; blocked pending NAA collector |

**C0-verify resolution — User `distinguished_name`/`user_principal_name`:** Both are in `RUSER_COLUMNS`
(`DistinguishedName`, `UserPrincipalName`). The `_node_user` staging table currently does **not** select
these columns — `_node_user` only selects `sid` and `name` from `adminservice_r_user`. The data is
collected; WS-3 C2 must add these columns to the `node_user` staging table and the collapsing SELECT.

**User port-now count: 2** (`distinguished_name`, `user_principal_name`)
**User deferred count: 1** (`is_sccm_network_access_account` — no NAA collector)

---

## Group (`node_group`)

| CMBP property | port snake_case | classification | source column or reason |
|---|---|---|---|
| `DistinguishedName` | `distinguished_name` | DEFER-NO-COLLECTOR | No LDAP group collector; `node_group` is built from `security_group_name` lists (name-only, resolved to SID via `principal_by_name`). The `adminservice_user_group` / `wmi_user_group` rows (`USERGROUP_COLUMNS`) carry only `ResourceId`, `SID`, `UniqueUsergroupName`, `UsergroupName` — no DN. `admins` rows (is_group=True) carry `DistinguishedName` via `ADMIN_COLUMNS`, but that is the admin account's DN, not the group's. A true group DN would require a live LDAP lookup by SID/name — uncollected. |
| `SamAccountName` | `sam_account_name` | DEFER-NO-COLLECTOR | Same — not in `USERGROUP_COLUMNS`; no group DN/SAM LDAP collector. The `UsergroupName` field is the bare group name (not the `DOMAIN\name` form that is in `UniqueUsergroupName`); still not a true `sAMAccountName`. |

**C0-verify resolution — Group `distinguished_name`/`sam_account_name`:** Neither `USERGROUP_COLUMNS`
nor any currently-active group source emits a DN or SAM account name for AD groups. The brief's
suggestion "optionally expose if C0 finds a source" resolves to: **no source exists — both remain
deferred**. The `ADMIN_COLUMNS.DistinguishedName` is the admin *user/group account*'s DN, which is
already handled under SCCM_AdminUser.

**Group port-now count: 0**
**Group deferred count: 2** (`distinguished_name`, `sam_account_name` — no group LDAP collector)

---

## SCCM_Collection (`node_collection`)

| CMBP property | port snake_case | classification | source column or reason |
|---|---|---|---|
| `SourceSite` | `source_site_code` | PORT-NOW | `_row()` always injects `source_site_code` (the `site_code` parameter passed to `_row()` in `sms_rows.py:47`); present in every adminservice/wmi row. Note: `COLLECTION_COLUMNS` does not include a `SourceSite` API field — `source_site_code` is the injected metadata column, not an API field. Correct. |
| `LastChangeTime` | `last_change_time` | PORT-NOW | `COLLECTION_COLUMNS.LastChangeTime` → `adminservice_collections.last_change_time` |
| `LastMemberChangeTime` | `last_member_change_time` | PORT-NOW | `COLLECTION_COLUMNS.LastMemberChangeTime` → `adminservice_collections.last_member_change_time` |
| `members` (relationship list) | `members` | PORT-NOW | `adminservice_collection_members` / `wmi_collection_members` via `COLLECTION_MEMBER_COLUMNS`; raw `CollectionID + ResourceID` keys |

**Collection port-now count: 4** (`source_site_code`, `last_change_time`, `last_member_change_time`, `members`)
**Collection deferred count: 0**

---

## SCCM_SecurityRole (`node_security_role`)

| CMBP property | port snake_case | classification | source column or reason |
|---|---|---|---|
| `SourceSite` | `source_site` | PORT-NOW | `ROLE_COLUMNS.SourceSite` → `adminservice_security_roles.source_site` |
| `CreatedBy` | `created_by` | PORT-NOW | `ROLE_COLUMNS.CreatedBy` → `adminservice_security_roles.created_by` |
| `CreatedDate` | `created_date` | PORT-NOW | `ROLE_COLUMNS.CreatedDate` → `adminservice_security_roles.created_date` |
| `LastModifiedBy` | `last_modified_by` | PORT-NOW | `ROLE_COLUMNS.LastModifiedBy` → `adminservice_security_roles.last_modified_by` |
| `LastModifiedDate` | `last_modified_date` | PORT-NOW | `ROLE_COLUMNS.LastModifiedDate` → `adminservice_security_roles.last_modified_date` |
| `members` (relationship list) | `members` | PORT-NOW | derived from `graph_edges` `SCCM_IsMappedTo` edges (admin→role) already built in Stage 2 |

**SecurityRole port-now count: 6** (`source_site`, `created_by`, `created_date`, `last_modified_by`, `last_modified_date`, `members`)
**SecurityRole deferred count: 0**

---

## SCCM_AdminUser (`node_admin_user`)

| CMBP property | port snake_case | classification | source column or reason |
|---|---|---|---|
| `DisplayName` | `display_name` | PORT-NOW | `ADMIN_COLUMNS.DisplayName` → `adminservice_admins.display_name`; already in `node_admin_user` staging (transforms.py:1214) |
| `SourceSite` | `source_site_code` | PORT-NOW | `ADMIN_COLUMNS.SourceSite` → `adminservice_admins.source_site`; `_row()` also injects `source_site_code` metadata |
| `CreatedBy` | `created_by` | PORT-NOW | `ADMIN_COLUMNS.CreatedBy` → `adminservice_admins.created_by` |
| `CreatedDate` | `created_date` | PORT-NOW | `ADMIN_COLUMNS.CreatedDate` → `adminservice_admins.created_date` |
| `LastModifiedBy` | `last_modified_by` | PORT-NOW | `ADMIN_COLUMNS.LastModifiedBy` → `adminservice_admins.last_modified_by` |
| `LastModifiedDate` | `last_modified_date` | PORT-NOW | `ADMIN_COLUMNS.LastModifiedDate` → `adminservice_admins.last_modified_date` |
| `collection_ids` (relationship list) | `collection_ids` | PORT-NOW | `ADMIN_COLUMNS.CollectionNames` → resolved via `collection_by_name`; raw names from `adminservice_admins.collection_names` |
| `role_ids` (relationship list) | `role_ids` | PORT-NOW | `ADMIN_COLUMNS.RoleNames` → resolved via `role_by_name`; raw names from `adminservice_admins.role_names` |
| `member_of` (relationship list) | `member_of` | PORT-NOW | derived from `graph_edges` `SCCM_IsAssigned` edges (admin→collection) already built in Stage 2 |

**AdminUser port-now count: 9** (`display_name`, `source_site_code`, `created_by`, `created_date`, `last_modified_by`, `last_modified_date`, `collection_ids`, `role_ids`, `member_of`)
**AdminUser deferred count: 0**

---

## SCCM_ClientDevice (`node_client_device`)

| CMBP property | port snake_case | classification | source column or reason |
|---|---|---|---|
| `ADLastLogonTime` | `ad_last_logon_time` | PORT-NOW | `DEVICE_COLUMNS.ADLastLogonTime` → `adminservice_client_devices.a_d_last_logon_time` (dlt snake-case of `ADLastLogonTime`; note the dlt camelCase gotcha — collector fixes this) |
| `UserDomainName` | `ad_last_logon_user_domain` | PORT-NOW | `DEVICE_COLUMNS.UserDomainName` → `adminservice_client_devices.user_domain_name` |
| `SiteCode` | `source_site_code` | PORT-NOW | `_row()` injects `source_site_code`; also `DEVICE_COLUMNS` does not have a `SiteCode` field, but `source_site_code` is the metadata column |
| `PrimaryUser` (SID) | `primary_user_sid` | PORT-NOW | `DEVICE_COLUMNS.PrimaryUser` → resolved at preproc via `principal_by_name`; `adminservice_client_devices.primary_user` |
| `CurrentLogonUser` (SID) | `current_logon_user_sid` | PORT-NOW | `DEVICE_COLUMNS.CurrentLogonUser` → resolved via `principal_by_name`; `adminservice_client_devices.current_logon_user` |
| `UserName` (AD last logon, SID) | `ad_last_logon_user_sid` | PORT-NOW | `DEVICE_COLUMNS.UserName` → resolved via `principal_by_name`; `adminservice_client_devices.user_name` |
| `LastMPServerName` (SID) | `last_reported_mp_server_sid` | PORT-NOW | `DEVICE_COLUMNS.LastMPServerName` → resolved via `principal_by_name`; `adminservice_client_devices.last_mp_server_name` (already in `node_client_device` as `last_mp_server_name`) |
| `collection_ids` (relationship list) | `collection_ids` | PORT-NOW | from `adminservice_collection_members` / `wmi_collection_members` via `COLLECTION_MEMBER_COLUMNS.ResourceID` join |
| `collection_names` (relationship list) | `collection_names` | PORT-NOW | from `adminservice_collection_members` joined with `adminservice_collections.name` |
| `CurrentManagementPoint` | `current_management_point` | DEFER-NO-COLLECTOR | `DEVICE_COLUMNS` does not include `CurrentManagementPoint` (not in the tuple); uncollected |
| `DistinguishedName` | `distinguished_name` | DEFER-NO-COLLECTOR | Not in `DEVICE_COLUMNS`; no client device → AD DN collector |
| `DNSHostName` | `dnshostname` | DEFER-NO-COLLECTOR | Not in `DEVICE_COLUMNS`; already on the Computer node (same host, different node kind). Could be added via `RSYSTEM_COLUMNS` join on `SMSUniqueIdentifier` — but that is a cross-table join not currently in the node_client_device coalesce. Deferred. |
| `Domain` | `domain` | DEFER-NO-COLLECTOR | Not in `DEVICE_COLUMNS`; no domain field on client device rows |
| `PreviousSMSID` | `previous_smsid` | DEFER-NO-COLLECTOR | Not in `DEVICE_COLUMNS` |
| `LastActiveTime` | `last_active_time` | DEFER-NO-COLLECTOR | `DEVICE_COLUMNS.LastActiveTime` exists → `adminservice_client_devices.last_active_time`. **Reclassified: PORT-NOW** (it is in `DEVICE_COLUMNS`). |
| `CNLastOnlineTime` | `last_online_time` | DEFER-NO-COLLECTOR | `DEVICE_COLUMNS.CNLastOnlineTime` exists → `adminservice_client_devices.c_n_last_online_time`. **Reclassified: PORT-NOW** (in `DEVICE_COLUMNS`; dlt snake-casing handled by collector). |
| `CNLastOfflineTime` | `last_offline_time` | DEFER-NO-COLLECTOR | `DEVICE_COLUMNS.CNLastOfflineTime` exists → `adminservice_client_devices.c_n_last_offline_time`. **Reclassified: PORT-NOW** (in `DEVICE_COLUMNS`). |

**Reclassifications from brief's deferred list:**
- `last_active_time` → **PORT-NOW**: `DEVICE_COLUMNS.LastActiveTime` is in the tuple.
- `last_online_time` → **PORT-NOW**: `DEVICE_COLUMNS.CNLastOnlineTime` is in the tuple.
- `last_offline_time` → **PORT-NOW**: `DEVICE_COLUMNS.CNLastOfflineTime` is in the tuple.

**ClientDevice port-now count: 12** (`ad_last_logon_time`, `ad_last_logon_user_domain`, `source_site_code`, `primary_user_sid`, `current_logon_user_sid`, `ad_last_logon_user_sid`, `last_reported_mp_server_sid`, `collection_ids`, `collection_names`, `last_active_time`, `last_online_time`, `last_offline_time`)
**ClientDevice deferred count: 5** (`current_management_point`, `distinguished_name`, `dnshostname`, `domain`, `previous_smsid` — not in `DEVICE_COLUMNS`)

---

## SCCM_Site (`node_site`)

| CMBP property | port snake_case | classification | source column or reason |
|---|---|---|---|
| `SQLServiceAccountName` | `sql_service_account_name` | PORT-NOW | `SMS_SCI_SysResUse` Props `"SQL Server Service Logon Account"` extracted in `privileged.py:225` as `extra_fn` → `site_systems.sql_server_service_logon_account` (via `SYSRES_COLUMNS` + `extra_fn`); used in `_edge_sql_admin` transform |
| `DisplayName` | `display_name` | DEFER-NO-COLLECTOR | `mSSMSSite` LDAP object does not carry a `displayName` attribute; `_SITE_ATTRS` in `ldap.py:117` does not include it; `SITE_COLUMNS` (`SMS_Site`) does not include it either. The `SiteName` field is the equivalent (`site_name` in `node_site`). `display_name` as a distinct property does not exist in any site source. **Reclassified: DEFER-NO-COLLECTOR** — no source emits a `display_name` distinct from `site_name`. |
| `DistinguishedName` | `distinguished_name` | PORT-NOW | `ldap_sites.distinguished_name` — `ldap.py:174` yields `"distinguished_name": entry.get("distinguished_name")` from the `mSSMSSite` LDAP object. However the `_node_site` staging table and all its INSERTs do **not** currently select `distinguished_name` — the `ldap_sites` INSERT (`transforms.py:1017-1023`) does not include it. **Data available, transform gap**: add to `node_site` staging + collapsing SELECT in C5. |
| `SourceForest` | `source_forest` | PORT-NOW | `ldap_sites.source_forest` — `ldap.py:179` yields `"source_forest": entry.get("mSSMSSourceForest")` from `_SITE_ATTRS`. Same gap: `node_site` INSERT does not currently select `source_forest`. Add to `node_site` staging + SELECT in C5. |
| `admin_users` (relationship list) | `admin_users` | PORT-NOW | from `adminservice_admins` / `wmi_admins` rows (raw `logon_name` list); no cross-table edge needed |
| `stored_accounts` (relationship list) | `stored_accounts` | PORT-NOW | from `adminservice_reserved_accounts` / `wmi_reserved_accounts` (raw name/SID list) |
| `SiteServerDomainSID` | `site_server_domain_sid` | DEFER-STAGE5 | MSSQL-coupled; Stage 5 |
| `SiteServerFQDN` | `site_server_fqdn` | DEFER-STAGE5 | MSSQL-coupled; Stage 5 |
| `SQLServerDomainSID` | `sql_server_domain_sid` | DEFER-STAGE5 | MSSQL-coupled; Stage 5 |
| `SQLServerFQDN` | `sql_server_fqdn` | DEFER-STAGE5 | DEFER-STAGE5 | MSSQL-coupled; Stage 5 |
| `SQLServicePort` | `sql_service_port` | DEFER-STAGE5 | MSSQL-coupled; Stage 5 |
| `SQLServiceAccountDomainSID` | `sql_service_account_domain_sid` | DEFER-STAGE5 | MSSQL-coupled; Stage 5 |
| `ClientCertificateRequired` | `client_certificate_required` | DEFER-ON-COMPUTER | Already on the Computer node (`sccm_client_certificate_required` via `http_management_points.client_cert_required`); deferred here as redundant per brief |

**C0-verify resolution — Site `display_name`:** No LDAP, AdminService, or WMI site source emits a
`display_name` distinct from `site_name`. The `mSSMSSite` AD object does not have a `displayName`
attribute (it uses `name`). The field `display_name` does not exist as a separate property in any
site source. **Moved to DEFER-NO-COLLECTOR.**

**C0-verify resolution — Site `distinguished_name` / `source_forest`:** Both are collected by
`ldap_sites` (confirmed in `ldap.py:174,179` and `_SITE_ATTRS:121,123`). The transform does not yet
select them — they must be added to the `node_site` staging table and collapsing SELECT in C5.
**Classification: PORT-NOW** (data present, transform gap).

**Site port-now count: 5** (`sql_service_account_name`, `distinguished_name`, `source_forest`, `admin_users`, `stored_accounts`)
**Site deferred count: 7** (`display_name` DEFER-NO-COLLECTOR; 5x DEFER-STAGE5; `client_certificate_required` DEFER-ON-COMPUTER)

---

# Deferral Ledger

## DEFER-NO-COLLECTOR — DHCP/PXE fields (Computer)

Fields: `pxe_vendor_class`, `pxe_next_server`, `pxe_boot_file`, `tftp_reachable`, `is_dhcp_server`

No DHCP or PXE-detail collector exists. Blocked on gtk tickets `Ope-o6bh` (DHCP) and `Ope-gqwo` (PXE).
The collector detects *whether* a host is PXE-enabled via the `REMINST` SMB share, but cannot obtain
the DHCP/PXE configuration parameters without a DHCP/PXE-specific collector.

## DEFER-NO-COLLECTOR — NAA field (User)

Field: `is_sccm_network_access_account`

No Network Access Account (NAA) collector. The edge `SCCM_HasNetworkAccessAccount` was deferred in
Stage 2 pending a NAA collector implementation. Until that collector exists and emits user SIDs
for NAA accounts, this flag cannot be set.

## DEFER-NO-COLLECTOR — Group DN/SAM (Group)

Fields: `distinguished_name`, `sam_account_name`

Groups are built from `security_group_name` lists (name-only) resolved to SIDs via `principal_by_name`.
The `USERGROUP_COLUMNS` tuple carries only `ResourceId`, `SID`, `UniqueUsergroupName`, `UsergroupName`
— no DN or `sAMAccountName`. The `ADMIN_COLUMNS.DistinguishedName` is the admin account's DN, not
the group object's DN. Obtaining group DNs/SAMs requires a separate LDAP lookup by SID, which no
current collector performs.

## DEFER-NO-COLLECTOR — ClientDevice uncollected fields

Fields: `current_management_point`, `distinguished_name` (client), `dnshostname` (client), `domain`, `previous_smsid`

None of these appear in `DEVICE_COLUMNS`. They would require either expanding `DEVICE_COLUMNS` to
include additional AdminService/WMI fields (a collection change) or a cross-join with `RSYSTEM_COLUMNS`
data. Out of scope for Stage 3 (preproc/convert only, no re-collect).

## DEFER-NO-COLLECTOR — Site `display_name`

No site source (LDAP `mSSMSSite`, AdminService `SMS_Site`, or WMI) emits a `display_name` distinct
from the site name. The `site_name` field (`SMS_Site.SiteName` → `node_site.site_name`) is the
human-readable label. A separate `display_name` property does not exist.

## DEFER-STAGE5 — MSSQL-coupled site fields

Fields: `site_server_domain_sid`, `site_server_fqdn`, `sql_server_domain_sid`, `sql_server_fqdn`,
`sql_service_port`, `sql_service_account_domain_sid`

These require resolving server hostnames to domain SIDs via MSSQL or active AD queries.
The `MSSQL_*` node tables do not yet exist. Deferred to Stage 5 when those tables are introduced.

## DEFER-ON-COMPUTER — Site `client_certificate_required`

The SCCM client certificate requirement is recorded on each management point (Computer node), not
on the Site object itself. Per the brief, this is already on `node_computer.sccm_client_certificate_required`
(from `http_management_points.client_cert_required`). No separate port to `node_site` is needed.
