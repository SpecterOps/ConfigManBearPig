"""Transport-neutral row shaping shared by the AdminService and WMI collectors.

The SCCM AdminService REST API is a veneer over the SMS Provider's
``root\\SMS\\site_<code>`` WMI namespace, so both collectors read the *same*
classes and want the *same* output rows. The atoms here — snake-casing, row
shaping, SMS ``Props`` extraction — plus the per-class column selections are the
single source of truth both collectors share.

``adminservice.py`` renders the column tuples into OData ``$select`` clauses via
:func:`odata_select`; ``wmi.py`` uses the same tuples as WQL ``SELECT`` lists and
``keep`` whitelists. Keeping one definition prevents the two collectors' field
sets from drifting apart.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

# Acronym-aware camelCase/PascalCase -> snake_case (AADDeviceID -> aad_device_id).
_SNAKE_1 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_SNAKE_2 = re.compile(r"([a-z0-9])([A-Z])")


def _snake(name: str) -> str:
    return _SNAKE_2.sub(r"\1_\2", _SNAKE_1.sub(r"\1_\2", name)).lower()


def _prop(props: Optional[list], name: str, field: str = "Value1") -> Any:
    """Return one SMS Props value (by PropertyName), or None."""
    for p in props or []:
        if p.get("PropertyName") == name:
            return p.get(field)
    return None


def _row(source: str, site_code: Optional[str], obj: dict, *,
         keep: Optional[Iterable] = None, drop: Optional[Iterable] = None,
         extra: Optional[dict] = None) -> dict:
    """Build a raw row: snake-cased API fields + source + source_site_code.

    ``keep`` (original field names) whitelists columns for endpoints that return
    every column; ``drop`` excludes flattened blobs (e.g. Props); ``extra`` adds
    derived values. OData metadata keys (``@...``) are always dropped. ``keep``
    and ``drop`` accept any container (tuples from the column-set constants work
    directly).
    """
    row: dict[str, Any] = {"source": source, "source_site_code": site_code}
    drop = set(drop or ())
    keep_set = set(keep) if keep is not None else None
    for k, v in obj.items():
        if k.startswith("@") or k in drop:
            continue
        if keep_set is not None and k not in keep_set:
            continue
        row[_snake(k)] = v
    if extra:
        row.update(extra)
    return row


def odata_select(columns: Iterable[str]) -> str:
    """Render an OData ``$select`` clause from a column tuple."""
    return "$select=" + ",".join(columns)


# --- per-class column selections (single source of truth) -----------------
# AdminService renders these into ``$select`` (or uses them as ``keep`` for the
# lazy-column classes). WMI uses them as WQL ``SELECT`` lists / ``keep`` sets.

SITE_COLUMNS = ("BuildNumber", "InstallDir", "ReportingSiteCode", "ServerName",
                "SiteCode", "SiteName", "Status", "Type", "Version")
SITEDEF_COLUMNS = ("ParentSiteCode", "SiteCode", "SiteName", "SiteServerDomain",
                   "SiteServerName", "SiteType", "SQLDatabaseName", "SQLServerName", "Props")
DEVICE_COLUMNS = ("AADDeviceID", "AADTenantID", "ADLastLogonTime", "CNAccessMP", "CNLastOfflineTime",
                  "CNLastOnlineTime", "CoManaged", "CurrentLogonUser", "DeviceOS", "DeviceOSBuild",
                  "IsClient", "IsObsolete", "IsVirtualMachine", "LastActiveTime", "LastMPServerName",
                  "Name", "PrimaryUser", "ResourceID", "SiteCode", "SMSID", "UserName", "UserDomainName")
RSYSTEM_COLUMNS = ("Client", "Name", "Obsolete", "ResourceID", "SID", "SMSUniqueIdentifier",
                   "SecurityGroupName", "SystemRoles")
RUSER_COLUMNS = ("AADTenantID", "AADUserID", "DistinguishedName", "FullDomainName", "FullUserName",
                 "Name", "ResourceID", "SecurityGroupName", "SID", "UniqueUserName", "UserName",
                 "UserPrincipalName")
# SMS_R_UserGroup mirrors the security groups discovered by AD Security Group
# Discovery, one resource row per group WITH its SID. SMS_R_System / SMS_R_User
# only carry group *names* in SecurityGroupName, so this class is what turns those
# names into SIDs offline (fed into principal_by_name during preproc). UniqueUsergroupName
# is the DOMAIN\group form that matches the SecurityGroupName values exactly.
# NB: this class exposes "ResourceId" (not "ResourceID" like SMS_R_System); match its casing.
USERGROUP_COLUMNS = ("ResourceId", "SID", "UniqueUsergroupName", "UsergroupName")
COLLECTION_COLUMNS = ("CollectionID", "CollectionType", "CollectionVariablesCount", "Comment",
                      "IsBuiltIn", "LastChangeTime", "LastMemberChangeTime", "LimitToCollectionID",
                      "LimitToCollectionName", "MemberCount", "Name")
COLLECTION_MEMBER_COLUMNS = ("CollectionID", "ResourceID", "SiteCode")
# SMS_Role / SMS_Admin / SMS_SCI_SysResUse reject column projection on lazy
# columns, so both transports fetch every column and whitelist these.
ROLE_COLUMNS = ("CopiedFromID", "CreatedBy", "CreatedDate", "IsBuiltIn", "IsSecAdminRole",
                "LastModifiedBy", "LastModifiedDate", "NumberOfAdmins", "Operations", "RoleID",
                "RoleName", "RoleDescription", "SourceSite")
ADMIN_COLUMNS = ("AccountType", "AdminID", "AdminSid", "CategoryNames", "CollectionNames", "CreatedBy",
                 "CreatedDate", "DisplayName", "DistinguishedName", "IsGroup", "LastModifiedBy",
                 "LastModifiedDate", "LogonName", "RoleNames", "Roles", "SourceSite")
SYSRES_COLUMNS = ("NetworkOSPath", "SiteCode", "RoleName", "Type")
