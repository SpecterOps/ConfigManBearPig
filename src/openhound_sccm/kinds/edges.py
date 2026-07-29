"""Edge kind constants for the SCCM extension.

Mirrors the distinct edge kinds emitted by ConfigManBearPig.
"""

# Site replication topology
SCCM_ADMINS_REPLICATED_TO = "SCCM_AdminsReplicatedTo"

# Stage 2 edge kinds
SCCM_IS_MAPPED_TO = "SCCM_IsMappedTo"
SCCM_IS_ASSIGNED = "SCCM_IsAssigned"
SCCM_HAS_MEMBER = "SCCM_HasMember"
SCCM_HAS_CLIENT = "SCCM_HasClient"
SCCM_HAS_PRIMARY_USER = "SCCM_HasPrimaryUser"
SCCM_HAS_CURRENT_USER = "SCCM_HasCurrentUser"
SCCM_HAS_AD_LAST_LOGON_USER = "SCCM_HasADLastLogonUser"
SCCM_HAS_STORED_ACCOUNT = "SCCM_HasStoredAccount"
MEMBER_OF = "MemberOf"
HAS_SESSION = "HasSession"

# Standard BloodHound base kind (Task 11, Tier A+): each Full-Control principal on
# the System Management container gets one of these edges to it. NOT part of
# schema_SCCM.json -- composes with SharpHound's own GenericAll edges.
GENERIC_ALL = "GenericAll"

# Stage 3 edge kinds (containment + RBAC fan-out)
SCCM_CONTAINS = "SCCM_Contains"
SCCM_FULL_ADMINISTRATOR = "SCCM_FullAdministrator"
SCCM_APPLICATION_AUTHOR = "SCCM_ApplicationAuthor"
SCCM_APPLICATION_ADMINISTRATOR = "SCCM_ApplicationAdministrator"
SCCM_COMPLIANCE_SETTINGS_MANAGER = "SCCM_ComplianceSettingsManager"
SCCM_OSD_MANAGER = "SCCM_OSDManager"
SCCM_OPERATIONS_ADMINISTRATOR = "SCCM_OperationsAdministrator"
SCCM_SECURITY_ADMINISTRATOR = "SCCM_SecurityAdministrator"
SCCM_ALL_PERMISSIONS = "SCCM_AllPermissions"
SCCM_ASSIGN_ALL_PERMISSIONS = "SCCM_AssignAllPermissions"

# Stage 4 edge kinds (host correlation + local-admin mesh)
SCCM_SAME_HOST_AS = "SCCM_SameHostAs"
SCCM_LOCAL_ADMIN_REQUIRED = "SCCM_LocalAdminRequired"

# Stage 5 edge kinds (MSSQL). These belong to the separately maintained MSSQL OpenGraph
# schema (not this extension's schema.json), even though the SCCM collector emits them.
# The string values are already in TRAVERSABLE_EDGE_KINDS, except MSSQL_ServiceAccountFor
# which CMBP comments out (ps1:2233 — not traversable).
MSSQL_CONTAINS = "MSSQL_Contains"
MSSQL_CONTROL_SERVER = "MSSQL_ControlServer"
MSSQL_CONTROL_DB = "MSSQL_ControlDB"
MSSQL_HOST_FOR = "MSSQL_HostFor"
MSSQL_EXECUTE_ON_HOST = "MSSQL_ExecuteOnHost"
MSSQL_HAS_LOGIN = "MSSQL_HasLogin"
MSSQL_IS_MAPPED_TO = "MSSQL_IsMappedTo"
MSSQL_MEMBER_OF = "MSSQL_MemberOf"
MSSQL_SERVICE_ACCOUNT_FOR = "MSSQL_ServiceAccountFor"
MSSQL_GET_ADMIN_TGS = "MSSQL_GetAdminTGS"
MSSQL_GET_TGS = "MSSQL_GetTGS"

# Stage 6 edge kinds (coerce-and-relay possible edges). The AdminService and SMB relays are
# SCCM-namespaced (this extension's schema.json); the MSSQL relay is MSSQL-namespaced (the
# separately maintained MSSQL schema) because its end node is an MSSQL_Login, even though the
# SCCM collector is what emits it.
SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE = "SCCM_CoerceAndRelayToAdminService"
MSSQL_COERCE_AND_RELAY_TO_MSSQL = "MSSQL_CoerceAndRelayToMSSQL"
SCCM_COERCE_AND_RELAY_TO_SMB = "SCCM_CoerceAndRelayToSMB"

# CMBP traversable allow-list (ConfigManBearPig.ps1:2216-2249, uncommented entries only).
# Edges whose kind is in this set get properties.traversable = True. Includes future
# (Stage 3-6) kinds so later stages reuse this one source of truth.
TRAVERSABLE_EDGE_KINDS = frozenset({
    "AdminTo", "SCCM_LocalAdminRequired",
    # Base BloodHound kinds (Task 11/12, Tier A+): control of the System
    # Management container and its group memberships are real, pathfinding-usable
    # relationships, same as SharpHound's own GenericAll/MemberOf edges.
    "GenericAll", "MemberOf",
    # CMBP's allow-list (ps1:2221) named "CoerceAndRelayNTLMtoSMB", but the function
    # (ps1:6775) emits an SMB relay edge — the mismatch left the SMB relay
    # non-traversable. The port emits SCCM_CoerceAndRelayToSMB and marks it traversable.
    "SCCM_CoerceAndRelayToAdminService", "MSSQL_CoerceAndRelayToMSSQL", "SCCM_CoerceAndRelayToSMB",
    "HasSession",
    "MSSQL_Contains", "MSSQL_ControlDB", "MSSQL_ControlServer", "MSSQL_ExecuteOnHost",
    "MSSQL_GetAdminTGS", "MSSQL_GetTGS", "MSSQL_HasLogin", "MSSQL_HostFor",
    "MSSQL_IsMappedTo", "MSSQL_MemberOf",
    "SCCM_SameHostAs",
    "SCCM_AdminsReplicatedTo", "SCCM_AllPermissions", "SCCM_ApplicationAdministrator",
    "SCCM_AssignAllPermissions", "SCCM_Contains", "SCCM_FullAdministrator",
    "SCCM_HasADLastLogonUser", "SCCM_HasClient", "SCCM_HasCurrentUser",
    "SCCM_HasPrimaryUser", "SCCM_IsMappedTo",
})
