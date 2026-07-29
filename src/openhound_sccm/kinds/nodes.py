"""Node kind constants for the SCCM extension.

Mirrors the distinct node kinds emitted by ConfigManBearPig
"""

# AD-native kinds
COMPUTER = "Computer"
USER = "User"
GROUP = "Group"
BASE = "Base"
# Standard BloodHound base kind (Task 11, Tier A+) for the System Management
# container: id = the container's own objectGUID, so it merges with SharpHound's
# own Container node for the same AD object. NOT part of schema_SCCM.json.
CONTAINER = "Container"

# SCCM kinds
SCCM_SITE = "SCCM_Site"
SCCM_CLIENT_DEVICE = "SCCM_ClientDevice"
SCCM_COLLECTION = "SCCM_Collection"
SCCM_ADMIN_USER = "SCCM_AdminUser"
SCCM_SECURITY_ROLE = "SCCM_SecurityRole"

# MSSQL kinds
MSSQL_SERVER = "MSSQL_Server"
MSSQL_LOGIN = "MSSQL_Login"
MSSQL_DATABASE = "MSSQL_Database"
MSSQL_DATABASE_USER = "MSSQL_DatabaseUser"
MSSQL_SERVER_ROLE = "MSSQL_ServerRole"
MSSQL_DATABASE_ROLE = "MSSQL_DatabaseRole"

ALL_KINDS = (
    COMPUTER, USER, GROUP, BASE, CONTAINER,
    SCCM_SITE, SCCM_CLIENT_DEVICE, SCCM_COLLECTION, SCCM_ADMIN_USER, SCCM_SECURITY_ROLE,
    MSSQL_SERVER, MSSQL_LOGIN, MSSQL_DATABASE, MSSQL_DATABASE_USER, MSSQL_SERVER_ROLE, MSSQL_DATABASE_ROLE,
)
