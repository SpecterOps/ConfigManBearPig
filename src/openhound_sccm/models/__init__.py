"""SCCM extension model registry.

Each module here defines `BaseAsset` subclasses the convert phase uses to produce
OpenGraph nodes/edges. Models are imported here so the convert pipeline can resolve
them by name and so callers can do `from openhound_sccm.models import ComputerNode`.
"""
from .computer import ComputerNode
from .container import ContainerNode
from .group import GroupNode
from .graph_edge import GraphEdge
from .mssql_database import MSSQLDatabase
from .mssql_database_role import MSSQLDatabaseRole
from .mssql_database_user import MSSQLDatabaseUser
from .mssql_login import MSSQLLogin
from .mssql_server import MSSQLServer
from .mssql_server_role import MSSQLServerRole
from .sccm_admin_user import SCCMAdminUser
from .sccm_client_device import SCCMClientDevice
from .sccm_collection import SCCMCollection
from .sccm_security_role import SCCMSecurityRole
from .sccm_site import SCCMSite
from .stub_node import StubNode
from .user import UserNode

__all__ = ["ComputerNode", "ContainerNode", "GraphEdge", "GroupNode", "MSSQLDatabase", "MSSQLDatabaseRole", "MSSQLDatabaseUser", "MSSQLLogin", "MSSQLServer", "MSSQLServerRole", "SCCMAdminUser", "SCCMClientDevice", "SCCMCollection", "SCCMSecurityRole", "SCCMSite", "StubNode", "UserNode"]
