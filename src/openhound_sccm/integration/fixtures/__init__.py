"""mayyhem.com integration-test fixture package for the SCCM extension.

Holds the SCCM-specific case-type extensions shared by edges.py and nodes.py so they
are defined once instead of duplicated per module.
"""
from __future__ import annotations

from dataclasses import dataclass

from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase


@dataclass
class SCCMEdgeCase(EdgeCase):
    """EdgeCase extended with the low-priv privilege partition (plan
    2026-07-23-low-priv-assumed-edges, Task 9). Defined here rather than in
    openhound-collector-common so this SCCM-fixture-only detail cannot affect the
    MSSQL collector or any other consumer of the shared integration-testing engine.

    requires_privilege=True marks a case that can only be asserted against an
    AdminService/WMI-privileged collection (design spec S:5, Tier D): the SCCM RBAC
    families with no AD/LDAP/RemoteRegistry representation (SCCM_FullAdministrator,
    SCCM_IsAssigned, SCCM_IsMappedTo, SCCM_AllPermissions). A low-priv test run
    should filter these cases out rather than assert their absence -- Tier D means
    "cannot check this without privilege", not "this must not exist".
    """
    requires_privilege: bool = False


@dataclass
class SCCMNodeCase(NodeCase):
    """NodeCase extended with the same low-priv partition flag; see SCCMEdgeCase.
    Marks the RBAC-object node kinds (SCCM_AdminUser, SCCM_SecurityRole,
    SCCM_Collection) that design spec S:5 calls out as AdminService/WMI-only.
    """
    requires_privilege: bool = False
