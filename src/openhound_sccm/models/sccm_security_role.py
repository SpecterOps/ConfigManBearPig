# src/openhound_sccm/models/sccm_security_role.py
"""SCCMSecurityRole: converts a node_security_role coalesced row into an SCCMNode.

Each row in the node_security_role preproc table represents one SCCM security
role (keyed by role_id). This model reads those rows and emits an
SCCM_SecurityRole node with id = '<ROLE_ID>@<root_site_code>'.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import SCCMNode, SCCMSecurityRoleProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMSecurityRole(BaseAsset):
    """One coalesced security role row -> one OpenGraph SCCM_SecurityRole node.

    Fields map directly to the node_security_role columns produced by
    transforms._node_security_role(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    role_id: str | None = None
    role_name: str | None = None
    role_description: str | None = None
    is_built_in: bool | None = None
    is_sec_admin_role: bool | None = None
    copied_from_id: str | None = None
    number_of_admins: int | None = None
    operations: list[str] = Field(default_factory=list)
    root_site_code: str | None = None
    # Audit fields from ROLE_COLUMNS (CMBP parity, Stage 3 C2).
    site_code: str | None = None
    created_by: str | None = None
    created_date: str | None = None
    last_modified_by: str | None = None
    last_modified_date: str | None = None
    # Members: upper(logon_name)@root for each admin assigned to this role.
    members: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable role_id."""
        rid = (self.role_id or "").upper() or None
        if not rid:
            logger.warning("SCCMSecurityRole: dropping row with no role_id")
            return None

        root = self.root_site_code or ""
        node_id = f"{rid}@{root}" if root else rid
        display = f"{self.role_name}@{root}" if (self.role_name and root) else (self.role_name or node_id)

        return SCCMNode(
            id=node_id,
            kinds=[nk.SCCM_SECURITY_ROLE],
            properties=SCCMSecurityRoleProperties(
                name=self.role_name or node_id,
                displayname=display,
                environmentid=root or rid,
                roleID=rid,
                roleName=self.role_name,
                roleDescription=self.role_description,
                isBuiltIn=self.is_built_in,
                isSecAdminRole=self.is_sec_admin_role,
                copiedFromID=self.copied_from_id,
                numberOfAdmins=self.number_of_admins,
                operations=list(self.operations or []),
                rootSiteCode=self.root_site_code,
                siteCode=self.site_code,
                createdBy=self.created_by,
                createdDate=self.created_date,
                lastModifiedBy=self.last_modified_by,
                lastModifiedDate=self.last_modified_date,
                members=list(self.members or []),
            ),
        )

    @property
    def edges(self):
        """Security role membership edges are built in a later task."""
        return iter(())
