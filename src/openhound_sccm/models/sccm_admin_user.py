# src/openhound_sccm/models/sccm_admin_user.py
"""SCCMAdminUser: converts a node_admin_user coalesced row into an SCCMNode.

Each row in the node_admin_user preproc table represents one SCCM RBAC admin
object (keyed by upper(logon_name)). This model reads those rows and emits an
SCCM_AdminUser node with id = '<UPPER_LOGON_NAME>@<root_site_code>'.

Note: the node id uses the uppercased logon_name while properties.name keeps
the original case, matching the casing rule in the node_admin_user coalesce.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import SCCMNode, SCCMAdminUserProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMAdminUser(BaseAsset):
    """One coalesced admin user row -> one OpenGraph SCCM_AdminUser node.

    Fields map directly to the node_admin_user columns produced by
    transforms._node_admin_user(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    logon_name: str | None = None
    admin_id: str | None = None
    admin_sid: str | None = None
    display_name: str | None = None
    distinguished_name: str | None = None
    is_group: bool | None = None
    account_type: int | None = None
    root_site_code: str | None = None
    # Audit fields from ADMIN_COLUMNS (CMBP parity, Stage 3 C3).
    source_site_code: str | None = None
    created_by: str | None = None
    created_date: str | None = None
    last_modified_by: str | None = None
    last_modified_date: str | None = None
    # Assignment lists added by _enrich_admin_assignments.
    collection_ids: list[str] = Field(default_factory=list)
    role_ids: list[str] = Field(default_factory=list)
    member_of: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable logon_name."""
        logon = self.logon_name or ""
        key = logon.upper() or None
        if not key:
            logger.warning("SCCMAdminUser: dropping row with no logon_name")
            return None

        root = self.root_site_code or ""
        node_id = f"{key}@{root}" if root else key

        return SCCMNode(
            id=node_id,
            kinds=[nk.SCCM_ADMIN_USER],
            properties=SCCMAdminUserProperties(
                name=logon or node_id,
                # CMBP parity: admin-user nodes carry ONLY the camelCase `displayName`
                # (below), never the framework base lowercase `displayname`. Setting both
                # would put two keys that differ only by case on one node's properties,
                # which every case-insensitive consumer rejects as a duplicate key —
                # BloodHound/Neo4j ingestion and the PowerShell unit-test kit's
                # ConvertFrom-Json alike. CMBP never emits the lowercase key, so we drop
                # it here by passing None (pruned on emit).
                displayname=None,
                environmentid=root or key,
                adminID=self.admin_id,
                adminSid=self.admin_sid,
                distinguishedName=self.distinguished_name,
                isGroup=self.is_group,
                accountType=self.account_type,
                rootSiteCode=self.root_site_code,
                # CMBP parity: empty display name is omitted, not emitted as "".
                displayName=self.display_name or None,
                sourceSiteCode=self.source_site_code,
                createdBy=self.created_by,
                createdDate=self.created_date,
                lastModifiedBy=self.last_modified_by,
                lastModifiedDate=self.last_modified_date,
                collectionIds=list(self.collection_ids),
                roleIDs=list(self.role_ids),
                memberOf=list(self.member_of),
            ),
        )

    @property
    def edges(self):
        """Admin user membership edges are built in a later task (C4/C5)."""
        return iter(())
