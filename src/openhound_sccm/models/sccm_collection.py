# src/openhound_sccm/models/sccm_collection.py
"""SCCMCollection: converts a node_collection coalesced row into an SCCMNode.

Each row in the node_collection preproc table represents one SCCM collection
(keyed by collection_id). This model reads those rows and emits an
SCCM_Collection node with id = '<COLLECTION_ID>@<root_site_code>'.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import SCCMNode, SCCMCollectionProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)

# SCCM collection_type integers from the database map to human-readable labels.
# Source of truth: CMBP ConfigManBearPig.ps1:1741 — 0=Other, 1=User, 2=Device
# (:1742 treats collectionType==2 as a Device collection).
_COLLECTION_TYPE: dict[int, str] = {0: "Other", 1: "User", 2: "Device"}


class SCCMCollection(BaseAsset):
    """One coalesced collection row -> one OpenGraph SCCM_Collection node.

    Fields map directly to the node_collection columns produced by
    transforms._node_collection(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    collection_id: str | None = None
    name: str | None = None
    collection_type: int | None = None
    member_count: int | None = None
    comment: str | None = None
    is_built_in: bool | None = None
    limit_to_collection_id: str | None = None
    limit_to_collection_name: str | None = None
    collection_variables_count: int | None = None
    root_site_code: str | None = None
    source_site_code: str | None = None
    last_change_time: str | None = None
    last_member_change_time: str | None = None
    members: list[str] = Field(default_factory=list)

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable collection_id."""
        cid = (self.collection_id or "").upper() or None
        if not cid:
            logger.warning("SCCMCollection: dropping row with no collection_id")
            return None

        root = self.root_site_code or ""
        node_id = f"{cid}@{root}" if root else cid
        display = f"{self.name}@{root}" if (self.name and root) else (self.name or node_id)

        return SCCMNode(
            id=node_id,
            kinds=[nk.SCCM_COLLECTION],
            properties=SCCMCollectionProperties(
                name=self.name or node_id,
                displayname=display,
                environmentid=root or cid,
                collectionID=cid,
                # dict.get(None) happens to return None rather than raising, but the
                # int-keyed map has no None key -- say so instead of relying on that.
                collectionType=(_COLLECTION_TYPE.get(self.collection_type)
                                if self.collection_type is not None else None),
                memberCount=self.member_count,
                comment=self.comment,
                isBuiltIn=self.is_built_in,
                limitToCollectionID=self.limit_to_collection_id,
                limitToCollectionName=self.limit_to_collection_name,
                collectionVariablesCount=self.collection_variables_count,
                rootSiteCode=self.root_site_code,
                sourceSiteCode=self.source_site_code,
                lastChangeTime=self.last_change_time,
                lastMemberChangeTime=self.last_member_change_time,
                members=list(self.members or []),
            ),
        )

    @property
    def edges(self):
        """Collection membership edges are built in a later task."""
        return iter(())
