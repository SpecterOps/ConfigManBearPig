# src/openhound_sccm/models/container.py
"""ContainerNode: converts a node_container row into a Container+Base OpenGraph node.

Task 11 (Tier A+): wires up the System Management container's already-collected
DACL (ldap_system_management_dacl), which previously fed no node at all. Container
is a standard BloodHound BASE kind, not a custom SCCM one -- the id is the AD
object's own objectGUID (uppercased in the collector, see
collectors/ldap.py::_format_guid), matching SharpHound's own Container node for the
same object so the two merge.
"""
import logging

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import NodeProperties
from pydantic import ConfigDict

from ..graph import SCCMNode, domain_environment_id

logger = logging.getLogger(__name__)


class ContainerNode(BaseAsset):
    """One node_container row -> one OpenGraph Container+Base node.

    fallback_domain_sid is populated by transforms._node_smc_container from any
    co-collected GenericAll principal with a normal domain-relative SID (the
    container itself has no SID of its own to derive one from) -- the same
    "co-occurring domain SID" idiom GroupNode already uses for builtin SIDs.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str | None = None
    distinguished_name: str | None = None
    fallback_domain_sid: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.id:
            # No GUID means no merge key with SharpHound's own node; drop the row.
            logger.warning("ContainerNode: dropping row with no id")
            return None
        display = self.distinguished_name or self.id
        env = domain_environment_id(self.id, self.fallback_domain_sid) or self.fallback_domain_sid or self.id
        return SCCMNode(
            id=self.id,
            kinds=["Container", "Base"],
            properties=NodeProperties(
                name=display,
                displayname=display,
                environmentid=env,
            ),
        )

    @property
    def edges(self):
        """Container nodes have no edges of their own -- GenericAll edges point AT
        them, they don't originate from them."""
        return iter(())
