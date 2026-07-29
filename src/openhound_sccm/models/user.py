# src/openhound_sccm/models/user.py
"""UserNode: converts a node_user coalesced row into an SCCMNode.

Each row in the node_user preproc table represents one unique user (keyed by
SID). This model reads those rows, resolves the AD domain SID for the
environmentid, and emits a User+Base node with all SCCM-specific properties.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import SCCMNode, UserProperties, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class UserNode(BaseAsset):
    """One coalesced user row -> one OpenGraph User+Base node.

    Fields map directly to the node_user columns produced by
    transforms._node_user(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    sid: str | None = None
    name: str | None = None
    resource_ids: list[str] = Field(default_factory=list)
    sccm_infra: bool = False
    stored_in_sccm_site: str | None = None
    distinguished_name: str | None = None
    user_principal_name: str | None = None
    sam_account_name: str | None = None
    # AD attributes LEFT-JOINed on by _join_ad_props (Task A3); all null when this
    # SID was never LDAP-resolved.
    enabled: bool | None = None
    type: str | None = None
    is_domain_principal: bool | None = None
    object_class: list[str] | None = None
    service_principal_name: list[str] | None = None
    cn: str | None = None
    domain: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable SID."""
        sid = (self.sid or "").upper() or None
        if not sid:
            # No SID means we have no merge key; drop the row.
            logger.warning(
                "UserNode: dropping row with no SID (name=%r)", self.name
            )
            return None

        env = domain_environment_id(sid)
        if env is None:
            # Non-domain SID with no fallback available (builtin or well-known);
            # these cannot be placed in a domain environment, so we drop them.
            logger.warning(
                "UserNode: dropping SID %r — not a domain SID and no fallback "
                "domain SID available",
                sid,
            )
            return None

        display = self.name or sid

        return SCCMNode(
            id=sid,
            kinds=[nk.USER, nk.BASE],
            properties=UserProperties(
                name=self.name or display,
                displayname=display,
                environmentid=env,
                collectionSource=[],
                SCCMResourceIDs=self.resource_ids,
                SCCMInfra=self.sccm_infra,
                storedInSCCMSite=self.stored_in_sccm_site,
                distinguishedName=self.distinguished_name,
                userPrincipalName=self.user_principal_name,
                samAccountName=self.sam_account_name,
                Domain=self.domain,
                Enabled=self.enabled,
                IsDomainPrincipal=self.is_domain_principal,
                Type=self.type,
                objectClass=self.object_class,
                servicePrincipalName=self.service_principal_name,
                CN=self.cn,
            ),
        )

    @property
    def edges(self):
        """User nodes have no edges in Stage 1."""
        return iter(())
