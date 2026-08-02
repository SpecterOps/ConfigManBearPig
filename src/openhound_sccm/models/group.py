# src/openhound_sccm/models/group.py
"""GroupNode: converts a node_group coalesced row into an SCCMNode.

Each row in the node_group preproc table represents one unique group (keyed by
SID, either resolved from a name via principal_by_name or known directly from
the admins tables). This model reads those rows, resolves the AD domain SID for
the environmentid, and emits a Group+Base node with all SCCM-specific
properties.

Builtin/well-known SIDs (S-1-5-32-*, S-1-5-11, etc.) have no domain part on
their own; they are qualified using a co-occurring domain SID stored in
fallback_domain_sid. If no fallback is available, the node is dropped.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import GroupProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class GroupNode(BaseAsset):
    """One coalesced group row -> one OpenGraph Group+Base node.

    Fields map directly to the node_group columns produced by
    transforms._node_group(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    sid: str | None = None
    name: str | None = None
    sccm_infra: bool = False
    sccm_resource_ids: list[str] = Field(default_factory=list)
    # A co-occurring domain SID used to qualify builtin/well-known SIDs that
    # have no domain part of their own. Populated by the _node_group coalesce
    # when a domain SID from a co-occurring device/user is available.
    fallback_domain_sid: str | None = None
    # AD attributes LEFT-JOINed on by _join_ad_props (Task A3); all null when this
    # SID was never LDAP-resolved.
    enabled: bool | None = None
    type: str | None = None
    is_domain_principal: bool | None = None
    object_class: list[str] | None = None
    service_principal_name: list[str] | None = None
    cn: str | None = None
    domain: str | None = None
    # sam_account_name / distinguished_name (Task ope-c141): ad_props-only fields --
    # node_group has no raw arm of its own that spreads an AD object like
    # Computer/User do, so these are populated solely when this SID was
    # independently LDAP-resolved elsewhere (_derive_ad_props).
    sam_account_name: str | None = None
    distinguished_name: str | None = None
    # SAMACCOUNTNAME@DOMAIN.FQDN, built by transforms._stamp_sharphound_name. None when the
    # domain FQDN could not be resolved, in which case the node ships with no name at all.
    sharphound_name: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row cannot be placed."""
        sid = (self.sid or "").upper() or None
        if not sid:
            # No SID means we have no merge key; drop the row.
            logger.warning(
                "GroupNode: dropping row with no SID (name=%r)", self.name
            )
            return None

        env = domain_environment_id(sid, self.fallback_domain_sid)
        if env is None:
            # Non-domain SID (builtin/well-known) with no fallback available;
            # we cannot place this group in a domain environment, so we drop it.
            logger.warning(
                "GroupNode: dropping SID %r (name=%r) — not a domain SID and "
                "no fallback domain SID available",
                sid,
                self.name,
            )
            return None

        # SharpHound's form or nothing. These nodes merge into BloodHound's native AD graph
        # by SID, so a name we emit overwrites SharpHound's own label -- 'mayyhem\Domain
        # Admins' or a bare SID would each degrade a merged graph. Null is pruned on emit
        # and BloodHound falls back to the object id. See transforms._stamp_sharphound_name.
        display = self.sharphound_name

        return SCCMNode(
            id=sid,
            kinds=[nk.GROUP, nk.BASE],
            properties=GroupProperties(
                name=display,
                displayname=display,
                environmentid=env,
                collectionSource=[],
                SCCMInfra=self.sccm_infra,
                SCCMResourceIDs=self.sccm_resource_ids,
                Domain=self.domain,
                Enabled=self.enabled,
                IsDomainPrincipal=self.is_domain_principal,
                Type=self.type,
                objectClass=self.object_class,
                servicePrincipalName=self.service_principal_name,
                CN=self.cn,
                SamAccountName=self.sam_account_name,
                distinguishedName=self.distinguished_name,
            ),
        )

    @property
    def edges(self):
        """Group nodes have no edges in Stage 1."""
        return iter(())
