# src/openhound_sccm/models/computer.py
"""ComputerNode: converts a node_computer coalesced row into an SCCMNode.

Each row in the node_computer preproc table represents one unique computer
(keyed by SID). This model reads those rows, resolves the AD domain SID for
the environmentid, and emits a Computer+Base node with all SCCM-specific
properties populated.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import ComputerProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class ComputerNode(BaseAsset):
    """One coalesced computer row -> one OpenGraph Computer+Base node.

    Fields map directly to the node_computer columns produced by
    transforms._node_computer(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    sid: str | None = None
    name: str | None = None
    dnshostname: str | None = None
    sam_account_name: str | None = None
    distinguished_name: str | None = None
    site_system_roles: list[str] = Field(default_factory=list)
    resource_ids: list[str] = Field(default_factory=list)
    sccm_infra: bool = False
    sms_unique_identifier: str | None = None
    smb_signing_required: bool | None = None
    sccm_has_client_remote_control_spn: bool = False
    network_boot_server: bool = False
    disable_loopback_check: bool | None = None
    restrict_receiving_ntlm_traffic: str | None = None
    sccm_client_certificate_required: bool | None = None
    sccm_hosts_content_library: bool | None = None
    sccm_is_pxe_support_enabled: bool | None = None
    # AD attributes LEFT-JOINed on by _join_ad_props (Task A3); all null when this
    # SID was never LDAP-resolved.
    enabled: bool | None = None
    type: str | None = None
    is_domain_principal: bool | None = None
    object_class: list[str] | None = None
    service_principal_name: list[str] | None = None
    cn: str | None = None
    domain: str | None = None
    # HOSTNAME.DOMAIN.FQDN, built by transforms._stamp_sharphound_name. None when the domain
    # FQDN could not be resolved, in which case the node ships with no name at all.
    sharphound_name: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable SID."""
        sid = (self.sid or "").upper() or None
        if not sid:
            # No SID means we have no merge key; drop the row.
            logger.warning(
                "ComputerNode: dropping row with no SID (name=%r)", self.name
            )
            return None

        env = domain_environment_id(sid)
        if env is None:
            # Non-domain SID with no fallback available (builtin or well-known);
            # these are filtered out at the node_computer coalesce level in practice
            # but we guard here too.
            logger.warning(
                "ComputerNode: dropping SID %r — not a domain SID and no fallback "
                "domain SID available",
                sid,
            )
            return None

        # SharpHound's form or nothing -- see GroupNode.as_node for the reasoning. For a
        # computer that is the uppercase dNSHostName, not the short name.
        display = self.sharphound_name

        return SCCMNode(
            id=sid,
            kinds=[nk.COMPUTER, nk.BASE],
            properties=ComputerProperties(
                name=display,
                displayname=display,
                environmentid=env,
                collectionSource=[],
                SCCMSiteSystemRoles=self.site_system_roles,
                SCCMInfra=self.sccm_infra,
                SCCMResourceIDs=self.resource_ids,
                SCCMClientDeviceIdentifier=self.sms_unique_identifier,
                dNSHostName=self.dnshostname,
                samAccountName=self.sam_account_name,
                distinguishedName=self.distinguished_name,
                SMBSigningRequired=self.smb_signing_required,
                SCCMHasClientRemoteControlSPN=self.sccm_has_client_remote_control_spn,
                networkBootServer=self.network_boot_server,
                disableLoopbackCheck=self.disable_loopback_check,
                restrictReceivingNtlmTraffic=self.restrict_receiving_ntlm_traffic,
                SCCMClientCertificateRequired=self.sccm_client_certificate_required,
                SCCMHostsContentLibrary=self.sccm_hosts_content_library,
                SCCMIsPXESupportEnabled=self.sccm_is_pxe_support_enabled,
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
        """Computer nodes have no edges in Stage 1."""
        return iter(())
