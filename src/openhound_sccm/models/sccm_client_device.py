# src/openhound_sccm/models/sccm_client_device.py
"""SCCMClientDevice: converts a node_client_device coalesced row into an SCCMNode.

Each row in node_client_device represents one SCCM client device, keyed by upper(smsid).
Real SCCM-managed clients (AdminService or WMI source; is_client=True AND NOT is_obsolete)
have is_confirmed_active_client=True. Inferred clients discovered via CmRcService SPNs
have is_confirmed_active_client=False. The ad_domain_sid column is NULL for real clients
and resolved later from SMS_R_System; inferred clients carry it from the SPN object_sid.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import SCCMNode, SCCMClientDeviceProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMClientDevice(BaseAsset):
    """One coalesced client device row -> one OpenGraph SCCM_ClientDevice node.

    Fields map directly to the node_client_device columns produced by
    transforms._node_client_device(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    smsid: str | None = None
    name: str | None = None
    site_code: str | None = None
    resource_id_str: str | None = None
    device_os: str | None = None
    device_os_build: str | None = None
    is_virtual_machine: bool | None = None
    co_managed: bool | None = None
    aad_device_id: str | None = None
    aad_tenant_id: str | None = None
    last_mp_server_name: str | None = None
    primary_user_name: str | None = None
    current_logon_user_name: str | None = None
    ad_last_logon_user_name: str | None = None
    root_site_code: str | None = None
    is_confirmed_active_client: bool = False
    ad_domain_sid: str | None = None
    # Telemetry scalars — Stage 3 C4 (CMBP parity).
    ad_last_logon_time: str | None = None
    ad_last_logon_user_domain: str | None = None
    source_site_code: str | None = None
    last_active_time: str | None = None
    last_online_time: str | None = None
    last_offline_time: str | None = None
    # Resolved SID fields — Stage 3 C4 (CMBP ps1:7227/7232/7245/7248).
    primary_user_sid: str | None = None
    current_logon_user_sid: str | None = None
    ad_last_logon_user_sid: str | None = None
    last_reported_mp_server_sid: str | None = None
    # Collection membership lists — Stage 3 C4 (CMBP ps1:7228-7229).
    collection_ids: list[str] = Field(default_factory=list)
    collection_names: list[str] = Field(default_factory=list)
    # Telemetry extras — Task B3 (CMBP parity). currentManagementPoint/SID: Local
    # SMS_Authority + AdminService device resource (ps1:4010-4011/7233-7234). previousSMSID/
    # ChangeDate: Local-only, CCM_Client's PreviousClientId/ClientIdChangeDate (ps1:4016-4017).
    current_management_point: str | None = None
    current_management_point_sid: str | None = None
    previous_smsid: str | None = None
    previous_smsid_change_date: str | None = None
    # AD attributes of the underlying computer -- joined in from node_computer via
    # ad_domain_sid by transforms._enrich_client_device_ad_attrs (ope-fb99).
    cn: str | None = None
    dnshostname: str | None = None
    distinguished_name: str | None = None
    domain: str | None = None
    object_class: list[str] | None = None
    sam_account_name: str | None = None
    service_principal_name: list[str] | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable smsid."""
        sid = (self.smsid or "").upper() or None
        if not sid:
            logger.warning("SCCMClientDevice: dropping row with no smsid")
            return None

        root = self.root_site_code or ""
        # CMBP names a client device "<netbios>@<siteCode>" (e.g. "PS1-DEV@PS1") because the same
        # device can be a client of multiple sites, each with its own record. `name` (not just
        # `displayname`) must carry the suffix so edges/tests that resolve the device by name match.
        display = f"{self.name}@{self.site_code}" if (self.name and self.site_code) else (self.name or sid)

        return SCCMNode(
            id=sid,
            kinds=[nk.SCCM_CLIENT_DEVICE],
            properties=SCCMClientDeviceProperties(
                name=display,
                displayname=display,
                environmentid=root or sid,
                SMSID=sid,
                resourceID=self.resource_id_str,
                siteCode=self.site_code,
                deviceOS=self.device_os,
                deviceOSBuild=self.device_os_build,
                isVirtualMachine=self.is_virtual_machine,
                coManaged=self.co_managed,
                AADDeviceID=self.aad_device_id,
                AADTenantID=self.aad_tenant_id,
                lastReportedMPServerName=self.last_mp_server_name,
                primaryUser=self.primary_user_name,
                currentLogonUser=self.current_logon_user_name,
                ADLastLogonUser=self.ad_last_logon_user_name,
                rootSiteCode=self.root_site_code,
                is_confirmed_active_client=self.is_confirmed_active_client,
                ADDomainSID=self.ad_domain_sid,
                # Telemetry scalars (Stage 3 C4).
                ADLastLogonTime=self.ad_last_logon_time,
                ADLastLogonUserDomain=self.ad_last_logon_user_domain,
                sourceSiteCode=self.source_site_code,
                lastActiveTime=self.last_active_time,
                lastOnlineTime=self.last_online_time,
                lastOfflineTime=self.last_offline_time,
                # Resolved SIDs (Stage 3 C4).
                primaryUserSID=self.primary_user_sid,
                currentLogonUserSID=self.current_logon_user_sid,
                ADLastLogonUserSID=self.ad_last_logon_user_sid,
                lastReportedMPServerSID=self.last_reported_mp_server_sid,
                # Collection membership lists (Stage 3 C4).
                collectionIds=self.collection_ids or [],
                collectionNames=self.collection_names or [],
                # Telemetry extras (Task B3).
                currentManagementPoint=self.current_management_point,
                currentManagementPointSID=self.current_management_point_sid,
                previousSMSID=self.previous_smsid,
                previousSMSIDChangeDate=self.previous_smsid_change_date,
                # userName/userDomainName intentionally mirror ADLastLogonUser/
                # ADLastLogonUserDomain -- CMBP emits the same collected value under both
                # output keys (ps1:7225/7253 and 7226/7254), not a mismapping.
                userName=self.ad_last_logon_user_name,
                userDomainName=self.ad_last_logon_user_domain,
                # AD attributes of the underlying computer (Task ope-fb99).
                CN=self.cn,
                DNSHostName=self.dnshostname,
                distinguishedName=self.distinguished_name,
                domain=self.domain,
                objectClass=self.object_class,
                samAccountName=self.sam_account_name,
                servicePrincipalName=self.service_principal_name,
            ),
        )

    @property
    def edges(self):
        """Client device edges are built in later tasks (D1: HasPrimaryUser, etc.)."""
        return iter(())
