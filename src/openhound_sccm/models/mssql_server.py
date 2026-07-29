"""MSSQLServer: one node_mssql_server row -> one MSSQL_Server node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLServerProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLServer(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    server_id: str | None = None
    host_sid: str | None = None
    port: str | None = None
    name: str | None = None
    dns_host_name: str | None = None
    sccm_site: str | None = None
    sccm_infra: bool = False
    databases: list[str] = Field(default_factory=list)
    force_encryption: bool | None = None
    extended_protection: str | None = None
    strict_encryption: bool | None = None
    instance_names: list[str] = Field(default_factory=list)
    service_account_name: str | None = None
    service_account_domain_sid: str | None = None
    collection_source: list[str] = Field(default_factory=list)
    assumed: bool | None = None
    assumption_basis: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.server_id:
            logger.warning("MSSQLServer: dropping row with no server_id")
            return None
        env = domain_environment_id(self.host_sid or "")
        display = self.name or self.server_id
        return SCCMNode(
            id=self.server_id,
            kinds=[nk.MSSQL_SERVER],
            properties=MSSQLServerProperties(
                name=display, displayname=display, environmentid=env,
                collectionSource=list(self.collection_source),
                dnsHostName=self.dns_host_name, SQLServicePort=self.port,
                SCCMInfra=self.sccm_infra, SCCMSite=self.sccm_site,
                databases=list(self.databases),
                forceEncryption=self.force_encryption,
                extendedProtection=self.extended_protection,
                SQLServiceAccountName=self.service_account_name,
                SQLServiceAccountDomainSID=self.service_account_domain_sid,
                strictEncryption=self.strict_encryption,
                instanceNames=list(self.instance_names),
                # or None: prune the false a confirmed (or non-site-DB) row carries;
                # NULL (arms 2/3 only) already falls through unchanged.
                assumed=self.assumed or None, assumptionBasis=self.assumption_basis,
            ),
        )

    @property
    def edges(self):
        return iter(())
