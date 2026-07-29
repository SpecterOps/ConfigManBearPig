"""MSSQLServerRole: one node_mssql_server_role row -> one MSSQL_ServerRole node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLServerRoleProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLServerRole(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    role_id: str | None = None
    server_id: str | None = None
    host_sid: str | None = None
    name: str | None = None
    members: list[str] = Field(default_factory=list)
    sccm_site: str | None = None
    sql_server: str | None = None
    collection_source: list[str] = Field(default_factory=list)
    assumed: bool = False
    assumption_basis: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.role_id:
            logger.warning("MSSQLServerRole: dropping row with no role_id")
            return None
        display = self.name or self.role_id
        return SCCMNode(
            id=self.role_id,
            kinds=[nk.MSSQL_SERVER_ROLE],
            properties=MSSQLServerRoleProperties(
                name=display, displayname=display,
                environmentid=domain_environment_id(self.host_sid or ""),
                collectionSource=list(self.collection_source),
                isFixedRole=True, members=list(self.members),
                SCCMSite=self.sccm_site, SQLServer=self.sql_server,
                assumed=self.assumed or None, assumptionBasis=self.assumption_basis,
            ),
        )

    @property
    def edges(self):
        return iter(())
