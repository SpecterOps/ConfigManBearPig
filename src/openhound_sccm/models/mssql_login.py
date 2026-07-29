"""MSSQLLogin: one node_mssql_login row -> one MSSQL_Login node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLLoginProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLLogin(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    login_id: str | None = None
    login_name: str | None = None
    server_id: str | None = None
    host_sid: str | None = None
    port: str | None = None
    sql_server: str | None = None
    sccm_site: str | None = None
    sysadmin_computer_sid: str | None = None
    collection_source: list[str] = Field(default_factory=list)
    assumed: bool = False
    assumption_basis: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.login_id:
            logger.warning("MSSQLLogin: dropping row with no login_id")
            return None
        display = self.login_name or self.login_id
        roles = [f"sysadmin@{self.server_id}"] if self.server_id else []
        return SCCMNode(
            id=self.login_id,
            kinds=[nk.MSSQL_LOGIN],
            properties=MSSQLLoginProperties(
                name=display, displayname=display,
                environmentid=domain_environment_id(self.host_sid or ""),
                collectionSource=list(self.collection_source),
                loginType="Windows", memberOfRoles=roles,
                SCCMInfra=True, SCCMSite=self.sccm_site, SQLServer=self.sql_server,
                assumed=self.assumed or None, assumptionBasis=self.assumption_basis,
            ),
        )

    @property
    def edges(self):
        return iter(())
