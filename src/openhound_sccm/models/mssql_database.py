"""MSSQLDatabase: one node_mssql_database row -> one MSSQL_Database node."""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..graph import MSSQLDatabaseProperties, SCCMNode, domain_environment_id
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class MSSQLDatabase(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    database_id: str | None = None
    server_id: str | None = None
    host_sid: str | None = None
    port: str | None = None
    name: str | None = None
    sccm_site: str | None = None
    sql_server: str | None = None
    collection_source: list[str] = Field(default_factory=list)
    assumed: bool = False
    assumption_basis: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.database_id:
            logger.warning("MSSQLDatabase: dropping row with no database_id")
            return None
        display = self.name or self.database_id
        return SCCMNode(
            id=self.database_id,
            kinds=[nk.MSSQL_DATABASE],
            properties=MSSQLDatabaseProperties(
                name=display, displayname=display,
                environmentid=domain_environment_id(self.host_sid or ""),
                collectionSource=list(self.collection_source),
                isTrustworthy=True, SCCMInfra=True,
                SCCMSite=self.sccm_site, SQLServer=self.sql_server,
                # or None: prune the false a confirmed row carries (Task 4's
                # basis-derived CASE), matching the SCCMInfra convention.
                assumed=self.assumed or None, assumptionBasis=self.assumption_basis,
            ),
        )

    @property
    def edges(self):
        return iter(())
