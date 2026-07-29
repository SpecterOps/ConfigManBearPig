# src/openhound_sccm/models/sccm_site.py
"""SCCMSite: converts a node_site coalesced row into an SCCMNode.

Each row in the node_site preproc table represents one SCCM site (keyed by
site code). This model reads those rows and emits an SCCM_Site node with the
hierarchy and infrastructure properties populated.
"""
import logging

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict, Field

from ..cve_table import lookup_cves
from ..graph import SCCMNode, SCCMSiteProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)

# Integer site_type values from the SCCM database map to human-readable strings.
# Values match CMBP's site type constants (ps1:2620 area).
_SITE_TYPE_LABELS: dict[int, str] = {
    1: "Secondary Site",
    2: "Primary Site",
    4: "Central Administration Site",
}


class SCCMSite(BaseAsset):
    """One coalesced site row -> one OpenGraph SCCM_Site node.

    Fields map directly to the node_site columns produced by
    transforms._node_site(). Extra columns from the DB are silently
    ignored (extra="ignore") so schema drift doesn't crash convert.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    site_code: str | None = None
    site_guid: str | None = None
    parent_site_code: str | None = None
    site_type: int | None = None          # raw integer from DB; converted in as_node
    site_name: str | None = None          # human-readable display name
    server_name: str | None = None        # site server hostname
    sql_server_name: str | None = None
    sql_database_name: str | None = None
    version: str | None = None
    build_number: str | None = None
    install_dir: str | None = None
    root_site_code: str | None = None
    collection_source: list[str] = Field(default_factory=list)
    # Stage 3 C5 additions — CMBP parity.
    sql_service_account_name: str | None = None
    distinguished_name: str | None = None
    source_forest: str | None = None
    admin_users: list[str] = Field(default_factory=list)
    stored_accounts: list[str] = Field(default_factory=list)
    site_system_roles: list[str] = Field(default_factory=list)
    # Site/SQL server identity (CMBP ps1:7052-7065, 3040), derived in _node_site.
    site_server_fqdn: str | None = None
    site_server_domain_sid: str | None = None
    sql_server_fqdn: str | None = None
    sql_server_domain_sid: str | None = None
    sql_service_account_domain_sid: str | None = None
    sql_service_port: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        """Build the SCCMNode, or return None if the row has no usable site_code."""
        if not self.site_code:
            # No site code means we have no merge key; drop the row.
            logger.warning("SCCMSite: dropping row with no site_code")
            return None

        # environmentid is the root of the hierarchy; fall back to the site's
        # own code for standalone / single-site deployments with no CAS.
        env = self.root_site_code or self.site_code

        # Convert the integer site_type to a human-readable label.
        site_type_str = _SITE_TYPE_LABELS.get(self.site_type) if self.site_type is not None else None
        if self.site_type is None:
            # no site_type from any source; leave unset
            pass
        elif site_type_str is None:
            logger.warning(
                "SCCMSite: unrecognised site_type %r for site %r; leaving as None",
                self.site_type,
                self.site_code,
            )

        display = self.site_name or self.site_code

        # Known CVEs for this site's SCCM build (None when version unknown so the key
        # prunes; [] when the version is known but fully patched).
        version_cves = lookup_cves(self.version) if self.version else None

        return SCCMNode(
            id=self.site_code,
            kinds=[nk.SCCM_SITE],
            properties=SCCMSiteProperties(
                name=display,
                displayname=display,
                environmentid=env,
                collectionSource=list(self.collection_source),
                siteCode=self.site_code,
                parentSiteCode=self.parent_site_code,
                rootSiteCode=self.root_site_code,
                siteType=site_type_str,
                siteGUID=self.site_guid,
                siteServerName=self.server_name,
                SQLServerName=self.sql_server_name,
                SQLDatabaseName=self.sql_database_name,
                version=self.version,
                buildNumber=self.build_number,
                installDir=self.install_dir,
                SQLServiceAccountName=self.sql_service_account_name,
                distinguishedName=self.distinguished_name,
                sourceForest=self.source_forest,
                adminUsers=list(self.admin_users),
                storedAccounts=list(self.stored_accounts),
                siteSystemRoles=list(self.site_system_roles),
                siteServerFQDN=self.site_server_fqdn,
                siteServerDomainSID=self.site_server_domain_sid,
                SQLServerFQDN=self.sql_server_fqdn,
                SQLServerDomainSID=self.sql_server_domain_sid,
                SQLServiceAccountDomainSID=self.sql_service_account_domain_sid,
                SQLServicePort=self.sql_service_port,
                versionCVEs=version_cves,
            ),
        )

    @property
    def edges(self):
        """Site edges (SCCM_AdminsReplicatedTo) are built in Task 7."""
        return iter(())
