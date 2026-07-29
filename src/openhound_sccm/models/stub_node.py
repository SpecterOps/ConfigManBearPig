# src/openhound_sccm/models/stub_node.py
"""StubNode: a bare backfilled node synthesised for edge endpoints with no real node.

`node_backfill` rows are produced by `transforms._node_backfill` for edge END
endpoints that resolved to a SID/smsid not present in any `node_*` table. Each
row carries the endpoint id and the kind inferred from the edge kind (see
`BACKFILL_END_KIND` in graph.py). AD-principal kinds (User, Group, Computer)
also get a 'Base' kind appended; ambiguous ends land with kind='Base' only.
"""
import logging

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import NodeProperties
from pydantic import ConfigDict

from ..graph import SCCMNode, domain_environment_id

logger = logging.getLogger(__name__)

# These kinds represent AD principals and get 'Base' appended per the OpenGraph
# identity model (spec §2 "Root/environment node").
_AD_KINDS = {"User", "Group", "Computer"}


class StubNode(BaseAsset):
    """A bare backfilled node (node_backfill row): id + an inferred kind. AD-principal
    kinds also get 'Base'; environmentid is the domain SID when id is a SID, else the id."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    id: str | None = None
    kind: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.id or not self.kind:
            logger.warning(
                "StubNode: dropping row with missing id/kind (id=%r kind=%r)",
                self.id,
                self.kind,
            )
            return None
        kinds = [self.kind, "Base"] if self.kind in _AD_KINDS else [self.kind]
        env = domain_environment_id(self.id) or self.id
        return SCCMNode(
            id=self.id,
            kinds=kinds,
            properties=NodeProperties(name=self.id, displayname=self.id, environmentid=env),
        )

    @property
    def edges(self):
        return iter(())
