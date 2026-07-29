# src/openhound_sccm/models/graph_edge.py
"""GraphEdge: converts any graph_edges row into an OpenGraph edge of the matching kind.

Each row in the graph_edges preproc table represents one directed relationship
between two graph nodes. This model reads those rows and emits an Edge whose
`traversable` property is set from the CMBP allow-list. The three coerce-and-relay
kinds additionally carry coercion-context lists (SCCMRelayEdgeProperties); every
other kind uses the lean base SCCMEdgeProperties. It never produces a node
(as_node returns None) because graph_edges rows are pure edge data.

Subclasses the shared `openhound_collector_common.graph.graph_edge.GraphEdge` (the
same base the MSSQL extension uses): the base contributes the row fields
(start_id/end_id/kind/collection_source), the id-matched-endpoint contract, and
`as_node = None`. This subclass sets SCCM's traversable allow-list, adds the
relay-only coercion columns, and overrides `edges` to emit SCCM's richer,
CMBP-cased edge properties.
"""
import logging
from typing import Any, Iterator

from openhound.core.models.entries_dataclass import Edge, EdgePath
from openhound_collector_common.graph.graph_edge import GraphEdge as _BaseGraphEdge

from ..edge_help import EDGE_HELP
from ..graph import SCCMEdgeProperties, SCCMRelayEdgeProperties
from ..kinds.edges import (
    MSSQL_COERCE_AND_RELAY_TO_MSSQL,
    SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE,
    SCCM_COERCE_AND_RELAY_TO_SMB,
    TRAVERSABLE_EDGE_KINDS,
)

logger = logging.getLogger(__name__)

# The only edge kinds that carry coerce-and-relay context lists.
_RELAY_KINDS = frozenset({
    SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE,
    MSSQL_COERCE_AND_RELAY_TO_MSSQL,
    SCCM_COERCE_AND_RELAY_TO_SMB,
})


class GraphEdge(_BaseGraphEdge):
    """One graph_edges row -> one OpenGraph edge of any kind. Endpoints matched by id;
    `traversable` is set from the CMBP allow-list. Never produces a node.

    Inherits start_id/end_id/kind/collection_source, the model config, and `as_node`
    (None) from the shared base; adds the relay-only coercion columns and overrides
    `edges` to emit SCCM's SCCMEdgeProperties / SCCMRelayEdgeProperties.
    """

    # SCCM's traversable-edge allow-list. This is the same ClassVar the shared base
    # reads; we compute `traversable` from it below because SCCM emits richer,
    # kind-dependent property types rather than the base's generic properties.
    traversable_kinds = TRAVERSABLE_EDGE_KINDS

    # Relay edges carry coerce-and-relay context columns the base doesn't declare.
    coercion_victim_and_relay_target_pairs: list[str] | None = None
    coercion_victim_hostnames: list[str] | None = None

    # SCCM_IsMappedTo rows carry this true (CMBP parity); every other kind leaves it
    # NULL, so convert prunes the property from their panels.
    sccm_infra: bool | None = None

    # Provenance (Task 3/4/5, D3): populated only by the MSSQL site-DB-scaffolding
    # edges (Task 4) and the Tier-B SCCM permission/coerce/local-admin edges (Task
    # 5); every other kind leaves both NULL, so convert prunes them.
    assumed: bool | None = None
    assumption_basis: str | None = None

    @property
    def edges(self) -> Iterator[Edge]:
        """Yield one Edge for this row.

        If start_id, end_id, or kind is missing, the row is dropped with a
        warning rather than emitting a malformed edge. Entity-panel help content
        (edge_help.py) is merged into the property bag for kinds we document; other
        kinds leave the help fields None and convert prunes them on emit.
        """
        if not self.start_id or not self.end_id or not self.kind:
            logger.warning(
                "GraphEdge: dropping incomplete row (start=%r end=%r kind=%r)",
                self.start_id, self.end_id, self.kind,
            )
            return
        traversable = self.kind in self.traversable_kinds
        # Merge entity-panel help for this kind, if any is authored.
        help_block = EDGE_HELP.get(self.kind)
        help_fields: dict[str, Any]
        if help_block:
            help_fields = help_block.as_fields()
            logger.debug("GraphEdge: attached entity-panel help for kind %r", self.kind)
        else:
            help_fields = {}
            logger.debug("GraphEdge: no entity-panel help authored for kind %r", self.kind)
        # `assumed` is stored as an explicit false (not null) for confirmed rows in
        # the MSSQL site-DB scaffolding family (Task 4's basis-derived CASE), so
        # `or None` prunes those to match the sccm_infra convention: only an
        # affirmative claim is worth cluttering a confirmed edge's panel with.
        assumed = self.assumed or None
        if self.kind in _RELAY_KINDS:
            # Relay edges carry the operator-facing coercion context (CMBP).
            properties = SCCMRelayEdgeProperties(
                traversable=traversable,
                collectionSource=self.collection_source or [],
                coercionVictimAndRelayTargetPairs=self.coercion_victim_and_relay_target_pairs or [],
                coercionVictimHostnames=self.coercion_victim_hostnames or [],
                SCCMInfra=self.sccm_infra,
                assumed=assumed, assumptionBasis=self.assumption_basis,
                **help_fields,
            )
        else:
            # Every other edge keeps the lean base properties.
            properties = SCCMEdgeProperties(
                traversable=traversable,
                collectionSource=self.collection_source or [],
                SCCMInfra=self.sccm_infra,
                assumed=assumed, assumptionBasis=self.assumption_basis,
                **help_fields,
            )
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=properties,
        )
