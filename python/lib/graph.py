"""
Graph data structures and upsert logic for ConfigManBearPig.

Translated from PowerShell Upsert-Node and Upsert-Edge functions.
Provides the in-memory graph store with merge semantics for nodes and edges.
"""

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("ConfigManBearPig")

# Edge types that are traversable in BloodHound (from PowerShell source lines 2160-2225)
TRAVERSABLE_EDGE_TYPES = {
    "AdminTo",
    "CoerceAndRelayToAdminService",
    "CoerceAndRelayToMSSQL",
    "CoerceAndRelayToSMB",
    "CoerceAndRelaytoSMB",
    "HasSession",
    "MSSQL_Contains",
    "MSSQL_ControlDB",
    "MSSQL_ControlServer",
    "MSSQL_ExecuteOnHost",
    "MSSQL_GetAdminTGS",
    "MSSQL_GetTGS",
    "MSSQL_HasLogin",
    "MSSQL_HostFor",
    "MSSQL_IsMappedTo",
    "MSSQL_LinkedAsAdmin",
    "MSSQL_MemberOf",
    "MSSQL_ServiceAccountFor",
    "SameHostAs",
    "SCCM_AdminsReplicatedTo",
    "SCCM_AllPermissions",
    "SCCM_ApplicationAdministrator",
    "SCCM_AssignAllPermissions",
    "SCCM_AssignSpecificPermissions",
    "SCCM_Contains",
    "SCCM_FullAdministrator",
    "SCCM_HasADLastLogonUser",
    "SCCM_HasClient",
    "SCCM_HasCurrentUser",
    "SCCM_HasMember",
    "SCCM_HasCollectionVar",
    "SCCM_HasNetworkAccessAccount",
    "SCCM_HasPrimaryUser",
    "SCCM_HasTaskSequence",
    "SCCM_HasStoredAccount",
    "SCCM_IsAssigned",
    "SCCM_IsMappedTo",
    "SCCM_ObtainCertFor",
    "LocalAdminRequired",
}


class GraphStore:
    """
    In-memory graph store with upsert semantics.

    Nodes are keyed by their 'id' field. Edges are keyed by (source_id, target_id, kind).
    Both support merge semantics: upserting a node/edge that already exists merges
    the properties and kinds arrays (with deduplication).
    """

    def __init__(self):
        # Nodes indexed by id for O(1) lookup
        self._nodes: dict[str, dict[str, Any]] = {}
        # Edges indexed by (start_id, end_id, kind) for O(1) lookup
        self._edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        # Extra duplicate edges (to match PS behavior where admin replication
        # causes duplicate SCCM_IsAssigned, SCCM_IsMappedTo, SCCM_HasClient edges)
        self._duplicate_edges: list[dict[str, Any]] = []
        # Track which edges have been duplicated (max one extra per unique edge)
        self._duplicated_keys: set[tuple[str, str, str]] = set()
        # Thread safety lock for concurrent access
        self._lock = threading.RLock()

    @property
    def nodes(self) -> list[dict[str, Any]]:
        """Return list of all nodes."""
        with self._lock:
            return list(self._nodes.values())

    @property
    def edges(self) -> list[dict[str, Any]]:
        """Return list of all edges (including duplicates from admin replication)."""
        with self._lock:
            return list(self._edges.values()) + list(self._duplicate_edges)

    def upsert_node(
        self,
        node_id: str,
        kinds: list[str],
        properties: Optional[dict[str, Any]] = None,
        ad_object: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Create or update a node with merge semantics.

        Translated from PowerShell Upsert-Node (lines 1428-1575).

        Merge rules:
        - kinds: union of existing and new kinds (deduplicated, case-preserving)
        - properties: new properties override existing, except:
          - Arrays are merged with deduplication
          - None/null values do not override existing values
          - collectionSource arrays are always merged

        Args:
            node_id: Unique node identifier (SID, site code, GUID, etc.)
            kinds: List of kind labels (e.g., ["Computer", "Base"])
            properties: Dictionary of node properties
            ad_object: AD object properties to merge (from LDAP/AD resolution)

        Returns:
            The created or updated node dictionary
        """
        if properties is None:
            properties = {}

        with self._lock:
            existing = self._nodes.get(node_id)

            if existing is None:
                # Create new node
                node = {
                    "id": node_id,
                    "kinds": list(kinds),
                    "properties": dict(properties),
                }
                # Merge AD object properties if provided
                if ad_object:
                    for key, value in ad_object.items():
                        if value is not None and key not in node["properties"]:
                            node["properties"][key] = value
                self._nodes[node_id] = node
                logger.debug(f"Created node: {node_id} (kinds: {kinds})")
                return node

            # Update existing node - merge kinds
            existing_kinds_lower = {k.lower() for k in existing["kinds"]}
            for kind in kinds:
                if kind.lower() not in existing_kinds_lower:
                    existing["kinds"].append(kind)
                    existing_kinds_lower.add(kind.lower())
                    logger.debug(f"Added kind '{kind}' to node {node_id}")

            # Merge AD object properties first (lower priority)
            if ad_object:
                for key, value in ad_object.items():
                    if value is not None and key not in existing["properties"]:
                        existing["properties"][key] = value

            # Merge explicit properties (higher priority)
            for key, value in properties.items():
                if value is None:
                    continue

                existing_value = existing["properties"].get(key)

                if existing_value is None:
                    existing["properties"][key] = value
                    logger.debug(f"Set property '{key}' on node {node_id}")
                elif isinstance(value, list) and isinstance(existing_value, list):
                    # Merge arrays with deduplication
                    merged = list(existing_value)
                    existing_lower = {
                        str(v).lower() if isinstance(v, str) else v
                        for v in existing_value
                    }
                    for item in value:
                        item_key = str(item).lower() if isinstance(item, str) else item
                        if item_key not in existing_lower:
                            merged.append(item)
                            existing_lower.add(item_key)
                    existing["properties"][key] = merged
                elif isinstance(value, list) and not isinstance(existing_value, list):
                    # New is array, existing is scalar - merge
                    merged = list(value)
                    existing_lower = {
                        str(v).lower() if isinstance(v, str) else v
                        for v in value
                    }
                    ev_key = (
                        str(existing_value).lower()
                        if isinstance(existing_value, str)
                        else existing_value
                    )
                    if ev_key not in existing_lower:
                        merged.append(existing_value)
                    existing["properties"][key] = merged
                elif key == "collectionSource":
                    # collectionSource is always merged as array
                    if not isinstance(existing_value, list):
                        existing_value = [existing_value]
                    if not isinstance(value, list):
                        value = [value]
                    merged = list(existing_value)
                    existing_lower = {str(v).lower() for v in existing_value}
                    for item in value:
                        if str(item).lower() not in existing_lower:
                            merged.append(item)
                            existing_lower.add(str(item).lower())
                    existing["properties"][key] = merged
                else:
                    # Scalar override
                    if existing_value != value:
                        logger.debug(
                            f"Updated property '{key}' on node {node_id}: "
                            f"{existing_value} -> {value}"
                        )
                        existing["properties"][key] = value

            return existing

    def upsert_edge(
        self,
        source_id: str,
        target_id: str,
        kind: str,
        properties: Optional[dict[str, Any]] = None,
        traversable: Optional[bool] = None,
    ) -> dict[str, Any]:
        """
        Create or update an edge with merge semantics.

        Translated from PowerShell Upsert-Edge (lines 2103-2259).

        Args:
            source_id: Source node id
            target_id: Target node id
            kind: Edge kind/type
            properties: Edge properties to merge
            traversable: Override traversable flag (auto-detected from kind if None)

        Returns:
            The created or updated edge dictionary
        """
        if properties is None:
            properties = {}

        edge_key = (source_id, target_id, kind)

        # Determine traversable status
        if traversable is None:
            is_traversable = kind in TRAVERSABLE_EDGE_TYPES
        else:
            is_traversable = traversable

        with self._lock:
            existing = self._edges.get(edge_key)

            if existing is None:
                # Create new edge
                edge: dict[str, Any] = {
                    "kind": kind,
                    "start": {"value": source_id},
                    "end": {"value": target_id},
                }
                if properties:
                    edge["properties"] = dict(properties)
                if not is_traversable:
                    edge["traversable"] = False
                self._edges[edge_key] = edge
                logger.debug(f"Created edge: {source_id} -[{kind}]-> {target_id}")
                return edge

            # Merge properties into existing edge
            if properties:
                if "properties" not in existing:
                    existing["properties"] = {}
                for key, value in properties.items():
                    if value is None:
                        continue
                    existing_value = existing["properties"].get(key)
                    if existing_value is None:
                        existing["properties"][key] = value
                    elif isinstance(value, list) and isinstance(existing_value, list):
                        # Merge arrays with dedup
                        merged = list(existing_value)
                        existing_set = {
                            str(v).lower() if isinstance(v, str) else v
                            for v in existing_value
                        }
                        for item in value:
                            ik = str(item).lower() if isinstance(item, str) else item
                            if ik not in existing_set:
                                merged.append(item)
                                existing_set.add(ik)
                        existing["properties"][key] = merged
                    elif isinstance(value, list):
                        # New is array, existing is scalar
                        merged = list(value)
                        existing_set = {
                            str(v).lower() if isinstance(v, str) else v
                            for v in value
                        }
                        ev_k = (
                            str(existing_value).lower()
                            if isinstance(existing_value, str)
                            else existing_value
                        )
                        if ev_k not in existing_set:
                            merged.append(existing_value)
                        existing["properties"][key] = merged
                    else:
                        existing["properties"][key] = value

            return existing

    def upsert_edge_allow_duplicate(
        self,
        source_id: str,
        target_id: str,
        kind: str,
        properties: Optional[dict[str, Any]] = None,
        traversable: Optional[bool] = None,
    ) -> dict[str, Any]:
        """
        Create or update an edge, allowing duplicates.

        Matches PS behavior where admin replication causes the same edge
        to be created from multiple AdminService endpoints. If the edge
        already exists, a duplicate is added to the output.
        """
        edge_key = (source_id, target_id, kind)

        if traversable is None:
            is_traversable = kind in TRAVERSABLE_EDGE_TYPES
        else:
            is_traversable = traversable

        edge: dict[str, Any] = {
            "kind": kind,
            "start": {"value": source_id},
            "end": {"value": target_id},
        }
        if properties:
            edge["properties"] = dict(properties)
        if not is_traversable:
            edge["traversable"] = False

        with self._lock:
            existing = self._edges.get(edge_key)
            if existing is None:
                self._edges[edge_key] = edge
                logger.debug(f"Created edge: {source_id} -[{kind}]-> {target_id}")
            elif edge_key not in self._duplicated_keys:
                # Allow at most one duplicate per unique edge (matches PS 2x behavior)
                self._duplicate_edges.append(edge)
                self._duplicated_keys.add(edge_key)
                logger.debug(f"Added duplicate edge: {source_id} -[{kind}]-> {target_id}")

        return edge

    def get_node(self, node_id: str) -> Optional[dict[str, Any]]:
        """Get a node by id, or None if not found."""
        with self._lock:
            return self._nodes.get(node_id)

    def find_nodes_by_kind(self, kind: str) -> list[dict[str, Any]]:
        """Find all nodes containing the specified kind."""
        with self._lock:
            return [
                n for n in self._nodes.values()
                if kind in n.get("kinds", [])
            ]

    def find_edges_by_kind(self, kind: str) -> list[dict[str, Any]]:
        """Find all edges of the specified kind."""
        with self._lock:
            return [
                e for e in self._edges.values()
                if e.get("kind") == kind
            ]

    def find_edges_from(self, source_id: str) -> list[dict[str, Any]]:
        """Find all edges originating from the specified node."""
        with self._lock:
            return [
                e for (s, t, k), e in self._edges.items()
                if s == source_id
            ]

    def find_edges_to(self, target_id: str) -> list[dict[str, Any]]:
        """Find all edges targeting the specified node."""
        with self._lock:
            return [
                e for (s, t, k), e in self._edges.items()
                if t == target_id
            ]

    def rename_node(self, old_id: str, new_id: str) -> Optional[dict[str, Any]]:
        """
        Rename a node's ID and update all edge references.

        Translated from PowerShell Update-GlobalObjectIdentifiers (lines 2397-2509).

        If new_id already exists, merges old node into existing node.
        Updates all edges referencing old_id to use new_id.

        Returns:
            The node at new_id after rename/merge, or None if old_id not found
        """
        with self._lock:
            if old_id == new_id:
                return self._nodes.get(old_id)

            old_node = self._nodes.get(old_id)
            if old_node is None:
                return None

            existing_new = self._nodes.get(new_id)
            if existing_new is not None:
                # Merge old node into existing new node
                # Merge kinds
                existing_kinds_lower = {k.lower() for k in existing_new["kinds"]}
                for kind in old_node.get("kinds", []):
                    if kind.lower() not in existing_kinds_lower:
                        existing_new["kinds"].append(kind)
                        existing_kinds_lower.add(kind.lower())

                # Merge properties (old node values don't override existing)
                for key, value in old_node.get("properties", {}).items():
                    if value is None:
                        continue
                    existing_value = existing_new["properties"].get(key)
                    if existing_value is None:
                        existing_new["properties"][key] = value
                    elif isinstance(value, list) and isinstance(existing_value, list):
                        # Merge arrays with dedup
                        merged = list(existing_value)
                        existing_set = {
                            str(v).lower() if isinstance(v, str) else v
                            for v in existing_value
                        }
                        for item in value:
                            ik = str(item).lower() if isinstance(item, str) else item
                            if ik not in existing_set:
                                merged.append(item)
                                existing_set.add(ik)
                        existing_new["properties"][key] = merged

                del self._nodes[old_id]
            else:
                # Simple rename
                old_node["id"] = new_id
                self._nodes[new_id] = old_node
                del self._nodes[old_id]

            # Update all edges referencing old_id
            edges_to_update: list[tuple[tuple[str, str, str], tuple[str, str, str], dict[str, Any]]] = []
            for (s, t, k), edge in list(self._edges.items()):
                new_s = new_id if s == old_id else s
                new_t = new_id if t == old_id else t
                if new_s != s or new_t != t:
                    edges_to_update.append(((s, t, k), (new_s, new_t, k), edge))

            updated_count = 0
            for old_key, new_key, edge in edges_to_update:
                del self._edges[old_key]
                if edge["start"]["value"] == old_id:
                    edge["start"]["value"] = new_id
                if edge["end"]["value"] == old_id:
                    edge["end"]["value"] = new_id

                if new_key in self._edges:
                    # Edge already exists at new key - preserve as duplicate
                    # (matches PS behavior where rename doesn't deduplicate)
                    self._duplicate_edges.append(edge)
                else:
                    self._edges[new_key] = edge
                updated_count += 1

            if updated_count > 0:
                logger.debug(f"Renamed node {old_id} -> {new_id}, updated {updated_count} edges")

            return self._nodes.get(new_id)

    def has_edge(self, source_id: str, target_id: str, kind: str) -> bool:
        """Check if a specific edge exists."""
        with self._lock:
            return (source_id, target_id, kind) in self._edges
