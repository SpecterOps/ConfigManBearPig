# src/openhound_sccm/convert_pipeline.py
"""Convert-time pipeline (Convert2-Read-DB): read node_* tables and graph_edges from the preproc
DuckDB and emit them as OpenGraph nodes/edges.

The framework's built-in convert reader only globs JSONL from the bucket, so a
coalesced DuckDB table can't be iterated by it. We read DuckDB directly through
the open lookup connection and use common's bounded graph writer. See
docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md §4.

Stage 1+ replaces the Stage-0 spike shapers with typed models driven by node_specs
and edge_specs. Each spec is a (table_name, ModelClass) pair; for every row the model
is instantiated, the lookup is injected, and as_node / edges produce the OpenGraph
content.
"""

import logging
from dataclasses import asdict
from pathlib import Path

from dlt.common import json
from openhound_collector_common.graph.files import GraphFileWriter

from .kinds import nodes as nk
from .lookup import SCCMLookup
from .models.graph_edge import GraphEdge

logger = logging.getLogger(__name__)


def emit_hybrid_edges_from_duckdb(
    lookup: SCCMLookup,
    output_path: str | Path,
) -> None:
    """Write SQL-to-SCCM relationships to one untagged hybrid_edges.json file.

    Use the existing edge model and property cleanup so moving a relationship
    does not change its meaning. Write one edge at a time, without collecting
    the whole graph in memory. Replace the previous file only after writing a
    complete document, including an empty document when there are no matches.
    """
    output_file = Path(output_path) / "hybrid_edges.json"
    temporary_file = output_file.with_suffix(".json.tmp")
    edge_count = 0
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with temporary_file.open("w", encoding="utf-8") as stream:
            # No metadata.source_kind: these connections span two products.
            stream.write('{"graph":{"nodes":[],"edges":[')
            for row in lookup.table_rows("graph_edges_hybrid"):
                model = GraphEdge(**row)
                model._lookup = lookup
                for edge in model.edges:
                    if edge_count:
                        # Commas only separate JSON entries; no operational decision.
                        stream.write(",")
                    stream.write(json.dumps(_normalize_properties(asdict(edge))))
                    edge_count += 1
            stream.write("]}}\n")
        temporary_file.replace(output_file)
    except Exception:
        # A write/model failure must not look like a successful empty graph.
        logger.exception("Failed to write %s; conversion is incomplete", output_file)
        raise
    logger.info(
        "Wrote %s (%d SQL-to-SCCM relationships, no source label)",
        output_file,
        edge_count,
    )


# Array properties whose element order carries meaning and must be preserved.
# `object_class` arrives straight from LDAP in class-hierarchy order (top, leaf,
# connectionPoint, serviceConnectionPoint, ...), which is how a reader expects to see it
# and is already reproducible run to run, so sorting it would destroy information for no
# gain. Add to this set only for an array whose order a *reader* relies on — not merely
# one that happens to look tidy today.
_ORDER_SIGNIFICANT_PROPERTIES = frozenset({"objectClass"})


def _normalize_properties(content: dict) -> dict:
    """Prepare a node/edge's `properties` dict for emit: drop nulls, sort arrays.

    This is the single point every node and edge flows through before being written, so
    both normalizations live here rather than at the ~20 places that build arrays.

    **Nulls are dropped** because BloodHound's OpenGraph schema accepts a property value
    of string/number/boolean/array but NOT null, so an absent attribute must be omitted
    entirely rather than emitted as JSON null (missing != null is the BloodHound
    convention). Our models default optional attributes to None, and the
    dataclasses.asdict() + json.dumps path the destination uses keeps those as null —
    unlike the framework's Pydantic exclude_none path.

    **Arrays are sorted** because they are aggregated in DuckDB with `list()` /
    `array_agg()`, which give no ordering guarantee and run multi-threaded: two converts
    over byte-identical input emit the same elements in different orders. Verified by
    reprocessing one cached bucket twice, which differed in `collectionIds`,
    `siteSystemRoles`, `coercionVictimHostnames`, and
    `coercionVictimAndRelayTargetPairs`. That cost twice over — BloodHound saw a property
    change on re-ingest when nothing had changed, and any run-to-run graph diff (the basis
    of a parity check) drowned in false positives. These arrays are unordered sets of facts
    for an entity panel, so a stable order loses nothing; the exceptions are named in
    `_ORDER_SIGNIFICANT_PROPERTIES` above.

    Sorting here rather than in the SQL is deliberate: it is one place instead of twenty,
    it covers any array added later for free, and it cannot be partially applied — a
    half-sorted set of aggregations is harder to reason about than none.
    """
    props = content.get("properties")
    if not isinstance(props, dict):
        return content

    dropped = [k for k, v in props.items() if v is None]
    if dropped:
        props = {k: v for k, v in props.items() if v is not None}
        logger.debug("Omitted null-valued properties before emit: %s", dropped)

    # Sort in place on the (already copied or original) mapping. Mixed-type arrays would
    # make `sorted` raise, so fall back to leaving such an array alone rather than failing
    # the whole convert over a property nobody sorted before.
    reordered = []
    for key, value in props.items():
        if not isinstance(value, list) or key in _ORDER_SIGNIFICANT_PROPERTIES:
            continue
        try:
            ordered = sorted(value)
        except TypeError:
            logger.debug("Left %r unsorted: elements are not mutually comparable", key)
            continue
        if ordered != value:
            props[key] = ordered
            reordered.append(key)
    if reordered:
        logger.debug("Sorted array properties for reproducible output: %s", reordered)

    content["properties"] = props
    return content


def emit_graph_from_duckdb(
    lookup: SCCMLookup,
    output_path,
    source_kind: str | None,
    node_specs: list[tuple[str, type]] | None = None,
    edge_specs: list[tuple[str, type]] | None = None,
    resource_prefix: str = "sccm",
) -> None:
    """Read node/edge tables from the lookup DuckDB and write OpenGraph JSON to output_path.

    node_specs and edge_specs are lists of (table_name, ModelClass) pairs. For each row in
    each table, the model is instantiated with the row dict, given access to the lookup, and
    its as_node / edges properties are called to produce OpenGraph content.

    source_kind supplies metadata.source_kind for custom output. None omits the
    metadata block so AD records retain their native ownership. Common owns the
    file mechanics; this collector still owns every graph and routing rule.

    resource_prefix names the output file sets (<prefix>_nodes / <prefix>_edges)
    so the three passes into the same directory stay separate.

    Passing empty lists for both specs produces an empty but valid OpenGraph output.
    """
    out = Path(output_path)
    out.mkdir(parents=True, exist_ok=True)

    # Default to empty specs so the pipeline always runs cleanly.
    node_specs = node_specs or []
    edge_specs = edge_specs or []

    def nodes():
        for table, model in node_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                node = obj.as_node
                if node is not None:
                    content = _normalize_properties(asdict(node))
                    # Keep the specific kind first; the broad kind lets BloodHound
                    # group nodes by service. Native AD nodes need no added kind.
                    for environment_kind in (nk.SCCM, nk.MSSQL):
                        if any(
                            kind.startswith(f"{environment_kind}_")
                            for kind in node.kinds
                        ):
                            content["kinds"].append(environment_kind)
                            logger.debug(
                                "Node %s: added kind %s", node.id, environment_kind
                            )
                            break
                        # A different kind is routine; leave its properties alone.
                    yield content
                else:
                    # as_node returns None for rows that can't be keyed (no SID, etc.).
                    # The model logs a warning internally; nothing to emit here.
                    logger.debug(
                        "emit_graph_from_duckdb: %s row produced no node (table=%r)",
                        model.__name__,
                        table,
                    )

    def edges():
        for table, model in edge_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                parts = [_normalize_properties(asdict(e)) for e in obj.edges]
                if parts:
                    yield from parts
                else:
                    logger.debug(
                        "emit_graph_from_duckdb: %s row produced no edges (table=%r)",
                        model.__name__,
                        table,
                    )

    with GraphFileWriter(out, {resource_prefix: source_kind}) as writer:
        for content in nodes():
            writer.write_node(resource_prefix, content)
        for content in edges():
            writer.write_edge(resource_prefix, content)
    kind_label = source_kind if source_kind is not None else "<untagged AD payload>"
    logger.info(
        "Convert2-Read-DB wrote OpenGraph files (prefix=%r, source_kind=%s) to %s",
        resource_prefix,
        kind_label,
        out,
    )
