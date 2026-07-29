# src/openhound_sccm/convert_pipeline.py
"""Convert-time pipeline (Convert2-Read-DB): read node_* tables and graph_edges from the preproc
DuckDB and emit them as OpenGraph nodes/edges.

The framework's built-in convert reader only globs JSONL from the bucket, so a
coalesced DuckDB table can't be iterated by it. We run our own dlt pipeline that reads
DuckDB directly via the open lookup connection -> opengraph_file. See
docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md §4.

Stage 1+ replaces the Stage-0 spike shapers with typed models driven by node_specs
and edge_specs. Each spec is a (table_name, ModelClass) pair; for every row the model
is instantiated, the lookup is injected, and as_node / edges produce the OpenGraph
content.
"""
import logging
from dataclasses import asdict
from pathlib import Path

import dlt
from openhound.destinations.opengraph.destination import opengraph_file

from .lookup import SCCMLookup
from .opengraph_untagged import opengraph_file_untagged

logger = logging.getLogger(__name__)


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

    source_kind controls the writer: a string routes through core's opengraph_file, which
    stamps {"metadata": {"source_kind": ...}}; None routes through opengraph_file_untagged,
    which writes no metadata block at all (the AD payload, merged natively by BloodHound).

    resource_prefix names the two dlt resources (<prefix>_nodes / <prefix>_edges), which
    become the output file basenames, and the dlt pipeline — so two passes into the same
    output directory never collide.

    Passing empty lists for both specs produces an empty but valid OpenGraph output.
    """
    out = Path(output_path)
    # The opengraph_file destination opens files without creating the dir, and this runs
    # before the framework would create output_path — so make it ourselves.
    out.mkdir(parents=True, exist_ok=True)

    # Default to empty specs so the pipeline always runs cleanly.
    node_specs = node_specs or []
    edge_specs = edge_specs or []

    @dlt.resource(name=f"{resource_prefix}_nodes")
    def nodes():
        for table, model in node_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                node = obj.as_node
                if node is not None:
                    content = _normalize_properties(asdict(node))
                    yield {"graph": {"entity_type": "node", "content": content}}
                else:
                    # as_node returns None for rows that can't be keyed (no SID, etc.).
                    # The model logs a warning internally; nothing to emit here.
                    logger.debug(
                        "emit_graph_from_duckdb: %s row produced no node (table=%r)",
                        model.__name__,
                        table,
                    )

    @dlt.resource(name=f"{resource_prefix}_edges")
    def edges():
        for table, model in edge_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                # Edge content is a LIST: the destination does edges.extend(content).
                parts = [_normalize_properties(asdict(e)) for e in obj.edges]
                if parts:
                    yield {"graph": {"entity_type": "edge", "content": parts}}
                else:
                    logger.debug(
                        "emit_graph_from_duckdb: %s row produced no edges (table=%r)",
                        model.__name__,
                        table,
                    )

    destination = (
        opengraph_file_untagged(output_path=str(out))
        if source_kind is None
        else opengraph_file(output_path=str(out), source_kind=source_kind)
    )
    pipeline = dlt.pipeline(
        pipeline_name=f"sccm_convert_graph_{resource_prefix}",
        dataset_name="sccm",
        destination=destination,
    )
    pipeline.run([nodes(), edges()])
    kind_label = source_kind if source_kind is not None else "<untagged AD payload>"
    logger.info(
        "Convert2-Read-DB convert pipeline wrote OpenGraph files (prefix=%r, source_kind=%s) to %s",
        resource_prefix, kind_label, out,
    )
