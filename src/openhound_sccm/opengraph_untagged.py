"""Convert-time OpenGraph file destination that writes NO `metadata` block.

Core's `opengraph_file` (openhound.destinations.opengraph.destination) always writes
`{"graph": {...}, "metadata": {"source_kind": ...}}` and requires a `source_kind`. The AD
payload must carry no `source_kind` at all — a file with no `metadata` block — so BloodHound
merges its Computer/User/Group/stub nodes into the native AD graph (and existing SharpHound
data) instead of registering them under a custom SCCM source. Core is off-limits, so the
extension ships this sibling writer. It is identical to core's writer except the `metadata`
block is omitted entirely. See ARCHITECTURE.md §11f.
"""
import logging
from collections import defaultdict
from pathlib import Path

import dlt
from dlt.common import json
from dlt.common.schema import TTableSchema
from dlt.common.typing import TDataItems

logger = logging.getLogger(__name__)

# Per-table file-part counter, mirroring core's DEST_PART. Module-global so repeated
# pipeline.run() calls in one process keep numbering files uniquely.
_DEST_PART: defaultdict[str, int] = defaultdict(int)


@dlt.destination(skip_dlt_columns_and_tables=True, batch_size=1000)
def opengraph_file_untagged(
    items: TDataItems,
    table: TTableSchema,
    output_path: str = dlt.config.value,
):
    table_name = table.get("name") or "opengraph"
    _DEST_PART[table_name] += 1

    nodes = []
    edges = []
    for item in items:
        if item["graph"]["entity_type"] == "node":
            nodes.append(item["graph"]["content"])
        elif item["graph"]["entity_type"] == "edge":
            edges.extend(item["graph"]["content"])
        else:
            logger.warning(
                "opengraph_file_untagged: unexpected entity_type %r — item skipped",
                item["graph"]["entity_type"],
            )

    file_name = f"{table_name}-{_DEST_PART[table_name]}.json"
    file_path = Path(output_path) / file_name
    with file_path.open("w", encoding="utf-8") as fh:
        # No "metadata" block: BloodHound treats these nodes as native AD objects.
        fh.write(json.dumps({"graph": {"nodes": nodes, "edges": edges}}))
    logger.debug(
        "Wrote untagged OpenGraph file %s (%d nodes, %d edges)",
        file_path, len(nodes), len(edges),
    )
