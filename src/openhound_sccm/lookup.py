# src/openhound_sccm/lookup.py
"""DuckDB lookup helpers for the SCCM convert phase.

`SCCMLookup` is injected into convert as `ctx.lookup` and as `self._lookup` on each
model. Stage 0 needs only `table_rows`, the streaming iterator the Convert2-Read-DB convert pipeline
reads. Cached point/list lookups (for edge resolution) are added in later stages.
"""
import logging
from collections.abc import Iterator

from duckdb import DuckDBPyConnection
from openhound.core.lookup import LookupManager

logger = logging.getLogger(__name__)


class SCCMLookup(LookupManager):
    def __init__(self, client: DuckDBPyConnection, schema: str = "sccm"):
        # The framework constructs this as `lookup(client)` (one arg), so schema must default.
        super().__init__(client, schema)

    def table_rows(self, table: str) -> Iterator[dict]:
        """Yield each row of {schema}.{table} as a column-named dict.

        Uses an independent cursor so this streaming scan never clobbers the active
        result of other `self._lookup` queries that share the connection.
        """
        try:
            cur = self.client.cursor()
            cur.execute(f"SELECT * FROM {self.schema}.{table}")
        except Exception as err:
            # Missing/!readable table — log and yield nothing so a not-yet-built table
            # can't crash convert.
            logger.warning("SCCMLookup.table_rows(%r) failed: %s", table, err)
            return
        cols = [c[0] for c in cur.description]
        while True:
            batch = cur.fetchmany(2000)
            if not batch:
                break
            for row in batch:
                yield dict(zip(cols, row))
