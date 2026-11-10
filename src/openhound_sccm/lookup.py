# src/openhound_sccm/lookup.py
"""DuckDB lookup helpers for the SCCM convert phase.

`SCCMLookup` is injected into convert as `ctx.lookup` and as `self._lookup` on each
model. Stage 0 needs only `table_rows`, the streaming iterator the Convert2-Read-DB convert pipeline
reads. Cached point/list lookups (for edge resolution) are added in later stages.
"""
import logging
from collections.abc import Iterator

from duckdb import DuckDBPyConnection, Error
from openhound.core.lookup import LookupManager

logger = logging.getLogger(__name__)


class SCCMLookup(LookupManager):
    def __init__(self, client: DuckDBPyConnection, schema: str = "sccm"):
        # The framework constructs this as `lookup(client)` (one arg), so schema must default.
        super().__init__(client, schema)

    def table_rows(self, table: str) -> Iterator[dict]:
        """Yield each row of {schema}.{table} as a column-named dict.

        These are prepared tables: preprocessing creates them even when empty.
        A missing or unreadable table is incomplete work and must reach the caller.
        An independent cursor protects other scans and is closed on early exit.
        """
        try:
            with self.client.cursor() as cur:
                cur.execute(f"SELECT * FROM {self.schema}.{table}")
                cols = [c[0] for c in cur.description]
                while True:
                    batch = cur.fetchmany(2000)
                    if not batch:
                        break  # An exhausted successful query has no more rows.
                    for row in batch:
                        yield dict(zip(cols, row))
        except Error as err:
            logger.error("Required prepared table %r could not be read: %s", table, err)
            raise
