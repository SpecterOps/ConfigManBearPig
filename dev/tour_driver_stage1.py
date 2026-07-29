# tour_driver_stage1.py — Stage 1 code tour. Set the breakpoints listed in
# docs/superpowers/plans/2026-06-17-sccm-preproc-convert-stage1-validation.md,
# then debug THIS file (launch profile "Debug: Stage 1 code tour").
#
# Unlike tour_driver.py (Stage 0, empty DB → empty graph), this seeds a minimal
# but genuinely-structured dataset so the full preproc→convert path produces a
# real Computer node, two SCCM_Site nodes, and the SCCM_AdminsReplicatedTo edges.
#
# Load step: the real preproc loads the collected JSONL into DuckDB with dlt and
# THEN runs transforms(). This tour loads the two seeded tables into DuckDB
# directly (read_json_auto) before calling transforms() — same end state for the
# Stage-1 code under tour (coalesces, models, emit pipeline), without standing up
# the framework's 30-table dlt load. For a production-faithful check, run the real
# CLI on collected data instead:  openhound preproc sccm <bucket> <db> ; openhound convert sccm <bucket> <out> --lookup-file <db>
import gzip
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

# Create the disposable work dir first and point dlt's pipeline state at it instead
# of the default ~/.dlt. On Windows, files dlt writes under the user profile (~/.dlt)
# get briefly locked by the Search Indexer / endpoint agents right after they're
# written, so dlt's atomic rename/remove fails with WinError 32 — intermittently, and
# leaving a stuck "pending package" that re-trips on the next run. A fresh per-run dir
# under %TEMP% is excluded from indexing and starts clean. Must be set BEFORE importing
# dlt/openhound so dlt resolves its data dir to this path.
work = Path(tempfile.mkdtemp(prefix="sccm_stage1_tour_"))
os.environ["DLT_DATA_DIR"] = str(work / "dlt_home")

import duckdb

import openhound_sccm.main as m               # importing registers @app.preproc/@app.convert
from openhound_sccm.transforms import transforms

# Show the tour's log messages in the terminal by default: the _ensure_columns
# "added column" lines, the per-source "_safe skipped/failed" messages, and the
# node_* "built" lines. Our package is DEBUG; dlt stays WARNING so its internal
# debug firehose doesn't bury the messages we care about. force=True replaces the
# framework's import-time handlers (incl. the rotating file handler behind the
# benign WinError 32 log-rollover noise) so everything lands on stdout cleanly.
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-7s %(name)s: %(message)s",
    stream=sys.stdout,
    force=True,
)
logging.getLogger("openhound_sccm").setLevel(logging.DEBUG)
logging.getLogger("dlt").setLevel(logging.WARNING)

db = work / "lookup.duckdb"


def _gz(table: str, rows: list[dict]) -> None:
    """Write rows as gzipped JSONL under <work>/sccm/<table>/ (the collector's layout)."""
    d = work / "sccm" / table
    d.mkdir(parents=True, exist_ok=True)
    with gzip.open(d / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


# adminservice_r_system — one computer with a real S-1-5-21 SID.
# system_roles is a comma string here; the coalesce normalises it to an array.
_gz("adminservice_r_system", [{
    "name": "HOST1",
    "sid": "S-1-5-21-111-222-333-1104",
    "obsolete": False,
    "resource_id": 7,
    "source_site_code": "PS1",
    "system_roles": "SMS Provider",
    "sms_unique_identifier": "GUID:tour-abc",
    "security_group_name": [],            # no groups on this host for this tour
}])

# adminservice_site_definitions — CAS + Primary so _site_hierarchy resolves the root.
_gz("adminservice_site_definitions", [
    {"site_code": "CAS", "parent_site_code": None, "site_type": 4,
     "site_guid": "GUID-CAS", "sql_server_name": "sql-cas.lab", "sql_database_name": "CM_CAS"},
    {"site_code": "PS1", "parent_site_code": "CAS", "site_type": 2,
     "site_guid": "GUID-PS1", "sql_server_name": "sql-ps1.lab", "sql_database_name": "CM_PS1"},
])

# --- preproc: load the seeded JSONL into DuckDB, then run transforms() exactly as
#     @app.preproc does. Breakpoint Stops 1, 2, 3, 6 (transforms.py) fire in here. ---
con = duckdb.connect(str(db))
con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
for table in ("adminservice_r_system", "adminservice_site_definitions"):
    src = (work / "sccm" / table / "data.jsonl.gz").as_posix()
    con.execute(
        f"CREATE TABLE sccm.{table} AS "
        f"SELECT * FROM read_json_auto('{src}', format='newline_delimited')"
    )
transforms(con)                              # Stops 1, 2, 3, 6 live in here
con.close()

# --- convert: app.converter IS the framework's run_convert. It opens the lookup
#     read-only, builds SCCMLookup(client), calls our convert(ctx) -> emit_graph_from_duckdb
#     (which instantiates the models — Stops 4, 5, 7 fire here), then runs Converter.run
#     with the no-op source (Stops 8, 9). ---
m.app.converter(input_path=work, output_path=work / "graph", lookup_file=db)

print("TOUR OUTPUT:", [p.name for p in (work / "graph").glob("*.json")])
print("WORKDIR:", work)
