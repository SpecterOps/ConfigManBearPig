# tour_driver.py — set the breakpoints listed below, then debug THIS file.
import tempfile
from pathlib import Path

import duckdb

import openhound_sccm.main as m              # importing registers @app.collect/@app.preproc/@app.convert
from openhound_sccm.transforms import transforms

work = Path(tempfile.mkdtemp(prefix="sccm_tour_"))
db = work / "lookup.duckdb"

# --- preproc: build the spike tables exactly as @app.preproc's transformer does ---
con = duckdb.connect(str(db))
transforms(con)                              # Stop 1 lives in here
con.close()

# --- convert: app.converter IS the framework's run_convert. It opens the lookup
#     read-only, builds SCCMLookup(client), calls our convert(ctx) -> emit_graph_from_duckdb,
#     then runs Converter.run with the no-op source. Stops 2-4 all fire under this one call. ---
m.app.converter(input_path=work, output_path=work / "graph", lookup_file=db)

print("TOUR OUTPUT:", [p.name for p in (work / "graph").glob("*.json")])
print("WORKDIR:", work)