# src/openhound_sccm/lookup_test.py
import duckdb
from openhound_sccm.lookup import SCCMLookup


def _db(tmp_path):
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.node_spike AS SELECT 'SPIKE-1' AS id, 'spike' AS name")
    con.close()
    return str(path)


def test_table_rows_yields_dicts(tmp_path):
    client = duckdb.connect(_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)               # one-arg construction, schema defaults to "sccm"
    rows = list(lookup.table_rows("node_spike"))
    assert rows == [{"id": "SPIKE-1", "name": "spike"}]


def test_table_rows_missing_table_is_empty(tmp_path):
    client = duckdb.connect(_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    assert list(lookup.table_rows("does_not_exist")) == []
