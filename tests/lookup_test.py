# src/openhound_sccm/lookup_test.py
import duckdb
import pytest
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


def test_table_rows_missing_required_table_raises(tmp_path):
    client = duckdb.connect(_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    with pytest.raises(duckdb.CatalogException):
        list(lookup.table_rows("does_not_exist"))
    client.close()


def test_empty_prepared_table_is_a_successful_empty_result():
    with duckdb.connect(":memory:") as client:
        client.execute("CREATE SCHEMA sccm")
        client.execute("CREATE TABLE sccm.node_site (id VARCHAR)")
        assert list(SCCMLookup(client).table_rows("node_site")) == []
