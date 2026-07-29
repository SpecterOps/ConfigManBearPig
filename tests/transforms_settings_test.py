# src/openhound_sccm/transforms_settings_test.py
import duckdb
from openhound_sccm.transforms import _read_disable_possible


def test_read_disable_possible_absent_defaults_false():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    assert _read_disable_possible(con, "sccm") is False


def test_read_disable_possible_true():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.collection_settings AS "
                "SELECT true AS disable_possible_edges, false AS enable_bad_opsec")
    assert _read_disable_possible(con, "sccm") is True


def test_read_disable_possible_false():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.collection_settings AS "
                "SELECT false AS disable_possible_edges, false AS enable_bad_opsec")
    assert _read_disable_possible(con, "sccm") is False


def test_read_disable_possible_column_dropped_defaults_false():
    # FAMILY-1: collection_settings can EXIST while disable_possible_edges is
    # MISSING from it -- dlt drops a column that is all-NULL/all-False across an
    # entire load, the exact production shape C1/I1 were bitten by elsewhere in
    # this same file. BinderException is a sibling of CatalogException, not a
    # subclass, and this function is called first and unwrapped from
    # transforms() -- an uncaught BinderException here would abort the entire
    # preprocess run, not just default one setting.
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.collection_settings AS SELECT false AS enable_bad_opsec")
    assert _read_disable_possible(con, "sccm") is False   # must not raise
