"""A broken SQL statement must be visible to the caller, not just the logs."""

import duckdb
import pytest

from openhound_sccm.transforms import _safe


def test_sql_bug_propagates_after_logging(caplog):
    with duckdb.connect(":memory:") as connection:
        with pytest.raises(duckdb.BinderException):
            _safe(connection, "required-column", "SELECT misspelled FROM (SELECT 1 AS actual)")
    assert "required-column" in caplog.text and "failed" in caplog.text


def test_missing_optional_raw_table_remains_an_expected_skip():
    with duckdb.connect(":memory:") as connection:
        _safe(connection, "optional-source", "SELECT * FROM no_collected_table")
