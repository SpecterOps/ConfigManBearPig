import duckdb
import pytest
from openhound_sccm.transforms import _read_disable_possible


def _con(table_value):
    con = duckdb.connect()
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    if table_value is not None:
        con.execute(
            "CREATE TABLE sccm.collection_settings AS "
            f"SELECT {str(bool(table_value)).lower()} AS disable_possible_edges"
        )
    # table_value is None -> no collection_settings table at all (older collection)
    return con


def test_env_unset_uses_table_true(monkeypatch):
    monkeypatch.delenv("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", raising=False)
    assert _read_disable_possible(_con(True), "sccm") is True


def test_env_unset_uses_table_false(monkeypatch):
    monkeypatch.delenv("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", raising=False)
    assert _read_disable_possible(_con(False), "sccm") is False


def test_env_truthy_overrides_table_false(monkeypatch):
    monkeypatch.setenv("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", "true")
    assert _read_disable_possible(_con(False), "sccm") is True


@pytest.mark.parametrize("val", ["1", "TRUE", "Yes", "on"])
def test_env_truthy_spellings(monkeypatch, val):
    monkeypatch.setenv("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", val)
    assert _read_disable_possible(_con(False), "sccm") is True


def test_env_falsey_cannot_loosen_table_true(monkeypatch):
    # tightening-only: env 'false' must NOT re-enable when the table already disabled.
    monkeypatch.setenv("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", "false")
    assert _read_disable_possible(_con(True), "sccm") is True


def test_env_falsey_and_table_false_is_false(monkeypatch):
    monkeypatch.setenv("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", "0")
    assert _read_disable_possible(_con(False), "sccm") is False


def test_env_truthy_when_settings_table_absent(monkeypatch):
    # older collection (no collection_settings table) + env override -> True
    monkeypatch.setenv("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", "true")
    assert _read_disable_possible(_con(None), "sccm") is True
