"""A failed EPA measurement preserves independently collected SQL host facts."""

from types import SimpleNamespace

import pytest

from openhound_sccm.clients.mssql_epa import EPAPrereqError
from openhound_sccm.collectors import mssql


def test_inconclusive_epa_keeps_sql_row_then_reports_incomplete(monkeypatch):
    context = SimpleNamespace(
        method_enabled=lambda _: True,
        ad=SimpleNamespace(get_spns=lambda _: ["MSSQLSvc/ps1-db.mayyhem.com:1433"]),
        domain="mayyhem.com", username="alice", password="example",
        nt_hash=None, kerberos_ticket=None, target_hosts_by_hostname={},
    )
    monkeypatch.setattr(mssql, "_check_port", lambda *args: True)

    def inconclusive(**kwargs):
        raise EPAPrereqError("EPA bogus_cbt probe was inconclusive")

    monkeypatch.setattr(mssql, "test_epa", inconclusive)
    rows = iter(mssql.collect_mssql("ps1-db.mayyhem.com", context))
    table, row = next(rows)
    assert table == "mssql_server_instances"
    assert row["port"] == 1433 and row["has_mssql_spn"] is True
    assert row["extended_protection"] is None
    with pytest.raises(EPAPrereqError):
        next(rows)
