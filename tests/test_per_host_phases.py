"""Tests for the SCCM per-host phase list and stub collectors.

The phases are the ordered per-host steps; for this framework build they point
at deterministic stubs. One stub (HTTP) discovers a new target to exercise
recursion; one (AdminService) writes to several tables.
"""
from openhound_sccm.collectors import stubs
from tests.per_host_phases_test import PER_HOST_PHASES, all_table_names


class FakeCtx:
    """Minimal stand-in capturing register_target calls."""

    def __init__(self):
        self.registered = []

    def register_target(self, identifier, source=None, **kwargs):
        self.registered.append((identifier, source))
        return None


def test_phase_names_in_expected_order():
    assert [p.name for p in PER_HOST_PHASES] == [
        "RemoteRegistry", "MSSQL", "AdminService", "HTTP", "SMB",
    ]


def test_all_table_names_is_deduped_union_including_adminservice_tables():
    tables = all_table_names(PER_HOST_PHASES)
    assert len(tables) == len(set(tables))           # no duplicates
    assert "adminservice_admin_users" in tables
    assert "adminservice_client_devices" in tables


def test_stub_remote_registry_is_deterministic():
    first = list(stubs.stub_remote_registry("hostA", None))
    second = list(stubs.stub_remote_registry("hostA", None))
    assert first == [("registry_sccm_components", {"name": "hostA"})]
    assert first == second


def test_adminservice_stub_writes_more_than_one_table():
    tables = {table for table, _row in stubs.stub_adminservice("hostA", None)}
    assert len(tables) >= 2
    assert tables <= {"adminservice_admin_users", "adminservice_client_devices"}


def test_http_stub_discovers_one_target_and_still_yields_its_row():
    ctx = FakeCtx()
    rows = list(stubs.stub_http("hostA", ctx))
    assert ctx.registered == [("hostA-discovered", "STUB-HTTP")]
    assert any(table == "http_management_points" for table, _row in rows)


def test_http_stub_does_not_recurse_on_an_already_discovered_target():
    ctx = FakeCtx()
    rows = list(stubs.stub_http("hostA-discovered", ctx))
    assert ctx.registered == []                       # no further discovery
    assert any(table == "http_management_points" for table, _row in rows)


def test_every_stub_only_writes_tables_its_phase_declares():
    ctx = FakeCtx()
    for phase in PER_HOST_PHASES:
        for table, _row in phase.run("hostA", ctx):
            assert table in phase.streams
