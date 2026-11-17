"""Site mappings prefer collected answers and explain every port assumption."""

from types import SimpleNamespace

import duckdb
import pytest

from openhound_collector_common.discovery.sql_server import SqlAddress
from openhound_sccm.collectors import registry, sql_site
from openhound_sccm.site_database import resolve_site_databases

HOST = "ps1-sec.mayyhem.com"
SID = "S-1-5-21-1-2-3-1200"


@pytest.fixture
def connection():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("""
        CREATE TABLE sccm._mssql_sql_servers (
            site_code VARCHAR, root_site_code VARCHAR, host_sid VARCHAR,
            dns_host_name VARCHAR, port VARCHAR, db_name VARCHAR,
            service_account_name VARCHAR, service_account_sid VARCHAR,
            basis VARCHAR, collection_source VARCHAR[], resolved_port VARCHAR)
    """)
    con.execute("INSERT INTO sccm._mssql_sql_servers VALUES ('SEC','PS1',?,?,NULL,NULL,NULL,NULL,'RemoteRegistry',['RemoteRegistry-SiteSystemRole'],NULL)", [SID, HOST])
    con.execute("CREATE TABLE sccm.remoteregistry_mssql_servers (domain_computer_sid VARCHAR, port INTEGER, instance_name VARCHAR, is_static_port BOOLEAN)")
    con.execute("CREATE TABLE sccm.mssql_server_instances (domain_computer_sid VARCHAR, port INTEGER, instance_name VARCHAR, epa_measured BOOLEAN, port_open BOOLEAN, source VARCHAR)")
    yield con
    con.close()


def add_listener(con, port, *, is_static=True, answered=True, instance="CONFIGMGRSEC"):
    con.execute("INSERT INTO sccm.remoteregistry_mssql_servers VALUES (?,?,?,?)", [SID, port, instance, is_static])
    con.execute("INSERT INTO sccm.mssql_server_instances VALUES (?,?,?,?,?,'MSSQL-ScanForEPA')", [SID, port, instance, answered, answered])


def choice(con, disable_possible=False):
    resolve_site_databases(con, "sccm", disable_possible)
    return con.execute("SELECT port, db_name, assumed, assumption_basis FROM sccm._mssql_sql_servers").fetchone()


@pytest.mark.parametrize("unread_port", [None, "1433.5", "1e3", "70000", "0"])
def test_missing_or_invalid_information_retains_explained_default_port(connection, unread_port):
    connection.execute("UPDATE sccm._mssql_sql_servers SET port=?", [unread_port])
    port, database, assumed, reason = choice(connection)
    assert (port, database, assumed) == ("1433", "CM_SEC", True)
    assert "1433 assumed" in reason


def test_strict_mode_omits_default_port_mapping(connection):
    assert choice(connection, disable_possible=True) is None


def test_explicit_sccm_port_wins_over_other_listeners(connection):
    connection.execute("UPDATE sccm._mssql_sql_servers SET port='51433', db_name='CONFIGMGRSEC\\CM_SEC'")
    add_listener(connection, 1433)
    assert choice(connection) == ("51433", "CONFIGMGRSEC\\CM_SEC", False, None)


def test_site_server_registry_supplies_its_own_database_and_port(connection):
    connection.execute("""
        CREATE TABLE sccm.remoteregistry_site_databases AS
        SELECT 'SEC' AS site_code, ? AS domain_computer_sid,
            51433 AS sql_service_port, ? AS sql_database_name
    """, [SID, "CONFIGMGRSEC\\CM_SEC"])
    assert choice(connection) == ("51433", "CONFIGMGRSEC\\CM_SEC", False, None)


def test_provider_port_wins_over_site_server_registry(connection):
    connection.execute("UPDATE sccm._mssql_sql_servers SET port='51433', db_name='CM_SEC'")
    connection.execute("CREATE TABLE sccm.remoteregistry_site_databases AS SELECT 'SEC' AS site_code, ? AS domain_computer_sid, 1433 AS sql_service_port", [SID])
    assert choice(connection)[0] == "51433"


def test_sccm_named_database_selects_matching_instance(connection):
    connection.execute("UPDATE sccm._mssql_sql_servers SET db_name='CONFIGMGRSEC\\CM_SEC'")
    add_listener(connection, 51433, is_static=False)
    add_listener(connection, 1433, instance="OTHER")
    # Here the site identifies the instance: its observed port need not be static
    # to establish the match, even though dynamic SCCM configurations are unsupported.
    assert choice(connection) == ("51433", "CONFIGMGRSEC\\CM_SEC", False, None)


def test_browser_answer_for_sccms_instance_precedes_static_inference(connection):
    connection.execute("UPDATE sccm._mssql_sql_servers SET resolved_port='51433', db_name='CONFIGMGRSEC\\CM_SEC'")
    add_listener(connection, 1433)
    assert choice(connection) == ("51433", "CONFIGMGRSEC\\CM_SEC", False, None)


def test_only_static_sql_listener_is_an_explained_inference(connection):
    add_listener(connection, 51433)
    port, _, assumed, reason = choice(connection)
    assert (port, assumed) == ("51433", True)
    assert "only observed static SQL listener" in reason


def test_static_inference_is_omitted_in_strict_mode(connection):
    add_listener(connection, 51433)
    assert choice(connection, disable_possible=True) is None


@pytest.mark.parametrize("is_static,answered", [(False, True), (None, True), (True, False)])
def test_dynamic_unknown_or_unanswered_ports_cannot_satisfy_static_rule(connection, is_static, answered):
    add_listener(connection, 51433, is_static=is_static, answered=answered)
    assert choice(connection)[0] == "1433"


def test_two_static_sql_listeners_do_not_select_an_arbitrary_one(connection):
    add_listener(connection, 51433)
    add_listener(connection, 51434, instance="OTHER")
    assert choice(connection)[0] == "1433"


def test_dynamic_evidence_conflict_prevents_static_inference(connection):
    add_listener(connection, 51433)
    add_listener(connection, 51433, is_static=False)
    assert choice(connection)[0] == "1433"


def test_unrelated_hosts_port_cannot_identify_this_sites_instance(connection):
    add_listener(connection, 51433)
    connection.execute("UPDATE sccm.remoteregistry_mssql_servers SET domain_computer_sid='S-OTHER'")
    assert choice(connection)[0] == "1433"


def test_registry_collection_retains_site_host_database_and_port():
    values = [("Server", HOST), ("Database Name", "CONFIGMGRSEC\\CM_SEC"), ("Port", "51433"), ("SSBPort", "4022")]
    probe = SimpleNamespace(hostname=HOST, read_values=lambda key: values)
    entry = SimpleNamespace(ad_object={"object_sid": SID})
    ctx = SimpleNamespace(register_target=lambda *args, **kwargs: entry)
    table, row = next(registry.get_site_database(probe, ctx, "SEC"))
    assert table == "remoteregistry_site_databases"
    assert row["sql_service_port"] == 51433
    assert row["sql_database_name"] == "CONFIGMGRSEC\\CM_SEC"
    assert row["domain_computer_sid"] == SID


def test_denied_site_mapping_keeps_other_discovery_usable():
    probe = SimpleNamespace(hostname=HOST, read_values=lambda key: None)
    assert list(registry.get_site_database(probe, SimpleNamespace(), "SEC")) == []


def test_matching_registry_instance_port_does_not_need_browser():
    entry = SimpleNamespace(sql_instances=[SqlAddress(HOST, 1433, "OTHER"), SqlAddress(HOST, 51433, "CONFIGMGRSEC")])
    ctx = SimpleNamespace(method_enabled=lambda method: True, target_hosts_by_hostname={HOST: entry})
    assert sql_site.resolve_site_sql_port(ctx, HOST, "CONFIGMGRSEC\\CM_SEC") == 51433


def test_site_instance_is_sent_to_browser_when_registry_cannot_resolve_it():
    calls = []
    def resolve(host, instance, **kwargs):
        calls.append((host, instance))
        return 51433
    ctx = SimpleNamespace(method_enabled=lambda method: True, target_hosts_by_hostname={HOST: SimpleNamespace(sql_instances=[])}, sql_browser=SimpleNamespace(resolve=resolve))
    assert sql_site.resolve_site_sql_port(ctx, HOST, "CONFIGMGRSEC\\CM_SEC") == 51433
    assert calls == [(HOST, "CONFIGMGRSEC")]


def test_excluded_site_sql_host_is_never_contacted():
    ctx = SimpleNamespace(method_enabled=lambda method: True, target_hosts_by_hostname={}, register_target=lambda *args, **kwargs: None)
    assert sql_site.resolve_site_sql_port(ctx, HOST, "CM_SEC") is None


@pytest.mark.parametrize("dynamic,expected", [("", True), (None, None), ("0", False), ("51433", False)])
def test_static_classification_requires_an_explicitly_disabled_dynamic_setting(dynamic, expected):
    probe = SimpleNamespace(
        hostname=HOST,
        read_dword=lambda key, name: 1,
        read_value=lambda key, name: "51433" if name == "TcpPort" else dynamic,
    )
    assert registry._mssql_tcp_port_settings(probe, "Network")[51433] is expected


@pytest.mark.parametrize("enabled", [None, 0])
def test_disabled_or_unread_tcp_cannot_establish_a_static_listener(enabled):
    probe = SimpleNamespace(
        hostname=HOST,
        read_dword=lambda key, name: enabled if name == "Enabled" else 1,
        read_value=lambda key, name: "51433" if name == "TcpPort" else "",
    )
    settings = registry._mssql_tcp_port_settings(probe, "Network")
    assert settings.get(51433) is None
