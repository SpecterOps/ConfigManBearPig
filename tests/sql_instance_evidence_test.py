"""Different SQL engines must not borrow ports, accounts or protection values."""

import json
from types import SimpleNamespace

import duckdb
import pytest

from openhound_collector_common.discovery.sql_server import SqlAddress
from openhound_collector_common.discovery.sql_fallback import SqlPortFallback
from openhound_sccm.clients.mssql_epa import EPAPrereqError, EPAResult
from openhound_sccm.collectors import mssql, registry
from openhound_sccm.models.target_entry import TargetEntry
from openhound_sccm.transforms import transforms

HOST = "ps1-db.mayyhem.com"
HOST_SID = "S-1-5-21-1-2-3-1200"


def context(holders=()):
    entry = TargetEntry(
        HOST, {"object_sid": HOST_SID, "name": "PS1-DB", "dns_host_name": HOST}
    )
    return SimpleNamespace(
        ad=SimpleNamespace(
            find_mssql_spn_holders=lambda host: list(holders), get_spns=lambda host: []
        ),
        domain="mayyhem.com",
        username="reader",
        password="example",
        nt_hash=None,
        kerberos_ticket=None,
        credential_guard=None,
        method_enabled=lambda method: True,
        target_hosts_by_hostname={HOST: entry},
        sql_browser=SimpleNamespace(),
        sql_port_fallback=SqlPortFallback(),
    )


def holder(port, account):
    return {
        "spns": [f"MSSQLSvc/{HOST}:{port}"],
        "object_sid": f"S-1-5-21-1-2-3-{account}",
        "sam_account_name": f"sql{account}",
        "object_class": ["user"],
    }


def test_each_port_uses_its_own_account_and_protection_probe(monkeypatch):
    ctx = context([holder(1433, 2001), holder(51433, 2002)])
    calls = []
    monkeypatch.setattr(mssql, "_check_port", lambda *args: True)

    def probe(**arguments):
        calls.append((arguments["port"], arguments["spns"]))
        return EPAResult("Off" if arguments["port"] == 1433 else "Required")

    monkeypatch.setattr(mssql, "test_epa", probe)
    rows = [row for _, row in mssql.collect_mssql(HOST, ctx)]
    assert {
        (row["port"], row["service_account_name"], row["extended_protection"])
        for row in rows
    } == {(1433, "sql2001", "Off"), (51433, "sql2002", "Required")}
    assert calls == [
        (1433, [f"MSSQLSvc/{HOST}:1433"]),
        (51433, [f"MSSQLSvc/{HOST}:51433"]),
    ]


def test_conflicting_owners_are_saved_without_a_selected_service_account(monkeypatch):
    ctx = context([holder(51433, 2001), holder(51433, 2002)])
    monkeypatch.setattr(mssql, "_check_port", lambda *args: False)
    rows = [row for _, row in mssql.collect_mssql(HOST, ctx)]
    assert len(rows) == 1 and rows[0]["service_account_sid"] is None
    assert len(rows[0]["service_account_candidates"]) == 2


def test_unread_identity_cannot_make_another_registration_look_unambiguous(monkeypatch):
    unknown = holder(51433, 2002)
    unknown["object_sid"] = None
    ctx = context([holder(51433, 2001), unknown])
    monkeypatch.setattr(mssql, "_check_port", lambda *args: False)
    rows = [row for _, row in mssql.collect_mssql(HOST, ctx)]
    assert rows[0]["service_account_sid"] is None
    assert len(rows[0]["service_account_candidates"]) == 2


def test_unresolved_named_instance_saves_unknown_port_and_tries_anonymous_1433(monkeypatch):
    ctx = context(
        [
            {
                "spns": [f"MSSQLSvc/{HOST}:REPORTS"],
                "object_sid": "S-1",
                "sam_account_name": "sql",
                "object_class": ["user"],
            }
        ]
    )

    def unavailable(*args, **kwargs):
        raise TimeoutError("Browser did not answer")

    ctx.sql_browser.resolve = unavailable
    checked = []
    monkeypatch.setattr(mssql, "_check_port", lambda host, port: checked.append(port) or False)
    rows = iter(mssql.collect_mssql(HOST, ctx))
    assert next(rows)[1]["port"] is None
    with pytest.raises(EPAPrereqError):
        next(rows)
    assert checked == [1433]


@pytest.mark.parametrize("actual", ["REPORTS", "OTHER", None])
def test_fallback_only_attaches_the_account_after_sql_confirms_the_name(monkeypatch, actual):
    account = holder(1433, 2001)
    account["spns"] = [f"MSSQLSvc/{HOST}:REPORTS"]
    ctx = context([account])
    ctx.sql_browser.resolve = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("Browser unavailable"))
    monkeypatch.setattr(mssql, "_check_port", lambda *args: True)
    calls = []

    def probe(**arguments):
        calls.append(arguments)
        return EPAResult("Required", instance_name=actual)

    monkeypatch.setattr(mssql, "test_epa", probe)
    rows = []
    if actual == "REPORTS":
        rows = [row for _, row in mssql.collect_mssql(HOST, ctx)]
    else:
        with pytest.raises(EPAPrereqError):
            for _, row in mssql.collect_mssql(HOST, ctx):
                rows.append(row)
    assert len(calls) == 1 and calls[0]["identify_instance"] is True
    assert calls[0]["spns"] == []
    original, measured = rows
    assert original["port"] is None and original["instance_name"] == "REPORTS"
    assert measured["port"] == 1433 and measured["instance_name"] == actual
    assert measured["extended_protection"] == "Required"
    assert measured["service_account_sid"] == (account["object_sid"] if actual == "REPORTS" else None)


def test_multiple_unknown_names_and_known_1433_do_not_repeat_the_probe(monkeypatch):
    accounts = [holder(1433, 2001), holder(1433, 2002), holder(1433, 2003)]
    accounts[1]["spns"] = [f"MSSQLSvc/{HOST}:ONE"]
    accounts[2]["spns"] = [f"MSSQLSvc/{HOST}:TWO"]
    ctx = context(accounts)
    ctx.sql_browser.resolve = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("Browser unavailable"))
    calls = []
    monkeypatch.setattr(mssql, "_check_port", lambda host, port: calls.append(port) or False)
    with pytest.raises(EPAPrereqError):
        list(mssql.collect_mssql(HOST, ctx))
    assert calls == [1433]


def test_open_fallback_port_without_a_sql_result_creates_no_sql_node(monkeypatch):
    account = holder(1433, 2001)
    account["spns"] = [f"MSSQLSvc/{HOST}:REPORTS"]
    ctx = context([account])
    ctx.sql_browser.resolve = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("Browser unavailable"))
    monkeypatch.setattr(mssql, "_check_port", lambda *args: True)
    monkeypatch.setattr(mssql, "test_epa", lambda **kwargs: None)
    saved = []
    with pytest.raises(EPAPrereqError):
        for _, row in mssql.collect_mssql(HOST, ctx):
            saved.append(row)
    assert len(saved) == 1 and saved[0]["port"] is None


def test_failed_probe_does_not_prevent_another_instance_from_being_saved(monkeypatch):
    ctx = context([holder(1433, 2001), holder(51433, 2002)])
    monkeypatch.setattr(mssql, "_check_port", lambda *args: True)

    def probe(**arguments):
        if arguments["port"] == 1433:
            raise EPAPrereqError("Inconclusive measurement")
        return EPAResult("Required")

    monkeypatch.setattr(mssql, "test_epa", probe)
    rows = iter(mssql.collect_mssql(HOST, ctx))
    first, second = next(rows)[1], next(rows)[1]
    assert first["port"] == 1433 and first["extended_protection"] is None
    assert second["port"] == 51433 and second["extended_protection"] == "Required"
    with pytest.raises(EPAPrereqError):
        next(rows)


def test_named_registration_reuses_its_own_known_registry_ports(monkeypatch):
    account = holder(51433, 2001)
    account["spns"] = [f"MSSQLSvc/{HOST}:REPORTS"]
    ctx = context([account])
    ctx.target_hosts_by_hostname[HOST].sql_instances = [
        SqlAddress(HOST, 51433, "REPORTS"),
        SqlAddress(HOST, 51434, "REPORTS"),
    ]
    ctx.sql_browser.resolve = lambda *args, **kwargs: pytest.fail(
        "The instance's actual ports are already known"
    )
    monkeypatch.setattr(mssql, "_check_port", lambda *args: False)
    rows = [row for _, row in mssql.collect_mssql(HOST, ctx)]
    assert {(row["port"], row["service_account_name"]) for row in rows} == {
        (51433, "sql2001"),
        (51434, "sql2001"),
    }


def test_registry_instances_keep_their_own_ports_settings_and_services():
    ctx = context()
    inventory = registry.MSSQL_INSTANCE_NAMES_KEY
    default = registry.MSSQL_NETWORK_KEY.format(instance_key="MSSQL16.MSSQLSERVER")
    reports = registry.MSSQL_NETWORK_KEY.format(instance_key="MSSQL16.REPORTS")
    values = {
        inventory: [
            ("MSSQLSERVER", "MSSQL16.MSSQLSERVER"),
            ("REPORTS", "MSSQL16.REPORTS"),
        ],
        default: [],
        reports: [],
    }
    dwords = {
        (default, "ForceEncryption"): 0,
        (default, "ExtendedProtection"): 0,
        (reports, "ForceEncryption"): 1,
        (reports, "ExtendedProtection"): 2,
        (default + r"\Tcp", "ListenOnAllIPs"): 1,
        (reports + r"\Tcp", "ListenOnAllIPs"): 1,
    }
    strings = {
        (default + r"\Tcp\IPAll", "TcpPort"): "1433",
        (reports + r"\Tcp\IPAll", "TcpDynamicPorts"): "51433",
        (
            registry.MSSQL_SERVICE_KEY.format(service="MSSQLSERVER"),
            "ObjectName",
        ): "MAYYHEM\\sqlone",
        (
            registry.MSSQL_SERVICE_KEY.format(service="MSSQL$REPORTS"),
            "ObjectName",
        ): "MAYYHEM\\sqltwo",
    }
    probe = SimpleNamespace(
        hostname=HOST,
        read_values=lambda key: values.get(key),
        read_dword=lambda key, name: dwords.get((key, name)),
        read_value=lambda key, name: strings.get((key, name)),
        was_denied=lambda key: False,
    )
    rows = [row for _, row in registry.get_mssql_settings(probe, ctx)]
    assert {
        (
            row["instance_name"],
            row["port"],
            row["service_account_name"],
            row["extended_protection"],
        )
        for row in rows
    } == {
        ("MSSQLSERVER", "1433", "MAYYHEM\\sqlone", "Off"),
        ("REPORTS", "51433", "MAYYHEM\\sqltwo", "Required"),
    }
    assert ctx.target_hosts_by_hostname[HOST].sql_instances == [
        SqlAddress(HOST, 1433, "MSSQLSERVER"),
        SqlAddress(HOST, 51433, "REPORTS"),
    ]


def test_registry_listen_all_disabled_uses_only_active_enabled_ip_settings():
    network = "SQLNetwork"
    tcp = network + r"\Tcp"
    dwords = {
        (tcp, "ListenOnAllIPs"): 0,
        (tcp + r"\IP1", "Enabled"): 1,
        (tcp + r"\IP1", "Active"): 1,
        (tcp + r"\IP2", "Enabled"): 0,
        (tcp + r"\IP2", "Active"): 1,
    }
    strings = {
        (tcp + r"\IPAll", "TcpPort"): "1433",
        (tcp + r"\IP1", "TcpPort"): "51433,51434",
        (tcp + r"\IP1", "TcpDynamicPorts"): "0",
        (tcp + r"\IP2", "TcpPort"): "9999",
    }
    probe = SimpleNamespace(
        hostname=HOST,
        read_dword=lambda key, name: dwords.get((key, name)),
        read_value=lambda key, name: strings.get((key, name)),
        enum_keys=lambda key: ["IPAll", "IP1", "IP2"],
    )
    assert registry._mssql_tcp_ports(probe, network) == [51433, 51434]


def test_denied_legacy_key_without_inventory_does_not_establish_sql():
    ctx = context()
    probe = SimpleNamespace(
        hostname=HOST, read_values=lambda key: None, was_denied=lambda key: True
    )
    assert list(registry.get_mssql_settings(probe, ctx)) == []
    assert ctx.target_hosts_by_hostname[HOST].sql_instances == []


def graph_from_rows(tmp_path, rows):
    path = tmp_path / "instances.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    connection = duckdb.connect(":memory:")
    connection.execute("CREATE SCHEMA sccm")
    connection.execute(
        "CREATE TABLE sccm.mssql_server_instances AS SELECT * FROM read_json_auto(?)",
        [str(path)],
    )
    transforms(connection)
    return connection


def test_graph_keeps_ports_separate_and_does_not_invent_unresolved_instance(tmp_path):
    rows = [
        {
            "domain_computer_sid": HOST_SID,
            "name": HOST,
            "port": port,
            "instance_name": name,
            "extended_protection": protection,
            "has_mssql_spn": True,
        }
        for port, name, protection in [
            (1433, None, "Off"),
            (51433, "REPORTS", "Required"),
            (None, "UNRESOLVED", None),
        ]
    ]
    connection = graph_from_rows(tmp_path, rows)
    assert connection.execute(
        "SELECT server_id, extended_protection FROM sccm.node_mssql_server ORDER BY port"
    ).fetchall() == [(HOST_SID + ":1433", "Off"), (HOST_SID + ":51433", "Required")]


def test_graph_withholds_conflicting_protection_and_account_evidence(tmp_path):
    rows = [
        {
            "domain_computer_sid": HOST_SID,
            "name": HOST,
            "port": 51433,
            "force_encryption": force,
            "extended_protection": protection,
            "service_account_sid": account,
        }
        for force, protection, account in [
            (False, "Off", "S-1"),
            (True, "Required", "S-2"),
        ]
    ]
    connection = graph_from_rows(tmp_path, rows)
    assert connection.execute(
        "SELECT force_encryption, extended_protection, service_account_sid FROM sccm.node_mssql_server"
    ).fetchone() == (None, None, None)
