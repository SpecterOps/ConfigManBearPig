"""Tests for the CurrentUser SID selection and Multisite role logic in the
RemoteRegistry collector.

CurrentUser: the logged-in user's domain SID is the *data* of the value named
``UserSID``. ``collect_registry`` must select it by name (not by enumeration
position) so the sibling ``Session`` DWORD is never mistaken for the SID.

Multisite Component Servers: an *absent* key means nothing, an *empty* key means
the site database is local to the site server (this host gets SQL + Site Server
roles), and a populated key lists remote SQL database servers.

Both paths only run once the Triggers key yields a site code, so the fakes seed
one by default.
"""
import logging

from openhound_sccm.collectors import registry

TARGET = "ps1-pss.mayyhem.com"
TRIGGERS = registry.SCCM_REG_KEYS["triggers"]
COMPONENTS = registry.SCCM_REG_KEYS["component_servers"]
MULTISITE = registry.SCCM_REG_KEYS["multisite_component_servers"]


class _Entry:
    """Minimal stand-in for a TargetEntry (only ``ad_object`` is read)."""

    def __init__(self, ad_object=None):
        self.ad_object = ad_object


class FakeProbe:
    """Stand-in for ``_RegistryProbe`` used as a context manager.

    ``enum_results`` maps a registry key path to the value ``enum_keys`` should
    return (``None`` = key absent). ``read_values_result`` backs CurrentUser.
    """

    def __init__(self, enum_results=None, read_values_result=None,
                 values_by_key=None, dword_results=None, value_results=None,
                 denied_keys=None):
        # Registry paths this fake host refuses. The real probe records these as
        # its read helpers hit access-denied; here they are seeded up front so a
        # test can pick "denied" or "absent" for the same None return value.
        self._denied_keys = set(denied_keys or ())
        self._enum_results = enum_results or {}
        self._read_values_result = read_values_result
        # Per-key overrides for the MSSQL paths, which need more than one key to
        # answer differently: {key_path: [(name, data), ...]} for read_values, and
        # {(key_path, value_name): data} for read_dword / read_value.
        self._values_by_key = values_by_key or {}
        self._dword_results = dword_results or {}
        self._value_results = value_results or {}
        self.hostname = TARGET
        # The real _RegistryProbe holds an SMB connection; get_ntlm_settings reads
        # the negotiated signing flag off it when the registry DWORD is absent.
        # None is enough here (negotiated_signing_required tolerates it).
        self.smb = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def was_denied(self, key_path):
        return key_path in self._denied_keys

    def enum_keys(self, key_path):
        return self._enum_results.get(key_path)

    def read_values(self, key_path):
        if key_path in self._values_by_key:
            return self._values_by_key[key_path]
        return self._read_values_result

    def read_dword(self, key_path, value_name):
        # Defaults to None so get_ntlm_settings / get_mssql_settings run without
        # error in the tests that do not care about them.
        return self._dword_results.get((key_path, value_name))

    def read_value(self, key_path, value_name):
        return self._value_results.get((key_path, value_name))


class FakeCtx:
    """Context capturing resolve_principal / register_target calls."""

    domain = "MAYYHEM"
    username = None
    password = None

    def __init__(self, resolve_result=None, register_result="auto"):
        self._resolve_result = resolve_result
        self._register_result = register_result
        self.resolved = []
        self.registered = []
        self.target_hosts_by_hostname = {TARGET: _Entry(ad_object=None)}

    def method_enabled(self, name):
        return True

    def resolve_principal(self, identifier):
        self.resolved.append(identifier)
        return self._resolve_result

    def register_target(self, identifier, source=None, **kwargs):
        self.registered.append((identifier, source))
        if self._register_result == "auto":
            return _Entry(ad_object=None)
        return self._register_result


def _run(monkeypatch, *, enum_results, read_values_result=None, ctx=None):
    ctx = ctx or FakeCtx()
    monkeypatch.setattr(
        registry, "_RegistryProbe", lambda *a, **k: FakeProbe(enum_results, read_values_result)
    )
    rows = list(registry.collect_registry(TARGET, ctx))
    return ctx, rows


def _site_server(**overrides):
    """enum_results for a host whose Triggers key yields site code 'PS1'."""
    base = {TRIGGERS: ["PS1"]}
    base.update(overrides)
    return base


# --- CurrentUser SID selection -------------------------------------------------

def test_usersid_value_selected_by_name_not_position(monkeypatch):
    """Regression: the SID is the data of the value named 'UserSID', chosen by
    name — never by enumeration position. Here 'UserSID' enumerates *before* the
    sibling 'Session' DWORD, so the old index-1 rule wrongly picked '1'.
    """
    values = [("UserSID", "S-1-5-21-BBB-1107"), ("Session", "1")]
    ctx, rows = _run(
        monkeypatch, enum_results=_site_server(), read_values_result=values,
        ctx=FakeCtx(resolve_result={"sAMAccountName": "bob"}),
    )
    assert ctx.resolved == ["S-1-5-21-BBB-1107"]
    user_rows = [row for table, row in rows if table == "remoteregistry_users"]
    assert len(user_rows) == 1
    assert user_rows[0]["object_sid"] == "S-1-5-21-BBB-1107"


def test_single_usersid_value_selected(monkeypatch):
    """A lone UserSID value is selected by name."""
    ctx, _ = _run(
        monkeypatch, enum_results=_site_server(),
        read_values_result=[("UserSID", "S-1-5-21-AAA-1106")],
        ctx=FakeCtx(resolve_result={"sAMAccountName": "alice"}),
    )
    assert ctx.resolved == ["S-1-5-21-AAA-1106"]


def test_usersid_match_is_case_insensitive(monkeypatch):
    """Registry value names are case-insensitive, so any casing must match."""
    ctx, _ = _run(
        monkeypatch, enum_results=_site_server(),
        read_values_result=[("usersid", "S-1-5-21-CCC-1108"), ("Session", "1")],
        ctx=FakeCtx(resolve_result={"sAMAccountName": "carol"}),
    )
    assert ctx.resolved == ["S-1-5-21-CCC-1108"]


def test_empty_usersid_data_resolves_nothing(monkeypatch):
    """A UserSID value with empty data is ignored (no logged-in user)."""
    values = [("UserSID", ""), ("Session", "1")]
    ctx, rows = _run(monkeypatch, enum_results=_site_server(), read_values_result=values)
    assert ctx.resolved == []
    assert [row for table, row in rows if table == "remoteregistry_users"] == []


def test_no_usersid_value_resolves_nothing(monkeypatch):
    """When the key holds only a Session DWORD (no UserSID), nothing resolves."""
    values = [("Session", "1")]
    ctx, rows = _run(monkeypatch, enum_results=_site_server(), read_values_result=values)
    assert ctx.resolved == []
    assert [row for table, row in rows if table == "remoteregistry_users"] == []


def test_none_result_does_not_crash(monkeypatch):
    """A missing CurrentUser key (read_values -> None) must not raise."""
    ctx, rows = _run(monkeypatch, enum_results=_site_server(), read_values_result=None)
    assert ctx.resolved == []
    assert [row for table, row in rows if table == "remoteregistry_users"] == []


# --- Multisite Component Servers ----------------------------------------------

def test_multisite_empty_key_marks_local_site_database(monkeypatch):
    """Empty key -> the site database is local; this host gets both roles."""
    ctx = FakeCtx()
    ctx.target_hosts_by_hostname[TARGET] = _Entry(ad_object={"name": "PS1-PSS"})
    _, rows = _run(
        monkeypatch, enum_results=_site_server(**{MULTISITE: []}),
        read_values_result=[], ctx=ctx,
    )
    db_rows = [
        row for table, row in rows
        if table == "remoteregistry_computers" and row["source"] == "RemoteRegistry-MultisiteComponentServers"
    ]
    assert len(db_rows) == 1
    roles = db_rows[0]["sccm_site_system_roles"]
    assert "SMS SQL Server@PS1" in roles
    assert "SMS Site Server@PS1" in roles
    # The local case must NOT register a separate target.
    assert ctx.registered == []


def test_multisite_remote_server_is_registered_as_sql(monkeypatch):
    """Populated key -> each subkey is a remote SQL database server target."""
    ctx, rows = _run(
        monkeypatch, enum_results=_site_server(**{MULTISITE: ["PS1-DB.MAYYHEM.COM"]}),
        read_values_result=[], ctx=FakeCtx(),
    )
    assert ("PS1-DB.MAYYHEM.COM", "RemoteRegistry-MultisiteComponentServers") in ctx.registered
    db_rows = [
        row for table, row in rows
        if table == "remoteregistry_computers" and row["source"] == "RemoteRegistry-MultisiteComponentServers"
    ]
    assert len(db_rows) == 1
    assert db_rows[0]["sccm_site_system_roles"] == ["SMS SQL Server@PS1"]


def test_multisite_absent_key_emits_no_database_row(monkeypatch):
    """Absent key (enum_keys -> None) -> no multisite rows, no crash."""
    _, rows = _run(
        monkeypatch, enum_results=_site_server(), read_values_result=[], ctx=FakeCtx(),
    )
    db_rows = [
        row for table, row in rows
        if table == "remoteregistry_computers" and row["source"] == "RemoteRegistry-MultisiteComponentServers"
    ]
    assert db_rows == []


# --- con-be15: the empty-key SQL role is an inference, not a confirmation ---
#
# "Multisite Component Servers present but empty" means the site database is
# local *for a standalone primary site server*. A PASSIVE site server has the
# same empty key while the site database lives elsewhere, so asserting
# "SMS SQL Server" from the key alone invents a SQL server. Against the mayyhem
# lab this produced a spurious MSSQL_Server for ps1-psv, which runs no SQL, and
# inflated every dependent MSSQL count. The role is still emitted -- preprocess
# decides -- but it must be marked so preprocess can tell it apart from the
# populated-key branch, where the named servers really are site databases.

def test_multisite_empty_key_marks_the_sql_role_as_assumed(monkeypatch):
    """The local-site-database inference flags itself as unverified."""
    ctx = FakeCtx()
    ctx.target_hosts_by_hostname[TARGET] = _Entry(ad_object={"name": "PS1-PSS"})
    _, rows = _run(
        monkeypatch, enum_results=_site_server(**{MULTISITE: []}),
        read_values_result=[], ctx=ctx,
    )
    row = next(r for t, r in rows
               if t == "remoteregistry_computers"
               and r["source"] == "RemoteRegistry-MultisiteComponentServers")
    assert row["sql_role_assumed"] is True


def test_multisite_remote_server_sql_role_is_not_assumed(monkeypatch):
    """A named remote database server is confirmed, so it carries no flag."""
    _, rows = _run(
        monkeypatch, enum_results=_site_server(**{MULTISITE: ["PS1-DB.MAYYHEM.COM"]}),
        read_values_result=[], ctx=FakeCtx(),
    )
    row = next(r for t, r in rows
               if t == "remoteregistry_computers"
               and r["source"] == "RemoteRegistry-MultisiteComponentServers")
    assert not row.get("sql_role_assumed")


# --- con-be15: SQL Server service state + account from the registry ---------
#
# We reach these hosts over RemoteRegistry anyway, so read the service control
# entry directly rather than inferring "is there really SQL here" from a port
# probe -- a firewall can hide a running instance, and a stopped instance can
# still hold a listening-looking config. The service key also carries ObjectName,
# which is the account the engine runs as.
#
# Note Start is the STARTUP TYPE, not live running state (only the SCM knows
# that): 2=Automatic, 3=Manual, 4=Disabled. Disabled is conclusive proof the
# engine is not running; Automatic only says it should be.

INSTANCE_NAMES = r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"


def _supersocket(instance_key):
    """Network-settings path for the instance subkey *instance_key*."""
    return (rf"SOFTWARE\Microsoft\Microsoft SQL Server\{instance_key}"
            r"\MSSQLServer\SuperSocketNetLib")


def _mssql_probe(instance="MSSQLSERVER", start=None, object_name=None):
    """A probe that finds SQL Server and answers for one instance's service key.

    The inventory value's DATA is the instance's own subkey (``MSSQL16.<INSTANCE>``),
    which is what the real registry holds and what the settings path is derived from.
    The fixture used to put the bare instance name there, which made a named instance
    look like it lived at the default instance's path — hiding the very gap con-ab59
    was about.
    """
    instance_key = f"MSSQL16.{instance}"
    service = "MSSQLSERVER" if instance.upper() == "MSSQLSERVER" else f"MSSQL${instance}"
    svc_key = rf"SYSTEM\CurrentControlSet\Services\{service}"
    dwords, values = {}, {}
    if start is not None:
        dwords[(svc_key, "Start")] = start
    if object_name is not None:
        values[(svc_key, "ObjectName")] = object_name
    return FakeProbe(
        values_by_key={_supersocket(instance_key): [], INSTANCE_NAMES: [(instance, instance_key)]},
        dword_results=dwords, value_results=values,
    )


def _mssql_row(probe):
    ctx = FakeCtx()
    ctx.target_hosts_by_hostname[TARGET] = _Entry(ad_object={"name": "PS1-PSV"})
    probe.hostname = TARGET
    rows = list(registry.get_mssql_settings(probe, ctx))
    return next(r for t, r in rows if t == "remoteregistry_mssql_servers")


def test_mssql_default_instance_reports_startup_type_and_account():
    """Default instance -> service MSSQLSERVER; Start and ObjectName are surfaced."""
    row = _mssql_row(_mssql_probe(start=2, object_name=r"MAYYHEM\sqlsccmsvc"))
    assert row["service_start_type"] == "Automatic"
    assert row["service_account_name"] == r"MAYYHEM\sqlsccmsvc"


def test_mssql_named_instance_uses_the_dollar_service_name():
    """A named instance's service is MSSQL$<name>, not MSSQLSERVER."""
    row = _mssql_row(_mssql_probe(instance="CONFIGMGRSEC", start=4,
                                  object_name="LocalSystem"))
    assert row["service_start_type"] == "Disabled"
    assert row["service_account_name"] == "LocalSystem"


def test_mssql_disabled_service_is_reported():
    """Start=4 is the one value that proves the engine is not running."""
    row = _mssql_row(_mssql_probe(start=4))
    assert row["service_start_type"] == "Disabled"


def test_mssql_manual_service_is_reported():
    """Start=3 is Manual -- it may or may not be up; we report only what we read."""
    row = _mssql_row(_mssql_probe(start=3))
    assert row["service_start_type"] == "Manual"


def test_mssql_unreadable_service_key_leaves_fields_unset():
    """Access-denied or absent service key must not break collection.

    This is the normal low-privilege case: the Services hive is admin-gated.
    """
    row = _mssql_row(_mssql_probe())
    assert row["service_start_type"] is None
    assert row["service_account_name"] is None


# --- denied vs. absent site code ----------------------------------------------
# Both leave enum_keys(Triggers) returning None, but they mean opposite things:
# "this host is not a site server" vs. "I could not look". The phase used to
# report the first for both, which sends the operator away from a host that may
# well be a site system (con-8a28).

def _run_without_site_code(monkeypatch, *, denied):
    ctx = FakeCtx()
    monkeypatch.setattr(
        registry, "_RegistryProbe",
        lambda *a, **k: FakeProbe({}, denied_keys=[TRIGGERS] if denied else []),
    )
    return list(registry.collect_registry(TARGET, ctx))


def test_denied_triggers_key_reports_access_denied_not_a_missing_key(monkeypatch, caplog):
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        _run_without_site_code(monkeypatch, denied=True)
    text = "\n".join(r.getMessage() for r in caplog.records)

    assert "Access denied reading" in text
    assert "site code is unknown" in text
    assert "does not exist or no site code subkey found" not in text


def test_absent_triggers_key_still_reports_the_host_as_not_a_site_server(monkeypatch, caplog):
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        _run_without_site_code(monkeypatch, denied=False)
    text = "\n".join(r.getMessage() for r in caplog.records)

    assert "does not exist or no site code subkey found" in text
    assert "Access denied reading" not in text


# --- named SQL instances (con-ab59) -------------------------------------------
# The settings paths used to be eight hard-coded strings all ending .MSSQLSERVER,
# so a named instance could never match one. ps1-sec runs the SEC site database as
# CONFIGMGRSEC and was missed even with full local administrator rights, looking
# exactly like a host with no SQL at all. Paths are now derived from SQL Server's
# own instance inventory, whose value data IS the instance subkey.

def _named_instance_probe(instance, instance_key, *, force_encryption=1, extended_protection=2):
    """A host running one instance whose subkey is *instance_key*, and nothing else."""
    return FakeProbe(
        values_by_key={
            INSTANCE_NAMES: [(instance, instance_key)],
            _supersocket(instance_key): [],
        },
        dword_results={
            (_supersocket(instance_key), "ForceEncryption"): force_encryption,
            (_supersocket(instance_key), "ExtendedProtection"): extended_protection,
        },
        value_results={(_supersocket(instance_key) + r"\Tcp\IPAll", "TcpPort"): "1433"},
    )


def test_named_instance_settings_are_read():
    """The ps1-sec case: a named instance's EPA/port must be collected, not missed."""
    row = _mssql_row(_named_instance_probe("CONFIGMGRSEC", "MSSQL16.CONFIGMGRSEC"))
    assert row["instance_names"] == ["CONFIGMGRSEC"]
    assert row["force_encryption"] == "Yes"
    assert row["extended_protection"] == "Required"
    assert row["port"] == "1433"


def test_default_instance_still_works():
    """Deriving paths from the inventory must not regress the default instance,
    which is the only shape the old hard-coded list could ever match."""
    row = _mssql_row(_named_instance_probe("MSSQLSERVER", "MSSQL16.MSSQLSERVER",
                                           force_encryption=0, extended_protection=0))
    assert row["instance_names"] == ["MSSQLSERVER"]
    assert row["force_encryption"] == "No"
    assert row["extended_protection"] == "Off"


def test_instance_subkey_is_used_verbatim_whatever_the_version():
    """The version prefix is not guessable, so it is never constructed -- an old
    SQL 2014 named instance is addressed exactly as the inventory reports it."""
    row = _mssql_row(_named_instance_probe("LEGACYINST", "MSSQL12.LEGACYINST"))
    assert row["instance_names"] == ["LEGACYINST"]
    assert row["force_encryption"] == "Yes"


def test_host_without_sql_is_silent(caplog):
    """Seven of nine lab hosts on a FULLY PRIVILEGED run have no SQL at all. That is
    the normal case and must not produce a warning."""
    ctx = FakeCtx()
    probe = FakeProbe()  # no inventory, no legacy key
    probe.hostname = TARGET
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        rows = list(registry.get_mssql_settings(probe, ctx))

    assert rows == []
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("does not appear to run SQL Server" in r.getMessage() for r in caplog.records)


def test_instances_listed_but_settings_unreadable_still_warns(caplog):
    """The one case that IS a real gap: the host says it runs SQL and then its
    settings key is not where the inventory said. That contradiction stays loud."""
    ctx = FakeCtx()
    probe = FakeProbe(values_by_key={INSTANCE_NAMES: [("CONFIGMGRSEC", "MSSQL16.CONFIGMGRSEC")]})
    probe.hostname = TARGET
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        rows = list(registry.get_mssql_settings(probe, ctx))

    assert rows == []
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "CONFIGMGRSEC" in warnings[0]


def test_denied_settings_do_not_warn_twice(caplog):
    """At low privilege the per-host denial summary already reports the loss."""
    ctx = FakeCtx()
    key = _supersocket("MSSQL16.MSSQLSERVER")
    probe = FakeProbe(
        values_by_key={INSTANCE_NAMES: [("MSSQLSERVER", "MSSQL16.MSSQLSERVER")]},
        denied_keys=[key],
    )
    probe.hostname = TARGET
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        list(registry.get_mssql_settings(probe, ctx))

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("reported in the denial summary" in r.getMessage() for r in caplog.records)


def test_legacy_default_instance_path_is_the_fallback():
    """SQL 7.0/2000 predate the inventory key and had one fixed location."""
    ctx = FakeCtx()
    legacy = registry.MSSQL_LEGACY_NETWORK_KEY
    probe = FakeProbe(values_by_key={legacy: []})
    probe.hostname = TARGET
    rows = list(registry.get_mssql_settings(probe, ctx))
    assert [t for t, _ in rows] == ["remoteregistry_mssql_servers"]


def test_inventory_value_with_no_subkey_is_skipped(caplog):
    r"""A value naming no subkey cannot be turned into a path; skip it and say so
    rather than building 'Microsoft SQL Server\\MSSQLServer\SuperSocketNetLib'."""
    ctx = FakeCtx()
    probe = FakeProbe(values_by_key={INSTANCE_NAMES: [("BROKEN", "")]})
    probe.hostname = TARGET
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.collectors.registry"):
        list(registry.get_mssql_settings(probe, ctx))
    assert any("has no subkey recorded" in r.getMessage() for r in caplog.records)
