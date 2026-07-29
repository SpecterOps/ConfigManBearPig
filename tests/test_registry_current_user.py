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

    def __init__(self, enum_results=None, read_values_result=None):
        self._enum_results = enum_results or {}
        self._read_values_result = read_values_result
        self.hostname = TARGET
        # The real _RegistryProbe holds an SMB connection; get_ntlm_settings reads
        # the negotiated signing flag off it when the registry DWORD is absent.
        # None is enough here (negotiated_signing_required tolerates it).
        self.smb = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def enum_keys(self, key_path):
        return self._enum_results.get(key_path)

    def read_values(self, key_path):
        return self._read_values_result

    def read_dword(self, key_path, value_name):
        # NTLM/MSSQL settings are not under test here; return None so
        # get_ntlm_settings / get_mssql_settings run without error.
        return None

    def read_value(self, key_path, value_name):
        return None


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
