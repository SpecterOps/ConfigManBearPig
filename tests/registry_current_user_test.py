# src/openhound_sccm/collectors/registry_current_user_test.py
import types
from openhound_sccm.collectors import registry


class _FakeProbe:
    hostname = "host1.lab"
    def read_values(self, _key):
        return [("UserSID", "S-1-5-21-1-2-3-1106"), ("Session", 1)]


def _fake_ctx():
    host_obj = {"name": "HOST1", "object_sid": "S-1-5-21-1-2-3-1104"}
    user_obj = {"sam_account_name": "alice", "object_sid": "S-1-5-21-1-2-3-1106"}
    ctx = types.SimpleNamespace()
    ctx.resolve_principal = lambda sid: dict(user_obj)
    ctx.target_hosts_by_hostname = {"host1.lab": types.SimpleNamespace(ad_object=host_obj)}
    return ctx


def test_current_user_row_has_host_object_sid():
    rows = list(registry.get_current_user(_FakeProbe(), _fake_ctx()))
    assert len(rows) == 1
    table, row = rows[0]
    assert table == "remoteregistry_users"
    assert row["object_sid"] == "S-1-5-21-1-2-3-1106"        # the logged-on user
    assert row["host_object_sid"] == "S-1-5-21-1-2-3-1104"   # the host it logged onto
