"""Tests for the privileged (AdminService/WMI) per-host collector helpers.

These exercise the shared collection helpers with a stub :class:`_Run` whose
``fetch`` returns canned SMS Provider rows, so no transport/network is needed.
"""
from openhound_sccm.collectors.privileged import _COLLECTIONS, _Run, _user_group


def _stub_run(rows, *, name="AdminService", site_code="PS1"):
    """Build a _Run whose fetch yields *rows*; records the class it was asked for."""
    captured = {}

    def fetch(cls, columns=None, where=None):
        captured["cls"] = cls
        captured["columns"] = columns
        yield from rows

    run = _Run(fetch=fetch, name=name, eq="eq", site_code=site_code, ctx=None)
    return run, captured


def test_user_group_collects_sms_r_usergroup_with_name_and_sid():
    """_user_group queries SMS_R_UserGroup and yields user_group rows carrying the
    DOMAIN\\group name (UniqueUsergroupName) and the group SID — the (name, SID)
    pair principal_by_name needs to resolve security_group_name memberships."""
    rows = [{
        "UniqueUsergroupName": "mayyhem\\Domain Users",
        "SID": "S-1-5-21-1-2-3-513",
        "ResourceId": 2080374784,
        "UsergroupName": "Domain Users",
    }]
    run, captured = _stub_run(rows)

    out = list(_user_group(run))

    assert captured["cls"] == "SMS_R_UserGroup"
    assert len(out) == 1
    table, row = out[0]
    assert table == "adminservice_user_group"
    assert row["unique_usergroup_name"] == "mayyhem\\Domain Users"
    assert row["sid"] == "S-1-5-21-1-2-3-513"
    assert row["source"] == "AdminService-SMS_R_UserGroup"
    assert row["source_site_code"] == "PS1"


def test_user_group_table_prefix_follows_transport():
    """WMI transport must produce wmi_user_group (table prefix = run.name.lower())."""
    run, _ = _stub_run(
        [{"UniqueUsergroupName": "mayyhem\\Domain Admins", "SID": "S-1-5-21-1-2-3-512"}],
        name="WMI",
    )
    table, _row = list(_user_group(run))[0]
    assert table == "wmi_user_group"


def test_user_group_registered_in_collections():
    """The resource must be wired into the shared collection set so both
    transports actually run it."""
    assert _user_group in _COLLECTIONS
