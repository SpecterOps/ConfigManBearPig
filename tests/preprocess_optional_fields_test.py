"""Sparse collected rows must preserve known facts without inventing memberships."""

import json

import duckdb
import pytest

from openhound_sccm.transforms import (
    _derive_ad_props,
    _domain_fqdn_by_sid,
    _node_group,
    _principal_by_name,
)


@pytest.mark.parametrize("transport", ["adminservice", "wmi"])
@pytest.mark.parametrize("source", ["r_system", "r_user"])
@pytest.mark.parametrize("memberships", [None, [], ["LAB\\KnownGroup"]])
def test_missing_empty_and_populated_membership_fields(transport, source, memberships):
    with duckdb.connect(":memory:") as connection:
        connection.execute("CREATE SCHEMA sccm")
        table = f"sccm.{transport}_{source}"
        connection.execute(f"CREATE TABLE {table} (name VARCHAR, sid VARCHAR)")
        connection.execute(
            f"INSERT INTO {table} VALUES ('known-principal', 'S-1-5-21-1-2-3-1100')"
        )
        if memberships is not None:
            # dlt stores these lists as JSON; supplying a native list would miss
            # the real collection shape this regression needs to cover.
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN security_group_name JSON"
            )
            connection.execute(
                f"UPDATE {table} SET security_group_name = ?", [json.dumps(memberships)]
            )
        connection.execute(
            "CREATE TABLE sccm.adminservice_user_group AS "
            "SELECT 'LAB\\KnownGroup' AS unique_usergroup_name, 'S-1-5-21-1-2-3-2200' AS sid"
        )
        _principal_by_name(connection, "sccm")
        _derive_ad_props(connection, "sccm")
        _domain_fqdn_by_sid(connection, "sccm")
        _node_group(connection, "sccm")
        assert connection.execute(
            "SELECT sid FROM sccm.principal_by_name WHERE name = 'known-principal'"
        ).fetchone() == ("S-1-5-21-1-2-3-1100",)
        groups = connection.execute("SELECT sid FROM sccm.node_group").fetchall()
        assert groups == ([("S-1-5-21-1-2-3-2200",)] if memberships else [])
        if memberships is not None:
            # Preparing missing fields must never rewrite a collected JSON list.
            assert (
                json.loads(
                    connection.execute(
                        f"SELECT security_group_name FROM {table}"
                    ).fetchone()[0]
                )
                == memberships
            )


def test_absent_admin_group_flag_does_not_invent_a_group():
    with duckdb.connect(":memory:") as connection:
        connection.execute("CREATE SCHEMA sccm")
        connection.execute(
            "CREATE TABLE sccm.adminservice_admins AS "
            "SELECT 'LAB\\alice' AS logon_name, 'S-1-5-21-1-2-3-1100' AS admin_sid"
        )
        _principal_by_name(connection, "sccm")
        _derive_ad_props(connection, "sccm")
        _domain_fqdn_by_sid(connection, "sccm")
        _node_group(connection, "sccm")
        assert (
            connection.execute("SELECT count(*) FROM sccm.node_group").fetchone()[0]
            == 0
        )
