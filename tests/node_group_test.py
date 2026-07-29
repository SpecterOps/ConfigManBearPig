# src/openhound_sccm/node_group_test.py
"""Tests for the node_group preproc table built by transforms._node_group().

The node_group coalesce has two source paths:
  1. security_group_name lists on r_system / r_user rows: name-only, resolved to
     SID via a case-insensitive join against principal_by_name.
  2. admins / wmi_admins rows where is_group=True: SID is known directly, no
     name resolution required.

A case mismatch between the group name in security_group_name and the name
stored in principal_by_name must not cause the row to be silently dropped —
the join must be case-insensitive on both sides.
"""
import duckdb

from openhound_sccm.transforms import transforms


def test_node_group_resolves_name_and_includes_admin_group():
    """A name-resolved group + a direct admin group SID both appear."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")

    # r_system row: host belongs to 'LAB\\SCCMAdmins' (group name in list)
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'HOST1' AS name, 'S-1-5-21-1-2-3-1104' AS sid, "
        "['LAB\\\\SCCMAdmins'] AS security_group_name, false AS obsolete"
    )
    # r_user row provides the (name, sid) pair that resolves the group
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT "
        "'LAB\\\\SCCMAdmins' AS name, 'S-1-5-21-1-2-3-5001' AS sid"
    )
    # admins row: a group SID is known directly (is_group=True)
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS SELECT "
        "'LAB\\\\SiteAdmins' AS logon_name, "
        "'S-1-5-21-1-2-3-5002' AS admin_sid, true AS is_group"
    )

    transforms(con)

    sids = sorted(r[0] for r in con.execute("SELECT sid FROM sccm.node_group").fetchall())
    assert sids == ["S-1-5-21-1-2-3-5001", "S-1-5-21-1-2-3-5002"]


def test_node_group_case_insensitive_name_resolution():
    """A group name that differs in case from principal_by_name still resolves."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")

    # principal_by_name will store the name in lowercase because the r_user row has it lowercase
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT "
        "'lab\\\\sccmadmins' AS name, 'S-1-5-21-1-2-3-5001' AS sid"
    )
    # r_system references the same group but with different casing
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'HOST1' AS name, 'S-1-5-21-1-2-3-1104' AS sid, "
        "['LAB\\\\SCCMAdmins'] AS security_group_name, false AS obsolete"
    )

    transforms(con)

    sids = [r[0] for r in con.execute("SELECT sid FROM sccm.node_group").fetchall()]
    assert "S-1-5-21-1-2-3-5001" in sids


def test_node_group_sccm_infra_flag_for_admin_groups():
    """Groups sourced from admins tables carry sccm_infra=True."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")

    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS SELECT "
        "'LAB\\\\SiteAdmins' AS logon_name, "
        "'S-1-5-21-1-2-3-5002' AS admin_sid, true AS is_group"
    )

    transforms(con)

    rows = con.execute(
        "SELECT sid, sccm_infra FROM sccm.node_group WHERE sid = 'S-1-5-21-1-2-3-5002'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][1] is True  # sccm_infra must be True for admin-sourced groups


def test_node_group_resource_ids_from_r_user_parent():
    """Groups resolved from r_user carry the parent user's resource_id as sccm_resource_ids."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")

    # r_user row: user 'alice' (resource_id=9, site PS1) belongs to group 'LAB\\Grp'
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT "
        "'alice' AS name, 'S-1-5-21-1-2-3-1106' AS sid, "
        "9 AS resource_id, 'PS1' AS source_site_code, "
        "['LAB\\\\Grp'] AS security_group_name"
    )
    # The group's (name, sid) is also in r_user (so principal_by_name has it)
    # We seed it via a second insert to the same table using UNION approach — but
    # for test simplicity, add a wmi_r_user row for the group itself.
    con.execute(
        "CREATE TABLE sccm.wmi_r_user AS SELECT "
        "'LAB\\\\Grp' AS name, 'S-1-5-21-1-2-3-5003' AS sid, "
        "NULL::INTEGER AS resource_id, NULL::VARCHAR AS source_site_code, "
        "NULL::VARCHAR[] AS security_group_name"
    )

    transforms(con)

    rows = con.execute(
        "SELECT sid, sccm_resource_ids FROM sccm.node_group WHERE sid = 'S-1-5-21-1-2-3-5003'"
    ).fetchall()
    assert len(rows) == 1
    _sid, resource_ids = rows[0]
    assert "9@PS1" in resource_ids


def test_node_group_resolves_via_user_group_source_with_json_membership():
    """End-to-end offline chain with the REAL data shapes:

      * the group's SID comes from SMS_R_UserGroup (adminservice_user_group), the
        class we now collect specifically to carry group SIDs, and
      * the user's membership arrives as a dlt JSON security_group_name.

    The full path (user_group -> principal_by_name -> node_group name->SID join)
    must resolve the group SID, replacing CMBP's live per-name AD lookup. This is
    the exact failure that produced 0 groups on real lab data.
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("INSTALL json; LOAD json;")
    # Group SID source (SMS_R_UserGroup): DOMAIN\name + SID.
    con.execute(
        "CREATE TABLE sccm.adminservice_user_group AS SELECT "
        "'mayyhem\\Domain Users' AS unique_usergroup_name, 'S-1-5-21-1-2-3-513' AS sid"
    )
    # A user whose membership lists the group by NAME only, dlt-typed as JSON.
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user "
        "(sid VARCHAR, security_group_name JSON, resource_id BIGINT, source_site_code VARCHAR)"
    )
    con.execute(
        "INSERT INTO sccm.adminservice_r_user VALUES "
        "('S-1-5-21-1-2-3-1106', '[\"mayyhem\\\\Domain Users\"]', 9, 'PS1')"
    )

    transforms(con)

    rows = con.execute("SELECT sid, name FROM sccm.node_group").fetchall()
    con.close()
    assert ("S-1-5-21-1-2-3-513", "mayyhem\\Domain Users") in rows, rows


def test_node_group_gains_sam_account_name_and_distinguished_name_from_ad_props():
    """A group whose SID was independently LDAP-resolved (e.g. via the
    System Management container GenericAll ACL walk) must carry SamAccountName
    and distinguishedName -- the same ad_props table that already backfills
    Domain/Enabled/IsDomainPrincipal/Type onto node_group via _join_ad_props
    carries these two fields too (ldap_resolved_principals persists them,
    context.py:_record_resolved_principal), they just weren't being read.

    Mirrors the live 2026-07-28 low-priv run: 'Domain Admins' sits fully resolved
    in ldap_resolved_principals (LDAP-GenericAllSystemManagement) but node_group
    never surfaced sam_account_name/distinguished_name for it.
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")

    # This group's SID is known directly (is_group=True), same as any admin-sourced group.
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS SELECT "
        "'MAYYHEM\\Domain Admins' AS logon_name, "
        "'S-1-5-21-1-2-3-512' AS admin_sid, true AS is_group"
    )
    # The SAME sid was independently LDAP-resolved (e.g. GenericAll ACL walk).
    con.execute(
        "CREATE TABLE sccm.ldap_resolved_principals ("
        "sid VARCHAR, object_class VARCHAR[], user_account_control BIGINT, "
        "service_principal_name VARCHAR[], cn VARCHAR, sam_account_name VARCHAR, "
        "distinguished_name VARCHAR, domain VARCHAR)"
    )
    con.execute(
        "INSERT INTO sccm.ldap_resolved_principals VALUES ("
        "'S-1-5-21-1-2-3-512', ['top', 'group'], 0, NULL, 'Domain Admins', "
        "'Domain Admins', 'CN=Domain Admins,CN=Users,DC=mayyhem,DC=com', 'mayyhem.com')"
    )

    transforms(con)

    row = con.execute(
        "SELECT sam_account_name, distinguished_name FROM sccm.node_group "
        "WHERE sid = 'S-1-5-21-1-2-3-512'"
    ).fetchone()
    assert row is not None
    assert row[0] == "Domain Admins"
    assert row[1] == "CN=Domain Admins,CN=Users,DC=mayyhem,DC=com"


def test_node_group_deduplicates_same_sid_from_multiple_sources():
    """The same group SID appearing in both r_system and admins produces one row."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")

    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'HOST1' AS name, 'S-1-5-21-1-2-3-1104' AS sid, "
        "['LAB\\\\Admins'] AS security_group_name, false AS obsolete"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_r_user AS SELECT "
        "'LAB\\\\Admins' AS name, 'S-1-5-21-1-2-3-5004' AS sid"
    )
    # Same group also appears in admins directly
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS SELECT "
        "'LAB\\\\Admins' AS logon_name, "
        "'S-1-5-21-1-2-3-5004' AS admin_sid, true AS is_group"
    )

    transforms(con)

    rows = con.execute(
        "SELECT sid FROM sccm.node_group WHERE sid = 'S-1-5-21-1-2-3-5004'"
    ).fetchall()
    # Should be exactly one row despite appearing in two sources
    assert len(rows) == 1
