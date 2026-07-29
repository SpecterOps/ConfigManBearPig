"""Hardening tests for the preproc coalesces against real-data schema drift.

Two failure modes seen on real collected data (lab mayyhem.com):

1. A source table is MISSING an optional column the coalesce SELECT references —
   because the source never emits it OR dlt dropped it as all-NULL. INSERT ... BY NAME
   only maps the target side, so the SELECT fails to bind and _safe drops the whole
   source. Fixed by _ensure_columns adding the missing column as NULL before the insert.

2. security_group_name arrives dlt-typed as JSON (e.g. '["mayyhem\\Domain Computers"]'),
   not a native list, so UNNEST raises "requires a single list as input".
   Fixed by CAST(... AS VARCHAR[]) before UNNEST.
"""
import duckdb

from openhound_sccm.transforms import _node_computer, _node_group, _node_site


def test_node_computer_source_missing_optional_columns_still_coalesces():
    """ldap_cmrc_devices with only object_sid+name (no roles/sccm_infra) must still
    produce a Computer row, not be dropped by a binder error."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    # Real ldap_cmrc_devices lacks sccm_site_system_roles and sccm_infra entirely.
    con.execute("CREATE TABLE sccm.ldap_cmrc_devices (object_sid VARCHAR, name VARCHAR)")
    con.execute("INSERT INTO sccm.ldap_cmrc_devices VALUES ('S-1-5-21-1-2-3-1104', 'HOST1')")

    _node_computer(con, "sccm")

    rows = con.execute(
        "SELECT sid, site_system_roles, sccm_has_client_remote_control_spn "
        "FROM sccm.node_computer"
    ).fetchall()
    con.close()
    assert rows == [("S-1-5-21-1-2-3-1104", [], True)], rows


def test_node_group_security_group_name_as_json_unnests():
    """security_group_name stored as JSON (dlt's real type) must still unnest and
    resolve to a group SID via principal_by_name."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("INSTALL json; LOAD json;")
    con.execute("CREATE TABLE sccm.principal_by_name (name VARCHAR, sid VARCHAR)")
    con.execute(
        "INSERT INTO sccm.principal_by_name VALUES "
        "('mayyhem\\Domain Computers', 'S-1-5-21-1-2-3-512')"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system "
        "(sid VARCHAR, obsolete BIGINT, security_group_name JSON, "
        " resource_id BIGINT, source_site_code VARCHAR)"
    )
    con.execute(
        "INSERT INTO sccm.adminservice_r_system VALUES "
        "('S-1-5-21-1-2-3-1104', 0, '[\"mayyhem\\\\Domain Computers\"]', 7, 'PS1')"
    )

    _node_group(con, "sccm")

    rows = con.execute("SELECT sid, name FROM sccm.node_group").fetchall()
    con.close()
    assert rows == [("S-1-5-21-1-2-3-512", "mayyhem\\Domain Computers")], rows


def test_node_computer_roles_as_json_text_in_varchar_parse_clean():
    """smb/registry collectors emit sccm_site_system_roles as JSON-array TEXT held
    in a VARCHAR column (e.g. '["SMS Site Server@CAS","SMS Distribution Point@CAS"]').

    _arr must recognise the JSON-array text and parse it into clean role elements,
    NOT comma-split the JSON punctuation into garbage like '["SMS Site Server@CAS"'.
    A bare scalar role string (no brackets) must still pass through unchanged.
    """
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("INSTALL json; LOAD json;")
    con.execute(
        "CREATE TABLE sccm.smb_computers "
        "(object_sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR)"
    )
    con.execute(
        "INSERT INTO sccm.smb_computers VALUES "
        # JSON-array text in a VARCHAR (smb collector shape)
        "('S-1-5-21-1-2-3-1104', 'HOST1', "
        " '[\"SMS Site Server@CAS\",\"SMS Distribution Point@CAS\"]'), "
        # bare scalar role (site_definitions_computers shape) must be untouched
        "('S-1-5-21-1-2-3-1105', 'HOST2', 'SMS Management Point@PS1')"
    )

    _node_computer(con, "sccm")

    roles_host1 = con.execute(
        "SELECT list_sort(site_system_roles) FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchone()[0]
    roles_host2 = con.execute(
        "SELECT list_sort(site_system_roles) FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1105'"
    ).fetchone()[0]
    con.close()
    assert roles_host1 == ["SMS Distribution Point@CAS", "SMS Site Server@CAS"], roles_host1
    assert roles_host2 == ["SMS Management Point@PS1"], roles_host2


def test_node_site_site_definitions_missing_site_guid_still_coalesces():
    """Real adminservice_site_definitions can lack site_guid entirely (the source
    never emits it / dlt drops it as all-NULL). _node_site must add the missing
    optional columns (as _node_computer/_node_user already do) so the INSERT binds
    and the site_definitions sql_server_name/sql_database_name survive — instead of
    a binder error dropping the whole source and losing those properties."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    # site_hierarchy is consumed by _node_site's final LEFT JOIN; minimal stub.
    con.execute(
        "CREATE TABLE sccm.site_hierarchy "
        "(site_code VARCHAR, parent_site_code VARCHAR, site_type INTEGER, root_site_code VARCHAR)"
    )
    con.execute("INSERT INTO sccm.site_hierarchy VALUES ('PS1', NULL, 2, 'PS1')")
    # principal_by_name is consumed by _node_site's SQLServiceAccountDomainSID subquery
    # (it always exists before _node_site in the real pipeline); empty stub here.
    con.execute("CREATE TABLE sccm.principal_by_name (name VARCHAR, sid VARCHAR)")
    # No site_guid / version / build_number / install_dir columns — the real shape.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions "
        "(site_code VARCHAR, parent_site_code VARCHAR, site_type BIGINT, "
        " sql_server_name VARCHAR, sql_database_name VARCHAR)"
    )
    con.execute(
        "INSERT INTO sccm.adminservice_site_definitions VALUES "
        "('PS1', NULL, 2, 'PS1-DB.mayyhem.com', 'CM_PS1')"
    )

    _node_site(con, "sccm")

    row = con.execute(
        "SELECT site_code, sql_server_name, sql_database_name, site_guid, root_site_code "
        "FROM sccm.node_site WHERE site_code = 'PS1'"
    ).fetchone()
    con.close()
    assert row == ("PS1", "PS1-DB.mayyhem.com", "CM_PS1", None, "PS1"), row


def test_node_computer_no_resource_id_yields_empty_list_not_null():
    """A computer with no resource_id (e.g. an LDAP-only host) must get resource_ids=[],
    not NULL. array_agg(...) FILTER returns SQL NULL for zero matches, and the node model
    types resource_ids as list[str] — a None then fails validation (the field default
    only applies when the key is absent, not when None is explicitly passed). Array
    properties must coalesce to []. Same pattern guards node_user/node_group resource ids."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    # ldap_cmrc_devices carries no resource_id at all.
    con.execute("CREATE TABLE sccm.ldap_cmrc_devices (object_sid VARCHAR, name VARCHAR)")
    con.execute("INSERT INTO sccm.ldap_cmrc_devices VALUES ('S-1-5-21-1-2-3-1104', 'HOST1')")

    _node_computer(con, "sccm")

    resource_ids = con.execute(
        "SELECT resource_ids FROM sccm.node_computer WHERE sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchone()[0]
    con.close()
    assert resource_ids == [], resource_ids
