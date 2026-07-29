"""Task 4: provenance stamp on the MSSQL site-DB scaffolding, keyed off `basis`
(from `assumed_site_dbs`, Task 2), not a second `disable_possible_edges` gate.

A confirmed site DB (basis='RemoteRegistry', which also covers an AdminService/WMI-
merged 'SMS SQL Server@<site>' tag -- see `_assumed_site_dbs`'s docstring) keeps its
full scaffolding in both flag modes with NO `assumed` stamp: the CM_<site> database,
sysadmin/db_owner roles, machine-account logins/db-users, and their edges are a
consequence of the confirmed fact, not a possible edge (spec §7). An SPN+SCCM-inferred
site DB gets the identical scaffolding but stamped `assumed`/`assumptionBasis`/an
`Assumed-*` collectionSource tag -- `--disable-possible-edges` already dropped these
rows upstream in `_assumed_site_dbs` (Task 2), so these builders take no flag
parameter of their own; re-checking it here would be a second, driftable policy.

`_node_mssql_server` arm 1 (the SCCM-resolved-site-database arm) gets the same
treatment (ownership gap found in the Task 2 review, folded into this task): before
this fix it unconditionally claimed the privileged `collection_source`, which would
have let an SPN+SCCM inference masquerade as a privileged confirmation.
"""
import duckdb

from openhound_sccm.transforms import (
    _assumed_site_dbs,
    _edge_mssql_membership,
    _edge_mssql_structural,
    _graph_edges_init,
    _mssql_sql_servers,
    _node_mssql_database,
    _node_mssql_database_role,
    _node_mssql_database_user,
    _node_mssql_login,
    _node_mssql_server,
    _node_mssql_server_role,
)

SCHEMA = "sccm"


def _con_with_computers(rows):
    """rows: (sid, site_system_roles, sccm_infra, dnshostname, sam_account_name)."""
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_computer "
        "(sid VARCHAR, site_system_roles VARCHAR[], sccm_infra BOOLEAN, "
        " dnshostname VARCHAR, sam_account_name VARCHAR)"
    )
    if rows:
        con.executemany(f"INSERT INTO {SCHEMA}.node_computer VALUES (?,?,?,?,?)", rows)
    # _mssql_sql_servers LEFT JOINs node_site unconditionally (site-level SQL
    # attributes); an empty one just means every attribute defaults/coalesces.
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_site "
        "(site_code VARCHAR, root_site_code VARCHAR, sql_service_port VARCHAR, "
        " sql_database_name VARCHAR, sql_service_account_name VARCHAR, "
        " sql_service_account_domain_sid VARCHAR)"
    )
    return con


def _add_spn_host(con, host_sid):
    con.execute(
        f"CREATE TABLE {SCHEMA}.mssql_server_instances "
        "(domain_computer_sid VARCHAR, has_mssql_spn BOOLEAN)"
    )
    con.execute(f"INSERT INTO {SCHEMA}.mssql_server_instances VALUES (?, true)", [host_sid])


def _build_scaffolding(con, disable_possible_edges=False):
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=disable_possible_edges)
    _mssql_sql_servers(con, SCHEMA)
    _node_mssql_server(con, SCHEMA)
    _node_mssql_database(con, SCHEMA)
    _node_mssql_login(con, SCHEMA)
    _node_mssql_database_user(con, SCHEMA)
    _node_mssql_server_role(con, SCHEMA)
    _node_mssql_database_role(con, SCHEMA)
    _graph_edges_init(con, SCHEMA)
    _edge_mssql_structural(con, SCHEMA)
    _edge_mssql_membership(con, SCHEMA)


# A SQL host (S-1-DB) plus a separate sysadmin computer (S-1-SRV, the site server) --
# node_mssql_login excludes the SQL host from being its own sysadmin.
_SYSADMIN_ROW = ("S-1-SRV", ["SMS Site Server@PS1"], True, "SRV01.lab.local", "SRV01$")


def test_confirmed_site_db_scaffolding_is_not_marked_assumed():
    # RemoteRegistry (here: the merged 'SMS SQL Server@<site>' tag) confirmed this
    # host IS the site database, so the schema SCCM requires on it is a consequence
    # of that fact -- not a "possible" edge.
    con = _con_with_computers([
        ("S-1-DB", ["SMS SQL Server@PS1"], True, "SQL01.lab.local", "SQL01$"),
        _SYSADMIN_ROW,
    ])
    _build_scaffolding(con)
    name, assumed, basis, src = con.execute(
        f"SELECT name, assumed, assumption_basis, collection_source FROM {SCHEMA}.node_mssql_database"
    ).fetchone()
    assert name == "CM_PS1"
    assert assumed is False
    assert basis is None
    assert src == ["SCCM-SiteDBDefaultSchema"]


def test_assumed_site_db_scaffolding_is_marked():
    # SPN+SCCM: the SQL host carries an MSSQLSvc SPN and is SCCM-related, but is
    # never RemoteRegistry/AdminService/WMI-confirmed as THE site database.
    con = _con_with_computers([
        ("S-1-DB", ["SMS Distribution Point@PS1"], True, "SQL01.lab.local", "SQL01$"),
        _SYSADMIN_ROW,
    ])
    _add_spn_host(con, "S-1-DB")
    _build_scaffolding(con)
    name, assumed, basis, src = con.execute(
        f"SELECT name, assumed, assumption_basis, collection_source FROM {SCHEMA}.node_mssql_database"
    ).fetchone()
    assert name == "CM_PS1"
    assert assumed is True
    assert basis and "SPN" in basis
    assert src == ["Assumed-SiteDB"]


def test_builder_has_no_flag_of_its_own():
    # The possible-edges filter lives in Task 2 (_assumed_site_dbs), upstream. An
    # empty assumed_site_dbs table is what suppresses the scaffolding -- these
    # builders must not re-decide it themselves.
    con = _con_with_computers([])
    _build_scaffolding(con)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.node_mssql_database").fetchone()[0] == 0


def test_node_mssql_server_arm1_provenance_matches_basis():
    # Ownership gap (2026-07-27 review): arm 1 used to stamp the privileged
    # collection_source unconditionally, letting an SPN+SCCM inference claim
    # privileged provenance. It must now carry the same basis-derived stamp.
    con = _con_with_computers([
        ("S-1-DB", ["SMS Distribution Point@PS1"], True, "SQL01.lab.local", "SQL01$"),
        _SYSADMIN_ROW,
    ])
    _add_spn_host(con, "S-1-DB")
    _build_scaffolding(con)
    assumed, src = con.execute(
        f"SELECT assumed, collection_source FROM {SCHEMA}.node_mssql_server WHERE host_sid = 'S-1-DB'"
    ).fetchone()
    assert assumed is True
    assert "Assumed-SiteDB" in src
    # The old unconditional privileged tag must NOT leak onto an SPN+SCCM-inferred row.
    assert "SCCM_Add-MSSQLServerNodesAndEdges" not in src


def test_login_and_dbuser_inherit_assumed_stamp():
    con = _con_with_computers([
        ("S-1-DB", ["SMS Distribution Point@PS1"], True, "SQL01.lab.local", "SQL01$"),
        _SYSADMIN_ROW,
    ])
    _add_spn_host(con, "S-1-DB")
    _build_scaffolding(con)
    login = con.execute(
        f"SELECT assumed, collection_source FROM {SCHEMA}.node_mssql_login"
    ).fetchone()
    assert login[0] is True and login[1] == ["Assumed-SiteDB"]
    dbuser = con.execute(
        f"SELECT assumed, collection_source FROM {SCHEMA}.node_mssql_database_user"
    ).fetchone()
    assert dbuser[0] is True and dbuser[1] == ["Assumed-SiteDB"]


def test_roles_inherit_assumed_stamp():
    con = _con_with_computers([
        ("S-1-DB", ["SMS Distribution Point@PS1"], True, "SQL01.lab.local", "SQL01$"),
        _SYSADMIN_ROW,
    ])
    _add_spn_host(con, "S-1-DB")
    _build_scaffolding(con)
    srv_role = con.execute(f"SELECT assumed FROM {SCHEMA}.node_mssql_server_role").fetchone()
    assert srv_role[0] is True
    db_role = con.execute(f"SELECT assumed FROM {SCHEMA}.node_mssql_database_role").fetchone()
    assert db_role[0] is True


def test_structural_and_membership_edges_carry_the_stamp_except_host_edges():
    # HostFor/ExecuteOnHost are confirmed and ungated per D2(a) regardless of the
    # site-DB basis -- they must stay unmarked even for an SPN+SCCM-inferred host.
    con = _con_with_computers([
        ("S-1-DB", ["SMS Distribution Point@PS1"], True, "SQL01.lab.local", "SQL01$"),
        _SYSADMIN_ROW,
    ])
    _add_spn_host(con, "S-1-DB")
    _build_scaffolding(con)
    contains = con.execute(
        f"SELECT assumed FROM {SCHEMA}.graph_edges WHERE kind = 'MSSQL_Contains' "
        f"AND end_id LIKE 'sysadmin@%'"
    ).fetchone()
    assert contains[0] is True
    host_for = con.execute(
        f"SELECT assumed FROM {SCHEMA}.graph_edges WHERE kind = 'MSSQL_HostFor'"
    ).fetchone()
    assert host_for[0] is None


def test_db_assign_all_permissions_inherits_the_databases_confidence():
    """The DB->site AssignAllPermissions edge must carry the database's own stamp.

    Found in the Task 8 doc-truth pass: _edge_mssql_db_assign_all emitted no provenance at
    all, so an edge asserting "this database can assign all permissions over that site" --
    resting on a CM_<site> database that may itself be inferred from an MSSQLSvc SPN --
    reached the graph indistinguishable from a privileged-confirmed one. Same
    inherit-from-the-source rule Task 14 applies to logins.
    """
    import duckdb
    from openhound_sccm.transforms import _graph_edges_init, _edge_mssql_db_assign_all

    def _run(assumed, basis):
        con = duckdb.connect()
        con.execute("CREATE SCHEMA sccm")
        con.execute("CREATE TABLE sccm.node_mssql_database "
                    "(database_id VARCHAR, sccm_site VARCHAR, assumed BOOLEAN, assumption_basis VARCHAR)")
        con.execute(r"INSERT INTO sccm.node_mssql_database VALUES ('S-1-DB:1433\CM_PS1','PS1',?,?)",
                    [assumed, basis])
        con.execute("CREATE TABLE sccm.site_hierarchy "
                    "(site_code VARCHAR, parent_site_code VARCHAR, site_type INTEGER, root_site_code VARCHAR)")
        con.execute("INSERT INTO sccm.site_hierarchy VALUES ('PS1',NULL,2,'PS1')")
        _graph_edges_init(con, "sccm")
        _edge_mssql_db_assign_all(con, "sccm")
        return con.execute("SELECT assumed, assumption_basis FROM sccm.graph_edges "
                           "WHERE kind = 'SCCM_AssignAllPermissions'").fetchall()

    confirmed = _run(False, None)
    assert confirmed and confirmed[0][0] is False and confirmed[0][1] is None

    inferred = _run(True, "site DB inferred from MSSQLSvc SPN")
    assert inferred and inferred[0][0] is True
    assert inferred[0][1] == "site DB inferred from MSSQLSvc SPN"
