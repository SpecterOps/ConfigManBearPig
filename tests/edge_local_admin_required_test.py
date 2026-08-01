import duckdb
from openhound_sccm.transforms import transforms


def test_site_server_is_local_admin_on_other_site_systems():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-100', 'SITESRV', '[\"SMS Site Server@PS1\"]', true), "
        "('S-1-5-21-1-2-3-200', 'MP', '[\"SMS Management Point@PS1\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_LocalAdminRequired'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-200") in edges      # site server -> MP
    assert ("S-1-5-21-1-2-3-200", "S-1-5-21-1-2-3-100") not in edges  # MP is NOT admin on the server
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-100") not in edges  # no self-edge


def test_no_local_admin_required_for_secondary_site():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2), ('SEC', 'PS1', 1)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-300', 'SECSRV', '[\"SMS Site Server@SEC\"]', true), "
        "('S-1-5-21-1-2-3-400', 'SECDP', '[\"SMS Distribution Point@SEC\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    n = con.execute(
        "SELECT count(*) FROM sccm.graph_edges WHERE kind = 'SCCM_LocalAdminRequired'"
    ).fetchone()[0]
    assert n == 0


# --- parent primary -> child secondary site server ---------------------------
#
# Microsoft's secondary-site prerequisites say outright: "Add the computer account of the
# parent primary site to the Administrators group on the secondary site server."
# The same-site rule above can never produce that edge -- it joins a site server only to
# site systems AT ITS OWN SITE, and skips secondaries entirely.
#
# In the mayyhem lab the edge appears anyway, but for an accidental reason: ps1-sec also
# carries 'SMS Management Point@PS1', which pulls it into PS1's own mesh. Strip that role
# and the edge vanishes, even though Microsoft still requires the local admin rights. The
# arm below produces it from the actual parent/child relationship instead, so it survives a
# secondary that serves no role for its parent. The first test deliberately gives the
# secondary site server NO parent-site role, which is exactly the case the old rule missed.

_PSS = "S-1-5-21-1-2-3-1112"   # PS1 primary site server (the parent)
_PSV = "S-1-5-21-1-2-3-1111"   # PS1 site server in passive mode
_SEC = "S-1-5-21-1-2-3-1113"   # SEC secondary site server -- ONLY @SEC roles


def _con_parent_child(sec_type_row):
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    rows = ["('PS1', NULL, 2)"]
    if sec_type_row:
        rows.append(sec_type_row)
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM (VALUES "
                + ", ".join(rows) + ") AS t(site_code, parent_site_code, site_type)")
    # SEC is always visible as a bare site code (an SMB share comment gives a low-priv run
    # this much); on its own that must not be enough.
    con.execute("CREATE TABLE sccm.smb_sites AS SELECT * FROM "
                "(VALUES ('SMB-Shares','SEC')) AS t(source, site_code)")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        f"('{_PSS}', 'PS1-PSS', '[\"SMS Site Server@PS1\"]', true), "
        f"('{_PSV}', 'PS1-PSV', '[\"SMS Site Server@PS1\"]', true), "
        f"('{_SEC}', 'PS1-SEC', '[\"SMS Site Server@SEC\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)")
    return con


def _lar_edges(con):
    return set(con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_LocalAdminRequired'"
    ).fetchall())


def test_parent_primary_site_servers_are_local_admin_on_a_confirmed_secondary():
    con = _con_parent_child("('SEC', 'PS1', 1)")
    transforms(con)
    edges = _lar_edges(con)
    assert (_PSS, _SEC) in edges, f"parent primary missing local admin on the secondary: {edges}"
    # By role, not by picking one "the" site server -- so a passive node is covered too.
    assert (_PSV, _SEC) in edges, f"passive parent site server missing: {edges}"


def test_secondary_site_server_gains_no_rights_over_its_parent():
    """The relationship is one-way: parent -> child, never child -> parent."""
    con = _con_parent_child("('SEC', 'PS1', 1)")
    transforms(con)
    edges = _lar_edges(con)
    assert (_SEC, _PSS) not in edges
    assert (_SEC, _PSV) not in edges
    assert (_SEC, _SEC) not in edges


def test_unconfirmed_secondary_gets_no_parent_local_admin_edge():
    """site_type unknown => no cross-site claim, even with an identical topology."""
    con = _con_parent_child(None)
    transforms(con)
    edges = _lar_edges(con)
    assert (_PSS, _SEC) not in edges, f"claimed local admin without confirmation: {edges}"
    assert (_PSV, _SEC) not in edges


def test_multiple_site_servers_are_mutually_local_admin():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions_computers AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-100', 'SRV1', '[\"SMS Site Server@PS1\"]', true), "
        "('S-1-5-21-1-2-3-101', 'SRV2', '[\"SMS Site Server@PS1\"]', true)"
        ") AS t(object_sid, name, sccm_site_system_roles, sccm_infra)"
    )
    transforms(con)
    edges = con.execute(
        "SELECT start_id, end_id FROM sccm.graph_edges WHERE kind = 'SCCM_LocalAdminRequired'"
    ).fetchall()
    assert ("S-1-5-21-1-2-3-100", "S-1-5-21-1-2-3-101") in edges
    assert ("S-1-5-21-1-2-3-101", "S-1-5-21-1-2-3-100") in edges
