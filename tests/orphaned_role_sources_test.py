# tests/orphaned_role_sources_test.py
"""Tests for the three previously-orphaned role sources wired into _node_computer
(design spec Sec4.1 / task-1b): http_site_servers, ldap_management_points_raw's
fallback-status-point columns, and dns_management_points. All three are
collected, registered in the preproc table map, and loaded into DuckDB, but
before this task no transform ever read them -- these sources contributed no
role to any node.

Column names below match what the real collectors emit (object_sid / dns_host_name
etc. from a spread AD object, or the bespoke ldap_management_points_raw shape),
not the shorthand placeholders in the design brief -- the behavioral assertions
(which role string appears on which sid) are the contract, not the spellings.
"""
import duckdb
from openhound_sccm.transforms import _node_computer

SCHEMA = "sccm"


def _con():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    return con


def _roles_for(con, sid):
    row = con.execute(
        f"SELECT site_system_roles FROM {SCHEMA}.node_computer WHERE sid = ?", [sid]
    ).fetchone()
    return set(row[0]) if row else set()


def test_site_server_takes_site_code_from_the_mp_that_served_the_cert():
    con = _con()
    # Anonymous run: the sitesigncert row has no site code of its own (the probe
    # runs before MPKEYINFORMATION sets one -- ps1:8611 ordering), but the MP it
    # was read from learned one from its own MPKEYINFORMATION.
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_site_servers "
        "(object_sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
        " site_code VARCHAR, mp_host VARCHAR, sccm_infra BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_site_servers VALUES "
        "('S-1-SS', 'PS1-SITE', 'SMS Site Server', NULL, 'ps1-mp.mayyhem.com', true)"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_management_points "
        "(object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, site_code VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_management_points VALUES "
        "('S-1-MP', 'PS1-MP', 'ps1-mp.mayyhem.com', 'PS1')"
    )
    _node_computer(con, SCHEMA)
    assert "SMS Site Server@PS1" in _roles_for(con, "S-1-SS")


def test_site_server_keeps_bare_role_when_the_mp_has_no_site_code_either():
    con = _con()
    # D6: never guess. Neither the site-server row nor the MP it came from
    # knows a site code -> bare role, no fabricated '@'.
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_site_servers "
        "(object_sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
        " site_code VARCHAR, mp_host VARCHAR, sccm_infra BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_site_servers VALUES "
        "('S-1-SS', 'PS1-SITE', 'SMS Site Server', NULL, 'ps1-mp.mayyhem.com', true)"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_management_points "
        "(object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, site_code VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_management_points VALUES "
        "('S-1-MP', 'PS1-MP', 'ps1-mp.mayyhem.com', NULL)"
    )
    _node_computer(con, SCHEMA)
    assert _roles_for(con, "S-1-SS") == {"SMS Site Server"}


def test_fallback_status_point_gets_a_role():
    con = _con()
    # fsp_sid is Task 1b's own addition to ldap_management_points_raw (hoisted
    # out of a log-message-only local in collectors/ldap.py); site_code here is
    # the MP's own site code, which the collector already attributes directly to
    # the FSP it names (register_target(..., site_code=mp_code_upper)) -- not a
    # cross-host guess.
    con.execute(
        f"CREATE TABLE {SCHEMA}.ldap_management_points_raw "
        "(mp_hostname VARCHAR, site_code VARCHAR, fsp_hostname VARCHAR, fsp_sid VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES "
        "('ps1-mp', 'PS1', 'ps1-fsp.mayyhem.com', 'S-1-FSP')"
    )
    _node_computer(con, SCHEMA)
    assert "SMS Fallback Status Point@PS1" in _roles_for(con, "S-1-FSP")


def test_dns_discovered_mp_gets_a_role():
    con = _con()
    # The SRV query key IS the site code (authoritative, D6) and the collector
    # now emits the role string directly -- a plain arm, no join needed.
    con.execute(
        f"CREATE TABLE {SCHEMA}.dns_management_points "
        "(object_sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
        " site_code VARCHAR, sccm_infra BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.dns_management_points VALUES "
        "('S-1-MP', 'ps1-mp', 'SMS Management Point@PS1', 'PS1', true)"
    )
    _node_computer(con, SCHEMA)
    assert "SMS Management Point@PS1" in _roles_for(con, "S-1-MP")


# --- review fix round 1: IMPORTANT-1 (ambiguous MP site code must not be
# guessed) + MINOR-2 (site-server row must not depend on http_management_points
# existing) -------------------------------------------------------------

def test_site_server_bare_role_when_mp_reports_two_competing_site_codes(caplog):
    con = _con()
    # collectors/http.py:322-324,370: MPLIST1 sibling enumeration stamps the
    # PROBING MP's own site_code onto every sibling it lists, so the same
    # dns_host_name can legitimately appear under two different site codes --
    # once as itself (its true site), once as a mislabeled sibling of another
    # site's MP. D6 forbids picking either: only an UNAMBIGUOUS (single
    # distinct) site code may be trusted.
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_site_servers "
        "(object_sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
        " site_code VARCHAR, mp_host VARCHAR, sccm_infra BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_site_servers VALUES "
        "('S-1-SS', 'PS1-SITE', 'SMS Site Server', NULL, 'ps1-mp.mayyhem.com', true)"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_management_points "
        "(object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, site_code VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_management_points VALUES "
        "('S-1-MP', 'PS1-MP', 'ps1-mp.mayyhem.com', 'PS1'), "
        "('S-1-MP', 'PS1-MP', 'ps1-mp.mayyhem.com', 'PS2')"
    )

    import logging
    with caplog.at_level(logging.WARNING, logger="openhound_sccm.transforms"):
        _node_computer(con, SCHEMA)

    # Bare role only -- neither 'PS1' nor 'PS2' may be guessed.
    assert _roles_for(con, "S-1-SS") == {"SMS Site Server"}
    assert any(
        "ps1-mp.mayyhem.com" in r.message and "competing site codes" in r.message
        for r in caplog.records
    )


def test_site_server_row_still_emitted_when_http_management_points_is_absent():
    con = _con()
    # The credential-free scenario this arm exists for is exactly one where
    # http_management_points may be thin or missing entirely -- a missing join
    # target must enrich nothing, never gate whether the site-server row itself
    # (and its bare-role fallback) is emitted at all.
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_site_servers "
        "(object_sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
        " site_code VARCHAR, mp_host VARCHAR, sccm_infra BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_site_servers VALUES "
        "('S-1-SS', 'PS1-SITE', 'SMS Site Server', NULL, 'ps1-mp.mayyhem.com', true)"
    )
    # No http_management_points table at all.
    _node_computer(con, SCHEMA)
    assert _roles_for(con, "S-1-SS") == {"SMS Site Server"}


def test_site_server_keeps_its_own_site_code_when_http_management_points_is_absent():
    con = _con()
    # Same missing-table scenario, but the site-server row already knows its own
    # code (e.g. a later privileged pass filled it in) -- that must still win.
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_site_servers "
        "(object_sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
        " site_code VARCHAR, mp_host VARCHAR, sccm_infra BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_site_servers VALUES "
        "('S-1-SS', 'PS1-SITE', 'SMS Site Server', 'PS1', 'ps1-mp.mayyhem.com', true)"
    )
    _node_computer(con, SCHEMA)
    assert "SMS Site Server@PS1" in _roles_for(con, "S-1-SS")
