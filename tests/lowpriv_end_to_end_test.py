"""End-to-end coverage for the low-privilege assumed-nodes/edges plan
(docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md, Tasks 1/1b/1c/2).

Every other test in this suite calls one builder (``_site_hierarchy``,
``_node_computer``, ``_assumed_site_dbs``, ...) in isolation. That pins each
builder's own contract, but nothing runs the real ``transforms()`` pipeline
over a single, realistic low-privilege fixture -- so nothing pins the actual
headline claim these four tasks make ("a non-privileged run now produces a
usable graph"), and nothing would catch an inter-builder ordering regression
or a whole-graph --disable-possible-edges contract break. This file closes
that gap.

The fixture models a small SCCM hierarchy collected with NO AdminService/WMI
access at all (no adminservice_* / wmi_* tables exist) -- only what a domain
user can read via LDAP, RemoteRegistry, anonymous HTTP, and AD-readable SPNs:

  - LDAP MP-capabilities (``ldap_management_points_raw``): a standalone Primary
    site PS1 whose mSSMSCapabilities XML names PS1 as its own RootSiteCode --
    the true-root signal D4 resolves from (transforms.py Step A), not a guess.
  - ``ldap_sites`` (mSSMSSite object) for PS1, with the 'Undetermined' parent
    placeholder every mSSMSSite object emits (ldap.py:197) -- exercises D5's
    sentinel normalization end-to-end, not just in the ``_site_hierarchy``
    unit tests.
  - A CmRcService-tagged device (``ldap_cmrc_devices``) -- feeds the possible
    SCCM_ClientDevice + SCCM_SameHostAs + SCCM_HasClient family (Tier A).
  - RemoteRegistry on the site server (PS1SRV): the site code, plus BOTH
    'SMS Site Server@PS1' and 'SMS SQL Server@PS1' role tags (the "Multisite
    Component Servers" key was empty -- the site database is local to the
    site server, registry.py:405-418) -- a RemoteRegistry-CONFIRMED site
    database (D2 basis='RemoteRegistry'). Plus a RemoteRegistry current-user
    row -- the HasSession arm that is confirmed and never possible-gated.
  - Anonymous HTTP: MPKEYINFORMATION on a separate management point (PS1MP)
    that also answers as an SMS Provider, plus the sitesigncert probe run
    against PS1MP returning a Site Server certificate for PS1SRV -- the only
    credential-free way to identify a site server (Task 1b / design spec
    Sec4.1), resolved via the mp_host -> http_management_points join (D6).
  - An MSSQLSvc-SPN host (SQL2) with TCP/1433 filtered and no other SCCM role
    at all -- Task 1c's D2(a): the SPN alone is enough for a Computer node +
    MSSQL_Server + MSSQL_HostFor/MSSQL_ExecuteOnHost, unconditionally, even
    though the port never answered and the host is not the site database.

No adminservice_* / wmi_* table exists anywhere in this fixture -- every
signal above is what a plain domain user can collect.
"""
import duckdb

from openhound_sccm.transforms import transforms

SCHEMA = "sccm"

# Stable, readable SIDs for each host in the fixture.
SITE_SERVER_SID = "S-1-5-21-1000-2000-3000-10"   # PS1SRV: site server + site DB (co-located)
MP_SID = "S-1-5-21-1000-2000-3000-20"            # PS1MP: management point + SMS Provider
SPN_SQL_HOST_SID = "S-1-5-21-1000-2000-3000-30"  # SQL2: MSSQLSvc SPN only, 1433 filtered
CURRENT_USER_SID = "S-1-5-21-1000-2000-3000-500"  # logged-on user on PS1SRV
CMRC_DEVICE_SID = "S-1-5-21-1000-2000-3000-2001"  # CmRcService-tagged possible client

ROOT_SITE_CODE = "PS1"


def _build_lowpriv_fixture(con: duckdb.DuckDBPyConnection, disable_possible_edges: bool) -> None:
    """Populate every raw table a low-privilege collection run would produce.

    Deliberately omits every adminservice_* / wmi_* table -- their total
    absence is the point of this fixture, not an oversight.
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")

    # collect-time flag, read by _read_disable_possible (transforms.py:2010).
    con.execute(
        f"CREATE TABLE {SCHEMA}.collection_settings "
        "(disable_possible_edges BOOLEAN, enable_bad_opsec BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.collection_settings VALUES (?, false)",
        [disable_possible_edges],
    )

    # --- LDAP MP-capabilities: standalone Primary, self-rooted (D4 Step A) ---
    con.execute(
        f"CREATE TABLE {SCHEMA}.ldap_management_points_raw ("
        "mp_hostname VARCHAR, site_code VARCHAR, site_type VARCHAR, "
        "parent_site_code VARCHAR, command_line_site_code VARCHAR, "
        "root_site_code VARCHAR, fsp_hostname VARCHAR, fsp_sid VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES "
        "('ps1mp.mayyhem.com', 'PS1', 'Primary Site', 'None', 'PS1', 'PS1', NULL, NULL)"
    )

    # --- ldap_sites (mSSMSSite object): the 'Undetermined' parent sentinel ---
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_sites (site_code VARCHAR, parent_site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.ldap_sites VALUES ('PS1', 'Undetermined')")

    # --- CmRcService-tagged device: possible-client family (Tier A) ---
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_cmrc_devices (object_sid VARCHAR, name VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.ldap_cmrc_devices VALUES ('{CMRC_DEVICE_SID}', 'CLIENT1')")

    # --- RemoteRegistry on the site server: site code + co-located roles ---
    con.execute(f"CREATE TABLE {SCHEMA}.remoteregistry_sites (site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.remoteregistry_sites VALUES ('PS1')")
    con.execute(
        f"CREATE TABLE {SCHEMA}.remoteregistry_computers ("
        "object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, sam_account_name VARCHAR, "
        "disable_loopback_check BOOLEAN, restrict_receiving_ntlm_traffic VARCHAR, "
        "smb_signing_required BOOLEAN, sccm_infra BOOLEAN, sccm_site_system_roles VARCHAR[])"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.remoteregistry_computers VALUES ("
        f"'{SITE_SERVER_SID}', 'PS1SRV', 'ps1srv.mayyhem.com', 'PS1SRV$', "
        "false, NULL, false, true, ['SMS Site Server@PS1', 'SMS SQL Server@PS1'])"
    )
    # RemoteRegistry current-user arm: confirmed, never possible-gated
    # (transforms.py:2798, called unconditionally at transforms.py:3593 equiv.).
    con.execute(
        f"CREATE TABLE {SCHEMA}.remoteregistry_users (object_sid VARCHAR, host_object_sid VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.remoteregistry_users VALUES ('{CURRENT_USER_SID}', '{SITE_SERVER_SID}')"
    )

    # --- Anonymous HTTP: MPKEYINFORMATION + SMS Provider + sitesigncert ---
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_management_points ("
        "object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, sam_account_name VARCHAR, "
        "sccm_site_system_roles VARCHAR, sccm_infra BOOLEAN, client_cert_required BOOLEAN, "
        "site_code VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_management_points VALUES ("
        f"'{MP_SID}', 'PS1MP', 'ps1mp.mayyhem.com', 'PS1MP$', "
        "'Management Point@PS1', true, false, 'PS1')"
    )
    # sitesigncert probe (dialed PS1MP) reports PS1SRV as the Site Server; site
    # code resolved via the mp_host -> http_management_points join (D6, Task 1b).
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_site_servers ("
        "object_sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
        "site_code VARCHAR, mp_host VARCHAR, sccm_infra BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_site_servers VALUES ("
        f"'{SITE_SERVER_SID}', 'PS1SRV', 'SMS Site Server', NULL, 'ps1mp.mayyhem.com', true)"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.http_smsproviders ("
        "object_sid VARCHAR, name VARCHAR, dns_host_name VARCHAR, sam_account_name VARCHAR, "
        "sccm_site_system_roles VARCHAR, sccm_infra BOOLEAN, client_cert_required BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.http_smsproviders VALUES ("
        f"'{MP_SID}', 'PS1MP', 'ps1mp.mayyhem.com', 'PS1MP$', "
        "'SMS Provider@PS1', true, false)"
    )

    # --- MSSQLSvc-SPN host, 1433 filtered, no other SCCM role (D2a, Task 1c) ---
    con.execute(
        f"CREATE TABLE {SCHEMA}.mssql_server_instances ("
        "domain_computer_sid VARCHAR, name VARCHAR, port INTEGER, "
        "has_mssql_spn BOOLEAN, port_open BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.mssql_server_instances VALUES ("
        f"'{SPN_SQL_HOST_SID}', 'sql2.mayyhem.com', 1433, true, false)"
    )


def _run(disable_possible_edges: bool) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    _build_lowpriv_fixture(con, disable_possible_edges)
    transforms(con, schema=SCHEMA)
    return con


def _roles(con, sid) -> set:
    row = con.execute(
        f"SELECT site_system_roles FROM {SCHEMA}.node_computer WHERE sid = ?", [sid]
    ).fetchone()
    return set(row[0]) if row else set()


def _edge_kinds(con) -> set:
    return {k for (k,) in con.execute(f"SELECT DISTINCT kind FROM {SCHEMA}.graph_edges").fetchall()}


# The families this fixture's default-mode run is expected to produce, given
# ONLY the low-priv evidence above and zero adminservice_*/wmi_* tables. This
# is the headline claim of the whole plan: real edges, real inter-builder
# wiring, no privileged collection required.
EXPECTED_DEFAULT_KINDS = {
    "HasSession",
    "MSSQL_CoerceAndRelayToMSSQL",
    "MSSQL_Contains",
    "MSSQL_ControlDB",
    "MSSQL_ControlServer",
    "MSSQL_ExecuteOnHost",
    "MSSQL_HasLogin",
    "MSSQL_HostFor",
    "MSSQL_IsMappedTo",
    "MSSQL_MemberOf",
    "SCCM_AssignAllPermissions",
    "SCCM_CoerceAndRelayToAdminService",
    "SCCM_HasClient",
    "SCCM_LocalAdminRequired",
    "SCCM_SameHostAs",
}

# Kinds this plan's design (docs/superpowers/specs/2026-07-23-low-priv-assumed-edges-design.md
# Sec7) documents as gated by --disable-possible-edges for THIS fixture's shape:
# the possible client device family (SCCM_HasClient + its SCCM_SameHostAs pair)
# and MSSQL_CoerceAndRelayToMSSQL's EPA-off assumption (this fixture's site DB
# has no EPA measurement at all, so null-EPA is only treated as vulnerable in
# default mode). NOTE: SCCM_AssignAllPermissions / SCCM_CoerceAndRelayToAdminService
# / SCCM_LocalAdminRequired are labelled "assumed" in the design doc's Tier-B
# table too, but the current builders (_edge_assign_all_permissions,
# _edge_local_admin_required, _edge_coerce_relay_adminservice) do not gate them
# on disable_possible_edges at all -- they fire off confirmed roles + confirmed
# site_hierarchy alone in both modes. This test pins that OBSERVED behavior
# rather than the design doc's summary table; see final-fix-wave-report.md for
# why this is flagged as a discrepancy worth the human's attention rather than
# something this fix wave changes.
ASSUMED_KINDS_REMOVED_BY_FLAG = {
    "MSSQL_CoerceAndRelayToMSSQL",
    "SCCM_HasClient",
    "SCCM_SameHostAs",
}


def test_lowpriv_default_mode_produces_a_wired_graph():
    """The headline claim: a non-privileged fixture with zero adminservice_*/
    wmi_* tables produces site_hierarchy, tagged roles, an MSSQL side, and a
    non-trivial, specifically-shaped graph -- via the real transforms()
    pipeline, not an isolated builder call."""
    con = _run(disable_possible_edges=False)

    # site_hierarchy is populated, and the root is resolved from the LDAP
    # MP-capabilities RootSiteCode (D4 Step A) -- not guessed via the
    # untyped-root fallback (this fixture has a typed Primary, so that
    # fallback never even runs).
    site_rows = con.execute(
        f"SELECT site_code, parent_site_code, site_type, root_site_code "
        f"FROM {SCHEMA}.site_hierarchy"
    ).fetchall()
    assert site_rows == [("PS1", None, 2, "PS1")]

    # node_computer carries the expected role tags, merged across every arm
    # that contributed to each host (RemoteRegistry + HTTP sitesigncert both
    # tag PS1SRV as 'SMS Site Server@PS1'; that's two independent sources
    # agreeing, not a conflict).
    assert _roles(con, SITE_SERVER_SID) == {"SMS Site Server@PS1", "SMS SQL Server@PS1"}
    assert _roles(con, MP_SID) == {"Management Point@PS1", "SMS Provider@PS1"}

    # The MSSQL side: the RemoteRegistry-confirmed site database (PS1SRV) got
    # its full SCCM-schema scaffolding (arm 1), AND the SPN-only host (SQL2)
    # got a Computer node + MSSQL_Server + host edges purely from its
    # MSSQLSvc SPN, even though 1433 never answered (D2a, Task 1c).
    servers = con.execute(
        f"SELECT server_id, host_sid, sccm_site, sccm_infra "
        f"FROM {SCHEMA}.node_mssql_server ORDER BY server_id"
    ).fetchall()
    assert servers == [
        (f"{SITE_SERVER_SID}:1433", SITE_SERVER_SID, "PS1", True),
        (f"{SPN_SQL_HOST_SID}:1433", SPN_SQL_HOST_SID, None, False),
    ]
    spn_host_computer = con.execute(
        f"SELECT sid, sccm_infra, site_system_roles FROM {SCHEMA}.node_computer WHERE sid = ?",
        [SPN_SQL_HOST_SID],
    ).fetchone()
    assert spn_host_computer == (SPN_SQL_HOST_SID, False, [])
    mssql_host_edges = {
        (s, e, k) for s, e, k in con.execute(
            f"SELECT start_id, end_id, kind FROM {SCHEMA}.graph_edges "
            f"WHERE kind IN ('MSSQL_HostFor', 'MSSQL_ExecuteOnHost') "
            f"  AND (start_id = ? OR end_id = ?)",
            [SPN_SQL_HOST_SID, SPN_SQL_HOST_SID],
        ).fetchall()
    }
    assert mssql_host_edges == {
        (SPN_SQL_HOST_SID, f"{SPN_SQL_HOST_SID}:1433", "MSSQL_HostFor"),
        (f"{SPN_SQL_HOST_SID}:1433", SPN_SQL_HOST_SID, "MSSQL_ExecuteOnHost"),
    }

    # The graph is non-trivial -- pin the KIND SET (what families exist), not
    # a bare count, so a future regression says what broke, not just "24 != 23".
    assert _edge_kinds(con) == EXPECTED_DEFAULT_KINDS

    # HasSession: the RemoteRegistry current-user arm, confirmed evidence,
    # never possible-gated.
    has_session = con.execute(
        f"SELECT start_id, end_id FROM {SCHEMA}.graph_edges WHERE kind = 'HasSession'"
    ).fetchall()
    assert has_session == [(SITE_SERVER_SID, CURRENT_USER_SID)]


def test_disable_possible_edges_removes_exactly_the_assumed_families():
    """The flag contract: --disable-possible-edges removes exactly the assumed
    families for this fixture's shape, and every confirmed item -- site rows,
    observed roles, the SPN host's MSSQL_Server + Computer + host edges,
    HasSession, and the resolved root -- survives unchanged."""
    con_default = _run(disable_possible_edges=False)
    con_disabled = _run(disable_possible_edges=True)

    default_kinds = _edge_kinds(con_default)
    disabled_kinds = _edge_kinds(con_disabled)
    assert default_kinds == EXPECTED_DEFAULT_KINDS  # pin the baseline this diff is measured against

    # Tightening-only: the flag only ever removes kinds, never adds one.
    assert disabled_kinds <= default_kinds
    assert default_kinds - disabled_kinds == ASSUMED_KINDS_REMOVED_BY_FLAG

    # --- Confirmed data must be identical in both modes ---

    # Site rows + the resolved root: site_hierarchy is confirmed data (D5) and
    # is populated identically regardless of the flag.
    site_rows = con_disabled.execute(
        f"SELECT site_code, parent_site_code, site_type, root_site_code "
        f"FROM {SCHEMA}.site_hierarchy"
    ).fetchall()
    assert site_rows == [("PS1", None, 2, "PS1")]

    # Observed roles: unaffected by the flag (they're confirmed, not assumed).
    assert _roles(con_disabled, SITE_SERVER_SID) == {"SMS Site Server@PS1", "SMS SQL Server@PS1"}
    assert _roles(con_disabled, MP_SID) == {"Management Point@PS1", "SMS Provider@PS1"}

    # The SPN host's MSSQL_Server + Computer + HostFor/ExecuteOnHost pair
    # (D2a): unconditional in both modes, since the SPN itself is confirmed
    # evidence, not an assumption.
    spn_server = con_disabled.execute(
        f"SELECT server_id, host_sid, sccm_site, sccm_infra FROM {SCHEMA}.node_mssql_server "
        f"WHERE host_sid = ?",
        [SPN_SQL_HOST_SID],
    ).fetchone()
    assert spn_server == (f"{SPN_SQL_HOST_SID}:1433", SPN_SQL_HOST_SID, None, False)
    spn_host_computer = con_disabled.execute(
        f"SELECT sid, sccm_infra FROM {SCHEMA}.node_computer WHERE sid = ?",
        [SPN_SQL_HOST_SID],
    ).fetchone()
    assert spn_host_computer == (SPN_SQL_HOST_SID, False)
    mssql_host_edges = {
        (s, e, k) for s, e, k in con_disabled.execute(
            f"SELECT start_id, end_id, kind FROM {SCHEMA}.graph_edges "
            f"WHERE kind IN ('MSSQL_HostFor', 'MSSQL_ExecuteOnHost') "
            f"  AND (start_id = ? OR end_id = ?)",
            [SPN_SQL_HOST_SID, SPN_SQL_HOST_SID],
        ).fetchall()
    }
    assert mssql_host_edges == {
        (SPN_SQL_HOST_SID, f"{SPN_SQL_HOST_SID}:1433", "MSSQL_HostFor"),
        (f"{SPN_SQL_HOST_SID}:1433", SPN_SQL_HOST_SID, "MSSQL_ExecuteOnHost"),
    }

    # HasSession: confirmed, present in both modes.
    has_session = con_disabled.execute(
        f"SELECT start_id, end_id FROM {SCHEMA}.graph_edges WHERE kind = 'HasSession'"
    ).fetchall()
    assert has_session == [(SITE_SERVER_SID, CURRENT_USER_SID)]
