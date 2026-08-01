"""Task 2 (D2): non-privileged site-database-server signal, `_assumed_site_dbs`.

Primary signal (basis='RemoteRegistry'): node_computer.site_system_roles already
carries a merged 'SMS SQL Server@<site>' role tag, however it was collected
(AdminService, WMI, or low-priv RemoteRegistry) -- node_computer merges every
source into one array, so the tag's mere presence is the confirmed signal.

Fallback (basis='SPN+SCCM'): a host with an AD-readable MSSQLSvc SPN
(mssql_server_instances.has_mssql_spn, from Task 1c) that is ALSO SCCM-related
(carries some SMS role or sccm_infra). A co-located SQL host need not be *the*
site database, so this is an inference, not a confirmation -- it is dropped
under --disable-possible-edges (D2), while the RemoteRegistry rows survive both
modes.

Deliberately does NOT use the brief's `mssql_spn` boolean stand-in column on
node_computer (that predates has_mssql_spn); instead fixtures the real
mssql_server_instances table and exercises the actual join, per the SPN
predicate this task hinges on: `has_mssql_spn`, not bare presence in the table
(which -- before Task 1c -- meant only "TCP/1433 answered").
"""
import logging

import duckdb

from openhound_sccm.transforms import _assumed_site_dbs, _mssql_sql_servers

SCHEMA = "sccm"


def _con_with_computers(rows):
    """rows: (sid, site_system_roles, sccm_infra) -- the real node_computer shape."""
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_computer "
        "(sid VARCHAR, site_system_roles VARCHAR[], sccm_infra BOOLEAN)"
    )
    con.executemany(f"INSERT INTO {SCHEMA}.node_computer VALUES (?,?,?)", rows)
    return con


def _add_spn_host(con, host_sid, has_mssql_spn=True):
    """Fixture the real mssql_server_instances table (Task 1c shape)."""
    con.execute(
        f"CREATE TABLE {SCHEMA}.mssql_server_instances "
        "(domain_computer_sid VARCHAR, has_mssql_spn BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.mssql_server_instances VALUES (?, ?)",
        [host_sid, has_mssql_spn],
    )


def test_rr_confirmed_site_db_classified():
    con = _con_with_computers([("S-1-DB", ["SMS SQL Server@PS1"], True)])
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    r = con.execute(f"SELECT host_sid, site_code, basis FROM {SCHEMA}.assumed_site_dbs").fetchone()
    assert r == ("S-1-DB", "PS1", "RemoteRegistry")


def test_spn_plus_sccm_related_classified():
    con = _con_with_computers([("S-1-DB", ["SMS Site Server@PS1"], True)])
    _add_spn_host(con, "S-1-DB")
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT basis FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == "SPN+SCCM"


def test_arbitrary_sql_host_not_classified():
    # MSSQLSvc SPN present but the host is NOT SCCM-related (no SMS role, not
    # sccm_infra) -- the SPN alone proves "runs SQL", not "is the site DB".
    con = _con_with_computers([("S-1-RANDOM", [], False)])
    _add_spn_host(con, "S-1-RANDOM")
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0


def test_spn_sccm_host_with_no_site_role_dropped_and_logged_at_info(caplog):
    # IMPORTANT-3 (review round 1): sccm_infra=true with an SPN but NO '@<site>'
    # role at all has no site to attribute -- previously this produced a row
    # ('S-1-DB', None, 'SPN+SCCM') that _mssql_sql_servers filtered out, but
    # Task 4 reads assumed_site_dbs directly and would have inherited the
    # useless row. It must never be inserted in the first place, and the drop
    # is reported at INFO (not WARNING -- there's no clash to name, just nothing
    # to report).
    con = _con_with_computers([("S-1-DB", [], True)])
    _add_spn_host(con, "S-1-DB")
    with caplog.at_level(logging.INFO, logger="openhound_sccm.transforms"):
        _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0
    infos = [r.message for r in caplog.records if r.levelno == logging.INFO]
    assert any("no '@<site>' role" in m and "1" in m for m in infos), infos


def test_spn_fallback_dropped_when_possible_off():
    # D2: SPN + SCCM-relatedness is an inference, so evidence-only mode must not
    # treat the host as the site database. Gated once, here, at the source.
    con = _con_with_computers([("S-1-DB", ["SMS Site Server@PS1"], True)])
    _add_spn_host(con, "S-1-DB")
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=True)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0


def test_rr_confirmed_survives_possible_off():
    con = _con_with_computers([("S-1-DB", ["SMS SQL Server@PS1"], True)])
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=True)
    assert con.execute(f"SELECT basis FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == "RemoteRegistry"


def test_spn_predicate_uses_has_mssql_spn_not_bare_port_reachability():
    # D2's core guardrail: a host merely present in mssql_server_instances (e.g. it
    # answered on port 1433) but WITHOUT an MSSQLSvc SPN must NOT be treated as
    # SPN-confirmed. has_mssql_spn=false must exclude it even though the row exists
    # -- the exact "bare semi-join tests port reachability" trap the brief warns about.
    con = _con_with_computers([("S-1-PORTONLY", ["SMS Site Server@PS1"], True)])
    _add_spn_host(con, "S-1-PORTONLY", has_mssql_spn=False)
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0


def test_missing_has_mssql_spn_column_is_not_a_crash(caplog):
    # Regression for the dlt column-dropping family: mssql_server_instances
    # collected before has_mssql_spn existed (or a load where dlt omitted it)
    # means the column is physically ABSENT, not NULL-filled. A NULL-filled
    # fixture would not reproduce this -- DuckDB binds fine against a real NULL
    # column; it only raises BinderException when the column doesn't exist at
    # all. Must not raise, and must not admit the host (no SPN evidence).
    #
    # Review round 1 (MINOR-5b/MINOR-6): "does not raise" + "0 rows" alone do not
    # pin _ensure_columns -- _safe's broad `except duckdb.Error` swallows the
    # BinderException either way, landing on 0 rows whether or not the guard is
    # in place. The real, testable difference is *how cleanly* it degrades: with
    # _ensure_columns, the query runs and legitimately matches nothing (no error
    # at all); without it, the query fails to bind and _safe logs it at ERROR.
    # Asserting no ERROR-level record fails if _ensure_columns is deleted.
    con = _con_with_computers([("S-1-DB", ["SMS Site Server@PS1"], True)])
    con.execute(f"CREATE TABLE {SCHEMA}.mssql_server_instances (domain_computer_sid VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.mssql_server_instances VALUES ('S-1-DB')")
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)  # must not raise
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0
    errors = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
    assert not errors, (
        "the absent has_mssql_spn column should be a clean, ensure_columns-backfilled "
        f"miss, not a DuckDB error swallowed after the fact: {errors}"
    )


def test_missing_site_system_roles_column_does_not_abort_the_run(caplog):
    # MINOR-4 (review round 1): the reviewer reproduced a HARD ABORT -- an
    # uncaught BinderException escaping _assumed_site_dbs and killing the whole
    # preprocess run -- when node_computer lacked site_system_roles entirely.
    # The original code's two statements (CREATE TABLE + INSERT ... FROM
    # node_computer) were bare `con.execute` calls with a comment arguing the
    # column "cannot be missing" -- the same reasoning that already failed three
    # other times in this plan. Every statement referencing node_computer's
    # optional columns is now run through _ensure_columns + _safe; this must not
    # raise even with node_computer reduced to just `sid`.
    #
    # As with the has_mssql_spn case above, "does not raise" alone doesn't pin
    # _ensure_columns -- the _safe wrap around the CREATE TEMP TABLE statement
    # already prevents the abort by itself, so removing just _ensure_columns
    # would still pass a bare no-raise check. Asserting no ERROR-level record
    # makes the _ensure_columns call provably load-bearing (clean skip vs. a
    # logged DuckDB error) rather than decorative.
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.node_computer (sid VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.node_computer VALUES ('S-1-DB')")
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)  # must not raise
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0
    errors = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
    assert not errors, (
        "the absent site_system_roles/sccm_infra columns should be a clean, "
        f"ensure_columns-backfilled miss, not a DuckDB error swallowed after the fact: {errors}"
    )


def test_ambiguous_rr_site_roles_dropped_not_guessed(caplog):
    # IMPORTANT-2 (review round 1): a host carrying 'SMS SQL Server@<site>' roles
    # for two DIFFERENT sites must not be attributed to whichever one happens to
    # come first in the (unordered, de-duplicated) role array -- D6 forbids
    # guessing. It must be dropped, with a WARNING naming the host and both codes.
    con = _con_with_computers(
        [("S-1-DB", ["SMS SQL Server@PS1", "SMS SQL Server@PS2"], True)]
    )
    with caplog.at_level(logging.WARNING, logger="openhound_sccm.transforms"):
        _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("S-1-DB" in w and "PS1" in w and "PS2" in w for w in warnings), warnings


def test_ambiguous_spn_sccm_site_roles_dropped_not_guessed(caplog):
    # IMPORTANT-2's exact reviewer repro: a host with an SPN carrying roles for
    # TWO different sites (Distribution Point@PS2, Site Server@PS1) was being
    # silently attributed to PS2 via array position [1]. Must now drop instead.
    con = _con_with_computers(
        [("S-1-DB", ["SMS Distribution Point@PS2", "SMS Site Server@PS1"], True)]
    )
    _add_spn_host(con, "S-1-DB")
    with caplog.at_level(logging.WARNING, logger="openhound_sccm.transforms"):
        _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("S-1-DB" in w and "PS1" in w and "PS2" in w for w in warnings), warnings


def test_role_tag_and_spn_together_yields_one_row_not_two():
    # MINOR-5(a): a host that is BOTH RemoteRegistry-confirmed (carries the
    # 'SMS SQL Server@<site>' tag) AND has an MSSQLSvc SPN must get exactly ONE
    # assumed_site_dbs row, basis='RemoteRegistry' -- not two rows with two
    # different basis values, which would make Task 4's provenance stamp
    # ambiguous. This regresses if the SPN+SCCM arm's
    # "len(list_filter(..., 'SMS SQL Server@%')) = 0" exclusion is ever removed.
    con = _con_with_computers([("S-1-DB", ["SMS SQL Server@PS1"], True)])
    _add_spn_host(con, "S-1-DB")
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    rows = con.execute(f"SELECT host_sid, site_code, basis FROM {SCHEMA}.assumed_site_dbs").fetchall()
    assert rows == [("S-1-DB", "PS1", "RemoteRegistry")]


def test_non_privileged_pair_reaches_mssql_sql_servers():
    # IMPORTANT-1 (review round 1): the second deliverable -- _mssql_sql_servers'
    # new non-privileged arm -- had NO test coverage; deleting it left the suite
    # green. This pins the end-to-end path: assumed_site_dbs -> _mssql_sql_hosts
    # -> _mssql_sql_servers, with the same columns the privileged arms produce.
    con = _con_with_computers([("S-1-DB", ["SMS SQL Server@PS1"], True)])
    con.execute(f"ALTER TABLE {SCHEMA}.node_computer ADD COLUMN dnshostname VARCHAR")
    con.execute(
        f"UPDATE {SCHEMA}.node_computer SET dnshostname = 'SQL01.mayyhem.com' "
        f"WHERE sid = 'S-1-DB'"
    )
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_site "
        "(site_code VARCHAR, root_site_code VARCHAR, sql_service_port VARCHAR, "
        " sql_database_name VARCHAR, sql_service_account_name VARCHAR, "
        " sql_service_account_domain_sid VARCHAR)"
    )
    con.execute(f"INSERT INTO {SCHEMA}.node_site VALUES ('PS1','PS1',NULL,NULL,NULL,NULL)")
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    _mssql_sql_servers(con, SCHEMA)
    row = con.execute(
        f"SELECT site_code, root_site_code, host_sid, dns_host_name, port, db_name "
        f"FROM {SCHEMA}._mssql_sql_servers WHERE host_sid = 'S-1-DB'"
    ).fetchone()
    assert row == ("PS1", "PS1", "S-1-DB", "SQL01.mayyhem.com", "1433", "CM_PS1")


# --- con-be15: an assumed SQL role needs a live-SQL signal to survive -------
#
# The RemoteRegistry arm treats the mere presence of an 'SMS SQL Server@<site>'
# tag as confirmed. That tag can come from the registry collector's empty-key
# inference ("Multisite Component Servers present but empty" -> the site database
# is local), which is wrong for a PASSIVE site server whose database lives
# elsewhere. The collector now flags those rows sql_role_assumed=True; here we
# require corroboration before believing them. Corroboration is a live answer on
# 1433 (mssql_server_instances.port_open), because the other candidate signals do
# not work: the SQL registry keys are admin-gated, and the MSSQLSvc SPN sits on
# the service account, so a real site database running as LocalSystem has none.

def _add_assumed_sql_role(con, host_sid, assumed=True):
    """Fixture remoteregistry_computers as the collector emits it.

    sccm_site_system_roles is typed JSON here, not VARCHAR[], because that is what
    dlt actually lands for this table -- confirmed against a real collection. An
    earlier version of this fixture used VARCHAR[]; the tests passed while the gate
    silently no-opped in production, because list_filter() cannot bind on a JSON
    column and _safe swallowed the BinderException. Keep this matching reality.
    """
    con.execute(
        f"CREATE TABLE IF NOT EXISTS {SCHEMA}.remoteregistry_computers "
        "(object_sid VARCHAR, sccm_site_system_roles JSON, sql_role_assumed BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.remoteregistry_computers VALUES (?, ?, ?)",
        [host_sid, '["SMS SQL Server@PS1", "SMS Site Server@PS1"]', assumed],
    )


def _add_live_sql(con, host_sid, port_open=True):
    con.execute(
        f"CREATE TABLE IF NOT EXISTS {SCHEMA}.mssql_server_instances "
        "(domain_computer_sid VARCHAR, has_mssql_spn BOOLEAN, port_open BOOLEAN)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.mssql_server_instances VALUES (?, ?, ?)",
        [host_sid, False, port_open],
    )


def test_assumed_sql_role_without_live_sql_is_dropped():
    """A passive site server: empty key, nothing listening on 1433 -> not a site DB."""
    con = _con_with_computers([("S-1-PSV", ["SMS SQL Server@PS1"], True)])
    _add_assumed_sql_role(con, "S-1-PSV")
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(
        f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs WHERE host_sid='S-1-PSV'"
    ).fetchone()[0] == 0


def test_assumed_sql_role_with_live_sql_is_kept():
    """A real local site database (mayyhem's SEC secondary) still classifies."""
    con = _con_with_computers([("S-1-SEC", ["SMS SQL Server@PS1"], True)])
    _add_assumed_sql_role(con, "S-1-SEC")
    _add_live_sql(con, "S-1-SEC", port_open=True)
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(
        f"SELECT basis FROM {SCHEMA}.assumed_site_dbs WHERE host_sid='S-1-SEC'"
    ).fetchone()[0] == "RemoteRegistry"


def test_unflagged_sql_role_is_kept_without_corroboration():
    """The populated-key branch names real database servers -- no gate applies."""
    con = _con_with_computers([("S-1-DB", ["SMS SQL Server@PS1"], True)])
    _add_assumed_sql_role(con, "S-1-DB", assumed=False)
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(
        f"SELECT basis FROM {SCHEMA}.assumed_site_dbs WHERE host_sid='S-1-DB'"
    ).fetchone()[0] == "RemoteRegistry"
