# src/openhound_sccm/site_hierarchy_lowpriv_test.py
"""Tests for _site_hierarchy's low-privilege widening (D5): every raw table that
carries a site_code column feeds site_hierarchy, not just the two privileged
AdminService/WMI sources. See docs/superpowers/specs/2026-07-23-low-priv-assumed-edges-design.md §2.1.
"""
import duckdb
from openhound_sccm.transforms import _bare_site_code_tables, _site_hierarchy

SCHEMA = "sccm"

def _con():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    return con

def _mp_raw(con, rows):
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_management_points_raw "
                "(site_code VARCHAR, site_type VARCHAR, parent_site_code VARCHAR, root_site_code VARCHAR)")
    con.executemany(f"INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES (?,?,?,?)", rows)

def _bare(con, table, rows, extra_cols=""):
    """Create a bare-site-code raw table (the shape most sources have)."""
    con.execute(f"CREATE TABLE {SCHEMA}.{table} (site_code VARCHAR{extra_cols})")
    con.executemany(f"INSERT INTO {SCHEMA}.{table} VALUES (?)", [(r,) for r in rows])

def test_hierarchy_from_ldap_mp_caps_only():
    con = _con()
    # CAS 'CAS' (root), Primary 'PS1' reporting to CAS.
    _mp_raw(con, [("PS1", "Primary Site", "CAS", "CAS"),
                  ("CAS", "Central Administration Site", "None", "CAS")])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    rows = {r[0]: r for r in con.execute(
        f"SELECT site_code, parent_site_code, site_type, root_site_code FROM {SCHEMA}.site_hierarchy").fetchall()}
    assert rows["CAS"][2] == 4 and rows["PS1"][2] == 2
    assert rows["PS1"][3] == "CAS" and rows["CAS"][3] == "CAS"   # root stamped

def test_hierarchy_from_remoteregistry_only_falls_back_to_single_primary():
    con = _con()
    _bare(con, "remoteregistry_sites", ["PS1"])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    row = con.execute(
        f"SELECT site_code, root_site_code FROM {SCHEMA}.site_hierarchy").fetchone()
    # RR gives site_code with no type; the single-site fallback treats it as the root.
    assert row[0] == "PS1" and row[1] == "PS1"

def test_hierarchy_from_ldap_sites_only():
    con = _con()
    # mSSMSSite objects emit the literal 'Undetermined' parent placeholder
    # (ldap.py:197) -- it must normalize to NULL or the parentless-Primary root
    # test silently fails.
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_sites (site_code VARCHAR, parent_site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.ldap_sites VALUES ('PS1','Undetermined')")
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    row = con.execute(f"SELECT site_code, parent_site_code, root_site_code "
                      f"FROM {SCHEMA}.site_hierarchy").fetchone()
    assert row == ("PS1", None, "PS1")

def test_hierarchy_from_anonymous_http_only():
    con = _con()
    # No LDAP, no creds: an anonymous MPKEYINFORMATION probe is the only source.
    _bare(con, "http_management_points", ["PS1"])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT site_code, root_site_code "
                       f"FROM {SCHEMA}.site_hierarchy").fetchone() == ("PS1", "PS1")

def test_hierarchy_from_smb_sites_only():
    con = _con()
    _bare(con, "smb_sites", ["PS1"])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    # Assert the actual row, not just a row count -- a wrong site_code or a
    # wrong/missing root would still leave count(*) == 1 (IMPORTANT-6a).
    row = con.execute(
        f"SELECT site_code, parent_site_code, site_type, root_site_code FROM {SCHEMA}.site_hierarchy"
    ).fetchone()
    assert row == ("PS1", None, None, "PS1")

def test_one_typed_source_rescues_all_the_typeless_ones():
    con = _con()
    # The collapse keeps max(site_type), so a single hierarchy-shaped source
    # types a site that three bare-code sources also reported.
    _mp_raw(con, [("PS1", "Primary Site", "None", "PS1")])
    _bare(con, "smb_sites", ["PS1"])
    _bare(con, "http_management_points", ["PS1"])
    _bare(con, "remoteregistry_sites", ["PS1"])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    rows = con.execute(f"SELECT site_code, site_type FROM {SCHEMA}.site_hierarchy").fetchall()
    assert rows == [("PS1", 2)]      # one row, typed -- not four rows

def test_privileged_still_works():
    con = _con()
    con.execute(f"CREATE TABLE {SCHEMA}.adminservice_site_definitions "
                "(site_code VARCHAR, parent_site_code VARCHAR, site_type VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.adminservice_site_definitions VALUES ('PS1','None','2')")
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT site_type FROM {SCHEMA}.site_hierarchy").fetchone()[0] == 2

def test_single_untyped_site_roots_in_both_modes():
    # One site -> the root is deduced, not guessed, so the flag must not change it.
    def run(disable):
        con = _con()
        _bare(con, "ldap_sites", ["PS1"])
        _site_hierarchy(con, SCHEMA, disable_possible_edges=disable)
        return con.execute(f"SELECT root_site_code FROM {SCHEMA}.site_hierarchy").fetchone()[0]
    assert run(False) == "PS1"
    assert run(True) == "PS1"

def test_multiple_untyped_sites_root_only_when_possible_on():
    # Two untyped sites -> picking one is an assumption; possible-OFF declines.
    def run(disable):
        con = _con()
        _bare(con, "ldap_sites", ["AAA", "BBB"])
        _site_hierarchy(con, SCHEMA, disable_possible_edges=disable)
        return {r[0] for r in con.execute(
            f"SELECT root_site_code FROM {SCHEMA}.site_hierarchy").fetchall()}
    assert run(False) == {"AAA"}     # alphabetical guess, WARNs
    assert run(True) == {None}       # no root asserted, WARNs about unscoped ids

def test_typed_root_unaffected_by_the_flag():
    # A CAS is observed, not guessed -> both modes resolve it identically.
    def run(disable):
        con = _con()
        _mp_raw(con, [("CAS", "Central Administration Site", "None", "CAS"),
                      ("PS1", "Primary Site", "CAS", "CAS")])
        _site_hierarchy(con, SCHEMA, disable_possible_edges=disable)
        return con.execute(f"SELECT DISTINCT root_site_code FROM {SCHEMA}.site_hierarchy").fetchone()[0]
    assert run(False) == run(True) == "CAS"

# --- Fix-round coverage (reviewer findings CRITICAL-1, CRITICAL-2, IMPORTANT-6) ---

def test_bare_source_null_parent_does_not_clobber_privileged_parent():
    # IMPORTANT-6b: the collapse's any_value(parent_site_code) must keep the
    # privileged, real parent -- not silently overwrite it with a bare source's
    # NULL parent for the same site_code. This currently works only because
    # DuckDB's any_value skips NULLs; this test pins that behavior so a future
    # change to the collapse aggregate can't regress it unnoticed.
    con = _con()
    con.execute(f"CREATE TABLE {SCHEMA}.adminservice_site_definitions "
                "(site_code VARCHAR, parent_site_code VARCHAR, site_type VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.adminservice_site_definitions VALUES ('PS1','CAS','2')")
    _bare(con, "smb_sites", ["PS1"])  # bare source: same site_code, no parent at all
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    row = con.execute(f"SELECT parent_site_code FROM {SCHEMA}.site_hierarchy WHERE site_code='PS1'").fetchone()
    assert row[0] == "CAS"

def test_bare_site_code_tables_excludes_reserved_and_internal_names():
    # IMPORTANT-6c: exercise every exclusion filter, including the load-bearing
    # escaped-underscore guard (MINOR-10 / the controller's original warning) --
    # an unescaped 'NOT LIKE '_%'' would treat '_' as a single-character
    # wildcard and exclude every table, including smb_sites itself.
    con = _con()
    _bare(con, "smb_sites", ["PS1"])                       # should be discovered
    con.execute(f"CREATE TABLE {SCHEMA}.node_computer (site_code VARCHAR)")        # node_ prefix
    con.execute(f"CREATE TABLE {SCHEMA}.edge_has_client (site_code VARCHAR)")      # edge_ prefix
    con.execute(f"CREATE TABLE {SCHEMA}._mssql_sql_servers (site_code VARCHAR)")   # leading underscore
    con.execute(f"CREATE TABLE {SCHEMA}.assumed_site_dbs (site_code VARCHAR)")     # explicit exclusion
    con.execute(f"CREATE TABLE {SCHEMA}.site_hierarchy (site_code VARCHAR)")       # explicit exclusion
    assert _bare_site_code_tables(con, SCHEMA) == ["smb_sites"]

def test_typed_but_unrooted_hierarchy_does_not_pick_a_secondary_as_root():
    # CRITICAL-1: AAA is a Secondary reporting to PS1; PS1 is a Primary
    # reporting to a CAS that was never observed. Every site IS typed, so the
    # old "no site had a type" guess path was never even the right branch --
    # and its untyped ORDER BY site_code candidate pool would have picked the
    # alphabetically-first site, 'AAA', a Secondary, as the root. A Secondary
    # must never be a candidate; only the Primary is a viable (still-a-guess)
    # root here, since its own parent (the CAS) was never observed.
    def run(disable):
        con = _con()
        _mp_raw(con, [("AAA", "Secondary Site", "PS1", None),
                      ("PS1", "Primary Site", "CAS", None)])
        _site_hierarchy(con, SCHEMA, disable_possible_edges=disable)
        return con.execute(f"SELECT root_site_code FROM {SCHEMA}.site_hierarchy LIMIT 1").fetchone()[0]
    assert run(False) == "PS1"   # only the Primary is ever a candidate; never the Secondary
    assert run(True) is None     # guessing among unrooted candidates is declined in evidence-only mode

def test_root_site_code_from_ldap_mp_wins_over_typed_root_query():
    # CRITICAL-2: only a single Primary is collected, with no parent (so the old
    # typed-root query -- type=2 AND parentless -- would deduce PS1 itself as
    # the root). But MP capabilities explicitly reported 'CAS' as the true
    # RootSiteCode. That observed fact must win over the derived guess.
    con = _con()
    _mp_raw(con, [("PS1", "Primary Site", "None", "CAS")])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT root_site_code FROM {SCHEMA}.site_hierarchy").fetchone()[0] == "CAS"

def test_multiple_disagreeing_mp_roots_pick_deterministically_in_both_modes():
    # CRITICAL-2: two MPs report different RootSiteCode values -- a
    # multi-hierarchy environment. Still observed evidence (not a guess), so it
    # must resolve identically in both flag modes; pick the smallest deterministically.
    def run(disable):
        con = _con()
        _mp_raw(con, [("PS1", "Primary Site", "None", "ZCAS"),
                      ("PS2", "Primary Site", "None", "ACAS")])
        _site_hierarchy(con, SCHEMA, disable_possible_edges=disable)
        return con.execute(f"SELECT DISTINCT root_site_code FROM {SCHEMA}.site_hierarchy").fetchone()[0]
    assert run(False) == run(True) == "ACAS"

# --- Fix round 2 (reviewer findings FIX-1, FIX-2) ---

def test_privileged_and_bare_source_agree_on_site_code_despite_casing():
    # FIX-1: a privileged source (adminservice) reporting a site code in one
    # case must collapse with a bare/LDAP source reporting the SAME site in a
    # different case -- not split into two rows. Before this fix the
    # adminservice/wmi arms inserted site_code un-uppercased while every other
    # arm upper()'d it, so 'ps1' (privileged) and 'PS1' (bare) would GROUP BY
    # site_code as two distinct sites, fanning out root_site_code and
    # mis-anchoring every SCCM-native id built from it.
    con = _con()
    con.execute(f"CREATE TABLE {SCHEMA}.adminservice_site_definitions "
                "(site_code VARCHAR, parent_site_code VARCHAR, site_type VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.adminservice_site_definitions VALUES ('ps1','None','2')")
    _bare(con, "smb_sites", ["PS1"])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    rows = con.execute(f"SELECT site_code, site_type, root_site_code FROM {SCHEMA}.site_hierarchy").fetchall()
    assert rows == [("PS1", 2, "PS1")]   # one row, not two -- and it kept its type and got a root

# --- Regression: all-NULL source column must not crash or drop the whole arm ---

def test_all_null_parent_site_code_does_not_crash_or_drop_the_arm():
    # A single standalone Primary site genuinely has no parent to report -- the
    # routine low-privilege shape this whole plan targets, not an artificial
    # fixture. Built via CTAS from a VALUES literal (like a real dlt-materialized
    # table would be), NOT this file's other helpers' pre-typed CREATE TABLE +
    # INSERT, so DuckDB infers parent_site_code's type from the data itself: with
    # no non-NULL value anywhere in the column, it can infer INTEGER instead of
    # VARCHAR. Before the fix, _norm_site_code's bare upper() on that column threw
    # a BinderException, _safe() swallowed it as a logged skip, and the WHOLE arm
    # (site_code and site_type included, not just the NULL parent) silently
    # vanished -- so PS1 never reached site_hierarchy at all.
    con = _con()
    con.execute(
        f"CREATE TABLE {SCHEMA}.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)   # must not raise
    row = con.execute(
        f"SELECT site_code, parent_site_code, site_type, root_site_code "
        f"FROM {SCHEMA}.site_hierarchy").fetchone()
    # Proves the arm actually contributed (not just "zero rows, no crash"): the row
    # landed with its real site_type, and the lone parentless Primary is the root.
    assert row == ("PS1", None, 2, "PS1")

def test_all_null_site_code_does_not_crash_the_arm(caplog):
    # Mirror of the above onto site_code itself: the same arms call a bare
    # upper(site_code) directly (not routed through _norm_site_code), so an
    # all-NULL site_code column is exposed to the identical hazard. Every row here
    # has a real parent_site_code/site_type but a NULL site_code, so the row itself
    # is meaningless and correctly disappears in the final WHERE site_code IS NOT
    # NULL collapse either way -- count(*) == 0 alone can't tell "cleanly filtered
    # out" apart from "the whole arm's INSERT BinderException'd and was swallowed",
    # since both produce zero rows. caplog is what actually distinguishes them: a
    # swallowed BinderException logs at ERROR (duckdb_safe.py's non-catalog-error
    # branch), which a clean run never does.
    import logging
    con = _con()
    con.execute(
        f"CREATE TABLE {SCHEMA}.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES (NULL, 'CAS', 2)) AS t(site_code, parent_site_code, site_type)"
    )
    with caplog.at_level(logging.DEBUG, logger="openhound_sccm.transforms"):
        _site_hierarchy(con, SCHEMA, disable_possible_edges=False)   # must not raise
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.site_hierarchy").fetchone()[0] == 0
    assert not any(r.levelno >= logging.ERROR for r in caplog.records), \
        "site_hierarchy<-adminservice must not fail/BinderException on an all-NULL site_code"

# --- Regression round 2 (reviewer C1/I1): a MISSING column, not merely an
# all-NULL one -- the actual production shape. dlt does not materialize an
# all-NULL column as some other type; it drops the column entirely
# (models/raw_table.py; _ensure_columns' own docstring). The tests above build
# their fixture via a VALUES-literal CTAS, which DOES create the column (typed
# INTEGER) -- so they exercise the CAST fix but cannot exercise this one. These
# tests instead CREATE TABLE with the column simply absent, matching what a real
# dlt-materialized table looks like when every row's value for it was NULL. ---

def test_missing_parent_site_code_column_does_not_crash_or_drop_the_arm():
    # A standalone Primary with genuinely no parent to report is exactly the
    # shape that produces a DROPPED parent_site_code column in production, not
    # an INTEGER-typed one. Before the _ensure_columns fix, referencing the
    # absent column raised a BinderException that _safe() swallowed, silently
    # dropping the whole arm (site_code/site_type included).
    con = _con()
    con.execute(
        f"CREATE TABLE {SCHEMA}.adminservice_site_definitions (site_code VARCHAR, site_type VARCHAR)"
    )
    con.execute(f"INSERT INTO {SCHEMA}.adminservice_site_definitions VALUES ('PS1', '2')")
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)   # must not raise
    row = con.execute(
        f"SELECT site_code, parent_site_code, site_type, root_site_code "
        f"FROM {SCHEMA}.site_hierarchy").fetchone()
    assert row == ("PS1", None, 2, "PS1")

def test_missing_site_type_column_does_not_crash_the_arm():
    # Mirror onto site_type: TRY_CAST already tolerates a NULL value, but not a
    # column reference that doesn't compile at all.
    con = _con()
    con.execute(
        f"CREATE TABLE {SCHEMA}.adminservice_site_definitions (site_code VARCHAR, parent_site_code VARCHAR)"
    )
    con.execute(f"INSERT INTO {SCHEMA}.adminservice_site_definitions VALUES ('PS1', NULL)")
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)   # must not raise
    row = con.execute(
        f"SELECT site_code, parent_site_code, site_type, root_site_code "
        f"FROM {SCHEMA}.site_hierarchy").fetchone()
    # Untyped + parentless -> the single-candidate deduction path still finds a root.
    assert row == ("PS1", None, None, "PS1")

def test_missing_root_site_code_column_on_ldap_mp_does_not_abort_the_run():
    # CRITICAL (C1): before the fix, an unguarded reference to a dropped
    # root_site_code column raised an UNCAUGHT BinderException straight out of
    # _site_hierarchy -- a sibling of CatalogException, not a subclass, so the
    # existing `except duckdb.CatalogException` did not catch it -- and
    # transforms() calls _site_hierarchy unwrapped, so this aborted the entire
    # preprocess run, not just one arm. Reproduces the exact routine case
    # collectors/ldap.py:35 describes: every MP's mSSMSCapabilities was
    # empty/unparseable, so RootSiteCode was never populated for any row.
    con = _con()
    con.execute(
        f"CREATE TABLE {SCHEMA}.ldap_management_points_raw "
        "(site_code VARCHAR, site_type VARCHAR, parent_site_code VARCHAR)"
    )
    con.execute(f"INSERT INTO {SCHEMA}.ldap_management_points_raw "
                "VALUES ('PS1', 'Primary Site', NULL)")
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)   # must not raise
    row = con.execute(f"SELECT site_code, root_site_code FROM {SCHEMA}.site_hierarchy").fetchone()
    assert row == ("PS1", "PS1")   # Step A found nothing -> falls through to Step B

def test_root_site_code_sentinel_falls_through_to_typed_root_query():
    # FIX-2: an ldap_management_points_raw row whose root_site_code is the
    # literal 'Undetermined' (or 'None' / '') placeholder must NOT be taken as
    # the observed root by Step A -- it must normalize to NULL and fall
    # through to Step B (the typed CAS/parentless-Primary query), same as an
    # ordinary missing root_site_code (NULL) would.
    con = _con()
    # CAS is real (type 4), so Step B has something to find once Step A
    # correctly declines the sentinel 'Undetermined' root.
    _mp_raw(con, [("CAS", "Central Administration Site", "None", "Undetermined"),
                  ("PS1", "Primary Site", "CAS", "Undetermined")])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT DISTINCT root_site_code FROM {SCHEMA}.site_hierarchy").fetchone()[0] == "CAS"
