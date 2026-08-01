# src/openhound_sccm/transforms.py
"""DuckDB transforms for the SCCM collector's preproc phase.

Stage 1 builds the cross-cutting lookup tables (`principal_by_name`, site hierarchy
with `root_site_code`) and — added in later tasks — the coalesced `node_*` tables and
`graph_edges`. Each builder is defensive: a missing source table is logged and
skipped (early stages won't have collected everything).
"""
import logging
import os
from typing import Any

import duckdb

from openhound_collector_common.dlt.duckdb_safe import arr_sql, ensure_columns, safe_execute

logger = logging.getLogger(__name__)

# Truthy spellings accepted for the SOURCES__SCCM__DISABLE_POSSIBLE_EDGES env override.
_TRUTHY_ENV = frozenset({"1", "true", "yes", "on"})


def _privileged_transport_ran(con: duckdb.DuckDBPyConnection) -> bool:
    """True if any AdminService/WMI source table exists — i.e. a privileged
    transport collected at least one host this run.

    HTTP and SMB are *fallback* phases: ``should_run_phase`` skips them for any
    host a privileged transport already collected (per_host_phases.py:116,
    mirroring ConfigManBearPig.ps1:8617). So when a privileged transport ran, an
    absent http_/smb_ role table just means every host they would cover was
    collected the privileged way — an expected, benign miss, not a real problem.
    The clearest example: the SMS Provider *is* the AdminService host, so it is
    privileged-collected and its HTTP probe is skipped, leaving http_smsproviders
    empty in every normal authenticated run.
    """
    try:
        found = con.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name LIKE 'adminservice_%' OR table_name LIKE 'wmi_%' "
            "LIMIT 1"
        ).fetchone()
    except duckdb.Error:
        # Can't query the catalog — stay safe and treat as "not privileged" (WARNING).
        return False
    return found is not None


def _sccm_expected_miss(con: duckdb.DuckDBPyConnection, missing: str) -> bool:
    """`expected_miss` predicate for the shared `safe_execute`: return True to
    downgrade a missing-source-table log from WARNING to DEBUG.

    Two benign-miss cases are specific to this collector:

    1. Fallback-phase skip (http_ / smb_ tables). Handled by
       ``_privileged_transport_ran``: when a privileged transport ran this
       collection, an absent http_/smb_ role table is expected. In an
       HTTP-only/SMB-only run (no privileged table) it stays a WARNING.

    2. Transport-mirror (wmi_ <-> adminservice_). The collector produces EITHER
       wmi_<X> OR adminservice_<X> per data type — whichever transport was
       available. A missing one whose sibling exists is a normal, expected miss.

    Any other missing table has no such excuse and stays a WARNING. The catalog
    lookups are schema-agnostic (match on table_name across schemas); under the
    collector's single `sccm` schema this is equivalent to a schema-scoped check.
    """
    # Case 1: HTTP/SMB are fallback phases — absent role tables are expected once
    # a privileged transport has collected the hosts they would have covered.
    if missing.startswith(("http_", "smb_")):
        return _privileged_transport_ran(con)

    # Case 2: wmi_/adminservice_ transport mirror — expected when the sibling ran.
    if missing.startswith("wmi_"):
        sibling = "adminservice_" + missing[len("wmi_"):]
    elif missing.startswith("adminservice_"):
        sibling = "wmi_" + missing[len("adminservice_"):]
    else:
        # Neither a fallback nor a transport-mirror prefix: a real miss (WARNING).
        return False
    try:
        found = con.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = ?",
            [sibling],
        ).fetchone()
    except duckdb.Error:
        # Can't query the catalog — stay safe and treat as a real miss (WARNING).
        return False
    return found is not None


def _safe(con: duckdb.DuckDBPyConnection, label: str, sql: str) -> None:
    """Run one SQL statement; log and continue if a source table is missing.

    Thin wrapper over the shared `safe_execute` engine, injecting SCCM's
    expected-miss downgrade (`_sccm_expected_miss`: wmi/adminservice transport
    mirror + http/smb fallback-phase skip) and this module's logger so log
    records stay under `openhound_sccm.transforms`.
    """
    safe_execute(con, label, sql, expected_miss=_sccm_expected_miss, logger=logger)


def _ensure_columns(
    con: duckdb.DuckDBPyConnection,
    schema: str,
    table: str,
    coldefs: dict[str, str],
) -> None:
    """Add any missing columns (as NULL, typed) so a coalesce SELECT always binds.

    Thin wrapper over the shared `ensure_columns`, passing this module's logger so
    its DEBUG records stay under `openhound_sccm.transforms`. Why it's needed: a
    coalesce SELECT references source columns inside expressions
    (e.g. ``_arr('sccm_site_system_roles')``, ``coalesce(sccm_infra, false)``);
    ``INSERT ... BY NAME`` only maps *output* aliases, so every referenced source
    column must physically exist or the whole SELECT fails to compile and ``_safe``
    drops the source. Columns go missing when the source never emits them (e.g.
    ldap_cmrc_devices has no roles column) or dlt drops an all-NULL column.
    """
    ensure_columns(con, schema, table, coldefs, logger=logger)


def _column_exists(con: duckdb.DuckDBPyConnection, schema: str, table: str, column: str) -> bool:
    """True if *table* in *schema* currently has a column named *column*.

    Backed by information_schema, which returns zero rows for a table that
    doesn't exist yet — no try/except needed here (unlike a direct SELECT
    against the table itself, which would raise CatalogException).
    """
    row = con.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_schema = ? AND table_name = ? AND column_name = ?",
        [schema, table, column],
    ).fetchone()
    return row is not None


# SCCM's former _arr was byte-identical to the shared arr_sql (normalize a
# list-shaped column to VARCHAR[] whatever physical shape dlt produced). Pure SQL
# string builder, no logging — alias directly.
_arr = arr_sql


def _scalar(con: duckdb.DuckDBPyConnection, *execute_args: Any) -> Any:
    """First column of the first row of a scalar query. Same arguments as ``con.execute``.

    DuckDB types ``fetchone()`` as ``tuple[Any, ...] | None``, so the bare
    ``con.execute(...).fetchone()[0]`` idiom this module used 28 times was 28 type errors —
    mypy cannot know that a ``count(*)`` always returns a row.

    Raising on a missing row is deliberate rather than returning None: every caller here
    runs an aggregate (``count``/``min``/``max``) or a ``LIMIT 1`` lookup that always
    yields exactly one row, so no row means the query is not the one the caller believes
    it is. Failing here names the query; a ``TypeError`` three frames away does not.
    """
    row = con.execute(*execute_args).fetchone()
    if row is None:
        raise RuntimeError(f"scalar query returned no row: {execute_args[0]!r}")
    return row[0]


def _principal_by_name(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Union every collected (name, SID) pair for offline name->SID resolution.

    Each source table is optional — a missing table is logged and skipped. The
    result is deduplicated with SIDs uppercased; names are stored in their
    original casing (callers must upper() both sides when joining on name).
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.principal_by_name (name VARCHAR, sid VARCHAR)")

    # Each entry is (label, SELECT statement yielding (name, sid) columns).
    sources = [
        ("principal_by_name<-adminservice_r_system",
         f"SELECT name, sid FROM {schema}.adminservice_r_system WHERE sid IS NOT NULL"),
        ("principal_by_name<-wmi_r_system",
         f"SELECT name, sid FROM {schema}.wmi_r_system WHERE sid IS NOT NULL"),
        ("principal_by_name<-adminservice_r_user",
         f"SELECT name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL"),
        ("principal_by_name<-wmi_r_user",
         f"SELECT name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL"),
        # SMS_R_UserGroup carries each security group's own SID + its DOMAIN\name
        # (unique_usergroup_name), so the security_group_name memberships on r_system /
        # r_user rows resolve to a group SID here (offline) instead of a live AD lookup.
        ("principal_by_name<-adminservice_user_group",
         f"SELECT unique_usergroup_name AS name, sid FROM {schema}.adminservice_user_group WHERE sid IS NOT NULL"),
        ("principal_by_name<-wmi_user_group",
         f"SELECT unique_usergroup_name AS name, sid FROM {schema}.wmi_user_group WHERE sid IS NOT NULL"),
        ("principal_by_name<-adminservice_admins",
         f"SELECT logon_name AS name, admin_sid AS sid FROM {schema}.adminservice_admins WHERE admin_sid IS NOT NULL"),
        ("principal_by_name<-wmi_admins",
         f"SELECT logon_name AS name, admin_sid AS sid FROM {schema}.wmi_admins WHERE admin_sid IS NOT NULL"),
        # DOMAIN\user / UPN name forms from r_user so device primary/current user and SQL service
        # account fields (which carry these forms) resolve to a SID via principal_by_name.
        ("principal_by_name<-adminservice_r_user_unique",
         f"SELECT unique_user_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND unique_user_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_unique",
         f"SELECT unique_user_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND unique_user_name IS NOT NULL"),
        ("principal_by_name<-adminservice_r_user_full",
         f"SELECT full_user_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND full_user_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_full",
         f"SELECT full_user_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND full_user_name IS NOT NULL"),
        ("principal_by_name<-adminservice_r_user_upn",
         f"SELECT user_principal_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND user_principal_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_upn",
         f"SELECT user_principal_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND user_principal_name IS NOT NULL"),
    ]

    for label, select_sql in sources:
        # Preserve the original name casing; only uppercase the SID for consistent lookups.
        _safe(
            con,
            label,
            f"INSERT INTO {schema}.principal_by_name "
            f"SELECT trim(name), upper(sid) FROM ({select_sql})",
        )

    # Replace the raw inserts with a deduplicated copy.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.principal_by_name AS "
        f"SELECT DISTINCT name, sid FROM {schema}.principal_by_name "
        f"WHERE name IS NOT NULL AND sid IS NOT NULL"
    )
    logger.info("principal_by_name built in schema %r", schema)


# 'None' / 'Undetermined' / '' are placeholders several collectors emit for an
# unknown parent OR root (e.g. ldap_sites:197 for parent; MP capabilities can
# in principle emit the same placeholders for root_site_code). Both columns
# hold "a site code this collector may not have resolved yet", so both must
# normalize these to NULL or the parentless-Primary root test in
# _site_hierarchy silently never matches. One constant, one SQL fragment, so
# every consumer (the arms below and the root query) agrees on what a
# placeholder looks like -- previously the root query re-typed this list
# inline and could drift from the arms' own normalization.
_SITE_CODE_SENTINELS = ("None", "Undetermined", "")
_SITE_CODE_SENTINEL_SQL = ", ".join(f"'{s}'" for s in _SITE_CODE_SENTINELS)

# "This site is NOT a secondary" -- same one-constant reasoning as the sentinels
# above. Five builders need it (_edge_contains, _edge_all_permissions,
# _edge_assign_all_permissions, _edge_local_admin_required, _edge_coerce_relay_smb)
# and each used to inline its own copy, so the unknown-type policy could drift
# between them.
#
# con-edee: that policy was `coalesce(site_type, 0) != 1`, i.e. anything not
# explicitly Secondary counts as non-secondary -- which silently includes a site
# whose type is UNKNOWN. At low privilege that is backwards. A site discovered only
# as a bare site code (mayyhem's SEC secondary, learned from SMB share comments)
# carries site_type NULL, so every SMS Provider gained a spurious
# hierarchy-takeover edge to it: 12 SCCM_AssignAllPermissions edges where the lab
# has 8. Requiring a KNOWN Primary (2) or CAS (4) inverts the default to "exclude
# what we could not characterize", because a false "can take over this site" edge
# costs an operator more than a missing one.
#
# This does not cost coverage on a site the collector actually characterized: every
# privileged source states the type outright, and at low privilege _site_hierarchy's
# CAS/Secondary inference derives it (mayyhem's CAS and PS1 are both typed in a
# lowpriv run; only the bare-code SEC is not).
_NON_SECONDARY_SITE_TYPE_SQL = "site_type IN (2, 4)"


def _norm_site_code(col: str) -> str:
    """SQL fragment: a parent/root site-code column with sentinels normalized to NULL.

    Casts to VARCHAR before comparing/upper-casing. When every row of *col* collected
    this run is NULL -- the routine low-privilege shape this whole plan targets (e.g.
    a single standalone Primary site genuinely has no parent to report) -- there is no
    non-NULL value in the column to infer a type from, and DuckDB can infer it as
    INTEGER instead of VARCHAR. A bare upper() on that then raises a BinderException;
    _safe() swallows it as a logged skip, which silently drops the WHOLE arm -- not
    just this column, but every other value (site_code, site_type, ...) that arm would
    have contributed. The CAST makes this type-safe regardless of what DuckDB inferred
    (same fix pattern already used ad hoc elsewhere in this file, e.g. for
    restrict_receiving_ntlm_traffic / extended_protection).
    """
    c = f"CAST({col} AS VARCHAR)"
    return f"CASE WHEN {c} IN ({_SITE_CODE_SENTINEL_SQL}) THEN NULL ELSE upper({c}) END"


# Tables already consumed with their full hierarchy shape (type + parent + root);
# re-reading them as bare codes in the discovery loop below would be harmless but
# confusing in the logs.
_HIERARCHY_SHAPED = frozenset({
    "adminservice_site_definitions", "wmi_site_definitions", "ldap_management_points_raw",
})


def _bare_site_code_tables(con: duckdb.DuckDBPyConnection, schema: str) -> list[str]:
    """Every raw table in *schema* carrying a site_code column, minus the ones
    already loaded above with their parent/type (D5).

    Discovered rather than hardcoded so a new collector that learns a site code
    feeds the hierarchy automatically, and so absent tables need no _safe guard —
    they simply aren't listed. A site_code appearing anywhere is evidence that
    site exists, so widening the net cannot invent a site.

    `_site_hierarchy` runs first in `transforms()`, before any node_*/edge_* table
    exists, so those two guards below are pure defence for a future reordering —
    they can't currently exclude anything. The underscore-prefixed and
    `assumed_site_dbs` exclusions serve the same defensive purpose: they keep this
    loop from ever feeding on transforms' own derived output if it is ever called
    again after those tables exist. Every `LIKE` that targets a literal
    underscore is `ESCAPE`d -- in DuckDB (as in standard SQL) an unescaped `_`
    in a LIKE pattern is a single-character wildcard, so an unescaped
    `'node_%'`/`'edge_%'`/`'_%'` would also match names like `nodeX...` or,
    worse, match (and so silently exclude) every table name via the bare `_%`
    guard.
    """
    rows = con.execute(
        "SELECT table_name FROM information_schema.columns "
        "WHERE table_schema = ? AND column_name = 'site_code' "
        "  AND table_name NOT LIKE 'node\\_%' ESCAPE '\\' "
        "  AND table_name NOT LIKE 'edge\\_%' ESCAPE '\\' "
        "  AND table_name NOT LIKE '\\_%' ESCAPE '\\' "
        "  AND table_name <> 'site_hierarchy' AND table_name <> 'assumed_site_dbs' "
        "ORDER BY table_name",
        [schema],
    ).fetchall()
    return [t for (t,) in rows if t not in _HIERARCHY_SHAPED]


def _site_hierarchy(con: duckdb.DuckDBPyConnection, schema: str, disable_possible_edges: bool) -> None:
    """Build site_code/parent_site_code/site_type, then stamp root_site_code.

    Root resolution is tried in order of strongest evidence first (D4/D5):
      A. `ldap_management_points_raw.root_site_code` — the site the MP
         capabilities XML itself names as root. Observed evidence, not derived,
         so it wins over B/C and applies in BOTH flag modes.
      B. CAS (site_type=4) if present, else a parentless Primary (site_type=2) —
         matching CMBP Get-HierarchyRoot (ps1:2620). Also observed, both modes.
      C. Only if A and B found nothing: a best-effort guess among the remaining
         untyped-or-Primary sites (never a Secondary — see Step C below), gated
         by `disable_possible_edges` except in the single-parentless-candidate
         case, which is deduction rather than a guess.
    Single-hierarchy assumption (README Assumptions): one root per graph.
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.site_hierarchy "
        f"(site_code VARCHAR, parent_site_code VARCHAR, site_type INTEGER)"
    )

    # Load from whichever site-definition sources were collected. site_code is
    # upper()'d here for the same reason every other arm upper()s it: the
    # collapse below groups by site_code, so if this privileged source and a
    # low-priv source (LDAP/HTTP/SMB, all upper()'d) ever disagree only on
    # casing for the same site, the un-normalized version would split into two
    # rows -- fanning out root_site_code and mis-anchoring every SCCM-native id
    # built from it. This was a latent risk introduced by D5 (before it, both
    # arms here were the only feeders, so a self-consistent casing was
    # guaranteed); site codes are already uppercase on live data, so this is a
    # no-op there. Sentinel parents are normalized here too (IMPORTANT-4) --
    # without it a privileged collection can still store a literal '' / 'None'
    # parent instead of NULL, which would silently fail the parentless-Primary
    # check in Step B below.
    #
    # site_code itself is cast to VARCHAR before upper() throughout this function
    # (here and in every arm below), for the same type-safety reason _norm_site_code
    # now casts: if site_code is all-NULL for a source's whole load, DuckDB can infer
    # it as a non-VARCHAR type and a bare upper() would BinderException the entire
    # arm away.
    #
    # But an all-NULL column is the FIXTURE shape, not the production one: dlt does
    # not materialize an all-NULL column as some other type -- it drops the column
    # entirely (models/raw_table.py, _ensure_columns' own docstring). A dropped
    # column raises the exact same BinderException the CAST above guards against,
    # so every raw column any arm below references must ALSO go through
    # _ensure_columns first -- the CAST alone only protects the test-fixture shape.
    # This mirrors the protection the bare-code loop already has via
    # _column_exists/has_parent a few lines down; these three hierarchy-shaped arms
    # never had it.
    for _hs in ("adminservice_site_definitions", "wmi_site_definitions"):
        _ensure_columns(con, schema, _hs, {
            "site_code": "VARCHAR", "parent_site_code": "VARCHAR", "site_type": "VARCHAR",
        })
    _safe(
        con,
        "site_hierarchy<-adminservice",
        f"INSERT INTO {schema}.site_hierarchy "
        f"SELECT upper(CAST(site_code AS VARCHAR)), {_norm_site_code('parent_site_code')}, "
        f"  TRY_CAST(site_type AS INTEGER) "
        f"FROM {schema}.adminservice_site_definitions",
    )
    _safe(
        con,
        "site_hierarchy<-wmi",
        f"INSERT INTO {schema}.site_hierarchy "
        f"SELECT upper(CAST(site_code AS VARCHAR)), {_norm_site_code('parent_site_code')}, "
        f"  TRY_CAST(site_type AS INTEGER) "
        f"FROM {schema}.wmi_site_definitions",
    )

    # LDAP management-point capabilities already carry site type/parent/root
    # (collectors/ldap.py _parse_mp_capabilities). Low-priv reachable; feed them
    # so a domain-only bind still yields a hierarchy. String site_type -> INTEGER
    # contract (1=Secondary, 2=Primary, 4=CAS). root_site_code is read separately
    # in Step A below (it is not a site_hierarchy row column; it is used once to
    # resolve root_code directly) -- ensured here too since Step A reads the same
    # table and would otherwise hit the identical dropped-column BinderException
    # (reviewer C1: collectors/ldap.py:35 defaults root_site_code to None, so a run
    # where every MP's mSSMSCapabilities is empty/unparseable never populates it,
    # and dlt drops the resulting all-NULL column entirely).
    _ensure_columns(con, schema, "ldap_management_points_raw", {
        "site_code": "VARCHAR", "parent_site_code": "VARCHAR", "site_type": "VARCHAR",
        "root_site_code": "VARCHAR",
    })
    _safe(
        con,
        "site_hierarchy<-ldap_mp",
        f"INSERT INTO {schema}.site_hierarchy "
        f"SELECT DISTINCT upper(CAST(site_code AS VARCHAR)), {_norm_site_code('parent_site_code')}, "
        f"  CASE site_type WHEN 'Central Administration Site' THEN 4 "
        f"                 WHEN 'Primary Site' THEN 2 "
        f"                 WHEN 'Secondary Site' THEN 1 ELSE NULL END "
        f"FROM {schema}.ldap_management_points_raw WHERE site_code IS NOT NULL",
    )

    # D5: every other site-code source registers its bare code. No type/parent, so
    # the collapse below lets any richer row for the same code win (max(site_type)).
    # Track which tables actually inserted a row (IMPORTANT-8): several bare
    # tables exist but carry only NULL site codes for every record they collect
    # (e.g. adminservice_admins), so "N tables discovered" overstates what was
    # actually learned -- log what contributed instead.
    bare_tables = _bare_site_code_tables(con, schema)
    contributed = []
    for table in bare_tables:
        # _bare_site_code_tables just confirmed this table exists (via
        # information_schema, moments ago, on this same single-threaded
        # connection), so this COUNT cannot hit a missing-table error. It
        # references a dynamic column type, though (like every other query in
        # this family), so a try/except still guards it for consistency: a
        # LIST/STRUCT/BLOB-typed site_code would fail the CAST/upper() with a
        # BinderException. This value only feeds the "which tables
        # contributed" log line below, not site_hierarchy itself -- the
        # _safe-wrapped INSERT further down is a separate statement and is
        # unaffected either way -- so a failure here just falls back to
        # "nothing counted" rather than aborting the loop.
        try:
            site_code_count = _scalar(con,
                f"SELECT count(DISTINCT upper(CAST(site_code AS VARCHAR))) "
                f"FROM {schema}.{table} WHERE site_code IS NOT NULL"
            )
        except duckdb.BinderException as ex:
            logger.debug(
                "site_hierarchy: could not count distinct site codes in %r for the "
                "contributor log line (%s); treating as zero", table, ex,
            )
            site_code_count = 0
        # Some bare sources (e.g. http_management_points) never collected a
        # parent_site_code column at all; referencing a column that doesn't
        # exist would fail the whole SELECT, so fall back to a literal NULL.
        has_parent = _column_exists(con, schema, table, "parent_site_code")
        parent_expr = _norm_site_code("parent_site_code") if has_parent else "NULL"
        _safe(
            con,
            f"site_hierarchy<-{table}",
            f"INSERT INTO {schema}.site_hierarchy "
            f"SELECT DISTINCT upper(CAST(site_code AS VARCHAR)), {parent_expr}, NULL "
            f"FROM {schema}.{table} WHERE site_code IS NOT NULL",
        )
        if site_code_count:
            contributed.append(table)
    logger.info(
        "site_hierarchy: %d of %d discovered bare-code source table(s) actually contributed a "
        "site code in schema %r: %s",
        len(contributed), len(bare_tables), schema, contributed,
    )

    # Collapse duplicate rows (same site_code from multiple sources). any_value
    # skips NULLs (picks the first non-null value in the group), so a bare
    # source's NULL parent never overwrites a richer source's real parent for
    # the same site_code -- pinned by
    # test_bare_source_null_parent_does_not_clobber_privileged_parent.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.site_hierarchy AS "
        f"SELECT site_code, "
        f"       any_value(parent_site_code) AS parent_site_code, "
        f"       max(site_type) AS site_type "
        f"FROM {schema}.site_hierarchy "
        f"WHERE site_code IS NOT NULL "
        f"GROUP BY site_code"
    )

    # --- Infer the site types the collected sources could not state ---
    # Only management-point capabilities carry an explicit site_type, and a CAS has no
    # management point, so a CAS is NEVER typed directly: live 2026-07-28 low-priv run
    # produced ldap_management_points_raw = [('PS1','Primary Site','CAS','CAS')] and
    # nothing at all for CAS, leaving site_hierarchy = [('CAS',NULL,NULL),('PS1','CAS',2)].
    # That silently cost every SCCM_AdminsReplicatedTo edge, because _edge_replication
    # joins on `child.site_type = 2 AND parent.site_type = 4`.
    #
    # Both rules below are deductions from SCCM's hierarchy model, not guesses: a Primary
    # site's parent can only be a CAS, and a site whose parent is a Primary can only be a
    # Secondary. Each fires only where the type is currently unknown, so an explicitly
    # collected type always wins.
    for label, sql in (
        ("cas-from-primary-parent",
         f"UPDATE {schema}.site_hierarchy SET site_type = 4 WHERE site_type IS NULL "
         f"AND site_code IN (SELECT parent_site_code FROM {schema}.site_hierarchy "
         f"                  WHERE site_type = 2 AND parent_site_code IS NOT NULL)"),
        ("secondary-from-primary-parent",
         f"UPDATE {schema}.site_hierarchy SET site_type = 1 WHERE site_type IS NULL "
         f"AND parent_site_code IN (SELECT site_code FROM {schema}.site_hierarchy "
         f"                         WHERE site_type = 2)"),
    ):
        try:
            n = con.execute(sql).fetchone()
            changed = n[0] if n else 0
            if changed:
                logger.info("site_hierarchy: inferred site_type for %s site(s) via %s",
                            changed, label)
            else:
                logger.debug("site_hierarchy: %s inferred nothing", label)
        except duckdb.Error as ex:
            # Never fatal: an un-inferred type only costs edges, whereas aborting
            # preprocess costs the whole graph.
            logger.warning("site_hierarchy: site_type inference %s failed: %s", label, ex)

    # --- Root resolution (strongest evidence first) ---

    # Step A (D4/CRITICAL-2): LDAP MP capabilities directly report the site the
    # site-hierarchy XML calls the root (RootSiteCode). This is observed
    # evidence read straight off the wire, not something derived from collected
    # types/parents, so it takes priority over Steps B/C and applies in BOTH
    # flag modes -- consulting it isn't a guess.
    try:
        mp_root_rows = con.execute(
            f"SELECT DISTINCT {_norm_site_code('root_site_code')} AS root_site_code "
            f"FROM {schema}.ldap_management_points_raw "
            f"WHERE root_site_code IS NOT NULL"
        ).fetchall()
    except duckdb.CatalogException:
        # No LDAP management-point capabilities this run (an HTTP-only,
        # SMB-only, or RemoteRegistry-only collection) -- fall through to Step B.
        logger.debug("site_hierarchy: ldap_management_points_raw absent in schema %r; "
                     "no MP-reported root to consult", schema)
        mp_root_rows = []
    except duckdb.BinderException as ex:
        # Belt-and-suspenders: root_site_code is _ensure_columns'd onto this table
        # above, so this branch should be unreachable via the column-dropped path
        # (reviewer C1) it was originally written for -- BinderException is a
        # SIBLING of CatalogException (not a subclass), so an unguarded reference
        # to a dropped column would otherwise propagate uncaught and abort the
        # entire preprocess run. But _ensure_columns now guarantees that specific
        # cause is gone, so any BinderException actually reaching this handler is,
        # BY DEFINITION, something else -- a typo, a bad cast, some other unguarded
        # reference. WARNING (not DEBUG) + the real exception text (reviewer
        # OVER-CATCH), so a genuine SQL bug here can't vanish silently under a
        # hardcoded "missing root_site_code" diagnosis that no longer applies.
        logger.warning(
            "site_hierarchy: unexpected BinderException reading root_site_code from "
            "ldap_management_points_raw in schema %r (%s); treating as no MP-reported "
            "root and falling through to Step B", schema, ex,
        )
        mp_root_rows = []
    mp_root_codes = sorted({code for (code,) in mp_root_rows if code is not None})

    root_code = None
    if len(mp_root_codes) == 1:
        root_code = mp_root_codes[0]
        logger.info(
            "site_hierarchy: root %r observed directly via LDAP MP capabilities' RootSiteCode "
            "in schema %r", root_code, schema,
        )
    elif len(mp_root_codes) > 1:
        # More than one distinct RootSiteCode means more than one hierarchy was
        # traversed (a multi-hierarchy environment). Still observed evidence --
        # not a guess -- so this resolves in BOTH modes; pick deterministically.
        root_code = min(mp_root_codes)
        logger.warning(
            "site_hierarchy: %d distinct RootSiteCode values reported by LDAP MP capabilities "
            "%s in schema %r (multi-hierarchy environment); using %r deterministically.",
            len(mp_root_codes), mp_root_codes, schema, root_code,
        )
    # else: no LDAP-reported root at all -- fall through to Step B.

    # Step B: CAS (type 4) takes priority; fall back to a parentless Primary
    # (type 2) for single-Primary hierarchies with no CAS. Only consulted when
    # Step A found nothing. The sentinel IN-list reuses _SITE_CODE_SENTINEL_SQL
    # (IMPORTANT-4) as a defensive backstop -- every arm above already
    # normalizes sentinels to NULL at insert time, so this should never match
    # a live row, but it keeps this query correct even if a future arm forgets.
    if root_code is None:
        root = con.execute(
            f"SELECT site_code FROM {schema}.site_hierarchy WHERE site_type = 4 "
            f"UNION ALL "
            f"SELECT site_code FROM {schema}.site_hierarchy "
            f"WHERE site_type = 2 "
            f"  AND (parent_site_code IS NULL OR parent_site_code IN ({_SITE_CODE_SENTINEL_SQL})) "
            f"LIMIT 1"
        ).fetchone()
        root_code = root[0] if root else None
        if root_code is not None:
            logger.info("site_hierarchy root resolved to %r in schema %r", root_code, schema)

    # Step C (CRITICAL-1): neither A nor B found a root. Only untyped-or-Primary
    # sites are ever viable roots: a Secondary (type 1) reports to something
    # above it by definition and is excluded outright here, not merely
    # deprioritized -- picking it would mint the whole graph under the wrong
    # '@<root>' scope.
    if root_code is None:
        # Preferred pool: no known type, or explicitly Primary (2), AND no known
        # parent. That is the same CAS-else-parentless-Primary shape the
        # contract requires, just without a confirmed type for the untyped
        # case -- so a SINGLE such site is deduction (it must be the root, the
        # same way a lone parentless Primary is in Step B), not a guess, and
        # resolves in BOTH modes.
        preferred = [
            code for (code,) in con.execute(
                f"SELECT site_code FROM {schema}.site_hierarchy "
                f"WHERE (site_type IS NULL OR site_type = 2) AND parent_site_code IS NULL "
                f"ORDER BY site_code"
            ).fetchall()
        ]
        if len(preferred) == 1:
            root_code = preferred[0]
            logger.info(
                "site_hierarchy: single untyped-or-Primary, parentless site %r in schema %r; "
                "using it as the root by deduction", root_code, schema,
            )
        elif len(preferred) > 1:
            # More than one parentless untyped-or-Primary site: picking one IS
            # an assumption, so evidence-only mode declines to make it. Leaving
            # root_code None means SCCM-native ids lose their '@<root>' scope
            # (transforms.py:1583), so say that plainly.
            if disable_possible_edges:
                logger.warning(
                    "site_hierarchy: %d parentless untyped-or-Primary sites %s in schema %r and "
                    "--disable-possible-edges is set, so no root is assumed. SCCM-native node ids "
                    "will be minted without their '@<root>' scope and will not match a "
                    "default-mode graph of the same environment. Collect with LDAP reachable "
                    "(or pass --site-codes) to resolve a real root.",
                    len(preferred), preferred, schema,
                )
            else:
                root_code = min(preferred)
                # WARNING here, because with more than one candidate the pick is
                # alphabetical and the root -- plus every id and edge anchored to
                # it -- may be wrong.
                logger.warning(
                    "site_hierarchy: %d parentless untyped-or-Primary sites %s in schema %r; none "
                    "is confirmed as the root (no CAS/RootSiteCode observed), so %r was chosen "
                    "alphabetically. Collect with LDAP reachable (or pass --site-codes) to anchor "
                    "the root correctly.",
                    len(preferred), preferred, schema, root_code,
                )
        else:
            # No parentless candidate at all: every known untyped-or-Primary
            # site reports to a parent that was never itself observed as a row
            # (e.g. a Primary whose CAS wasn't collected). That parent is
            # unresolved, so picking one of these is a guess too -- a weaker one
            # than the parentless case above, since even the sole candidate's
            # own parent is unknown.
            fallback = [
                code for (code,) in con.execute(
                    f"SELECT site_code FROM {schema}.site_hierarchy "
                    f"WHERE (site_type IS NULL OR site_type = 2) "
                    f"ORDER BY site_code"
                ).fetchall()
            ]
            if fallback and disable_possible_edges:
                logger.warning(
                    "site_hierarchy: %d untyped-or-Primary site(s) %s in schema %r have only an "
                    "unresolved parent (no CAS/RootSiteCode observed) and --disable-possible-edges "
                    "is set, so no root is assumed. SCCM-native node ids will be minted without "
                    "their '@<root>' scope. Collect with LDAP reachable (or pass --site-codes) to "
                    "resolve a real root.",
                    len(fallback), fallback, schema,
                )
            elif fallback:
                root_code = min(fallback)
                logger.warning(
                    "site_hierarchy: %d untyped-or-Primary site(s) %s in schema %r have only an "
                    "unresolved parent (no CAS/RootSiteCode observed), so %r was chosen "
                    "alphabetically as the root. Collect with LDAP reachable (or pass "
                    "--site-codes) to anchor the root correctly.",
                    len(fallback), fallback, schema, root_code,
                )
            else:
                # Every known site is a Secondary (excluded outright), or there
                # are no sites at all -- nothing viable to guess from in either mode.
                logger.warning(
                    "site_hierarchy: no untyped-or-Primary site found in schema %r (only Secondary "
                    "sites and/or no sites at all); no root can be determined", schema,
                )

    # Stamp every row with the resolved root.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.site_hierarchy AS "
        f"SELECT site_code, parent_site_code, site_type, ? AS root_site_code "
        f"FROM {schema}.site_hierarchy",
        [root_code],
    )


def _authed_users_id(dnshostname_col: str) -> str:
    """SQL fragment: the SharpHound-form Authenticated Users node id for the domain of a
    computer, derived from its dnshostname column. FQDN = dnshostname with the first
    (host) label stripped, uppercased (e.g. 'PROV01.mayyhem.com' -> 'MAYYHEM.COM-S-1-5-11').
    Always pair with a `<col> LIKE '%.%'` guard so a bare hostname can't yield a bad id."""
    return f"upper(regexp_replace({dnshostname_col}, '^[^.]+\\.', '')) || '-S-1-5-11'"


def _derive_ad_props(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build sccm.ad_props (sid -> CMBP-parity AD attributes) from ldap_resolved_principals.

    Enabled = userAccountControl bit 2 (ACCOUNTDISABLE) clear; Type = last objectClass
    element title-cased (e.g. 'user' -> 'User'); IsDomainPrincipal = True for every row,
    since only LDAP-resolved principals land in ldap_resolved_principals in the first
    place. Must run before _node_computer/_node_user/_node_group so _join_ad_props has
    something to join against.

    sam_account_name / distinguished_name are carried here too (ldap_resolved_principals
    already persists both -- context.py:_record_resolved_principal) so that a node type
    with no OTHER source for them (e.g. Group: unlike Computer/User it has no raw arm of
    its own that spreads an AD object) can still pick them up whenever its SID happens to
    have been independently LDAP-resolved.

    ldap_resolved_principals is itself a best-effort finalization table (Task A2) whose
    own pipeline.run is allowed to fail without aborting the collect, so it may be absent
    this run. Treated like any other optional source: _ensure_columns backfills columns a
    load never emitted or dropped as all-NULL, and _safe() logs+skips a missing table —
    leaving ad_props created-but-empty (schema-complete) rather than raising, so the
    LEFT JOINs in _join_ad_props always bind.
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.ad_props ("
        "sid VARCHAR, "
        "enabled BOOLEAN, "
        "type VARCHAR, "
        "is_domain_principal BOOLEAN, "
        "object_class VARCHAR[], "
        "service_principal_name VARCHAR[], "
        "cn VARCHAR, "
        "domain VARCHAR, "
        "sam_account_name VARCHAR, "
        "distinguished_name VARCHAR"
        ")"
    )
    _ensure_columns(con, schema, "ldap_resolved_principals", {
        "object_class": "VARCHAR",
        "user_account_control": "BIGINT",
        "service_principal_name": "VARCHAR",
        "cn": "VARCHAR",
        "domain": "VARCHAR",
        "sam_account_name": "VARCHAR",
        "distinguished_name": "VARCHAR",
    })
    _oc = _arr("object_class")
    _spn = _arr("service_principal_name")
    _safe(
        con,
        "ad_props<-ldap_resolved_principals",
        f"INSERT INTO {schema}.ad_props BY NAME "
        # Collapse to one row per sid: ldap_resolved_principals can carry more than one
        # row for the same principal (case-variant SID strings — the in-memory
        # accumulator dedupes on the raw, case-sensitive SID — or a resumed/retried
        # collect re-appending to the no-primary-key finalization resource). Without
        # this GROUP BY, a duplicated sid here would duplicate a real node row through
        # the LEFT JOIN in _join_ad_props.
        f"SELECT sid, "
        f"  any_value(enabled) AS enabled, "
        f"  any_value(type) AS type, "
        f"  any_value(is_domain_principal) AS is_domain_principal, "
        f"  any_value(object_class) AS object_class, "
        f"  any_value(service_principal_name) AS service_principal_name, "
        f"  any_value(cn) AS cn, "
        f"  any_value(domain) AS domain, "
        f"  any_value(sam_account_name) AS sam_account_name, "
        f"  any_value(distinguished_name) AS distinguished_name "
        f"FROM ("
        f"  SELECT upper(sid) AS sid, "
        # userAccountControl arrives as VARCHAR in production (ldap3 raw values decode to
        # strings and dlt infers a text column -- the BIGINT in _ensure_columns only applies
        # when the column is absent), so TRY_CAST it before the bitwise AND. Without the cast
        # DuckDB raises a VARCHAR & INTEGER binder error that _safe() would swallow, silently
        # emptying ad_props. TRY_CAST -> NULL on a non-numeric value, yielding enabled=NULL.
        f"    CASE WHEN user_account_control IS NULL THEN NULL "
        f"         ELSE (TRY_CAST(user_account_control AS BIGINT) & 2) = 0 END AS enabled, "
        f"    CASE WHEN len({_oc}) = 0 THEN NULL "
        f"         ELSE upper(substr({_oc}[-1], 1, 1)) || lower(substr({_oc}[-1], 2)) END AS type, "
        f"    TRUE AS is_domain_principal, "
        f"    {_oc} AS object_class, "
        f"    {_spn} AS service_principal_name, "
        f"    cn, domain, sam_account_name, distinguished_name "
        f"  FROM {schema}.ldap_resolved_principals "
        f"  WHERE sid IS NOT NULL"
        f") "
        f"GROUP BY sid",
    )
    logger.info("ad_props built in schema %r", schema)


def _join_ad_props(con: duckdb.DuckDBPyConnection, schema: str, table: str) -> None:
    """LEFT JOIN sccm.ad_props (built by _derive_ad_props) onto an AD node table by sid.

    Adds enabled / type / is_domain_principal / object_class / service_principal_name /
    cn / domain, NULL wherever the SID was never LDAP-resolved. _safe() skips (leaving
    `table` unchanged) if ad_props somehow isn't built yet — it always is when
    _derive_ad_props runs first in the pipeline, but this keeps a standalone call to a
    node builder (as in the unit tests) from crashing on a missing table.
    """
    _safe(
        con,
        f"{table}<-ad_props",
        f"CREATE OR REPLACE TABLE {schema}.{table} AS "
        f"SELECT t.*, ap.enabled, ap.type, ap.is_domain_principal, ap.object_class, "
        f"  ap.service_principal_name, ap.cn, ap.domain "
        f"FROM {schema}.{table} t "
        f"LEFT JOIN {schema}.ad_props ap ON ap.sid = t.sid",
    )
    logger.debug("%s enriched with ad_props in schema %r", table, schema)


def _node_computer(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_computer: one row per SID from every computer-bearing source.

    The full set of sources and which columns they contribute is documented in
    the Stage 1 plan "Computer property provenance" table. Missing source tables
    are skipped silently via _safe(). The final GROUP BY collapses all rows for
    the same SID with array-union for role/resource lists, bool_or for flags, and
    any_value for scalars.
    """
    # Start with an empty staging table whose column names match the SELECT aliases
    # used in every INSERT below. INSERT … BY NAME matches on column name, not
    # position, so every source SELECT only needs to name the columns it provides —
    # all others default to the types defined here (NULL / false / []).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_computer ("
        "sid VARCHAR, "
        "name VARCHAR, "
        "dnshostname VARCHAR, "
        "sam_account_name VARCHAR, "
        "distinguished_name VARCHAR, "
        "resource_id_str VARCHAR, "          # '<rid>@<site>' or NULL; aggregated later
        "roles VARCHAR[], "                  # normalised per-row list; array-union later
        "sccm_infra BOOLEAN, "
        "sms_unique_identifier VARCHAR, "
        "smb_signing_required BOOLEAN, "
        "smb_signing_source VARCHAR[], "          # which probe(s) reported signing: SMB-Negotiate / RemoteRegistry-SMBSigningCheck
        "sccm_has_client_remote_control_spn BOOLEAN, "
        "network_boot_server BOOLEAN, "
        "disable_loopback_check BOOLEAN, "
        "restrict_receiving_ntlm_traffic VARCHAR, "
        "sccm_client_certificate_required BOOLEAN, "
        "sccm_hosts_content_library BOOLEAN, "
        "sccm_is_pxe_support_enabled BOOLEAN"
        ")"
    )

    # Pre-create the optional columns every source SELECT below references, so a
    # source that lacks one (never-emitted, or dlt-dropped because all-NULL) still
    # binds instead of dropping the whole source. Keys (sid/object_sid) are not
    # listed — a source without its key is meaningless. See _ensure_columns.
    _optional = {
        "name": "VARCHAR",
        "dns_host_name": "VARCHAR",
        "sam_account_name": "VARCHAR",
        "distinguished_name": "VARCHAR",
        "sccm_site_system_roles": "VARCHAR",
        "sccm_infra": "BOOLEAN",
        "smb_signing_required": "BOOLEAN",
        "sccm_hosts_content_library": "BOOLEAN",
        "sccm_is_pxe_support_enabled": "BOOLEAN",
        "disable_loopback_check": "BOOLEAN",
        "restrict_receiving_ntlm_traffic": "VARCHAR",
        "client_cert_required": "BOOLEAN",
        "system_roles": "VARCHAR",
        "resource_id": "BIGINT",
        "source_site_code": "VARCHAR",
        "obsolete": "BOOLEAN",
        "sms_unique_identifier": "VARCHAR",
    }
    for _src in (
        "adminservice_r_system", "wmi_r_system",
        "ldap_cmrc_devices", "ldap_network_boot_servers",
        "smb_computers", "remoteregistry_computers",
        "adminservice_site_definitions_computers", "wmi_site_definitions_computers",
        "http_management_points", "http_distribution_points", "http_smsproviders",
        "http_site_servers", "dns_management_points",
    ):
        _ensure_columns(con, schema, _src, _optional)

    # site_code/mp_host are scoped to exactly the tables that need them (review
    # fix round 1, MINOR-3), not folded into the shared _optional dict above --
    # that would create all-NULL site_code/mp_host columns on the other ~11
    # unrelated tables in the loop, which a later re-run's _bare_site_code_tables
    # discovery (Task 1) would then pick up as spurious contributors.
    _ensure_columns(con, schema, "http_site_servers", {"site_code": "VARCHAR", "mp_host": "VARCHAR"})
    _ensure_columns(con, schema, "http_management_points", {"site_code": "VARCHAR"})
    _ensure_columns(con, schema, "dns_management_points", {"site_code": "VARCHAR"})

    # Each INSERT selects exactly the columns the source has, with NULL / false / []
    # for the rest. INSERT … BY NAME pairs source column names to staging column names
    # regardless of select-list order.

    # --- adminservice_r_system: sid, system_roles, resource_id@source_site_code, sms_unique_identifier ---
    _safe(
        con,
        "node_computer<-adminservice_r_system",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"NULL AS dnshostname, NULL AS sam_account_name, NULL AS distinguished_name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"{_arr('system_roles')} AS roles, "
        f"false AS sccm_infra, sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.adminservice_r_system "
        f"WHERE sid IS NOT NULL AND NOT coalesce(obsolete, false)",
    )

    # --- wmi_r_system: same shape as adminservice_r_system ---
    _safe(
        con,
        "node_computer<-wmi_r_system",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"NULL AS dnshostname, NULL AS sam_account_name, NULL AS distinguished_name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"{_arr('system_roles')} AS roles, "
        f"false AS sccm_infra, sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.wmi_r_system "
        f"WHERE sid IS NOT NULL AND NOT coalesce(obsolete, false)",
    )

    # --- ldap_cmrc_devices: object_sid; synthesize sccm_has_client_remote_control_spn=TRUE ---
    # Note: ldap_cmrc_devices does have distinguished_name (from entry.entry_dn via ad.py),
    # but we prefer smb_computers / remoteregistry_computers as primary sources to keep
    # the any_value coalesce consistent. NULL here; those arms fill it in.
    _safe(
        con,
        "node_computer<-ldap_cmrc_devices",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"true AS sccm_has_client_remote_control_spn, "  # membership = has CMRC SPN
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.ldap_cmrc_devices "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- ldap_network_boot_servers: synthesize network_boot_server=TRUE ---
    _safe(
        con,
        "node_computer<-ldap_network_boot_servers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"true AS network_boot_server, "                 # LDAP-discovered NBS membership
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.ldap_network_boot_servers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- smb_computers: smb_signing_required; sccm_hosts_content_library; sccm_is_pxe_support_enabled ---
    # smb_computers spreads **ad_object, which includes distinguished_name AND sam_account_name
    # (both resolved from the AD computer object). Read sam here so a host seen only over SMB
    # still gets its account name (any_value picks the first non-null across all sources).
    _safe(
        con,
        "node_computer<-smb_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"smb_signing_required, "
        f"['SMB-Negotiate'] AS smb_signing_source, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"sccm_hosts_content_library, "
        f"sccm_is_pxe_support_enabled "
        f"FROM {schema}.smb_computers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- remoteregistry_computers: disable_loopback_check; restrict_receiving_ntlm_traffic (string) ---
    # remoteregistry_computers spreads **ad_object, providing distinguished_name AND
    # sam_account_name. Read sam here: a site system reached over RemoteRegistry but not via a
    # user/LDAP source (e.g. a CAS-side site server) would otherwise have a NULL account name,
    # which blocks the MSSQL-login inference (transforms.py::_node_mssql_login).
    _safe(
        con,
        "node_computer<-remoteregistry_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"smb_signing_required, "
        f"['RemoteRegistry-SMBSigningCheck'] AS smb_signing_source, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"disable_loopback_check, "
        f"CAST(restrict_receiving_ntlm_traffic AS VARCHAR) AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.remoteregistry_computers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- adminservice_site_definitions_computers: object_sid; sccm_site_system_roles ---
    # This source also spreads **ad_object, providing distinguished_name AND sam_account_name.
    _safe(
        con,
        "node_computer<-adminservice_site_definitions_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.adminservice_site_definitions_computers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- wmi_site_definitions_computers: same shape as adminservice_site_definitions_computers ---
    _safe(
        con,
        "node_computer<-wmi_site_definitions_computers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.wmi_site_definitions_computers "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- http_management_points: client_cert_required -> sccm_client_certificate_required ---
    _safe(
        con,
        "node_computer<-http_management_points",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"client_cert_required AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.http_management_points "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- http_distribution_points: client_cert_required -> sccm_client_certificate_required ---
    _safe(
        con,
        "node_computer<-http_distribution_points",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"client_cert_required AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.http_distribution_points "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- http_smsproviders: client_cert_required -> sccm_client_certificate_required ---
    _safe(
        con,
        "node_computer<-http_smsproviders",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"client_cert_required AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.http_smsproviders "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- http_site_servers: role's site code resolved via the MP that served the
    # sitesigncert (D6). The probe runs before MPKEYINFORMATION sets self.site_code
    # (ps1:8611 ordering, which must not change), so the row's own site_code is
    # usually NULL; mp_host is the breadcrumb recording which MP it came from, so
    # join to that MP's own site_code as a fallback. Bare role when neither side
    # knows a code -- never guess (D6).
    #
    # Pre-aggregate http_management_points by host into a TEMP TABLE, mirroring the
    # _sysres_roles pattern below, for two reasons (review fix round 1):
    #
    #   IMPORTANT-1: http_management_points can legitimately hold two rows for the
    #   same dns_host_name with DIFFERENT site_code -- collectors/http.py:322-324
    #   probes MPLIST1&<other-site>, and :370 stamps the *probing* MP's own
    #   self.site_code onto every sibling it enumerates, so the same MP can be
    #   reported under a foreign site by one host's probe and its true site by
    #   another's. Taking "any" or "first" site_code here would fabricate a
    #   guessed '@<site>' exactly like D6 forbids, so a code is only trusted when
    #   it is the SAME across every row for that host (COUNT(DISTINCT) = 1);
    #   otherwise NULL, logged, and the site-server role falls back to bare.
    #
    #   MINOR-2: building this unconditionally (via _safe, which just leaves the
    #   temp table empty if http_management_points is absent) means a missing MP
    #   table can never gate whether the site-server row itself is emitted -- only
    #   whether its site code gets enriched. The credential-free scenario this arm
    #   exists for is exactly one where http_management_points may be thin/absent.
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _mp_site_by_host "
        "(dns_host_name VARCHAR, site_code VARCHAR, distinct_codes VARCHAR[])"
    )
    _safe(
        con,
        "_mp_site_by_host<-http_management_points",
        f"INSERT INTO _mp_site_by_host "
        f"SELECT lower(dns_host_name) AS dns_host_name, "
        f"  CASE WHEN count(DISTINCT {_norm_site_code('site_code')}) = 1 "
        f"       THEN any_value({_norm_site_code('site_code')}) ELSE NULL END AS site_code, "
        f"  list_distinct(list_filter(list({_norm_site_code('site_code')}), x -> x IS NOT NULL)) AS distinct_codes "
        f"FROM {schema}.http_management_points "
        f"WHERE dns_host_name IS NOT NULL "
        f"GROUP BY lower(dns_host_name)",
    )
    # Name the ambiguous hosts that actually matter -- i.e. only ones a real
    # http_site_servers row is joining to -- rather than every ambiguous MP.
    try:
        _ambiguous = con.execute(
            f"SELECT DISTINCT ss.mp_host, mp.distinct_codes "
            f"FROM {schema}.http_site_servers ss "
            f"JOIN _mp_site_by_host mp ON lower(ss.mp_host) = mp.dns_host_name "
            f"WHERE mp.site_code IS NULL AND len(mp.distinct_codes) > 1"
        ).fetchall()
    except duckdb.CatalogException:
        _ambiguous = []  # http_site_servers absent -- nothing to warn about
    except duckdb.BinderException as ex:
        # FAMILY-1 (same shape as C1/I1): BinderException is a SIBLING of
        # CatalogException, not a subclass. This query only binds today because
        # ss.mp_host is _ensure_columns'd onto http_site_servers earlier in this
        # function -- a fragile, non-obvious dependency, not a structural
        # guarantee at this call site. A future refactor that dropped or reordered
        # that _ensure_columns call would otherwise raise here uncaught (this is
        # NOT wrapped in _safe -- it's a plain con.execute for a warning list, not
        # an INSERT). WARNING + the real exception text (reviewer OVER-CATCH):
        # don't assume it's the column-missing case without saying so.
        logger.warning(
            "node_computer<-http_site_servers: could not compute the ambiguous-MP "
            "warning list in schema %r (%s); skipping it (site-server rows are "
            "still emitted, just without this diagnostic)", schema, ex,
        )
        _ambiguous = []
    for _host, _codes in _ambiguous:
        logger.warning(
            "node_computer<-http_site_servers: MP %r reports %d competing site codes %s "
            "across its http_management_points rows; cannot attribute the site server "
            "probed via it to any single site (D6) -- emitting a bare role instead.",
            _host, len(_codes), _codes,
        )

    _resolved_ss_site = f"coalesce({_norm_site_code('ss.site_code')}, mp.site_code)"
    _before = _scalar(con, f"SELECT count(*) FROM {schema}.node_computer")
    _safe(
        con,
        "node_computer<-http_site_servers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(ss.object_sid) AS sid, ss.name, "
        f"ss.dns_host_name AS dnshostname, ss.sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"CASE WHEN {_resolved_ss_site} IS NULL THEN ['SMS Site Server'] "
        f"     ELSE ['SMS Site Server@' || {_resolved_ss_site}] END AS roles, "
        f"true AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"ss.client_cert_required AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.http_site_servers ss "
        f"LEFT JOIN _mp_site_by_host mp ON lower(ss.mp_host) = mp.dns_host_name "
        f"WHERE ss.object_sid IS NOT NULL",
    )
    _after = _scalar(con, f"SELECT count(*) FROM {schema}.node_computer")
    logger.info("node_computer<-http_site_servers contributed %d row(s)", _after - _before)

    # --- ldap_management_points_raw (FSP): the fallback status point is a second
    # host named by the MP-capabilities row, keyed by fsp_sid (Task 1b hoists this
    # out of collectors/ldap.py's log-message-only local var). site_code here is
    # the naming MP's own site code, which the collector already attributes
    # directly to the FSP it names (register_target(..., site_code=mp_code_upper)),
    # so this is not a cross-host guess (D6). ---
    _ensure_columns(con, schema, "ldap_management_points_raw", {
        "fsp_hostname": "VARCHAR", "fsp_sid": "VARCHAR", "site_code": "VARCHAR",
    })
    _before = _scalar(con, f"SELECT count(*) FROM {schema}.node_computer")
    _safe(
        con,
        "node_computer<-ldap_management_points_raw(fsp)",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(fsp_sid) AS sid, fsp_hostname AS name, "
        f"fsp_hostname AS dnshostname, NULL AS sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"CASE WHEN {_norm_site_code('site_code')} IS NULL THEN ['SMS Fallback Status Point'] "
        f"     ELSE ['SMS Fallback Status Point@' || {_norm_site_code('site_code')}] END AS roles, "
        f"true AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.ldap_management_points_raw "
        f"WHERE fsp_sid IS NOT NULL",
    )
    _after = _scalar(con, f"SELECT count(*) FROM {schema}.node_computer")
    logger.info("node_computer<-ldap_management_points_raw(fsp) contributed %d row(s)", _after - _before)

    # --- dns_management_points: the SRV/ADIDNS query key IS the site code
    # (authoritative, D6), and the collector now emits the role string directly,
    # so this is a plain arm -- no join needed, same shape as http_management_points. ---
    _before = _scalar(con, f"SELECT count(*) FROM {schema}.node_computer")
    _safe(
        con,
        "node_computer<-dns_management_points",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"dns_host_name AS dnshostname, sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"{_arr('sccm_site_system_roles')} AS roles, "
        f"coalesce(sccm_infra, false) AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.dns_management_points "
        f"WHERE object_sid IS NOT NULL",
    )
    _after = _scalar(con, f"SELECT count(*) FROM {schema}.node_computer")
    logger.info("node_computer<-dns_management_points contributed %d row(s)", _after - _before)

    # --- mssql_server_instances: an MSSQLSvc SPN or a probed-open TCP/1433 is
    # proof the host runs SQL Server (D2a), collect_mssql.py now records it even
    # when only the SPN fired (port closed). Running SQL is NOT an SCCM role --
    # sccm_infra stays false and no role is added; a real SCCM role, if any,
    # arrives from another arm above and merges on sid. ---
    _ensure_columns(con, schema, "mssql_server_instances", {"name": "VARCHAR", "dns_host_name": "VARCHAR"})
    _before = _scalar(con, f"SELECT count(*) FROM {schema}.node_computer")
    _safe(
        con,
        "node_computer<-mssql_server_instances",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(domain_computer_sid) AS sid, name, "
        # dnshostname prefers the real FQDN (dns_host_name) over the AD CN (name)
        # -- using the CN here would fail every LIKE '%.%' dependent join downstream
        # (e.g. the coerce-and-relay builders) and misreport dnsHostName in the
        # entity panel (reviewer M2) -- but falls back to name (same reasoning as
        # REGRESSION-1's node_mssql_server fix) so a cached bucket collected before
        # collect_mssql emitted dns_host_name still gets SOME hostname rather than
        # NULL outright.
        f"coalesce(dns_host_name, name) AS dnshostname, NULL AS sam_account_name, NULL AS distinguished_name, "
        f"NULL AS resource_id_str, "
        f"CAST([] AS VARCHAR[]) AS roles, "
        f"false AS sccm_infra, "
        f"NULL AS sms_unique_identifier, "
        f"NULL AS smb_signing_required, "
        f"false AS sccm_has_client_remote_control_spn, "
        f"false AS network_boot_server, "
        f"NULL AS disable_loopback_check, "
        f"NULL AS restrict_receiving_ntlm_traffic, "
        f"NULL AS sccm_client_certificate_required, "
        f"NULL AS sccm_hosts_content_library, "
        f"NULL AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.mssql_server_instances "
        f"WHERE domain_computer_sid IS NOT NULL",
    )
    _after = _scalar(con, f"SELECT count(*) FROM {schema}.node_computer")
    logger.info("node_computer<-mssql_server_instances contributed %d row(s)", _after - _before)

    # Collapse all staging rows into one row per SID. Role lists are array-unioned;
    # boolean flags use bool_or (true wins); scalars use any_value (first non-null wins).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_computer AS "
        f"SELECT "
        f"  sid, "
        f"  any_value(name) AS name, "
        f"  any_value(dnshostname) AS dnshostname, "
        f"  any_value(sam_account_name) AS sam_account_name, "
        f"  any_value(distinguished_name) AS distinguished_name, "
        f"  list_distinct(list_filter(flatten(list(roles)), x -> x IS NOT NULL AND trim(x) != '')) AS site_system_roles, "
        f"  coalesce(list_distinct(array_agg(resource_id_str) FILTER (WHERE resource_id_str IS NOT NULL)), CAST([] AS VARCHAR[])) AS resource_ids, "
        f"  bool_or(sccm_infra) AS sccm_infra, "
        f"  any_value(sms_unique_identifier) AS sms_unique_identifier, "
        f"  bool_or(smb_signing_required) AS smb_signing_required, "
        # Array-union the probe tags; FILTER drops the NULLs other sources leave.
        f"  coalesce(list_distinct(flatten(list(smb_signing_source) "
        f"    FILTER (WHERE smb_signing_source IS NOT NULL))), CAST([] AS VARCHAR[])) AS smb_signing_source, "
        f"  bool_or(sccm_has_client_remote_control_spn) AS sccm_has_client_remote_control_spn, "
        f"  bool_or(network_boot_server) AS network_boot_server, "
        f"  bool_or(disable_loopback_check) AS disable_loopback_check, "
        f"  any_value(restrict_receiving_ntlm_traffic) AS restrict_receiving_ntlm_traffic, "
        f"  bool_or(sccm_client_certificate_required) AS sccm_client_certificate_required, "
        f"  bool_or(sccm_hosts_content_library) AS sccm_hosts_content_library, "
        f"  bool_or(sccm_is_pxe_support_enabled) AS sccm_is_pxe_support_enabled "
        f"FROM {schema}.node_computer "
        f"GROUP BY sid"
    )

    # Augment site_system_roles from SMS_SCI_SysResUse (adminservice_site_systems / wmi_site_systems).
    # That source lists EVERY site system — including passive site servers and SMS Providers — each
    # with its role_name + site_code, but keyed by hostname (network_os_path), not SID, so it can't be
    # a SID-keyed staging arm above. The only other source of "@<site>"-suffixed roles is
    # SMS_SCI_SiteDefinition, which covers just the ACTIVE site server + SQL host per site. Without this
    # step a passive server / SMS Provider never gets "SMS Site Server@<site>" / "SMS Provider@<site>",
    # so the MSSQL-login inference (_node_mssql_login, mirroring CMBP ps1:1912) skips it and only the
    # active site server gets a site-DB login. CMBP builds SCCMSiteSystemRoles from this same
    # per-site-system data. Join by dnshostname since SysResUse carries no SID; strip the leading
    # "\\" from network_os_path (e.g. "\\ps1-psv.mayyhem.com").
    con.execute("CREATE OR REPLACE TEMP TABLE _sysres_roles (host VARCHAR, roles VARCHAR[])")
    for _ss in ("adminservice_site_systems", "wmi_site_systems"):
        _ensure_columns(con, schema, _ss, {
            "network_os_path": "VARCHAR", "role_name": "VARCHAR", "site_code": "VARCHAR",
        })
        _safe(
            con, f"_sysres_roles<-{_ss}",
            f"INSERT INTO _sysres_roles "
            f"SELECT lower(ltrim(network_os_path, '\\')) AS host, "
            f"  list_distinct(list(role_name || '@' || site_code)) AS roles "
            f"FROM {schema}.{_ss} "
            f"WHERE role_name IS NOT NULL AND site_code IS NOT NULL "
            f"  AND network_os_path IS NOT NULL AND trim(network_os_path) != '' "
            f"GROUP BY host",
        )
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_computer AS "
        f"WITH _sr AS ("
        f"  SELECT host, list_distinct(flatten(list(roles))) AS roles FROM _sysres_roles GROUP BY host"
        f") "
        f"SELECT nc.* REPLACE ("
        f"  list_distinct(list_concat(nc.site_system_roles, "
        f"    coalesce(sr.roles, CAST([] AS VARCHAR[])))) AS site_system_roles"
        f") "
        f"FROM {schema}.node_computer nc "
        f"LEFT JOIN _sr sr ON nc.dnshostname IS NOT NULL AND lower(nc.dnshostname) = sr.host"
    )
    _backfill_bare_site_roles(con, schema)
    _join_ad_props(con, schema, "node_computer")
    logger.info("node_computer built in schema %r", schema)


def _backfill_bare_site_roles(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Backfill a bare ``<Role>`` to ``<Role>@<site>`` using the SAME host's other
    site-coded roles (D6).

    An HTTP SMS-Provider-only probe (or an SMS Distribution Point probe) has no site
    code of its own -- MPKEYINFORMATION is a management-point endpoint, not a
    site-server endpoint (collectors/http.py:180) -- so those roles land bare even
    though another probe against the SAME host (RemoteRegistry, SysResUse, ...)
    already established its site. Downstream matchers such as
    _edge_coerce_relay_adminservice key on 'SMS Provider@<site>' and silently miss
    the bare form (live 2026-07-28 low-priv run: 0 edges where CMBP emitted 1).

    Applying the site from a co-occurring role ON THE SAME ROW is not a guess (D6
    only forbids inferring a host's site from a DIFFERENT host) -- the site is a
    fact this exact host's own other roles already established. Only applied when
    those other @-suffixed roles resolve to exactly one distinct site; an
    ambiguous (>1 site) or absent (0 sites) case leaves the bare role untouched.
    """
    rows = con.execute(
        f"SELECT sid, dnshostname, site_system_roles FROM {schema}.node_computer "
        f"WHERE len(list_filter(site_system_roles, x -> NOT contains(x, '@'))) > 0"
    ).fetchall()
    for sid, dnshostname, roles in rows:
        bare = [r for r in roles if "@" not in r]
        sites = sorted({r.rsplit("@", 1)[1] for r in roles if "@" in r})
        if not sites:
            # Nothing on this host names a site at all -- leave the bare role(s)
            # alone rather than inventing a scope for them.
            logger.debug(
                "node_computer backfill: host %r (sid %s) has bare role(s) %s but no "
                "@-suffixed role to infer a site from; leaving bare",
                dnshostname, sid, bare,
            )
            continue
        if len(sites) > 1:
            # This host's own roles disagree on the site -- guessing which one
            # applies to the bare role would violate D6, so log and move on.
            logger.warning(
                "node_computer backfill: host %r (sid %s) has bare role(s) %s but its "
                "other roles span %d competing sites %s; cannot infer a single site "
                "(D6) -- leaving bare",
                dnshostname, sid, bare, len(sites), sites,
            )
            continue
        site = sites[0]
        # list(set(...)) then sort: de-duplicates in case '<role>@<site>' was
        # already present alongside the bare '<role>'.
        new_roles = sorted({r for r in roles if "@" in r} | {f"{b}@{site}" for b in bare})
        con.execute(
            f"UPDATE {schema}.node_computer SET site_system_roles = ? WHERE sid = ?",
            [new_roles, sid],
        )
        logger.info(
            "node_computer backfill: host %r (sid %s) bare role(s) %s -> site %r "
            "(inferred from this host's own other site-coded roles)",
            dnshostname, sid, bare, site,
        )


def _node_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_user: one row per SID from every user-bearing source.

    Sources and the columns they contribute:

    * adminservice_r_user / wmi_r_user  — sid, name, resource_id@source_site_code
    * remoteregistry_users              — object_sid (clean snake_case per Task-3 fix)
    * adminservice_admins / wmi_admins  — admin_sid where is_group=false → sccm_infra=true
    * adminservice_reserved_accounts / wmi_reserved_accounts
                                        — object_sid, site_code → stored_in_sccm_site

    The final GROUP BY collapses all rows for the same uppercased SID with
    array-union for resource_ids, bool_or for sccm_infra, and any_value for
    scalars (name, stored_in_sccm_site).
    """
    # Staging table holds one raw row per source record before collapsing.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_user ("
        "sid VARCHAR, "
        "name VARCHAR, "
        "resource_id_str VARCHAR, "     # '<rid>@<site>' or NULL; aggregated below
        "sccm_infra BOOLEAN, "
        "stored_in_sccm_site VARCHAR, "   # site_code where the account is stored (reserved)
        "distinguished_name VARCHAR, "
        "user_principal_name VARCHAR, "
        "sam_account_name VARCHAR"        # bare SAM (e.g. 'sqlsccmsvc'); any_value below
        ")"
    )

    # Pre-create optional columns so a source missing one still binds. See _ensure_columns.
    _optional = {
        "name": "VARCHAR",
        "resource_id": "BIGINT",
        "source_site_code": "VARCHAR",
        "sam_account_name": "VARCHAR",
        "user_name": "VARCHAR",
        "logon_name": "VARCHAR",
        "is_group": "BOOLEAN",
        "site_code": "VARCHAR",
        "distinguished_name": "VARCHAR",
        "user_principal_name": "VARCHAR",
    }
    for _src in (
        "adminservice_r_user", "wmi_r_user", "remoteregistry_users",
        "adminservice_admins", "wmi_admins",
        "adminservice_reserved_accounts", "wmi_reserved_accounts",
    ):
        _ensure_columns(con, schema, _src, _optional)

    # --- adminservice_r_user: sid, name, resource_id@source_site_code, AD attributes ---
    # RUSER_COLUMNS includes DistinguishedName and UserPrincipalName (dlt snake-cases them).
    _safe(
        con,
        "node_user<-adminservice_r_user",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site, "
        f"distinguished_name, "
        f"user_principal_name, "
        f"user_name AS sam_account_name "  # SMS_R_User.UserName is the bare SAM (e.g. 'sqlsccmsvc')
        f"FROM {schema}.adminservice_r_user "
        f"WHERE sid IS NOT NULL",
    )

    # --- wmi_r_user: same shape as adminservice_r_user ---
    _safe(
        con,
        "node_user<-wmi_r_user",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(sid) AS sid, name, "
        f"CASE WHEN resource_id IS NULL THEN NULL "
        f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(source_site_code AS VARCHAR) END AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site, "
        f"distinguished_name, "
        f"user_principal_name, "
        f"user_name AS sam_account_name "
        f"FROM {schema}.wmi_r_user "
        f"WHERE sid IS NOT NULL",
    )

    # --- remoteregistry_users: object_sid (clean snake_case); no resource_id or AD attrs ---
    _safe(
        con,
        "node_user<-remoteregistry_users",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(object_sid) AS sid, sam_account_name AS name, "
        f"NULL AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name, "
        f"sam_account_name "  # remoteregistry_users carries the bare SAM directly
        f"FROM {schema}.remoteregistry_users "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- adminservice_admins (users only): admin_sid, logon_name → sccm_infra=true ---
    _safe(
        con,
        "node_user<-adminservice_admins",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(admin_sid) AS sid, logon_name AS name, "
        f"NULL AS resource_id_str, "
        f"true AS sccm_infra, "
        f"NULL AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name, "
        f"NULL AS sam_account_name "  # admins carry only logon_name (DOMAIN\\user), not a bare SAM
        f"FROM {schema}.adminservice_admins "
        f"WHERE admin_sid IS NOT NULL AND NOT coalesce(is_group, false)",
    )

    # --- wmi_admins (users only): same shape as adminservice_admins ---
    _safe(
        con,
        "node_user<-wmi_admins",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(admin_sid) AS sid, logon_name AS name, "
        f"NULL AS resource_id_str, "
        f"true AS sccm_infra, "
        f"NULL AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name, "
        f"NULL AS sam_account_name "
        f"FROM {schema}.wmi_admins "
        f"WHERE admin_sid IS NOT NULL AND NOT coalesce(is_group, false)",
    )

    # --- adminservice_reserved_accounts: object_sid, site_code → stored_in_sccm_site ---
    # The account name column in reserved_accounts is 'name' (verified clean snake_case).
    _safe(
        con,
        "node_user<-adminservice_reserved_accounts",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"NULL AS resource_id_str, "
        f"false AS sccm_infra, "
        f"site_code AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name, "
        f"NULL AS sam_account_name "
        f"FROM {schema}.adminservice_reserved_accounts "
        f"WHERE object_sid IS NOT NULL",
    )

    # --- wmi_reserved_accounts: same shape as adminservice_reserved_accounts ---
    _safe(
        con,
        "node_user<-wmi_reserved_accounts",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT upper(object_sid) AS sid, name, "
        f"NULL AS resource_id_str, "
        f"false AS sccm_infra, "
        f"site_code AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name, "
        f"NULL AS sam_account_name "
        f"FROM {schema}.wmi_reserved_accounts "
        f"WHERE object_sid IS NOT NULL",
    )

    # con-c509 / con-2249: the MSSQLSvc SPN holder, the one LOW-PRIVILEGE arm.
    #
    # Every arm above reads an SCCM-privileged source (adminservice_*/wmi_*/
    # remoteregistry_users), so a run without AdminService/WMI built almost no
    # node_user rows at all -- 1 versus 23 against the mayyhem lab. The SQL service
    # account was among the missing, even though the low-priv LDAP path had already
    # resolved it by name (clients/ad.py find_mssql_spn_holder, which logs
    # "MSSQLSvc SPN for <host> is held by <name>"). With no row here it fell through
    # to _node_backfill and shipped as a stub whose only property is its own SID.
    #
    # That is why five integration cases reported "not found" at low privilege --
    # MSSQL_GetTGS, MSSQL_GetAdminTGS, MSSQL_ServiceAccountFor and both HasSession
    # cases. The edges were emitted correctly in BOTH modes; the fixtures pin this
    # shared endpoint by samAccountName, and a stub has none, so the matcher rejected
    # them. A property gap, not missing data.
    #
    # Read the raw mssql_server_instances rather than node_mssql_server so this does
    # not depend on the MSSQL node build running first. The is-computer guard keeps a
    # machine-account SQL service out of node_user -- _node_computer owns those.
    _ensure_columns(con, schema, "mssql_server_instances", {
        "service_account_sid": "VARCHAR", "service_account_name": "VARCHAR",
        "service_account_is_computer": "BOOLEAN",
    })
    _safe(
        con, "node_user<-mssql_server_instances",
        f"INSERT INTO {schema}.node_user BY NAME "
        f"SELECT DISTINCT upper(service_account_sid) AS sid, "
        f"service_account_name AS name, "
        f"NULL AS resource_id_str, "
        f"false AS sccm_infra, "
        f"NULL AS stored_in_sccm_site, "
        f"NULL AS distinguished_name, "
        f"NULL AS user_principal_name, "
        f"service_account_name AS sam_account_name "
        f"FROM {schema}.mssql_server_instances "
        f"WHERE service_account_sid IS NOT NULL "
        f"  AND service_account_name IS NOT NULL "
        f"  AND NOT coalesce(service_account_is_computer, false)",
    )

    # Collapse all staging rows into one row per SID.
    # resource_ids: array-union the non-null '<rid>@<site>' strings.
    # sccm_infra:   bool_or (true wins if any source set it true).
    # name / stored_in_sccm_site / distinguished_name / user_principal_name:
    #   any_value (first non-null wins; scalar per CMBP).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_user AS "
        f"SELECT "
        f"  sid, "
        f"  any_value(name) AS name, "
        f"  coalesce(list_distinct(array_agg(resource_id_str) FILTER (WHERE resource_id_str IS NOT NULL)), CAST([] AS VARCHAR[])) AS resource_ids, "
        f"  bool_or(sccm_infra) AS sccm_infra, "
        f"  any_value(stored_in_sccm_site) AS stored_in_sccm_site, "
        f"  any_value(distinguished_name) AS distinguished_name, "
        f"  any_value(user_principal_name) AS user_principal_name, "
        f"  any_value(sam_account_name) AS sam_account_name "
        f"FROM {schema}.node_user "
        f"GROUP BY sid"
    )
    _join_ad_props(con, schema, "node_user")
    logger.info("node_user built in schema %r", schema)


def _node_group(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_group: one row per SID from every group-bearing source.

    Groups arrive in two ways:
      1. Name-only: security_group_name lists on r_system / r_user rows.
         The group name is resolved to a SID via a case-insensitive join on
         principal_by_name (both sides uppercased, because principal_by_name
         stores names in original case while the list values may differ).
         r_user rows also carry a resource_id that we propagate as a
         sccm_resource_ids hint (per CMBP; the value is the parent user's
         ResourceID).
      2. Direct SID: admins / wmi_admins rows where is_group=True. These
         carry sccm_infra=True.

    A fallback_domain_sid is derived where possible — the domain SID of the
    r_system / r_user row that produced the group name — so that builtin
    group SIDs (S-1-5-32-*) can be qualified per the locked identity rule.

    The final GROUP BY deduplicates on upper(sid): sccm_infra uses bool_or
    (True wins), sccm_resource_ids are array-unioned, name and
    fallback_domain_sid use any_value (first non-null wins).
    """
    # Staging table: one raw row per source record before collapsing.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_group ("
        "sid VARCHAR, "
        "name VARCHAR, "
        "sccm_infra BOOLEAN, "
        "resource_id_str VARCHAR, "     # '<rid>@<site>' from the parent user row; NULL otherwise
        "fallback_domain_sid VARCHAR"   # domain SID of the co-occurring host/user; NULL when unknown
        ")"
    )

    # --- From r_system: unnest security_group_name, resolve to SID via principal_by_name.
    # The fallback_domain_sid is the domain SID of the r_system host (strip the RID via regex).
    # dlt loads security_group_name as a JSON column (e.g. '["mayyhem\\Domain Users"]'), not a
    # native list, so we route it through _arr() (JSON/scalar/list -> VARCHAR[]) before UNNEST;
    # a raw `unnest(json_col)` raises "UNNEST requires a single list as input".
    # DuckDB lateral unnest: `unnest(<expr>) AS t(gname)` — the column is `t.gname` in all refs.
    _safe(
        con,
        "node_group<-adminservice_r_system",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT pbn.sid AS sid, t.gname AS name, "
        f"false AS sccm_infra, "
        f"NULL AS resource_id_str, "
        f"regexp_extract(upper(r.sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS fallback_domain_sid "
        f"FROM {schema}.adminservice_r_system r, "
        f"unnest({_arr('r.security_group_name')}) AS t(gname) "
        f"JOIN {schema}.principal_by_name pbn "
        f"  ON upper(trim(t.gname)) = upper(pbn.name) "
        f"WHERE r.sid IS NOT NULL AND NOT coalesce(r.obsolete, false) "
        f"  AND t.gname IS NOT NULL AND trim(t.gname) != ''",
    )

    # --- From wmi_r_system: same shape as adminservice_r_system ---
    _safe(
        con,
        "node_group<-wmi_r_system",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT pbn.sid AS sid, t.gname AS name, "
        f"false AS sccm_infra, "
        f"NULL AS resource_id_str, "
        f"regexp_extract(upper(r.sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS fallback_domain_sid "
        f"FROM {schema}.wmi_r_system r, "
        f"unnest({_arr('r.security_group_name')}) AS t(gname) "
        f"JOIN {schema}.principal_by_name pbn "
        f"  ON upper(trim(t.gname)) = upper(pbn.name) "
        f"WHERE r.sid IS NOT NULL AND NOT coalesce(r.obsolete, false) "
        f"  AND t.gname IS NOT NULL AND trim(t.gname) != ''",
    )

    # --- From r_user: unnest security_group_name; carry parent resource_id as sccm_resource_ids.
    # Per CMBP: the value is the parent user's ResourceID (resource_id@source_site_code).
    _safe(
        con,
        "node_group<-adminservice_r_user",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT pbn.sid AS sid, t.gname AS name, "
        f"false AS sccm_infra, "
        f"CASE WHEN r.resource_id IS NULL THEN NULL "
        f"     ELSE CAST(r.resource_id AS VARCHAR) || '@' || CAST(r.source_site_code AS VARCHAR) END AS resource_id_str, "
        f"regexp_extract(upper(r.sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS fallback_domain_sid "
        f"FROM {schema}.adminservice_r_user r, "
        f"unnest({_arr('r.security_group_name')}) AS t(gname) "
        f"JOIN {schema}.principal_by_name pbn "
        f"  ON upper(trim(t.gname)) = upper(pbn.name) "
        f"WHERE r.sid IS NOT NULL "
        f"  AND t.gname IS NOT NULL AND trim(t.gname) != ''",
    )

    # --- From wmi_r_user: same shape as adminservice_r_user ---
    _safe(
        con,
        "node_group<-wmi_r_user",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT pbn.sid AS sid, t.gname AS name, "
        f"false AS sccm_infra, "
        f"CASE WHEN r.resource_id IS NULL THEN NULL "
        f"     ELSE CAST(r.resource_id AS VARCHAR) || '@' || CAST(r.source_site_code AS VARCHAR) END AS resource_id_str, "
        f"regexp_extract(upper(r.sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS fallback_domain_sid "
        f"FROM {schema}.wmi_r_user r, "
        f"unnest({_arr('r.security_group_name')}) AS t(gname) "
        f"JOIN {schema}.principal_by_name pbn "
        f"  ON upper(trim(t.gname)) = upper(pbn.name) "
        f"WHERE r.sid IS NOT NULL "
        f"  AND t.gname IS NOT NULL AND trim(t.gname) != ''",
    )

    # --- From adminservice_admins: direct group SID where is_group=True; sccm_infra=True ---
    _safe(
        con,
        "node_group<-adminservice_admins",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT upper(admin_sid) AS sid, logon_name AS name, "
        f"true AS sccm_infra, "
        f"NULL AS resource_id_str, "
        f"NULL AS fallback_domain_sid "
        f"FROM {schema}.adminservice_admins "
        f"WHERE admin_sid IS NOT NULL AND coalesce(is_group, false)",
    )

    # --- From wmi_admins: same shape as adminservice_admins ---
    _safe(
        con,
        "node_group<-wmi_admins",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT upper(admin_sid) AS sid, logon_name AS name, "
        f"true AS sccm_infra, "
        f"NULL AS resource_id_str, "
        f"NULL AS fallback_domain_sid "
        f"FROM {schema}.wmi_admins "
        f"WHERE admin_sid IS NOT NULL AND coalesce(is_group, false)",
    )

    # Collapse all staging rows into one row per SID (uppercased).
    # sccm_infra: bool_or (True wins if any source set it True).
    # sccm_resource_ids: array-union the non-null '<rid>@<site>' strings.
    # name / fallback_domain_sid: any_value (first non-null wins).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_group AS "
        f"SELECT "
        f"  upper(sid) AS sid, "
        f"  any_value(name) AS name, "
        f"  bool_or(sccm_infra) AS sccm_infra, "
        f"  coalesce(list_distinct(array_agg(resource_id_str) FILTER (WHERE resource_id_str IS NOT NULL)), CAST([] AS VARCHAR[])) AS sccm_resource_ids, "
        f"  any_value(fallback_domain_sid) AS fallback_domain_sid "
        f"FROM {schema}.node_group "
        f"WHERE sid IS NOT NULL "
        f"GROUP BY upper(sid)"
    )
    _join_ad_props(con, schema, "node_group")

    # sam_account_name / distinguished_name: unlike Computer/User, node_group has no raw
    # arm of its own that spreads an AD object (its only sources are principal_by_name
    # name-resolution and admins SID rows, neither of which carry these). ad_props is the
    # only place they can come from -- populated whenever this SID happened to be
    # independently LDAP-resolved elsewhere (e.g. the System Management container
    # GenericAll ACL walk, CMBP's own source for this: its 3 low-priv Group nodes with
    # these fields all trace to LDAP-GenericAllSystemManagement). A dedicated join (not
    # folded into _join_ad_props, which node_computer/node_user also use and already have
    # their own better-sourced sam_account_name/distinguished_name columns that a blind
    # ap.* would collide with by name).
    _safe(
        con,
        "node_group<-ad_props(sam/dn)",
        f"CREATE OR REPLACE TABLE {schema}.node_group AS "
        f"SELECT g.*, ap.sam_account_name, ap.distinguished_name "
        f"FROM {schema}.node_group g "
        f"LEFT JOIN {schema}.ad_props ap ON ap.sid = g.sid",
    )
    logger.info("node_group built in schema %r", schema)


def _node_site(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_site: one row per site_code, coalesced from all site sources.

    Sources and the columns they contribute:

    * adminservice_sites / wmi_sites         — site_code, site_name, server_name,
                                               reporting_site_code (= parent), type (= site_type),
                                               version, build_number, install_dir
    * adminservice_site_definitions / wmi_site_definitions
                                             — site_code, parent_site_code, site_guid,
                                               sql_server_name, sql_database_name, site_type
    * ldap_sites                             — site_code, site_guid, parent_site_code,
                                               distinguished_name, source_forest
    * adminservice_site_systems / wmi_site_systems (correlated subquery)
                                             — sql_service_account_name (any non-null
                                               sql_server_service_logon_account per site_code)

    After collapsing duplicates with GROUP BY upper(site_code), the result is
    LEFT JOINed to site_hierarchy (built by _site_hierarchy) to stamp each row
    with root_site_code and sql_service_account_name. site_hierarchy must already
    exist when this runs. admin_users and stored_accounts list columns are added
    later by _enrich_site_lists.
    """
    # Staging table — one raw row per source record before collapsing.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site ("
        "site_code VARCHAR, "
        "site_name VARCHAR, "
        "server_name VARCHAR, "
        "parent_site_code VARCHAR, "
        "site_type INTEGER, "
        "site_guid VARCHAR, "
        "sql_server_name VARCHAR, "
        "sql_database_name VARCHAR, "
        "version VARCHAR, "
        "build_number VARCHAR, "
        "install_dir VARCHAR, "
        "distinguished_name VARCHAR, "
        "source_forest VARCHAR, "
        "sql_server_fqdn VARCHAR, "       # SMS_SCI_SiteDefinition Props "SQLServerFQDN"
        "sql_service_port VARCHAR"        # SMS_SCI_SiteDefinition Props "SQLServicePort"
        ")"
    )

    # Pre-create the optional columns the site-source SELECTs reference, so a
    # source missing one (never-emitted, or dlt-dropped because all-NULL) still
    # binds instead of a binder error dropping the whole source. Real
    # adminservice_site_definitions, for instance, often lacks site_guid. site_code
    # is the key/filter — a source without it is meaningless, so it is not listed.
    # See _ensure_columns (same pattern as _node_computer / _node_user).
    _optional = {
        "site_name": "VARCHAR",
        "server_name": "VARCHAR",
        "reporting_site_code": "VARCHAR",   # adminservice_sites/wmi_sites -> parent_site_code
        "type": "INTEGER",                  # adminservice_sites/wmi_sites -> site_type
        "version": "VARCHAR",
        "build_number": "VARCHAR",
        "install_dir": "VARCHAR",
        "parent_site_code": "VARCHAR",      # site_definitions / ldap_sites
        "site_type": "INTEGER",             # site_definitions
        "site_guid": "VARCHAR",             # site_definitions / ldap_sites
        "sql_server_name": "VARCHAR",       # site_definitions
        "sql_database_name": "VARCHAR",     # site_definitions
        "distinguished_name": "VARCHAR",    # ldap_sites (mSSMSSite DN)
        "source_forest": "VARCHAR",         # ldap_sites (mSSMSSourceForest)
        "sql_server_fqdn": "VARCHAR",       # site_definitions (Props SQLServerFQDN)
        "sql_service_port": "VARCHAR",      # site_definitions (Props SQLServicePort)
    }
    for _src in (
        "adminservice_sites", "wmi_sites",
        "adminservice_site_definitions", "wmi_site_definitions",
        "ldap_sites",
    ):
        _ensure_columns(con, schema, _src, _optional)

    # --- adminservice_sites: site_code, site_name, server_name, reporting_site_code → parent, type → site_type ---
    _safe(
        con,
        "node_site<-adminservice_sites",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, site_name, server_name, "
        f"reporting_site_code AS parent_site_code, "
        f"TRY_CAST(type AS INTEGER) AS site_type, "
        f"NULL AS site_guid, NULL AS sql_server_name, NULL AS sql_database_name, "
        f"version, build_number, install_dir "
        f"FROM {schema}.adminservice_sites WHERE site_code IS NOT NULL",
    )

    # --- wmi_sites: same shape as adminservice_sites ---
    _safe(
        con,
        "node_site<-wmi_sites",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, site_name, server_name, "
        f"reporting_site_code AS parent_site_code, "
        f"TRY_CAST(type AS INTEGER) AS site_type, "
        f"NULL AS site_guid, NULL AS sql_server_name, NULL AS sql_database_name, "
        f"version, build_number, install_dir "
        f"FROM {schema}.wmi_sites WHERE site_code IS NOT NULL",
    )

    # --- adminservice_site_definitions: parent_site_code, site_guid, sql_*, site_type ---
    _safe(
        con,
        "node_site<-adminservice_site_definitions",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, NULL AS site_name, NULL AS server_name, "
        f"parent_site_code, TRY_CAST(site_type AS INTEGER) AS site_type, "
        f"site_guid, sql_server_name, sql_database_name, "
        f"NULL AS version, NULL AS build_number, NULL AS install_dir, "
        f"sql_server_fqdn, CAST(sql_service_port AS VARCHAR) AS sql_service_port "
        f"FROM {schema}.adminservice_site_definitions WHERE site_code IS NOT NULL",
    )

    # --- wmi_site_definitions: same shape as adminservice_site_definitions ---
    _safe(
        con,
        "node_site<-wmi_site_definitions",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, NULL AS site_name, NULL AS server_name, "
        f"parent_site_code, TRY_CAST(site_type AS INTEGER) AS site_type, "
        f"site_guid, sql_server_name, sql_database_name, "
        f"NULL AS version, NULL AS build_number, NULL AS install_dir, "
        f"sql_server_fqdn, CAST(sql_service_port AS VARCHAR) AS sql_service_port "
        f"FROM {schema}.wmi_site_definitions WHERE site_code IS NOT NULL",
    )

    # --- ldap_sites: site_code, site_guid, parent_site_code, distinguished_name, source_forest ---
    _safe(
        con,
        "node_site<-ldap_sites",
        f"INSERT INTO {schema}.node_site BY NAME "
        f"SELECT site_code, NULL AS site_name, NULL AS server_name, "
        f"parent_site_code, NULL AS site_type, "
        f"site_guid, NULL AS sql_server_name, NULL AS sql_database_name, "
        f"NULL AS version, NULL AS build_number, NULL AS install_dir, "
        f"distinguished_name, source_forest "
        f"FROM {schema}.ldap_sites WHERE site_code IS NOT NULL",
    )

    # Collapse all staging rows into one row per site_code (uppercased).
    # Scalars use any_value (first non-null wins); site_type uses max to prefer
    # the highest-authority value (e.g. CAS=4 wins over an older Secondary=1 row).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT "
        f"  upper(site_code) AS site_code, "
        f"  any_value(site_name) AS site_name, "
        f"  any_value(server_name) AS server_name, "
        f"  any_value(parent_site_code) AS parent_site_code, "
        f"  max(site_type) AS site_type, "
        f"  any_value(site_guid) AS site_guid, "
        f"  any_value(sql_server_name) AS sql_server_name, "
        f"  any_value(sql_database_name) AS sql_database_name, "
        f"  any_value(version) AS version, "
        f"  any_value(build_number) AS build_number, "
        f"  any_value(install_dir) AS install_dir, "
        f"  any_value(distinguished_name) AS distinguished_name, "
        f"  any_value(source_forest) AS source_forest, "
        f"  any_value(sql_server_fqdn) AS sql_server_fqdn, "
        f"  any_value(sql_service_port) AS sql_service_port "
        f"FROM {schema}.node_site "
        f"WHERE site_code IS NOT NULL "
        f"GROUP BY upper(site_code)"
    )

    # con-3354: recover sites that only a bare low-privilege source ever saw.
    #
    # _site_hierarchy sweeps *every* site-code source (its D5 bare-code arm), but the
    # arms above read only AdminService/WMI/LDAP. A site discovered solely from SMB
    # share comments or the RemoteRegistry triggers key therefore reached
    # site_hierarchy and stopped there — no node_site row, so no SCCM_Site node, so a
    # low-privilege run silently lost the site. Against the mayyhem lab that dropped
    # the real SEC secondary: site_hierarchy held CAS/PS1/SEC while node_site held
    # only CAS/PS1. A privileged run hid the bug, because AdminService/WMI supply SEC
    # as a source row of their own.
    #
    # Backfilling here — after the collapse, before the stamp below — means the
    # recovered rows pick up root_site_code and the site_type fallback exactly like
    # any other row. Every other column stays NULL, which is honest: a bare code is
    # all those sources ever knew. site_hierarchy stores codes uppercased and the
    # collapse above emits upper(site_code), so the anti-join needs no normalisation.
    _recovered_row = con.execute(
        f"SELECT count(DISTINCT sh.site_code) FROM {schema}.site_hierarchy sh "
        f"WHERE sh.site_code IS NOT NULL "
        f"  AND sh.site_code NOT IN (SELECT site_code FROM {schema}.node_site "
        f"                           WHERE site_code IS NOT NULL)"
    ).fetchone()
    # count(*) always yields a row; the guard is for mypy, which types fetchone()
    # as Optional and cannot know that.
    _recovered = _recovered_row[0] if _recovered_row else 0
    if _recovered:
        logger.info(
            "node_site: recovered %d site(s) known only to bare low-privilege sources "
            "(no AdminService/WMI/LDAP row supplied them)", _recovered,
        )
        con.execute(
            f"INSERT INTO {schema}.node_site (site_code) "
            f"SELECT DISTINCT sh.site_code FROM {schema}.site_hierarchy sh "
            f"WHERE sh.site_code IS NOT NULL "
            f"  AND sh.site_code NOT IN (SELECT site_code FROM {schema}.node_site "
            f"                           WHERE site_code IS NOT NULL)"
        )
    else:
        logger.debug("node_site: every site_hierarchy code already has a node_site row")

    # Aggregate sql_server_service_logon_account per site_code from both
    # site_systems sources into a temp table so the final JOIN can reference a
    # single table regardless of which sources are present (CMBP ps1:225 area).
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _site_sql_acct (site_code VARCHAR, acct VARCHAR)"
    )
    for _ss in ("adminservice_site_systems", "wmi_site_systems"):
        _ensure_columns(con, schema, _ss, {
            "site_code": "VARCHAR",
            "sql_server_service_logon_account": "VARCHAR",
        })
        _safe(
            con,
            f"_site_sql_acct<-{_ss}",
            f"INSERT INTO _site_sql_acct "
            f"SELECT upper(site_code), any_value(sql_server_service_logon_account) "
            f"FROM {schema}.{_ss} "
            f"WHERE site_code IS NOT NULL AND sql_server_service_logon_account IS NOT NULL "
            f"GROUP BY upper(site_code)",
        )

    # Resolve the site-server and SQL-server computer SIDs/FQDNs per site (CMBP
    # ps1:7052-7063). The privileged collector already resolved each server to an AD
    # object at collect time and tagged it with its role ("SMS Site Server@<site>" /
    # "SMS SQL Server@<site>") in *_site_definitions_computers, so we read object_sid
    # and dns_host_name straight from there instead of re-resolving. CMBP names these
    # properties "*DomainSID" but stores the full computer SID, not the domain prefix —
    # we mirror that. The site code is parsed back out of the role string.
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _site_def_computers "
        "(role_kind VARCHAR, site_code VARCHAR, object_sid VARCHAR, dns_host_name VARCHAR)"
    )
    for _sdc in ("adminservice_site_definitions_computers", "wmi_site_definitions_computers"):
        _ensure_columns(con, schema, _sdc, {
            "object_sid": "VARCHAR",
            "dns_host_name": "VARCHAR",
            "sccm_site_system_roles": "VARCHAR",
        })
        _safe(
            con,
            f"_site_def_computers<-{_sdc}",
            f"INSERT INTO _site_def_computers "
            f"SELECT CASE WHEN sccm_site_system_roles LIKE 'SMS Site Server@%' THEN 'SITE' "
            f"            WHEN sccm_site_system_roles LIKE 'SMS SQL Server@%' THEN 'SQL' END AS role_kind, "
            f"  upper(split_part(sccm_site_system_roles, '@', 2)) AS site_code, "
            f"  upper(object_sid) AS object_sid, dns_host_name "
            f"FROM {schema}.{_sdc} "
            f"WHERE object_sid IS NOT NULL "
            f"  AND (sccm_site_system_roles LIKE 'SMS Site Server@%' "
            f"       OR sccm_site_system_roles LIKE 'SMS SQL Server@%')",
        )

    # Stamp each row with root_site_code from site_hierarchy, sql_service_account_name
    # from the aggregated temp table (CMBP ps1:225 area), and the site-server/SQL-server
    # SIDs + FQDNs (CMBP ps1:7052-7065). The SQL service-account SID is resolved by
    # name through principal_by_name (CMBP ps1:3040). All LEFT JOINs so a site missing
    # any of these still appears.
    #
    # site_type: ns's own value (from adminservice_sites/wmi_sites/site_definitions --
    # all privileged sources) wins when known; site_hierarchy's value is the fallback.
    # site_hierarchy now infers a type _node_site's own arms can never state directly
    # (e.g. a CAS, which has no management point and so is never typed by the one
    # low-priv source that carries an explicit type -- see _site_hierarchy's CAS/
    # Secondary inference). Without this fallback a low-priv CAS/PS1 site kept
    # site_type = NULL even after that inference ran, so SCCM_Site.siteType (FIX4)
    # stayed unset. `ns.* EXCLUDE (site_type)` avoids a duplicate column name against
    # the coalesced replacement below.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT ns.* EXCLUDE (site_type), "
        f"  coalesce(ns.site_type, sh.site_type) AS site_type, "
        f"  sh.root_site_code, ssa.acct AS sql_service_account_name, "
        f"  site_srv.object_sid AS site_server_domain_sid, "
        f"  site_srv.dns_host_name AS site_server_fqdn, "
        f"  sql_srv.object_sid AS sql_server_domain_sid, "
        f"  (SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f"   WHERE upper(pbn.name) = upper(ssa.acct) LIMIT 1) AS sql_service_account_domain_sid "
        f"FROM {schema}.node_site ns "
        f"LEFT JOIN {schema}.site_hierarchy sh USING (site_code) "
        f"LEFT JOIN (SELECT site_code, any_value(acct) AS acct FROM _site_sql_acct GROUP BY site_code) ssa "
        f"  USING (site_code) "
        f"LEFT JOIN (SELECT site_code, any_value(object_sid) AS object_sid, "
        f"                  any_value(dns_host_name) AS dns_host_name "
        f"           FROM _site_def_computers WHERE role_kind = 'SITE' GROUP BY site_code) site_srv "
        f"  USING (site_code) "
        f"LEFT JOIN (SELECT site_code, any_value(object_sid) AS object_sid "
        f"           FROM _site_def_computers WHERE role_kind = 'SQL' GROUP BY site_code) sql_srv "
        f"  USING (site_code)"
    )
    _coalesce_http_site_version(con, schema)
    logger.info("node_site built in schema %r", schema)


def _coalesce_http_site_version(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Fill node_site.version from the HTTP ccmsetup.exe fingerprint where privileged
    collection provided none (privileged-preferred).

    Skips entirely when http_site_versions was not loaded this run (no MP fingerprinted,
    so dlt created no such table). We must NOT create it ourselves: http_site_versions is
    a dlt-managed resource table, and a bare hand-made version (lacking dlt's constrained
    ``_dlt_id`` column) makes the NEXT run's dlt load crash with DuckDB "Adding columns
    with constraints not yet supported" when it tries to ALTER in ``_dlt_id``. So we let
    dlt own creation and only read the table when it exists.
    """
    exists = _scalar(con,
        f"SELECT count(*) FROM information_schema.tables "
        f"WHERE table_schema = '{schema}' AND table_name = 'http_site_versions'"
    )
    if not exists:
        logger.debug("http_site_versions absent (no MP fingerprinted); skipping version coalesce")
        return
    # dlt drops an all-NULL column, so a load where every row had a null site_code (or
    # sccm_version) leaves the table without it. Restore it as a plain NULL column (no
    # constraint -> DuckDB-safe, and dlt reconciles it on the next load) so the WHERE /
    # GROUP BY below always binds instead of raising a BinderException. See _ensure_columns.
    _ensure_columns(con, schema, "http_site_versions", {"site_code": "VARCHAR", "sccm_version": "VARCHAR"})
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT ns.* REPLACE (coalesce(ns.version, hv.http_version) AS version) "
        f"FROM {schema}.node_site ns "
        f"LEFT JOIN (SELECT upper(site_code) AS u, any_value(sccm_version) AS http_version "
        f"           FROM {schema}.http_site_versions "
        f"           WHERE site_code IS NOT NULL AND sccm_version IS NOT NULL "
        f"           GROUP BY upper(site_code)) hv ON hv.u = upper(ns.site_code)"
    )


def _root_code(con: duckdb.DuckDBPyConnection, schema: str) -> str | None:
    """Return the single hierarchy root_site_code (built by _site_hierarchy).

    Used to mint SCCM-native ids at final coalesce time. Later tasks (B2, B3,
    E2) all call this helper — define it once here. Returns None if no site
    data was collected (site_hierarchy missing or empty).
    """
    try:
        row = con.execute(f"SELECT any_value(root_site_code) FROM {schema}.site_hierarchy").fetchone()
        return row[0] if row else None
    except duckdb.CatalogException:
        # site_hierarchy not yet built; caller handles None gracefully.
        logger.warning("_root_code: site_hierarchy missing; SCCM-native ids will lack a root scope")
        return None


def _first_primary_code(con: duckdb.DuckDBPyConnection, schema: str) -> str | None:
    """Return the lexicographically-first Primary site code (site_type == 2), or None.

    ConfigManBearPig attaches inferred (CmRcService-only) client devices to "the first
    primary site code published to AD" (ps1:3253-3254) -- deliberately never the CAS,
    which cannot own clients. site_hierarchy.site_type comes from privileged site
    definitions (2 = Primary, 4 = CAS). A deterministic MIN replaces CMBP's
    order-dependent 'Select -First 1' so repeated runs agree.
    """
    try:
        row = con.execute(
            f"SELECT min(site_code) FROM {schema}.site_hierarchy WHERE site_type = 2"
        ).fetchone()
        return row[0] if row else None
    except duckdb.CatalogException:
        # site_hierarchy not built (no privileged site definitions collected).
        logger.warning("_first_primary_code: site_hierarchy missing; cannot pick a Primary site")
        return None


def _read_disable_possible(con: duckdb.DuckDBPyConnection, schema: str) -> bool:
    """Return the effective disable_possible_edges setting for this preproc run.

    Combines two inputs, tightening-only (logical OR):
      1. The collect-time flag persisted in collection_settings (absent for older
         collections -> False).
      2. The SOURCES__SCCM__DISABLE_POSSIBLE_EDGES env var, which lets an operator
         re-process an EXISTING raw collection in high-confidence mode without
         re-collecting:
             SOURCES__SCCM__DISABLE_POSSIBLE_EDGES=true openhound preprocess sccm <raw> <db>
         This is the same SOURCES__SCCM__* env var `collect` maps its
         --disable-possible-edges flag to (main.py:97), now also honored at preproc time.

    The env var can only TIGHTEN: a truthy env forces disable; it can never re-enable
    possible edges that collection already disabled. With the env unset, behavior is
    unchanged from the collect-time value. Gates the possible-client rows and the
    Stage 6 relay edges."""
    # (1) Persisted collect-time value.
    try:
        row = con.execute(
            f"SELECT bool_or(disable_possible_edges) FROM {schema}.collection_settings"
        ).fetchone()
        table_disabled = bool(row[0]) if row and row[0] is not None else False
    except duckdb.CatalogException:
        # Older collection without the settings table -> default to emitting possible rows.
        logger.info("collection_settings absent; possible edges/nodes enabled by default")
        table_disabled = False
    except duckdb.BinderException as ex:
        # FAMILY-1 (same shape as C1/I1): BinderException is a SIBLING of
        # CatalogException, not a subclass, so a collection_settings table that
        # EXISTS but is missing the disable_possible_edges column (dlt dropped it,
        # e.g. every row happened to be all-NULL/all-False) would otherwise
        # propagate uncaught -- and this function is called first and unwrapped
        # from transforms(), so that would abort the entire preprocess run, same
        # as C1. Default to emitting possible rows, same outcome as the missing-
        # table case above. WARNING + the real exception text (reviewer
        # OVER-CATCH): this is a genuinely different cause than the table-missing
        # case, so don't fold it into the same low-visibility INFO message.
        logger.warning(
            "collection_settings.disable_possible_edges unreadable in schema %r "
            "(%s); possible edges/nodes enabled by default", schema, ex,
        )
        table_disabled = False
    # (2) Env-var override (tightening-only).
    env_raw = os.environ.get("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES")
    env_disabled = env_raw is not None and env_raw.strip().lower() in _TRUTHY_ENV
    disabled = table_disabled or env_disabled
    if env_disabled and not table_disabled:
        logger.info(
            "disable_possible_edges forced True by SOURCES__SCCM__DISABLE_POSSIBLE_EDGES "
            "env override (collection was collected with possible edges enabled)"
        )
    logger.info(
        "disable_possible_edges = %s (collect-time table=%s, env override=%s)",
        disabled, table_disabled, env_disabled,
    )
    return disabled


# ---------------------------------------------------------------------------
# Provenance stamp for assumed (unconfirmed) nodes/edges (D3)
# ---------------------------------------------------------------------------
# Shared strings so every SQL builder that stamps an assumed row (Tasks 4/5 below)
# uses the exact same wording instead of retyping it, and so the wording never
# drifts from what `_mark_assumed` would produce for the same concept.
ASSUMED_SITE_DB_BASIS = (
    "site DB inferred from MSSQLSvc SPN + SCCM-relatedness; DB internals not observed"
)
# ASSUMED_SITE_DB_SOURCE ("Assumed-SiteDB") was retired 2026-07-31: collection_source
# now names the originating collection phase, so the assumed/confirmed split no longer
# rides on the source tag. Nothing is lost -- assumedness is carried by the `assumed`
# column and explained by ASSUMED_SITE_DB_BASIS, both of which every scaffolded node
# still gets. Removed rather than left dangling because an unused module constant is
# not flagged by ruff and would read as a live contract to the next person.
# The MSSQL site-DB scaffolding (CM_<site>, sysadmin/db_owner, machine-account
# logins/db-users, and their edges) is templated from SCCM's own default schema
# knowledge whether the underlying site DB is confirmed or assumed -- CMBP never
# reads any of it out of SQL. So confirmed rows get THIS tag (not the old
# transport-name literal), keeping the derivation auditable without implying doubt.
CONFIRMED_SITE_DB_SOURCE = "SCCM-SiteDBDefaultSchema"

# Tables that can carry an 'SMS SQL Server@<site>' role tag, each with its own
# `source` column naming the collection phase that produced it. assumed_site_dbs
# reads these to record WHERE the site-database knowledge came from, rather than the
# static derivation tag above -- 'RemoteRegistry-MultisiteComponentServers' and
# 'AdminService-SiteDefinition' tell an operator which privilege level and which
# transport is behind a node; 'SCCM-SiteDBDefaultSchema' told them neither.
SITE_DB_ROLE_TABLES = (
    "remoteregistry_computers",
    "adminservice_site_definitions_computers",
    "wmi_site_definitions_computers",
)
# Used when the role tag is present on node_computer but no raw table still carries
# an attributable `source` -- keeps the array non-empty rather than silently dropping
# provenance, and is greppable if it ever shows up in a real graph.
RR_SITE_DB_FALLBACK_SOURCE = "RemoteRegistry-SiteSystemRole"
# The low-priv arm: an MSSQLSvc SPN read from AD plus SCCM-relatedness.
SPN_SITE_DB_SOURCE = "LDAP-MSSQLSvcSPN"

ASSIGN_ALL_PERMISSIONS_BASIS = "SMS Provider role implies site control; RBAC not confirmed"
ASSIGN_ALL_PERMISSIONS_SOURCE = "Assumed-AssignAllPermissions"
LOCAL_ADMIN_REQUIRED_BASIS = "site-system co-location implies mutual local admin rights; RBAC not confirmed"
LOCAL_ADMIN_REQUIRED_SOURCE = "Assumed-LocalAdminRequired"
# The parent-primary -> child-secondary arm rests on a DIFFERENT premise than the
# co-location basis above: not "these share a site so they probably trust each other",
# but a specific documented setup step. Keeping a separate string means an operator
# reading the entity panel sees which rule produced the edge.
#
# No apostrophes: every basis constant is interpolated into an f-string SQL literal, so a
# ' here terminates the literal and the whole INSERT fails to parse.
SECONDARY_PARENT_LOCAL_ADMIN_BASIS = (
    "documented secondary-site prerequisite: the computer account of the parent primary "
    "site is added to the Administrators group on the secondary site server; "
    "membership not confirmed"
)
COERCE_RELAY_BASIS = "relay feasibility assumed from role topology + NTLM/SMB-signing state"
COERCE_RELAY_SOURCE = "Assumed-CoerceRelay"
# A "possible" client device is inferred from a CmRcService SPN alone -- the SPN proves
# remote control was once configured, not that the SCCM client is still installed. The
# device node and both edges that hang off it (SCCM_HasClient, SCCM_SameHostAs) are
# therefore assumptions, and --disable-possible-edges already drops all three. They were
# nonetheless reaching the graph UNSTAMPED in default mode (found in Task 10's live run:
# 42 flag-removed edges carrying no `assumed`), which is exactly the D3 gap the stamp
# exists to close -- an operator could not tell them from confirmed client data.
POSSIBLE_CLIENT_BASIS = (
    "device inferred from a CmRcService SPN; SCCM client presence not confirmed"
)
POSSIBLE_CLIENT_SOURCE = "Assumed-PossibleClientDevice"
# MSSQL_CoerceAndRelayToMSSQL is the one relay family whose assumption is CONDITIONAL: the
# edge fires either on a measured Extended Protection of 'Off' (evidence) or on a NULL EPA
# that default mode treats as off (an assumption). Only the latter rows carry this basis,
# so the stamp is a per-row CASE rather than a literal true like its siblings.
MSSQL_RELAY_EPA_ASSUMED_BASIS = (
    "Extended Protection never measured (host unreachable on its SQL port); "
    "default mode assumes EPA is Off"
)


def _mark_assumed(props: dict, basis: str) -> dict:
    """Stamp provenance on an assumed (unconfirmed) node/edge property dict (D3).

    Adds assumed=True, a human assumptionBasis, and an 'Assumed-<slug>' entry in
    collectionSource (idempotent -- re-stamping an already-stamped dict adds no
    second tag). Assumed items still stay traversable -- the tag is how an
    operator tells assumed from confirmed apart, not a suppression.

    This module builds nearly everything via raw SQL, where a Python dict helper
    can't run mid-query -- so the SQL builders in Tasks 4/5 below inline the
    equivalent three columns directly into their INSERTs, referencing the
    ASSUMED_*_BASIS/ASSUMED_*_SOURCE constants above instead of calling this
    function. This helper is for any Python-side row construction that needs the
    same stamp.
    """
    props["assumed"] = True
    props["assumptionBasis"] = basis
    slug = "Assumed-" + basis.split(";")[0].strip().replace(" ", "")
    sources = list(props.get("collectionSource") or [])
    if slug not in sources:
        sources.append(slug)
    props["collectionSource"] = sources
    return props


def _site_db_provenance_cols(is_assumed_sql: str, source_sql: str) -> str:
    """Return the `assumed, assumption_basis, collection_source` SQL column trio
    for a row in the MSSQL site-DB scaffolding family (Task 4/D3/spec §7), keyed
    off a boolean SQL predicate for "this row rests on the SPN+SCCM inference".

    The scaffolding itself (CM_<site> database, sysadmin/db_owner roles,
    machine-account logins/db-users, and their containment/membership edges) is
    templated from SCCM's own default-schema knowledge -- CMBP never reads any of it
    out of SQL, confirmed site DB or not.

    *source_sql* is the SQL expression yielding that row's originating collection
    phase(s), threaded down from `assumed_site_dbs.collection_source` (e.g.
    ``s.collection_source``). It replaces the old static
    ``'SCCM-SiteDBDefaultSchema'`` tag, which named the DERIVATION but not the
    ORIGIN: every site-DB node looked identically sourced whether the knowledge came
    from an admin-only RemoteRegistry read, an AdminService query, or a plain domain
    user's SPN lookup. Provenance exists to answer "where did this come from", and a
    graph that mixes privilege levels needs that answer per node. The `assumed` stamp
    and its human explanation remain conditional on *is_assumed_sql*; callers pass
    either a `basis` comparison (e.g. "s.basis = 'SPN+SCCM'") or a boolean
    passthrough from an already-stamped parent row (e.g. "s.assumed").
    """
    return (
        f"({is_assumed_sql}) AS assumed, "
        f"CASE WHEN ({is_assumed_sql}) THEN '{ASSUMED_SITE_DB_BASIS}' ELSE NULL END AS assumption_basis, "
        f"coalesce({source_sql}, ['{CONFIRMED_SITE_DB_SOURCE}']) AS collection_source"
    )


def _node_smc_container(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One Container node for the System Management container (Task 11, Tier A+).

    Wires up ldap_system_management_dacl, which is collected but was previously read
    by nothing. Standard BloodHound BASE kind (NOT added to schema_SCCM.json): id is
    the container's own objectGUID, uppercased in the collector
    (collectors/ldap.py::_format_guid) to match SharpHound's own Container node for
    the same AD object so the two merge.

    fallback_domain_sid is read off any co-collected GenericAll principal that has a
    normal domain-relative SID (S-1-5-21-...-RID) -- the container itself has no SID
    of its own to derive a domain from. Same "co-occurring domain SID" idiom
    GroupNode already uses for builtin/well-known SIDs.

    Confirmed (an ACL read directly off AD), so this table is the same in both
    --disable-possible-edges modes -- no flag parameter.
    """
    # Unconditional CREATE first (mirrors node_mssql_server/node_computer): convert's
    # AD_NODE_SPECS reads this table by name regardless of whether LDAP collection
    # ran, so it must exist (possibly empty) even when the source table doesn't.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_container "
        "(id VARCHAR, distinguished_name VARCHAR, fallback_domain_sid VARCHAR)"
    )
    _ensure_columns(con, schema, "ldap_system_management_dacl", {
        "object_sid": "VARCHAR", "smc_container_guid": "VARCHAR", "smc_container_dn": "VARCHAR",
    })
    _safe(con, "node_smc_container<-ldap_system_management_dacl",
          f"INSERT INTO {schema}.node_container BY NAME "
          f"SELECT upper(smc_container_guid) AS id, "
          f"  any_value(smc_container_dn) AS distinguished_name, "
          f"  any_value(NULLIF(regexp_extract(upper(object_sid), "
          f"    '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1), '')) AS fallback_domain_sid "
          f"FROM {schema}.ldap_system_management_dacl "
          f"WHERE smc_container_guid IS NOT NULL "
          f"GROUP BY upper(smc_container_guid)")
    n = _scalar(con, f"SELECT count(*) FROM {schema}.node_container")
    logger.info("node_smc_container built (%d System Management container node(s)) in schema %r", n, schema)


def _edge_generic_all_smc(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """GenericAll from each Full-Control principal to the System Management
    container (Task 11, Tier A+). Standard BloodHound BASE kind; traversable via
    TRAVERSABLE_EDGE_KINDS (kinds/edges.py), like SharpHound's own GenericAll edges.

    Confirmed (an ACL read directly off AD, not a template) -- both flag modes, no
    disable_possible_edges parameter and no assumed/assumption_basis stamp.
    """
    from .kinds.edges import GENERIC_ALL
    _ensure_columns(con, schema, "ldap_system_management_dacl", {
        "object_sid": "VARCHAR", "smc_container_guid": "VARCHAR",
    })
    _safe(con, "edge_generic_all_smc",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(object_sid) AS start_id, upper(smc_container_guid) AS end_id, "
          f"  '{GENERIC_ALL}' AS kind, "
          f"  ['LDAP-GenericAllSystemManagement'] AS collection_source "
          f"FROM {schema}.ldap_system_management_dacl "
          f"WHERE object_sid IS NOT NULL AND smc_container_guid IS NOT NULL")


def _node_collection(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build node_collection: one row per collection_id, coalesced from all collection sources.

    Sources and the columns they contribute:

    * adminservice_collections — collection_id, name, collection_type, member_count, is_built_in,
                                 source_site_code, last_change_time, last_member_change_time
    * wmi_collections          — same shape

    The final GROUP BY collapses duplicates (same collection from multiple sources) with
    any_value for scalars, max for numeric aggregates, and bool_or for booleans. Each row
    is stamped with the hierarchy root_site_code from _root_code (via site_hierarchy).
    """
    # Staging table — one raw row per source record before collapsing.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection ("
        "collection_id VARCHAR, name VARCHAR, collection_type INTEGER, member_count BIGINT, "
        "comment VARCHAR, is_built_in BOOLEAN, limit_to_collection_id VARCHAR, "
        "limit_to_collection_name VARCHAR, collection_variables_count BIGINT, "
        "source_site_code VARCHAR, last_change_time VARCHAR, last_member_change_time VARCHAR)"
    )

    # Pre-create optional columns so a source missing one (never-emitted, or
    # dlt-dropped because all-NULL) still binds via INSERT … BY NAME. See _ensure_columns.
    _optional = {
        "name": "VARCHAR",
        "collection_type": "INTEGER",
        "member_count": "BIGINT",
        "comment": "VARCHAR",
        "is_built_in": "BOOLEAN",
        "limit_to_collection_id": "VARCHAR",
        "limit_to_collection_name": "VARCHAR",
        "collection_variables_count": "BIGINT",
        "source_site_code": "VARCHAR",
        "last_change_time": "VARCHAR",
        "last_member_change_time": "VARCHAR",
    }
    for _src in ("adminservice_collections", "wmi_collections"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(
            con,
            f"node_collection<-{_src}",
            f"INSERT INTO {schema}.node_collection BY NAME "
            f"SELECT upper(collection_id) AS collection_id, name, "
            f"TRY_CAST(collection_type AS INTEGER) AS collection_type, "
            f"TRY_CAST(member_count AS BIGINT) AS member_count, comment, "
            f"is_built_in, limit_to_collection_id, limit_to_collection_name, "
            f"TRY_CAST(collection_variables_count AS BIGINT) AS collection_variables_count, "
            f"source_site_code, last_change_time, last_member_change_time "
            f"FROM {schema}.{_src} WHERE collection_id IS NOT NULL",
        )

    # Collapse all staging rows into one row per collection_id, then stamp with root.
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection AS "
        f"SELECT collection_id, "
        f"any_value(name) AS name, "
        f"max(collection_type) AS collection_type, "
        f"max(member_count) AS member_count, "
        f"any_value(comment) AS comment, "
        f"bool_or(is_built_in) AS is_built_in, "
        f"any_value(limit_to_collection_id) AS limit_to_collection_id, "
        f"any_value(limit_to_collection_name) AS limit_to_collection_name, "
        f"max(collection_variables_count) AS collection_variables_count, "
        f"any_value(source_site_code) AS source_site_code, "
        f"any_value(last_change_time) AS last_change_time, "
        f"any_value(last_member_change_time) AS last_member_change_time, "
        f"? AS root_site_code "
        f"FROM {schema}.node_collection "
        f"GROUP BY collection_id",
        [root],
    )
    logger.info("node_collection built in schema %r", schema)


def _enrich_collection_members(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_collection.members: the raw ResourceID@SiteCode keys per collection
    (CMBP ps1:7605), faithful — built-in/unresolved members included. From the raw
    collection_members tables, NOT from graph_edges (Stage 3 Decision #6)."""
    con.execute("CREATE OR REPLACE TEMP TABLE _cmembers (collection_id VARCHAR, member_key VARCHAR)")
    for _src in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _src, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        _safe(con, f"_cmembers<-{_src}",
              f"INSERT INTO _cmembers SELECT upper(collection_id), "
              f"CAST(resource_id AS VARCHAR) || '@' || CAST(site_code AS VARCHAR) "
              f"FROM {schema}.{_src} WHERE collection_id IS NOT NULL AND resource_id IS NOT NULL")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection AS "
        f"SELECT c.*, coalesce(m.members, CAST([] AS VARCHAR[])) AS members "
        f"FROM {schema}.node_collection c "
        f"LEFT JOIN (SELECT collection_id, list_distinct(array_agg(member_key)) AS members "
        f"           FROM _cmembers GROUP BY collection_id) m ON m.collection_id = c.collection_id")
    logger.info("node_collection.members enriched in schema %r", schema)


def _enrich_role_members(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_security_role.members: the admin node ids assigned to each role
    (CMBP ps1:7854/7880). Resolved from raw admins (roles id list + role_names
    fallback via role_by_name when roles is empty), NOT from graph_edges (Decision #6).

    Each member id is upper(logon_name)@root, matching the SCCM_AdminUser node id.
    """
    root = _root_code(con, schema) or ""
    # Inline the @root suffix so the INSERT SQL needs no parameters (matches _safe convention).
    suffix = f" || '@{root}'" if root else ""
    con.execute("CREATE OR REPLACE TEMP TABLE _rmembers (role_id VARCHAR, admin_id VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR", "roles": "VARCHAR", "role_names": "VARCHAR"})

        # Arm 1: role id list — unnest the roles JSON/CSV array via _arr().
        _safe(con, f"_rmembers_roles<-{_src}",
              f"INSERT INTO _rmembers SELECT upper(trim(t.rid)), upper(a.logon_name){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rid) != ''")

        # Arm 2: role_names fallback — ONLY when roles is empty; resolve name -> id via role_by_name.
        _safe(con, f"_rmembers_names<-{_src}",
              f"INSERT INTO _rmembers SELECT rbn.role_id, upper(a.logon_name){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.role_names')}) AS t(rn) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rn)) = rbn.name "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rn) != '' AND len({_arr('a.roles')}) = 0")

    # Attach the aggregated member lists to node_security_role.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role AS "
        f"SELECT r.*, coalesce(m.members, CAST([] AS VARCHAR[])) AS members "
        f"FROM {schema}.node_security_role r "
        f"LEFT JOIN (SELECT role_id, list_distinct(array_agg(admin_id)) AS members "
        f"           FROM _rmembers GROUP BY role_id) m ON m.role_id = r.role_id")
    logger.info("node_security_role.members enriched in schema %r", schema)


def _enrich_admin_assignments(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_admin_user.collection_ids / role_ids / member_of (CMBP ps1:7775/7783/7848).

    role_ids = raw admin.roles list; member_of = resolved role node ids (roles list
    primary, role_names fallback when roles is empty); collection_ids = collection node
    ids resolved from collection_names via collection_by_name. Built from raw admins
    rows + name lookups, NOT from graph_edges (Decision #6).
    """
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""
    con.execute("CREATE OR REPLACE TEMP TABLE _aassign (logon_key VARCHAR, kind VARCHAR, val VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR", "roles": "VARCHAR",
                                            "role_names": "VARCHAR", "collection_names": "VARCHAR"})

        # Arm 1: role_ids — raw role id from the roles JSON/CSV array.
        _safe(con, f"_aassign_roleid<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'role_id', upper(trim(t.rid)) "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rid) != ''")

        # Arm 2: member_of — role node id from the roles list (upper(role_id)@root).
        _safe(con, f"_aassign_memberof_id<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'member_of', upper(trim(t.rid)){suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rid) != ''")

        # Arm 3: member_of fallback — role_names -> role_by_name -> role node id,
        # only when the roles list is empty (no direct ids available).
        _safe(con, f"_aassign_memberof_name<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'member_of', rbn.role_id{suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.role_names')}) AS t(rn) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rn)) = rbn.name "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.rn) != '' AND len({_arr('a.roles')}) = 0")

        # Arm 4: collection_ids — collection_names -> collection_by_name -> collection node id.
        _safe(con, f"_aassign_coll<-{_src}",
              f"INSERT INTO _aassign SELECT upper(a.logon_name), 'collection_id', cbn.collection_id{suffix} "
              f"FROM {schema}.{_src} a, unnest({_arr('a.collection_names')}) AS t(cn) "
              f"JOIN {schema}.collection_by_name cbn ON upper(trim(t.cn)) = cbn.name "
              f"WHERE a.logon_name IS NOT NULL AND trim(t.cn) != ''")

    # Correlated-subquery aggregation: attach all three list columns to node_admin_user.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user AS SELECT a.*, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x "
        f"          WHERE x.logon_key = upper(a.logon_name) AND x.kind = 'collection_id'), "
        f"         CAST([] AS VARCHAR[])) AS collection_ids, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x "
        f"          WHERE x.logon_key = upper(a.logon_name) AND x.kind = 'role_id'), "
        f"         CAST([] AS VARCHAR[])) AS role_ids, "
        f"coalesce((SELECT list_distinct(array_agg(val)) FROM _aassign x "
        f"          WHERE x.logon_key = upper(a.logon_name) AND x.kind = 'member_of'), "
        f"         CAST([] AS VARCHAR[])) AS member_of "
        f"FROM {schema}.node_admin_user a")
    logger.info("node_admin_user assignment lists enriched in schema %r", schema)


def _enrich_client_device(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add resolved *_sid fields and collection_ids/collection_names to node_client_device.

    SID resolution (CMBP ps1:7227/7232/7245/7248): each name-only user field on the
    device row (primary_user_name, current_logon_user_name, ad_last_logon_user_name,
    last_mp_server_name) is looked up in principal_by_name via a correlated subquery.

    Collection lists (CMBP ps1:7228-7229): built from collection_members JOIN collections
    keyed on the device's resource_id_str (<resource_id>@<site>).

    Current management point + previous SMSID (Task B3, CMBP ps1:4010-4011/4016-4017/
    7233-7234): current_management_point already carries the AdminService/WMI value from
    _node_client_device; here it's filled from local_wmi_ccm_client for the collector's own
    host when AdminService had no value, then its SID is resolved via principal_by_name
    (mirroring the other *_sid subqueries below), falling back to local_wmi_ccm_client's own
    SID field if the name doesn't resolve. previous_smsid / previous_smsid_change_date are
    Local-only (CCM_Client's PreviousClientId / ClientIdChangeDate) with no AdminService
    equivalent, so they come from local_wmi_ccm_client alone.
    """
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""

    # Gather all collection memberships per device resource_id into a temp table.
    con.execute("CREATE OR REPLACE TEMP TABLE _devcoll (rid_key VARCHAR, coll_id VARCHAR, coll_name VARCHAR)")
    for _cm in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _cm, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        for _c in ("adminservice_collections", "wmi_collections"):
            _ensure_columns(con, schema, _c, {"collection_id": "VARCHAR", "name": "VARCHAR"})
            _safe(con, f"_devcoll<-{_cm}+{_c}",
                  f"INSERT INTO _devcoll "
                  f"SELECT CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR), "
                  f"upper(cm.collection_id){suffix}, c.name "
                  f"FROM {schema}.{_cm} cm JOIN {schema}.{_c} c ON upper(c.collection_id) = upper(cm.collection_id) "
                  f"WHERE cm.resource_id IS NOT NULL AND cm.collection_id IS NOT NULL")

    # Real-client ADDomainSID (CMBP :7388-7392): SMS_R_System stamps the AD computer
    # SID onto the existing SMSID-keyed client device. Build a smsid -> SID map here,
    # keyed on SMSUniqueIdentifier == smsid (both uppercased). Obsolete r_system rows
    # are skipped (they keep stale duplicate machine records).
    con.execute("CREATE OR REPLACE TEMP TABLE _dev_sid (smsid VARCHAR, sid VARCHAR)")
    for _rs in ("adminservice_r_system", "wmi_r_system"):
        _ensure_columns(con, schema, _rs, {"sms_unique_identifier": "VARCHAR", "sid": "VARCHAR", "obsolete": "BOOLEAN"})
        _safe(con, f"_dev_sid<-{_rs}",
              f"INSERT INTO _dev_sid "
              f"SELECT upper(sms_unique_identifier), upper(sid) "
              f"FROM {schema}.{_rs} "
              f"WHERE sms_unique_identifier IS NOT NULL AND sid IS NOT NULL "
              f"  AND NOT coalesce(obsolete, false)")

    # local_wmi_ccm_client is Local-only telemetry (root\CCM's CCM_Client WMI class) and is
    # absent entirely on any collector host that is not itself an SCCM client -- the common
    # case for a purely-privileged (AdminService/WMI) collection run. ensure_columns() only
    # patches columns onto an EXISTING table, so create it as an empty stub first; the
    # correlated subqueries below then always bind against a real (possibly empty) table
    # instead of raising a CatalogException that would abort this whole rebuild statement
    # (unlike the other source reads in this function, it isn't wrapped in _safe).
    con.execute(f"CREATE TABLE IF NOT EXISTS {schema}.local_wmi_ccm_client (smsid VARCHAR)")
    _ensure_columns(con, schema, "local_wmi_ccm_client", {
        "smsid": "VARCHAR", "current_management_point": "VARCHAR",
        "current_management_point_sid": "VARCHAR", "previous_smsid": "VARCHAR",
        "previous_smsid_change_date": "VARCHAR",
    })

    # current_management_point's resolved value is needed twice below (the REPLACE itself,
    # and again to look up its SID) -- a SELECT list item can't reference a sibling alias in
    # DuckDB, so the expression is built once here and inlined both places instead of two
    # copies drifting out of sync.
    mp_name = (
        f"coalesce(d.current_management_point, "
        f"(SELECT lc.current_management_point FROM {schema}.local_wmi_ccm_client lc "
        f"WHERE upper(lc.smsid) = d.smsid LIMIT 1))"
    )

    # Rebuild node_client_device with SID columns and collection list columns appended.
    # ad_domain_sid: preserve any value already set (inferred clients carry
    # upper(object_sid)); fill NULLs (real clients) from the _dev_sid map above.
    # current_management_point: AdminService/WMI's value wins; Local fills the gap for the
    # collector's own host (CMBP ps1:4010 vs 7233 -- both write the same output key).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS SELECT d.* REPLACE ("
        f"  coalesce(d.ad_domain_sid, "
        f"           (SELECT s.sid FROM _dev_sid s WHERE s.smsid = d.smsid LIMIT 1)) AS ad_domain_sid, "
        f"  {mp_name} AS current_management_point"
        f"), "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.primary_user_name)) LIMIT 1) AS primary_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.current_logon_user_name)) LIMIT 1) AS current_logon_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.ad_last_logon_user_name)) LIMIT 1) AS ad_last_logon_user_sid, "
        f"(SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f" WHERE upper(pbn.name) = upper(trim(d.last_mp_server_name)) LIMIT 1) AS last_reported_mp_server_sid, "
        f"coalesce("
        f"  (SELECT pbn.sid FROM {schema}.principal_by_name pbn "
        f"   WHERE upper(pbn.name) = upper(trim({mp_name})) LIMIT 1), "
        f"  (SELECT lc.current_management_point_sid FROM {schema}.local_wmi_ccm_client lc "
        f"   WHERE upper(lc.smsid) = d.smsid LIMIT 1)"
        f") AS current_management_point_sid, "
        f"(SELECT lc.previous_smsid FROM {schema}.local_wmi_ccm_client lc "
        f" WHERE upper(lc.smsid) = d.smsid LIMIT 1) AS previous_smsid, "
        f"(SELECT lc.previous_smsid_change_date FROM {schema}.local_wmi_ccm_client lc "
        f" WHERE upper(lc.smsid) = d.smsid LIMIT 1) AS previous_smsid_change_date, "
        f"coalesce((SELECT list_distinct(array_agg(coll_id)) FROM _devcoll x WHERE x.rid_key = d.resource_id_str), "
        f"         CAST([] AS VARCHAR[])) AS collection_ids, "
        f"coalesce((SELECT list_distinct(array_agg(coll_name)) FROM _devcoll x WHERE x.rid_key = d.resource_id_str), "
        f"         CAST([] AS VARCHAR[])) AS collection_names "
        f"FROM {schema}.node_client_device d"
    )
    logger.info(
        "node_client_device resolved SIDs (incl. ad_domain_sid, current_management_point) "
        "+ previous_smsid + collection lists enriched in schema %r", schema
    )


def _dedup_client_device(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Collapse SCCM_ClientDevice rows that share an ad_domain_sid (CMBP ps1:2269-2311).

    CMBP merges duplicate client-device nodes found with the same ADDomainSID,
    preferring the authoritative node and unioning array properties. In the port the
    duplicate is a real client (is_confirmed_active_client=true, id=smsid) and its
    inferred twin (is_confirmed_active_client=false, id=<SID>@root) discovered via
    CmRcService SPN. The inferred row is a strict subset, so the merge keeps the real
    survivor's scalars and unions the array columns across the whole ad_domain_sid group.

    Runs BEFORE the edge builders (locked decision), so every edge is built from the
    deduped table and references only survivors — no graph_edges rewrite is needed.

    NULL ad_domain_sid rows (real clients whose SID could not be resolved) are never
    grouped: the composite partition key isolates each by smsid, so distinct unresolved
    devices are preserved (and simply won't get a SCCM_SameHostAs edge — matches CMBP).
    """
    before = (con.execute(f"SELECT count(*) FROM {schema}.node_client_device").fetchone() or (0,))[0]
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS "
        f"WITH ranked AS ("
        f"  SELECT d.* EXCLUDE (collection_ids, collection_names), "
        f"    list_distinct(flatten(array_agg(d.collection_ids) OVER w)) AS collection_ids, "
        f"    list_distinct(flatten(array_agg(d.collection_names) OVER w)) AS collection_names, "
        f"    row_number() OVER ("
        f"      PARTITION BY d.ad_domain_sid, (CASE WHEN d.ad_domain_sid IS NULL THEN d.smsid END) "
        f"      ORDER BY d.is_confirmed_active_client DESC, d.smsid ASC) AS _rn "
        f"  FROM {schema}.node_client_device d "
        f"  WINDOW w AS (PARTITION BY d.ad_domain_sid, (CASE WHEN d.ad_domain_sid IS NULL THEN d.smsid END))"
        f") "
        f"SELECT * EXCLUDE (_rn) FROM ranked WHERE _rn = 1"
    )
    after = (con.execute(f"SELECT count(*) FROM {schema}.node_client_device").fetchone() or (0,))[0]
    if before != after:
        logger.info("node_client_device dedup: merged %d duplicate client-device row(s)", before - after)
    else:
        logger.debug("node_client_device dedup: no duplicate ad_domain_sid rows found")


def _enrich_client_device_ad_attrs(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add CN / dnshostname / distinguished_name / domain / object_class /
    sam_account_name / service_principal_name to node_client_device.

    ad_domain_sid is the client device's join key to the resolved AD computer
    (node_computer already carries these -- either straight from a raw arm that
    spread an AD object, or via _join_ad_props when the SID was independently
    LDAP-resolved). These are attributes of that underlying computer, not of the
    SCCM device record itself, so they are joined in rather than collected twice.
    """
    _safe(
        con,
        "node_client_device<-node_computer(ad_attrs)",
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS "
        f"SELECT d.*, c.cn, c.dnshostname, c.distinguished_name, c.domain, "
        f"  c.object_class, c.sam_account_name, c.service_principal_name "
        f"FROM {schema}.node_client_device d "
        f"LEFT JOIN {schema}.node_computer c ON c.sid = d.ad_domain_sid",
    )
    logger.info("node_client_device enriched with AD computer attributes in schema %r", schema)


def _enrich_site_lists(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Add node_site.admin_users and node_site.stored_accounts list columns.

    admin_users (CMBP ps1:1724): all SCCM admin logon names uppercased and scoped
    to the hierarchy root (e.g. "DOMAIN\\USER@CAS"). Every admin in the single
    hierarchy is contained by every non-secondary site, so the same list appears
    on every site row.

    stored_accounts (CMBP ps1:7141): the object_sid values from the reserved-
    accounts table scoped to that specific site_code (uppercased).
    """
    root = _root_code(con, schema) or ""
    suffix = f" || '@{root}'" if root else ""

    # Collect all admin logon names into a temp table; upper() for consistency.
    con.execute("CREATE OR REPLACE TEMP TABLE _alladmins (admin_id VARCHAR)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"logon_name": "VARCHAR"})
        _safe(
            con,
            f"_alladmins<-{_src}",
            f"INSERT INTO _alladmins "
            f"SELECT DISTINCT upper(logon_name){suffix} "
            f"FROM {schema}.{_src} WHERE logon_name IS NOT NULL",
        )

    # Collect all reserved-account SIDs per site_code into a temp table.
    con.execute("CREATE OR REPLACE TEMP TABLE _stored (site_code VARCHAR, sid VARCHAR)")
    for _src in ("adminservice_reserved_accounts", "wmi_reserved_accounts"):
        _ensure_columns(con, schema, _src, {"site_code": "VARCHAR", "object_sid": "VARCHAR"})
        _safe(
            con,
            f"_stored<-{_src}",
            f"INSERT INTO _stored "
            f"SELECT upper(site_code), upper(object_sid) "
            f"FROM {schema}.{_src} "
            f"WHERE site_code IS NOT NULL AND object_sid IS NOT NULL",
        )

    # Rebuild node_site with both list columns appended. The admin_users subquery
    # has no site_code filter — all admins are contained by the single hierarchy.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT s.*, "
        f"coalesce("
        f"  (SELECT list_distinct(array_agg(admin_id)) FROM _alladmins), "
        f"  CAST([] AS VARCHAR[])"
        f") AS admin_users, "
        f"coalesce("
        f"  (SELECT list_distinct(array_agg(st.sid)) FROM _stored st WHERE st.site_code = s.site_code), "
        f"  CAST([] AS VARCHAR[])"
        f") AS stored_accounts "
        f"FROM {schema}.node_site s"
    )
    logger.info("node_site.admin_users + stored_accounts enriched in schema %r", schema)


def _derive_site_system_roles(con: duckdb.DuckDBPyConnection, schema: str) -> dict[str, list[str]]:
    """Add node_site.site_system_roles: per-site aggregation of site-system role
    assignments (CMBP ps1:1851-1897).

    node_computer.site_system_roles already carries each computer's own list of
    "<role>@<site>" strings (this is what Computer.SCCMSiteSystemRoles emits,
    per-host). CMBP separately re-aggregates that same data onto the SITE: for
    every "<role>@<site>" entry whose site suffix matches a given site, that site's
    siteSystemRoles list gains one "<dnsHostName>: <role>@<site>" string. The two
    properties are deliberately distinct views (per-host vs per-site) of the same
    underlying role assignments.

    Must run after both _node_site and _node_computer have built their tables --
    it reads node_computer.dnshostname/site_system_roles and joins the result back
    onto node_site by site_code, preserving node_site's one-row-per-site_code shape
    (LEFT JOIN + coalesce, so a site with no matching site-system computer keeps
    its row with an empty list rather than being dropped or left NULL).

    Returns the same {site_code: [entries]} mapping now stored in the new column,
    for callers (namely: this function's own tests) that want the plain dict
    without re-querying DuckDB.

    CMBP only attributes siteSystemRoles to a site when that site is NOT a
    Secondary Site (Type -ne "Secondary Site", ps1:1861-1865) -- Secondary Sites
    always keep an empty list, matching the site_type != 1 ("nonsec") convention
    used elsewhere in this module (e.g. _edge_local_admin_required).
    """
    # One row per (computer, role) pair, restricted to roles carrying a site
    # suffix ("<role>@<site>"); the site code is everything after the '@'.
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _site_system_role_entries AS "
        f"SELECT upper(regexp_extract(role, '@(.+)$', 1)) AS site_code, "
        f"  dnshostname || ': ' || role AS entry "
        f"FROM {schema}.node_computer, UNNEST(site_system_roles) AS t(role) "
        f"WHERE dnshostname IS NOT NULL AND role LIKE '%@%'"
    )
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_site AS "
        f"SELECT s.*, "
        f"CASE WHEN coalesce(s.site_type, 0) = 1 THEN CAST([] AS VARCHAR[]) ELSE "
        f"  coalesce("
        f"    (SELECT list_distinct(array_agg(e.entry)) FROM _site_system_role_entries e "
        f"     WHERE e.site_code = upper(s.site_code)), "
        f"    CAST([] AS VARCHAR[])"
        f"  ) END AS site_system_roles "
        f"FROM {schema}.node_site s"
    )
    logger.info("node_site.site_system_roles derived in schema %r", schema)
    return dict(con.execute(f"SELECT site_code, site_system_roles FROM {schema}.node_site").fetchall())


def _node_security_role(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per role_id, coalesced from adminservice/wmi security_roles.

    Audit fields (site_code, created_by, created_date, last_modified_by,
    last_modified_date) come from ROLE_COLUMNS in the source tables. site_code
    is aliased from source_site (ROLE_COLUMNS.SourceSite -> dlt snake-case).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role ("
        "role_id VARCHAR, role_name VARCHAR, role_description VARCHAR, is_built_in BOOLEAN, "
        "is_sec_admin_role BOOLEAN, copied_from_id VARCHAR, number_of_admins BIGINT, operations VARCHAR[], "
        "site_code VARCHAR, created_by VARCHAR, created_date VARCHAR, "
        "last_modified_by VARCHAR, last_modified_date VARCHAR)"
    )
    _optional = {
        "role_name": "VARCHAR",
        "role_description": "VARCHAR",
        "is_built_in": "BOOLEAN",
        "is_sec_admin_role": "BOOLEAN",
        "copied_from_id": "VARCHAR",
        "number_of_admins": "BIGINT",
        "operations": "VARCHAR",
        # Audit fields (ROLE_COLUMNS; may be absent if dlt dropped all-NULL columns).
        "source_site": "VARCHAR",
        "created_by": "VARCHAR",
        "created_date": "VARCHAR",
        "last_modified_by": "VARCHAR",
        "last_modified_date": "VARCHAR",
    }
    for _src in ("adminservice_security_roles", "wmi_security_roles"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(
            con,
            f"node_security_role<-{_src}",
            f"INSERT INTO {schema}.node_security_role BY NAME "
            f"SELECT upper(role_id) AS role_id, role_name, role_description, is_built_in, "
            f"is_sec_admin_role, copied_from_id, TRY_CAST(number_of_admins AS BIGINT) AS number_of_admins, "
            f"{_arr('operations')} AS operations, "
            f"source_site AS site_code, created_by, created_date, last_modified_by, last_modified_date "
            f"FROM {schema}.{_src} WHERE role_id IS NOT NULL",
        )

    # Collapse all staging rows into one row per role_id (already uppercased above), then stamp with root.
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role AS "
        f"SELECT role_id, "
        f"any_value(role_name) AS role_name, "
        f"any_value(role_description) AS role_description, "
        f"bool_or(is_built_in) AS is_built_in, "
        f"bool_or(is_sec_admin_role) AS is_sec_admin_role, "
        f"any_value(copied_from_id) AS copied_from_id, "
        f"max(number_of_admins) AS number_of_admins, "
        f"list_distinct(list_filter(flatten(list(operations)), x -> x IS NOT NULL AND trim(x) != '')) AS operations, "
        f"any_value(site_code) AS site_code, "
        f"any_value(created_by) AS created_by, "
        f"any_value(created_date) AS created_date, "
        f"any_value(last_modified_by) AS last_modified_by, "
        f"any_value(last_modified_date) AS last_modified_date, "
        f"? AS root_site_code "
        f"FROM {schema}.node_security_role "
        f"GROUP BY role_id",
        [root],
    )
    logger.info("node_security_role built in schema %r", schema)


def _node_admin_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per upper(logon_name), coalesced from adminservice/wmi admins.

    Scalar audit fields (display_name, source_site_code, created_by, created_date,
    last_modified_by, last_modified_date) come from ADMIN_COLUMNS in the source tables.
    source_site_code is aliased from source_site (ADMIN_COLUMNS.SourceSite -> dlt snake-case).
    logon_name stored original-case; dedup key is upper(logon_name).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user ("
        "logon_name VARCHAR, admin_id VARCHAR, admin_sid VARCHAR, display_name VARCHAR, "
        "distinguished_name VARCHAR, is_group BOOLEAN, account_type INTEGER, "
        "source_site_code VARCHAR, created_by VARCHAR, created_date VARCHAR, "
        "last_modified_by VARCHAR, last_modified_date VARCHAR)"
    )
    _optional = {
        "admin_id": "VARCHAR",
        "admin_sid": "VARCHAR",
        "display_name": "VARCHAR",
        "distinguished_name": "VARCHAR",
        "is_group": "BOOLEAN",
        "account_type": "INTEGER",
        # Audit fields (ADMIN_COLUMNS; may be absent if dlt dropped all-NULL columns).
        "source_site": "VARCHAR",
        "created_by": "VARCHAR",
        "created_date": "VARCHAR",
        "last_modified_by": "VARCHAR",
        "last_modified_date": "VARCHAR",
    }
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_admin_user<-{_src}",
              f"INSERT INTO {schema}.node_admin_user BY NAME "
              f"SELECT logon_name, CAST(admin_id AS VARCHAR) AS admin_id, upper(admin_sid) AS admin_sid, "
              f"display_name, distinguished_name, is_group, TRY_CAST(account_type AS INTEGER) AS account_type, "
              f"source_site AS source_site_code, created_by, created_date, last_modified_by, last_modified_date "
              f"FROM {schema}.{_src} WHERE logon_name IS NOT NULL")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user AS SELECT "
        f"any_value(logon_name) AS logon_name, any_value(admin_id) AS admin_id, "
        f"any_value(admin_sid) AS admin_sid, any_value(display_name) AS display_name, "
        f"any_value(distinguished_name) AS distinguished_name, bool_or(is_group) AS is_group, "
        f"max(account_type) AS account_type, "
        f"any_value(source_site_code) AS source_site_code, "
        f"any_value(created_by) AS created_by, "
        f"any_value(created_date) AS created_date, "
        f"any_value(last_modified_by) AS last_modified_by, "
        f"any_value(last_modified_date) AS last_modified_date, "
        f"? AS root_site_code "
        f"FROM {schema}.node_admin_user GROUP BY upper(logon_name)", [root])
    logger.info("node_admin_user built in schema %r", schema)


def _node_client_device(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per smsid from adminservice/wmi client_devices (real clients only:
    is_client AND NOT is_obsolete). is_confirmed_active_client is True for these real-client
    rows; inferred-client rows (from CmRcService SPNs) are appended by _node_client_device_possible
    with is_confirmed_active_client=False. ad_domain_sid is NULL here and resolved later from SMS_R_System.

    Telemetry scalars added in Stage 3 C4 (CMBP parity):
      ad_last_logon_time, ad_last_logon_user_domain, source_site_code (from brief)
      last_active_time, last_online_time, last_offline_time (reclassified PORT-NOW by matrix)
    SID resolution and collection lists are added by _enrich_client_device.

    current_management_point (Task B3, CMBP ps1:7233): AdminService/WMI's broad source for
    the device's current MP name (cn_access_mp). _enrich_client_device fills any gap from
    local_wmi_ccm_client and resolves the SID; the Local-only fields (previousSMSID/
    ChangeDate) have no AdminService equivalent and are added entirely in _enrich_client_device.
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device ("
        "smsid VARCHAR, name VARCHAR, site_code VARCHAR, resource_id_str VARCHAR, "
        "device_os VARCHAR, device_os_build VARCHAR, is_virtual_machine BOOLEAN, co_managed BOOLEAN, "
        "aad_device_id VARCHAR, aad_tenant_id VARCHAR, last_mp_server_name VARCHAR, "
        "primary_user_name VARCHAR, current_logon_user_name VARCHAR, ad_last_logon_user_name VARCHAR, "
        "ad_last_logon_time VARCHAR, ad_last_logon_user_domain VARCHAR, source_site_code VARCHAR, "
        "last_active_time VARCHAR, last_online_time VARCHAR, last_offline_time VARCHAR, "
        "current_management_point VARCHAR, "
        "is_confirmed_active_client BOOLEAN, ad_domain_sid VARCHAR)"
    )
    _optional = {
        "name": "VARCHAR", "site_code": "VARCHAR", "resource_id": "BIGINT",
        "device_os": "VARCHAR", "device_os_build": "VARCHAR", "is_virtual_machine": "BOOLEAN",
        "co_managed": "BOOLEAN", "aad_device_id": "VARCHAR", "aad_tenant_id": "VARCHAR",
        "last_mp_server_name": "VARCHAR", "primary_user": "VARCHAR",
        "current_logon_user": "VARCHAR", "user_name": "VARCHAR",
        "is_client": "BOOLEAN", "is_obsolete": "BOOLEAN",
        # Telemetry scalars (Stage 3 C4).
        "ad_last_logon_time": "VARCHAR", "user_domain_name": "VARCHAR",
        "source_site_code": "VARCHAR",
        # The SMS device-resource "CN*" fields are Client-Notification telemetry (SCCM's fast
        # online/offline push channel). Both sms_rows._snake() and dlt's snake_case convention
        # treat "CN" as a single token, so the real raw columns are cn_last_online_time,
        # cn_last_offline_time, and cn_access_mp -- NOT c_n_* (verified against a live bucket).
        # (ADLastLogonTime -> a_d_last_logon_time, which the collector fixes back to
        # ad_last_logon_time; LastActiveTime -> last_active_time.)
        "last_active_time": "VARCHAR",
        "cn_last_online_time": "VARCHAR",
        "cn_last_offline_time": "VARCHAR",
        "cn_access_mp": "VARCHAR",
    }
    for _src in ("adminservice_client_devices", "wmi_client_devices"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_client_device<-{_src}",
              f"INSERT INTO {schema}.node_client_device BY NAME "
              f"SELECT upper(smsid) AS smsid, name, site_code, "
              f"CASE WHEN resource_id IS NULL THEN NULL "
              f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(site_code AS VARCHAR) END AS resource_id_str, "
              f"device_os, device_os_build, is_virtual_machine, co_managed, aad_device_id, aad_tenant_id, "
              f"last_mp_server_name, primary_user AS primary_user_name, "
              f"current_logon_user AS current_logon_user_name, user_name AS ad_last_logon_user_name, "
              f"ad_last_logon_time, user_domain_name AS ad_last_logon_user_domain, source_site_code, "
              f"last_active_time, cn_last_online_time AS last_online_time, "
              f"cn_last_offline_time AS last_offline_time, "
              f"cn_access_mp AS current_management_point, "
              f"true AS is_confirmed_active_client, NULL AS ad_domain_sid "
              f"FROM {schema}.{_src} "
              f"WHERE smsid IS NOT NULL AND coalesce(is_client, false) AND NOT coalesce(is_obsolete, false)")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS SELECT smsid, "
        f"any_value(name) AS name, any_value(site_code) AS site_code, "
        f"any_value(resource_id_str) AS resource_id_str, any_value(device_os) AS device_os, "
        f"any_value(device_os_build) AS device_os_build, bool_or(is_virtual_machine) AS is_virtual_machine, "
        f"bool_or(co_managed) AS co_managed, any_value(aad_device_id) AS aad_device_id, "
        f"any_value(aad_tenant_id) AS aad_tenant_id, any_value(last_mp_server_name) AS last_mp_server_name, "
        f"any_value(primary_user_name) AS primary_user_name, "
        f"any_value(current_logon_user_name) AS current_logon_user_name, "
        f"any_value(ad_last_logon_user_name) AS ad_last_logon_user_name, "
        f"any_value(ad_last_logon_time) AS ad_last_logon_time, "
        f"any_value(ad_last_logon_user_domain) AS ad_last_logon_user_domain, "
        f"any_value(source_site_code) AS source_site_code, "
        f"any_value(last_active_time) AS last_active_time, "
        f"any_value(last_online_time) AS last_online_time, "
        f"any_value(last_offline_time) AS last_offline_time, "
        f"any_value(current_management_point) AS current_management_point, "
        f"bool_or(is_confirmed_active_client) AS is_confirmed_active_client, any_value(ad_domain_sid) AS ad_domain_sid, ? AS root_site_code "
        f"FROM {schema}.node_client_device GROUP BY smsid", [root])
    logger.info("node_client_device built in schema %r", schema)


def _node_client_device_possible(
    con: duckdb.DuckDBPyConnection, schema: str, disable_possible: bool
) -> None:
    """Append inferred possible-client SCCM_ClientDevice rows from ldap_cmrc_devices
    (CMBP ps1:3272, fixed to a deterministic id). id = upper(object_sid)@root — its own
    namespace, so it never merges with the Computer node (raw SID) and Stage 4 SCCM_SameHostAs
    can later dedup it against a real client via ad_domain_sid. site_code (which the
    HasClient edge starts from) is the first Primary site, not the root — a CAS root
    cannot own clients (CMBP ps1:3253-3254). Gated by --disable-possible-edges and on a
    present root_site_code."""
    if disable_possible:
        # --disable-possible-edges was set at collection time; skip all possible-client rows.
        logger.info("possible-client nodes disabled (--disable-possible-edges); skipping")
        return
    root = _root_code(con, schema)
    if not root:
        # Without a hierarchy root the id would collapse to the bare SID and collide
        # with the Computer node; a possible-client only makes sense inside a hierarchy.
        logger.warning("no root_site_code resolved; skipping possible-client nodes")
        return
    # A CAS cannot own clients, so the HasClient edge must originate from a Primary site
    # (CMBP ps1:3253-3254). The id keeps the '@root' suffix for stable namespacing; only
    # site_code -- the site the edge starts from -- moves to the Primary.
    primary = _first_primary_code(con, schema)
    if primary:
        logger.debug("possible-client site_code resolved to Primary %r", primary)
    else:
        # Degenerate hierarchy (a CAS with no Primary, or a standalone Primary that is
        # itself the root): fall back to the root so the HasClient edge is preserved.
        primary = root
        logger.debug("no Primary site resolved; possible-client site_code falls back to root %r", root)
    _ensure_columns(con, schema, "ldap_cmrc_devices", {"object_sid": "VARCHAR", "name": "VARCHAR"})
    # root/primary are 3-character alphanumeric site codes so inlining them as literals is safe.
    _safe(con, "node_client_device_possible<-ldap_cmrc_devices",
          f"INSERT INTO {schema}.node_client_device BY NAME "
          f"SELECT upper(object_sid) || '@{root}' AS smsid, name, '{primary}' AS site_code, "
          f"false AS is_confirmed_active_client, upper(object_sid) AS ad_domain_sid, '{root}' AS root_site_code "
          f"FROM {schema}.ldap_cmrc_devices WHERE object_sid IS NOT NULL")
    logger.info("node_client_device_possible built in schema %r", schema)


def _principal_by_resourceid(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build resource_key '<resource_id>@<site>' -> User/Group SID lookup.

    Sibling of `device_by_resourceid` (resource_key -> SCCM_ClientDevice smsid).
    Together they mirror how CMBP resolves a collection member to a node
    (ps1:7617-7619): a member is matched to a User node, a Group node, or an
    SCCM_ClientDevice node -- never to a plain Computer node.

    So this lookup deliberately covers ONLY user (r_user) and group (user_group)
    resources; it does NOT include r_system (computers). A computer that is a real
    SCCM client resolves through `device_by_resourceid` to its SCCM_ClientDevice; a
    computer SCCM only discovered (never installed the client) matches nothing and
    correctly gets no SCCM_HasMember edge (CMBP logs "No node found for member",
    ps1:7646). Including computer SIDs here would wrongly land SCCM_HasMember on the
    Computer node.

    SIDs are uppercased for consistent joins. Neither source carries an obsolete flag.
    """
    con.execute(f"CREATE OR REPLACE TABLE {schema}.principal_by_resourceid (resource_key VARCHAR, sid VARCHAR)")

    # Users (r_user) and groups (user_group) share identical shaping -- one loop.
    for _src in ("adminservice_r_user", "wmi_r_user", "adminservice_user_group", "wmi_user_group"):
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "source_site_code": "VARCHAR", "sid": "VARCHAR"})
        _safe(con, f"principal_by_resourceid<-{_src}",
              f"INSERT INTO {schema}.principal_by_resourceid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(source_site_code AS VARCHAR), upper(sid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND sid IS NOT NULL")

    con.execute(f"CREATE OR REPLACE TABLE {schema}.principal_by_resourceid AS "
                f"SELECT DISTINCT resource_key, sid FROM {schema}.principal_by_resourceid "
                f"WHERE resource_key IS NOT NULL AND sid IS NOT NULL")
    logger.info("principal_by_resourceid built in schema %r", schema)


def _device_by_resourceid(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build resource_key '<resource_id>@<site>' -> smsid lookup from real clients only.

    Only rows where is_client=True and is_obsolete=False are included, matching
    the same filter used when building node_client_device. smsid is uppercased
    for consistent joins. Used by Stage 2 edge builders that carry a resource_id
    and need to reach the smsid of the corresponding client device.
    """
    con.execute(f"CREATE OR REPLACE TABLE {schema}.device_by_resourceid (resource_key VARCHAR, smsid VARCHAR)")

    for _src in ("adminservice_client_devices", "wmi_client_devices"):
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "site_code": "VARCHAR", "is_client": "BOOLEAN", "is_obsolete": "BOOLEAN"})
        _safe(con, f"device_by_resourceid<-{_src}",
              f"INSERT INTO {schema}.device_by_resourceid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(site_code AS VARCHAR), upper(smsid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND smsid IS NOT NULL "
              f"AND coalesce(is_client, false) AND NOT coalesce(is_obsolete, false)")

    con.execute(f"CREATE OR REPLACE TABLE {schema}.device_by_resourceid AS "
                f"SELECT DISTINCT resource_key, smsid FROM {schema}.device_by_resourceid "
                f"WHERE resource_key IS NOT NULL AND smsid IS NOT NULL")
    logger.info("device_by_resourceid built in schema %r", schema)


def _collection_by_name(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build upper(trim(name)) -> upper(collection_id) lookup.

    Collection names are not guaranteed unique — if duplicates exist after
    dedup, the edge builders that join on name will produce multiple edges
    (fan-out), which is the correct CMBP behaviour (IsAssigned). Duplicates
    are logged at INFO so operators can spot misconfigured environments.
    """
    con.execute(f"CREATE OR REPLACE TABLE {schema}.collection_by_name (name VARCHAR, collection_id VARCHAR)")

    for _src in ("adminservice_collections", "wmi_collections"):
        _ensure_columns(con, schema, _src, {"name": "VARCHAR"})
        _safe(con, f"collection_by_name<-{_src}",
              f"INSERT INTO {schema}.collection_by_name "
              f"SELECT upper(trim(name)), upper(collection_id) "
              f"FROM {schema}.{_src} WHERE name IS NOT NULL AND collection_id IS NOT NULL")

    con.execute(f"CREATE OR REPLACE TABLE {schema}.collection_by_name AS "
                f"SELECT DISTINCT name, collection_id FROM {schema}.collection_by_name")

    dupes = _scalar(con,
        f"SELECT count(*) FROM (SELECT name FROM {schema}.collection_by_name GROUP BY name HAVING count(*) > 1)"
    )
    if dupes:
        # Multiple collection_ids share the same name — edge builders will fan out (correct per CMBP).
        logger.info("collection_by_name: %d collection name(s) map to multiple ids (IsAssigned will fan out)", dupes)
    else:
        logger.debug("collection_by_name: all names unique")


def _role_by_name(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Build upper(trim(role_name)) -> upper(role_id) lookup.

    Role names are expected to be unique, but the table is deduplicated the
    same way as collection_by_name for safety.
    """
    con.execute(f"CREATE OR REPLACE TABLE {schema}.role_by_name (name VARCHAR, role_id VARCHAR)")

    for _src in ("adminservice_security_roles", "wmi_security_roles"):
        _ensure_columns(con, schema, _src, {"role_name": "VARCHAR"})
        _safe(con, f"role_by_name<-{_src}",
              f"INSERT INTO {schema}.role_by_name "
              f"SELECT upper(trim(role_name)), upper(role_id) "
              f"FROM {schema}.{_src} WHERE role_name IS NOT NULL AND role_id IS NOT NULL")

    con.execute(f"CREATE OR REPLACE TABLE {schema}.role_by_name AS "
                f"SELECT DISTINCT name, role_id FROM {schema}.role_by_name")
    logger.info("role_by_name built in schema %r", schema)


# ---------------------------------------------------------------------------
# Stage 5: MSSQL — per-(site, SQL-host) SCCM resolution temp
# ---------------------------------------------------------------------------


def _assumed_site_dbs(con: duckdb.DuckDBPyConnection, schema: str,
                       disable_possible_edges: bool) -> None:
    """Identify site-database-server hosts without privileged (AdminService/WMI)
    data (D2): builds `{schema}.assumed_site_dbs(host_sid, site_code, basis)`.

    Two independent signals, UNIONed:

    - RemoteRegistry-confirmed (basis='RemoteRegistry'): node_computer.site_system_roles
      already carries a merged 'SMS SQL Server@<site>' role tag, however it was
      collected (AdminService, WMI, or low-priv RemoteRegistry) -- node_computer
      merges every source into one array, so the tag's mere presence is the
      confirmed signal. Emitted in BOTH flag modes.
    - SPN+SCCM fallback (basis='SPN+SCCM'): a host with an AD-readable MSSQLSvc
      SPN (mssql_server_instances.has_mssql_spn, Task 1c) that is ALSO
      SCCM-related (carries some SMS role or sccm_infra). A co-located SQL host
      need not be *the* site database, so this is a deliberate tightening of
      CMBP's "any host reachable on 1433" rule -- an inference, not a
      confirmation.

    The fallback is possible-edges-gated: --disable-possible-edges drops it and
    keeps only the RemoteRegistry-confirmed rows. Gating here, once, at the
    single source means every downstream consumer (starting with
    _mssql_sql_servers below) inherits the filter -- no builder repeats the
    check. Nothing confirmed is lost: an MSSQLSvc SPN host still gets its
    MSSQL_Server node from the independent SPN/EPA arm of _node_mssql_server,
    just without the sccm_site / sccm_infra / CM_<site> characterization that
    arm derives from this table.

    Site-code attribution never guesses (D6): each arm resolves a site code only
    when every candidate role for that host names the SAME site. A host whose
    roles span multiple sites (e.g. 'SMS Distribution Point@PS2' AND
    'SMS Site Server@PS1') is an unresolvable clash, not a coin flip -- taking
    array position [1] of a de-duplicated, unordered list would silently pick
    whichever site happened to sort first (review round 1 caught exactly this).
    Ambiguous hosts are logged at WARNING (naming the host and the competing
    codes) and dropped entirely, mirroring the http_management_points ambiguity
    fix above (transforms.py:1085-1134). A host with NO knowable site is dropped
    the same way (logged at INFO, not WARNING -- it isn't a clash, just nothing
    to report): a site DB row with a NULL site_code can't produce CM_<site> and
    has no downstream use, and Task 4 consumes this table directly, so the "gate
    once, here" principle applies to unknowable site codes exactly as it does to
    the possible-edges flag -- no row is emitted for a downstream builder to
    have to re-filter.
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.assumed_site_dbs "
        # collection_source carries the ORIGINATING COLLECTION PHASE(S) -- the
        # transport that actually learned this host is a site database, e.g.
        # 'RemoteRegistry-MultisiteComponentServers' or 'AdminService-SiteDefinition'.
        # It used to be a static derivation tag ('SCCM-SiteDBDefaultSchema'), which
        # told a reader HOW the scaffolding was templated but not WHERE the knowledge
        # came from -- and "where did this come from" is the question provenance
        # exists to answer, especially when the same graph mixes privileged and
        # low-privilege evidence.
        "(host_sid VARCHAR, site_code VARCHAR, basis VARCHAR, collection_source VARCHAR[])"
    )
    # node_computer.sid / site_system_roles / sccm_infra are unconditionally built
    # earlier in the pipeline, so node_computer itself never goes missing here --
    # but a referenced COLUMN can (dlt drops an all-NULL column; a cached bucket
    # predates a column). A bare reference to an absent column raises a
    # BinderException -- a sibling of CatalogException, not a subclass -- which
    # would otherwise escape uncaught and abort the whole preprocess run (the same
    # failure family fixed elsewhere in this plan, e.g. transforms.py:1112-1127).
    # _ensure_columns prevents the exception; every statement below is also run
    # through _safe as defense in depth, so this arm degrades to a logged skip
    # rather than a hard abort even if some other column loss slips past it.
    _ensure_columns(con, schema, "node_computer", {
        "sid": "VARCHAR", "site_system_roles": "VARCHAR[]", "sccm_infra": "BOOLEAN",
    })

    # --- RemoteRegistry-confirmed: authoritative, emitted in both flag modes. ---
    # Unconditional CREATE first, then a _safe-wrapped INSERT (mirrors
    # _mp_site_by_host, transforms.py:1085-1088): if the INSERT's SELECT ever
    # raises, _safe logs and swallows it, but the table itself is already a
    # freshly-emptied one from the CREATE OR REPLACE two lines above -- not the
    # previous transforms() invocation's TEMP table. Re-running transforms()
    # over an existing lookup.duckdb (same connection reused across calls) is a
    # supported workflow, so a stale table surviving a failed rebuild would leak
    # a prior run's rows into this run's assumed_site_dbs. Combining CREATE and
    # SELECT in one _safe-wrapped statement (the previous shape) does not have
    # this property: a failed SELECT means the CREATE never lands either, so the
    # old TEMP table (if any) is left standing with its stale contents intact.
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _rr_site_candidates "
        "(host_sid VARCHAR, distinct_codes VARCHAR[])"
    )

    # Per-host map of the collection phase(s) that actually reported an
    # 'SMS SQL Server@<site>' role, so assumed_site_dbs can record WHERE the
    # site-database knowledge came from. node_computer.site_system_roles is a merged
    # array with no per-source attribution, so the raw tables have to be read directly.
    #
    # Matching on the stringified roles column deliberately: dlt lands it as JSON on
    # remoteregistry_computers and list-typed elsewhere, and list_filter() cannot bind
    # on JSON -- a mismatch _safe would swallow, silently emptying this map and taking
    # the provenance with it (the same trap that disabled the con-be15 gate).
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _site_db_sources (host_sid VARCHAR, sources VARCHAR[])"
    )
    con.execute("CREATE OR REPLACE TEMP TABLE _site_db_source_rows (host_sid VARCHAR, source VARCHAR)")
    for _tbl in SITE_DB_ROLE_TABLES:
        _ensure_columns(con, schema, _tbl, {
            "object_sid": "VARCHAR", "source": "VARCHAR", "sccm_site_system_roles": "JSON",
        })
        _safe(
            con, f"_site_db_source_rows<-{_tbl}",
            f"INSERT INTO _site_db_source_rows "
            f"SELECT DISTINCT upper(object_sid), source FROM {schema}.{_tbl} "
            f"WHERE object_sid IS NOT NULL AND source IS NOT NULL "
            f"  AND CAST(sccm_site_system_roles AS VARCHAR) LIKE '%SMS SQL Server@%'",
        )
    con.execute(
        "INSERT INTO _site_db_sources "
        "SELECT host_sid, list_sort(list_distinct(array_agg(source))) "
        "FROM _site_db_source_rows GROUP BY host_sid"
    )
    _safe(
        con, "_rr_site_candidates<-node_computer",
        "INSERT INTO _rr_site_candidates "
        f"SELECT sid AS host_sid, "
        f"  list_distinct(list_transform("
        f"    list_filter(site_system_roles, x -> x LIKE 'SMS SQL Server@%'), "
        f"    x -> upper(split_part(x, '@', 2))"
        f"  )) AS distinct_codes "
        f"FROM {schema}.node_computer "
        f"WHERE len(list_filter(site_system_roles, x -> x LIKE 'SMS SQL Server@%')) > 0",
    )
    try:
        _rr_ambiguous = con.execute(
            "SELECT host_sid, distinct_codes FROM _rr_site_candidates WHERE len(distinct_codes) > 1"
        ).fetchall()
    except duckdb.CatalogException:
        # _rr_site_candidates is now unconditionally created above, so this is
        # unreachable in practice -- kept as defense in depth (FAMILY-1
        # precedent elsewhere in this module) in case a future refactor removes
        # the unconditional CREATE.
        _rr_ambiguous = []
    for _host, _codes in _rr_ambiguous:
        logger.warning(
            "assumed_site_dbs: host %r carries 'SMS SQL Server@<site>' roles naming "
            "%d competing site codes %s; cannot attribute it to a single site (D6) "
            "-- dropping it rather than guessing", _host, len(_codes), _codes,
        )
    # con-be15: an 'SMS SQL Server@<site>' tag is not always a confirmation.
    #
    # The registry collector emits one from an *inference*: "Multisite Component
    # Servers present but empty" means the site database is local -- true for a
    # standalone primary site server, false for a PASSIVE site server whose
    # database lives elsewhere. Those rows arrive flagged sql_role_assumed, and
    # believing them invents a site database (mayyhem's ps1-psv, which runs no SQL,
    # produced a spurious MSSQL_Server and inflated every dependent MSSQL count).
    #
    # Corroboration is a live answer on 1433. The alternatives do not work: the SQL
    # Server registry keys are admin-gated (access-denied for a plain domain user),
    # and the MSSQLSvc SPN sits on the service account rather than the host, so a
    # real site database running as LocalSystem has none -- an SPN gate would drop
    # mayyhem's genuine SEC secondary. A host whose SQL role came from any
    # *unflagged* source keeps it untouched: the populated-key branch names real
    # database servers, and the privileged arms never set the flag at all.
    # The two sources are collected into separate temp tables rather than joined in
    # one statement: _safe drops an entire statement when any table it names is
    # missing, so referencing both would mean a run without mssql_server_instances
    # silently lost the gate instead of finding no corroboration.
    con.execute("CREATE OR REPLACE TEMP TABLE _live_sql_hosts (host_sid VARCHAR)")
    _ensure_columns(con, schema, "mssql_server_instances", {
        "domain_computer_sid": "VARCHAR", "port_open": "BOOLEAN",
    })
    _safe(
        con, "_live_sql_hosts<-mssql_server_instances",
        f"INSERT INTO _live_sql_hosts "
        f"SELECT DISTINCT upper(domain_computer_sid) FROM {schema}.mssql_server_instances "
        f"WHERE domain_computer_sid IS NOT NULL AND coalesce(port_open, false)",
    )

    con.execute("CREATE OR REPLACE TEMP TABLE _rr_unverified_sql (host_sid VARCHAR)")
    _ensure_columns(con, schema, "remoteregistry_computers", {
        "object_sid": "VARCHAR", "sccm_site_system_roles": "JSON",
        "sql_role_assumed": "BOOLEAN",
    })
    # The roles column lands as JSON on this table (dlt's raw output), NOT as the
    # VARCHAR[] that node_computer.site_system_roles carries after preprocess
    # merges it. list_filter() cannot bind on JSON, and _safe swallows the
    # resulting BinderException -- which silently disabled this whole gate the
    # first time round while the unit tests, whose fixture wrongly used VARCHAR[],
    # went on passing. Matching on the stringified column binds for JSON, VARCHAR
    # and VARCHAR[] alike, so it cannot regress if dlt's typing shifts again.
    #
    # A privileged-only run has no remoteregistry_computers at all, in which case
    # this stays empty and nothing is excluded.
    _sql_role_text = "CAST(sccm_site_system_roles AS VARCHAR) LIKE '%SMS SQL Server@%'"
    _safe(
        con, "_rr_unverified_sql<-remoteregistry_computers",
        f"INSERT INTO _rr_unverified_sql "
        f"SELECT DISTINCT upper(object_sid) FROM {schema}.remoteregistry_computers "
        f"WHERE object_sid IS NOT NULL AND coalesce(sql_role_assumed, false) "
        f"  AND upper(object_sid) NOT IN ("
        f"    SELECT upper(object_sid) FROM {schema}.remoteregistry_computers "
        f"    WHERE object_sid IS NOT NULL AND NOT coalesce(sql_role_assumed, false) "
        f"      AND {_sql_role_text}) "
        f"  AND upper(object_sid) NOT IN (SELECT host_sid FROM _live_sql_hosts)",
    )
    for (_unverified,) in con.execute("SELECT host_sid FROM _rr_unverified_sql").fetchall():
        logger.info(
            "assumed_site_dbs: host %r claims 'SMS SQL Server' only from the empty "
            "Multisite Component Servers inference and nothing answered on 1433 -- "
            "treating it as a passive site server, not a site database (con-be15)",
            _unverified,
        )

    _safe(
        con, "assumed_site_dbs<-_rr_site_candidates",
        f"INSERT INTO {schema}.assumed_site_dbs "
        f"SELECT c.host_sid, c.distinct_codes[1] AS site_code, 'RemoteRegistry' AS basis, "
        f"  coalesce(src.sources, ['{RR_SITE_DB_FALLBACK_SOURCE}']) AS collection_source "
        f"FROM _rr_site_candidates c "
        f"LEFT JOIN _site_db_sources src ON src.host_sid = c.host_sid "
        f"WHERE len(c.distinct_codes) = 1 "
        f"  AND upper(c.host_sid) NOT IN (SELECT host_sid FROM _rr_unverified_sql)",
    )
    n_rr = _scalar(con, f"SELECT count(*) FROM {schema}.assumed_site_dbs")
    if disable_possible_edges:
        logger.info(
            "assumed_site_dbs: --disable-possible-edges set; keeping %d "
            "RemoteRegistry-confirmed site DB(s), dropping the SPN+SCCM inference (D2)",
            n_rr,
        )
        return

    # --- SPN+SCCM fallback, for hosts not already confirmed above. ---
    # The predicate is has_mssql_spn specifically, not bare presence in
    # mssql_server_instances -- before Task 1c that table only held hosts whose
    # TCP/1433 answered, so a plain semi-join would silently test port
    # reachability instead of SPN presence (the exact weakness D2 exists to
    # avoid). Site attribution draws from ANY '@'-suffixed role (not just SMS SQL
    # Server ones) since this arm's evidence is "SCCM-related, somehow" -- but the
    # same single-distinct-site rule applies. Hosts already RemoteRegistry-
    # confirmed are excluded (the trailing len(...) = 0 predicate) so a host never
    # gets two rows with two different basis values, which would make Task 4's
    # provenance stamp ambiguous.
    _ensure_columns(con, schema, "mssql_server_instances", {
        "domain_computer_sid": "VARCHAR", "has_mssql_spn": "BOOLEAN",
    })
    # Same unconditional-CREATE-then-_safe-INSERT shape as _rr_site_candidates
    # above, for the identical reason: a failed INSERT must not leave a prior
    # run's stale TEMP table in place for the SELECTs below to read from.
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _spn_site_candidates "
        "(host_sid VARCHAR, distinct_codes VARCHAR[])"
    )
    _safe(
        con, "_spn_site_candidates<-node_computer",
        "INSERT INTO _spn_site_candidates "
        f"SELECT nc.sid AS host_sid, "
        f"  list_distinct(list_transform("
        f"    list_filter(nc.site_system_roles, x -> x LIKE '%@%'), "
        f"    x -> upper(split_part(x, '@', 2))"
        f"  )) AS distinct_codes "
        f"FROM {schema}.node_computer nc "
        f"WHERE nc.sid IN ("
        f"        SELECT upper(domain_computer_sid) FROM {schema}.mssql_server_instances "
        f"        WHERE coalesce(has_mssql_spn, false)) "
        f"  AND (nc.sccm_infra = true OR len(nc.site_system_roles) > 0) "
        f"  AND len(list_filter(nc.site_system_roles, x -> x LIKE 'SMS SQL Server@%')) = 0",
    )
    try:
        _spn_ambiguous = con.execute(
            "SELECT host_sid, distinct_codes FROM _spn_site_candidates WHERE len(distinct_codes) > 1"
        ).fetchall()
    except duckdb.CatalogException:
        # Unreachable now that _spn_site_candidates is unconditionally created
        # above; kept as defense in depth, same rationale as _rr_ambiguous.
        _spn_ambiguous = []
    for _host, _codes in _spn_ambiguous:
        logger.warning(
            "assumed_site_dbs: SPN+SCCM host %r carries '@<site>' roles naming %d "
            "competing site codes %s; cannot attribute it to a single site (D6) "
            "-- dropping it rather than guessing", _host, len(_codes), _codes,
        )
    try:
        n_spn_no_site = _scalar(con,
            "SELECT count(*) FROM _spn_site_candidates WHERE len(distinct_codes) = 0"
        )
    except duckdb.CatalogException:
        # Unreachable now that _spn_site_candidates is unconditionally created
        # above; kept as defense in depth, same rationale as _spn_ambiguous.
        n_spn_no_site = 0
    if n_spn_no_site:
        logger.info(
            "assumed_site_dbs: dropping %d SPN+SCCM candidate(s) with no '@<site>' "
            "role at all -- a site DB with no knowable site has no downstream use",
            n_spn_no_site,
        )
    _safe(
        con, "assumed_site_dbs<-_spn_site_candidates",
        f"INSERT INTO {schema}.assumed_site_dbs "
        f"SELECT host_sid, distinct_codes[1] AS site_code, 'SPN+SCCM' AS basis, "
        f"  ['{SPN_SITE_DB_SOURCE}'] AS collection_source "
        f"FROM _spn_site_candidates WHERE len(distinct_codes) = 1",
    )
    n_total = _scalar(con, f"SELECT count(*) FROM {schema}.assumed_site_dbs")
    logger.info(
        "assumed_site_dbs built: %d RemoteRegistry-confirmed + %d SPN+SCCM-inferred "
        "= %d total in schema %r",
        n_rr, n_total - n_rr, n_total, schema,
    )


def _mssql_sql_servers(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Resolve every (site, SQL-host computer) pair that runs the site database.

    The privileged collector tagged each site-system computer with its role
    ("SMS SQL Server@<site>") in *_site_definitions_computers (same source the
    Stage-4 site-server resolution reads at transforms.py:1199). One row per
    (site, SQL host) preserves the multiple-site-database-per-site case (grilled
    2026-06-29) — node_site collapses to one SQL host via any_value, so we read the
    role rows directly here instead. Site-level SQL attributes (db name, port,
    service account) are shared across a site's SQL hosts, so they are joined from
    node_site. The database name falls back to CM_<siteCode> (CMBP :6082).

    A third, non-privileged source (D2/Task 2) reads `assumed_site_dbs` -- the
    RemoteRegistry-confirmed and (unless --disable-possible-edges dropped it)
    SPN+SCCM-inferred site-DB hosts a low-privilege operator can see without
    AdminService/WMI. That table is already possible-edges-gated at its own
    source, so this arm needs no flag check of its own; duplicates of a
    privileged-source pair simply collapse below via the same GROUP BY that
    already collapses the two privileged sources with each other.
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}._mssql_sql_servers ("
        "site_code VARCHAR, root_site_code VARCHAR, host_sid VARCHAR, dns_host_name VARCHAR, "
        "port VARCHAR, db_name VARCHAR, service_account_name VARCHAR, service_account_sid VARCHAR, "
        # The originating collection phase(s), carried from assumed_site_dbs (or the
        # privileged arms' own `source`) so every scaffolded node can say where its
        # site-database knowledge came from rather than only how it was templated.
        "basis VARCHAR, collection_source VARCHAR[])"
    )
    # Staging temp: collect (site, SQL host) pairs from all available sources. basis
    # carries assumed_site_dbs' provenance label through to the final table (Task 4);
    # the two privileged-source arms below leave it NULL -- they have no basis of
    # their own, and _node_mssql_database etc. below treat NULL the same as
    # 'RemoteRegistry' (both unstamped, spec §7).
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _mssql_sql_hosts "
        "(site_code VARCHAR, host_sid VARCHAR, dns_host_name VARCHAR, basis VARCHAR, "
        "collection_source VARCHAR[])"
    )
    for _sdc in ("adminservice_site_definitions_computers", "wmi_site_definitions_computers"):
        _ensure_columns(con, schema, _sdc, {
            "object_sid": "VARCHAR", "dns_host_name": "VARCHAR", "sccm_site_system_roles": "VARCHAR",
            "source": "VARCHAR",
        })
        _safe(con, f"_mssql_sql_hosts<-{_sdc}",
              f"INSERT INTO _mssql_sql_hosts "
              f"SELECT upper(split_part(sccm_site_system_roles, '@', 2)) AS site_code, "
              f"  upper(object_sid) AS host_sid, dns_host_name, NULL AS basis, "
              f"  CASE WHEN source IS NULL THEN NULL ELSE [source] END AS collection_source "
              f"FROM {schema}.{_sdc} "
              f"WHERE object_sid IS NOT NULL AND sccm_site_system_roles LIKE 'SMS SQL Server@%'")

    # Non-privileged arm (D2/Task 2): host/site pairs from assumed_site_dbs, joined
    # back to node_computer for a hostname (assumed_site_dbs itself carries none).
    # assumed_site_dbs (review round 1, IMPORTANT-3) now guarantees a non-NULL
    # site_code on every row it emits -- an unattributable candidate is dropped at
    # that single source rather than passed downstream for every consumer to
    # re-filter (Task 4 reads assumed_site_dbs directly and would otherwise
    # inherit a useless row too). The IS NOT NULL check below is intentionally
    # kept anyway as a belt-and-braces guard: if that upstream guarantee ever
    # regressed, a NULL site_code would otherwise join node_site as a site-less
    # ghost row instead of failing loudly.
    _safe(con, "_mssql_sql_hosts<-assumed_site_dbs",
          f"INSERT INTO _mssql_sql_hosts "
          f"SELECT a.site_code, a.host_sid, nc.dnshostname AS dns_host_name, a.basis, "
          f"  a.collection_source "
          f"FROM {schema}.assumed_site_dbs a "
          f"JOIN {schema}.node_computer nc ON nc.sid = a.host_sid "
          f"WHERE a.site_code IS NOT NULL")

    # Collapse duplicate (site, host) rows, then attach the site-level SQL attributes.
    # basis: max() over the group so a privileged-arm row (NULL) never masks a
    # same-host assumed_site_dbs row's real basis string -- max() ignores NULLs and
    # surfaces whichever non-null value is present (there is at most one, since
    # assumed_site_dbs never emits two basis values for the same host, Task 2).
    con.execute(
        f"INSERT INTO {schema}._mssql_sql_servers "
        f"SELECT h.site_code, ns.root_site_code, h.host_sid, any_value(h.dns_host_name) AS dns_host_name, "
        f"  coalesce(any_value(ns.sql_service_port), '1433') AS port, "
        f"  coalesce(any_value(ns.sql_database_name), 'CM_' || h.site_code) AS db_name, "
        f"  any_value(ns.sql_service_account_name) AS service_account_name, "
        f"  any_value(ns.sql_service_account_domain_sid) AS service_account_sid, "
        f"  max(h.basis) AS basis, "
        # list-union rather than any_value: a host confirmed by two phases should
        # name both, not whichever row the aggregate happened to see first.
        f"  list_sort(list_distinct(flatten(array_agg(h.collection_source) "
        f"    FILTER (WHERE h.collection_source IS NOT NULL)))) AS collection_source "
        f"FROM _mssql_sql_hosts h "
        f"LEFT JOIN {schema}.node_site ns ON upper(ns.site_code) = h.site_code "
        f"GROUP BY h.site_code, ns.root_site_code, h.host_sid"
    )
    n = _scalar(con, f"SELECT count(*) FROM {schema}._mssql_sql_servers")
    logger.info("_mssql_sql_servers resolved %d (site, SQL-host) pair(s) in schema %r", n, schema)


def _node_mssql_server(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Coalesce one MSSQL_Server per host_sid:port (CMBP Add-MSSQLServerNodesAndEdges :6088).

    MERGE of three sources (grilled 2026-06-29):
      - _mssql_sql_servers  (SCCM site DB; supplies SCCMSite/db/service-account/dnsHostName)
      - mssql_server_instances     (EPA scan; supplies extendedProtection/forceEncryption/strictEncryption)
      - remoteregistry_mssql_servers (registry; supplies port/forceEncryption/instanceNames)
    Key = upper(host_sid) || ':' || port, so multiple site DBs per site AND non-SCCM SQL
    servers are both captured. Non-SCCM rows have NULL SCCMSite / false SCCMInfra.

    EPA value vocabularies differ (scan: Off/Allowed/Required/Unknown; registry: On/Off);
    Stage 5 carries them as-is (Stage 6 interprets them). extended_protection prefers the
    scan's richer value, then registry. The port is a VARCHAR throughout (matches node_site).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_server ("
        "host_sid VARCHAR, port VARCHAR, name VARCHAR, dns_host_name VARCHAR, "
        "sccm_site VARCHAR, sccm_infra BOOLEAN, databases VARCHAR[], "
        "force_encryption BOOLEAN, extended_protection VARCHAR, strict_encryption BOOLEAN, "
        "instance_names VARCHAR[], service_account_name VARCHAR, service_account_domain_sid VARCHAR, "
        # Task 13 (Tier A+): the LOW-PRIV MSSQLSvc SPN holder, distinct from
        # service_account_domain_sid above (the PRIVILEGED SMS_SCI_SysResUse arm's
        # identity). Kept as separate columns rather than merged into one so neither
        # arm's provenance is misattributed to the other; when both resolve the same
        # real account on the same server, _graph_edges_dedup collapses the resulting
        # duplicate edge triples into one, so no cross-arm guard is needed here.
        "service_account_sid VARCHAR, service_account_is_computer BOOLEAN, "
        "port_open BOOLEAN, collection_source VARCHAR[], "
        # con-be15: SQL Server can be *installed* on a host that never serves
        # anything -- a passive site server is the case that exposed this. The node
        # is still emitted; these tell a live database from a dormant install.
        # start_type is the service's STARTUP TYPE from the registry, not live
        # running state, so running_possible is false only for Disabled (which is
        # conclusive) and true otherwise (which is not).
        "service_start_type VARCHAR, "
        "assumed BOOLEAN, assumption_basis VARCHAR)"
    )
    # Arm 1: SCCM-resolved site databases. No port probe involved -- port_open NULL
    # (neither confirmed open nor confirmed closed; see the Stage 6 relay gate below).
    # Provenance (Task 4 ownership gap, 2026-07-27 review): this arm used to stamp the
    # privileged collection_source unconditionally, which would let an SPN+SCCM
    # inference (basis, from _mssql_sql_servers <- assumed_site_dbs) claim privileged
    # provenance. basis drives the stamp now -- NULL (a privileged-arm-only pair with
    # no assumed_site_dbs row) is treated the same as 'RemoteRegistry' (confirmed).
    _server_provenance = _site_db_provenance_cols("basis = 'SPN+SCCM'", "collection_source")
    _safe(con, "node_mssql_server<-_mssql_sql_servers",
          f"INSERT INTO {schema}.node_mssql_server BY NAME "
          f"SELECT host_sid, coalesce(port, '1433') AS port, dns_host_name AS name, dns_host_name, "
          f"  site_code AS sccm_site, true AS sccm_infra, "
          f"  CASE WHEN db_name IS NULL THEN CAST([] AS VARCHAR[]) ELSE [db_name] END AS databases, "
          f"  NULL AS force_encryption, NULL AS extended_protection, NULL AS strict_encryption, "
          f"  CAST([] AS VARCHAR[]) AS instance_names, "
          f"  service_account_name, service_account_sid AS service_account_domain_sid, "
          # This arm's identity is the PRIVILEGED one (above); it has no SPN-search
          # result of its own, so the low-priv columns stay NULL here (arm 2 alone
          # populates them).
          f"  NULL AS service_account_sid, NULL AS service_account_is_computer, "
          f"  NULL AS port_open, "
          f"  {_server_provenance} "
          f"FROM {schema}._mssql_sql_servers WHERE host_sid IS NOT NULL")
    # Arm 2: EPA scan. port_open records whether collect_mssql actually reached 1433 --
    # a row can now exist on SPN evidence alone with the port filtered (Task 1c/D2a),
    # so this is the one arm where the flag can be an explicit false.
    _ensure_columns(con, schema, "mssql_server_instances", {
        "domain_computer_sid": "VARCHAR", "port": "INTEGER", "name": "VARCHAR", "dns_host_name": "VARCHAR",
        "extended_protection": "VARCHAR", "force_encryption": "BOOLEAN", "strict_encryption": "BOOLEAN",
        "port_open": "BOOLEAN", "service_account_sid": "VARCHAR", "service_account_is_computer": "BOOLEAN",
    })
    _safe(con, "node_mssql_server<-mssql_server_instances",
          f"INSERT INTO {schema}.node_mssql_server BY NAME "
          f"SELECT upper(domain_computer_sid) AS host_sid, CAST(coalesce(port, 1433) AS VARCHAR) AS port, "
          # name stays the AD CN; dns_host_name prefers the real FQDN (reviewer M2)
          # but falls back to name (reviewer REGRESSION-1) -- collect_mssql only
          # started emitting dns_host_name in this same task, so re-processing a
          # cached bucket collected before it existed would otherwise land NULL
          # here instead of the CN it used to carry.
          f"  name, coalesce(dns_host_name, name) AS dns_host_name, "
          f"  NULL AS sccm_site, false AS sccm_infra, "
          f"  CAST([] AS VARCHAR[]) AS databases, force_encryption, extended_protection, strict_encryption, "
          f"  CAST([] AS VARCHAR[]) AS instance_names, NULL AS service_account_name, "
          # This arm's identity is the LOW-PRIV one (Task 13: the MSSQLSvc SPN holder
          # collect_mssql resolves via find_mssql_spn_holder) -- service_account_domain_sid
          # (the PRIVILEGED arm 1 identity) stays NULL here.
          f"  NULL AS service_account_domain_sid, "
          f"  upper(service_account_sid) AS service_account_sid, service_account_is_computer, "
          f"  port_open, "
          # Provenance must reflect what actually happened (reviewer M1):
          # 'MSSQL-ScanForEPA' means an EPA scan actually ran, which
          # _edge_coerce_relay_mssql filters on as "the server's EPA-determination
          # sources" (CMBP ps1:6715). Since Task 1c a row can exist on SPN evidence
          # alone with port_open = false, where no scan ever ran -- tag those
          # 'MSSQL-SPN' instead so nothing downstream credits a scan that never
          # happened. NULL port_open (a row from before this column existed) predates
          # the SPN-only path entirely, so it was always a real scan.
          f"  CASE WHEN port_open = false THEN ['MSSQL-SPN'] ELSE ['MSSQL-ScanForEPA'] END "
          f"    AS collection_source, "
          # An EPA scan says nothing about whether the host is SCCM's site database --
          # that claim belongs to arm 1 alone, so this arm never stamps assumed.
          f"  NULL AS assumed, NULL AS assumption_basis "
          f"FROM {schema}.mssql_server_instances WHERE domain_computer_sid IS NOT NULL")
    # Arm 3: remote-registry. Reads the registry directly, no port probe -- NULL, same as arm 1.
    # port is a REG_SZ string in the registry, so dlt types it VARCHAR (unlike the
    # EPA scan's INTEGER). Declare/coalesce it as VARCHAR so the arm binds either way.
    _ensure_columns(con, schema, "remoteregistry_mssql_servers", {
        "domain_computer_sid": "VARCHAR", "port": "VARCHAR", "name": "VARCHAR",
        "extended_protection": "VARCHAR", "force_encryption": "BOOLEAN", "instance_names": "VARCHAR",
        # con-be15 service-state columns. Declared here for the same reason as the
        # rest: the Services hive is admin-gated, so a low-privilege collection
        # emits them as all-NULL and dlt drops them entirely. Without this the arm
        # fails to bind and _safe drops it wholesale, which would silently lose
        # every registry-discovered SQL server rather than just these three fields.
        "service_account_name": "VARCHAR", "service_start_type": "VARCHAR",
    })
    _safe(con, "node_mssql_server<-remoteregistry_mssql_servers",
          f"INSERT INTO {schema}.node_mssql_server BY NAME "
          f"SELECT upper(domain_computer_sid) AS host_sid, coalesce(port, '1433') AS port, "
          f"  name, name AS dns_host_name, NULL AS sccm_site, false AS sccm_infra, "
          f"  CAST([] AS VARCHAR[]) AS databases, force_encryption, extended_protection, NULL AS strict_encryption, "
          f"  {_arr('instance_names')} AS instance_names, "
          # The service control entry names the account the engine runs as
          # (ObjectName), which this arm previously discarded. It is the only
          # low-cost source for it outside the privileged SMS_SCI_SysResUse arm.
          f"  service_account_name, "
          f"  NULL AS service_account_domain_sid, "
          f"  NULL AS service_account_sid, NULL AS service_account_is_computer, "
          f"  NULL AS port_open, "
          f"  service_start_type, "
          f"  ['RemoteRegistry-MSSQL'] AS collection_source, "
          # Same reasoning as arm 2: this arm confirms a SQL instance exists, not
          # that it's SCCM's site database -- assumed is arm 1's claim alone.
          f"  NULL AS assumed, NULL AS assumption_basis "
          f"FROM {schema}.remoteregistry_mssql_servers WHERE domain_computer_sid IS NOT NULL")
    # Collapse to one row per host_sid:port. SCCM scalars win via any_value-skip-null ordering;
    # EPA prefers any non-null. server_id minted final here. port_open uses bool_or so a
    # host reached via multiple arms is "open" if ANY arm actually saw it answer.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_server AS "
        f"SELECT upper(host_sid) || ':' || port AS server_id, "
        f"  host_sid, port, any_value(name) AS name, any_value(dns_host_name) AS dns_host_name, "
        f"  any_value(sccm_site) AS sccm_site, bool_or(sccm_infra) AS sccm_infra, "
        f"  list_distinct(flatten(list(databases))) AS databases, "
        f"  bool_or(force_encryption) AS force_encryption, "
        f"  any_value(extended_protection) AS extended_protection, "
        f"  bool_or(strict_encryption) AS strict_encryption, "
        f"  list_distinct(flatten(list(instance_names))) AS instance_names, "
        f"  any_value(service_account_name) AS service_account_name, "
        f"  any_value(service_account_domain_sid) AS service_account_domain_sid, "
        # Task 13's low-priv columns: only arm 2 ever contributes them, so any_value/
        # bool_or just surface that arm's value untouched (same idiom as the
        # privileged pair above).
        f"  any_value(service_account_sid) AS service_account_sid, "
        f"  bool_or(service_account_is_computer) AS service_account_is_computer, "
        # Only the RemoteRegistry arm supplies these, so any_value/bool_or simply
        # carry its value through the collapse (con-be15).
        f"  any_value(service_start_type) AS service_start_type, "
        f"  bool_or(port_open) AS port_open, "
        f"  list_distinct(flatten(list(collection_source))) AS collection_source, "
        # assumed/assumption_basis are arm 1's claim alone (arms 2/3 always leave
        # them NULL) -- bool_or/max surface arm 1's value untouched when it
        # contributed, and stay NULL (no stamp) when only arms 2/3 did.
        f"  bool_or(assumed) AS assumed, max(assumption_basis) AS assumption_basis "
        f"FROM {schema}.node_mssql_server WHERE host_sid IS NOT NULL AND port IS NOT NULL "
        f"GROUP BY upper(host_sid), host_sid, port"
    )
    n = _scalar(con, f"SELECT count(*) FROM {schema}.node_mssql_server")
    logger.info("node_mssql_server built (%d server(s)) in schema %r", n, schema)


def _node_mssql_database(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One MSSQL_Database per SCCM site DB (CMBP :6140). id = <server_id>\\<db_name>.

    Built only from _mssql_sql_servers (the SCCM-linked servers) — CMBP never creates a
    database for a SQL server it didn't reach via site processing, and non-SCCM scan-only
    servers expose no database name. db_name defaults to CM_<siteCode> in _mssql_sql_servers.

    Provenance (Task 4/D3/spec §7): this whole templated schema is never read out of
    SQL, confirmed site DB or not -- basis (from assumed_site_dbs, via _mssql_sql_servers)
    decides only whether it rests on the SPN+SCCM inference. No disable_possible_edges
    parameter here -- Task 2 already dropped the SPN+SCCM rows upstream when the flag is
    set, so this builder simply has fewer _mssql_sql_servers rows to build from.
    """
    _db_provenance = _site_db_provenance_cols("basis = 'SPN+SCCM'", "collection_source")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_database AS "
        f"SELECT DISTINCT "
        f"  upper(host_sid) || ':' || coalesce(port, '1433') || '\\' || db_name AS database_id, "
        f"  upper(host_sid) || ':' || coalesce(port, '1433') AS server_id, "
        f"  upper(host_sid) AS host_sid, coalesce(port, '1433') AS port, "
        f"  db_name AS name, site_code AS sccm_site, dns_host_name AS sql_server, "
        f"  {_db_provenance} "
        f"FROM {schema}._mssql_sql_servers WHERE host_sid IS NOT NULL AND db_name IS NOT NULL"
    )
    n = _scalar(con, f"SELECT count(*) FROM {schema}.node_mssql_database")
    logger.info("node_mssql_database built (%d database(s)) in schema %r", n, schema)


def _node_mssql_login(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One MSSQL_Login per (SCCM SQL host, sysadmin computer) (CMBP :6232).

    Sysadmin computer = a Site Server / SMS Provider for the SAME site as the SQL host,
    EXCLUDING the SQL host itself (CMBP :1912-1920). Login id/name use the computer's OWN
    DNS domain first label as NETBIOS (grilled 2026-06-29): <NETBIOS>\\<sam>@<server_id>.

    A SECOND arm covers SECONDARY sites, whose database the same-site rule above can never
    reach. Microsoft requires a secondary's database to run ON the secondary site server
    (prerequisites-for-installing-sites#bkmk_secondary), so the site's only Site Server IS
    the SQL host and the self-exclusion removes it, leaving the database with no logins at
    all. The same page names who really holds sysadmin there: the computer account of the
    PARENT PRIMARY site, permanently ("Don't remove the sysadmin permissions"). When setup
    installs SQL Express instead, BUILTIN\\Administrators is sysadmin by default and the
    parent primary reaches it through the local Administrators membership that same page
    mandates -- so the parent primary ends up sysadmin either way, which is why this arm
    emits that grant without needing to know which install path was taken. (The BROADER
    "every local admin is sysadmin" claim is Express-only and is deliberately NOT emitted;
    see con-e2f1.)

    That arm fires only on a POSITIVELY known secondary (`site_type = 1`), never on an
    unknown type -- the same con-edee reasoning as _NON_SECONDARY_SITE_TYPE_SQL, in mirror
    image. At low privilege a secondary is typically discoverable only as a bare site code
    (an SMB share comment), and AD carries no mSSMSSite/mSSMSManagementPoint object for a
    secondary at all, so its type stays NULL and this arm correctly stays silent rather
    than inventing a sysadmin grant from a topology it could not confirm.

    Matching the parent's site servers BY ROLE rather than picking a single "the" site
    server also covers a parent running a site server in passive mode: both the active and
    passive nodes carry 'SMS Site Server@<parent>', and a SharpHound capture of the mayyhem
    lab confirms both machine accounts really are in the secondary's local Administrators.

    Provenance: same basis-derived stamp as _node_mssql_database (Task 4/D3) -- a login
    on an SPN+SCCM-inferred site DB is exactly as templated/unconfirmed as the database
    it maps into. The parent-primary arm carries the identical stamp: like the same-site
    rule, it is a documented consequence of confirmed topology rather than a read ACL, so
    it belongs in the same confidence class, not a weaker one.
    """
    _login_provenance = _site_db_provenance_cols("s.basis = 'SPN+SCCM'", "s.collection_source")
    # Both arms emit the same row shape and differ only in HOW the sysadmin computer `c`
    # was found (same-site role vs parent-primary role), so the projection is shared --
    # otherwise the two would drift and produce inconsistent login ids for the same fact.
    netbios = "upper(split_part(c.dnshostname, '.', 2))"
    server_id = "upper(s.host_sid) || ':' || coalesce(s.port, '1433')"
    login_id = f"{netbios} || '\\' || c.sam_account_name || '@' || ({server_id})"
    cols = (
        f"  {login_id} AS login_id, "
        f"  {netbios} || '\\' || c.sam_account_name AS login_name, "
        f"  {server_id} AS server_id, "
        f"  upper(s.host_sid) AS host_sid, coalesce(s.port, '1433') AS port, "
        f"  s.dns_host_name AS sql_server, s.site_code AS sccm_site, "
        f"  c.sid AS sysadmin_computer_sid, "
        f"  {_login_provenance} "
    )
    # A computer is never a sysadmin on the instance it hosts: for a co-located secondary
    # database that principal authenticates locally as NT AUTHORITY\SYSTEM, which is not a
    # domain principal and cannot be relayed back to its own host.
    not_the_sql_host = "c.sid != upper(s.host_sid)"
    named = "c.sam_account_name IS NOT NULL AND c.dnshostname LIKE '%.%'"

    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_login AS "
        f"SELECT DISTINCT {cols}"
        f"FROM {schema}._mssql_sql_servers s "
        f"JOIN {schema}.node_computer c "
        f"  ON {not_the_sql_host} "
        f"  AND {named} "
        f"  AND len(list_filter(c.site_system_roles, x -> "
        f"        upper(x) = 'SMS SITE SERVER@' || s.site_code "
        f"        OR upper(x) = 'SMS PROVIDER@' || s.site_code)) > 0 "
        f"WHERE s.host_sid IS NOT NULL"
    )

    # Arm 2 -- the parent primary's site servers, on a confirmed secondary's database.
    # A separate _safe INSERT rather than a UNION on the statement above: this arm is the
    # only one that reads site_hierarchy, and folding it in would make a missing
    # site_hierarchy fail the WHOLE statement and drop the same-site logins too.
    _safe(con, "node_mssql_login<-secondary_parent_primary",
          f"INSERT INTO {schema}.node_mssql_login BY NAME "
          f"SELECT DISTINCT {cols}"
          f"FROM {schema}._mssql_sql_servers s "
          f"JOIN {schema}.site_hierarchy sh "
          f"  ON upper(sh.site_code) = upper(s.site_code) "
          # Positively Secondary. NOT `!= 2,4`: an unknown type must exclude, not include.
          f"  AND sh.site_type = 1 "
          # Sentinel parents ('None'/'Undetermined'/'') are already normalized to NULL by
          # _norm_site_code upstream, so a plain NOT NULL is the whole check.
          f"  AND sh.parent_site_code IS NOT NULL "
          f"JOIN {schema}.node_computer c "
          f"  ON {not_the_sql_host} "
          f"  AND {named} "
          f"  AND len(list_filter(c.site_system_roles, x -> "
          f"        upper(x) = 'SMS SITE SERVER@' || upper(sh.parent_site_code))) > 0 "
          f"WHERE s.host_sid IS NOT NULL "
          # A host could in principle hold a role at both the secondary and its parent;
          # without this it would be inserted twice for the same login.
          f"  AND NOT EXISTS (SELECT 1 FROM {schema}.node_mssql_login e "
          f"                  WHERE e.login_id = {login_id})")

    n = _scalar(con, f"SELECT count(*) FROM {schema}.node_mssql_login")
    logger.info("node_mssql_login built (%d login(s)) in schema %r", n, schema)


def _node_mssql_database_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One MSSQL_DatabaseUser per (login, database on the same server) (CMBP :6247).

    The sysadmin computer's login is mapped into the site database as a db user with the
    same DOMAIN\\sam name. id = <login_name>@<database_id>. `database` is the db name; `login`
    is the source login name (CMBP sets both).

    Provenance: carried forward from the login (Task 4/D3) -- l and d share the same
    server, so they always agree on whether it rests on the SPN+SCCM inference.
    """
    _dbuser_provenance = _site_db_provenance_cols("l.assumed", "l.collection_source")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_database_user AS "
        f"SELECT DISTINCT "
        f"  l.login_name || '@' || d.database_id AS dbuser_id, "
        f"  l.login_name AS dbuser_name, l.login_id, l.login_name, "
        f"  d.database_id, d.name AS database, l.server_id, l.host_sid, l.port, "
        f"  l.sql_server, l.sccm_site, "
        f"  {_dbuser_provenance} "
        f"FROM {schema}.node_mssql_login l "
        f"JOIN {schema}.node_mssql_database d ON d.server_id = l.server_id"
    )
    n = _scalar(con, f"SELECT count(*) FROM {schema}.node_mssql_database_user")
    logger.info("node_mssql_database_user built (%d user(s)) in schema %r", n, schema)


def _node_mssql_server_role(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """The fixed `sysadmin` server role, one per SCCM-linked MSSQL_Server (CMBP :6101).

    members is populated from the logins on the server (fix for CMBP's empty-array scope
    bug at :6105, grilled 2026-06-29). Only SCCM-linked servers get the role — non-SCCM
    scan-only servers are bare (CMBP builds the role inside the per-site server function).

    Provenance: carried forward from the server (Task 4/D3) -- s.sccm_infra is only ever
    true via arm 1, which is the only arm that ever stamps assumed, so s.assumed is
    always boolean (never NULL) in this filtered set.
    """
    _role_provenance = _site_db_provenance_cols("s.assumed", "s.collection_source")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_server_role AS "
        f"SELECT 'sysadmin@' || s.server_id AS role_id, s.server_id, s.host_sid, "
        f"  'sysadmin' AS name, "
        f"  coalesce((SELECT list_distinct(list(l.login_id)) FROM {schema}.node_mssql_login l "
        f"            WHERE l.server_id = s.server_id), CAST([] AS VARCHAR[])) AS members, "
        f"  s.sccm_site, s.dns_host_name AS sql_server, "
        f"  {_role_provenance} "
        f"FROM {schema}.node_mssql_server s WHERE s.sccm_infra"
    )
    n = _scalar(con, f"SELECT count(*) FROM {schema}.node_mssql_server_role")
    logger.info("node_mssql_server_role built (%d sysadmin role(s)) in schema %r", n, schema)


def _node_mssql_database_role(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """The fixed `db_owner` database role, one per MSSQL_Database (CMBP :6151).

    members populated from the database users in the database (fix for CMBP's empty-array
    scope bug at :6155, grilled 2026-06-29).

    Provenance: carried forward from the database (Task 4/D3).
    """
    _dbrole_provenance = _site_db_provenance_cols("d.assumed", "d.collection_source")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_mssql_database_role AS "
        f"SELECT 'db_owner@' || d.database_id AS role_id, d.database_id, d.server_id, d.host_sid, "
        f"  'db_owner' AS name, d.name AS database, "
        f"  coalesce((SELECT list_distinct(list(u.dbuser_id)) FROM {schema}.node_mssql_database_user u "
        f"            WHERE u.database_id = d.database_id), CAST([] AS VARCHAR[])) AS members, "
        f"  d.sccm_site, d.sql_server, "
        f"  {_dbrole_provenance} "
        f"FROM {schema}.node_mssql_database d"
    )
    n = _scalar(con, f"SELECT count(*) FROM {schema}.node_mssql_database_role")
    logger.info("node_mssql_database_role built (%d db_owner role(s)) in schema %r", n, schema)


def _graph_edges_init(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Create the empty graph_edges table that every edge builder INSERTs into.
    Always runs (even with no site/edge data) so convert can read the table.

    The coercion_* columns are populated only by the Stage 6 relay builders; sccm_infra
    is populated only by _edge_is_mapped_to (CMBP parity, SCCM_IsMappedTo only); every
    other builder INSERTs BY NAME and leaves them NULL (dedup coalesces coercion_*
    NULL -> [] and leaves sccm_infra NULL when no duplicate row set it true).

    assumed/assumption_basis (Task 3/4/5, D3) are populated only by the MSSQL
    site-DB-scaffolding edges (Task 4, basis-derived) and the Tier-B SCCM
    permission/coerce/local-admin edges (Task 5, unconditionally true) -- every
    other builder leaves them NULL, meaning "not an assumption"."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges "
        f"(start_id VARCHAR, end_id VARCHAR, kind VARCHAR, collection_source VARCHAR[], "
        f"coercion_victim_and_relay_target_pairs VARCHAR[], coercion_victim_hostnames VARCHAR[], "
        f"sccm_infra BOOLEAN, assumed BOOLEAN, assumption_basis VARCHAR)"
    )


def _edge_replication(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append SCCM_AdminsReplicatedTo edges from the site_hierarchy self-join
    (CMBP ps1:1604-1624): CAS(4)<->Primary(2) bidirectional; Primary(2)->Secondary(1)
    one-way. _safe() skips+logs if site_hierarchy is missing."""
    from .kinds.edges import SCCM_ADMINS_REPLICATED_TO
    _safe(
        con, "edge_replication",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"SELECT child.site_code AS start_id, parent.site_code AS end_id, "
        f"'{SCCM_ADMINS_REPLICATED_TO}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 2 AND parent.site_type = 4 "
        f"UNION ALL "
        f"SELECT parent.site_code, child.site_code, '{SCCM_ADMINS_REPLICATED_TO}', ['SCCM_Invoke-PostProcessing'] "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 2 AND parent.site_type = 4 "
        f"UNION ALL "
        f"SELECT parent.site_code, child.site_code, '{SCCM_ADMINS_REPLICATED_TO}', ['SCCM_Invoke-PostProcessing'] "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 1 AND parent.site_type = 2"
    )


def _edge_has_member(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append SCCM_HasMember edges: Collection -> member (CMBP ps1:7613-7647).

    Mirrors CMBP's member->node resolution (ps1:7617-7619): a member resolves to an
    SCCM_ClientDevice (device_by_resourceid -> smsid), a User, or a Group
    (principal_by_resourceid -> SID) -- never to a plain Computer node. coalesce prefers
    the device lookup so a member that is a real client points at its ClientDevice.

    A member that matches none of those -- e.g. a computer SCCM only discovered but that
    never installed the client -- gets NO edge (CMBP logs "No node found for member",
    ps1:7646); the diagnostic below counts these so operators notice them. Built-in
    pseudo-resources (x86/x64 Unknown Computer, Provisioning Device) are skipped.

    Collection start id is upper(collection_id)@root (matches the SCCMCollection
    node id built in _node_collection). Because _safe() does not accept SQL params,
    the root literal is inlined into the SQL string — site codes are 3 alphanumerics
    so this is safe.
    """
    from .kinds.edges import SCCM_HAS_MEMBER
    root_lit = _root_code(con, schema) or ""
    start_expr = (f"upper(cm.collection_id) || '@{root_lit}'" if root_lit
                  else "upper(cm.collection_id)")
    # A member's resource key ('<resource_id>@<site>') joins both lookups; built-ins are
    # never real members. Defined once and reused by the insert and the diagnostic below.
    key_expr = "CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR)"
    not_builtin = ("CAST(cm.resource_id AS VARCHAR) NOT IN ('2046820352', '2046820353') "
                   "AND CAST(cm.resource_id AS VARCHAR) NOT LIKE '203004%'")
    _src_tags = {
        "adminservice_collection_members": "AdminService-SMS_FullCollectionMembership",
        "wmi_collection_members": "WMI-SMS_FullCollectionMembership",
    }
    for _src in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _src, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        _tag = _src_tags[_src]
        _safe(con, f"edge_has_member<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, coalesce(d.smsid, p.sid) AS end_id, "
              f"'{SCCM_HAS_MEMBER}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} cm "
              f"LEFT JOIN {schema}.device_by_resourceid d ON d.resource_key = {key_expr} "
              f"LEFT JOIN {schema}.principal_by_resourceid p ON p.resource_key = {key_expr} "
              f"WHERE cm.collection_id IS NOT NULL "
              f"  AND coalesce(d.smsid, p.sid) IS NOT NULL "
              f"  AND {not_builtin}")
        # Diagnostic: members matching neither a client device nor a user/group principal
        # (and not a built-in) get no edge -- CMBP logs "No node found for member"
        # (ps1:7646). Count distinct (collection, resource) so duplicate membership rows
        # don't inflate the number. Most such members are discovery-only, non-client
        # computers (only in SMS_R_System), which correctly have no ClientDevice node --
        # so this is INFO, not a warning: it fires in every normal environment.
        if con.execute("SELECT 1 FROM information_schema.tables WHERE table_name = ?",
                       [_src]).fetchone() is None:
            continue  # this transport wasn't collected; _safe already skipped the insert
        try:
            unresolved = _scalar(con,
                f"SELECT count(DISTINCT cm.collection_id || '|' || CAST(cm.resource_id AS VARCHAR)) "
                f"FROM {schema}.{_src} cm "
                f"LEFT JOIN {schema}.device_by_resourceid d ON d.resource_key = {key_expr} "
                f"LEFT JOIN {schema}.principal_by_resourceid p ON p.resource_key = {key_expr} "
                f"WHERE cm.collection_id IS NOT NULL AND coalesce(d.smsid, p.sid) IS NULL "
                f"  AND {not_builtin}"
            )
        except duckdb.Error as err:
            logger.warning("edge_has_member: unresolved-member audit failed for %s: %s", _src, err)
            unresolved = 0
        if unresolved:
            logger.info("edge_has_member: %d collection member(s) in %s matched no User, Group, or "
                        "SCCM_ClientDevice node and were skipped (e.g. discovery-only, non-client "
                        "computers; matches CMBP ps1:7646)", unresolved, _src)
        else:
            logger.debug("edge_has_member: every resolvable collection member in %s produced an edge", _src)


def _edge_is_mapped_to(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AD principal -> SCCM_AdminUser (CMBP ps1:7789-7807). start = upper(admin_sid)
    if present, else logon_name resolved via principal_by_name; end = upper(logon_name)@root.

    sccm_infra is set true on every row (CMBP parity: SCCM_IsMappedTo is the only edge
    kind CMBP flags SCCMInfra=true on) so the AD principal's entity panel calls out that
    it's SCCM admin infrastructure."""
    from .kinds.edges import SCCM_IS_MAPPED_TO
    root_lit = _root_code(con, schema) or ""
    end_expr = (f"upper(a.logon_name) || '@{root_lit}'" if root_lit else "upper(a.logon_name)")
    _src_tags = {
        "adminservice_admins": "AdminService-SMS_Admin",
        "wmi_admins": "WMI-SMS_Admin",
    }
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"admin_sid": "VARCHAR", "logon_name": "VARCHAR"})
        _tag = _src_tags[_src]
        _safe(con, f"edge_is_mapped_to<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT coalesce(upper(a.admin_sid), pbn.sid) AS start_id, {end_expr} AS end_id, "
              f"'{SCCM_IS_MAPPED_TO}' AS kind, ['{_tag}'] AS collection_source, true AS sccm_infra "
              f"FROM {schema}.{_src} a "
              f"LEFT JOIN {schema}.principal_by_name pbn ON upper(trim(a.logon_name)) = upper(pbn.name) "
              f"WHERE a.logon_name IS NOT NULL AND coalesce(upper(a.admin_sid), pbn.sid) IS NOT NULL")


def _edge_is_assigned(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AdminUser -> Collection / SecurityRole (CMBP ps1:7819/7841/7867).

    Three arms per admin source:
      1. Collection by name: split collection_names (comma-separated), join collection_by_name.
      2. Role by id list: unnest the roles JSON/CSV array via _arr(), one edge per role id.
      3. Role by name fallback: ONLY when roles is empty — split role_names, join role_by_name.

    start/end ids are upper(...)@root to match the AdminUser / Collection / SecurityRole node ids.
    """
    from .kinds.edges import SCCM_IS_ASSIGNED
    root_lit = _root_code(con, schema) or ""

    def _id(col: str) -> str:
        # Build <upper(col)>@root inline (no SQL params — _safe takes none).
        return f"upper({col}) || '@{root_lit}'" if root_lit else f"upper({col})"

    start_expr = _id("a.logon_name")
    _src_tags = {
        "adminservice_admins": "AdminService-SMS_Admin",
        "wmi_admins": "WMI-SMS_Admin",
    }
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src,
                        {"logon_name": "VARCHAR", "collection_names": "VARCHAR",
                         "role_names": "VARCHAR", "roles": "VARCHAR"})
        _tag = _src_tags[_src]

        # --- Arm 1: AdminUser -> Collection (by name) ---
        # collection_names arrives as JSON-array text (e.g. '["All Systems","All Users"]')
        # from the AdminService collector, so route it through _arr() to parse the JSON
        # before unnesting. string_split would shred the brackets/quotes into garbage.
        _safe(con, f"edge_is_assigned_collection<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('cbn.collection_id')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} a, unnest({_arr('a.collection_names')}) AS t(cname) "
              f"JOIN {schema}.collection_by_name cbn ON upper(trim(t.cname)) = cbn.name "
              f"WHERE a.logon_name IS NOT NULL AND a.collection_names IS NOT NULL AND trim(t.cname) != ''")

        # --- Arm 2: AdminUser -> SecurityRole (role-id list) ---
        _safe(con, f"edge_is_assigned_role_id<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('t.rid')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND t.rid IS NOT NULL AND trim(t.rid) != ''")

        # --- Arm 3: AdminUser -> SecurityRole (name fallback, only when roles list is empty) ---
        # role_names arrives as JSON-array text for the same reason as collection_names.
        _safe(con, f"edge_is_assigned_role_name<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('rbn.role_id')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} a, unnest({_arr('a.role_names')}) AS t(rname) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rname)) = rbn.name "
              f"WHERE a.logon_name IS NOT NULL AND a.role_names IS NOT NULL AND trim(t.rname) != '' "
              f"  AND len({_arr('a.roles')}) = 0")


def _edge_has_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append ClientDevice -> User edges for the three device user fields (CMBP ps1:7266/7275/7298).

    Each name-only field on node_client_device is resolved to a SID via a
    case-insensitive join on principal_by_name. Devices whose field is NULL or
    empty, or whose value does not resolve to a SID, are silently dropped (the
    JOIN filters them out), matching CMBP behaviour.
    """
    from .kinds.edges import (
        SCCM_HAS_PRIMARY_USER, SCCM_HAS_CURRENT_USER, SCCM_HAS_AD_LAST_LOGON_USER,
    )
    for col, kind in (
        ("primary_user_name", SCCM_HAS_PRIMARY_USER),
        ("current_logon_user_name", SCCM_HAS_CURRENT_USER),
        ("ad_last_logon_user_name", SCCM_HAS_AD_LAST_LOGON_USER),
    ):
        _safe(con, f"edge_has_user<-{kind}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT cd.smsid AS start_id, pbn.sid AS end_id, '{kind}' AS kind, "
              f"['AdminService-ClientDevices'] AS collection_source "
              f"FROM {schema}.node_client_device cd "
              f"JOIN {schema}.principal_by_name pbn ON upper(trim(cd.{col})) = upper(pbn.name) "
              f"WHERE cd.smsid IS NOT NULL AND cd.{col} IS NOT NULL AND trim(cd.{col}) != ''")


def _edge_member_of(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer/User -> Group (CMBP ps1:7375/7470). Reuses the security_group_name
    unnest+resolve from _node_group; principal->group only (group->group nesting comes
    from a merged SharpHound collection, per the 2026-06-23 decision)."""
    from .kinds.edges import MEMBER_OF
    # (source_table, apply_obsolete_filter, collection_source_tag)
    _src_tags = {
        "adminservice_r_system": "AdminService-SMS_R_System",
        "wmi_r_system": "WMI-SMS_R_System",
        "adminservice_r_user": "AdminService-SMS_R_User",
        "wmi_r_user": "WMI-SMS_R_User",
    }
    sources = (
        ("adminservice_r_system", True),
        ("wmi_r_system", True),
        ("adminservice_r_user", False),
        ("wmi_r_user", False),
    )
    for _src, drop_obsolete in sources:
        _ensure_columns(con, schema, _src, {"sid": "VARCHAR", "security_group_name": "VARCHAR", "obsolete": "BOOLEAN"})
        # Only r_system rows need the obsolete filter; r_user has no such column.
        obsolete_clause = " AND NOT coalesce(r.obsolete, false)" if drop_obsolete else ""
        _tag = _src_tags[_src]
        _safe(con, f"edge_member_of<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT upper(r.sid) AS start_id, pbn.sid AS end_id, '{MEMBER_OF}' AS kind, "
              f"['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} r, unnest({_arr('r.security_group_name')}) AS t(gname) "
              f"JOIN {schema}.principal_by_name pbn ON upper(trim(t.gname)) = upper(pbn.name) "
              f"WHERE r.sid IS NOT NULL AND t.gname IS NOT NULL AND trim(t.gname) != ''{obsolete_clause}")


def _edge_member_of_smc(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MemberOf edges for the full nested membership chain of each System
    Management DACL Full-Control group (Task 12, Tier A+).

    Wires up ldap_smc_group_members, which collectors/ldap.py::_expand_group_targets
    populates during the recursive walk it already performs (for scan-target
    registration) — one row per (member, its immediate containing group) at every
    nesting level, so the full chain is already present without extra recursion here.
    Standard BloodHound BASE kind; BloodHound de-dupes identical edges a merged
    SharpHound collection also supplies.

    Confirmed (the AD `member` attribute, read directly) -- both flag modes, no
    disable_possible_edges parameter and no assumed/assumption_basis stamp.
    """
    from .kinds.edges import MEMBER_OF
    _safe(con, "edge_member_of_smc",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT DISTINCT upper(member_sid) AS start_id, upper(group_sid) AS end_id, "
          f"  '{MEMBER_OF}' AS kind, "
          f"  ['LDAP-GenericAllSystemManagement'] AS collection_source "
          f"FROM {schema}.ldap_smc_group_members "
          f"WHERE member_sid IS NOT NULL AND group_sid IS NOT NULL")


def _edge_has_session(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer -> User sessions (CMBP ps1:5029 + ps1:8007). Three sources:
    (1) RemoteRegistry logged-on user; (2) the PRIVILEGED MSSQL service account on
    the site DB server (SMS_SCI_SysResUse, domain accounts only); (3) the LOW-PRIV
    MSSQLSvc SPN holder (Task 13, Tier A+). HasSession is traversable (allow-list).

    All three are confirmed evidence (an observed logon, or an observed service
    identity) -- this function deliberately takes no disable_possible_edges
    parameter and is called unconditionally; that must never change."""
    from .kinds.edges import HAS_SESSION

    # (1) RemoteRegistry: host_object_sid -> the logged-on user's object_sid.
    _safe(con, "edge_has_session<-remoteregistry_users",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(host_object_sid) AS start_id, upper(object_sid) AS end_id, "
          f"'{HAS_SESSION}' AS kind, ['RemoteRegistry-CurrentUser'] AS collection_source "
          f"FROM {schema}.remoteregistry_users "
          f"WHERE host_object_sid IS NOT NULL AND object_sid IS NOT NULL")

    # (2) MSSQL service account: SQL host computer -> service-account user.
    # network_os_path is like '\\SQL01.lab' -> strip leading backslashes, take the host
    # label before the first dot, lowercase; match node_computer by dnshostname or name.
    host_expr = "lower(split_part(ltrim(ss.network_os_path, '\\'), '.', 1))"
    _src_tags = {
        "adminservice_site_systems": "AdminService-SMS_SCI_SysResUse",
        "wmi_site_systems": "WMI-SMS_SCI_SysResUse",
    }
    for _src in ("adminservice_site_systems", "wmi_site_systems"):
        _ensure_columns(con, schema, _src, {"network_os_path": "VARCHAR", "sql_server_service_logon_account": "VARCHAR"})
        _tag = _src_tags[_src]
        # Skip local accounts: anything without a backslash (no DOMAIN\ prefix),
        # plus the NT AUTHORITY\ virtual accounts that do contain a backslash.
        _safe(con, f"edge_has_session<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT nc.sid AS start_id, pbn.sid AS end_id, '{HAS_SESSION}' AS kind, "
              f"['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} ss "
              f"JOIN {schema}.node_computer nc "
              f"  ON lower(split_part(nc.dnshostname, '.', 1)) = {host_expr} "
              f"  OR lower(nc.name) = {host_expr} "
              f"JOIN {schema}.principal_by_name pbn "
              f"  ON upper(trim(ss.sql_server_service_logon_account)) = upper(pbn.name) "
              f"WHERE ss.network_os_path IS NOT NULL "
              f"  AND ss.sql_server_service_logon_account IS NOT NULL "
              f"  AND contains(ss.sql_server_service_logon_account, '\\') "
              f"  AND upper(ss.sql_server_service_logon_account) NOT LIKE 'NT AUTHORITY\\%' "
              f"  AND upper(ss.sql_server_service_logon_account) NOT IN ('LOCALSYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')")

    # (3) SPN holder (Task 13, Tier A+): host computer -> the SPN-resolved service
    # account, skipped when the account IS a computer object (no distinct session --
    # mirrors mssql/mssql edges/derive_ad.py:_service_account_edges' built-in/
    # machine-account skip). Reads node_mssql_server's service_account_sid/
    # service_account_is_computer columns (Task 13); arm (2) above reads a
    # differently-named column (service_account_domain_sid) from a different,
    # privileged source, so the two arms overlapping on the same real account
    # collapse into one edge via _graph_edges_dedup, not by a guard here.
    _safe(con, "edge_has_session<-node_mssql_server_spn",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(host_sid) AS start_id, upper(service_account_sid) AS end_id, "
          f"'{HAS_SESSION}' AS kind, ['LDAP-MSSQLSvcSPN'] AS collection_source "
          f"FROM {schema}.node_mssql_server "
          f"WHERE service_account_sid IS NOT NULL "
          f"  AND coalesce(service_account_is_computer, false) = false")


def _edge_has_stored_account(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site -> stored User/Group account (CMBP ps1:7147). start = site_code (the
    SCCM_Site node id); end = the reserved account's AD object_sid (resolved at
    collection). The User/Group node property stored_in_sccm_site is set in Stage 1."""
    from .kinds.edges import SCCM_HAS_STORED_ACCOUNT
    _src_tags = {
        "adminservice_reserved_accounts": "AdminService-SMS_SCI_Reserved",
        "wmi_reserved_accounts": "WMI-SMS_SCI_Reserved",
    }
    for _src in ("adminservice_reserved_accounts", "wmi_reserved_accounts"):
        _ensure_columns(con, schema, _src, {"site_code": "VARCHAR", "object_sid": "VARCHAR"})
        _tag = _src_tags[_src]
        _safe(con, f"edge_has_stored_account<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT site_code AS start_id, upper(object_sid) AS end_id, "
              f"'{SCCM_HAS_STORED_ACCOUNT}' AS kind, ['{_tag}'] AS collection_source "
              f"FROM {schema}.{_src} WHERE site_code IS NOT NULL AND object_sid IS NOT NULL")


# Well-known security-role id -> the client-device edge kind it grants (CMBP ps1:1751-1797).
_ROLE_EDGE_KIND = {
    "SMS0001R": "SCCM_FullAdministrator",
    "SMS0008R": "SCCM_ApplicationAuthor",
    "SMS0009R": "SCCM_ApplicationAdministrator",
    "SMS0006R": "SCCM_ComplianceSettingsManager",
    "SMS000AR": "SCCM_OSDManager",
    "SMS000ER": "SCCM_OperationsAdministrator",
    "SMS000FR": "SCCM_SecurityAdministrator",
}
# Built-in roles CMBP knows but creates no client-device edge for (CMBP ps1:1803-1818).
# Built-in roles CMBP knows but creates no client-device edge for (full built-in list
# at CMBP ps1:1803-1810). NOTE the deliberate divergence: CMBP's runtime -notin array
# (ps1:1811-1818) omits SMS0003R (Remote Tools Operator) — a CMBP oversight that makes it
# spuriously log a "custom role" warning for that built-in. We include SMS0003R here (all 8
# built-ins) so the custom-role skip warning fires only for genuinely custom roles.
_ROLE_KNOWN_NO_EDGE = ("SMS0002R", "SMS0003R", "SMS0004R", "SMS0007R", "SMS000BR", "SMS000CR", "SMS000GR", "SMS000HR")


def _edge_contains(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site -> Collection/SecurityRole/AdminUser (CMBP ps1:1659-1690). Every
    non-secondary site (site_type != 1) in the single hierarchy contains every
    global object (all are @root). collection_source = SCCM_Invoke-PostProcessing."""
    from .kinds.edges import SCCM_CONTAINS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE {_NON_SECONDARY_SITE_TYPE_SQL} AND site_code IS NOT NULL)")
    cs = "['SCCM_Invoke-PostProcessing']"
    # -- Every non-secondary site contains every collection, security role, and admin user
    # -- in the hierarchy (all @root).
    _safe(con, "edge_contains",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT site.site_code AS start_id, collection.collection_id || '@' || collection.root_site_code AS end_id, "
          f"'{SCCM_CONTAINS}' AS kind, {cs} AS collection_source "
          f"FROM {nonsec} site JOIN {schema}.node_collection collection ON collection.root_site_code IS NOT NULL "
          f"UNION ALL "
          f"SELECT site.site_code, role.role_id || '@' || role.root_site_code, '{SCCM_CONTAINS}', {cs} "
          f"FROM {nonsec} site JOIN {schema}.node_security_role role ON role.root_site_code IS NOT NULL "
          f"UNION ALL "
          f"SELECT site.site_code, upper(admin.logon_name) || '@' || admin.root_site_code, '{SCCM_CONTAINS}', {cs} "
          f"FROM {nonsec} site JOIN {schema}.node_admin_user admin ON admin.root_site_code IS NOT NULL")


def _edge_rbac_role_grants(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """The 7 RBAC role edges (AdminUser -> ClientDevice), reconstructed from graph_edges
    (CMBP ps1:1714-1827). Path: IsAssigned(admin->role) JOIN IsAssigned(admin->Device-collection)
    JOIN HasMember(collection->clientdevice). The role's well-known id picks the edge kind.
    Custom (non-built-in) roles assigned to admins are counted and logged (CMBP ps1:1820)."""
    role_map = ", ".join(f"('{rid}','{kind}')" for rid, kind in _ROLE_EDGE_KIND.items())
    # -- Walk graph_edges: an admin --IsAssigned--> a security role, and the SAME admin
    # -- --IsAssigned--> a Device-type collection, whose members --HasMember--> client devices.
    # -- The role's well-known id selects the edge kind.
    _safe(con, "edge_rbac_role_grants",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT admin_to_role.start_id AS start_id, collection_to_device.end_id AS end_id, role_edge_kind.edge_kind AS kind, "
          f"['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.graph_edges admin_to_role "
          f"JOIN {schema}.node_security_role role "
          f"  ON role.role_id || '@' || role.root_site_code = admin_to_role.end_id "
          f"JOIN (VALUES {role_map}) AS role_edge_kind(role_id, edge_kind) ON upper(role.role_id) = role_edge_kind.role_id "
          f"JOIN {schema}.graph_edges admin_to_collection "
          f"  ON admin_to_collection.start_id = admin_to_role.start_id AND admin_to_collection.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection device_collection "
          f"  ON device_collection.collection_id || '@' || device_collection.root_site_code = admin_to_collection.end_id AND device_collection.collection_type = 2 "
          f"JOIN {schema}.graph_edges collection_to_device "
          f"  ON collection_to_device.start_id = admin_to_collection.end_id AND collection_to_device.kind = 'SCCM_HasMember' "
          f"JOIN {schema}.node_client_device client_device ON client_device.smsid = collection_to_device.end_id "
          f"WHERE admin_to_role.kind = 'SCCM_IsAssigned'")
    # Diagnostic: count custom roles assigned to admins that produce no device edge (CMBP warns per role).
    skip_list = ", ".join(f"'{r}'" for r in (*_ROLE_EDGE_KIND, *_ROLE_KNOWN_NO_EDGE))
    try:
        cnt = _scalar(con,
            f"SELECT count(DISTINCT role.role_id) FROM {schema}.graph_edges admin_to_role "
            f"JOIN {schema}.node_security_role role ON role.role_id || '@' || role.root_site_code = admin_to_role.end_id "
            f"WHERE admin_to_role.kind = 'SCCM_IsAssigned' AND upper(role.role_id) NOT IN ({skip_list})"
        )
    except duckdb.Error as err:
        logger.warning("edge_rbac_role_grants: custom-role audit query failed: %s", err)
        cnt = 0
    if cnt:
        logger.warning("edge_rbac_role_grants: %d custom security role(s) assigned to admins have no "
                       "traversable client-device edge (matches CMBP skip behaviour)", cnt)
    else:
        logger.debug("edge_rbac_role_grants: no custom roles to skip")


def _edge_all_permissions(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AdminUser -> Site SCCM_AllPermissions (CMBP ps1:1730-1837): Full Administrator
    (SMS0001R) AND assigned BOTH SMS00001 (All Systems) and SMS00004 (All Users and User
    Groups) -> every non-secondary site. Detection by well-known collection id (Decision #2;
    CMBP matched display name 'All Systems'/'All Users and User Groups')."""
    from .kinds.edges import SCCM_ALL_PERMISSIONS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE {_NON_SECONDARY_SITE_TYPE_SQL} AND site_code IS NOT NULL)")
    # -- An admin --IsAssigned--> the Full Administrator role (SMS0001R) AND
    # -- --IsAssigned--> BOTH the All Systems (SMS00001) and All Users and User Groups
    # -- (SMS00004) collections -> grant SCCM_AllPermissions to every non-secondary site.
    _safe(con, "edge_all_permissions",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT admin_to_full_admin_role.start_id AS start_id, site.site_code AS end_id, "
          f"'{SCCM_ALL_PERMISSIONS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source "
          f"FROM {schema}.graph_edges admin_to_full_admin_role "
          f"JOIN {schema}.node_security_role full_admin_role "
          f"  ON full_admin_role.role_id || '@' || full_admin_role.root_site_code = admin_to_full_admin_role.end_id AND upper(full_admin_role.role_id) = 'SMS0001R' "
          f"JOIN {schema}.graph_edges admin_to_all_systems ON admin_to_all_systems.start_id = admin_to_full_admin_role.start_id AND admin_to_all_systems.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection all_systems_collection "
          f"  ON all_systems_collection.collection_id || '@' || all_systems_collection.root_site_code = admin_to_all_systems.end_id AND upper(all_systems_collection.collection_id) = 'SMS00001' "
          f"JOIN {schema}.graph_edges admin_to_all_users ON admin_to_all_users.start_id = admin_to_full_admin_role.start_id AND admin_to_all_users.kind = 'SCCM_IsAssigned' "
          f"JOIN {schema}.node_collection all_users_collection "
          f"  ON all_users_collection.collection_id || '@' || all_users_collection.root_site_code = admin_to_all_users.end_id AND upper(all_users_collection.collection_id) = 'SMS00004' "
          f"CROSS JOIN {nonsec} site "
          f"WHERE admin_to_full_admin_role.kind = 'SCCM_IsAssigned'")


def _edge_assign_all_permissions(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer(SMS Provider) -> Site SCCM_AssignAllPermissions (CMBP ps1:1932-1940).

    Any computer whose site_system_roles contains an 'SMS Provider' entry gets an
    SCCM_AssignAllPermissions edge to every non-secondary site in the single hierarchy.
    start = computer SID (the Computer node id); end = non-secondary site_code.

    Provenance (Task 5/D3, spec §7 ruling): this templates "SMS Provider role implies
    site control" from role topology rather than reading an actual RBAC grant, so it
    is unconditionally assumed -- the design spec's earlier claim that
    --disable-possible-edges removes it was wrong (the code never gated it and never
    should: CMBP itself emits this same family under its own -DisablePossibleEdges).
    The stamp is unconditional, not flag-gated.
    """
    from .kinds.edges import SCCM_ASSIGN_ALL_PERMISSIONS
    nonsec = (f"(SELECT site_code FROM {schema}.site_hierarchy "
              f"WHERE {_NON_SECONDARY_SITE_TYPE_SQL} AND site_code IS NOT NULL)")
    # -- Any computer whose site_system_roles include 'SMS Provider' ->
    # -- SCCM_AssignAllPermissions to every non-secondary site.
    _safe(con, "edge_assign_all_permissions",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT computer.sid AS start_id, site.site_code AS end_id, "
          f"'{SCCM_ASSIGN_ALL_PERMISSIONS}' AS kind, "
          f"  ['SCCM_Invoke-PostProcessing', '{ASSIGN_ALL_PERMISSIONS_SOURCE}'] AS collection_source, "
          f"  true AS assumed, '{ASSIGN_ALL_PERMISSIONS_BASIS}' AS assumption_basis "
          f"FROM {schema}.node_computer computer "
          f"CROSS JOIN {nonsec} site "
          f"WHERE computer.sid IS NOT NULL "
          f"  AND len(list_filter(computer.site_system_roles, x -> x LIKE '%SMS Provider%')) > 0")


def _edge_same_host(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer <-> SCCM_ClientDevice SCCM_SameHostAs, both directions (CMBP ps1:2314-2320).

    Join the Computer node id (sid) to the deduped client device's ad_domain_sid.
    Two rows per match. CMBP set no collectionSource; the port tags
    'SCCM_Invoke-PostProcessing' for entity-panel provenance.
    """
    from .kinds.edges import SCCM_SAME_HOST_AS
    _safe(con, "edge_same_host",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT computer.sid AS start_id, dev.smsid AS end_id, "
          f"'{SCCM_SAME_HOST_AS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source, "
          f"NOT coalesce(dev.is_confirmed_active_client, true) AS assumed, "
          f"CASE WHEN NOT coalesce(dev.is_confirmed_active_client, true) "
          f"     THEN '{POSSIBLE_CLIENT_BASIS}' END AS assumption_basis "
          f"FROM {schema}.node_computer computer "
          f"JOIN {schema}.node_client_device dev ON dev.ad_domain_sid = computer.sid "
          f"WHERE computer.sid IS NOT NULL AND dev.smsid IS NOT NULL "
          f"UNION ALL "
          f"SELECT dev.smsid AS start_id, computer.sid AS end_id, "
          f"'{SCCM_SAME_HOST_AS}' AS kind, ['SCCM_Invoke-PostProcessing'] AS collection_source, "
          f"NOT coalesce(dev.is_confirmed_active_client, true) AS assumed, "
          f"CASE WHEN NOT coalesce(dev.is_confirmed_active_client, true) "
          f"     THEN '{POSSIBLE_CLIENT_BASIS}' END AS assumption_basis "
          f"FROM {schema}.node_computer computer "
          f"JOIN {schema}.node_client_device dev ON dev.ad_domain_sid = computer.sid "
          f"WHERE computer.sid IS NOT NULL AND dev.smsid IS NOT NULL")


def _edge_local_admin_required(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site server -> every other site system in the same non-secondary site
    (CMBP ps1:1882-1909).

    CMBP's two branches (non-server site systems seen from the server, and the
    server iterating its peers) collapse to one set-based rule: start = computers
    hosting 'SMS Site Server@<site>'; end = computers hosting ANY role at that site;
    start != end. Site servers are thus mutually local-admin when a site has more
    than one. Sites are restricted to non-secondary (site_type != 1), matching
    CMBP's `Type -ne "Secondary Site"`.

    Site codes are extracted from the 'Role@SiteCode' strings the same way CMBP did
    (everything after the first '@'); both sides are uppercased for a robust join.

    Provenance (Task 5/D3, spec §7 ruling): this templates "co-location at a site
    implies mutual local admin" from role topology rather than reading an actual ACL,
    so it is unconditionally assumed, flag-independent (same ruling as
    _edge_assign_all_permissions above).
    """
    from .kinds.edges import SCCM_LOCAL_ADMIN_REQUIRED
    _safe(con, "edge_local_admin_required",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"WITH roles AS ("
          f"  SELECT c.sid, role, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
          f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
          f"  WHERE c.sid IS NOT NULL AND role IS NOT NULL AND role LIKE '%@%'"
          f"), "
          f"nonsec AS ("
          f"  SELECT upper(site_code) AS site FROM {schema}.site_hierarchy "
          f"  WHERE {_NON_SECONDARY_SITE_TYPE_SQL} AND site_code IS NOT NULL"
          f"), "
          f"site_servers AS ("
          f"  SELECT DISTINCT sid, site FROM roles WHERE role LIKE 'SMS Site Server@%' AND site != ''"
          f"), "
          f"site_systems AS ("
          f"  SELECT DISTINCT sid, site FROM roles WHERE site != ''"
          f") "
          f"SELECT ss.sid AS start_id, sys.sid AS end_id, "
          f"'{SCCM_LOCAL_ADMIN_REQUIRED}' AS kind, "
          f"  ['SCCM_Invoke-PostProcessing', '{LOCAL_ADMIN_REQUIRED_SOURCE}'] AS collection_source, "
          f"  true AS assumed, '{LOCAL_ADMIN_REQUIRED_BASIS}' AS assumption_basis "
          f"FROM site_servers ss "
          f"JOIN site_systems sys ON ss.site = sys.site AND ss.sid != sys.sid "
          f"JOIN nonsec n ON n.site = ss.site")

    # Arm 2 -- parent primary site server -> CHILD SECONDARY site server, across sites.
    #
    # The arm above is strictly intra-site and skips secondaries outright, so it can never
    # produce this edge on its own. Microsoft requires it directly: "Add the computer
    # account of the parent primary site to the Administrators group on the secondary site
    # server" (prerequisites-for-installing-sites#bkmk_secondary). It matters because that
    # membership is also how the parent reaches sysadmin on the secondary's SQL Express
    # instance, where BUILTIN\Administrators holds the role.
    #
    # In the mayyhem lab the edge already appeared WITHOUT this arm, but only incidentally:
    # ps1-sec happens to carry 'SMS Management Point@PS1', which pulls it into PS1's own
    # intra-site mesh. A secondary serving no role for its parent would have been missed
    # despite the requirement still applying.
    #
    # Gated on a POSITIVELY known secondary (site_type = 1), the mirror image of
    # _NON_SECONDARY_SITE_TYPE_SQL: an unknown type must not be treated as a secondary any
    # more than it may be treated as a primary. A secondary is often discoverable at low
    # privilege only as a bare site code, and AD publishes no mSSMSSite or
    # mSSMSManagementPoint object for one, so its type stays NULL there and this stays quiet.
    #
    # Matching the parent BY ROLE covers a parent running a site server in passive mode --
    # both nodes carry 'SMS Site Server@<parent>' and a SharpHound capture of mayyhem shows
    # both machine accounts genuinely in the secondary's local Administrators group.
    #
    # Duplicates against arm 1 (the mayyhem case above) need no guard here:
    # _graph_edges_dedup collapses identical (start_id, end_id, kind) triples once, after
    # every edge builder -- the same convention _edge_has_session and the MSSQL service
    # account arms rely on.
    _safe(con, "edge_local_admin_required<-parent_primary_to_secondary",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"WITH roles AS ("
          f"  SELECT c.sid, role, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
          f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
          f"  WHERE c.sid IS NOT NULL AND role IS NOT NULL AND role LIKE '%@%'"
          f"), "
          f"site_servers AS ("
          f"  SELECT DISTINCT sid, site FROM roles "
          f"  WHERE role LIKE 'SMS Site Server@%' AND site != ''"
          f"), "
          f"secondaries AS ("
          f"  SELECT upper(site_code) AS site, upper(parent_site_code) AS parent "
          f"  FROM {schema}.site_hierarchy "
          f"  WHERE site_type = 1 AND site_code IS NOT NULL AND parent_site_code IS NOT NULL"
          f") "
          f"SELECT parent_ss.sid AS start_id, child_ss.sid AS end_id, "
          f"'{SCCM_LOCAL_ADMIN_REQUIRED}' AS kind, "
          f"  ['SCCM_Invoke-PostProcessing', '{LOCAL_ADMIN_REQUIRED_SOURCE}'] AS collection_source, "
          f"  true AS assumed, '{SECONDARY_PARENT_LOCAL_ADMIN_BASIS}' AS assumption_basis "
          f"FROM secondaries sec "
          f"JOIN site_servers parent_ss ON parent_ss.site = sec.parent "
          f"JOIN site_servers child_ss ON child_ss.site = sec.site "
          # One-way: the parent gains rights over the child, never the reverse. The sid
          # check also drops the degenerate self-edge if one host somehow served both sites.
          f"WHERE parent_ss.sid != child_ss.sid")


def _edge_mssql_structural(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MSSQL server/database containment + control + host edges (CMBP :6111-6172).

    #1 Server -Contains-> sysadmin role; #2 sysadmin -ControlServer-> Server;
    #3 host Computer -HostFor-> Server; #4 Server -ExecuteOnHost-> host Computer;
    #5 Server -Contains-> Database; #6 Database -Contains-> db_owner role;
    #7 db_owner -ControlDB-> Database. The host Computer node id is the raw host SID.
    Resolve-or-drop: #3/#4 require the host to exist as a node_computer row (same
    convention as _edge_mssql_service_account's acct_exists guard) -- else the pair
    is skipped rather than left dangling against a SID with no node.

    Provenance (Task 4/D3): #1/#2/#5/#6/#7 carry the assumed/assumption_basis/
    collection_source columns straight through from the node they attach to
    (node_mssql_server_role/node_mssql_database/node_mssql_database_role already
    carry the basis-derived stamp) -- these edges are just that node's containment/
    control relationship, so they're exactly as assumed as the node itself. #3/#4
    (HostFor/ExecuteOnHost) are the one confirmed-and-ungated exception (D2(a)) and
    keep the plain literal `src` tag, unmarked.
    """
    from .kinds.edges import (MSSQL_CONTAINS, MSSQL_CONTROL_DB, MSSQL_CONTROL_SERVER,
                              MSSQL_EXECUTE_ON_HOST, MSSQL_HOST_FOR)
    src = "['SCCM_Add-MSSQLServerNodesAndEdges']"
    # #1 + #2 server <-> sysadmin role
    _safe(con, "edge_mssql_server_role",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT server_id AS start_id, role_id AS end_id, '{MSSQL_CONTAINS}' AS kind, "
          f"  collection_source, assumed, assumption_basis "
          f"FROM {schema}.node_mssql_server_role "
          f"UNION ALL "
          f"SELECT role_id, server_id, '{MSSQL_CONTROL_SERVER}', collection_source, assumed, assumption_basis "
          f"FROM {schema}.node_mssql_server_role")
    # #3 + #4 host computer <-> server. Resolve-or-drop (same convention as the
    # service-account guard in _edge_mssql_service_account below): the host must
    # exist as a node_computer row, else these two edges would dangle against a
    # SID with no node behind it.
    # nc.sid = upper(host_sid), not a bare equality: node_mssql_server's collapse
    # (upper(host_sid) || ':' || port) uppercases server_id but leaves the plain
    # host_sid column as whatever case its feeder arm produced. Every current
    # feeder happens to already upper() it, so this works today by accident; a
    # future arm that didn't would otherwise silently fail this EXISTS check and
    # drop both host edges with only a DEBUG line (reviewer M3) -- matching the
    # explicit upper() every other join against node_computer.sid uses.
    # BREAK-1: the guard and the emitted endpoint must agree on casing. The guard
    # matches nc.sid = upper(host_sid); emitting the RAW host_sid as the edge
    # endpoint (as an earlier revision did) means a differently-cased feeder could
    # pass the guard yet still emit an edge whose endpoint resolves to no
    # node_computer row -- inverting resolve-or-drop in exactly the case it exists
    # to prevent (a dangling edge is worse than a dropped one). Emit upper(host_sid)
    # on both halves, matching how server_id is already minted.
    _host_exists = f"EXISTS (SELECT 1 FROM {schema}.node_computer nc WHERE nc.sid = upper(host_sid))"
    _safe(con, "edge_mssql_host",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(host_sid) AS start_id, server_id AS end_id, '{MSSQL_HOST_FOR}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_server WHERE host_sid IS NOT NULL AND {_host_exists} "
          f"UNION ALL "
          f"SELECT server_id, upper(host_sid), '{MSSQL_EXECUTE_ON_HOST}', {src} "
          f"FROM {schema}.node_mssql_server WHERE host_sid IS NOT NULL AND {_host_exists}")
    try:
        _dropped = con.execute(
            f"SELECT DISTINCT host_sid FROM {schema}.node_mssql_server "
            f"WHERE host_sid IS NOT NULL AND NOT {_host_exists}"
        ).fetchall()
    except duckdb.CatalogException:
        _dropped = []  # node_mssql_server / node_computer absent -- nothing to report
    for (_hsid,) in _dropped:
        logger.debug(
            "edge_mssql_host: host_sid %r has no node_computer row; "
            "MSSQL_HostFor/MSSQL_ExecuteOnHost skipped (resolve-or-drop)", _hsid,
        )
    # #5 server -> database
    _safe(con, "edge_mssql_server_db",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT server_id AS start_id, database_id AS end_id, '{MSSQL_CONTAINS}' AS kind, "
          f"  collection_source, assumed, assumption_basis "
          f"FROM {schema}.node_mssql_database")
    # #6 + #7 database <-> db_owner role
    _safe(con, "edge_mssql_db_role",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT database_id AS start_id, role_id AS end_id, '{MSSQL_CONTAINS}' AS kind, "
          f"  collection_source, assumed, assumption_basis "
          f"FROM {schema}.node_mssql_database_role "
          f"UNION ALL "
          f"SELECT role_id, database_id, '{MSSQL_CONTROL_DB}', collection_source, assumed, assumption_basis "
          f"FROM {schema}.node_mssql_database_role")


def _edge_mssql_membership(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Login/DatabaseUser membership + containment + host-login edges (CMBP :6262-6286).

    #9  Login -MemberOf-> sysadmin role; #10 Server -Contains-> Login;
    #11 sysadmin Computer -HasLogin-> Login; #12 Login -IsMappedTo-> DatabaseUser;
    #13 DatabaseUser -MemberOf-> db_owner role; #14 Database -Contains-> DatabaseUser.

    Provenance (Task 4/D3): every edge here carries the assumed/assumption_basis/
    collection_source columns straight through from the login/database-user row it
    attaches to -- each is just that node's membership/containment relationship, so
    it's exactly as assumed as the node itself.
    """
    from .kinds.edges import MSSQL_CONTAINS, MSSQL_HAS_LOGIN, MSSQL_IS_MAPPED_TO, MSSQL_MEMBER_OF
    # #9 + #10 + #11 from logins
    _safe(con, "edge_mssql_login",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT login_id AS start_id, 'sysadmin@' || server_id AS end_id, '{MSSQL_MEMBER_OF}' AS kind, "
          f"  collection_source, assumed, assumption_basis "
          f"FROM {schema}.node_mssql_login "
          f"UNION ALL SELECT server_id, login_id, '{MSSQL_CONTAINS}', collection_source, assumed, assumption_basis "
          f"  FROM {schema}.node_mssql_login "
          f"UNION ALL SELECT sysadmin_computer_sid, login_id, '{MSSQL_HAS_LOGIN}', collection_source, assumed, assumption_basis "
          f"  FROM {schema}.node_mssql_login WHERE sysadmin_computer_sid IS NOT NULL")
    # #12 + #13 + #14 from database users
    _safe(con, "edge_mssql_dbuser",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT login_id AS start_id, dbuser_id AS end_id, '{MSSQL_IS_MAPPED_TO}' AS kind, "
          f"  collection_source, assumed, assumption_basis "
          f"FROM {schema}.node_mssql_database_user "
          f"UNION ALL SELECT dbuser_id, 'db_owner@' || database_id, '{MSSQL_MEMBER_OF}', collection_source, assumed, assumption_basis "
          f"  FROM {schema}.node_mssql_database_user "
          f"UNION ALL SELECT database_id, dbuser_id, '{MSSQL_CONTAINS}', collection_source, assumed, assumption_basis "
          f"  FROM {schema}.node_mssql_database_user")


def _edge_mssql_service_account(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """SQL service-account edges (CMBP post-proc :1975 + :8013-8016).

    #15a MSSQL_GetTGS: service acct -> EACH login on the server (no acct!=host gate).
    #15b MSSQL_ServiceAccountFor + #15c MSSQL_GetAdminTGS: service acct -> server, only
         when the service account differs from the SQL host computer (CMBP :8012). Uses the
         COLLECTED port (server_id), not CMBP's hardcoded :1433 (fold-in fix, grilled).
    Resolve-or-drop: the service account SID must exist as a node_computer / node_user row
    (decision #7); else the row is skipped (the WHERE EXISTS guard) and nothing is emitted.
    """
    from .kinds.edges import MSSQL_GET_ADMIN_TGS, MSSQL_GET_TGS, MSSQL_SERVICE_ACCOUNT_FOR
    src = "['AdminService-SMS_SCI_SysResUse']"
    acct_exists = (
        f"EXISTS (SELECT 1 FROM {schema}.node_computer c WHERE c.sid = s.service_account_domain_sid) "
        f"OR EXISTS (SELECT 1 FROM {schema}.node_user u WHERE u.sid = s.service_account_domain_sid)"
    )
    # #15a GetTGS: service acct -> each login on the server.
    _safe(con, "edge_mssql_gettgs",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT s.service_account_domain_sid AS start_id, l.login_id AS end_id, "
          f"  '{MSSQL_GET_TGS}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_server s "
          f"JOIN {schema}.node_mssql_login l ON l.server_id = s.server_id "
          f"WHERE s.service_account_domain_sid IS NOT NULL AND ({acct_exists})")
    # #15b + #15c: service acct -> server, only when acct != host (CMBP :8012 gate).
    _safe(con, "edge_mssql_svcacct_server",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT s.service_account_domain_sid AS start_id, s.server_id AS end_id, "
          f"  '{MSSQL_SERVICE_ACCOUNT_FOR}' AS kind, {src} AS collection_source "
          f"FROM {schema}.node_mssql_server s "
          f"WHERE s.service_account_domain_sid IS NOT NULL "
          f"  AND s.service_account_domain_sid != s.host_sid AND ({acct_exists}) "
          f"UNION ALL "
          f"SELECT s.service_account_domain_sid, s.server_id, '{MSSQL_GET_ADMIN_TGS}', {src} "
          f"FROM {schema}.node_mssql_server s "
          f"WHERE s.service_account_domain_sid IS NOT NULL "
          f"  AND s.service_account_domain_sid != s.host_sid AND ({acct_exists})")


def _edge_mssql_service_account_spn(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MSSQL_ServiceAccountFor from the MSSQLSvc SPN holder (Task 13, Tier A+):
    confirmed, low-priv -- LDAP-readable proof of who a SQL service actually runs as.

    Distinct from the PRIVILEGED arm above (_edge_mssql_service_account, reading
    node_mssql_server.service_account_domain_sid, sourced from AdminService/WMI's
    SMS_SCI_SysResUse): this reads the service_account_sid column Task 13 added,
    populated from collectors/mssql.py's LDAP SPN-holder search (clients/ad.py
    find_mssql_spn_holder). When both sources resolve the same real account on the
    same server, they emit the identical (start_id, end_id, kind) triple --
    _graph_edges_dedup (run once, after every edge builder) collapses that into one
    edge, so no NOT EXISTS guard against the privileged arm is needed here.

    Unlike the privileged arm, no resolve-or-drop existence guard: this identity is
    already a live AD lookup result (a real objectSid returned by an LDAP search),
    not an account NAME pending resolution, so there is nothing that can fail to
    resolve. HasSession's end_id is in BACKFILL_END_KIND ("User"), so the common
    case -- a service account not otherwise known to any SCCM source -- still gets a
    node via the stub-backfill mechanism, covering this edge's start_id too (same id).

    Not traversable (CMBP comments this kind out of its allow-list, ps1:2233) --
    matches the privileged arm's TRAVERSABLE_EDGE_KINDS omission.
    """
    from .kinds.edges import MSSQL_SERVICE_ACCOUNT_FOR
    _safe(con, "edge_mssql_service_account_for_spn",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(service_account_sid) AS start_id, server_id AS end_id, "
          f"  '{MSSQL_SERVICE_ACCOUNT_FOR}' AS kind, "
          f"  ['LDAP-MSSQLSvcSPN'] AS collection_source "
          f"FROM {schema}.node_mssql_server WHERE service_account_sid IS NOT NULL")


def _edge_mssql_kerberoast_spn(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MSSQL_GetAdminTGS + MSSQL_GetTGS from the SPN-resolved service account
    (Task 13) to Task 4's site-server/provider sysadmin logins (node_mssql_login).

    Every node_mssql_login row is, by construction, a domain sysadmin login (it is
    built from the Site Server/SMS Provider machine account, which SCCM's own
    default schema grants sysadmin -- see _node_mssql_login), so "at least one
    login exists for this server" already means "a domain principal is sysadmin",
    and every login qualifies as a GetTGS target. Mirrors mssql/mssql
    edges/derive_ad.py:_service_account_edges' GetAdminTGS/GetTGS (lines 460-476),
    simplified for that always-sysadmin invariant.

    These edges inherit the confidence of the login they rest on (plan amendment,
    Task 14) -- assumed/assumption_basis/collection_source are copied straight from
    node_mssql_login (the same columns _site_db_provenance_cols already stamps
    there for Task 4), not recomputed here. A login built off a RemoteRegistry/
    privileged-confirmed site DB is confirmed and unstamped; one off an SPN+SCCM
    site DB is assumed and stamped. --disable-possible-edges already removed the
    SPN+SCCM logins upstream (Task 2's _assumed_site_dbs), so under the flag those
    rows simply don't exist here for the join to find -- no separate gate is needed
    in this builder, and it takes no disable_possible_edges parameter.
    """
    from .kinds.edges import MSSQL_GET_ADMIN_TGS, MSSQL_GET_TGS
    _safe(con, "edge_mssql_get_admin_tgs_spn",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT DISTINCT upper(i.service_account_sid) AS start_id, i.server_id AS end_id, "
          f"  '{MSSQL_GET_ADMIN_TGS}' AS kind, "
          f"  l.collection_source, l.assumed, l.assumption_basis "
          f"FROM {schema}.node_mssql_server i "
          f"JOIN {schema}.node_mssql_login l ON l.server_id = i.server_id "
          f"WHERE i.service_account_sid IS NOT NULL")
    _safe(con, "edge_mssql_get_tgs_spn",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(i.service_account_sid) AS start_id, l.login_id AS end_id, "
          f"  '{MSSQL_GET_TGS}' AS kind, "
          f"  l.collection_source, l.assumed, l.assumption_basis "
          f"FROM {schema}.node_mssql_server i "
          f"JOIN {schema}.node_mssql_login l ON l.server_id = i.server_id "
          f"WHERE i.service_account_sid IS NOT NULL")


def _edge_mssql_db_assign_all(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Database -SCCM_AssignAllPermissions-> its OWN (non-secondary) site (CMBP :6173-6180).

    Each PRIMARY site database can assign all permissions to its own site (it holds that site's
    RBAC). The join keys the DB to its own `sccm_site` and the non-secondary filter drops
    secondary-site databases (e.g. CM_SEC), whose DB holds no assignable RBAC. CMBP's code loops
    `Get-SitesInHierarchy -ExcludeSecondarySites`, but on a CAS+primary topology its live output
    is own-site only — matching that avoids DB->every-site false positives (e.g. PS1-DB->CAS,
    which would imply a child primary controlling the CAS). The site node id is the bare
    site_code (SCCMSite model id). (Unlike the SMS-Provider *computer* assign-all edge, which
    legitimately fans out to every primary site via the AdminService.)
    """
    from .kinds.edges import SCCM_ASSIGN_ALL_PERMISSIONS
    # This edge inherits the confidence of the DATABASE it starts from -- the same rule
    # Task 14 applies to the kerberoast edges and their logins. A CM_<site> database off a
    # RemoteRegistry/privileged-confirmed site DB is confirmed, so the edge is too; off an
    # SPN+SCCM-inferred site DB the database is assumed, and an edge asserting "this DB can
    # assign all permissions over that site" is then equally an assumption. Reading the
    # node's own columns rather than re-deriving keeps the two from drifting apart.
    _safe(con, "edge_mssql_db_assign_all",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT d.database_id AS start_id, sh.site_code AS end_id, "
          f"  '{SCCM_ASSIGN_ALL_PERMISSIONS}' AS kind, "
          f"  coalesce(d.assumed, false) AS assumed, "
          f"  d.assumption_basis AS assumption_basis, "
          f"  ['SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source "
          f"FROM {schema}.node_mssql_database d "
          f"JOIN {schema}.site_hierarchy sh "
          f"  ON upper(sh.site_code) = upper(d.sccm_site) "
          # con-edee, extended: this arm kept the old `coalesce(site_type, 0) != 1`
          # after the five computer-side builders moved to the strict form. That reads
          # an UNKNOWN type as "not a secondary", so a site discovered only by bare code
          # -- which is every secondary a low-privilege run finds, since only the
          # admin-gated site-definition source carries site_type -- passed as a takeover
          # target. Requiring a POSITIVELY KNOWN Primary/CAS type instead means an
          # unproven site is excluded rather than assumed safe to claim.
          f"  AND sh.{_NON_SECONDARY_SITE_TYPE_SQL} AND sh.site_code IS NOT NULL")


def _edge_coerce_relay_adminservice(
    con: duckdb.DuckDBPyConnection, schema: str
) -> None:
    """SCCM_CoerceAndRelayToAdminService: Authenticated Users -> SCCM_Site (CMBP ps1:6572-6624).

    For each non-secondary site, every SMS Provider relay target is paired with every Site
    Server coercion victim (provider != site server). The relay coerces the site server and
    relays its NTLM to the provider's AdminService; the edge end is the site code (the
    SCCM_Site node id). Start = the Authenticated Users node of the SITE SERVER's domain
    (CMBP keys it off the coerced victim, ps1:6606).

    NTLM gate is on the PROVIDER (the relay target must accept NTLM) and is
    **flag-independent**: an unset RestrictReceivingNTLMTraffic is the Windows default
    (0 = allow all inbound NTLM) = vulnerable, so null-or-'Off' qualifies and any other
    explicit value disqualifies, in BOTH modes. This builder therefore takes no
    disable_possible parameter -- it used to accept one and never read it, which read as
    deliberate gating that did not exist (dead parameter removed 2026-07-27).
    Ruling (Task 5, design spec §7, 2026-07-28): the code was right and the spec was
    wrong -- this family is unconditionally assumed (D3: templated relay feasibility
    from role topology, not read from an ACL) but NOT flag-gated, so it carries the
    stamp on every row regardless of --disable-possible-edges. collectionSource keeps
    CMBP's static ['Post-processing'] tag (CMBP ps1:1955) with an added 'Assumed-*'
    tag. Sites confirmed running SCCM 2509+ (build >= ADMINSERVICE_NTLM_MIN_BUILD) are
    excluded — the AdminService rejects NTLM there; unknown versions fail open (edge kept).
    _safe() skips+logs if site_hierarchy / node_computer is missing."""
    from .kinds.edges import SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE
    from .cve_table import ADMINSERVICE_NTLM_MIN_BUILD
    # Cast to VARCHAR first — DuckDB may infer the column as INTEGER when the seed row
    # contains a NULL placeholder; real node_computer always emits VARCHAR but be explicit.
    # NTLM gate is flag-INDEPENDENT: an unset RestrictReceivingNTLMTraffic is the Windows default
    # (0 = allow all inbound NTLM) = genuinely vulnerable, so NULL counts as vulnerable even under
    # --disable-possible-edges (matches CMBP, which emits these confirmed edges under its flag).
    # The confirmed gate for this edge is the provider's SMS Provider role, always applied below.
    ntlm_ok = "upper(coalesce(CAST(c.restrict_receiving_ntlm_traffic AS VARCHAR), 'OFF')) = 'OFF'"
    # Guarantee node_site exists so the join below never fails the whole INSERT (safe_execute
    # would otherwise skip every site's edge on a CatalogException) when this runs before
    # _node_site has built it (e.g. a caller invoking this builder in isolation).
    con.execute(
        f"CREATE TABLE IF NOT EXISTS {schema}.node_site (site_code VARCHAR, version VARCHAR)"
    )
    _safe(
        con, "edge_coerce_relay_adminservice",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"WITH nonsec AS ("
        f"  SELECT sh.site_code, upper(sh.site_code) AS u FROM {schema}.site_hierarchy sh "
        f"  LEFT JOIN {schema}.node_site nsite ON upper(nsite.site_code) = upper(sh.site_code) "
        f"  WHERE coalesce(sh.site_type, 0) != 1 AND sh.site_code IS NOT NULL "
        # Fail open: NULL/unparseable version -> coalesce to 0 -> kept. Build >= 9141
        # (SCCM 2509+) rejects NTLM at the AdminService -> suppress the relay edge.
        f"    AND coalesce(try_cast(split_part(nsite.version, '.', 3) AS INTEGER), 0) "
        f"        < {ADMINSERVICE_NTLM_MIN_BUILD}"
        f"), "
        f"providers AS ("
        f"  SELECT c.sid, c.dnshostname, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
        f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
        f"  WHERE role LIKE 'SMS Provider@%' AND c.sid IS NOT NULL AND ({ntlm_ok})"
        f"), "
        f"servers AS ("
        f"  SELECT c.sid, c.dnshostname, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
        f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
        f"  WHERE role LIKE 'SMS Site Server@%' AND c.sid IS NOT NULL AND c.dnshostname LIKE '%.%'"
        f") "
        f"SELECT DISTINCT {_authed_users_id('srv.dnshostname')} AS start_id, "
        f"  n.site_code AS end_id, "
        f"  '{SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE}' AS kind, "
        f"  ['Post-processing', '{COERCE_RELAY_SOURCE}'] AS collection_source, "
        f"  true AS assumed, '{COERCE_RELAY_BASIS}' AS assumption_basis, "
        f"  ['Coerce ' || coalesce(srv.dnshostname, srv.sid) || ', relay to ' "
        f"    || coalesce(prov.dnshostname, prov.sid)] AS coercion_victim_and_relay_target_pairs, "
        f"  CAST(NULL AS VARCHAR[]) AS coercion_victim_hostnames "
        f"FROM providers prov "
        f"JOIN servers srv ON srv.site = prov.site AND srv.sid != prov.sid "
        f"JOIN nonsec n ON n.u = srv.site"
    )


def _edge_coerce_relay_mssql(
    con: duckdb.DuckDBPyConnection, schema: str, disable_possible: bool
) -> None:
    """MSSQL_CoerceAndRelayToMSSQL: Authenticated Users -> MSSQL_Login (CMBP ps1:6626-6726).

    Driven off node_mssql_login, which already encodes the (sysadmin computer, server)
    pairing CMBP reconstructs by hand. For each login: coerce the sysadmin computer and
    relay NTLM to the site DB server, authenticating as that login.

    'Can't relay to self' is enforced HERE, by `v.sid != l.host_sid`, rather than being
    inherited from _node_mssql_login's exclusion of the SQL host as its own sysadmin.
    Relying on that exclusion made this builder's correctness depend on a filter in a
    different function, with nothing failing here if it were ever loosened -- and SCCM
    gives a real reason to loosen it: Microsoft requires a SECONDARY site's database to
    run ON the secondary site server, so that host's Local System genuinely IS a sysadmin
    on its own instance. Coercing a host and relaying its NTLM straight back to itself is
    blocked by Windows' reflection defences, so such a pair is always a false positive
    regardless of how the login arose.

    Two gates (Stage 6 decision #1): the SQL HOST computer's NTLM and the SERVER's Extended
    Protection. Default treats null as vulnerable (null NTLM => assume Off; null EPA =>
    assume Off). A known EPA other than 'Off' always disqualifies the server. With
    --disable-possible-edges both must be EXPLICITLY 'Off'. collectionSource = the server's
    EPA-determination sources only (CMBP ps1:6715). _safe() skips+logs missing tables.

    Deliberately NOT gated on node_mssql_server.port_open (considered during Task 1c,
    reverted on review): a port unreachable FROM THE COLLECTOR's network position is not
    evidence an attacker cannot reach it -- this edge models attacker capability, and the
    attacker's foothold may be elsewhere on the network. node_mssql_login (and therefore
    every row this builder can ever see) is built solely from _mssql_sql_servers -- a
    confirmed SCCM site DB -- never from the SPN-only mssql_server_instances arm, so an
    unreachable-from-here port says nothing about whether relaying would succeed from a
    different vantage point. The existing EPA gate above already does the right thing when
    EPA was never measured: null-or-Off is honoured only in default mode (Tier C of the
    design spec), so --disable-possible-edges already withholds the edge until EPA is
    confirmed. Gating on port_open in addition would only WITHHOLD a genuine default-mode
    edge for a confirmed site DB whose 1433 this collector's run happened not to reach --
    silently diverging from CMBP without a decision to do so."""
    from .kinds.edges import MSSQL_COERCE_AND_RELAY_TO_MSSQL
    # Cast to VARCHAR first — DuckDB may infer the column as INTEGER when the seed row
    # contains a NULL placeholder; real node_mssql_server and node_computer always emit
    # VARCHAR but be explicit (same pattern as _edge_coerce_relay_adminservice).
    # EPA is the CONFIRMED gate: default treats null-or-'Off' as vulnerable; the flag requires an
    # explicit 'Off' (a known EPA other than 'Off' always disqualifies). NTLM is flag-INDEPENDENT:
    # an unset RestrictReceivingNTLMTraffic is the Windows default (0 = allow all inbound NTLM) =
    # genuinely vulnerable, so NULL counts even under --disable-possible-edges (matches CMBP).
    ntlm_ok = "upper(coalesce(CAST(h.restrict_receiving_ntlm_traffic AS VARCHAR), 'OFF')) = 'OFF'"
    if not disable_possible:
        epa_ok = "(s.extended_protection IS NULL OR upper(CAST(s.extended_protection AS VARCHAR)) = 'OFF')"
    else:
        epa_ok = "upper(CAST(s.extended_protection AS VARCHAR)) = 'OFF'"
    _safe(
        con, "edge_coerce_relay_mssql",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"SELECT DISTINCT {_authed_users_id('v.dnshostname')} AS start_id, "
        f"  l.login_id AS end_id, "
        f"  '{MSSQL_COERCE_AND_RELAY_TO_MSSQL}' AS kind, "
        f"  coalesce(list_filter(s.collection_source, "
        f"    x -> x IN ('MSSQL-ScanForEPA', 'RemoteRegistry-MSSQL')), CAST([] AS VARCHAR[])) "
        f"    AS collection_source, "
        f"  ['Coerce ' || v.dnshostname || ', relay to ' "
        f"    || coalesce(s.dns_host_name, s.name) || ':' || coalesce(s.port, '1433')] "
        f"    AS coercion_victim_and_relay_target_pairs, "
        f"  CAST(NULL AS VARCHAR[]) AS coercion_victim_hostnames, "
        # Unlike its SMB/AdminService siblings, this family's assumption is CONDITIONAL, so
        # the stamp is per-row rather than a literal true. The edge fires either because EPA
        # was measured 'Off' (evidence -> not assumed) or because EPA was never measured at
        # all and default mode treats NULL as off (an assumption -> stamped). Marking the
        # whole family assumed would libel the measured rows; marking none of it would hide
        # exactly the inference design spec §7 calls out.
        f"  (s.extended_protection IS NULL) AS assumed, "
        f"  CASE WHEN s.extended_protection IS NULL "
        f"       THEN '{MSSQL_RELAY_EPA_ASSUMED_BASIS}' END AS assumption_basis "
        f"FROM {schema}.node_mssql_login l "
        f"JOIN {schema}.node_mssql_server s ON s.server_id = l.server_id "
        f"JOIN {schema}.node_computer h ON h.sid = l.host_sid "
        f"JOIN {schema}.node_computer v "
        f"  ON v.sid = l.sysadmin_computer_sid AND v.dnshostname LIKE '%.%' "
        # No reflective relay: the coercion victim must not BE the relay target.
        f"  AND v.sid != l.host_sid "
        f"WHERE ({epa_ok}) AND ({ntlm_ok})"
    )


def _edge_coerce_relay_smb(
    con: duckdb.DuckDBPyConnection, schema: str
) -> None:
    """SCCM_CoerceAndRelayToSMB: Authenticated Users -> Computer (CMBP ps1:6728-6781).

    The edge END is a site system whose SMB signing is NOT required (the relay target); the
    coerced victim is a Site Server in the same non-secondary site (system != server). Start
    = the Authenticated Users node of the SITE SERVER's domain (CMBP ps1:6763).

    Gates (Stage 6 decision #1): the TARGET's smb_signing_required is false (always explicit
    in CMBP) AND its NTLM is null-or-'Off'. **Both gates are flag-independent**, so this
    builder takes no disable_possible parameter -- it used to accept one and never read it
    (dead parameter removed 2026-07-27). The docstring previously claimed the NTLM gate
    tightened under the flag, contradicting the inline comment a few lines below; the comment
    was right.
    Ruling (Task 5, design spec §7, 2026-07-28): the code was right and the spec was
    wrong -- this family is unconditionally assumed (D3: templated relay feasibility
    from role topology, not read from an ACL) but NOT flag-gated, so it carries the
    stamp on every row regardless of --disable-possible-edges.
    collectionSource = the target's smb_signing_source filtered to the SMB-signing probes
    (CMBP ps1:6773), plus an 'Assumed-*' tag. coercionVictimHostnames = the coerced site
    server's dnshostname.
    _safe() skips+logs missing tables."""
    from .kinds.edges import SCCM_COERCE_AND_RELAY_TO_SMB
    # Cast restrict_receiving_ntlm_traffic to VARCHAR before upper() — DuckDB types a
    # ?-bound NULL column as INTEGER at bind time, causing upper() to fail. This CAST is
    # harmless in production (the real column is VARCHAR). Same fix as E1/F1.
    # NTLM gate is flag-INDEPENDENT: unset RestrictReceivingNTLMTraffic = Windows default
    # (0 = allow all inbound NTLM) = vulnerable, so NULL counts even under --disable-possible-edges
    # (matches CMBP). The CONFIRMED gate for SMB is the target's smb_signing_required = false,
    # applied strictly below regardless of the flag.
    ntlm_ok = "upper(coalesce(CAST(c.restrict_receiving_ntlm_traffic AS VARCHAR), 'OFF')) = 'OFF'"
    _safe(
        con, "edge_coerce_relay_smb",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"WITH nonsec AS ("
        f"  SELECT upper(site_code) AS u FROM {schema}.site_hierarchy "
        f"  WHERE {_NON_SECONDARY_SITE_TYPE_SQL} AND site_code IS NOT NULL"
        f"), "
        f"targets AS ("
        f"  SELECT DISTINCT c.sid, c.smb_signing_source, "
        f"    upper(regexp_extract(role, '@(.+)$', 1)) AS site "
        f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
        f"  WHERE role LIKE '%@%' AND c.sid IS NOT NULL "
        f"    AND c.smb_signing_required = false AND ({ntlm_ok})"
        f"), "
        f"servers AS ("
        f"  SELECT DISTINCT c.sid, c.dnshostname, upper(regexp_extract(role, '@(.+)$', 1)) AS site "
        f"  FROM {schema}.node_computer c, UNNEST(c.site_system_roles) AS t(role) "
        f"  WHERE role LIKE 'SMS Site Server@%' AND c.sid IS NOT NULL AND c.dnshostname LIKE '%.%'"
        f") "
        f"SELECT DISTINCT {_authed_users_id('srv.dnshostname')} AS start_id, "
        f"  tgt.sid AS end_id, "
        f"  '{SCCM_COERCE_AND_RELAY_TO_SMB}' AS kind, "
        f"  list_append(coalesce(list_filter(tgt.smb_signing_source, "
        f"    x -> x IN ('SMB-Negotiate', 'RemoteRegistry-SMBSigningCheck')), CAST([] AS VARCHAR[])), "
        f"    '{COERCE_RELAY_SOURCE}') AS collection_source, "
        f"  true AS assumed, '{COERCE_RELAY_BASIS}' AS assumption_basis, "
        f"  CAST(NULL AS VARCHAR[]) AS coercion_victim_and_relay_target_pairs, "
        f"  [srv.dnshostname] AS coercion_victim_hostnames "
        f"FROM targets tgt "
        f"JOIN servers srv ON srv.site = tgt.site AND srv.sid != tgt.sid "
        f"JOIN nonsec n ON n.u = tgt.site"
    )


def _node_authenticated_users(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Synthesise the Authenticated Users group node for every domain a Stage 6 relay edge
    starts from (CMBP Upsert-Node ps1:6609/6708/6766).

    id = UPPER(<FQDN>)-S-1-5-11 (SharpHound well-known-SID form, so it merges with
    SharpHound-collected AD data); name = 'AUTHENTICATED USERS@<FQDN-UPPER>'. environmentid
    is resolved by GroupNode from fallback_domain_sid — here the AD-domain SID of any
    domain-joined computer in that FQDN (S-1-5-11 has no domain part of its own).

    Lazy: only domains that actually produced a relay edge get a node — matching CMBP, where
    the node is upserted inside the relay loop. Inserted into node_group BEFORE
    _node_backfill / _graph_edges_split so the AD id set and GroupNode pick it up. The
    DISTINCT join to _domain_to_sid guarantees the edge's start id has a resolvable domain
    SID; the same domain computer that seeded the relay's start id seeds this map, so every
    relay-start id resolves."""
    from .kinds.edges import (
        SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE,
        MSSQL_COERCE_AND_RELAY_TO_MSSQL,
        SCCM_COERCE_AND_RELAY_TO_SMB,
    )
    # UPPER(FQDN) -> AD-domain SID, from every domain-joined computer.
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _domain_to_sid AS "
        f"SELECT DISTINCT upper(regexp_replace(dnshostname, '^[^.]+\\.', '')) AS fqdn_upper, "
        f"  regexp_extract(upper(sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) AS domain_sid "
        f"FROM {schema}.node_computer "
        f"WHERE dnshostname LIKE '%.%' AND sid IS NOT NULL "
        f"  AND regexp_extract(upper(sid), '^(S-1-5-21(?:-\\d+){{3}})-\\d+$', 1) != ''"
    )
    # Any newly-introduced relay edge kind must be added here so its start nodes get an
    # AUTHENTICATED USERS node.
    relay_kinds = (f"('{SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE}', "
                   f"'{MSSQL_COERCE_AND_RELAY_TO_MSSQL}', '{SCCM_COERCE_AND_RELAY_TO_SMB}')")
    _safe(
        con, "node_group<-authenticated_users",
        f"INSERT INTO {schema}.node_group BY NAME "
        f"SELECT DISTINCT ge.start_id AS sid, "
        f"  'AUTHENTICATED USERS@' || replace(ge.start_id, '-S-1-5-11', '') AS name, "
        f"  false AS sccm_infra, "
        f"  CAST([] AS VARCHAR[]) AS sccm_resource_ids, "
        f"  d.domain_sid AS fallback_domain_sid "
        f"FROM {schema}.graph_edges ge "
        f"JOIN _domain_to_sid d ON d.fqdn_upper = replace(ge.start_id, '-S-1-5-11', '') "
        f"WHERE ge.kind IN {relay_kinds} AND ge.start_id LIKE '%-S-1-5-11'"
    )
    n = _scalar(con,
        f"SELECT count(*) FROM {schema}.node_group WHERE sid LIKE '%-S-1-5-11'"
    )
    logger.info("node_authenticated_users: node_group holds %d AUTHENTICATED USERS node(s)", n)


def _graph_edges_dedup(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Collapse duplicate (start_id, end_id, kind) rows into one row per unique triple.

    Duplicates arise when both the adminservice and wmi sources contribute the same
    edge, or when name fan-out (collection_by_name, role_by_name) matches the same
    id twice. CMBP's Upsert-Edge dedupes at insert time; we do it once here after all
    edge builders have run.

    collection_source tags from all duplicate rows are merged into one distinct list
    (same array-union idiom as site_system_roles in _node_computer).

    sccm_infra: bool_or() so a row set true by one source (or one duplicate) wins over
    a NULL from another; stays NULL only when every duplicate row left it NULL.

    assumed/assumption_basis (Task 3/4/5, D3): same bool_or()/max() idiom as
    node_mssql_server's arm collapse above -- a confirmed duplicate (NULL) never
    masks an assumed one, and vice versa is impossible (an edge triple only ever
    gets an assumed stamp from one builder).
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges AS "
        f"SELECT start_id, end_id, kind, "
        f"  coalesce(list_distinct(flatten(list(collection_source))), CAST([] AS VARCHAR[])) AS collection_source, "
        # Stage 6: array-union the coercion lists (CMBP Upsert-Edge merges arrays, ps1:2155-2158).
        # FILTER drops the NULLs that every non-relay builder leaves in these columns.
        f"  coalesce(list_distinct(flatten(list(coercion_victim_and_relay_target_pairs) "
        f"    FILTER (WHERE coercion_victim_and_relay_target_pairs IS NOT NULL))), CAST([] AS VARCHAR[])) "
        f"    AS coercion_victim_and_relay_target_pairs, "
        f"  coalesce(list_distinct(flatten(list(coercion_victim_hostnames) "
        f"    FILTER (WHERE coercion_victim_hostnames IS NOT NULL))), CAST([] AS VARCHAR[])) "
        f"    AS coercion_victim_hostnames, "
        f"  bool_or(sccm_infra) AS sccm_infra, "
        f"  bool_or(assumed) AS assumed, max(assumption_basis) AS assumption_basis "
        f"FROM {schema}.graph_edges "
        f"GROUP BY start_id, end_id, kind"
    )
    logger.info("graph_edges deduplicated in schema %r", schema)


def _edge_has_client(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append SCCM_HasClient edges: Site -> ClientDevice (CMBP ps1:7257/7394).
    start = device.site_code (the site that owns the client), end = smsid.
    Inferred-client rows (added in _node_client_device_possible) carry site_code set to
    the first Primary site (never the CAS), so they also get a HasClient edge
    automatically. _safe() skips+logs if node_client_device is missing."""
    from .kinds.edges import SCCM_HAS_CLIENT
    _safe(
        con, "edge_has_client",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"SELECT site_code AS start_id, smsid AS end_id, '{SCCM_HAS_CLIENT}' AS kind, "
        f"CASE WHEN coalesce(is_confirmed_active_client, true) THEN ['AdminService-ClientDevices'] "
        f"     ELSE ['LDAP-CmRcService', '{POSSIBLE_CLIENT_SOURCE}'] END AS collection_source, "
        # Same predicate the collection_source CASE above already uses, so the stamp can
        # never disagree with the provenance tag: only the inferred devices are assumed.
        f"NOT coalesce(is_confirmed_active_client, true) AS assumed, "
        f"CASE WHEN NOT coalesce(is_confirmed_active_client, true) "
        f"     THEN '{POSSIBLE_CLIENT_BASIS}' END AS assumption_basis "
        f"FROM {schema}.node_client_device "
        f"WHERE site_code IS NOT NULL AND smsid IS NOT NULL"
    )


def _node_backfill(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Synthesise bare nodes for edge END endpoints that resolved to a SID/smsid with no
    node (graph-integrity decision 2026-06-23). Kind is inferred from the edge position
    (BACKFILL_END_KIND); ambiguous ends get 'Base'. Logs a warning count. Runs LAST."""
    from .graph import BACKFILL_END_KIND

    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _existing_ids AS "
        f"SELECT sid AS id FROM {schema}.node_computer WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_user WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_group WHERE sid IS NOT NULL "
        f"UNION SELECT smsid FROM {schema}.node_client_device WHERE smsid IS NOT NULL"
    )
    map_values = ", ".join(f"('{k}', '{v}')" for k, v in BACKFILL_END_KIND.items())
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_backfill AS "
        f"SELECT DISTINCT ge.end_id AS id, m.kind AS kind "
        f"FROM {schema}.graph_edges ge "
        f"JOIN (VALUES {map_values}) AS m(edge_kind, kind) ON ge.kind = m.edge_kind "
        f"WHERE ge.end_id IS NOT NULL "
        f"  AND ge.end_id NOT IN (SELECT id FROM _existing_ids)"
    )
    cnt = _scalar(con, f"SELECT count(*) FROM {schema}.node_backfill")
    if cnt:
        logger.warning(
            "node_backfill: synthesised %d stub node(s) for edge endpoints with no node",
            cnt,
        )
    else:
        logger.debug("node_backfill: every edge endpoint has a node")


def _graph_edges_split(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Partition graph_edges into three payloads: AD-touching, MSSQL-only, SCCM-only.

    Routing precedence (each edge lands in exactly one payload):
      1. AD    -- EITHER endpoint is an AD node id (Computer/User/Group coalesce
                  row, or a backfill stub). Emitted untagged (no source_kind) so BloodHound
                  merges it into the native AD graph. This is what keeps AD<->MSSQL edges
                  (MSSQL_HostFor, MSSQL_HasLogin, the service-account and relay edges) here.
      2. MSSQL -- NOT AD-touching AND BOTH endpoints are MSSQL node ids. Emitted under
                  source_kind="MSSQL" so the separate MSSQL source owns its own SQL topology.
      3. SCCM  -- everything else: not AD-touching, not both-MSSQL, so at least one endpoint
                  is an SCCM node. This keeps MSSQL<->SCCM edges (SCCM_AssignAllPermissions,
                  database -> site) here.

    Runs LAST, after _node_backfill, so the AD id set includes the stub ids minted there.
    Every node_* table it reads is built earlier in transforms() with CREATE OR REPLACE
    TABLE, so all are guaranteed present. EXISTS/NOT EXISTS make the three outputs an exact,
    disjoint, complete partition, NULL-safe even for a malformed edge with a NULL endpoint
    (it falls to the SCCM side deterministically). MSSQL node ids never collide with AD SIDs,
    but the explicit NOT-AD guard on the MSSQL and SCCM arms keeps the precedence unambiguous.
    """
    # _ad_ids / _mssql_ids are session-local TEMP TABLEs (DuckDB's temp schema);
    # intentionally unqualified -- do NOT add a {schema}. prefix, that is invalid for a temp table.
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _ad_ids AS "
        f"SELECT sid AS id FROM {schema}.node_computer WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_user WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_group WHERE sid IS NOT NULL "
        f"UNION SELECT id FROM {schema}.node_backfill WHERE id IS NOT NULL"
    )
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _mssql_ids AS "
        f"SELECT server_id AS id FROM {schema}.node_mssql_server WHERE server_id IS NOT NULL "
        f"UNION SELECT database_id FROM {schema}.node_mssql_database WHERE database_id IS NOT NULL "
        f"UNION SELECT login_id FROM {schema}.node_mssql_login WHERE login_id IS NOT NULL "
        f"UNION SELECT dbuser_id FROM {schema}.node_mssql_database_user WHERE dbuser_id IS NOT NULL "
        f"UNION SELECT role_id FROM {schema}.node_mssql_server_role WHERE role_id IS NOT NULL "
        f"UNION SELECT role_id FROM {schema}.node_mssql_database_role WHERE role_id IS NOT NULL"
    )
    # The full 9-column projection every payload keeps identical (one place, added arrays free).
    cols = (
        "e.start_id, e.end_id, e.kind, e.collection_source, "
        "e.coercion_victim_and_relay_target_pairs, e.coercion_victim_hostnames, e.sccm_infra, "
        "e.assumed, e.assumption_basis"
    )
    start_ad = "EXISTS (SELECT 1 FROM _ad_ids a WHERE a.id = e.start_id)"
    end_ad = "EXISTS (SELECT 1 FROM _ad_ids a WHERE a.id = e.end_id)"
    start_mssql = "EXISTS (SELECT 1 FROM _mssql_ids m WHERE m.id = e.start_id)"
    end_mssql = "EXISTS (SELECT 1 FROM _mssql_ids m WHERE m.id = e.end_id)"
    # 1. AD payload: either endpoint is an AD node id (highest precedence, unchanged).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges_ad AS "
        f"SELECT {cols} FROM {schema}.graph_edges e "
        f"WHERE {start_ad} OR {end_ad}"
    )
    # 2. MSSQL payload: not AD-touching AND both endpoints are MSSQL node ids.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges_mssql AS "
        f"SELECT {cols} FROM {schema}.graph_edges e "
        f"WHERE NOT {start_ad} AND NOT {end_ad} "
        f"  AND {start_mssql} AND {end_mssql}"
    )
    # 3. SCCM payload: not AD-touching AND not both-MSSQL (at least one SCCM endpoint).
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges_sccm AS "
        f"SELECT {cols} FROM {schema}.graph_edges e "
        f"WHERE NOT {start_ad} AND NOT {end_ad} "
        f"  AND NOT ({start_mssql} AND {end_mssql})"
    )
    ad_cnt = _scalar(con, f"SELECT count(*) FROM {schema}.graph_edges_ad")
    mssql_cnt = _scalar(con, f"SELECT count(*) FROM {schema}.graph_edges_mssql")
    sccm_cnt = _scalar(con, f"SELECT count(*) FROM {schema}.graph_edges_sccm")
    logger.info(
        "graph_edges split: %d AD-touching, %d MSSQL-only, %d SCCM-only",
        ad_cnt, mssql_cnt, sccm_cnt,
    )


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Top-level transform entrypoint (registered via @app.preproc(transformer=transforms))."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    # Read once, up front: _site_hierarchy's untyped-root fallback (D5) needs this
    # flag and runs before any other builder, so it can no longer be read lazily
    # at its first use further down (that used to be right before
    # _node_client_device_possible). Every later gated builder reuses this value.
    disable_possible = _read_disable_possible(con, schema)
    _principal_by_name(con, schema)
    _site_hierarchy(con, schema, disable_possible)
    _derive_ad_props(con, schema)  # must precede the AD node builders below (_join_ad_props)
    _node_computer(con, schema)
    _node_user(con, schema)
    _node_group(con, schema)
    _node_smc_container(con, schema)
    _node_site(con, schema)
    _node_collection(con, schema)
    _node_security_role(con, schema)
    _node_admin_user(con, schema)
    _node_client_device(con, schema)
    _node_client_device_possible(con, schema, disable_possible)
    # Stage 2 lookup tables: name/id -> id maps that edge builders join against.
    # These read from the raw source tables (not the node_* coalesces) and must
    # run after all _node_* builders (which may add columns via _ensure_columns)
    # and before _graph_edges_init so edge builders can reference them.
    _principal_by_resourceid(con, schema)
    _device_by_resourceid(con, schema)
    _collection_by_name(con, schema)
    _role_by_name(con, schema)
    # Relationship-list enrichment: add denormalised list columns to node_* tables.
    # These run after all _node_* builders and lookup tables but before edge builders,
    # so edge builders see the fully-enriched node tables.
    _enrich_collection_members(con, schema)
    _enrich_role_members(con, schema)
    _enrich_admin_assignments(con, schema)
    _enrich_client_device(con, schema)
    # Stage 4: collapse real+inferred ClientDevice twins by ad_domain_sid BEFORE edges,
    # so every edge builder references survivors (no graph_edges rewrite needed).
    _dedup_client_device(con, schema)
    # ad_domain_sid is only finalized once dedup has run (real clients get it from
    # _enrich_client_device; both real and inferred survive dedup keyed on it), so the
    # join to node_computer's AD attributes runs here, after both.
    _enrich_client_device_ad_attrs(con, schema)
    _enrich_site_lists(con, schema)
    _derive_site_system_roles(con, schema)
    # Stage 5: MSSQL nodes (built from SCCM topology + EPA scan; spec §6 Stage 5).
    # _assumed_site_dbs (D2/Task 2) must run first -- it is the non-privileged
    # signal _mssql_sql_servers' new arm reads, and it needs disable_possible to
    # gate its own SPN+SCCM inference.
    _assumed_site_dbs(con, schema, disable_possible)
    _mssql_sql_servers(con, schema)
    _node_mssql_server(con, schema)
    _node_mssql_database(con, schema)
    _node_mssql_login(con, schema)
    _node_mssql_database_user(con, schema)
    _node_mssql_server_role(con, schema)
    _node_mssql_database_role(con, schema)
    # _graph_edges_init must run before all edge builders; _edge_replication and future
    # edge builders all INSERT into the table created here.
    _graph_edges_init(con, schema)
    _edge_replication(con, schema)
    _edge_has_client(con, schema)
    _edge_has_member(con, schema)
    _edge_generic_all_smc(con, schema)
    _edge_is_mapped_to(con, schema)
    _edge_is_assigned(con, schema)
    _edge_has_user(con, schema)
    _edge_member_of(con, schema)
    _edge_member_of_smc(con, schema)
    _edge_has_session(con, schema)
    _edge_has_stored_account(con, schema)
    _edge_contains(con, schema)
    _edge_rbac_role_grants(con, schema)
    _edge_all_permissions(con, schema)
    _edge_assign_all_permissions(con, schema)
    # Stage 4 edges.
    _edge_same_host(con, schema)
    _edge_local_admin_required(con, schema)
    # Stage 5 MSSQL edges.
    _edge_mssql_structural(con, schema)
    _edge_mssql_membership(con, schema)
    _edge_mssql_service_account(con, schema)
    _edge_mssql_service_account_spn(con, schema)
    _edge_mssql_kerberoast_spn(con, schema)
    _edge_mssql_db_assign_all(con, schema)
    # Stage 6: coerce-and-relay possible edges + the synthetic Authenticated Users node.
    # disable_possible was read up top (for _site_hierarchy and _node_client_device_possible).
    # The relay builders gate the "assume vulnerable on null" cases on it (surgical, Stage 6 decision #1).
    # _node_authenticated_users runs AFTER the relay builders (it reads their start ids) and
    # BEFORE dedup/backfill/split (which read node_group for the AD id set).
    # adminservice/smb take no flag: both their gates are flag-independent (see their
    # docstrings). Only the MSSQL relay's EPA gate actually tightens under it.
    _edge_coerce_relay_adminservice(con, schema)
    _edge_coerce_relay_mssql(con, schema, disable_possible)
    _edge_coerce_relay_smb(con, schema)
    _node_authenticated_users(con, schema)
    # Dedup after all edge builders: both adminservice and wmi sources can contribute the
    # same edge, and name fan-out (collection_by_name, role_by_name) can match the same
    # id twice. CMBP's Upsert-Edge dedupes at insert time; we do it once here.
    _graph_edges_dedup(con, schema)
    # node_backfill runs LAST: synthesises bare stub nodes for edge END endpoints
    # that resolved to a SID/smsid not present in any node_* table (graph-integrity
    # decision 2026-06-23). All node_* and graph_edges tables exist by this point.
    _node_backfill(con, schema)
    # Split the finalised graph_edges into the AD payload (either endpoint is an AD node id,
    # including the backfill stubs minted just above), the MSSQL-only payload (both endpoints
    # are MSSQL node ids), and the SCCM payload (everything else). Must run after _node_backfill
    # so stub ids are in the AD id set. See ARCHITECTURE.md §11f.
    _graph_edges_split(con, schema)
