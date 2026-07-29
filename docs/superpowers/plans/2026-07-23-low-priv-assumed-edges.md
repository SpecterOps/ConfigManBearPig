# Low-Privilege Assumed Nodes/Edges Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DEFAULT collection mode (possible edges ON) build the SCCM/MSSQL attack graph a non-privileged domain user can support — by wiring OpenHound's already-collected low-priv evidence (every site-code source, plus the orphaned site-server / FSP / DNS-MP role signals) into `site_hierarchy`, `node_computer`, and the assumption/scaffolding builders — while `--disable-possible-edges` stays conservative, and every assumed node/edge is provenance-tagged and documented.

**Architecture:** The dominant fix is data wiring in the DuckDB preprocess transforms (`transforms.py`): feed `site_hierarchy` from **all** site-code sources (D5 — unblocks the `nonsec`-gated families), feed `node_computer` from the three orphaned role sources (design spec §4.1), and give the MSSQL site-DB identity a non-privileged signal (RemoteRegistry-confirmed → `MSSQLSvc` SPN + SCCM-relatedness). Assumed families get a shared provenance stamp and stay traversable. Almost nothing is re-collected — the evidence is already present. The four small collector edits (Tasks 1b, 11, 12, 13) each add a *field* to an existing row or capture an identity already fetched; none changes probe ordering.

**Tech Stack:** Python 3.13+ (stdlib + DuckDB SQL via `duckdb`), Typer CLI (existing), pytest 9. Design spec: `docs/superpowers/specs/2026-07-23-low-priv-assumed-edges-design.md`.

## Global Constraints

- **No git commits.** No-commit harness: each task ends at a *green checkpoint* (targeted tests pass); the human commits. Never run `git add`/`git commit`. ([[sdd-no-commit-harness]])
- **Only modify `sccm/sccm/`.** Do not edit OpenHound core or `openhound-collector-common` without asking (this plan needs neither).
- **Property casing = ConfigManBearPig-verbatim on OUTPUT** (graph.py `*Properties` field names / output keys), while DuckDB columns + model input fields stay `snake_case`. ([[sccm-property-casing-cmbp]])
- **`schema_SCCM.json` is hand-maintained** — if a new node/edge kind is emitted, sync it both ways with `kinds/edges.py`. `MSSQL_*` kinds go in the MSSQL schema, NOT `schema_SCCM.json`. ([[sccm-opengraph-schema-maintenance]])
- **`site_type` INTEGER contract:** 1=Secondary, 2=Primary, 4=CAS. Root = CAS(4) else parentless Primary(2). Preserve this in every `site_hierarchy` writer. Normalize the `'None'`/`'Undetermined'`/`''` parent placeholders to NULL in **every** arm, or the parentless-Primary root test silently never matches.
- **Site-code attribution never guesses (D6).** A host may only be tagged `<Role>@<site>` from a source that knows *that host's* site. No backfilling from "the only site in the hierarchy". The one sanctioned cross-host inference is the sitesigncert → `mp_host` join (Task 1b), and it is a join precisely so the inference stays visible in the raw table.
- **Do not reorder collector probes.** CLAUDE.md requires the collector's steps to run in ConfigManBearPig.ps1's order (e.g. sitesigncert is ps1:8611, first). Where a value isn't ready yet, carry a provenance field and resolve it in the transform.
- **`HasSession` is confirmed in both arms and must never be possible-gated.** `_edge_has_session` (transforms.py:2798) deliberately takes only `(con, schema)` and is called unconditionally (transforms.py:3593): the RemoteRegistry current-user arm is an observed logon, and the MSSQL service-account arm is an observed service identity. No task in this plan may add a `disable_possible_edges` parameter to it — including Task 13, which adds a third (SPN-holder) arm that is likewise confirmed.
- **A confirmed site database keeps its full MSSQL scaffolding in both modes** (spec §7). Once RR/AdminService/WMI confirms the host is the site DB, the schema SCCM requires there is a consequence of that fact, not a possible edge. Only the `SPN+SCCM`-basis scaffolding is assumed, and it is filtered once in `_assumed_site_dbs` (Task 2) — not re-checked per builder.
- **`--disable-possible-edges` is tightening-only** — it removes/does-not-create *assumed* families; it never removes *confirmed* data. `site_hierarchy` (Task 1) is confirmed and populated in BOTH modes.
- **Targeted tests only** ([[feedback-targeted-tests]]): run the specific offline `*_test.py` with the SCCM venv from repo root `c:\Users\domainadmin\Desktop\OpenHound`:
  `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/<file>_test.py -v`. Do NOT run the full suite.
- **Logging:** every new if/else or try/except gets an appropriately-levelled log line (error/warning/info/verbose/debug) or a comment saying why not (project CLAUDE.md).

---

## File Structure

**Modify (preprocess/convert):**
- `sccm/sccm/src/openhound_sccm/transforms.py` — the bulk. New helpers: `_assumed_site_dbs`, `_mark_assumed`, `_node_smc_container`, `_edge_generic_all_smc`, `_edge_member_of_smc`, `_edge_mssql_service_account_spn`. Modified: `_site_hierarchy` (arms for **all ten** site-code sources per D5 + root fallback), `_node_computer` (arms for `http_site_servers` with the `mp_host` join, the FSP role, and `dns_management_points` — Task 1b), `_mssql_sql_servers` (non-privileged arm), the MSSQL scaffolding node/edge builders (Tier C gating + provenance), the Tier-B edge builders (provenance tags), `_edge_coerce_relay_smb` (traversability), `_node_client_device_possible` (deterministic id — verify).
- `sccm/sccm/src/openhound_sccm/kinds/edge_help.py` (or the existing edge-help module) — help blurbs for assumed edge kinds.
- `sccm/sccm/src/openhound_sccm/kinds/nodes.py` + `kinds/edges.py` — `Container`/`GenericAll` base-kind constants (Task 11); `MemberOf`/`HasSession`/`MSSQL_ServiceAccountFor` already exist.

**Modify (collectors — small, additive):**
- `sccm/sccm/src/openhound_sccm/collectors/http.py` — `_sitesigncert_probe`: add one `mp_host` field to the emitted row (Task 1b). **Do not reorder the probes** — sitesigncert runs first per ps1:8611 and the CLAUDE.md ordering rule.
- `sccm/sccm/src/openhound_sccm/collectors/dns.py` — `dns_management_points`: emit the site code and MP role on the yielded row instead of a bare AD object (Task 1b).
- `sccm/sccm/src/openhound_sccm/collectors/ldap.py` — `ldap_system_management_dacl` (capture container `objectGUID`/DN, Task 11) and `_expand_group_targets` (persist direct group members to `ldap_smc_group_members`, Task 12).
- `sccm/sccm/src/openhound_sccm/collectors/mssql.py` — `collect_mssql`: persist `has_mssql_spn` / `port_open` and stop discarding SPN hosts whose 1433 is filtered (Task 1c); resolve + record the `MSSQLSvc` SPN *holder* account (Task 13).

**Reference (read-only, do not modify):**
- `mssql/mssql/src/openhound_mssql/edges/derive_ad.py` + `collection/ad_resolve.py` — the `ServiceAccountFor`/`HasSession` implementation to port for Task 13.

**Modify (docs):**
- `sccm/sccm/README.md` — Assumptions/possible-edges catalog + Tier-D "needs privilege" callout + examples.
- `sccm/sccm/ARCHITECTURE.md` — new subsystem section + changelog.

**Modify (fixtures/tests):**
- `sccm/sccm/src/openhound_sccm/integration/fixtures/` — low-priv-expected cases (Task 9).
- Tests: `sccm/sccm/tests/site_hierarchy_lowpriv_test.py`, `orphaned_role_sources_test.py`, `mssql_spn_host_test.py`, `assumed_site_db_test.py`, `provenance_test.py`, `mssql_scaffold_possible_test.py`, `sccm_possible_edges_lowpriv_test.py`, `coerce_smb_traversable_test.py`, `edge_help_assumed_test.py`, `integration_lowpriv_fixtures_test.py`.

**Test harness note:** the transforms take a `duckdb` connection + schema name. Existing offline tests (e.g. `transforms_safe_fallback_test.py`) show the pattern: create an in-memory/temp duckdb, create the raw input tables with the columns the transform reads, call the transform, assert on the output table. Reuse that pattern; read `transforms_safe_fallback_test.py` first for the exact fixture helpers.

---

## Task 1: Feed `site_hierarchy` from every site-code source (the unlock) — decision D5

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_site_hierarchy` (currently lines 192-256).
- Test: `sccm/sccm/tests/site_hierarchy_lowpriv_test.py`

**Interfaces:**
- Consumes **two shapes** of source (design spec §2.1 has the full inventory):
  - *Hierarchy-shaped* (bespoke arms — they carry type/parent/root): `ldap_management_points_raw`
    (`site_code`, `site_type` STRING, `parent_site_code` STRING, `root_site_code` STRING — `collectors/ldap.py:300-304`)
    plus the two existing privileged ones (`adminservice_site_definitions`, `wmi_site_definitions`).
  - *Bare-code* (one shared loop): every other raw table carrying a `site_code` column — `ldap_sites`,
    `remoteregistry_sites`, `smb_sites`, `smb_computers`, `http_management_points`,
    `http_distribution_points`, `http_smsproviders`, `http_site_servers`, `http_site_versions`,
    `dns_management_points` (once Task 1b makes it emit one), `local_wmi_sms_authority`,
    `local_wmi_sms_lookupmp`, `local_wmi_ccm_client`, `ldap_cmrc_devices`.
- Produces: `{schema}.site_hierarchy(site_code, parent_site_code, site_type INTEGER, root_site_code)`
  populated whenever *any* phase found a site code. Downstream `_root_code`/`_first_primary_code` unchanged.
- **New parameter:** `_site_hierarchy(con, schema, disable_possible_edges)` — needed only by the untyped-root
  fallback in Step 4. The site rows themselves are confirmed and identical in both modes.

> **The untyped-root fallback is partly possible-gated (decided 2026-07-27).** Guessing which of several
> untyped sites is the root is an assumption, so `--disable-possible-edges` declines it. With exactly **one**
> site it is not a guess — a single-site hierarchy has one root and it must be that site — so that case runs
> in both modes. This matters more than a normal property, because the root is baked into SCCM-native node
> **ids**: `suffix = f" || '@{root}'" if root else ""` (transforms.py:1583) at 8 of 13 `_root_code` call
> sites. A missing root does not suppress those builders; it mints the same objects under different ids. So
> the divergence is deliberately confined to the multi-site-untyped case, which already warns in both modes.

> **Why a loop and not 14 INSERTs:** hardcoding the list guarantees it goes stale the next time a collector
> is added. Discover the bare-code tables from `information_schema` instead (Step 3) — then "all sources"
> stays true by construction, and absent tables are skipped for free because they simply aren't listed.
> A `site_code` value appearing anywhere is evidence that site exists, so this is semantically safe.
> If introspection turns out to be awkward against the real schema, fall back to the explicit list above
> and add a comment saying it must be updated when a collector gains a `site_code`.

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/site_hierarchy_lowpriv_test.py
import duckdb
from openhound_sccm.transforms import _site_hierarchy

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
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.site_hierarchy").fetchone()[0] == 1

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
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/site_hierarchy_lowpriv_test.py -v`
Expected: FAIL — every low-priv test finds an empty `site_hierarchy` (only the two privileged arms exist today).

- [ ] **Step 3: Add the MP-capabilities arm and the bare-code discovery loop**

In `_site_hierarchy`, after the existing adminservice/wmi INSERTs (transforms.py:206-219) and BEFORE the "Collapse duplicate rows" block (222).

First the one hierarchy-shaped low-priv source. Map the MP-caps string `site_type` to the INTEGER contract and normalize sentinel parents to NULL.

> **`root_site_code` must be carried too (corrected 2026-07-27 — the first draft of this SQL dropped it).**
> Design-spec D4 says to use the *true* `root_site_code` from MP-capabilities rather than inferring a root,
> and `ldap_management_points_raw` already carries it ([ldap.py:304](../../src/openhound_sccm/collectors/ldap.py)).
> Resolve it **before** the typed-root query in Step 4: a non-NULL, non-sentinel `root_site_code` IS the
> root, it is observed evidence, so it applies in **both** flag modes with no assumption and an INFO log.
> Only when MP-capabilities gave nothing (an HTTP/SMB/RemoteRegistry-only run) does control fall through to
> the typed-root query and then to the Step-4 guess. If several distinct non-NULL `root_site_code` values
> disagree that is a multi-hierarchy environment: pick deterministically (`min`) and WARN naming all of
> them. Without this, a hierarchy whose CAS was never directly observed resolves to the wrong root — and
> the root is baked into SCCM-native node ids.

```python
    # LDAP management-point capabilities already carry site type/parent/root
    # (collectors/ldap.py _parse_mp_capabilities). Low-priv reachable; feed them
    # so a domain-only bind still yields a hierarchy. String site_type -> INTEGER
    # contract (1=Secondary, 2=Primary, 4=CAS).
    _safe(
        con,
        "site_hierarchy<-ldap_mp",
        f"INSERT INTO {schema}.site_hierarchy "
        f"SELECT DISTINCT upper(site_code), {_norm_parent('parent_site_code')}, "
        f"  CASE site_type WHEN 'Central Administration Site' THEN 4 "
        f"                 WHEN 'Primary Site' THEN 2 "
        f"                 WHEN 'Secondary Site' THEN 1 ELSE NULL END "
        f"FROM {schema}.ldap_management_points_raw WHERE site_code IS NOT NULL",
    )
```

Then every remaining table that has a `site_code` column, discovered rather than listed (D5). Add a small module-level helper for the sentinel-parent normalization since three places need it:

```python
# 'None' / 'Undetermined' / '' are placeholders several collectors emit for an
# unknown parent (e.g. ldap_sites:197). They must become NULL or the
# parentless-Primary root test in _site_hierarchy silently never matches.
_PARENT_SENTINELS = ("None", "Undetermined", "")

def _norm_parent(col: str) -> str:
    """SQL fragment: a parent site code column with sentinels normalized to NULL."""
    sentinels = ", ".join(f"'{s}'" for s in _PARENT_SENTINELS)
    return f"CASE WHEN {col} IN ({sentinels}) THEN NULL ELSE upper({col}) END"


# Tables already consumed above with their full hierarchy shape; re-reading them
# as bare codes would be harmless but confusing in the logs.
_HIERARCHY_SHAPED = frozenset({
    "adminservice_site_definitions", "wmi_site_definitions", "ldap_management_points_raw",
})

def _bare_site_code_tables(con: duckdb.DuckDBPyConnection, schema: str) -> list[str]:
    """Every raw table in *schema* carrying a site_code column, minus the ones
    already loaded with their parent/type (D5).

    Discovered rather than hardcoded so a new collector that learns a site code
    feeds the hierarchy automatically, and so absent tables need no _safe guard --
    they simply aren't listed. A site_code appearing anywhere is evidence that
    site exists, so widening the net cannot invent a site.
    """
    rows = con.execute(
        "SELECT table_name FROM information_schema.columns "
        "WHERE table_schema = ? AND column_name = 'site_code' "
        "  AND table_name NOT LIKE 'node_%' AND table_name NOT LIKE 'edge_%' "
        "  AND table_name <> 'site_hierarchy' "
        "ORDER BY table_name",
        [schema],
    ).fetchall()
    return [t for (t,) in rows if t not in _HIERARCHY_SHAPED]
```

…and drive the loop, logging which tables actually contributed so a live run shows the discovery breadth:

```python
    # D5: every other site-code source registers its bare code. No type/parent, so
    # the collapse below lets any richer row for the same code win (max(site_type)).
    for table in _bare_site_code_tables(con, schema):
        has_parent = _column_exists(con, schema, table, "parent_site_code")
        parent_expr = _norm_parent("parent_site_code") if has_parent else "NULL"
        _safe(
            con,
            f"site_hierarchy<-{table}",
            f"INSERT INTO {schema}.site_hierarchy "
            f"SELECT DISTINCT upper(site_code), {parent_expr}, NULL "
            f"FROM {schema}.{table} WHERE site_code IS NOT NULL",
        )
    logger.info("site_hierarchy: loaded site codes from %d bare-code source table(s) in schema %r",
                len(_bare_site_code_tables(con, schema)), schema)
```

`_column_exists` may already exist near `_ensure_columns` — grep before adding one. `_safe` already no-ops when a source table is absent, so partial-phase runs stay safe.

- [ ] **Step 4: Add the single-site root fallback**

The existing root query (transforms.py:234-241) returns `None` when no row has `site_type` 4 or a parentless 2. With D5 that is now the *common* low-priv case, not an edge case — only 2 of the ~16 source tables carry a type, so a run with no LDAP MP-capabilities and no AdminService produces an all-NULL `site_type` column. After computing `root_code` (line 243) and before stamping (251), add:

```python
    if root_code is None:
        # No type-classified root: normal at low privilege, since most site-code
        # sources (D5) know only the bare code. Fall back to the first code so
        # single-hierarchy runs still anchor a root -- arbitrary in a multi-site
        # hierarchy, hence the INFO naming the choice (design spec §10).
        # Deterministic ordering keeps reruns stable.
        candidates = [
            code for (code,) in con.execute(
                f"SELECT site_code FROM {schema}.site_hierarchy "
                f"WHERE site_code IS NOT NULL ORDER BY site_code"
            ).fetchall()
        ]
        if len(candidates) == 1:
            # Exactly one site: a single-site hierarchy has exactly one root and it
            # must be this site, so this is deduction, not a guess. It therefore
            # runs in BOTH flag modes, and INFO rather than WARNING -- untyped
            # single-site is the normal shape of a low-priv run.
            root_code = candidates[0]
            logger.info("site_hierarchy: single untyped site %r in schema %r; using it as the root",
                        root_code, schema)
        elif candidates and disable_possible_edges:
            # Two or more untyped sites: picking one IS an assumption, so
            # evidence-only mode declines to make it. Leaving root_code None means
            # SCCM-native ids lose their '@<root>' scope (transforms.py:1583), so
            # say that plainly -- it changes node identity, it is not just a
            # missing property.
            logger.warning(
                "site_hierarchy: %d untyped sites %s in schema %r and --disable-possible-edges is set, "
                "so no root is assumed. SCCM-native node ids will be minted without their '@<root>' "
                "scope and will not match a default-mode graph of the same environment. "
                "Collect with LDAP reachable (or pass --site-codes) to resolve a real root.",
                len(candidates), candidates, schema,
            )
        elif candidates:
            root_code = candidates[0]
            # WARNING here, because with more than one candidate the pick is
            # alphabetical and the root -- plus every id and edge anchored to it --
            # may be wrong. Name the alternatives and the fix; nothing downstream
            # fails loudly if this choice is incorrect.
            logger.warning(
                "site_hierarchy: no site had a type (CAS/Primary/Secondary), so the root was "
                "chosen alphabetically: %r of %d candidates %s in schema %r. "
                "Only LDAP management-point capabilities and AdminService/WMI carry site type; "
                "run with LDAP reachable (or --site-codes) to anchor the root correctly.",
                root_code, len(candidates), candidates, schema,
            )
        else:
            logger.warning("site_hierarchy: no sites from any source in schema %r", schema)
```

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/site_hierarchy_lowpriv_test.py -v`
Expected: PASS (10 tests).

- [ ] **Step 6: Green checkpoint** — leave uncommitted for the human.

---

## Task 1b: Wire the orphaned role sources into `_node_computer` — design spec §4.1

Three role signals are collected, registered in `_preproc_table_map`, loaded into the DuckDB lookup, and
then read by nothing. All are **confirmed** evidence → emitted in **both** flag modes, no `assumed` stamp.
Two are pure preprocess wiring; the DNS one needs a small collector change first.

Do this **before Task 5**, which builds edges off `node_computer.site_system_roles`, and before Task 10's
live re-validation.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/http.py` — `_sitesigncert_probe` (216-254): add `mp_host`.
- Modify: `sccm/sccm/src/openhound_sccm/collectors/dns.py` — `dns_management_points` (102-141): emit site code + role.
- Modify: `sccm/sccm/src/openhound_sccm/collectors/local.py` — `local_wmi_sms_authority` (122) and `local_wmi_sms_lookupmp` (158): emit `site_code` on the yielded row. **Added 2026-07-27 from the Task 1 review.** Same defect as DNS: `ctx.current_site_code` is parsed from the `SMS:<site>` authority name at [local.py:102](../../src/openhound_sccm/collectors/local.py) and passed to `register_target(...)` as a keyword, but both resources `yield target.ad_object` alone, so the column never reaches DuckDB and Task 1's discovery loop can never find it. Change each to `yield {**target.ad_object, "site_code": ctx.current_site_code}` (guarding the None case as the surrounding code does) and add the column to both raw-table assets. Do **not** synthesize a role from these — an MP discovered via local WMI is already role-tagged by the HTTP/LDAP paths; the site code is the whole point. On a Local-only run this is the sole site-code source.
- Modify: `sccm/sccm/src/openhound_sccm/collectors/ldap.py` — `ldap_management_points_raw` (298-306): add `fsp_sid` to the yielded row. **Verified 2026-07-27:** the FSP's SID is already resolved at [ldap.py:291](../../src/openhound_sccm/collectors/ldap.py) (`fsp_sid = fsp_target.ad_object.get("object_sid")`) but is used only to build a log-message suffix and never reaches the row. Hoist it out of the `if fsp_target:` block into a variable initialised to `None`, and add `"fsp_sid": fsp_sid` beside the existing `"fsp_hostname"` key. Without this the transform has only a hostname and would have to invent an id.
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_node_computer` (367-770): three new arms.
- Test: `sccm/sccm/tests/orphaned_role_sources_test.py`

**Interfaces:**
- Consumes: `http_site_servers` (+ new `mp_host`), `http_management_points` (for the site-code join),
  `ldap_management_points_raw` (`fsp_hostname`, `site_code`), `dns_management_points` (+ new `site_code`).
- Produces: `node_computer` rows carrying `SMS Site Server@<site>`, `SMS Fallback Status Point@<site>`,
  and `SMS Management Point@<site>` from these three sources, which today contribute no role at all.

- [ ] **Step 1: Collector change — stamp `mp_host` on the site-server row (D6)**

`_role_row` builds the role as `f"{role_base}@{site_code}" if site_code else role_base` (http.py:180), and
`_sitesigncert_probe` passes `target_entry.site_code` — populated only by LDAP discovery. In a no-LDAP run
it is `None`, so the role is the bare `SMS Site Server`, which matches neither `LIKE 'SMS Site Server@%'`
nor the generic `LIKE '%@%'` the edge builders use. The site server would become a node with no edges —
exactly the credential-free scenario this table exists for.

Per D6 the fix is *not* to guess a site code and *not* to reorder the probes (sitesigncert runs first per
ps1:8611). The sitesigncert endpoint is an MP endpoint, so a valid cert response proves the probed host is
an MP, and the cert's issuer is that MP's site's site server. Record which MP it came from and resolve the
code in the transform. `http_site_versions` already emits exactly this breadcrumb as `mp_host`
(http.py:419-423) — mirror it:

```python
    table, row = _role_row("http_site_servers", ad_object, dns_name, "HTTP-sitesigncert",
                           "SMS Site Server", site_code, None)
    # D6: sitesigncert is an MP endpoint, so the issuer named in the cert is the
    # site server of *this MP's* site. The probe runs before MPKEYINFORMATION has
    # set self.site_code (ps1:8611 ordering, which we must not change), so record
    # the MP we dialed and let the transform join it for the code. Mirrors
    # http_site_versions.mp_host.
    row["mp_host"] = target
    yield table, row
```

Add `mp_host` to the `http_site_servers` raw-table asset so the column survives to DuckDB.

- [ ] **Step 2: Collector change — emit the DNS site code and MP role**

`dns_management_points` knows the site code authoritatively (it is the SRV query key) but passes it only to
`register_target(...)` and then yields `target.ad_object` alone, so the row reaches DuckDB with no site
code and no role. Emit them, matching `_role_row`'s shape:

```python
                if target:
                    logger.info("Found management point: %s:%s (site: %s)", target_host, port, site_code)
                    # The SRV query key IS the site code, so this attribution is
                    # authoritative (D6) -- emit it plus the role rather than a
                    # bare AD object, so _node_computer can tag the host.
                    yield {
                        **target.ad_object,
                        "source": f"DNS-SRV-{site_code}",
                        "sccm_infra": True,
                        "sccm_site_system_roles": f"SMS Management Point@{site_code}",
                        "site_code": site_code,
                    }
```

Apply the same to the ADIDNS fallback branch (dns.py:131-141). Update the `dns_management_points`
raw-table asset with the new columns.

- [ ] **Step 3: Write the failing test**

```python
# sccm/sccm/tests/orphaned_role_sources_test.py
import duckdb
from openhound_sccm.transforms import _node_computer

SCHEMA = "sccm"

def _con():
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    return con

def _roles_for(con, sid):
    row = con.execute(f"SELECT site_system_roles FROM {SCHEMA}.node_computer "
                      f"WHERE sid = ?", [sid]).fetchone()
    return set(row[0]) if row else set()

def test_site_server_takes_site_code_from_the_mp_that_served_the_cert():
    con = _con()
    # Anonymous run: the sitesigncert row has no site code of its own, but the MP
    # it was read from learned one from MPKEYINFORMATION.
    con.execute(f"CREATE TABLE {SCHEMA}.http_site_servers "
                "(sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
                " site_code VARCHAR, mp_host VARCHAR, sccm_infra BOOLEAN)")
    con.execute(f"INSERT INTO {SCHEMA}.http_site_servers "
                "VALUES ('S-1-SS','PS1-SITE','SMS Site Server',NULL,'ps1-mp.mayyhem.com',true)")
    con.execute(f"CREATE TABLE {SCHEMA}.http_management_points "
                "(sid VARCHAR, name VARCHAR, site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.http_management_points "
                "VALUES ('S-1-MP','ps1-mp.mayyhem.com','PS1')")
    _node_computer(con, SCHEMA)
    assert "SMS Site Server@PS1" in _roles_for(con, "S-1-SS")

def test_site_server_keeps_bare_role_when_the_mp_has_no_site_code_either():
    con = _con()
    # D6: never guess. No knowable site -> bare role, no fabricated '@'.
    con.execute(f"CREATE TABLE {SCHEMA}.http_site_servers "
                "(sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
                " site_code VARCHAR, mp_host VARCHAR, sccm_infra BOOLEAN)")
    con.execute(f"INSERT INTO {SCHEMA}.http_site_servers "
                "VALUES ('S-1-SS','PS1-SITE','SMS Site Server',NULL,'ps1-mp.mayyhem.com',true)")
    con.execute(f"CREATE TABLE {SCHEMA}.http_management_points "
                "(sid VARCHAR, name VARCHAR, site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.http_management_points "
                "VALUES ('S-1-MP','ps1-mp.mayyhem.com',NULL)")
    _node_computer(con, SCHEMA)
    assert _roles_for(con, "S-1-SS") == {"SMS Site Server"}

def test_fallback_status_point_gets_a_role():
    con = _con()
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_management_points_raw "
                "(sid VARCHAR, name VARCHAR, site_code VARCHAR, "
                " fsp_hostname VARCHAR, fsp_sid VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.ldap_management_points_raw "
                "VALUES ('S-1-MP','ps1-mp','PS1','ps1-fsp.mayyhem.com','S-1-FSP')")
    _node_computer(con, SCHEMA)
    assert "SMS Fallback Status Point@PS1" in _roles_for(con, "S-1-FSP")

def test_dns_discovered_mp_gets_a_role():
    con = _con()
    con.execute(f"CREATE TABLE {SCHEMA}.dns_management_points "
                "(sid VARCHAR, name VARCHAR, sccm_site_system_roles VARCHAR, "
                " site_code VARCHAR, sccm_infra BOOLEAN)")
    con.execute(f"INSERT INTO {SCHEMA}.dns_management_points "
                "VALUES ('S-1-MP','ps1-mp','SMS Management Point@PS1','PS1',true)")
    _node_computer(con, SCHEMA)
    assert "SMS Management Point@PS1" in _roles_for(con, "S-1-MP")
```

> Adapt the input column names to what the raw-table assets actually declare (read
> `models/raw_table.py` / the asset definitions first) and the output column name
> (`site_system_roles` vs `roles`) to what `_node_computer` really produces — the
> behavioral assertions are the contract, not the column spellings.

- [ ] **Step 4: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/orphaned_role_sources_test.py -v`
Expected: FAIL — none of the three tables is read by `_node_computer` today.

- [ ] **Step 5: Add the three `_node_computer` arms**

Add `"http_site_servers"` and `"dns_management_points"` to the `_ensure_columns` loop (transforms.py:426-432),
then three INSERT arms modeled on the existing `http_smsproviders` block (636-703).

*Site server* — the only arm needing a join. Resolve the site code from the MP that served the cert, and
leave the role bare when neither side knows one (D6 forbids inventing it):

```python
    # --- http_site_servers: role site code via the MP that served the cert (D6) ---
    _safe(
        con,
        "node_computer<-http_site_servers",
        f"INSERT INTO {schema}.node_computer BY NAME "
        f"SELECT upper(ss.sid) AS sid, ss.name, ... "
        f"  CASE WHEN coalesce(ss.site_code, mp.site_code) IS NULL "
        f"       THEN ['SMS Site Server'] "
        f"       ELSE ['SMS Site Server@' || coalesce(ss.site_code, mp.site_code)] END AS roles, "
        f"  true AS sccm_infra "
        f"FROM {schema}.http_site_servers ss "
        f"LEFT JOIN {schema}.http_management_points mp "
        f"       ON lower(mp.name) = lower(ss.mp_host) "
        f"WHERE ss.sid IS NOT NULL",
    )
```

*Fallback Status Point* — a second host named by the MP-capabilities row, so it keys off `fsp_hostname`,
not the MP's own SID. Mirror the `ldap_cmrc_devices` / `ldap_network_boot_servers` arms (485-532), which
already synthesize a role for a host discovered *by* another row. Check whether the collector records a
resolved SID for the FSP; if it only has the hostname, join to the AD-resolved computer set the same way
those arms do rather than inventing an id.

*DNS MP* — a plain arm, no join: the collector now emits the role string directly (Step 2).

Log at INFO the row count each arm contributed, matching the other arms.

- [ ] **Step 6: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/orphaned_role_sources_test.py -v`
Expected: PASS (4 tests).

- [ ] **Step 7: Green checkpoint.**

---

## Task 1c: Persist the `MSSQLSvc` SPN; give every SQL host a Computer node — decision D2(a)

An `MSSQLSvc` SPN is AD-readable proof the host runs SQL Server. D2(a) says such a host must reach the
graph as `MSSQL_Server` + `Computer` + `MSSQL_HostFor`/`MSSQL_ExecuteOnHost` in **both** flag modes. Three
things stop that today (design spec §4.2). Task 2's SPN predicate also depends on fixing #1 and #2, so
this runs first.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/mssql.py` — `collect_mssql` (28-103).
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_node_computer` (new arm); `_edge_mssql_structural` (3058, resolve-or-drop guard).
- Test: `sccm/sccm/tests/mssql_spn_host_test.py`

**Interfaces:**
- Produces: `mssql_server_instances` rows for SPN hosts **whether or not TCP/1433 answers**, with new
  columns `has_mssql_spn` BOOLEAN and `port_open` BOOLEAN; EPA/encryption fields stay NULL when the port is
  closed. A `node_computer` row per SQL host. `HostFor`/`ExecuteOnHost` only for hosts that resolved.

- [ ] **Step 1: Record the SPN and stop dropping unreachable hosts**

Today `spns` is fetched (mssql.py:41) purely to parse a port, and `if not _check_port(...): return`
(mssql.py:63-65) discards the host when 1433 is filtered — so `mssql_server_instances` is really a
*1433-is-reachable* table. That contradicts D2's "works even when 1433 is filtered" and loses the node
D2(a) requires. Keep the port probe (EPA needs it) but make it non-fatal:

```python
    mssql_spn = next((s for s in spns if s.upper().startswith("MSSQLSvc/")), None) if spns else None
    ...
    port_open = _check_port(target, port)
    if not port_open:
        # An SPN is proof the host runs SQL Server, so it still belongs in the graph
        # (D2a) -- we just cannot probe EPA. Only skip entirely when there is no SPN
        # either, i.e. no evidence of SQL at all.
        if not mssql_spn:
            logger.info("MSSQL port %d closed on %s and no MSSQLSvc SPN; nothing to record", port, target)
            return
        logger.info("MSSQL port %d closed on %s but an MSSQLSvc SPN exists; recording the host "
                    "without EPA data", port, target)
```

Guard the `test_epa(...)` call on `port_open`, and add to the yielded row:

```python
        "has_mssql_spn": mssql_spn is not None,
        "port_open": port_open,
```

Add both columns to the `mssql_server_instances` raw-table asset.

> **Knock-on:** any builder that treats a `mssql_server_instances` row as "EPA was measured" must now
> require the EPA columns instead. Grep `mssql_server_instances` in `transforms.py` (currently only
> `_node_mssql_server` arm 2 at 2380) and check `_edge_coerce_relay_mssql` (3254), which gates on EPA
> values — a NULL EPA must not read as "EPA off".

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/mssql_spn_host_test.py
import duckdb
from openhound_sccm.transforms import _node_computer, _edge_mssql_structural

SCHEMA = "sccm"

def _con():
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.mssql_server_instances "
                "(domain_computer_sid VARCHAR, name VARCHAR, port INTEGER, "
                " has_mssql_spn BOOLEAN, port_open BOOLEAN)")
    con.execute(f"INSERT INTO {SCHEMA}.mssql_server_instances "
                "VALUES ('S-1-DB','ps1-db.mayyhem.com',1433,true,false)")
    return con

def test_spn_host_becomes_a_computer_node_even_with_1433_filtered():
    con = _con()
    _node_computer(con, SCHEMA)
    row = con.execute(f"SELECT sid, sccm_infra FROM {SCHEMA}.node_computer "
                      f"WHERE sid = 'S-1-DB'").fetchone()
    # D2a: the SPN proves it runs SQL. It is NOT thereby SCCM infrastructure.
    assert row is not None and row[1] is False

def test_host_edges_do_not_dangle():
    con = _con()
    _node_computer(con, SCHEMA)
    con.execute(f"CREATE TABLE {SCHEMA}.node_mssql_server "
                "(server_id VARCHAR, host_sid VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES ('S-1-DB:1433','S-1-DB')")
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES ('S-1-GHOST:1433','S-1-GHOST')")
    _edge_mssql_structural(con, SCHEMA)
    ends = {(s, e) for s, e in con.execute(
        f"SELECT start_id, end_id FROM {SCHEMA}.graph_edges "
        f"WHERE kind IN ('MSSQL_HostFor','MSSQL_ExecuteOnHost')").fetchall()}
    assert ("S-1-DB", "S-1-DB:1433") in ends          # resolved host -> edges
    assert not any("S-1-GHOST" in pair for pair in ends)   # unresolved -> dropped, not dangling
```

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_spn_host_test.py -v`
Expected: FAIL — `mssql_server_instances` feeds no `_node_computer` arm, and `_edge_mssql_structural`
(3077-3083) emits host edges with no existence check.

- [ ] **Step 4: Add the `_node_computer` arm and the resolve-or-drop guard**

Add `"mssql_server_instances"` to the `_ensure_columns` loop and one INSERT arm shaped like the others.
Set `sccm_infra = false` and no roles — running SQL is not an SCCM role, and any real role arrives from
another arm and merges on `sid`.

Then bring `_edge_mssql_structural`'s host edges in line with the resolve-or-drop convention its sibling
`_edge_mssql_service_account` already documents (transforms.py:3131) — add
`AND EXISTS (SELECT 1 FROM {schema}.node_computer nc WHERE nc.sid = host_sid)` to both halves of the
`edge_mssql_host` statement, and log at DEBUG each host dropped for want of a Computer node.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_spn_host_test.py -v`
Expected: PASS (2 tests).

- [ ] **Step 6: Green checkpoint.**

---

## Task 2: Non-privileged site-database-server signal (`_assumed_site_dbs`) — decision D2

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — add helper `_assumed_site_dbs`; extend `_mssql_sql_servers` (currently line 2078) with a non-privileged arm.
- Test: `sccm/sccm/tests/assumed_site_db_test.py`

**Interfaces:**
- Consumes: `node_computer` (cols incl. `sid`/`object_sid`, `site_system_roles` VARCHAR[], `sccm_infra`), `mssql_server_instances` (SPN-derived host/port, from `collectors/mssql.py`), `remoteregistry_computers` (role tags incl. `SMS SQL Server@<site>`), and the `disable_possible_edges` flag.
- Produces: `{schema}.assumed_site_dbs(host_sid, site_code, basis)` where `basis` ∈ {`RemoteRegistry`, `SPN+SCCM`}; consumed by Task 4. Also: `_mssql_sql_servers` (now at transforms.py:2293) gains a non-privileged arm sourced from this table, so site DBs no longer come only from privileged `*_site_definitions_computers`.

> **The `SPN+SCCM` basis is possible-edges-gated (D2).** When `--disable-possible-edges` is set,
> `_assumed_site_dbs` emits **only** `RemoteRegistry`-basis rows. A co-located SQL host is not necessarily
> *the* site database, so that inference must not drive site-DB treatment in evidence-only mode.
> **Gate here, once** — every downstream consumer then inherits the filter and no builder needs its own
> basis check.
>
> Nothing confirmed is lost by this. `_node_mssql_server` (transforms.py:2342) merges three independent
> arms keyed on `host_sid:port`; arm 2 (transforms.py:2380-2387) already builds an `MSSQL_Server` for
> **every** `MSSQLSvc` SPN host with `sccm_site = NULL` / `sccm_infra = false`. The flag removes only the
> *characterization* that arm 1 adds — `sccm_site`, `sccm_infra = true`, `databases = ['CM_<site>']` — and
> the Tier-C scaffolding templated off it. The SQL server itself still appears in the graph.

- [ ] **Step 1: Read the current `_mssql_sql_servers`**

Read `transforms.py` around line 2078 (`_mssql_sql_servers`) and 2127-2207 (`_node_mssql_server` 3 arms) to see the exact columns produced (`host_sid`, `server_id`, `site_code`, `sccm_infra`). The new arm must produce the same columns.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/assumed_site_db_test.py
import duckdb
from openhound_sccm.transforms import _assumed_site_dbs

SCHEMA = "sccm"

def _con_with_computers(rows):
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.node_computer "
                "(sid VARCHAR, site_system_roles VARCHAR[], sccm_infra BOOLEAN, mssql_spn BOOLEAN)")
    con.executemany(f"INSERT INTO {SCHEMA}.node_computer VALUES (?,?,?,?)", rows)
    return con

def test_rr_confirmed_site_db_classified():
    con = _con_with_computers([("S-1-DB", ["SMS SQL Server@PS1"], True, False)])
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    r = con.execute(f"SELECT host_sid, site_code, basis FROM {SCHEMA}.assumed_site_dbs").fetchone()
    assert r == ("S-1-DB", "PS1", "RemoteRegistry")

def test_spn_plus_sccm_related_classified():
    con = _con_with_computers([("S-1-DB", ["SMS Site Server@PS1"], True, True)])
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT basis FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == "SPN+SCCM"

def test_arbitrary_sql_host_not_classified():
    # MSSQLSvc SPN but NOT SCCM-related (no SMS role, not sccm_infra) -> excluded.
    con = _con_with_computers([("S-1-RANDOM", [], False, True)])
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=False)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0

def test_spn_fallback_dropped_when_possible_off():
    # D2: SPN + SCCM-relatedness is an inference, so evidence-only mode must not
    # treat the host as the site database. Gated once, here, at the source.
    con = _con_with_computers([("S-1-DB", ["SMS Site Server@PS1"], True, True)])
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=True)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0

def test_rr_confirmed_survives_possible_off():
    con = _con_with_computers([("S-1-DB", ["SMS SQL Server@PS1"], True, False)])
    _assumed_site_dbs(con, SCHEMA, disable_possible_edges=True)
    assert con.execute(f"SELECT basis FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == "RemoteRegistry"
```

> Note: the test models the `MSSQLSvc` SPN presence as a boolean `mssql_spn` column for isolation. In the real transform, derive SPN presence by joining `mssql_server_instances` (SPN-sourced) on `host_sid`; the implementer wires that join in Step 4 and the smoke/live run validates it.

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/assumed_site_db_test.py -v`
Expected: FAIL — `_assumed_site_dbs` does not exist.

- [ ] **Step 4: Implement `_assumed_site_dbs`**

Add near the other MSSQL helpers. RR-confirmed (authoritative) UNION the SPN+SCCM-related fallback:

```python
def _assumed_site_dbs(con: duckdb.DuckDBPyConnection, schema: str,
                      disable_possible_edges: bool) -> None:
    """Identify site database servers without privileged (AdminService) data (D2).

    Primary signal: RemoteRegistry-confirmed 'SMS SQL Server@<site>' role (low-priv
    on a site server). Fallback: a host with an MSSQLSvc SPN that is also
    SCCM-related (carries an SMS role or sccm_infra). This is a deliberate
    tightening of CMBP's 'any host reachable on 1433' rule.

    The fallback is an inference -- a co-located SQL host need not be *the* site
    database -- so --disable-possible-edges drops it and keeps only the
    RemoteRegistry-confirmed rows. Gating here, at the single source, means every
    downstream consumer inherits the filter and no builder repeats the check.
    Confirmed data is untouched: an MSSQLSvc SPN host still gets its MSSQL_Server
    node from the independent SPN/EPA arm of _node_mssql_server, just without the
    sccm_site / sccm_infra / CM_<site> characterization.
    """
    # RemoteRegistry-confirmed: authoritative, emitted in both flag modes.
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.assumed_site_dbs AS "
        f"SELECT sid AS host_sid, "
        f"       upper(split_part(list_filter(site_system_roles, x -> x LIKE 'SMS SQL Server@%')[1], '@', 2)) AS site_code, "
        f"       'RemoteRegistry' AS basis "
        f"FROM {schema}.node_computer "
        f"WHERE len(list_filter(site_system_roles, x -> x LIKE 'SMS SQL Server@%')) > 0"
    )
    if disable_possible_edges:
        n = con.execute(f"SELECT count(*) FROM {schema}.assumed_site_dbs").fetchone()[0]
        logger.info("assumed_site_dbs: --disable-possible-edges set; keeping only the %d "
                    "RemoteRegistry-confirmed site DB(s) and skipping the SPN+SCCM fallback", n)
        return
    # SPN + SCCM-related fallback, for hosts RemoteRegistry did not already confirm.
    _safe(
        con,
        "assumed_site_dbs<-spn",
        f"INSERT INTO {schema}.assumed_site_dbs "
        f"SELECT nc.sid AS host_sid, "
        f"       upper(split_part(list_filter(nc.site_system_roles, x -> x LIKE '%@%')[1], '@', 2)) AS site_code, "
        f"       'SPN+SCCM' AS basis "
        f"FROM {schema}.node_computer nc "
        f"WHERE nc.mssql_spn = true "                       # unit-test stand-in; see the join note below
        f"  AND (nc.sccm_infra = true OR len(nc.site_system_roles) > 0) "
        f"  AND len(list_filter(nc.site_system_roles, x -> x LIKE 'SMS SQL Server@%')) = 0",
    )
```

Replace the `nc.mssql_spn = true` unit-test stand-in with a semi-join on Task 1c's new column:

```python
        f"  AND nc.sid IN (SELECT upper(domain_computer_sid) FROM {schema}.mssql_server_instances "
        f"                 WHERE coalesce(has_mssql_spn, false)) "
```

> **Do not write `sid IN (SELECT host_sid FROM mssql_server_instances)` without the `has_mssql_spn`
> predicate.** Before Task 1c that table only contains hosts whose TCP/1433 answered, so the bare
> semi-join silently tests *port reachability* while appearing to test *SPN presence* — the exact
> weakness D2 claims to avoid ("works even when 1433 is filtered"). Task 1c makes the table SPN-driven and
> adds the flag; the predicate is what keeps the two meanings apart.

Add a `logger.info` reporting the assumed-site-DB count broken down by basis.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/assumed_site_db_test.py -v`
Expected: PASS (5 tests) — the `mssql_spn` boolean stands in for the SPN join in the unit test.

Then extend `_mssql_sql_servers` (transforms.py:2293) with a non-privileged arm sourced from
`assumed_site_dbs`, producing the same columns as the existing privileged arms
(`site_code`, `host_sid`, `dns_host_name`; the `port` / `db_name` / service-account fields keep their
existing `node_site` join and `CM_<site>` fallback). Because `assumed_site_dbs` is already gated, this arm
needs **no** flag check of its own.

- [ ] **Step 6: Green checkpoint.**

---

## Task 3: Provenance stamp helper (`_mark_assumed`) — decision D3

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — add `_mark_assumed`.
- Test: `sccm/sccm/tests/provenance_test.py`

**Interfaces:**
- Produces: `_mark_assumed(props: dict, basis: str) -> dict` — returns `props` with `assumed=True`, `assumptionBasis=<human string>`, and `collectionSource` list gaining `f"Assumed-{basis}"`. Idempotent; preserves existing `collectionSource` entries. Output keys use CMBP-verbatim casing (`assumed`, `assumptionBasis`, `collectionSource`).

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/provenance_test.py
from openhound_sccm.transforms import _mark_assumed

def test_marks_assumed_and_tags_source():
    out = _mark_assumed({"collectionSource": ["LDAP-CmRcService"]},
                        basis="CmRcService SPN; SCCM client not confirmed")
    assert out["assumed"] is True
    assert out["assumptionBasis"] == "CmRcService SPN; SCCM client not confirmed"
    assert "Assumed-CmRcService SPN; SCCM client not confirmed" not in out["collectionSource"]  # tag is slugged, not raw
    assert any(s.startswith("Assumed-") for s in out["collectionSource"])
    assert "LDAP-CmRcService" in out["collectionSource"]  # preserved

def test_idempotent():
    a = _mark_assumed({}, basis="x")
    b = _mark_assumed(dict(a), basis="x")
    assert b["collectionSource"].count(next(s for s in b["collectionSource"] if s.startswith("Assumed-"))) == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/provenance_test.py -v`
Expected: FAIL — `_mark_assumed` not defined.

- [ ] **Step 3: Implement `_mark_assumed`**

```python
def _mark_assumed(props: dict, basis: str) -> dict:
    """Stamp provenance on an assumed (unconfirmed) node/edge property dict (D3).

    Adds assumed=True, a human assumptionBasis, and an 'Assumed-<slug>' entry in
    collectionSource (idempotent). Assumed items still stay traversable — the tag
    is how an operator tells assumed from confirmed, not a suppression.
    """
    props["assumed"] = True
    props["assumptionBasis"] = basis
    slug = "Assumed-" + basis.split(";")[0].strip().replace(" ", "")
    sources = list(props.get("collectionSource") or [])
    if slug not in sources:
        sources.append(slug)
    props["collectionSource"] = sources
    return props
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/provenance_test.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Green checkpoint.**

> Note: SQL-built edges (most of transforms.py) can't call a Python dict helper mid-query. For those, add the equivalent columns directly in the INSERT (`true AS assumed`, `'<basis>' AS assumptionBasis`, `list_append(collectionSource, 'Assumed-<slug>')`). `_mark_assumed` is for any Python-side row construction; the SQL builders in Tasks 4-5 inline the same three fields. Keep the slug/basis strings identical between the two paths.

---

## Task 4: Tier-C MSSQL scaffolding off `assumed_site_dbs`, provenance by basis

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — **`_node_mssql_server` arm 1** (see the ownership note below), `_node_mssql_database`, `_node_mssql_login`, `_node_mssql_database_user`, `_node_mssql_server_role`, `_node_mssql_database_role`; edge builders `_edge_mssql_structural`, `_edge_mssql_membership`, `_edge_coerce_relay_mssql`. **Line numbers in this task are stale** — re-derive with `grep -n '^def _node_mssql\|^def _edge_mssql\|^def _edge_coerce_relay_mssql' transforms.py`.

> **Ownership gap found in the Task 2 review (2026-07-27) — `_node_mssql_server` arm 1 must be added to this task.** Arm 1 reads `_mssql_sql_servers` unconditionally and stamps `sccm_infra = true`, `sccm_site`, `databases = ['CM_<site>']` and `collection_source = ['SCCM_Add-MSSQLServerNodesAndEdges']`. Once Task 2 lands, SPN+SCCM-*inferred* site DBs flow into that same arm — so the `MSSQL_Server` node would claim SCCM-privileged provenance for an inference, with **no** `assumed` marker, while the databases/logins/roles hanging off it are correctly stamped. Apply this task's basis-derived provenance to arm 1 too: join `assumed_site_dbs` on `host_sid`, and for `basis = 'SPN+SCCM'` set `assumed = true` + `assumptionBasis` and use an `Assumed-SiteDB` collection source rather than the privileged tag.
>
> **Never emit `basis` verbatim as a node/edge property.** `_assumed_site_dbs` labels a row `RemoteRegistry` whenever the merged `SMS SQL Server@<site>` role tag is present, regardless of which transport actually produced that tag — an AdminService/WMI-derived role is labelled `RemoteRegistry` too. That conflation is intentional (all three are one confirmed class) and harmless while `basis` is only ever tested with `basis = 'SPN+SCCM'`, but it becomes a real provenance lie the moment the literal is written into the graph. Test it; never surface it.
- Test: `sccm/sccm/tests/mssql_scaffold_possible_test.py`

**Interfaces:**
- Consumes: `{schema}.assumed_site_dbs` (Task 2) — already possible-edges-filtered, so **these builders take no flag parameter**. The sole exception is `_edge_coerce_relay_mssql`, which keeps `disable_possible_edges` for its EPA-off assumption (threaded via env `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES` — confirm the exact accessor while reading).
- Produces: the MSSQL scaffolding (`MSSQL_Database` `CM_<site>`, sysadmin/db_owner roles, machine-account logins/users, `MSSQL_Contains`/`Control*`/`HasLogin`/`IsMappedTo`/`MemberOf`) built off every `assumed_site_dbs` row. Rows whose `basis` is `SPN+SCCM` carry `assumed=true`/`assumptionBasis`/`Assumed-*`; RemoteRegistry- and privileged-confirmed rows carry no `assumed` stamp and a `SCCM-SiteDBDefaultSchema` collection source. Under `--disable-possible-edges` the `SPN+SCCM` rows are simply absent (Task 2), so the assumed scaffolding disappears while the confirmed scaffolding is untouched.

> **Line numbers in this task were stale** and are corrected above against the current `transforms.py`. Re-verify with `grep -n '^def _node_mssql\|^def _edge_mssql' transforms.py` before editing — the file has moved since the plan was written.

- [ ] **Step 1: Read the current MSSQL node/edge builders**

Read `transforms.py` 2293-2340 (`_mssql_sql_servers`), 2342-2424 (`_node_mssql_server`'s three merge arms), 2425 onward (the scaffold node builders), 3058-3122 (structural/membership edges), 3254 (`_edge_coerce_relay_mssql`). Note which read `_mssql_sql_servers` and how the site-DB rows flow in.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/mssql_scaffold_possible_test.py
import duckdb
from openhound_sccm.transforms import _assumed_site_dbs, _node_mssql_database

SCHEMA = "sccm"

def _base(basis):
    """One site DB of the given basis, plus its MSSQL_Server."""
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.assumed_site_dbs (host_sid VARCHAR, site_code VARCHAR, basis VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.assumed_site_dbs VALUES ('S-1-DB','PS1',?)", [basis])
    con.execute(f"CREATE TABLE {SCHEMA}.node_mssql_server (server_id VARCHAR, host_sid VARCHAR, sccm_infra BOOLEAN)")
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES ('S-1-DB:1433','S-1-DB',true)")
    return con

def test_confirmed_site_db_scaffolding_is_not_marked_assumed():
    # RemoteRegistry confirmed this host IS the site database, so the schema SCCM
    # requires on it is a consequence of that fact -- not a "possible" edge.
    con = _base(basis="RemoteRegistry")
    _node_mssql_database(con, SCHEMA)
    r = con.execute(f"SELECT name, assumed FROM {SCHEMA}.node_mssql_database").fetchone()
    assert r[0] == "CM_PS1" and not r[1]

def test_assumed_site_db_scaffolding_is_marked():
    con = _base(basis="SPN+SCCM")
    _node_mssql_database(con, SCHEMA)
    r = con.execute(f"SELECT name, assumed FROM {SCHEMA}.node_mssql_database").fetchone()
    assert r[0] == "CM_PS1" and r[1] is True

def test_builder_has_no_flag_of_its_own():
    # The possible-edges filter lives in Task 2, upstream. An empty table under the
    # flag is what suppresses the scaffolding -- this builder must not re-decide it.
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.assumed_site_dbs (host_sid VARCHAR, site_code VARCHAR, basis VARCHAR)")
    con.execute(f"CREATE TABLE {SCHEMA}.node_mssql_server (server_id VARCHAR, host_sid VARCHAR, sccm_infra BOOLEAN)")
    _node_mssql_database(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.node_mssql_database").fetchone()[0] == 0
```

> **A confirmed site DB keeps its full scaffolding, in both modes** (spec §7). Once RemoteRegistry /
> AdminService / WMI confirms the host *is* the site database, the structure SCCM requires and defaults to
> there — `CM_<site>`, sysadmin, db_owner, the site-server/provider machine-account logins and users — is a
> consequence of that confirmed fact, not a possible edge. So it emits unflagged and unstamped.
>
> **Consequence: these builders take no `disable_possible_edges` parameter at all.** Task 2 already dropped
> the `SPN+SCCM` rows upstream, so under the flag `assumed_site_dbs` simply contains less and the
> scaffolding has nothing to build from. Re-checking the flag here would be a second, independent policy
> that could drift from the first. `basis` is still read — but only to decide the *provenance stamp*
> (`SPN+SCCM` → `assumed = true` + `assumptionBasis` + `Assumed-*`; otherwise unstamped, with
> `collectionSource` recording that the row came from the SCCM default schema rather than from SQL).
>
> The one exception is `_edge_coerce_relay_mssql`, which keeps the flag for its EPA-off assumption — that is
> independent of how the site DB was identified.

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_scaffold_possible_test.py -v`
Expected: FAIL — builders don't yet source `assumed_site_dbs` or derive provenance from `basis`.

- [ ] **Step 4: Rewire each scaffold builder to source `assumed_site_dbs` + gate + provenance**

For `_node_mssql_database`: build one `MSSQL_Database` per `assumed_site_dbs` row, linked to the `MSSQL_Server` by `host_sid`, name per the existing `coalesce(node_site.sql_database_name, 'CM_' || site_code)` rule (transforms.py:2331). No flag parameter — derive the provenance from `basis` alone:

```sql
    -- basis drives the STAMP, not a gate: --disable-possible-edges already emptied
    -- the SPN+SCCM rows upstream (Task 2). A RemoteRegistry/privileged-confirmed
    -- site DB carries the SCCM-required schema as a consequence of the confirmation,
    -- so it is not marked assumed (spec 7).
    CASE WHEN a.basis = 'SPN+SCCM' THEN true ELSE false END AS assumed,
    CASE WHEN a.basis = 'SPN+SCCM'
         THEN 'site DB inferred from MSSQLSvc SPN + SCCM-relatedness; DB internals not observed'
         ELSE NULL END AS assumptionBasis,
    CASE WHEN a.basis = 'SPN+SCCM'
         THEN ['Assumed-SiteDB'] ELSE ['SCCM-SiteDBDefaultSchema'] END AS collectionSource
```

The `SCCM-SiteDBDefaultSchema` tag keeps the derivation auditable — an operator can still tell "sysadmin inferred from SCCM requirements" from "sysadmin read out of SQL" — without implying the row is doubtful.

Apply the same pattern (source from `assumed_site_dbs`, basis-derived provenance, no flag parameter) to `_node_mssql_server_role` (sysadmin), `_node_mssql_database_role` (db_owner), `_node_mssql_login` + `_node_mssql_database_user` (machine-account logins for hosts whose `site_system_roles` include `SMS Site Server@<site>`/`SMS Provider@<site>`), and the edge builders `_edge_mssql_structural` and `_edge_mssql_membership`. `_edge_coerce_relay_mssql` is the exception that keeps `disable_possible_edges`, for its EPA-off assumption only.

Keep the existing privileged arms intact (they already emit confirmed, un-assumed rows); the new arm is additive and de-duplicates by node id (privileged/confirmed wins — do not stamp `assumed` on a row that also has a confirmed source).

> `_edge_mssql_structural` is also touched by Task 1c (the resolve-or-drop guard on the host edges). Its `MSSQL_HostFor`/`MSSQL_ExecuteOnHost` half is **confirmed and ungated** per D2(a) — only the sysadmin/database/db_owner halves are template. Do not let this task's early return suppress the host edges.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_scaffold_possible_test.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Green checkpoint.**

---

## Task 5: Tier-B SCCM edges — provenance tags now that `site_hierarchy` is populated

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_edge_assign_all_permissions` (2752), `_edge_coerce_relay_adminservice` (2965), `_edge_coerce_relay_smb` (3082), `_edge_local_admin_required` (grep for it), `_edge_replication` (2338).
- Test: `sccm/sccm/tests/sccm_possible_edges_lowpriv_test.py`

**Interfaces:**
- Consumes: `site_hierarchy` (Task 1, now non-empty at low-priv), `node_computer.site_system_roles` (Task 1b adds the site-server / FSP / DNS-MP tags these builders match on).
- Produces: these edges now emit at low-priv (they already build once `nonsec` is non-empty — Task 1 does that); the assumption-derived ones gain `assumed`/`assumptionBasis`/`Assumed-*`. `_edge_replication` stays confirmed (topology), NOT assumed.

> **Depends on Task 1b.** `_edge_local_admin_required` and `_edge_coerce_relay_smb` match any `role LIKE '%@%'`, and `_edge_coerce_relay_adminservice` matches `SMS Site Server@%`. Running this task before 1b silently under-emits: the cert-discovered site server and any FSP-only host carry no role at all and are skipped without a warning.

- [ ] **Step 1: Confirm the Task-1 unblock end-to-end (integration-style offline test)**

```python
# sccm/sccm/tests/sccm_possible_edges_lowpriv_test.py
import duckdb
from openhound_sccm.transforms import _site_hierarchy, _edge_assign_all_permissions

SCHEMA = "sccm"

def _con():
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    # LDAP-only hierarchy: single Primary PS1 (root via type=2, parentless).
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_management_points_raw "
                "(site_code VARCHAR, site_type VARCHAR, parent_site_code VARCHAR, root_site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES ('PS1','Primary Site','None','PS1')")
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    # One computer tagged SMS Provider@PS1 (from HTTP SMS_Identification at low-priv).
    con.execute(f"CREATE TABLE {SCHEMA}.node_computer (id VARCHAR, sid VARCHAR, site_system_roles VARCHAR[])")
    con.execute(f"INSERT INTO {SCHEMA}.node_computer VALUES ('C-PROV','S-1-PROV',['SMS Provider@PS1'])")
    con.execute(f"CREATE TABLE {SCHEMA}.node_site (id VARCHAR, site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.node_site VALUES ('SITE-PS1','PS1')")
    return con

def test_assign_all_permissions_emits_at_lowpriv_and_is_marked():
    con = _con()
    _edge_assign_all_permissions(con, SCHEMA, disable_possible_edges=False)
    rows = con.execute(f"SELECT assumed FROM {SCHEMA}.graph_edges "
                       f"WHERE kind = 'SCCM_AssignAllPermissions'").fetchall()
    assert len(rows) >= 1 and all(r[0] is True for r in rows)
```

> Adapt the exact input-table columns/edge-output table (`graph_edges` vs a per-builder table) to what you find in Step-1-of-Task-4's read. The behavioral assertion — "emits at low-priv once `site_hierarchy` is fed, and carries `assumed`" — is the contract.

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/sccm_possible_edges_lowpriv_test.py -v`
Expected: FAIL — edge emits (Task 1 populated the hierarchy) but lacks the `assumed` column.

- [ ] **Step 0 (added 2026-07-27 from the Tasks 1/1b/1c/2 final review): resolve the flag-gating mismatch first.**

Design spec §7 says `--disable-possible-edges` removes "the assumed SCCM permission/coerce/local-admin edges", but `_edge_assign_all_permissions`, `_edge_local_admin_required` and `_edge_coerce_relay_adminservice` **never read the flag** — verified pre-existing at HEAD and untouched by the low-priv work. So today the spec describes behaviour the code does not implement, and this task's premise ("add provenance tags to the assumed families") assumes those families are gated when they are not.

Decide and make the two agree before adding tags: either add the gate (spec becomes true) or amend §7 (doc becomes true). Note the sibling precedent — `edge_coerce_relay_smb_test.py::test_smb_relay_flag_keeps_null_ntlm` deliberately pins flag-independence for the SMB relay's NTLM arm — so gating these three would be a behaviour change with an existing test alongside it expressing the opposite intent. **Ask the human which governs rather than picking.**

- [ ] **Step 3: Add provenance columns to the assumption-derived edge builders**

In `_edge_assign_all_permissions`, `_edge_coerce_relay_adminservice`, `_edge_coerce_relay_smb`, `_edge_local_admin_required`, add to each INSERT's edge-properties: `true AS assumed`, a builder-specific `assumptionBasis` (e.g. AssignAllPermissions → `"SMS Provider role implies site control; RBAC not confirmed"`; CoerceRelay* → `"relay feasibility assumed from role topology + NTLM/SMB-signing state"`), and append the matching `Assumed-*` tag to `collectionSource`. Leave `_edge_replication` unmarked (it is confirmed hierarchy topology, not an assumption). No change to the SQL join logic — Task 1 already made `nonsec` non-empty.

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/sccm_possible_edges_lowpriv_test.py -v`
Expected: PASS.

- [ ] **Step 5: Green checkpoint.**

---

## Task 6: `SCCM_CoerceAndRelayToSMB` traversability + deterministic possible-client ids

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_edge_coerce_relay_smb` (3082); `_node_client_device_possible` (1924).
- Test: `sccm/sccm/tests/coerce_smb_traversable_test.py`

**Interfaces:**
- Produces: `SCCM_CoerceAndRelayToSMB` edges carry `traversable=true`; possible-client-device node ids are deterministic (stable across reruns), not random GUIDs.

- [ ] **Step 1: Read the two functions** — confirm the current traversable value on `_edge_coerce_relay_smb` (CMBP shipped this non-traversable due to a kind-name-mismatch bug; verify OpenHound's value) and confirm `_node_client_device_possible` id construction (per agent map it may already be deterministic — if so, this half is a no-op + a regression test).

- [ ] **Step 2: Write the failing/guard test**

```python
# sccm/sccm/tests/coerce_smb_traversable_test.py
import duckdb
from openhound_sccm.transforms import _node_client_device_possible

SCHEMA = "sccm"

def test_possible_client_ids_are_deterministic():
    def run():
        con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
        con.execute(f"CREATE TABLE {SCHEMA}.ldap_cmrc_devices "
                    "(name VARCHAR, ad_domain_sid VARCHAR, site_code VARCHAR)")
        con.execute(f"INSERT INTO {SCHEMA}.ldap_cmrc_devices VALUES ('PS1-DEV','S-1-DEV','PS1')")
        con.execute(f"CREATE TABLE {SCHEMA}.site_hierarchy "
                    "(site_code VARCHAR, parent_site_code VARCHAR, site_type INTEGER, root_site_code VARCHAR)")
        con.execute(f"INSERT INTO {SCHEMA}.site_hierarchy VALUES ('PS1',NULL,2,'PS1')")
        _node_client_device_possible(con, SCHEMA, disable_possible=False)   # real kwarg is disable_possible (transforms.py:2140)
        return con.execute(f"SELECT id FROM {SCHEMA}.node_client_device").fetchone()[0]
    assert run() == run()   # same id across two independent runs
```

- [ ] **Step 3: Run to verify it fails (or passes if already deterministic)**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/coerce_smb_traversable_test.py -v`
Expected: FAIL if ids are random; PASS if already deterministic (then this is a guard test).

- [ ] **Step 4: Make ids deterministic + ensure SMB relay traversable**

If ids are random, derive them from stable inputs, e.g. `'possible-client-' || lower(ad_domain_sid)` (one possible client per computer SID). In `_edge_coerce_relay_smb`, ensure the emitted edge sets `traversable = true` (match the other coerce builders). Add a comment referencing the CMBP kind-mismatch bug this avoids ([[sccm-stage6-relay-decisions]]).

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/coerce_smb_traversable_test.py -v`
Expected: PASS.

- [ ] **Step 6: Green checkpoint.**

---

## Task 7: Entity-panel help blurbs for assumed edge kinds

**Files:**
- Modify: the edge-help module (grep for the existing edge-help/property-bag pattern — [[bloodhound-opengraph-edge-help-limit]]; likely `src/openhound_sccm/kinds/edge_help.py` or similar).
- Test: `sccm/sccm/tests/edge_help_assumed_test.py`

**Interfaces:**
- Produces: each assumed edge kind (`SCCM_AssignAllPermissions`, `SCCM_LocalAdminRequired`, `SCCM_CoerceAndRelayToAdminService`, `SCCM_CoerceAndRelayToSMB`, `MSSQL_CoerceAndRelayToMSSQL`, `MSSQL_Contains`/`Control*`/`HasLogin`/`IsMappedTo`/`MemberOf` when assumed, `SCCM_SameHostAs`/`SCCM_HasClient`) has a help string stating: the inference rule, the data source, and the false-positive caveat.

- [ ] **Step 1: Read the existing edge-help module** to learn the exact structure (dict keyed by kind → help text) and how it reaches the property bag.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/edge_help_assumed_test.py
from openhound_sccm.kinds import edge_help  # adjust import to the real module

ASSUMED_KINDS = [
    "SCCM_AssignAllPermissions", "SCCM_LocalAdminRequired",
    "SCCM_CoerceAndRelayToAdminService", "SCCM_CoerceAndRelayToSMB",
    "MSSQL_CoerceAndRelayToMSSQL", "SCCM_SameHostAs", "SCCM_HasClient",
]

def test_every_assumed_kind_has_help_with_caveat():
    table = edge_help.HELP  # adjust to the real accessor
    for k in ASSUMED_KINDS:
        assert k in table, f"missing help for {k}"
        assert any(w in table[k].lower() for w in ("assume", "may be", "false positive", "unconfirmed"))
```

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/edge_help_assumed_test.py -v`
Expected: FAIL — missing kinds or missing caveat wording.

- [ ] **Step 4: Add/extend the help entries** with the inference rule + source + caveat for each kind (concrete text per the design-spec §4 table).

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/edge_help_assumed_test.py -v`
Expected: PASS.

- [ ] **Step 6: Green checkpoint.**

---

## Task 8: Documentation — README assumption catalog + ARCHITECTURE section

**Files:**
- Modify: `sccm/sccm/README.md`, `sccm/sccm/ARCHITECTURE.md`.

- [ ] **Step 1: README** — expand the possible-edges/Assumptions section into a catalog table (one row per assumed family: kind, inference rule, data source, false-positive caveat), add a "Requires privileged collection (AdminService/WMI)" callout listing the Tier-D families (design-spec §5), and add copy-pasteable mayyhem examples for default vs `--disable-possible-edges`. Keep it code-truth ([[readme-code-truth-scope]]): only document kinds actually emitted.

- [ ] **Step 1b: README — collection-tier table.** Now that a credential-free run produces real edges, the README should say what each privilege level actually buys: anonymous HTTP/DNS (site code, MP/DP/Provider/Site-Server roles, relay edges), + domain user (LDAP hierarchy with type/parent/root, FSP, SMB shares, RemoteRegistry roles), + AdminService (Tier D RBAC). Include the credential-free example from Task 10 Step 2c.

- [ ] **Step 2: ARCHITECTURE.md** — add a section describing the all-sources-fed `site_hierarchy` (the Task-1 wiring and its `information_schema` discovery loop, why it diverges from a stock AdminService-only build), the D6 site-code attribution rule and the `mp_host` join that implements its one cross-host exception (Task 1b), and the assumption/provenance engine (`_assumed_site_dbs`, `_mark_assumed`, the possible-edges gate and basis filter). Add a changelog entry. Fix any code references the change invalidated (per CLAUDE.md ARCHITECTURE rule).

- [ ] **Step 3: Doc-truth check** — re-read both against the final code; confirm every documented kind is emitted and every assumption row matches a builder. No automated test; this is a manual read.

- [ ] **Step 4: Green checkpoint.**

---

## Task 9: Integration fixtures — low-priv baseline for `--run-integration-tests`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/integration/fixtures/` (edges.py/nodes.py) and `integration/__init__.py`.
- Test: `sccm/sccm/tests/integration_lowpriv_fixtures_test.py`

**Interfaces:**
- Produces: a low-priv-expected fixture set (or per-case tags) capturing what DEFAULT mode should now emit without AdminService (the Tier A+B+C families), distinct from the existing domainadmin baseline. Decide the mechanism during Step 1 (a second fixture list vs a `requires_privilege` flag per case that the runner can partition).

- [ ] **Step 1: Read `integration/fixtures/edges.py`, `nodes.py`, `__init__.py`** and decide the partition mechanism. Recommended: add a `requires_privilege: bool` to `EdgeCase`/`NodeCase` (default False) for the Tier-D families, so a low-priv run asserts only the non-privileged subset.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/integration_lowpriv_fixtures_test.py
from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES

def test_tier_d_cases_flagged_requires_privilege():
    # Only the SCCM RBAC families need AdminService. Everything MSSQL is now
    # low-priv reachable: MSSQL_ServiceAccountFor + HasSession are SPN-derived
    # (Task 13) and GetTGS/GetAdminTGS are built off the site-DB logins (Task 14),
    # so none of them belongs in this set.
    tier_d = {"SCCM_FullAdministrator", "SCCM_IsAssigned", "SCCM_IsMappedTo",
              "SCCM_AllPermissions"}
    for c in MAYYHEM_EDGE_CASES:
        if c.kind in tier_d:
            assert getattr(c, "requires_privilege", False) is True, f"{c.id} must be flagged"
```

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_lowpriv_fixtures_test.py -v`
Expected: FAIL — the attribute/flag doesn't exist yet.

- [ ] **Step 4: Add the `requires_privilege` flag** to the case dataclasses (shared engine change is owner-approved-additive only if truly needed — prefer keeping the flag in the SCCM fixture layer if `EdgeCase` can't be extended without a shared-lib edit; if a shared-lib edit is required, STOP and ask). Flag the Tier-D cases. Update `run_integration_tests` to accept a `privileged: bool` param (default True to preserve current behavior) that filters out `requires_privilege` cases when False.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_lowpriv_fixtures_test.py -v`
Expected: PASS.

- [ ] **Step 6: Green checkpoint.**

---

## Task 10: Live re-validation (no TDD — evidence gathering) — RUN LAST

> **Scope widened by the owner, 2026-07-28: validate BOTH privilege levels, not just low-priv.**
> Everything in this plan was motivated by and measured against `MAYYHEM\lowpriv`, but the changes
> landed in shared code that the **privileged** path runs through too — `_site_hierarchy` now takes
> every site-code source and infers missing site types, `_node_computer` gained four arms,
> `_edge_mssql_structural` gained a resolve-or-drop guard, `_node_mssql_server` changed its
> `dns_host_name` coalesce, and every assumed family gained provenance columns. **A privileged run is
> therefore the regression gate for this entire plan**, and nothing in Tasks 1-14 has exercised it.
> Run the full matrix below; a low-priv-only pass is not sufficient evidence to commit.
>
> | run | identity | how | integration tests |
> |---|---|---|---|
> | 1 | `MAYYHEM\lowpriv` | OpenHound `-u/-p`; CMBP via `Run-AsNetOnly.ps1` | `privileged=False` |
> | 2 | `MAYYHEM\domainadmin` | current logon context — OpenHound with **no** `-u/-p`; CMBP directly | `privileged=True` |
>
> Each identity runs both flag states (default and `--disable-possible-edges`) for **both** tools =
> 8 collections. Compare each OpenHound run against the CMBP zip from the **same identity and same
> day** — §0 of `SUMMARY-20260728.md` records why a cross-day baseline is worthless here (`ps1-sms`
> was down on 2026-07-23, so CMBP skipped its AdminService phases: 39 s and 16 AdminService log hits
> vs 3 m 48 s and 188 today).
>
> **The privileged run's pass condition is regression, not parity:** its graph must be no smaller than
> a pre-plan privileged baseline in any edge or node kind, and `--run-integration-tests` with
> `privileged=True` must pass the FULL fixture set including the Tier-D cases. If no pre-plan
> privileged baseline exists, capture one first by stashing nothing and instead re-running from a
> clean checkout copy — or state plainly in the summary that the privileged side has a same-day CMBP
> comparison but no before/after.

- [ ] **Step 0 (prerequisite):** every run must pass `--clean`, and every CMBP run must write to its own
  empty directory. Re-running into a used directory silently UNIONs the previous collection's rows
  (11 of 24 raw tables on 2026-07-28). `run-openhound-both.ps1` now passes `--clean`; verify any new
  runner does too.
- [ ] **Step 1:** Re-run the `lowpriv_check` harness end-to-end: `run-cmbp-both.ps1` (already produces CMBP baselines) and `run-openhound-both.ps1` (default + `--disable-possible-edges`), both as `MAYYHEM\lowpriv` via the netonly launcher.
- [ ] **Step 1b:** Run the same matrix as `MAYYHEM\domainadmin` (the current logon context — OpenHound takes no `-u/-p` and CMBP needs no netonly shim), into `privileged_check/`. This is the regression gate described above.
- [ ] **Step 2:** Confirm DEFAULT-mode OpenHound now emits the Tier A+B+C families (client devices, SameHostAs/HasClient, AdminsReplicatedTo, AssignAllPermissions, LocalAdminRequired, CoerceAndRelay{AdminService,SMB,MSSQL}, MSSQL scaffolding) with `assumed`/`assumptionBasis` set, and that `--disable-possible-edges` drops the assumed families while keeping confirmed data.
- [ ] **Step 2b:** Confirm the Task 1/1b wiring landed, by inspecting the lookup DuckDB directly rather than only the graph: `site_hierarchy` is non-empty and names which source tables contributed (the INFO log from Task 1 Step 3); `node_computer` has a row carrying `SMS Site Server@<site>` sourced from `HTTP-sitesigncert`; the FSP host carries `SMS Fallback Status Point@<site>`. Check the `mp_host` join actually resolved — a NULL `mp_host` or an unmatched join shows up as a bare `SMS Site Server` role, which is silent (D6 says that's correct behavior, so nothing warns). Also check whether the untyped-root WARNING fired: in a run that included LDAP it should **not**, because MP-capabilities carry the site type; if it does, the MP-capabilities arm isn't landing.
- [ ] **Step 2c:** Run one **credential-free** pass (no domain creds, HTTP+DNS phases only) against the mayyhem MP and confirm it alone yields a site code, a Site Server role, and the `SCCM_LocalAdminRequired` / `SCCM_CoerceAndRelayToAdminService` edges. This is the scenario §4.1 exists for and nothing else in the plan exercises it.
- [ ] **Step 2d:** Confirm the D2 split on the live SQL host: `ps1-db.mayyhem.com` has an `MSSQL_Server` node, a `Computer` node, and both host edges in **both** flag modes; and that under `--disable-possible-edges` it is not labelled the site database (no `sccm_site`, `sccm_infra = false`) unless RemoteRegistry actually confirmed it. Exercise the filtered-port path too — block 1433 (or point at a host with SQL stopped) and confirm the SPN alone still produces the node with NULL EPA fields, and that `MSSQL_CoerceAndRelayToMSSQL` does **not** fire off those NULLs.
- [ ] **Step 2e:** Confirm the confirmed-vs-assumed scaffolding split on the same host. In the low-priv run where RemoteRegistry reached the site server, `--disable-possible-edges` should still emit the full `CM_<site>` / sysadmin / db_owner / machine-account-login set with **no** `assumed` property and a `SCCM-SiteDBDefaultSchema` collection source. Also confirm `HasSession` is present in both modes (both arms), and that the mayyhem hierarchy resolves a **typed** root (CAS) in both modes — so the D4 gate never fires there. To exercise the gate deliberately, reprocess a cached bucket with the LDAP MP-capabilities table emptied and two sites present, and confirm possible-OFF leaves `root_site_code` NULL and warns.
- [ ] **Step 3:** Confirm NO Tier-D fabrication (no `SCCM_FullAdministrator`/`IsAssigned`/`AllPermissions`, no `MSSQL_GetTGS`/service-account edges) unless privileged data was actually collected.
- [ ] **Step 4:** Run the integration suite at BOTH privilege levels via the Task 9 partition:
  `run_integration_tests(..., privileged=False)` against the low-priv graph (asserts the
  non-privileged subset) and `privileged=True` against the domainadmin graph (asserts the FULL set
  including Tier D). Nothing on the CLI passes `privileged` yet, so call it in-process. A low-priv
  run that fails a Tier-D case means the partition is wrong; a privileged run that fails ANY case is
  a regression from this plan and blocks the commit.
- [ ] **Step 4b (privileged regression specifics):** confirm the privileged path still produces what
  only it can — `SCCM_FullAdministrator`, `SCCM_IsAssigned`, `SCCM_AllPermissions`, the admin-user /
  security-role / collection nodes, and `MSSQL_ServiceAccountFor` from the `SMS_SCI_SysResUse` path —
  and that Task 4's provenance work did **not** stamp `assumed` on any privileged-sourced row.
  Cross-check the two site-type inference rules added for the CAS: on a privileged run
  `adminservice_site_definitions` supplies real types, so the inference must fire zero times (its
  INFO line should be absent) and must not have overwritten anything.
- [ ] **Step 5:** Write both summaries — refresh `lowpriv_check/SUMMARY-20260728.md` (its §0 numbers
  predate Tasks 3-14) and add `privileged_check/SUMMARY.md`. State plainly for each side whether it
  has a same-day CMBP comparison, a before/after, or only one of the two. Green checkpoint (no commit).

---

## Task 11: System Management container `Container` node + `GenericAll` edges (confirmed, both modes)

Wires up the already-collected-but-discarded `ldap_system_management_dacl`. Uses **standard BloodHound base kinds** (`Container`, `GenericAll`) so it composes with SharpHound — do NOT add these to `schema_SCCM.json`.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/ldap.py` — `ldap_system_management_dacl` (521): add `objectGUID`, `distinguishedName`, `name` to the container query (currently only `nTSecurityDescriptor`, line 545); stamp each yielded principal row with `smc_container_guid` + `smc_container_dn` (read once from `results[0]`).
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — add `_node_smc_container` + `_edge_generic_all_smc`; register both in the convert pipeline (near the other node/edge builders, e.g. after `_edge_has_member`).
- Modify: `sccm/sccm/src/openhound_sccm/kinds/nodes.py` + `kinds/edges.py` — add `CONTAINER = "Container"` and `GENERIC_ALL = "GenericAll"` constants if absent (base kinds; NOT added to `schema_SCCM.json`).
- Test: `sccm/sccm/tests/smc_container_test.py`

**Interfaces:**
- Consumes: `ldap_system_management_dacl` raw table (per-principal rows: `object_sid`, `object_class`, `sam_account_name`, and the new `smc_container_guid`/`smc_container_dn`).
- Produces: one `Container`/`Base` node id = upper(`smc_container_guid`) (matches SharpHound's objectid so the two merge); one `GenericAll` edge per principal, `start_id = upper(object_sid)`, `end_id = <container guid>`, `traversable = true`.

- [ ] **Step 1: Add the container identity to the collector**

In `ldap_system_management_dacl`, change the container query `attributes=["nTSecurityDescriptor"]` (line 545) to `attributes=["nTSecurityDescriptor", "objectGUID", "distinguishedName", "name"]`. After reading `results[0]`, capture:

```python
    container_guid = results[0].get("objectGUID")   # bytes or str depending on the client; normalize to the SharpHound GUID string
    container_dn = results[0].get("distinguishedName") or system_mgmt_dn
```

Then in the per-principal `yield ad_obj`, stamp the container identity so the transform can build both the node and the edge from one table:

```python
        ad_obj["smc_container_guid"] = _format_guid(container_guid)  # match SharpHound's uppercase GUID format
        ad_obj["smc_container_dn"] = container_dn
        yield ad_obj
```

If a `_format_guid` helper is not already present, add one that renders the AD `objectGUID` in the same canonical uppercase form SharpHound uses for BloodHound `objectid` (so the nodes merge). Log at debug the resolved container GUID.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/smc_container_test.py
import duckdb
from openhound_sccm.transforms import _node_smc_container, _edge_generic_all_smc

SCHEMA = "sccm"

def _con():
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_system_management_dacl "
                "(object_sid VARCHAR, object_class VARCHAR[], sam_account_name VARCHAR, "
                " smc_container_guid VARCHAR, smc_container_dn VARCHAR)")
    con.executemany(f"INSERT INTO {SCHEMA}.ldap_system_management_dacl VALUES (?,?,?,?,?)", [
        ("S-1-5-21-1-513", ["group"], "Domain Admins", "AAAA-GUID", "CN=System Management,CN=System,DC=x"),
        ("S-1-5-21-1-1104", ["computer"], "PS1-PSS$", "AAAA-GUID", "CN=System Management,CN=System,DC=x"),
    ])
    return con

def test_single_container_node_merges_by_guid():
    con = _con()
    _node_smc_container(con, SCHEMA)
    rows = con.execute(f"SELECT id, kinds FROM {SCHEMA}.node_container").fetchall()
    assert len(rows) == 1 and rows[0][0] == "AAAA-GUID"
    assert "Container" in rows[0][1] and "Base" in rows[0][1]

def test_generic_all_edge_per_principal():
    con = _con()
    _edge_generic_all_smc(con, SCHEMA)
    edges = con.execute(f"SELECT start_id, end_id, kind, traversable FROM {SCHEMA}.graph_edges "
                        f"WHERE kind = 'GenericAll'").fetchall()
    assert {e[0] for e in edges} == {"S-1-5-21-1-513", "S-1-5-21-1-1104"}
    assert all(e[1] == "AAAA-GUID" and e[3] is True for e in edges)
```

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/smc_container_test.py -v`
Expected: FAIL — builders not defined.

- [ ] **Step 4: Implement the two builders**

```python
def _node_smc_container(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One Container node for the System Management container, keyed by its objectGUID
    so it merges with SharpHound's node (base BloodHound kind — not a custom SCCM kind)."""
    _safe(con, "node_smc_container",
          f"CREATE OR REPLACE TABLE {schema}.node_container AS "
          f"SELECT DISTINCT upper(smc_container_guid) AS id, ['Container','Base'] AS kinds, "
          f"       any_value(smc_container_dn) AS distinguishedName "
          f"FROM {schema}.ldap_system_management_dacl "
          f"WHERE smc_container_guid IS NOT NULL GROUP BY upper(smc_container_guid)")

def _edge_generic_all_smc(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """GenericAll from each Full-Control principal to the System Management container
    (base BloodHound edge; traversable so pathfinding uses it)."""
    _safe(con, "edge_generic_all_smc",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(object_sid) AS start_id, upper(smc_container_guid) AS end_id, "
          f"       'GenericAll' AS kind, true AS traversable, "
          f"       ['LDAP-GenericAllSystemManagement'] AS collection_source "
          f"FROM {schema}.ldap_system_management_dacl "
          f"WHERE object_sid IS NOT NULL AND smc_container_guid IS NOT NULL")
```

Adapt the exact `graph_edges` column set / `node_*` emission convention to what the convert stage expects (read a sibling builder like `_edge_has_member` first). Register both in the convert pipeline. `GenericAll`/`Container` are base kinds → confirm they are NOT written into `schema_SCCM.json`.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/smc_container_test.py -v`
Expected: PASS (2 tests).

- [ ] **Step 6: Green checkpoint.**

---

## Task 12: `MemberOf` edges for System Management DACL group members (confirmed, both modes)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/ldap.py` — `_expand_group_targets` (618): yield membership rows (a new raw resource/table `ldap_smc_group_members`) as it walks each Full-Control group's `member` list; resolve each direct member DN to its `objectSid` via a BASE search.
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — add `_edge_member_of_smc`; register in convert.
- Modify: `kinds/edges.py` — ensure `MEMBER_OF = "MemberOf"` constant exists (it does, line 18).
- Test: `sccm/sccm/tests/smc_memberof_test.py`

**Interfaces:**
- Consumes: `ldap_smc_group_members` raw table (`group_sid`, `member_sid`, `member_type`).
- Produces: `MemberOf` edges `start_id = upper(member_sid)`, `end_id = upper(group_sid)`, base kind, `traversable = true`. Scope = the **full nested membership** the existing recursive `_expand_group_targets` walk already visits — a `MemberOf` row for every member→containing-group hop at every nesting level (users, groups, computers). Not just direct members: we already pay for the recursion (for target registration), so emit the complete chain. BloodHound de-dupes against SharpHound.

- [ ] **Step 1: Persist every membership hop during the existing recursive walk**

`_expand_group_targets` (618) already recurses the entire nested-group tree with a `visited` guard, reading each group's `member` list (line 628) and recursing into nested groups. Extend it so that at **every** level, for **every** direct member of the group currently being expanded, it records a `(group_sid, member_sid, member_type)` row — resolving the member DN to its `objectSid` via a BASE search. Because the recursion already descends nested groups, accumulating one row per (member, its-immediate-parent-group) at each level yields the full nested `MemberOf` chain automatically; the `visited` set prevents cycles/duplicates.

```python
    for member_dn in members:
        m = next(ctx.ad.paged_search("(objectClass=*)", ["objectSid", "objectClass"],
                                     base=member_dn, scope=BASE), None) or {}
        member_sid = m.get("object_sid") or m.get("objectSid")
        if not member_sid:
            logger.debug("SMC group member %s has no resolvable objectSid; skipping MemberOf", member_dn)
            continue
        member_classes = m.get("object_class") or ["unknown"]
        rows.append({"group_sid": group_obj.get("object_sid"), "member_sid": member_sid,
                     "member_type": member_classes[-1]})
        # nested group -> recurse (existing behavior); its own members become rows at the next level
        if any(c.lower() == "group" for c in member_classes):
            _expand_group_targets(ctx, m, visited)   # accumulates deeper hops into `rows`
```

Because `_expand_group_targets` is a helper (not a `@app.resource`), route the accumulated `rows` out the same way the DACL resource emits: have the helper accumulate into a shared list (or `return` its rows) that the `ldap_system_management_dacl` resource generator (which already calls it) `yield`s into the `ldap_smc_group_members` table. Grep other collectors for a helper whose rows a resource re-yields into a distinct table and mirror that. Keep the existing computer-target registration side effect intact.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/smc_memberof_test.py
import duckdb
from openhound_sccm.transforms import _edge_member_of_smc

SCHEMA = "sccm"

def test_memberof_edges_full_nested_chain():
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_smc_group_members "
                "(group_sid VARCHAR, member_sid VARCHAR, member_type VARCHAR)")
    # SMC group 513 contains a nested group 600; 600 contains a user 1201.
    # The recursive collector records BOTH hops (513<-600 and 600<-1201).
    con.executemany(f"INSERT INTO {SCHEMA}.ldap_smc_group_members VALUES (?,?,?)", [
        ("S-1-5-21-1-513", "S-1-5-21-1-600", "group"),
        ("S-1-5-21-1-600", "S-1-5-21-1-1201", "user"),
    ])
    _edge_member_of_smc(con, SCHEMA)
    edges = {(s, e) for s, e in con.execute(
        f"SELECT start_id, end_id FROM {SCHEMA}.graph_edges WHERE kind = 'MemberOf'").fetchall()}
    # both nesting levels present -> user can path transitively to the SMC group
    assert ("S-1-5-21-1-600", "S-1-5-21-1-513") in edges
    assert ("S-1-5-21-1-1201", "S-1-5-21-1-600") in edges
```

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/smc_memberof_test.py -v`
Expected: FAIL — `_edge_member_of_smc` not defined.

- [ ] **Step 4: Implement `_edge_member_of_smc`**

```python
def _edge_member_of_smc(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """MemberOf from direct members of System-Management-DACL groups to the group
    (base BloodHound edge). One hop only; SharpHound/BloodHound supply transitivity.
    Redundant-but-harmless if SharpHound also ran (BloodHound de-dupes identical edges)."""
    _safe(con, "edge_member_of_smc",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT DISTINCT upper(member_sid) AS start_id, upper(group_sid) AS end_id, "
          f"       'MemberOf' AS kind, true AS traversable, "
          f"       ['LDAP-GenericAllSystemManagement'] AS collection_source "
          f"FROM {schema}.ldap_smc_group_members "
          f"WHERE member_sid IS NOT NULL AND group_sid IS NOT NULL")
```

Register in the convert pipeline. Adapt the `graph_edges` column set to the convention confirmed in Task 11 Step 4.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/smc_memberof_test.py -v`
Expected: PASS.

- [ ] **Step 6: Green checkpoint.**

---

## Task 13: `MSSQL_ServiceAccountFor` + `HasSession` from the `MSSQLSvc` SPN holder (confirmed, both modes)

Reference implementation to port from: `mssql/mssql` extension — `edges/derive_ad.py:419 _service_account_edges` (incl. the built-in/virtual-account → host-computer rule at lines 61/447) and `collection/ad_resolve.py` (SPN-holder / service-account resolution). This corrects the earlier Tier-D exclusion of these two kinds.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/mssql.py` — `collect_mssql` (28): resolve the `MSSQLSvc` SPN *holder* account (not just the port). `ctx.ad.get_spns(target)` returns the TARGET computer's own SPNs, which misses SQL running as a domain service account — so search LDAP for `(servicePrincipalName=MSSQLSvc/<target>*)` and take the holder object (`objectSid`, `sam_account_name`, `object_class`). Add `service_account_sid` / `service_account_is_computer` to the yielded `mssql_server_instances` row (currently has `domain_computer_sid`, `port`, EPA fields — mssql.py:93-101).
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — add `_edge_mssql_service_account_spn` (or extend the existing `_edge_mssql_service_account` at 2902 with a non-privileged arm); register in convert.
- Modify: `kinds/edges.py` — ensure `MSSQL_SERVICE_ACCOUNT_FOR` / `HAS_SESSION` constants exist (they do — `HasSession`, `MSSQL_ServiceAccountFor`).
- Test: `sccm/sccm/tests/mssql_service_account_spn_test.py`

**Interfaces:**
- Consumes: `mssql_server_instances` rows with `service_account_sid`, `service_account_is_computer` (bool), `domain_computer_sid` (host), `server_id`.
- Produces: `MSSQL_ServiceAccountFor` (svc account SID → MSSQL server instance) always; `HasSession` (**host computer SID → svc account SID** — direction per `mssql/mssql` derive_ad.py:452-454) UNLESS `service_account_is_computer` (a service running as the machine account has no distinct session — matches derive_ad.py:447-451). Confirmed → emitted in both flag modes, no `assumed` stamp.

- [ ] **Step 1: Read the `mssql/mssql` reference**

Read `mssql/mssql/src/openhound_mssql/edges/derive_ad.py` lines 419-478 (`_service_account_edges`) and 61 (built-in service-account name set), and `collection/ad_resolve.py` `resolve_referenced_objects` / `_resolve_name`. Port the direction (ServiceAccountFor: account→server; HasSession: host→account or account→host per that module's convention) and the built-in/virtual-account handling verbatim in intent.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/mssql_service_account_spn_test.py
import duckdb
from openhound_sccm.transforms import _edge_mssql_service_account_spn

SCHEMA = "sccm"

def _con(rows):
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.mssql_server_instances "
                "(server_id VARCHAR, domain_computer_sid VARCHAR, "
                " service_account_sid VARCHAR, service_account_is_computer BOOLEAN)")
    con.executemany(f"INSERT INTO {SCHEMA}.mssql_server_instances VALUES (?,?,?,?)", rows)
    return con

def test_domain_service_account_gets_both_edges():
    con = _con([("S-1-DB:1433", "S-1-DB", "S-1-SVC", False)])
    _edge_mssql_service_account_spn(con, SCHEMA)
    got = {(k, s, e) for s, e, k in con.execute(
        f"SELECT start_id, end_id, kind FROM {SCHEMA}.graph_edges "
        f"WHERE kind IN ('MSSQL_ServiceAccountFor','HasSession')").fetchall()}
    assert ("MSSQL_ServiceAccountFor", "S-1-SVC", "S-1-DB:1433") in got   # sa -> server
    assert ("HasSession", "S-1-DB", "S-1-SVC") in got                     # host computer -> sa

def test_machine_account_service_skips_hassession():
    con = _con([("S-1-DB:1433", "S-1-DB", "S-1-DB", True)])   # runs as the host machine account
    _edge_mssql_service_account_spn(con, SCHEMA)
    kinds = [r[0] for r in con.execute(f"SELECT kind FROM {SCHEMA}.graph_edges").fetchall()]
    assert "MSSQL_ServiceAccountFor" in kinds and "HasSession" not in kinds
```

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_service_account_spn_test.py -v`
Expected: FAIL — `_edge_mssql_service_account_spn` not defined.

- [ ] **Step 4: Implement the edge builder**

```python
def _edge_mssql_service_account_spn(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """ServiceAccountFor + HasSession from the MSSQLSvc SPN holder (confirmed, low-priv).
    HasSession is skipped when the service runs as the host machine account (no distinct
    session) -- mirrors mssql/mssql edges/derive_ad.py:_service_account_edges."""
    _safe(con, "edge_mssql_service_account_for",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(service_account_sid) AS start_id, server_id AS end_id, "
          f"       'MSSQL_ServiceAccountFor' AS kind, true AS traversable, "
          f"       ['LDAP-MSSQLSvcSPN'] AS collection_source "
          f"FROM {schema}.mssql_server_instances WHERE service_account_sid IS NOT NULL")
    _safe(con, "edge_mssql_has_session",
          # HasSession direction is host computer -> service account (derive_ad.py:452-454).
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(domain_computer_sid) AS start_id, upper(service_account_sid) AS end_id, "
          f"       'HasSession' AS kind, true AS traversable, "
          f"       ['LDAP-MSSQLSvcSPN'] AS collection_source "
          f"FROM {schema}.mssql_server_instances "
          f"WHERE service_account_sid IS NOT NULL AND domain_computer_sid IS NOT NULL "
          f"  AND coalesce(service_account_is_computer, false) = false")
```

Register in the convert pipeline. Align the `graph_edges` column set to the convention confirmed in Task 11 Step 4.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_service_account_spn_test.py -v`
Expected: PASS (2 tests).

- [ ] **Step 6: Green checkpoint.**

---

## Task 14: `MSSQL_GetTGS` + `MSSQL_GetAdminTGS` from the SPN service account (confidence inherited from the login)

Depends on Task 4 (the site-server/provider `MSSQL_Login`s and modeled sysadmin) and Task 13 (SPN-holder service account). Mirrors `mssql/mssql` derive_ad.py:460-476 (`GetAdminTGS` when any domain principal is sysadmin; `GetTGS` to each enabled domain login with CONNECT SQL).

> **These edges inherit the confidence of the login they rest on** — same rule as Task 4, and a direct consequence of "a confirmed site DB keeps its full scaffolding". A login built off a RemoteRegistry/privileged-confirmed site DB is confirmed, so the kerberoast edge from it is confirmed too: emitted in **both** flag modes, no `assumed` stamp. A login built off an `SPN+SCCM` site DB is assumed, so the edge is assumed and stamped. Since `_assumed_site_dbs` already removed the `SPN+SCCM` rows under the flag, those logins do not exist in that mode and the edges cannot be built — no per-builder flag check is needed here either. Carry `basis` (or an `assumed` column) through `node_mssql_login` so this builder can derive the stamp without re-joining `assumed_site_dbs`.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — add `_edge_mssql_kerberoast_spn`; register in convert after Task 13's builder.
- Modify: `kinds/edges.py` — ensure `MSSQL_GET_TGS = "MSSQL_GetTGS"` / `MSSQL_GET_ADMIN_TGS = "MSSQL_GetAdminTGS"` constants exist.
- Test: `sccm/sccm/tests/mssql_kerberoast_spn_test.py`

**Interfaces:**
- Consumes: `mssql_server_instances` (`service_account_sid`, `server_id`) + `node_mssql_login` (Task 4's site-server/provider logins, each with `login_id`, `is_domain`, `is_sysadmin`, **and the `assumed` flag Task 4 stamps**).
- Produces: `MSSQL_GetAdminTGS` (svc account SID → server instance) when at least one login is a domain sysadmin; `MSSQL_GetTGS` (svc account SID → each domain login). Both `traversable = true`. `assumed` mirrors the source login: an RR/privileged-confirmed site DB yields unstamped, confirmed edges present in both flag modes; an `SPN+SCCM` site DB yields stamped edges that exist only under possible-ON, because Task 2 removed those logins otherwise. **No flag parameter on this builder.**

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/mssql_kerberoast_spn_test.py
import duckdb
from openhound_sccm.transforms import _edge_mssql_kerberoast_spn

SCHEMA = "sccm"

def _con():
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.mssql_server_instances "
                "(server_id VARCHAR, service_account_sid VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.mssql_server_instances VALUES ('S-1-DB:1433','S-1-SVC')")
    con.execute(f"CREATE TABLE {SCHEMA}.node_mssql_login "
                "(login_id VARCHAR, server_id VARCHAR, is_domain BOOLEAN, is_sysadmin BOOLEAN, "
                " assumed BOOLEAN)")
    return con

def _login(con, assumed):
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_login "
                "VALUES ('S-1-PSS$@S-1-DB:1433','S-1-DB:1433',true,true,?)", [assumed])

def test_getadmin_and_gettgs_built_from_a_sysadmin_login():
    con = _con(); _login(con, assumed=True)
    _edge_mssql_kerberoast_spn(con, SCHEMA)
    got = {(k, s, e) for s, e, k in con.execute(
        f"SELECT start_id, end_id, kind FROM {SCHEMA}.graph_edges "
        f"WHERE kind IN ('MSSQL_GetAdminTGS','MSSQL_GetTGS')").fetchall()}
    assert ("MSSQL_GetAdminTGS", "S-1-SVC", "S-1-DB:1433") in got
    assert ("MSSQL_GetTGS", "S-1-SVC", "S-1-PSS$@S-1-DB:1433") in got

def test_edge_inherits_the_confidence_of_its_login():
    # Login off a confirmed site DB -> confirmed edge, no stamp.
    con = _con(); _login(con, assumed=False)
    _edge_mssql_kerberoast_spn(con, SCHEMA)
    assert not con.execute(f"SELECT DISTINCT assumed FROM {SCHEMA}.graph_edges").fetchone()[0]
    # Login off an SPN+SCCM site DB -> assumed edge, stamped.
    con = _con(); _login(con, assumed=True)
    _edge_mssql_kerberoast_spn(con, SCHEMA)
    assert con.execute(f"SELECT DISTINCT assumed FROM {SCHEMA}.graph_edges").fetchone()[0] is True

def test_no_logins_means_no_edges():
    # Under --disable-possible-edges an SPN+SCCM site DB contributes no logins at
    # all (filtered in Task 2), so the edges vanish without this builder checking
    # any flag.
    con = _con()
    _edge_mssql_kerberoast_spn(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.graph_edges").fetchone()[0] == 0
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_kerberoast_spn_test.py -v`
Expected: FAIL — `_edge_mssql_kerberoast_spn` not defined.

- [ ] **Step 3: Implement `_edge_mssql_kerberoast_spn`**

```python
def _edge_mssql_kerberoast_spn(con, schema) -> None:
    """GetAdminTGS + GetTGS from the SPN service account, via Task 4's sysadmin logins.

    No flag parameter: each edge inherits the confidence of the login it rests on
    (node_mssql_login.assumed), and --disable-possible-edges already removed the
    assumed logins upstream in _assumed_site_dbs. Mirrors mssql/mssql
    derive_ad.py:460-476."""
    _safe(con, "edge_mssql_get_admin_tgs",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT DISTINCT upper(i.service_account_sid) AS start_id, i.server_id AS end_id, "
          f"       'MSSQL_GetAdminTGS' AS kind, true AS traversable, "
          f"       l.assumed AS assumed, "
          f"       CASE WHEN l.assumed THEN 'kerberoast path via assumed sysadmin login' END AS assumption_basis, "
          f"       CASE WHEN l.assumed THEN ['Assumed-KerberoastSPN'] "
          f"            ELSE ['SCCM-SiteDBDefaultSchema'] END AS collection_source "
          f"FROM {schema}.mssql_server_instances i "
          f"JOIN {schema}.node_mssql_login l ON l.server_id = i.server_id "
          f"WHERE i.service_account_sid IS NOT NULL AND l.is_domain AND l.is_sysadmin")
    _safe(con, "edge_mssql_get_tgs",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(i.service_account_sid) AS start_id, l.login_id AS end_id, "
          f"       'MSSQL_GetTGS' AS kind, true AS traversable, "
          f"       l.assumed AS assumed, "
          f"       CASE WHEN l.assumed THEN 'kerberoast path via assumed domain login' END AS assumption_basis, "
          f"       CASE WHEN l.assumed THEN ['Assumed-KerberoastSPN'] "
          f"            ELSE ['SCCM-SiteDBDefaultSchema'] END AS collection_source "
          f"FROM {schema}.mssql_server_instances i "
          f"JOIN {schema}.node_mssql_login l ON l.server_id = i.server_id "
          f"WHERE i.service_account_sid IS NOT NULL AND l.is_domain")
```

Align column names (`assumption_basis`/`assumed`/`collection_source`) to the confirmed convert convention and to the inline-provenance approach from Tasks 4/5. Task 4 must carry `assumed` through to `node_mssql_login` for the join above to work.

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_kerberoast_spn_test.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Green checkpoint.**

---

## Self-Review notes

- **Spec coverage:** Tiers A (Task 1,6), B (Task 1,1b,5), C (Task 1c,2,4); §4.1 orphaned role sources (Task 1b); §4.2 / D2(a) unconditional SQL-host nodes (Task 1c); Tier A+ additions — SMC Container/GenericAll (Task 11), MemberOf full nested chain (Task 12), MSSQL service account confirmed (Task 13), MSSQL kerberoast assumed (Task 14); provenance (Task 3, inlined in 4/5/14); labeling/help (Task 7); docs (Task 8); Tier-D exclusion asserted (Task 9, now only RBAC + no MSSQL svc-acct/kerberoast); improvements #1 (Task 1/D5), #2 (Task 1 root/D4), #3 (Task 2), #4 (Task 3), #5 (Task 6), #6 (Task 6), #7 (Task 11/12), #8 (Task 13/14), #9 (Task 1b), #10 (Task 1b/D6), #11 (Task 1b); live re-validation (Task 10). All spec sections map to a task.
- **Task ordering matters in three places:** Task 1b must precede Task 5 (its edge builders match on the role tags 1b creates) and Task 10 (which validates them live); Task 1c must precede Task 2 (whose SPN predicate joins the `has_mssql_spn` column 1c adds — without it the join silently degrades to a 1433-reachability test). Tasks 11-14 remain appended after Task 10 by original design; re-run Task 10's checks after them if executing strictly top-to-bottom.
- **Two different MSSQL claims, kept apart (D2):** "this host runs SQL Server" is confirmed by the `MSSQLSvc` SPN and is unconditional in both flag modes (Task 1c). "This host is the SCCM site database" is a separate, weaker claim that only RemoteRegistry/AdminService/WMI can confirm; the SPN+SCCM fallback yields it only under possible-ON and only stamped `assumed` (Tasks 2/4). Reviewers should check that no builder collapses the two.
- **One filter, one stamp — do not duplicate either.** The possible-edges decision for MSSQL lives *only* in `_assumed_site_dbs` (Task 2). Downstream builders read `basis` solely to choose the provenance stamp, never to re-decide whether to emit. A confirmed site DB therefore keeps its full scaffolding in both modes; an assumed one disappears under the flag because its row is gone, not because a builder checked.
- **Things that must stay ungated, verified against the code:** `_edge_has_session` (both arms, transforms.py:2798/3593); `MSSQL_HostFor`/`MSSQL_ExecuteOnHost` and the SPN-derived `MSSQL_Server`/`Computer` (D2a, Task 1c); the site rows in `site_hierarchy` (D5); a *typed* hierarchy root, and an untyped root when there is exactly one site (D4).
- **Silent-failure modes to watch** (none of these raise): an unnormalized `'Undetermined'` parent makes the parentless-Primary root test never match; a bare `SMS Site Server` role (no `@site`) matches no edge builder; a `mp_host` join that misses resolves to NULL and degrades to that bare role. All three produce a smaller graph with no error, which is why Task 1b and Task 10 Step 2b assert on them explicitly.
- **Base vs custom kinds:** Tasks 11-12 emit `Container`/`GenericAll`/`MemberOf` and Task 13 emits `HasSession` — all **base BloodHound kinds**; they must NOT be added to `schema_SCCM.json` and they merge with SharpHound-collected AD nodes by objectid/SID. `MSSQL_ServiceAccountFor` is an MSSQL custom kind → belongs in the MSSQL schema, not `schema_SCCM.json` ([[sccm-opengraph-schema-maintenance]]).
- **Confirmed vs assumed:** Tasks 11-13 are **confirmed** (observed/LDAP-derived) → emitted in BOTH flag modes, NO `assumed` stamp. Tasks 4 and 14 are **basis-dependent**: rows resting on an RR/privileged-confirmed site DB are confirmed and unstamped; rows resting on an `SPN+SCCM` site DB are assumed and stamped, and exist only under possible-ON because Task 2 filtered them out otherwise. Task 5's SCCM permission/coerce edges remain assumed in the plain sense.
- **Discovery steps are deliberate, not placeholders:** Tasks 2/4/5/6/7/9/11/12/13 open with a "read the current function / reference" step because they modify a large existing file (`transforms.py`, ~3400 lines) or port from a sibling extension; the concrete change (SQL/columns/predicates) is specified in the following step.
- **Type consistency:** provenance fields are `assumed`/`assumptionBasis`/`collectionSource` everywhere; `assumed_site_dbs(host_sid, site_code, basis)` consumed identically in Task 4; `site_type` INTEGER 1/2/4 consistent in Tasks 1/6; edge `start_id`/`end_id`/`kind`/`traversable` column names consistent across Tasks 11/12/13 (align to the real convert convention in Task 11 Step 4).
- **Open items to confirm at execution:** (a) the exact accessor `_edge_coerce_relay_mssql` uses for `disable_possible_edges` — the *other* MSSQL scaffold builders now take no flag at all, so this is the only one left to check (Task 4 Step 1); (b) the container `objectGUID` normalization must match SharpHound's `objectid` format so the `Container` node merges (Task 11 Step 1); (c) `ctx.ad.get_spns(target)` returns the target's own SPNs — Task 13 needs a search-by-SPN to find a holder that is a *different* account.
- **Tier-D (still excluded):** only the SCCM RBAC families remain AdminService/WMI-only — `SCCM_FullAdministrator`, `SCCM_AllPermissions`, `SCCM_ApplicationAdministrator`, `SCCM_IsAssigned`, `SCCM_IsMappedTo`, `SCCM_Contains`(RBAC objects), `SCCM_HasMember`, and the admin-user/security-role/collection nodes. Everything MSSQL is now in scope (Tasks 13-14).
