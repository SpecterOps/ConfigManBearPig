# tour_driver_stage3.py — Stage 3 code tour. Set the breakpoints listed in
# docs/superpowers/plans/2026-06-24-sccm-preproc-convert-stage3-validation.md §5,
# then debug THIS file (launch profile "Debug: Stage 3 code tour").
#
# Seeds a CAS->PS1->SEC hierarchy with enough cross-referenced data to exercise
# EVERY Stage-3 feature:
#   * _enrich_collection_members  -> node_collection.members (incl. a built-in key)
#   * _enrich_role_members        -> node_security_role.members (admin node ids)
#   * _enrich_admin_assignments   -> node_admin_user.collection_ids/role_ids/member_of
#   * _enrich_client_device       -> node_client_device.*_sid + collection_ids/names
#   * _enrich_site_lists          -> node_site.admin_users + stored_accounts
#   * _edge_contains              -> SCCM_Contains (Site->Collection/Role/AdminUser)
#   * _edge_rbac_role_grants      -> SCCM_FullAdministrator (via IsAssigned+HasMember)
#   * _edge_all_permissions       -> SCCM_AllPermissions (SMS0001R+SMS00001+SMS00004)
#   * _edge_assign_all_permissions-> SCCM_AssignAllPermissions (SMS Provider computer)
#   * collection_source           -> non-empty on every edge (incl. Stage-1/2 retrofit)
#   * node_computer.distinguished_name -> seeded via smb_computers
#
# Parameterised inserts (con.execute(sql, params)) are used for DOMAIN\user values
# throughout, avoiding any Python string-escape confusion with backslashes.
#
# Same load pattern as Stage 1/2 tour: seed gzipped-JSONL, load into DuckDB,
# run transforms(), then convert. For a production-faithful check use the three
# real-data CLI profiles (openhound collect/preprocess/convert sccm).
import gzip
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

# Point dlt's pipeline dir at a disposable per-run dir BEFORE importing dlt/openhound
# (avoids the Windows ~/.dlt WinError 32 lock; see ARCHITECTURE §8). Must precede imports.
work = Path(tempfile.mkdtemp(prefix="sccm_stage3_tour_"))
os.environ["DLT_DATA_DIR"] = str(work / "dlt_home")

import duckdb

import openhound_sccm.main as m               # importing registers @app.preproc/@app.convert
from openhound_sccm.transforms import transforms

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s",
                    stream=sys.stdout, force=True)
logging.getLogger("openhound_sccm").setLevel(logging.DEBUG)
logging.getLogger("dlt").setLevel(logging.WARNING)

db = work / "lookup.duckdb"

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
# Backslash note: all DOMAIN\user values are written below with a single backslash
# (the intended stored value). JSON encoding via json.dumps handles the escaping for
# the JSONL files, and the DuckDB parameterised inserts handle the escaping for any
# directly-inserted SQL values. No double-backslash gymnastics needed.
#
# Topology: CAS (site_type=4) -> PS1 (primary, site_type=2) -> SEC (secondary, site_type=1)
# Actors:
#   * SQL01  — the domain computer that is both:
#              - the SMS Provider host (site_system_roles includes "SMS Provider@PS1"),
#              - a client device (resource_id=5, smsid="GUID-1")
#   * alice  — a domain user; primary/current logon user on SQL01 client device
#   * sccmadmin — SCCM admin with Full Administrator (SMS0001R) assigned to
#                 All Systems (SMS00001) and All Users and User Groups (SMS00004)
#   * reserved-NAA — network access account stored on PS1 (triggers HasStoredAccount)
#
# Collections:
#   SMS00001 (All Systems, Device collection, built-in)
#   SMS00004 (All Users and User Groups, User collection, built-in)
#   PS100016 (a custom Device collection that also contains SQL01)
# Both SMS00001 and SMS00004 are needed to trigger SCCM_AllPermissions.
# PS100016 is needed to exercise the SCCM_Contains fan-out to a custom collection.

SEED: dict[str, list[dict]] = {
    # --- Site hierarchy ---
    "adminservice_site_definitions": [
        {"site_code": "CAS", "parent_site_code": None,   "site_type": 4,
         "site_guid": "G-CAS", "sql_server_name": None, "sql_database_name": None},
        {"site_code": "PS1", "parent_site_code": "CAS",  "site_type": 2,
         "site_guid": "G-PS1", "sql_server_name": "sql-ps1.lab", "sql_database_name": "CM_PS1"},
        {"site_code": "SEC", "parent_site_code": "PS1",  "site_type": 1,
         "site_guid": "G-SEC", "sql_server_name": None, "sql_database_name": None},
    ],
    # --- SMS Provider + client device host (resource_id=5) ---
    # system_roles is stored as a JSON array string matching the real AdminService shape.
    "adminservice_r_system": [
        {"name": "SQL01", "sid": "S-1-5-21-1-2-3-1200",
         "obsolete": False, "resource_id": 5, "source_site_code": "PS1",
         "system_roles": '["SMS SQL Server", "SMS Provider"]',
         "sms_unique_identifier": "GUID:sql01",
         "security_group_name": ["MAYYHEM\\SCCMAdmins"]},
    ],
    # --- Domain users ---
    "adminservice_r_user": [
        {"name": "alice", "sid": "S-1-5-21-1-2-3-1106",
         "resource_id": 9, "source_site_code": "PS1",
         "unique_user_name": "MAYYHEM\\alice",
         "distinguished_name": "CN=alice,DC=MAYYHEM,DC=COM",
         "user_principal_name": "alice@mayyhem.com"},
    ],
    # --- Security group (feeds MemberOf for SQL01) ---
    "adminservice_user_group": [
        {"sid": "S-1-5-21-1-2-3-5001", "unique_usergroup_name": "MAYYHEM\\SCCMAdmins",
         "usergroup_name": "SCCMAdmins", "resource_id": 50},
    ],
    # --- Collections ---
    # SMS00001 and SMS00004 are the two built-in global collections CMBP gates on.
    # PS100016 is a custom Device collection that also contains SQL01 (client).
    "adminservice_collections": [
        {"collection_id": "SMS00001", "name": "All Systems",
         "collection_type": 2, "member_count": 1, "is_built_in": True,
         "source_site_code": "CAS", "last_change_time": "2026-01-01"},
        {"collection_id": "SMS00004", "name": "All Users and User Groups",
         "collection_type": 1, "member_count": 1, "is_built_in": True,
         "source_site_code": "CAS", "last_change_time": "2026-01-01"},
        {"collection_id": "PS100016", "name": "Custom Devices",
         "collection_type": 2, "member_count": 1, "is_built_in": False,
         "source_site_code": "PS1", "last_change_time": "2026-01-15"},
    ],
    # --- Collection members ---
    # SQL01 (resource 5) is in SMS00001 and PS100016.
    # alice (resource 9) is in SMS00004.
    # 2046820352 is a well-known built-in pseudo-resource; included to verify members is faithful.
    "adminservice_collection_members": [
        {"collection_id": "SMS00001",  "resource_id": 5,          "site_code": "PS1"},
        {"collection_id": "SMS00001",  "resource_id": 2046820352, "site_code": "PS1"},  # built-in
        {"collection_id": "SMS00004",  "resource_id": 9,          "site_code": "PS1"},
        {"collection_id": "PS100016",  "resource_id": 5,          "site_code": "PS1"},
    ],
    # --- Security roles ---
    "adminservice_security_roles": [
        {"role_id": "SMS0001R", "role_name": "Full Administrator", "is_built_in": True},
    ],
    # --- SCCM admins ---
    # sccmadmin has Full Administrator (SMS0001R) assigned via the roles id list,
    # and is scoped to both All Systems (SMS00001) and All Users and User Groups (SMS00004)
    # via collection_names (JSON-array-text, the real AdminService shape).
    "adminservice_admins": [
        {"logon_name": "MAYYHEM\\sccmadmin",
         "admin_sid": "S-1-5-21-1-2-3-1110",
         "is_group": False,
         "collection_names": '["All Systems", "All Users and User Groups"]',
         "role_names": '["Full Administrator"]',
         "roles": '["SMS0001R"]'},
    ],
    # --- Client devices ---
    # SQL01 is a real client (is_client=True, not obsolete). Primary, current, and
    # ad_last_logon user are all alice (DOMAIN\user form) so _enrich_client_device
    # resolves all three *_sid fields via principal_by_name.
    "adminservice_client_devices": [
        {"smsid": "GUID-1", "name": "SQL01",
         "resource_id": 5, "site_code": "PS1",
         "is_client": True, "is_obsolete": False,
         "primary_user": "MAYYHEM\\alice",
         "current_logon_user": "MAYYHEM\\alice",
         "user_name": "MAYYHEM\\alice",
         "source_site_code": "PS1",
         "ad_last_logon_time": "2026-06-01T08:00:00Z",
         "user_domain_name": "MAYYHEM"},
    ],
    # --- Reserved/stored accounts (site PS1 -> NAA user) ---
    "adminservice_reserved_accounts": [
        {"object_sid": "S-1-5-21-1-2-3-1500", "site_code": "PS1", "name": "naa"},
    ],
    # --- Site systems (SQL service account; triggers HasSession + site sql_service_account_name) ---
    "adminservice_site_systems": [
        {"network_os_path": "\\\\SQL01.lab", "site_code": "PS1",
         "role_name": "SMS SQL Server",
         "type": "SMS SQL Server",
         "sql_server_service_logon_account": "MAYYHEM\\svc_sql"},
    ],
    # --- RemoteRegistry current-user session (SQL01 host -> alice user) ---
    "remoteregistry_users": [
        {"object_sid": "S-1-5-21-1-2-3-1106",
         "host_object_sid": "S-1-5-21-1-2-3-1200",
         "source": "RemoteRegistry-CurrentUser"},
    ],
    # --- SMB computers: provides distinguished_name for SQL01 ---
    # smb_computers uses object_sid (computer SID) as the key.
    "smb_computers": [
        {"object_sid": "S-1-5-21-1-2-3-1200", "name": "SQL01",
         "dns_host_name": "sql01.lab",
         "distinguished_name": "CN=SQL01,OU=Servers,DC=MAYYHEM,DC=COM",
         "smb_signing_required": True, "sccm_infra": True},
    ],
    # --- CmRcService SPN device (triggers possible-client node) ---
    "ldap_cmrc_devices": [
        {"object_sid": "S-1-5-21-1-2-3-1300", "name": "WS09", "dns_host_name": "ws09.lab"},
    ],
    # --- Site definitions computers: the SMS Provider role is also collected here ---
    # This seeds the sccm_site_system_roles for the SMS Provider computer, which feeds
    # node_computer.site_system_roles -> _edge_assign_all_permissions.
    "adminservice_site_definitions_computers": [
        {"object_sid": "S-1-5-21-1-2-3-1200", "name": "SQL01",
         "dns_host_name": "sql01.lab",
         "sccm_site_system_roles": '["SMS SQL Server@PS1", "SMS Provider@PS1"]',
         "sccm_infra": True},
    ],
    # --- Behaviour flags ---
    "collection_settings": [
        {"disable_possible_edges": False, "enable_bad_opsec": False},
    ],
}


def _gz(table: str, rows: list[dict]) -> None:
    """Write rows as gzipped JSONL under <work>/sccm/<table>/ (the collector's layout)."""
    d = work / "sccm" / table
    d.mkdir(parents=True, exist_ok=True)
    with gzip.open(d / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


for _table, _rows in SEED.items():
    _gz(_table, _rows)

# ---------------------------------------------------------------------------
# Preproc: seed the DuckDB, run transforms()
# ---------------------------------------------------------------------------
# Seed the raw JSONL tables into DuckDB, then run transforms() exactly as
# @app.preproc does. Every Stage-3 builder (enrich_*, edge_contains,
# edge_rbac_role_grants, edge_all_permissions, edge_assign_all_permissions,
# graph_edges_dedup) fires here. Set your debugger breakpoints now.
con = duckdb.connect(str(db))
con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
for _table in SEED:
    src = (work / "sccm" / _table / "data.jsonl.gz").as_posix()
    con.execute(
        f"CREATE TABLE sccm.{_table} AS "
        f"SELECT * FROM read_json_auto('{src}', format='newline_delimited')"
    )
transforms(con)

# ---------------------------------------------------------------------------
# Post-transform inspection: print results for every Stage-3 feature
# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("STAGE 3 TOUR — node/edge table inspection")
print("="*70)

# --- 1. node_collection.members (raw keys incl. built-in) ---
print("\n[1] node_collection.members (raw faithful ResourceID@Site keys):")
rows = con.execute(
    "SELECT collection_id, name, source_site_code, last_change_time, members "
    "FROM sccm.node_collection ORDER BY collection_id"
).fetchall()
for r in rows:
    print(f"  {r[0]:12s}  name={r[1]!r:40s}  src={r[2]}  changed={r[3]}  members={r[4]}")

# --- 2. node_security_role.members (admin node ids) ---
print("\n[2] node_security_role.members (SCCM_AdminUser node ids):")
rows = con.execute(
    "SELECT role_id, role_name, members FROM sccm.node_security_role ORDER BY role_id"
).fetchall()
for r in rows:
    print(f"  {r[0]}  {r[1]!r:30s}  members={r[2]}")

# --- 3. node_admin_user.collection_ids / role_ids / member_of ---
print("\n[3] node_admin_user enrichment (collection_ids / role_ids / member_of):")
rows = con.execute(
    "SELECT logon_name, collection_ids, role_ids, member_of "
    "FROM sccm.node_admin_user ORDER BY logon_name"
).fetchall()
for r in rows:
    print(f"  logon={r[0]!r}")
    print(f"    collection_ids={r[1]}")
    print(f"    role_ids      ={r[2]}")
    print(f"    member_of     ={r[3]}")

# --- 4. node_client_device resolved *_sid + collection lists ---
print("\n[4] node_client_device enrichment (*_sid + collection_ids/names):")
rows = con.execute(
    "SELECT smsid, name, primary_user_sid, current_logon_user_sid, "
    "ad_last_logon_user_sid, ad_last_logon_time, source_site_code, "
    "collection_ids, collection_names "
    "FROM sccm.node_client_device WHERE possible = false ORDER BY smsid"
).fetchall()
for r in rows:
    print(f"  smsid={r[0]}  name={r[1]}")
    print(f"    primary_user_sid          ={r[2]}")
    print(f"    current_logon_user_sid    ={r[3]}")
    print(f"    ad_last_logon_user_sid    ={r[4]}")
    print(f"    ad_last_logon_time        ={r[5]}")
    print(f"    source_site_code          ={r[6]}")
    print(f"    collection_ids            ={r[7]}")
    print(f"    collection_names          ={r[8]}")

# --- 5. node_site.admin_users + stored_accounts ---
print("\n[5] node_site enrichment (admin_users + stored_accounts):")
rows = con.execute(
    "SELECT site_code, site_type, root_site_code, admin_users, stored_accounts "
    "FROM sccm.node_site ORDER BY site_code"
).fetchall()
for r in rows:
    print(f"  site={r[0]}  type={r[1]}  root={r[2]}")
    print(f"    admin_users    ={r[3]}")
    print(f"    stored_accounts={r[4]}")

# --- 6. node_computer.distinguished_name (from smb_computers) ---
print("\n[6] node_computer.distinguished_name (seeded via smb_computers):")
rows = con.execute(
    "SELECT sid, name, distinguished_name, site_system_roles "
    "FROM sccm.node_computer ORDER BY sid"
).fetchall()
for r in rows:
    print(f"  sid={r[0]}  name={r[1]}")
    print(f"    distinguished_name={r[2]!r}")
    print(f"    site_system_roles ={r[3]}")

# --- 7. All edges by kind (counts) ---
print("\n[7] graph_edges counts by kind:")
rows = con.execute(
    "SELECT kind, count(*) AS cnt FROM sccm.graph_edges "
    "GROUP BY kind ORDER BY kind"
).fetchall()
for r in rows:
    print(f"  {r[0]:45s}  {r[1]:4d}")

# --- 8. Stage-3 edges — detailed rows ---
stage3_kinds = [
    "SCCM_Contains",
    "SCCM_FullAdministrator",
    "SCCM_ApplicationAuthor",
    "SCCM_ApplicationAdministrator",
    "SCCM_ComplianceSettingsManager",
    "SCCM_OSDManager",
    "SCCM_OperationsAdministrator",
    "SCCM_SecurityAdministrator",
    "SCCM_AllPermissions",
    "SCCM_AssignAllPermissions",
]
print("\n[8] Stage-3 edges (start_id -> end_id, collection_source):")
for kind in stage3_kinds:
    rows = con.execute(
        "SELECT start_id, end_id, collection_source FROM sccm.graph_edges "
        "WHERE kind=? ORDER BY start_id, end_id", [kind]
    ).fetchall()
    if rows:
        print(f"\n  {kind} ({len(rows)} edge(s)):")
        for r in rows:
            print(f"    {r[0]}  ->  {r[1]}  src={r[2]}")
    else:
        print(f"\n  {kind}: (no rows)")

# --- 9. collection_source non-empty check (covers Stage-1/2 retrofit) ---
print("\n[9] collection_source coverage check:")
total = con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0]
empty = con.execute(
    "SELECT count(*) FROM sccm.graph_edges "
    "WHERE collection_source IS NULL OR len(collection_source) = 0"
).fetchone()[0]
print(f"  Total edges: {total}  |  Empty collection_source: {empty}")
if empty == 0:
    print("  PASS: every edge has a non-empty collection_source")
else:
    print("  FAIL: some edges are missing collection_source — inspect the list above")
    missing_kinds = con.execute(
        "SELECT DISTINCT kind FROM sccm.graph_edges "
        "WHERE collection_source IS NULL OR len(collection_source) = 0 "
        "ORDER BY kind"
    ).fetchall()
    for r in missing_kinds:
        print(f"    missing: {r[0]}")

# --- 10. SCCM_FullAdministrator fan-out confirmation ---
print("\n[10] SCCM_FullAdministrator path verification:")
fa_rows = con.execute(
    "SELECT start_id, end_id, collection_source FROM sccm.graph_edges "
    "WHERE kind='SCCM_FullAdministrator'"
).fetchall()
if fa_rows:
    print("  PASS: Full Administrator admin reaches client device(s):")
    for r in fa_rows:
        print(f"    {r[0]}  ->  {r[1]}  src={r[2]}")
else:
    print("  FAIL: no SCCM_FullAdministrator edges — check seed data and _edge_rbac_role_grants")

# --- 11. node_backfill count ---
print("\n[11] node_backfill (should be 0 for a self-consistent seed):")
cnt = con.execute("SELECT count(*) FROM sccm.node_backfill").fetchone()[0]
print(f"  node_backfill rows: {cnt}")
if cnt:
    rows = con.execute("SELECT id, kind FROM sccm.node_backfill ORDER BY id").fetchall()
    for r in rows:
        print(f"    {r[0]}  kind={r[1]}")

con.close()

# ---------------------------------------------------------------------------
# Convert: build the OpenGraph JSON output
# ---------------------------------------------------------------------------
print("\n[12] Running openhound convert (emit_graph_from_duckdb) ...")
m.app.converter(input_path=work, output_path=work / "graph", lookup_file=db)

graph_files = [p.name for p in (work / "graph").glob("*.json")]
print(f"\nTOUR OUTPUT: {graph_files}")
print(f"WORKDIR:     {work}")
print("\nStage 3 tour complete. Meatbag, review the output above and set breakpoints "
      "per the validation doc to step through the transforms live.")
