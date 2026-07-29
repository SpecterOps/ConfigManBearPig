# tour_driver_stage2.py — Stage 2 code tour. Set the breakpoints listed in
# docs/superpowers/plans/2026-06-23-sccm-preproc-convert-stage2-validation.md §5,
# then debug THIS file (launch profile "Debug: Stage 2 code tour").
#
# Seeds a small but genuinely cross-referenced dataset so the full preproc->convert
# path exercises every Stage 2 builder: the 4 entity-node coalesces, the 4 lookups,
# all inline edges (HasClient/HasMember/IsMappedTo/IsAssigned/Has*User/MemberOf/
# HasSession[both sources]/HasStoredAccount), the possible-client node, the
# graph_edges dedup, and the stub backfill. Topology mirrors the lab: CAS -> PS1
# (primary) -> SEC (secondary).
#
# Same load pattern as the Stage 1 tour: seed the collector's gzipped-JSONL layout,
# load each table into DuckDB directly, run transforms(), then convert. For a
# production-faithful check run the real CLI instead (the three launch profiles).
import gzip
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

# Point dlt's pipeline dir at a disposable per-run dir BEFORE importing dlt/openhound
# (avoids the Windows ~/.dlt WinError 32 lock; see ARCHITECTURE §8). Must precede imports.
work = Path(tempfile.mkdtemp(prefix="sccm_stage2_tour_"))
os.environ["DLT_DATA_DIR"] = str(work / "dlt_home")

import duckdb

import openhound_sccm.main as m               # importing registers @app.preproc/@app.convert
from openhound_sccm.transforms import transforms

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s",
                    stream=sys.stdout, force=True)
logging.getLogger("openhound_sccm").setLevel(logging.DEBUG)
logging.getLogger("dlt").setLevel(logging.WARNING)

db = work / "lookup.duckdb"

# Backslash note: in Python source, "MAYYHEM\\alice" is ONE backslash (the stored
# value). JSON-array-text columns (admins.collection_names/role_names) are seeded as
# literal strings like '["All Systems"]' to match the real SMS Provider shape that the
# IsAssigned builder parses via _arr().
SEED: dict[str, list[dict]] = {
    # hierarchy: CAS -> PS1 (primary) -> SEC (secondary)
    "adminservice_site_definitions": [
        {"site_code": "CAS", "parent_site_code": None, "site_type": 4, "site_guid": "G-CAS",
         "sql_server_name": "sql-cas.lab", "sql_database_name": "CM_CAS"},
        {"site_code": "PS1", "parent_site_code": "CAS", "site_type": 2, "site_guid": "G-PS1",
         "sql_server_name": "sql-ps1.lab", "sql_database_name": "CM_PS1"},
        {"site_code": "SEC", "parent_site_code": "PS1", "site_type": 1, "site_guid": "G-SEC",
         "sql_server_name": None, "sql_database_name": None},
    ],
    # a computer (also the SQL host + the client device, one machine = one resource_id)
    "adminservice_r_system": [
        {"name": "SQL01", "sid": "S-1-5-21-1-2-3-1200", "obsolete": False, "resource_id": 5,
         "source_site_code": "PS1", "system_roles": "SMS SQL Server",
         "sms_unique_identifier": "GUID:sql01", "security_group_name": ["MAYYHEM\\SCCMAdmins"]},
    ],
    # users: alice (device user + collection member), svc_sql (SQL service account)
    "adminservice_r_user": [
        {"name": "alice", "sid": "S-1-5-21-1-2-3-1106", "resource_id": 9, "source_site_code": "PS1",
         "unique_user_name": "MAYYHEM\\alice"},
        {"name": "svc_sql", "sid": "S-1-5-21-1-2-3-1700", "resource_id": 11, "source_site_code": "PS1",
         "unique_user_name": "MAYYHEM\\svc_sql"},
    ],
    # the group's SID (feeds principal_by_name -> MemberOf resolution)
    "adminservice_user_group": [
        {"sid": "S-1-5-21-1-2-3-5001", "unique_usergroup_name": "MAYYHEM\\SCCMAdmins",
         "usergroup_name": "SCCMAdmins", "resource_id": 50},
    ],
    "adminservice_collections": [
        {"collection_id": "PS100016", "name": "All Systems", "collection_type": 2,
         "member_count": 2, "is_built_in": False, "source_site_code": "PS1"},
    ],
    # device member (resource 5 -> client device) + user member (resource 9 -> alice)
    "adminservice_collection_members": [
        {"collection_id": "PS100016", "resource_id": 5, "site_code": "PS1"},
        {"collection_id": "PS100016", "resource_id": 9, "site_code": "PS1"},
    ],
    "adminservice_security_roles": [
        {"role_id": "SMS0001R", "role_name": "Full Administrator", "is_built_in": True},
    ],
    # admin with JSON-array-text collection_names/role_names (real shape) + empty roles
    "adminservice_admins": [
        {"logon_name": "MAYYHEM\\sccmadmin", "admin_sid": "S-1-5-21-1-2-3-1110", "is_group": False,
         "collection_names": '["All Systems"]', "role_names": '["Full Administrator"]', "roles": "[]"},
    ],
    # real client device (resource 5 = SQL01); its user fields resolve to alice
    "adminservice_client_devices": [
        {"smsid": "GUID-1", "name": "SQL01", "resource_id": 5, "site_code": "PS1",
         "is_client": True, "is_obsolete": False, "primary_user": "MAYYHEM\\alice",
         "current_logon_user": "MAYYHEM\\alice", "user_name": "MAYYHEM\\alice"},
    ],
    # stored account (Site -> User edge); object_sid already AD-resolved
    "adminservice_reserved_accounts": [
        {"object_sid": "S-1-5-21-1-2-3-1500", "site_code": "PS1", "name": "naa"},
    ],
    # SQL service-account session source (HasSession MSSQL arm)
    "adminservice_site_systems": [
        {"network_os_path": "\\\\SQL01.lab", "site_code": "PS1", "role_name": "SMS SQL Server",
         "type": "SMS SQL Server", "sql_server_service_logon_account": "MAYYHEM\\svc_sql"},
    ],
    # RemoteRegistry logged-on user session (HasSession registry arm): host -> user
    "remoteregistry_users": [
        {"object_sid": "S-1-5-21-1-2-3-1106", "host_object_sid": "S-1-5-21-1-2-3-1200",
         "source": "RemoteRegistry-CurrentUser"},
    ],
    # CmRcService SPN holder -> a possible-client device (gated on; root present)
    "ldap_cmrc_devices": [
        {"object_sid": "S-1-5-21-1-2-3-1300", "name": "WS09", "dns_host_name": "ws09.lab"},
    ],
    # behaviour flags persisted at collect time (gate reader)
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

# --- preproc: load the seeded JSONL into DuckDB, then run transforms() exactly as
#     @app.preproc does. The transforms.py breakpoints (coalesces, lookups, edge
#     builders, dedup, backfill) all fire in here. ---
con = duckdb.connect(str(db))
con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
for _table in SEED:
    src = (work / "sccm" / _table / "data.jsonl.gz").as_posix()
    con.execute(
        f"CREATE TABLE sccm.{_table} AS "
        f"SELECT * FROM read_json_auto('{src}', format='newline_delimited')"
    )
transforms(con)
con.close()

# --- convert: app.converter opens the lookup read-only, builds SCCMLookup, calls our
#     convert(ctx) -> emit_graph_from_duckdb (the node/edge models incl. GraphEdge fire
#     here), then runs the framework no-op source. ---
m.app.converter(input_path=work, output_path=work / "graph", lookup_file=db)

print("TOUR OUTPUT:", [p.name for p in (work / "graph").glob("*.json")])
print("WORKDIR:", work)
