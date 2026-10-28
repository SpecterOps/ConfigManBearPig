"""Keep each administrator's role, collection, and security-scope assignments together.

SCCM's Permissions entries describe assignments, while a role's Operations describe
its actions. The original Permissions entries stay in the collected data. These
tables make those assignments usable by graph generation without mixing roles.
"""

import logging

import duckdb

from openhound_collector_common.dlt.duckdb_safe import ensure_columns

logger = logging.getLogger(__name__)


def build_role_assignments(
    con: duckdb.DuckDBPyConnection, schema: str, root_site_code: str
) -> None:
    """Build verified administrator/role assignments from saved SMS_Admin.Permissions.

    Missing or malformed details withhold the affected read's access claims. Summary
    role and collection lists are never used to guess pairings. An empty retrieved
    list is valid and grants nothing. Multiple providers can confirm the same entry.
    """
    con.execute(
        "CREATE OR REPLACE TEMP TABLE _admin_permission_reads ("
        "admin_id VARCHAR, logon_key VARCHAR, collection_source VARCHAR, permissions JSON, "
        "details_complete BOOLEAN)"
    )
    tables = {
        row[0]
        for row in con.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = ?",
            [schema],
        ).fetchall()
    }
    for source in ("adminservice_admins", "wmi_admins"):
        if source not in tables:
            logger.debug("Role assignments: %s was not collected", source)
            continue
        ensure_columns(
            con,
            schema,
            source,
            {
                "logon_name": "VARCHAR",
                "permissions": "JSON",
                "permissions_complete": "BOOLEAN",
            },
        )
        # dlt stores embedded arrays as JSON. Hand-built/cached tables may instead
        # contain JSON text or a typed list, so accept those without changing it.
        con.execute(
            "INSERT INTO _admin_permission_reads "
            "SELECT upper(logon_name) || ?, upper(logon_name), ?, "
            "CASE WHEN typeof(permissions) IN ('VARCHAR', 'JSON') "
            "     THEN try_cast(permissions AS JSON) ELSE to_json(permissions) END, "
            "coalesce(permissions_complete, true) "
            f"FROM {schema}.{source} WHERE nullif(trim(logon_name), '') IS NOT NULL",
            [
                f"@{root_site_code}" if root_site_code else "",
                "AdminService-SMS_Admin"
                if source.startswith("adminservice")
                else "WMI-SMS_Admin",
            ],
        )

    # Validate every entry before using a read. Unknown categories and malformed
    # values remain in the raw evidence, but must never be interpreted as access.
    con.execute("""
        CREATE OR REPLACE TEMP TABLE _checked_admin_permission_reads AS
        SELECT *, coalesce(details_complete AND json_type(permissions) = 'ARRAY'
            AND NOT EXISTS (
                SELECT 1 FROM json_each(permissions) entry
                WHERE json_type(entry.value) != 'OBJECT'
                   OR coalesce(json_type(entry.value, '$.RoleID') != 'VARCHAR', true)
                   OR coalesce(json_type(entry.value, '$.CategoryID') != 'VARCHAR', true)
                   OR nullif(trim(entry.value->>'RoleID'), '') IS NULL
                   OR nullif(trim(entry.value->>'CategoryID'), '') IS NULL
                   OR coalesce(json_type(entry.value, '$.CategoryTypeID') NOT IN ('UBIGINT', 'BIGINT'), true)
                   OR coalesce(try_cast(entry.value->>'CategoryTypeID' AS INTEGER) NOT IN (1, 29), true)
            ), false) AS is_valid
        FROM _admin_permission_reads
    """)
    incomplete = con.execute(
        "SELECT count(*) FROM _checked_admin_permission_reads WHERE NOT is_valid"
    ).fetchall()[0][0]
    if incomplete:
        logger.warning(
            "Role assignments: %d administrator read(s) have missing or invalid Permissions; "
            "withholding their calculated access. Recollect to retrieve complete assignments.",
            incomplete,
        )
    else:
        logger.debug("Role assignments: all saved administrator details are valid")

    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.admin_role_assignments AS
        SELECT admin_id, logon_key, upper(trim(entry.value->>'RoleID')) AS role_id,
            list_sort(list_distinct(list(upper(trim(entry.value->>'CategoryID')))
                FILTER (WHERE entry.value->>'CategoryTypeID' = '1'))) AS collection_ids,
            list_sort(list_distinct(list(upper(trim(entry.value->>'CategoryID')))
                FILTER (WHERE entry.value->>'CategoryTypeID' = '29'))) AS security_scope_ids,
            list_sort(list_distinct(list(collection_source))) AS collection_source
        FROM _checked_admin_permission_reads, json_each(permissions) entry
        WHERE is_valid
        GROUP BY admin_id, logon_key, role_id
    """)
    # A role can have only scope entries, or only collection entries. Empty lists
    # mean we retrieved no assignment of that type; NULL would mean unknown.
    con.execute(
        f"UPDATE {schema}.admin_role_assignments SET "
        "collection_ids = coalesce(collection_ids, []::VARCHAR[]), "
        "security_scope_ids = coalesce(security_scope_ids, []::VARCHAR[])"
    )
    count = con.execute(
        f"SELECT count(*) FROM {schema}.admin_role_assignments"
    ).fetchall()[0][0]
    logger.info("Preserved %d administrator-to-role assignment(s)", count)


def build_collection_coverage(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Expand assigned collections through their limiting-collection descendants.

    Keep the original assigned collection as evidence. UNION removes repeated
    rows, including cycles in malformed collection data, so recursion terminates.
    Collections and memberships stay in DuckDB rather than expanding in memory.
    Security scopes are object permissions and do not filter device membership.
    """
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.admin_collection_permissions AS
        WITH RECURSIVE coverage(admin_id, role_id, assigned_collection_id, collection_id) AS (
            SELECT a.admin_id, a.role_id, assigned.collection_id, assigned.collection_id
            FROM {schema}.admin_role_assignments a,
                 unnest(a.collection_ids) assigned(collection_id)
            UNION
            SELECT parent.admin_id, parent.role_id, parent.assigned_collection_id, child.collection_id
            FROM coverage parent
            JOIN {schema}.node_collection child
              ON upper(child.limit_to_collection_id) = parent.collection_id
        )
        SELECT * FROM coverage
    """)
    count = con.execute(
        f"SELECT count(*) FROM {schema}.admin_collection_permissions"
    ).fetchall()[0][0]
    logger.debug(
        "Expanded role assignments into %d collection permission record(s)", count
    )
