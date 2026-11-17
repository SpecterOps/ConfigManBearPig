"""Choose the site database port from saved facts before applying marked guesses.

This runs entirely during graph preparation. It never contacts a remote host.
"""

import duckdb

from openhound_collector_common.dlt.duckdb_safe import ensure_columns

from .log_context import get_logger

logger = get_logger(__name__)


def _port_observations(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Retain instance names and distinguish configured static ports from replies."""
    con.execute("CREATE OR REPLACE TEMP TABLE _sql_port_observations (host_sid VARCHAR, port INTEGER, instance_name VARCHAR, is_static BOOLEAN, answered BOOLEAN, source VARCHAR)")
    sources = {
        "remoteregistry_mssql_servers": {
            "domain_computer_sid": "VARCHAR", "port": "VARCHAR",
            "instance_name": "VARCHAR", "is_static_port": "BOOLEAN",
        },
        "mssql_server_instances": {
            "domain_computer_sid": "VARCHAR", "port": "VARCHAR",
            "instance_name": "VARCHAR", "epa_measured": "BOOLEAN",
            "source": "VARCHAR", "port_open": "BOOLEAN",
        },
    }
    for table, columns in sources.items():
        exists = con.execute("SELECT 1 FROM information_schema.tables WHERE table_schema = ? AND table_name = ?", [schema, table]).fetchone()
        if not exists:
            logger.debug("No saved SQL port observations from %s", table)
            continue
        ensure_columns(con, schema, table, columns, logger=logger)
        is_registry = table == "remoteregistry_mssql_servers"
        static = "is_static_port" if is_registry else "NULL::BOOLEAN"
        answered = "NULL::BOOLEAN" if is_registry else "port_open AND coalesce(epa_measured, source = 'MSSQL-ScanForEPA', false)"
        source = "'RemoteRegistry-MSSQL'" if is_registry else "coalesce(source, 'MSSQL')"
        # The two known raw formats supply different facts, not different policies.
        con.execute(f"""
            INSERT INTO _sql_port_observations
            SELECT upper(domain_computer_sid), _sccm_sql_port(port),
                   upper(instance_name), {static}, {answered}, {source}
            FROM {schema}.{table}
            WHERE _sccm_sql_port(port) BETWEEN 1 AND 65535
        """)
    con.execute("""
        CREATE OR REPLACE TEMP TABLE _sql_observed_static_ports AS
        SELECT host_sid, port FROM _sql_port_observations
        GROUP BY host_sid, port
        HAVING bool_or(is_static) AND NOT coalesce(bool_or(NOT is_static), false)
               AND bool_or(answered)
    """)


def resolve_site_databases(
    con: duckdb.DuckDBPyConnection, schema: str, disable_possible: bool
) -> None:
    """Complete the staged site mappings in order of evidence, then mark guesses.

    SCCM's explicit port wins, followed by its site-server registry mapping.
    Matching instance observations can fill a missing port. Only one static
    port with an actual SQL response permits the single-listener inference.
    Otherwise the owner's default-mode policy retains port 1433 as an assumption.
    """
    # DuckDB's integer cast accepts decimals and exponent notation. Saved port
    # evidence must instead obey the same whole-number rule as the SQL parser.
    con.execute("""
        CREATE OR REPLACE TEMP MACRO _sccm_sql_port(raw_value) AS
        CASE WHEN regexp_full_match(trim(cast(raw_value AS VARCHAR)), '[0-9]+')
             AND try_cast(raw_value AS INTEGER) BETWEEN 1 AND 65535
             THEN try_cast(raw_value AS INTEGER) END
    """)
    _port_observations(con, schema)
    con.execute("CREATE OR REPLACE TEMP TABLE _site_database_registry (site_code VARCHAR, host_sid VARCHAR, port INTEGER, resolved_port INTEGER, db_name VARCHAR)")
    table = "remoteregistry_site_databases"
    exists = con.execute("SELECT 1 FROM information_schema.tables WHERE table_schema = ? AND table_name = ?", [schema, table]).fetchone()
    if exists:
        ensure_columns(con, schema, table, {
            "site_code": "VARCHAR", "domain_computer_sid": "VARCHAR",
            "sql_service_port": "VARCHAR", "sql_resolved_service_port": "VARCHAR",
            "sql_database_name": "VARCHAR",
        }, logger=logger)
        con.execute(f"""
            INSERT INTO _site_database_registry
            SELECT upper(site_code), upper(domain_computer_sid),
                CASE WHEN count(DISTINCT _sccm_sql_port(sql_service_port)) = 1
                     THEN min(_sccm_sql_port(sql_service_port)) END,
                CASE WHEN count(DISTINCT _sccm_sql_port(sql_resolved_service_port)) = 1
                     THEN min(_sccm_sql_port(sql_resolved_service_port)) END,
                CASE WHEN count(DISTINCT sql_database_name) = 1 THEN min(sql_database_name) END
            FROM {schema}.{table} GROUP BY upper(site_code), upper(domain_computer_sid)
        """)
    else:
        logger.debug("No saved site-server SQL mapping; using the remaining evidence")
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE _site_sql_choices AS
        WITH names AS (
            SELECT s.*, coalesce(s.db_name, r.db_name) AS recorded_database,
                r.port AS registry_port, r.resolved_port AS registry_resolved_port,
                r.host_sid IS NOT NULL AS has_registry_mapping
            FROM {schema}._mssql_sql_servers s
            LEFT JOIN _site_database_registry r USING (site_code, host_sid)
        ), matched AS (
            SELECT n.*,
                (SELECT CASE WHEN count(DISTINCT o.port) = 1 THEN min(o.port) END
                 FROM _sql_port_observations o WHERE o.host_sid = n.host_sid
                 AND o.instance_name = CASE
                    WHEN contains(n.recorded_database, chr(92))
                    THEN upper(split_part(n.recorded_database, chr(92), 1))
                    WHEN n.recorded_database IS NOT NULL THEN 'MSSQLSERVER' END) AS instance_port,
                (SELECT CASE WHEN count(*) = 1 THEN min(p.port) END
                 FROM _sql_observed_static_ports p WHERE p.host_sid = n.host_sid) AS single_static_port
            FROM names n
        ), chosen AS (
            SELECT *, CASE
                WHEN _sccm_sql_port(port) BETWEEN 1 AND 65535 THEN _sccm_sql_port(port)
                WHEN registry_port BETWEEN 1 AND 65535 THEN registry_port
                WHEN _sccm_sql_port(resolved_port) BETWEEN 1 AND 65535 THEN _sccm_sql_port(resolved_port)
                WHEN registry_resolved_port BETWEEN 1 AND 65535 THEN registry_resolved_port
                WHEN instance_port IS NOT NULL THEN instance_port
                WHEN single_static_port IS NOT NULL THEN single_static_port
                ELSE 1433 END AS chosen_port,
                CASE
                WHEN _sccm_sql_port(port) BETWEEN 1 AND 65535
                  OR registry_port BETWEEN 1 AND 65535
                  OR _sccm_sql_port(resolved_port) BETWEEN 1 AND 65535
                  OR registry_resolved_port BETWEEN 1 AND 65535
                  OR instance_port IS NOT NULL THEN NULL
                WHEN single_static_port IS NOT NULL
                  THEN 'site database inferred from the only observed static SQL listener; database ownership not confirmed'
                ELSE 'site SQL port unread; default TCP port 1433 assumed' END AS port_assumption
            FROM matched
        )
        SELECT *, (SELECT list_distinct(list(o.source)) FROM _sql_port_observations o
                   WHERE o.host_sid = chosen.host_sid AND o.port = chosen.chosen_port) AS port_sources,
            (basis = 'SPN+SCCM' AND NOT has_registry_mapping)
                      OR port_assumption IS NOT NULL AS is_assumed,
            nullif(concat_ws('; ',
                CASE WHEN basis = 'SPN+SCCM' AND NOT has_registry_mapping
                     THEN 'site DB inferred from MSSQLSvc SPN + SCCM-relatedness; DB internals not observed' END,
                port_assumption), '') AS reason
        FROM chosen
    """)
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}._mssql_sql_servers AS
        SELECT site_code, root_site_code, host_sid, dns_host_name,
            cast(chosen_port AS VARCHAR) AS port,
            coalesce(recorded_database, 'CM_' || site_code) AS db_name,
            service_account_name, service_account_sid, basis,
            list_distinct(list_concat(collection_source,
                CASE WHEN has_registry_mapping THEN ['RemoteRegistry-SiteDatabase'] ELSE [] END,
                CASE WHEN _sccm_sql_port(port) BETWEEN 1 AND 65535
                       OR registry_port BETWEEN 1 AND 65535 THEN [] ELSE port_sources END)) AS collection_source,
            coalesce(is_assumed, false) AS assumed, reason AS assumption_basis
        FROM _site_sql_choices
        WHERE NOT (? AND coalesce(is_assumed, false))
    """, [disable_possible])
    for reason, count in con.execute("SELECT reason, count(*) FROM _site_sql_choices WHERE port_assumption IS NOT NULL GROUP BY reason").fetchall():
        logger.warning("%d site database mapping(s): %s%s", count, reason, "; omitted because possible edges are disabled" if disable_possible else "")
    logger.info("Site database port choices prepared from saved SCCM and SQL evidence")
