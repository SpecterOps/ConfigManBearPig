"""--dc-only produces a DuckDB with only the discovery tables (ldap_*/dns_*/
collection_settings) and NONE of the per-host tables (adminservice_*, wmi_*,
smb_*, remoteregistry_*, mssql_server_instances). The full preproc transforms()
must run over that shape without raising and still emit the LDAP/DNS-discovered
entities (SharpHound-DCOnly value proposition)."""
import duckdb

from openhound_sccm.transforms import transforms


def _discovery_only_db():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("INSTALL json; LOAD json;")
    # An LDAP-discovered computer carrying the CmRcService SPN.
    con.execute("CREATE TABLE sccm.ldap_cmrc_devices (object_sid VARCHAR, name VARCHAR)")
    con.execute(
        "INSERT INTO sccm.ldap_cmrc_devices VALUES "
        "('S-1-5-21-1-2-3-1104', 'HOST1.mayyhem.com')"
    )
    # collection_settings is ungated, so it is written even in --dc-only mode.
    con.execute("CREATE TABLE sccm.collection_settings (disable_possible_edges BOOLEAN)")
    con.execute("INSERT INTO sccm.collection_settings VALUES (false)")
    return con


def test_transforms_over_dc_only_db_does_not_raise():
    con = _discovery_only_db()
    # Must complete despite every per-host table being absent.
    transforms(con, "sccm")
    con.close()


def test_transforms_over_dc_only_db_emits_discovered_host():
    con = _discovery_only_db()
    transforms(con, "sccm")
    sids = [r[0] for r in con.execute("SELECT sid FROM sccm.node_computer").fetchall()]
    con.close()
    assert "S-1-5-21-1-2-3-1104" in sids, sids


def test_dc_only_ad_props_populate_when_resolved_principals_present():
    """When discovery resolved a principal (ldap_resolved_principals present), its AD
    attributes must reach node_computer -- the exact props that were silently empty
    before the dc-only flush was wired up (main.py's collect_sccm elif branch calling
    _emit_resolved_principals). Schema/columns verified against
    SourceContext._record_resolved_principal (context.py) and _derive_ad_props /
    _join_ad_props (transforms.py)."""
    con = _discovery_only_db()
    # Minimal resolved-principal row for the same SID, using the exact raw columns
    # _record_resolved_principal writes: sid, object_class, user_account_control,
    # service_principal_name, cn, dns_host_name, sam_account_name,
    # user_principal_name, distinguished_name, domain. Only the columns
    # _derive_ad_props actually reads are needed here; the rest are backfilled
    # as NULL by _ensure_columns.
    con.execute(
        "CREATE TABLE sccm.ldap_resolved_principals ("
        "sid VARCHAR, object_class VARCHAR, user_account_control BIGINT, "
        "service_principal_name VARCHAR, cn VARCHAR, domain VARCHAR)"
    )
    con.execute(
        "INSERT INTO sccm.ldap_resolved_principals VALUES "
        # user_account_control=4096 (0x1000): ACCOUNTDISABLE bit (0x2) clear -> enabled=True.
        "('S-1-5-21-1-2-3-1104', 'computer', 4096, NULL, 'HOST1', 'mayyhem.com')"
    )

    transforms(con, "sccm")

    row = con.execute(
        "SELECT cn, domain, type, enabled FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchone()
    con.close()
    assert row is not None, row
    cn, domain, type_, enabled = row
    assert (cn, domain, type_, enabled) == ("HOST1", "mayyhem.com", "Computer", True), row
