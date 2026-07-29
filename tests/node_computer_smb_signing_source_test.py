import duckdb

from openhound_sccm.transforms import _node_computer


def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # Same SID seen by BOTH the SMB negotiate probe and the remote-registry check.
    con.execute(
        "CREATE TABLE sccm.smb_computers AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'SS01' AS name, "
        "'SS01.mayyhem.com' AS dns_host_name, 'CN=SS01' AS distinguished_name, "
        "false AS smb_signing_required"
    )
    con.execute(
        "CREATE TABLE sccm.remoteregistry_computers AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS object_sid, 'SS01' AS name, "
        "'SS01.mayyhem.com' AS dns_host_name, 'CN=SS01' AS distinguished_name, "
        "false AS smb_signing_required, 'Off' AS restrict_receiving_ntlm_traffic"
    )
    # A computer only LDAP knew about -> no smb_signing_source.
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'S-1-5-21-1-2-3-2222' AS sid, 'WS01' AS name, NULL AS resource_id, "
        "NULL AS source_site_code, NULL AS system_roles, NULL AS sms_unique_identifier, "
        "false AS obsolete"
    )


def test_smb_signing_source_unions_both_probes():
    con = duckdb.connect()
    _seed(con)
    _node_computer(con, "sccm")
    src = con.execute(
        "SELECT list_sort(smb_signing_source) FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-1104'"
    ).fetchone()[0]
    assert src == ["RemoteRegistry-SMBSigningCheck", "SMB-Negotiate"]


def test_smb_signing_source_empty_when_unprobed():
    con = duckdb.connect()
    _seed(con)
    _node_computer(con, "sccm")
    src = con.execute(
        "SELECT smb_signing_source FROM sccm.node_computer "
        "WHERE sid = 'S-1-5-21-1-2-3-2222'"
    ).fetchone()[0]
    assert src == []
