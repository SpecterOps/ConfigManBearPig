# src/openhound_sccm/transforms_lookups_test.py
import duckdb
from openhound_sccm.transforms import transforms

def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'WS01' AS name, "
                "'S-1-5-21-1-2-3-1104' AS sid, 7 AS resource_id, 'PS1' AS source_site_code, false AS obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code, "
                "'MAYYHEM\\alice' AS unique_user_name")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'PS100016' AS collection_id, 'All Systems' AS name")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS000AR' AS role_id, 'Full Administrator' AS role_name")

def test_lookups_built():
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    assert con.execute("SELECT sid FROM sccm.principal_by_resourceid WHERE resource_key='9@PS1'").fetchone()[0] == "S-1-5-21-1-2-3-1106"
    assert con.execute("SELECT smsid FROM sccm.device_by_resourceid WHERE resource_key='7@PS1'").fetchone()[0] == "GUID-1"
    assert con.execute("SELECT collection_id FROM sccm.collection_by_name WHERE name='ALL SYSTEMS'").fetchone()[0] == "PS100016"
    assert con.execute("SELECT role_id FROM sccm.role_by_name WHERE name='FULL ADMINISTRATOR'").fetchone()[0] == "SMS000AR"

def test_principal_by_name_resolves_unique_user_name():
    con = duckdb.connect(":memory:")
    _seed(con)
    transforms(con)
    # the DOMAIN\user form resolves to the user's SID (enrichment)
    row = con.execute("SELECT sid FROM sccm.principal_by_name WHERE upper(name)=upper('MAYYHEM\\alice')").fetchone()
    assert row is not None and row[0] == "S-1-5-21-1-2-3-1106"
