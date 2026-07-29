# src/openhound_sccm/edge_has_member_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_has_member_device_and_user_skip_builtin():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # single primary PS1 -> root resolves to PS1
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    # a device resource (-> ClientDevice smsid) and a user resource (-> user SID)
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code")
    # memberships: device (7), user (9), and a built-in pseudo-resource (skipped)
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT * FROM (VALUES "
                "('PS100016', 7, 'PS1'), ('PS100016', 9, 'PS1'), ('PS100016', 2046820352, 'PS1')) "
                "AS t(collection_id, resource_id, site_code)")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_HasMember' ORDER BY end_id").fetchall()
    assert rows == [("PS100016@PS1", "GUID-1"), ("PS100016@PS1", "S-1-5-21-1-2-3-1106")]


def test_edge_has_member_skips_non_client_computer():
    """A discovery-only computer -- one SCCM only knows about from AD/heartbeat
    discovery (present in SMS_R_System, so it has a SID) but that never installed the
    SCCM client (no SMS_R_System client-device record) -- must NOT get an SCCM_HasMember
    edge to its Computer/SID node.

    CMBP (ps1:7617-7619) resolves a collection member only to a User, Group, or
    SCCM_ClientDevice node; a non-client computer matches none of those, so CMBP draws
    no edge and logs "No node found for member" (ps1:7646). This reproduces the live
    DC/WAC/HYPER-V case where such machines (member of the built-in All Systems
    collection) were wrongly linked to their AD Computer node because the SID fallback
    still covered SMS_R_System computers.
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    # A discovery-only computer: in SMS_R_System (has a SID) but NOT a client device.
    # security_group_name is NULL here (present only so the unrelated node_group builder,
    # which reads SMS_R_System, doesn't log a missing-column error during this test).
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'DC' AS name, "
                "'S-1-5-21-1-2-3-1001' AS sid, 100 AS resource_id, 'PS1' AS source_site_code, "
                "false AS obsolete, NULL AS security_group_name")
    # A real client device (7) is present so we prove the fix drops ONLY the non-client
    # computer, not legitimate device members.
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    # All Systems (SMS00001-style) membership: the client device (7) and the non-client
    # computer (100). Only the client device should produce an edge.
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT * FROM (VALUES "
                "('PS100016', 7, 'PS1'), ('PS100016', 100, 'PS1')) "
                "AS t(collection_id, resource_id, site_code)")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_HasMember' ORDER BY end_id").fetchall()
    # Only the client device (7 -> GUID-1) survives; the non-client computer (100 ->
    # S-1-5-21-1-2-3-1001) gets no edge.
    assert rows == [("PS100016@PS1", "GUID-1")]
