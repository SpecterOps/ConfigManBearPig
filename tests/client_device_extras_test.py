# src/openhound_sccm/tests/client_device_extras_test.py
"""Task B3: SCCM_ClientDevice telemetry extras (CMBP parity).

currentManagementPoint/SID (CMBP ps1:4010-4011/7233-7234) and previousSMSID/
ChangeDate (ps1:4016-4017, Local-only) are net-new; userName/userDomainName
(ps1:7253-7254) are new output keys that reuse the existing ad_last_logon_*
values (CMBP emits the one collected value under two keys).
"""
import duckdb

from openhound_sccm.models.sccm_client_device import SCCMClientDevice
from openhound_sccm.transforms import transforms


def _hierarchy(con):
    # Standalone primary site PS1 -> root_site_code = 'PS1'.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('PS1', NULL, 2)) AS t(site_code, parent_site_code, site_type)"
    )


def test_client_device_extras_from_adminservice_and_local_wmi():
    """Full case: AdminService supplies current_management_point (real raw column is
    cn_access_mp, confirmed against a live collection bucket -- NOT c_n_access_mp);
    local_wmi_ccm_client supplies previous_smsid/ChangeDate and a fallback SID;
    principal_by_name resolves the MP name to a SID and must win over local's own
    current_management_point_sid field (AdminService/resolved-name path takes priority)."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)

    # Seeds principal_by_name with (name, sid) so the MP name resolves to a SID.
    con.execute(
        "CREATE TABLE sccm.adminservice_r_system AS SELECT "
        "'PS1-MP' AS name, 'S-1-5-21-1-2-3-9001' AS sid"
    )

    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'guid-1' AS smsid, 'WS01' AS name, 7 AS resource_id, 'PS1' AS site_code, "
        "true AS is_client, false AS is_obsolete, "
        "'PS1-MP' AS cn_access_mp, "
        "'MAYYHEM\\alice' AS user_name, 'CORP' AS user_domain_name"
    )

    # local_wmi_ccm_client's current_management_point_sid is deliberately wrong/stale so the
    # test proves principal_by_name resolution wins over it in the coalesce.
    con.execute(
        "CREATE TABLE sccm.local_wmi_ccm_client AS SELECT "
        "'guid-1' AS smsid, 'PS1-MP' AS current_management_point, "
        "'S-1-5-21-1-2-3-STALE' AS current_management_point_sid, "
        "'GUID-0-OLD' AS previous_smsid, "
        "'2026-01-01T00:00:00Z' AS previous_smsid_change_date"
    )

    transforms(con)

    row = con.execute(
        "SELECT current_management_point, current_management_point_sid, "
        "previous_smsid, previous_smsid_change_date, ad_last_logon_user_name, "
        "ad_last_logon_user_domain "
        "FROM sccm.node_client_device WHERE smsid = 'GUID-1'"
    ).fetchone()
    assert row is not None, "node_client_device row for GUID-1 not found"
    (current_mp, current_mp_sid, previous_smsid, previous_smsid_change_date,
     ad_last_logon_user_name, ad_last_logon_user_domain) = row

    assert current_mp == "PS1-MP", f"current_management_point: {current_mp}"
    # principal_by_name's resolved SID must win over local_wmi_ccm_client's own (stale) SID.
    assert current_mp_sid == "S-1-5-21-1-2-3-9001", f"current_management_point_sid: {current_mp_sid}"
    assert previous_smsid == "GUID-0-OLD", f"previous_smsid: {previous_smsid}"
    assert previous_smsid_change_date == "2026-01-01T00:00:00Z", \
        f"previous_smsid_change_date: {previous_smsid_change_date}"
    assert ad_last_logon_user_name == "MAYYHEM\\alice"
    assert ad_last_logon_user_domain == "CORP"

    # Model layer: build the SCCMNode from this row's shape and confirm the six output
    # properties carry exact CMBP casing, including userName/userDomainName mirroring
    # ADLastLogonUser/ADLastLogonUserDomain from the SAME source values.
    device = SCCMClientDevice(
        smsid="GUID-1", name="WS01", site_code="PS1", root_site_code="PS1",
        resource_id_str="7@PS1",
        ad_last_logon_user_name=ad_last_logon_user_name,
        ad_last_logon_user_domain=ad_last_logon_user_domain,
        current_management_point=current_mp,
        current_management_point_sid=current_mp_sid,
        previous_smsid=previous_smsid,
        previous_smsid_change_date=previous_smsid_change_date,
    )
    p = device.as_node.properties
    assert p.currentManagementPoint == "PS1-MP"
    assert p.currentManagementPointSID == "S-1-5-21-1-2-3-9001"
    assert p.previousSMSID == "GUID-0-OLD"
    assert p.previousSMSIDChangeDate == "2026-01-01T00:00:00Z"
    assert p.userName == p.ADLastLogonUser == "MAYYHEM\\alice"
    assert p.userDomainName == p.ADLastLogonUserDomain == "CORP"


def test_client_device_cn_online_offline_times_populate():
    """Regression: lastOnlineTime/lastOfflineTime must populate from the real raw columns.

    The SMS device-resource CNLastOnlineTime/CNLastOfflineTime snake-case to
    cn_last_online_time/cn_last_offline_time (dlt treats "CN" as one token). A prior
    typo sourced them from c_n_last_online_time/c_n_last_offline_time, which no collector
    emits -- _ensure_columns silently NULL-stubbed those, so both output properties were
    always empty. This test seeds the real cn_* columns and asserts the values reach the
    node column and the CMBP-cased output property, so the typo can't silently return.
    """
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)

    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'guid-3' AS smsid, 'WS03' AS name, 9 AS resource_id, 'PS1' AS site_code, "
        "true AS is_client, false AS is_obsolete, "
        "'2026-07-01T08:00:00Z' AS cn_last_online_time, "
        "'2026-07-01T18:30:00Z' AS cn_last_offline_time"
    )

    transforms(con)

    row = con.execute(
        "SELECT last_online_time, last_offline_time "
        "FROM sccm.node_client_device WHERE smsid = 'GUID-3'"
    ).fetchone()
    assert row is not None, "node_client_device row for GUID-3 not found"
    last_online_time, last_offline_time = row
    assert last_online_time == "2026-07-01T08:00:00Z", f"last_online_time: {last_online_time}"
    assert last_offline_time == "2026-07-01T18:30:00Z", f"last_offline_time: {last_offline_time}"

    # Model layer: the values must reach the CMBP-cased output properties.
    device = SCCMClientDevice(
        smsid="GUID-3", name="WS03", site_code="PS1", root_site_code="PS1",
        resource_id_str="9@PS1",
        last_online_time=last_online_time, last_offline_time=last_offline_time,
    )
    p = device.as_node.properties
    assert p.lastOnlineTime == "2026-07-01T08:00:00Z"
    assert p.lastOfflineTime == "2026-07-01T18:30:00Z"


def test_client_device_extras_without_local_wmi_ccm_client():
    """Guard case: no local_wmi_ccm_client table at all (e.g. a collector host that
    isn't itself an SCCM client). previousSMSID/ChangeDate stay NULL, currentManagementPoint
    still comes through from AdminService, and the missing table must not crash the
    correlated subqueries in _enrich_client_device."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    _hierarchy(con)

    con.execute(
        "CREATE TABLE sccm.adminservice_client_devices AS SELECT "
        "'guid-2' AS smsid, 'WS02' AS name, 8 AS resource_id, 'PS1' AS site_code, "
        "true AS is_client, false AS is_obsolete, "
        "'PS1-MP2' AS cn_access_mp"
    )
    # No sccm.local_wmi_ccm_client table at all.

    transforms(con)  # must not raise

    row = con.execute(
        "SELECT current_management_point, current_management_point_sid, "
        "previous_smsid, previous_smsid_change_date "
        "FROM sccm.node_client_device WHERE smsid = 'GUID-2'"
    ).fetchone()
    assert row is not None, "node_client_device row for GUID-2 not found"
    current_mp, current_mp_sid, previous_smsid, previous_smsid_change_date = row

    assert current_mp == "PS1-MP2", f"current_management_point: {current_mp}"
    # No principal_by_name entry and no local fallback -> unresolved SID stays NULL.
    assert current_mp_sid is None, f"current_management_point_sid: {current_mp_sid}"
    assert previous_smsid is None, f"previous_smsid: {previous_smsid}"
    assert previous_smsid_change_date is None, f"previous_smsid_change_date: {previous_smsid_change_date}"
