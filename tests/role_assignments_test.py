"""Prove that one role cannot borrow another role's collections or scopes."""

import json

import duckdb
import pytest

from openhound_sccm.models.graph_edge import GraphEdge
from openhound_sccm.role_assignments import (
    build_collection_coverage,
    build_role_assignments,
)
from openhound_sccm.transforms import transforms


def permission(role: str, category: str, category_type: int = 1) -> dict[str, object]:
    """One original SCCM assignment entry, with its native field names."""
    return {
        "RoleID": role,
        "CategoryID": category,
        "CategoryTypeID": category_type,
        "RoleName": "Original role name",
        "CategoryName": "Original category name",
    }


@pytest.fixture
def connection():
    """Two device collections, an inherited collection, and overlapping devices."""
    with duckdb.connect() as con:
        con.execute("CREATE SCHEMA sccm")
        con.execute(
            "CREATE TABLE sccm.adminservice_site_definitions AS "
            "SELECT 'CAS' AS site_code, NULL AS parent_site_code, 4 AS site_type"
        )
        con.execute(
            "CREATE TABLE sccm.adminservice_security_roles AS SELECT * FROM (VALUES "
            "('SMS0001R','Full Administrator'),('SMS000ER','Operations Administrator')) "
            "t(role_id, role_name)"
        )
        con.execute(
            "CREATE TABLE sccm.adminservice_collections AS SELECT * FROM (VALUES "
            "('C1','Servers',2,NULL), ('C2','Workstations',2,NULL), "
            "('C3','Limited servers',2,'C1')) "
            "t(collection_id,name,collection_type,limit_to_collection_id)"
        )
        con.execute(
            "CREATE TABLE sccm.adminservice_client_devices AS SELECT * FROM (VALUES "
            "('GUID-1','Server',1,'CAS',true,false), "
            "('GUID-2','Workstation',2,'CAS',true,false), "
            "('GUID-3','Shared',3,'CAS',true,false), "
            "('GUID-4','Inherited',4,'CAS',true,false)) "
            "t(smsid,name,resource_id,site_code,is_client,is_obsolete)"
        )
        con.execute(
            "CREATE TABLE sccm.adminservice_collection_members AS SELECT * FROM (VALUES "
            "('C1',1,'CAS'), ('C1',3,'CAS'), ('C2',2,'CAS'), ('C2',3,'CAS'), ('C3',4,'CAS')) "
            "t(collection_id,resource_id,site_code)"
        )
        con.execute(
            "CREATE TABLE sccm.adminservice_admins (logon_name VARCHAR, "
            "roles VARCHAR[], collection_names VARCHAR[], permissions JSON, permissions_complete BOOLEAN, admin_sid VARCHAR)"
        )
        yield con


def add_admin(con, name: str, entries: object, complete: bool | None = True) -> None:
    """Deliberately give every administrator the same broad overview lists."""
    con.execute(
        "INSERT INTO sccm.adminservice_admins VALUES (?, ?, ?, ?, ?, NULL)",
        [
            name,
            ["SMS0001R", "SMS000ER"],
            ["Servers", "Workstations"],
            json.dumps(entries) if entries is not None else None,
            complete,
        ],
    )


def access_edges(con, name: str) -> set[tuple[str, str]]:
    return set(
        con.execute(
            "SELECT kind, end_id FROM sccm.graph_edges WHERE start_id = ? "
            "AND kind IN ('SCCM_FullAdministrator','SCCM_OperationsAdministrator')",
            [name.upper() + "@CAS"],
        ).fetchall()
    )


def test_different_roles_keep_their_own_collections_and_overlapping_devices(connection):
    con = connection
    add_admin(
        con,
        "MAYYHEM\\alice",
        [
            permission("SMS0001R", "C1"),
            permission("SMS000ER", "C2"),
            permission("SMS0001R", "SCOPE-A", 29),
        ],
    )
    transforms(con)
    assert access_edges(con, "MAYYHEM\\alice") == {
        ("SCCM_FullAdministrator", "GUID-1"),
        ("SCCM_FullAdministrator", "GUID-3"),
        ("SCCM_FullAdministrator", "GUID-4"),
        ("SCCM_OperationsAdministrator", "GUID-2"),
        ("SCCM_OperationsAdministrator", "GUID-3"),
    }
    assignment = con.execute(
        "SELECT collection_ids, security_scope_ids FROM sccm.graph_edges "
        "WHERE start_id = 'MAYYHEM\\ALICE@CAS' AND end_id = 'SMS0001R@CAS' "
        "AND kind = 'SCCM_IsAssigned'"
    ).fetchone()
    assert assignment == (["C1"], ["SCOPE-A"])
    evidence = con.execute(
        "SELECT collection_ids FROM sccm.graph_edges WHERE "
        "kind='SCCM_FullAdministrator' AND end_id='GUID-4'"
    ).fetchone()
    assert evidence == (
        ["C1"],
    )  # Record the actual assignment, even for inherited access.


def test_same_role_shared_by_two_administrators_does_not_mix_collections(connection):
    con = connection
    add_admin(con, "MAYYHEM\\alice", [permission("SMS0001R", "C1")])
    add_admin(con, "MAYYHEM\\bob", [permission("SMS0001R", "C2")])
    transforms(con)
    assert ("SCCM_FullAdministrator", "GUID-2") not in access_edges(
        con, "MAYYHEM\\alice"
    )
    assert access_edges(con, "MAYYHEM\\bob") == {
        ("SCCM_FullAdministrator", "GUID-2"),
        ("SCCM_FullAdministrator", "GUID-3"),
    }


def test_full_administrator_cannot_borrow_read_only_collections(connection):
    """Match the live allow/deny test: Full Administrator here, Read-only there."""
    con = connection
    con.execute(
        "INSERT INTO sccm.adminservice_security_roles VALUES "
        "('SMS0002R', 'Read-only Analyst')"
    )
    add_admin(
        con,
        "MAYYHEM\\alice",
        [
            permission("SMS0001R", "C1"),
            permission("SMS0002R", "C2"),
            permission("SMS0001R", "SMS00ALL", 29),
            permission("SMS0002R", "SMS00ALL", 29),
        ],
    )
    con.execute("UPDATE sccm.adminservice_admins SET roles = ['SMS0001R','SMS0002R']")
    transforms(con)
    assert access_edges(con, "MAYYHEM\\alice") == {
        ("SCCM_FullAdministrator", "GUID-1"),
        ("SCCM_FullAdministrator", "GUID-3"),
        ("SCCM_FullAdministrator", "GUID-4"),
    }


@pytest.mark.parametrize(
    "entries,complete",
    [
        (None, None),
        ({"RoleID": "SMS0001R"}, True),
        ([permission("SMS0001R", "C1")], False),
        ([permission("SMS0001R", "C1"), permission("SMS0001R", "C2", 999)], True),
        ([{"RoleID": "SMS0001R", "CategoryID": "C1"}], True),
        ([permission("", "C1")], True),
    ],
)
def test_missing_or_invalid_details_never_use_the_overview_lists(
    connection, entries, complete, caplog
):
    add_admin(connection, "MAYYHEM\\alice", entries, complete)
    transforms(connection)
    assert access_edges(connection, "MAYYHEM\\alice") == set()
    assert "withholding their calculated access" in caplog.text


def test_security_scope_with_collection_id_does_not_grant_device_access(connection):
    add_admin(connection, "MAYYHEM\\alice", [permission("SMS0001R", "C1", 29)])
    transforms(connection)
    assert access_edges(connection, "MAYYHEM\\alice") == set()
    assert connection.execute(
        "SELECT collection_ids, security_scope_ids FROM sccm.admin_role_assignments"
    ).fetchone() == ([], ["C1"])


def test_empty_retrieved_list_is_valid_and_grants_nothing(connection, caplog):
    add_admin(connection, "MAYYHEM\\alice", [])
    transforms(connection)
    assert access_edges(connection, "MAYYHEM\\alice") == set()
    assert "withholding their calculated access" not in caplog.text


def test_collection_cycles_stop_and_keep_original_assignment_evidence(connection):
    con = connection
    add_admin(con, "MAYYHEM\\alice", [permission("SMS0001R", "C1")])
    build_role_assignments(con, "sccm", "CAS")
    con.execute(
        "CREATE TABLE sccm.node_collection AS SELECT * FROM (VALUES "
        "('C1','C3'), ('C3','C1')) t(collection_id, limit_to_collection_id)"
    )
    build_collection_coverage(con, "sccm")
    assert con.execute(
        "SELECT assigned_collection_id, collection_id FROM "
        "sccm.admin_collection_permissions ORDER BY collection_id"
    ).fetchall() == [("C1", "C1"), ("C1", "C3")]


def test_raw_assignments_keep_original_fields_and_values(connection):
    entries = [permission("sms0001r", "c1"), permission("sms0001r", "Scope-A", 29)]
    add_admin(connection, "MAYYHEM\\alice", entries)
    build_role_assignments(connection, "sccm", "CAS")
    assert (
        json.loads(
            connection.execute(
                "SELECT permissions FROM sccm.adminservice_admins"
            ).fetchone()[0]
        )
        == entries
    )
    assert connection.execute(
        "SELECT role_id, collection_ids, security_scope_ids FROM "
        "sccm.admin_role_assignments"
    ).fetchone() == ("SMS0001R", ["C1"], ["SCOPE-A"])


def test_duplicate_providers_merge_evidence_without_mixing_roles(connection):
    con = connection
    add_admin(
        con,
        "MAYYHEM\\alice",
        [permission("SMS0001R", "C1"), permission("SMS000ER", "C2")],
    )
    con.execute(
        "CREATE TABLE sccm.wmi_admins AS SELECT * FROM sccm.adminservice_admins"
    )
    transforms(con)
    # Convert a real preprocessed row, using DuckDB's native list values.
    cursor = con.execute(
        "SELECT * FROM sccm.graph_edges_sccm WHERE kind='SCCM_FullAdministrator' AND end_id='GUID-1'"
    )
    edge = dict(zip([column[0] for column in cursor.description], cursor.fetchone()))
    emitted = list(GraphEdge(**edge).edges)[0]
    assert emitted.properties.collectionIds == ["C1"]
    assert sorted(emitted.properties.collectionSource) == [
        "AdminService-SMS_Admin",
        "WMI-SMS_Admin",
    ]
    assert emitted.properties.securityScopeIds is None


def test_all_permissions_cannot_borrow_global_collection_from_another_role(connection):
    con = connection
    add_admin(
        con,
        "MAYYHEM\\alice",
        [permission("SMS0001R", "SMS00001"), permission("SMS000ER", "SMS00004")],
    )
    add_admin(
        con,
        "MAYYHEM\\bob",
        [permission("SMS0001R", "SMS00001"), permission("SMS0001R", "SMS00004")],
    )
    transforms(con)
    assert con.execute(
        "SELECT start_id FROM sccm.graph_edges WHERE kind='SCCM_AllPermissions'"
    ).fetchall() == [("MAYYHEM\\BOB@CAS",)]
