"""Check that the retained lab evidence supports the permission findings.

These tests read recorded results and never connect to SCCM. The PowerShell
scripts beside this file perform the separate, manual live experiments.
"""

import json
from pathlib import Path

import pytest

EVIDENCE_DIRECTORY = Path(__file__).parent / "evidence"


def dictionary(value: object) -> dict[str, object]:
    """Validate a JSON object at the evidence-file boundary."""
    assert isinstance(value, dict)
    result: dict[str, object] = {}
    for key, item in value.items():
        assert isinstance(key, str)
        result[key] = item
    return result


def sequence(value: object) -> list[object]:
    """Validate a JSON list without assuming its contents have a fixed shape."""
    assert isinstance(value, list)
    return list(value)


def read_json(name: str) -> object:
    """Read a retained result; JSON values are validated by their caller."""
    return json.loads((EVIDENCE_DIRECTORY / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def experiments() -> dict[str, list[dict[str, object]]]:
    """Index the different experiments while preserving their original fields."""
    evidence = dictionary(read_json("results.json"))
    result: dict[str, list[dict[str, object]]] = {}
    for raw_experiment in sequence(evidence["experiments"]):
        experiment = dictionary(raw_experiment)
        name = experiment["experiment"]
        assert isinstance(name, str)
        result[name] = [dictionary(row) for row in sequence(experiment["records"])]
    return result


def find(
    experiments: dict[str, list[dict[str, object]]],
    experiment: str,
    **selectors: str | int,
) -> dict[str, object]:
    """Require exactly one record matching a named scenario."""
    matches = [
        row
        for row in experiments[experiment]
        if all(row.get(key) == value for key, value in selectors.items())
    ]
    assert len(matches) == 1, (experiment, selectors)
    return matches[0]


def assert_system_marker(record: dict[str, object], computer: str = "PS1-DEV") -> None:
    """A successful request alone is insufficient: require the observed identity."""
    assert record["verified"] is True
    marker = dictionary(record["marker"])
    assert marker["sid"] == "S-1-5-18"
    assert marker["computer"] == computer
    nonce = marker["nonce"]
    assert isinstance(nonce, str) and len(nonce) == 32


@pytest.mark.parametrize(
    "experiment",
    [
        "application-author-and-deploy",
        "package-author-and-deploy",
        "task-sequence-author-and-deploy",
        "configuration-item-author-and-deploy",
    ],
)
def test_same_restricted_actor_supplied_and_deployed_code(experiments, experiment):
    record = experiments[experiment][0]
    assert_system_marker(record)
    assert record.get("applicationMask", record.get("objectMask")) == 1027
    assert str(record["actor"]).startswith("MAYYHEM\\cpr")


@pytest.mark.parametrize(
    "experiment",
    [
        "application-outside-collection",
        "package-outside-collection",
        "task-sequence-outside-collection",
        "configuration-item-outside-collection",
    ],
)
def test_editing_deployed_objects_can_cross_collection_boundary(
    experiments, experiment
):
    record = experiments[experiment][0]
    assert_system_marker(record)
    assert record["assignedCollection"] != record["deploymentCollection"]
    assert record["collectionMask"] == 0


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Minimal Run Script plus script Read", True),
        ("Narrow collection inside target", True),
        ("Narrow collection outside target", False),
        ("Global read with narrow Run Script outside target", False),
        ("Run Script and script Read on separate roles and scopes", True),
        ("Script Read outside the script object scope", False),
    ],
)
def test_script_collection_and_object_scope_boundaries(experiments, name, expected):
    record = find(experiments, "script-limits-valid", name=name)
    assert record["verified"] is expected
    if expected:
        assert_system_marker(record)
    else:
        assert dictionary(record["run"])["status"] == 403
        assert record["marker"] is None


def test_script_runner_did_not_need_site_or_collection_read(experiments):
    record = find(
        experiments, "script-limits-valid", name="Minimal Run Script plus script Read"
    )
    assert record["collectionMask"] == 268435456
    assert record["siteMask"] == 0
    assert record["scriptMask"] == 1


def test_separate_script_author_approval_was_enforced(experiments):
    for record in experiments["script-approval"]:
        expected = record["name"] == "Approve only approving another script"
        assert record["approved"] is expected
        if record["created"] and not expected:
            assert record["finalApproval"] == 0


def test_editing_script_required_create_and_reset_approval(experiments):
    assert all(not row["updated"] for row in experiments["script-modification-valid"])
    for record in experiments["script-modification-create-permission"]:
        assert record["updated"] is True
        assert record["approvalAfterChange"] == 0
        assert record["finalApproval"] == 0
        assert str(record["authorAfterChange"]).lower() == str(record["actor"]).lower()


def test_site_route_and_role_edit_route_really_executed(experiments):
    site = find(
        experiments,
        "status-filters-native-console",
        name="Manage status filters with Read",
    )
    assert_system_marker(site, "PS1-PSS")
    role = experiments["role-to-site"][0]
    assert_system_marker(role, "PS1-PSS")
    assert sequence(role["assignedCollections"]) != ["SMS00001"]


def test_site_computer_reached_database_and_provider_as_administrator(experiments):
    record = experiments["site-to-infrastructure-identity"][0]
    assert_system_marker(record, "PS1-PSS")
    remote_markers = sequence(record["remoteMarkers"])
    assert len(remote_markers) == 2
    for raw_remote in remote_markers:
        remote = dictionary(raw_remote)
        assert remote["verified"] is True
        marker = dictionary(remote["marker"])
        assert marker["sid"] == record["expectedRemoteIdentity"]
        assert marker["identity"] == "mayyhem\\PS1-PSS$"
        assert marker["isAdministrator"] is True


def test_separate_read_role_did_not_widen_modification_scope(experiments):
    package = experiments["package-object-scope-control"][0]
    assert package["actionAccepted"] is False
    assert "no modify permissions" in str(
        dictionary(package["error"])["providerDescription"]
    )
    site = experiments["site-object-scope-control"][0]
    assert site["created"] is False
    assert "required security rights" in str(dictionary(site["error"])["message"])


def test_grants_respected_the_granting_roles_own_boundaries(experiments):
    for record in experiments["delegation-limits"]:
        expected = record["name"] in {
            "narrow read, global grant role, request global",
            "all assignments narrow, request same narrow",
        }
        assert record["granted"] is expected
        assert record["verified"] is expected


def test_add_and_modify_are_different_abilities(experiments):
    for record in experiments["administrator-minimal-permissions"]:
        expected = (
            record["profile"]
            in {"Add only", "CMPivot Administrator as found in this lab"}
            and record["target"] == "new entry"
        ) or (
            record["profile"]
            in {
                "Modify only",
                "CMPivot Administrator as found in this lab",
            }
            and record["target"] == "update own existing entry by key"
        )
        assert record["success"] is expected


def test_all_completed_cases_reported_cleanup_and_roles_were_unchanged(experiments):
    records = [row for rows in experiments.values() for row in rows]
    assert len(records) == 134
    assert all(row["cleanupComplete"] is True for row in records)
    verification = dictionary(read_json("original-role-verification.json"))
    assert verification == {
        "roleCount": 15,
        "operationsUnchanged": True,
        "namesUnchanged": True,
    }
    assert all(
        count == 0
        for count in dictionary(read_json("cleanup-client-policies.json")).values()
    )


def test_independent_final_audit_found_no_remaining_assets():
    audit = dictionary(read_json("cleanup-final.json"))
    assert all(count == 0 for count in dictionary(audit["remainingObjects"]).values())
    assert all(
        count == 0 for count in dictionary(audit["remainingMarkerFiles"]).values()
    )
