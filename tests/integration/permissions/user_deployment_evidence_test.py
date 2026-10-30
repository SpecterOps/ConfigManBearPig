"""Check the recorded lab comparisons without contacting SCCM.

Deployment acceptance alone does not prove execution. Successful execution cases
must contain the requested unique marker and the actual Windows identity.
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

EVIDENCE = Path(__file__).parent / "evidence" / "user-deployment-results.json"
EXECUTION_CASES = (
    "user-required-as-user",
    "device-required-as-user",
    "user-required-as-system-disconnected",
    "device-required-as-system",
    "user-available-as-user",
    "user-available-as-system",
    "user-required-future-deadline",
)


def object_value(value: object) -> dict[str, object]:
    """Require a JSON object before inspecting its recorded fields."""
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return dict(value)


def list_value(value: object) -> list[object]:
    """Require a JSON array before inspecting its records."""
    assert isinstance(value, list)
    return list(value)


def timestamp(value: object) -> datetime:
    """Require a timestamp with a timezone for deadline comparisons."""
    assert isinstance(value, str)
    result = datetime.fromisoformat(value)
    assert result.utcoffset() is not None
    return result


@pytest.fixture(scope="module")
def evidence() -> dict[str, object]:
    """Read retained evidence, including excluded attempts and cleanup."""
    return object_value(json.loads(EVIDENCE.read_text(encoding="utf-8")))


def case(evidence: dict[str, object], name: str) -> dict[str, object]:
    """Select a named experiment so similar runs cannot be mixed up."""
    return object_value(object_value(evidence["executionCases"])[name])


@pytest.mark.parametrize("target", ["User", "Device"])
def test_same_deployment_rights_work_for_both_execution_identities(evidence, target):
    rows = [
        object_value(value)
        for value in list_value(evidence["permissionComparisons"])
        if object_value(value)["group"] == "deployment-permissions"
        and object_value(value)["targetType"] == target
    ]
    assert len(rows) == 5
    for row in rows:
        assert "setupError" not in row
        assert row["matchesExpectation"] is True
        expected = row["name"] in {"deploy user identity", "deploy system identity"}
        assert row["accepted"] is expected
        if expected:
            assert row["applicationMask"] == 1
            assert row["collectionMask"] == 1052673
            assert row["assignedCollection"] == row["targetCollection"]
            assert isinstance(row["assignmentID"], int)
        else:
            assert object_value(row["error"])["message"]
            # No Application Read failed console lookup; this is not evidence
            # of a separately tested direct-provider authorization check.


@pytest.mark.parametrize("application_mask", [1, 3])
def test_application_modify_switches_both_directions(evidence, application_mask):
    rows = [
        object_value(value)
        for value in list_value(evidence["permissionComparisons"])
        if object_value(value)["group"] == "context-permissions"
        and object_value(value)["applicationMask"] == application_mask
    ]
    assert len(rows) == 2
    assert {row["initialBehavior"] for row in rows} == {
        "InstallForUser",
        "InstallForSystem",
    }
    for row in rows:
        assert row["collectionMask"] == 0
        assert row["accepted"] is (application_mask == 3)
        saved_behavior = (
            row["changedBehavior"] if row["accepted"] else row["initialBehavior"]
        )
        assert isinstance(saved_behavior, str)
        assert object_value(row["saved"])["Contexts"] == [
            saved_behavior.removeprefix("InstallFor")
        ]


@pytest.mark.parametrize("name", EXECUTION_CASES)
def test_execution_requires_a_matching_identity_marker(evidence, name):
    row = case(evidence, name)
    assert row["verified"] is True
    assert "error" not in row and "setupError" not in row
    assert row["applicationMask"] == 1027
    assert row["collectionMask"] == 1052673
    marker = object_value(row["marker"])
    requested = object_value(row["requestedMarker"])
    assert marker["nonce"] == requested["nonce"]
    assert isinstance(marker["nonce"], str) and len(marker["nonce"]) == 32
    expected_sid = (
        "S-1-5-18"
        if row["behavior"] == "InstallForSystem"
        else evidence["recipientSID"]
    )
    assert marker["sid"] == expected_sid == row["expectedSID"]
    assert timestamp(marker["writtenUTC"]) >= timestamp(row["assignedUTC"])
    # Notify Resource is a different bit and was absent from every execution actor.
    assert int(str(row["collectionMask"])) & 536870912 == 0
    if row["purpose"] == "Required":
        assert "recipientInstall" not in row


@pytest.mark.parametrize("name", ["user-available-as-user", "user-available-as-system"])
def test_available_execution_followed_the_actual_software_center_action(evidence, name):
    row = case(evidence, name)
    assert row["beforeUserInstall"] is None
    action = object_value(row["recipientInstall"])
    assert action["action"] == "SoftwareCenter"
    assert action["sid"] == evidence["recipientSID"]
    assert (
        object_value(action["softwareCenter"])["exactApplicationTitlePresent"] is True
    )
    install = object_value(action["install"])
    assert install["invoked"] is True
    assert install["application"] == object_value(row["application"])["Name"]
    assert timestamp(object_value(row["marker"])["writtenUTC"]) >= timestamp(
        action["utc"]
    )


def test_required_execution_obeyed_the_future_deadline(evidence):
    row = case(evidence, "user-required-future-deadline")
    assert row["beforeDeadlineMarker"] is None
    deadline = timestamp(row["enforcementDeadlineUTC"])
    assert timestamp(row["beforeDeadlineObservedUTC"]) < deadline
    assert timestamp(object_value(row["marker"])["writtenUTC"]) >= deadline


def test_disconnected_user_execution_waited_but_system_execution_succeeded(evidence):
    waiting = object_value(evidence["disconnectedUserObservation"])
    assert waiting["verified"] is False and waiting["marker"] is None
    applications = list_value(object_value(waiting["recipientAfter"])["applications"])
    assert len(applications) == 1
    assert object_value(applications[0])["EvaluationState"] == 17
    system = case(evidence, "user-required-as-system-disconnected")
    sessions = list_value(system["sessionsBefore"])
    assert any("domainuser" in str(line) and "Disc" in str(line) for line in sessions)
    assert object_value(system["marker"])["sid"] == "S-1-5-18"


def test_policy_notification_is_a_separate_optional_permission(evidence):
    rows = list_value(evidence["notificationComparisons"])
    assert len(rows) == 4
    for value in rows:
        row = object_value(value)
        expected = row["targetType"] == "Device" and row["collectionMask"] == 536875009
        assert row["accepted"] is expected
        if row["targetType"] == "User":
            assert "No object corresponds" in str(object_value(row["error"])["message"])
            # This console lookup failure is not a general provider denial.


def test_recipient_privileges_are_reported_without_claiming_zero_sccm_rights(evidence):
    verification = object_value(evidence["recipientVerification"])
    recipient = object_value(verification["recipient"])
    assert recipient["isWindowsAdministrator"] is False
    assert recipient["sid"] == evidence["recipientSID"]
    role = object_value(verification["existingRole"])
    assert role["name"] == "CMPivot Administrator"
    operations = [object_value(value) for value in list_value(role["operations"])]
    assert not any(row["objectType"] == 31 for row in operations)
    collection = next(row for row in operations if row["objectType"] == 1)
    assert "Deploy Applications" not in list_value(collection["actions"])
    assert "Notify Resource" not in list_value(collection["actions"])


def test_cleanup_and_original_roles_were_independently_verified(evidence):
    cleanup = object_value(evidence["cleanup"])
    assert all(
        count == 0 for count in object_value(cleanup["remainingObjects"]).values()
    )
    for field in (
        "remainingClientPolicies",
        "remainingClientRequests",
        "remainingMarkers",
    ):
        assert cleanup[field] == 0
    assert cleanup["originalRoleCount"] == 15
    assert cleanup["originalRolesUnchanged"] is True
    assert any(
        "domainuser" in str(line) and "Disc" in str(line)
        for line in list_value(cleanup["sessions"])
    )
    assert list_value(evidence["excludedAttempts"])
