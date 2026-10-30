"""Check retained two-client evidence without connecting to the lab.

A deployment ID is not execution evidence. These checks require matching
markers, Windows identities, ordering, local detection, and completed cleanup.
Unresolved primary-device experiments must remain separate from confirmed paths.
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

EVIDENCE = Path(__file__).parent / "evidence" / "user-placement-results.json"


@pytest.fixture(scope="module")
def evidence():
    """Load the recorded observations, including unsuccessful experiments."""
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def phase(row, name):
    """Select one phase by its purpose rather than its position."""
    return next(item["result"] for item in row["phases"] if item["name"] == name)


@pytest.mark.parametrize("behavior", ["InstallForSystem", "InstallForUser"])
def test_one_assignment_executes_independently_on_two_clients(evidence, behavior):
    row = next(row for row in evidence["propagation"] if row["behavior"] == behavior)
    assert isinstance(row["assignment"]["ID"], int)
    assert row["applicationMask"] == 1027
    assert row["collectionMask"] == 1052673
    assert row["secondBeforeRequest"]["markerCount"] == 0
    first = phase(row, "first-computer")
    second = phase(row, "second-computer-same-assignment")
    assert first["expectedObserved"] is True
    assert second["expectedObserved"] is True
    first_assignments = {
        assignment["AssignmentID"]
        for client in first["clients"]
        for assignment in client["assignments"]
    }
    second_assignments = {
        assignment["AssignmentID"]
        for client in second["clients"]
        for assignment in client["assignments"]
    }
    assert len(first_assignments) == 1
    assert first_assignments == second_assignments
    first_marker = first["clients"][0]["markers"][0]
    second_marker = second["clients"][0]["markers"][0]
    assert first_marker["computer"] == "PS1-DEV"
    assert second_marker["computer"] == "PS1-DP"
    expected_sid = (
        "S-1-5-18" if behavior == "InstallForSystem" else evidence["recipientSID"]
    )
    for marker in (first_marker, second_marker):
        assert marker["sid"] == expected_sid
        assert marker["nonce"] == row["requestedMarker"]["nonce"]
    assert datetime.fromisoformat(first_marker["utc"]) < datetime.fromisoformat(
        second_marker["utc"]
    )


@pytest.mark.parametrize("behavior", ["InstallForSystem", "InstallForUser"])
def test_detected_installation_does_not_repeat_during_policy_checks(evidence, behavior):
    row = next(row for row in evidence["propagation"] if row["behavior"] == behavior)
    repeat = phase(row, "same-clients-after-success")
    assert repeat["elapsedSeconds"] >= 65
    assert {client["computer"] for client in repeat["clients"]} == {"PS1-DEV", "PS1-DP"}
    for client in repeat["clients"]:
        assert client["markerCount"] == 1
        assert client["markers"][0]["nonce"] == row["requestedMarker"]["nonce"]
    for state in row["recipientStates"]:
        assert state["isWindowsAdministrator"] is False
        assert len(state["applications"]) == 1
        assert state["applications"][0]["InstallState"] == "Installed"


def test_primary_requirement_has_no_claimed_success_without_positive_control(evidence):
    """A server-side primary association did not establish client execution."""
    run = evidence["primaryRequirement"]
    row = run["records"][0]
    assert (
        run["error"]["message"]
        == "Primary requirement positive control did not execute."
    )
    assert row["primaryRequirement"]["hasPrimaryDeviceRequirement"] is True
    assert row["primaryRequirement"]["addedBySetupAdministrator"] is True
    primary = row["firstPrimary"]
    assert primary["active"] is True
    assert 1 in primary["types"]
    result = phase(row, "only-primary-computer")
    assert result["expectedObserved"] is False
    assert result["elapsedSeconds"] >= 360
    assert all(client["markerCount"] == 0 for client in result["clients"])
    assert all(client["assignments"] for client in result["clients"])


def test_setup_failures_are_retained_separately(evidence):
    assert evidence["excludedAttempts"]
    for attempt in evidence["excludedAttempts"]:
        assert attempt["reason"]
        assert attempt["run"]["cleanupComplete"] is True
    assert evidence["machinePolicyIsSetupAcceleration"] is True


def test_predeployment_control_and_saved_flag_are_verified(evidence):
    run = evidence["predeployment"]
    row = run["records"][0]
    assert run["freshRecipient"]["credentialsPassedToClients"] is False
    assert row["initialOfferFlags"] & 1 == 0
    assert row["savedOfferFlags"] & 1 == 1
    assert row["savedPreDeploy"] is True
    assert row["applicationMask"] == 1027
    assert row["collectionMask"] == 1052673
    before = row["before"]
    assert {client["computer"] for client in before} == {"PS1-DEV", "PS1-DP"}
    assert all(client["recipientProfilePresent"] is False for client in before)
    assert all(
        client["recipientUserPolicyNamespacePresent"] is False for client in before
    )
    control = phase(row, "predeployment-disabled-no-session")
    assert control["elapsedSeconds"] >= 90
    assert all(client["markerCount"] == 0 for client in control["clients"])


def test_predeployment_does_not_count_a_saved_option_as_execution(evidence):
    """An observed failure is useful evidence and must not become a success."""
    run = evidence["predeployment"]
    row = run["records"][0]
    result = phase(row, "first-primary-no-session")
    if result["expectedObserved"]:
        observed = next(
            client for client in result["clients"] if client["computer"] == "PS1-DP"
        )
        assert observed["markerCount"] == 1
        marker = observed["markers"][0]
        assert marker["nonce"] == row["requestedMarker"]["nonce"]
        assert marker["sid"] == "S-1-5-18"
    else:
        assert result["elapsedSeconds"] >= 600
        assert all(client["markerCount"] == 0 for client in result["clients"])
        assert (
            run["error"]["message"]
            == "No-session primary predeployment was not observed."
        )
    assert all(
        client["recipientProfilePresent"] is False for client in result["clients"]
    )
    assert all(
        client["recipientUserPolicyNamespacePresent"] is False
        for client in result["clients"]
    )


def test_all_managed_clients_and_original_state_are_checked(evidence):
    audit = evidence["cleanup"]
    assert len(audit["clients"]) == 13
    assert len({client["computer"] for client in audit["clients"]}) == 13
    assert all(value == 0 for value in audit["remainingObjects"].values())
    for field in ("remainingClientPolicies", "remainingMarkers", "remainingTasks"):
        assert audit[field] == 0
    assert audit["originalRoleCount"] == 15
    assert audit["originalRolesUnchanged"] is True
    assert audit["originalAffinitiesRestored"] is True
    assert evidence["allRunJournalsEmpty"] is True
    assert evidence["recipientSessionRestored"] is True


def test_cleanup_preserves_original_sources_and_removes_only_new_association(evidence):
    proof = evidence["cleanupHelperProof"]
    assert proof["cleanupComplete"] is True
    assert len(proof["records"]) == 2
    for row in proof["records"]:
        assert row["restoredTypes"] == row["original"]["originalTypes"]
        assert row["restoredSources"] == row["original"]["originalSources"]
        if row["original"]["originalRelationshipExists"]:
            assert row["remainingRows"] == 1
            assert row["restoredSources"] == [4, 9]
        else:
            assert row["remainingRows"] == 0
    repair = evidence["cleanupRepair"]
    assert repair["afterSources"] == [4, 9]
    assert repair["afterTypes"] == []
    assert repair["ownedInactiveRecordDeleted"] is True
