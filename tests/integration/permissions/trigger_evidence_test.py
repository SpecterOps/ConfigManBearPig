"""Check recorded execution mechanisms without contacting the SCCM lab.

An accepted request is not execution proof. These checks require an original
successful run, a separate changed-code SYSTEM marker, and the tested rights.
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

EVIDENCE = Path(__file__).parent / "evidence" / "trigger-results.json"


def object_value(value: object) -> dict[str, object]:
    """Require a JSON object before reading recorded fields."""
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return dict(value)


def list_value(value: object) -> list[object]:
    """Require a JSON list before examining individual records."""
    assert isinstance(value, list)
    return list(value)


def timestamp(value: object) -> datetime:
    """Preserve UTC offsets when comparing the observer's timestamps."""
    assert isinstance(value, str)
    result = datetime.fromisoformat(value)
    assert result.utcoffset() is not None
    return result


@pytest.fixture(scope="module")
def evidence() -> dict[str, object]:
    """Load the separately retained completed-deployment experiments."""
    return object_value(json.loads(EVIDENCE.read_text(encoding="utf-8")))


def case(evidence: dict[str, object], name: str) -> dict[str, object]:
    """Read one named comparison so similar experiments cannot be mixed up."""
    return object_value(object_value(evidence["cases"])[name])


def assert_marker(value: object, computer: str) -> str:
    """Require a nonce and the actual SYSTEM identity on the intended host."""
    marker = object_value(value)
    assert marker["sid"] == "S-1-5-18"
    assert marker["computer"] == computer
    nonce = marker["nonce"]
    assert isinstance(nonce, str) and len(nonce) == 32
    return nonce


def test_every_comparison_started_after_success(evidence):
    for value in object_value(evidence["cases"]).values():
        row = object_value(value)
        assert row["initialSuccess"] is True
        assert row["privilegedClientActionsAfterModification"] == 0
        original = object_value(row["original"])
        assert_marker(original["marker"], "PS1-DEV")
        assert timestamp(original["completedUTC"]) <= timestamp(row["attackStartedUTC"])
        state = object_value(original["state"])
        if row["workload"] == "Application":
            assert state["installState"] == "Installed"
        elif row["workload"] == "ConfigurationItem":
            assert state["compliance"] == 1
        else:
            assert state["lastRunStatus"] == "Success"
            assert int(str(state["lastExitCode"])) == 0


@pytest.mark.parametrize(
    "name",
    [
        "app-detection-notify",
        "ci-baseline-revision-notify",
        "package-reschedule-future-deploy",
        "ts-reschedule-package-id-deploy",
        "package-existing-recurrence",
        "ts-existing-recurrence",
    ],
)
def test_changed_code_really_ran_as_system(evidence, name):
    row = case(evidence, name)
    assert row["verified"] is True
    assert row["modified"] is True
    changed_nonce = assert_marker(row["secondMarker"], "PS1-DEV")
    original = object_value(row["original"])
    assert changed_nonce != assert_marker(original["marker"], "PS1-DEV")
    assert timestamp(row["modifiedUTC"]) >= timestamp(original["completedUTC"])
    assert row["cleanupComplete"] is True


def test_install_command_and_detection_have_different_results(evidence):
    install = case(evidence, "app-installed-notify")
    detection = case(evidence, "app-detection-notify")
    assert install["verified"] is False
    assert install["modified"] is True
    assert object_value(install["finalState"])["revision"] == "3"
    assert object_value(install["finalState"])["installState"] == "Installed"
    assert detection["verified"] is True
    assert object_value(detection["finalState"])["installState"] == "Installed"
    control = case(evidence, "app-read-notify-control")
    assert control["modified"] is False
    assert control["objectMask"] == 1
    # The console stopped at its application-lock step, before changing code.
    assert "lock" in str(control["actionError"]).lower()


@pytest.mark.parametrize("action", [8, 13, 125])
@pytest.mark.parametrize(
    "profile",
    ["Read control", "Notify Resource", "Modify Resource", "Deploy Applications"],
)
def test_notifications_require_the_separate_notify_permission(
    evidence, action, profile
):
    matches = [
        object_value(value)
        for value in list_value(evidence["notifications"])
        if object_value(value)["action"] == action
        and object_value(value)["profile"] == profile
    ]
    assert len(matches) == 1
    row = matches[0]
    assert row["accepted"] is (profile == "Notify Resource")
    if profile != "Notify Resource":
        assert "no permission to initiate" in str(row["error"])


@pytest.mark.parametrize(
    ("positive", "negative", "deploy_bit"),
    [
        (
            "package-reschedule-future-deploy",
            "package-reschedule-no-deploy-history",
            16384,
        ),
        (
            "ts-reschedule-package-id-deploy",
            "ts-reschedule-package-id-no-deploy",
            8388608,
        ),
    ],
)
def test_rescheduling_needs_the_matching_deployment_permission(
    evidence, positive, negative, deploy_bit
):
    allowed = case(evidence, positive)
    denied = case(evidence, negative)
    assert int(str(allowed["collectionMask"])) & deploy_bit
    assert not int(str(denied["collectionMask"])) & deploy_bit
    assert "security rights" in str(denied["actionError"]).lower()
    assert denied["verified"] is False
    assert allowed["rescheduled"] is True
    assert allowed["verified"] is True


@pytest.mark.parametrize(
    "name", ["package-existing-recurrence", "ts-existing-recurrence"]
)
def test_preexisting_recurrence_does_not_need_deployment_rights(evidence, name):
    row = case(evidence, name)
    assert row["recurringDeployment"] is True
    assert row["profile"] == "ModifyNotify"
    assert row["mechanism"] == "Notify"
    assert row["collectionMask"] == 4097 | 536870912
    assert "rescheduled" not in row
    assert row["verified"] is True


def test_ci_parent_revision_supplied_the_faster_demonstrated_mechanism(evidence):
    child_only = case(evidence, "ci-completed-notify")
    parent_revised = case(evidence, "ci-baseline-revision-notify")
    assert child_only["modified"] is True
    assert child_only["verified"] is False
    assert object_value(child_only["finalState"])["version"] == "2"
    assert parent_revised["baselineRevised"] is True
    assert parent_revised["collectionMask"] == 4097 | 536870912
    assert object_value(parent_revised["finalState"])["version"] == "3"
    assert parent_revised["verified"] is True


def test_passive_application_executed_without_notifications(evidence):
    passive = object_value(evidence["passive"])
    assert passive["initialSuccess"] is True
    assert passive["notifications"] == []
    assert passive["collectionMask"] == 4097
    assert passive["privilegedClientActionsAfterModification"] == 0
    app = next(
        object_value(value)
        for value in list_value(passive["experiments"])
        if object_value(value)["workload"] == "Application"
    )
    assert app["verified"] is True
    assert_marker(app["secondMarker"], "PS1-DP")
    elapsed = (
        timestamp(app["observedUTC"]) - timestamp(app["modifiedUTC"])
    ).total_seconds()
    assert 1573 < elapsed < 1574
    assert abs(float(str(app["elapsedSinceModificationSeconds"])) - elapsed) < 0.02


def test_passive_ci_also_executed_without_a_parent_revision(evidence):
    passive = object_value(evidence["passive"])
    ci = next(
        object_value(value)
        for value in list_value(passive["experiments"])
        if object_value(value)["workload"] == "ConfigurationItem"
    )
    assert ci["verified"] is True
    assert_marker(ci["secondMarker"], "PS1-DP")
    elapsed = (
        timestamp(ci["observedUTC"]) - timestamp(ci["modifiedUTC"])
    ).total_seconds()
    assert 3158 < elapsed < 3159
    assert abs(float(str(ci["elapsedSinceModificationSeconds"])) - elapsed) < 0.02
    assert passive["notifications"] == []
    assert passive["collectionMask"] == 4097


def test_cleanup_and_original_roles_were_independently_checked(evidence):
    audit = object_value(evidence["cleanup"])
    assert audit["remainingOwnedResources"] == 0
    assert audit["remainingOwnedAccounts"] == 0
    assert audit["remainingMarkers"] == 0
    assert audit["remainingClientPolicies"] == 0
    assert audit["originalRoleCount"] == 15
    assert audit["originalRoleOperationsUnchanged"] is True
    assert audit["originalRoleNamesUnchanged"] is True
    assert object_value(evidence["passive"])["cleanupComplete"] is True
    assert all(
        object_value(value)["cleanupComplete"] is True
        for value in object_value(evidence["cases"]).values()
    )
