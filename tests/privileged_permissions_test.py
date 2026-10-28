"""Individual reads must preserve original SCCM permission and operation entries."""

import json
from types import SimpleNamespace

import pytest

from openhound_sccm.clients.http import ErrorClass, HttpResult
from openhound_sccm.collectors import privileged


@pytest.mark.parametrize("transport", ["AdminService", "WMI"])
@pytest.mark.parametrize(
    "class_name,key_field,key,field,collector",
    [
        ("SMS_Admin", "AdminID", 17, "Permissions", privileged._admins),
        ("SMS_Role", "RoleID", "SMS0001R", "Operations", privileged._security_roles),
    ],
)
def test_individual_read_preserves_original_embedded_fields(
    transport, class_name, key_field, key, field, collector
):
    entries = (
        [
            {
                "RoleID": "SMS0001R",
                "CategoryID": "PS100001",
                "CategoryTypeID": 1,
                "RoleName": "Full Administrator",
                "CategoryName": "Servers",
            }
        ]
        if field == "Permissions"
        else [{"ObjectTypeID": 1, "GrantedOperations": 4294967039}]
    )
    summary = {key_field: key, "LogonName": "MAYYHEM\\alice", field: None}
    calls = []

    def read(cls, key_name, value):
        calls.append((cls, key_name, value))
        return {**summary, field: entries}

    run = privileged._Run(
        lambda *args: iter([summary]), transport, "=", "PS1", None, read
    )
    row = list(collector(run))[0][1]
    assert calls == [(class_name, key_field, key)]
    assert row[field.lower()] == entries
    assert row[field.lower() + "_complete"] is True
    assert summary[field] is None  # Collection does not mutate the enumerated summary.


@pytest.mark.parametrize("detail", [None, {"AdminID": 99, "Permissions": []}])
def test_failed_or_wrong_instance_keeps_summary_but_marks_details_incomplete(
    detail, caplog
):
    summary = {"AdminID": 17, "LogonName": "MAYYHEM\\alice", "Roles": ["SMS0001R"]}
    run = privileged._Run(
        lambda *args: iter([summary]), "WMI", "=", "PS1", None, lambda *args: detail
    )
    row = list(privileged._admins(run))[0][1]
    assert row["roles"] == ["SMS0001R"]
    assert row["permissions"] is None
    assert row["permissions_complete"] is False
    assert "incomplete" in caplog.text


def test_http_individual_read_handles_the_real_adminservice_response_shape():
    calls = []

    def get(path):
        calls.append(path)
        return HttpResult(
            200,
            json.dumps({"value": [{"AdminID": 17, "Permissions": []}]}).encode(),
            ErrorClass.RESPONSE,
        )

    read = privileged._http_read_instance(SimpleNamespace(get=get))
    assert read("SMS_Admin", "AdminID", 17) == {"AdminID": 17, "Permissions": []}
    assert calls == ["/AdminService/wmi/SMS_Admin(17)"]


@pytest.mark.parametrize("value", [[], [{}, {}], {}, None])
def test_http_incomplete_individual_response_is_reported(value, caplog):
    client = SimpleNamespace(
        get=lambda path: HttpResult(
            200, json.dumps({"value": value}).encode(), ErrorClass.RESPONSE
        )
    )
    assert privileged._http_read_instance(client)("SMS_Admin", "AdminID", 17) is None
    assert "incomplete" in caplog.text
