"""Check property-based collection member tables and assignment query links."""

import base64
import json
import re
from dataclasses import fields
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import pytest

from openhound_sccm.graph import SCCMCollectionProperties
from openhound_sccm.integration import SCHEMA_PATH

SECTIONS = next(
    node["info"]
    for node in json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["node_kinds"]
    if node["name"] == "SCCM_Collection"
)
TEMPLATES = {key: section["markdown"]["content"] for key, section in SECTIONS.items()}
RenderPanel = Callable[[dict[str, object]], dict[str, str]]
TableRows = Callable[[str, list[str]], list[str]]


def decode_queries(content: str) -> list[str]:
    """Read the actual Cypher behind each rendered Explore link."""
    return [
        base64.b64decode(
            parse_qs(urlsplit(link).query)["cypherSearch"][0], validate=True
        ).decode()
        for link in re.findall(r"\]\((/ui/explore\?[^)]+)\)", content)
    ]


@pytest.fixture(scope="module")
def render_panel(
    render_entity_panel: Callable[[dict[str, str], dict[str, object]], dict[str, str]],
) -> RenderPanel:
    """Render the actual Collection templates with the shared Go helper."""

    def render(properties: dict[str, object]) -> dict[str, str]:
        return render_entity_panel(TEMPLATES, properties)

    return render


def test_collection_sections_use_only_existing_properties():
    assert list(SECTIONS) == ["members", "collection_assignments"]
    assert [value["title"] for value in SECTIONS.values()] == [
        "Members",
        "Collection Assignments",
    ]
    assert [value["position"] for value in SECTIONS.values()] == [1, 2]
    declared = {field.name for field in fields(SCCMCollectionProperties)} | {"objectid"}
    for key, expected in (
        ("members", {"members"}),
        ("collection_assignments", {"objectid"}),
    ):
        used = set(re.findall(r"\.Properties\.(\w+)", TEMPLATES[key]))
        assert used == expected
        assert used <= declared


def test_member_keys_select_clients_or_ad_users_and_groups(
    render_panel: RenderPanel, table_rows: TableRows
):
    content = render_panel({"members": ["42@PS1", "7@CAS", "42@PS1", "", " "]})[
        "members"
    ]
    rows = table_rows(content, [""])
    assert len(rows) == 2
    for row, key in zip(rows, ("42@PS1", "7@CAS"), strict=True):
        assert row.startswith(f"| [{key}](")
        (query,) = decode_queries(row)
        assert query == (
            "MATCH (object)\n"
            f"WHERE (object:SCCM_ClientDevice AND object.resourceID = '{key}')\n"
            f"   OR ((object:User OR object:Group) AND '{key}' IN object.SCCMResourceIDs)\n"
            "RETURN DISTINCT object"
        )
        # Resource keys must not be mistaken for a client's SMSID/objectid.
        assert "objectid:" not in query


@pytest.mark.parametrize("members", [None, [], ["", " ", "\t"]])
def test_empty_member_arrays_emit_no_header(
    members: list[str] | None, render_panel: RenderPanel, table_rows: TableRows
):
    rendered = render_panel({"members": members, "memberCount": 99})
    assert table_rows(rendered["members"], [""]) == []
    assert not rendered["collection_assignments"].strip()


@pytest.mark.parametrize("object_id", ["SMS00001@CAS", "SMS00001@OTHER"])
def test_assignment_columns_query_full_collection_ids_and_ad_sids(
    object_id: str, render_panel: RenderPanel, table_rows: TableRows
):
    content = render_panel({"objectid": object_id, "sourceSiteCode": "UNRELATED"})[
        "collection_assignments"
    ]
    (row,) = table_rows(content, ["SCCM Administrators", "AD Identities"])
    administrators, identities = decode_queries(row)
    assert administrators == (
        "MATCH (admin:SCCM_AdminUser)\n"
        f"WHERE '{object_id}' IN admin.collectionIds\nRETURN DISTINCT admin"
    )
    assert identities == (
        "MATCH (admin:SCCM_AdminUser), (identity:Base)\n"
        f"WHERE '{object_id}' IN admin.collectionIds\n"
        "  AND identity.objectid = admin.adminSid\nRETURN DISTINCT identity"
    )


@pytest.mark.parametrize("object_id", [None, "", " \t"])
def test_missing_collection_id_does_not_guess_assignment_scope(
    object_id: str | None, render_panel: RenderPanel
):
    rendered = render_panel(
        {"objectid": object_id, "collectionID": "SMS00001", "rootSiteCode": "CAS"}
    )
    assert not rendered["collection_assignments"].strip()


def test_labels_and_both_query_arguments_escape_unusual_member_keys(
    render_panel: RenderPanel, table_rows: TableRows
):
    saved_key = "A\\B'_[x]|<&>\r\n\t@PS1"
    content = render_panel({"members": [saved_key], "objectid": saved_key})
    (member_row,) = table_rows(content["members"], [""])
    assert "&#124;" in member_row and "&lt;&amp;&gt;" in member_row
    (member_query,) = decode_queries(member_row)
    escaped = "A\\\\B\\'_[x]|<&>\\r\\n\\t@PS1"
    assert member_query.count("'" + escaped + "'") == 2
    for query in decode_queries(content["collection_assignments"]):
        assert "'" + escaped + "' IN admin.collectionIds" in query
