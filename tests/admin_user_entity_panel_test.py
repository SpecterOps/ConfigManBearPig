"""Check administrator links without adding or rewriting graph properties.

The shared Go helper renders the shipped templates. These tests inspect link
text and decoded queries; they do not measure BloodHound's screen layout.
"""

import base64
import json
import re
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import pytest

from openhound_sccm.integration import SCHEMA_PATH
from openhound_sccm.kinds.edges import TRAVERSABLE_EDGE_KINDS

SECTIONS = next(
    node["info"]
    for node in json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["node_kinds"]
    if node["name"] == "SCCM_AdminUser"
)
TEMPLATES = {key: section["markdown"]["content"] for key, section in SECTIONS.items()}
RenderPanel = Callable[[dict[str, object]], dict[str, str]]
LINK_LABELS = {
    "inbound_object_control": "Show incoming control paths",
    "outbound_object_control": "Show outgoing control paths",
}


def decode_query(content: str) -> str:
    """Require one plain Explore link and decode the query it will execute."""
    match = re.fullmatch(r"\[([^\r\n]+)\]\((/ui/explore\?[^)]+)\)\s*", content)
    assert match is not None, content
    parameters = parse_qs(urlsplit(match[2]).query)
    assert parameters["exploreSearchTab"] == ["cypher"]
    assert parameters["searchType"] == ["cypher"]
    return base64.b64decode(parameters["cypherSearch"][0], validate=True).decode()


@pytest.fixture(scope="module")
def render_panel(
    render_entity_panel: Callable[[dict[str, str], dict[str, object]], dict[str, str]],
) -> RenderPanel:
    """Render administrator templates with the same helper used for Sites."""

    def render(properties: dict[str, object]) -> dict[str, str]:
        return render_entity_panel(TEMPLATES, properties)

    return render


def test_sections_add_no_related_objects_or_duplicate_object_information():
    assert list(SECTIONS) == ["security_roles", "collections", *LINK_LABELS]
    assert [section["title"] for section in SECTIONS.values()] == [
        "Security Roles",
        "Collections",
        "Inbound Object Control",
        "Outbound Object Control",
    ]
    assert [section["position"] for section in SECTIONS.values()] == [1, 2, 3, 4]


def test_templates_read_only_the_requested_existing_properties():
    expected_properties = {
        "security_roles": {"memberOf"},
        "collections": {"collectionIds"},
        "inbound_object_control": {"objectid"},
        "outbound_object_control": {"objectid"},
    }
    for key, content in TEMPLATES.items():
        assert (
            set(re.findall(r"\.Properties\.(\w+)", content)) == expected_properties[key]
        )
        assert "b64enc | urlquery" in content


@pytest.mark.parametrize(
    "object_id", ["MAYYHEM\\DOMAINADMIN@CAS", "MAYYHEM\\DOMAINADMIN@PS1"]
)
def test_control_links_keep_the_selected_administrator_and_hierarchy(
    object_id: str, render_panel: RenderPanel
):
    content = render_panel(
        {
            "objectid": object_id,
            "name": "a different display name",
            "sourceSiteCode": "OTHER",
            "rootSiteCode": "OTHER",
            "environmentid": "OTHER",
        }
    )
    for key, label in LINK_LABELS.items():
        assert content[key].startswith(f"[{label}](")
        query = decode_query(content[key])
        escaped_id = object_id.replace("\\", "\\\\")
        assert f"selected:SCCM_AdminUser {{objectid: '{escaped_id}'}}" in query
        assert "OTHER" not in query
        assert "LIMIT" not in query
        assert "*" not in query


@pytest.mark.parametrize(
    "section,property_name,kind",
    [
        ("security_roles", "memberOf", "SCCM_SecurityRole"),
        ("collections", "collectionIds", "SCCM_Collection"),
    ],
)
def test_each_saved_id_gets_its_own_link_without_an_administrator_id(
    section: str, property_name: str, kind: str, render_panel: RenderPanel
):
    # Labels and selection use the saved full IDs, without guessing their names.
    rendered = render_panel(
        {
            property_name: ["Z@PS1", "A@CAS", "Z@PS1", "", " ", "\t"],
            "roleIDs": ["UNRELATED"],
            "sourceSiteCode": "OTHER",
            "rootSiteCode": "OTHER",
        }
    )[section]
    rows = [row for row in rendered.splitlines() if row.strip()]
    assert len(rows) == 2
    assert rendered.startswith("[A@CAS](")
    assert "\n\n" in rendered
    for row, object_id in zip(rows, ("A@CAS", "Z@PS1"), strict=True):
        assert row.startswith(f"[{object_id}](")
        assert decode_query(row) == (
            f"MATCH (object:{kind} {{objectid: '{object_id}'}})\nRETURN object"
        )


@pytest.mark.parametrize("entries", [None, [], ["", " ", "\t\r\n"]])
def test_empty_saved_arrays_stay_blank_instead_of_querying_assignments(
    entries: list[str] | None, render_panel: RenderPanel
):
    rendered = render_panel(
        {
            "objectid": "ADMIN@CAS",
            "memberOf": entries,
            "collectionIds": entries,
            "roleIDs": ["SMS0001R"],
        }
    )
    assert not rendered["security_roles"].strip()
    assert not rendered["collections"].strip()
    assert all(
        rendered[key].startswith(f"[{label}](") for key, label in LINK_LABELS.items()
    )


def test_control_links_keep_direct_paths_and_traversable_kind_filter(
    render_panel: RenderPanel,
):
    rendered = render_panel({"objectid": "ADMIN@CAS"})
    inbound = decode_query(rendered["inbound_object_control"])
    outbound = decode_query(rendered["outbound_object_control"])
    assert inbound.startswith(
        "MATCH path = (object)-[edge]->"
        "(selected:SCCM_AdminUser {objectid: 'ADMIN@CAS'})\n"
    )
    assert outbound.startswith(
        "MATCH path = (selected:SCCM_AdminUser {objectid: 'ADMIN@CAS'})"
        "-[edge]->(object)\n"
    )
    for query in (inbound, outbound):
        assert query.endswith("RETURN DISTINCT path")
        assert query.count("MATCH ") == 1
        assert "*" not in query
        (kind_list,) = re.findall(r"type\(edge\) IN (\[[^\n]+\])", query)
        assert set(json.loads(kind_list.replace("'", '"'))) == TRAVERSABLE_EDGE_KINDS
        # Assignment links are separate from attack-path queries.
        assert "SCCM_IsAssigned" not in kind_list


@pytest.mark.parametrize("object_id", [None, "", " ", "\t\r\n"])
def test_absent_identifier_does_not_guess_from_account_or_site(
    object_id: str | None, render_panel: RenderPanel
):
    properties: dict[str, object] = {
        "name": "MAYYHEM\\DOMAINADMIN",
        "sourceSiteCode": "PS1",
        "rootSiteCode": "CAS",
        "environmentid": "CAS",
    }
    if object_id is not None:
        properties["objectid"] = object_id
    # None deliberately exercises an absent property rather than a null value.
    assert all(not content.strip() for content in render_panel(properties).values())


def test_identifier_punctuation_is_data_inside_every_query(render_panel: RenderPanel):
    object_id = "MAYYHEM\\O'BRIEN\r\n\t@CAS"
    rendered = render_panel(
        {"objectid": object_id, "memberOf": [object_id], "collectionIds": [object_id]}
    )
    for content in rendered.values():
        query = decode_query(content)
        assert "objectid: 'MAYYHEM\\\\O\\'BRIEN\\r\\n\\t@CAS'" in query
        assert "\r" not in query
        assert "\t" not in query


def test_saved_id_labels_escape_markdown_and_html_punctuation(
    render_panel: RenderPanel,
):
    saved_id = r"A\B_[x]|<&>*`~@CAS"
    rendered = render_panel({"memberOf": [saved_id], "collectionIds": [saved_id]})
    expected_label = r"A\\B\_\[x\]&#124;&lt;&amp;&gt;\*\`\~@CAS"
    for section in ("security_roles", "collections"):
        content = rendered[section]
        assert content.startswith(f"[{expected_label}](")
        # Escaping the displayed label must not alter the ID selected by Cypher.
        assert "objectid: 'A\\\\B_[x]|<&>*`~@CAS'" in decode_query(content)
