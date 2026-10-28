"""Check saved collection tables and direct control paths for SCCM clients."""

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
    if node["name"] == "SCCM_ClientDevice"
)
TEMPLATES = {key: section["markdown"]["content"] for key, section in SECTIONS.items()}
RenderPanel = Callable[[dict[str, object]], dict[str, str]]
TableRows = Callable[[str, list[str]], list[str]]


def decode_queries(content: str) -> list[str]:
    """Decode the rendered deep links to check the executed query text."""
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
    """Render Client Device templates using the shared Go helper."""

    def render(properties: dict[str, object]) -> dict[str, str]:
        return render_entity_panel(TEMPLATES, properties)

    return render


def test_client_sections_and_property_sources():
    assert list(SECTIONS) == [
        "member_of_collections",
        "inbound_object_control",
        "outbound_object_control",
    ]
    assert [section["title"] for section in SECTIONS.values()] == [
        "Member of Collections",
        "Inbound Object Control",
        "Outbound Object Control",
    ]
    assert [section["position"] for section in SECTIONS.values()] == [1, 2, 3]
    for key, content in TEMPLATES.items():
        expected = {"collectionIds"} if key == "member_of_collections" else {"objectid"}
        assert set(re.findall(r"\.Properties\.(\w+)", content)) == expected


def test_collection_ids_have_individual_links_without_pairing_unrelated_names(
    render_panel: RenderPanel, table_rows: TableRows
):
    content = render_panel(
        {
            "collectionIds": ["Z@PS1", "A@CAS", "Z@PS1", "", " "],
            "collectionNames": [
                "This array is independently sorted",
                "Not paired with those IDs",
            ],
        }
    )["member_of_collections"]
    rows = table_rows(content, [""])
    assert len(rows) == 2
    for row, object_id in zip(rows, ("A@CAS", "Z@PS1"), strict=True):
        assert row.startswith(f"| [{object_id}](")
        assert decode_queries(row) == [
            f"MATCH (object:SCCM_Collection {{objectid: '{object_id}'}})\nRETURN object"
        ]


@pytest.mark.parametrize("collection_ids", [None, [], ["", " ", "\t\r\n"]])
def test_empty_collection_ids_do_not_fall_back_to_names(
    collection_ids: list[str] | None, render_panel: RenderPanel
):
    content = render_panel(
        {"collectionIds": collection_ids, "collectionNames": ["All Systems"]}
    )
    assert all(not section.strip() for section in content.values())


def test_client_controls_return_direct_paths_with_the_existing_kind_filter(
    render_panel: RenderPanel,
):
    rendered = render_panel({"objectid": "GUID:CLIENT"})
    (inbound,) = decode_queries(rendered["inbound_object_control"])
    (outbound,) = decode_queries(rendered["outbound_object_control"])
    assert inbound.startswith(
        "MATCH path = (object)-[edge]->(selected:SCCM_ClientDevice {objectid: 'GUID:CLIENT'})\n"
    )
    assert outbound.startswith(
        "MATCH path = (selected:SCCM_ClientDevice {objectid: 'GUID:CLIENT'})-[edge]->(object)\n"
    )
    for query in (inbound, outbound):
        assert query.endswith("RETURN DISTINCT path")
        assert "*" not in query and "LIMIT" not in query
        (kinds,) = re.findall(r"type\(edge\) IN (\[[^\n]+\])", query)
        assert set(json.loads(kinds.replace("'", '"'))) == TRAVERSABLE_EDGE_KINDS


@pytest.mark.parametrize("object_id", [None, "", " \t"])
def test_controls_do_not_guess_an_id_from_device_properties(
    object_id: str | None, render_panel: RenderPanel
):
    rendered = render_panel(
        {"objectid": object_id, "SMSID": "GUID:OTHER", "name": "HOST@PS1"}
    )
    assert all(not content.strip() for content in rendered.values())


def test_collection_and_control_queries_escape_ids(render_panel: RenderPanel):
    object_id = "A\\B'\r\n\t@CAS"
    rendered = render_panel({"objectid": object_id, "collectionIds": [object_id]})
    for content in rendered.values():
        (query,) = decode_queries(content)
        assert "objectid: 'A\\\\B\\'\\r\\n\\t@CAS'" in query
        assert "\r" not in query and "\t" not in query
