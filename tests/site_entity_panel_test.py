"""Render Site links using only properties present in existing collections.

Set CMBP_GO_BINARY or put Go on PATH for rendering checks. The structural checks
run without Go. No compiler or Go dependency is needed by the collector itself.
"""

import base64
import json
import re
from dataclasses import fields
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import pytest

from openhound_sccm.graph import SCCMSiteProperties
from openhound_sccm.integration import SCHEMA_PATH
from openhound_sccm.kinds.edges import TRAVERSABLE_EDGE_KINDS

ROOT = Path(__file__).resolve().parents[1]
SECTIONS = next(
    node["info"]
    for node in json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["node_kinds"]
    if node["name"] == "SCCM_Site"
)
TEMPLATES: dict[str, str] = {
    key: section["markdown"]["content"] for key, section in SECTIONS.items()
}
RenderPanel = Callable[[dict[str, object]], dict[str, str]]


def explore_queries(markdown: str) -> list[str]:
    """Decode the exact queries behind the displayed object links."""
    return [
        base64.b64decode(parse_qs(urlsplit(link).query)["cypherSearch"][0]).decode()
        for link in re.findall(r"\]\((/ui/explore\?[^)]+)\)", markdown)
    ]


def test_site_sections_have_no_redundant_details():
    assert [section["title"] for section in SECTIONS.values()] == [
        "Administrative Users",
        "Site System Roles",
        "Inbound Object Control",
        "Outbound Object Control",
    ]
    assert [section["position"] for section in SECTIONS.values()] == [1, 2, 3, 4]
    assert "site_details" not in SECTIONS


def test_templates_only_read_declared_site_properties():
    properties = {field.name for field in fields(SCCMSiteProperties)}
    expected_properties = {
        "administrative_users": {"adminUsers", "rootSiteCode", "environmentid"},
        "site_system_roles": {"siteSystemRoles"},
        "inbound_object_control": {"objectid", "siteCode"},
        "outbound_object_control": {"objectid", "siteCode"},
    }
    assert "sitePanelObjects" not in properties
    for key, content in TEMPLATES.items():
        used_properties = set(re.findall(r"\.Properties\.(\w+)", content))
        assert used_properties == expected_properties[key]
        # objectid is added by BloodHound rather than the Python node model.
        assert used_properties <= properties | {"objectid"}
        assert "sitePanelObjects" not in content
        assert "b64enc | urlquery" in content


@pytest.mark.parametrize("schema_name", ["schema_SCCM.json", "schema_MSSQL.json"])
def test_upload_copies_match_the_packaged_schemas(schema_name: str):
    assert (ROOT / "extension" / schema_name).read_bytes() == (
        ROOT / "src/openhound_sccm" / schema_name
    ).read_bytes()


@pytest.fixture(scope="module")
def render_panel(
    render_entity_panel: Callable[[dict[str, str], dict[str, object]], dict[str, str]],
) -> RenderPanel:
    """Render the Site templates using the shared test-only Go helper."""

    def render(properties: dict[str, object]) -> dict[str, str]:
        return render_entity_panel(TEMPLATES, properties)

    return render


@pytest.mark.parametrize("site_code", ["CAS", "PS1", "SEC"])
def test_control_sections_render_plain_links_without_tables(
    site_code: str, render_panel: RenderPanel
):
    # Control links work without either of the Site's saved object arrays.
    rendered = render_panel({"objectid": site_code, "siteCode": site_code})
    assert not rendered["administrative_users"].strip()
    assert not rendered["site_system_roles"].strip()
    for key in ("inbound_object_control", "outbound_object_control"):
        content = rendered[key]
        assert content.startswith("[Show ")
        rows = [row for row in content.splitlines() if row.strip()]
        assert len(rows) == 1
        assert re.fullmatch(r"\[[^]]+\]\(/ui/explore\?[^)]+\)", rows[0])
        (query,) = explore_queries(content)
        assert f"selected:SCCM_Site {{objectid: '{site_code}'}}" in query
        assert query.endswith("RETURN DISTINCT path")
        assert "LIMIT" not in query


def test_site_code_is_used_when_objectid_is_absent(render_panel: RenderPanel):
    fallback = render_panel({"siteCode": "PS1"})
    assert fallback == render_panel({"objectid": "PS1", "siteCode": "PS1"})
    selected = render_panel({"objectid": "PS1", "siteCode": "WRONG"})
    assert selected == fallback


@pytest.mark.parametrize(
    "properties",
    [
        {},
        {"adminUsers": [], "siteSystemRoles": []},
        {"adminUsers": None, "siteSystemRoles": None},
        {
            "adminUsers": [""],
            "siteSystemRoles": [
                "malformed",
                "host.lab: SMS Site System@PS1",
                "host.lab: SMS Component Server@PS1",
            ],
        },
    ],
)
def test_empty_arrays_and_absent_identifiers_create_no_broken_links(
    properties: dict[str, object], render_panel: RenderPanel
):
    assert all(not content.strip() for content in render_panel(properties).values())


def test_control_queries_return_paths_through_exactly_one_edge(
    render_panel: RenderPanel,
):
    rendered = render_panel({"objectid": "PS1"})
    (inbound,) = explore_queries(rendered["inbound_object_control"])
    (outbound,) = explore_queries(rendered["outbound_object_control"])
    assert inbound.startswith(
        "MATCH path = (object)-[edge]->(selected:SCCM_Site {objectid: 'PS1'})\n"
    )
    assert outbound.startswith(
        "MATCH path = (selected:SCCM_Site {objectid: 'PS1'})-[edge]->(object)\n"
    )
    for query in (inbound, outbound):
        assert "*" not in query
        assert query.count("MATCH ") == 1
        (kind_list,) = re.findall(r"type\(edge\) IN (\[[^\n]+\])", query)
        # Kind names contain no quotes; convert the Cypher string list to JSON.
        assert set(json.loads(kind_list.replace("'", '"'))) == TRAVERSABLE_EDGE_KINDS
        assert query.endswith("RETURN DISTINCT path")


@pytest.mark.parametrize("root_property", ["rootSiteCode", "environmentid"])
def test_administrator_array_links_select_each_saved_id(
    root_property: str,
    render_panel: RenderPanel,
):
    content = render_panel(
        {
            root_property: "CAS",
            "adminUsers": ["DOMAIN\\ZED@CAS", "DOMAIN\\ANN@CAS", "DOMAIN\\ZED@CAS", ""],
        }
    )["administrative_users"]
    assert content.startswith("[DOMAIN")
    assert "\n\n" in content
    rows = [row for row in content.splitlines() if row.strip()]
    assert len(rows) == 2
    assert rows[0].startswith("[DOMAIN\\\\ANN](")
    assert rows[1].startswith("[DOMAIN\\\\ZED](")
    assert all(re.fullmatch(r"\[[^]]+\]\(/ui/explore\?[^)]+\)", row) for row in rows)
    assert explore_queries(content) == [
        "MATCH (object:SCCM_AdminUser {objectid: 'DOMAIN\\\\ANN@CAS'})\nRETURN object",
        "MATCH (object:SCCM_AdminUser {objectid: 'DOMAIN\\\\ZED@CAS'})\nRETURN object",
    ]


def test_site_role_array_links_each_qualifying_computer_once(render_panel: RenderPanel):
    content = render_panel(
        {
            "siteSystemRoles": [
                "b.lab: SMS Provider@PS1",
                "a.lab: SMS Site System@PS1",
                "a.lab: SMS SQL Server@PS1",
                "B.LAB: SMS Site Server@PS1",
                "background.lab: SMS Component Server@PS1",
                "background.lab: sms site system@PS1",
                " : SMS Provider@PS1",
                "malformed",
                "c.lab: Custom: Role@PS1",
            ]
        }
    )["site_system_roles"]
    assert content.startswith("[A.LAB]")
    assert "\n\n" in content
    rows = [row for row in content.splitlines() if row.strip()]
    assert len(rows) == 3
    for row, hostname in zip(rows, ("A.LAB", "B.LAB", "C.LAB"), strict=True):
        assert row.startswith(f"[{hostname}](")
        assert re.fullmatch(r"\[[^]]+\]\(/ui/explore\?[^)]+\)", row)
    queries = explore_queries(content)
    assert len(queries) == 3
    for query, hostname in zip(queries, ("A.LAB", "B.LAB", "C.LAB"), strict=True):
        assert query == (
            "MATCH (object:Computer)\n"
            f"WHERE toUpper(object.name) = '{hostname}' OR toUpper(object.dNSHostName) = '{hostname}'\n"
            "RETURN DISTINCT object"
        )


def test_array_labels_and_identifiers_keep_punctuation_literal(
    render_panel: RenderPanel,
):
    rendered = render_panel(
        {
            "rootSiteCode": "CAS",
            "adminUsers": ["O'Brien\\SQL[1]|&<x>@CAS"],
            "siteSystemRoles": ["o'brien\"\\sql[1]|&<x>.lab: SMS Provider@PS1"],
        }
    )
    for key in ("administrative_users", "site_system_roles"):
        content = rendered[key]
        rows = [row for row in content.splitlines() if row.strip()]
        assert len(rows) == 1
        assert "|" not in rows[0]
        assert "\\[1\\]&#124;&amp;&lt;" in rows[0]
        (query,) = explore_queries(content)
        assert "\\'" in query and "\\\\" in query


def test_site_identifiers_cannot_change_the_query_or_link(
    render_panel: RenderPanel,
):
    rendered = render_panel({"objectid": "O'Brien\\SQL\nnext\r\tX"})
    for key in ("inbound_object_control", "outbound_object_control"):
        content = rendered[key]
        (query,) = explore_queries(content)
        assert "O\\'Brien\\\\SQL\\nnext\\r\\tX" in query
        assert len([line for line in content.splitlines() if line.strip()]) == 1
