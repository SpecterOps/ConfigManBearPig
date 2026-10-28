"""Check the two-column role assignment table using existing graph properties.

These checks use Go's template engine. BloodHound's screen layout, accordion
state, and live query execution remain separate manual checks.
"""

import base64
import json
import re
from dataclasses import fields
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import pytest

from openhound_sccm.graph import SCCMSecurityRoleProperties
from openhound_sccm.integration import SCHEMA_PATH

SECTIONS = next(
    node["info"]
    for node in json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))["node_kinds"]
    if node["name"] == "SCCM_SecurityRole"
)
TEMPLATES = {key: section["markdown"]["content"] for key, section in SECTIONS.items()}
RenderPanel = Callable[[dict[str, object]], dict[str, str]]


def decode_queries(content: str) -> list[str]:
    """Decode each Explore link without confusing escaped brackets in a label."""
    queries = []
    for link in re.findall(r"\]\((/ui/explore\?[^)]+)\)", content):
        parameters = parse_qs(urlsplit(link).query)
        assert parameters["exploreSearchTab"] == ["cypher"]
        assert parameters["searchType"] == ["cypher"]
        queries.append(
            base64.b64decode(parameters["cypherSearch"][0], validate=True).decode()
        )
    return queries


@pytest.fixture(scope="module")
def render_panel(
    render_entity_panel: Callable[[dict[str, str], dict[str, object]], dict[str, str]],
) -> RenderPanel:
    """Render role templates using the existing shared test-only Go helper."""

    def render(properties: dict[str, object]) -> dict[str, str]:
        return render_entity_panel(TEMPLATES, properties)

    return render


def test_role_sections_do_not_duplicate_object_information():
    assert list(SECTIONS) == ["role_assignments"]
    assert SECTIONS["role_assignments"]["title"] == "Role Assignments"
    assert SECTIONS["role_assignments"]["position"] == 1
    for section in SECTIONS.values():
        # Expansion is controlled by BloodHound; do not invent a schema setting.
        assert set(section) == {"title", "position", "markdown"}


def test_templates_only_read_existing_members():
    declared_properties = {field.name for field in fields(SCCMSecurityRoleProperties)}
    expected = {"role_assignments": {"members"}}
    for key, content in TEMPLATES.items():
        used_properties = set(re.findall(r"\.Properties\.(\w+)", content))
        assert used_properties == expected[key]
        assert used_properties <= declared_properties


def test_member_rows_link_to_each_administrator_and_its_ad_identity(
    render_panel: RenderPanel,
    table_rows: Callable[[str, list[str]], list[str]],
):
    # A role ID or source-site lookup is unnecessary: members holds full IDs.
    rendered = render_panel(
        {
            "members": [
                "DOMAIN\\ZED@PS1",
                "DOMAIN\\ANN@CAS",
                "DOMAIN\\ZED@PS1",
                "",
                " ",
            ],
            "rootSiteCode": "OTHER",
            "siteCode": "OTHER",
        }
    )["role_assignments"]
    rows = table_rows(rendered, ["SCCM Administrator", "AD Identity"])
    assert len(rows) == 2
    assert rows[0].startswith("| [DOMAIN\\\\ANN@CAS](")
    for row, member_id in zip(
        rows, ("DOMAIN\\ANN@CAS", "DOMAIN\\ZED@PS1"), strict=True
    ):
        escaped_id = member_id.replace("\\", "\\\\")
        admin_query, identity_query = decode_queries(row)
        assert admin_query == (
            f"MATCH (object:SCCM_AdminUser {{objectid: '{escaped_id}'}})\nRETURN object"
        )
        assert identity_query == (
            f"MATCH (admin:SCCM_AdminUser {{objectid: '{escaped_id}'}})\n"
            "MATCH (identity:Base)\n"
            "WHERE identity.objectid = admin.adminSid\n"
            "RETURN DISTINCT identity"
        )
        assert " | [AD identity](" in row
        assert "OTHER" not in row


@pytest.mark.parametrize("members", [None, [], ["", " ", "\t\r\n"]])
def test_empty_members_do_not_guess_assignments_from_other_fields(
    members: list[str] | None, render_panel: RenderPanel
):
    rendered = render_panel(
        {
            "members": members,
            "objectid": "SMS0001R@CAS",
            "numberOfAdmins": 99,
            "rootSiteCode": "CAS",
        }
    )
    assert not rendered["role_assignments"].strip()


def test_member_query_escaping_preserves_the_same_id_in_both_links(
    render_panel: RenderPanel,
):
    member_id = "DOMAIN\\O'BRIEN\r\n\t@CAS"
    rendered = render_panel({"members": [member_id]})["role_assignments"]
    queries = decode_queries(rendered)
    assert len(queries) == 2
    for query in queries:
        assert "objectid: 'DOMAIN\\\\O\\'BRIEN\\r\\n\\t@CAS'" in query
        assert "\r" not in query
        assert "\t" not in query


def test_member_labels_escape_markdown_and_html(render_panel: RenderPanel):
    member_id = r"A\B_[x]|<&>*`~@CAS"
    rendered = render_panel({"members": [member_id]})["role_assignments"]
    label = r"A\\B\_\[x\]&#124;&lt;&amp;&gt;\*\`\~@CAS"
    assert f"| [{label}](" in rendered
    assert len(decode_queries(rendered)) == 2
