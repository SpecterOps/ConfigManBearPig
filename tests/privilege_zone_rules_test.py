"""Check the rule files against OpenHound and the collector's actual graph names."""

import json
import re
from dataclasses import fields, is_dataclass
from pathlib import Path

import pytest
from openhound.core.models.privilege_zone import PrivilegeZone

from openhound_sccm import graph
from openhound_sccm.kinds import edges, nodes
from openhound_sccm.transforms import _ROLE_EDGE_KIND

RULE_DIRECTORY = (
    Path(__file__).resolve().parents[1] / "extension" / "privilege_zone_rules"
)
RULE_FILES = sorted(RULE_DIRECTORY.glob("*.json"))


def test_one_policy_has_three_default_rules_and_one_optional_administrator_rule():
    """Retired selectors must not silently restore the old administrator policy."""
    assert {path.name for path in RULE_FILES} == {
        "t0-hierarchy-sites.json",
        "t0-hierarchy-infrastructure.json",
        "t0-computers.json",
        "t0-hierarchy-administrators.json",
    }


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda path: path.stem)
def test_rule_matches_openhound_format_and_agreed_defaults(rule_file: Path):
    rule = PrivilegeZone.from_json(rule_file)
    assert rule.name.startswith("SCCM: Tier Zero ")
    assert rule.description
    assert rule.zone == "Tier Zero"
    assert rule.enabled is (rule_file.name != "t0-hierarchy-administrators.json")
    assert rule.allow_disable is True
    assert rule.cypher.rstrip().endswith("RETURN DISTINCT n")
    assert not re.search(
        r"\b(CREATE|DELETE|DETACH|MERGE|SET|REMOVE|CALL)\b", rule.cypher
    )


def test_names_are_unique_for_repeated_uploads():
    names = [PrivilegeZone.from_json(path).name for path in RULE_FILES]
    assert len(names) == len(set(names))


def test_queries_avoid_syntax_rejected_by_the_live_bloodhound_instance():
    """Neo4j accepts these forms, but the tested BloodHound build rejects them."""
    for path in RULE_FILES:
        query = PrivilegeZone.from_json(path).cypher
        assert not re.search(r"\b(UNION|UNWIND)\b", query, re.IGNORECASE), path.name


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda path: path.stem)
def test_queries_use_existing_graph_names_and_properties(rule_file: Path):
    """Catch renamed graph fields and accidental dependencies on uncollected edges."""
    query = PrivilegeZone.from_json(rule_file).cypher
    node_kinds = {value for value in vars(nodes).values() if isinstance(value, str)}
    edge_kinds = {value for value in vars(edges).values() if isinstance(value, str)}
    declared_names = set(re.findall(r":([A-Za-z][A-Za-z0-9_]*)", query))
    assert declared_names <= node_kinds | edge_kinds | {"Tag_Tier_Zero"}
    relationship_names = {
        name
        for expression in re.findall(r"\[:([A-Za-z0-9_|]+)", query)
        for name in expression.split("|")
    }
    assert relationship_names <= edge_kinds

    property_names = {
        field.name
        for model in vars(graph).values()
        if isinstance(model, type) and is_dataclass(model)
        for field in fields(model)
    }
    assert set(re.findall(r"\b\w+\.([A-Za-z][A-Za-z0-9_]*)", query)) <= property_names


def test_global_device_control_covers_the_seven_supported_built_in_roles():
    query = PrivilegeZone.from_json(
        RULE_DIRECTORY / "t0-hierarchy-administrators.json"
    ).cypher
    assert set(re.findall(r"SMS[0-9A-Z]{5}", query)) == set(_ROLE_EDGE_KIND) | {
        "SMS00001"
    }
    assert "SMS00004" not in query  # All Users is unnecessary for device control.
    assert "SMS00ALL" not in query  # The All security scope is unnecessary too.


def test_optional_administrator_rule_does_not_classify_mapped_ad_identities():
    """A control relationship does not establish identity equivalence in both directions."""
    query = PrivilegeZone.from_json(
        RULE_DIRECTORY / "t0-hierarchy-administrators.json"
    ).cypher
    assert "MATCH (admin:SCCM_AdminUser)" in query
    assert "WITH admin AS n" in query
    assert "SCCM_IsMappedTo" not in query
    assert "MemberOf" not in query
    assert "Tag_Tier_Zero" not in query


def test_optional_administrator_rule_uses_the_exact_role_assignment():
    query = PrivilegeZone.from_json(
        RULE_DIRECTORY / "t0-hierarchy-administrators.json"
    ).cypher
    assert "[assignment:SCCM_IsAssigned]" in query
    assert "'SMS00001' IN assignment.collectionIds" in query
    assert "(collection:SCCM_Collection)" not in query


def test_rules_do_not_turn_general_sccm_relatedness_into_tier_zero():
    for path in RULE_FILES:
        query = json.loads(path.read_text(encoding="utf-8"))["cypher"]
        assert "SCCMInfra" not in query
        assert "SCCM_HasStoredAccount" not in query
        assert "assumed" not in query  # Relevant assumptions are eligible by default.
        assert "system_tags" not in query  # Use BloodHound's current zone label.
