"""Execute the unchanged JSON queries on a disposable, local Neo4j database.

Set CMBP_PZ_NEO4J_URL to its HTTP base URL, for example http://127.0.0.1:18474.
Optional CMBP_PZ_NEO4J_USER and CMBP_PZ_NEO4J_PASSWORD enable authentication.
The test creates uniquely marked fixture nodes and removes only those nodes.
It never uploads rules to BloodHound. Without a configured server it is skipped.
"""

import json
import os
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict
from urllib.parse import urlparse
from uuid import uuid4

import pytest
import requests
from openhound.core.models.privilege_zone import PrivilegeZone

ROOT = Path(__file__).resolve().parents[1]
RULE_DIRECTORY = ROOT / "extension" / "privilege_zone_rules"
FIXTURE_PATH = ROOT / "tests" / "data" / "privilege_zones" / "graph.json"
RULE_FILES = sorted(RULE_DIRECTORY.glob("*.json"))


class FixtureNode(TypedDict):
    """One synthetic object, using the collector's actual labels and properties."""

    id: str
    labels: list[str]
    properties: dict[str, object]


class FixtureEdge(TypedDict):
    """One synthetic relationship between two fixture object IDs."""

    start: str
    kind: str
    end: str
    properties: dict[str, object]


class FixtureData(TypedDict):
    description: str
    nodes: list[FixtureNode]
    edges: list[FixtureEdge]
    tier_zero_nodes: list[str]
    expected: dict[str, list[str]]


@dataclass
class RuleGraph:
    """Keep HTTP access and this test's unique object marker together."""

    session: requests.Session
    endpoint: str
    namespace: str
    data: FixtureData

    def execute(
        self, statement: str, parameters: dict[str, object] | None = None
    ) -> list[list[object]]:
        """Run a query and surface both HTTP errors and Cypher errors."""
        response = self.session.post(
            self.endpoint,
            json={
                "statements": [{"statement": statement, "parameters": parameters or {}}]
            },
            timeout=60,
        )
        response.raise_for_status()
        # The HTTP JSON decoder is the single untyped boundary. These assertions
        # and the consumer's object-ID check expose unexpected response shapes.
        result = response.json()
        assert result["errors"] == [], result["errors"]
        return [entry["row"] for entry in result["results"][0]["data"]]

    def matching_ids(self, rule_file: Path) -> set[str]:
        """Execute the shipped query verbatim, then identify this run's results."""
        query = PrivilegeZone.from_json(rule_file).cypher
        matches = set()
        for row in self.execute(query):
            properties = row[0]
            assert isinstance(properties, dict)
            object_id = properties.get("objectid")
            assert isinstance(object_id, str)
            if object_id.startswith(self.namespace):
                matches.add(object_id.removeprefix(self.namespace))
            # Objects outside this fixture are irrelevant to its expectations.
        return matches


@pytest.fixture(scope="module")
def rule_graph() -> Iterator[RuleGraph]:
    server_url = os.environ.get("CMBP_PZ_NEO4J_URL")
    if not server_url:
        pytest.skip("Set CMBP_PZ_NEO4J_URL to a disposable local Neo4j HTTP server.")
    parsed = urlparse(server_url)
    assert parsed.scheme in {"http", "https"}
    assert parsed.hostname in {"127.0.0.1", "localhost", "::1"}, (
        "Use a local test server."
    )
    username = os.environ.get("CMBP_PZ_NEO4J_USER")
    password = os.environ.get("CMBP_PZ_NEO4J_PASSWORD")
    assert bool(username) == bool(password), (
        "Provide both authentication values, or neither."
    )
    session = requests.Session()
    if username and password:
        session.auth = (username, password)
    # With neither value, the explicitly configured local server needs no auth.
    fixture: FixtureData = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    graph = RuleGraph(
        session,
        server_url.rstrip("/") + "/db/neo4j/tx/commit",
        uuid4().hex + ":",
        fixture,
    )
    try:
        nodes_by_labels: dict[tuple[str, ...], list[dict[str, object]]] = defaultdict(
            list
        )
        for node in fixture["nodes"]:
            assert all(
                re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", label)
                for label in node["labels"]
            )
            properties = dict(node["properties"])
            properties.update(
                objectid=graph.namespace + node["id"], pz_test_run=graph.namespace
            )
            if "environmentid" in properties:
                properties["environmentid"] = graph.namespace + str(
                    properties["environmentid"]
                )
            # No environment field means that this object is not used to join hierarchies.
            nodes_by_labels[tuple(node["labels"])].append(properties)
        for labels, properties_list in nodes_by_labels.items():
            graph.execute(
                f"UNWIND $nodes AS properties CREATE (n:{':'.join(labels)}) SET n = properties",
                {"nodes": properties_list},
            )
        edges_by_kind: dict[str, list[dict[str, object]]] = defaultdict(list)
        for edge in fixture["edges"]:
            assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", edge["kind"])
            edges_by_kind[edge["kind"]].append(
                {
                    "start": graph.namespace + edge["start"],
                    "end": graph.namespace + edge["end"],
                    "properties": edge["properties"],
                }
            )
        for kind, relationships in edges_by_kind.items():
            graph.execute(
                "UNWIND $relationships AS entry "
                "MATCH (source {objectid: entry.start}), (target {objectid: entry.end}) "
                f"CREATE (source)-[relationship:{kind}]->(target) SET relationship = entry.properties",
                {"relationships": relationships},
            )
        yield graph
    finally:
        try:
            graph.execute(
                "MATCH (n {pz_test_run: $run}) DETACH DELETE n",
                {"run": graph.namespace},
            )
        finally:
            session.close()


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda path: path.stem)
def test_rule_returns_only_the_expected_objects(rule_graph: RuleGraph, rule_file: Path):
    """The fixture includes two hierarchies and explicit positive/negative cases."""
    assert rule_graph.matching_ids(rule_file) == set(
        rule_graph.data["expected"][rule_file.stem]
    )


def test_only_computer_matching_needs_an_existing_tier_zero_seed(rule_graph: RuleGraph):
    """Protect the hierarchy and preview global administrators without a T0 client."""
    rule_graph.execute(
        "MATCH (n {pz_test_run: $run}) REMOVE n:Tag_Tier_Zero",
        {"run": rule_graph.namespace},
    )
    try:
        assert rule_graph.matching_ids(RULE_DIRECTORY / "t0-computers.json") == set()
        for path in RULE_DIRECTORY.glob("t0-hierarchy-*.json"):
            assert rule_graph.matching_ids(path) == set(
                rule_graph.data["expected"][path.stem]
            )
    finally:
        rule_graph.execute(
            "MATCH (n {pz_test_run: $run}) WHERE n.objectid IN $ids SET n:Tag_Tier_Zero",
            {
                "run": rule_graph.namespace,
                "ids": [
                    rule_graph.namespace + node_id
                    for node_id in rule_graph.data["tier_zero_nodes"]
                ],
            },
        )


def test_default_rules_leave_administrators_and_mapped_identities_outside_tier_zero(
    rule_graph: RuleGraph,
):
    """Global and scoped role assignments remain potential finding sources."""
    default_matches = set()
    for path in RULE_FILES:
        if PrivilegeZone.from_json(path).enabled:
            default_matches.update(rule_graph.matching_ids(path))
        # Disabled rules are previews only, so they contribute no default members.
    administrators_and_identities = {
        node["id"]
        for node in rule_graph.data["nodes"]
        if {"SCCM_AdminUser", "User", "Group"}.intersection(node["labels"])
    }
    assert default_matches.isdisjoint(administrators_and_identities)
    assert "nested-computer" not in default_matches


def test_tier_zero_ad_identity_does_not_promote_its_sccm_administrator_record(
    rule_graph: RuleGraph,
):
    """AD-to-SCCM control does not establish control in the other direction."""
    identity_id = rule_graph.namespace + "scoped-0001r-user"
    rule_graph.execute(
        "MATCH (n {objectid: $id}) SET n:Tag_Tier_Zero", {"id": identity_id}
    )
    try:
        for path in RULE_FILES:
            assert "scoped-0001r" not in rule_graph.matching_ids(path)
    finally:
        rule_graph.execute(
            "MATCH (n {objectid: $id}) REMOVE n:Tag_Tier_Zero", {"id": identity_id}
        )
