import pytest

from openhound_sccm.models.graph_edge import GraphEdge


@pytest.mark.parametrize("kind", [
    "SCCM_ApplicationAuthor",
    "SCCM_ComplianceSettingsManager",
    "SCCM_OSDManager",
    "SCCM_OperationsAdministrator",
    "SCCM_SecurityAdministrator",
    "SCCM_HasStoredAccount",
])
def test_role_and_stored_account_edges_are_emitted_as_traversable(kind):
    """The emitted property must agree with the schema's potential attack paths."""
    edge = next(GraphEdge(start_id="SOURCE", end_id="TARGET", kind=kind).edges)

    assert edge.kind == kind
    assert edge.start.value == "SOURCE" and edge.end.value == "TARGET"
    assert edge.properties.traversable is True


def test_graph_edge_sets_traversable_from_allowlist():
    e = list(GraphEdge(start_id="A", end_id="B", kind="SCCM_HasClient").edges)[0]
    assert e.kind == "SCCM_HasClient"
    assert e.start.value == "A" and e.end.value == "B"
    assert e.properties.traversable is True


def test_graph_edge_non_traversable_kind():
    e = list(GraphEdge(start_id="A", end_id="B", kind="SCCM_HasMember").edges)[0]
    assert e.properties.traversable is False


def test_graph_edge_drops_incomplete_row():
    assert list(GraphEdge(start_id="A", end_id=None, kind="MemberOf").edges) == []


def test_graph_edge_carries_collection_source():
    e = list(GraphEdge(start_id="A", end_id="B", kind="SCCM_HasClient",
                       collection_source=["AdminService-ClientDevices"]).edges)[0]
    assert e.properties.collectionSource == ["AdminService-ClientDevices"]
    assert e.properties.traversable is True


def test_graph_edge_collection_source_defaults_empty():
    e = list(GraphEdge(start_id="A", end_id="B", kind="MemberOf").edges)[0]
    assert e.properties.collectionSource == []
