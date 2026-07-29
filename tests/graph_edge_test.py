from openhound_sccm.models.graph_edge import GraphEdge


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
