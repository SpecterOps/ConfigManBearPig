"""GraphEdge merges entity-panel help content into the edge property bag."""
import pytest

from openhound_sccm.edge_help import EDGE_HELP, PENDING_HELP_KINDS, EdgeHelp
from openhound_sccm.graph import SCCMEdgeProperties, SCCMRelayEdgeProperties
from openhound_sccm.kinds import edges as ek
from openhound_sccm.models.graph_edge import GraphEdge


def _edge(kind, **kw):
    return next(iter(GraphEdge(start_id="A", end_id="B", kind=kind, **kw).edges))


def test_authored_kind_edge_carries_help():
    e = _edge(ek.SCCM_ADMINS_REPLICATED_TO)
    block = EDGE_HELP[ek.SCCM_ADMINS_REPLICATED_TO]
    assert e.properties.general == block.general
    assert e.properties.windowsAbuse == block.windowsAbuse
    assert e.properties.linuxAbuse == block.linuxAbuse
    assert e.properties.opsec == block.opsec
    assert e.properties.references == block.references


def test_excluded_kind_edge_has_no_help():
    e = _edge(ek.MEMBER_OF)
    assert isinstance(e.properties, SCCMEdgeProperties)
    assert e.properties.general is None
    assert e.properties.windowsAbuse is None
    assert e.properties.linuxAbuse is None
    assert e.properties.opsec is None
    assert e.properties.references is None


def test_pending_kind_edge_has_no_help_until_authored():
    # A kind still in PENDING_HELP_KINDS (no block yet) emits no help fields. Pick the
    # kind dynamically so authoring any specific edge never breaks this test. Once every
    # scoped kind is authored PENDING is empty and there is nothing to exercise here
    # (the excluded-kind test still covers the "no help" path).
    if not PENDING_HELP_KINDS:
        pytest.skip("all scoped kinds authored; no pending kind to exercise")
    e = _edge(PENDING_HELP_KINDS[0])
    assert isinstance(e.properties, SCCMEdgeProperties)
    assert e.properties.general is None
    assert e.properties.references is None


def test_relay_edge_merges_help_and_keeps_coercion(monkeypatch):
    # Inject a block for a relay kind so the test does not depend on authored content.
    # graph_edge imported EDGE_HELP by reference, so mutating this dict is visible there.
    monkeypatch.setitem(EDGE_HELP, ek.SCCM_COERCE_AND_RELAY_TO_SMB, EdgeHelp(general="RELAY-GENERAL"))
    e = _edge(
        ek.SCCM_COERCE_AND_RELAY_TO_SMB,
        coercion_victim_hostnames=["SS01.mayyhem.com"],
    )
    assert isinstance(e.properties, SCCMRelayEdgeProperties)
    assert e.properties.general == "RELAY-GENERAL"          # help merged in
    assert e.properties.coercionVictimHostnames == ["SS01.mayyhem.com"]  # relay context intact


def test_help_fields_optional_sections_stay_none(monkeypatch):
    # A block with only `general` leaves the other four fields None on the edge.
    monkeypatch.setitem(EDGE_HELP, ek.SCCM_CONTAINS, EdgeHelp(general="ONLY-GENERAL"))
    e = _edge(ek.SCCM_CONTAINS)
    assert e.properties.general == "ONLY-GENERAL"
    assert e.properties.windowsAbuse is None
    assert e.properties.references is None


def test_edgehelp_fields_are_all_edge_properties():
    # Every EdgeHelp field must exist on SCCMEdgeProperties, or merging a help block's
    # fields into an edge's properties (**help_fields) would TypeError at convert time.
    from dataclasses import fields

    from openhound_sccm.edge_help import EdgeHelp
    help_names = {f.name for f in fields(EdgeHelp)}
    prop_names = {f.name for f in fields(SCCMEdgeProperties)}
    assert help_names <= prop_names, f"EdgeHelp fields missing from SCCMEdgeProperties: {help_names - prop_names}"
