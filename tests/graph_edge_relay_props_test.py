from openhound_sccm.graph import SCCMEdgeProperties, SCCMRelayEdgeProperties
from openhound_sccm.kinds import edges as ek
from openhound_sccm.models.graph_edge import GraphEdge


def test_relay_kind_emits_relay_properties_with_coercion_lists():
    row = GraphEdge(
        start_id="MAYYHEM.COM-S-1-5-11",
        end_id="PS1",
        kind=ek.SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE,
        collection_source=["Post-processing"],
        coercion_victim_and_relay_target_pairs=["Coerce SS01.mayyhem.com, relay to PROV01.mayyhem.com"],
        coercion_victim_hostnames=None,
    )
    edge = next(iter(row.edges))
    assert isinstance(edge.properties, SCCMRelayEdgeProperties)
    assert edge.properties.traversable is True
    assert edge.properties.collectionSource == ["Post-processing"]
    assert edge.properties.coercionVictimAndRelayTargetPairs == [
        "Coerce SS01.mayyhem.com, relay to PROV01.mayyhem.com"
    ]
    assert edge.properties.coercionVictimHostnames == []


def test_smb_relay_carries_victim_hostnames():
    row = GraphEdge(
        start_id="MAYYHEM.COM-S-1-5-11",
        end_id="S-1-5-21-1-2-3-1104",
        kind=ek.SCCM_COERCE_AND_RELAY_TO_SMB,
        collection_source=["SMB-Negotiate"],
        coercion_victim_and_relay_target_pairs=None,
        coercion_victim_hostnames=["SS01.mayyhem.com"],
    )
    edge = next(iter(row.edges))
    assert isinstance(edge.properties, SCCMRelayEdgeProperties)
    assert edge.properties.coercionVictimHostnames == ["SS01.mayyhem.com"]


def test_non_relay_kind_uses_base_properties_no_coercion_fields():
    row = GraphEdge(
        start_id="A", end_id="B", kind=ek.SCCM_HAS_MEMBER,
        collection_source=["AdminService-SMS_FullCollectionMembership"],
    )
    edge = next(iter(row.edges))
    assert isinstance(edge.properties, SCCMEdgeProperties)
    assert not isinstance(edge.properties, SCCMRelayEdgeProperties)
    assert not hasattr(edge.properties, "coercionVictimHostnames")
