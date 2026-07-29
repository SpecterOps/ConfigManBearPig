from dataclasses import asdict
from openhound_sccm.graph import domain_environment_id, SCCMNode, ComputerProperties


def test_domain_env_id_strips_rid():
    assert domain_environment_id("S-1-5-21-11-22-33-1104") == "S-1-5-21-11-22-33"


def test_domain_env_id_uppercases():
    assert domain_environment_id("s-1-5-21-11-22-33-500") == "S-1-5-21-11-22-33"


def test_domain_env_id_builtin_uses_fallback():
    assert domain_environment_id("S-1-5-32-544", fallback_domain_sid="S-1-5-21-11-22-33") == "S-1-5-21-11-22-33"


def test_domain_env_id_builtin_no_fallback_is_none():
    assert domain_environment_id("S-1-5-11") is None


def test_domain_env_id_empty_is_none():
    assert domain_environment_id("") is None


def test_sccm_node_serializes_id_kinds_properties():
    node = SCCMNode(
        id="S-1-5-21-11-22-33-1104",
        kinds=["Computer", "Base"],
        properties=ComputerProperties(name="HOST1", displayname="HOST1", environmentid="S-1-5-21-11-22-33"),
    )
    d = asdict(node)
    assert d["id"] == "S-1-5-21-11-22-33-1104"
    assert d["kinds"] == ["Computer", "Base"]
    assert d["properties"]["name"] == "HOST1"
    assert d["properties"]["environmentid"] == "S-1-5-21-11-22-33"
