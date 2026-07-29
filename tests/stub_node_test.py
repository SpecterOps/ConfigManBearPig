# src/openhound_sccm/models/stub_node_test.py
from openhound_sccm.models.stub_node import StubNode


def test_stub_node_user_gets_base_and_domain_env():
    n = StubNode(id="S-1-5-21-1-2-3-9999", kind="User").as_node
    assert n.id == "S-1-5-21-1-2-3-9999"
    assert n.kinds == ["User", "Base"]
    assert n.properties.environmentid == "S-1-5-21-1-2-3"


def test_stub_node_base_only_falls_back_to_id_env():
    n = StubNode(id="SOMEID", kind="Base").as_node
    assert n.kinds == ["Base"]
    assert n.properties.environmentid == "SOMEID"


def test_stub_node_missing_returns_none():
    assert StubNode(id=None, kind="User").as_node is None
