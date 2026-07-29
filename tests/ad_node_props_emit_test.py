# src/openhound_sccm/models/ad_node_props_emit_test.py
"""Tests for CMBP-parity AD attribute properties (Task A4).

Verifies that ComputerProperties/UserProperties/GroupProperties carry the
Domain/Enabled/IsDomainPrincipal/Type/objectClass/servicePrincipalName/CN
fields (CMBP casing), and that the AD node models (ComputerNode/UserNode/
GroupNode) thread the node-table columns from Task A3 through to those
fields, leaving them null (not coerced) when the underlying column is NULL.
"""
from openhound_sccm.graph import ComputerProperties, GroupProperties, UserProperties
from openhound_sccm.models.computer import ComputerNode
from openhound_sccm.models.group import GroupNode
from openhound_sccm.models.user import UserNode


def test_ad_props_fields_exist_with_cmbp_casing():
    """All three AD property dataclasses must expose the CMBP-cased AD fields."""
    for cls in (ComputerProperties, UserProperties, GroupProperties):
        names = cls.__dataclass_fields__
        for f in (
            "Domain",
            "Enabled",
            "IsDomainPrincipal",
            "Type",
            "objectClass",
            "servicePrincipalName",
            "CN",
        ):
            assert f in names, f"{cls.__name__} missing {f}"


def test_computer_node_threads_ad_props():
    """ComputerNode.as_node must map the ad_props columns to CMBP-cased fields."""
    n = ComputerNode(
        sid="S-1-5-21-1-2-3-1104",
        name="HOST1",
        enabled=True,
        type="Computer",
        is_domain_principal=True,
        object_class=["top", "person", "computer"],
        service_principal_name=["HOST/host1.lab"],
        cn="HOST1",
        domain="lab.local",
    ).as_node
    assert n is not None
    props = n.properties
    assert props.Enabled is True
    assert props.Type == "Computer"
    assert props.IsDomainPrincipal is True
    assert props.objectClass == ["top", "person", "computer"]
    assert props.servicePrincipalName == ["HOST/host1.lab"]
    assert props.CN == "HOST1"
    assert props.Domain == "lab.local"


def test_computer_node_ad_props_null_when_unresolved():
    """A computer that was never LDAP-resolved must keep every AD field null
    (not coerced to a default like False/[])."""
    n = ComputerNode(sid="S-1-5-21-1-2-3-1104", name="HOST1").as_node
    assert n is not None
    props = n.properties
    assert props.Enabled is None
    assert props.Type is None
    assert props.IsDomainPrincipal is None
    assert props.objectClass is None
    assert props.servicePrincipalName is None
    assert props.CN is None
    assert props.Domain is None


def test_user_node_threads_ad_props():
    """UserNode.as_node must map the ad_props columns to CMBP-cased fields."""
    n = UserNode(
        sid="S-1-5-21-1-2-3-1106",
        name="alice",
        enabled=False,
        type="User",
        is_domain_principal=True,
        object_class=["top", "person", "user"],
        service_principal_name=None,
        cn="alice",
        domain="lab.local",
    ).as_node
    assert n is not None
    props = n.properties
    assert props.Enabled is False
    assert props.Type == "User"
    assert props.IsDomainPrincipal is True
    assert props.objectClass == ["top", "person", "user"]
    assert props.servicePrincipalName is None
    assert props.CN == "alice"
    assert props.Domain == "lab.local"


def test_user_node_ad_props_null_when_unresolved():
    """A user that was never LDAP-resolved must keep every AD field null."""
    n = UserNode(sid="S-1-5-21-1-2-3-1106", name="alice").as_node
    assert n is not None
    props = n.properties
    assert props.Enabled is None
    assert props.IsDomainPrincipal is None
    assert props.objectClass is None
    assert props.servicePrincipalName is None
    assert props.CN is None
    assert props.Domain is None


def test_group_node_threads_ad_props():
    """GroupNode.as_node must map the ad_props columns to CMBP-cased fields."""
    n = GroupNode(
        sid="S-1-5-21-1-2-3-1108",
        name="Domain Admins",
        enabled=True,
        type="Group",
        is_domain_principal=True,
        object_class=["top", "group"],
        service_principal_name=None,
        cn="Domain Admins",
        domain="lab.local",
    ).as_node
    assert n is not None
    props = n.properties
    assert props.Enabled is True
    assert props.Type == "Group"
    assert props.IsDomainPrincipal is True
    assert props.objectClass == ["top", "group"]
    assert props.servicePrincipalName is None
    assert props.CN == "Domain Admins"
    assert props.Domain == "lab.local"


def test_group_node_ad_props_null_when_unresolved():
    """A group that was never LDAP-resolved (e.g. a synthesized well-known SID
    group) must keep every AD field null, not coerced to False."""
    n = GroupNode(
        sid="S-1-5-21-1-2-3-1108",
        name="Domain Admins",
    ).as_node
    assert n is not None
    props = n.properties
    assert props.Enabled is None
    assert props.IsDomainPrincipal is None
    assert props.objectClass is None
    assert props.servicePrincipalName is None
    assert props.CN is None
    assert props.Domain is None
