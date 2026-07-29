# src/openhound_sccm/models/group_test.py
"""Tests for GroupNode: coalesced row -> OpenGraph Group+Base node.

Mirrors the pattern in computer_test.py / user_test.py.
"""
from openhound_sccm.models.group import GroupNode


def test_group_as_node_basic():
    """A normal domain-account group SID produces a valid Group+Base node."""
    node = GroupNode(
        sid="S-1-5-21-1-2-3-5001",
        name="LAB\\SCCMAdmins",
        sccm_infra=False,
        sccm_resource_ids=["9@PS1"],
    ).as_node

    assert node is not None
    assert node.id == "S-1-5-21-1-2-3-5001"
    assert node.kinds == ["Group", "Base"]
    assert node.properties.environmentid == "S-1-5-21-1-2-3"
    assert node.properties.SCCMResourceIDs == ["9@PS1"]
    assert node.properties.SCCMInfra is False


def test_group_as_node_sccm_infra():
    """Admin-sourced groups have sccm_infra=True on the emitted node."""
    node = GroupNode(
        sid="S-1-5-21-1-2-3-5002",
        name="LAB\\SiteAdmins",
        sccm_infra=True,
    ).as_node

    assert node is not None
    assert node.properties.SCCMInfra is True


def test_group_no_sid_returns_none():
    """A row with no SID must return None (no merge key)."""
    assert GroupNode(sid=None, name="SomeGroup").as_node is None


def test_group_empty_sid_returns_none():
    """An empty string SID is treated the same as None."""
    assert GroupNode(sid="", name="SomeGroup").as_node is None


def test_group_builtin_sid_with_fallback():
    """A builtin SID (S-1-5-32-*) uses fallback_domain_sid as environmentid."""
    node = GroupNode(
        sid="S-1-5-32-544",
        name="BUILTIN\\Administrators",
        fallback_domain_sid="S-1-5-21-1-2-3",
    ).as_node

    assert node is not None
    assert node.id == "S-1-5-32-544"
    assert node.properties.environmentid == "S-1-5-21-1-2-3"


def test_group_builtin_sid_without_fallback_returns_none():
    """A builtin SID with no fallback domain cannot be placed; dropped."""
    assert GroupNode(
        sid="S-1-5-32-544",
        name="BUILTIN\\Administrators",
        fallback_domain_sid=None,
    ).as_node is None


def test_group_well_known_sid_without_fallback_returns_none():
    """S-1-5-11 (Authenticated Users) has no domain part and no fallback; dropped."""
    assert GroupNode(
        sid="S-1-5-11",
        name="Authenticated Users",
        fallback_domain_sid=None,
    ).as_node is None


def test_group_ad_attributes_mapped():
    """sam_account_name/distinguished_name (from ad_props) surface as CMBP-verbatim
    SamAccountName/distinguishedName -- casing confirmed against a real CMBP Group
    node (bloodhound-sccm-20260728-113941.zip groups.json): CMBP uses PascalCase
    'SamAccountName' here, unlike the camelCase 'samAccountName' Computer/User use.
    """
    node = GroupNode(
        sid="S-1-5-21-1-2-3-512",
        name="MAYYHEM\\Domain Admins",
        domain="mayyhem.com",
        enabled=True,
        is_domain_principal=True,
        type="Group",
        sam_account_name="Domain Admins",
        distinguished_name="CN=Domain Admins,CN=Users,DC=mayyhem,DC=com",
    ).as_node

    assert node is not None
    assert node.properties.Domain == "mayyhem.com"
    assert node.properties.Enabled is True
    assert node.properties.IsDomainPrincipal is True
    assert node.properties.Type == "Group"
    assert node.properties.SamAccountName == "Domain Admins"
    assert node.properties.distinguishedName == "CN=Domain Admins,CN=Users,DC=mayyhem,DC=com"


def test_group_sid_uppercased():
    """The node id is always uppercase regardless of the input SID casing."""
    node = GroupNode(
        sid="s-1-5-21-1-2-3-5001",
        name="LAB\\SCCMAdmins",
    ).as_node

    assert node is not None
    assert node.id == "S-1-5-21-1-2-3-5001"
