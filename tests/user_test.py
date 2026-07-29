# src/openhound_sccm/models/user_test.py
"""Tests for UserNode — the model that converts a node_user coalesced row into
an SCCMNode. Mirrors models/computer_test.py in structure and naming."""
import pytest
from openhound_sccm.models.user import UserNode


def test_user_as_node():
    """Basic UserNode row -> node conversion: id=SID, kinds, environmentid."""
    n = UserNode(
        sid="S-1-5-21-1-2-3-1106",
        name="alice",
        resource_ids=["9@PS1"],
    ).as_node
    assert n is not None
    assert n.id == "S-1-5-21-1-2-3-1106"
    assert n.kinds == ["User", "Base"]
    assert n.properties.environmentid == "S-1-5-21-1-2-3"


def test_user_as_node_resource_ids_in_properties():
    """sccm_resource_ids on the node properties should reflect the input list."""
    n = UserNode(
        sid="S-1-5-21-1-2-3-1106",
        name="alice",
        resource_ids=["9@PS1"],
    ).as_node
    assert n.properties.SCCMResourceIDs == ["9@PS1"]


def test_user_as_node_sccm_infra():
    """An SCCM admin user should have sccm_infra=True on its node properties."""
    n = UserNode(
        sid="S-1-5-21-1-2-3-1500",
        name="svc_sccm",
        sccm_infra=True,
    ).as_node
    assert n.properties.SCCMInfra is True


def test_user_as_node_stored_in_sccm_site():
    """A reserved-account user should carry stored_in_sccm_site in properties."""
    n = UserNode(
        sid="S-1-5-21-1-2-3-2000",
        name="naa_account",
        stored_in_sccm_site="PS1",
    ).as_node
    assert n.properties.storedInSCCMSite == "PS1"


def test_user_no_sid_returns_none():
    """A row without a SID cannot be keyed; as_node must return None."""
    assert UserNode(sid=None, name="ghost").as_node is None


def test_user_empty_sid_returns_none():
    """An empty-string SID is equivalent to no SID and must return None."""
    assert UserNode(sid="", name="ghost").as_node is None


def test_user_non_domain_sid_returns_none():
    """A well-known/builtin SID with no fallback domain SID cannot be placed in a
    domain environment and must be dropped (as_node returns None)."""
    assert UserNode(sid="S-1-5-11", name="Authenticated Users").as_node is None


@pytest.mark.parametrize("distinguished_name,user_principal_name", [
    ("CN=alice,DC=lab,DC=local", "alice@lab.local"),
    ("CN=bob,OU=Users,DC=corp,DC=com", "bob@corp.com"),
    (None, None),
])
def test_user_exposes_distinguished_name_and_upn(distinguished_name, user_principal_name):
    """distinguished_name and user_principal_name must flow from UserNode fields
    through to UserProperties and be accessible on the emitted node."""
    n = UserNode(
        sid="S-1-5-21-1-2-3-1200",
        name="alice",
        distinguished_name=distinguished_name,
        user_principal_name=user_principal_name,
    ).as_node
    assert n is not None
    assert n.properties.distinguishedName == distinguished_name
    assert n.properties.userPrincipalName == user_principal_name


def test_user_exposes_sam_account_name():
    """sam_account_name must flow through to UserProperties.samAccountName so edges keyed
    on the User endpoint by samAccountName (HasSession, MSSQL_GetTGS/GetAdminTGS/
    ServiceAccountFor, SCCM_HasPrimaryUser/HasADLastLogonUser/IsMappedTo) can resolve it."""
    n = UserNode(
        sid="S-1-5-21-1-2-3-1116",
        name="mayyhem\\sqlsccmsvc (sqlsccmsvc)",
        sam_account_name="sqlsccmsvc",
    ).as_node
    assert n is not None
    assert n.properties.samAccountName == "sqlsccmsvc"
