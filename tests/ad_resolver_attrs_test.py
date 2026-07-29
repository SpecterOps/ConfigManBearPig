from openhound_sccm.clients.ad import ADClient


def test_attr_map_has_uac_and_spn():
    # The shared AD client maps LDAP attribute names -> snake_case dict keys.
    m = ADClient._ATTR_KEY_MAP
    assert m.get("useraccountcontrol") == "user_account_control"
    assert m.get("serviceprincipalname") == "service_principal_name"


def test_resolver_requests_uac_and_spn():
    import openhound_sccm.context as ctx_mod
    src = ctx_mod.__file__
    text = open(src, encoding="utf-8").read()
    # Both resolver searches must request the two new attributes.
    assert text.count('"userAccountControl"') >= 2
    assert text.count('"servicePrincipalName"') >= 2
