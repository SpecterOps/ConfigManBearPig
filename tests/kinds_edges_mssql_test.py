from openhound_sccm.kinds import edges as ek


def test_mssql_edge_kind_values():
    assert ek.MSSQL_CONTAINS == "MSSQL_Contains"
    assert ek.MSSQL_CONTROL_SERVER == "MSSQL_ControlServer"
    assert ek.MSSQL_CONTROL_DB == "MSSQL_ControlDB"
    assert ek.MSSQL_HOST_FOR == "MSSQL_HostFor"
    assert ek.MSSQL_EXECUTE_ON_HOST == "MSSQL_ExecuteOnHost"
    assert ek.MSSQL_HAS_LOGIN == "MSSQL_HasLogin"
    assert ek.MSSQL_IS_MAPPED_TO == "MSSQL_IsMappedTo"
    assert ek.MSSQL_MEMBER_OF == "MSSQL_MemberOf"
    assert ek.MSSQL_SERVICE_ACCOUNT_FOR == "MSSQL_ServiceAccountFor"
    assert ek.MSSQL_GET_ADMIN_TGS == "MSSQL_GetAdminTGS"
    assert ek.MSSQL_GET_TGS == "MSSQL_GetTGS"


def test_mssql_structural_edges_are_traversable():
    # All present in the frozenset by string since Stage 0.
    for k in (ek.MSSQL_CONTAINS, ek.MSSQL_CONTROL_DB, ek.MSSQL_CONTROL_SERVER,
              ek.MSSQL_EXECUTE_ON_HOST, ek.MSSQL_HOST_FOR, ek.MSSQL_HAS_LOGIN,
              ek.MSSQL_IS_MAPPED_TO, ek.MSSQL_MEMBER_OF, ek.MSSQL_GET_ADMIN_TGS,
              ek.MSSQL_GET_TGS):
        assert k in ek.TRAVERSABLE_EDGE_KINDS
