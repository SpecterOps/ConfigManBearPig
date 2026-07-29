from openhound_sccm.kinds import edges as ek


def test_stage3_edge_kind_values():
    assert ek.SCCM_CONTAINS == "SCCM_Contains"
    assert ek.SCCM_FULL_ADMINISTRATOR == "SCCM_FullAdministrator"
    assert ek.SCCM_ALL_PERMISSIONS == "SCCM_AllPermissions"
    assert ek.SCCM_ASSIGN_ALL_PERMISSIONS == "SCCM_AssignAllPermissions"


def test_traversable_set_unchanged_for_role_edges():
    # Only FullAdministrator + ApplicationAdministrator are traversable among the 7 (CMBP :2216-2249).
    assert ek.SCCM_FULL_ADMINISTRATOR in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_APPLICATION_ADMINISTRATOR in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_APPLICATION_AUTHOR not in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_OSD_MANAGER not in ek.TRAVERSABLE_EDGE_KINDS


def test_stage4_edge_kind_values():
    assert ek.SCCM_SAME_HOST_AS == "SCCM_SameHostAs"
    assert ek.SCCM_LOCAL_ADMIN_REQUIRED == "SCCM_LocalAdminRequired"


def test_stage4_edges_are_traversable():
    # Both are traversable per CMBP :2216-2249 (already in the frozenset by string).
    assert ek.SCCM_SAME_HOST_AS in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_LOCAL_ADMIN_REQUIRED in ek.TRAVERSABLE_EDGE_KINDS
