from openhound_sccm.kinds import edges as ek


def test_stage3_edge_kind_values():
    assert ek.SCCM_CONTAINS == "SCCM_Contains"
    assert ek.SCCM_FULL_ADMINISTRATOR == "SCCM_FullAdministrator"
    assert ek.SCCM_ALL_PERMISSIONS == "SCCM_AllPermissions"
    assert ek.SCCM_ASSIGN_ALL_PERMISSIONS == "SCCM_AssignAllPermissions"


def test_role_and_stored_account_paths_are_traversable():
    # All seven built-in role paths and site-stored accounts can participate in
    # attack paths, subject to the prerequisites described in their findings.
    for kind in (
        ek.SCCM_FULL_ADMINISTRATOR,
        ek.SCCM_APPLICATION_ADMINISTRATOR,
        ek.SCCM_APPLICATION_AUTHOR,
        ek.SCCM_COMPLIANCE_SETTINGS_MANAGER,
        ek.SCCM_OSD_MANAGER,
        ek.SCCM_OPERATIONS_ADMINISTRATOR,
        ek.SCCM_SECURITY_ADMINISTRATOR,
        ek.SCCM_HAS_STORED_ACCOUNT,
    ):
        assert kind in ek.TRAVERSABLE_EDGE_KINDS


def test_stage4_edge_kind_values():
    assert ek.SCCM_SAME_HOST_AS == "SCCM_SameHostAs"
    assert ek.SCCM_LOCAL_ADMIN_REQUIRED == "SCCM_LocalAdminRequired"


def test_stage4_edges_are_traversable():
    # Both are traversable per CMBP :2216-2249 (already in the frozenset by string).
    assert ek.SCCM_SAME_HOST_AS in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_LOCAL_ADMIN_REQUIRED in ek.TRAVERSABLE_EDGE_KINDS
