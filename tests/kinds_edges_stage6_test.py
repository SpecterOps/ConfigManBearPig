from openhound_sccm.kinds import edges as ek


def test_relay_edge_kind_values():
    assert ek.SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE == "SCCM_CoerceAndRelayToAdminService"
    assert ek.MSSQL_COERCE_AND_RELAY_TO_MSSQL == "MSSQL_CoerceAndRelayToMSSQL"
    assert ek.SCCM_COERCE_AND_RELAY_TO_SMB == "SCCM_CoerceAndRelayToSMB"


def test_all_three_relays_traversable():
    # All three relay edges are real attack paths; CMBP intended them traversable
    # (the SMB one was a name-mismatch bug, ps1:2221 vs :6775 — fixed here).
    assert ek.SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.MSSQL_COERCE_AND_RELAY_TO_MSSQL in ek.TRAVERSABLE_EDGE_KINDS
    assert ek.SCCM_COERCE_AND_RELAY_TO_SMB in ek.TRAVERSABLE_EDGE_KINDS


def test_dead_smb_allowlist_name_removed():
    # The never-matching CMBP allow-list string must be gone, else the SMB relay
    # silently reverts to non-traversable.
    assert "CoerceAndRelayNTLMtoSMB" not in ek.TRAVERSABLE_EDGE_KINDS
