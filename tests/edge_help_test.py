"""Tests for the per-edge entity-panel help content map (edge_help.py)."""
from openhound_sccm.edge_help import EDGE_HELP, PENDING_HELP_KINDS, EdgeHelp
from openhound_sccm.kinds import edges as ek


def _valid_kind_strings() -> set[str]:
    """Every edge-kind string constant declared in kinds/edges.py."""
    return {
        v for name, v in vars(ek).items()
        if name.isupper() and isinstance(v, str)
    }


def test_as_fields_omits_none_sections():
    h = EdgeHelp(general="G")
    assert h.as_fields() == {"general": "G"}
    h2 = EdgeHelp(general="G", windowsAbuse="W", references=["u"])
    assert h2.as_fields() == {"general": "G", "windowsAbuse": "W", "references": ["u"]}


def test_admins_replicated_to_block_is_populated():
    block = EDGE_HELP[ek.SCCM_ADMINS_REPLICATED_TO]
    assert "replicated" in block.general.lower()
    assert block.windowsAbuse and "SharpSCCM" in block.windowsAbuse
    assert block.linuxAbuse and "sccmhunter" in block.linuxAbuse
    assert block.opsec and "EDR" in block.opsec
    assert block.references and all(r.startswith("http") for r in block.references)


def test_all_map_and_pending_keys_are_valid_edge_kinds():
    valid = _valid_kind_strings()
    unknown = (set(EDGE_HELP) | set(PENDING_HELP_KINDS)) - valid
    assert not unknown, f"Not real edge-kind constants: {unknown}"


def test_authored_and_pending_are_disjoint():
    overlap = set(EDGE_HELP) & set(PENDING_HELP_KINDS)
    assert not overlap, f"Kinds both authored and pending: {overlap}"


def test_native_help_kinds_are_excluded():
    # BloodHound ships native help for these; we must not author or list them.
    for kind in (ek.MEMBER_OF, ek.HAS_SESSION, "AdminTo"):
        assert kind not in EDGE_HELP
        assert kind not in PENDING_HELP_KINDS


#: Standard BloodHound base kinds that SharpHound emits and BloodHound documents itself.
#: This collector emits them so its nodes merge into the native AD graph, but writing our
#: own entity-panel help for them would duplicate — and eventually contradict —
#: BloodHound's. GenericAll joined the list when the System Management container DACL work
#: (Tier A+) started emitting it; the assertion below had gone red unnoticed since, because
#: nothing was running the full suite.
NATIVELY_DOCUMENTED_KINDS = {ek.MEMBER_OF, ek.HAS_SESSION, ek.GENERIC_ALL}


def test_scope_is_complete():
    # Authored + pending must cover every real edge kind except the ones BloodHound
    # documents natively. Asserting against the real kind constants (rather than a
    # hardcoded count) means a newly added and emitted edge kind fails this test loudly
    # instead of silently getting no entity-panel help.
    assert (set(EDGE_HELP) | set(PENDING_HELP_KINDS)) == _valid_kind_strings() - NATIVELY_DOCUMENTED_KINDS
