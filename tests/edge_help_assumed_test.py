"""Task 7 (low-priv assumed edges plan): every EdgeHelp block for a kind that can be
built from an *assumed* (templated/inferred) basis states three things -- the
inference rule, the data source, and the false-positive caveat.

edge_help.py already authors a block for every real edge kind (edge_help_test.py's
test_scope_is_complete proves that), so this is not a coverage test -- it is a content
test over the subset of kinds the 2026-07-23 low-priv-assumed-edges design spec (S:4)
marks as assumed at least some of the time.

Three of those kinds -- SCCM_AssignAllPermissions, SCCM_LocalAdminRequired,
SCCM_CoerceAndRelayToAdminService -- are measured from directly observed site-system
role tags and the site hierarchy; their builders never gate on
--disable-possible-edges (verified pre-existing at HEAD, spec S:7's "known
spec-vs-code gap" note). So their help text must carry a caveat without claiming the
flag removes them -- this suite checks that negatively (the literal flag spelling must
not appear in their blocks) rather than trying to parse the positive claim out of free
text.
"""
from openhound_sccm.edge_help import EDGE_HELP
from openhound_sccm.kinds import edges as ek

# Kinds that are (at least sometimes) built from an inference rather than read
# straight off the target system, per design spec S:4 Tier B/C and Tier A's client
# device correlation. HasSession/MemberOf are deliberately excluded from EDGE_HELP
# entirely (BloodHound documents them natively) and so are not part of this list.
ASSUMED_KINDS = [
    ek.SCCM_ASSIGN_ALL_PERMISSIONS,
    ek.SCCM_LOCAL_ADMIN_REQUIRED,
    ek.SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE,
    ek.SCCM_COERCE_AND_RELAY_TO_SMB,
    ek.MSSQL_COERCE_AND_RELAY_TO_MSSQL,
    ek.SCCM_SAME_HOST_AS,
    ek.SCCM_HAS_CLIENT,
    ek.MSSQL_CONTAINS,
    ek.MSSQL_CONTROL_DB,
    ek.MSSQL_CONTROL_SERVER,
    ek.MSSQL_HAS_LOGIN,
    ek.MSSQL_IS_MAPPED_TO,
    ek.MSSQL_MEMBER_OF,
]

# These read like they could be "assumed" (they sit in the same MSSQL-scaffolding
# family as the kinds above) but design spec D2(a) says they are confirmed and
# unconditional -- built straight from an AD-readable MSSQLSvc SPN, never templated.
# Listed here so a future edit accidentally adding a false-positive caveat to them
# gets caught, not so this test enforces one.
CONFIRMED_UNCONDITIONAL_KINDS = [ek.MSSQL_HOST_FOR, ek.MSSQL_EXECUTE_ON_HOST]

# Prose markers that indicate an inference rule / caveat is actually present. Loose on
# purpose -- this module's docstring forbids templated prose, so the exact wording
# differs block to block; this only checks that *some* caveat language landed.
_CAVEAT_MARKERS = ("assum", "possible edge", "false positive", "template", "infer", "may be")

# The three kinds whose builders are measured evidence and never gated on the CLI
# flag (spec S:7's documented gap). Their help text must not claim otherwise.
_NOT_FLAG_GATED = [
    ek.SCCM_ASSIGN_ALL_PERMISSIONS,
    ek.SCCM_LOCAL_ADMIN_REQUIRED,
    ek.SCCM_COERCE_AND_RELAY_TO_ADMIN_SERVICE,
]


def _combined_text(kind: str) -> str:
    block = EDGE_HELP[kind]
    parts = [block.general, block.windowsAbuse, block.linuxAbuse, block.opsec]
    return " ".join(p for p in parts if p).lower()


def test_every_assumed_kind_is_authored():
    for kind in ASSUMED_KINDS:
        assert kind in EDGE_HELP, f"missing help for {kind}"


def test_every_assumed_kind_states_a_caveat():
    for kind in ASSUMED_KINDS:
        text = _combined_text(kind)
        assert any(w in text for w in _CAVEAT_MARKERS), (
            f"{kind}: help text has no inference-rule/false-positive caveat "
            f"(looked for any of {_CAVEAT_MARKERS})"
        )


def test_not_flag_gated_kinds_never_name_the_cli_flag():
    # Per the owner's ruling, these three are NOT removed by --disable-possible-edges
    # (their gates are measured evidence) -- the help text must not claim they are.
    for kind in _NOT_FLAG_GATED:
        text = _combined_text(kind)
        assert "disable-possible-edges" not in text and "disable_possible_edges" not in text, (
            f"{kind}: help text must not claim the CLI flag suppresses this edge"
        )


def test_confirmed_unconditional_kinds_carry_no_false_positive_caveat():
    # HostFor/ExecuteOnHost are confirmed straight off an AD-readable SPN in both flag
    # modes (D2a) -- they should read as solid fact, not as an assumption to distrust.
    for kind in CONFIRMED_UNCONDITIONAL_KINDS:
        text = _combined_text(kind)
        assert "assum" not in text and "false positive" not in text, (
            f"{kind}: is confirmed/unconditional per D2(a); it should not carry an "
            f"assumed-edge caveat"
        )


def test_has_client_general_still_mentions_client_device():
    # Regression guard: edge_help_integration_test.py asserts "client device" (lower)
    # is present in SCCM_HasClient's general text end-to-end; keep it intact while
    # extending the block with the possible-client-device caveat.
    assert "client device" in EDGE_HELP[ek.SCCM_HAS_CLIENT].general.lower()
