"""Task 9 (low-priv assumed edges plan): partition the mayyhem integration fixtures so
a low-priv test run can assert only the subset that does not require AdminService/WMI
collection.

Mechanism: a `requires_privilege: bool = False` field on the fixture case dataclasses,
so `run_integration_tests` can later filter `requires_privilege=True` cases out of a
low-priv run instead of asserting they are absent (they may or may not be, depending on
what else was collected -- Tier D is "cannot check this without privilege", not "this
must not exist").

Corrections to the plan's own (stale) test snippet, applied here:
  (a) The Tier-D EDGE set is ONLY the SCCM RBAC families that have no AD/LDAP/
      RemoteRegistry representation (design spec S:5): SCCM_FullAdministrator,
      SCCM_IsAssigned, SCCM_IsMappedTo, SCCM_AllPermissions. MSSQL_GetTGS and
      MSSQL_GetAdminTGS must NOT be flagged -- they are low-priv reachable (built off
      the site-DB login) and already emitted; this suite guards against a future edit
      re-adding them to the flagged set.
  (b) The Tier-D NODE set is the RBAC-object kinds design spec S:5 explicitly calls
      privileged: SCCM_AdminUser, SCCM_SecurityRole, SCCM_Collection. Without flagging
      these too, a low-priv run's node-count assertions (node-adminuser-count,
      node-securityrole-count, node-collection-count) would still require AdminService
      data and defeat the point of the partition.
"""
from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES
from openhound_sccm.integration.fixtures.nodes import MAYYHEM_NODE_CASES
from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase

# The SCCM RBAC families with no AD/LDAP/RemoteRegistry representation (design spec
# S:5) -- AdminService/WMI-gated in both collection modes.
TIER_D_EDGE_KINDS = {"SCCM_FullAdministrator", "SCCM_IsAssigned", "SCCM_IsMappedTo", "SCCM_AllPermissions"}

# Kinds that must NEVER be flagged even though they sit in the same MSSQL/RBAC-adjacent
# family: they are built off the site-DB login (Tier C), which is low-priv reachable
# once a site database is identified (confirmed or SPN+SCCM-assumed).
NEVER_FLAG_EDGE_KINDS = {"MSSQL_GetTGS", "MSSQL_GetAdminTGS"}

# The RBAC-object node kinds design spec S:5 calls out by name as AdminService/WMI-only.
TIER_D_NODE_KINDS = {"SCCM_AdminUser", "SCCM_SecurityRole", "SCCM_Collection"}


def test_tier_d_edge_cases_flagged_requires_privilege():
    for c in MAYYHEM_EDGE_CASES:
        if c.kind in TIER_D_EDGE_KINDS:
            assert getattr(c, "requires_privilege", False) is True, f"{c.id} must be flagged"


def test_non_tier_d_edge_cases_not_flagged():
    for c in MAYYHEM_EDGE_CASES:
        if c.kind not in TIER_D_EDGE_KINDS:
            assert getattr(c, "requires_privilege", False) is False, (
                f"{c.id} (kind={c.kind}) unexpectedly flagged requires_privilege"
            )


def test_mssql_tgs_kinds_never_flagged():
    kinds_present = {c.kind for c in MAYYHEM_EDGE_CASES}
    assert NEVER_FLAG_EDGE_KINDS & kinds_present, "fixture drifted: expected TGS cases are gone"
    for c in MAYYHEM_EDGE_CASES:
        if c.kind in NEVER_FLAG_EDGE_KINDS:
            assert getattr(c, "requires_privilege", False) is False, f"{c.id} must NOT be flagged"


def test_tier_d_node_cases_flagged_requires_privilege():
    for c in MAYYHEM_NODE_CASES:
        if any(k in TIER_D_NODE_KINDS for k in c.kinds):
            assert getattr(c, "requires_privilege", False) is True, f"{c.id} must be flagged"


def test_non_tier_d_node_cases_not_flagged():
    for c in MAYYHEM_NODE_CASES:
        if not any(k in TIER_D_NODE_KINDS for k in c.kinds):
            assert getattr(c, "requires_privilege", False) is False, (
                f"{c.id} (kinds={c.kinds}) unexpectedly flagged requires_privilege"
            )


def test_case_types_still_real_edgecase_nodecase():
    # requires_privilege must be additive, not a replacement type -- the shared engine
    # (run_suite, compare_graphs, etc.) type-checks against these base classes.
    assert all(isinstance(c, EdgeCase) for c in MAYYHEM_EDGE_CASES)
    assert all(isinstance(c, NodeCase) for c in MAYYHEM_NODE_CASES)


def test_low_priv_subset_excludes_all_tier_d():
    # The actual partition a low-priv run would apply: filter out requires_privilege
    # cases and confirm none of the Tier-D kinds survive.
    low_priv_edges = [c for c in MAYYHEM_EDGE_CASES if not getattr(c, "requires_privilege", False)]
    low_priv_nodes = [c for c in MAYYHEM_NODE_CASES if not getattr(c, "requires_privilege", False)]
    assert not ({c.kind for c in low_priv_edges} & TIER_D_EDGE_KINDS)
    assert not any(k in TIER_D_NODE_KINDS for c in low_priv_nodes for k in c.kinds)
    # And the partition must not be vacuous in either direction.
    assert len(low_priv_edges) < len(MAYYHEM_EDGE_CASES)
    assert len(low_priv_nodes) < len(MAYYHEM_NODE_CASES)


def test_run_integration_tests_filters_privileged_cases(monkeypatch, tmp_path):
    """privileged=False must skip exactly the requires_privilege cases, and nothing else.

    Closes the half of Task 9 the fixture work could not reach: flagging cases is inert
    unless the runner actually honours the flag.
    """
    import openhound_sccm.integration as integ
    from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES
    from openhound_sccm.integration.fixtures.nodes import MAYYHEM_NODE_CASES

    seen = {}

    def _fake_run_suite(graph, edge_cases, node_cases, **kw):
        seen["edges"], seen["nodes"] = list(edge_cases), list(node_cases)
        class _S:  # noqa: D401 - minimal stand-in
            failed = 0
        return _S()

    monkeypatch.setattr(integ, "load_graph", lambda d: {})
    monkeypatch.setattr(integ, "run_suite", _fake_run_suite)

    integ.run_integration_tests(tmp_path, privileged=True, log=lambda m: None)
    assert len(seen["edges"]) == len(MAYYHEM_EDGE_CASES)
    assert len(seen["nodes"]) == len(MAYYHEM_NODE_CASES)

    integ.run_integration_tests(tmp_path, privileged=False, log=lambda m: None)
    assert all(not getattr(c, "requires_privilege", False) for c in seen["edges"])
    assert all(not getattr(c, "requires_privilege", False) for c in seen["nodes"])
    # And it must actually have removed something -- otherwise the flag is untested.
    n_flagged = sum(getattr(c, "requires_privilege", False)
                    for c in (*MAYYHEM_EDGE_CASES, *MAYYHEM_NODE_CASES))
    assert n_flagged > 0
    assert len(seen["edges"]) + len(seen["nodes"]) == \
        len(MAYYHEM_EDGE_CASES) + len(MAYYHEM_NODE_CASES) - n_flagged
