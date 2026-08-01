"""Task 9 (low-priv assumed edges plan): partition the mayyhem integration fixtures so
a low-priv test run can assert only the subset that does not require AdminService/WMI
collection.

Mechanism: a `requires_privilege: bool = False` field on the fixture case dataclasses,
so `run_integration_tests` can later filter `requires_privilege=True` cases out of a
low-priv run instead of asserting they are absent (they may or may not be, depending on
what else was collected -- "requires SCCM admin" means "cannot check this without
privilege", not "this must not exist").

Corrections to the plan's own (stale) test snippet, applied here:
  (a) The EDGE set is the kinds a low-priv collection genuinely cannot produce. It
      started as the four SCCM RBAC families with no AD/LDAP/RemoteRegistry
      representation (design spec S:5) and was widened on 2026-07-31 by measurement --
      see the comment on REQUIRES_SCCM_ADMIN_EDGE_KINDS below. MSSQL_GetTGS and
      MSSQL_GetAdminTGS must NOT be flagged -- they are low-priv reachable (built off
      the site-DB login) and already emitted; this suite guards against a future edit
      re-adding them to the flagged set. @_Mayyhem reconfirmed that on 2026-07-31:
      those two "should not require privileges in SCCM" (they are under-produced at low
      privilege today, which is a collector gap, not a privilege boundary -- con-c509).
  (b) The NODE set is the RBAC-object kinds design spec S:5 explicitly calls
      privileged: SCCM_AdminUser, SCCM_SecurityRole, SCCM_Collection. Without flagging
      these too, a low-priv run's node-count assertions (node-adminuser-count,
      node-securityrole-count, node-collection-count) would still require AdminService
      data and defeat the point of the partition.
"""
from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES
from openhound_sccm.integration.fixtures.nodes import MAYYHEM_NODE_CASES
from openhound_collector_common.integration_testing.cases import EdgeCase, NodeCase

# Edge kinds that a low-priv collection cannot produce, so a low-priv run must skip
# rather than assert them.
#
# BROADENED 2026-07-31 (con-c542). This set was originally just the four SCCM RBAC
# families design spec S:5 names. A privileged/unprivileged A/B against the mayyhem
# lab -- same code, same lab, one run as an SCCM admin and one as MAYYHEM\lowpriv --
# measured 34 cases that pass privileged and fail unprivileged, against only 8 then
# flagged. The five kinds added below were confirmed privilege-dependent by that
# measurement and by @_Mayyhem's per-case review, so the flag now means "measured to
# need AdminService/WMI", not "named in the design spec's original list". Leaving them
# unflagged meant a low-priv run reported failures for data it could never collect.
#
# The four originals are RBAC families with no AD/LDAP/RemoteRegistry representation.
# The five additions are all AdminService/WMI-sourced too: SCCM_Contains here always
# targets an RBAC node (admin user / security role / collection), and the four
# device-affinity kinds come from the SCCM device inventory.
REQUIRES_SCCM_ADMIN_EDGE_KINDS = {
    "SCCM_FullAdministrator", "SCCM_IsAssigned", "SCCM_IsMappedTo", "SCCM_AllPermissions",
    "SCCM_Contains", "SCCM_HasADLastLogonUser", "SCCM_HasMember",
    "SCCM_HasPrimaryUser", "SCCM_HasCurrentUser",
}

# Kinds that must NEVER be flagged even though they sit in the same MSSQL/RBAC-adjacent
# family: they are built off the site-DB login, which is low-priv reachable
# once a site database is identified (confirmed or SPN+SCCM-assumed).
NEVER_FLAG_EDGE_KINDS = {"MSSQL_GetTGS", "MSSQL_GetAdminTGS"}

# The RBAC-object node kinds design spec S:5 calls out by name as AdminService/WMI-only.
REQUIRES_SCCM_ADMIN_NODE_KINDS = {"SCCM_AdminUser", "SCCM_SecurityRole", "SCCM_Collection"}

# Cases where the PRIVILEGE REQUIREMENT BELONGS TO THE ASSERTION, NOT THE KIND.
#
# The two guards below decide by kind, which works while "needs SCCM admin" is a
# property of the node type. node-clientdevice-confirmed-has-guid-id (con-5e71) is the
# first case where it is not: SCCM_ClientDevice is emphatically NOT admin-only -- a
# low-privilege run produces 14 of them -- but that case asserts the *id form*, and only
# a confirmed, AdminService-seen device is keyed by its SMS GUID. An SPN-inferred
# possible client is keyed "<sid>@<site>".
#
# Adding SCCM_ClientDevice to the kind set above would be wrong: it would force
# node-clientdevice-count to be flagged too, and that case must stay asserted at low
# privilege. So this is an explicit, per-case escape hatch rather than a widened kind
# set -- deliberately a short list, because every entry is a place the kind-based model
# does not describe reality.
PRIVILEGE_BY_ASSERTION_NOT_KIND = {
    # Only a confirmed, AdminService-seen device is keyed by its SMS GUID.
    "node-clientdevice-confirmed-has-guid-id",
    # These three need all THREE site databases characterized, and at low privilege
    # only two are.
    #
    # CORRECTED 2026-08-01. This block used to justify that with "ps1-sec is correctly
    # a plain MSSQL_Server and not a site database there". That is FALSE, and the
    # distinction matters because it changes what a future fix must do. Microsoft
    # requires a secondary site's database to run ON the secondary site server
    # (prerequisites-for-installing-sites#bkmk_secondary), so ps1-sec unambiguously IS
    # SEC's site database -- privileged collection sees it as CONFIGMGRSEC\CM_SEC. The
    # real limitation is that low privilege cannot PROVE SEC is a secondary:
    #
    #   * site_type / parent_site_code come only from AdminService SMS_SCI_SiteDefinition
    #     (admin-gated) or from the LDAP mSSMSManagementPoint capabilities classifier in
    #     collectors/ldap.py.
    #   * AD publishes NOTHING for a secondary. Verified against mayyhem 2026-08-01: the
    #     System Management container holds exactly SMS-Site-PS1, SMS-Site-CAS and
    #     SMS-MP-PS1-PS1-MP.MAYYHEM.COM -- no SEC site object and no SEC management
    #     point -- so ldap_management_points_raw has a single row and the classifier has
    #     no SEC input to work on.
    #
    # So site_hierarchy holds ('SEC', parent NULL, type NULL) at low privilege versus
    # ('SEC', 'PS1', 1) privileged, and every secondary-site rule gates on a POSITIVELY
    # known site_type = 1 and correctly stays silent. That is the intended behaviour, not
    # a gap: @_Mayyhem 2026-08-01, "Don't infer/create the nodes/relationships we aren't
    # certain about when we can't confirm a site is secondary via LDAP or privileged
    # AdminService/WMI collection" -- while still emitting everything that IS observable,
    # so a low-priv run keeps the SEC site node, ps1-sec as an MSSQL_Server, and its
    # 'SMS Site Server@SEC' role.
    #
    # con-0394 hunts a domain-user-reachable signal that positively identifies a
    # secondary. If it lands, these three entries and their requires_privilege flags all
    # come off together.
    #
    # Their KINDS stay unflagged -- MSSQL_Contains has eight other cases that pass at low
    # privilege, and flagging the kind would wrongly skip those too.
    "edge-contains-servers-sysadmin-role",
    "edge-controlserver-sysadmin-server-instances",
    "node-mssql-database-count",
    # Added 2026-08-01 with the secondary-site work, same root cause as the three above.
    # Microsoft requires the parent primary computer account to hold sysadmin on a
    # secondary site database, so at privileged SEC gains logins for PS1-PSS$ and PS1-PSV$
    # (by role, which is why the passive node is included) and matching database users.
    # None of it can be asserted at low privilege, because SEC must first be CONFIRMED a
    # secondary and nothing reachable by a domain user establishes that.
    #
    # These are deliberately SEPARATE cases pinned by SCCMSite = "SEC" rather than raised
    # counts on the existing same-site cases. Folding them in would have turned four
    # assertions that hold at BOTH privilege levels into admin-only ones, deleting
    # low-privilege coverage of MSSQL_HasLogin, MSSQL_MemberOf and the login/database-user
    # node counts as a side effect of asserting something new.
    "edge-haslogin-parent-primary-secondary-database",
    "edge-memberof-secondary-parent-primary-sysadmin-role",
    "node-mssql-login-secondary-parent-primary",
    "node-mssql-databaseuser-secondary-parent-primary",
}


def test_sccm_admin_edge_cases_flagged_requires_privilege():
    for c in MAYYHEM_EDGE_CASES:
        if c.kind in REQUIRES_SCCM_ADMIN_EDGE_KINDS:
            assert getattr(c, "requires_privilege", False) is True, f"{c.id} must be flagged"


def test_non_sccm_admin_edge_cases_not_flagged():
    for c in MAYYHEM_EDGE_CASES:
        if c.id in PRIVILEGE_BY_ASSERTION_NOT_KIND:
            continue
        if c.kind not in REQUIRES_SCCM_ADMIN_EDGE_KINDS:
            assert getattr(c, "requires_privilege", False) is False, (
                f"{c.id} (kind={c.kind}) unexpectedly flagged requires_privilege"
            )


def test_mssql_tgs_kinds_never_flagged():
    kinds_present = {c.kind for c in MAYYHEM_EDGE_CASES}
    assert NEVER_FLAG_EDGE_KINDS & kinds_present, "fixture drifted: expected TGS cases are gone"
    for c in MAYYHEM_EDGE_CASES:
        if c.kind in NEVER_FLAG_EDGE_KINDS:
            assert getattr(c, "requires_privilege", False) is False, f"{c.id} must NOT be flagged"


def test_sccm_admin_node_cases_flagged_requires_privilege():
    for c in MAYYHEM_NODE_CASES:
        if any(k in REQUIRES_SCCM_ADMIN_NODE_KINDS for k in c.kinds):
            assert getattr(c, "requires_privilege", False) is True, f"{c.id} must be flagged"


def test_non_sccm_admin_node_cases_not_flagged():
    for c in MAYYHEM_NODE_CASES:
        if c.id in PRIVILEGE_BY_ASSERTION_NOT_KIND:
            continue
        if not any(k in REQUIRES_SCCM_ADMIN_NODE_KINDS for k in c.kinds):
            assert getattr(c, "requires_privilege", False) is False, (
                f"{c.id} (kinds={c.kinds}) unexpectedly flagged requires_privilege"
            )


def test_assertion_level_privilege_cases_are_actually_flagged():
    """The escape hatch must not become a way to silently unflag a case.

    Every id listed in PRIVILEGE_BY_ASSERTION_NOT_KIND is exempted from the kind-based
    guard above, so this pins that each one really is flagged and really does exist --
    otherwise a stale entry would quietly widen the exemption to nothing.
    """
    by_id = {c.id: c for c in list(MAYYHEM_EDGE_CASES) + list(MAYYHEM_NODE_CASES)}
    for cid in PRIVILEGE_BY_ASSERTION_NOT_KIND:
        assert cid in by_id, f"{cid} is exempted but no longer exists"
        assert getattr(by_id[cid], "requires_privilege", False) is True, (
            f"{cid} is exempted from the kind guard but is not flagged"
        )


def test_case_types_still_real_edgecase_nodecase():
    # requires_privilege must be additive, not a replacement type -- the shared engine
    # (run_suite, compare_graphs, etc.) type-checks against these base classes.
    assert all(isinstance(c, EdgeCase) for c in MAYYHEM_EDGE_CASES)
    assert all(isinstance(c, NodeCase) for c in MAYYHEM_NODE_CASES)


def test_low_priv_subset_excludes_all_sccm_admin_cases():
    # The actual partition a low-priv run would apply: filter out requires_privilege
    # cases and confirm none of the SCCM-admin-only kinds survive.
    low_priv_edges = [c for c in MAYYHEM_EDGE_CASES if not getattr(c, "requires_privilege", False)]
    low_priv_nodes = [c for c in MAYYHEM_NODE_CASES if not getattr(c, "requires_privilege", False)]
    assert not ({c.kind for c in low_priv_edges} & REQUIRES_SCCM_ADMIN_EDGE_KINDS)
    assert not any(k in REQUIRES_SCCM_ADMIN_NODE_KINDS for c in low_priv_nodes for k in c.kinds)
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
