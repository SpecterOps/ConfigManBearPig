"""mayyhem.com lab node fixtures + whole-graph invariants.

Anchor counts come from the validated mayyhem.com parity run (2026-07-22, 239 total nodes,
sccm/tests/live-comparison/rename_check/). `exact` is used only for structurally-fixed kinds
(site count, MSSQL server count) that cannot change without rebuilding the lab; `at_least` is
used everywhere else so the lab can grow (more client devices, collections, roles, etc.)
without breaking these fixtures.
"""
from __future__ import annotations

import re
from typing import Callable

from openhound_collector_common.integration_testing.cases import CountSpec, NodeCase
from openhound_collector_common.integration_testing.graph import Graph
from openhound_collector_common.integration_testing.results import FAIL, PASS, Result

from openhound_sccm.integration.fixtures import SCCMNodeCase

ROOT_SITE = "CAS"

MAYYHEM_NODE_CASES: list[NodeCase] = [

    ################
    # SCCM_Site    #
    ################
    NodeCase(id="node-site-count", description="Exactly 3 SCCM sites (CAS + PS1 + secondary)",
             kinds=["SCCM_Site"], count=CountSpec(exact=3)),
    NodeCase(id="node-site-has-sitecode", description="Every SCCM_Site carries a siteCode",
             kinds=["SCCM_Site"], properties={"siteCode": "*"}, count=CountSpec(at_least=3)),

    ######################
    # SCCM_ClientDevice  #
    ######################
    # at_least 13, not 19: device-derived, so it must survive the lab gaining or
    # losing a VM. A low-privilege run legitimately sees fewer than a privileged
    # one (14 vs 19 measured 2026-07-31), and this case is not privilege-gated.
    NodeCase(id="node-clientdevice-count", description="At least 13 SCCM client devices across the hierarchy",
             kinds=["SCCM_ClientDevice"], count=CountSpec(at_least=13)),
    # con-5e71: keeps the confirmed-vs-possible distinction covered.
    #
    # Three SameHostAs/HasClient cases used to pin their ClientDevice endpoint with
    # id="GUID:*". That looked like it asserted the relationship; it actually asserted
    # the PRIVILEGE LEVEL, because only a confirmed (enrolled, AdminService-seen) device
    # gets an SMS-GUID id -- an SPN-inferred possible client is keyed "<sid>@<site>".
    # The devices and edges are produced at low privilege too, so those cases now pin by
    # name and this case carries the id-form assertion on its own, where it belongs.
    # requires_privilege because the GUID form only exists in a privileged collection
    # (mayyhem: 19 GUID-form privileged, 0 unprivileged).
    SCCMNodeCase(id="node-clientdevice-confirmed-has-guid-id",
                 description="Confirmed (enrolled) client devices are keyed by their SMS GUID",
                 kinds=["SCCM_ClientDevice"], properties={"id": "GUID:*"},
                 count=CountSpec(at_least=1), requires_privilege=True),

    ###################
    # SCCM_Collection #
    ###################
    # Requires SCCM admin (design spec S:5): collections have no AD/LDAP/RemoteRegistry
    # representation, so this count can only be checked against a privileged
    # (AdminService/WMI) collection.
    SCCMNodeCase(id="node-collection-count", description="At least 10 SCCM collections across the hierarchy",
                 kinds=["SCCM_Collection"], count=CountSpec(at_least=10), requires_privilege=True),

    #################
    # SCCM_AdminUser #
    #################
    # Requires SCCM admin: SCCM admin-user objects live in the site database's RBAC tables only.
    SCCMNodeCase(id="node-adminuser-count", description="At least 3 SCCM admin users across the hierarchy",
                 kinds=["SCCM_AdminUser"], count=CountSpec(at_least=3), requires_privilege=True),

    #####################
    # SCCM_SecurityRole #
    #####################
    # Requires SCCM admin: security roles are likewise site-database RBAC objects.
    SCCMNodeCase(id="node-securityrole-count", description="At least 17 SCCM security roles across the hierarchy",
                 kinds=["SCCM_SecurityRole"], count=CountSpec(at_least=17), requires_privilege=True),

    ################################################
    # MSSQL_ node kinds (bonus coverage, not SCCM) #
    ################################################
    # PS1-PSV was named here in error: the passive site server runs no SQL. The
    # third server is PS1-SEC, which hosts the SEC secondary's own site database.
    NodeCase(id="node-mssql-server-count", description="3 MSSQL servers discovered (CAS-DB, PS1-DB, PS1-SEC)",
             kinds=["MSSQL_Server"], count=CountSpec(exact=3)),
    # One CM_<SiteCode> per site that has its own site database -- in mayyhem that
    # is two primary sites plus the SEC secondary, which carries its own.
    # Requires SCCM admin: only 2 of the 3 site databases are characterized without it.
    # NOT because ps1-sec is "correctly a plain MSSQL_Server" at low privilege, as an
    # earlier revision of this comment said -- it IS SEC's site database, since Microsoft
    # requires a secondary's database to run ON the secondary site server. Low privilege
    # simply cannot PROVE SEC is a secondary (site_type stays NULL), and the
    # secondary-site rules correctly decline to fire on an unconfirmed type, so CM_SEC
    # does not materialise there. con-0394 tracks a domain-user-reachable positive signal.
    SCCMNodeCase(id="node-mssql-database-count", description="At least 3 MSSQL databases (one CM_<SiteCode> per site with its own site database: two primary sites plus the SEC secondary)",
                 kinds=["MSSQL_Database"], count=CountSpec(at_least=3), requires_privilege=True),
    # These two stay at the SAME-SITE baseline (a Site Server or SMS Provider is sysadmin
    # on its OWN site's database), which holds at BOTH privilege levels, so they keep
    # asserting something in a low-priv run. The cross-site secondary logins are asserted
    # separately by the two cases below, which are flagged because they need SEC
    # characterized as a site database.
    NodeCase(id="node-mssql-login-count", description="At least 4 MSSQL logins (site server/provider machine accounts)",
             kinds=["MSSQL_Login"], count=CountSpec(at_least=4)),
    NodeCase(id="node-mssql-databaseuser-count", description="At least 4 MSSQL database users mapped from those logins",
             kinds=["MSSQL_DatabaseUser"], count=CountSpec(at_least=4)),
    # Microsoft requires the parent primary computer account to hold sysadmin on a
    # secondary site database, and matching the parent BY ROLE picks up the passive node
    # too -- so PS1-PSS$ and PS1-PSV$ each gain a login on SEC's database, and neither the
    # same-site rule nor PS1-SEC$ itself contributes one. Pinned by SCCMSite rather than by
    # a hard-coded host SID. Requires SCCM admin only because SEC must first be CONFIRMED
    # a secondary (see the PRIVILEGE_BY_ASSERTION_NOT_KIND block in
    # tests/integration_lowpriv_fixtures_test.py and con-0394).
    SCCMNodeCase(id="node-mssql-login-secondary-parent-primary",
                 description="Exactly 2 MSSQL logins on the SEC secondary site database, both PS1 parent primary site servers (PS1-PSS$, PS1-PSV$) -- and none for PS1-SEC$ itself",
                 kinds=["MSSQL_Login"], properties={"SCCMSite": "SEC"},
                 count=CountSpec(exact=2), requires_privilege=True),
    SCCMNodeCase(id="node-mssql-databaseuser-secondary-parent-primary",
                 description="Those 2 SEC logins are mapped to database users in the SEC secondary site database",
                 kinds=["MSSQL_DatabaseUser"], properties={"SCCMSite": "SEC"},
                 count=CountSpec(exact=2), requires_privilege=True),
]


# AdminUser / SecurityRole / Collection are the node kinds the collector canonicalizes
# to the hierarchy ROOT site code: their node ids end "@<root>" (e.g. "SMS0002R@CAS")
# so a principal/role/collection replicated across sites collapses to ONE node instead
# of duplicating per site. ClientDevice is deliberately NOT here — devices belong to a
# PRIMARY site under the CAS (checked separately below). Member LISTS are not blanket
# root-checked here: SCCM_Collection.members legitimately reference PRIMARY-scoped device
# resource ids (e.g. "16777238@PS1"), so only the node ids of these three kinds are checked.
_ROOT_NORMALIZED_KINDS = ("SCCM_AdminUser", "SCCM_SecurityRole", "SCCM_Collection")
_SITE_SUFFIX = re.compile(r"@([A-Za-z0-9]{3})$")


def _root_site_normalization_invariant(graph: Graph) -> Result:
    """AdminUser / SecurityRole / Collection node ids must be canonicalized to the
    hierarchy ROOT site code (@CAS). A child-site suffix (e.g. @PS1) means a cross-site
    duplicate was not collapsed to the root, producing duplicate nodes / dangling
    references on the graph."""
    cid = "node-root-site-normalization"
    desc = "AdminUser/SecurityRole/Collection node ids use the root site code"
    bad: list[str] = []
    for node in graph.nodes:
        if not any(k in node.kinds for k in _ROOT_NORMALIZED_KINDS):
            continue
        m = _SITE_SUFFIX.search(node.id)
        if m and m.group(1) != ROOT_SITE:
            bad.append(node.id)
    if bad:
        return Result(cid, "invariant", desc, FAIL,
                      f"{len(bad)} non-root node id(s) e.g. {bad[0]}", len(bad))
    return Result(cid, "invariant", desc, PASS)


def _clientdevice_primary_site_invariant(graph: Graph) -> Result:
    """SCCM_ClientDevice nodes belong to a PRIMARY site under the CAS, never the root.
    If the hierarchy has at least one Primary site, every client device's siteCode must
    be one of those primary codes (guards the ope-e739 regression where inferred devices
    were wrongly attached to the CAS). If there is no primary site, there is nothing to
    check, so it passes."""
    cid = "node-clientdevice-primary-site"
    desc = "SCCM_ClientDevice belongs to a primary site (not the root)"
    primary_codes = {
        (n.properties.get("siteCode") or n.id)
        for n in graph.nodes
        if "SCCM_Site" in n.kinds and n.properties.get("siteType") == "Primary Site"
    }
    if not primary_codes:
        return Result(cid, "invariant", desc, PASS, "no primary site in hierarchy; skipped")
    bad: list[str] = []
    for node in graph.nodes:
        if "SCCM_ClientDevice" not in node.kinds:
            continue
        site_code = node.properties.get("siteCode")
        if site_code not in primary_codes:
            bad.append(f"{node.id} (siteCode={site_code})")
    if bad:
        return Result(cid, "invariant", desc, FAIL,
                      f"{len(bad)} device(s) not under a primary e.g. {bad[0]}", len(bad))
    return Result(cid, "invariant", desc, PASS)


MAYYHEM_INVARIANTS: list[Callable[[Graph], Result]] = [
    _root_site_normalization_invariant,
    _clientdevice_primary_site_invariant,
]
