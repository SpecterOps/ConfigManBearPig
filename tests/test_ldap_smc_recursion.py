"""Tests for recursive GenericAll group expansion on the System Management
container (ope-e191).

``ldap_system_management_dacl`` finds AD principals with GenericAll on
``CN=System Management,CN=System,<base_dn>``. When a holder is a group, its
members effectively inherit Full Control and must be discovered too:
computer members become scan targets, nested groups recurse, user members
are only logged, and circular nesting must terminate rather than hang.

Fakes model only what ``ldap_system_management_dacl`` /
``_expand_group_targets`` actually touch:
- ``_FakeAD.paged_search`` routes on ``search_filter``/``base`` — the
  container's own SD lookup (filter ``(objectClass=container)``) versus a
  BASE-scope ``member`` fetch on a specific group DN (mirrors
  ``context.py``'s ``_ldap_resolve_dn`` pattern).
- ``_FakeCtx.resolve_principal`` is a plain dict lookup keyed by whatever
  string is passed in — a SID for the top-level GenericAll holder, or a
  member DN when resolving group members. Real AD returns the member
  attribute holding literal DNs (confirmed against ``context.py:184-190``,
  which resolves DNs directly via BASE scope), so this fake's ``principals``
  dict is deliberately keyed by DN strings for member lookups — the
  ``member`` attribute key itself only ever appears as a dict key on the
  fake group's paged_search result (``{"member": [...]}``), never as an
  object attribute name.
- ``_FakeCtx.register_target`` records a lightweight stand-in (not the real
  ``TargetEntry``) exposing only ``.identifier`` — the one attribute these
  tests read.
"""
import pytest

from openhound_sccm.collectors import ldap as ldap_mod
from openhound_sccm.collectors.ldap import ldap_system_management_dacl


class _RegisteredTarget:
    """Minimal recording stand-in for register_target's return value."""

    def __init__(self, identifier, source, ad_object=None):
        self.identifier = identifier
        self.source = source
        self.ad_object = ad_object


class _FakeAD:
    """Fake ADClient. Routes paged_search by search_filter/base:

    - The container's own SD query (``search_filter="(objectClass=container)"``)
      always succeeds with a dummy (but valid ``bytes``) security descriptor —
      the real parsing is bypassed via a monkeypatched ``_parse_sd_generic_all``.
    - A BASE-scope ``member`` fetch on a known group DN returns that group's
      fake ``{"member": [...]}`` (or range-limited) row from ``group_members``.
    - Anything else returns no results.
    """

    base_dn = "DC=mayyhem,DC=com"

    def __init__(self, group_members=None):
        self._group_members = group_members or {}

    def paged_search(self, search_filter, attributes=None, base=None, scope=None, controls=None, size_limit=0):
        # A generator, like the real AdClient.paged_search — _expand_group_targets
        # calls next() directly on the result, which requires a true iterator
        # (a plain list/tuple has no __next__ and raises TypeError).
        if search_filter == "(objectClass=container)":
            yield {"nTSecurityDescriptor": b"\x00" * 20}
        elif base in self._group_members:
            yield self._group_members[base]


class _FakeCtx:
    """Fake SourceContext exposing only what ldap_system_management_dacl and
    _expand_group_targets touch: ``ad``, ``method_enabled``,
    ``resolve_principal``, ``register_target``."""

    def __init__(self, ad, principals, generic_all_sids):
        self.ad = ad
        self._principals = principals
        self._generic_all_sids = generic_all_sids
        self.registered: list[_RegisteredTarget] = []

    def method_enabled(self, name):
        return True

    def resolve_principal(self, identifier):
        return self._principals.get(identifier)

    def register_target(self, identifier, source=None, site_code=None, ad_object=None):
        entry = _RegisteredTarget(identifier, source, ad_object)
        self.registered.append(entry)
        return entry


def _patch_parser(monkeypatch, ctx):
    """Bypass real SD-byte parsing — the parser's GenericAll-only detection
    is out of scope for this task, so just hand back the holder SID(s)."""
    monkeypatch.setattr(ldap_mod, "_parse_sd_generic_all", lambda sd_bytes: ctx._generic_all_sids)


def _obj(object_class, **fields):
    return {"object_class": [object_class], **fields}


def test_generic_all_group_expands_members_recursively(fake_ctx_smc_group):
    # group G1 (GenericAll) -> {computerA, group G2}; G2 -> {computerB, userC}
    ctx = fake_ctx_smc_group()
    list(ldap_system_management_dacl(ctx))
    assert {t.identifier for t in ctx.registered} == {"computerA.dns", "computerB.dns"}


def test_circular_group_nesting_terminates(fake_ctx_smc_cyclic):
    # G1 -> G2 -> G1 ; must return, not hang
    list(ldap_system_management_dacl(fake_ctx_smc_cyclic()))


def test_direct_computer_holder_unchanged(fake_ctx_smc_computer):
    ctx = fake_ctx_smc_computer()
    list(ldap_system_management_dacl(ctx))
    assert [t.identifier for t in ctx.registered] == ["directComputer.dns"]


def test_auto_range_full_membership_processed_no_warning(fake_ctx_smc_full_membership, caplog):
    # ldap3's auto_range (default True in the shared client) already merged every
    # member;range= page under the plain "member" key before this code runs -- the
    # normal-huge-group case. No "member;range=" key survives, so no warning should fire.
    import logging
    caplog.set_level(logging.WARNING)
    ctx = fake_ctx_smc_full_membership()
    list(ldap_system_management_dacl(ctx))
    assert {t.identifier for t in ctx.registered} == {"computerA.dns"}
    assert not any("range" in r.getMessage().lower() for r in caplog.records)


def test_residual_range_key_warns(fake_ctx_smc_residual_range, caplog):
    # A "member;range=" key surviving to this code means ldap3's auto_range did NOT
    # complete for this group (a rare failure, not normal huge-group behavior) -> must WARN.
    import logging
    caplog.set_level(logging.WARNING)
    ctx = fake_ctx_smc_residual_range()
    list(ldap_system_management_dacl(ctx))
    assert any("auto_range did not complete" in r.getMessage() for r in caplog.records)


# --- fixtures -----------------------------------------------------------


@pytest.fixture
def fake_ctx_smc_group(monkeypatch):
    g1_dn = "CN=G1,CN=Users,DC=mayyhem,DC=com"
    g2_dn = "CN=G2,CN=Users,DC=mayyhem,DC=com"
    computer_a_dn = "CN=computerA,CN=Computers,DC=mayyhem,DC=com"
    computer_b_dn = "CN=computerB,CN=Computers,DC=mayyhem,DC=com"
    user_c_dn = "CN=userC,CN=Users,DC=mayyhem,DC=com"

    g1_sid = "S-1-5-21-1-1-1-1101"
    g1_obj = _obj("group", object_sid=g1_sid, distinguished_name=g1_dn, sam_account_name="G1")
    g2_obj = _obj("group", object_sid="S-1-5-21-1-1-1-1102", distinguished_name=g2_dn, sam_account_name="G2")
    computer_a_obj = _obj("computer", dns_host_name="computerA.dns", distinguished_name=computer_a_dn)
    computer_b_obj = _obj("computer", dns_host_name="computerB.dns", distinguished_name=computer_b_dn)
    user_c_obj = _obj("user", sam_account_name="userC", distinguished_name=user_c_dn)

    principals = {
        g1_sid: g1_obj,
        computer_a_dn: computer_a_obj,
        g2_dn: g2_obj,
        computer_b_dn: computer_b_obj,
        user_c_dn: user_c_obj,
    }
    group_members = {
        g1_dn: {"member": [computer_a_dn, g2_dn]},
        g2_dn: {"member": [computer_b_dn, user_c_dn]},
    }

    def _build():
        ad = _FakeAD(group_members)
        ctx = _FakeCtx(ad, principals, [g1_sid])
        _patch_parser(monkeypatch, ctx)
        return ctx

    return _build


@pytest.fixture
def fake_ctx_smc_cyclic(monkeypatch):
    g1_dn = "CN=G1,CN=Users,DC=mayyhem,DC=com"
    g2_dn = "CN=G2,CN=Users,DC=mayyhem,DC=com"
    g1_sid = "S-1-5-21-2-2-2-1101"
    g2_sid = "S-1-5-21-2-2-2-1102"
    g1_obj = _obj("group", object_sid=g1_sid, distinguished_name=g1_dn, sam_account_name="G1")
    g2_obj = _obj("group", object_sid=g2_sid, distinguished_name=g2_dn, sam_account_name="G2")

    # G1 is resolved twice: once as the top-level SID holder, once as a
    # member DN when G2 loops back to it — both keys map to the same object.
    principals = {
        g1_sid: g1_obj,
        g1_dn: g1_obj,
        g2_dn: g2_obj,
    }
    group_members = {
        g1_dn: {"member": [g2_dn]},
        g2_dn: {"member": [g1_dn]},
    }

    def _build():
        ad = _FakeAD(group_members)
        ctx = _FakeCtx(ad, principals, [g1_sid])
        _patch_parser(monkeypatch, ctx)
        return ctx

    return _build


@pytest.fixture
def fake_ctx_smc_computer(monkeypatch):
    computer_dn = "CN=directComputer,CN=Computers,DC=mayyhem,DC=com"
    computer_sid = "S-1-5-21-3-3-3-1101"
    computer_obj = _obj("computer", object_sid=computer_sid, dns_host_name="directComputer.dns",
                        distinguished_name=computer_dn)
    principals = {computer_sid: computer_obj}

    def _build():
        ad = _FakeAD()  # no group_members needed — direct computer holder, no expansion
        ctx = _FakeCtx(ad, principals, [computer_sid])
        _patch_parser(monkeypatch, ctx)
        return ctx

    return _build


@pytest.fixture
def fake_ctx_smc_full_membership(monkeypatch):
    g1_dn = "CN=G1,CN=Users,DC=mayyhem,DC=com"
    computer_a_dn = "CN=computerA,CN=Computers,DC=mayyhem,DC=com"
    user_b_dn = "CN=userB,CN=Users,DC=mayyhem,DC=com"
    g1_sid = "S-1-5-21-5-5-5-1101"
    g1_obj = _obj("group", object_sid=g1_sid, distinguished_name=g1_dn, sam_account_name="G1")
    computer_a_obj = _obj("computer", dns_host_name="computerA.dns", distinguished_name=computer_a_dn)
    user_b_obj = _obj("user", sam_account_name="userB", distinguished_name=user_b_dn)
    principals = {
        g1_sid: g1_obj,
        computer_a_dn: computer_a_obj,
        user_b_dn: user_b_obj,
    }
    # A normal huge group: ldap3's auto_range already merged every range page under the
    # plain "member" key by the time this code sees the entry -- no ";range=" key at all.
    group_members = {
        g1_dn: {"member": [computer_a_dn, user_b_dn]},
    }

    def _build():
        ad = _FakeAD(group_members)
        ctx = _FakeCtx(ad, principals, [g1_sid])
        _patch_parser(monkeypatch, ctx)
        return ctx

    return _build


@pytest.fixture
def fake_ctx_smc_residual_range(monkeypatch):
    g1_dn = "CN=G1,CN=Users,DC=mayyhem,DC=com"
    g1_sid = "S-1-5-21-4-4-4-1101"
    g1_obj = _obj("group", object_sid=g1_sid, distinguished_name=g1_dn, sam_account_name="G1")
    principals = {g1_sid: g1_obj}
    # A residual "member;range=" key only appears when ldap3's auto_range (default True in
    # the shared client) failed to complete paging for this group -- a rare failure mode,
    # not the normal huge-group response. Its contents are irrelevant since the collector
    # no longer reassembles range pages itself; only the key's presence matters.
    group_members = {
        g1_dn: {"member;range=0-1499": []},
    }

    def _build():
        ad = _FakeAD(group_members)
        ctx = _FakeCtx(ad, principals, [g1_sid])
        _patch_parser(monkeypatch, ctx)
        return ctx

    return _build
