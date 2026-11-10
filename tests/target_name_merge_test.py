"""A computer the directory cannot confirm is visited once, by its full name.

A lab run on October 30, 2026 visited ps1-mp twice, as "ps1-mp" and as
"ps1-mp.mayyhem.com", because directory lookups were failing and only a
directory ID merged the two names. Each visit signed in separately. The owner's
rule: never visit a computer by its short name when its full name works.
DNS answers are fixed per test; nothing here touches the network.
"""

from __future__ import annotations

import pytest

from openhound_sccm.context import SourceContext


class FakeWorkQueue:
    def __init__(self):
        self.submitted: list[str] = []

    def submit(self, target):
        self.submitted.append(target)
        return True


def unresolved_context(monkeypatch, in_dns=(), domain="mayyhem.com"):
    """A run whose directory lookups fail and whose DNS knows only *in_dns*."""
    queue = FakeWorkQueue()
    ctx = SourceContext(ad=None, domain=domain, work_queue=queue)
    looked_up: list[str] = []

    def resolve_ip(name):
        looked_up.append(name)
        return "10.10.11.55" if name.lower() in in_dns else None

    monkeypatch.setattr(ctx, "resolve_principal", lambda identifier: None)
    monkeypatch.setattr(ctx, "resolve_ip", resolve_ip)
    return ctx, queue, looked_up


def test_short_name_first_is_visited_once_by_its_full_name(monkeypatch):
    ctx, queue, _ = unresolved_context(monkeypatch, in_dns={"ps1-mp.mayyhem.com"})
    first = ctx.register_target("ps1-mp", source="Local")
    second = ctx.register_target("ps1-mp.mayyhem.com", source="CLI")
    assert second is first
    assert queue.submitted == ["ps1-mp.mayyhem.com"]
    assert first.hostname == "ps1-mp.mayyhem.com"
    assert first.sources == ["Local", "CLI"]


def test_full_name_first_absorbs_a_later_short_name_without_a_lookup(monkeypatch):
    ctx, queue, looked_up = unresolved_context(monkeypatch)
    first = ctx.register_target("ps1-mp.mayyhem.com", source="CLI")
    second = ctx.register_target("PS1-MP", source="Local")
    assert second is first
    assert queue.submitted == ["ps1-mp.mayyhem.com"]
    assert looked_up == []  # The registered full name settled it.
    assert ctx.target_hosts_by_hostname["ps1-mp"] is first


@pytest.mark.parametrize("in_dns", [{"ps1-mp"}, set()])
def test_short_name_is_kept_when_its_full_name_is_not_in_dns(monkeypatch, in_dns):
    # For example, a computer in another domain that the short name still reaches.
    # A full name that is not in DNS could not be visited anyway.
    ctx, queue, looked_up = unresolved_context(monkeypatch, in_dns=in_dns)
    ctx.register_target("ps1-mp", source="Local")
    assert queue.submitted == ["ps1-mp"]
    assert looked_up == ["ps1-mp.mayyhem.com"]  # One lookup, for the full name only.


def test_without_a_domain_the_short_name_stays(monkeypatch):
    ctx, queue, looked_up = unresolved_context(monkeypatch, domain="")
    ctx.register_target("ps1-mp", source="Local")
    assert queue.submitted == ["ps1-mp"]
    assert looked_up == []


def test_a_short_name_matching_two_full_names_uses_the_runs_domain(monkeypatch):
    ctx, queue, _ = unresolved_context(monkeypatch, in_dns={"sql.mayyhem.com"})
    ours = ctx.register_target("sql.mayyhem.com", source="CLI")
    ctx.register_target("sql.child.mayyhem.com", source="CLI")
    assert ctx.register_target("sql", source="Local") is ours
    assert queue.submitted == ["sql.mayyhem.com", "sql.child.mayyhem.com"]


@pytest.mark.parametrize(
    "identifier",
    ["S-1-5-21-1004336348-1177238915-682003330-1105", "MAYYHEM\\ps1-mp", "10.10.11.55"],
)
def test_other_identifier_forms_are_never_given_a_domain(monkeypatch, identifier):
    ctx, queue, looked_up = unresolved_context(monkeypatch)
    ctx.register_target(identifier, source="Local")
    assert queue.submitted == [identifier]
    assert looked_up == []
