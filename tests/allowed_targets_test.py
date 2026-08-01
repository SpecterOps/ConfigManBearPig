"""Tests for allow-list (Test-AllowedTarget) construction in source.py.

The allow-list must be **lowercased**: ``SourceContext._is_allowed_target``
compares lowercased candidate names against ``allowed_targets``, so any entry
that keeps its original casing can never match. Both ``--computers`` and
``--computer-file`` feed the same expansion, so both must lowercase and both
must add the short-name form (the text before the first dot).
"""
from openhound_sccm.context import SourceContext
from openhound_sccm.source import _expand_allowed_targets


def test_expand_lowercases_and_adds_short_name():
    """An uppercase FQDN yields its lowercased FQDN and short-name forms."""
    assert _expand_allowed_targets(["PS1-PSS.MAYYHEM.COM"]) == {
        "ps1-pss.mayyhem.com",
        "ps1-pss",
    }


def test_expand_strips_and_skips_blanks():
    """Blank/whitespace entries are dropped; surrounding whitespace is stripped."""
    assert _expand_allowed_targets(["  ", "Host2 ", ""]) == {"host2"}


def test_uppercase_computer_allows_lowercased_target():
    """Regression: an uppercase --computers value must still match a host that is
    later presented in lowercase (the casing-mismatch bug).
    """
    allowed = frozenset(_expand_allowed_targets(["PS1-PSS.MAYYHEM.COM"]))
    ctx = SourceContext(ad=None, domain="mayyhem.com", allowed_targets=allowed)
    assert ctx._is_allowed_target("ps1-pss.mayyhem.com", None) is True
    assert ctx._is_allowed_target("ps1-pss", None) is True
