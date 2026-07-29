"""Tests for the RemoteRegistry collector's pure helpers."""
from openhound_sccm.collectors.registry import _roles


def test_roles_suffixes_site_code_and_returns_list():
    """A single role still comes back as a LIST, suffixed @<site_code>."""
    assert _roles(["SMS Site Server"], "PS1") == ["SMS Site Server@PS1"]


def test_roles_without_site_code_omits_suffix():
    assert _roles(["SMS Component Server"], None) == ["SMS Component Server"]


def test_roles_multiple_bases_all_suffixed():
    assert _roles(["SMS SQL Server", "SMS Site Server"], "CAS") == [
        "SMS SQL Server@CAS",
        "SMS Site Server@CAS",
    ]
