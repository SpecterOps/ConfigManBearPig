# tests/mssql_spn_service_account_test.py
"""D2(a) holds when SQL runs as a DOMAIN SERVICE ACCOUNT.

The host part of ``MSSQLSvc/<host>:<port>`` names the machine running SQL Server
regardless of which principal holds the SPN. When SQL runs as a domain service
account -- Microsoft's recommended configuration, and the usual one for an SCCM
site database -- the SPN lives on a *user* object and the target computer object
has none, so reading the computer's own servicePrincipalName finds nothing.

These pin that the collector searches for the SPN itself in that case, so the host
still reaches the graph.
"""
import pytest

from openhound_sccm.clients.ad import ADClient


class _FakeAD:
    """Minimal ADClient stand-in: records the filters it was asked for."""

    def __init__(self, entries):
        self._entries = entries
        self.filters = []

    def paged_search(self, search_filter, attributes=None, **kw):
        self.filters.append(search_filter)
        return iter(self._entries)


def _find(entries, host):
    ad = _FakeAD(entries)
    # Bind the real method to the fake so we exercise the production logic.
    return ADClient.find_mssql_spns(ad, host), ad


def test_finds_spn_held_by_a_service_account():
    # The SPN is on sqlsccmsvc (a user), not on the ps1-db computer object.
    found, ad = _find(
        [{"service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com:1433"]}],
        "ps1-db.mayyhem.com",
    )
    assert found == ["MSSQLSvc/ps1-db.mayyhem.com:1433"]
    # Must search BY SPN, not by the computer's dNSHostName.
    assert ad.filters == ["(servicePrincipalName=MSSQLSvc/ps1-db.mayyhem.com*)"]


def test_trailing_wildcard_cannot_match_a_longer_hostname():
    # '(servicePrincipalName=MSSQLSvc/ps1-db.mayyhem.com*)' also matches
    # ps1-db.mayyhem.com.evil.tld; the host part must be pinned exactly.
    found, _ = _find(
        [{"service_principal_name": [
            "MSSQLSvc/ps1-db.mayyhem.com.evil.tld:1433",
            "MSSQLSvc/ps1-db.mayyhem.com:1433",
        ]}],
        "ps1-db.mayyhem.com",
    )
    assert found == ["MSSQLSvc/ps1-db.mayyhem.com:1433"]


def test_named_instance_form_matches():
    found, _ = _find(
        [{"service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com\\CMSQL"]}],
        "ps1-db.mayyhem.com",
    )
    assert found == ["MSSQLSvc/ps1-db.mayyhem.com\\CMSQL"]


def test_case_insensitive_both_ways():
    # SPNs are case-insensitive identifiers; `setspn -A mssqlsvc/...` is valid.
    found, _ = _find(
        [{"service_principal_name": ["mssqlsvc/PS1-DB.MAYYHEM.COM:1433"]}],
        "ps1-db.mayyhem.com",
    )
    assert found == ["mssqlsvc/PS1-DB.MAYYHEM.COM:1433"]


def test_non_mssql_spns_are_ignored():
    found, _ = _find(
        [{"service_principal_name": ["HOST/ps1-db.mayyhem.com", "CmRcService/ps1-db.mayyhem.com"]}],
        "ps1-db.mayyhem.com",
    )
    assert found == []


def test_single_string_value_not_a_list():
    # ldap3 returns a bare string when the attribute has exactly one value.
    found, _ = _find(
        [{"service_principal_name": "MSSQLSvc/ps1-db.mayyhem.com:1433"}],
        "ps1-db.mayyhem.com",
    )
    assert found == ["MSSQLSvc/ps1-db.mayyhem.com:1433"]


def test_empty_hostname_does_not_wildcard_the_forest():
    ad = _FakeAD([{"service_principal_name": ["MSSQLSvc/anything:1433"]}])
    assert ADClient.find_mssql_spns(ad, "") == []
    assert ad.filters == []          # no query issued at all


def test_search_failure_is_not_fatal():
    class _Boom:
        def paged_search(self, **kw):
            raise RuntimeError("LDAP down")

        def paged_search_positional(self, *a, **kw):  # pragma: no cover
            raise RuntimeError("LDAP down")

    class _BoomAD:
        def paged_search(self, search_filter, attributes=None, **kw):
            raise RuntimeError("LDAP down")

    assert ADClient.find_mssql_spns(_BoomAD(), "ps1-db.mayyhem.com") == []


@pytest.mark.parametrize("host", ["ps1-db.mayyhem.com", "PS1-DB.mayyhem.com"])
def test_caller_hostname_casing_does_not_matter(host):
    found, _ = _find(
        [{"service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com:1433"]}], host
    )
    assert found == ["MSSQLSvc/ps1-db.mayyhem.com:1433"]


# Account lookups preserve each registration's owner instead of choosing one.


def _find_holders(entries, host):
    ad = _FakeAD(entries)
    return ADClient.find_mssql_spn_holders(ad, host), ad


def test_holder_identity_is_resolved():
    holders, ad = _find_holders([{
        "service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com:1433"],
        "object_sid": "S-1-5-21-1-2-3-1105",
        "sam_account_name": "sqlsvc",
        "object_class": ["user"],
    }], "ps1-db.mayyhem.com")
    assert holders == [{
        "spns": ["MSSQLSvc/ps1-db.mayyhem.com:1433"],
        "object_sid": "S-1-5-21-1-2-3-1105",
        "sam_account_name": "sqlsvc", "object_class": ["user"],
    }]
    assert ad.filters == ["(servicePrincipalName=MSSQLSvc/ps1-db.mayyhem.com*)"]


def test_no_holders_when_no_spn_matches():
    holders, _ = _find_holders([], "ps1-db.mayyhem.com")
    assert holders == []


def test_holder_flags_a_computer_object():
    holders, _ = _find_holders([{
        "service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com:1433"],
        "object_sid": "S-1-5-21-1-2-3-1104", "sam_account_name": "PS1-DB$",
        "object_class": ["user", "computer"],
    }], "ps1-db.mayyhem.com")
    assert "computer" in holders[0]["object_class"]


def test_holders_ignore_spns_not_naming_this_host():
    holders, _ = _find_holders([{
        "service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com.evil.tld:1433"],
        "object_sid": "S-1-5-21-1-2-3-1105",
    }], "ps1-db.mayyhem.com")
    assert holders == []


def test_multiple_holders_keep_their_own_registrations():
    holders, _ = _find_holders([
        {"service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com:1433"], "object_sid": "S-1"},
        {"service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com:51433"], "object_sid": "S-2"},
    ], "ps1-db.mayyhem.com")
    assert [(holder["object_sid"], holder["spns"]) for holder in holders] == [
        ("S-1", ["MSSQLSvc/ps1-db.mayyhem.com:1433"]),
        ("S-2", ["MSSQLSvc/ps1-db.mayyhem.com:51433"]),
    ]


def test_holder_empty_hostname_does_not_wildcard_the_forest():
    ad = _FakeAD([{"service_principal_name": ["MSSQLSvc/anything:1433"]}])
    assert ADClient.find_mssql_spn_holders(ad, "") == []
    assert ad.filters == []


def test_holder_search_failure_is_not_fatal():
    class BoomAD:
        def paged_search(self, search_filter, attributes=None, **kwargs):
            raise RuntimeError("LDAP down")

    assert ADClient.find_mssql_spn_holders(BoomAD(), "ps1-db.mayyhem.com") == []


# --- production key-shape regression (found 2026-07-28) --------------------------
# paged_search yields _entry_to_dict output, which lowercases the LDAP attribute name
# and maps it via _ATTR_KEY_MAP: 'servicePrincipalName' -> 'service_principal_name'.
# Every fake above now uses that production shape. These two pin the contract from both
# sides so a future fake using the wrong casing cannot re-hide the bug: reading only
# camelCase made find_mssql_spns AND the long-standing get_spns return nothing for every
# real host, while passing a camelCase-fake test suite.

def test_reads_the_snake_case_key_production_actually_yields():
    found, _ = _find(
        [{"service_principal_name": ["MSSQLSvc/ps1-db.mayyhem.com:1433"]}],
        "ps1-db.mayyhem.com",
    )
    assert found == ["MSSQLSvc/ps1-db.mayyhem.com:1433"]


def test_camelcase_still_accepted_as_a_fallback():
    # Kept working for any raw/unmapped caller, but it is NOT the production shape.
    found, _ = _find(
        [{"servicePrincipalName": ["MSSQLSvc/ps1-db.mayyhem.com:1433"]}],
        "ps1-db.mayyhem.com",
    )
    assert found == ["MSSQLSvc/ps1-db.mayyhem.com:1433"]


def test_attr_key_map_still_maps_spn_to_snake_case():
    """If this mapping ever changes, the readers above must change with it."""
    assert ADClient._ATTR_KEY_MAP["serviceprincipalname"] == "service_principal_name"
