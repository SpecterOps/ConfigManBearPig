"""Regression guard for the per-host phase stream declarations.

A forgotten comma between two string literals in a phase's stream tuple silently
concatenates them into one bogus table name (Python implicit string concatenation),
with no syntax or import error. That is exactly how `adminservice_user_group` got
swallowed into `adminservice_user_groupadminservice_collections` — undetected until a
live collect tried to `streams[...].put(row)` and hit a KeyError, and it also quietly
broke group collection (no SMS_R_UserGroup rows -> empty node_group).
"""
from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names

_ADMIN = "adminservice_"
_WMI = "wmi_"


def test_adminservice_and_wmi_phases_declare_mirrored_tables():
    """WMI mirrors AdminService over DCOM — same collections, so the two phases must
    declare the same table *suffixes*. A missing comma in either tuple breaks the
    mirror (a concatenated name has no counterpart), which is what this catches."""
    by_name = {p.name: p for p in PER_HOST_PHASES}
    admin_suffixes = {t[len(_ADMIN):] for t in by_name["AdminService"].streams}
    wmi_suffixes = {t[len(_WMI):] for t in by_name["WMI"].streams}
    assert admin_suffixes == wmi_suffixes, {
        "only_adminservice": sorted(admin_suffixes - wmi_suffixes),
        "only_wmi": sorted(wmi_suffixes - admin_suffixes),
    }


def test_user_group_and_collections_tables_are_separate_entries():
    """The two tables that the missing comma swallowed must each be their own entry."""
    names = set(all_table_names(PER_HOST_PHASES))
    for required in (
        "adminservice_user_group",
        "adminservice_collections",
        "wmi_user_group",
        "wmi_collections",
    ):
        assert required in names, f"{required!r} missing from declared phase streams"
    # No declared name may be the tell-tale concatenation of two table names.
    assert not any("group" + _ADMIN in n or "group" + _WMI in n for n in names), [
        n for n in names if "group" + _ADMIN in n or "group" + _WMI in n
    ]
