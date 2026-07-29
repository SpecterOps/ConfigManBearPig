# src/openhound_sccm/ad_props_derive_test.py
"""Tests for _derive_ad_props (transforms.py): derives CMBP-parity AD attributes
(enabled, type, is_domain_principal, ...) from the raw ldap_resolved_principals
table into sccm.ad_props, keyed by sid.

NOTE: user_account_control is seeded as VARCHAR here on purpose -- in production
ldap3 raw values decode to strings and dlt infers a text column, so the derivation
must TRY_CAST before the bitwise AND (ope-c141 final-review finding). Do NOT change
this back to BIGINT: that would mask the VARCHAR & INTEGER binder error the fix guards
against. The integer literals below auto-coerce to strings on insert into the VARCHAR
column, matching how the data actually arrives."""
import duckdb
from openhound_sccm.transforms import _derive_ad_props


def test_enabled_and_type_derivation():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.ldap_resolved_principals (sid VARCHAR, object_class VARCHAR[], "
                "user_account_control VARCHAR, service_principal_name VARCHAR[], cn VARCHAR, "
                "dns_host_name VARCHAR, sam_account_name VARCHAR, user_principal_name VARCHAR, "
                "distinguished_name VARCHAR, domain VARCHAR)")
    con.execute("INSERT INTO sccm.ldap_resolved_principals VALUES "
                "('S-1-1', ['top','user'], 512, [], 'Bob', NULL, 'bob', 'bob@c', 'CN=Bob', 'corp.local'),"
                "('S-1-2', ['top','computer'], 4098, ['HOST/x'], 'PC1', 'pc1.c', 'PC1$', NULL, 'CN=PC1', 'corp.local')")
    _derive_ad_props(con, "sccm")   # creates sccm.ad_props
    rows = {r[0]: r for r in con.execute(
        "SELECT sid, enabled, type, is_domain_principal FROM sccm.ad_props ORDER BY sid").fetchall()}
    assert rows['S-1-1'][1] is True and rows['S-1-1'][2] == 'User'      # uac 512 -> enabled
    assert rows['S-1-2'][1] is False and rows['S-1-2'][2] == 'Computer' # uac 4098 has bit 2 -> disabled
    assert rows['S-1-1'][3] is True


def test_carries_object_class_spn_cn_domain():
    """The passthrough columns (object_class, service_principal_name, cn, domain,
    sam_account_name, distinguished_name) must survive unchanged so later tasks can
    surface them on the AD nodes -- sam_account_name/distinguished_name (ope-c141)
    exist for node types with no other AD-object source of their own, e.g. Group."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.ldap_resolved_principals (sid VARCHAR, object_class VARCHAR[], "
                "user_account_control VARCHAR, service_principal_name VARCHAR[], cn VARCHAR, "
                "dns_host_name VARCHAR, sam_account_name VARCHAR, user_principal_name VARCHAR, "
                "distinguished_name VARCHAR, domain VARCHAR)")
    con.execute("INSERT INTO sccm.ldap_resolved_principals VALUES "
                "('S-1-2', ['top','computer'], 4098, ['HOST/x'], 'PC1', 'pc1.c', 'PC1$', NULL, 'CN=PC1', 'corp.local')")
    _derive_ad_props(con, "sccm")
    row = con.execute(
        "SELECT object_class, service_principal_name, cn, domain, sam_account_name, "
        "distinguished_name FROM sccm.ad_props WHERE sid = 'S-1-2'"
    ).fetchone()
    assert row == (['top', 'computer'], ['HOST/x'], 'PC1', 'corp.local', 'PC1$', 'CN=PC1')


def test_null_uac_and_empty_object_class_yield_null():
    """NULL userAccountControl -> NULL enabled; empty objectClass -> NULL type."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.ldap_resolved_principals (sid VARCHAR, object_class VARCHAR[], "
                "user_account_control VARCHAR, service_principal_name VARCHAR[], cn VARCHAR, "
                "dns_host_name VARCHAR, sam_account_name VARCHAR, user_principal_name VARCHAR, "
                "distinguished_name VARCHAR, domain VARCHAR)")
    con.execute("INSERT INTO sccm.ldap_resolved_principals VALUES "
                "('S-1-3', [], NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)")
    _derive_ad_props(con, "sccm")
    row = con.execute(
        "SELECT enabled, type, is_domain_principal FROM sccm.ad_props WHERE sid = 'S-1-3'"
    ).fetchone()
    assert row == (None, None, True)


def test_missing_source_table_leaves_ad_props_empty_not_raising():
    """ldap_resolved_principals is a best-effort finalization table (Task A2) and can be
    absent this run; _derive_ad_props must not raise, and must still create a
    schema-complete (empty) ad_props table so downstream LEFT JOINs bind."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    _derive_ad_props(con, "sccm")   # no ldap_resolved_principals table at all
    count = con.execute("SELECT count(*) FROM sccm.ad_props").fetchone()[0]
    assert count == 0
    # Column set must still be the full CMBP-parity shape.
    cols = {r[0] for r in con.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'sccm' AND table_name = 'ad_props'"
    ).fetchall()}
    assert cols == {"sid", "enabled", "type", "is_domain_principal", "object_class",
                     "service_principal_name", "cn", "domain",
                     "sam_account_name", "distinguished_name"}


def test_sid_is_uppercased():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.ldap_resolved_principals (sid VARCHAR, object_class VARCHAR[], "
                "user_account_control VARCHAR, service_principal_name VARCHAR[], cn VARCHAR, "
                "dns_host_name VARCHAR, sam_account_name VARCHAR, user_principal_name VARCHAR, "
                "distinguished_name VARCHAR, domain VARCHAR)")
    con.execute("INSERT INTO sccm.ldap_resolved_principals VALUES "
                "('s-1-5-21-1-2-3-1104', ['top','user'], 512, [], 'Bob', NULL, 'bob', 'bob@c', 'CN=Bob', 'corp.local')")
    _derive_ad_props(con, "sccm")
    rows = con.execute("SELECT sid FROM sccm.ad_props").fetchall()
    assert rows == [("S-1-5-21-1-2-3-1104",)]


def test_case_variant_sid_duplicates_collapse_to_one_row():
    """Two ldap_resolved_principals rows for the same principal differing only by SID
    case (the in-memory accumulator dedupes on the raw, case-sensitive SID, so
    case-variant strings both survive) must collapse to a single ad_props row per
    upper(sid) -- otherwise the LEFT JOIN in _join_ad_props duplicates a real node."""
    con = duckdb.connect()
    con.execute("CREATE SCHEMA sccm")
    con.execute("CREATE TABLE sccm.ldap_resolved_principals (sid VARCHAR, object_class VARCHAR[], "
                "user_account_control VARCHAR, service_principal_name VARCHAR[], cn VARCHAR, "
                "dns_host_name VARCHAR, sam_account_name VARCHAR, user_principal_name VARCHAR, "
                "distinguished_name VARCHAR, domain VARCHAR)")
    con.execute("INSERT INTO sccm.ldap_resolved_principals VALUES "
                "('S-1-5-21-9', ['top','user'], 512, [], 'Bob', NULL, 'bob', 'bob@c', 'CN=Bob', 'corp.local'),"
                "('s-1-5-21-9', ['top','user'], 512, [], 'Bob', NULL, 'bob', 'bob@c', 'CN=Bob', 'corp.local')")
    _derive_ad_props(con, "sccm")
    count = con.execute(
        "SELECT count(*) FROM sccm.ad_props WHERE sid = upper('S-1-5-21-9')"
    ).fetchone()[0]
    assert count == 1
