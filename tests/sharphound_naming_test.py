# tests/sharphound_naming_test.py
"""Tests for SharpHound-format AD node naming and endpoint integrity (Ope-15m7).

Background. This collector's Computer/User/Group/Container nodes ship in the *untagged*
AD payload (ARCHITECTURE 11f) so BloodHound merges them into its native AD graph by id.
That merge means any `name` this collector emits **overwrites** SharpHound's own label on
the merged node. The rule these tests pin down is therefore: emit the name in SharpHound's
exact format, or emit no name at all -- never a bare short name, a DOMAIN\\-prefixed name,
or the object's own SID.

The bug that motivated it: an unprivileged collect rendered Domain Admins, Enterprise
Admins, IT Helpdesk and Workstation Admins as bare SIDs, because every source feeding
node_group required SCCM privilege while the LDAP-derived names sat unused in ad_props.
"""
import duckdb
import pytest
from openhound_sccm.models.container import ContainerNode
from openhound_sccm.models.group import GroupNode
from openhound_sccm.models.stub_node import StubNode
from openhound_sccm.transforms import (
    _derive_ad_props,
    _domain_fqdn_by_sid,
    _node_backfill,
    _node_group,
    _node_user,
    _stamp_sharphound_name,
)

SCHEMA = "sccm"

AD_PROPS_DDL = (
    f"CREATE TABLE {SCHEMA}.ad_props (sid VARCHAR, enabled BOOLEAN, type VARCHAR, "
    "is_domain_principal BOOLEAN, object_class VARCHAR[], service_principal_name VARCHAR[], "
    "cn VARCHAR, domain VARCHAR, sam_account_name VARCHAR, distinguished_name VARCHAR)"
)


def _con() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    return con


def _with_ad_props(rows: str = "") -> duckdb.DuckDBPyConnection:
    con = _con()
    con.execute(AD_PROPS_DDL)
    if rows:
        con.execute(f"INSERT INTO {SCHEMA}.ad_props VALUES {rows}")
    return con


# --------------------------------------------------------------------------------------
# _domain_fqdn_by_sid: domain SID -> FQDN recovery
# --------------------------------------------------------------------------------------

def test_domain_fqdn_map_is_built_and_uppercased():
    con = _with_ad_props(
        "('S-1-5-21-1-2-3-500', true, 'User', true, ['top','user'], [], 'A', 'corp.local', "
        "'admin', 'CN=admin')"
    )
    _domain_fqdn_by_sid(con, SCHEMA)
    assert con.execute(f"SELECT domain_sid, fqdn FROM {SCHEMA}.domain_fqdn_by_sid").fetchall() == [
        ("S-1-5-21-1-2-3", "CORP.LOCAL")
    ]


def test_domain_fqdn_map_ignores_netbios_domains():
    """A NetBIOS name has no dot. Admitting one would produce 'ADMIN@CORP', which is not a
    SharpHound name and would overwrite a correct label on merge."""
    con = _with_ad_props(
        "('S-1-5-21-1-2-3-500', true, 'User', true, ['top','user'], [], 'A', 'CORP', "
        "'admin', 'CN=admin')"
    )
    _domain_fqdn_by_sid(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.domain_fqdn_by_sid").fetchone()[0] == 0


def test_domain_fqdn_map_is_deterministic_under_disagreement():
    """mode() picks the majority FQDN so one odd row cannot flip the whole domain's naming."""
    rows = ", ".join(
        f"('S-1-5-21-1-2-3-{100 + i}', true, 'User', true, ['top','user'], [], 'A', "
        f"'{'corp.local' if i < 3 else 'stale.local'}', 'u{i}', 'CN=u{i}')"
        for i in range(4)
    )
    con = _with_ad_props(rows)
    _domain_fqdn_by_sid(con, SCHEMA)
    assert con.execute(f"SELECT fqdn FROM {SCHEMA}.domain_fqdn_by_sid").fetchone()[0] == "CORP.LOCAL"


# --------------------------------------------------------------------------------------
# _stamp_sharphound_name: per-kind formats
# --------------------------------------------------------------------------------------

def _stamp_group(con, *, sid, name, sam, domain, dn=None):
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_group (sid VARCHAR, name VARCHAR, "
        "sam_account_name VARCHAR, domain VARCHAR, distinguished_name VARCHAR, "
        "fallback_domain_sid VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.node_group VALUES (?, ?, ?, ?, ?, NULL)",
        [sid, name, sam, domain, dn],
    )
    _stamp_sharphound_name(
        con, SCHEMA, "node_group", "group", fallback_domain_sid_col="fallback_domain_sid"
    )
    return con.execute(f"SELECT sharphound_name FROM {SCHEMA}.node_group").fetchone()[0]


def test_group_name_is_samaccountname_at_fqdn():
    con = _with_ad_props()
    _domain_fqdn_by_sid(con, SCHEMA)
    assert _stamp_group(
        con, sid="S-1-5-21-1-2-3-512", name="Domain Admins", sam="Domain Admins",
        domain="corp.local",
    ) == "DOMAIN ADMINS@CORP.LOCAL"


def test_group_name_strips_the_sccm_domain_backslash_prefix():
    """SCCM's SecurityGroupName arrives as 'corp\\Domain Admins'. Shipping that verbatim is
    what the privileged collect used to do, and it overwrites SharpHound's label."""
    con = _with_ad_props()
    _domain_fqdn_by_sid(con, SCHEMA)
    assert _stamp_group(
        con, sid="S-1-5-21-1-2-3-512", name="corp\\Domain Admins", sam=None,
        domain=None, dn="CN=Domain Admins,CN=Users,DC=corp,DC=local",
    ) == "DOMAIN ADMINS@CORP.LOCAL"


def test_fqdn_falls_back_to_the_dn_then_to_the_sid_map():
    """No domain column: the DN's DC= components resolve it without needing the map."""
    con = _with_ad_props()
    _domain_fqdn_by_sid(con, SCHEMA)
    assert _stamp_group(
        con, sid="S-1-5-21-1-2-3-512", name="Domain Admins", sam="Domain Admins",
        domain=None, dn="CN=Domain Admins,CN=Users,DC=corp,DC=local",
    ) == "DOMAIN ADMINS@CORP.LOCAL"


def test_fqdn_recovered_from_the_sid_map_when_row_has_neither_domain_nor_dn():
    """The sqlsccmsvc case: discovered from SQL Server, never LDAP-resolved, so it carries a
    domain SID but no domain name and no DN. The map supplies the FQDN."""
    con = _with_ad_props(
        "('S-1-5-21-1-2-3-500', true, 'User', true, ['top','user'], [], 'A', 'corp.local', "
        "'admin', 'CN=admin')"
    )
    _domain_fqdn_by_sid(con, SCHEMA)
    assert _stamp_group(
        con, sid="S-1-5-21-1-2-3-1116", name="sqlsccmsvc", sam="sqlsccmsvc",
        domain=None, dn=None,
    ) == "SQLSCCMSVC@CORP.LOCAL"


def test_name_is_null_when_no_fqdn_can_be_resolved():
    """The whole point of the omit rule: with no FQDN we cannot build SharpHound's form, so
    we assert nothing rather than shipping a bare name that would clobber a real label."""
    con = _with_ad_props()
    _domain_fqdn_by_sid(con, SCHEMA)
    assert _stamp_group(
        con, sid="S-1-5-21-9-9-9-512", name="Domain Admins", sam="Domain Admins",
        domain=None, dn=None,
    ) is None


def test_a_name_already_in_sharphound_form_passes_through():
    """The synthetic Authenticated Users node is built as NAME@FQDN directly, and its
    well-known SID has no domain part -- the stamp must not blank it."""
    con = _with_ad_props()
    _domain_fqdn_by_sid(con, SCHEMA)
    assert _stamp_group(
        con, sid="CORP.LOCAL-S-1-5-11", name="AUTHENTICATED USERS@CORP.LOCAL", sam=None,
        domain=None, dn=None,
    ) == "AUTHENTICATED USERS@CORP.LOCAL"


def test_computer_name_is_the_uppercase_dnshostname():
    con = _with_ad_props()
    _domain_fqdn_by_sid(con, SCHEMA)
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_computer (sid VARCHAR, name VARCHAR, dnshostname VARCHAR, "
        "sam_account_name VARCHAR, domain VARCHAR, distinguished_name VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.node_computer VALUES "
        "('S-1-5-21-1-2-3-1118', 'PS1-MP', 'ps1-mp.corp.local', 'PS1-MP$', 'CORP.LOCAL', NULL)"
    )
    _stamp_sharphound_name(con, SCHEMA, "node_computer", "computer")
    assert con.execute(
        f"SELECT sharphound_name FROM {SCHEMA}.node_computer"
    ).fetchone()[0] == "PS1-MP.CORP.LOCAL"


def test_computer_name_is_built_from_the_short_name_and_drops_the_trailing_dollar():
    """No dNSHostName (20 of 35 computers in the recorded privileged run): build HOST.FQDN
    from the account name, minus the machine account's trailing '$'."""
    con = _with_ad_props()
    _domain_fqdn_by_sid(con, SCHEMA)
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_computer (sid VARCHAR, name VARCHAR, dnshostname VARCHAR, "
        "sam_account_name VARCHAR, domain VARCHAR, distinguished_name VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.node_computer VALUES "
        "('S-1-5-21-1-2-3-1001', 'DC', NULL, 'DC$', 'corp.local', NULL)"
    )
    _stamp_sharphound_name(con, SCHEMA, "node_computer", "computer")
    assert con.execute(
        f"SELECT sharphound_name FROM {SCHEMA}.node_computer"
    ).fetchone()[0] == "DC.CORP.LOCAL"


def test_container_name_is_its_cn_at_the_dn_derived_fqdn():
    con = _with_ad_props()
    _domain_fqdn_by_sid(con, SCHEMA)
    con.execute(
        f"CREATE TABLE {SCHEMA}.node_container (id VARCHAR, distinguished_name VARCHAR, "
        "fallback_domain_sid VARCHAR)"
    )
    con.execute(
        f"INSERT INTO {SCHEMA}.node_container VALUES "
        "('AAAA-GUID', 'CN=System Management,CN=System,DC=corp,DC=local', 'S-1-5-21-1-2-3')"
    )
    _stamp_sharphound_name(
        con, SCHEMA, "node_container", "container",
        sid_col="id", fallback_domain_sid_col="fallback_domain_sid",
    )
    assert con.execute(
        f"SELECT sharphound_name FROM {SCHEMA}.node_container"
    ).fetchone()[0] == "SYSTEM MANAGEMENT@CORP.LOCAL"


def test_stamp_binds_even_when_the_fqdn_map_was_never_built():
    """A caller running one node builder outside transforms() must still get the column, or
    every model reads None and emits unnamed nodes."""
    con = _with_ad_props()  # note: no _domain_fqdn_by_sid call
    assert _stamp_group(
        con, sid="S-1-5-21-1-2-3-512", name="Domain Admins", sam="Domain Admins",
        domain="corp.local",
    ) == "DOMAIN ADMINS@CORP.LOCAL"


# --------------------------------------------------------------------------------------
# Models: SharpHound form or nothing
# --------------------------------------------------------------------------------------

def test_group_model_emits_the_sharphound_name_not_the_raw_name():
    props = GroupNode(
        sid="S-1-5-21-1-2-3-512",
        name="corp\\Domain Admins",
        sharphound_name="DOMAIN ADMINS@CORP.LOCAL",
    ).as_node.properties
    assert props.name == "DOMAIN ADMINS@CORP.LOCAL"
    assert props.displayname == "DOMAIN ADMINS@CORP.LOCAL"


def test_group_model_emits_no_name_rather_than_the_sid():
    """The exact regression from the reported graph: four groups labelled with their SIDs."""
    props = GroupNode(sid="S-1-5-21-1-2-3-512", name=None, sharphound_name=None).as_node.properties
    assert props.name is None
    assert props.displayname is None


def test_stub_node_carries_no_name_at_all():
    """ARCHITECTURE 11e specifies a stub as "just id, kinds ... and environmentid". Naming a
    stub after its own SID is what put S-1-5-21-...-512 on screen where SharpHound would
    otherwise have supplied DOMAIN ADMINS@... on the merged node."""
    node = StubNode(id="S-1-5-21-1-2-3-512", kind="Group").as_node
    assert node.properties.name is None
    assert node.properties.displayname is None
    assert node.properties.environmentid == "S-1-5-21-1-2-3"
    assert node.kinds == ["Group", "Base"]


@pytest.mark.parametrize("dn", [None, "CN=System Management,CN=System,DC=corp,DC=local"])
def test_container_model_never_falls_back_to_its_guid(dn):
    props = ContainerNode(
        id="AAAA-GUID", distinguished_name=dn, fallback_domain_sid="S-1-5-21-1-2-3",
        sharphound_name=None,
    ).as_node.properties
    assert props.name is None


# --------------------------------------------------------------------------------------
# _node_backfill: both endpoints
# --------------------------------------------------------------------------------------

def _backfill_con() -> duckdb.DuckDBPyConnection:
    con = _con()
    for t, col in (("node_computer", "sid"), ("node_user", "sid"), ("node_group", "sid")):
        con.execute(f"CREATE TABLE {SCHEMA}.{t} ({col} VARCHAR)")
    con.execute(f"CREATE TABLE {SCHEMA}.node_client_device (smsid VARCHAR)")
    con.execute(f"CREATE TABLE {SCHEMA}.graph_edges (start_id VARCHAR, end_id VARCHAR, kind VARCHAR)")
    return con


def test_backfill_covers_dangling_edge_starts():
    """Ends alone left a MemberOf whose start had no node to be dropped whole at ingest,
    silently hiding real members of Domain Admins rather than showing them unnamed."""
    con = _backfill_con()
    con.execute(f"INSERT INTO {SCHEMA}.node_group VALUES ('S-1-5-21-1-2-3-512')")
    con.execute(
        f"INSERT INTO {SCHEMA}.graph_edges VALUES "
        "('S-1-5-21-1-2-3-500', 'S-1-5-21-1-2-3-512', 'MemberOf')"
    )
    _node_backfill(con, SCHEMA)
    assert con.execute(f"SELECT id, kind FROM {SCHEMA}.node_backfill").fetchall() == [
        ("S-1-5-21-1-2-3-500", "Base")
    ]


def test_backfill_still_covers_dangling_edge_ends():
    con = _backfill_con()
    con.execute(f"INSERT INTO {SCHEMA}.node_user VALUES ('S-1-5-21-1-2-3-500')")
    con.execute(
        f"INSERT INTO {SCHEMA}.graph_edges VALUES "
        "('S-1-5-21-1-2-3-500', 'S-1-5-21-1-2-3-512', 'MemberOf')"
    )
    _node_backfill(con, SCHEMA)
    assert con.execute(f"SELECT id, kind FROM {SCHEMA}.node_backfill").fetchall() == [
        ("S-1-5-21-1-2-3-512", "Group")
    ]


def test_an_id_dangling_as_both_start_and_end_yields_one_stub():
    """A nested group is the end of one MemberOf and the start of the next; two rows for one
    id would emit the node twice."""
    con = _backfill_con()
    con.execute(
        f"INSERT INTO {SCHEMA}.graph_edges VALUES "
        "('S-1-5-21-1-2-3-1130', 'S-1-5-21-1-2-3-1131', 'MemberOf'), "
        "('S-1-5-21-1-2-3-1131', 'S-1-5-21-1-2-3-512', 'MemberOf')"
    )
    _node_backfill(con, SCHEMA)
    ids = [r[0] for r in con.execute(f"SELECT id FROM {SCHEMA}.node_backfill").fetchall()]
    assert ids.count("S-1-5-21-1-2-3-1131") == 1
    assert len(ids) == len(set(ids))


def test_backfill_is_empty_when_every_endpoint_has_a_node():
    con = _backfill_con()
    con.execute(
        f"INSERT INTO {SCHEMA}.node_user VALUES ('S-1-5-21-1-2-3-500')"
    )
    con.execute(f"INSERT INTO {SCHEMA}.node_group VALUES ('S-1-5-21-1-2-3-512')")
    con.execute(
        f"INSERT INTO {SCHEMA}.graph_edges VALUES "
        "('S-1-5-21-1-2-3-500', 'S-1-5-21-1-2-3-512', 'MemberOf')"
    )
    _node_backfill(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.node_backfill").fetchone()[0] == 0


# --------------------------------------------------------------------------------------
# ad_props arms: an LDAP-resolved principal becomes a real node, not a stub
# --------------------------------------------------------------------------------------

def test_group_node_is_built_from_ad_props_with_no_sccm_source_at_all():
    """The unprivileged case. Every other node_group arm needs AdminService or WMI on the
    site server, so without this one node_group came back with no rows and the groups on the
    System Management container path degraded to SID-named stubs."""
    con = _with_ad_props(
        "('S-1-5-21-1-2-3-1130', true, 'Group', true, ['top','group'], [], 'IT Helpdesk', "
        "'corp.local', 'IT Helpdesk', 'CN=IT Helpdesk,CN=Users,DC=corp,DC=local')"
    )
    _domain_fqdn_by_sid(con, SCHEMA)
    _node_group(con, SCHEMA)
    assert con.execute(
        f"SELECT sid, sharphound_name, sccm_infra FROM {SCHEMA}.node_group"
    ).fetchall() == [("S-1-5-21-1-2-3-1130", "IT HELPDESK@CORP.LOCAL", False)]


def test_user_node_is_built_from_ad_props_with_no_sccm_source_at_all():
    con = _with_ad_props(
        "('S-1-5-21-1-2-3-500', true, 'User', true, ['top','person','user'], [], 'A', "
        "'corp.local', 'Administrator', 'CN=Administrator,CN=Users,DC=corp,DC=local')"
    )
    _domain_fqdn_by_sid(con, SCHEMA)
    _node_user(con, SCHEMA)
    assert con.execute(
        f"SELECT sid, sharphound_name FROM {SCHEMA}.node_user"
    ).fetchall() == [("S-1-5-21-1-2-3-500", "ADMINISTRATOR@CORP.LOCAL")]


def test_the_user_arm_does_not_swallow_computer_accounts():
    """AD's objectClass chains nest: a computer is (top, person, organizationalPerson, user,
    computer), so a naive 'is it a user' test claims every computer in the domain. Caught by
    replaying a recorded collect, where node_user jumped from 5 rows to 18."""
    con = _with_ad_props(
        "('S-1-5-21-1-2-3-500', true, 'User', true, ['top','person','user'], [], 'A', "
        "'corp.local', 'Administrator', 'CN=Administrator,DC=corp,DC=local'), "
        "('S-1-5-21-1-2-3-1118', true, 'Computer', true, "
        "['top','person','organizationalPerson','user','computer'], [], 'PS1-MP', "
        "'corp.local', 'PS1-MP$', 'CN=PS1-MP,DC=corp,DC=local')"
    )
    _domain_fqdn_by_sid(con, SCHEMA)
    _node_user(con, SCHEMA)
    assert [r[0] for r in con.execute(f"SELECT sid FROM {SCHEMA}.node_user").fetchall()] == [
        "S-1-5-21-1-2-3-500"
    ]


def test_empty_ad_props_warns_at_the_consumption_site(caplog):
    """_safe() logs-and-skips a missing ldap_resolved_principals, leaving ad_props empty and
    stripping names and AD attributes from the entire graph. Without this the only warning
    was at the emission site, so the degradation was invisible from the preproc log."""
    con = _con()
    with caplog.at_level("WARNING"):
        _derive_ad_props(con, SCHEMA)
    assert any("ad_props is empty" in r.message for r in caplog.records)
