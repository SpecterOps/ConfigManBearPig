# src/openhound_sccm/node_client_device_possible_test.py
import duckdb
from openhound_sccm.transforms import transforms


def _seed(con, disable, *, with_primary):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(f"CREATE TABLE sccm.collection_settings AS "
                f"SELECT {str(disable).lower()} AS disable_possible_edges, false AS enable_bad_opsec")
    # A CAS always sits at the top here. Add a child Primary when the scenario needs a
    # real place to attach the client: a CAS cannot own clients, so an inferred client
    # must land on a Primary (ConfigManBearPig ps1:3253-3254).
    sites = "('CAS', NULL, 4), ('PS1', 'CAS', 2)" if with_primary else "('CAS', NULL, 4)"
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                f"(VALUES {sites}) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
                "'S-1-5-21-1-2-3-1104' AS object_sid, 'WS09' AS name")


def test_possible_client_attaches_to_primary_not_cas():
    # Inferred client attaches to the first PRIMARY site (PS1), never the CAS. The id
    # keeps the @root (CAS) suffix for stable namespacing; only site_code moves to the
    # Primary, matching CMBP's "first primary site published to AD" (ps1:3253-3254).
    con = duckdb.connect(":memory:")
    _seed(con, disable=False, with_primary=True)
    transforms(con)
    row = con.execute(
        "SELECT smsid, site_code, name, is_confirmed_active_client, ad_domain_sid, root_site_code "
        "FROM sccm.node_client_device WHERE NOT is_confirmed_active_client").fetchone()
    assert row == ("S-1-5-21-1-2-3-1104@CAS", "PS1", "WS09", False, "S-1-5-21-1-2-3-1104", "CAS")
    # HasClient originates from the Primary site, never the CAS.
    hc = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                     "WHERE kind='SCCM_HasClient' AND end_id='S-1-5-21-1-2-3-1104@CAS'").fetchall()
    assert hc == [("PS1", "S-1-5-21-1-2-3-1104@CAS")]


def test_possible_client_falls_back_to_root_without_primary():
    # Degenerate hierarchy with only a CAS and no primary: preserve the edge by falling
    # back to the root rather than dropping the client entirely.
    con = duckdb.connect(":memory:")
    _seed(con, disable=False, with_primary=False)
    transforms(con)
    hc = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                     "WHERE kind='SCCM_HasClient' AND end_id='S-1-5-21-1-2-3-1104@CAS'").fetchall()
    assert hc == [("CAS", "S-1-5-21-1-2-3-1104@CAS")]


def test_possible_client_suppressed_when_disabled():
    con = duckdb.connect(":memory:")
    _seed(con, disable=True, with_primary=True)
    transforms(con)
    cnt = con.execute("SELECT count(*) FROM sccm.node_client_device WHERE NOT is_confirmed_active_client").fetchone()[0]
    assert cnt == 0
