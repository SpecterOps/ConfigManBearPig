# tests/site_type_inference_test.py
"""A CAS is never typed directly, so infer it from the hierarchy.

Only management-point capabilities carry an explicit site_type, and a CAS has no
management point -- so nothing ever states "CAS is a CAS". Live 2026-07-28 low-priv run:
ldap_management_points_raw held exactly [('PS1','Primary Site','CAS','CAS')] and nothing
for CAS, leaving site_hierarchy = [('CAS',NULL,NULL),('PS1','CAS',2),('SEC',NULL,NULL)].
_edge_replication joins `child.site_type = 2 AND parent.site_type = 4`, so every
SCCM_AdminsReplicatedTo edge silently vanished (CMBP emitted 2).

Both inferences are deductions from SCCM's model, not guesses: a Primary's parent can
only be a CAS, and a site whose parent is a Primary can only be a Secondary.
"""
import duckdb

from openhound_sccm.transforms import _site_hierarchy, _edge_replication, _graph_edges_init

SCHEMA = "sccm"


def _con():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    return con


def _mp(con, rows):
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_management_points_raw "
                "(site_code VARCHAR, site_type VARCHAR, parent_site_code VARCHAR, root_site_code VARCHAR)")
    con.executemany(f"INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES (?,?,?,?)", rows)


def _sites(con, codes):
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_sites (site_code VARCHAR, parent_site_code VARCHAR)")
    con.executemany(f"INSERT INTO {SCHEMA}.ldap_sites VALUES (?,'Undetermined')", [(c,) for c in codes])


def _types(con):
    return {r[0]: r[1] for r in con.execute(
        f"SELECT site_code, site_type FROM {SCHEMA}.site_hierarchy").fetchall()}


def test_cas_is_typed_from_being_a_primarys_parent():
    # Exactly the live shape: only PS1's MP reports anything; CAS is invisible to typing.
    con = _con()
    _mp(con, [("PS1", "Primary Site", "CAS", "CAS")])
    _sites(con, ["PS1", "CAS"])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    t = _types(con)
    assert t["PS1"] == 2
    assert t["CAS"] == 4, f"CAS must be inferred as a CAS, got {t}"


def test_replication_edges_appear_once_the_cas_is_typed():
    # The whole point: _edge_replication needs parent.site_type = 4.
    con = _con()
    _mp(con, [("PS1", "Primary Site", "CAS", "CAS")])
    _sites(con, ["PS1", "CAS"])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    _graph_edges_init(con, SCHEMA)
    _edge_replication(con, SCHEMA)
    edges = {(s, e) for s, e, k in con.execute(
        f"SELECT start_id, end_id, kind FROM {SCHEMA}.graph_edges "
        f"WHERE kind = 'SCCM_AdminsReplicatedTo'").fetchall()}
    # CMBP emits this pair bidirectionally (CAS<->PS1); so must we.
    assert ("PS1", "CAS") in edges and ("CAS", "PS1") in edges, edges


def test_secondary_is_typed_from_its_primary_parent():
    con = _con()
    _mp(con, [("PS1", "Primary Site", "CAS", "CAS"),
              ("SEC", None, "PS1", "CAS")])       # SEC's MP reports a parent but no type
    _sites(con, ["PS1", "CAS", "SEC"])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    assert _types(con)["SEC"] == 1


def test_an_explicitly_collected_type_is_never_overwritten():
    # Inference must only fill gaps. Here CAS is explicitly typed as a CAS already.
    con = _con()
    _mp(con, [("PS1", "Primary Site", "CAS", "CAS"),
              ("CAS", "Central Administration Site", "None", "CAS")])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    t = _types(con)
    assert t["CAS"] == 4 and t["PS1"] == 2


def test_a_parentless_untyped_site_stays_untyped():
    # SEC in the live run: no type, no parent, nothing to deduce from. Must not be guessed.
    con = _con()
    _mp(con, [("PS1", "Primary Site", "CAS", "CAS")])
    _sites(con, ["PS1", "CAS"])
    con.execute(f"CREATE TABLE {SCHEMA}.smb_sites (site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.smb_sites VALUES ('SEC')")
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    assert _types(con)["SEC"] is None


def test_inference_does_not_disturb_a_fully_typed_privileged_hierarchy():
    con = _con()
    con.execute(f"CREATE TABLE {SCHEMA}.adminservice_site_definitions "
                "(site_code VARCHAR, parent_site_code VARCHAR, site_type VARCHAR)")
    con.executemany(f"INSERT INTO {SCHEMA}.adminservice_site_definitions VALUES (?,?,?)",
                    [("CAS", "None", "4"), ("PS1", "CAS", "2"), ("SEC", "PS1", "1")])
    _site_hierarchy(con, SCHEMA, disable_possible_edges=False)
    assert _types(con) == {"CAS": 4, "PS1": 2, "SEC": 1}
