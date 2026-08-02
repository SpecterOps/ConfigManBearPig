# src/openhound_sccm/transforms_test (Task 11): System Management Container node +
# GenericAll edges, wiring up ldap_system_management_dacl (collected, previously
# read by nothing).
#
# node_container has no "kinds" column -- kinds are a model-layer concept in this
# codebase (see models/container.py::ContainerNode, mirroring GroupNode/StubNode),
# not stored in DuckDB. graph_edges likewise has no "traversable" column --
# GraphEdge derives it from kind membership in TRAVERSABLE_EDGE_KINDS at convert
# time (see models/graph_edge.py). Both are asserted separately below.
import duckdb

from openhound_sccm.kinds.edges import GENERIC_ALL, TRAVERSABLE_EDGE_KINDS
from openhound_sccm.models.container import ContainerNode
from openhound_sccm.transforms import _edge_generic_all_smc, _graph_edges_init, _node_smc_container

SCHEMA = "sccm"


def _con():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.ldap_system_management_dacl "
        "(object_sid VARCHAR, object_class VARCHAR[], sam_account_name VARCHAR, "
        " smc_container_guid VARCHAR, smc_container_dn VARCHAR)"
    )
    con.executemany(
        f"INSERT INTO {SCHEMA}.ldap_system_management_dacl VALUES (?,?,?,?,?)",
        [
            ("S-1-5-21-1-2-3-512", ["group"], "Domain Admins",
             "aaaa-guid", "CN=System Management,CN=System,DC=x"),
            ("S-1-5-21-1-2-3-1104", ["computer"], "PS1-PSS$",
             "aaaa-guid", "CN=System Management,CN=System,DC=x"),
        ],
    )
    return con


def test_single_container_node_merges_by_guid():
    con = _con()
    _node_smc_container(con, SCHEMA)
    rows = con.execute(
        f"SELECT id, distinguished_name, fallback_domain_sid FROM {SCHEMA}.node_container"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "AAAA-GUID"  # uppercased to match SharpHound's objectid form
    assert rows[0][1] == "CN=System Management,CN=System,DC=x"
    # Derived from a co-collected principal's domain-relative SID (GroupNode idiom).
    assert rows[0][2] == "S-1-5-21-1-2-3"


def test_container_node_model_emits_container_and_base_kinds():
    node = ContainerNode(
        id="AAAA-GUID",
        distinguished_name="CN=System Management,CN=System,DC=x",
        fallback_domain_sid="S-1-5-21-1-2-3",
    ).as_node
    assert node.id == "AAAA-GUID"
    assert node.kinds == ["Container", "Base"]
    assert node.properties.environmentid == "S-1-5-21-1-2-3"


def test_container_node_exposes_lowercase_distinguishedname():
    # The DN is published as its own property, not just folded into the display name,
    # so queries can filter the System Management container out of a graph that holds
    # every SharpHound-collected Container. The key must be lowercase to match
    # SharpHound's own node for this object (Cypher property lookups are
    # case-sensitive) -- this is the one node kind that does not use CMBP's camelCase.
    props = ContainerNode(
        id="AAAA-GUID",
        distinguished_name="CN=System Management,CN=System,DC=x",
        fallback_domain_sid="S-1-5-21-1-2-3",
        sharphound_name="SYSTEM MANAGEMENT@X",
    ).as_node.properties
    assert props.distinguishedname == "CN=System Management,CN=System,DC=x"
    assert not hasattr(props, "distinguishedName")
    # The display name is SharpHound's NAME@DOMAIN form, NOT the DN (Ope-15m7). This node
    # merges with SharpHound's own Container by objectGUID, so emitting the DN as the name
    # would replace SharpHound's label with a DN string on the merged node.
    assert props.name == "SYSTEM MANAGEMENT@X"
    assert props.displayname == "SYSTEM MANAGEMENT@X"


def test_container_node_is_unnamed_when_no_sharphound_name_could_be_built():
    # No DN means _stamp_sharphound_name had no CN and no DC= components to work with, so
    # it left sharphound_name NULL. The node must then ship with NO name rather than falling
    # back to its raw GUID: null is pruned on emit and BloodHound displays the object id,
    # whereas a GUID-as-name would overwrite a real SharpHound label on the merged node.
    # The DN property stays null too, so a STARTS WITH filter never sees a GUID string.
    props = ContainerNode(id="AAAA-GUID", fallback_domain_sid="S-1-5-21-1-2-3").as_node.properties
    assert props.distinguishedname is None
    assert props.name is None
    assert props.displayname is None


def test_generic_all_edge_per_principal():
    con = _con()
    _graph_edges_init(con, SCHEMA)
    _edge_generic_all_smc(con, SCHEMA)
    edges = con.execute(
        f"SELECT start_id, end_id, kind FROM {SCHEMA}.graph_edges WHERE kind = '{GENERIC_ALL}'"
    ).fetchall()
    assert {e[0] for e in edges} == {"S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-1104"}
    assert all(e[1] == "AAAA-GUID" for e in edges)


def test_generic_all_is_traversable():
    # traversable is derived at convert time from kind membership, not stored here.
    assert GENERIC_ALL in TRAVERSABLE_EDGE_KINDS


def test_node_smc_container_tolerates_missing_source_table():
    # An older cached bucket / a run without LDAP collection has no
    # ldap_system_management_dacl table at all -- must not raise, and must still
    # leave an (empty) node_container table for convert to read.
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    _node_smc_container(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.node_container").fetchone()[0] == 0
