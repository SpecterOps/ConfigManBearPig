from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES
from openhound_sccm.integration.fixtures.nodes import MAYYHEM_NODE_CASES, MAYYHEM_INVARIANTS
from openhound_collector_common.integration_testing.cases import EdgeCase
from openhound_collector_common.integration_testing.graph import Node, Graph
from openhound_collector_common.integration_testing.results import PASS, FAIL


def test_edge_fixture_count_matches_ps_kit():
    # The renamed PS kit has 61 $ExpectedEdges cases; the port must carry them all.
    assert len(MAYYHEM_EDGE_CASES) == 61


def test_edge_fixture_ids_unique_and_typed():
    ids = [c.id for c in MAYYHEM_EDGE_CASES]
    assert len(ids) == len(set(ids)), "duplicate fixture ids"
    assert all(isinstance(c, EdgeCase) and c.kind and c.description for c in MAYYHEM_EDGE_CASES)


def test_no_old_edge_names_or_typo():
    banned = {"SameHostAs", "LocalAdminRequired", "CoerceAndRelayToAdminService",
              "CoerceAndRelayToSMB", "CoerceAndRelayToMSSQL", "CoerceAndRelaytoSMB"}
    assert not (banned & {c.kind for c in MAYYHEM_EDGE_CASES})




def test_node_fixtures_present_and_cover_sccm_site():
    assert MAYYHEM_NODE_CASES, "expected at least one node case"
    assert any("SCCM_Site" in c.kinds for c in MAYYHEM_NODE_CASES)


def _sites():
    # A minimal CAS(root) + PS1(primary) hierarchy for invariant tests.
    return [Node("CAS", ["SCCM_Site"], {"siteCode": "CAS", "siteType": "Central Administration Site"}),
            Node("PS1", ["SCCM_Site"], {"siteCode": "PS1", "siteType": "Primary Site"})]


def test_root_site_normalization_invariant_flags_non_root_node_id():
    # AdminUser/SecurityRole/Collection node ids must end @CAS (root); @PS1 is a leak.
    inv = MAYYHEM_INVARIANTS[0]
    good = Graph(nodes=_sites() + [Node("SMS0002R@CAS", ["SCCM_SecurityRole"], {}),
                                   Node("MAYYHEM\\X@CAS", ["SCCM_AdminUser"], {})], edges=[])
    bad = Graph(nodes=_sites() + [Node("SMS0002R@PS1", ["SCCM_SecurityRole"], {})], edges=[])
    assert inv(good).outcome == PASS
    assert inv(bad).outcome == FAIL


def test_clientdevice_primary_site_invariant():
    # Client devices belong to a primary site (PS1), never the root (CAS).
    inv = MAYYHEM_INVARIANTS[1]
    good = Graph(nodes=_sites() + [Node("GUID:1", ["SCCM_ClientDevice"], {"siteCode": "PS1"})], edges=[])
    bad = Graph(nodes=_sites() + [Node("GUID:1", ["SCCM_ClientDevice"], {"siteCode": "CAS"})], edges=[])
    assert inv(good).outcome == PASS
    assert inv(bad).outcome == FAIL


def test_prefixed_fixture_kinds_exist_in_a_schema():
    # Guards against a typo'd SCCM_/MSSQL_ kind (esp. on a negative case, which would
    # otherwise find 0 matches and spuriously PASS). Native kinds (MemberOf/HasSession/
    # Computer/User/Group/Base) live in BloodHound's core schema, not ours, so only
    # SCCM_/MSSQL_-prefixed kinds are checked here.
    import json
    import pathlib
    base = pathlib.Path(__file__).resolve().parents[1] / "src" / "openhound_sccm"  # schemas ship inside the wheel
    schema_kinds: set[str] = set()
    for name in ("schema_SCCM.json", "schema_MSSQL.json"):
        d = json.loads((base / name).read_text(encoding="utf-8"))
        schema_kinds |= {k["name"] for k in d.get("relationship_kinds", [])}
        schema_kinds |= {k["name"] for k in d.get("node_kinds", [])}
    # SCCM_AssignSpecificPermissions is a coverage placeholder (constraint-less SKIP,
    # no schema entry) — faithful to the PS kit.
    allow = {"SCCM_AssignSpecificPermissions"}
    prefixed = {c.kind for c in MAYYHEM_EDGE_CASES if c.kind.startswith(("SCCM_", "MSSQL_"))}
    prefixed |= {k for c in MAYYHEM_NODE_CASES for k in c.kinds if k.startswith(("SCCM_", "MSSQL_"))}
    missing = prefixed - schema_kinds - allow
    assert not missing, f"SCCM_/MSSQL_ fixture kinds absent from both schemas: {sorted(missing)}"
