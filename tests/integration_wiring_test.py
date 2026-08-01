"""Tests for SCCM integration-test wiring (openhound_sccm.integration).

Verifies that run_integration_tests / compare_to_zip correctly assemble the
mayyhem.com fixtures with the shared openhound_collector_common engine and the
SCCM schema (schema_SCCM.json).
"""
import json
import zipfile

from openhound_sccm.integration import run_integration_tests, compare_to_zip, SCHEMA_PATH


def _write_min_graph(d):
    (d / "sccm_nodes.json").write_text(json.dumps({"graph": {"nodes": [
        {"id": "CAS", "kinds": ["SCCM_Site"], "properties": {"siteCode": "CAS"}},
        {"id": "PS1", "kinds": ["SCCM_Site"], "properties": {"siteCode": "PS1"}},
        {"id": "SEC", "kinds": ["SCCM_Site"], "properties": {"siteCode": "SEC"}}], "edges": []}}), encoding="utf-8")


def test_schema_path_exists():
    assert SCHEMA_PATH.exists() and SCHEMA_PATH.name == "schema_SCCM.json"


def test_run_integration_tests_returns_exit_code(tmp_path):
    _write_min_graph(tmp_path)
    rc = run_integration_tests(tmp_path, results_path=tmp_path / "res.json")
    assert rc in (0, 1)                       # runs end-to-end without raising
    assert (tmp_path / "res.json").exists()


def test_compare_to_zip_flags_a_regression(tmp_path):
    """The zip is the BASELINE. A node it has and the fresh graph lacks is a drop."""
    _write_min_graph(tmp_path)                     # graph has CAS, PS1, SEC
    zp = tmp_path / "b.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("nodes.json", json.dumps({"graph": {"nodes": [
            {"id": "CAS", "kinds": ["SCCM_Site"], "properties": {"siteCode": "CAS"}},
            {"id": "GONE", "kinds": ["SCCM_Site"], "properties": {}}], "edges": []}}))
    rc = compare_to_zip(tmp_path, zp, out_path=tmp_path / "cmp.json")
    assert rc == 1
    report = json.loads((tmp_path / "cmp.json").read_text())
    assert report["nodes_only_in_baseline"] == ["GONE"]      # the zip's node, lost
    assert "PS1" in report["nodes_only_in_candidate"]        # the graph's extras, added


def test_compare_to_zip_clean_when_candidate_only_grew(tmp_path):
    _write_min_graph(tmp_path)
    zp = tmp_path / "b.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("nodes.json", json.dumps({"graph": {"nodes": [
            {"id": "CAS", "kinds": ["SCCM_Site"], "properties": {"siteCode": "CAS"}}],
            "edges": []}}))
    assert compare_to_zip(tmp_path, zp, out_path=tmp_path / "cmp.json") == 0
