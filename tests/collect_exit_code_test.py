"""The collect command's combined testing exit code.

--compare-to-zip used to always return 0. Now either testing flag can fail, so
collect_sccm must surface a non-zero exit if EITHER does, while still running both
so the operator sees both reports.
"""
import pytest

from openhound_sccm import main


@pytest.mark.parametrize("rc_compare,rc_suite,expected", [
    (0, 0, 0),
    (1, 0, 1),          # compare found a regression
    (0, 1, 1),          # a fixture case failed
    (1, 1, 1),          # both
])
def test_combined_exit_code(monkeypatch, tmp_path, rc_compare, rc_suite, expected):
    import openhound_sccm.integration as integration

    calls = []

    def compare(graph, baseline, *, out_path, log):
        calls.append("compare")
        out_path.write_text('{}')
        return rc_compare

    def suite(graph, report, *, privileged):
        assert privileged is False
        calls.append("suite")
        report.write_text('{}')
        return rc_suite

    monkeypatch.setattr(integration, "compare_to_zip", compare)
    monkeypatch.setattr(main, "_run_integration_suite", suite)
    code = main._run_graph_checks(tmp_path / "graph", tmp_path, "run", compare_to_zip=tmp_path / "baseline.zip", privileged=False)
    assert code == expected and calls == ["compare", "suite"]


def test_exception_in_comparison_still_runs_the_requested_suite(monkeypatch, tmp_path):
    import openhound_sccm.integration as integration
    calls = []

    def fail(*args, **kwargs):
        raise ValueError("Unreadable comparison input")

    def suite(graph, report, *, privileged):
        calls.append(privileged)
        report.write_text('{}')
        return 0

    monkeypatch.setattr(integration, "compare_to_zip", fail)
    monkeypatch.setattr(main, "_run_integration_suite", suite)
    assert main._run_graph_checks(tmp_path / "graph", tmp_path, "run", compare_to_zip=tmp_path / "missing.zip", privileged=True) == 1
    assert calls == [True]
    assert (tmp_path / "compare-run.json").exists()
    assert (tmp_path / "integration_results-run.json").exists()
