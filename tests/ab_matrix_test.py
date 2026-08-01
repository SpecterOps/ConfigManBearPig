"""Cell planning and argv construction for dev/ab_matrix.py.

dev/ is not an importable package, so the module is loaded by path. Nothing here
runs a collection -- only the pure planning functions are exercised.
"""
import importlib.util
import pathlib
import sys

import pytest

_PATH = pathlib.Path(__file__).resolve().parents[1] / "dev" / "ab_matrix.py"
_SPEC = importlib.util.spec_from_file_location("ab_matrix", _PATH)
assert _SPEC and _SPEC.loader
ab = importlib.util.module_from_spec(_SPEC)
# Register before exec: @dataclass resolves a class's annotations by looking its
# module up in sys.modules, and a module built with module_from_spec is not there
# until you put it there -- the lookup returns None and the decorator raises.
sys.modules["ab_matrix"] = ab
_SPEC.loader.exec_module(ab)


def test_plan_cells_is_identities_times_flag_states():
    cells = ab.plan_cells(["lowpriv", "domainadmin"])
    assert len(cells) == 4
    assert [c.tag for c in cells] == [
        "lowpriv-pe-on", "lowpriv-pe-off",
        "domainadmin-pe-on", "domainadmin-pe-off",
    ]
    assert [c.possible_edges for c in cells] == [True, False, True, False]


def test_collect_argv_always_passes_clean_and_run_all():
    cell = ab.plan_cells(["lowpriv"])[0]
    argv = ab.collect_argv(cell, "mayyhem.com", "dc.mayyhem.com", "pw", pathlib.Path("out"))
    assert "--clean" in argv            # non-negotiable: dlt APPENDS without it
    assert "--run-all" in argv
    assert "--run-integration-tests" in argv
    assert "--disable-possible-edges" not in argv        # pe-on cell


def test_collect_argv_disables_possible_edges_on_the_off_cell():
    cell = ab.plan_cells(["lowpriv"])[1]
    argv = ab.collect_argv(cell, "mayyhem.com", "dc.mayyhem.com", "pw", pathlib.Path("out"))
    assert "--disable-possible-edges" in argv


def test_collect_argv_omits_credentials_for_the_current_context():
    """password=None selects integrated auth -- how the domainadmin cell runs."""
    cell = ab.plan_cells(["domainadmin"])[0]
    argv = ab.collect_argv(cell, "mayyhem.com", "dc.mayyhem.com", None, pathlib.Path("out"))
    assert "-u" not in argv and "-p" not in argv


def test_collect_argv_pins_the_privilege_mode_per_identity():
    """auto would read row counts; an A/B must force the mode so both sides are comparable."""
    low = ab.collect_argv(ab.plan_cells(["lowpriv"])[0], "d", "dc", "pw", pathlib.Path("o"))
    assert "--integration-privilege" in low
    assert low[low.index("--integration-privilege") + 1] in ("low", "high", "auto")


def test_compare_argv_puts_the_baseline_first():
    cell = ab.plan_cells(["lowpriv"])[0]
    argv = ab.compare_argv(cell, pathlib.Path("baselines"), pathlib.Path("out"))
    assert argv[0] == "openhound-compare"
    assert argv[1].endswith("lowpriv-pe-on.zip")          # baseline
    assert argv[2].endswith("graph")                       # candidate


def test_assert_empty_rejects_a_used_directory(tmp_path):
    used = tmp_path / "used"
    used.mkdir()
    (used / "stale.jsonl.gz").write_text("x", encoding="utf-8")
    with pytest.raises(SystemExit):
        ab.assert_empty(used)


def test_assert_empty_accepts_a_missing_or_empty_directory(tmp_path):
    ab.assert_empty(tmp_path / "does-not-exist")
    (tmp_path / "empty").mkdir()
    ab.assert_empty(tmp_path / "empty")


def test_password_for_prefers_the_identity_specific_variable(monkeypatch):
    monkeypatch.setenv("SCCM_LAB_PASSWORD", "generic")
    monkeypatch.setenv("SCCM_LAB_PASSWORD_LOWPRIV", "specific")
    assert ab.password_for("lowpriv") == "specific"
    assert ab.password_for("domainadmin") == "generic"


def test_password_for_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv("SCCM_LAB_PASSWORD", raising=False)
    monkeypatch.delenv("SCCM_LAB_PASSWORD_DOMAINADMIN", raising=False)
    assert ab.password_for("domainadmin") is None
