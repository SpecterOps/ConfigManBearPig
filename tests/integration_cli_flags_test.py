"""Offline tests for the SCCM collect `--run-integration-tests` / `--compare-to-zip` flags.

Run from the repository root:
    uv run pytest tests\\integration_cli_flags_test.py -v
"""
import os
import re
from pathlib import Path
from unittest import mock

import typer
from typer.testing import CliRunner

from openhound_sccm import main
from openhound_sccm.main import collect_sccm

runner = CliRunner()

# The escape sequences rich emits for bold/dim/colour. Stripped rather than
# suppressed: NO_COLOR turns off the colours but leaves the bold and dim codes,
# and either one landing mid-name is enough to break a search for an option.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Wide enough that no option name folds. Below 75 columns rich breaks the long
# names ("--run-integration-tests") across two lines, which fails the assertions
# below for a reason that has nothing to do with the flag being registered.
_RENDER_WIDTH = "100"


def _help_output():
    """Render ``collect sccm --help`` as plain text, at a fixed width.

    collect_sccm is a plain function carrying typer.Option defaults, not itself a
    Typer app, so wrap it the same way cli_option_panels_test.py does to drive a
    real --help render.

    The render is normalised before it is returned, because searching a raw one
    for a flag name is not safe. Typer forces colour whenever GITHUB_ACTIONS,
    FORCE_COLOR or PY_COLORS is set (see typer/rich_utils.py), and the styling
    lands *inside* the option name -- so ``"--compare-to-zip" in out`` misses a
    flag that is plainly there on screen. Every GitHub runner sets
    GITHUB_ACTIONS, which is precisely how these assertions passed on a developer
    machine and went red the moment this file entered the CI list.

    COLUMNS is the width lever rather than typer's own TERMINAL_WIDTH: that one
    is read once at import time, so setting it here would be silently too late.
    """
    app = typer.Typer()
    app.command()(collect_sccm)
    with mock.patch.dict(os.environ, {"COLUMNS": _RENDER_WIDTH}):
        result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    return _ANSI.sub("", result.output)


def test_testing_flags_registered_in_help():
    out = _help_output()
    assert "--run-integration-tests" in out
    assert "--compare-to-zip" in out
    assert "Testing" in out  # rich_help_panel


def test_compare_to_zip_takes_a_path():
    out = _help_output()
    assert "--compare-to-zip" in out


# --- privilege selection (con-6677, superseded by --integration-privilege) ----
#
# --integration-lowpriv was a boolean the operator had to remember, and forgetting
# it on a low-privilege run asserted SCCM-admin-only cases that could never have
# been collected. The three-way flag replaces it: `low` is that boolean, `high`
# forces the full set for a partially-privileged collection, and `auto` -- the
# default -- reads the run's own AdminService/WMI row counts.

def test_integration_privilege_registered_in_help():
    out = _help_output()
    assert "--integration-privilege" in out
    assert "Testing" in out  # same rich_help_panel as the other testing flags


def test_superseded_boolean_flag_is_gone():
    assert "--integration-lowpriv" not in _help_output()


# --- guards on the render itself ---------------------------------------------
#
# Every assertion above searches plain text for an option name, which only holds
# because _help_output() normalises the render. These two reproduce the exact
# conditions that broke it, so dropping either normalisation fails here on any
# machine instead of only on a CI runner.
#
# Note the negative assertion above is the one with teeth removed by styling: a
# name that cannot be found when it is present cannot be found when it is absent
# either, so without the strip that test would pass no matter what.

def test_flags_are_found_when_colour_is_forced(monkeypatch):
    # rich checks for the *presence* of FORCE_COLOR, not its value -- setting it
    # to "0" forces colour on just as much as "1" does.
    monkeypatch.setenv("FORCE_COLOR", "1")
    out = _help_output()
    assert "--run-integration-tests" in out
    assert "--integration-privilege" in out


def test_flags_are_found_in_a_narrow_terminal(monkeypatch):
    monkeypatch.setenv("COLUMNS", "60")
    out = _help_output()
    assert "--run-integration-tests" in out
    assert "--integration-privilege" in out


def test_suite_translates_privileged_to_the_harness(monkeypatch):
    """``privileged`` reaches the harness verbatim -- no double negative in between."""
    import openhound_sccm.integration as integ
    seen = {}
    monkeypatch.setattr(integ, "run_integration_tests",
                        lambda graph_dir, **kw: seen.update(kw) or 0)
    rc = main._run_integration_suite(Path("graph"), Path("results.json"), privileged=False)
    assert rc == 0
    assert seen["privileged"] is False
