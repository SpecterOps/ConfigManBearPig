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
def test_combined_exit_code(rc_compare, rc_suite, expected):
    assert main._combined_testing_exit_code(rc_compare, rc_suite) == expected
