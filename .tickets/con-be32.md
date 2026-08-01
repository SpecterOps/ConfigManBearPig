---
id: con-be32
status: closed
deps: []
links: []
created: 2026-08-01T21:46:07Z
type: task
priority: 2
---

# CI red: --help substring tests break under forced colour and narrow terminals -type bug -priority 1 -tags testing,ci,cli,help -assignee cthompson -description The three --run-integration-tests / --compare-to-zip / --integration-privilege help assertions in tests/integration_cli_flags_test.py search the rendered --help text for a literal flag name. Typer forces colour whenever GITHUB_ACTIONS, FORCE_COLOR or PY_COLORS is set (typer/rich_utils.py), and the styling lands inside the option name, so the search misses a flag that is plainly on screen. Every GitHub runner sets GITHUB_ACTIONS, so CI went red at 99596fd -- the commit that first added this file to the CI list. The flags themselves are correctly registered; this is a test defect only. A second independent trigger: below 75 columns the long names fold across two lines and the same search fails. -acceptance The CI list is green under GITHUB_ACTIONS=true and at a narrow terminal width; guards exist that fail if either normalisation is removed.

## Notes

**2026-08-01T21:46:24Z**

FIXED. Both help-driving test files now normalise the render before asserting: strip the escape sequences (NO_COLOR is not enough -- the codes here are bold and dim, which are attributes rather than colours, and rich treats the mere PRESENCE of FORCE_COLOR as true, so FORCE_COLOR=0 still forces it) and pin the width via COLUMNS. COLUMNS rather than typer's TERMINAL_WIDTH because that one is read once at import time and would be frozen before a test could set it.

Two guards added in integration_cli_flags_test.py that reproduce each trigger, so removing either normalisation fails on any machine rather than only on a runner. Both proven load-bearing: with the ANSI strip disabled the flags are missing, with the width pin dropped to 55 they are missing, with the fix in place neither is.

cli_option_panels_test.py got the same normalisation for a different reason -- it was PASSING under colour, but its test_help_omits_removed_flags asserts a name is ABSENT, and a name that cannot be found when present cannot be found when absent either. That test was passing without checking anything on every coloured run. Verified now discriminating: --dc (present) is found, --machine-name (removed) is not.

VERIFICATION: ruff clean; mypy 0/63 files; CI list 63 passed under GITHUB_ACTIONS=true and at COLUMNS=55; full suite 974 passed / 5 skipped under GITHUB_ACTIONS=true. No src/ change -- the flags were always registered correctly.
