# Investigation: restored command-line target reader

## Finding

An earlier code check found a call to `_cli_seed_targets` without a definition
in `main.py`. The file was changing independently during the role-assignment
work. The owner requested a separate investigation rather than including a CLI
repair in that change.

At investigation time, the function was present again. Its implementation
matches the committed version. No edits to collector CLI code were necessary
or made during this investigation.

## What the function does

The function in [main.py](../../src/openhound_sccm/main.py) reads computer names
from the command line and an optional file. It trims surrounding whitespace and
ignores blank entries. The collection command then passes each name through
`register_target`, which applies the existing target restrictions and duplicate
handling. The function itself performs no network collection.

## Checks performed

Direct checks passed for:

- No names or file: an empty list.
- Comma-separated names, including extra whitespace and blank entries.
- A file containing names, blank lines, and surrounding whitespace.
- Names and a file together: all supplied names are retained.
- Current function compared with the committed copy: identical implementation.
- `main.py` checked before and after investigation: unchanged by these checks.

The focused warning, role-assignment, and command-line test selection passed
27 tests. Whole-tree Ruff and mypy passed after the restoration, with 64 source
files checked by mypy. No lab collection or service changes were needed here.

Evidence is saved in
`C:\Users\domainadmin\.tmp\cmbp-role-warning-20261026\cli-investigation.json`.
The checked `main.py` SHA-256 was
`8b5b7e7d520d326e3952795cfc1d04ad4ab25389226b67bcc26f902660b97c76`.
The input file used by the checks is `computer-targets.txt` in that directory.

This closes the missing-function finding for the checked working tree. It does
not resolve the separate installed shared-package mismatch; the owner explicitly
left that for follow-up. Tests used the matching local shared checkout through
`PYTHONPATH`, without editing or installing that repository.

## Recheck

From the repository root, in a fresh PowerShell window using the existing local
development environment:

```powershell
$env:UV_PROJECT_ENVIRONMENT = 'C:\Users\domainadmin\.codex\venvs\configmanbearpig-pz'
$env:PYTHONPATH = 'C:\Users\domainadmin\ConfigManBearPig\src;C:\Users\domainadmin\openhound-collector-common\src'
uv run --no-sync --offline python -B -m pytest tests/integration_cli_flags_test.py -q
uv run --no-sync --offline python -B -m ruff check --no-cache src tests
uv run --no-sync --offline python -B -m mypy src/openhound_sccm
```

The command-line tests check the public options; `cli-investigation.json`
records the separate direct checks of this helper's input handling.

## Optional documentation commit

There is no CLI code fix to commit. If retaining this investigation separately
is useful, review this document and run:

```powershell
git add -- docs/changes/2026-10-26-cli-seed-investigation.md
git diff --cached
git commit -m "Document verification of restored CLI target reader"
```

These commands are for the owner. Nothing was staged, committed, or pushed.
