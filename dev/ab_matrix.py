"""A/B matrix runner: collect the same lab under several identities and both
possible-edge states, then diff each result against its saved baseline.

Replaces the four PowerShell drivers that lived in the OpenHound monorepo under
sccm/tests/live-comparison/. Those hardcoded one desktop's absolute paths and a
literal password; this takes both as parameters and reads credentials only from the
environment.

Credentials: SCCM_LAB_PASSWORD_<IDENTITY> (uppercased), falling back to
SCCM_LAB_PASSWORD. An identity with neither runs with integrated auth as the current
logon context -- which is how the domainadmin cell is meant to run.

    uv run python dev/ab_matrix.py \
        --identity lowpriv:low --identity domainadmin:high \
        --domain mayyhem.com --dc dc.mayyhem.com \
        --baselines ./baselines --out-root ./ab-20260801

Baselines are one labelled zip per cell: baselines/<identity>-pe-on.zip and
baselines/<identity>-pe-off.zip. openhound-compare accepts a zip or a directory on
either side, so a convert output directory works equally well.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
from dataclasses import dataclass

FLAG_STATES = ((True, "pe-on"), (False, "pe-off"))
PRIVILEGE_MODES = ("auto", "high", "low")


@dataclass(frozen=True)
class Cell:
    identity: str
    possible_edges: bool
    tag: str
    privilege: str = "auto"


def parse_identity(spec: str) -> tuple[str, str]:
    """Split ``name`` or ``name:mode`` into (identity, privilege mode).

    Pinning the mode per identity matters for an A/B: --integration-privilege
    defaults to `auto`, which reads the run's AdminService/WMI row counts. That is
    the right default for a one-off run, but in a matrix it means the asserted case
    set can change between runs -- so a diff would reflect detection flipping rather
    than the code change under test. Naming the mode makes each cell deterministic.
    """
    name, _, mode = spec.partition(":")
    mode = mode or "auto"
    if mode not in PRIVILEGE_MODES:
        sys.exit(f"ab_matrix: unknown privilege mode {mode!r} in --identity {spec!r}; "
                 f"expected one of {', '.join(PRIVILEGE_MODES)}")
    if not name:
        sys.exit(f"ab_matrix: --identity {spec!r} has no identity name")
    return name, mode


def plan_cells(identity_specs: list[str]) -> list[Cell]:
    """Every (identity, possible-edge state) pair, in a stable order."""
    cells = []
    for spec in identity_specs:
        identity, privilege = parse_identity(spec)
        for on, label in FLAG_STATES:
            cells.append(Cell(identity, on, f"{identity}-{label}", privilege))
    return cells


def password_for(identity: str) -> str | None:
    """Per-identity password from the environment, or None for integrated auth."""
    specific = os.environ.get(f"SCCM_LAB_PASSWORD_{identity.upper()}")
    if specific:
        return specific
    return os.environ.get("SCCM_LAB_PASSWORD") or None


def collect_argv(cell: Cell, domain: str, dc: str, password: str | None,
                 out_dir: pathlib.Path) -> list[str]:
    """The `openhound collect sccm` command line for one cell.

    --clean is not optional. Re-running into a used directory does not overwrite raw
    data: dlt appends a load package, and preprocess reads every .jsonl.gz per table,
    so the previous run's rows are unioned into this run's graph. Measured 2026-07-28:
    11 of 24 raw tables held rows from two different dates, with exit code 0 and fresh
    graph timestamps hiding it completely.
    """
    argv = ["openhound", "collect", "sccm", str(out_dir),
            "-m", "All", "-d", domain, "--dc", dc,
            "--clean", "--run-all", "--run-integration-tests",
            "--integration-privilege", cell.privilege]
    if password is not None:
        argv += ["-u", cell.identity, "-p", password]
    if not cell.possible_edges:
        argv.append("--disable-possible-edges")
    return argv


def compare_argv(cell: Cell, baselines: pathlib.Path, out_dir: pathlib.Path) -> list[str]:
    """Baseline first, candidate second -- the orientation openhound-compare expects."""
    return ["openhound-compare",
            str(baselines / f"{cell.tag}.zip"),
            str(out_dir / "graph"),
            "--json", str(out_dir / "compare.json")]


def assert_empty(path: pathlib.Path) -> None:
    """Refuse to reuse a directory that already holds a collection."""
    if path.exists() and any(path.iterdir()):
        sys.exit(f"ab_matrix: {path} is not empty. Every cell needs a fresh directory -- "
                 f"reusing one unions the previous run's rows into this run's graph.")


def _run(argv: list[str], log_path: pathlib.Path) -> int:
    """Run a command, writing combined output to a per-cell log. Returns its code."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as fh:
        proc = subprocess.run(argv, stdout=fh, stderr=subprocess.STDOUT, text=True)
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="ab_matrix",
        description="Collect the lab under several identities and both possible-edge "
                    "states, then diff each result against its saved baseline.")
    p.add_argument("--identity", action="append", required=True, dest="identities",
                   metavar="NAME[:auto|high|low]",
                   help="Repeatable. One collection pair per identity. The optional "
                        "suffix pins --integration-privilege for that identity's cells; "
                        "without it, each run detects its own level.")
    p.add_argument("--domain", required=True)
    p.add_argument("--dc", required=True)
    p.add_argument("--baselines", type=pathlib.Path, required=True,
                   help="Directory of <identity>-<pe-on|pe-off>.zip baselines.")
    p.add_argument("--out-root", type=pathlib.Path, required=True,
                   help="Parent directory for this run's per-cell output.")
    p.add_argument("--with-cmbp", action="store_true",
                   help="Also run the deprecated ConfigManBearPig.ps1 per cell "
                        "(Windows only; expects the shell to already be running as "
                        "the target identity).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the planned commands and exit without running anything.")
    args = p.parse_args(argv)

    cells = plan_cells(args.identities)
    results: list[tuple[str, int, int]] = []
    worst = 0

    for cell in cells:
        out_dir = args.out_root / cell.tag
        assert_empty(out_dir)
        collect = collect_argv(cell, args.domain, args.dc,
                               password_for(cell.identity), out_dir)
        compare = compare_argv(cell, args.baselines, out_dir)

        if args.dry_run:
            # Never print the collect argv directly -- it carries -p <password>.
            print(f"[{cell.tag}] collect  -> {out_dir} "
                  f"(--integration-privilege {cell.privilege})")
            print(f"[{cell.tag}] compare  -> {' '.join(compare)}")
            continue

        if args.with_cmbp:
            from _ab_cmbp import run_cmbp          # imported only on this path
            run_cmbp(cell, args.domain, args.dc, args.out_root)

        rc_collect = _run(collect, out_dir / "_collect.log")
        rc_compare = _run(compare, out_dir / "_compare.log")
        results.append((cell.tag, rc_collect, rc_compare))
        worst = max(worst, 1 if (rc_collect or rc_compare) else 0)

    if args.dry_run:
        return 0

    print("\n===== A/B MATRIX =====")
    for tag, rc_c, rc_d in results:
        print(f"{tag:<24} collect_exit={rc_c}  compare_exit={rc_d}")
    print(f"\nWorst outcome: {worst}. compare_exit=1 means that cell lost content "
          f"its baseline had; see <cell>/compare.json.")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
