"""The --with-cmbp half of ab_matrix: drive the deprecated ConfigManBearPig.ps1.

Kept in its own module so the default 4-cell path never imports it. Windows-only --
CMBP.ps1 has no username/password parameter and authenticates as whatever context it
runs in.

There is deliberately no runas /netonly shim here. `runas` reads its password from an
interactive console and cannot be driven from a pipe, which is exactly why the old
harness kept Run-AsNetOnly.ps1 as a separate launcher rather than calling it inline.
Run ab_matrix.py --with-cmbp from a shell already launched under the target identity,
as that harness required.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

CMBP = pathlib.Path(__file__).resolve().parents[1] / "powershell_deprecated" / "ConfigManBearPig.ps1"


def run_cmbp(cell, domain: str, dc: str, out_root: pathlib.Path) -> int:
    """Run CMBP.ps1 for one cell into its own empty directory.

    -MemoryThresholdPercent 100 disables CMBP's self-imposed memory guard: a lab host
    near its ceiling from hypervisor ballooning otherwise aborts before the
    AdminService/HTTP phases. A real OOM has never been observed.
    """
    if sys.platform != "win32":
        raise RuntimeError("--with-cmbp requires Windows (PowerShell + the current "
                           "logon context supplies CMBP's identity).")
    if not CMBP.exists():
        raise FileNotFoundError(f"CMBP.ps1 not found at {CMBP}")

    out_dir = out_root / f"cmbp-{cell.tag}"
    out_dir.mkdir(parents=True, exist_ok=True)
    ps = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(CMBP),
        "-CollectionMethods", "All", "-Domain", domain, "-DomainController", dc,
        "-MemoryThresholdPercent", "100",
        "-LogFile", str(out_dir / "cmbp.log"),
    ]
    if not cell.possible_edges:
        ps.append("-DisablePossibleEdges")
    with (out_dir / "_console.txt").open("w", encoding="utf-8") as fh:
        return subprocess.run(ps, cwd=out_dir, stdout=fh,
                              stderr=subprocess.STDOUT, text=True).returncode
