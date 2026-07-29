"""SCCM integration-test wiring: assemble mayyhem fixtures + the shared engine."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable

from openhound_collector_common.integration_testing.compare import compare_graphs
from openhound_collector_common.integration_testing.graph import load_graph
from openhound_collector_common.integration_testing.results import write_results_json  # noqa: F401 (re-export)
from openhound_collector_common.integration_testing.runner import run_suite

from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES
from openhound_sccm.integration.fixtures.nodes import MAYYHEM_INVARIANTS, MAYYHEM_NODE_CASES

logger = logging.getLogger(__name__)

# schema_SCCM.json ships inside the package alongside this subpackage:
# src/openhound_sccm/integration/__init__.py -> parents[0]=integration, [1]=openhound_sccm.
# Must stay a pathlib.Path — run_suite() types schema_path as `Path | None`.
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema_SCCM.json"


def run_integration_tests(graph_dir: Path, results_path: Path | None = None,
                          log: Callable[[str], None] = logger.info,
                          privileged: bool = True) -> int:
    """Load a collected graph and run it against the mayyhem.com fixtures + schema coverage.

    *privileged* describes the COLLECTION the graph came from, not the fixtures. The
    default True preserves the historical behaviour (assert every case). Pass False for a
    graph collected without AdminService/WMI: cases marked ``requires_privilege`` are then
    skipped, because the Tier-D RBAC families (SCCM_FullAdministrator / IsAssigned /
    IsMappedTo / AllPermissions and the admin-user, security-role and collection nodes) are
    structurally uncollectable at low privilege -- asserting them there would report a
    failure for behaving correctly. Everything else is still asserted, so a low-priv run
    remains a real gate rather than a weakened one.

    Returns a process-friendly exit code: 1 if any case failed, else 0.
    """
    graph = load_graph(graph_dir)
    edge_cases, node_cases = MAYYHEM_EDGE_CASES, MAYYHEM_NODE_CASES
    if not privileged:
        # getattr keeps this working for any case that predates the flag.
        edge_cases = [c for c in edge_cases if not getattr(c, "requires_privilege", False)]
        node_cases = [c for c in node_cases if not getattr(c, "requires_privilege", False)]
        log(f"low-privilege mode: skipping "
            f"{len(MAYYHEM_EDGE_CASES) - len(edge_cases)} edge and "
            f"{len(MAYYHEM_NODE_CASES) - len(node_cases)} node case(s) that require "
            f"AdminService/WMI collection")
    else:
        logger.debug("privileged mode: asserting all %d edge and %d node cases",
                     len(edge_cases), len(node_cases))
    summary = run_suite(graph, edge_cases, node_cases,
                        invariants=MAYYHEM_INVARIANTS, schema_path=SCHEMA_PATH,
                        results_path=results_path, log=log)
    return 1 if summary.failed > 0 else 0


def compare_to_zip(graph_dir: Path, zip_path: Path, out_path: Path | None = None,
                   log: Callable[[str], None] = logger.info) -> int:
    """Diff a freshly-collected graph against a previously collected OpenGraph zip.

    Informational only -- always returns 0 so a drift report never fails a CI run.
    """
    a = load_graph(graph_dir)
    b = load_graph(zip_path)
    report = compare_graphs(a, b)
    report.render(log=log)
    if out_path is not None:
        Path(out_path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return 0  # informational: never fails the process
