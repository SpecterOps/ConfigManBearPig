"""
Phase orchestration pipeline for ConfigManBearPig.

Translated from PowerShell phase management functions:
- Get-SelectedPhases (lines 290-305)
- Ensure-GlobalPhaseStatus / Ensure-PerHostPhaseStatus (lines 307-356)
- Invoke-DiscoveryPipeline (lines 358-417)

Enhanced with ThreadPoolExecutor for parallel per-host collection.
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

logger = logging.getLogger("ConfigManBearPig")

# Phase definitions matching PowerShell (lines 276-288)
PHASES_ONCE = ["LDAP", "Local", "DNS", "DHCP"]
PHASES_PER_HOST = ["RemoteRegistry", "MSSQL", "AdminService", "WMI", "HTTP", "SMB"]
ALL_PHASES = PHASES_ONCE + PHASES_PER_HOST


def get_selected_phases(methods: str) -> list[str]:
    """
    Parse collection methods string into list of phases.

    Translated from PowerShell Get-SelectedPhases (lines 290-305).

    Args:
        methods: Comma-separated method names (e.g., "LDAP,DNS,AdminService")
                 or "All" for all phases

    Returns:
        List of selected phase names
    """
    methods_split = [m.strip().upper() for m in methods.split(",") if m.strip()]

    if not methods_split or "ALL" in methods_split or "" in methods_split:
        return list(ALL_PHASES)

    selected = []
    valid_phases_upper = {p.upper(): p for p in ALL_PHASES}

    for method in methods_split:
        if method in valid_phases_upper:
            selected.append(valid_phases_upper[method])
        else:
            logger.error(f"Unknown collection method: {method}")

    return selected


class PipelineOrchestrator:
    """
    Orchestrates collection phases: once-phases run globally,
    per-host phases run for each discovered target.

    Translated from PowerShell Invoke-DiscoveryPipeline (lines 358-417).

    Enhanced with parallel per-host collection via ThreadPoolExecutor.
    When max_workers=1 (default), behavior is identical to the original
    sequential pipeline for output parity with PowerShell.
    """

    def __init__(self, max_workers: int = 1):
        # Phase status tracking
        self._global_phase_status: dict[str, str] = {}
        self._per_host_phase_status: dict[str, dict[str, str]] = {}
        self._status_lock = threading.Lock()

        # Phase handlers: phase_name -> callable
        self._once_handlers: dict[str, Callable] = {}
        self._per_host_handlers: dict[str, Callable] = {}

        # Parallelism configuration
        self._max_workers = max(1, max_workers)

    def register_once_handler(self, phase: str, handler: Callable) -> None:
        """Register a handler for a once-phase (LDAP, Local, DNS, DHCP)."""
        self._once_handlers[phase] = handler

    def register_per_host_handler(self, phase: str, handler: Callable) -> None:
        """Register a handler for a per-host phase."""
        self._per_host_handlers[phase] = handler

    def _process_target(
        self,
        target: Any,
        per_host_phases: list[str],
    ) -> None:
        """
        Process all per-host phases for a single target.

        Runs phases sequentially within a target to preserve
        inter-phase dependencies (e.g., RemoteRegistry before MSSQL).
        """
        hostname = target.hostname

        for phase in per_host_phases:
            if phase in self._per_host_handlers:
                with self._status_lock:
                    if hostname not in self._per_host_phase_status:
                        self._per_host_phase_status[hostname] = {}
                    if phase not in self._per_host_phase_status[hostname]:
                        self._per_host_phase_status[hostname][phase] = "NotStarted"
                    status = self._per_host_phase_status[hostname][phase]

                if status == "Complete":
                    logger.debug(f"Skipping {phase} for {hostname} (already complete)")
                    continue

                logger.info(f"Running {phase} on {hostname}")
                with self._status_lock:
                    self._per_host_phase_status[hostname][phase] = "InProgress"
                try:
                    self._per_host_handlers[phase](target)
                    with self._status_lock:
                        self._per_host_phase_status[hostname][phase] = "Complete"
                except Exception as e:
                    with self._status_lock:
                        self._per_host_phase_status[hostname][phase] = "Failed"
                    logger.error(f"Phase {phase} failed for {hostname}: {e}")

        target.collected = True

    def run(
        self,
        selected_phases: list[str],
        get_targets: Callable,
    ) -> None:
        """
        Execute the discovery pipeline.

        Translated from PowerShell Invoke-DiscoveryPipeline (lines 358-417).

        1. Run once-phases (LDAP, Local, DNS, DHCP) in order
        2. For each target, run per-host phases in order
           - With max_workers > 1, multiple targets are processed in parallel
        3. After first pass, check for new targets to feed per-host phases

        Args:
            selected_phases: List of phases to run
            get_targets: Callable returning list of current targets
        """
        # Split into once and per-host
        once_phases = [p for p in selected_phases if p in PHASES_ONCE]
        per_host_phases = [p for p in selected_phases if p in PHASES_PER_HOST]

        # Run once-phases (always sequential)
        for phase in once_phases:
            if phase in self._once_handlers:
                self._ensure_global_status(phase)
                if self._global_phase_status[phase] == "Complete":
                    logger.debug(f"Skipping already-complete phase: {phase}")
                    continue

                logger.info(f"Running once-phase: {phase}")
                self._global_phase_status[phase] = "InProgress"
                try:
                    self._once_handlers[phase]()
                    self._global_phase_status[phase] = "Complete"
                    logger.info(f"Phase {phase} completed successfully")
                except Exception as e:
                    self._global_phase_status[phase] = "Failed"
                    logger.error(f"Phase {phase} failed: {e}")

        # Run per-host phases for each target
        if not per_host_phases:
            return

        targets = get_targets()
        if not targets:
            logger.warning("No targets available for per-host collection")
            return

        logger.info(f"Running per-host phases on {len(targets)} targets")

        if self._max_workers <= 1:
            # Sequential mode (default) — identical to original behavior
            for target in targets:
                logger.info(f"Processing target: {target.hostname}")
                self._process_target(target, per_host_phases)
        else:
            # Parallel mode — process multiple targets concurrently
            start_time = time.time()
            completed_count = 0
            total_count = len(targets)

            with ThreadPoolExecutor(
                max_workers=self._max_workers,
                thread_name_prefix="cmbp-host",
            ) as executor:
                futures = {
                    executor.submit(self._process_target, target, per_host_phases): target
                    for target in targets
                }

                for future in as_completed(futures):
                    target = futures[future]
                    completed_count += 1
                    try:
                        future.result()  # Propagate exceptions
                        elapsed = time.time() - start_time
                        logger.info(
                            f"Completed {target.hostname} "
                            f"[{completed_count}/{total_count}] "
                            f"({elapsed:.1f}s elapsed)"
                        )
                    except Exception as e:
                        logger.error(
                            f"Target {target.hostname} failed: {e} "
                            f"[{completed_count}/{total_count}]"
                        )

        # Check for new targets discovered during per-host phases
        new_targets = [t for t in get_targets() if not t.collected]
        if new_targets:
            logger.info(f"Discovered {len(new_targets)} new targets during collection")

            if self._max_workers <= 1:
                for target in new_targets:
                    logger.info(f"Processing newly discovered target: {target.hostname}")
                    self._process_target(target, per_host_phases)
            else:
                with ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix="cmbp-new",
                ) as executor:
                    futures = {
                        executor.submit(self._process_target, target, per_host_phases): target
                        for target in new_targets
                    }
                    for future in as_completed(futures):
                        target = futures[future]
                        try:
                            future.result()
                            logger.info(f"Completed new target: {target.hostname}")
                        except Exception as e:
                            logger.error(f"New target {target.hostname} failed: {e}")

    def _ensure_global_status(self, phase: str) -> None:
        """Initialize global phase status if not set."""
        if phase not in self._global_phase_status:
            self._global_phase_status[phase] = "NotStarted"

    def _ensure_per_host_status(self, hostname: str, phase: str) -> None:
        """Initialize per-host phase status if not set."""
        if hostname not in self._per_host_phase_status:
            self._per_host_phase_status[hostname] = {}
        if phase not in self._per_host_phase_status[hostname]:
            self._per_host_phase_status[hostname][phase] = "NotStarted"
