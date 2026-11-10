"""Track missing requested reads without stopping other reachable work."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from time import monotonic
from typing import Any
from collections.abc import Iterator

from openhound_collector_common.collection.errors import FatalCollectionError
from openhound_collector_common.collection.outcomes import OperationResult, RunResult, TargetResult

from .context import SourceContext
from .log_context import get_logger
from .models.target_entry import TargetEntry
from .phased_pipeline import Phase

logger = get_logger(__name__)


def unrecovered_operations(entry: TargetEntry) -> list[OperationResult]:
    """A completed read through the other provider transport recovers the same read."""
    missing = []
    for result in entry.operation_results.values():
        if result.state != "failed":
            continue  # Completed or intentional skipped reads are not missing work.
        transport, separator, name = result.operation.partition(".")
        if not separator and transport == "AdminService" and "WMI" in entry.completed_phases:
            logger.debug("Failed AdminService phase on %s was recovered by complete WMI collection", entry.hostname)
            continue
        if separator and transport in ("AdminService", "WMI"):
            alternative = ("WMI" if transport == "AdminService" else "AdminService") + "." + name
            recovered = entry.operation_results.get(alternative)
            if recovered is not None and recovered.state == "completed":
                logger.debug("%s on %s was recovered by %s", result.operation, entry.hostname, alternative)
                continue
        # Ordinary phase failures have no equivalent transport to recover them.
        missing.append(result)
    return missing


def observe_phase(phase: Phase) -> Phase:
    """Wrap an existing phase with completion records; the engine still owns scheduling."""
    def run(target: str, context: SourceContext) -> Iterator[tuple[str, dict[str, Any]]]:
        entry = context.target_hosts_by_hostname.get(target.lower())
        started = monotonic()
        row_count = 0
        rows = None
        try:
            rows = iter(phase.run(target, context))
            for table, row in rows:
                row_count += 1
                yield table, row
        except FatalCollectionError:
            logger.error("%s on %s requires collection to stop", phase.name, target)
            raise
        except Exception:
            if entry is not None:
                entry.operation_results[phase.name] = OperationResult(
                    phase.name, "failed", None, int((monotonic() - started) * 1000),
                    "phase_read_failed",
                )
            # The engine logs the error and continues the remaining phases.
            logger.warning("%s on %s left requested work incomplete", phase.name, target)
            raise
        else:
            if entry is not None:
                entry.operation_results[phase.name] = OperationResult(
                    phase.name, "completed", row_count, int((monotonic() - started) * 1000),
                )
            # Provider operation records separately identify partial successful phases.
            logger.debug("%s on %s saved %d rows", phase.name, target, row_count)
        finally:
            try:
                close = getattr(rows, "close", None)
                if callable(close):
                    close()
                # A plain iterator owns no provider cleanup to perform.
            finally:
                if entry is not None:
                    entry.saved_row_count += row_count
                # A failed attempt may still have yielded usable rows before failing.

    return Phase(phase.name, phase.streams, run)


def save_run_status(context: SourceContext, output: Path, run_id: str) -> RunResult:
    """Save non-secret operation outcomes and return the collector's final-status input."""
    targets = []
    attempts = []
    for entry in context.target_hosts_snapshot():
        results = tuple(entry.operation_results.values())
        missing = unrecovered_operations(entry)
        state = "partial" if missing else "completed" if results else "skipped"
        targets.append(TargetResult(
            entry.hostname, state, entry.saved_row_count,
            operations_completed=sum(result.state == "completed" for result in results),
            operations_failed=len(missing),
        ))
        for result in results:
            attempts.append({"target": entry.hostname, **result.as_row()})
        for result in missing:
            logger.error("Missing requested read on %s: %s (%s)", entry.hostname, result.operation, result.failure_category)
    run = RunResult(run_id, tuple(targets))
    path = output / f"collection_status_{run_id}.json"
    path.write_text(json.dumps({**asdict(run), "operations": attempts}, indent=2) + "\n", encoding="utf-8")
    logger.info("Collection completion record: %s", path)
    return run
