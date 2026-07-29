"""The phased-collection engine.

This module defines:

* :class:`Phase` — the read-only description of one collection step;
* :func:`run_one_target` — run a single target through its phases in order,
  routing each row to its named stream and isolating per-phase failures.

The thread pool that drives many targets concurrently (:func:`run_pipeline`) is
added in the next task.

The engine imports only the standard library — no SCCM, Active Directory, or
DLT — so it stays portable.
"""
from __future__ import annotations

import contextlib
import logging
import queue
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, ContextManager, Iterable, Optional, Sequence

from .streams import broadcast_done
from .work_queue import WorkQueue

logger = logging.getLogger(__name__)

# A phase's run() yields (stream_name, row) pairs. Rows are opaque to the engine.
PhaseRun = Callable[[str, Any], Iterable[tuple[str, Any]]]
ShouldRun = Callable[[str, "Phase", Any], bool]
PhaseScope = Callable[[str, str], ContextManager[Any]]
OnTargetComplete = Callable[[str], None]


@dataclass(frozen=True)
class Phase:
    """One ordered collection step.

    Attributes:
        name: Stable identifier for the phase (e.g. "RemoteRegistry"). Callers
            may also use it as the gating token for ``should_run``.
        streams: The names of every output stream this phase may write to.
        run: A generator function ``(target, context) -> Iterable[(stream, row)]``.
    """

    name: str
    streams: tuple[str, ...]
    run: PhaseRun


def run_one_target(
    target: str,
    context: Any,
    phases: Sequence[Phase],
    streams: dict[str, queue.Queue],
    should_run: Optional[ShouldRun] = None,
    phase_scope: Optional[PhaseScope] = None,
) -> None:
    """Run *target* through *phases* in order, routing rows to *streams*.

    For each phase (unless ``should_run`` says to skip it), the optional
    ``phase_scope(target, phase.name)`` context manager is entered (used by
    callers to set logging context), then the phase's ``run`` is iterated and
    each ``(stream_name, row)`` is put onto ``streams[stream_name]`` — a put that
    blocks when the stream is full (intended backpressure).

    A phase that raises is logged and skipped; the remaining phases still run.
    """
    for phase in phases:
        if should_run is not None and not should_run(target, phase, context):
            continue
        scope: ContextManager[Any] = (
            phase_scope(target, phase.name) if phase_scope is not None else contextlib.nullcontext()
        )
        with scope:
            try:
                for stream_name, row in phase.run(target, context):
                    streams[stream_name].put(row)
            except Exception:
                logger.exception("Phase %r failed for target %r", phase.name, target)


def run_pipeline(
    work_queue: WorkQueue,
    context: Any,
    phases: Sequence[Phase],
    streams: dict[str, queue.Queue],
    max_workers: int,
    should_run: Optional[ShouldRun] = None,
    phase_scope: Optional[PhaseScope] = None,
    on_target_complete: Optional[OnTargetComplete] = None,
) -> None:
    """Drive the whole collection to completion, then close every stream.

    A dispatcher pulls targets off ``work_queue`` and hands each to a worker in a
    pool of ``max_workers``. Each worker runs its target through ``phases`` in
    order (:func:`run_one_target`); a phase may discover new targets by calling
    ``work_queue.submit(...)`` (typically via ``context``), and the next free
    worker picks them up — recursion. When the queue is quiescent (nothing
    pending and nothing in flight) the dispatcher stops, all workers are awaited,
    and :func:`broadcast_done` puts the ``DONE`` marker on every stream so
    consumers finish.

    ``on_target_complete`` (if given) is called once per target after its phases
    finish but *before* its in-flight slot is released, so a callback that
    submits a new target cannot race quiescence.
    """

    def worker(target: str) -> None:
        try:
            run_one_target(target, context, phases, streams, should_run, phase_scope)
        finally:
            # Notify completion while the target is still counted in flight, then
            # release the slot. Releasing last means any target submitted by
            # run_one_target *or* by on_target_complete is already pending before
            # in_flight can reach zero — quiescence cannot be declared early.
            if on_target_complete is not None:
                try:
                    on_target_complete(target)
                except Exception:
                    logger.exception("on_target_complete failed for %r", target)
            work_queue.complete(target)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while True:
                target = work_queue.next()
                if target is None:   # quiescent: nothing pending, nothing in flight
                    break
                executor.submit(worker, target)
        # All workers have finished by here (next() returned None only at in_flight==0).
    finally:
        # Always close the streams — even on an unexpected dispatcher error —
        # so consumers draining them can never hang.
        broadcast_done(streams)
