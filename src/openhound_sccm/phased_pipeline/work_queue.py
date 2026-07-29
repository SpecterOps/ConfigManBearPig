"""The engine's to-do list.

``WorkQueue`` holds targets waiting to be collected. It:

* refuses duplicates (a target is ever handed out at most once);
* counts how many targets are *in flight* (handed to a worker but not yet
  completed);
* detects *quiescence* — nothing waiting and nothing in flight — and signals it
  by returning ``None`` from :meth:`next`.

All state is guarded by a single ``threading.Condition`` so many producer
threads can :meth:`submit` while one dispatcher thread calls :meth:`next` /
:meth:`complete`.

**Ordering contract (this is what makes quiescence race-free):** a worker that
discovers a new target must :meth:`submit` it *before* calling :meth:`complete`
for the target it is finishing. Because ``submit`` adds to the pending list
while the discovering target is still counted in flight, the dispatcher can
never observe "nothing pending and nothing in flight" while a discovery is
mid-flight.
"""
from __future__ import annotations

import threading
from collections import deque


class WorkQueue:
    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._pending: deque[str] = deque()
        self._seen: set[str] = set()
        self._in_flight = 0

    def submit(self, target: str) -> bool:
        """Add *target* to the to-do list.

        Returns ``True`` if it was newly added, ``False`` if it was blank or a
        duplicate (case-insensitive). Wakes any thread waiting in :meth:`next`.
        """
        if target is None:
            return False
        cleaned = target.strip()
        if not cleaned:
            return False
        key = cleaned.lower()
        with self._cond:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._pending.append(cleaned)
            self._cond.notify_all()
            return True

    def next(self) -> str | None:
        """Return the next target to collect, blocking while work may still
        appear. Returns ``None`` exactly when the queue is quiescent (nothing
        pending and nothing in flight) — the dispatcher's signal to stop.
        """
        with self._cond:
            while True:
                if self._pending:
                    target = self._pending.popleft()
                    self._in_flight += 1
                    return target
                if self._in_flight == 0:
                    return None
                self._cond.wait()

    def complete(self, target: str) -> None:
        """Mark a previously handed-out *target* as finished.

        If this empties the queue (nothing pending, nothing in flight), wake any
        waiters so they observe quiescence and stop.
        """
        with self._cond:
            self._in_flight -= 1
            if not self._pending and self._in_flight == 0:
                self._cond.notify_all()

    def in_flight(self) -> int:
        """Number of targets currently handed out but not yet completed."""
        with self._cond:
            return self._in_flight
