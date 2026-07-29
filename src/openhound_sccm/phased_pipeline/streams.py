"""Named, bounded output streams and the end-of-stream marker.

A *stream* is a ``queue.Queue`` with a maximum length. Phases put ``row`` items
on streams; consumers get them off and write them out. Because the queue is
bounded, a producer that outruns its consumer simply *waits* on ``put`` until a
slot frees up — this backpressure keeps total memory flat regardless of how many
rows are produced.

``DONE`` is a single shared sentinel value. A consumer reads rows until it gets
``DONE``, then stops. :func:`broadcast_done` places that marker on every stream
once collection has reached quiescence.

These three primitives come from ``openhound_collector_common.dlt.source_bridge``
— the shared bridge was generalized from this module, so the implementations are
identical. Re-exporting them (rather than keeping a byte-for-byte copy) means the
engine, SCCM's ``source.py`` emit resources, and the shared :class:`StreamBridge`
all share the SAME ``DONE`` instance: the marker is identity-compared
(``item is DONE``), so a single shared object is required for producer and
consumer to agree. This is the integration the shared bridge's docstring
anticipated; the engine's dependency on the shared infra is deliberate (its
portability test permits ``openhound_collector_common``).
"""
from __future__ import annotations

from openhound_collector_common.dlt.source_bridge import DONE, broadcast_done, build_streams

__all__ = ["DONE", "build_streams", "broadcast_done"]
