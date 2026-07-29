"""Tests for the portable output streams (phased_pipeline.streams).

A *stream* is a named, bounded queue. Phases drop rows onto streams; consumers
read rows off and write them to disk. "Bounded" means a full stream makes the
producer wait (backpressure), which caps memory. ``DONE`` is the single shared
marker that tells a consumer "no more rows are coming."
"""
import queue
import threading
import time

from openhound_sccm.phased_pipeline.streams import DONE, broadcast_done, build_streams


def test_build_streams_creates_one_bounded_queue_per_name():
    streams = build_streams(["a", "b"], maxsize=5)
    assert set(streams) == {"a", "b"}
    assert all(isinstance(q, queue.Queue) for q in streams.values())
    assert streams["a"].maxsize == 5
    assert streams["b"].maxsize == 5


def test_full_stream_blocks_put_until_a_slot_is_freed():
    streams = build_streams(["a"], maxsize=2)
    q = streams["a"]
    q.put("r1")
    q.put("r2")  # stream is now full

    started = threading.Event()
    finished = threading.Event()

    def producer():
        started.set()
        q.put("r3")  # must block until a get() frees a slot
        finished.set()

    t = threading.Thread(target=producer)
    t.start()
    started.wait()
    time.sleep(0.1)
    assert not finished.is_set()  # still blocked on the full stream

    assert q.get() == "r1"  # free a slot
    t.join(timeout=2)
    assert finished.is_set()


def test_broadcast_done_puts_the_same_marker_on_every_stream():
    streams = build_streams(["a", "b", "c"], maxsize=10)
    broadcast_done(streams)
    for q in streams.values():
        assert q.get() is DONE
