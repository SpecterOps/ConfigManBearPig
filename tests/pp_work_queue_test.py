"""Tests for the portable work queue (phased_pipeline.work_queue.WorkQueue).

The work queue is the engine's to-do list: it refuses duplicates, counts how
many targets are in flight, and reports quiescence (nothing waiting AND nothing
running) by returning None from next().
"""
import threading
import time

from openhound_sccm.phased_pipeline.work_queue import WorkQueue


def test_submit_returns_true_for_new_and_false_for_duplicate():
    q = WorkQueue()
    assert q.submit("hostA") is True
    assert q.submit("hostA") is False          # exact duplicate
    assert q.submit("HOSTA") is False          # case-insensitive duplicate
    assert q.submit("hostB") is True


def test_submit_ignores_empty_or_blank():
    q = WorkQueue()
    assert q.submit("") is False
    assert q.submit("   ") is False


def test_next_hands_out_each_target_and_counts_in_flight():
    q = WorkQueue()
    q.submit("h1")
    q.submit("h2")
    handed_out = {q.next(), q.next()}
    assert handed_out == {"h1", "h2"}
    assert q.in_flight() == 2


def test_next_returns_none_at_quiescence():
    q = WorkQueue()
    q.submit("h1")
    assert q.next() == "h1"
    q.complete("h1")
    # nothing pending, nothing in flight -> quiescent
    assert q.next() is None


def test_next_blocks_until_a_new_target_is_submitted():
    q = WorkQueue()
    q.submit("h1")
    assert q.next() == "h1"           # h1 now in flight, pending empty

    got = []
    started = threading.Event()

    def waiter():
        started.set()
        got.append(q.next())          # must block: in_flight=1, pending empty

    t = threading.Thread(target=waiter)
    t.start()
    started.wait()
    time.sleep(0.1)
    assert t.is_alive()               # still blocked, not quiescent (h1 in flight)

    q.submit("h2")                    # wakes the waiter
    t.join(timeout=2)
    assert not t.is_alive()
    assert got == ["h2"]
    q.complete("h1")
    q.complete("h2")


def test_next_wakes_to_none_when_last_in_flight_completes():
    q = WorkQueue()
    q.submit("h1")
    assert q.next() == "h1"

    got = []

    def waiter():
        got.append(q.next())          # blocks until h1 completes -> quiescent

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.1)
    assert t.is_alive()

    q.complete("h1")                  # in_flight -> 0, pending empty -> quiescent
    t.join(timeout=2)
    assert got == [None]


def test_many_producers_single_consumer_hands_out_each_once():
    q = WorkQueue()
    names = [f"h{i}" for i in range(100)]

    producers = [threading.Thread(target=q.submit, args=(n,)) for n in names]
    for p in producers:
        p.start()
    for p in producers:
        p.join()

    seen = []
    while True:
        target = q.next()
        if target is None:
            break
        seen.append(target)
        q.complete(target)

    assert sorted(seen) == sorted(names)
    assert len(seen) == len(set(seen))     # each handed out exactly once
