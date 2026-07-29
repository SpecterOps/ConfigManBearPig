"""Tests for the portable engine (phased_pipeline.engine).

This module covers the single-target runner (run_one_target) here; the thread
pool / recursion / shutdown (run_pipeline) tests are added alongside in Task 4.
All tests use *fake* phases and no SCCM/AD/DLT code — proving the engine stands
on its own.
"""
import contextlib
import pathlib
import re
import threading
import time

from openhound_sccm.phased_pipeline.engine import Phase, run_one_target, run_pipeline
from openhound_sccm.phased_pipeline.streams import DONE, build_streams
from openhound_sccm.phased_pipeline.work_queue import WorkQueue


def _drain_until_done(q):
    out = []
    while True:
        item = q.get()
        if item is DONE:
            break
        out.append(item)
    return out


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get())
    return out


def test_phases_run_in_order_and_rows_arrive_in_order():
    def p1(target, ctx):
        yield ("out", "p1")

    def p2(target, ctx):
        yield ("out", "p2a")
        yield ("out", "p2b")

    def p3(target, ctx):
        yield ("out", "p3")

    phases = [Phase("P1", ("out",), p1), Phase("P2", ("out",), p2), Phase("P3", ("out",), p3)]
    streams = build_streams(["out"], maxsize=100)
    run_one_target("hostA", None, phases, streams)
    assert _drain(streams["out"]) == ["p1", "p2a", "p2b", "p3"]


def test_rows_route_to_their_named_stream():
    def reg(target, ctx):
        yield ("registry", {"name": target})

    def mssql(target, ctx):
        yield ("mssql", {"host": target})

    phases = [Phase("REG", ("registry",), reg), Phase("MSSQL", ("mssql",), mssql)]
    streams = build_streams(["registry", "mssql"], maxsize=100)
    run_one_target("hostA", None, phases, streams)
    assert _drain(streams["registry"]) == [{"name": "hostA"}]
    assert _drain(streams["mssql"]) == [{"host": "hostA"}]


def test_should_run_can_skip_a_phase():
    def reg(target, ctx):
        yield ("registry", "r")

    def mssql(target, ctx):
        yield ("mssql", "m")

    phases = [Phase("RemoteRegistry", ("registry",), reg), Phase("MSSQL", ("mssql",), mssql)]
    streams = build_streams(["registry", "mssql"], maxsize=100)
    run_one_target(
        "hostA", None, phases, streams,
        should_run=lambda target, phase, ctx: phase.name == "RemoteRegistry",
    )
    assert _drain(streams["registry"]) == ["r"]
    assert _drain(streams["mssql"]) == []


def test_a_failing_phase_does_not_stop_the_following_phases():
    def p1(target, ctx):
        yield ("out", "p1")

    def p2(target, ctx):
        yield ("out", "p2a")
        raise RuntimeError("boom")  # p2b is never reached

    def p3(target, ctx):
        yield ("out", "p3")

    phases = [Phase("P1", ("out",), p1), Phase("P2", ("out",), p2), Phase("P3", ("out",), p3)]
    streams = build_streams(["out"], maxsize=100)
    run_one_target("hostA", None, phases, streams)  # must NOT raise
    assert _drain(streams["out"]) == ["p1", "p2a", "p3"]


def test_phase_scope_wraps_each_phase_in_order():
    entered = []

    @contextlib.contextmanager
    def scope(target, phase_name):
        entered.append((target, phase_name))
        yield

    def p1(target, ctx):
        yield ("out", "p1")

    def p2(target, ctx):
        yield ("out", "p2")

    phases = [Phase("P1", ("out",), p1), Phase("P2", ("out",), p2)]
    streams = build_streams(["out"], maxsize=100)
    run_one_target("hostA", None, phases, streams, phase_scope=scope)
    assert entered == [("hostA", "P1"), ("hostA", "P2")]


# --------------------------------------------------------------------------
# run_pipeline (thread pool + recursion + quiescent shutdown)
# --------------------------------------------------------------------------

def test_pipeline_runs_every_target():
    q = WorkQueue()
    for i in range(10):
        q.submit(f"h{i}")

    def emit(target, ctx):
        yield ("out", target)

    streams = build_streams(["out"], maxsize=100)
    run_pipeline(q, None, [Phase("E", ("out",), emit)], streams, max_workers=4)
    assert sorted(_drain_until_done(streams["out"])) == sorted(f"h{i}" for i in range(10))


def test_pipeline_collects_recursively_discovered_targets():
    q = WorkQueue()
    q.submit("root")

    def emit(target, ctx):
        if target == "root":
            q.submit("child")     # discovered mid-phase, before this worker completes
        yield ("out", target)

    streams = build_streams(["out"], maxsize=100)
    run_pipeline(q, None, [Phase("E", ("out",), emit)], streams, max_workers=2)
    assert sorted(_drain_until_done(streams["out"])) == ["child", "root"]


def test_pipeline_respects_the_worker_limit():
    q = WorkQueue()
    for i in range(6):
        q.submit(f"h{i}")

    lock = threading.Lock()
    state = {"current": 0, "max": 0}

    def emit(target, ctx):
        with lock:
            state["current"] += 1
            state["max"] = max(state["max"], state["current"])
        time.sleep(0.05)
        with lock:
            state["current"] -= 1
        yield ("out", target)

    streams = build_streams(["out"], maxsize=100)
    run_pipeline(q, None, [Phase("E", ("out",), emit)], streams, max_workers=2)
    items = _drain_until_done(streams["out"])
    assert sorted(items) == sorted(f"h{i}" for i in range(6))
    assert state["max"] <= 2


def test_pipeline_broadcasts_done_on_every_stream():
    q = WorkQueue()
    q.submit("h1")

    def emit(target, ctx):
        yield ("a", 1)
        yield ("b", 2)

    streams = build_streams(["a", "b"], maxsize=100)
    run_pipeline(q, None, [Phase("E", ("a", "b"), emit)], streams, max_workers=2)
    assert _drain_until_done(streams["a"]) == [1]
    assert _drain_until_done(streams["b"]) == [2]


def test_pipeline_does_not_deadlock_under_backpressure():
    q = WorkQueue()
    for i in range(5):
        q.submit(f"h{i}")

    def emit(target, ctx):
        for j in range(3):
            yield ("out", f"{target}-{j}")

    streams = build_streams(["out"], maxsize=1)   # tiny -> heavy backpressure
    collected = []

    def slow_consumer():
        while True:
            item = streams["out"].get()
            if item is DONE:
                break
            collected.append(item)
            time.sleep(0.005)

    consumer = threading.Thread(target=slow_consumer)
    consumer.start()
    run_pipeline(q, None, [Phase("E", ("out",), emit)], streams, max_workers=3)
    consumer.join(timeout=15)
    assert not consumer.is_alive()
    assert len(collected) == 15


def test_pipeline_calls_on_target_complete_once_per_target():
    q = WorkQueue()
    for i in range(3):
        q.submit(f"h{i}")

    def emit(target, ctx):
        yield ("out", target)

    streams = build_streams(["out"], maxsize=100)
    completed = []
    lock = threading.Lock()

    def on_done(target):
        with lock:
            completed.append(target)

    run_pipeline(q, None, [Phase("E", ("out",), emit)], streams, max_workers=2,
                 on_target_complete=on_done)
    _drain_until_done(streams["out"])
    assert sorted(completed) == sorted(f"h{i}" for i in range(3))


def test_engine_source_imports_nothing_project_specific():
    """The engine stays free of the dlt library, ldap3, the openhound framework,
    and the SCCM extension. It MAY use the shared collector-common infra: the
    stream primitives (DONE / build_streams / broadcast_done) are pure-queue and
    pull in neither the dlt library nor the openhound framework, so importing
    ``openhound_collector_common.dlt.source_bridge`` is allowed (that's the one
    dependency permitted by relaxing the old zero-dependency rule)."""
    pkg = pathlib.Path(__file__).resolve().parent.parent / "src" / "openhound_sccm" / "phased_pipeline"
    forbidden = ("dlt", "ldap3", "openhound", "openhound_sccm")
    for py in sorted(pkg.glob("*.py")):
        for line in py.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not (stripped.startswith("import ") or stripped.startswith("from ")):
                continue
            # The shared collector-common infra is the one allowed dependency.
            if "openhound_collector_common" in stripped:
                continue
            for name in forbidden:
                assert not re.search(rf"\b{name}\b", stripped), f"{py.name}: {stripped}"
