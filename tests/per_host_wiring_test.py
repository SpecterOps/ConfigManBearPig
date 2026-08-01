"""Tests for the SCCM wiring: per-table emit resources and the context feeding
the work queue (with the allow-list preserved upstream of submit)."""
from openhound_collector_common.dlt.source_bridge import StreamBridge

from openhound_sccm import source as source_mod
from openhound_sccm.context import SourceContext
from openhound_sccm.main import app
from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
from openhound_sccm.phased_pipeline.streams import DONE


class FakeWorkQueue:
    def __init__(self):
        self.submitted = []

    def submit(self, target):
        self.submitted.append(target)
        return True


def _ctx(allowed=frozenset(), work_queue=None):
    return SourceContext(
        ad=None,
        domain="example.com",
        work_queue=work_queue,
        allowed_targets=frozenset(allowed),
    )


# ---- emit resources / no broken cycle -------------------------------------

def test_one_emit_resource_registered_per_table_and_no_broken_cycle():
    names = {r.name for r in app.dlt_resources}
    for table in all_table_names(PER_HOST_PHASES):
        assert table in names, f"missing emit resource for {table}"
    assert "per_host_collector_pipeline" not in names


def test_drain_stream_yields_rows_until_done():
    # source._drain_stream now delegates to a planted StreamBridge, so drive it
    # through one: push rows + the DONE marker onto the bridge's own queue.
    bridge = StreamBridge(["some_table"])
    bridge.streams["some_table"].put({"r": 1})
    bridge.streams["some_table"].put({"r": 2})
    bridge.streams["some_table"].put(DONE)
    source_mod.set_bridge(bridge)
    try:
        assert list(source_mod._drain_stream("some_table")) == [{"r": 1}, {"r": 2}]
    finally:
        source_mod.clear_bridge()


# ---- context feeds the work queue (allow-list preserved) ------------------

def _obj(host, sid):
    return {"dNSHostName": host, "name": host, "object_sid": sid}


def test_register_new_target_submits_to_work_queue():
    wq = FakeWorkQueue()
    ctx = _ctx(work_queue=wq)
    ctx.register_target("hostA", source="X", ad_object=_obj("hostA", "S-1-1"))
    assert wq.submitted == ["hostA"]


def test_register_existing_target_does_not_resubmit():
    wq = FakeWorkQueue()
    ctx = _ctx(work_queue=wq)
    obj = _obj("hostA", "S-1-2")
    ctx.register_target("hostA", source="X", ad_object=obj)
    ctx.register_target("hostA", source="Y", ad_object=obj)
    assert wq.submitted == ["hostA"]  # submitted exactly once


def test_allow_list_blocks_non_listed_discoveries():
    wq = FakeWorkQueue()
    ctx = _ctx(allowed={"hosta"}, work_queue=wq)
    # hostB is not in the allow-list -> dropped before submit
    ctx.register_target("hostB", source="X", ad_object=_obj("hostB", "S-1-3"))
    assert wq.submitted == []
    # hostA is in the allow-list -> submitted
    ctx.register_target("hostA", source="X", ad_object=_obj("hostA", "S-1-4"))
    assert wq.submitted == ["hostA"]


def test_empty_allow_list_allows_everything():
    wq = FakeWorkQueue()
    ctx = _ctx(allowed=frozenset(), work_queue=wq)
    ctx.register_target("anyhost", source="X", ad_object=_obj("anyhost", "S-1-5"))
    assert wq.submitted == ["anyhost"]
