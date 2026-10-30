"""A failed output consumer must release producers and keep the original error."""

from threading import Event

import pytest

from openhound_sccm import main, source
from openhound_sccm.context import SourceContext
from openhound_sccm.phased_pipeline import Phase, WorkQueue


def test_failed_consumer_cancels_full_queues_and_waits_for_generator_cleanup():
    queue = WorkQueue()
    queue.submit("hostA")
    producing, closed = Event(), Event()
    original = ValueError("Illustrative output failure")

    class BrokenPipeline:
        def run(self, *args, **kwargs):
            assert producing.wait(5)
            raise original

    def phase(target, context):
        try:
            yield "registry_sccm_components", {"name": target}
            producing.set()
            yield "registry_sccm_components", {"name": target}
        finally:
            closed.set()

    ctx = SourceContext(ad=None, domain="example.com", work_queue=queue, collection_methods="All")
    with pytest.raises(ValueError) as captured:
        main._run_per_host_stage(
            BrokenPipeline(), queue, ctx, threads=2, maxsize=1,
            phases=[Phase("RemoteRegistry", ("registry_sccm_components",), phase)],
        )
    assert captured.value is original
    assert closed.is_set()
    assert queue.in_flight() == 0
    assert source.get_bridge() is None
