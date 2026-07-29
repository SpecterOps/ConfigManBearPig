"""Tests for per-host ordered-log blocks.

Per-host worker records carry a target (host) context but no resource context.
The ordered-log handler buckets them by host and flushes a contiguous [host]
block when that host's phase sequence completes, so the FILE reads host-by-host
even though the console interleaves.
"""
import logging

from openhound_sccm.log_context import (
    fire_host_complete,
    register_host_complete_callback,
    register_resource_complete_callback,
    target_context,
    unregister_host_complete_callback,
    unregister_resource_complete_callback,
)
from openhound_sccm.main import _OrderedLogFileHandler
from openhound_sccm.per_host_phases import PER_HOST_PHASES


def test_host_complete_callback_fires_once_with_hostname():
    got = []
    register_host_complete_callback(got.append)
    try:
        fire_host_complete("hostA")
    finally:
        unregister_host_complete_callback(got.append)
    assert got == ["hostA"]


def test_per_host_records_flush_as_contiguous_blocks_in_completion_order(tmp_path):
    log_path = tmp_path / "ordered.log"
    handler = _OrderedLogFileHandler(log_path, level=logging.INFO)
    logger = logging.getLogger("test_per_host_log_blocks")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    register_host_complete_callback(handler.flush_host)
    try:
        # Interleave two hosts' records, as two concurrent workers would.
        with target_context("hostA"):
            logger.info("A-1")
        with target_context("hostB"):
            logger.info("B-1")
        with target_context("hostA"):
            logger.info("A-2")
        with target_context("hostB"):
            logger.info("B-2")
        # hostA finishes first, then hostB.
        fire_host_complete("hostA")
        fire_host_complete("hostB")
    finally:
        register_host_complete_callback(handler.flush_host)  # ensure registered for cleanup symmetry
        unregister_host_complete_callback(handler.flush_host)
        logger.removeHandler(handler)
        handler.close()

    text = log_path.read_text(encoding="utf-8")
    # Both of hostA's lines appear before either of hostB's (contiguous blocks,
    # hostA before hostB because it completed first).
    a1, a2 = text.index("A-1"), text.index("A-2")
    b1, b2 = text.index("B-1"), text.index("B-2")
    assert a1 < a2 < b1 < b2
    # The block is labelled with the host name.
    assert "# hostA" in text and "# hostB" in text


class _DisabledCtx:
    """Minimal SourceContext stand-in whose every collection method is disabled,
    so each per-host collector returns immediately without any network I/O."""

    def method_enabled(self, _name: str) -> bool:
        return False

    def __getattr__(self, _name: str):  # permissive: any other attr access -> None
        return None


def test_per_host_collectors_do_not_fire_resource_complete():
    """Per-host phase collectors must not carry a DLT-style resource lifecycle.

    Regression guard for the ordered-log grouping bug: when a per-host collector
    was decorated with ``@with_log_context``, iterating it set a resource context
    (``func.__name__``) and fired a resource-complete callback on exhaustion —
    once per (host, phase). That hijacked the ordered log's per-host bucketing and
    produced repeated ``# collect_registry`` blocks. The engine's ``phase_scope``
    already supplies ``[target][phase]``, so these collectors must NOT set a
    resource context. Iterating them must fire no resource-complete callback.
    """
    fired: list[str] = []
    register_resource_complete_callback(fired.append)
    try:
        for phase in PER_HOST_PHASES:
            list(phase.run("host.example.com", _DisabledCtx()))
    finally:
        unregister_resource_complete_callback(fired.append)
    assert fired == [], f"per-host collectors fired resource-complete: {fired}"


def test_verbose_records_render_with_level_name_not_l15(tmp_path):
    """VERBOSE (level 15) records must render with their level name in the full log,
    not a bare 'L15'. The always-DEBUG full log now captures VERBOSE lines, so the
    ordered handler's label table must resolve level 15 to 'VERBOSE'."""
    from openhound_sccm.log_context import VERBOSE

    log_path = tmp_path / "full.log"
    handler = _OrderedLogFileHandler(log_path, level=logging.DEBUG)
    logger = logging.getLogger("test_verbose_label_render")
    logger.setLevel(VERBOSE)
    logger.addHandler(handler)
    register_host_complete_callback(handler.flush_host)
    try:
        with target_context("hostV"):
            logger.log(VERBOSE, "a verbose line")
        fire_host_complete("hostV")
    finally:
        unregister_host_complete_callback(handler.flush_host)
        logger.removeHandler(handler)
        handler.close()

    text = log_path.read_text(encoding="utf-8")
    assert "a verbose line" in text
    assert "VERBOSE " in text
    assert "L15" not in text
