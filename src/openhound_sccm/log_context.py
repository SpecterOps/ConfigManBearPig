"""Per-target / per-phase / per-resource logging context for the SCCM extension.

The full logging-context machinery — ``VERBOSE`` + ``logger.verbose()``, the
``contextvars``-backed ``target_context`` / ``phase_context`` / resource context,
``LogContextFilter`` (the ``[target][phase]`` prefix), ``install_filter``,
``with_log_context`` (including per-``next()`` generator handling), the
resource/host completion-callback registry, ``per_host_iter`` / ``per_pair_iter``,
``VerboseLogger`` / ``get_logger``, the debug exc-info filter, the cache-with-log
decorator, and the OpenGraph build-trace helpers — now lives in the shared library
(``openhound_collector_common.logging.log_context``). It was proven here first and
promoted so the MSSQL collector and future collectors share one implementation.

This module re-exports the shared machinery unchanged, and keeps only SCCM's
*logger bindings* for the two helpers that emit under SCCM's own logger namespace
(so SCCM's log routing / ordered-log file handler, which key on the
``openhound_sccm.*`` names, are unchanged):

  * ``trace_node`` / ``trace_edge`` / ``trace_property_added`` /
    ``trace_node_with_properties`` -> ``openhound_sccm.graph``;
  * ``cached_with_log`` -> ``openhound_sccm.lookup``.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Optional, TypeVar

from openhound_collector_common.logging.log_context import (  # noqa: F401 (re-exported)
    VERBOSE,
    LogContextFilter,
    VerboseLogger,
    fire_host_complete,
    get_current_resource,
    get_current_target,
    get_logger,
    install_filter,
    per_host_iter,
    per_pair_iter,
    phase_context,
    register_host_complete_callback,
    register_resource_complete_callback,
    target_context,
    unregister_host_complete_callback,
    unregister_resource_complete_callback,
    with_log_context,
)
from openhound_collector_common.logging.log_context import (
    cached_with_log as _shared_cached_with_log,
    trace_edge as _shared_trace_edge,
    trace_node as _shared_trace_node,
    trace_node_with_properties as _shared_trace_node_with_properties,
    trace_property_added as _shared_trace_property_added,
)

_F = TypeVar("_F", bound=Callable)

# SCCM's graph-build traces and lookup-cache logs land under these logger names;
# SCCM's log filtering / ordered-log handler key on them.
_GRAPH_LOGGER = logging.getLogger("openhound_sccm.graph")
_LOOKUP_LOGGER = logging.getLogger("openhound_sccm.lookup")


def cached_with_log(label: str) -> Callable[[_F], _F]:
    """SCCM cache-with-log: the shared decorator bound to the SCCM lookup logger."""
    return _shared_cached_with_log(label, logger=_LOOKUP_LOGGER)


def trace_node(kind: str, node_id: str, name: Optional[str] = None) -> None:
    """SCCM graph node trace (shared ``trace_node`` bound to ``openhound_sccm.graph``)."""
    _shared_trace_node(kind, node_id, name, logger=_GRAPH_LOGGER)


def trace_edge(kind: str, start: str, end: str) -> None:
    """SCCM graph edge trace (shared ``trace_edge`` bound to ``openhound_sccm.graph``)."""
    _shared_trace_edge(kind, start, end, logger=_GRAPH_LOGGER)


def trace_property_added(kind: str, node_id: str, prop_name: str, value) -> None:
    """SCCM property-added trace (shared, bound to ``openhound_sccm.graph``)."""
    _shared_trace_property_added(kind, node_id, prop_name, value, logger=_GRAPH_LOGGER)


def trace_node_with_properties(kind: str, node_id: str, name: Optional[str], properties: Any) -> None:
    """SCCM node+properties trace (shared, bound to ``openhound_sccm.graph``)."""
    _shared_trace_node_with_properties(kind, node_id, name, properties, logger=_GRAPH_LOGGER)


__all__ = [
    "LogContextFilter",
    "VERBOSE",
    "VerboseLogger",
    "cached_with_log",
    "fire_host_complete",
    "get_current_resource",
    "get_logger",
    "get_current_target",
    "install_filter",
    "register_host_complete_callback",
    "unregister_host_complete_callback",
    "per_host_iter",
    "per_pair_iter",
    "phase_context",
    "register_resource_complete_callback",
    "target_context",
    "trace_edge",
    "trace_node",
    "trace_node_with_properties",
    "trace_property_added",
    "unregister_resource_complete_callback",
    "with_log_context",
]
