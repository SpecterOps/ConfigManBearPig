"""SCCM's stable import path for the shared ordered-phase engine.

Phase definitions, target identity and method gating stay in this collector.
The generic runner and its background-failure handling live in common.
"""

from openhound_collector_common.collection.engine import Phase, run_one_target, run_pipeline

__all__ = ["Phase", "run_one_target", "run_pipeline"]
