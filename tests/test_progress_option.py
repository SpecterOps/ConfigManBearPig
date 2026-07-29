"""Tests for the `collect sccm --progress` backend selection.

The default must silence dlt's per-resource progress counters entirely (so they
stop smearing into the collector's own [target][phase] logs), achieved purely
SCCM-side with no OpenHound-core change. tqdm / log / alive_progress stay opt-in.
"""
import inspect

from dlt.pipeline.progress import _NULL_COLLECTOR, _from_name

from openhound.core.progress import Progress
from openhound_sccm.main import ProgressOption, _resolve_progress, collect_sccm


def test_off_resolves_to_dlt_null_collector():
    resolved = _resolve_progress(ProgressOption.off)
    # Collector forwards `.value` to dlt.pipeline(progress=...); dlt turns None
    # into its no-op NULL_COLLECTOR, i.e. no progress output at all.
    assert resolved.value is None
    assert _from_name(resolved.value) is _NULL_COLLECTOR


def test_real_backends_map_to_core_progress_enum():
    for choice in (ProgressOption.tqdm, ProgressOption.log, ProgressOption.alive_progress):
        resolved = _resolve_progress(choice)
        assert isinstance(resolved, Progress)
        assert resolved.value == choice.value


def test_collect_sccm_defaults_progress_to_off():
    param = inspect.signature(collect_sccm).parameters["progress"]
    # Typer wraps the default in an OptionInfo; the real default lives on `.default`.
    default = getattr(param.default, "default", param.default)
    assert default is ProgressOption.off
