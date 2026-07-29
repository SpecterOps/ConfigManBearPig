"""Integration tests for the SCCM per-host stage (Stage 2).

These drive the real worker pool + streaming emit against an isolated DLT
filesystem pipeline writing to a temp dir, using the stub phases. Task 7 covers
the orchestration shape; Task 9 adds the full recursion / backpressure /
allow-list scenarios.
"""
import gzip
import json
import threading

import dlt
from dlt.destinations import filesystem

from openhound_sccm import main as main_mod
from openhound_sccm.context import SourceContext
from tests.per_host_phases_test import PER_HOST_PHASES, all_table_names
from openhound_sccm.phased_pipeline import WorkQueue


def _isolated_pipeline(tmp_path, name):
    return dlt.pipeline(
        pipeline_name=name,
        destination=filesystem(bucket_url=str(tmp_path)),
        dataset_name="sccm",
        pipelines_dir=str(tmp_path / "_pipelines"),
    )


def _written_tables(tmp_path):
    dataset = tmp_path / "sccm"
    return {
        p.name
        for p in dataset.iterdir()
        if p.is_dir() and not p.name.startswith("_dlt")
    }


def _read_rows(tmp_path, table):
    """Read every JSONL row written for a table (handles optional gzip)."""
    table_dir = tmp_path / "sccm" / table
    rows = []
    if not table_dir.is_dir():
        return rows
    for f in sorted(table_dir.glob("*.jsonl*")):
        opener = gzip.open if f.suffix == ".gz" else open
        with opener(f, "rt", encoding="utf-8") as fh:
            rows.extend(json.loads(line) for line in fh if line.strip())
    return rows


def _run_stage_with_timeout(pipeline, work_queue, ctx, threads, maxsize=1000, timeout=60):
    done = threading.Event()
    errbox = {}

    def run():
        try:
            # Drive the stage with the stub phases so the engine orchestration
            # (recursion / backpressure / allow-list / method gating) is exercised
            # deterministically, independent of the real network collectors.
            main_mod._run_per_host_stage(
                pipeline, work_queue, ctx, threads=threads, maxsize=maxsize,
                phases=PER_HOST_PHASES,
            )
        except Exception as exc:  # pragma: no cover - surfaced via errbox
            errbox["exc"] = exc
        finally:
            done.set()

    runner = threading.Thread(target=run, daemon=True)  # daemon so a deadlock can't hang pytest exit
    runner.start()
    finished = done.wait(timeout=timeout)
    assert finished, "per-host stage did not finish in time (possible deadlock)"
    assert "exc" not in errbox, f"per-host stage raised: {errbox.get('exc')}"


def test_threads_option_defaults_to_10():
    import inspect

    param = inspect.signature(main_mod.collect_sccm).parameters["threads"]
    # typer.Option(...) returns an OptionInfo whose .default holds the value.
    assert param.default.default == 10


def test_run_per_host_stage_writes_all_stub_tables(tmp_path):
    wq = WorkQueue()
    wq.submit("hostA")
    wq.submit("hostB")
    ctx = SourceContext(ad=None, domain="example.com", work_queue=wq, collection_methods="All")
    pipeline = _isolated_pipeline(tmp_path, "test_stage_tables")

    _run_stage_with_timeout(pipeline, wq, ctx, threads=4)

    written = _written_tables(tmp_path)
    for table in all_table_names(PER_HOST_PHASES):
        assert table in written, f"missing table {table}; got {sorted(written)}"


def test_recursion_collects_discovered_hosts(tmp_path):
    wq = WorkQueue()
    wq.submit("hostA")
    wq.submit("hostB")
    ctx = SourceContext(ad=None, domain="example.com", work_queue=wq, collection_methods="All")
    pipeline = _isolated_pipeline(tmp_path, "test_recursion")

    _run_stage_with_timeout(pipeline, wq, ctx, threads=4)

    # 2 seeded + 2 discovered by the HTTP stub = 4 hosts; one registry row each.
    registry = _read_rows(tmp_path, "registry_sccm_components")
    assert {r.get("name") for r in registry} == {
        "hostA", "hostB", "hostA-discovered", "hostB-discovered",
    }
    # AdminService writes 2 + 2 rows per host -> 8 each across 4 hosts.
    assert len(_read_rows(tmp_path, "adminservice_admin_users")) == 8
    assert len(_read_rows(tmp_path, "adminservice_client_devices")) == 8


def test_allow_list_blocks_discovered_hosts(tmp_path):
    wq = WorkQueue()
    wq.submit("hostA")
    wq.submit("hostB")
    # Allow-list limits collection to the two seeded hosts; the HTTP stub's
    # discovered "*-discovered" hosts are not in the list and must be dropped.
    ctx = SourceContext(
        ad=None,
        domain="example.com",
        work_queue=wq,
        collection_methods="All",
        allowed_targets=frozenset({"hosta", "hostb"}),
    )
    pipeline = _isolated_pipeline(tmp_path, "test_allow_list")

    _run_stage_with_timeout(pipeline, wq, ctx, threads=4)

    registry = _read_rows(tmp_path, "registry_sccm_components")
    assert {r.get("name") for r in registry} == {"hostA", "hostB"}
    assert len(registry) == 2  # discovered hosts blocked -> recursion suppressed


def test_backpressure_with_tiny_streams_still_completes(tmp_path):
    wq = WorkQueue()
    for i in range(4):
        wq.submit(f"host{i}")
    ctx = SourceContext(ad=None, domain="example.com", work_queue=wq, collection_methods="All")
    pipeline = _isolated_pipeline(tmp_path, "test_backpressure")

    # maxsize=1 forces heavy backpressure; the run must still complete and
    # produce every row (producers block-and-proceed rather than wedging).
    _run_stage_with_timeout(pipeline, wq, ctx, threads=2, maxsize=1, timeout=90)

    # 4 seeded + 4 discovered = 8 hosts, one registry row each.
    assert len(_read_rows(tmp_path, "registry_sccm_components")) == 8


def test_selected_methods_limit_which_phases_run(tmp_path):
    wq = WorkQueue()
    wq.submit("hostA")
    # Only RemoteRegistry enabled -> only its table gets rows; others stay empty.
    ctx = SourceContext(ad=None, domain="example.com", work_queue=wq, collection_methods="RemoteRegistry")
    pipeline = _isolated_pipeline(tmp_path, "test_methods")

    _run_stage_with_timeout(pipeline, wq, ctx, threads=2)

    assert len(_read_rows(tmp_path, "registry_sccm_components")) == 1
    # MSSQL / SMB phases were gated off -> no rows (and no recursion, since the
    # HTTP phase that discovers hosts didn't run).
    assert _read_rows(tmp_path, "mssql_instances") == []
    assert _read_rows(tmp_path, "smb_signing") == []
