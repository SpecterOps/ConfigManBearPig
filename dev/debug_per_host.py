"""Debugger harness for the per-host queueing engine.

Run under the VS Code debugger ("Run and Debug" -> "Debug per-host queue", or
"Debug Python File"). No DLT is needed — it seeds the work queue by hand and
drains raw streams to exercise the queue, recursion, ordering, backpressure,
and quiescence. It binds LDAP as the current Windows user via SSPI, so per-host
collectors that resolve principals behave like the full CLI.

Stepping tips
-------------
* Keep MAX_WORKERS = 1 while stepping so the debugger stays on one worker thread.
  Set it to 10 to watch real concurrency (harder to single-step).
* COMPUTERS mirrors the CLI's --computers flag: each entry is both a seed
  (collected) and the allow-list. Only the listed hosts (and their short-name
  forms) are collected — anything they discover is skipped. To watch a
  discovered host get collected, add it to COMPUTERS too. Leaving COMPUTERS
  empty reproduces a CLI run with no --computers (allow-all), but with no seeds
  the pipeline then has nothing to collect.
* COLLECTION_METHODS mirrors the CLI's -m/--collection-methods flag: a
  comma-separated list of phase names to run (RemoteRegistry, MSSQL,
  AdminService, WMI). "All" (the default) runs every phase. Set it to e.g.
  "AdminService" to step through just one collector — gated-off phases are
  skipped via the same ctx.method_enabled(phase.name) gate the full run uses,
  and their tables report 0 rows below.
* WMI is the AdminService fallback. To step through the skip, keep AdminService
  enabled so it completes (e.g. COLLECTION_METHODS = "AdminService,WMI"), put a
  breakpoint in per_host_phases.should_run_phase, and run against a reachable
  SMS Provider: AdminService records "AdminService" in the host's
  TargetEntry.completed_phases (collect_adminservice, at the end of its
  collection loop), so should_run_phase returns False for the WMI
  phase and collect_wmi never runs. Set COLLECTION_METHODS = "WMI" alone for the
  opposite case — AdminService never runs, so WMI runs as the fallback.
* Set MAXSIZE = 1 to watch backpressure (producers block on put until drained).
  With MAX_WORKERS >= number of tables this still completes; lower it to see a
  stall (that's the dlt-worker-count constraint, here simulated with raw streams).
"""
import logging
import os

from openhound_sccm.clients.ad import ADClient, ADCredentials
from openhound_sccm.context import SourceContext
from openhound_sccm.log_context import VERBOSE, install_filter
from openhound_sccm.main import _apply_log_level, _build_phase_scope, _detect_windows_domain
from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names, should_run_phase
from openhound_sccm.phased_pipeline import DONE, WorkQueue, build_streams, run_pipeline
from openhound_sccm.source import _expand_allowed_targets

# Log to the console exactly like the main collector: reuse its own setup, which
# lowers the framework's console handler (here to the DEBUG tier), strips the
# "(openhound_version=...)" suffix its formatter appends, and installs the
# [target][phase] prefix filter. Reusing the framework handler (rather than adding
# a second one) is what avoids the duplicate / version-suffixed lines.
# (Set debug=False, verbose=True for the VERBOSE tier without dlt / ldap3 internals.)
_apply_log_level(verbose=False, debug=True, silent=False)

# Fallback: when no console handler is present (e.g. output redirected with no
# TTY, so the framework attached only a file handler), add one so the harness
# still prints — in the same "time=..., msg=..." shape.
_root = logging.getLogger()
if not any(not isinstance(h, logging.FileHandler) for h in _root.handlers):
    _console = logging.StreamHandler()
    _console.setLevel(VERBOSE)
    _console.setFormatter(
        logging.Formatter(
            "%(levelname)-7s time=%(asctime)s, msg=%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    _root.addHandler(_console)
    if _root.level == 0 or _root.level > VERBOSE:
        _root.setLevel(VERBOSE)
    install_filter()

MAX_WORKERS = 1                         # 1 = easy stepping; 10 = real concurrency
MAXSIZE = 1000                          # 1 = watch backpressure
COMPUTERS = ["ps1-dp.mayyhem.com"]      # mirrors --computers: each entry is both a seed AND the allow-list
COLLECTION_METHODS = "SMB"              # mirrors -m/--collection-methods: CSV of phase names to run (RemoteRegistry, MSSQL, AdminService, WMI); "All" runs every phase. Use "AdminService,WMI" to step the WMI fallback skip.
PRINT_ROWS = 0                          # rows to dump per table (0 = counts only); set to None to print all

# Derive the domain from the current Windows user (USERDNSDOMAIN), the same way
# the CLI does. We skip the CLI's DNS-SRV domain-controller lookup (it calls
# sys.exit() when SRV lookup fails); with no explicit DC, ADClient connects to
# the domain name, which DNS resolves to a DC.
DOMAIN = _detect_windows_domain() or "mayyhem.com"


def main() -> None:
    wq = WorkQueue()

    # Same env vars the CLI's -u/-p populate. Unset → both LDAP and SMB
    # authenticate as the current Windows user (SSPI); set them to use explicit
    # credentials, exactly like the CLI.
    username = os.environ.get("SOURCES__SCCM__USERNAME")
    password = os.environ.get("SOURCES__SCCM__PASSWORD")

    # --computers does double duty in the CLI: every entry seeds the queue AND
    # becomes the allow-list. Mirror that here by reusing source.py's expansion
    # (lowercased FQDN + short-name forms). Empty COMPUTERS -> empty allow-list
    # (allow-all), matching a CLI run with no --computers; with no seeds the
    # pipeline then has nothing to collect.
    allowed = _expand_allowed_targets(COMPUTERS)

    # Build a real LDAP client so per-host collectors that resolve principals
    # (RemoteRegistry component/database servers, CurrentUser SIDs) behave like
    # the full CLI. With no explicit DC, ADClient connects to the domain name,
    # which DNS resolves to a DC.
    ctx = SourceContext(
        ad=ADClient(ADCredentials(domain=DOMAIN, username=username, password=password)),
        domain=DOMAIN,
        username=username,
        password=password,
        work_queue=wq,
        collection_methods=COLLECTION_METHODS,
        allowed_targets=frozenset(allowed),
    )

    # Seed the targets exactly as the CLI does (main.py:946-948). register_target
    # both records each host in ctx.target_hosts_by_hostname — the probe-target
    # accumulator the per-host phases read via target_hosts_snapshot(), and that
    # collect_registry indexes directly as ctx.target_hosts_by_hostname[target] —
    # AND submits the host onto the work queue. This reproduces the state the run
    # is in once LDAP/DNS discovery has registered its hosts; a bare wq.submit()
    # would queue the host but leave that accumulator empty.
    #
    # [BP] step into register_target(): it resolves the host in AD (LDAP via
    # SSPI), applies the allow-list filter, then falls through to wq.submit()
    # (dedup + pending grows). Because COMPUTERS feeds both the seeds and the
    # allow-list, every seed always passes the filter; only hosts discovered
    # mid-run that aren't in COMPUTERS get rejected (returns None, never runs).
    for host in COMPUTERS:
        ctx.register_target(host, source="CLI")

    # Build streams for every phase's tables (like the CLI), regardless of
    # COLLECTION_METHODS. Gated-off phases simply never write, so their tables
    # report 0 rows in the results section below — that's the same shape the CLI
    # produces when -m excludes a method.
    streams = build_streams(all_table_names(PER_HOST_PHASES), maxsize=MAXSIZE)

    logging.getLogger(__name__).info("per-host phases gated by COLLECTION_METHODS=%s", COLLECTION_METHODS)

    # [BP] step into run_pipeline: dispatcher pulls from wq.next(), submits workers;
    # each worker runs run_one_target(host) -> phases in order; the HTTP stub calls
    # ctx.register_target(...) -> wq.submit(...) (recursion). At quiescence
    # wq.next() returns None, the loop breaks, and broadcast_done closes the streams.
    # phase_scope tags each phase's log lines with [target][phase], exactly like
    # the main collector (_run_per_host_stage passes the same _build_phase_scope()).
    # should_run is the CLI's exact phase gate: per_host_phases.should_run_phase
    # applies ctx.method_enabled(phase.name) (so COLLECTION_METHODS filters phases
    # like -m/--collection-methods) AND the WMI-is-a-fallback rule.
    #
    # [BP] Set a breakpoint in per_host_phases.should_run_phase to watch the WMI
    # skip: when the WMI phase is evaluated for a host whose AdminService phase
    # already completed, entry.completed_phases contains "AdminService", so it
    # returns False and the WMI collector never runs. AdminService records that in
    # collect_adminservice at the end of its collection loop. (Keep
    # AdminService enabled — e.g. COLLECTION_METHODS = "AdminService,WMI" — so it
    # completes; set COLLECTION_METHODS = "WMI" alone to see the opposite, where
    # AdminService never runs and WMI runs as the fallback.)
    run_pipeline(
        wq, ctx, PER_HOST_PHASES, streams,
        max_workers=MAX_WORKERS,
        should_run=should_run_phase,
        phase_scope=_build_phase_scope(),
    )

    # Drain and report. DONE was broadcast on every stream at quiescence.
    print("\n=== results ===")
    for table, stream in streams.items():
        rows = []
        while True:
            item = stream.get()
            if item is DONE:
                break
            rows.append(item)
        # Print the table title with its row count. By default (PRINT_ROWS = 0)
        # that's all — the per-row dump is too noisy. Set PRINT_ROWS = N to dump
        # the first N rows beneath it, one row per indented line, each truncated
        # to 150 chars; set PRINT_ROWS = None to dump every row in full (no row
        # cap, no per-line truncation).
        print(f"{table:32} {len(rows):3d} rows")
        shown = rows if PRINT_ROWS is None else rows[:PRINT_ROWS]
        for i, row in enumerate(shown):
            text = repr(row)
            if PRINT_ROWS is not None and len(text) > 150:
                text = text[:150] + "..."
            print(f"    row {i}: {text}")
        if shown and len(shown) < len(rows):
            print(f"    ... {len(rows) - len(shown)} more rows (set PRINT_ROWS = None to show all)")


if __name__ == "__main__":
    main()
