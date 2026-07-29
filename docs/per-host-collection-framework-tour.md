# A Tour of the Per-Host Collection Framework

This document explains the concurrent per-host collection framework: what it
does, how the pieces fit together, and — most importantly — **how to plug your
own collector into it so it runs against every discovered target**.

It is written to be read top-to-bottom. Terms are defined the first time they
appear.

---

## 1. What problem it solves

We need to collect from many machines, where:

- each machine runs a fixed sequence of **collection steps** (RemoteRegistry,
  MSSQL, AdminService, WMI, HTTP, SMB) **in order**;
- many machines are collected **at the same time** (default 10);
- a step on one machine can **discover a new machine**, which must then get the
  full sequence too — and so on, **recursively**, until no machines remain;
- output streams to disk as it's collected, so memory stays flat even with huge
  result sets.

The framework is split into two halves:

1. **A portable engine** (`src/openhound_sccm/phased_pipeline/`) that knows
   nothing about SCCM, Active Directory, or DLT. It understands only *targets*,
   *ordered phases*, *named output streams*, and *recursion*. It can be lifted
   into any project.
2. **An SCCM adapter** that plugs SCCM's phases, tables, and plumbing into the
   engine.

---

## 2. The mental model (plain English)

Picture a team clearing a to-do list:

- The **to-do list** (`WorkQueue`) holds *targets* (machines, identified by
  hostname) waiting to be collected.
- There are N **workers** (a thread pool; N = `--threads`, default 10). Each idle
  worker takes the next target off the list.
- A worker runs **every phase on that target, in order** — it's just a function
  calling each step one after another, so the order is guaranteed per machine.
- As a phase produces rows, the worker drops them onto a **stream** (a bounded
  queue, one per output table) headed for disk. It does not pile them up.
- If a phase **discovers a new target**, the worker adds it to the to-do list.
  The next free worker picks it up and runs *its* full sequence. That's the
  **recursion**.
- When the to-do list is empty **and** no worker is busy — **quiescence** — we're
  done. A `DONE` marker is sent down every stream to close it.
- On the consuming side, one **emit resource** per table reads its stream and
  lets DLT write the rows to that table's files.

Two jargon terms you'll see:

- **Backpressure** — the streams are *bounded* (capped length). When a stream is
  full, the worker's `put` *waits* until the reader drains it. This makes
  collection proceed only as fast as rows are written, keeping memory flat.
- **Quiescence** — the single "everything is done" signal: nothing pending on the
  to-do list **and** nothing in flight (being worked on right now).

---

## 3. File map

### Portable engine — `src/openhound_sccm/phased_pipeline/` (no SCCM/AD/DLT imports)

| File | Responsibility |
|---|---|
| `work_queue.py` | `WorkQueue`: the to-do list — dedup, in-flight counting, quiescence detection. |
| `streams.py` | `DONE` marker, `build_streams(names, maxsize)`, `broadcast_done(streams)`. |
| `engine.py` | `Phase` record, `run_one_target(...)` (one target through its phases), `run_pipeline(...)` (thread pool + recursion + shutdown). |
| `__init__.py` | Public surface: `WorkQueue`, `Phase`, `run_one_target`, `run_pipeline`, `DONE`, `build_streams`, `broadcast_done`. |

### SCCM adapter

| File | Responsibility |
|---|---|
| `per_host_phases.py` | `PER_HOST_PHASES` (the ordered phase list) + `all_table_names(phases)`. |
| `collectors/stubs.py` | Stub phase collectors (fake data) — replaced one-by-one by real collectors. |
| `source.py` | Per-table **emit resources** (drain streams → disk), the shared stream registry, discovery-resource wiring, `register_target` plumbing. |
| `context.py` | `SourceContext.register_target(...)` — resolve + allow-list + dedup + submit to the work queue. |
| `main.py` | `collect_sccm` (the CLI) and `_run_per_host_stage` (Stage 2 orchestration), plus per-host log blocks. |
| `log_context.py` | `[host][phase]` log tagging + host-completion callbacks. |

---

## 4. How a run flows, end to end

```
  collect_sccm  (main.py)
  │
  ├─ Stage 1: DISCOVERY (once)                     pipeline.run(discovery resources)
  │   LDAP / Local / DNS resources run.
  │   Each calls ctx.register_target(host)  ──────────────►  WorkQueue.submit(host)
  │   (+ CLI --computers seeded the same way)
  │
  └─ Stage 2: PER-HOST  (_run_per_host_stage)
      │
      │   build_streams(tables) ; set_table_queues(...)
      │
      ├─ background thread:  run_pipeline(work_queue, ctx, PER_HOST_PHASES, streams, workers=--threads)
      │     dispatcher pulls targets ──► worker pool (N workers)
      │        each worker: run_one_target(host)  → phase1, phase2, … in order
      │           phase yields (table, row)  ──►  streams[table].put(row)        [backpressure]
      │           phase discovers a host     ──►  ctx.register_target → WorkQueue.submit  [recursion]
      │        at quiescence: broadcast_done(streams)  → DONE on every stream
      │
      └─ main thread:  pipeline.run(emit resources)
            each emit resource drains its stream until DONE  ──►  DLT writes <table>/*.jsonl
```

Key point: **phase order lives inside each worker** (sequential Python), and
**concurrency lives across workers** (the pool). The to-do list + recursion +
quiescence handle "collect newly found machines until none remain."

---

## 5. How to plug in your own collector (the part you asked for)

A **phase** is one ordered step. To add a real collector (or replace a stub),
you do three things: write the collect function, register the phase, and (for
graph output) give its tables real models.

### Step 1 — Write the collect function

It's a **generator** that takes `(target, ctx)` and `yield`s `(table_name, row)`
pairs. Put it in `collectors/<phase>.py`.

```python
# collectors/mssql.py
from typing import Any, Iterable
from ..context import SourceContext

def collect_mssql(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict]]:
    # `target` is the hostname. `ctx` is the shared SourceContext: it has the
    # AD client (ctx.ad), settings, caches, and register_target().
    for instance in _enumerate_sql_instances(target, ctx):
        yield ("mssql_instances", {"host": target, "instance": instance.name})
        for login in instance.logins:
            yield ("mssql_logins", {"host": target, "login": login})

            # Discovered a NEW machine (e.g. a linked server)? Register it so it
            # gets the full phase sequence too. This is how recursion happens.
            if login.is_linked_server:
                ctx.register_target(login.remote_host, source="MSSQL-LinkedServer")
```

Rules for the collect function:

- **`yield` rows one at a time** (it's a generator). Never build and return a
  giant list — that's what keeps memory flat for huge tables.
- **Only `yield (table_name, row)` for tables your phase declares** (see Step 2).
- **To discover a new *machine to probe***, call
  `ctx.register_target(name, source="...")`. The next free worker collects it.
- **Inventory rows are data, not targets.** If AdminService returns 100,000
  client devices, `yield` them as rows — do **not** call `register_target` per
  device. Only genuine probe targets (servers, management points) go on the
  queue. (This is what keeps the to-do list small.)
- **Failures are isolated**: if your function raises, the engine logs it and
  moves on to the next phase for that host. You don't need to catch everything,
  but catch what you can recover from.
- **Logging is automatic**: any `logger.*` call inside the function is tagged
  `[host][phase]` for you.

### Step 2 — Register the phase

Add it to the ordered list in `per_host_phases.py`. **The order in this tuple is
the order phases run.** The phase **name must equal its `--collection-methods`
token** (that's how method-gating works — see §6).

```python
# per_host_phases.py
from .collectors import mssql

PER_HOST_PHASES = (
    Phase("RemoteRegistry", ("registry_sccm_components",), stubs.stub_remote_registry),
    Phase("MSSQL", ("mssql_instances", "mssql_logins"), mssql.collect_mssql),   # ← real one
    Phase("AdminService", (...), stubs.stub_adminservice),
    Phase("HTTP", ("http_management_points",), stubs.stub_http),
    Phase("SMB", ("smb_signing",), stubs.stub_smb),
)
```

`Phase` has three fields:
- `name` — stable id + the `--collection-methods` gating token;
- `streams` — the **tuple of every table** this phase may write to;
- `run` — your collect function.

That's it. The framework now feeds every target through your phase, streams its
tables to disk, and re-runs it for any machine your phase (or any other)
discovers. **No changes to `main.py` or the engine are needed.**

### Step 3 — Give the tables real models (for graph conversion)

Today every per-host table is emitted with a **placeholder** model
(`raw_table_asset(table_name)` in `source.py`), which stages the raw rows but
emits no graph nodes/edges. When you want a table to become BloodHound
nodes/edges, define a typed `BaseAsset` model for it (see
`.agents/skills/openhound/references/add-asset.md`) and point its emit resource
at that model instead of the placeholder. The convert phase maps each table to
its model by the resource's `columns=` model, so the table name and the model
must line up.

> The emit resources are generated in `source.py::_make_emit_resource`. Extending
> it to look up a real model per table (falling back to `raw_table_asset`) is the
> natural next step when you wire the first real collector's graph output.

---

## 6. The guarantees, and how each is enforced

| Guarantee | How |
|---|---|
| **Phases run in order, per machine** | `run_one_target` iterates `PER_HOST_PHASES` sequentially for one target ([engine.py](../src/openhound_sccm/phased_pipeline/engine.py)). |
| **Many machines at once** | `run_pipeline` uses a `ThreadPoolExecutor(max_workers=--threads)`. |
| **New machines get the full sequence** | a phase calls `ctx.register_target` → `WorkQueue.submit`; the dispatcher hands it to a free worker. |
| **Runs until nothing is left** | `WorkQueue.next()` returns `None` only at *quiescence* (nothing pending **and** nothing in flight); the discovering worker submits **before** it releases its in-flight slot, so "done" can't be declared mid-discovery. |
| **Bounded memory** | streams are bounded (`maxsize`, default 1000); a full stream makes the producer wait (backpressure). |
| **Clean shutdown** | at quiescence `broadcast_done` puts `DONE` on every stream; emit resources stop on `DONE`. `run_pipeline` broadcasts `DONE` in a `finally`, and `_run_per_host_stage` drains streams + joins the engine thread even if `pipeline.run` errors — so it never hangs. |
| **`--computers` limits collection** | `register_target` runs the allow-list check (`_is_allowed_target`) **before** submitting; a discovered machine not in `--computers`/`--computer-file` is dropped (recursion suppressed for it). Empty list = allow all. |
| **`--collection-methods` selects steps** | the engine's `should_run(target, phase, ctx)` hook returns `ctx.method_enabled(phase.name)`. It selects *which phases run*, not which machines — discovered machines still get the enabled phases. |
| **Readable logs under concurrency** | every line is tagged `[host][phase]`; the ordered log **file** buffers each machine's lines and writes them as one contiguous block when the machine finishes (`_OrderedLogFileHandler.flush_host`). The console still interleaves — that's inherent to running 10 machines at once. |

---

## 7. Reusing the engine in another project

The `phased_pipeline` package has **no SCCM/AD/DLT imports** (a test enforces
this), so any project can use it. Minimal example:

```python
from phased_pipeline import WorkQueue, Phase, run_pipeline, build_streams, DONE

# 1. Define phases: each run() yields (stream_name, row).
def scan_ports(host, ctx):
    for port in (22, 80, 443):
        if _is_open(host, port):
            yield ("open_ports", {"host": host, "port": port})

def scan_web(host, ctx):
    if _has_web(host):
        yield ("web", {"host": host})
        for link in _crawl(host):                 # discover new hosts → recursion
            ctx.work_queue.submit(link)

PHASES = (Phase("ports", ("open_ports",), scan_ports),
          Phase("web", ("web",), scan_web))

# 2. Seed the to-do list and build the output streams.
wq = WorkQueue()
for h in ("a.example", "b.example"):
    wq.submit(h)
streams = build_streams(["open_ports", "web"], maxsize=1000)

# 3. Start a consumer per stream (drain until DONE) however your project writes
#    output, then run the engine. (DONE is broadcast at quiescence.)
ctx = MyContext(work_queue=wq)            # whatever object your phases need
run_pipeline(wq, ctx, PHASES, streams, max_workers=10)
```

The engine's optional hooks let a host project add cross-cutting behavior
without the engine knowing about it:

- `should_run(target, phase, ctx) -> bool` — skip phases (SCCM uses it for
  `--collection-methods`).
- `phase_scope(target, phase_name)` — a context manager wrapped around each phase
  (SCCM uses it to set `[host][phase]` logging context).
- `on_target_complete(target)` — called when a target finishes all phases (SCCM
  uses it to flush that host's log block). It runs **before** the in-flight slot
  is released, so it may safely submit new targets.

> **One operational note when reusing it:** every stream needs a consumer that
> keeps draining until `DONE`. If you drain N streams with a thread pool, give
> the pool **at least N threads** — an undrained stream + a full bounded queue
> will deadlock the producer. (This is exactly why the SCCM adapter raises
> `EXTRACT__WORKERS` to one-per-table for the emit pass.)

---

## 8. Running it from the CLI

```
openhound collect sccm <output_dir> -d mayyhem.com \
    --threads 10 \                 # machines collected concurrently (default 10)
    -m All \                       # or: RemoteRegistry,MSSQL,...  (which steps run)
    -c host1,host2                 # optional allow-list: ONLY these machines
```

- `--threads` → worker-pool size (machines at once).
- `--collection-methods` (`-m`) → which phases run (discovery + per-host). Phase
  names are the tokens: `RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB`
  (plus discovery: `LDAP, Local, DNS`).
- `--computers` / `--computer-file` → machine allow-list. With either set, only
  those machines are collected and discovered machines outside the list are
  dropped. With neither, discovery + recursion run fully.

---

## 9. Current status

- The framework is complete and tested (`tests/test_pp_*.py`,
  `tests/test_per_host_*.py`).
- **All per-host phases are stubs** returning deterministic test data
  (`collectors/stubs.py`). They prove the orchestration works end-to-end
  (ordering, concurrency, recursion, multi-table emission, backpressure,
  termination, per-host logging) before the real collectors are ported.
- Replacing each stub with a real collector is a separate follow-up ticket
  (RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB) — each one is just §5
  applied to that phase.
- Per-domain re-collection (re-running LDAP/DNS against newly discovered
  domains) is a deliberately deferred feature; the two-stage design leaves room
  for a second to-do list (for domains) but builds none of it yet.
