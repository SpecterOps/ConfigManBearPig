# Concurrent Per-Target Collection Framework — Implementation Plan (plain-English edition)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **About this edition:** This version is written for a human reviewer with an *intermediate* (not advanced) software background. Every uncommon term is defined in the Glossary below and explained again the first time it appears in a task. Steps describe *what* to do and *what to check* in plain words rather than as code. A second, terser edition aimed at senior engineers/agents will be produced after this one is approved.

**Goal:** Build the machinery that collects from many machines at the same time — each machine running its collection steps in a fixed order — and that automatically collects from any *new* machine it discovers along the way, until there are no machines left to collect. For this build, the collection steps are **stubs** (fake steps returning test data) so we can prove the machinery works before writing the real collectors.

**Two-piece design (this is the important part):**
1. A **reusable engine** (`phased_pipeline/`) that knows nothing about SCCM, Active Directory, or DLT. It only understands "targets," "ordered steps," "output channels," and "collect new targets you discover." Another project could drop this engine in and supply its own steps.
2. A thin **SCCM adapter** that plugs SCCM's specific steps, output tables, and plumbing into that engine.

**Tech Stack:** Python, threads (`concurrent.futures.ThreadPoolExecutor`, `queue.Queue`, `threading`), DLT for writing tables to disk (SCCM adapter only), pytest. All changes are inside `sccm/sccm/`.

---

## Glossary (plain-language definitions)

Read these once; each is also re-explained where it first appears.

- **Target** — a machine we collect from, identified by its hostname.
- **Phase / step** — one unit of collection (e.g. "RemoteRegistry"). For each target, phases run in a fixed order.
- **Context object** — a shared bag of settings, connections, and helpers handed to each phase so it can do its work.
- **Generator function** — a function that hands back results one at a time using `yield`, instead of building a giant list. This lets us pass along millions of rows without ever holding them all in memory at once.
- **Work queue / to-do list** — the list of targets waiting to be collected.
- **Worker** — one thread collecting one target at a time. **Thread pool** — a fixed-size group of workers (default **10**), so at most 10 targets are collected simultaneously.
- **Dispatcher** — the loop that takes targets off the to-do list and hands each to a free worker.
- **In-flight** — how many targets are *currently being worked on* (handed to a worker but not finished yet). We track this so we know when everything is truly done.
- **Quiescence** — the "everything is quiet" moment: the to-do list is empty **and** nothing is in-flight. Nothing left to start, nothing still running. This is when we stop.
- **Recursion (here)** — "collection that feeds itself": while collecting target A we may discover target B; we add B to the to-do list and collect it the same way. New discoveries from B feed back in too, until quiescence.
- **Stream / output channel** — a named pipe for results, one per output table. A phase drops rows onto a stream; a consumer reads them off and writes them to disk.
- **Stream registry** — a simple dictionary mapping each stream/table name to its queue, shared so the side putting rows in and the side taking rows out use the *same* queue.
- **Bounded queue** — a queue with a maximum length. When it's full, adding an item *waits* until something is removed. This is what caps memory.
- **Backpressure** — the automatic "slow down" that happens when a fast producer has to wait because a bounded queue is full. It makes collection proceed only as fast as rows are written to disk, keeping memory flat.
- **Producer / consumer** — *producer* = code putting rows onto a stream (a worker running a phase). *consumer* = code taking rows off and writing them (the emit resource → DLT → disk).
- **Sentinel** — a special marker value put on a queue to mean "no more items are coming — you can stop." We use one shared marker called `DONE`.
- **Guarded (by a lock)** — protected so only one thread touches a piece of shared data at a time, preventing corruption when many threads run at once.
- **Waiter** — a thread that has paused *inside* the queue, waiting for either new work to arrive or a "we're all done" signal.
- **Deadlock** — a stuck situation where threads wait on each other forever and nothing makes progress. We design specifically to avoid it.
- **Factory function** — a function whose job is to build and return another object. Here, a factory builds one "emit" resource per table so we don't hand-write near-identical copies.
- **Frozen dataclass** — a tiny read-only record (its fields can't change after it's created), good for fixed configuration like "the definition of a phase."
- **Determinism / deterministic** — always gives the same result for the same input. Our stubs are deterministic so tests can check for exact, known output.
- **Assert (in a test)** — a check that something is true; if it isn't, the test fails. When a step says "assert X," it means "the test confirms X."

---

## Background: what this replaces and why

- Today's `source.py` tries to express per-target work as a DLT pipe **loop** (it feeds a step's output back into itself). DLT pipes can't loop, so this crashes (`InvalidResourceDataTypeMultiplePipes`). We delete that wiring.
- Today's `main.py` drives collection with `TargetQueue` from the `collector-utils` package, which tracks a status for every `(target, phase)` pair. In the new design a single worker runs *all* phases for one target in order, so that per-pair status is unnecessary bookkeeping. We stop importing `TargetQueue` (we do **not** modify it — it lives outside `sccm/sccm/` and is off-limits) and use the new engine's own to-do list instead.
- Because each target is collected exactly once (the to-do list refuses duplicates), there is **no need to track which phases finished per target** — that complexity is dropped.

## The five rules that keep it correct and memory-safe

1. **Phases are generator functions** — they `yield` one `(stream_name, row)` at a time and never build a full list. (So a phase can emit millions of rows without holding them in memory.)
2. **Streams are bounded** — each output channel has a maximum length; a full channel makes the worker *wait* (backpressure), so total memory stays roughly `workers × channel size` no matter how much data exists.
3. **Consumers stop only on the `DONE` marker** — an emit resource reading an empty stream *waits*; it stops only when it receives the shared `DONE` sentinel, which is sent to *every* stream at quiescence. An empty stream means "wait," never "finished."
4. **Quiescence can't be declared early** — when a phase discovers a new target it adds it to the to-do list *before* its worker reports finished, so the dispatcher never thinks "all done" while a discovery is in progress.
5. **New machines are targets; their inventory is data** — a phase adds genuine probe targets (servers, management points) to the to-do list, but writes client-device inventory as plain rows. It must **not** add a to-do entry per client device (that's what keeps the to-do list small even with millions of devices).

## How the limiting options behave (preserve this intent)

Two command-line options "limit" work, but they limit *different* things — and only one is a machine allow-list. The plan must preserve both behaviors exactly as the PS1 does.

- **`--computers` / `--computer-file` = machine allow-list (limits *which machines* we collect).** When either is given, only those machines (and any discovered machine that happens to match the list) are collected; **newly-discovered machines that are not in the list are dropped and never added to the to-do list** — so recursion is effectively switched off for anything you didn't ask for. With *neither* option given, the list is empty, which means "allow everything," and discovery + recursion run fully. This filter already lives in `register_target(...)` (`_is_allowed_target`), which sits *upstream* of adding to the to-do list. **The one risk is accidentally dropping this filter while rewiring `register_target` to the new to-do list — Task 6 keeps it explicitly and tests it.**
- **`--collection-methods` = phase selector (limits *which steps run*), NOT a machine limiter.** It decides which phases execute (both the discovery steps and the per-machine steps), via `ctx.method_enabled(...)`. It does **not** stop discovered machines from being added — those machines still get whatever phases are enabled. (If you turn off a discovery step, fewer machines turn up, but that's a side effect of not running that step, not an allow-list.) The engine receives this as the optional `should_run(target, phase, context)` check, which simply returns `ctx.method_enabled(phase.method)`.

## File structure

### Reusable engine — `sccm/sccm/src/openhound_sccm/phased_pipeline/` (no SCCM, AD, or DLT imports)

- `phased_pipeline/__init__.py` — the public surface: `WorkQueue`, `Phase`, `run_pipeline`, `DONE`, `build_streams`, `broadcast_done`.
- `phased_pipeline/work_queue.py` — `WorkQueue`: the to-do list with duplicate-rejection, in-flight counting, and quiescence detection.
- `phased_pipeline/streams.py` — the `DONE` marker, `build_streams(...)` to make one bounded queue per channel name, and `broadcast_done(...)` to drop `DONE` on every channel.
- `phased_pipeline/engine.py` — the `Phase` record, `run_one_target(...)` (run one target through its phases in order), and `run_pipeline(...)` (the dispatcher + thread pool + recursion + quiescence shutdown).

This sub-package imports only the Python standard library, so it can later be copied into its own installable package and reused by another project.

### SCCM adapter — existing `sccm/sccm/src/openhound_sccm/` modules

- `collectors/stubs.py` (new) — one fake phase per real phase, returning deterministic test data.
- `per_host_phases.py` (new) — the ordered list of SCCM phases (pointing at the stubs for now) and the helper that lists every table they write.
- `source.py` (modify) — delete the broken loop; register one "emit" resource per table; expose them for the writing stage.
- `context.py` (modify) — give the context the engine's to-do list; `register_target(...)` adds new targets to it.
- `main.py` (modify) — run discovery first, then run the engine and the table-writing stage together; change the `--threads` default from 1 to 10; stop using `TargetQueue`.
- `log_context.py` (modify) — add a "this target is fully finished" notification so the log file can group each target's lines together.

### Tests — `sccm/sccm/tests/`

- Engine: `test_pp_work_queue.py`, `test_pp_streams.py`, `test_pp_engine.py` (engine tests use *fake* phases and **no** SCCM code — proving the engine stands alone).
- Adapter: `test_per_host_phases.py`, `test_per_host_wiring.py`, `test_per_host_log_blocks.py`, `test_per_host_integration.py`.

## How to run tests (per AGENTS.md — use a throwaway environment, never the repo's `.venv`)

From `sccm/sccm/`, on this Windows machine:

```
$env:UV_PROJECT_ENVIRONMENT="$env:TEMP\openhound-venv"; uv run pytest tests/<file>::<test> -v
```

Each "run the test" step below uses this command form.

---

## PART A — The reusable engine

### Task 1: The to-do list (`WorkQueue`)

The to-do list holds targets waiting to be collected. It refuses duplicates, counts how many targets are *in-flight* (being worked on right now), and can tell when we've reached *quiescence* (nothing waiting and nothing running).

**Files:**
- Create: `phased_pipeline/__init__.py` (empty for now)
- Create: `phased_pipeline/work_queue.py`
- Test: `tests/test_pp_work_queue.py`

- [ ] **Step 1: Write the failing tests.** In plain terms, the tests check:
  - **Refuses duplicates:** adding the same target name twice (ignoring upper/lower case) means it is handed out only once.
  - **Hands out and counts:** after a target is handed out, the count of "in-flight" targets goes up by one.
  - **Knows when we're done (quiescence):** when nothing is waiting and nothing is in-flight, asking for the next target returns a special "stop" answer (`None`).
  - **A pause that ends when work appears:** if a target is in-flight and another thread asks for the next target, that asking thread *pauses* (it's a "waiter") until either a new target is added or the in-flight target is marked finished.
  - **Safe with many threads at once:** several threads adding targets while one thread takes them out hands every distinct target out exactly once, then returns the stop answer.

- [ ] **Step 2: Run the tests and confirm they fail** (the `WorkQueue` class doesn't exist yet).

- [ ] **Step 3: Build `WorkQueue`.** In plain terms:
  - Keep three pieces of shared data, all *guarded by* one lock (so only one thread changes them at a time): a list of waiting targets, a set of names already seen (for duplicate-rejection), and an integer count of in-flight targets.
  - `submit(target)` — clean up the name; if already seen, do nothing and report "not added"; otherwise record it as seen, add it to the waiting list, and wake any paused waiter.
  - `next()` — if a target is waiting, remove and return it and add one to the in-flight count; if nothing is waiting but some target is still in-flight, *pause* until woken; if nothing is waiting and nothing is in-flight, return the stop answer (`None`).
  - `complete(target)` — subtract one from the in-flight count; if now nothing is waiting and nothing is in-flight, wake any waiters so they can see we've reached quiescence.
  - Add a docstring noting that callers must always add a discovered target (`submit`) *before* marking the current one finished (`complete`) — this ordering is what prevents declaring "done" too early.

- [ ] **Step 4: Run the tests and confirm they pass.**

- [ ] **Step 5: Commit** — message: `feat(phased-pipeline): work queue with dedup, in-flight count, quiescence`.

---

### Task 2: Output channels (`streams`) and the `DONE` marker

Each output table has its own *stream* (a named queue). Phases drop rows onto streams; later, consumers read rows off and write them to disk. Streams are *bounded* (capped length) so memory stays flat. When everything is finished, we put one shared `DONE` marker on every stream to tell consumers to stop.

**Files:**
- Create: `phased_pipeline/streams.py`
- Test: `tests/test_pp_streams.py`

- [ ] **Step 1: Write the failing tests.** They check:
  - **Builds one capped queue per name:** asking for streams `{"a","b"}` with a max length of 5 gives two queues, each with maximum length 5.
  - **Full means wait (backpressure):** filling a stream to its limit makes the next "put" *wait* until a "get" frees a slot (check with a quick two-thread producer/consumer pair).
  - **`DONE` is one shared marker:** `broadcast_done(streams)` places that same marker on every stream.

- [ ] **Step 2: Run the tests and confirm they fail.**

- [ ] **Step 3: Build `streams.py`.** In plain terms:
  - Define a single unique marker value named `DONE` (one shared object meaning "no more rows").
  - `build_streams(names, maxsize)` — return a dictionary mapping each name to a new bounded queue of length `maxsize`.
  - `broadcast_done(streams)` — put the `DONE` marker on every stream (a normal blocking put is fine; it guarantees the marker is delivered even when a stream is momentarily full).

- [ ] **Step 4: Run the tests and confirm they pass.**

- [ ] **Step 5: Commit** — `feat(phased-pipeline): bounded output streams and DONE marker`.

---

### Task 3: Running one target through its phases (`Phase` + `run_one_target`)

This is the per-target recipe: take one target and run each of its phases *in order*, sending every row a phase produces to the right output stream. If a phase fails, log it and keep going with the next phase.

**Files:**
- Create: `phased_pipeline/engine.py` (this task adds `Phase` and `run_one_target`; Task 4 adds the pool)
- Test: `tests/test_pp_engine.py`

- [ ] **Step 1: Write the failing tests.** Using *fake* phases (simple generator functions), they check:
  - **Order is preserved:** rows arrive in phase order — everything from phase 1 before anything from phase 2, and so on.
  - **Rows go to the right stream:** each row a phase yields lands on the stream named in its `(stream_name, row)` pair and on no other.
  - **A phase can be skipped:** if the optional "should this phase run?" check returns false for a phase, that phase produces nothing.
  - **One failing phase doesn't stop the rest:** if a phase raises an error partway through, it's logged and the *following* phases still run and still produce their rows.
  - **The wrapper runs around each phase:** the optional "scope" wrapper (used later for logging) is active while each phase runs (check with a small probe).

- [ ] **Step 2: Run the tests and confirm they fail** (`run_one_target` doesn't exist).

- [ ] **Step 3: Build `Phase` and `run_one_target`.** In plain terms:
  - `Phase` is a *frozen dataclass* (a small read-only record) with: a `name`, the list of `streams` (output channel names) it can write to, and `run` — a *generator function* taking `(target, context)` and yielding `(stream_name, row)` pairs.
  - `run_one_target(target, context, phases, streams, should_run=None, phase_scope=None)`:
    - For each phase in order: if `should_run` is given and returns false for this phase, skip it. Otherwise, enter the optional `phase_scope(target, phase.name)` wrapper, then loop over the phase's `run(target, context)`; for each `(stream_name, row)`, put `row` onto `streams[stream_name]` (this put may *wait* when the stream is full — that's the intended backpressure).
    - Wrap each phase in error handling: if it raises, log the error and continue to the next phase (don't abort the target).
  - `should_run` and `phase_scope` default to "no-op" so the engine works with or without them — keeping it project-neutral.

- [ ] **Step 4: Run the tests and confirm they pass.**

- [ ] **Step 5: Commit** — `feat(phased-pipeline): Phase record and single-target ordered runner`.

---

### Task 4: The thread pool and the whole loop (`run_pipeline`)

This ties it together: a *dispatcher* takes targets off the to-do list and hands each to a free *worker* (one of up to N threads). Workers run targets through their phases; when a phase discovers a new target it's added to the to-do list and picked up by the next free worker (*recursion*). When the to-do list is empty and nothing is in-flight (*quiescence*), we shut down and put the `DONE` marker on every stream.

**Files:**
- Modify: `phased_pipeline/engine.py`
- Modify: `phased_pipeline/__init__.py` (export the public names)
- Test: `tests/test_pp_engine.py` (add cases)

- [ ] **Step 1: Write the failing tests** (still using fake phases, no SCCM):
  - **Clears the list:** start with several targets; after running, every target's rows reached the right streams and the call returned (it didn't hang).
  - **Recursion works:** start with one target whose fake phase adds one new target; confirm the new target's phases also ran before everything finished.
  - **Respects the worker limit:** with the pool size set to 2 and a fake phase that briefly sleeps, confirm no more than 2 targets are ever being collected at the same time (record the simultaneous count under a lock).
  - **Signals the end:** after the run, every stream has received the `DONE` marker.
  - **No getting stuck under backpressure:** with a very small stream limit and a deliberately slow consumer, the whole run still finishes (producers wait, then continue — no *deadlock*).

- [ ] **Step 2: Run the tests and confirm they fail** (`run_pipeline` doesn't exist).

- [ ] **Step 3: Build `run_pipeline(work_queue, context, phases, streams, max_workers, should_run=None, phase_scope=None, on_target_complete=None)`.** In plain terms:
  - Create a thread pool of `max_workers` workers.
  - Dispatcher loop: ask the to-do list for the `next()` target; if it returns the stop answer (`None`, meaning quiescence), break out of the loop; otherwise hand the target to a free worker, which runs `run_one_target(...)` for it and then, in a "no matter what" block, marks the target finished on the to-do list (`complete`) and calls `on_target_complete(target)` if provided.
  - Because a phase adds any new target *before* its worker marks finished, the to-do list won't report quiescence while a discovery is mid-flight.
  - After the loop ends, wait for all workers to finish, then call `broadcast_done(streams)` so every consumer stops.
  - Keep this function ordinary/synchronous; the SCCM adapter will run it on a background thread so the table-writing stage can run at the same time.
  - Export `WorkQueue`, `Phase`, `run_pipeline`, `DONE`, `build_streams`, `broadcast_done` from `phased_pipeline/__init__.py`.

- [ ] **Step 4: Run the tests and confirm they pass** — including a short "module imports nothing project-specific" check (importing `phased_pipeline` must not require SCCM/AD/DLT).

- [ ] **Step 5: Commit** — `feat(phased-pipeline): thread pool, recursion, quiescent shutdown`.

---

## PART B — The SCCM adapter

### Task 5: SCCM phase list + stub collectors

Define the ordered SCCM phases and, for now, point each at a *stub* — a fake collector returning *deterministic* (fixed, predictable) test data. One stub adds a new target (to exercise recursion); one stub writes to several tables (to show a single phase can fill multiple tables).

**Files:**
- Create: `collectors/stubs.py`
- Create: `per_host_phases.py`
- Test: `tests/test_per_host_phases.py`

- [ ] **Step 1: Write the failing tests.** They check:
  - **Right phases, right order:** the phase list is exactly `RemoteRegistry, MSSQL, AdminService, HTTP, SMB` in that order (WMI is intentionally left out — it comes with the real collectors later).
  - **Table list:** the helper that lists every table the phases write returns the combined set with no repeats, and includes the several AdminService tables.
  - **Stubs are deterministic:** each stub, given a hostname, yields a fixed, known set of `(table, row)` pairs (the test checks the exact rows).
  - **AdminService writes several tables:** its stub yields rows for more than one table name.
  - **Recursion hook:** the HTTP stub adds exactly one new target (a made-up hostname based on the input) by calling `register_target(...)` on the context, and only for "real" hosts (so it doesn't keep discovering forever), while still yielding its own row(s).
  - **Each phase only writes tables it declares.**

- [ ] **Step 2: Run the tests and confirm they fail.**

- [ ] **Step 3: Build the stubs and the phase list.** In plain terms:
  - In `stubs.py`: five *generator functions*, one per phase, each yielding `(table_name, row)` pairs with fixed content based on the hostname (for example, the registry stub yields one `registry_sccm_components` row `{"name": host}`; the AdminService stub yields a couple of `adminservice_admin_users` rows and a couple of `adminservice_client_devices` rows). The HTTP stub additionally calls `context.register_target("<host>-discovered", source="STUB-HTTP")` to simulate discovering a new machine, guarded so it only fires for non-made-up hosts.
  - In `per_host_phases.py`: build the ordered list of `Phase` records (from Part A) wrapping the five stubs, each with its `name`, the SCCM `--collection-methods` token it belongs to, and its table names. Add a helper that returns every table name across all phases with no duplicates. Use the existing `raw_table_asset(table_name)` placeholder as each table's validation model for now.

- [ ] **Step 4: Run the tests and confirm they pass.**

- [ ] **Step 5: Commit** — `feat(sccm): ordered phase list with deterministic stub collectors`.

---

### Task 6: Wire the writing side into `source.py`; remove the broken loop; connect discovery to the to-do list

The phases *produce* rows onto streams; we now need the DLT side that *consumes* those streams and writes each table to disk — one small "emit" resource per table, built by a *factory function* so we don't hand-write each one. We also delete the old broken loop and make `register_target(...)` add new machines to the engine's to-do list.

**Files:**
- Modify: `source.py`
- Modify: `context.py`
- Test: `tests/test_per_host_wiring.py`

- [ ] **Step 1: Write the failing tests.** They check:
  - **One emit resource per table:** building the SCCM source exposes a resource named after each table the phases write, and the old broken `per_host_collector_pipeline` name no longer exists.
  - **An emit resource drains then stops:** an emit resource for table "t" reading a stream that has two rows followed by the `DONE` marker yields exactly those two rows and then stops (it does not hang and does not yield the marker).
  - **New target reaches the to-do list:** calling `register_target(...)` for a brand-new machine calls the to-do list's `submit(...)` (use a stand-in to capture the call); for a machine already known, it does not.
  - **Allow-list still limits (this is the key regression test):** with the context's allowed-targets set to `{hostA}`, calling `register_target("hostB", ...)` does **not** call `submit(...)` (hostB is dropped); calling `register_target("hostA", ...)` does. With the allowed-targets set *empty*, any machine is submitted (allow-all).

- [ ] **Step 2: Run the tests and confirm they fail.**

- [ ] **Step 3: Implement.** In plain terms:
  - In `source.py`: delete the `per_host_collector_pipeline` step, the old `PER_HOST_RESOURCE_NAMES` list, and the looping entries in the source's return value. Keep the discovery resources (`ldap_*`, `dns_*`, `local_*`). Add a *factory function* that, given a table name, returns a small DLT resource which repeatedly reads from that table's stream and yields each row, stopping when it reads the `DONE` marker. Build one such resource for every table the phases write (look the streams up from a shared *stream registry* — a module-level dictionary set just before the writing stage runs, the same pattern the file already uses for shared state). Include these emit resources in what the source returns, so the writing stage can pick them by name.
  - In `context.py`: replace the old `target_queue` field with the engine's to-do list (`WorkQueue`), and change `register_target(...)` so that when it records a genuinely new machine it calls the to-do list's `submit(...)`. **Keep the existing allow-list check (`_is_allowed_target`) exactly where it is — it runs *before* the "new machine" step, so a discovered machine that isn't allowed is rejected and never reaches `submit(...)`. This is what preserves `--computers`/`--computer-file` limiting; do not move or remove it.** Remove only the leftover references to the old per-phase queue.

- [ ] **Step 4: Run the tests and confirm they pass**, and run the existing `tests/test_extension_methods.py` to confirm every emit resource still declares a validation model (a project rule checked by that test).

- [ ] **Step 5: Commit** — `refactor(sccm): per-table emit resources via factory; context feeds the work queue`.

---

### Task 7: Two stages in `main.py`; default to 10 workers; drop `TargetQueue`

Run collection in two stages: first **discovery** (find the initial machines), then the **engine plus the writing stage running together** (workers collect and push rows; emit resources pull rows and write them). Change the default number of concurrent machines to 10 and remove the old `TargetQueue` driver.

**Files:**
- Modify: `main.py`
- Test: `tests/test_per_host_integration.py` (a focused orchestration check; the full end-to-end is Task 9)

- [ ] **Step 1: Write the failing tests.** They check:
  - The `--threads` option now defaults to **10**.
  - The new "stage 2" helper runs the engine on a background thread while the writing stage runs on the main thread, and only returns after *both* finish (it doesn't hang); confirm all stub tables were written to a temporary output folder.

- [ ] **Step 2: Run the tests and confirm they fail.**

- [ ] **Step 3: Implement.** In plain terms:
  - Change the `threads` option default from 1 to 10; update its help text to "Number of machines collected at the same time (default 10)."
  - Remove the `TargetQueue` import and the old `while queue.has_pending(): ...` loop. In their place:
    - **Stage 1 — discovery:** create the engine's to-do list, attach it to the shared context, and run the discovery resources once (the existing first pass). Discovery adds machines to the to-do list through `register_target(...)`. Also seed any machines given on the command line (`--computers` / `--computer-file`) by calling `register_target(host, source="CLI")` for each — **not** by adding them straight to the to-do list — so seeding goes through the same allow-list, resolution, and duplicate-rejection path as everything else. (The allow-list is built from those same options, so seeded machines pass it; discovered machines outside the list are dropped — see "How the limiting options behave.")
    - **Stage 2 — collect and write together:** build the bounded streams for every table the phases write (pick a sensible default maximum length — start with 1000) and install them in the shared stream registry. Start a background thread that runs the engine (`run_pipeline(...)`) with the worker count from `--threads`, passing in: the "should this phase run?" check, defined as `lambda target, phase, ctx: ctx.method_enabled(phase.method)` so `--collection-methods` selects which steps run; and the "target finished" notification (used for logging in Task 8). On the main thread, run the writing stage (the emit resources) so rows stream to disk as they're produced. When the background thread reports quiescence it puts the `DONE` marker on every stream, which lets the writing stage finish; then join the background thread and clear the stream registry.

- [ ] **Step 4: Run the tests and confirm they pass.**

- [ ] **Step 5: Commit** — `feat(sccm): two-stage discovery + concurrent collect/write; --threads default 10`.

---

### Task 8: Group each machine's log lines together in the log file

With up to 10 machines collected at once, the **console** will naturally mix lines from different machines (each line is already tagged `[host][phase]`, so it's still readable). For the **log file**, we want each machine's lines kept together as one block, written when that machine finishes.

**Files:**
- Modify: `log_context.py`
- Modify: `main.py` (the ordered log-file handler)
- Test: `tests/test_per_host_log_blocks.py`

- [ ] **Step 1: Write the failing tests.** They check:
  - **"Machine finished" notification:** registering a "target finished" callback and finishing a machine's phases calls it once with that machine's name.
  - **Blocks in the file:** with two machines collected at once, the log file contains each machine's lines as one unbroken block (one machine's lines are not interleaved with the other's *in the file*), and the blocks appear in the order the machines finished. (Console mixing is expected and not checked.)

- [ ] **Step 2: Run the tests and confirm they fail.**

- [ ] **Step 3: Implement.** In plain terms:
  - In `log_context.py`: add a "target finished" callback list (a sibling of the existing "resource finished" one), with register/unregister functions and an internal "fire" used by the engine's "target finished" notification (wired in Task 7).
  - In `main.py`'s ordered log-file handler: collect each machine's log lines into a per-machine buffer (keyed by the `[host]` tag on each line); when the "target finished" notification fires for a machine, write that machine's buffered lines to the file as one labelled block and drop the buffer. Lines with no machine tag (discovery/summary) keep their current behavior.

- [ ] **Step 4: Run the tests and confirm they pass.**

- [ ] **Step 5: Commit** — `feat(sccm): per-machine log blocks written on completion`.

---

### Task 9: Full end-to-end check with stubs

Prove the whole thing works together against a temporary output folder, using the stubs.

**Files:**
- Test: `tests/test_per_host_integration.py` (the full scenario)

- [ ] **Step 1: Write the failing end-to-end test.** Seed two machines onto the to-do list, run the real stage-2 (real thread pool, real bounded streams, real writing stage), and confirm:
  - Every stub table exists on disk and has the expected number of rows for the two machines.
  - The **recursion** machine (the made-up one the HTTP stub discovered) also has its rows in every table its phases write — **in the no-allow-list case** (run with no `--computers`).
  - **Allow-list limiting works (second scenario):** run the same setup but with the allow-list set to only the seeded machines. Confirm the seeded machines are collected but the HTTP stub's discovered machine is **absent** from the output (it was dropped by the allow-list, so recursion didn't reach it). This is the end-to-end proof that `--computers` limiting survives the rewire.
  - **It finishes** within a generous time limit (no hang) and the background thread has joined.
  - **Memory stays bounded:** run with a deliberately tiny stream limit (e.g. 2) and confirm the run still completes and writes all rows (proving producers wait-then-continue instead of piling up or getting stuck).
  - **Order is visible per machine:** a machine's log block shows its phase lines in `RemoteRegistry → … → SMB` order.

- [ ] **Step 2: Run the test and confirm it fails** (or is red until the wiring is right).

- [ ] **Step 3: Make it pass.** Fix any integration gaps (marker delivery, callback registration, stream registry timing). If this needs *new* behavior beyond Tasks 1–8, that means an earlier task has a gap — fix it there.

- [ ] **Step 4: Run all the new tests together:** `pytest tests/test_pp_*.py tests/test_per_host_*.py -v`.

- [ ] **Step 5: Commit** — `test(sccm): end-to-end framework check with stubs (recursion, backpressure, ordering)`.

---

## Out of scope (deliberately left for later)

- **Real collectors** (RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB) — each is its own follow-up; this build uses stubs only. The existing partial `collectors/registry.py` stays untouched for the future RemoteRegistry work and is not wired in.
- **Per-domain re-collection (ticket ope-e512)** — a future sprint. The two-stage design leaves room for a second to-do list (for domains) but builds none of it now.
- **DHCP and WMI phases** — turned off in the PS1's current settings; not built here.

## Final checklist before calling the framework done

- `pytest tests/test_pp_*.py tests/test_per_host_*.py -v` all pass in the throwaway environment.
- `pytest tests/test_extension_methods.py -v` still passes (every emit resource declares a validation model).
- A manual run (`openhound collect sccm ... --computers hostA,hostB --threads 10`) with stubs writes all stub tables, collects the discovered recursion machine, and produces per-machine log blocks. No live Active Directory is needed because the machines are seeded and the phases are fake.

## Notes for the reviewer

- **Where the reusable engine lives (decided):** inside `sccm/sccm/`, as a standalone sub-package with no SCCM/AD/DLT imports, written to be portable so it can be lifted into its own installable package later. (Confirmed: keep it here for now as long as it's import-clean.)
- **A simplification vs the earlier draft:** because the to-do list refuses duplicates, each machine is collected exactly once, so we no longer track "which phases finished" per machine — that bookkeeping is gone.
- **Default stream length (1000):** confirmed fine.
- **Limiting-option intent (decided):** `--computers`/`--computer-file` is a machine allow-list that suppresses recursion into non-listed machines (enforced by `register_target`'s `_is_allowed_target`, kept upstream of the to-do list in Task 6); `--collection-methods` only selects which phases run (the engine's `should_run` hook) and does not limit machines. See "How the limiting options behave."
