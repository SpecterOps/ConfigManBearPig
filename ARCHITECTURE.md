# Architecture: How the SCCM Collector Diverges from a Stock OpenHound Collector

This document explains **how and why the SCCM collector's architecture had to depart from the shape
of a "normal" OpenHound collector** — the kind of collector OpenHound was designed for, which talks to
**one cloud service over one authenticated REST API** (Okta, GitHub, Jamf, …).

It is written for two readers:

- An **OpenHound framework maintainer** asking *"what does an on-prem collector need that the framework
  doesn't provide out of the box?"*
- A **contributor to this collector** asking *"why is the code shaped so differently from the
  reference collectors, and where does each unusual piece live?"*

Every section follows the same spine:

1. **The framework baseline** — what a stock REST collector assumes, and what OpenHound gives you for free.
2. **Why it breaks for SCCM** — the on-prem reality that violates that assumption.
3. **The add-on** — what this extension built on top, with code references.
4. **Trade-offs** — what the add-on costs.

> ### The one ground rule that shapes everything
>
> **We cannot modify OpenHound core.** Every divergence below is therefore an *add-on layered on the
> framework's public extension points* — a new Typer command, a DLT resource, a logging filter, a
> preproc transformer — or, where no extension point exists, a **runtime adjustment of live framework
> objects** (e.g. swapping a formatter on an already-attached log handler). Nothing here edits a file
> under `openhound/`. That constraint is *why* several of these solutions look indirect: when you can't
> change the framework, you wrap it, feed it, or mutate its instances at runtime.

> ### A second home, added later
>
> Several of the divergences below (the Windows auth stacks, the per-target logging layer, the
> push→pull streaming bridge, the DNS resolver) were originally built *inside this extension* and have
> since been **promoted into a shared library, `openhound-collector-common`, that both this collector
> and the MSSQL collector consume.** That library is still not `openhound/` core — the ground rule
> holds — but it means the *implementation* of those subsystems now lives one directory over, with
> SCCM's own files reduced to thin adapters. Read
> [Where this code lives](#where-this-code-lives-the-shared-collector-common-library) next; it explains
> what moved and why, and the sections that follow point back to it.

---

## Table of Contents

- [The big picture: one tenant vs. many hosts](#the-big-picture-one-tenant-vs-many-hosts)
- [Where this code lives: the shared collector-common library](#where-this-code-lives-the-shared-collector-common-library)
- [1. Pull-based DLT resources → a push-based per-host phased pipeline](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline)
- [2. Sequential phases per target, concurrent across targets — and a sequential debug harness](#2-sequential-phases-per-target-concurrent-across-targets--and-a-sequential-debug-harness)
- [3. Recursive target discovery and collection](#3-recursive-target-discovery-and-collection)
- [4. Targeted collection: an include-only allow-list](#4-targeted-collection-an-include-only-allow-list)
- [5. An Active Directory CLI surface and context auto-detection](#5-an-active-directory-cli-surface-and-context-auto-detection)
- [6. Windows authentication across five protocols](#6-windows-authentication-across-five-protocols)
- [7. Enhanced logging and diagnostics for blind remote environments](#7-enhanced-logging-and-diagnostics-for-blind-remote-environments)
- [8. Windows-isms: the platform fights back](#8-windows-isms-the-platform-fights-back)
- [9. Convert can't iterate DuckDB rows: the unified Computer-node problem](#9-convert-cant-iterate-duckdb-rows-the-unified-computer-node-problem)
- [10. dlt loads whatever the data contains; our SQL expects fixed columns](#10-dlt-loads-whatever-the-data-contains-our-sql-expects-fixed-columns)
- [11. Stage 2 preproc/convert add-ons](#11-stage-2-preprocconvert-add-ons)
  - [11a. Collect-side additions](#11a-collect-side-additions)
  - [11b. Persist-at-collect / gate-in-preproc for inferred client nodes](#11b-persist-at-collect--gate-in-preproc-for-inferred-client-nodes)
  - [11c. Traversable allow-list and the generic GraphEdge model](#11c-traversable-allow-list-and-the-generic-graphedge-model)
  - [11d. Stage 4: client-device dedup and host-correlation edges](#11d-stage-4-client-device-dedup-and-host-correlation-edges)
  - [11e. Edge-endpoint stub-node backfill (new divergence category)](#11e-edge-endpoint-stub-node-backfill-new-divergence-category)
  - [11f. Split output: an untagged AD payload beside the SCCM source](#11f-split-output-an-untagged-ad-payload-beside-the-sccm-source)
  - [11g. Stage 5: MSSQL node merge and topology inference](#11g-stage-5-mssql-node-merge-and-topology-inference)
  - [11h. Stage 6: coerce-and-relay possible edges and the synthetic Authenticated Users node](#11h-stage-6-coerce-and-relay-possible-edges-and-the-synthetic-authenticated-users-node)
  - [11i. HTTP version fingerprint from ccmsetup.exe — a new HTTP-phase capability](#11i-http-version-fingerprint-from-ccmsetupexe--a-new-http-phase-capability)
  - [11j. AD-object attribute capture via the per-host resolution cache](#11j-ad-object-attribute-capture-via-the-per-host-resolution-cache)
  - [11k. Tier A+ low-priv additions: the System Management container, nested `MemberOf`, and the `MSSQLSvc` SPN service account](#11k-tier-a-low-priv-additions-the-system-management-container-nested-memberof-and-the-mssqlsvc-spn-service-account)
  - [11l. The rest of the low-priv-assumed-edges plan: `site_hierarchy` fed from every source, D6 attribution, and the assumption/provenance engine](#11l-the-rest-of-the-low-priv-assumed-edges-plan-site_hierarchy-fed-from-every-source-d6-attribution-and-the-assumptionprovenance-engine)
- [12. One-command end-to-end: a `--run-all` flag, not a new verb](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)
- [13. Tunneling all collection traffic through a SOCKS5 pivot](#13-tunneling-all-collection-traffic-through-a-socks5-pivot)
- [14. A shared integration-test and payload-diff engine, invoked off `--run-all`](#14-a-shared-integration-test-and-payload-diff-engine-invoked-off---run-all)
- [Reference key: the shorthand used in this document](#reference-key-the-shorthand-used-in-this-document)
- [Changelog](#changelog)

---

## Reference key: the shorthand used in this document

Where each shorthand token below was decided. **Two unrelated things are numbered "Stage"** in this
document, and which one is meant depends on the section:

| Shorthand | Scheme | Meaning, and where it was decided |
|---|---|---|
| **Stage 1** / **Stage 2** — in [§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline) and [§4](#4-targeted-collection-an-include-only-allow-list) | **Collection** stages | The two halves of `collect`: Stage 1 is once-per-run discovery (LDAP / Local / DNS), Stage 2 is the per-host phased pipeline. From the per-host collection framework plan, `docs/superpowers/plans/2026-06-03-per-host-collection-framework.md`; walkthrough in `docs/per-host-collection-framework-tour.md`. |
| **Stage 1** – **Stage 7** — in [§9](#9-convert-cant-iterate-duckdb-rows-the-unified-computer-node-problem), [§11](#11-stage-2-preprocconvert-add-ons) and the [Changelog](#changelog) | **Graph pipeline** (Convert2-Read-DB) stages | The increments by which ConfigManBearPig's post-processing was ported into the DuckDB `preprocess` + `convert` stages: Stage 3 the RBAC fan-out, Stage 4 host correlation, Stage 5 MSSQL, Stage 6 coerce-and-relay, Stage 7 docs + validation. From the numbered plans `docs/superpowers/plans/2026-06-16-sccm-preproc-convert-stage0.md` … `2026-07-01-sccm-preproc-convert-stage7.md`, under one design spec, `docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md`. Note §11's own title uses *this* scheme. |
| **D2**, **D2a**, **D2b**, **D3**, **D4**, **D5**, **D6** | Locked design decisions | All from the **low-privilege assumed-edges** plan, `docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md` (design spec `docs/superpowers/specs/2026-07-23-low-priv-assumed-edges-design.md`). D2 = which hosts count as *the* site database; D2a = resolving the `MSSQLSvc` SPN holder at low privilege; D2b/D3 = the `SPN+SCCM` inference and the `assumed`/`assumptionBasis` provenance stamp; D4 = the capabilities-XML-named hierarchy root; D5 = `site_hierarchy` fed from every site-code source; D6 = per-host site-code attribution. **These are *not* the `D1`–`D11` of the separate MSSQL-extension collector's plan, which is a different repository and out of scope here.** |
| **Task 1** – **Task 14** (incl. `Task 1b`, `Task 1c`) | Implementation tasks | Tasks of that same low-privilege assumed-edges plan. Tasks 11–14 are its "Tier A+" additions: the `Container` node with `GenericAll` edges, the full nested `MemberOf` chain, and the `MSSQLSvc` SPN service account. |
| **Phase A** / **Phase B** | The two halves of the CMBP-parity property effort | `docs/superpowers/plans/2026-07-23-cmbp-parity-node-edge-properties.md` (design spec alongside it). Phase A = AD-object attribute capture (ticket `ope-c141`); Phase B = the extra `SCCM_Site` / `SCCM_ClientDevice` telemetry properties (ticket `ope-fb99`). |
| **§N** (e.g. `§7`, `§11h`) | Section anchors *within this document* | Self-navigating internal links, not external references. |
| **ope-XXXX** | `gtk` ticket ids | Files under `.tickets/`, not plans. Run `gtk show <id>` to read one. |

---

## The big picture: one tenant vs. many hosts

A stock OpenHound collector models a **single environment reached through a single API endpoint**. The
framework's three-phase pipeline (`collect → preproc → convert`) is built around that:

| Phase | What the framework assumes |
|---|---|
| `collect` | Each **resource** is a Python generator that the DLT engine *pulls* from — it calls the API, paginates, and yields rows. One resource ≈ one API endpoint ≈ one table of JSONL on disk. |
| `preproc` | Optionally load the JSONL into DuckDB and build derived/lookup tables for cross-referencing. |
| `convert` | Read the JSONL back, and for each row emit one OpenGraph node or edge. One row ≈ one graph entity. |

Authentication is a single bearer/OAuth token attached to every request. Discovery is trivial — there is
one tenant, and you already have its URL. There is no notion of "the data I collect tells me about *more
things to collect*," no notion of "collect host A but not host B," and no need to run different *kinds* of
collection in a fixed order against the *same* target.

**SCCM violates every one of those assumptions:**

- It collects from **many on-prem Windows hosts**, not one API. The set of hosts isn't known up front —
  it's **discovered** from LDAP, DNS, and the responses of hosts already probed.
- Each host is collected by running an **ordered sequence of protocol phases** (registry → SQL →
  AdminService → WMI → HTTP → SMB), where a later phase is *skipped* depending on what an earlier phase
  achieved.
- It speaks **five wire protocols** (LDAP, SMB, WMI/DCOM, HTTP, TDS/MSSQL), each with **Windows
  authentication** (Kerberos, NTLM, current-user SSPI, pass-the-hash, pass-the-ticket) — not a bearer token.
- A single graph entity (a **Computer**) is assembled from **many** collected tables, not one row.

The rest of this document is the catalogue of what had to be built to bridge that gap. The reference
predecessor is the PowerShell tool **ConfigManBearPig**, archived in
[`powershell_deprecated/`](powershell_deprecated/); many add-ons exist to
reproduce a behavior the single-process PowerShell script got "for free" by sharing in-memory state.

---

## Where this code lives: the shared collector-common library

### The framework baseline

A stock OpenHound collector is **one self-contained Python package**. The framework gives you extension
points to build against, but it has no notion of *code shared between two collectors* — each REST
collector is small and stands alone, so there is nothing to share and nowhere to put it.

### Why it breaks for SCCM (and MSSQL)

On-prem collectors are not small, and they are not alone. This extension and the sibling **MSSQL
collector** both have to do the same hard, **security-critical** things: authenticate over Windows
protocols with the full credential toolkit (Kerberos / NTLM / SSPI / pass-the-hash / pass-the-ticket),
bridge a *pushing* worker pool to DLT's *pulling* extractor, tag every log line with which target and
phase produced it, and resolve a domain controller over DNS. Built independently, each collector would
carry its **own copy** of an NTLM/SPNEGO token minter, an EPA channel-binding probe, a bounded-queue
stream bridge, and a `contextvars` logging layer. Two copies of code this subtle **drift** — a
lockout-safety fix or a channel-binding correction lands in one and rots in the other.

### The add-on: a shared library, with the mature implementation promoted *up* into it

The shared code lives in **`openhound-collector-common`** — a separate **published** package, declared as
a capped version range in `[project.dependencies]` in [`pyproject.toml`](pyproject.toml)
(`>=0.1.0,<0.2.0`; a 0.x library makes no API-stability promise, so an uncapped floor would let a
breaking 0.2 land silently in users' installs). It resolves from PyPI: there is deliberately **no**
`[tool.uv.sources]` table, because a `path = "../openhound-collector-common"` redirect breaks every
environment without that sibling checkout, starting with CI. A local editable redirect is a
develop-against-the-library convenience only, and never reaches a commit — the rationale and the exact
`git update-index --skip-worktree` dance are written out in `pyproject.toml`'s own comments. Both
collectors import the *same* module objects, not copies. It is **not** part of `openhound/` core; the
ground rule holds.

The direction of travel matters. These subsystems were **proven first in the SCCM collector**, then
**promoted up** into the shared library as a superset (SCCM's battle-tested behavior plus the
generalizations MSSQL needed), and both collectors were re-pointed at the shared implementation. Nothing
was cautiously re-written for the lowest common denominator — the richer, live-validated SCCM version
became the shared one. What moved:

| Subsystem (section) | Shared home (`openhound_collector_common.*`) | What SCCM keeps locally (the adapter) |
|---|---|---|
| Windows auth ladders + token minters ([§6](#6-windows-authentication-across-five-protocols)) | `clients/auth` (`choose_auth`, `is_ip`, `KerberosToken`, `SspiClient`, NTLM type-1/3), `clients/ad` (`AdClient` + lockout-safe bind waterfall), `clients/wmi` (impacket + pywin32 backends), `clients/mssql` (`detect_epa`) | `clients/ad.py` `ADClient(AdClient)` subclass + SCCM attribute maps; `clients/wmi.py` `WmiClient` wrapper; `clients/http_auth.py` negotiators wrapping `KerberosToken`/`SspiClient`; `clients/mssql_epa.py` thin `test_epa` adapter over `detect_epa` |
| Per-target/-phase/-resource logging ([§7](#7-enhanced-logging-and-diagnostics-for-blind-remote-environments)) | `logging/log_context` (the full superset: `[target][phase]` tagging, `with_log_context`, completion-callback registry, `VERBOSE`, the debug exc-info filter, `cached_with_log`, `trace_node/edge/...`) | `log_context.py` re-exports the shared machinery and binds the two collector-specific helpers (`cached_with_log`, `trace_*`) to SCCM's own logger names |
| Push→pull streaming bridge ([§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline)) | `dlt/source_bridge` (`StreamBridge`, `DONE`, `build_streams`, `broadcast_done`, `extract_workers_for`) | `phased_pipeline/streams.py` re-exports `DONE`/`build_streams`/`broadcast_done`; `source.py` plants a `StreamBridge` and its emit resources delegate their drain to it |
| DNS resolution ([§5](#5-an-active-directory-cli-surface-and-context-auto-detection)) | `discovery/dns` (`make_resolver`) | `main.py::_resolve_dc_via_dns` calls the shared `make_resolver`, keeps the SCCM-specific SRV query |
| End-to-end phase chaining ([§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)) | `orchestration/run` (`run_end_to_end`, `derive_stage_paths`, `StagePaths`, `zip_graph_output`) | `main.py::_run_e2e_after_collect` maps `--progress` and delegates; the `--run-all` flag on `collect_sccm` triggers it, passing `configmanbearpig_collection_<ts>.zip` as `graph_zip_name` |
| SOCKS5 pivot ([§13](#13-tunneling-all-collection-traffic-through-a-socks5-pivot)) | `proxy/patch.py` (process-wide `socket` interception), `proxy/socks.py` (dialer/handshake), `discovery/dns.py` (`force_tcp`) | `main.py` parse/validate (`_parse_proxy_or_exit`, `_require_dc_or_dns_for_proxy`) + the install-around-run wrap (`socks_proxy_installed`); the four proxy-aware DNS sites (`_resolve_dc_via_dns`, two sites in `collectors/dns.py`, `context.resolve_ip`) |
| Integration testing / payload diff ([§14](#14-a-shared-integration-test-and-payload-diff-engine-invoked-off---run-all)) | `integration_testing` (`graph.load_graph`, `matcher`, `cases.EdgeCase`/`NodeCase`, `runner.run_suite`, `compare.compare_graphs`, `coverage.report`) | `openhound_sccm/integration/` — mayyhem.com `fixtures/edges.py`+`fixtures/nodes.py` (61 `EdgeCase`, `NodeCase`s, two whole-graph invariants) and the `__init__.py` wiring (`run_integration_tests`, `compare_to_zip`) called from the two `collect sccm` **Testing** flags |

**Governance.** From an extension agent's point of view the shared library is **read-only** — an SCCM
change may not edit `openhound-collector-common`, exactly as it may not edit `openhound/` core. Promoting
new code up into the shared library is a deliberate, owner-approved act (it affects *both* collectors, so
both must be re-validated), not something done casually mid-feature.

**One relaxed invariant.** The phased engine ([§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline))
used to be provably self-contained: a test forbade *any* import of `dlt` / `ldap3` / `openhound` /
`openhound_sccm` in `phased_pipeline/*.py`. Adopting the shared stream primitives means the engine now
imports `openhound_collector_common.dlt.source_bridge` — so that test was relaxed to permit **exactly
that one** shared dependency, and nothing else ([`tests/pp_engine_test.py`](tests/pp_engine_test.py)).
The shared bridge is pure-queue standard-library code, so the engine stays free of the dlt library and
the framework.

### Trade-offs

- **A shared-library change is a two-collector change.** A fix in `clients/auth` or `logging/log_context`
  now lands in SCCM *and* MSSQL at once — good for consistency, but every such change must be validated
  against both, not just the collector that motivated it.
- **A third place to look.** Tracing an auth failure or a log-format quirk may lead out of `sccm/sccm/`
  into `openhound-collector-common/`. The adapter files above are deliberately thin so the jump is
  obvious, and each names its shared counterpart in its module docstring.
- **The behavior did not change — only its home.** The detailed descriptions in [§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline),
  [§6](#6-windows-authentication-across-five-protocols), and [§7](#7-enhanced-logging-and-diagnostics-for-blind-remote-environments)
  remain accurate about *what the code does*; they now describe code that lives in the shared library,
  reached through SCCM's adapters. Where a `file:line` reference in those sections points at a SCCM file
  that is now a re-export shim, the real implementation is the correspondingly-named module in
  `openhound_collector_common`.

---

## 1. Pull-based DLT resources → a push-based per-host phased pipeline

### The framework baseline

In a stock collector, `@app.resource` decorates a generator and DLT *owns the loop*: it calls your
generator, pulls rows, and writes them to disk. You never schedule anything — you just yield. DLT
interleaves several resource generators round-robin and runs them in a small worker pool it controls.

### Why it breaks for SCCM

SCCM collection isn't "iterate one API." It's "for each of N hosts, run an ordered list of phases, in a
worker pool, where the host list grows while you work." DLT's pull-the-generator model has no place to
express *per-host ordering*, *per-host fan-out across a thread pool*, or *a phase that decides at runtime
whether to run*. If we wrote each phase as a normal DLT resource, DLT would interleave them globally and
we'd lose the per-target ordering SCCM depends on.

### The add-on: a service-agnostic phased engine, bridged to DLT by streams

The extension ships its own miniature collection engine under
[`phased_pipeline/`](src/openhound_sccm/phased_pipeline/) — standard-library only, no DLT, no SCCM
knowledge, so it's independently testable:

| Piece | File | Role |
|---|---|---|
| `WorkQueue` | [`phased_pipeline/work_queue.py`](src/openhound_sccm/phased_pipeline/work_queue.py) | The to-do list of targets. Dedups, counts in-flight work, signals *quiescence* (see [§3](#3-recursive-target-discovery-and-collection)). |
| `Phase` + `run_one_target` + `run_pipeline` | [`phased_pipeline/engine.py`](src/openhound_sccm/phased_pipeline/engine.py) | A `Phase` is `(name, output-stream-names, generator)`. `run_one_target` runs one host through its phases **in declaration order** ([engine.py:70-81](src/openhound_sccm/phased_pipeline/engine.py#L70-L81)); `run_pipeline` drives a `ThreadPoolExecutor` over the queue ([engine.py:84-136](src/openhound_sccm/phased_pipeline/engine.py#L84-L136)). |
| `build_streams` / `DONE` / `broadcast_done` | [`phased_pipeline/streams.py`](src/openhound_sccm/phased_pipeline/streams.py) — a **re-export** of the shared `openhound_collector_common.dlt.source_bridge` primitives (see [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)) | One **bounded** `queue.Queue` per output table. Bounded means a fast producer *blocks* until the consumer catches up — **backpressure** that keeps memory flat. `DONE` is the single end-of-stream sentinel. Re-exporting (not copying) means the engine broadcasts the *same* `DONE` object the shared bridge compares against — the marker is identity-compared, so producer and consumer must agree on one instance. |

The hard part is making DLT — which insists on *pulling* — consume rows that are *pushed* by a separate
thread pool. The bridge itself is the shared **`StreamBridge`** (`openhound_collector_common.dlt.source_bridge`):
it owns the bounded per-table queues, the blocking drain, and the `DONE` handling. SCCM keeps only the
glue that `StreamBridge` can't provide, in [`source.py`](src/openhound_sccm/source.py):

- For every per-host output table, the extension registers a one-line DLT **"emit resource"** whose entire
  body delegates to the planted bridge's drain — [`_drain_stream` / `_make_emit_resource`](src/openhound_sccm/source.py).
  The bridge's `drain_stream` does a blocking `get()`: "an empty queue is a *wait*, not an end." This turns
  each DLT resource into a **consumer** of the engine's output instead of a producer. SCCM must keep this
  registration glue local (rather than use `StreamBridge.build_emit_resources` directly) because a
  conformance guard checks `app.dlt_resources` at **import** time — earlier than any run-scoped bridge can
  exist — so the emit resources are registered up front with the queue **late-bound** through a planted
  bridge.
- The two halves run concurrently in [`_run_per_host_stage`](src/openhound_sccm/main.py): the **engine runs
  on a background thread** (producing rows onto `bridge.streams`, then closing them with `DONE` at
  quiescence) while **`pipeline.run(...)` drains those queues on the main thread**.
- Each emit resource is declared `parallelized=True` so DLT gives each its own extract thread. A
  single-threaded round-robin extractor would block on the first momentarily-empty queue while another
  filled to capacity — a deadlock. To guarantee a worker per table, `_run_per_host_stage` wraps the run in
  the shared **`extract_workers_for(len(tables))`** context manager, which raises the framework's
  `EXTRACT__WORKERS` env var to `len(tables) + 2` for the duration and restores it afterward. (Both this
  worker bump and the bridge were **generalized from this exact SCCM code**; see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library).)

A second framework-shaped problem: DLT builds the source via **config injection** (every `source()`
parameter is a `dlt.config.value` / `dlt.secrets.value`, see [source.py:198-231](src/openhound_sccm/source.py#L198-L231)),
so there is **no constructor** through which to hand the source live Python objects (the shared work
queue, the AD-resolution cache, the stream registry). The extension threads them through **module-level
globals** planted just before each `pipeline.run` and cleared after —
[`set_shared_queue` / `set_bridge` / `get_last_ctx`](src/openhound_sccm/source.py) (`set_bridge` plants the
run-scoped `StreamBridge` the emit resources drain). It's a handshake, not elegance, but it's the only
channel the injection model leaves open.

Finally, collection is explicitly **two-staged** in [`collect_sccm`](src/openhound_sccm/main.py#L842-L1009).
These are the two **collection** stages of the per-host collection framework plan,
`docs/superpowers/plans/2026-06-03-per-host-collection-framework.md` — a different numbering from the
graph-pipeline stages used in §9 and §11 (see the
[Reference key](#reference-key-the-shorthand-used-in-this-document)):

```
Stage 1 — Discovery (DLT-scheduled, runs once)
  ldap_* / dns_* / local_*  resources  →  register_target()  →  seeds the WorkQueue
                                   │
Stage 2 — Per-host (engine thread pool + emit-resource drain)
  drain WorkQueue → run_one_target(host) per worker → stream rows → emit resources write JSONL
```

Stage 1 is selected with `src.with_resources(*DISCOVERY_RESOURCE_NAMES)`
([main.py:957-959](src/openhound_sccm/main.py#L957-L959)); Stage 2 is the engine + emit pass.

### Trade-offs

- `_run_per_host_stage` installs **process-global** state (the planted `StreamBridge`, the bumped
  `EXTRACT__WORKERS`), so it assumes **one collect run per process** — true for the CLI, documented as
  "not reentrant" in the function docstring.
- The `finally` block must empty the queues (`bridge.drain_to_unblock()`) while joining the engine thread
  so a crashed `pipeline.run` can't leave a worker blocked forever on a full queue.
- We pay the cost of running two cooperating schedulers (our engine + DLT's extractor) instead of one.

---

## 2. Sequential phases per target, concurrent across targets — and a sequential debug harness

### The framework baseline

A stock collector has no concept of "phases that must run in a fixed order against the same target."
Resources are independent; DLT may run them in any interleaving. There is also no built-in way to run a
*single unit of collection* deterministically for debugging — you'd run the whole `collect` command.

### Why it breaks for SCCM

Order matters. ConfigManBearPig probes a host RemoteRegistry-first, then MSSQL, then the privileged
AdminService API, then WMI **only if** AdminService failed, then unauthenticated HTTP/SMB **only if**
nothing privileged succeeded. That ordering and the "fall back only if the better method didn't work"
logic is core to both correctness and operational stealth. And because these phases make real network
calls to real customer infrastructure, a developer needs to step through **one host, one phase, on one
thread** without the noise of a 10-way thread pool.

### The add-on: ordered phases + a runtime `should_run` gate + a standalone harness

- **Ordering** is just the declaration order of [`PER_HOST_PHASES`](src/openhound_sccm/per_host_phases.py#L19-L89);
  `run_one_target` honors it strictly ([engine.py:70-81](src/openhound_sccm/phased_pipeline/engine.py#L70-L81)).
- **Concurrency vs. sequence** are separated cleanly: the *engine* runs many targets at once
  (`max_workers = --threads`, default 10) but each target's phases run *in order* on a single worker.
- **The fallback logic** lives in [`should_run_phase`](src/openhound_sccm/per_host_phases.py#L96-L121),
  the engine's `should_run` hook. It does two things: enforce `--collection-methods` gating
  (`ctx.method_enabled(phase.name)`) and skip the fallback phases. WMI is skipped on a host whose
  `TargetEntry.completed_phases` already contains `"AdminService"`; HTTP and SMB are skipped once
  `{"AdminService", "WMI"}` collected the host. This keeps each collector a plain "collect everything"
  function — the *decision* to run lives in one pipeline-native place, mirroring CMBP's
  `$CollectionTargets[$target]['Collected']` skip checks.

- **The sequential debug harness** is [`debug_per_host.py`](dev/debug_per_host.py) (one of three lab
  harnesses, alongside `debug_epa_matrix.py` and `spike_smb_sso.py`). It seeds the work queue by hand and
  drives `run_pipeline` directly — **no DLT** — so the whole per-host engine can be single-stepped under a
  debugger. Its knobs map 1:1 to CLI flags:
  - `MAX_WORKERS = 1` ([debug_per_host.py:74](dev/debug_per_host.py#L74)) forces a single worker thread so the
    debugger never jumps between targets — the deterministic-sequential mode. `= 10` reproduces real
    concurrency.
  - `COMPUTERS` mirrors `--computers` (seed + allow-list); `COLLECTION_METHODS` mirrors
    `-m/--collection-methods`; `MAXSIZE` (the bounded-stream depth, default 1000) set to `1` lets you
    watch backpressure block a producer.

  The same determinism is reachable from the real CLI with `--threads 1 -c <one-host> -m <one-method>` —
  the engine's `run_one_target` is a public, standalone entry point precisely so a single target can be
  run in isolation.

### Trade-offs

A phase that raises is **logged and skipped**, and the remaining phases still run
([engine.py:77-81](src/openhound_sccm/phased_pipeline/engine.py#L77-L81)) — one flaky host or protocol
never aborts the collection, but it does mean failures are surfaced through logs (see [§7](#7-enhanced-logging-and-diagnostics-for-blind-remote-environments))
rather than by crashing.

---

## 3. Recursive target discovery and collection

### The framework baseline

A REST collector's "targets" are fixed: the tenant's endpoints. Collection never *grows* the work it has
to do. There is no framework primitive for "the data I just collected revealed another host I must now go
collect."

### Why it breaks for SCCM

SCCM topology is self-describing and only partially visible from any one vantage point. A management point
queried over HTTP returns an `MPLIST` naming **sibling** management points; LDAP and DNS each reveal a
different slice of the site systems. ConfigManBearPig handles this by appending to a live target list that
every subsequent phase re-reads (`Add-DeviceToTargets`). New hosts found mid-run must themselves be
collected — **recursion**.

### The add-on: a quiescence-aware work queue with a strict ordering contract

[`WorkQueue`](src/openhound_sccm/phased_pipeline/work_queue.py) is the recursion engine. Producers (any
phase, via the context) call `submit(host)`; the dispatcher calls `next()`/`complete()`. The subtle part
is knowing **when collection is actually finished** when new work can appear at any moment. The queue
tracks *in-flight* work (handed out but not completed) and declares **quiescence** — `next()` returns
`None` — only when *nothing is pending and nothing is in flight*
([work_queue.py:55-68](src/openhound_sccm/phased_pipeline/work_queue.py#L55-L68)).

The race-free guarantee rests on an **ordering contract** spelled out in the module docstring
([work_queue.py:15-21](src/openhound_sccm/phased_pipeline/work_queue.py#L15-L21)) and enforced in the
engine's worker: a worker that discovers a new target must `submit` it *before* the discovering target's
slot is released. `run_pipeline`'s worker calls `on_target_complete` (and any submits) **while the target
is still counted in flight**, then calls `complete` last ([engine.py:110-123](src/openhound_sccm/phased_pipeline/engine.py#L110-L123)).
Because of that ordering, the dispatcher can never observe "empty and idle" while a discovery is mid-flight,
so it can't stop early.

Two more pieces wire discovery into this loop:

- [`SourceContext.register_target`](src/openhound_sccm/context.py#L260-L358) is the single funnel every
  discovery path calls. It resolves the identifier against AD (best-effort), applies the allow-list (see
  [§4](#4-targeted-collection-an-include-only-allow-list)), dedups by SID then hostname (with an FQDN
  upgrade path), merges sources/site-codes onto an existing `TargetEntry`, and — for a genuinely new host —
  calls `work_queue.submit(...)` ([context.py:355-356](src/openhound_sccm/context.py#L355-L356)). Both
  Stage-1 discovery resources (which call it from inside `collectors/*`) and the CLI's `--computers`
  seeds ([main.py:963-965](src/openhound_sccm/main.py#L963-L965)) go through this *same* funnel, so dedup
  and filtering are identical.
- [`target_hosts_snapshot`](src/openhound_sccm/context.py#L361-L369) lets phases read the *current* target
  set at iteration time, so a host discovered after a phase started is still picked up — the OpenHound
  equivalent of CMBP's "iterate the updated list."

One discovery path recurses on its own, one level below `register_target`:
[`_expand_group_targets`](src/openhound_sccm/collectors/ldap.py#L618-L661) (ope-e191). When
`ldap_system_management_dacl` finds a **group** holding GenericAll on the System Management container,
the group's members effectively inherit that Full Control too — so a group holder used to be only logged,
silently missing every computer that controlled the container through membership. The helper fetches the
group's `member` attribute with a direct BASE-scope search on its DN, resolves each member, registers
computer members as targets (source `LDAP-GenericAllSystemManagement`, same as a direct-computer holder),
logs user members (modeled, not scanned), and recurses into nested groups — a `visited` set keyed on
group DN stops circular nesting (`G1 → G2 → G1`) from recursing forever. Huge group memberships are paged
transparently by the shared client's `ldap3` `Connection`, which is opened with `auto_range=True`: ldap3
itself fetches every `member;range=N-M` chunk and merges them under the plain `member` key before this
code ever sees the entry, so a normal huge group already arrives with its complete membership. The
collector does not follow ranges itself — it only checks for a **residual** `member;range=` key, which
can appear solely when auto_range failed to complete, and logs a **warning** in that case rather than
silently under-collecting.

### Trade-offs

The whole queue is guarded by one `threading.Condition`, which is simple and correct but serializes
submit/next/complete. At SCCM target counts that's a non-issue. The dedup set is process-lifetime, so a
host is collected at most once per run even if discovered by three different paths.

---

## 4. Targeted collection: an include-only allow-list

### The framework baseline

A REST collector collects *the whole tenant*. "Collect only part of it" isn't a first-class idea, and
certainly not "discover the topology but only actually touch these specific hosts."

### Why it breaks for SCCM

Operators routinely need to (a) probe a single named host they already care about, or (b) let discovery
map the environment but **only authenticate against an approved subset** — for scoping, for stealth, or
because they only have rights against certain machines. Discovery and the *decision to touch a host* must
be decoupled.

### The add-on: an allow-list applied at the registration funnel

- `--computers` and `--computer-file` feed [`_expand_allowed_targets`](src/openhound_sccm/source.py#L41-L58),
  which lowercases each name **and** adds its short-name form so a host matches whether it's later seen as
  an FQDN or a NetBIOS name. The lowercased, short-name-expanded set is assembled at
  [source.py:244-248](src/openhound_sccm/source.py#L244-L248) and handed to `SourceContext.allowed_targets`
  ([source.py:267](src/openhound_sccm/source.py#L267)).
- [`_is_allowed_target`](src/openhound_sccm/context.py#L239-L258) (CMBP's `Test-AllowedTarget`) is checked
  inside `register_target`: an **empty** allow-list means *allow all* (pure discovery mode), and a
  non-empty one rejects any host whose candidate name forms don't intersect it — logging the skip rather
  than silently dropping it ([context.py:296-297](src/openhound_sccm/context.py#L296-L297)).

Because the gate sits at the single registration funnel, the same filter governs LDAP-discovered hosts,
DNS-discovered hosts, mid-run HTTP-discovered siblings, and CLI seeds alike. `--computers` therefore does
**double duty**: every listed host is both a *seed* (collected) and the *allow-list* (nothing else is
touched) — the behavior `debug_per_host.py` documents explicitly.

### Trade-offs

The allow-list is name-based, not SID-based, so it relies on consistent name forms (mitigated by the
short-name expansion). A host that can't be resolved to a name at all can't be matched against a non-empty
allow-list.

### DC-only recon mode (`--dc-only`)

`--dc-only` is a second, coarser scoping control layered on the same machinery. It
does two things: (1) forces `--collection-methods` to `LDAP,DNS` so the discovery
resources self-gate (`local_*` skips; `collection_settings` still fires because it is
ungated), and (2) turns off the `per_host_expected` gate so collection Stage 2 — the
per-host engine, stream bridge, and emit resources (the per-host collection framework
plan, `docs/superpowers/plans/2026-06-03-per-host-collection-framework.md`) — never starts. The result is a full map of
the SCCM attack surface derived from the domain controller (AD directory + DNS) with
zero connections to any site system or client. `--dc-only` and `-m/--collection-methods`
are mutually exclusive (`_resolve_dc_only_methods` in `main.py`).

---

## 5. An Active Directory CLI surface and context auto-detection

### The framework baseline

OpenHound gives you a generic `openhound collect <source> <output>` command and resolves configuration via
DLT's layered config system (`SOURCES__<SOURCE>__*` env vars, `.env`, `secrets.toml`). The convenience
decorator `@app.collect()` registers a *minimal* command. A REST collector typically needs one secret (an
API token) and one config value (a base URL).

### Why it breaks for SCCM

SCCM operators think in **CMBP flags**: `-d/--domain`, `--dc`, `-u/-p`, `--nt-hash`, `--ticket`,
`-m/--collection-methods`, `-c/--computers`, `--site-codes`, `--threads`, and more. They also expect the tool to
**auto-detect** the AD domain and a domain controller when run on a domain-joined Windows box — the way the
PowerShell tool does — rather than demanding flags. None of that fits a one-token REST command.

### The add-on: a hand-registered Typer command + a flag→env bridge + context discovery

Rather than use `@app.collect()`, [`main.py`](src/openhound_sccm/main.py) registers
[`collect_sccm`](src/openhound_sccm/main.py#L842-L1009) **directly on the framework's public Typer group**
(`from openhound.cli.collect import collect as _collect_typer`) so it can expose the full CMBP flag surface
([main.py:842-885](src/openhound_sccm/main.py#L842-L885)). It then assigns `app.collector = collect_sccm`
([main.py:1057](src/openhound_sccm/main.py#L1057)) so the framework's import-time
`validate_extension` still sees a registered hook.

Because the DLT `source()` factory only reads configuration through injection, the command **translates
every flag into the env var the source expects** before the source is built:

- [`_FLAG_TO_ENV`](src/openhound_sccm/main.py#L59-L90) maps each flag to its `SOURCES__SCCM__*` name;
  [`_apply_env_overrides`](src/openhound_sccm/main.py#L227-L248) sets them last (so an explicit flag wins
  over an env/`.env` value), and [`_drop_empty_dlt_env_values`](src/openhound_sccm/main.py#L103-L111)
  removes empties so an unset flag can't clobber a higher-priority source.
- [`_suspicious_cli_argument_warnings`](src/openhound_sccm/main.py#L168-L218) catches a real foot-gun:
  Click parses `-dc 10.0.0.1` as `-d c` (because `-d` takes a value), silently turning the intended DC
  into a stray positional. The collector warns on these, masking sensitive values.
- **Context auto-detection** mirrors CMBP's order: [`_detect_windows_domain`](src/openhound_sccm/main.py)
  reads `USERDNSDOMAIN` then the FQDN suffix (Windows only); [`_resolve_dc_via_dns`](src/openhound_sccm/main.py)
  finds a DC via the `_ldap._tcp.dc._msdcs.<domain>` SRV record (cross-platform), building its resolver
  with the shared `openhound_collector_common.discovery.dns.make_resolver` (see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)) and keeping the
  SCCM-specific SRV query. When neither yields a domain,
  [`_require_domain_or_explain`](src/openhound_sccm/main.py) fails fast with a platform-specific message
  *before* DLT's config resolver throws a noisy `ConfigFieldMissingException`.

### Trade-offs

- The flag→env round-trip is indirection the framework doesn't need for REST collectors, but it's the
  price of keeping the source DLT-injectable while presenting a rich CLI.
- `extension.yaml`'s `credentials`/`parameters` blocks
  ([src/openhound_sccm/extension.yaml:27-69](src/openhound_sccm/extension.yaml#L27-L69)) describe the CLI
  accurately but drive nothing — no code reads them, and configuration flows through the flags/env above
  instead. OpenHound parses the file for extension *metadata* only. (Documented as a limitation in the
  README.) The file lives inside the package because it is read at runtime; a path above the package
  works in a checkout and vanishes once installed.

---

## 6. Windows authentication across five protocols

### The framework baseline

OpenHound's auth story is REST auth: attach an OAuth/bearer token (or basic auth) to an HTTPS request.
One scheme, one header, stateless, cross-platform, and the framework/`requests` handle it. There is **no
framework support** for Windows-network authentication — Kerberos, NTLM, SSPI, channel binding, DCOM, or
SMB session setup — because no REST collector needs it.

### Why it breaks for SCCM

SCCM lives entirely on Windows authentication. The collector must authenticate over **five different wire
protocols**, each supporting the operator's full credential toolkit: the **current Windows user** (no
password — single sign-on via SSPI), explicit **username/password** (NTLM and Kerberos), **pass-the-hash**
(an NT hash instead of a password), and **pass-the-ticket** (a base64 Kerberos `.kirbi`). This is the
bulk of the divergence and lives under [`clients/`](src/openhound_sccm/clients/).

### The add-on: per-protocol auth stacks with a shared credential-precedence idea

> **Now in the shared library.** The auth realizers below — `choose_auth`, the NTLM/SPNEGO token
> minters (`KerberosToken` / `SspiClient` / NTLM type-1/3), the lockout-safe LDAP `AdClient`, the WMI
> impacket/pywin32 backends, and the MSSQL EPA `detect_epa` probe — were **promoted into
> `openhound-collector-common`** and are now shared with the MSSQL collector (see
> [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)). The SCCM files
> named in the table are the thin **adapters** (`ADClient(AdClient)`, the `WmiClient` wrapper, the
> `http_auth` negotiators over `KerberosToken`/`SspiClient`, the `mssql_epa.test_epa` adapter over
> `detect_epa`); the implementation lives in the correspondingly-named `clients/*` modules under
> `openhound_collector_common`. The precedence philosophy and per-protocol behavior described here are
> unchanged by that move.

There is no single universal selector — each protocol family has its own realizer — but they share the
same **credential precedence philosophy**: *explicit credentials win (Kerberos first, NTLM fallback),
then current-user SSO, then (where the protocol allows) anonymous.*

| Family | Where the ladder lives | Schemes (in precedence order) | Key libraries |
|---|---|---|---|
| **HTTP / AdminService** | shared `choose_auth` in [`clients/http_auth.py:134-168`](src/openhound_sccm/clients/http_auth.py#L134-L168), driven by [`clients/http.py`](src/openhound_sccm/clients/http.py) | pass-the-ticket → explicit (Kerberos→NTLM) → current-user SSPI → **anonymous** | `impacket` (krb5/ntlm/spnego), `pywin32` (SSPI), `requests` |
| **WMI (AdminService fallback)** | reuses the **same** `choose_auth` ([`clients/wmi.py:333-353`](src/openhound_sccm/clients/wmi.py#L333-L353)) | pass-the-ticket → explicit (Kerberos→NTLM) → current-user SSPI → ~~anonymous~~ (skipped — DCOM requires auth) | `impacket` (DCOM), `pywin32` (`win32com`) |
| **LDAP / AD** | attempt plan in [`clients/ad.py`](src/openhound_sccm/clients/ad.py) (`_build_attempt_plan`), credential precedence in the shared `AdClient._select_auth_modes` | pass-the-ticket (GSSAPI via a private ccache) → pass-the-hash (`ntlm_hash`, ldap3 `LM:NT`) → explicit NTLM → integrated Kerberos (GSSAPI) → current-user SSPI-NTLM → anonymous — each over an auto-detected transport | `ldap3`, `impacket` (krb5 ccache), `pywin32` (SSPI), `winkerberos`/`gssapi` |
| **SMB (RemoteRegistry + SMB phases)** | inline ladder in `connect_smb` ([`clients/smb_sso.py:215-279`](src/openhound_sccm/clients/smb_sso.py#L215-L279)) | pass-the-ticket → pass-the-hash → explicit password → current-user SSPI Negotiate → null session | `impacket` (SMBConnection, krb5 CCache), `pywin32` (SSPI) |
| **MSSQL EPA probe** | `impacket_prober` / `sspi_prober` in [`clients/mssql_epa.py`](src/openhound_sccm/clients/mssql_epa.py) | explicit creds (incl. pass-the-hash) → current Windows user (SSPI); a **ticket-only** credential yields a WARNING+skip — pass-the-ticket can't forge the channel-binding AV pairs the probe needs | `impacket` (tds/ntlm), `pywin32` (SSPI) |

A few specifics worth calling out, because they show how much harder this is than a bearer token:

- **HTTP is a multi-leg challenge/response, not a header.** `http.py` runs the SPNEGO `401 →
  WWW-Authenticate: Negotiate <token> →` re-request loop itself, minting tokens with impacket/SSPI and
  carrying them in `Authorization: Negotiate <b64>` ([http.py:215-227](src/openhound_sccm/clients/http.py#L215-L227)).
  Kerberos needs a **Service Principal Name** (`HTTP/<fqdn>`); a bare-IP target can't form one, so the
  ladder skips Kerberos and uses NTLM directly. The GSS checksum deliberately omits the DCE-style flag
  because IIS/http.sys rejects it.
- **WMI realizes the *same* credential rungs over a completely different transport** — DCOM via impacket
  (one connection per WMI namespace, because a second `IWbemLevel1Login` over one connection is rejected)
  or `win32com` for the current user. The anonymous rung is dropped because DCOM always requires
  authentication. The payoff: `-u/-p/--nt-hash/--ticket` and passwordless collection behave identically
  whether a host answers over AdminService or only over WMI.
- **LDAP auto-detects transport *and* signing** and is **lockout-safe**. `ad.py` tries
  LDAPS:636 → StartTLS:389 → LDAP:389-with-sign-and-seal, varying by auth mode, and adds a TLS
  channel-binding token where the scheme supports it. Crucially, [`_is_credential_failure`](src/openhound_sccm/clients/ad.py)
  inspects the LDAP *result-49 subcode* and only treats genuine bad-password codes (`52e`, `532`, `533`,
  `701`, `773`, `775`) as credential failures — every other error (signing required, CBT mismatch, TLS
  failure) falls through to the next transport **without incrementing `badPwdCount`**, so the fallback
  chain can't lock out the account. A REST API has no such hazard.
- **The MSSQL EPA probe authenticates *in order to misbehave*.** It can't read Extended Protection
  enforcement directly, so it sends **deliberately malformed** NTLM channel-binding and service-binding
  values and watches how SQL Server reacts ([`mssql_epa.py`](src/openhound_sccm/clients/mssql_epa.py),
  `determine_epa`/`_classify_binding`). The impacket explicit-credential path can omit/corrupt those AV
  pairs independently and so can distinguish **Allowed** from **Required**; the current-user SSPI path
  *cannot* (Windows always inserts the channel-binding and target-name AV pairs), so it honestly reports
  the literal `Allowed/Required`.

### Trade-offs

- **Platform split.** Current-user SSO (SSPI) is Windows-only across every protocol (gated by
  `sys.platform == "win32"` + import probes). Kerberos is cross-platform but needs different backends
  (`winkerberos` on Windows, `gssapi` on Linux, the latter not bundled). Explicit credentials and
  pass-the-hash/ticket work everywhere via impacket. This is why the README's System Requirements draw a
  hard Windows-vs-Linux line.
- **Heavy dependencies** the framework never pulls in: `impacket`, `ldap3`, `winkerberos`, `pywin32`,
  `cryptography`. Each is load-bearing (see [`pyproject.toml:10-42`](pyproject.toml#L10-L42)).
- The EPA `Allowed/Required` ambiguity under SSPI is an unavoidable consequence of how Windows builds the
  NTLM type-3 message — a genuine limitation, not a bug.

---

## 7. Enhanced logging and diagnostics for blind remote environments

### The framework baseline

OpenHound configures one logging stack at import time — a `RichHandler` (or a plain stream handler in
container mode) plus a rotating file handler, fed by the root and `dlt` loggers
(`openhound/core/logging.py`). For a REST collector that you run locally and can re-run at will, that's
enough.

### Why it breaks for SCCM

This collector runs **in someone else's network**, against infrastructure we can't see and can't re-probe
on a whim, often once. When something fails on host #47 of 200, "re-run with a breakpoint" isn't an
option. The logs *are* the debugger. They have to answer, after the fact: *which host, which phase, what
went wrong, and what was the exception?* DLT also interleaves resource output, so a naive log is an
unreadable braid of 10 hosts' lines.

### The add-on: a context-tagging, ordered, diagnostics-capturing logging layer

> **Now in the shared library.** The whole `log_context` machinery — `[target][phase]` tagging,
> `with_log_context`, the completion-callback registry, `VERBOSE`, and the debug exc-info filter — was
> **promoted into `openhound_collector_common.logging.log_context`** as a superset and is now shared with
> the MSSQL collector (see [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)).
> SCCM's [`log_context.py`](src/openhound_sccm/log_context.py) re-exports it and binds the two
> collector-specific helpers (`cached_with_log`, `trace_*`) to SCCM's own logger names. The two
> file-handler classes below (`_DiagnosticFileHandler`, `_OrderedLogFileHandler`) stay in SCCM's
> [`main.py`](src/openhound_sccm/main.py) — they are the SCCM CLI's output artifacts, not shared infra.
> The behavior described here is unchanged by the move; where a `log_context.py#Lxx` reference below points
> at what is now a re-export, the implementation is the same-named symbol in the shared module.

All in [`log_context.py`](src/openhound_sccm/log_context.py) and the handler classes in
[`main.py`](src/openhound_sccm/main.py), built *without editing the framework's handlers* — only by adding
filters/handlers and mutating live handler instances at runtime:

- **`[target][phase]` tagging.** [`target_context`](src/openhound_sccm/log_context.py#L152-L167) /
  [`phase_context`](src/openhound_sccm/log_context.py#L170-L183) push the current host/phase onto
  `contextvars`, and [`LogContextFilter`](src/openhound_sccm/log_context.py#L189-L220) folds them into
  every record's message — so the framework's own Rich handler renders `[ps1-mp.mayyhem.com][SMB] ...`
  with no formatter change. The decorator [`with_log_context`](src/openhound_sccm/log_context.py#L301-L394)
  even pushes/pops the context **per `next()` call** of a DLT resource generator, because DLT interleaves
  generators and a once-around-the-generator context would leak across hosts.
- **A `VERBOSE` tier between INFO and DEBUG** ([log_context.py:48-59](src/openhound_sccm/log_context.py#L48-L59)),
  surfaced by `-v`, gives CMBP's `[Verbose]` per-resolution/per-node traces without DLT/ldap3 internal
  noise (that's `--debug`). The console ladder is `(none)`=INFO → `-v`=VERBOSE → `--debug`=DEBUG,
  applied in [`_apply_log_level`](src/openhound_sccm/main.py) by lowering the console handlers.
- **A console-only mute, `--silent`.** The console handlers and the file handlers are two independent
  audiences (see the Rich handler vs. the rotating/`_Diagnostic`/`_Ordered` file handlers), so `--silent`
  gags the terminal *without* darkening the on-disk logs: [`_silence_console_handlers`](src/openhound_sccm/main.py)
  raises only the console handlers above `CRITICAL` (identified by [`_is_console_handler`](src/openhound_sccm/main.py):
  not a `FileHandler`, and either a `StreamHandler` or a duck-typed Rich handler with a `.console`), while
  the **root logger stays at the requested detail level**. That separation is what lets `--silent` *compose*
  with the verbosity flags — `--silent --debug` is a quiet terminal with DEBUG-level file logs. It's the
  mirror image of the normal path: same "mutate live handler instances" technique, raising instead of
  lowering. `--silent` also forces `--progress off`, since the progress tracker renders straight to the
  console and bypasses logging.
- **A per-run issues file** (`collect_issues_<ts>.log`, [`_DiagnosticFileHandler`](src/openhound_sccm/main.py)) captures
  every WARNING+ **with full traceback** — even when the warning was logged without one, by injecting
  `sys.exc_info()` if a live exception is in flight, then restoring the record so the console isn't
  affected. The companion [`_DebugExcInfoFilter`](src/openhound_sccm/log_context.py) does the
  same on the console in `--debug`. (A clean run writes no issues file — the handler opens lazily.)
- **A complete, human-ordered full log** (`collect_full_<ts>.log`, [`_OrderedLogFileHandler`](src/openhound_sccm/main.py))
  is **always written at DEBUG**, independent of the console level: for the duration of a run the collector's
  own namespaces (`openhound_sccm` + `openhound_collector_common`) are pinned to DEBUG and this handler's level
  is DEBUG, so a finished collection always has the full trace on disk without a re-run (`--debug` additionally
  folds `dlt`/`ldap3` internals in, via the root logger). It solves the interleaving problem by **buffering**
  records keyed by the active resource *or* host, flushing each group as one labelled block the moment that
  resource/host *completes* — driven by completion callbacks fired from the DLT generator wrapper and the
  engine's `on_target_complete`. The result is a log you can read host-by-host even though collection ran 10-wide.

  **The two grouping keys — and why the per-host collectors are *not* `@with_log_context`-decorated.** The
  handler buckets by *resource* when a resource context is set, else by *host*. That split maps onto the two
  schedulers ([§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline)): Stage-1 discovery
  resources (`ldap_*`, `dns_*`, `local_*`) are DLT generators driven **interleaved**, so they carry
  `@with_log_context(...)`, which pushes a *resource* context per `next()` and fires the resource-complete
  callback on exhaustion — one clean per-resource block. The Stage-2 per-host collectors (`collect_registry`,
  `collect_mssql`, `collect_adminservice`, `collect_wmi`, `collect_http`, `collect_smb`) are the opposite:
  the engine runs each to exhaustion **inside a `phase_scope(target, phase)` block on one worker thread**
  ([§2](#2-sequential-phases-per-target-concurrent-across-targets--and-a-sequential-debug-harness)), so
  `phase_scope` already supplies `[target][phase]`. Decorating them too was an active bug: `with_log_context`
  set a *resource* context (`func.__name__`, e.g. `"collect_registry"`) that hijacked the bucket key and fired
  resource-complete **once per (host, phase)** — so the full log filled with repeated `# collect_registry`
  blocks, each an interleaved fragment, while the intended per-host `flush_host` was a no-op. The fix is to
  **not** decorate the per-host collectors: with no resource context their records bucket by host and flush
  once, when the host finishes all its phases. Guarded by [`tests/per_host_log_blocks_test.py`](tests/per_host_log_blocks_test.py).
- **Expected-failure triage, so severity means something.** The logs are only a debugger if `ERROR`
  implies "something broke". Two conditions violated that on every low-privilege run, and both are
  handled by classifying rather than by shouting:
  - **Refused registry reads.** A dozen-odd reads per site system are admin-gated. Logged one-per-read
    they were ~120 of the 125 `ERROR`s in a low-privilege lab run, and **zero** in the same run as a
    local admin — the definition of an expected failure. All four `_RegistryProbe` read helpers now
    funnel failures through one [`_log_read_failure`](src/openhound_sccm/collectors/registry.py)
    that splits three ways: absent → verbose, denied → verbose **plus a tally**, anything else → error.
    The tally is drained by `log_denied_summary()` from the probe's `__exit__` — deliberately not from
    the end of `collect_registry`, which `return`s early precisely when the site code is unreadable, so
    a summary at the function end would miss the hosts that most need it. The tally also gives the phase
    a way to tell *denied* from *absent*, which a bare `None` return cannot: `was_denied()` is what stops
    a refused `SMS\Triggers` read from being reported as "this host has no site code".
  - **A third party's misleading CRITICAL.** impacket logs `CRITICAL: CCache file is not found.
    Skipping...` once per host whenever the WMI Kerberos rung runs without `--ticket` — it checks the
    Unix `KRB5CCNAME` variable, finds nothing on Windows, and then succeeds anyway with the supplied
    password. [`_ImpacketNoiseFilter`](src/openhound_sccm/main.py) rewrites that one record's `levelno`
    to DEBUG in place (handlers gate on `levelno`, and the `impacket` logger propagates to root with no
    handlers of its own, so this is sufficient), matched on the message rather than by capping the
    logger so other impacket CRITICALs survive. `clients/wmi.py` logs its own verbose line in its place
    so the log still explains itself. Installed and removed per run, alongside the file handlers.
- **Runtime tidy-ups of the framework's Rich handler** ([`install_filter`](src/openhound_sccm/log_context.py#L253-L292)
  and [`_strip_version_suffix_from_handlers`](src/openhound_sccm/main.py#L317-L335)): turn off Rich markup
  parsing (so `[mayyhem.com]` isn't eaten as a malformed tag), drop the `file.py:line` column, and swap
  out the formatter that appends `(openhound_version=…)` — all by writing attributes on the *existing*
  handler instances, never by editing core.

### Trade-offs

This is a lot of logging machinery for an extension to carry, and it reaches into framework handler
internals by **class name and attribute** (e.g. matching `"OpenHoundRichFormatter"` /
`"RotatingFileHandler"`). That's deliberate — it means a framework change to those internals shows up as a
*visible* loss of behavior rather than a crash — but it is a coupling to watch on every OpenHound upgrade.

---

## 8. Windows-isms: the platform fights back

A scattering of fixes exist purely because the collector runs Python on Windows against Windows services.
A stock REST collector on Linux CI never meets any of these.

- **Log rollover crashes at midnight (WinError 32).** OpenHound core attaches its rotating file handler to
  **both** the root and `dlt` loggers, pointed at the *same* file. The first record after midnight (or past
  the size cap) triggers a rollover that `os.rename`s the open log — which **fails on Windows** because the
  sibling handler still holds the file open. The extension can't edit core, so
  [`_make_core_rotation_windows_safe`](src/openhound_sccm/main.py#L382-L409) (run once at import) mutates
  the live handler instances: it repoints each to a **per-run timestamped file** and replaces `doRollover`
  with [`_copytruncate_rollover`](src/openhound_sccm/main.py#L356-L379) — *copy the file to a dated sibling,
  then truncate in place* — so rotation never needs exclusive access to the open handle. It's a no-op off
  Windows, where rename-based rotation works.
- **dlt's pipeline storage gets locked under the user profile (WinError 32, again).** A *second* WinError 32,
  unrelated to logging. dlt keeps each pipeline's working state under `~/.dlt/pipelines/<name>/` and moves
  files with **atomic rename/remove** (`os.replace` during `extract`, `os.remove` during `load`). On Windows
  a file freshly written under the **user profile** is briefly held open by the **Search Indexer** (which
  indexes `C:\Users\<you>` by default) or an endpoint-security agent — so dlt's rename/remove
  **intermittently fails with WinError 32**, and worse, leaves a **stuck "pending package"** that re-trips
  the next run. (Seen at convert time at both `extract` and `load`; Defender real-time protection was *off*,
  which rules out its scanner and points at the indexer/agent.) Unlike the log handler above, this isn't a
  core handler instance we can mutate at runtime — it's dlt's own storage — so the fix is dlt's built-in
  knob: **relocate the pipeline dir off the indexed profile via the `DLT_DATA_DIR` environment variable**
  (dlt reads it in its run-context resolver and places pipelines under `<DLT_DATA_DIR>/pipelines`). The
  Stage-1 code tour sets it **in-process to a fresh per-run temp dir** before importing dlt
  ([`tour_driver_stage1.py`](dev/tour_driver_stage1.py)); the real CLI sets it to a stable off-profile path
  (`C:\dlt-home`) via the `Debug: openhound collect sccm` launch profile's `env` block and/or a user-level
  `setx DLT_DATA_DIR`. A fresh, un-indexed location both dodges the lock and avoids inheriting a stuck
  pending package. `~/.dlt` is fine on Linux CI, so this is Windows-only.
- **uv-managed Python aborts every TLS handshake.** [`pyproject.toml`](pyproject.toml#L47-L52) sets
  `python-preference = "only-system"` because the `python-build-standalone` builds uv installs ship a
  `libcrypto` without the `OPENSSL_Applink` cross-CRT shim — which aborts the process mid-handshake on
  Windows. Harmless on Linux, but on Windows the collector deliberately prefers an official/system Python.
- **Single-label (NetBIOS) domains have no valid LDAP naming context.** `DC=MAYYHEM` doesn't exist, so AD
  answers with a referral that ldap3 chases into "invalid server address." [`_ldap_resolve`](src/openhound_sccm/context.py#L210-L237)
  detects the dot-less domain and skips it, deferring to an FQDN domain in the try-list — which is why only
  NetBIOS-prefixed principals (NAA, `sccm_push`) ever hit that path.
- **Dependency pins that exist only for Windows auth:** `ldap3>=2.10.2rc4` is the first release exporting
  the `ENCRYPT` and `TLS_CHANNEL_BINDING` constants needed for NTLM sign-and-seal and LDAP channel binding
  against signing-required DCs; `winkerberos` and `pywin32` are `sys_platform == 'win32'`-gated
  ([pyproject.toml:10-42](pyproject.toml#L10-L42)).

---

## 9. Convert can't iterate DuckDB rows: the unified Computer-node problem

> **Status — graph-pipeline Stages 1–2 shipped.** (Stage numbers in this section and §11 are increments of
> the preprocess/convert port — plans `docs/superpowers/plans/2026-06-16-sccm-preproc-convert-stage0.md` …
> `2026-07-01-sccm-preproc-convert-stage7.md` — not the collection stages of §1/§4; see the
> [Reference key](#reference-key-the-shorthand-used-in-this-document).)
> The previous preproc/convert layer (`graph.py`, `lookup.py`, `transforms.py`,
> `models/computer.py`, `models/sccm_site.py`) was **deleted** in commit `6af5cc0 "Delete preproc/convert
> data"` pending a rebuild. The chosen design is recorded in
> [`docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md`](docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md)
> (authoritative) with rationale in the two proposals cited below. Stages 1 and 2 of the Convert2-Read-DB
> pipeline are now implemented; this section describes the divergence and the shipped design.

### The framework baseline

OpenHound's `convert` reads **JSONL driver files from the collected-data bucket** and emits one
node/edge per row. The model is *one API resource == one graph entity* (an Okta user row → a User node, a
GitHub repo row → a Repository node). `preproc` can build correlation tables in DuckDB, but `convert` can
reach those tables **only** through `self._lookup` — *point* and *list* queries
(`_find_single_object` / `_find_all_objects`), used to *enrich* a node or *fan out* edges. There is **no
code path that lets `convert` iterate a DuckDB table to emit one node per row** — the OpenGraph reader is
hardwired to a filesystem JSONL glob. (Full code evidence is in the proposal below.)

### Why it breaks for SCCM

The SCCM **Computer** node has no single driver file. One computer's properties are spread across *many*
collected tables — `ldap_computers`, AdminService/`SMS_R_System`, `remoteregistry_computers`,
`smb_computers`, site-definition servers, WMI — all keyed by **AD SID**, with array properties
(site-system roles, resource IDs) that must be **unioned**. ConfigManBearPig does this with an in-memory
`Upsert-Node` merge. The natural OpenHound equivalent is a DuckDB `GROUP BY sid` in `preproc` that yields
**one coalesced row per computer** — but then `convert` has *no supported way to iterate that coalesced
table*. This is the framework gap that most directly blocks a clean port.

Discussion: https://specterops.slack.com/archives/C09LBVA5T1N/p1781633877476619

### The add-on / design direction

Two routes out of this gap were written up. The first is a proposed **core** fix, for the framework
maintainers, in
[`docs/proposals/2026-06-16-convert-read-from-duckdb.md`](docs/proposals/2026-06-16-convert-read-from-duckdb.md):
an opt-in `read_from="duckdb"` selector on `@app.convert` that makes the convert reader iterate the
preproc tables through the already-open lookup connection (using an **independent cursor** so per-row
`self._lookup` calls don't clobber the in-flight scan).

Because we can't depend on a core change landing, the **chosen approach needs no core edit**. It is
recorded in the spec as the **Second Convert Pipeline with DuckDB Read** (`Convert2-Read-DB`):

1. **`preproc`** loads the raw JSONL into DuckDB and builds **coalesced, one-row-per-entity** node tables
   (`node_*`) plus a derived `graph_edges` table with set-based SQL — `UNION` every contributing table
   normalized to a common shape, then `GROUP BY sid` (scalars coalesce via `any_value`, arrays union via
   `list_distinct(flatten(...))`). This `GROUP BY` is the in-DuckDB equivalent of CMBP's `Upsert-Node`, and
   the only construct that does a true column-and-array union across the per-source tables.
2. **`convert`** then runs its **own explicit `dlt.pipeline`** that reads those coalesced DuckDB tables
   directly and emits to the `opengraph_file` destination, instantiating a trivial typed model per table
   (`row → node` / `row → edge`). Reading DuckDB straight from the manual pipeline — rather than first
   writing the coalesced rows back out to JSONL — is the more DLT-native of the two patterns, confirmed
   with the OpenHound author. Each entity is therefore emitted **exactly once** (flat 1×).

Two alternatives were considered and **rejected**, recorded so the mechanism isn't re-litigated:

- **Multi-driver emit + merge-by-id — rejected on scale.** One trivial `convert` driver per contributing
  table, each emitting the *same* `Computer` node id so BloodHound coalesces the byte-identical duplicates
  by `ObjectIdentifier` on ingest. It stays within public extension points, but in the common worst case
  (every domain computer is a client, found by *both* LDAP and the privileged `r_system`) each computer
  emits ~2×, with further multiples on per-host-probed infrastructure — where Convert2-Read-DB's one-row-per-entity
  coalescing stays flat 1×. Sketched, as history, in
  [`docs/proposals/2026-06-16-computer-node-multi-driver-merge.md`](docs/proposals/2026-06-16-computer-node-multi-driver-merge.md).
- **JSONL writeback — kept as the documented fallback.** `preproc` `COPY`s each coalesced table back to
  `<bucket>/sccm/<table>/data.jsonl.gz`, and `convert` reads it with the framework's stock filesystem
  reader. Fully idiomatic on the read side, but a filesystem side-channel: the preproc transformer must
  learn the bucket path and write into it (coupling the preproc/convert path args), and it doubles IO.
  Held in reserve if Convert2-Read-DB hits a wall.

### Group identity: a collected `SMS_R_UserGroup` class replaces CMBP's live AD lookup *(shipped)*

CMBP turned each `SecurityGroupName` membership on an `SMS_R_System` / `SMS_R_User` record into a Group
node by calling `Resolve-PrincipalInDomain` — a **live Active Directory lookup, per group name, at
collection time** (`ConfigManBearPig.ps1:459`, `:7368`, `:7462`). An offline coalesce can make no AD
calls, and the membership strings carry only names, so a naive port produced **zero Group nodes** on real
lab data: `SMS_R_System` / `SMS_R_User` list groups by *name* only, and the offline `principal_by_name`
table (built from user/computer/admin records) has no entry for an ordinary AD group such as
`DOMAIN\Domain Users`.

The divergence: we collect **`SMS_R_UserGroup`** (`collectors/privileged.py::_user_group` →
`adminservice_user_group` / `wmi_user_group` tables) — a class CMBP never queried. AD Security Group
Discovery mirrors each security group into that class **with its own SID** and a `UniqueUsergroupName` in
the exact `DOMAIN\name` form the membership strings use. `preproc` folds `(unique_usergroup_name, sid)`
into `principal_by_name`, so `transforms._node_group`'s case-insensitive name→SID join resolves every
membership **offline and set-based**, instead of one AD round-trip per name. This is strictly more
scalable than CMBP and needs no live AD at convert time. (Inherent limit: a `SecurityGroupName` string
can't disambiguate two groups that share a name — both resolve — exactly the ambiguity CMBP's by-name AD
lookup also had.)

### Role columns arrive in heterogeneous shapes; preproc normalises them *(shipped)*

`sccm_site_system_roles` is contributed by several collectors that disagree on wire shape: AdminService
`system_roles` is a JSON array; `site_definitions_computers` / HTTP emit a bare `role@site` scalar; SMB /
RemoteRegistry emit a list that dlt + DuckDB's `read_json` can surface as JSON-array *text inside a
VARCHAR*. `transforms._arr` normalises all four shapes (NULL / JSON-array-text / scalar / native array) to
`VARCHAR[]` before the array-union, so a JSON-array string is *parsed* rather than comma-split into
bracket/quote garbage. The collectors were also made internally consistent (RemoteRegistry now always
emits a list via `_roles(...)`, matching SMB) so the source data is well-typed going forward — the preproc
normaliser is the belt, the collector fix the braces.

### Trade-offs

Convert2-Read-DB keeps each entity to a single emission — no duplicate-node disk cost and no dependence on BloodHound's
merge-by-id — at the price of `convert` carrying its **own** `dlt.pipeline` that reads DuckDB and re-shapes
nodes itself instead of using the stock JSONL reader. The exact DuckDB read-implementation (a custom
`@dlt.resource` over the open lookup connection vs. DLT's `sql_database` source) is **deferred to the
implementation plan**, where both are prototyped against the real `lookup.duckdb`. If Convert2-Read-DB proves
unworkable, the JSONL-writeback fallback above is the documented escape hatch.

---

## 10. dlt loads whatever the data contains; our SQL expects fixed columns

### The framework baseline

In `preproc`, **dlt** is the piece that turns the collected JSONL files into DuckDB tables. It does this
by **looking at the data and guessing the shape** — a "figure it out from whatever showed up" approach:

- It creates **only the columns it actually sees** in the rows.
- If a column is **empty (NULL) in every row** of a load, dlt **drops that column entirely**.
- It stores list-like fields (a list of group names, a list of roles) as **JSON**, not as a real list.

For a normal OpenHound collector — one tidy API where every row has the same shape — this is fine. The
data is uniform, so what dlt infers is exactly what you expect, every time.

### Why it breaks for SCCM

SCCM data is the opposite of uniform. It is **sparse and irregular**:

- Many source tables are **optional** — run LDAP only, or skip WMI, and whole tables simply don't exist on
  a given run.
- Many **columns are optional** — a registry flag like `disable_loopback_check` is often NULL on every host,
  so dlt drops the column.
- The **same kind of host seen over different protocols reports different columns** — an SMB-discovered
  computer and an LDAP-discovered computer don't carry the same fields.
- **List fields** (group memberships, site-system roles) come back as JSON — sometimes even as JSON *text
  sitting inside a plain-text column*.

Meanwhile our `preproc` coalesce SQL (the queries that merge many source tables into one
`node_*` row) is written the **opposite way**: it asks for a **fixed, known list of columns by name**
(`SELECT sid, sccm_site_system_roles, disable_loopback_check, …`). When the real data is missing one of
those columns, the SQL **can't even compile** — it fails before reading a single row. And because every
source-load is wrapped in `_safe` (which logs the error and moves on), one missing column **silently drops
the entire source**, so the finished graph is quietly incomplete.

Put simply: **dlt hands us "whatever the data happened to contain," but our SQL demands "exactly this set
of columns."** On real SCCM data those two expectations collide constantly.

### The add-on: three small defenses that make the SQL tolerant

All three live in [`transforms.py`](src/openhound_sccm/transforms.py) and run during `preproc`, *after* dlt
has loaded the tables. The easy way to remember them: **`_safe` keeps the pipeline alive, `_ensure_columns`
makes the columns exist, `_arr` makes the values the right shape.**

1. **`_safe` — the safety net** ([transforms.py:90](src/openhound_sccm/transforms.py#L90)). Each "load
   source X into table Y" step runs as its own statement. If it fails, `_safe` **logs it and keeps going**
   instead of aborting the whole preproc. This is what lets a run that used only some collection methods
   still build a graph from whatever *was* collected. It mainly catches the missing-*table* case (a table
   that doesn't exist at all).

2. **`_ensure_columns` — fill the gaps** ([transforms.py:101](src/openhound_sccm/transforms.py#L101)). Right
   before each coalesce, it looks at the source table and **adds any missing columns the SQL needs as empty
   (NULL) columns**. So whether a column vanished because dlt dropped it (all-NULL) or because that source
   never had it, the column now exists and the SQL compiles. Adding a column the SQL doesn't actually read
   is harmless; a column that's already there keeps its real values. This is the piece that stops `_safe`
   from silently dropping a source just because one optional column went missing.

3. **`_arr` (and `CAST(... AS VARCHAR[])`) — fix the shapes**
   ([transforms.py:124](src/openhound_sccm/transforms.py#L124)). List-like columns arrive in several shapes:
   a native list, a JSON array, JSON-array *text* inside a plain column, or a single scalar string. `_arr`
   turns **all of them into a real list** so DuckDB operations like `UNNEST` and array-union work. Without
   it, `UNNEST` on a JSON value errors out with "requires a single list as input." (The specific role-column
   case is detailed in [§9](#9-convert-cant-iterate-duckdb-rows-the-unified-computer-node-problem).)

### Why we defend in the SQL instead of pinning the schema at load

dlt *can* be told the opposite: pin an **explicit, complete column list and types** for every table at load
time, so nothing is ever missing or mis-typed. If we did that, `_ensure_columns` and most of `_arr` wouldn't
be needed.

We deliberately **didn't**, because pinning is **rigid**: the moment the real data drifts from the pinned
shape, dlt **refuses the entire load**. That is exactly the failure we already hit — the `ldap_sites` table
was pinned to a model, the real data's `site_code` came back slightly different (allowed to be empty), and
dlt's "freeze" rule **crashed the whole collect** instead of adapting (the `ldap_sites` decoupling fix).

So there is a real fork in the road, and we chose the tolerant side:

- **Pin at load** → strict and tidy, but any unexpected real-world shape is a **hard crash**.
- **Defend in the SQL** (our choice) → flexible; an unexpected shape becomes a **logged, survivable skip**
  — or, with `_ensure_columns`, no problem at all.

Given how much SCCM environments vary, the tolerant approach is the safer default.

### Trade-offs

- The defenses are **spread across every coalesce**. Each new node/edge stage must remember to list its
  optional columns for `_ensure_columns` and route every list column through `_arr`. Forget one and a source
  can silently drop on some future data. This is guarded by tests and by the log lines below.
- **`_safe` is a double-edged sword.** It keeps the run alive, but it can also *hide* a real problem by
  dropping a source. `_ensure_columns` exists largely to stop `_safe` from catching things it shouldn't.
- **Reading the log is the diagnostic.** `WARNING … skipped (missing source)` means a table that was never
  collected — usually a method you simply didn't run, which is normal. `ERROR … failed` means a table that
  *was* collected but still didn't load — that's the one worth chasing.
- **Expected misses are demoted to DEBUG** by [`_sccm_expected_miss`](src/openhound_sccm/transforms.py), the
  `expected_miss` predicate injected into `safe_execute`, so routine emptiness doesn't masquerade as a
  warning. Two cases qualify: **(1) transport mirror** — the collector emits EITHER `wmi_<X>` OR
  `adminservice_<X>` per data type, so a missing one whose sibling exists is normal; **(2) fallback-phase
  skip** — HTTP and SMB are fallback phases that `should_run_phase` skips for any host a privileged transport
  (AdminService/WMI) already collected ([§2](#2-sequential-phases-per-target-concurrent-across-targets--and-a-sequential-debug-harness)),
  so an absent `http_*`/`smb_*` role table is expected *whenever any privileged transport ran this
  collection*. The canonical example: the SMS Provider **is** the AdminService host, so it is
  privileged-collected and its HTTP probe is skipped — leaving `http_smsproviders` empty (and its transform
  a DEBUG skip) in every normal authenticated run. In an HTTP-only / SMB-only run no privileged table exists,
  so those fallback misses correctly stay a WARNING.

### The downstream consequence: convert must normalize properties on output

The NULL handling above is deliberate — `_ensure_columns` *creates* all-NULL columns on purpose so the SQL
compiles, and many optional attributes (`disable_loopback_check`, `dNSHostName`, the SCCM client flags) are
genuinely NULL on most rows. Those NULL columns flow into the typed node/edge models, whose optional fields
default to `None`. If we emitted them as-is, `dataclasses.asdict()` + the destination's plain `json.dumps`
would write each as JSON `null`.

**BloodHound's OpenGraph ingest rejects that.** A property value must be `string`/`number`/`boolean`/`array`
(an `anyOf` over those four) — `null` is not a member, so a single null-valued property fails the *entire*
file's schema validation and the ingest is refused. (The framework's other, Pydantic, serialization path
strips nulls via `exclude_none=True`; the dataclass + `asdict` path the convert pipeline uses does not, so
the responsibility lands here.)

So the convert emit step omits any property whose value is `None` before writing —
[`_normalize_properties`](src/openhound_sccm/convert_pipeline.py) runs on every node and every edge, the
single point all graph content flows through. This matches BloodHound's convention that an absent attribute
is *missing*, not `null`. Empty lists are kept (an array is a valid value); only `None` is dropped.

**The same function also sorts array-valued properties, for a second and unrelated reason.** The arrays in
the graph are built by DuckDB `list()` / `array_agg()` aggregations (about twenty of them across
`transforms.py`). Neither gives an ordering guarantee, and DuckDB aggregates multi-threaded — so two converts
over *byte-identical* input emit the same elements in different orders. Measured 2026-07-29 by reprocessing
one cached bucket twice: 14 node and 6 edge property differences, in `collectionIds`, `siteSystemRoles`,
`coercionVictimHostnames`, and `coercionVictimAndRelayTargetPairs`. Node and edge counts, kinds, identities
and triples were all stable — only element order moved.

That cost twice over. BloodHound saw a changed property on re-ingest when nothing had changed, and any
run-to-run graph diff — which is exactly what the `--compare-to-zip` parity check is — filled with false
positives that could mask a real regression. Sorting makes the output a function of the input alone: the same
experiment now reports zero differences.

Two design points worth keeping:

- **Sorted at the emit boundary, not in the SQL.** One place instead of twenty, it covers any array added
  later for free, and it cannot end up half-applied — a codebase where eight aggregations sort and thirteen
  do not is harder to reason about than one where none do.
- **`objectClass` is exempt**, via `_ORDER_SIGNIFICANT_PROPERTIES`. LDAP returns it most-general-first
  (`top`, `person`, `organizationalPerson`, `user`, `computer`); that order is how a reader interprets the
  value and is already reproducible, so sorting it would destroy information for no gain. It is the only
  exemption, and the test for adding another is whether a *reader* relies on the order — not whether it
  happens to look tidy.

---

## 11. Stage 2 preproc/convert add-ons

Stage 2 of the Convert2-Read-DB **graph pipeline** ships four design additions beyond the Stage 1 baseline. (Every "Stage N" in this section is one of those preprocess/convert port increments — plans `docs/superpowers/plans/2026-06-16-sccm-preproc-convert-stage0.md` … `2026-07-01-sccm-preproc-convert-stage7.md`, under the design spec `docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md` — **not** the collection stages of §1/§4. See the [Reference key](#reference-key-the-shorthand-used-in-this-document).) Three of them extend the collect → preproc → convert contract; one is a new category of divergence that gets its own subsection below.

### 11a. Collect-side additions

Two small additions land in the `collect` phase to carry information forward to the decoupled `preprocess` and `convert` runs.

**`host_object_sid` on the RemoteRegistry current-user row** ([collectors/registry.py](src/openhound_sccm/collectors/registry.py)). The `remoteregistry_users` row for the current logged-on user now includes the host machine's own AD SID (`host_object_sid`). This gives the `graph_edges` builder a stable start-node id for the `HasSession` edge — without it, the edge could not connect the computer to the session user because the raw row carries only the user's SID. The field is `None` when the target's AD object could not be resolved; downstream, the edge builder drops the row with a warning rather than emitting a malformed edge.

**`collection_settings` table — one-row flag persistence** ([collectors/local.py](src/openhound_sccm/collectors/local.py)). A discovery-phase resource called `collection_settings` writes a single row carrying `disable_possible_edges` and `enable_bad_opsec` — the two CLI flags whose effects are decided at collect time but must be respected by the separate `preprocess` run. The `preprocess` step reads this row via `_read_disable_possible` ([transforms.py](src/openhound_sccm/transforms.py)) and uses it to gate possible-client rows and future Stage 6 relay edges. If the table is absent (older collection without the row), `_read_disable_possible` defaults to `False` — possible nodes are emitted.

### 11b. Persist-at-collect / gate-in-preproc for inferred client nodes

CMBP emits "possible" client nodes for devices that have a `CmRcService` SPN in AD (indicating the Remote Control client) but no confirmed SCCM enrollment (`SMS_R_System is_client = True`). The flag that gates this behaviour (`--disable-possible-edges`) is a CLI argument on `openhound collect sccm`, but the separate `openhound preprocess sccm` run has no access to the CLI that produced the raw data.

The solution is the `collection_settings` table described above. `_read_disable_possible` in [transforms.py](src/openhound_sccm/transforms.py) reads `bool_or(disable_possible_edges)` from that table and passes the result to `_node_client_device_possible`, which appends inferred client rows (`is_confirmed_active_client = False`) to `node_client_device` only when the flag is `False`. The inferred-client node id is `upper(object_sid)@root_site_code` — a deterministic, namespaced id that avoids merging with the `Computer` node (raw SID) yet allows the Stage 4 `SCCM_SameHostAs` edge to link it back to the AD computer object.

CMBP used a random GUID as the id for possible-client nodes; we use `object_sid@root_site_code` instead so id assignment is stable across repeated collections.

**Which site owns an inferred client — the Primary, never the CAS.** The `SCCM_HasClient` edge starts from the client's `site_code`, so that column decides which site "owns" the inferred client. A Central Administration Site cannot own clients, so this must be a **Primary** site. CMBP picks "the first primary site code published to AD" (`ps1:3253-3254`, filtering `siteType -eq "Primary Site"`). Two places cooperate to reproduce that, because the id keeps the `@root_site_code` suffix (which resolves to the CAS in a CAS-topped hierarchy) purely for namespacing:

- **Preproc (authoritative).** `_node_client_device_possible` sets `site_code` to `_first_primary_code` — `MIN(site_code) WHERE site_type = 2` from `site_hierarchy` (`site_type` comes from privileged AdminService/WMI site definitions, which are also what makes a hierarchy root exist at all, so the Primary/CAS distinction is always available when a possible-client is created). It falls back to the root only in the degenerate case of a hierarchy with no Primary, so the edge is never dropped. The deterministic `MIN` replaces CMBP's order-dependent `Select -First 1`.
- **Collect (raw-data hygiene).** `ldap_cmrc_devices` stamps the raw row's `site_code` via `_pick_client_device_site_code`, preferring a site the MP-capabilities parse classified as `"Primary Site"` (recorded on `ctx.primary_site_codes` during `ldap_management_points_raw`, which runs first). A CAS publishes an `mSSMSSite` object like any other site but has no management point, so without this it would sort into `ctx.site_codes` and could be picked as the client's site. This raw value is not consumed by the preproc builder above (which derives its own Primary from `site_hierarchy`); it exists so the collected artifact is itself coherent.

Earlier the port attached these to `_root_code` (the CAS in a CAS hierarchy), producing an impossible `CAS → SCCM_ClientDevice` edge — a port-parity bug against CMBP's explicit Primary-site filter (`ope-e739`).

### 11c. Traversable allow-list and the generic GraphEdge model

CMBP maintains a hard-coded list of edge kinds whose `traversable` property is `True` — the set that BloodHound's attack-path engine follows when building attack paths (`ConfigManBearPig.ps1:2216-2249`). Kinds outside the list are stored but not traversed (e.g. `SCCM_HasMember`).

In OpenHound the list lives in `TRAVERSABLE_EDGE_KINDS` in [kinds/edges.py](src/openhound_sccm/kinds/edges.py). It is a `frozenset` covering current and future (Stage 3–6) kinds so later stages can add edges without updating the traversability logic.

All edges — regardless of kind — are emitted by the single generic [`GraphEdge`](src/openhound_sccm/models/graph_edge.py) model. It reads the `graph_edges` preproc table and sets both `SCCMEdgeProperties.traversable = kind in TRAVERSABLE_EDGE_KINDS` and `SCCMEdgeProperties.collectionSource` from the row's `collection_source` array (defaulting to `[]`). The `collection_source` column is a typed `VARCHAR[]` array — **not** a JSON string. Storing it as JSON was a Stage-2 bug (DuckDB returns JSON columns as plain strings, which would have required manual parsing in convert); the typed array avoids that entirely. This keeps the edge model trivially thin and `graph_edges` a uniform table — new edge kinds only require rows in the table plus an entry in the allow-list if they should be traversable.

**`graph_edges` columns (as of the low-priv-assumed-edges plan, §11l):**

| Column | Type | Description |
|---|---|---|
| `start_id` | `VARCHAR` | Start node id |
| `end_id` | `VARCHAR` | End node id |
| `kind` | `VARCHAR` | Edge kind string |
| `collection_source` | `VARCHAR[]` | Provenance tags array-unioned across duplicate rows |
| `coercion_victim_and_relay_target_pairs` | `VARCHAR[]` | Human-readable `"Coerce <victim>, relay to <target>"` strings; populated only by the three `CoerceAndRelay*` builders; `NULL` (coalesced to `[]` by dedup) for every other edge kind. |
| `coercion_victim_hostnames` | `VARCHAR[]` | FQDNs of coercion victim hosts; populated only by `_edge_coerce_relay_smb`; `NULL` (coalesced to `[]` by dedup) for all other kinds. |
| `sccm_infra` | `BOOLEAN` | Flags the start-node principal as SCCM infrastructure; populated only by `_edge_is_mapped_to` (`SCCM_IsMappedTo` only, CMBP parity); `NULL` for every other kind. |
| `assumed` | `BOOLEAN` | D3 provenance (§11l) — decision D3 of the low-privilege assumed-edges plan, `docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md`, which pairs this flag with a human-readable `assumptionBasis`: `true` on a templated/inferred edge, `NULL` (no stamp) on a confirmed one. Populated by the MSSQL site-DB-scaffolding edges (basis-derived, via `_site_db_provenance_cols`) and the Tier-B SCCM permission/coerce/local-admin edges (unconditionally `true`, flag-independent). |
| `assumption_basis` | `VARCHAR` | Human-readable explanation of the inference; non-NULL only when `assumed` is `true`. |

The three `CoerceAndRelay*` edge kinds carry additional context via the `SCCMRelayEdgeProperties` subclass of `SCCMEdgeProperties` (defined in [graph.py](src/openhound_sccm/graph.py)), which adds `coercionVictimAndRelayTargetPairs` and `coercionVictimHostnames` fields. `GraphEdge` emits these relay-only properties when the edge's kind is one of the three relay kinds; every other edge uses the lean base `SCCMEdgeProperties` with only `collectionSource` and `traversable`. Field names in both classes mirror ConfigManBearPig's exact casing.

A final dedup pass (`_graph_edges_dedup`) in the `graph_edges` preproc query groups by `(start_id, end_id, kind)` and array-unions both `collection_source` and the two coercion columns via `list_distinct(flatten(list(...)))` — matching CMBP's `Upsert-Edge` array-merge behaviour (`ps1:2155-2158`).

**`node_computer.smb_signing_source` — SMB-signing probe provenance.** `node_computer` carries a `smb_signing_source VARCHAR[]` column that records which probe(s) observed the host's SMB-signing state: `["SMB-Negotiate"]` (from the unauthenticated SMB2-negotiate check in `smb_computers`), `["RemoteRegistry-SMBSigningCheck"]` (from the registry-based check in `remoteregistry_computers`), or both. This array is array-unioned across sources during the `GROUP BY sid` collapse and is consumed directly by `_edge_coerce_relay_smb` as the `collection_source` for the `SCCM_CoerceAndRelayToSMB` edge (filtered to the two SMB-signing probe tags). It is not emitted as a node property.

### 11d. Stage 4: client-device dedup and host-correlation edges

Stage 4 adds two new edge kinds and a pre-edge dedup pass, all of which interact closely with the `node_client_device` table built by Stages 2–3.

**`_dedup_client_device` — merge real+inferred twins before edges are built.** After `_enrich_client_device` resolves `ad_domain_sid` on real clients (from `SMS_R_System`) and inferred clients carry it from the CmRcService SPN's `object_sid`, the table can contain two rows for the same physical host: a real client (`is_confirmed_active_client = True`, id = SMSID) and its inferred twin (`is_confirmed_active_client = False`, id = `<SID>@root`). `_dedup_client_device` ([transforms.py:1531](src/openhound_sccm/transforms.py#L1531)) groups by `ad_domain_sid` (with a NULL-isolation guard so unresolved real clients are never grouped together), ranks the real client first, and keeps only the top-ranked row. Array columns (`collection_ids`, `collection_names`) are unioned across the group before the inferred row is discarded, so no data is lost. Critically, this runs **before** `_graph_edges_init` and all edge builders — so every edge is built from the deduped table and references only survivors, with no `graph_edges` rewrite needed afterward. This is a deliberate divergence from CMBP's order, where the merge happens after edges are built (`ps1:2269-2311`).

**`_edge_same_host` — bidirectional Computer ↔ SCCM_ClientDevice.** After dedup, each surviving `SCCM_ClientDevice` row whose `ad_domain_sid` matches a `Computer` node's `sid` gets two `SCCM_SameHostAs` edges (one in each direction). This gives BloodHound paths in both directions (CMBP `ps1:2314-2320`). Because dedup runs first, the edge builder always sees the canonical survivor, never the discarded inferred twin.

**`_edge_local_admin_required` — site server → peer site systems, plus parent primary → child secondary.** Arm 1 (CMBP `ps1:1882-1909`): a computer hosting `SMS Site Server@<site>` is granted local-administrator rights on every other site system in that site, built set-based from `site_system_roles`, with self-edges and secondary sites excluded.

Arm 2 (2026-08-01, no CMBP equivalent) crosses sites: the site servers of a **parent primary** get the same edge onto the site server of a **child secondary**. Microsoft states it as a setup prerequisite — *"Add the computer account of the parent primary site to the Administrators group on the secondary site server"* ([prerequisites-for-installing-sites](https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites#bkmk_secondary)) — and arm 1 can never produce it, being strictly intra-site and skipping secondaries outright. It matters beyond local admin: on a secondary whose SQL Express instance SCCM installed, `BUILTIN\Administrators` holds sysadmin, so this membership is also how the parent reaches the secondary's database.

In the mayyhem lab the edge already appeared without arm 2, but incidentally — `ps1-sec` happens to carry `SMS Management Point@PS1`, pulling it into PS1's own mesh. A secondary serving no role for its parent would have been missed while the requirement still applied. Arm 2 gates on a **positively known** `site_type = 1` (the mirror of `_NON_SECONDARY_SITE_TYPE_SQL`: an unknown type may no more be treated as a secondary than as a primary), matches the parent **by role** so a site server in passive mode is covered, and relies on `_graph_edges_dedup` rather than a guard where the two arms overlap. Both edge kinds carry `collection_source = ['SCCM_Invoke-PostProcessing']` for entity-panel provenance; arm 2 carries its own `SECONDARY_PARENT_LOCAL_ADMIN_BASIS` so the entity panel distinguishes which rule fired.

### 11e. Edge-endpoint stub-node backfill (new divergence category)

*This is a new category of divergence from a stock OpenHound collector.*

#### The framework baseline

In a stock collector, every node is produced by an explicit `@app.asset` model whose driver file contains a row for each entity. Edges reference nodes that are guaranteed to exist because both sides are collected from the same API. There is no provision for "an edge references a node that has no row in any driver table."

#### Why it breaks for SCCM

SCCM's data is inherently cross-referencing: an `SMS_R_System` record names the primary user's SID, but that SID may not appear in any `SMS_R_User` record — the user exists in AD but has never logged on interactively via SCCM. An `SMS_CollectionMember` names a device that was enrolled but later removed. CMBP handles this with `Upsert-Node` — an in-memory call that creates a bare node on the fly whenever an edge references an id with no existing node. OpenHound has no equivalent: if a `HasPrimaryUser` edge's end SID has no User node in the `node_user` table, the edge will silently point to a missing node in the OpenGraph output.

#### The add-on: node_backfill + StubNode

After all `node_*` tables are built and `graph_edges` is finalised, `preprocess` runs `transforms._node_backfill` ([transforms.py](src/openhound_sccm/transforms.py)). This function:

1. Collects every `end_id` from `graph_edges` whose kind is in `BACKFILL_END_KIND`, and every `start_id` whose kind is in `BACKFILL_START_KIND`.
2. LEFT JOINs against every `node_*` table to find ids with no matching node.
3. Infers the kind for each missing endpoint from those maps (defined in [graph.py](src/openhound_sccm/graph.py)): ends — `HasSession`→`User`, `MemberOf`→`Group`, `SCCM_HasMember`/`SCCM_HasStoredAccount`→`Base` (ambiguous principal); starts — `MemberOf`→`Base`, since a member may be a user, a group or a computer. Both arms are unioned and collapsed to one row per id (an id can dangle at both ends — a nested group is the end of one `MemberOf` and the start of the next). Writes the results to a `node_backfill` table.

The `node_backfill` table is read by the [`StubNode`](src/openhound_sccm/models/stub_node.py) convert model. `StubNode` emits a minimal node — just `id`, `kinds` (with `Base` appended for AD-principal kinds), and `environmentid` (domain SID for SID-keyed ids, else the id itself). **It carries no `name` or `displayname`**: a stub exists precisely because nothing in the collect knew what the principal *is*, and since these nodes ship untagged (§11f) to merge into the native AD graph by id, naming a stub after its own SID would replace a real SharpHound label with the SID string on the merged node. Both properties are null and pruned on emit, so BloodHound displays the object id when it knows nothing better. It never carries SCCM-specific properties either; those are populated if a future collection brings in the matching row.

This mirrors CMBP's `Upsert-Node` semantics: **every edge endpoint gets a node**, even if only a stub. The stub is later enriched or deduplicated if the real node arrives from SharpHound or a subsequent collection.

#### Why the start side exists (Ope-15m7)

The original design covered only ends, on the assumption that an edge's start is always something this collector built. That does not hold for the System Management container ACL walk, which discovers group *members* by SID and turns each into a `MemberOf` start without ever creating a node for them. A dangling end merely renders as an unnamed node; a dangling start makes BloodHound **drop the whole edge** at ingest. In the recorded unprivileged run that silently removed five `MemberOf` edges and hid the real membership of Domain Admins, Enterprise Admins and IT Helpdesk.

Most of those endpoints are now resolved upstream instead: the `ad_props` arms on `_node_group` and `_node_user` (§11m) turn every LDAP-resolved principal into a real, named node, which took `node_backfill` to zero rows on both recorded datasets. The start-side backfill remains as the residual net for a principal LDAP never resolved.

#### Trade-offs

- `BACKFILL_END_KIND` / `BACKFILL_START_KIND` must be updated whenever a new edge kind is added whose endpoint may lack a full node. Forgetting to add an entry leaves an orphan endpoint (end) or a dropped edge (start). This is guarded by the `graph_edges_dedup_test.py`, `graph_edge_test.py` and `sharphound_naming_test.py` test files.
- `Base`-kind stubs (for `SCCM_HasMember` / `SCCM_HasStoredAccount` ends and all `MemberOf` starts) have no `User` or `Group` label — they merge with a SharpHound node if the SID is ever resolved, but until then they appear as plain `Base` nodes in the graph.
- A stub is now completely unnamed, so a standalone graph with no SharpHound data shows object ids for these nodes. That is the intended trade: an id is honest about what is unknown, whereas a SID-as-name is a claim that overwrites better data on merge.

---

### 11f. Split output: an untagged AD payload beside the SCCM source

*This is a new category of divergence from a stock OpenHound collector.*

#### The framework baseline

A stock collector emits one OpenGraph dataset under a single `source_kind`. Core's
`opengraph_file` destination takes `source_kind` as a required `dlt.config.value` and stamps
`{"metadata": {"source_kind": ...}}` into every file. There is no provision for emitting part
of the graph under a *different* source — or under *no* source at all.

#### Why it breaks for SCCM

The SCCM graph mixes two ownership domains. `SCCM_*` nodes are genuinely SCCM-owned and should
register under the `SCCM` source. But `Computer` / `User` / `Group` (and the backfill stubs) are
**Active Directory** objects — the same objects SharpHound collects. Tagging them with
`source_kind="SCCM"` makes the SCCM source *own* native AD nodes, so re-ingesting or deleting the
SCCM source would touch AD data it shouldn't. We want the AD nodes (and the edges touching them)
to merge into BloodHound's **native AD graph** by SID, augmenting SharpHound rather than shadowing
it — which means emitting them with **no `source_kind` at all**.

#### The add-on: three emit passes + an untagged extension destination

- **Node routing needs no preproc step.** The coalesced `node_*` tables are already segregated by type, so the
  convert spec list is just split into `SCCM_NODE_SPECS` (`node_site`/`collection`/`security_role`/
  `admin_user`/`client_device`), `MSSQL_NODE_SPECS` (the six `node_mssql_*` tables, `source_kind="MSSQL"`,
  `resource_prefix="mssql"`), and `AD_NODE_SPECS` (`node_computer`/`user`/`group`/`backfill`) in
  [main.py](src/openhound_sccm/main.py).
- **Edge routing is one preproc step, now a three-way partition.** `transforms._graph_edges_split`
  runs *after* `_node_backfill` and partitions `graph_edges` into `graph_edges_ad` (either endpoint id
  is in `node_computer ∪ node_user ∪ node_group ∪ node_backfill` — highest precedence),
  `graph_edges_mssql` (not AD-touching **and** both endpoints are in the new `_mssql_ids` set, unioned
  from the six MSSQL node id columns), and `graph_edges_sccm` (the remaining complement). AD↔MSSQL
  edges stay in `graph_edges_ad` under this precedence (e.g. `MSSQL_HostFor`, `MSSQL_HasLogin`), and
  the MSSQL↔SCCM edge `SCCM_AssignAllPermissions` (database → site) stays in `graph_edges_sccm`, since
  it is not both-MSSQL. Every backfill stub id counts as AD, so the `SCCM_HasMember` /
  `SCCM_HasStoredAccount` edges to bare-`Base` principals follow their stub into the AD payload.
- **Three emit passes.** `_emit_split_graph` calls `emit_graph_from_duckdb` three times into the same
  directory: the SCCM pass (`source_kind="SCCM"`, `resource_prefix="sccm"`) and the MSSQL pass
  (`source_kind="MSSQL"`, `resource_prefix="mssql"`) both through core's `opengraph_file`, and the AD
  pass (`source_kind=None`, `resource_prefix="ad"`) through the extension's
  [`opengraph_file_untagged`](src/openhound_sccm/opengraph_untagged.py) — a sibling of core's writer
  that omits the `metadata` block entirely. Distinct resource prefixes give distinct file basenames
  (`sccm_*` / `mssql_*` / `ad_*`), so three pipelines writing to one directory never collide.

#### Trade-offs

- An AD↔SCCM or AD↔MSSQL edge lives in the untagged file but references an `SCCM_*` or `MSSQL_*` node
  defined in a differently-tagged file; this is safe only because BloodHound resolves edge endpoints
  by id across all ingested files — so all three file sets must be uploaded together.
- `opengraph_file_untagged` duplicates core's writer logic (a coupling to watch on OpenHound
  upgrades), because core's destination can't express "no metadata" and core is off-limits.
- `_graph_edges_split` must run after `node_backfill`; a future reordering of `transforms()` that
  breaks that would silently route stub-edges to the wrong file. Guarded by
  [`graph_edges_split_test.py`](tests/graph_edges_split_test.py).

---

### 11g. Stage 5: MSSQL node merge and topology inference

Stage 5 adds six `MSSQL_*` node tables and ~15 edge kinds, all built entirely in `preproc`
(`transforms.py`) and emitted through the existing Convert2-Read-DB pipeline. No new framework
divergence categories are introduced; the MSSQL work is an extension of the preproc node-coalesce
design from §9 and the output-split routing from §11f.

**`MSSQL_Server` merge — one row per `host_sid:port`.** `node_mssql_server` is built like
`node_computer`: three `INSERT` arms into a staging table, then collapsed by
`GROUP BY upper(host_sid), host_sid, port` with `any_value` for scalars (the raw `host_sid`
is carried alongside `upper(host_sid)` in the GROUP BY so the non-uppercased value stays
selectable):

- `mssql_server_instances` — the EPA scan; supplies `extendedProtection`, `forceEncryption`,
  `strictEncryption`.
- `remoteregistry_mssql_servers` — the registry walk; supplies port, `forceEncryption`,
  `instanceNames`.
- `_mssql_sql_servers` — a staging table resolved per `(site, SQL-host)` role row from
  `sccm_site_system_roles` joined through `node_computer`; supplies `SCCMSite`, `SCCMInfra`,
  `dnsHostName`, `SQLServicePort`, and the SQL service-account fields.

Using the per-`(site, SQL-host)` role rows (not `node_site`'s single `any_value` per site) means
a site with **multiple SQL hosts** gets one `MSSQL_Server` row per host. Scan/registry rows with
no SCCM match still produce a bare `MSSQL_Server` (plus `MSSQL_HostFor` / `MSSQL_ExecuteOnHost`);
their `SCCMSite` / `SCCMInfra` columns stay null/false. This directly mirrors CMBP's
`Add-MSSQLServerNodesAndEdges` (ps1:6050-6186) while capturing non-SCCM SQL servers that CMBP
skips.

**Login / DatabaseUser topology inference.** CMBP never queries SQL for user identity.
Instead it infers the `sysadmin` logins from the machine accounts of the site's Primary Site
Server and SMS Provider computers — the hosts SCCM architecturally grants `sysadmin` on the site
database (`Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer`, ps1:6187-6292). The port uses the
same pattern: login name and id use `upper(split_part(dnshostname, '.', 2)) || '\' || sam_account_name`
from the **sysadmin computer's own** DNS domain (`dnshostname` second label), which is correct for
cross-domain Site Server / SMS Provider hosts (a refinement over CMBP's `$Domain.Split('.')[0]`
which read the **collector's** domain). Database, `sysadmin` ServerRole, and `db_owner`
DatabaseRole nodes follow from the same SCCM topology: the database is always `CM_<siteCode>` and
the roles always exist. Stage 5 fixes one CMBP scope bug: CMBP left `sysadmin`/`db_owner` `members`
arrays empty (undefined variable, ps1:6105/6155); the set-based port fills them from the joined
logins/database-users.

**`environmentid`.** All six MSSQL node kinds use `domain_environment_id(host_sid)` — the
AD-domain SID of the SQL host — the same derivation as `Computer` / `User` / `Group` nodes
(see §9 "Group identity" and [graph.py](src/openhound_sccm/graph.py) for `domain_environment_id`).
This ensures MSSQL nodes merge correctly with a future `MSSQLHound` collection keyed on the same
domain SID.

**Output routing.** MSSQL nodes register in `MSSQL_NODE_SPECS` (`source_kind="MSSQL"`,
`mssql_*` files) — the separate MSSQL OpenGraph schema (`schema_MSSQL.json`) owns them,
even though this collector emits them. MSSQL edges insert into the single `graph_edges`
table and are routed by `_graph_edges_split` (§11f) **by endpoint**: both-MSSQL edges
(`MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_MemberOf`,
`MSSQL_IsMappedTo`) go to `graph_edges_mssql`; edges with an AD endpoint (`MSSQL_HostFor`,
`MSSQL_ExecuteOnHost`, `MSSQL_HasLogin`, `MSSQL_GetTGS`, `MSSQL_ServiceAccountFor`,
`MSSQL_GetAdminTGS`) go to `graph_edges_ad` (untagged AD payload); and the MSSQL↔SCCM
`SCCM_AssignAllPermissions` (database → site) goes to `graph_edges_sccm`. `_graph_edges_split`
builds an `_mssql_ids` set from the six MSSQL node id columns to make this decision.

### 11h. Stage 6: coerce-and-relay possible edges and the synthetic Authenticated Users node

Stage 6 adds three new edge kinds (`SCCM_CoerceAndRelayToAdminService`, `MSSQL_CoerceAndRelayToMSSQL`, `SCCM_CoerceAndRelayToSMB`) and one new synthetic node type. No new framework divergence categories are introduced; Stage 6 extends the existing preproc-only pattern from §11c and the output-split routing from §11f.

**`--disable-possible-edges` semantics, as originally shipped (superseded below).** The
`disable_possible_edges` flag (persisted in `collection_settings`, read by `_read_disable_possible`)
already gated Stage 3–4 possible-client nodes. Stage 6, as first written, extended it to all three relay
builders with a *surgical* two-level gate: default (flag off) treated a null/absent NTLM restriction as
*assumed vulnerable* (matching ConfigManBearPig's behavior at `ps1:6618`, `ps1:6712`, `ps1:6762`), and the
flag required an *explicitly confirmed* `Off` for each condition.

> **Superseded (2026-07-28, low-priv-assumed-edges plan, §11l).** Auditing the actual builders found that
> only `MSSQL_CoerceAndRelayToMSSQL`'s **EPA** condition is genuinely flag-gated. `SCCM_CoerceAndRelayToAdminService`'s
> and `SCCM_CoerceAndRelayToSMB`'s NTLM conditions (and `MSSQL_CoerceAndRelayToMSSQL`'s own NTLM condition)
> are **flag-independent** in both today's code and CMBP's actual behavior: an unset NTLM restriction
> genuinely **is** the Windows default (0 = allow all inbound NTLM), so treating it as vulnerable is a
> measured fact, not a topology guess, in **both** modes — and CMBP itself emits these families under its
> own `-DisablePossibleEdges` switch. `SCCM_CoerceAndRelayToSMB`'s SMB-signing condition was never
> assumed either way (always required a confirmed `false`). See §11l for the full ruling, the dead-parameter
> cleanup this caused (`_edge_coerce_relay_adminservice`/`_edge_coerce_relay_smb` no longer take a
> `disable_possible_edges` parameter at all), and the D3 provenance stamp that replaced this section's
> original flag-gating as the way these families are marked to an operator.

`_read_disable_possible` combines the collect-time `collection_settings` value with the `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES` env var (tightening-only OR), so preproc can re-tighten existing raw without a re-collect.

**Lazy Authenticated Users node.** Rather than creating a fixed set of Authenticated Users nodes up front, `_node_authenticated_users` runs *after* all three relay edge builders have inserted into `graph_edges`. It reads the distinct `start_id` values from relay-kind rows and inserts one `Group` row into `node_group` per domain that actually produced at least one relay edge. The node id follows SharpHound's well-known-SID form (`UPPER(FQDN)-S-1-5-11`) so it merges with SharpHound data by id; the `environmentid` is resolved from a co-occurring domain computer's AD domain SID via a join on `_domain_to_sid`. This lazy approach matches CMBP's per-iteration `Upsert-Node` pattern and avoids creating orphan Authenticated Users nodes for domains with no exploitable relay path. The node must be inserted into `node_group` *before* `_node_backfill` and `_graph_edges_split` so it is included in the AD id set and routed to the AD payload correctly.

**`SCCM_CoerceAndRelayToSMB` traversable bug fix.** ConfigManBearPig's traversable allow-list at `ps1:2221` named the SMB relay kind `CoerceAndRelayNTLMtoSMB`, while the function that emits the edge at `ps1:6775` used `CoerceAndRelayToSMB` — the string mismatch meant the SMB relay edge was stored but never marked traversable. This port emits `SCCM_CoerceAndRelayToSMB` and includes that exact string in `TRAVERSABLE_EDGE_KINDS`, so all three relay kinds are traversable.

**Output routing.** All three relay edges touch an AD `Group` start node (Authenticated Users), so they are routed to `graph_edges_ad` (the untagged AD payload) by `_graph_edges_split`. For `SCCM_CoerceAndRelayToSMB` the end node is also an AD `Computer`, so both endpoints are AD nodes. For `SCCM_CoerceAndRelayToAdminService` the end is a `SCCM_Site` (SCCM payload), and for `MSSQL_CoerceAndRelayToMSSQL` the end is an `MSSQL_Login` (MSSQL payload since the §11f/§11g split) — but the AD-start-node rule routes both to the AD payload regardless. `MSSQL_CoerceAndRelayToMSSQL` therefore lands in the **AD payload**, not the MSSQL payload, despite its `MSSQL_` kind — the by-endpoint routing rule (§11f) wins over the kind's naming convention.

### 11i. HTTP version fingerprint from ccmsetup.exe — a new HTTP-phase capability

*This is a new category of divergence from a stock OpenHound collector.*

#### The framework baseline

Every existing HTTP-phase probe (§2/§3 above) reads at most a small status code or a few KB of XML —
`MPKEYINFORMATION`, `MPLIST`, the site-signing certificate. A stock REST-API collector (and every
probe this extension had until now) treats "make an unauthenticated or authenticated request and
parse the response" as reading a small, structured payload. There is no precedent, here or in a stock
OpenHound extension, for downloading and parsing a multi-megabyte *binary* file as a source of truth.

#### Why it breaks for SCCM

[SCCMVersionGuesser](https://github.com/synacktiv/SCCMVersionGuesser)'s technique for learning a
site's exact SCCM build **without any credentials** is to read the version string Microsoft embeds in
`ccmsetup.exe`, the client-installer binary every Management Point serves unauthenticated. This is the
only way to fingerprint the site's patch level (and therefore its outstanding CVEs, and whether it's
new enough that the AdminService rejects NTLM) when the operator has no domain credentials, or when
privileged collection (AdminService/WMI) reached the site but returned no version. Getting that string
means fetching and regexing an actual binary — a fundamentally different operation from every other
probe in this file.

#### The add-on: a best-effort binary fetch inside the confirmed-MP handler

- [`_probe_ccmsetup_version`](src/openhound_sccm/collectors/http.py#L378-L404) runs only after
  `probe_management_point` confirms the MP role (`self.is_mp = True`) via the existing anonymous
  `HttpClient`; a failed, missing, or version-less fetch is logged (`logger.debug`) and skipped — it
  never gates or affects role detection.
- The version is pulled out of the raw response bytes with a UTF-16LE regex
  ([`_CCMSETUP_VERSION_RE`](src/openhound_sccm/collectors/http.py#L147-L151)) matching the
  `5.XX.XXXX.XXXX` pattern SCCMVersionGuesser uses; a hit is emitted as one row to a new raw table,
  `http_site_versions` (`site_code`, `sccm_version`, `source="HTTP-ccmsetup"`, `mp_host`).
- `preprocess`'s [`_coalesce_http_site_version`](src/openhound_sccm/transforms.py#L1224-L1241) LEFT
  JOINs this table onto `node_site` and coalesces **privileged-first**
  (`coalesce(ns.version, hv.http_version)`) — AdminService/WMI's `version` always wins when both are
  known; the HTTP fingerprint only fills sites that yielded no privileged version. This must run as
  part of `_node_site`, before anything downstream reads `node_site.version`.
- Two things now consume that coalesced version: `convert`'s `SCCMSite.as_node`
  ([models/sccm_site.py](src/openhound_sccm/models/sccm_site.py)) calls
  `cve_table.lookup_cves(version)` to populate the new `SCCM_Site.versionCVEs` property (the
  SCCMVersionGuesser build/CVE map, `cve_table.BUILD_MAP` / `CVE_MAP`), and
  [`_edge_coerce_relay_adminservice`](src/openhound_sccm/transforms.py#L2880-L2896) reads the same
  version to **suppress** the `SCCM_CoerceAndRelayToAdminService` edge on sites confirmed to be SCCM 2509+
  (build ≥ `cve_table.ADMINSERVICE_NTLM_MIN_BUILD` = 9141 — the build where the AdminService starts
  rejecting NTLM). An unknown/unparseable version fails **open**: the edge is kept as a possible edge
  that can't be confirmed mitigated.

#### Trade-offs

- **Bandwidth/OPSEC.** v1 downloads the entire `ccmsetup.exe` (multiple MB) through the existing
  `HttpClient.get()`, which has no partial/`Range` request support. On an unauthenticated probe this is
  a much larger and more noticeable footprint than every other HTTP-phase probe (a few KB of XML/JSON
  at most). A bounded/`Range` fetch is a known future optimization, gated on adding a `headers=`
  parameter to `HttpClient.get()`.
- **Two decoupled version sources feeding one field.** Because `node_site.version` can now come from
  either privileged collection or this HTTP fingerprint, `_coalesce_http_site_version` must run before
  every downstream reader of that column (the CVE lookup and the relay-edge gate). A future reordering
  of `transforms()` that read `node_site.version` before this coalesce runs would silently see only the
  privileged value.
- **Fail-open gate has a blind spot.** The 2509+ relay suppression only fires on a *confirmed* version.
  If privileged collection is unavailable and the HTTP fingerprint also fails (fetch error, no MP
  confirmed, unrecognized version string), a genuinely-patched 2509+ site still emits the (now
  inaccurate) `SCCM_CoerceAndRelayToAdminService` possible edge — correct by design (an unconfirmed
  mitigation can't be assumed), but a source of false positives operators should be aware of.

---

### 11j. AD-object attribute capture via the per-host resolution cache

`Computer`, `User`, and `Group` nodes now also carry the underlying AD object's own attributes —
`Domain`, `Enabled`, `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`, `CN` (see
[graph.py](src/openhound_sccm/graph.py) `ComputerProperties`/`UserProperties`/`GroupProperties`) —
alongside the SCCM-specific properties already emitted. No new AD collector was added; the
extension reuses AD-resolution work the collector was already doing for other reasons.

Every phase that needs to turn a name/SID/DN into an AD object calls
`SourceContext.resolve_principal` ([context.py:187](src/openhound_sccm/context.py#L187)) — LDAP
discovery resolving admins, RemoteRegistry resolving current users, AdminService/WMI resolving
device-referenced principals, and so on. `resolve_principal` already caches every lookup in
`ad_resolution_cache` (hits *and* misses, keyed by lookup string — see
[Where this code lives](#where-this-code-lives-the-shared-collector-common-library) for the
"AD-resolution cache" reference in §1) to avoid repeat LDAP round-trips. It now *also* calls
`_record_resolved_principal` ([context.py:300](src/openhound_sccm/context.py#L300)) on every fresh
(non-cache-hit) success, deduping by SID into a second, purely-successful accumulator,
`SourceContext.resolved_principals`.

At the end of the per-host stage, a new DLT resource, `ldap_resolved_principals`
([source.py:227](src/openhound_sccm/source.py#L227)), drains that accumulator into a raw table — one
row per uniquely-resolved AD object, regardless of which phase resolved it. `preprocess`'s
`_derive_ad_props` ([transforms.py:267](src/openhound_sccm/transforms.py#L267)) builds a
`sid -> AD-attribute` lookup table (`ad_props`) from it — deriving `Enabled` from the
`userAccountControl` `ACCOUNTDISABLE` bit, `Type` from the last `objectClass` element (title-cased),
and always setting `IsDomainPrincipal = True` (every row in this table was, by construction,
actually resolved against AD) — and `_join_ad_props`
([transforms.py:341](src/openhound_sccm/transforms.py#L341)) LEFT JOINs it onto `node_computer`,
`node_user`, and `node_group` by SID, before those tables reach `convert`.

> **CRITICAL: resolved-principals-only, not a domain-wide sweep.** This reaches only the principals
> the collector actually resolved during *this run* — site servers, admins, device-referenced
> users/groups, and anything else a phase happened to look up. It is deliberately **not** a new LDAP
> enumeration pass over the whole domain. A principal SCCM knows about (e.g. a device's
> `primaryUser`) that no phase ever needed to resolve stays bare — `Domain`, `Enabled`,
> `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`, and `CN` are all `null` on that
> node, exactly as before this feature existed. This is **partial parity by design**: these seven
> properties are best-effort enrichment of whatever the run already touched, not a guarantee that
> every AD-native node in the graph carries them.

**Trade-off.** `ldap_resolved_principals` is itself a best-effort finalization table whose own
`pipeline.run` is allowed to fail without aborting the collect ([transforms.py:276](src/openhound_sccm/transforms.py#L276)),
so it may be absent on some runs. `_derive_ad_props` treats it like any other optional source
(`_ensure_columns` backfills missing/all-NULL columns, `_safe` logs and skips outright absence),
leaving `ad_props` created-but-empty rather than raising, so `_join_ad_props`'s LEFT JOINs always
bind — a missing or partial `ldap_resolved_principals` degrades to "no AD-attribute enrichment this
run," never a preproc failure.

### 11k. Tier A+ low-priv additions: the System Management container, nested `MemberOf`, and the `MSSQLSvc` SPN service account

Tasks 11-14 of the low-privilege assumed-edges plan,
`docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md` (2026-07-28). No new framework divergence categories — an
extension of the node-coalesce design (§9), the split-output routing (§11f), and the MSSQL topology
inference (§11g). All four are **confirmed** (LDAP/AD-derived), so they emit in both
`--disable-possible-edges` modes with no `assumed` stamp.

**`Container` node + `GenericAll` edges (Task 11).** `ldap_system_management_dacl` was collected but
read by no transform. `collectors/ldap.py`'s `ldap_system_management_dacl` resource now also captures
the System Management container's own `objectGUID`/`name`, uppercases it to SharpHound's canonical
GUID form (`_format_guid`), and stamps it on every yielded GenericAll-principal row
(`smc_container_guid`/`smc_container_dn`). `transforms._node_smc_container` builds one `Container`+
`Base` node keyed by that GUID — a **standard BloodHound base kind**, not in `schema_SCCM.json`, so it
merges with SharpHound's own node for the same AD object — and `_edge_generic_all_smc` builds one
`GenericAll` edge per principal. Both new kinds (`Container` in `kinds/nodes.py`, `GenericAll` in
`kinds/edges.py`) are added to `TRAVERSABLE_EDGE_KINDS` alongside the pre-existing `MemberOf`/
`HasSession` base kinds. `node_container` is registered in `AD_NODE_SPECS` (§11f), emitted untagged.

**Full nested `MemberOf` chain (Task 12).** `collectors/ldap.py::_expand_group_targets` already
recursed every DACL Full-Control group's nested membership (to register computer members as scan
targets); it now also *returns* a `(group_sid, member_sid, member_type)` row for every member →
containing-group hop it visits, at every nesting level. The resource routes those rows to a second
destination table, `ldap_smc_group_members`, via `dlt.mark.with_table_name` — the same
`@app.resource` generator feeding two tables, since the membership walk is a side effect of the
already-registered DACL-principal resource rather than its own resource. `_edge_member_of_smc` reads
that table into base-kind `MemberOf` edges; BloodHound de-dupes against an equivalent SharpHound edge.
One incidental effect: a DACL group with members that had no `node_group` row of its own before (e.g.
it was never independently discovered by another SCCM source) now gets a `Group` stub node via the
pre-existing `_node_backfill`/`BACKFILL_END_KIND["MemberOf"] = "Group"` mechanism, since its SID is now
referenced as a `MemberOf` edge endpoint. Confirmed live-DB-augmented (see the Task 11-14 report,
`.sdd/2026-07-23-low-priv-assumed-edges/tasks-11-14-report.md`) to newly produce a `Group` node for
"Domain Admins" that the graph previously carried none for.

**`MSSQLSvc` SPN service account (Task 13).** `clients/ad.py::ADClient.find_mssql_spns` (D2a's mere
existence check) discards *who* holds the SPN. A new module-level `_find_mssql_spn_entries` helper
factors out the shared search + host-pinning logic; `find_mssql_spns` keeps its old signature/tests,
and a new `find_mssql_spn_holder` additionally surfaces the holder's `objectSid`/`sAMAccountName`/
`objectClass`. `collectors/mssql.py::collect_mssql` calls it when the target computer's own SPN list
lacks `MSSQLSvc` (the domain-service-account case), and adds `service_account_sid`/
`service_account_is_computer` to the `mssql_server_instances` row. `node_mssql_server` carries these as
new columns, **distinct from** the privileged `service_account_domain_sid` (SMS_SCI_SysResUse) pair —
when both resolve the same real account on the same server, the pre-existing `_graph_edges_dedup` pass
(run once, after every edge builder) collapses the resulting duplicate edge triple into one, so neither
builder needs to know about the other. `_edge_mssql_service_account_spn` emits `MSSQL_ServiceAccountFor`
(not traversable, matching CMBP); a third arm added to `_edge_has_session` emits `HasSession` (host →
service account), skipped when `service_account_is_computer` (no distinct session).

**Kerberoasting from the SPN account (Task 14).** `_edge_mssql_kerberoast_spn` joins the low-priv
service account to Task 4's site-server/provider sysadmin logins (`node_mssql_login`) — every row
there is, by construction, a domain sysadmin login, so "a login exists for this server" already
implies `MSSQL_GetAdminTGS`, and each login is a `MSSQL_GetTGS` target. Both edges copy
`assumed`/`assumptionBasis`/`collectionSource` straight from the login row rather than recomputing
them — the edge is exactly as confirmed/assumed as the login it rests on, and needs no
`disable_possible_edges` parameter of its own because Task 2 already removed the assumed logins
upstream when the flag is set.

### 11l. The rest of the low-priv-assumed-edges plan: `site_hierarchy` fed from every source, D6 attribution, and the assumption/provenance engine

Tasks 1, 1b, 1c, and 2-6 of the low-privilege assumed-edges plan,
`docs/superpowers/plans/2026-07-23-low-priv-assumed-edges.md`, whose decisions D2-D6 are also named
throughout this subsection (2026-07-27/28). Documented after §11k above because that
section was written first, mid-plan — chronologically these tasks landed *before* Tasks 11-14, and
everything in §11k builds on the `site_hierarchy`/provenance machinery described here. No new framework
divergence category: this extends the preproc node-coalesce design (§9) and the assumed/possible-edges
gate already established in §11b/§11h.

#### The linchpin: `site_hierarchy` fed from every site-code source (D5)

Before this work, `_site_hierarchy` (`transforms.py`) INSERTed only from `adminservice_site_definitions`
and `wmi_site_definitions` — both AdminService/WMI-only. When AdminService was unreachable,
`site_hierarchy` was empty, `_root_code`/`_first_primary_code` returned `None`, and every builder that
joins the `nonsec` CTE derived from `site_hierarchy` emitted zero rows — regardless of what LDAP,
RemoteRegistry, HTTP, SMB, or DNS had actually collected. A 2026-07-23 live low-priv run measured the
consequence directly: ConfigManBearPig emitted 106-146 edges from the same collection; OpenHound emitted 9.

The collector learns a site code in **ten** distinct ways across ~16 raw tables. Two of them are
*hierarchy-shaped* (they carry `site_type`/`parent_site_code`, and — for LDAP management-point
capabilities only — a directly observed `root_site_code`); the rest are *bare-code* (a table has a
`site_code` column and nothing else). `_site_hierarchy` now feeds from all of them:

- **Hierarchy-shaped arms** — `adminservice_site_definitions`, `wmi_site_definitions` (unchanged), plus a
  new arm for `ldap_management_points_raw` (LDAP MP capabilities, low-priv reachable), which maps the
  string `site_type` (`"Central Administration Site"`/`"Primary Site"`/`"Secondary Site"`) onto the
  existing `1`=Secondary/`2`=Primary/`4`=CAS INTEGER contract.
- **Bare-code arms, discovered rather than hardcoded (D5).** `_bare_site_code_tables` queries
  `information_schema.columns` for every table in the schema that has a `site_code` column, minus the
  three hierarchy-shaped ones already loaded and the derived `node_*`/`edge_*`/`site_hierarchy`/
  `assumed_site_dbs` tables. Each discovered table registers its bare site code with `NULL` type/parent; the
  collapse step below (`GROUP BY site_code`, `max(site_type)`, `any_value(parent_site_code)`) lets any
  richer row for the same code win, so widening the net this way can never degrade a stronger source — it
  can only rescue a code that would otherwise be missing entirely. **Rationale for discovery over a
  hardcoded list:** a hardcoded list goes stale the moment a new collector learns a site code; querying
  `information_schema` means "all sources" stays true by construction, and a genuinely absent table is
  simply not in the result set (no `_safe` guard needed for it).
- **`_node_site` backfills from `site_hierarchy` (con-3354, 2026-07-31).** Widening the D5 net above made
  `site_hierarchy` know every site code the collector saw — but `_node_site`'s own arms read only
  AdminService/WMI/LDAP, and its `LEFT JOIN site_hierarchy` merely *stamps* `root_site_code`/`site_type`
  onto rows that already exist. It cannot add one. A site discovered **solely** by a bare low-privilege
  source therefore reached `site_hierarchy` and stopped there: no `node_site` row, so no `SCCM_Site` node,
  so a low-privilege run silently lost the site. Against the mayyhem lab this dropped the real `SEC`
  secondary — `site_hierarchy` held `CAS/PS1/SEC` while `node_site` held only `CAS/PS1`. A privileged run
  hid the bug entirely, because AdminService supplies `SEC` as a source row of its own. `_node_site` now
  inserts any `site_hierarchy.site_code` no other arm supplied, **after** the `GROUP BY upper(site_code)`
  collapse and **before** the stamp, so recovered rows pick up `root_site_code` and the `site_type`
  fallback like any other. Every other column stays `NULL`, which is honest: a bare code is all those
  sources ever knew. Note the `SEC` secondary is not published to AD at all (`(objectClass=mSSMSSite)`
  returns two objects in this forest), so LDAP can never be the rescuing source — the low-priv evidence is
  the HTTP probe and the SMB share comments (`SMS_SEC`, `SCCMContentLib$ ... for site SEC`).
- **Sentinel normalization, one place.** `'None'`/`'Undetermined'`/`''` are placeholders several
  collectors emit for an unknown parent or root (`ldap_sites` emits the literal `'Undetermined'`,
  ps1-parity). `_norm_site_code` (formerly `_norm_parent`, generalized once it needed to normalize
  `root_site_code` too) centralizes the sentinel list and casts to `VARCHAR` before `upper()` — without
  the cast, an all-NULL column for a run with no non-NULL value can be inferred as `INTEGER` by DuckDB,
  and a bare `upper()` on it raises a `BinderException` that `_safe` silently swallows as a dropped arm.
  This exact failure mode recurred **four times** across this plan's review cycles (site_hierarchy's own
  arms, `_node_computer`'s new arms, `_assumed_site_dbs`, and `_read_disable_possible`) — see
  [§10](#10-dlt-loads-whatever-the-data-contains-our-sql-expects-fixed-columns) for the general pattern; a
  second, distinct failure mode in the same family is dlt **dropping** an all-NULL column outright rather
  than typing it wrong, which only `_ensure_columns` (not the `CAST`) protects against — every hierarchy-
  shaped arm's source table is now run through `_ensure_columns` before being read.

**Root resolution, strongest evidence first.** Three steps, tried in order, each only consulted if the
previous one found nothing:

- **Step A — the directly observed root.** `ldap_management_points_raw.root_site_code` is the site the MP
  capabilities XML itself names as root (D4) — read straight off the wire, not derived, so it applies in
  **both** flag modes. Multiple distinct values mean a multi-hierarchy environment; picked deterministically
  (`min`) with a WARNING naming all of them.
- **Step B — CAS, else parentless Primary.** The pre-existing `site_type = 4` / parentless `site_type = 2`
  query, also observed (not guessed), also both modes.
- **Step C — the guess, gated.** Only when A and B found nothing: among the remaining
  parentless/untyped-or-Primary candidates (a Secondary is **excluded outright** — it reports to something
  above it by definition, so it can never be a root), a **single** candidate is deduction (there is only
  one possible answer) and resolves in both modes; **two or more** candidates means picking one is a real
  assumption, so `--disable-possible-edges` declines and leaves `root_site_code` NULL (WARNING, naming the
  candidates and that SCCM-native ids will be minted without their `@<root>` scope), while default mode
  picks alphabetically (WARNING, naming the pick and the alternatives).

**Site-type inference for the CAS and Secondary sites.** Because a CAS has no management point, LDAP MP
capabilities — the *only* low-priv source of `site_type` — can never observe a CAS's type directly: a
live low-priv run produced `ldap_management_points_raw = [('PS1','Primary Site','CAS','CAS')]` and nothing
for `CAS` itself, which silently cost every `SCCM_AdminsReplicatedTo` edge (`_edge_replication` joins on
`site_type = 2 AND site_type = 4`). Two deduction rules (not guesses — they fire unconditionally in both
flag modes, and only when the type is currently unknown) close this: a site is inferred CAS-typed if it is
the recorded parent of a site already typed Primary; a site is inferred Secondary-typed if its recorded
parent is already typed Primary. The blind spot this leaves: a Secondary whose parent was never recorded
in this run (a `SEC`-style site with no parent observed) has no parent to key either rule off, so it stays
untyped and outside `SCCM_AdminsReplicatedTo`'s Primary↔Secondary edge — documented in the README
Limitations, not silently misclassified.

#### D6: site-code attribution is per-host and never guessed, plus its one sanctioned exception

A host may only be tagged `<Role>@<site>` from a source that actually knows *that host's* site — never
backfilled from "the only site in the hierarchy" or a similar heuristic. Three previously-orphaned role
signals (collected, registered in the preprocess table map, loaded into DuckDB, and then read by nothing)
are now wired into `_node_computer`, each honoring D6 differently:

- **`http_site_servers` (the site-signing-certificate probe) — the one sanctioned cross-host exception.**
  The probe reads an MP endpoint (`/SMS_MP/.sms_aut?sitesigncert`) *before* MPKEYINFORMATION has set
  `self.site_code` (ps1:8611 ordering, which this plan does not reorder), so the row's own site code is
  usually `NULL`. But a valid cert response proves the probed host is an MP, and the cert's issuer is by
  definition the site server of *that MP's* site — so the collector stamps the probed MP's hostname
  (`mp_host`, mirroring `http_site_versions.mp_host`) and the transform **joins** it to that MP's
  `http_management_points` row for the site code. The join (rather than a coalesced default) keeps the
  inference visible in the raw data. Guarded against a subtle trap found in review: `http_management_points`
  can legitimately hold two rows for the same host with *different* site codes (`collectors/http.py`'s
  MPLIST1 enumeration stamps the *probing* MP's own site code onto every sibling it enumerates), so the
  join only trusts a site code when `count(DISTINCT site_code) = 1` for that host — otherwise the role
  falls back to bare with a WARNING naming the competing codes, never a coin flip.
- **`ldap_management_points_raw.fsp_hostname`/`fsp_sid` (the Fallback Status Point)** — the FSP's SID was
  already resolved in the collector (`fsp_sid = fsp_target.ad_object.get("object_sid")`) but only used to
  build a log-message suffix; hoisted into the yielded row. The site code here is the naming MP's own,
  which the collector already attributes directly to the FSP it names — not a cross-host guess.
- **`dns_management_points` (SRV-discovered MPs)** — the SRV query key (`_mssms_mp_<site>._tcp.<domain>`)
  **is** the site code, authoritative by construction; the collector now emits it plus the role string
  directly instead of a bare AD object.

All three are **confirmed** (observed evidence), not assumed, so they land in `node_computer` in **both**
flag modes with no `assumed` stamp — this is a data-completeness fix, not a new inference. A fourth
signal, `smb_sites`, was folded into the D5 bare-code loop above rather than needing its own
`_node_computer` arm (it only ever fed `site_hierarchy`, never a role).

#### The assumption/provenance engine (D2, D3)

Every assumed node/edge in this plan shares one stamp — `assumed: bool`, `assumptionBasis: str`, and an
`Assumed-<Family>` tag folded into `collectionSource` — added as three new columns on `graph_edges`
(alongside `sccm_infra`) and as fields on the six `*Properties` dataclasses for the MSSQL scaffolding
nodes (`graph.py`). Two constructors produce it:

- **`_mark_assumed(props, basis)`** — a Python-side helper for any row built outside raw SQL; mutates a
  property dict in place and de-duplicates the `Assumed-*` tag so re-stamping an already-stamped dict is
  idempotent.
- **`_site_db_provenance_cols(is_assumed_sql)`** — the SQL-side equivalent, used by every MSSQL
  scaffolding-node builder. Takes a boolean SQL predicate ("this row rests on the `SPN+SCCM` inference")
  and returns the `assumed, assumption_basis, collection_source` column trio as one SQL fragment, so every
  builder that templates a piece of the MSSQL default schema stays byte-for-byte consistent in its
  provenance wording. Confirmed rows get `collection_source = ['SCCM-SiteDBDefaultSchema']` (replacing the
  old unconditional `'SCCM_Add-MSSQLServerNodesAndEdges'`/`'SCCM_Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer'`
  literals for these specific rows) — the schema SCCM requires there is still templated, not read out of
  SQL, so the source tag documents that, but it is no longer a guess once the site DB is confirmed.

**`_assumed_site_dbs` — the single gate.** A new preproc table, `{schema}.assumed_site_dbs(host_sid,
site_code, basis)`, identifies which hosts get treated as *the* SCCM site database (D2), from two
independent signals:

- **`basis = 'RemoteRegistry'`** — `node_computer.site_system_roles` already carries a merged
  `'SMS SQL Server@<site>'` tag, however it was collected (RemoteRegistry, AdminService, or WMI all feed
  the same array). Confirmed, both flag modes — **except where that tag is itself an inference**, see
  the corroboration gate immediately below.

  **The corroboration gate (con-be15, 2026-07-31).** Treating the *mere presence* of an
  `'SMS SQL Server@<site>'` tag as confirmation was wrong, because one producer of that tag is a guess.
  `collect_registry` reads `…\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers`; when the key is
  **present but empty** it concludes "the site database is local to this site server" and emits both
  `SMS SQL Server@<site>` and `SMS Site Server@<site>`. That holds for a standalone primary site server
  and is false for a **passive** site server, which has the same empty key while the database lives
  elsewhere. In the mayyhem lab this invented an `MSSQL_Server` for `ps1-psv` (which runs no SQL) and
  inflated every dependent MSSQL count — `HasLogin`/`IsMappedTo`/`MemberOf` 6 instead of 4,
  `ExecuteOnHost`/`HostFor` 5 instead of 3.

  The collector now flags those rows `sql_role_assumed = true` rather than suppressing them — it cannot
  settle the question locally, so it labels and defers. `_assumed_site_dbs` drops such a host only when
  **all three** hold: the role is flagged assumed, no *unflagged* source also claims it, and nothing
  answered on 1433 (`mssql_server_instances.port_open`). The populated-key branch names genuine remote
  database servers and is never flagged, so `ps1-db`/`cas-db` cannot regress.

  **Why 1433 and not the obvious alternatives.** The SQL Server registry keys are admin-gated
  (`rpc_s_access_denied` on all eight `SuperSocketNetLib` paths for a plain domain user), so they cannot
  gate the low-privilege path — the tier that matters most. An `MSSQLSvc` SPN does not discriminate
  either: SPNs live on the *service account*, not the host, and mayyhem's genuine `SEC` site database
  runs as `LocalSystem` with no SPN at all, so an SPN gate would delete a true finding. Only a live 1433
  answer separates `ps1-sec` (real) from `ps1-psv` (not). Since `PER_HOST_PHASES` runs RemoteRegistry
  *before* MSSQL, that answer does not exist at collection time — which is precisely why the decision
  belongs here in preproc, where every source has landed.

  Separately, the registry collector now reads the engine's service control entry
  (`HKLM\SYSTEM\CurrentControlSet\Services\{MSSQLSERVER|MSSQL$<instance>}`) for `Start` and `ObjectName`,
  surfaced as `SQLServiceStartType` and `SQLServiceAccountName`. Read from the registry rather than a port
  probe so a firewall cannot hide a healthy instance. `Start` is the **startup type**, not live running
  state — only the SCM knows that — so `Disabled` is the one value that proves the engine is down.
- **`basis = 'SPN+SCCM'`** — a host with an AD-readable `MSSQLSvc` SPN (`mssql_server_instances.has_mssql_spn`,
  Task 1c) that is *also* SCCM-related (carries some SMS role, or `sccm_infra`). A co-located SQL host need
  not be *the* site database, so this is a deliberate tightening of CMBP's "any host reachable on 1433"
  rule — an inference, not a confirmation.

`--disable-possible-edges` drops the `SPN+SCCM` rows here, **once**, at the source — every downstream
consumer (starting with `_mssql_sql_servers`, then the six MSSQL scaffolding node builders, then
`_edge_mssql_structural`/`_edge_mssql_membership`) inherits the filter with no builder repeating the check.
Site-code attribution follows D6 here too: a host whose `'SMS SQL Server@%'`-role or SPN-relatedness spans
more than one distinct site is dropped (WARNING, naming the host and the competing codes) rather than
picking arbitrarily. Nothing confirmed is lost by the flag: a `MSSQLSvc`-SPN host still gets its bare
`MSSQL_Server`/`Computer`/`HostFor`/`ExecuteOnHost` set (D2a, unconditional — see §11g) from the
independent EPA/SPN arm of `_node_mssql_server`; the flag removes only the *site-database
characterization* (`SCCMSite`, `SCCMInfra = true`, `CM_<site>`, and the scaffolding templated off it) that
the `SPN+SCCM` basis would otherwise add. A confirmed site database (`RemoteRegistry` basis, or
AdminService/WMI) keeps its **full** scaffolding in **both** flag modes with **no** `assumed` stamp — the
schema SCCM requires there follows from the confirmed fact, not a guess.

**Ruling: the code was right, the design spec was wrong (2026-07-28).** The design spec originally claimed
`--disable-possible-edges` tightens `SCCM_AssignAllPermissions`, `SCCM_LocalAdminRequired`, and the two
non-MSSQL `CoerceAndRelay*` edges (`SCCM_CoerceAndRelayToAdminService`, `SCCM_CoerceAndRelayToSMB`) to
require an explicitly confirmed `Off`/grant. Auditing the actual builders found none of the four ever
read the flag — `_edge_assign_all_permissions` and `_edge_local_admin_required` never took a
`disable_possible_edges` parameter at all, and `_edge_coerce_relay_adminservice`/`_edge_coerce_relay_smb`
used to accept one and never read it (dead parameters, removed). The owner ruled the **code**, not the
spec, was correct, for three reasons: (1) each of these four builders' gates are **measured evidence about
a Windows/protocol default**, not a topology guess — an unset `RestrictReceivingNtlmTraffic` genuinely
**is** vulnerable (Windows default 0 = allow all inbound NTLM), and `SCCM_CoerceAndRelayToSMB`'s SMB-signing
requirement was always a confirmed `false`, never assumed; (2) a live CMBP-vs-OpenHound comparison run
under `--disable-possible-edges` showed CMBP itself emits these same four families under its own
`-DisablePossibleEdges` switch, so gating them here would make OpenHound *stricter* than the tool it ports;
(3) `edge_coerce_relay_smb_test.py::test_smb_relay_flag_keeps_null_ntlm` predates this plan and already
pinned the opposite (flag-independent) behavior deliberately. All four families still carry the
unconditional `assumed = true` stamp (D3) — they template a permission/relay conclusion from role topology
rather than reading it from an ACL, which is worth flagging to an operator even though the flag never
removes them — but the stamp itself is unconditional, not flag-gated. (§11h below, written before this
ruling, is corrected accordingly.)

**The one MSSQL relay edge with a genuinely conditional stamp.** `MSSQL_CoerceAndRelayToMSSQL` is
different from its three siblings above in two ways: its **NTLM** gate follows the same
Windows-default-vulnerable reasoning (flag-independent, both modes), but its **Extended Protection** gate
is a real, flag-gated assumption (default: null/uncollected EPA treated as vulnerable; flag: EPA must be
explicitly `Off`) — and its `assumed`/`assumptionBasis` stamp is therefore a **per-row `CASE`**
(`s.extended_protection IS NULL`), not the unconditional literal `true` its siblings use. A row where EPA
was actually measured `Off` is evidence, not an assumption, and correctly carries no stamp even in default
mode; marking the whole family assumed would have libeled those measured rows, and marking none of it
would have hidden the genuine inference for the rows where EPA was never measured at all.

**`--clean` (a small, separately user-requested addition during this pass).** `collect` now accepts
`--clean`, which removes the reusable output artifacts (`sccm/`, `graph/`, `lookup.duckdb`) before
collecting; it always keeps timestamped per-run logs and integration/compare reports. Without it, `dlt`
appends a new load package beside any already present and `preprocess` UNIONs every package's rows into
one graph — invisibly, since the exit code and `graph/`'s file timestamps look identical either way, and a
table the new run finds empty simply keeps the old run's rows. `_clean_previous_collection` (`main.py`)
runs deliberately **outside** the collection's own try/except, so a locked artifact (e.g. `lookup.duckdb`
open in another tool) aborts the run rather than silently collecting onto stale data; without the flag it
still warns (naming the prior load-package count and the oldest package's date) instead of staying silent.
See the README's [`--clean`](README.md#--clean-and-re-running-into-a-used-output-directory) section.

**Known gap, surfaced not fixed.** `_edge_mssql_db_assign_all` (the `SCCM_AssignAllPermissions`
Database→Site configuration, §11g) was not brought into this provenance system — it still emits only the
literal `collection_source = ['SCCM_Add-MSSQLServerNodesAndEdges']` with no `assumed`/`assumption_basis`
columns, even when built from an `SPN+SCCM`-inferred `node_mssql_database` row that itself carries the
stamp. Every other MSSQL scaffolding edge builder (`_edge_mssql_structural`, `_edge_mssql_membership`)
does propagate the stamp from the node it attaches to; this one edge shape is the one place that doesn't.
Documented as a known gap in the README rather than silently glossed over.

---

### 11m. AD node names are SharpHound's, or absent (new divergence category)

*This is a new category of divergence from a stock OpenHound collector.*

#### The framework baseline

A stock collector owns every node it emits. `NodeProperties.name` is a required field, and the natural implementation is "use whatever the upstream API called this thing, falling back to its id" — nobody else is writing to that node, so any name is better than none.

#### Why it breaks for SCCM

This collector's `Computer` / `User` / `Group` / `Container` nodes are not its own. They are Active Directory objects keyed by the same ids SharpHound uses — SIDs for principals, `objectGUID` for the container — and §11f emits them **untagged** on purpose, so BloodHound merges them into its native AD graph rather than shadowing it.

Merging by id means the collector is writing into a node that may already exist and already be correct. Every property it emits **overwrites** SharpHound's. The framework's natural fallback behaviour is therefore actively harmful here: naming a node after its own SID, its bare short name, or its DN replaces a correct SharpHound label with a worse one, and the operator sees a graph that got worse after ingesting SCCM data. The reported symptom was four groups on the System Management container attack path — Domain Admins, Enterprise Admins, IT Helpdesk, Workstation Admins — rendering as bare SIDs.

Two independent defects fed it:

- **`node_group` had no LDAP arm.** All six of its sources (four `SecurityGroupName` arms off AdminService/WMI `R_System`/`R_User`, plus the two SCCM admins tables) require SCCM privilege. An unprivileged collect produced exactly **one** `node_group` row, so every group fell through to `_node_backfill` and shipped as a SID-named stub. The names were never missing — the System Management container ACL walk had LDAP-resolved those exact groups, and `ad_props` held their `sam_account_name`, `cn` and `distinguished_name` the whole time. The existing `ad_props` join could not reach them because a `LEFT JOIN` only enriches rows that already exist.
- **Names were shipped in the wrong format even when known.** A privileged collect named groups `mayyhem\Domain Admins` (SCCM's `SecurityGroupName` verbatim), computers `PS1-MP`, users `domainuser`, and the container by its full DN. None of those is SharpHound's form; all four overwrite it.

#### The add-on: `_stamp_sharphound_name` + `ad_props` arms + `domain_fqdn_by_sid`

- **`ad_props` arms on `_node_group` and `_node_user`.** Any LDAP-resolved principal becomes a real, named node rather than a stub. This also restores CMBP behaviour the port had dropped: `Upsert-Node` was handed the whole resolved domain object (`-PSObject $thisGroupDomainObject`), and Group was the one node kind with no equivalent spread. The user arm must exclude computers — AD's `objectClass` chain for a machine account is `(top, person, organizationalPerson, user, computer)`, so a naive "is it a user" test claims every computer in the domain (caught by replay: `node_user` jumped 5 → 18).
- **`_domain_fqdn_by_sid`** maps a domain SID to its uppercase FQDN, derived from `ad_props`. This inverts the idiom the node builders already use for `environmentid` — a co-occurring principal supplying domain context a SID lacks — to recover the *FQDN* that a SharpHound name needs. It exists for principals discovered from a non-LDAP direction: the SCCM site database's SQL service account arrives via `mssql_server_instances` with a bare account name and a SID and is never passed through `resolve_principal`, so it has no `ad_props` row, but its SID shares the domain prefix of every principal that does.
- **`_stamp_sharphound_name`** adds a `sharphound_name` column to each AD node table, and the models emit that or nothing. Formats, all uppercase: `SAMACCOUNTNAME@DOMAIN.FQDN` (user, group), `HOSTNAME.DOMAIN.FQDN` (computer), `NAME@DOMAIN.FQDN` (container). The FQDN resolves in decreasing order of directness — the row's own `domain` column (guarded on containing a dot, so a NetBIOS name can never pass as an FQDN), then the DN's `DC=` components, then the `domain_fqdn_by_sid` map. A name already in SharpHound form passes through unchanged, which is what keeps the synthetic Authenticated Users node (§11h) intact, since its well-known SID has no domain part to rebuild from.

**When the form cannot be built, the name is omitted entirely** — `sharphound_name` stays NULL, the model passes None, and `_normalize_properties` prunes it on emit. BloodHound then displays the object id, and any SharpHound-collected label survives untouched. The same rule governs `StubNode` (§11e). The principle: *never assert a label we cannot put in SharpHound's form*, because on a merged graph a wrong name is worse than no name.

#### Divergence from CMBP parity

CMBP names these nodes `$domainObject.samAccountName` — bare, unqualified. This collector deliberately does not, and this is the first place the port diverges from CMBP on a *property value* rather than on structure. The reason is that CMBP and this collector do not have the same relationship to the graph: CMBP's output was read on its own, whereas this collector's AD payload is explicitly designed to merge with SharpHound's. Parity with CMBP would mean degrading the merged graph, so SharpHound's convention wins.

#### Trade-offs

- A standalone graph with no SharpHound data will show object ids for any principal whose domain FQDN could not be resolved, where the old code showed *something*. Accepted: an id is honest about what is unknown; a fabricated name is a claim that overwrites better data.
- `ad_props` is now load-bearing for names as well as attributes. If `ldap_resolved_principals` fails to persist (a best-effort final `pipeline.run`, never observed across 12 recorded runs), `ad_props` builds empty and the whole AD payload ships unnamed. `_derive_ad_props` and `_domain_fqdn_by_sid` each warn when they build empty, so the degradation is visible in the preproc log rather than silent — previously there was a warning at the emission site but none at the consumption site.
- Any future AD node kind must be stamped too, or it ships unnamed. Guarded by `sharphound_naming_test.py`.

---

## 12. One-command end-to-end: a `--run-all` flag, not a new verb

### The framework baseline

OpenHound models the pipeline as three separate top-level CLI verbs — `collect`,
`preprocess`, `convert` — each a Typer group created as a module-level singleton
and mounted on the root app with `add_typer` (`openhound/main.py`). There is no
"run everything" verb, and no hook for an extension to add its own top-level verb.
The reason is import order: an extension's module is imported *inside* the root
app's constructor — `TyperOverride.__init__` calls
`CollectorManager.from_entrypoint("openhound.sources")` (`openhound/cli/override.py`),
which loads every extension *before* `main.py` binds the root `app` or mounts the
verb groups onto it. So when an extension runs it can import and hang commands off
the pre-existing verb *groups* (that is how it registers `collect sccm`), but it
never receives a reference to the root app instance and there is no registry to
attach a new verb to.

### Why it breaks for SCCM

Operators expect to point the tool at an environment and get a graph — one
command, not three, and without hand-deriving the intermediate `lookup.duckdb` /
dataset-dir / `graph` paths each time. But the natural shape (`openhound run
sccm`) is exactly the thing the framework can't express without a core edit.

### The add-on: a flag on `collect`, backed by a shared orchestrator

- **CLI surface:** a `--run-all` flag on the already-hand-registered `collect sccm`
  command ([`collect_sccm`](src/openhound_sccm/main.py)), so no new verb and no
  core edit. When set, `collect_sccm` runs collection as usual, then calls
  [`_run_e2e_after_collect`](src/openhound_sccm/main.py) once the collect log
  handlers are torn down, so the two follow-on stages log through the normal
  console handlers.
- **The chaining itself is shared.** The actual "preproc then convert" logic lives
  in `openhound_collector_common.orchestration.run_end_to_end` (see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)),
  which invokes the app's registered `preprocessor` / `converter` hooks
  **in-process** and derives every path from the single collect `OUTPUT_PATH`.
  It is framework-agnostic (duck-types the app; no `openhound`/`dlt` import), so
  the MSSQL collector can adopt the same flag by calling it.
- **The graph output is also bundled into a zip.** After convert finishes, `run_end_to_end` calls the
  shared `openhound_collector_common.orchestration.zip_graph_output`, which flat-bundles every
  `*.json` in the graph directory into `graph/<archive_name>` (the loose `.json` files are kept, not
  replaced). The `--run-all` path (`_run_e2e_after_collect`) passes
  `configmanbearpig_collection_<ts>.zip` — the same `_ts` used for `collect_full_<ts>.log` — as
  `run_end_to_end(..., graph_zip_name=...)`; the shared default when no name is given is
  `<app.name>_collection.zip`. This zip step requires `openhound-collector-common` **>=0.1.1**
  (the release that adds `graph_zip_name`/`zip_graph_output`) — against an installed `0.1.0` it is
  inactive/would error, which is why the dependency floor bump is paired with the library's v0.1.1
  release.
- **Progress plumbing quirk:** the framework stages read progress inconsistently
  (`Converter` uses `progress.value`; `PreProcessor` forwards the object straight
  to `dlt.pipeline()`), so the orchestrator's contract is `Progress | None` and it
  applies a `.value=None` shim on the convert side for the silent case.
- **Consolidated output summary:** because the three phases each write their own
  artifacts (collect: raw JSONL + the ordered/diagnostics logs; preproc:
  `lookup.duckdb`; convert: the `graph/*.json` files) and interleave their logs,
  `_run_e2e_after_collect` returns the `StagePaths` and `collect_sccm` calls
  [`_log_all_output_locations`](src/openhound_sccm/main.py) as the very last step —
  re-surfacing every file location in one block. It runs *after* collect's
  finally-block tears down the ordered/diagnostics file handlers, so the summary
  points back at those files by path rather than duplicating their content.
  The block **closes with the zip path**, because of everything listed it is the only
  artifact the operator does something *with* (upload to File Ingest) rather than
  merely knows the location of — so it is where their eye lands last. The archive
  name is chosen once in `collect_sccm` and passed to both `_run_e2e_after_collect`
  (which writes it) and `_log_all_output_locations` (which reports it), so the two
  cannot drift. It is passed rather than read back off `StagePaths` because
  `run_end_to_end` discards `zip_graph_output`'s return value and `StagePaths` carries
  no zip field. Adding one to the shared library would let the collector report the
  archive the chain actually wrote instead of reconstructing where it should be — a
  small improvement to `openhound-collector-common`, not a change this repo can make.

### Trade-offs

- `--run-all` runs all three stages in **one process**, an execution mode the
  manual three-command workflow never exercises. Collect's process-global state
  (the planted `StreamBridge`, the bumped `EXTRACT__WORKERS`) is cleaned up in its
  `finally` before the chain starts, so the follow-on stages start clean.
- It is a *flag*, not the `openhound run sccm` verb an operator might expect —
  the price of not editing core.
- On failure the chain stops and re-raises, leaving raw data intact and logging
  the manual resume commands (stop-on-first-failure).

---

## 13. Tunneling all collection traffic through a SOCKS5 pivot

### The framework baseline

A stock OpenHound collector authenticates a single HTTPS endpoint from wherever
the process happens to run — a cloud REST API is reachable from anywhere with
an internet connection. The framework has no notion of routing traffic through
an intermediary; there is nothing to configure because there is nothing to
route around.

### Why it breaks for SCCM

This collector's whole reason for existing is on-prem, and on-prem engagements
are routinely run from **outside** the target network, through a single
foothold. Unlike a REST collector's one endpoint, SCCM collection is discovery
(LDAP/DNS/DC) plus **five** per-host wire protocols (RemoteRegistry, MSSQL,
AdminService, WMI, HTTP, SMB) across four different client libraries
(`ldap3`, `impacket`, `requests`, plus the collector's own raw-socket probes).
For a pivoted engagement to be usable at all, every one of those has to egress
through the same SOCKS5 hop — a single "proxy this one HTTP client" option
would leave four other protocols leaking traffic straight from the outside box.

### The add-on: a process-wide `socket` interception, installed for the run

- **Implementation** (`openhound_collector_common.proxy`, `proxy/patch.py` +
  `proxy/socks.py`): three stdlib entry points are swapped for the duration of
  the run — `socket.socket` (subclassed as `_ProxiedSocket`, whose `connect`
  performs the SOCKS5 handshake to the destination), `socket.create_connection`
  (dials the proxy and hands it the destination **hostname**, never resolving
  locally), and `socket.getaddrinfo` (a pass-through that hands back the
  hostname unresolved, so callers that pre-resolve before connecting — e.g.
  `urllib3`/`requests` — still route the real name through `connect` instead of
  failing on an internal-only name). Loopback targets and the proxy's own
  endpoint are always bypassed (a recursion / local-traffic guard).
- **Scoped to the collect run only**, via the `socks_proxy_installed(proxy_cfg)`
  context manager (`main.py`), wrapping the entire discovery + per-host-phase
  window; a no-op pass-through when no proxy is configured, so the direct-mode
  code path is unchanged.
- **Destination names resolve at the proxy** (`socks5h` behavior) — the
  collector never needs to resolve an internal-only hostname itself for TCP
  traffic.
- **Our own DNS lookups are forced onto TCP** so they ride the same tunnel
  (SOCKS5 `CONNECT` cannot carry UDP): four proxy-aware call sites check
  `active_proxy()` and pass `force_tcp=True` into the shared
  `discovery.dns.make_resolver` — `main.py::_resolve_dc_via_dns`, two sites in
  [`collectors/dns.py`](src/openhound_sccm/collectors/dns.py)
  (`dns_management_points`'s SRV lookups and the `_resolve_v4`/`_resolve_v4_via_dns`
  pair), and `context.py::resolve_ip`.
- **SCCM's own footprint is thin**: the CLI parse/validate
  (`_parse_proxy_or_exit`, `_require_dc_or_dns_for_proxy` — the latter exits(2)
  when `--proxy` is set without `--dc`/`--dns`, since internal names can't
  be resolved from the outside box), the install-around-run wrap, and the four
  DNS call sites above. The interception itself carries no SCCM-specific logic,
  so it was built directly in the shared library (see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library))
  so the MSSQL collector can adopt it without re-deriving it.

### Trade-offs

- **Native OS authentication cannot be tunneled — a hard, documented limit, not
  a bug.** Live current-user SSPI Negotiate and OS-Kerberos make their
  KDC/DCOM calls inside the OS itself (LSASS for Kerberos; `win32com` for the
  WMI SSPI rung — see [§6](#6-windows-authentication-across-five-protocols)) —
  traffic this process never touches, so no userland socket hook can carry it.
  To use a logged-in identity through the pivot, export its Kerberos ticket and
  pass `--ticket` (pass-the-ticket runs in-process through impacket, so it
  tunnels completely), or set up OS-level transparent proxying (tun2socks /
  Proxifier) on the outside box. Everything else in-process — explicit
  credentials, pass-the-hash, pass-the-ticket, and impacket-minted Kerberos +
  NTLM including the KDC exchange — tunnels fully.
- **No UDP.** SOCKS5 `CONNECT` is TCP-only; DNS is the only UDP-shaped traffic
  this collector produces, and it is forced onto TCP for exactly this reason.
- **Install-once-per-process, not reentrant.** `install()` raises if a proxy is
  already active — consistent with the existing assumption that `collect` runs
  once per process, but it means the interception cannot be nested or shared
  across concurrent runs in the same interpreter.
- **The `getaddrinfo` pass-through is aggressive** — it returns an unresolved
  hostname for anything that isn't loopback/bypassed rather than attempting
  resolution and falling back. Validated offline against `ldap3`, `requests`,
  and `impacket` (see [`spike_socks_proxy.md`](dev/spike_socks_proxy.md) — all three
  funnel through the patched stdlib entry points with no bypass found); a
  live-lab run against a real SOCKS5 pivot is the remaining confirmation.

---

## 14. A shared integration-test and payload-diff engine, invoked off `--run-all`

### The framework baseline

A stock OpenHound collector's correctness is checked with ordinary unit tests against mocked HTTP
responses — the framework has no notion of asserting the *shape and content of a collected OpenGraph
payload* against a set of expected nodes/edges, and no comparator for diffing one collected payload
against another. A small, stable cloud REST API doesn't usually need either.

### Why it breaks for SCCM

This collector's correctness has always been checked against ConfigManBearPig by hand: re-run the
PowerShell predecessor's own test kit (`powershell_deprecated/Invoke-ConfigManBearPigUnitTests.ps1`),
which asserted specific nodes/edges existed with position-based, `$expectedEdges_*`-hardcoded checks and a
dead coverage report (`Get-MissingTests`); or run the standalone `compare_results.py`, which aligns two
BloodHound zips by **list index**, not by identity. Neither is reachable from the collector's own CLI, so
"collect, then immediately assert the graph is right" or "collect, then diff it against yesterday's run"
took a separate, manual step outside `openhound collect sccm`.

### The add-on: a shared assert/diff engine, two `collect` flags

- **The engine is collector-agnostic** and lives in `openhound_collector_common/integration_testing/`
  (no third-party deps — stdlib `json`/`zipfile`/`fnmatch` only):
  - `graph.py` — `Graph`/`Node`/`Edge` + `load_graph`, accepting either a directory of `*.json` OpenGraph
    payloads or a `.zip` of them; a duplicate node id across payloads (e.g. `sccm_*` + `ad_*`) merges by
    unioning `kinds` and filling in missing properties rather than overwriting.
  - `cases.py` — typed `EdgeCase`/`NodeCase` fixtures, each with a stable `id`, an optional `CountSpec`
    (`exact` / `at_least` / `at_most`, combinable into a range) and a `negative` flag for "this must NOT
    exist".
  - `matcher.py` — `property_match` / `node_matches` / `edge_matches`, a direct port of the PowerShell
    kit's `Test-PropertyMatch` / `Test-NodePattern` / `Test-EdgePattern`: case-insensitive matching,
    `*`/`?` wildcards via `fnmatch`, list-subset semantics, tolerant `"True"/"1"`/`"False"/"0"` bool
    coercion.
  - `runner.py` — `run_suite` runs every edge/node case plus an optional list of whole-graph **invariant**
    callables (`Callable[[Graph], Result]`) — a hook for cross-node checks that don't reduce to a single
    case (the PS kit's one hardcoded `memberOf` root-site check generalizes to this hook). Prints the same
    `<kind>: <description> - PASS/FAIL/SKIP` line shape as the PS kit, plus totals and a coverage report.
  - `results.py` — `Result`/`Summary` + `write_results_json`.
  - `compare.py` — `compare_graphs(baseline, candidate)` builds a `ComparisonReport`: nodes/edges only in
    the baseline vs. only in the candidate, a per-node/per-edge property diff (`only_in_baseline` /
    `only_in_candidate` / `changed`), and a **by-kind property rollup** (which property names appear on a
    given kind on one side but not the other) — fixing `compare_results.py`'s index-based fragility with
    identity-keyed comparison. **Baseline is what came first**; the parameters and report keys are named
    rather than lettered because v0.1.2 flipped the argument order, and a flipped meaning under an
    unchanged name produces reports that are silently backwards. `regressions()` classifies the
    baseline-has/candidate-lacks direction into six kinds of loss — missing node, missing edge, lost
    property, property emptied to `null`/`""`/`[]`/`{}`, list-valued property that lost items, and a
    property name that no longer appears on a kind at all — and `has_regressions` drives the exit code.
    Additions and ordinary value changes are reported under `ADDED` and never fail a run.
  - `cli.py` — the `openhound-compare` console script (`argparse`, stdlib only), diffing any two payloads
    with no collection involved. It exists as a console script rather than an `openhound compare`
    subcommand because `openhound/main.py` builds its root Typer app inside `TyperOverride.__init__`,
    which loads extensions via entry points *before* the app name is bound — so an extension cannot
    register a new verb without editing framework core.
  - `coverage.py` — `load_schema_kinds` / `coverage` / `report` diff a schema JSON's `node_kinds` /
    `relationship_kinds` against the fixture-covered kinds, replacing the PS kit's dead `Get-MissingTests`.
- **SCCM's fixtures + wiring are extension-local**, in `openhound_sccm/integration/` — none of the
  mayyhem.com-specific knowledge is shared:
  - `fixtures/edges.py` — 61 `EdgeCase` fixtures ported from the PS kit, retargeted at the new `SCCM_`/
    `MSSQL_`-prefixed edge kind names (and the CMBP `CoerceAndRelaytoSMB` typo dropped).
  - `fixtures/nodes.py` — `NodeCase` count fixtures per node kind, plus two whole-graph invariants:
    AdminUser/SecurityRole/Collection node ids are canonicalized to the hierarchy root site code, and
    every `SCCM_ClientDevice` belongs to a primary site (guards the ope-e739 regression).
  - `__init__.py` — `run_integration_tests(graph_dir, ..., privileged=)` (loads the graph, runs the
    fixtures against it plus a `schema_SCCM.json` coverage report, returns `1` if any case failed) and
    `compare_to_zip(graph_dir, zip_path, ...)`, which passes the **saved payload as the baseline** and this
    run's graph as the candidate, and returns `1` on any regression.
- **Three `collect sccm` flags, in a "Testing" help panel** (`main.py`). The two that need a graph force
  `run_all = True` before the pipeline starts, since there is nothing to test or diff without a completed
  convert:
  - `--run-integration-tests` calls `run_integration_tests` once convert finishes, writing
    `integration_results-<ts>.json`.
  - `--integration-privilege auto|high|low` selects which fixture set is asserted. It describes the
    **collection**, not the fixtures. `auto` — the default — derives the verdict from whether any
    `adminservice_*` / `wmi_*` table returned rows this run (`_detect_privileged`, prefix-matched so the
    `local_wmi_*` discovery tables, which any domain user can read on the collector host, are not counted
    as privileged evidence). Deriving it from the **collection input** rather than from graph content is
    deliberate: a privileged run whose builder is broken emits nothing, would read as low-privilege, and
    would then skip exactly the cases that would have caught it. Supersedes the boolean
    `--integration-lowpriv` (con-6677), of which it is a strict superset.
  - `--compare-to-zip <path>` calls `compare_to_zip` against an arbitrary node/edge payload — a CMBP zip
    or another OpenHound run — writing `compare-<ts>.json`.
  - **Exit code.** Both testing flags run to completion before either decides the result, so an operator
    who passed both always gets both reports; `_combined_testing_exit_code` then returns non-zero if
    *either* failed. This replaces the earlier contract in which `--compare-to-zip` always exited `0`.
  - Both reuse `_ts`, the same run timestamp already used for the collect logs, so every artifact from one
    invocation shares a suffix.
- **No new framework extension point.** This reuses exactly the pattern [§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)
  established: a flag on the hand-registered `collect` command, running shared-library logic in-process
  after the app's own `preprocessor`/`converter` hooks have already produced the graph.

### Trade-offs

- **The engine is shared; the correctness knowledge is not.** `integration_testing/` knows nothing about
  SCCM, sites, or client devices, so adopting it for **MSSQL** means writing MSSQL's own `fixtures/` (its
  own `EdgeCase`/`NodeCase` list and invariants), not importing SCCM's. `openhound_collector_common.integration_testing`
  is available today for the MSSQL collector to wire the same two flags onto `collect mssql` against its
  own graph.
- **Supersedes, doesn't extend, the old validation flow.** The PowerShell test kit and `compare_results.py`
  are no longer the sanctioned way to check a collection — these in-process flags cover the same
  assert/diff ground without leaving the `collect` command and without requiring PowerShell.
- **`--compare-to-zip` is now a gate, and deliberately has no opt-out.** A regression exits non-zero on
  both surfaces. The consequence is accepted rather than worked around: a CMBP-vs-OpenHound parity diff
  **will** exit non-zero on a perfectly healthy run, because the two tools emit different sets — CMBP
  produced 160 nodes / 468 edges against OpenHound's 148 / 454 on the same lab, same day, and uses the
  pre-rename edge names. The exit code means "these differ", not "something broke", and the operator
  reads the report. Automatic same-tool detection was considered and rejected: CMBP payloads declare
  `"metadata": {"source_kind": "SCCM_Base"}` while none of OpenHound's four emitted files carry a metadata
  block at all, so there is no dependable marker, and a heuristic that guessed wrong would silently skip
  the gate on a real regression.
- **Comparison is no longer welded to collection.** `openhound-compare BASELINE CANDIDATE` diffs two saved
  payloads directly, which is what the before/after workflow actually needs; `dev/ab_matrix.py` drives it
  across an identity × possible-edges matrix, replacing the four per-desktop PowerShell drivers that used
  to live in the OpenHound monorepo.

---

## Changelog

| Date | Change |
|---|---|
| 2026-08-01 | **The registry arm could not see a named SQL Server instance, and the warning that said so was camouflaged by six false ones** (con-ab59). `get_mssql_settings` probed eight hard-coded `SuperSocketNetLib` paths, every one ending `.MSSQLSERVER` — so a *named* instance could never match. The lab's `ps1-sec` runs the SEC site database as `CONFIGMGRSEC` (SCCM's own site definition: `SQLDatabaseName 'CONFIGMGRSEC\CM_SEC'`, port 1433) and was missed **on a fully privileged run**: eight `not found`s, then "Could not access any MSSQL registry paths". That line was a true positive sitting among six identical ones from hosts with genuinely no SQL, which is why it read as noise — and is why the fix was not to quieten it. Paths are now **derived from SQL Server's own inventory** (`Instance Names\SQL`), whose value *data* is the instance's subkey (`MSSQL16.CONFIGMGRSEC`); the settings path is therefore exact, with no version prefix to guess and no default-instance assumption. Eight hard-coded strings collapse to one derivation plus a single pre-2000 fallback (`SOFTWARE\Microsoft\MSSQLServer\...`, which predates the inventory key and had only a default instance), and the duplicate second read of `Instance Names\SQL` further down the function goes with them — one read now serves both the candidate paths and the reported `instance_names`. Severity was moderate rather than urgent because the separate MSSQL phase covers a *reachable* instance (the same run logs `port 1433 is open` / `EPA testing … via SSPI`); the gap bit a firewalled instance, and `service_start_type` / `service_account_name`, which the live probe does not supply — note `_mssql_service_name` already handled `MSSQL$<name>` correctly and was simply unreachable behind the early return. The warning now fires only on the contradiction worth hearing: the inventory lists instances *and* none of their settings keys can be read. No inventory at all means no SQL Server, the normal case (seven of nine lab hosts, privileged), and logs at verbose. **A test fixture was complicit:** `_mssql_probe` seeded the inventory as `[(instance, instance)]`, putting the instance *name* where the registry stores the *subkey*, so `test_mssql_named_instance_uses_the_dollar_service_name` passed against code that could not reach a named instance — a fake mirroring the code's belief rather than the system's behaviour. Fixture corrected, 8 tests added. Suite 1025 passed / 5 skipped. |
| 2026-08-01 | **Added §11m — AD node names are SharpHound's, or absent; and §11e's backfill grew a start side** (Ope-15m7). Reported symptom: an unprivileged graph rendered the four groups on the System Management container attack path — Domain Admins, Enterprise Admins, IT Helpdesk, Workstation Admins — as bare SIDs. Root cause was **not** missing data. `_node_group`'s six arms all require SCCM privilege (four `SecurityGroupName` arms off AdminService/WMI `R_System`/`R_User`, plus the two admins tables), so an unprivileged collect built exactly **one** `node_group` row and every group fell through to `_node_backfill`, where `StubNode` set `name = displayname = self.id`. Meanwhile `sccm.ad_props` already held `sam_account_name`, `cn` and `distinguished_name` for all four — the System Management container ACL walk resolves them — but the existing `ad_props` join is a `LEFT JOIN` onto `node_group`, and a SID with no row gets nothing. Fixes: (1) **`ad_props` arms on `_node_group` and `_node_user`**, so any LDAP-resolved principal becomes a real named node; this restores CMBP's `Upsert-Node -PSObject $thisGroupDomainObject` spread, which the port had dropped for Group alone. The user arm must exclude computers — AD's machine-account `objectClass` chain is `(top, person, organizationalPerson, user, computer)` and so satisfies "user", which a replay caught as `node_user` jumping 5 → 18 rows. (2) **`_domain_fqdn_by_sid`**, a domain-SID → uppercase-FQDN map derived from `ad_props`, inverting the co-occurring-principal idiom the builders already use for `environmentid` in order to recover the FQDN a SharpHound name needs; it exists for principals found from a non-LDAP direction, the standing case being the site database's SQL service account, which enters via `mssql_server_instances` with a bare name and a SID and is never `resolve_principal`'d. (3) **`_stamp_sharphound_name`** stamps every AD node table with `SAMACCOUNTNAME@FQDN` (user/group), `HOSTNAME.FQDN` (computer) or `NAME@FQDN` (container), uppercase, resolving the FQDN from the row's `domain` (guarded on a dot so NetBIOS cannot pass), then the DN's `DC=` parts, then the map — passing through a name already in SharpHound form so the synthetic Authenticated Users node survives. **Where the form cannot be built the name is omitted entirely** rather than falling back to a bare name, a DN or a SID: these nodes ship untagged (§11f) and merge into the native AD graph by id, so anything emitted *overwrites* SharpHound's label, and a wrong name is worse than none. Same rule now applies to `StubNode`, which finally matches what §11e always specified it to be ("just `id`, `kinds` … and `environmentid`"). This is the first deliberate divergence from CMBP on a property *value*: CMBP emits a bare `samAccountName`, correct for a tool read on its own, wrong for a payload designed to merge. (4) **`BACKFILL_START_KIND`** — backfill covered only edge ends, but a dangling *start* makes BloodHound drop the whole edge rather than render it unnamed, which had silently removed five `MemberOf` edges and hidden the real membership of Domain Admins, Enterprise Admins and IT Helpdesk. (5) **An empty `ad_props` now warns at the consumption site**, not just at emission, so a run that ships an attribute-less graph says so. Verified by replaying `preprocess` + `convert` over both recorded lab datasets: unprivileged went from 4 SID-named nodes and 5 dangling endpoints to **0 and 0** (23 → 26 AD nodes, edge count unchanged at 148); privileged went from 35 `DOMAIN\`-prefixed names to **0**, nodes and edges unchanged at 150/454. Suite 1017 passed / 5 skipped; ruff + mypy clean. |
| 2026-08-01 | **`ERROR` was made to mean "something broke" again, and the `--run-all` summary now ends with the artifact you upload** (§7, §12; con-8a28). A low-privilege collect against the mayyhem lab logged **125 `ERROR`s and 9 `CRITICAL`s while working correctly** — the same collection as a local admin logged zero of either. Severity that high on a healthy run trains an operator to ignore it, which defeats the whole point of the logging layer, so each expected failure was classified instead of quieted wholesale. (1) **Refused registry reads.** All four `_RegistryProbe` read helpers were collapsed into one `_log_read_failure` that splits three ways — key/value absent → verbose, access denied → verbose **plus a tally**, anything else → error — replacing four near-identical `except DCERPCException` blocks (and fixing `read_value`, which reported string reads as "Failed to read DWORD value"). Each host then emits **one** WARNING naming the capabilities it lost and that local Administrators is required; ~120 ERRORs became 9 actionable lines with every per-key detail still in `collect_full_<ts>.log`. The summary hangs off the probe's `__exit__` rather than the end of `collect_registry`, because that function `return`s early exactly when the site code is unreadable — a summary at the function end would have skipped the hosts that most needed it. (2) **Denied is now distinguishable from absent.** The tally backs `was_denied()`, which fixes a genuinely misleading message: on five lab hosts `SMS\Triggers` is refused, and the phase reported "does not exist or no site code subkey found" — telling the operator the host is not a site server when the truth was a permissions gap, the opposite conclusion, with nothing in the message hinting at privilege. It now says access denied, and says that the host may still be a site system. Two now-redundant messages were folded in as well: `get_current_user`'s second ERROR for a failure `read_values` had already reported, and `get_mssql_settings`'s eight-line path dump when every candidate path was refused (kept when the paths are genuinely absent). (3) **impacket's one misleading CRITICAL.** `CCache file is not found. Skipping...` fires once per host whenever the WMI Kerberos rung runs without `--ticket`: impacket checks the Unix `KRB5CCNAME` variable, finds nothing on Windows, and then requests a fresh TGT with the supplied password and succeeds — only the *cache lookup* is skipped. `_ImpacketNoiseFilter` rewrites that record's `levelno` to DEBUG in place, matched on the message rather than by capping the `impacket` logger so any other impacket CRITICAL still reaches the operator, and `clients/wmi.py` logs its own verbose line in its place so the log explains itself instead of going silent. (4) **The `--run-all` summary closes with the zip.** `_log_all_output_locations` ended with the loose `graph/*.json` list and never named `graph/configmanbearpig_collection_<ts>.zip` at all — the one artifact an operator acts on, mentioned only in a `Bundled N graph file(s)` line logged back during convert. The archive name is now chosen once in `collect_sccm` and passed to both the chain that writes it and the summary that reports it, so they cannot drift; a missing archive is flagged rather than printed as a path to nothing. `run_end_to_end` discarding `zip_graph_output`'s return value, and `StagePaths` having no zip field, is the shared-library gap that forces the reconstruction. Suite 991 passed / 5 skipped; ruff + mypy clean. |
| 2026-08-01 | **Payload comparison became a gate, and the privilege level became something the run works out for itself** (§14). Three changes, all adopting `openhound-collector-common` **v0.1.2** (floor raised `>=0.1.1` → `>=0.1.2`, cap unchanged). (1) **Comparison orientation is now named, not lettered.** `compare_graphs(baseline, candidate)` replaced `(a, b)`, and every report key with it (`nodes_only_in_baseline` / `..._candidate`, `changed: {prop: {baseline, candidate}}`). The rename was the point: v0.1.2 flipped the argument order, and `compare_to_zip` had been passing this run's graph first and the saved zip second — so adopting the new library *without* swapping those two lines would have inverted every report silently, with no exception raised, because the collector only calls `render()` and `to_dict()` and never reads a key by name. Renaming turns that class of mistake into a `KeyError` for anything reading the old shape. The saved payload is now the baseline, which is also how the flag reads: the zip is what came first. (2) **A regression fails the run.** `regressions()` classifies six kinds of loss (missing node, missing edge, lost property, property emptied to `null`/`""`/`[]`/`{}`, list-valued property that lost items, property name gone from a kind); additions and ordinary value changes are reported under `ADDED` and exit `0`. Per-instance strictness with **no opt-out flag**, which means a CMBP parity diff now exits non-zero by design — accepted and documented, since the two tools emit different sets. `--compare-to-zip`'s always-exit-`0` contract is retired, and `_combined_testing_exit_code` reports the worse of the two testing flags after both have run, so neither report hides the other. The engine also gained a standalone entry point, `openhound-compare BASELINE CANDIDATE`, so the before/after workflow no longer requires a collection it does not need; `openhound compare` is *not* available as a framework subverb because extensions are imported inside the root Typer app's constructor, before its name is bound. (3) **`--integration-privilege auto\|high\|low` supersedes `--integration-lowpriv`** (con-6677, annotated rather than reopened — the three-way flag is a strict superset and still satisfies its acceptance criteria). `auto`, the default, reads the run's own `adminservice_*` / `wmi_*` row counts, prefix-matched so the `local_wmi_*` discovery tables any domain user can read are not miscounted as privileged evidence. The verdict is derived from the collection **input** rather than from graph content on purpose: inferring from the graph is circular, because a broken privileged builder emits nothing, reads as low-privilege, and skips the very cases that would catch it. This removes the "operator forgot the flag" failure mode and nothing else — con-c542's tagging audit is what closes the remaining low-privilege failures. Also ported the four per-desktop PowerShell drivers from the OpenHound monorepo into `dev/ab_matrix.py` (+ `dev/_ab_cmbp.py` for the deprecated-PowerShell half): parameterized, credentials from the environment only, every cell forced to a fresh directory, and `--integration-privilege` pinned per identity so a matrix diff reflects the code change rather than detection flipping between runs. |
| 2026-08-01 | **Secondary-site modelling: the parent primary reaches a secondary's database, two fail-open guards closed, and the low-privilege boundary established by measurement rather than assumption.** Microsoft's [secondary-site prerequisites](https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/prerequisites-for-installing-sites#bkmk_secondary) state that a secondary's database *must* run on the secondary site server, that the parent primary's computer account is added to that server's local Administrators group, and that it holds sysadmin on the instance permanently. None of that was modelled: at privileged, `SEC` had `CONFIGMGRSEC\CM_SEC` and a sysadmin role but **zero** logins. That was misread twice — first as correct behaviour, then as a co-location rule to exploit — before the docs settled it. It is a gap, and it arises from two filters coinciding: `_node_mssql_login` joins a site server to the database *of the same site* (so the parent never reaches the child) and then excludes the SQL host itself (so the secondary's own server never reaches its own instance). Changes: (1) **`_node_mssql_login` gains a parent-primary arm** — on a positively-known secondary (`site_type = 1`) with a known parent, the parent's site servers get sysadmin on the secondary's database. Emitted as a separate `_safe` INSERT rather than a `UNION`, because it is the only arm reading `site_hierarchy` and a missing table must not take the same-site logins down with it. The grant holds on **both** install paths — directly when the instance pre-existed, transitively via `BUILTIN\Administrators` when setup installed SQL Express (lab-verified by @_Mayyhem) — so it needs no discriminator; the broader Express-only "every local admin is sysadmin" claim is deferred to **con-53eb** with the discriminator (`sql_database_name` carries an instance-qualified `CONFIGMGRSEC\` prefix versus a bare `CM_<site>`), the SharpHound-verified `<computer objectSID>-544` format, and the `fallback_domain_sid` trap written down. The secondary site server's **own** machine account is deliberately not emitted: co-location means it authenticates locally as `NT AUTHORITY\SYSTEM` and NTLM cannot be reflected to the same host, so it is a node with no traversable edge. (2) **`_edge_local_admin_required` gains a cross-site arm** — parent primary site servers → child secondary site server. The mayyhem lab already produced this edge, but only because `ps1-sec` happens to carry `SMS Management Point@PS1`, pulling it into PS1's intra-site mesh; a secondary serving no role for its parent would have been missed. Matching the parent **by role** also settles an open question about site servers in passive mode without a separate rule — both nodes carry `SMS Site Server@<parent>`, and SharpHound's capture of this lab confirms `PS1-PSS$` *and* `PS1-PSV$` really are in `ADMINISTRATORS@PS1-SEC`. (3) **`_edge_mssql_db_assign_all` fail-open closed** — con-edee replaced `coalesce(site_type, 0) != 1` in five builders and missed this one, whose docstring nonetheless claimed it "drops secondary-site databases (e.g. CM_SEC)". `coalesce(NULL, 0) != 1` is TRUE, so an unknown-type site passed as a takeover target; dormant only because low privilege built no `SEC` database, and it would have fired the moment one existed. (4) **`_edge_coerce_relay_mssql` self-guard localized** — it had no self-check, delegating "can't relay to self" to `_node_mssql_login`'s exclusion via a docstring. That is a correctness guarantee borrowed from another function, and the secondary work is exactly the case that loosens it; `v.sid != l.host_sid` now lives in the builder, so a co-located secondary cannot produce `Coerce ps1-sec, relay to ps1-sec`. Both new arms gate on a **positively known** `site_type = 1` — the mirror image of `_NON_SECONDARY_SITE_TYPE_SQL`, so the two guards now point in opposite directions and neither acts on NULL. **The low-privilege boundary was then measured, not assumed:** a direct AD query showed the System Management container holds exactly `SMS-Site-PS1`, `SMS-Site-CAS` and `SMS-MP-PS1-PS1-MP.MAYYHEM.COM` — no `SEC` site object and no `SEC` management point — so `ldap_management_points_raw` has one row and the ported `mSSMSCapabilities` classifier (`collectors/ldap.py`, which already improves on CMBP by resolving a secondary's parent where the original leaves it `"Undetermined"`) has no `SEC` input at all. `site_hierarchy` therefore holds `('SEC', NULL, NULL)` unprivileged versus `('SEC', 'PS1', 1)` privileged, and both new arms correctly stay silent. Per @_Mayyhem: do not infer from negative evidence, but do "emit what can be confirmed or positively inferred" — so a low-privilege run still emits the `SEC` site node, `ps1-sec` as an `MSSQL_Server`, and its `SMS Site Server@SEC` role (which comes from SMB share enumeration, `SMB-SMS_SITE`). Finding a domain-user-reachable *positive* signal is **con-0394**, which records the candidate host fingerprint (MP+DP roles for a possible parent, running MSSQL, site server for a different site), MP HTTP endpoints that may serve the same `ClientOperationalSettings` XML, registry keys, the SMB share set, and the no-SMS-Provider negative ranked last. The three fixture cases exempted in `PRIVILEGE_BY_ASSERTION_NOT_KIND` keep their `requires_privilege` flag but had their justification corrected: they claimed `ps1-sec` "is correctly a plain MSSQL_Server and not a site database", which is false — it *is* SEC's site database; low privilege simply cannot prove SEC is a secondary. Two stale fixture descriptions naming `ps1-psv` as the third SQL host (it runs no SQL) were fixed to `ps1-sec`. Suite 935 passed / 5 skipped; ruff + mypy clean in both packages. |
| 2026-07-31 | **Low-privilege gap sweep: six tickets root-caused against a privileged/unprivileged A/B, and the finding that reframed all of them — the edges were never missing.** A parallel investigation with an independent adversarial verifier per finding traced each remaining low-priv fixture failure through both real lab datasets. `MSSQL_GetTGS`, `MSSQL_GetAdminTGS`, `MSSQL_ServiceAccountFor` and both `HasSession` cases reach `graph_edges` **identically** at both privilege levels; what differed was that their shared endpoint — the `sqlsccmsvc` SPN holder — had no `samAccountName`, because every one of `_node_user`'s seven arms read an SCCM-privileged source (`node_user`: 23 rows privileged, **1** unprivileged). The account fell to `_node_backfill` and shipped as a SID-only stub, and five fixtures pin that endpoint by `samAccountName`, so the matcher rejected correct edges and the runner reported "not found". **A property gap presenting as missing data**, and the runner's inability to distinguish "no such edge" from "edge rejected by property match" is what sent three separate tickets hunting for it (filed as **con-acdd**; the runner lives in `openhound-collector-common`). Changes: (1) **con-c509/con-2249** — `collectors/mssql.py` keeps `holder['sam_account_name']` (the LDAP lookup already resolved *and logged* it) and emits `service_account_name`; `_node_user` gains an eighth arm reading `mssql_server_instances`, its first low-privilege arm, excluding machine accounts which belong to `_node_computer`. One fix, five fixture cases. (2) **con-edee** — the non-secondary filter `coalesce(site_type, 0) != 1` read an *unknown* type as non-secondary, so low-priv's bare-code `SEC` became a hierarchy-takeover target: 12 `SCCM_AssignAllPermissions` edges where the lab has 8. It now requires a known Primary(2)/CAS(4), inverting the default to "exclude what we could not characterize" because a false takeover edge costs an operator more than a missing one. The predicate was copy-pasted across five builders and is now one constant, `_NON_SECONDARY_SITE_TYPE_SQL`, deciding the unknown-type policy once — which also removed a spurious `PS1-SEC → PS1-MP` `SCCM_LocalAdminRequired` edge no fixture was catching. (3) **con-5e71** — three fixtures pinned their `SCCM_ClientDevice` endpoint with `id="GUID:*"`, which asserts the *privilege level* (only an AdminService-confirmed device is GUID-keyed; an SPN-inferred one is `<sid>@<site>`) rather than the relationship. Repinned by name, with a new `requires_privilege` case carrying the confirmed-vs-possible assertion so that coverage is not silently deleted. That case is the first where privilege is a property of the **assertion** rather than the **kind**, so the guard tests gained a narrow per-case exemption plus a test ensuring the exemption cannot be used to unflag anything. (4) **con-2ca2 (A)** — the real reason a swallowed transform error left "no trail at all": `main.py` tore down both per-run file handlers in the collect phase's `finally`, and the `--run-all` chain ran *after* it, so preprocess failures reached **no** on-disk log. The chain now runs in its own `try/finally` with `_diag` still attached (the `finally` is required because the integration suite exits via `typer.Exit`). Parts B/C remain in the shared library. (5) **con-7741** — `sms_provider()` builds an `https://` URL regardless of loop protocol but sat behind the MP/DP `connection_failed` breaks, which the port-80 pass drives, so a host with 80 filtered and 443 serving the AdminService lost its SMS Provider tag — and that tag feeds `SCCM_AssignAllPermissions` and `SCCM_CoerceAndRelayToAdminService`'s pair list. Hoisted out of the loop, self-guarded on `is_sms`. (6) **con-6198** closed not-reproducible: the edge is present in all seven datasets on disk; the original failure was `ps1-psv` being powered off. Separately, **`collection_source` now carries the originating collection phase** rather than the static `SCCM-SiteDBDefaultSchema` derivation tag: `assumed_site_dbs` gained a `collection_source VARCHAR[]` populated from the contributing tables' own `source` values, threaded through `_mssql_sql_hosts` → `_mssql_sql_servers` to all six `_site_db_provenance_cols` consumers, so a node now reads `['RemoteRegistry-MultisiteComponentServers', 'MSSQL-ScanForEPA']` instead of a tag that named how the scaffolding was templated but not where the knowledge came from. `ASSUMED_SITE_DB_SOURCE` was retired (assumedness still rides on `assumed` + `assumption_basis`). Lab effect across the whole sweep: privileged 50→72 passing, unprivileged 32→54 (40 failures → 3). The three that remain are one genuine boundary — `ps1-sec` cannot be characterized as SEC's site database at low privilege because its SMS registry keys are admin-gated and it holds no `MSSQLSvc` SPN (it runs as `LocalSystem`). Suite 923 passed / 5 skipped / 0 failed. |
| 2026-07-31 | **Two low-privilege data-loss bugs fixed, plus a dependency bump, three robustness guards and a privilege-vocabulary rename.** (1) **con-3354 — `_node_site` backfills from `site_hierarchy`** (§11l). The D5 net made `site_hierarchy` know every site code the collector saw, but `_node_site` reads only AdminService/WMI/LDAP and its `LEFT JOIN site_hierarchy` only *stamps* existing rows. A site known solely to a bare low-priv source therefore never became an `SCCM_Site` node — the mayyhem `SEC` secondary was silently absent from every low-privilege graph, while a privileged run hid the bug because AdminService supplies `SEC` itself. Worth recording that the first diagnosis was **wrong**: the `register_target` scalar-`site_code` discard (a real warning, fired 4x in both runs) is *not* what loses the site; following the data through `smb_sites`/`remoteregistry_sites`/`site_hierarchy`/`node_site` located the break one layer down. `SEC` is not published to AD at all, so LDAP can never rescue it. (2) **con-be15 — corroboration gate on the "site database is local" inference** (§11l). An *empty* `Multisite Component Servers` key made the collector assert `SMS SQL Server@<site>`; true for a standalone primary, false for a passive site server, which invented an `MSSQL_Server` for `ps1-psv` and inflated six dependent MSSQL counts. The collector now flags those rows `sql_role_assumed` and `_assumed_site_dbs` drops them only when nothing unflagged claims the role *and* nothing answered on 1433 — the SQL registry keys are admin-gated and `MSSQLSvc` SPNs live on the service account (mayyhem's genuine `SEC` database runs as `LocalSystem` with none), so neither can gate it. `get_mssql_settings` additionally reads the engine service's `Start`/`ObjectName`, surfaced as `SQLServiceStartType`/`SQLServiceAccountName`. (3) **Dependency bump (con-c522), lock-only** — cleared 14 Dependabot alerts: GitPython 3.1.50→3.1.57, pyasn1 0.6.3→0.6.4, setuptools 82.0.1→83.0.0, pymdown-extensions 10.21.3→11.0.1, cryptography 48.0.0→**48.0.1** (deliberately not 49.0.0, which drops win32 and macOS x86_64 wheels and newly raises `ValueError` on X.509 certs with NULL `AlgorithmIdentifier` params — which the remote sitesigncert probe parses). Verified against the lab with a privileged/unprivileged A/B: signing and channel binding unaffected on both LDAP rungs (`LDAPS+CBT` and `LDAP+sign/seal`), SMB signing verdicts and MSSQL EPA verdicts byte-identical, and all 192 graph nodes/edges identical as order-insensitive sets. (4) **Robustness guards** — the remote sitesigncert X.509 parse (con-0170) and the `--ticket` base64/KRB-CRED decode on both the SMB-SSO and WMI paths (con-8a33) now fail with messages naming the flag and the failing step instead of a raw `binascii`/`pyasn1` traceback. A sweep found no other unguarded remote-input parse. (5) **`--integration-lowpriv`** (con-6677) wires the harness's long-existing `privileged=False` mode to the CLI — it was implemented, documented and unit-tested but reachable only from a test, so low-priv runs asserted RBAC cases they could never collect. (6) **`LOG_CONTAINER=1` documented** (con-401c): the framework picks its logging mode from `sys.stdout.isatty()`, so a redirected run falls through to *service* mode, which installs no console handler at all — an empty CI log beside a non-zero exit is that, not a crash. Root cause is in `openhound/core/logging.py`, out of scope for this repo, so documentation only. (7) **"Tier D" renamed to "requires SCCM admin"** across code, tests and README, and the privilege boundary re-derived by measurement: a privileged/unprivileged A/B measured 34 privilege-dependent fixture cases against only 8 then flagged. The README now separates the RBAC families from the device-inventory families and explicitly names `SCCM_HasClient`/`SCCM_SameHostAs`/`HasSession` as collector *gaps* rather than boundaries, so the doc cannot be read as blessing them. Known gap filed as **con-2ca2**: `_safe` swallows `BinderException` as well as missing-source errors, so a column type mismatch silently disables a transform with no log line naming it — this bit the con-be15 gate itself, which passed its tests while doing nothing in production because the fixture typed a column `VARCHAR[]` that dlt lands as `JSON`. |
| 2026-07-30 | **MSSQL payload split out, and `--run-all` now zips the graph output.** MSSQL nodes and MSSQL-only edges now emit as a third OpenGraph payload (`mssql_*` files, `source_kind="MSSQL"`, matching `schema_MSSQL.json`) instead of under `source_kind="SCCM"`. `transforms._graph_edges_split` became a three-way partition — added `graph_edges_mssql` (not AD-touching, both endpoints in the new `_mssql_ids` set) between the existing AD and SCCM sets; AD keeps top precedence so AD↔MSSQL edges stay untagged and MSSQL↔SCCM edges (`SCCM_AssignAllPermissions`) stay SCCM. `main.py` gained `MSSQL_NODE_SPECS` / `MSSQL_EDGE_SPECS` / `MSSQL_SOURCE_KIND` and a third `_emit_split_graph` pass; the six `node_mssql_*` tables moved out of `SCCM_NODE_SPECS`. Separately, `run_end_to_end` (§12) now finishes by calling the shared `openhound_collector_common.orchestration.zip_graph_output`, flat-bundling the graph `*.json` files into `graph/<archive_name>`; the `--run-all` path passes the run's own `configmanbearpig_collection_<ts>.zip` (the shared default is `<app.name>_collection.zip`). Updated §11f/§11g/§11h, §12, the "Where this code lives" table, and the README. No framework/shared-library change from this collector's side — the zip behavior ships in `openhound-collector-common` v0.1.1; this repo's dependency floor bump to `>=0.1.1` is **deferred** until that version is actually resolvable here (`v0.1.0` is still what's tagged/installed at the time of this entry). |
| 2026-07-29 | **First green `ruff` + `mypy` across both packages** (ope-60fe step 2e), prerequisite for the new `ci.yml` in each repo. Neither tool had ever passed despite both being declared dev dependencies and documented commands — the pre-commit config runs `black` and the standard hooks only. Starting point: **273 mypy errors** (206 collector / 67 library) and **50 ruff** (27 / 23); end state zero of each, with the offline suites green and a live `--run-all` collect producing a graph identical to the pre-session baseline (148 nodes / 454 edges, same kinds, identities, triples and property population). Four root causes covered nearly all the mypy count: **88 `logger.verbose` errors** fixed by routing 18 modules through the shared `get_logger()` (which already returned a `VerboseLogger` declaring the custom level) instead of `logging.getLogger` — this also retired five side-effect-only `from .. import log_context  # noqa: F401` imports whose sole job was installing the monkeypatch; **85 `import-untyped`** resolved with `ignore_missing_imports` overrides for `impacket`/`openhound`/`sspi`, none of which ship `py.typed`; **three missing stub packages** added (`types-ldap3`, `types-pywin32`, `types-pyasn1`), which surfaced three real library issues — noting `types-ldap3` targets 2.9.13 while this project pins ldap3 2.10.2rc4, so `ENCRYPT` / `TLS_CHANNEL_BINDING` / `session_security` need a narrow version-gap suppression rather than losing ldap3 checking; and **28 `fetchone()[0]`** sites replaced by a `transforms._scalar()` helper that raises a query-naming error instead of indexing `tuple \| None` (rewritten with a paren-matching scan, not a regex — the file has 130 `con.execute(` calls and only 28 with that suffix, so a forward non-greedy match runs across newlines into the next query; verified behaviour-preserving by reprocessing one cached bucket and diffing the graph). Several findings were real defects rather than annotation noise: `registry.py`'s `get_current_user` / `get_ntlm_settings` were annotated `Optional[list[str]]` / `Optional[dict]` but are generators yielding `(table, row)` tuples; two sites in `ldap.py` yielded a possibly-`None` `target.ad_object` into a dlt resource, which fails schema validation downstream without naming the host; `dns.py` referenced `dns.resolver.NXDOMAIN` in an `except` clause where `dns` binds only on a successful import, correlated to a separate boolean; `test_extension_methods.py` carried a bare `try/except` that swallowed every exception around an unused import, plus a skip claiming "convert phase not yet implemented" (false — `app.converter` is assigned and the test passes); and one library test asserted a public API purely by importing eight names, seven of which read as unused, so `ruff --fix` would have deleted them and left a green test checking nothing (rewritten to assert the export list as data; that test was retired with the upload feature later the same day, but the lesson — an unused import can be a contract — outlives it). Deliberate suppressions are confined to genuine duck-typing and stub defects, each naming its reason: the SOCKS `socket`-module patch (§13), the per-instance dnspython `resolve` override, pywin32's read-only-typed `PySecBuffer.Buffer`, ldap3's undeclared `ntlm_client`, and core's `RotatingFileHandler` — the last replaced by a `_RotatingHandler` Protocol in `main.py` that documents which six attributes (two private) the Windows rollover fix depends on. No new divergence category. |
| 2026-07-29 | **Adopted the published `openhound` 0.2.12 and fixed two bugs the validation exposed** (ope-60fe, during the PyPI publishing run). The framework dependency moved from an unpinned `git+` dev reference to a declared `openhound>=0.2.12` — 0.2.12 being what PyPI actually serves, versus the 0.1.4 commit this collector was built against. Equivalence was proven by reprocessing one cached bucket under both versions rather than by comparing two live collects: identical 148 nodes / 454 edges, kinds, node identities, edge triples, and property population. (Two live collects are *not* comparable — the pre-existing baseline had accumulated three dlt load packages for want of `--clean`, inflating its raw AdminService counts 3×, and the fresh run hit 5-second AdminService read timeouts. Neither is a framework effect.) **Bug 1 — nondeterministic array ordering (§10).** The ~20 DuckDB `list()`/`array_agg()` aggregations feeding graph arrays give no ordering guarantee and run multi-threaded, so two converts over byte-identical input emitted the same elements in different orders (measured: 14 node + 6 edge property diffs in `collectionIds`, `siteSystemRoles`, `coercionVictimHostnames`, `coercionVictimAndRelayTargetPairs`). BloodHound saw property changes on re-ingest that had not happened, and the `--compare-to-zip` parity diff filled with false positives. Fixed at the single emit boundary — `_without_null_properties` became `_normalize_properties`, which now sorts array properties as well as dropping nulls — rather than in twenty SQL expressions, because one place cannot end up half-applied and covers future arrays for free. `objectClass` is exempt via `_ORDER_SIGNIFICANT_PROPERTIES`: LDAP returns it in class-hierarchy order (`top`, `person`, …), which is meaningful and already reproducible. Same experiment now reports zero differences. Three offline tests in `convert_pipeline_test.py`. **Bug 2 — a read timeout reported as zero rows (§7).** `_http_get_value` logged `ErrorClass.CONNECT_FAILURE` (which covers timeouts) at VERBOSE while every other failure class logged WARNING, so a timed-out AdminService query surfaced only as `Collected 0 stored accounts` at INFO with nothing in the issues log — a silently incomplete graph indistinguishable from an accurate one, and it dropped two `SCCM_HasStoredAccount` edges. The level is now WARNING when collecting, with a new `probing=True` parameter keeping it at VERBOSE for `_http_identify`, whose whole job is testing whether a host is a provider at all (a connect failure there is an expected negative, and warning per candidate host would be noise). The paging loop also now distinguishes `None` (request failed) from `[]` (no rows) and reports how many rows it did get. The HTTP client's connect/read timeout was raised 5s → 10s, since `SMS_SCI_Reserved` exceeded 5s on every site server in a healthy lab. No new divergence category — extends §7 and §10. |
| 2026-07-29 | **Removed direct BloodHound CE upload**, deleting §15 and its 16 CLI options (eight each on `collect sccm` and `convert sccm`), the collector's `bloodhound_schemas.py` / `bloodhound_upload.py`, and the shared library's whole `bloodhound/` subpackage — which also lets the library drop its `requests` dependency, since nothing else there used it. Operators register the two shipped schema JSON files and ingest the OpenGraph output through BloodHound's own **File Ingest** UI; the README's Quick Start covers it. Three things deliberately unchanged: the hand-registered `convert sccm` stays (it still carries `--lookup-file` and `--progress`, and the `@app.convert()` decorator offers no seam for them, so `app.converter` is still assigned and `openhound` is still a declared dependency for that reason); both schema files stay inside the package, because `integration/__init__.py` reads `schema_SCCM.json` at runtime for the test kit's coverage check and `schema_MSSQL.json` ships as an operator deliverable; and `--disable-possible-edges` stays on `collect`, where it changes the graph. It was removed from `convert`, where it was a no-op in all but name — possible edges are gated during preprocess (`transforms._read_disable_possible`), so by convert time the decision is already in the lookup DB and the flag's only remaining effect was on the schema being uploaded. Verified: both commands bind, ruff and mypy clean in both packages, and a live `--run-all` collect produced an unchanged 148-node / 454-edge graph. |
| 2026-07-28 | **Added §11l — the rest of the low-priv-assumed-edges plan (Tasks 1, 1b, 1c, 2-6), plus Task 8 doc-truth pass.** Documents the D5 all-sources `site_hierarchy` wiring (the `information_schema` bare-code discovery loop, the observed-root-first resolution order, and the CAS/Secondary `site_type` deduction rules), the D6 site-code attribution rule and its one sanctioned cross-host exception (the `mp_host` join resolving the site-signing-certificate probe's site server), the assumption/provenance engine (`_mark_assumed`, `_site_db_provenance_cols`, `_assumed_site_dbs`'s gate-once RemoteRegistry-vs-SPN+SCCM basis), and the owner's ruling that `SCCM_AssignAllPermissions`/`SCCM_LocalAdminRequired`/`SCCM_CoerceAndRelayToAdminService`/`SCCM_CoerceAndRelayToSMB` are unconditionally assumed but **not** flag-gated (superseding §11h's original two-level-gate description, corrected in place) — leaving `MSSQL_CoerceAndRelayToMSSQL`'s EPA condition as the one genuinely flag-gated relay assumption. Also notes the small `--clean` CLI addition and one known gap (`_edge_mssql_db_assign_all` doesn't yet propagate the `assumed` stamp). Updated the `graph_edges` columns table (§11c) to include `sccm_infra`/`assumed`/`assumption_basis`. README gained a full assumed-vs-confirmed catalog, a collection-privilege-tier table, a `Container`/`GenericAll` Node/Edge Reference, and corrected the `--disable-possible-edges` documentation to match the ruling above. No new framework divergence category — extends §9 and §11b/§11h. No code changed by this pass (documentation only). |
| 2026-07-28 | **Added §11k — Tier A+ low-priv additions (low-priv-assumed-edges plan Tasks 11-14).** `Container`+`GenericAll` from the previously-unread `ldap_system_management_dacl` (id = SharpHound-matching uppercase objectGUID, standard base kinds, not in `schema_SCCM.json`); the full nested `MemberOf` chain from the same DACL's recursive group walk, routed to a new `ldap_smc_group_members` table via `dlt.mark.with_table_name` from the same resource; `ADClient.find_mssql_spn_holder` (a new sibling of `find_mssql_spns`, sharing its search/host-pinning via `_find_mssql_spn_entries`) resolving the low-priv `MSSQLSvc` SPN holder for `MSSQL_ServiceAccountFor`/a third `HasSession` arm, distinct from and deduped against the privileged `SMS_SCI_SysResUse` pair via the pre-existing `_graph_edges_dedup`; and `MSSQL_GetAdminTGS`/`MSSQL_GetTGS` from that service account to Task 4's site-server sysadmin logins, inheriting the login's confirmed/assumed stamp. All four confirmed (both flag modes, no `assumed` stamp). No new framework divergence category. 46 new/updated targeted tests + the `lowpriv_end_to_end_test.py` guard all pass; live-DB-augmented verification (see `.sdd/2026-07-23-low-priv-assumed-edges/tasks-11-14-report.md`) confirmed a DACL group ("Domain Admins") now gets a `Group` stub node it previously had none for. |
| 2026-07-24 | **Added `--dc-only` recon mode** (Ope-4tdt) — forces `--collection-methods` to `LDAP,DNS` and skips the Stage-2 per-host pass (§4). No new divergence category; it reuses the existing `--collection-methods` gate and the `per_host_expected` Stage-2 gate. |
| 2026-07-24 | ~~**Added §15 — direct BloodHound CE upload**~~ **— the upload half was removed on 2026-07-29; §15 no longer exists. The hand-registered `convert sccm` described below survives, for its own options rather than for upload flags.** Original entry, for the record: **direct BloodHound CE upload + hand-registered `convert sccm`** (ope-8c44, implementing the pivoted [Ope-8wi2](.tickets/Ope-8wi2.md)). New shared `openhound_collector_common.bloodhound` subpackage (`auth.py` HMAC/Bearer signing, `client.py` retrying HTTP client over the BH CE schema/file-upload endpoints, `uploader.py` orchestration + credential resolution, `zip_bundle.py`, `schema.py::disable_possible_edges`) plus a new `openhound-collector-common` `requests` dependency; 25 offline tests. SCCM adds `bloodhound_schemas.py` (loads + mutates `schema_SCCM.json` **and** `schema_MSSQL.json` — this collector emits `MSSQL_*` kinds too) and `bloodhound_upload.py::run_upload` (single dispatch shared by both CLI commands). An identical **BloodHound Upload** panel (`-B`/`--bloodhound`, `--bloodhound-url`/`--token-id`/`--token-key` + env vars, `--upload-schema-only`/`--upload-results-only`, `--skip-collection`, `--upload-dir`) was added to both `collect sccm` (uploads after a `--run-all` chain, or schema-only via `--skip-collection`) and `convert sccm`. Landing the `convert sccm` flags required **hand-registering** `convert sccm` on the framework's `convert` Typer group — replacing the `@app.convert(lookup=SCCMLookup)` decorator with a manual `app.converter = _run_convert` assignment + `_convert_typer.command`, the same seam `collect sccm` already used — because the decorator exposes no flag-carrying seam. Updated the README Quick Start (direct-upload examples) and added a "BloodHound Upload" Command Line Options subsection. Full SCCM suite: 731 pass. Live validation against `bloodhound.mayyhem.com` is the remaining step (offline tests use fakes for the HTTP layer). |
| 2026-07-24 | **Added §11j — AD-object attribute capture via the per-host resolution cache** (ope-c141, Phase A of a broader CMBP-parity property effort; also documents Phase B, ope-fb99, and the ope-c0c0 bug fix). `Computer`/`User`/`Group` nodes gain `Domain`, `Enabled`, `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`, `CN` (`graph.py` `ComputerProperties`/`UserProperties`/`GroupProperties`), sourced from AD attributes captured whenever `SourceContext.resolve_principal` freshly resolves a principal during collection (`context.py::_record_resolved_principal`), persisted by a new `ldap_resolved_principals` DLT resource run at the end of the per-host stage (`source.py`), and joined onto the three AD node tables in preproc via new `transforms._derive_ad_props`/`_join_ad_props`. Deliberately **resolved-principals-only** — not a domain-wide LDAP sweep; a principal never resolved during a run stays bare. No new framework divergence category — extends the existing collect-side-table + preproc-join pattern (§11a/§11b). Also (Phase B, ope-fb99): `SCCM_Site.siteSystemRoles` (per-site aggregation of `Computer.SCCMSiteSystemRoles`, empty on Secondary Sites); six new `SCCM_ClientDevice` telemetry-extra properties (`currentManagementPoint`, `currentManagementPointSID`, `previousSMSID`, `previousSMSIDChangeDate`, `userName`, `userDomainName`); and `SCCM_IsMappedTo` now carries `SCCMInfra = true` (the only edge kind that does). And a bug fix (ope-c0c0): `SCCM_ClientDevice.lastOnlineTime`/`lastOfflineTime` were always empty due to a `c_n_*` vs `cn_*` raw-column-name typo in `_node_client_device`; both now populate. Updated the README Node Reference (Computer/User/Group/SCCM_Site/SCCM_ClientDevice tables + Limitations) and Edge Reference (`SCCM_IsMappedTo`). |
| 2026-07-22 | **Python integration-test kit + payload diff.** New shared `openhound_collector_common/integration_testing/` engine (graph loader for dir/zip, wildcard matcher, typed EdgeCase/NodeCase with exact/at_least/at_most counts, results+JSON, runner with a whole-graph invariant hook, deep comparator, schema-kind coverage). SCCM adds `openhound_sccm/integration/` fixtures (61 ported edge cases with new SCCM_/MSSQL_ names, node cases, memberOf invariant) and two `collect sccm` **Testing** flags: `--run-integration-tests` (assert vs mayyhem fixtures, non-zero exit on failure) and `--compare-to-zip` (property-level diff of this run vs an arbitrary payload, always exit 0). Both imply `--run-all`. Supersedes the PowerShell kit + `compare_results.py` for the assert/diff workflows. Shared-lib change is additive (new subpackage) so MSSQL can adopt the same engine + flags. |
| 2026-07-22 | **Renamed five graph edge kinds to match the hand-maintained OpenGraph schema (`schema.json`).** Added the `SCCM_` namespace prefix to `SameHostAs`→`SCCM_SameHostAs`, `LocalAdminRequired`→`SCCM_LocalAdminRequired`, `CoerceAndRelayToAdminService`→`SCCM_CoerceAndRelayToAdminService`, and `CoerceAndRelayToSMB`→`SCCM_CoerceAndRelayToSMB`; moved the SQL relay into the separately maintained MSSQL schema as `CoerceAndRelayToMSSQL`→`MSSQL_CoerceAndRelayToMSSQL` (its end node is an `MSSQL_Login`, so it belongs to the MSSQL schema the operator uploads alongside this one). Reconciled the other direction too: `schema.json` had listed the site-replication edge as `SCCM_SameAdminsAs`, corrected to the code-true `SCCM_AdminsReplicatedTo`. Emission and entity-panel help key off the `kinds/edges.py` constants, so the change centers on the constant *values* + the `TRAVERSABLE_EDGE_KINDS` allow-list, then propagates to the saved cypher queries, README (Edge Reference / TOC / Mermaid), and the offline edge tests. CMBP-history references (the `CoerceAndRelayNTLMtoSMB` allow-list vs `CoerceAndRelayToSMB` emitter mismatch) are left verbatim as historical record. The schema also lists `SCCM_HasNetworkAccessAccount`, which no collector code emits yet — left as a placeholder and tracked in ope-e10b (emit from Local collection, reading the NAA from client WMI). No graph-shape change: same edges, new kind strings. |
| 2026-07-22 | **Ordered-log per-host grouping fix + always-DEBUG full log + log rename** (ope-54be, §7). Three coupled logging-layer changes. (1) **Grouping bug:** the six Stage-2 per-host collectors were `@with_log_context`-decorated, which set a *resource* context (`func.__name__`) and fired resource-complete once per (host, phase) — so the ordered log filled with repeated `# collect_registry` fragments and the intended per-host `flush_host` was a no-op. Removed the decorator from `collect_registry` / `collect_mssql` / `collect_adminservice` / `collect_wmi` / `collect_http` / `collect_smb` (the engine's `phase_scope(target, phase)` already tags `[target][phase]`); with no resource context their records now bucket by host and flush once per host. Stage-1 discovery resources keep the decorator (DLT drives them interleaved). Regression guard: `tests/test_per_host_log_blocks.py::test_per_host_collectors_do_not_fire_resource_complete`. (2) **Always-DEBUG full log:** the ordered handler is now created at DEBUG and both collector namespaces (`openhound_sccm` + `openhound_collector_common`) are pinned to DEBUG for the run, so the full log always holds the complete collector trace regardless of console level; `dlt`/`ldap3` internals still require `--debug`. (3) **Rename:** `collect_log_* → collect_full_*`, `collect_diagnostics_* → collect_issues_*`; summary labels + README/§7 updated. Separately, truncated the ccmsetup.exe HTTP body-preview debug line in `clients/http.py` to 1024 chars (it dumped multi-MB binary, now always in the full log). The always-DEBUG change also surfaced a latent label bug: VERBOSE (level 15) was missing from `_ORDERED_LEVEL_LABEL`, so those newly-captured lines rendered as `L15` — the handler's fallback now uses `logging.getLevelName` so any named level (VERBOSE included) prints its name (guard: `test_verbose_records_render_with_level_name_not_l15`). |
| 2026-07-22 | **`-v` now enables VERBOSE (was a no-op) + new `--silent` console mute** (ope-76f1, §7). The `-v`/`--verbose` option changed from a repeatable count (`-v`→INFO no-op, `-vv`→VERBOSE) to a plain boolean that raises the console straight to VERBOSE; the ladder is now `(none)`=INFO → `-v`=VERBOSE → `--debug`=DEBUG, and `-vv` is no longer valid (no-backward-compat rule). Added `--silent`, a **console-only** mute: `_silence_console_handlers` raises just the console handlers above `CRITICAL` (identified by the new `_is_console_handler` helper — not a `FileHandler`, and either a `StreamHandler` or a duck-typed Rich handler with `.console`), leaving the root logger and the two on-disk logs at their detail level. Because the mute is at the *handler* level, `--silent` composes with the verbosity flags — `--silent --debug` = quiet terminal, DEBUG-level file logs — and it also forces `--progress off` (the tracker bypasses logging). `_apply_log_level` gained a `silent` parameter. Offline tests: `tests/test_verbose_silent_flags.py` (13). Follow-up ope-00df tracks per-file `--no-diagnostics-log` / `--no-collect-log` switches. Updated §7 (VERBOSE bullet + new `--silent` bullet), the README verbosity tip + CLI options table. |
| 2026-07-22 | **Renamed the SOCKS5 pivot flag `--socks-proxy` → `-x` / `--proxy`** (§13). CLI-facing rename only: the option now takes a short `-x` and a long `--proxy`, and the help text is the concise `SOCKS5 proxy address (host:port or socks5://[user:pass@]host:port). Requires --dc or --dns.`. The Python parameter stays named `socks_proxy`, so the `SOURCES__SCCM__SOCKS_PROXY` env var, the `_FLAG_TO_ENV` mapping, `_parse_proxy_or_exit` / `_require_dc_or_dns_for_proxy`, and all downstream plumbing are unchanged. Registered `-x`/`--proxy` in the `_SHORT_OPTIONS_WITH_VALUES` / `_LONG_OPTIONS_WITH_VALUES` typo-detection tables so the suspicious-argument warnings still fire on the new flag. Per the no-backward-compat rule, `--socks-proxy` no longer works. Updated the §13 prose, the README Network row / Limitations / Proxying-pivoting examples, and the two `_parse_proxy_or_exit` error strings. No behavioral change to the interception itself. |
| 2026-07-21 | **Wired `--nt-hash` / `--ticket` into the LDAP auth path + MSSQL EPA ticket-only warning** (ope-b7b2, subsumes ope-272e). LDAP was the last protocol ignoring pass-the-hash / pass-the-ticket: SCCM's `ADCredentials`/`ADClient` now forward `nt_hash` + `kerberos_ticket` onto the shared `LdapAuth`, so the shared lockout-safe waterfall selects `ntlm_hash` (ldap3 `LM:NT`) or ticket-backed GSSAPI by the same precedence used across SMB/WMI/HTTP (updated [§6](#6-windows-authentication-across-five-protocols) LDAP row). No shared-library change — SCCM's adapter simply stopped dead-ending the credentials. Separately, SCCM's MSSQL phase does only EPA detection, which distinguishes Allowed/Required by forging bogus/missing NTLM channel-binding AV pairs — impossible over impacket's opaque Kerberos login — so `test_epa` now logs a WARNING and skips when a ticket is the *sole* usable credential (explicit creds and current-user SSPI still take precedence and detect EPA normally, since EPA is a server-side/identity-agnostic setting). Pass-the-ticket-for-EPA was deliberately not implemented and no follow-up ticket was opened (owner decision). Offline tests: `tests/test_ad_pth_ptt.py` (3) + `tests/test_mssql_epa.py` (+2). Live-lab validated against `dc.mayyhem.com`: LDAP pass-the-hash bound `auth=ntlm_hash` and pass-the-ticket (runtime-minted `.kirbi`) bound `auth=kerberos`, both LDAPS:636+CBT, authenticated as `MAYYHEM\domainadmin`. |
| 2026-07-21 | **Recursive GenericAll group expansion on the System Management container** (ope-e191), reconciled against final-review findings the same day. `ldap_system_management_dacl` used to only log a group holding GenericAll on the container — its members, who effectively inherit Full Control, were never discovered as targets. New helper `_expand_group_targets` (updated [§3](#3-recursive-target-discovery-and-collection)) fetches the group's `member` attribute directly (BASE-scope search on the group DN), registers computer members as scan targets (source `LDAP-GenericAllSystemManagement`), logs user members without scanning them, and recurses into nested groups with a `visited` set keyed on **group DN** (not SID, so a SID-less group cycle still terminates) to stop circular nesting. Huge memberships are paged transparently by the shared client's `ldap3` `auto_range` (on by default) — the collector no longer reassembles `member;range=N-M` pages itself; it only warns when a **residual** `member;range=` key survives, meaning auto_range failed to complete. `_parse_sd_generic_all` gained warning/debug logging on its five degraded-SD/ACE branches (too-short SD, out-of-range DACL offset, truncated ACE header, invalid ACE size, short access-mask) so a malformed ACL is distinguishable from a genuinely empty GenericAll set. Target discovery only — no new edges, no schema change, the SD parser stays GenericAll-only. `tests/test_ldap_smc_recursion.py` (5 tests: recursive expansion, circular-nesting termination via DN, unchanged direct-computer regression, auto-range full-membership no-warning, residual-range-key warning). |
| 2026-07-20 | **Fixed inferred (CmRcService-only) client devices being attached to the CAS** (ope-e739). The `SCCM_HasClient` edge for a "possible" client started from `_root_code` (the CAS in a CAS-topped hierarchy), producing an impossible `CAS → SCCM_ClientDevice` edge — a port-parity bug against CMBP's explicit `siteType -eq "Primary Site"` filter (`ps1:3253-3254`). Two coordinated fixes (updated §11b): preproc `_node_client_device_possible` now stamps `site_code` from the new `_first_primary_code` helper (`MIN(site_code) WHERE site_type = 2`), falling back to the root only when a hierarchy has no Primary; and collect-side `ldap_cmrc_devices` picks a Primary via the new `_pick_client_device_site_code`, using `ctx.primary_site_codes` recorded from MP-capabilities `site_type` during `ldap_management_points_raw`. The node id keeps its `@root_site_code` suffix for namespacing. Targeted offline tests updated/added (`node_client_device_possible_test.py`, `ldap_cmrc_site_code_test.py`); no impact on confirmed clients. |
| 2026-07-17 | **Added §13: `--socks-proxy` tunnels ALL collection traffic through a SOCKS5 pivot** (discovery + every per-host protocol — RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB). New divergence category: a process-wide interception of the stdlib `socket` module (`socket.socket`/`create_connection`/`getaddrinfo`), promoted straight into `openhound-collector-common` (`proxy/patch.py` + `proxy/socks.py`) so MSSQL can adopt it. Requires `--dc` or `--dns` (enforced by `_require_dc_or_dns_for_proxy`, exits 2 otherwise); destination names resolve at the proxy (socks5h); the collector's own DNS lookups are forced onto TCP across four proxy-aware call sites (`_resolve_dc_via_dns`, two sites in `collectors/dns.py`, `context.resolve_ip`). Documented boundary: live current-user SSPI and OS-Kerberos make their KDC/DCOM calls in the OS (LSASS/`win32com`), not this process, so they cannot be tunneled — use `--ticket` (tunnels completely) or OS-level transparent proxying instead. All in-process auth (explicit creds, pass-the-hash, pass-the-ticket, impacket Kerberos+NTLM including the KDC exchange) tunnels fully. Offline-validated against `ldap3`/`requests`/`impacket` (`spike_socks_proxy.md`); a live-lab run is the remaining confirmation. Added rows to the [Where this code lives](#where-this-code-lives-the-shared-collector-common-library) table and the quick-reference table, plus a TOC entry. Fixed the README `--socks-proxy` row and Limitations, which had gone stale claiming the flag was "intended for DHCP/TFTP collection — not yet ported." |
| 2026-07-17 | **Added §11i (new divergence category) — HTTP version fingerprint from `ccmsetup.exe`** (ope-b916). The unauthenticated HTTP phase now fetches `/CCM_Client/ccmsetup.exe` from a confirmed Management Point and regexes the embedded PE version string (the SCCMVersionGuesser technique) into a new raw table `http_site_versions` — the first HTTP-phase probe that reads binary content rather than a status code, with a bandwidth/OPSEC trade-off (full multi-MB download in v1; a bounded/`Range` fetch is a future optimization). `preprocess`'s new `_coalesce_http_site_version` fills `node_site.version` from this fingerprint, privileged-preferred (AdminService/WMI wins when both are known). `convert` uses the resolved version to populate a new `SCCM_Site.versionCVEs` property (via `cve_table.lookup_cves`, previously dead code) and `_edge_coerce_relay_adminservice` now suppresses `CoerceAndRelayToAdminService` on sites confirmed to be SCCM 2509+ (build ≥ 9141, `cve_table.ADMINSERVICE_NTLM_MIN_BUILD`) since that AdminService version rejects NTLM; unknown/unparseable versions fail open (edge kept). Updated README's Node Reference (`SCCM_Site.versionCVEs`, `version` fallback note) and Collection Overview (HTTP row + edge version-gate cross-reference). |
| 2026-07-16 | **Added §12: a `--run-all` flag on `collect sccm`** that chains preprocess + convert in-process via the new framework-agnostic `openhound_collector_common.orchestration.run_end_to_end`. New kind of divergence (end-to-end orchestration without a new top-level verb). Added a row to the [Where this code lives](#where-this-code-lives-the-shared-collector-common-library) table and the quick-reference table, plus a TOC entry. |
| 2026-07-14 | **Shared-library reconciliation (new divergence category).** Added the [Where this code lives](#where-this-code-lives-the-shared-collector-common-library) section: the Windows auth stacks, the per-target logging layer, the push→pull streaming bridge, and the DNS resolver were **promoted up** out of this extension into `openhound-collector-common`, a shared library both SCCM and MSSQL now consume (SCCM's own files reduced to thin adapters). Seven promote-up reconciliations landed on branch `integration` (`choose_auth`+`is_ip`; WMI impacket/pywin32 backends; `mssql_epa`→`detect_epa`; DNS `make_resolver`; HTTP negotiators over `KerberosToken`/`SspiClient`; `log_context` superset; `StreamBridge`+unified `DONE`). Updated §1 (streams re-export + `StreamBridge` + `extract_workers_for`; `set_bridge` handshake), §5 (shared `make_resolver`), §6 + §7 (relocation notes), the ground-rule box, and the quick-reference table. Relaxed the engine's zero-dependency test to permit exactly `openhound_collector_common`. Validated: 552 SCCM unit / 5 skipped, 172 MSSQL unit, ruff clean, and a full lab collection streaming 5 per-host sources (1005 rows through one bounded queue) with no lost rows or deadlock. |
| 2026-07-01 | Stage 7 (docs + validation) — final stage of the preproc/convert port. Whole-document reconciliation of README + ARCHITECTURE.md + in-code docstrings against code-truth (14 node kinds, 37 edge kinds). Fixed the stale Graph Model prose (README claimed 8 emitted). Added three Mermaid diagrams (pipeline data-flow, clustered AD/SCCM/MSSQL overview, complete edge reference). Non-behavioral docstring/`Attributes` completeness pass. Ran ruff/mypy/pytest in an isolated uv env + the validate-extension structural checklist. Verified + closed ope-7f61 (edge-count banner miscount, already corrected to 11 for Stages 1–2). No behavioral code changes; known limitations (e.g. ope-3dbc null-property BloodHound rejection) documented, not fixed. |
| 2026-06-30 | Stage 6 (coerce-and-relay) shipped. Added §11h: three `CoerceAndRelay*` possible-edge kinds with surgical `--disable-possible-edges` gate (default: null NTLM/EPA assumed vulnerable; flag: only explicit `Off` qualifies). Lazy `_node_authenticated_users` synthesises one `Group` node per domain with at least one relay edge (id = `UPPER(FQDN)-S-1-5-11`, merges with SharpHound). `graph_edges` gains two `VARCHAR[]` coercion columns (`coercion_victim_and_relay_target_pairs`, `coercion_victim_hostnames`); `SCCMRelayEdgeProperties` subclass carries them to the BloodHound entity panel. Fixed `CoerceAndRelayToSMB` traversable mismatch (CMBP allow-list used `CoerceAndRelayNTLMtoSMB`; the port emits and marks traversable `CoerceAndRelayToSMB`). Updated §11c `graph_edges` column list + `SCCMRelayEdgeProperties` note; added `node_computer.smb_signing_source` provenance note. Quick-reference table updated. |
| 2026-06-30 | Stage 5 (MSSQL) shipped. Added §11g: `MSSQL_Server` is a three-source coalesce (`mssql_server_instances` + `remoteregistry_mssql_servers` + `_mssql_sql_servers`), keyed on `upper(host_sid):port`, capturing multiple SQL hosts per site and non-SCCM servers. Six MSSQL node kinds inferred from SCCM topology (no live SQL enumeration). `environmentid` = AD-domain SID of the SQL host via `domain_environment_id`. MSSQL nodes in `SCCM_NODE_SPECS`; edges auto-routed by the existing `_graph_edges_split`. Quick-reference table updated. |
| 2026-06-29 | Split output shipped. Added §11f: `convert` now writes two payloads — the SCCM-tagged set (`sccm_*`, `source_kind="SCCM"`) and an untagged AD set (`ad_*`, no `metadata` block) for native AD-graph merge. New preproc step `transforms._graph_edges_split` partitions `graph_edges` into `graph_edges_ad` / `graph_edges_sccm`; new extension destination `opengraph_file_untagged`; `emit_graph_from_duckdb` gained `resource_prefix` + `source_kind=None` (untagged) handling; `NODE_SPECS`/`EDGE_SPECS` split into `SCCM_*`/`AD_*` spec lists. |
| 2026-06-29 | Stage 4 shipped. Added §11d documenting `_dedup_client_device` (merge real+inferred SCCM_ClientDevice twins by `ad_domain_sid`, runs before all edge builders — deliberate divergence from CMBP's post-edge merge order), `_edge_same_host` (bidirectional `Computer ↔ SCCM_ClientDevice` `SameHostAs`), and `_edge_local_admin_required` (site server → peer site systems `LocalAdminRequired`). Renamed §11d stub-node backfill to §11e. Updated §11b: inferred client rows now use `is_confirmed_active_client = False` (not "possible"); note the Stage 4 `SameHostAs` edge that links them back to AD computer objects. |
| 2026-06-25 | Stage 3 shipped. Updated §11c: `graph_edges` is now four columns (`start_id`, `end_id`, `kind`, `collection_source VARCHAR[]`); `GraphEdge` sets both `traversable` and `collection_source`; dedup pass groups by `(start_id, end_id, kind)` and array-unions `collection_source` via `list_distinct(flatten(list(...)))`. Updated quick-reference table row. |
| 2026-06-23 | Stage 2 preproc/convert shipped. Added §11 documenting the four Stage 2 add-ons: `host_object_sid` on RemoteRegistry current-user rows; `collection_settings` one-row flag persistence; `_read_disable_possible` persist-at-collect/gate-in-preproc mechanism; `TRAVERSABLE_EDGE_KINDS` + generic `GraphEdge`; and the new divergence category **edge-endpoint stub-node backfill** (`node_backfill` + `StubNode`). Updated §9 status from "design stage" to "Stages 1–2 shipped". Updated quick-reference table. |
