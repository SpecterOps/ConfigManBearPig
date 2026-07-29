# Design: merge AdminService + WMI collectors into `privileged.py`; genericize `WmiClient`

- **Date:** 2026-06-12
- **Status:** **Approved (not yet implemented).** Brainstorming complete; all branches resolved with the project owner. Plan: _to be written next (`writing-plans`)._ Nothing committed (per project owner).
- **Scope of change:** `sccm/sccm` only. Builds on the now-working AdminService collector (ope-b287) and WMI fallback collector (ope-3f2a).
- **Ticket:** ope-38ad (links ope-3f2a)

## 1. Goal

`collectors/adminservice.py` and `collectors/wmi.py` are near-identical: the same
ten collection helpers and the same orchestrator, differing only in (a) transport
(AdminService REST over OData vs the SMS Provider's WMI namespace over DCOM),
(b) the `AdminService-`/`WMI-` source-label prefix, and (c) the `adminservice_`/
`wmi_` table prefix. Row shaping is already shared via `collectors/sms_rows.py`.
The `wmi.py` docstring admits it must "mirror `adminservice.py` one-to-one" — a
hand-maintained mirror that drifts.

Collapse the two modules into one `collectors/privileged.py` with **one** set of
helpers and **one** orchestrator, and make `clients/wmi.py` a **transport-only,
SCCM-free** WMI client so it can be reused in other projects. **Collect-stage
only** — no graph/kind/model/lookup/preproc changes.

## 2. Decisions (resolved during brainstorming)

| Decision | Choice |
|---|---|
| **De-dup shape** | Transport adapter + flavor, **not** `if`-branches inside helpers. One implementation, two inputs. |
| **Streaming** | Both transports stream a **row iterator**; no materialized lists. AdminService keeps page-by-page streaming; WMI backends become generators. |
| **Generic `WmiClient`** | Single public method `query(namespace, class_name, *, columns=None, where=None) -> Iterator[dict]`. Lazy auth ladder runs on the first query (that query is the probe), caches the winning backend; later queries reuse it. No `identify`, no site code, no `root\SMS` in the client. |
| **Identification** | Moves into `privileged.py` (the SCCM adapter): HTTP GETs `SMS_Identification` → `ThisSiteCode`; WMI does `list(client.query("root\\SMS", "SMS_ProviderLocation"))` → pick `ProviderForLocalSite` → `SiteCode`. |
| **`completed_phases` timing** | Mark `add(name)` at the **end of collection** for both flavors — PS1-faithful (`ConfigManBearPig.ps1:6875` for AdminService, `:8194` for WMI). **Reverses** the current `adminservice.py` mark-after-identify. A catastrophic mid-loop abort leaves the host unmarked so the fallback can retry. |
| **No success-count gate** | The PS1 WMI's "≥1 collection succeeded" check exists only to disambiguate its multi-candidate-site-code guessing loop (`:8103-8186`). OpenHound identifies exactly one site code, so the equivalent is simply "the loop completed without a catastrophic exception" — same condition AdminService's PS1 uses. |
| **`WHERE` clause** | A visible **where string** at the call site, with the dialect's equality operator on the flavor: `where=f"SiteCode {run.eq} '{target_site}'"` (`eq` for OData, `=` for WQL). Only `_site_definition` uses it. Adapters slot the string into `&$filter=…` / `WHERE …` with no translation. |
| **Parameter threading** | Bundle `(fetch, name, eq, site_code, ctx)` into one small `_Run` dataclass; each helper takes a single `run` argument. |
| **Entry points** | Keep **two** thin functions `collect_adminservice` / `collect_wmi` (the engine registers two phases with separate gating tokens, table lists, and the WMI-fallback rule). |
| **Scope** | One pass: production + tests + both debug scripts. |

## 3. Architecture

### 3.1 `clients/wmi.py` → generic WMI client

- **Remove** (relocate to the SCCM adapter): `_ROOT_SMS`, `identify()`,
  `_site_code_from_providers()`, `self._site_code`, and the hardcoded
  `root\SMS\site_<code>` namespace inside `query()`.
- **New public surface:** `query(namespace, class_name, *, columns=None,
  where=None) -> Iterator[dict]`. On the first call (when `self._backend is
  None`), run the auth ladder using that query as the probe: per rung, build the
  backend and call `backend.execquery(namespace, wql)`; the first that returns an
  enumerator without raising wins and is cached. Then stream normalized rows off
  the enumerator. Later calls reuse the cached backend. On ladder exhaustion or a
  query error, log and yield nothing (the agreed streaming contract: failure ==
  empty iteration, already logged).
- **Backends become generators / split fetch from stream:** each backend exposes
  `execquery(namespace, wql) -> raw_enum` (eager; raises on auth/connection
  failure — this is the rung-validation signal) and `stream(raw_enum) ->
  Iterator[dict]` (impacket loops `enum.Next()`, ends on `S_FALSE`, `RemRelease`
  in `finally`; pywin32 iterates the `ExecQuery` object set). Normalization
  helpers unchanged.
- **Unchanged:** the auth ladder selection (`http_auth.choose_auth`), both
  backends' auth/connect, `from_context`, `close`, `_build_wql`, row
  normalization. Docstrings de-SCCM'd.

### 3.2 `collectors/privileged.py` (new)

```python
@dataclass(frozen=True)
class _Run:
    fetch: Callable          # (class_name, columns=None, where=None) -> Iterator[dict]
    name: str                # "AdminService" / "WMI"  (phase token + completed_phases key + source prefix)
    eq: str                  # "eq" / "="              (query dialect's equality operator)
    site_code: str
    ctx: SourceContext
    def source(self, cls):   return f"{self.name}-{cls}"           # "AdminService-SMS_Site"
    def table(self, suffix): return f"{self.name.lower()}_{suffix}"  # "adminservice_sites"
```

- **Fetch adapters** (closures over a connected client), both presenting
  `fetch(class_name, columns=None, where=None) -> Iterator[dict]`:
  - *HTTP* (`_http_fetch(client)`): builds `/AdminService/wmi/<class>` + `$select`
    (+ `&$filter=<where>` when given), streams via `_paginate` (small classes
    just return one short page — this removes the old `_get_value`/`_paginate`
    split for collections).
  - *WMI* (`_wmi_fetch(client, namespace)`): `client.query(namespace,
    class_name, columns=columns, where=where)`.
- **Ten shared helpers** `(run)` — one copy each, counting as they stream and
  logging the total after the loop. Use `run.fetch(...)`, `run.source(cls)`,
  `run.table(suffix)`, `run.site_code`, `run.ctx`. `_row`/`_prop`/column tuples
  come from `sms_rows.py`. Order preserved exactly:
  `_sites` (→ `_site_definition`), `_reserved_accounts`, `_client_devices`,
  `_r_system`, `_r_user`, `_collections`, `_collection_members`,
  `_security_roles`, `_admins`, `_site_systems`.
- **Identify helpers** (transport-specific): `_http_identify(client)`,
  `_wmi_identify(client)`.
- **Shared orchestrator** `_collect(run, target)`: loop the ten helpers with a
  per-collection `try/except` (one failure doesn't abort the rest); after the
  loop, mark `completed_phases.add(run.name)`.
- **Entry points:**

```python
@with_log_context(phase="AdminService")
def collect_adminservice(target, ctx):
    if not ctx.method_enabled("AdminService"): return
    client = HttpClient.from_context(ctx, target, auth=AuthMode.NEGOTIATE)
    try:
        site_code = _http_identify(client)
        if site_code is None: return                      # logged inside _http_identify
        run = _Run(_http_fetch(client), "AdminService", "eq", site_code, ctx)
        yield from _collect(run, target)
    except Exception as ex:                               # never crash the worker
        logger.error("AdminService collection failed for %s: %s", target, ex)
    finally:
        client.close()

@with_log_context(phase="WMI")
def collect_wmi(target, ctx):
    if not ctx.method_enabled("WMI"): return
    client = WmiClient.from_context(ctx, target)
    try:
        site_code = _wmi_identify(client)
        if site_code is None: return
        namespace = f"root\\SMS\\site_{site_code}"
        run = _Run(_wmi_fetch(client, namespace), "WMI", "=", site_code, ctx)
        yield from _collect(run, target)
    except Exception as ex:
        logger.error("WMI collection failed for %s: %s", target, ex)
    finally:
        client.close()
```

The marker sits inside the outer `try`, after the helper loop; a catastrophic
escape is caught by the `except`, leaving the host unmarked (fallback retries).

## 4. Files

- **Create:** `collectors/privileged.py`; `tests/test_privileged.py`
- **Modify:**
  - `clients/wmi.py` — genericize + stream (§3.1)
  - `per_host_phases.py` — `from .collectors import … privileged`; both phases
    point at `privileged.collect_adminservice` / `privileged.collect_wmi`
    (phase tokens, table lists, `should_run_phase` unchanged)
  - `tests/test_wmi_client.py` — trim to the generic client (namespace + WQL →
    streamed rows; ladder picks a rung). `identify`/`_site_code_from_providers`
    assertions move into `test_privileged.py`.
  - `debug_wmi_auth.py` — identify via the adapter helper, not the removed
    `client.identify()`
  - `debug_per_host.py` — fix the stale "mark right after `_identification()`"
    comment (now end-of-collection)
- **Delete:** `collectors/adminservice.py`; `collectors/wmi.py`;
  `tests/test_adminservice.py`; `tests/test_wmi.py`
- **Keep:** `collectors/sms_rows.py` (shared transport-neutral row shaping).
  `odata_select` moves out of it into the HTTP adapter in `privileged.py`
  (OData-specific, not transport-neutral).

## 5. Tests

- `tests/test_privileged.py`: the shared-helper suite **parameterized over both
  flavors** (canned fetch returning class→rows; assert table names, source
  labels, `source_site_code`, the device skip filter, site-definition computer
  rows, end-of-collection marking, and the per-collection failure isolation).
  Plus the two `_identify` paths and the `should_run`/`method_enabled` gates.
- `tests/test_wmi_client.py`: generic client only — first query runs the ladder
  and streams; later queries reuse the backend; ladder exhaustion yields nothing;
  `where`/`columns` render into WQL.

## 6. Validation

```
UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run pytest
UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run ruff check src/
UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run mypy src/
```

Live lab validation (`ps1-sms` AdminService + WMI) is best-effort per environment
availability; report if skipped.

## 7. Risks / notes

- **Behavioral change (intended):** AdminService now marks complete at
  end-of-collection instead of after identification, so a catastrophic mid-loop
  abort lets WMI retry the host (and may produce overlapping `adminservice_*` +
  `wmi_*` rows for that host). Faithful to the PS1; convert already dedupes nodes
  across sources.
- **Generic-client surface is the only irreducible complexity;** it stays sealed
  behind one `query()` method so it never leaks into the collector.
- **Order parity:** the ten collections must run in the exact existing order
  (which already matches the PS1). Covered by a test asserting yielded order.
