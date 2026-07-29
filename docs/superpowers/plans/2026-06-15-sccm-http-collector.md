# SCCM HTTP Role-Probe Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `Invoke-HTTPCollection` (+ its `Get-ManagementPointCertIssuer` helper) from ConfigManBearPig.ps1 into a collect-only, unauthenticated per-host phase that identifies SCCM site-system roles over HTTP and writes role-tagged raw rows.

**Architecture:** A new `collectors/http.py` per-host phase, registered after WMI in `per_host_phases.py`. Probes each target over `http` then `https`, reads the unauthenticated status codes (401/403/200) to detect Management Point / Distribution Point / SMS Provider / Site Server roles, registers newly discovered MPs and the site server as live work-queue targets, and yields one role-tagged computer-shaped row per discovery into four raw tables. Cross-role reconciliation is deferred to preproc; node/edge construction to convert (both later tickets).

**Tech Stack:** Python 3.13+, the existing `clients/http.py` `HttpClient` (AuthMode.NONE), `xml.etree.ElementTree` for the `.sms_aut` XML, `cryptography` for the site-signing X.509 certificate, DLT raw-table emit resources, pytest.

**Ticket:** ope-9d62 (HTTP per-host collector). Related: ope-ad1c (DP-role / client-cert gap — partially closed by this plan's decision B).

---

## Locked Design Decisions (from grilling)

1. **Row shape (A):** `collect` makes the trivial status-code→role call inline and emits computer-shaped rows already tagged with `sccm_site_system_roles`, `site_code`, `client_cert_required`, `sccm_infra`, plus the spread AD-object fields — exactly like `registry.py` / `privileged.py`. The *comparative* logic (assuming a site code onto rows that lack one, merging repeated rows for one host) is deferred to **preproc**; node/edge build to **convert**.
2. **Site-signing cert probe included:** `Get-ManagementPointCertIssuer` is ported as step 1 (it is the first call inside `Invoke-HTTPCollection`). Adds a `cryptography` dependency.
3. **Four role-typed tables:** `http_management_points`, `http_distribution_points`, `http_smsproviders`, `http_site_servers`.
4. **Skip gate:** the HTTP phase is skipped for a host once `AdminService` or `WMI` has completed it (PS1's `"Collected"` skip at 8617), enforced in `should_run_phase` via `completed_phases`.
5. **Decision B — fix the MP-endpoint guard to intent:** PS1 wraps the whole per-endpoint body in `if ($isMP -ne $true)`, so on a healthy MP `MPKEYINFORMATION` (endpoint 1) sets `$isMP` and `MPLIST` / `SMSTRC` / `MPLIST1` (endpoints 2-4) never run — defeating their documented "enumerate MPs" / "check client cert" purpose. We keep the **exact endpoint order** but drop the early-exit so all four run within a protocol; `is_mp` becomes true if *any* responds positively. (The cross-protocol guard stays: if `http` already confirmed MP, the `https` MP endpoints are skipped.) This realizes the documented intent, performs the MP-discovery cascade, and closes the client-cert half of ope-ad1c. Output is a superset of PS1's, not byte-identical.

6. **Confirmed-only rows; connected-system FQDN fallback (refines B; supersedes the discarded "bare fallback row").** A row is emitted *only* when a role is **confirmed** by a positive response (401/200/403, or 200+content/403 for MP) on an SCCM-specific path. A non-SCCM target — e.g. a random computer added because it holds rights on the System Management container — returns `404`/refused on every probe, so `is_*` never flips and it is tagged with **nothing**. When a role *is* confirmed but the payload yields no host name (e.g. a cert-required MP whose `MPKEYINFORMATION` is `403`), the row is attributed to **the system we connected to**: the MP's self-reported FQDN from `MPKEYINFORMATION` when present, otherwise the probe target itself (its AD-resolved identity). DP and SMS rows already work this way (attributed to the target); MP now does too. This never invents a role from a status code alone, but once a role is confirmed it is always recorded against a nameable host — closing the cert-flag gap without false positives. `MPLIST`/`MPLIST1` entries are *separate* enumerated sibling MPs, each recorded against its listed FQDN. Target + sibling MP rows are emitted **after** all MP endpoints are probed, so `site_code` and `client_cert_required` are final for every MP row; a sibling FQDN equal to the target may duplicate the target row, which preproc dedupes (row merging is the deferred preproc step).

## PS1-Faithful Order (preserved)

1. `?sitesigncert` site-server probe (http then https), best-effort/swallowed.
2. For `http` then `https`:
   a. MP endpoints, in order: `?MPKEYINFORMATION`, `?MPLIST`, `?SMSTRC`, `?MPLIST1&<code>` per known site code — **all probed** (decision B).
   b. DP endpoint: `/SMS_DP_SMSPKG$`.
   c. SMS Provider endpoint: `/AdminService/wmi/SMS_Identification` (https only).
3. A connection failure on either protocol stops everything (PS1's `$connectionFailed`).

## File Structure

- **Create** `src/openhound_sccm/collectors/http.py` — the collector: XML/cert parse helpers, `_role_row`, `_sitesigncert_probe`, `_HttpProbe` (MP/DP/SMS methods), `collect_http` entry point.
- **Create** `tests/test_http.py` — unit tests with a canned `_FakeHttp` client and a `_Ctx` stand-in recording `register_target`.
- **Modify** `src/openhound_sccm/per_host_phases.py` — import `http`, append the `HTTP` phase after `WMI`, extend `should_run_phase` with the HTTP skip gate.
- **Modify** `src/openhound_sccm/main.py` — add `http_site_servers` to `_preproc_table_map()` (the other three already listed).
- **Modify** `pyproject.toml` — add `cryptography>=42.0.0`.
- **Modify** `README.md` — status-only note that HTTP collection is implemented (collect stage; convert pending). No node/edge docs yet (code-truth: convert not built).

## Row Contract

Every emitted row (each of the four tables) is a dict:
```python
{
    **entry.ad_object,                 # spread resolved AD fields (object_sid, name, dNSHostName, ...)
    "source": "<HTTP-...>",            # provenance label, e.g. "HTTP-MPKEYINFORMATION"
    "sccm_infra": True,
    "sccm_site_system_roles": "<role>@<site_code>" or "<role>",
    "site_code": "<code>" or None,
    "client_cert_required": True/False/None,   # None for the site-server row (PS1 omits it there)
    "name": <ad name or hostname>,     # via setdefault
}
```
Rows are emitted **only when the host resolves in AD** (PS1 guards every node upsert on `$x.ADObject`). Crucially, the allowed-targets (`--computers`) filter gates **probing, not recording**: a discovered host the filter excludes (e.g. a site server named in another MP's certificate, or a sibling MP from `MPLIST`) is still emitted as a row — `_register_and_resolve` falls back to `resolve_principal` when `register_target` declines to queue it — it simply isn't probed directly. The `register_target` side-effect still runs so allowed discoveries fan out onto the work queue.

---

### Task 1: Dependency + preproc table map

**Files:**
- Modify: `pyproject.toml` (dependencies list)
- Modify: `src/openhound_sccm/main.py` (`_preproc_table_map`, near the existing `http_*` entries ~1120-1124)

- [ ] **Step 1: Add `cryptography` to `pyproject.toml`**

Under `dependencies`, after the `requests` entry:
```toml
    # X.509 parsing for the unauthenticated HTTP collector's sitesigncert probe
    # (collectors/http.py): the management point's site-signing certificate is
    # parsed to read its issuer CN ("Site Server") and SAN DNS name.
    "cryptography>=42.0.0",
```

- [ ] **Step 2: Add `http_site_servers` to the preproc map**

In `_preproc_table_map()`, alongside the existing `http_management_points` / `http_smsproviders` / `http_distribution_points` entries, add:
```python
        "http_site_servers",
```

- [ ] **Step 3: Sync the isolated venv**

Run: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run --project sccm/sccm python -c "import cryptography; print(cryptography.__version__)"`
Expected: prints a version (≥42).

- [ ] **Step 4: Commit** (deferred — user commits; per CLAUDE.md we do not git commit).

---

### Task 2: Register the HTTP phase + skip gate

**Files:**
- Modify: `src/openhound_sccm/per_host_phases.py`
- Test: `tests/test_http.py` (pipeline-wiring + gate tests)

- [ ] **Step 1: Write failing tests** for phase registration and the skip gate.

```python
def test_http_phase_registered_after_wmi():
    from openhound_sccm.per_host_phases import PER_HOST_PHASES, all_table_names
    names = [p.name for p in PER_HOST_PHASES]
    assert "HTTP" in names
    assert names.index("HTTP") > names.index("WMI")
    tables = set(all_table_names(PER_HOST_PHASES))
    assert {"http_management_points", "http_distribution_points",
            "http_smsproviders", "http_site_servers"} <= tables

@pytest.mark.parametrize("completed", [{"AdminService"}, {"WMI"}, {"AdminService", "WMI"}])
def test_should_run_phase_skips_http_after_privileged_collection(completed):
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None, completed_phases=set(completed))
    assert should_run_phase("h", _http_phase(), _GateCtx({"h": entry})) is False

def test_should_run_phase_runs_http_when_privileged_collection_absent():
    from openhound_sccm.per_host_phases import should_run_phase
    entry = TargetEntry(hostname="h", ad_object=None)
    assert should_run_phase("h", _http_phase(), _GateCtx({"h": entry})) is True
```
(`_GateCtx` and `_http_phase` helpers as in the existing `test_privileged.py` gate tests.)

- [ ] **Step 2: Run to verify they fail.** Run: `... pytest sccm/sccm/tests/test_http.py -k "phase or gate" -v` → FAIL (no HTTP phase / `http` import error).

- [ ] **Step 3: Implement.** Add `http` to the collectors import; append the phase after the `WMI` phase:
```python
from .collectors import registry, mssql, privileged, http
...
    Phase("HTTP", (
        "http_management_points",
        "http_distribution_points",
        "http_smsproviders",
        "http_site_servers",
    ), http.collect_http),
```
Extend `should_run_phase` (after the existing `WMI` branch):
```python
    if phase.name == "HTTP":
        entry = ctx.target_hosts_by_hostname.get(target.lower())
        if entry is not None and ({"AdminService", "WMI"} & entry.completed_phases):
            logger.info("[%s][%s] Skipping HTTP phase because AdminService/WMI already collected this host", target, phase.name)
            return False
```

- [ ] **Step 4: Run to verify pass.** (Will pass once `collect_http` exists in Task 6; the gate/registration tests pass independently of probe logic.)

---

### Task 3: XML + certificate parse helpers

**Files:**
- Create (incrementally): `src/openhound_sccm/collectors/http.py`
- Test: `tests/test_http.py`

- [ ] **Step 1: Write failing tests** for the pure parse helpers.

```python
def test_parse_mpkeyinformation():
    xml = b"<MPKEYINFORMATION><FQDN>ps1.mayyhem.com</FQDN><SITECODE>PS1</SITECODE></MPKEYINFORMATION>"
    assert http._parse_mpkeyinformation(xml) == ("ps1.mayyhem.com", "PS1")

def test_parse_mplist():
    xml = (b"<MPList><MP><FQDN>mp1.mayyhem.com</FQDN></MP>"
           b"<MP><FQDN>mp2.mayyhem.com</FQDN></MP></MPList>")
    assert http._parse_mplist(xml) == ["mp1.mayyhem.com", "mp2.mayyhem.com"]

def test_parse_sitesigncert_hex_rejects_short_payload():
    assert http._parse_sitesigncert_hex(b"<X509Certificate>ABCD</X509Certificate>") is None  # < 20 chars

def test_cert_issuer_and_dns():
    hex_der = _site_server_cert_hex("siteserver.mayyhem.com")  # cryptography-built fixture
    issuer, dns = http._cert_issuer_and_dns(hex_der)
    assert issuer == "Site Server" and dns == "siteserver.mayyhem.com"
```

- [ ] **Step 2: Run to verify they fail** (module/functions missing).

- [ ] **Step 3: Implement** the helpers in `collectors/http.py`: `_localname`, `_find_text` (namespace-tolerant), `_parse_mpkeyinformation`, `_parse_mplist`, `_parse_sitesigncert_hex` (even length, ≥ 20 chars per PS1), `_cert_issuer_and_dns` (lazy `cryptography` import; issuer CN + first SAN DNS).

- [ ] **Step 4: Run to verify pass.**

---

### Task 4: `_role_row` + sitesigncert probe

**Files:**
- Modify: `src/openhound_sccm/collectors/http.py`
- Test: `tests/test_http.py`

- [ ] **Step 1: Write failing tests** (`test_sitesigncert_detects_site_server`, `test_sitesigncert_ignores_non_site_server_issuer`) using a `_FakeHttp` returning a cert XML and a `_Ctx` recording registrations. Assert one `http_site_servers` row with role containing `"SMS Site Server"`, source `"HTTP-sitesigncert"`, and that `("siteserver.mayyhem.com", "HTTP-sitesigncert", None)` was registered; and that a non-"Site Server" issuer emits nothing and registers nothing.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** `_role_row(table, entry, source, role_base, site_code, client_cert_required)` (builds the row per the Row Contract) and `_sitesigncert_probe(client, target, ctx)` (http then https; parse hex; `_cert_issuer_and_dns`; if issuer CN contains "site server" (case-insensitive) and a DNS name, `register_target(dns, source="HTTP-sitesigncert")` and — when `ad_object` present — yield the `http_site_servers` row with `client_cert_required=None`).

- [ ] **Step 4: Run to verify pass.**

---

### Task 5: `_HttpProbe` — MP (decision B), DP, SMS

**Files:**
- Modify: `src/openhound_sccm/collectors/http.py`
- Test: `tests/test_http.py`

- [ ] **Step 1: Write failing tests:**
  - `test_mpkeyinformation_detects_mp` — `MPKEYINFORMATION` 200+XML (site PS1) → one `http_management_points` row for the connected MP, role `"SMS Management Point@PS1"`, `client_cert_required` False.
  - `test_decision_b_probes_mplist_and_smstrc_even_after_mpkeyinformation` — **decision B regression test:** `MPKEYINFORMATION` 200 (site PS1) **and** `MPLIST` 200 (two sibling MPs) **and** `SMSTRC` 403 → the connected MP's row **plus** both sibling rows are emitted, both siblings registered, and `client_cert_required` is True on **every** MP row (final flag, since rows are emitted after all endpoints). This is the behavior PS1's guard suppresses.
  - `test_cert_required_mp_attributes_row_to_connected_target` — **decision 6 / cert-gap test:** `MPKEYINFORMATION` 403 (no parseable FQDN) + `SMSTRC` 403 → exactly one `http_management_points` row, attributed to the **probe target itself**, `client_cert_required` True.
  - `test_non_sccm_target_all_404_emits_nothing` — **decision 6 / false-positive test:** every endpoint 404 → no rows, target tagged with nothing.
  - `test_mplist_enumerates_management_points` — MPLIST-only path (MPKEYINFORMATION non-MP) emits a row per sibling MP.
  - `test_distribution_point_role` (parametrized 401/200/403; 403 ⇒ cert True) — row attributed to the target.
  - `test_sms_provider_role` — https `SMS_Identification` 200 → one `http_smsproviders` row for the target.
  - `test_unresolved_host_emits_no_row_but_still_registers`.

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** `_HttpProbe` with `is_mp/is_dp/is_sms`, `site_code`, `mp_self_fqdn`, `client_cert_required`, `connection_failed`, plus `_request` (returns None + sets `connection_failed` on connect/TLS failure) and one shared emitter `_emit_role(table, identifier, source, role_base)` — registers *identifier* as a target (work-queue feed), and yields the role row only when `entry.ad_object` is present (decision 6: confirmed + nameable, never bare).
  - `management_points(protocol)`: top-guard `if self.is_mp: return` (cross-protocol). Build the ordered endpoint list (`MPKEYINFORMATION`, `MPLIST`, `SMSTRC`, then `MPLIST1&<code>` per `ctx.site_codes`) and **probe them all** (decision B — no early-exit inside the list). For each positive response set `is_mp`; `MPKEYINFORMATION` → set `site_code` and `mp_self_fqdn`; `SMSTRC` 403 → `client_cert_required = True`; `MPLIST`/`MPLIST1` → collect sibling FQDNs. **After** the loop, if `is_mp`: `_emit_role` once for the connected MP (`mp_self_fqdn or target`, source `"HTTP-MPKEYINFORMATION"` if self-reported else `"HTTP-SMS_MP"`), then `_emit_role` per sibling FQDN (source `"HTTP-MPLIST"`; PS1's `"HTTP-MPKEYINFORMATION"` label at 8743 is a copy-paste bug we correct).
  - `distribution_points(protocol)` / `sms_provider()`: keep their own `if self.is_dp/_sms: return` short-circuit (one endpoint each — correct). Detect on 401/200/403, set cert on 403, then `_emit_role(<table>, self.target, <source>, <role>)`.

- [ ] **Step 4: Run to verify pass.**

---

### Task 6: `collect_http` orchestrator

**Files:**
- Modify: `src/openhound_sccm/collectors/http.py`
- Test: `tests/test_http.py`

- [ ] **Step 1: Write failing tests:** `test_method_disabled_yields_nothing`, `test_connection_failure_stops_all_probing` (fail on `MPKEYINFORMATION` ⇒ no https retry, no DP/SMS probes).

- [ ] **Step 2: Run to verify they fail.**

- [ ] **Step 3: Implement** `@with_log_context(phase="HTTP")` `collect_http(target, ctx)`: gate on `method_enabled("HTTP")`; build `HttpClient.from_context(ctx, target, auth=AuthMode.NONE)`; run `_sitesigncert_probe` in a swallowing try/except; then the `("http", "https")` loop calling `management_points` → `distribution_points` → `sms_provider`, breaking on `connection_failed`; outer try/except so the per-host worker never crashes; `client.close()` in `finally`.

- [ ] **Step 4: Run to verify pass:** `... pytest sccm/sccm/tests/test_http.py -v` → all green.

---

### Task 7: README status note

**Files:**
- Modify: `README.md` (Collection Overview / Limitations / Command Line Options HTTP rows)

- [ ] **Step 1:** Update the HTTP collection-method status marker to reflect that the collect stage is implemented (role discovery via HTTP), with preproc/convert (graph emission) pending. Do **not** add HTTP node/edge reference rows — convert is not built yet (code-truth: docs describe only implemented nodes/edges).

---

### Task 8: Validate

- [ ] **Step 1:** `UV_PROJECT_ENVIRONMENT=/tmp/openhound-sccm-venv uv run --project sccm/sccm pytest sccm/sccm/tests/test_http.py -v` → all pass; also run the full suite to confirm no regressions in `test_privileged.py`'s gate tests.
- [ ] **Step 2:** `... uv run --project sccm/sccm ruff check src/openhound_sccm/collectors/http.py` and `... mypy src/openhound_sccm/collectors/http.py` (report, don't force, if env unavailable).
- [ ] **Step 3 (live):** Run the real collector against `ps1-mp.mayyhem.com`, `ps1-pss.mayyhem.com`, `ps1-dp.mayyhem.com`, `ps1-sms.mayyhem.com` (per user request) and confirm the expected roles/rows. Report status codes seen and rows written.

---

## Self-Review

- **Spec coverage:** sitesigncert (Task 4), MP/DP/SMS detection in PS1 order (Task 5), decision-B fix (Task 5 + regression test), four tables + phase wiring (Task 2), skip gate (Task 2), connection-failure short-circuit (Task 6), method gating (Task 6), live validation against the four hosts (Task 8). Deferrals (preproc reconciliation, convert nodes/edges) are explicitly out of scope.
- **Placeholders:** none — each task names files, tests, and the concrete implementation behavior.
- **Type consistency:** `_role_row` signature `(table, entry, source, role_base, site_code, client_cert_required)` is used identically by `_sitesigncert_probe`, `_handle_mpkeyinformation`, `_handle_mplist`, and `_role_for_target`. Table names match across the phase tuple, the preproc map, and the row emissions.

## Risks / Follow-ups

- **Decision B** makes output a superset of PS1 (more sibling MPs registered, client-cert detected on healthy MPs). Intended; closes the cert half of ope-ad1c.
- **Duplicate MP rows:** when the probe target's own FQDN also appears in its `MPLIST`, the connected-MP row and a sibling row name the same host. Intentional — row merging for one host is the deferred preproc step. (The earlier SMSTRC-only cert-flag gap is now *closed* by decision 6: a confirmed MP always emits a row for the connected host carrying the cert flag.)
- **False positives are bounded by SCCM-specific paths:** detection only flips on a response to `/SMS_MP/.sms_aut`, `/SMS_DP_SMSPKG$`, or `/AdminService/` — a non-SCCM host 404s/refuses on all of them and is tagged with nothing.
- Preproc reconciliation and convert node/edge emission are separate future tickets.
