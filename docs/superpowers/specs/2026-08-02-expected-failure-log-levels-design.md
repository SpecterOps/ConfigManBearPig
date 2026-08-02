# Design: expected-failure log levels and message shape (RemoteRegistry denials, skipped transforms, probe negatives, impacket's SyntaxWarning)

**Date:** 2026-08-02 · **Status:** design (approved for planning) · **Driver:** SCCM extension, with the
impacket import guard and the skipped-transform message shape landing in `openhound-collector-common`.

## 1. Goal

A low-privilege run's `collect_issues_<ts>.log` should hold only things an operator can act on. It
currently holds **146 WARNINGs**, every one of which the collector produced while behaving exactly as
designed. **123 are reclassified** below the WARNING threshold, and two more categories (14 records)
keep their level but are rewritten — they are real privilege gaps worth surfacing, they were just long
enough to be skimmed past. The file drops to **23 WARNINGs**.

Baseline measurement: `out/ab-lowpriv-pe-off/collect_issues_20260801_230714.log` (9-host mayyhem.com
lab, plain domain user, `--run-all`).

| Category | Count | Disposition |
|---|---:|---|
| `transform '<X>' skipped (missing source)` — `wmi_*` / `adminservice_*` | 106 | → DEBUG (D3) |
| `Unable to connect to <url> - skipping remaining HTTP checks` | 10 | → INFO (D4) |
| `AdminService GET <path> returned HTTP 404` | 7 | → VERBOSE (D5) |
| `N registry read(s) denied on <host> -- not collected: ...` | 9 | stays WARNING, rewritten (D2) |
| `Access denied reading SMS\Triggers ...` | 5 | stays WARNING, shortened (D1) |
| site-code conflicts (4), MP competing site codes (2) | 6 | untouched |
| `transform ... skipped` — `remoteregistry_mssql_servers` | 1 | untouched (not a transport-family table) |
| LDAP `Could not resolve GenericAll principal 'S-1-5-18'` | 1 | untouched |
| `N WARNINGs detected` summary line | 1 | untouched (its count falls out) |

Separately, impacket emits a Python 3.14 `SyntaxWarning` to the console that no operator can act on
(D6), and every skipped transform prints as a five-line block (D7).

## 2. Why (gaps this addresses)

- **Severity stopped meaning anything.** ARCHITECTURE §7 states the design intent plainly: the logs are
  only a debugger if `ERROR` implies "something broke". The same argument applies one level down. A run
  that behaves exactly as designed emits 146 WARNINGs, so an operator learns to ignore the file — which
  is where the 23 real ones were hiding.
- **The existing transport-mirror downgrade only covers half its own case.** `_sccm_expected_miss`
  ([`transforms.py:48-88`](../../../src/openhound_sccm/transforms.py)) downgrades a missing `wmi_<X>`
  when `adminservice_<X>` exists, and vice versa. On an unprivileged run **neither** exists, so the
  downgrade never fires — precisely the run where the absence is most expected. 106 of the 146
  warnings are this one gap.
- **Two probe negatives are reported as faults.** A host that is not an SMS Provider answers the
  AdminService probe with HTTP 404, and a host not serving IIS refuses the HTTP probe. Both are
  *discovery results*. `privileged.py` already knows this — `_http_get_value` takes a `probing` flag
  and drops connect failures to VERBOSE for exactly this reason
  ([`privileged.py:252-272`](../../../src/openhound_sccm/collectors/privileged.py)) — but the flag is
  never consulted on the non-200 branch.
- **The RemoteRegistry roll-up buries its own content.** It reports *capabilities* ("SMB signing
  requirement") plus two sentences of remediation prose. The operator is a security practitioner who
  reads registry paths faster than prose, and the remediation advice is already in README's
  "What a low-privilege run looks like".
- **A third party's SyntaxWarning reaches the console.** impacket 0.13.1's `mssql/version.py:182`
  returns from inside a `finally` block. Under Python 3.14 that is a `SyntaxWarning`, emitted when the
  module is first compiled.

## 3. What is *not* in scope

Recorded so the omissions are deliberate, not forgotten:

- **The 8 untouched WARNINGs.** Site-code conflicts (6), the `remoteregistry_mssql_servers` transform
  (1), and the LDAP `S-1-5-18` resolution failure (1) stay exactly as they are. They may be real
  findings about the lab rather than privilege artifacts; that is judged separately, once the 123 are
  out of the way and they can actually be seen.
- **`collect_full_<ts>.log` stops before preprocess.** Its handler is torn down when collection ends
  (the file's last line is `--run-all set: preprocess and convert will run automatically next`), while
  `_DiagnosticFileHandler` stays attached to root and keeps recording. Preproc warnings therefore reach
  the *issues* log but never the *full* log, which is the opposite of how both files are documented.
  Real, and its own ticket.
- **Reporting impacket's bug upstream.** `finally: return string` also swallows every non-`KeyError`
  exception, so it is a defect and not only a warning. Out of scope here.

---

## 4. Decision D1 — the `SMS\Triggers` denial

`collectors/registry.py:457-462`:

```python
logger.warning("Access denied reading %s, skipping remaining Remote Registry checks",
               SCCM_REG_KEYS["triggers"])
```

```
WARNING [ps1-sms.mayyhem.com][RemoteRegistry] Access denied reading SOFTWARE\Microsoft\SMS\Triggers, skipping remaining Remote Registry checks
```

**Stays at WARNING.** `SMS\Triggers` is documented in `SCCM_REG_KEYS` as readable by any authenticated
AD user, so a refusal there is genuinely unusual — unlike the admin-gated keys.

The explanatory comment above the call (`registry.py:449-456`) is **kept**. It records why this branch
exists at all: reporting a refused read as "key does not exist" told the operator the host was not a
site server when the truth was a permissions gap, which is the opposite conclusion.

Accepted redundancy: the path also appears in the D2 roll-up for the same host. The two lines answer
different questions — this one says *why collection stopped*, the roll-up says *what was lost in
total* — and the roll-up alone does not explain the early return.

## 5. Decision D2 — the per-host denial roll-up

`collectors/registry.py:224-248`. Three coupled choices:

**Denied only.** The tally continues to exclude absent keys (`ERROR_FILE_NOT_FOUND`). A missing SQL key
means the host runs no SQL — normal, unactionable, and listing it would add the SuperSocketNetLib paths
to every non-SQL host. The denied/absent split also backs `was_denied()`, which is what stops a refused
`SMS\Triggers` read from being reported as "this host has no site code".

**Count = distinct keys, not reads.** `self._denied` holds one entry per denied *read*, and the message
now prints a *list of paths*, so the number must be the length of that list or it reads as a bug.

On the sampled run the two are identical on all nine hosts (7 reads / 7 paths, or 5 / 5), so this
changes no output today — it is a safety property. They diverge on a host where several *values* under
one key are refused: `_read_mssql_service_state` reads `Start` and `ObjectName` under the same service
key (`registry.py:736-737`), and `get_mssql_settings` reads three values under one SuperSocketNetLib
path (`registry.py:826-836`). Neither is reached on these hosts because the enclosing
read is refused first and the loop `continue`s. Dedupe with `dict.fromkeys` so first-seen order is
preserved and paths appear in the order the phase attempted them.

**No remediation prose, no capability names.**

**One key per line.** Semicolon-joined, seven paths is a 300-character wall that word-wraps at
arbitrary points; these are meant to be read and copied one at a time.

```python
keys = list(dict.fromkeys(self._denied))
logger.warning("Access denied reading %d registry key(s):\n%s",
               len(keys), "\n".join(f"    {key}" for key in keys))
```

Rendered against the real denied set for `ps1-sms` in the baseline run:

```
WARNING [ps1-sms.mayyhem.com][RemoteRegistry] Access denied reading 7 registry key(s):
        SOFTWARE\Microsoft\SMS\CurrentUser
        SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
        SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
        SYSTEM\CurrentControlSet\Control\Lsa
        SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL
        SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib
        SOFTWARE\Microsoft\SMS\Triggers
```

Two consequences of embedding newlines in a log message, both accepted:

- **The indent has to be explicit.** Rich aligns a multi-line message to its own message column, which
  produces the layout above on the console for free. The two file handlers use a plain
  `logging.Formatter`, which does not — without the four spaces the paths would start at column 0 in
  `collect_issues_<ts>.log`. The literal `"    "` is what makes all three sinks agree.
- **The record is no longer one grep-able line.** `grep "Access denied reading"` now returns the header
  without the paths. This is the deliberate trade for readability; `grep -A8` or reading the block gets
  them. Nothing machine-parses this message (verified: it appears in no test or tool outside
  `registry_access_denied_test.py`).

### 5.1 No hostname in the message text

Both D1 and D2 drop the trailing `on <host>`. `LogContextFilter` prefixes every record from a per-host
phase with `[target][phase]`, so the hostname is already there — confirmed in both on-disk logs and on
the console, including for `log_denied_summary`, which fires from the probe's `__exit__` while the
phase scope is still open.

The same duplication is in the per-read detail lines that feed this summary, so they go too
(`registry.py:265-272`, plus the "nothing was denied" DEBUG at line 238):

| Line | Before | After |
|---|---|---|
| 267 | `"%s not found on %s", description, self.hostname` | `"%s not found", description` |
| 270 | `"Access denied reading %s on %s", description, self.hostname` | `"Access denied reading %s", description` |
| 272 | `"Failed to read %s on %s: %s", description, self.hostname, ex` | `"Failed to read %s: %s", description, ex` |
| 238 | `"No registry reads were denied on %s.", self.hostname` | `"No registry reads were denied."` |

**Bounded deliberately.** `registry.py` has other messages that repeat the host (e.g. line 604's
`"No values readable under %s on %s"`, line 739's service-control-entry line), and so do the other
per-host collectors. Sweeping all of them is a separate, mechanical change; this one covers the two
messages being redesigned and the per-read lines directly behind them.

**Consequence: `_DENIED_CAPABILITIES` and `_capability_for` (`registry.py:75-99`) are deleted.** The
prose was their only consumer. The "re-run as a local administrator" advice is not lost — README's
low-privilege section carries it once, instead of every host repeating it.

The `log_denied_summary` docstring is rewritten: its current text justifies the capability mapping and
the remediation sentence, both of which are going away. What must survive is *why the summary exists at
all* (≈120 of 125 ERRORs in a low-privilege lab run were denied reads, zero as admin) and *why it hangs
off `__exit__`* (`collect_registry` returns early exactly when the site code is unreadable).

## 6. Decision D3 — downgrade transform misses when no privileged transport ran

`transforms.py:_sccm_expected_miss`. Today's case 2 returns `False` when the sibling table is absent.
Replace that tail:

```python
if found is not None:
    return True                               # case 2: the sibling transport ran
# Case 3: NEITHER transport produced this table. If no adminservice_*/wmi_* table
# exists at all, the privileged phases never ran, so every table they would have
# produced is expected to be absent -- not news. But if some DID land, this one
# query specifically came back empty, which is.
return not _privileged_transport_ran(con)
```

`_privileged_transport_ran` already exists for the `http_`/`smb_` fallback case, so case 3 adds a
reuse, not a new mechanism.

**Level: DEBUG**, matching the existing downgrade. INFO was rejected: it would put one console line per
skipped transform (106 of them) on every low-privilege run.

**Scope: `wmi_` / `adminservice_` prefixes only.** The single `remoteregistry_mssql_servers` miss in the
baseline stays a WARNING, because RemoteRegistry is not a privilege-gated transport in the same sense —
if it produced nothing, that is worth knowing.

### 6.1 This inverts a pinned test

[`tests/transforms_safe_fallback_test.py:87`](../../../tests/transforms_safe_fallback_test.py),
`test_safe_no_sibling_logs_warning`, seeds an empty schema and asserts WARNING. Its docstring reads
*"the old behaviour must be preserved"*. Under D3 that scenario becomes DEBUG, so the test is inverted
deliberately — and renamed, so the file does not claim to protect behaviour it no longer protects.

A new test covers what that test was really guarding: **a privileged transport ran, but this specific
pair is missing → still WARNING.** Seed `sccm.adminservice_other`, then reference a missing
`sccm.wmi_foo` whose `adminservice_foo` sibling also does not exist.

## 7. Decision D4 — HTTP connect failures become INFO

`collectors/http.py:306-315`. **Level only — the text is unchanged**, apart from the `-` becoming `;`
to match the house separator:

```python
logger.info("Unable to connect to %s (%s); skipping remaining HTTP checks",
            url, result.error_class.value)
```

The existing wording already names no host (only the URL, which needs its scheme because the phase
loops `http` then `https`), so per §5.1 there is nothing to strip. An earlier draft of this design
reworded it to `"%s is not reachable at %s"` in the style of `privileged.py:396/416` — that was
rejected on review because it *introduced* the very duplication §5.1 removes, and those two siblings
carry it only because they predate the rule.

**INFO, not VERBOSE**, and the asymmetry with D5 is the whole point. The HTTP phase has **no**
"this host is not an MP/DP" conclusion line — it logs only positives (`Found management point role on
%s`) between `Attempting HTTP collection on: %s` and `HTTP collection completed for %s`. Drop this to
VERBOSE and a host that served nothing reads on the console as a clean, successful collection. Here the
message *is* the conclusion, so INFO is doing the work that a separate summary line does in
`privileged.py`.

Gating on "have we confirmed a role yet" was considered and rejected: a confirmed MP that does not run
AdminService is completely normal, and the SMS Provider probe deliberately runs outside the
`connection_failed` loop (`http.py:536-543`), so such a gate would re-warn on every healthy MP.

## 8. Decision D5 — AdminService 404 while probing becomes VERBOSE

`collectors/privileged.py:273-278`. `_http_get_value` already accepts `probing`; honor it on the
non-200 branch, for 404 only:

```python
if result.status_code != 200:
    if probing and result.status_code == 404:
        # No AdminService at this path: the host is not an SMS Provider. The caller
        # turns this into the INFO "is not a reachable AdminService provider; skipping"
        # conclusion, so this line is only the evidence behind it. A 401/403/500 while
        # probing means the provider IS there and rejected us or broke -- still a WARNING.
        logger.verbose("AdminService GET %s returned HTTP 404; not an SMS Provider", path)
    else:
        logger.warning("AdminService GET %s returned HTTP %s", path, result.status_code)
    return None
```

**VERBOSE, not INFO**, because the conclusion already exists at INFO. In
`collect_full_20260801_230714.log:685-686` the two lines are consecutive for the same host:

```
WARNING [ps1-dp][AdminService] AdminService GET /AdminService/wmi/SMS_Identification... returned HTTP 404
INFO    [ps1-dp][AdminService] ps1-dp.mayyhem.com is not a reachable AdminService provider; skipping
```

Promoting the first to INFO would state the same fact twice on the console, once per non-provider host.

**404 only, not every status.** Across every retained run, all 105 observed AdminService non-200s are
HTTP 404 on `/AdminService/wmi/SMS_Identification` — the single call site that passes `probing=True`
(`privileged.py:333-334`). A 401/403 means the provider exists and rejected the credentials, and a 500
means it is present but broken; both are findings, not negatives, so they keep their WARNING. No other
status has been observed, so this narrowing costs nothing today and preserves the signal if one appears.

The only non-probing AdminService failure in the corpus confirms the existing split already works:
`AdminService GET /AdminService/wmi/SMS_Role?$top=1000&$skip=0 failed to connect` on `cas-pss` is a
*connect* failure on a `_simple(...)` call (`privileged.py:220`) that does not pass `probing`, so it is
already a WARNING and D5 does not touch it.

## 9. Decision D6 — silence impacket's SyntaxWarning in the shared library

The offending module is not imported anywhere in this repository. The chain is
`openhound_collector_common/clients/mssql.py:52` → `impacket/tds.py:54` →
`impacket/mssql/version.py:182`. The fix therefore belongs in the shared library, at the import that
triggers it:

```python
# impacket 0.13.1's mssql/version.py:182 returns from inside a finally block, which
# Python 3.14 reports as a SyntaxWarning the first time the module is compiled.
# impacket.tds imports it (tds.py:54), so that warning lands on the operator's console
# -- noise about a third-party file they cannot act on. Scoped rather than a global
# filterwarnings(): a return-in-finally in OUR code must still be reported.
with warnings.catch_warnings():
    warnings.simplefilter("ignore", SyntaxWarning)
    from impacket import ntlm, tds
```

### 9.1 Verified facts behind this shape

- **`module=` does not work.** For a compile-time warning CPython calls `warn_explicit()` with
  `module=None`, and `warnings.py` then derives the module from the *file path*
  (`.../impacket/mssql/version`), not the dotted name. Both `module=r"impacket\..*"` and a
  path-shaped regex were tested and failed to suppress; `message=` and a scoped `catch_warnings()`
  both worked.
- **Global `message=` matching was rejected** because it is process-wide and matches on text alone, so
  it would also hide a `return`-in-`finally` written in our own code. Confirmed: under the scoped form,
  compiling our own return-in-finally still warns.
- **Import time, not call time.** `clients/mssql.py:52` imports `tds` at module top level, so the
  warning fires once, single-threaded, at import. `catch_warnings()` is not thread-safe and is
  documented as such, which would matter if the guard sat around the redundant lazy
  `from impacket.tds import TDS_SSVARIANT` inside `parseRow` (line 307) — a per-row hot path in a
  10-thread collector. It does not.
- **That redundant lazy import stays.** It sits inside the verbatim-copied `parseRow` body, where
  fidelity to upstream is the stated point; it costs a `sys.modules` hit.
- **One offender only.** Compiling every module in impacket 0.13.1 outside `examples/` under
  Python 3.14 produces exactly one warning, this one.

## 10. Decision D7 — compact the skipped-transform message

`dlt/duckdb_safe.py:88-95` logs DuckDB's whole `CatalogException`, which carries a spell-check guess
and a re-print of the failing SQL with a caret. One skipped transform is five lines; 107 of them is
~535 lines in `collect_issues_<ts>.log`.

```python
if downgrade:
    log.debug("transform %r skipped: expected missing source table %r", label, match)
else:
    log.warning("transform %r skipped: source table %r does not exist", label, match)
    # Full DuckDB text (spell-check guess + SQL echo) only when the miss is UNEXPECTED
    # -- that is when a typo'd table name is worth diagnosing.
    log.debug("transform %r: %s", label, err)
```

The detail record is emitted only on the WARNING path. On the downgrade path the summary already says
everything the exception does; the guess and the SQL echo only earn their space when the miss is a
surprise.

This is a shared code path, so the MSSQL collector inherits the change. That is the intent — the
formatting is not SCCM-specific.

## 11. Cross-repo sequencing

`openhound-collector-common` is a separate repository, published to PyPI from a git tag via
`hatch-vcs`. `pyproject.toml` here deliberately has no `[tool.uv.sources]` redirect, so a local sibling
checkout is a temporary, `--skip-worktree`-guarded edit (see the note at `pyproject.toml:79-105`).

1. Land D6, D7 and their tests in `openhound-collector-common`.
2. Tag `v0.1.4`; publish.
3. In this repository: land D1–D5, then bump the floor to
   `"openhound-collector-common>=0.1.4,<0.2.0"` (`pyproject.toml:47`) with a comment recording that
   0.1.4 is the release that silences impacket's Python 3.14 SyntaxWarning and shortens the
   skipped-transform message.

The floor bump is what makes the fix reach anyone with a pinned lockfile; without it only fresh
resolutions pick it up, and nothing records which release matters.

## 12. Testing

**`openhound-collector-common`**

| Test | Assertion |
|---|---|
| `tests/test_duckdb_safe.py:138` (`..._is_loud`) | update — matches the literal `"skipped (missing source)"`, which D7 removes |
| `tests/test_duckdb_safe.py:148` (`..._is_still_quiet`) | update — same literal |
| new, in `test_duckdb_safe.py` | an unexpected miss emits one WARNING summary **and** a companion DEBUG carrying the full DuckDB text |
| new, in `test_duckdb_safe.py` | an expected miss emits the DEBUG summary and **no** companion detail record |
| new | importing `openhound_collector_common.clients.mssql` under `simplefilter("error", SyntaxWarning)` does not raise |

**ConfigManBearPig**

| Test | Assertion |
|---|---|
| `tests/registry_access_denied_test.py:86` | rewrite — assert the deduped **key paths** appear and the count equals the number of distinct paths, not reads. Drop the `local Administrators` / capability-name assertions (lines 102-105) |
| new, in `registry_access_denied_test.py` | dedup actually bites: two denied reads under **one** key path produce `1 registry key(s)` and one entry in the list |
| new, in `registry_access_denied_test.py` | §5.1 — neither the roll-up nor the `SMS\Triggers` warning contains the hostname in its message text (the `[target]` prefix is the filter's job) |
| `tests/registry_access_denied_test.py:130` | delete `test_unmapped_path_falls_back_to_the_raw_key` — `_capability_for` no longer exists |
| `tests/registry_access_denied_test.py:117` | keep — `__exit__` still fires the summary on the early-return path |
| `tests/registry_collect_test.py:381` | fix one assertion — line 387 requires `"site code is unknown"`, a phrase D1 deletes. The test's real intent (a denied read is reported as denied, not as a missing key) survives; retarget it at the surviving `"skipping remaining Remote Registry checks"` |
| `tests/registry_collect_test.py:391` | keep as-is — the absent-key path is untouched by D1 |
| `tests/transforms_safe_fallback_test.py:87` | invert and rename — no sibling **and** no privileged transport is now DEBUG |
| new, in `transforms_safe_fallback_test.py` | no sibling but a privileged transport **did** run → still WARNING |
| new | `http.py:_request` connect failure logs at INFO, not WARNING |
| new | `_http_get_value` with `probing=True` logs 404 at VERBOSE, and 401/403/500 at WARNING |
| new | `_http_get_value` with `probing=False` logs 404 at WARNING |

**Acceptance check.** Re-run the low-privilege A/B collection that produced the baseline and confirm
`collect_issues_<ts>.log` holds 23 WARNINGs, none of them from the five reclassified categories.

## 13. Docs

- **`README.md:712-724`** — the "Refused registry reads" bullet in "What a low-privilege run looks
  like". Replace the sample block at 717-723 with the D2 rendering, and keep the "Re-running as a local
  administrator on those hosts is what fills the gap" sentence at 724 — that prose is now the *only*
  place the remediation advice lives, since the per-host line no longer repeats it. Add the transform
  downgrade and the two probe levels to that section's list of things deliberately kept off the console.
- **`ARCHITECTURE.md:698-710`** — §7's "Expected-failure triage" bullet. Its "Refused registry reads"
  sub-bullet (701-710) describes the capability-naming roll-up; update it, and add the two new triage
  cases (D3, and D4/D5 together as one "probe negatives are discovery results, not faults" entry). Per
  CLAUDE.md this is a logging/diagnostics-layer change, so the section is updated in the same change.
- **`ARCHITECTURE.md` changelog** — add a **new** entry dated 2026-08-02. Do **not** edit the
  2026-08-01 entry at line 2058, even though it describes the behaviour being replaced ("Each host then
  emits one WARNING naming the capabilities it lost and that local Administrators is required"). The
  changelog is a historical record of what changed when; the new entry supersedes it and should say so.
- **Ticket** via `gtk`, then `uv run python dev/regen_ticket_index.py` — never hand-edit
  `.tickets/_TICKETS-BY-STATUS.md`.

## 14. Risks and notes

- **D3 can hide a real gap in one narrow case.** If the AdminService phase authenticates, produces at
  least one table, and a *different* query silently returns nothing, `_privileged_transport_ran` is
  True and the WARNING survives — that case is protected. The unprotected case is a run where the
  privileged phases produce **zero** tables for a reason other than privilege (a total AdminService
  outage). That run is already loud elsewhere: `privileged.py` warns per failed collection, and the
  end-of-run counts show zero rows.
- **D2 lengthens the line on hosts with many denied keys.** Six paths is roughly 300 characters. It is
  one line per host, wraps in the console, and paths are what the operator wants; accepted.
- **D7 changes a message other tooling may match on.** Grepped across both repositories, the literal
  `skipped (missing source)` appears only in `duckdb_safe.py:95` (the source), two assertions in
  `test_duckdb_safe.py` (lines 144 and 153) and an explanatory comment at line 117 of the same file.
  **Zero occurrences anywhere in ConfigManBearPig**, test or otherwise.
- **D6 assumes the fix reaches users through a release.** Until `v0.1.4` is tagged and published, the
  SyntaxWarning persists on the currently installed 0.1.3. A local guard in this repository was
  considered and rejected as dead weight the moment 0.1.4 lands.
