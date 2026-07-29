# ope-b7b2: LDAP pass-the-hash / pass-the-ticket + MSSQL ticket-only EPA warning — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `--nt-hash` (pass-the-hash) and `--ticket` (pass-the-ticket) work uniformly across the SCCM collector's auth paths by wiring them into LDAP (the last protocol that ignored them), and make the MSSQL EPA phase log an honest WARNING when a Kerberos ticket is the only usable credential (because pass-the-ticket cannot drive EPA detection).

**Architecture:** The shared `openhound-collector-common` `AdClient` already implements LDAP pass-the-hash (ldap3 `LM:NT` NTLM bind) and pass-the-ticket (base64 `.kirbi` → impacket ccache → SASL GSSAPI), lockout-safe. SCCM's `ADCredentials`/`ADClient` adapter simply never forwarded the two credentials onto the shared `LdapAuth`, so the plumbing dead-ended. This plan forwards them — three small SCCM edits, **no shared-library change**. Separately, SCCM's MSSQL phase does *only* EPA detection, which relies on forging bad channel-binding AV pairs that impacket's Kerberos login can't produce; so instead of a meaningless ticket-based probe, `test_epa` gains a `kerberos_ticket` parameter used solely to detect the "ticket is the only credential" case and emit a WARNING.

**Tech Stack:** Python 3, `ldap3`, `impacket`, `pywin32`; the shared `openhound_collector_common.clients.ad.AdClient` / `LdapAuth`; pytest (function-style, `monkeypatch`/`caplog`); Typer CLI.

## Global Constraints

- **SCCM-only.** All edits are under `sccm/sccm/`. The shared library `openhound-collector-common/` is read-only (AGENTS.md); this plan needs no shared-library change (confirmed during the code dive).
- **No commits.** Do not `git add`/`commit`. Each task ends at a **green checkpoint** (tests + lint pass); the user commits when ready. (Overrides the writing-plans skill's "Commit" step.)
- **Logging on every branch.** Every new `if/elif/else` branch gets an appropriately-levelled log line (error/warning/info/verbose/debug) or a comment saying why none is needed.
- **Docs are code-truth.** Update `--nt-hash`/`--ticket` help text, `clients/ad.py` and `clients/mssql_epa.py` docstrings, `ARCHITECTURE.md` §6, and the README auth coverage to match what the code actually does — no aspirational claims.
- **Targeted tests.** Run the specific changed test files with the existing `sccm/sccm/.venv` interpreter (do not rebuild `.venv`, do not run the full suite). Run `ruff` on changed files.
- **Ladder-order assumption (vetoable):** `test_epa` credential order is `explicit → SSPI → ticket-only-warning → skip`. SSPI precedes the warning because EPA is server-side (identity-agnostic), so SSPI still yields a real verdict; the warning is the honest outcome only when a ticket is the *sole* usable credential.
- **Subsumes ope-272e** (the LDAP pass-the-hash placeholder). No new ticket is opened for MSSQL PtT (owner decision).

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `sccm/sccm/src/openhound_sccm/clients/ad.py` | Modify | Add `nt_hash`/`kerberos_ticket` to `ADCredentials`; forward onto shared `LdapAuth`; correct the module docstring. |
| `sccm/sccm/src/openhound_sccm/source.py` | Modify (`~257-263`) | Pass the already-in-scope `nt_hash`/`kerberos_ticket` into the `ADCredentials(...)` constructor. |
| `sccm/sccm/tests/test_ad_pth_ptt.py` | Create | Offline unit tests: forwarding + shared auth-mode selection (`ntlm`/`ntlm_hash`/`kerberos`). |
| `sccm/sccm/src/openhound_sccm/clients/mssql_epa.py` | Modify (`73-104`, docstring) | Add `kerberos_ticket` param; ticket-only WARNING branch; update docstring. |
| `sccm/sccm/src/openhound_sccm/collectors/mssql.py` | Modify (`72-81`) | Forward `ctx.kerberos_ticket` into `test_epa`. |
| `sccm/sccm/tests/test_mssql_epa.py` | Modify | Add ticket-only-warning test + ticket-with-SSPI precedence test. |
| `sccm/sccm/src/openhound_sccm/main.py` | Modify (`954-955`) | Help text: add LDAP (both flags), MSSQL EPA (`--nt-hash`), and the `--ticket`-not-used-for-MSSQL note. |
| `sccm/sccm/ARCHITECTURE.md` | Modify (§6 table + changelog) | LDAP row now lists PtH/PtT; MSSQL EPA row notes the ticket limitation; changelog entry. |
| `sccm/sccm/README.md` | Modify | Auth coverage / CLI table reflects LDAP PtH/PtT and the MSSQL ticket limitation. |
| `.tickets/ope-b7b2.md`, `.tickets/ope-272e.md`, `TICKETS-BY-STATUS.md` | Modify | Close both tickets; update the status index. |

---

## Task 1: LDAP pass-the-hash / pass-the-ticket forwarding

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/clients/ad.py:44-55` (`ADCredentials`), `:76-91` (`ADClient.__init__`), `:11-13` (docstring)
- Modify: `sccm/sccm/src/openhound_sccm/source.py:257-263` (`ADCredentials(...)` construction)
- Test: `sccm/sccm/tests/test_ad_pth_ptt.py`

**Interfaces:**
- Consumes: shared `openhound_collector_common.clients.ad.LdapAuth(username, password, nt_hash, kerberos_ticket)` and `AdClient._select_auth_modes() -> list[str]` (returns `["kerberos"]` for a ticket, `["ntlm_hash"]` for an NT hash, `["ntlm"]` for username+password).
- Produces: `ADCredentials(domain, domain_controller, username, password, nt_hash, kerberos_ticket, port)`; `ADClient(credentials).auth` is a `LdapAuth` carrying all four credentials.

- [ ] **Step 1: Write the failing test**

Create `sccm/sccm/tests/test_ad_pth_ptt.py`:

```python
"""Offline unit tests for SCCM LDAP pass-the-hash / pass-the-ticket wiring.

SCCM's ADClient forwards --nt-hash / --ticket onto the shared LdapAuth so the
shared lockout-safe waterfall picks the right bind mode. These assert the
forwarding and the resulting auth-mode selection without a live DC (ADClient
binds lazily, so construction does no network I/O).
"""
from openhound_sccm.clients.ad import ADClient, ADCredentials


def test_password_selects_ntlm_mode():
    client = ADClient(ADCredentials(domain="mayyhem.com", username="MAYYHEM\\u", password="pw"))
    assert client.auth.password == "pw"
    assert client._select_auth_modes() == ["ntlm"]


def test_nt_hash_forwarded_and_selects_ntlm_hash_mode():
    client = ADClient(ADCredentials(domain="mayyhem.com", username="MAYYHEM\\u", nt_hash="a" * 32))
    assert client.auth.nt_hash == "a" * 32
    assert client._select_auth_modes() == ["ntlm_hash"]


def test_ticket_forwarded_and_selects_kerberos_mode():
    client = ADClient(ADCredentials(domain="mayyhem.com", kerberos_ticket="Zm9vYmFy"))
    assert client.auth.kerberos_ticket == "Zm9vYmFy"
    assert client._select_auth_modes() == ["kerberos"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/test_ad_pth_ptt.py -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'nt_hash'` (from `ADCredentials`).

- [ ] **Step 3: Add the two fields to `ADCredentials`**

In `sccm/sccm/src/openhound_sccm/clients/ad.py`, insert the two fields after `password` (before the `port` comment block):

```python
@dataclass
class ADCredentials:
    domain: str
    domain_controller: str | None = None
    username: str | None = None
    password: str | None = None
    # Pass-the-hash (bare 32-hex NT or LM:NT) and pass-the-ticket (base64
    # KRB-CRED / .kirbi). The shared waterfall selects the bind mode by
    # credential precedence: ticket -> nt_hash -> password -> integrated.
    nt_hash: str | None = None
    kerberos_ticket: str | None = None
    # Optional port override. ``None`` lets ``bind()`` auto-detect the transport
    # (LDAPS 636 → StartTLS 389 → LDAP 389+sign/seal). Setting a value pins the
    # port and narrows the attempt chain: 636/3269 → LDAPS; anything else → LDAP
    # (with NTLM sign/seal when creds are supplied, plain LDAP only as a last
    # resort).
    port: int | None = None
```

- [ ] **Step 4: Forward the fields in `ADClient.__init__`**

Replace the `LdapAuth(...)` construction and its comment at `sccm/sccm/src/openhound_sccm/clients/ad.py:80-90`:

```python
        # SCCM binds LDAP with username+password, an NT hash (pass-the-hash), a
        # Kerberos ticket (pass-the-ticket), or integrated auth; the shared
        # LdapAuth + waterfall selects the mode by credential precedence
        # (ticket → nt_hash → password → SSPI/anonymous).
        super().__init__(
            domain=credentials.domain,
            dc=credentials.domain_controller,
            auth=LdapAuth(
                username=credentials.username,
                password=credentials.password,
                nt_hash=credentials.nt_hash,
                kerberos_ticket=credentials.kerberos_ticket,
            ),
            port=credentials.port,
        )
```

- [ ] **Step 5: Correct the module docstring**

In `sccm/sccm/src/openhound_sccm/clients/ad.py`, replace the bullet at lines 11-13:

```python
  * constructed from SCCM's :class:`ADCredentials` (username+password, an NT hash
    for pass-the-hash, a base64 Kerberos ticket for pass-the-ticket, or
    integrated auth), mapped onto the shared ``LdapAuth``;
```

- [ ] **Step 6: Pass the credentials in `source.py`**

In `sccm/sccm/src/openhound_sccm/source.py`, add the two fields to the `ADCredentials(...)` call at lines 257-263 (`nt_hash` and `kerberos_ticket` are already in scope as source-function parameters):

```python
    creds = ADCredentials(
        domain=domain,
        domain_controller=domain_controller,
        username=username,
        password=password,
        nt_hash=nt_hash,
        kerberos_ticket=kerberos_ticket,
        port=ldap_port,
    )
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/test_ad_pth_ptt.py sccm/sccm/tests/ad_test.py -v`
Expected: PASS (new file all green; `ad_test.py` still green — no regression).

- [ ] **Step 8: Lint the changed files**

Run: `sccm/sccm/.venv/Scripts/python.exe -m ruff check sccm/sccm/src/openhound_sccm/clients/ad.py sccm/sccm/src/openhound_sccm/source.py sccm/sccm/tests/test_ad_pth_ptt.py`
Expected: no errors.

- [ ] **Step 9: Green checkpoint** — LDAP PtH/PtT wired; stop for user review (no commit).

---

## Task 2: MSSQL EPA ticket-only WARNING

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/clients/mssql_epa.py:73-104` (signature + ladder), docstring `:10-19`
- Modify: `sccm/sccm/src/openhound_sccm/collectors/mssql.py:72-81` (forward `ctx.kerberos_ticket`)
- Test: `sccm/sccm/tests/test_mssql_epa.py` (add two tests)

**Interfaces:**
- Consumes: `SourceContext.kerberos_ticket: str | None` (already exists, `context.py:29`); the shared `Auth`/`detect_epa` (unchanged — the ticket is never passed to them).
- Produces: `test_epa(*, target, port, remote_name, domain, username, password, nt_hash, kerberos_ticket, spns) -> Optional[EPAResult]` — returns `None` (with a WARNING) when a ticket is the only usable credential.

- [ ] **Step 1: Write the failing tests**

Append to `sccm/sccm/tests/test_mssql_epa.py`:

```python
def test_test_epa_warns_and_skips_when_only_ticket(monkeypatch, caplog):
    """Ticket only (no explicit creds, no SSPI) -> WARNING + None; detect_epa never called."""
    import logging
    called = []
    monkeypatch.setattr(mssql_epa, "_sspi_available", lambda: False)
    monkeypatch.setattr(mssql_epa, "detect_epa", lambda *a, **k: called.append(1))
    with caplog.at_level(logging.WARNING):
        result = mssql_epa.test_epa(target="ps1-db.mayyhem.com", domain="mayyhem.com",
                                    kerberos_ticket="Zm9vYmFy")
    assert result is None
    assert called == []
    assert "pass-the-ticket" in caplog.text.lower()
    assert "--nt-hash" in caplog.text


def test_test_epa_prefers_sspi_over_ticket_only(monkeypatch):
    """Ticket + SSPI available -> SSPI is used (EPA is server-side; SSPI still detects it)."""
    captured = {}
    monkeypatch.setattr(mssql_epa, "_sspi_available", lambda: True)
    monkeypatch.setattr(mssql_epa, "detect_epa",
                        lambda t, a, **k: (captured.update(auth=a) or _VERDICT))
    result = mssql_epa.test_epa(target="x", domain="d", kerberos_ticket="Zm9vYmFy")
    assert result.extended_protection == "Required"
    assert captured["auth"].use_sspi is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/test_mssql_epa.py -v -k "only_ticket or prefers_sspi_over_ticket"`
Expected: FAIL — `TypeError: test_epa() got an unexpected keyword argument 'kerberos_ticket'`.

- [ ] **Step 3: Add the parameter and warning branch to `test_epa`**

In `sccm/sccm/src/openhound_sccm/clients/mssql_epa.py`, add `kerberos_ticket` to the signature (after `nt_hash`) and insert the ticket-only branch **after** the SSPI branch and **before** the final `else`:

```python
def test_epa(
    *,
    target: str,
    port: int = 1433,
    remote_name: Optional[str] = None,
    domain: str = "",
    username: Optional[str] = None,
    password: Optional[str] = None,
    nt_hash: Optional[str] = None,
    kerberos_ticket: Optional[str] = None,
    spns: Optional[list] = None,
) -> Optional[EPAResult]:
```

```python
    if username and (password or nt_hash):
        auth_domain, sam = split_user_domain(username, domain)
        logger.info("EPA testing %s via explicit credentials for %s\\%s", target, auth_domain, sam)
        auth = Auth(username=sam, password=password, nt_hash=nt_hash, domain=auth_domain, spn=spn)
    elif _sspi_available():
        logger.info("EPA testing %s via current-user SSPI (NTLM) integrated auth", target)
        auth = Auth(use_sspi=True, domain=domain, spn=spn)
    elif kerberos_ticket:
        # Pass-the-ticket cannot drive EPA detection: the probe tells Allowed from
        # Required by forging bogus/missing NTLM channel-binding AV pairs, and
        # impacket's Kerberos login exposes no hook to do that. Warn and skip
        # rather than emit a misleading verdict. (This branch is reached only when
        # a ticket is the *sole* usable credential — explicit creds and SSPI, both
        # of which can detect EPA, take precedence above.)
        logger.warning(
            "EPA testing %s skipped: pass-the-ticket (--ticket) cannot probe EPA "
            "enforcement. For EPA detection supply -p/--password or --nt-hash, or "
            "run on a domain-joined Windows host to use current-user SSPI.",
            target,
        )
        return None
    else:
        logger.warning("EPA testing %s skipped: no credentials and SSPI unavailable", target)
        return None
```

- [ ] **Step 4: Update the `test_epa` docstring**

In the same function, replace the credential-ladder sentence in the docstring so it names the ticket-only case:

```python
    """Determine EPA enforcement for one SQL Server via the shared detector.

    Credential ladder: explicit credentials (password or NT hash) -> current-user
    SSPI integrated auth -> (ticket-only: WARNING + skip, because pass-the-ticket
    cannot probe channel binding) -> skip (returns ``None``). *spns* is the host's
    AD SPN list, used to pin the registered ``MSSQLSvc`` SPN so the service-binding
    AV pair matches what the server expects. Raises :class:`EPAPrereqError` (from
    the shared detector) when the baseline login can't establish a trustworthy
    result.
    """
```

- [ ] **Step 5: Update the module docstring**

In `sccm/sccm/src/openhound_sccm/clients/mssql_epa.py`, adjust the `test_epa` bullet (lines ~10-13) to mention the ticket-only skip:

```python
  * :func:`test_epa` — the credential-ladder entry point the MSSQL collector calls;
    it selects explicit-creds vs current-user SSPI (vs a ticket-only WARNING+skip,
    since pass-the-ticket can't probe channel binding, vs skip), pins the
    registered ``MSSQLSvc`` SPN from the host's AD SPN list, runs the shared
    ``detect_epa``, and returns an :class:`EPAResult` (or ``None``);
```

- [ ] **Step 6: Forward the ticket from the collector**

In `sccm/sccm/src/openhound_sccm/collectors/mssql.py`, add `kerberos_ticket=ctx.kerberos_ticket` to the `test_epa(...)` call at lines 72-81:

```python
    epa_result = test_epa(
        target=target,
        port=port,
        remote_name=target,
        domain=ctx.domain,
        username=ctx.username,
        password=ctx.password,
        nt_hash=ctx.nt_hash,
        kerberos_ticket=ctx.kerberos_ticket,
        spns=spns,
    )
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/test_mssql_epa.py -v`
Expected: PASS (new tests green; the four existing `test_epa` ladder tests still green).

- [ ] **Step 8: Lint the changed files**

Run: `sccm/sccm/.venv/Scripts/python.exe -m ruff check sccm/sccm/src/openhound_sccm/clients/mssql_epa.py sccm/sccm/src/openhound_sccm/collectors/mssql.py sccm/sccm/tests/test_mssql_epa.py`
Expected: no errors.

- [ ] **Step 9: Green checkpoint** — MSSQL ticket-only warning wired; stop for user review (no commit).

---

## Task 3: CLI help text + docs + tickets

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py:954-955`
- Modify: `sccm/sccm/ARCHITECTURE.md` (§6 auth table + Changelog)
- Modify: `sccm/sccm/README.md` (auth coverage)
- Modify: `.tickets/ope-b7b2.md`, `.tickets/ope-272e.md`, `TICKETS-BY-STATUS.md`

**Interfaces:** none (documentation + metadata only).

- [ ] **Step 1: Update the `--nt-hash` / `--ticket` help text**

In `sccm/sccm/src/openhound_sccm/main.py`, replace lines 954-955:

```python
    nt_hash: Optional[str] = typer.Option(None, "--nt-hash", help="NT hash for pass-the-hash auth (bare 32-hex NT hash; LM half assumed empty). Used by LDAP, AdminService (Kerberos RC4 key and NTLM), the SMB-based phases (RemoteRegistry, SMB), and the MSSQL EPA probe."),
    ticket: Optional[str] = typer.Option(None, "--ticket", help="Base64-encoded Kerberos ticket (.kirbi / KRB-CRED) for pass-the-ticket. Kerberos only, no NTLM fallback. Honored by LDAP, AdminService/WMI, and the SMB-based phases (RemoteRegistry, SMB). Not used for the MSSQL EPA probe (it cannot probe channel binding — use -p/--password or --nt-hash there)."),
```

- [ ] **Step 2: Verify the help renders**

Run: `sccm/sccm/.venv/Scripts/python.exe -m openhound_sccm.main collect sccm --help`
Expected: `--nt-hash` and `--ticket` help lines show "LDAP"; the `--ticket` line shows the "Not used for the MSSQL EPA probe" note. (If the module entry point differs, use the project's documented CLI invocation from the README Quick Start.)

- [ ] **Step 3: Update ARCHITECTURE.md §6 auth table**

In `sccm/sccm/ARCHITECTURE.md`, in the §6 "Windows authentication across five protocols" table:
- **LDAP / AD** row: change the schemes cell to note pass-the-ticket and pass-the-hash now flow from SCCM, e.g. `pass-the-ticket → pass-the-hash (ntlm_hash) → explicit NTLM → Kerberos (GSSAPI) → current-user SSPI-NTLM → anonymous`, and remove any "SCCM does not pass an NT hash / Kerberos ticket to LDAP" wording.
- **MSSQL EPA probe** row: append a note that a Kerberos ticket is *not* accepted for EPA (pass-the-ticket can't forge channel bindings); ticket-only credentials produce a WARNING + skip.

- [ ] **Step 4: Add an ARCHITECTURE.md changelog entry**

Append to the Changelog section (match the existing entry format/date style), summarizing: "ope-b7b2 — wired `--nt-hash`/`--ticket` into the LDAP adapter (forwarded onto the shared `LdapAuth`; PtH/PtT now uniform across LDAP/SMB/WMI/HTTP); MSSQL EPA now warns and skips on ticket-only credentials. Subsumes ope-272e. No shared-library change."

- [ ] **Step 5: Update the README auth coverage**

In `sccm/sccm/README.md`, update the command-line / auth section so the per-protocol coverage shows LDAP supports `--nt-hash` and `--ticket`, and add a one-line note that `--ticket` does not drive MSSQL EPA detection. Add a copy-pasteable mayyhem.com example for each, e.g.:

```
# LDAP pass-the-hash
openhound collect sccm -d mayyhem.com --dc dc.mayyhem.com -u MAYYHEM\domainadmin --nt-hash <32-hex> -m LDAP <out>

# LDAP pass-the-ticket
openhound collect sccm -d mayyhem.com --dc dc.mayyhem.com --ticket <base64-kirbi> -m LDAP <out>
```

- [ ] **Step 6: Close the tickets**

Set `.tickets/ope-b7b2.md` and `.tickets/ope-272e.md` `status:` to `done` (via `gtk` per CLAUDE.md — e.g. `gtk status ope-b7b2 done`), and add a short closing note to each body: ope-272e is subsumed by ope-b7b2's LDAP PtH/PtT; ope-b7b2 delivered LDAP PtH/PtT + the MSSQL ticket-only warning, MSSQL pass-the-ticket-for-EPA intentionally not implemented (owner decision — no follow-up ticket).

- [ ] **Step 7: Update the status index**

Update `TICKETS-BY-STATUS.md` to move ope-b7b2 and ope-272e into the done section (run whatever regeneration the repo uses, or edit by hand to match the existing format).

- [ ] **Step 8: Green checkpoint** — docs + tickets updated; stop for user review (no commit).

---

## Task 4: Live-lab validation (user powers on the lab)

**Files:** none (runtime validation only). Requires the lab up and two operator-supplied secrets: a domain user's NT hash and a base64 `.kirbi` for that user. Check ps1-sms `:443` first (the lab is often powered off); KDC is `dc.mayyhem.com`; reuse creds from `sccm/sccm/debug_epa_matrix.py`.

**Interfaces:** none.

- [ ] **Step 1: Confirm the lab is reachable**

Check the DC and AdminService host are up (e.g. TCP `dc.mayyhem.com:389`/`:636` and `ps1-sms:443`). If down, report "lab unavailable" and stop — the offline tests in Tasks 1-2 are the authoritative checks.

- [ ] **Step 2: Live LDAP pass-the-hash**

Run a single-host LDAP-only collect with an NT hash (no password):

```
openhound collect sccm -d mayyhem.com --dc dc.mayyhem.com -u MAYYHEM\<user> --nt-hash <32-hex> -m LDAP -c <one-host> <out>
```

Expected: an `LDAP connected: ... (auth=ntlm_hash, profile=...)` log line and successful LDAP rows; no `badPwdCount` lockout, no cleartext password used.

- [ ] **Step 3: Live LDAP pass-the-ticket**

Run the same with a base64 ticket (no password/hash):

```
openhound collect sccm -d mayyhem.com --dc dc.mayyhem.com --ticket <base64-kirbi> -m LDAP -c <one-host> <out>
```

Expected: an `LDAP connected: ... (auth=kerberos, profile=...)` log line and successful LDAP rows.

- [ ] **Step 4: MSSQL ticket behavior (Windows caveat)**

Run an MSSQL-only collect with `--ticket` against a SQL host:

```
openhound collect sccm -d mayyhem.com --dc dc.mayyhem.com --ticket <base64-kirbi> -m MSSQL -c <sql-host> <out>
```

Expected on this **domain-joined Windows** host: SSPI takes precedence, so EPA is still detected (a normal verdict) and the ticket-only WARNING does **not** appear — this is by design (see the ladder-order constraint). The WARNING path is covered by the offline test `test_test_epa_warns_and_skips_when_only_ticket`. To see the WARNING live, run the same command from a non-Windows collector (or one where SSPI is unavailable); this is optional.

- [ ] **Step 5: Report results** — summarize which live checks ran, their log evidence, and any that were skipped (e.g. lab down, no Linux host for the WARNING path).

---

## Self-Review

- **Spec coverage.** ope-b7b2 names LDAP, SMB/RemoteRegistry, MSSQL, HTTP. The code dive confirmed SMB/RemoteRegistry/WMI/HTTP already fully wired and MSSQL PtH already wired; the only gaps were LDAP (Task 1) and MSSQL ticket handling (Task 2, resolved as a WARNING per owner decision). ope-272e (LDAP PtH placeholder) is closed by Task 1 / Task 3 Step 6.
- **Placeholder scan.** Every code step shows real code; every run step shows the exact command and expected output. No TBD/TODO.
- **Type consistency.** `ADCredentials` gains `nt_hash`/`kerberos_ticket` (Task 1 Step 3), forwarded onto `LdapAuth` (Step 4) and constructed with them (Step 6); tests assert `client.auth.nt_hash`/`.kerberos_ticket` and `_select_auth_modes()` outputs that match the shared `AdClient` (`["ntlm"]`/`["ntlm_hash"]`/`["kerberos"]`). `test_epa` gains `kerberos_ticket` (Task 2 Step 3), forwarded by `collect_mssql` (Step 6); tests call it with that keyword.
- **No shared-library edit.** Confirmed: the ticket is used only for a presence check in `test_epa`; it is never passed to `Auth`/`detect_epa`.
