# Design: SSPI Single Sign-On for impacket SMB authentication

- **Date:** 2026-06-04
- **Status:** **Implemented** — `clients/smb_sso.py` built and the Remote Registry probe wired to it; 16 unit tests green; mechanism validated end-to-end against the live host ps1-pss.mayyhem.com (SMB 3.1.1, signing-required). Live integration test (`tests/test_smb_sso_integration.py`) is opt-in. Nothing committed (per project owner). Plan: [../plans/2026-06-04-impacket-sspi-smb-sso.md](../plans/2026-06-04-impacket-sspi-smb-sso.md)
- **Scope of change:** `sccm/sccm` only. No edits to OpenHound or to impacket source.

## 1. Goal

Let the SCCM collector's impacket-based per-host phases authenticate to remote
hosts as the **current logged-in Windows user**, with no explicit password,
using Windows SSPI — exactly the way native Windows tools (and
`ConfigManBearPig.ps1`) authenticate. Today the only impacket consumer is the
Remote Registry probe ([collectors/registry.py](../../../src/openhound_sccm/collectors/registry.py)),
whose no-credentials path falls back to an anonymous **null session** that
cannot bind Remote Registry. After this change, the no-credentials path uses
SSPI Single Sign-On (SSO) instead.

This brings impacket auth in line with what already exists for LDAP in
[clients/ad.py](../../../src/openhound_sccm/clients/ad.py), which uses the
current user's Kerberos ticket (via `winkerberos`) with a current-user NTLM
fallback (via pywin32 `sspi.ClientAuth`).

## 2. Decisions (resolved during brainstorming)

| Decision | Choice |
|---|---|
| **Scope** | Build a reusable helper; wire the Remote Registry probe as the first consumer. Future impacket phases (MSSQL, WMI, SMB, AdminService) reuse it. |
| **Mechanism** | SSPI **Negotiate** (SPNEGO): Kerberos-preferred with automatic NTLM fallback, like native Windows SMB. |
| **Integration** | A **single SSPI Negotiate security context** driving a **custom SMB2 SESSION_SETUP loop**, built **on top of** impacket's public API — no impacket source edits, no runtime monkeypatching. |
| **Helper API** | A high-level `connect_smb(...)` that owns the whole auth ladder and returns an authenticated `SMBConnection`. |
| **SSO trigger** | SSO engages whenever a **complete** explicit credential pair (username *and* password) is **not** supplied — so username-without-password also uses SSO (matches `ad.py`). |
| **On SSPI failure** | **Give up on the host**: log and return no connection (probe yields nothing). No null-session retry after a real authentication attempt. |

### Locked assumptions

- **Target SPN:** `cifs/<hostname-as-given>`. Bare-IP or SPN-less targets get
  NTLM automatically via Negotiate's fallback — no separate code path.
- **No new CLI flag:** SSO is implicit (the absence of complete creds), mirroring `ad.py`.
- **Cross-platform:** on non-Windows, or when the SSPI Python modules are not
  importable, the existing null-session behavior is preserved as the last resort.
- **Validation:** real authentication is validated against the lab host
  `ps1-pss.mayyhem.com` and via [debug_per_host.py](../../../debug_per_host.py).

## 3. Architecture

### 3.1 New module: `src/openhound_sccm/clients/smb_sso.py`

Lives beside `ad.py` (the auth-client home), mirroring its proven structure:

1. **`sspi_negotiate_available() -> bool`** — capability gate. Returns `True`
   only on Windows with `sspi` / `sspicon` importable. Mirrors `ad.py`'s
   `_current_user_ntlm_available()`. Evaluated once at import.

2. **`class _SSPINegotiateClient`** — thin wrapper over
   `sspi.ClientAuth("Negotiate", targetspn="cifs/<host>")`, mirroring
   `ad.py`'s `_SSPICurrentUserNtlmClient`. Surface:
   - `step(server_token: bytes | None) -> tuple[bytes, bool]` — feed the
     server's previous token (or `None` to start), return `(our_token,
     done)`. `done` is `True` when SSPI reports `SEC_E_OK`.
   - `session_key() -> bytes` — after completion, the negotiated session key
     from `QueryContextAttributes(SECPKG_ATTR_SESSION_KEY)`.
   - (optional) `mechanism() -> str` — "Kerberos" or "NTLM" for logging, from
     `SECPKG_ATTR_NEGOTIATION_INFO` if cheaply available.

3. **`smb_login_sspi(smb_connection, target_spn) -> None`** — drives the SMB2
   SESSION_SETUP exchange against an already-negotiated `SMBConnection` using
   the `_SSPINegotiateClient`, then installs the session/signing keys. See §4.

4. **`connect_smb(hostname, domain, username, password, *, timeout=5) -> SMBConnection | None`**
   — the high-level entry point that owns the auth ladder (§3.3) and returns an
   authenticated connection (or `None` on failure). This is what consumers call.

### 3.2 Consumer change: the Remote Registry probe

`_RegistryProbe.__enter__` ([registry.py:62-110](../../../src/openhound_sccm/collectors/registry.py))
keeps its fast TCP/445 reachability probe and its winreg DCE/RPC bind. Only the
SMB connect+login block ([registry.py:80-90](../../../src/openhound_sccm/collectors/registry.py))
changes: instead of building an `SMBConnection` and calling `smb.login(...)`
directly, it calls `connect_smb(self.hostname, self.domain, self.username,
self.password)` and uses the returned connection. The probe owns nothing about
*how* auth happens.

### 3.3 The auth ladder (owned by `connect_smb`)

In precedence order:

1. **Complete explicit creds** (username **and** password present) →
   `SMBConnection.login(user, password, domain)` (today's explicit path,
   unchanged).
2. **Incomplete creds + SSPI available** (`sspi_negotiate_available()` is
   `True`) → `smb_login_sspi(...)` as the current user.
3. **SSPI unavailable** (non-Windows / modules missing) → `smb.login("", "",
   domain)` null session (today's last resort, preserved).

A failure at the chosen rung is logged and yields `None` — there is no
fall-through to a lower rung after an authentication attempt (per the
"give up on the host" decision). The TCP/445 reachability check stays in the
registry probe and runs before `connect_smb`.

## 4. Core mechanism: SSPI Negotiate over SMB2 SESSION_SETUP

`smb_login_sspi` reproduces what `impacket.smb3.SMB3.login`
([smb3.py:953-1155](../../../.venv/Lib/site-packages/impacket/smb3.py)) does
internally, but sources the security tokens from SSPI instead of impacket's
NTLM, using only public API:

1. Obtain the underlying `SMB3` object via `smb_connection.getSMBServer()`
   ([smbconnection.py:212](../../../.venv/Lib/site-packages/impacket/smbconnection.py)).
2. `_SSPINegotiateClient.step(None)` → first SPNEGO token (SSPI emits a
   complete SPNEGO blob; we do **not** wrap it in impacket's `SPNEGO_NegTokenInit`).
3. Place the token in an `SMB2SessionSetup` packet (`impacket.smb3structs`),
   send via `SMB3.sendSMB` / receive via `SMB3.recvSMB`.
4. Loop while the server returns `STATUS_MORE_PROCESSING_REQUIRED`: extract the
   server's response token from the SESSION_SETUP response buffer, feed it to
   `step(...)`, send the next token. (Kerberos typically completes in one round
   trip; NTLM in two.)
5. On `STATUS_SUCCESS`, record `_Session['SessionID']` and install keys (§5).

### 5. Session key and SMB signing

SMB signing/encryption keys derive from the negotiated **session key**. After
the handshake:

- Read the session key from `_SSPINegotiateClient.session_key()`.
- Set `_Session['SessionKey']` on the `SMB3` object.
- Derive the dialect-specific subkeys (`SigningKey`, `ApplicationKey`,
  `EncryptionKey`, `DecryptionKey`) using impacket's **public**
  `impacket.crypto.KDF_CounterMode` with the SMB-spec labels, matching the
  derivation block in `SMB3.login` ([smb3.py:1083-1140](../../../.venv/Lib/site-packages/impacket/smb3.py)).
  Labels/inputs are fixed by the SMB protocol spec (stable across impacket
  versions); only the dialect branch selects between them.

### Known coupling / wrinkles (drive the plan + tests)

- **SMB 3.1.1 pre-auth integrity hash.** For dialect 3.1.1, impacket updates a
  running pre-auth hash on each SESSION_SETUP message
  (`__UpdatePreAuthHash`, [smb3.py:1012-1013](../../../.venv/Lib/site-packages/impacket/smb3.py)),
  and the signing-key derivation depends on it. Our loop must update the same
  state. This is the deepest coupling to impacket internals (a name-mangled
  private method / private `_Session` field) and the highest-risk part of the
  implementation; it must be covered by an integration test against a
  signing-required host.
- **Private `_Session` access.** We read/write impacket's private `_Session`
  dict. This survives `pip` upgrades but not internal redesigns — mitigated by
  pinning impacket and an integration test that fails loudly on drift.

### Validated corrections (from the live spike)

A throwaway spike ran the full mechanism against `ps1-pss.mayyhem.com` and
proved it after three fixes, all folded into the implementation plan:

1. **Finalize the SSPI context.** Kerberos completes in one SESSION_SETUP leg,
   but the SSPI context is not complete until the server's final token (AP-REP,
   carried in the STATUS_SUCCESS response) is fed back via one more
   `authorize(...)`. Without this, `QueryContextAttributes(SECPKG_ATTR_SESSION_KEY)`
   fails with "function not supported."
2. **16-byte session key.** SSPI returns the full 32-byte Kerberos AES256 key;
   MS-SMB2 3.2.5.3.1 uses only the first 16 bytes (zero-padded if shorter) for
   key derivation. Using all 32 yields a bad signing key → `STATUS_ACCESS_DENIED`.
3. **Pre-auth-hash ordering.** impacket's `sendSMB` folds each SESSION_SETUP
   *request* into the 3.1.1 pre-auth hash automatically. We must fold **only
   intermediate** responses and **never** the final success response — matching
   impacket's `login()`. (One-leg Kerberos makes this bite immediately.)

## 6. Capability gating & cross-platform behavior

- `sspi_negotiate_available()` returns `False` off Windows or when `sspi`/
  `sspicon` are absent; `connect_smb` then uses the null-session rung.
- `pywin32` and `winkerberos` are already dependencies, guarded by
  `sys_platform == 'win32'` ([pyproject.toml:24-28](../../../pyproject.toml));
  no new dependency is required.

## 7. Error handling

- SSPI handshake errors, KDC/ticket errors, and `STATUS_*` auth failures from
  the server are caught in `connect_smb`, logged at an appropriate level
  (parity with the probe's existing `logger.verbose` connection traces), and
  result in `connect_smb` returning `None`. The registry probe treats `None`
  exactly as it treats today's failed connect (logs "could not connect", yields
  nothing).
- No password is ever transmitted in the SSO path, so account-lockout concerns
  (which drive `ad.py`'s elaborate bind-error classification) do not apply.

## 8. Logging / observability

`connect_smb` logs which rung it took ("SMB auth: current user via SSPI
Negotiate", "SMB auth: explicit NTLM as <user>", "SMB auth: null session"),
mirroring `ad.py`'s clear per-attempt auth logging. When cheaply available, log
the negotiated mechanism (Kerberos vs NTLM).

## 9. Testing & validation

- **Unit tests** (cross-platform, SSPI mocked): the `connect_smb` auth ladder
  (each rung selected for the right credential/capability combination), the
  "give up on failure" behavior, and SPN construction. SSPI and `SMBConnection`
  are mocked so the decision logic runs anywhere.
- **Integration test** (Windows + live host, opt-in/skipped otherwise): real
  SSPI Negotiate login against `ps1-pss.mayyhem.com`, asserting a usable
  authenticated session and that **signed** SMB requests succeed (covers the
  3.1.1 pre-auth-hash + key-derivation path). Manual repro via
  [debug_per_host.py](../../../debug_per_host.py).
- **Validation commands** (isolated uv env, per `validate-extension.md`):
  `uv run pytest`, `uv run ruff check src/`, `uv run mypy src/` with
  `UV_PROJECT_ENVIRONMENT` set outside the repo.

## 10. Out of scope

- Wiring SSPI auth into MSSQL / WMI / SMB / AdminService phases (they do not
  exist yet; they reuse `connect_smb` when they land).
- Linux/macOS integrated auth (Kerberos via `gssapi`) for impacket.
- Any new CLI flag or `extension.yaml` parameter.
- Changes to OpenHound or impacket source.
