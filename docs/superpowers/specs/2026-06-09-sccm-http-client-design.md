# Design: Shared HTTP client for AdminService and HTTP collectors

- **Date:** 2026-06-09
- **Status:** **Approved (not yet implemented).** Brainstorming complete; all branches resolved with the project owner. Plan: _to be written next (`writing-plans`)._ Nothing committed (per project owner).
- **Scope of change:** `sccm/sccm` only. No edits to OpenHound, impacket, or requests source.

## 1. Goal

Build a single, reusable HTTP client that two upcoming per-host collectors share:

- **AdminService** ([ope-b287]) — queries the SCCM AdminService REST API
  (`https://<smsprovider>/AdminService/wmi/...`), which authenticates with
  Microsoft **Negotiate** (SPNEGO). Many paginated `GET`s per target.
- **HTTP** ([ope-9d62]) — probes management-point / distribution-point
  endpoints (`/SMS_MP/.sms_aut?MPLIST`, `?SMSTRC`, `/SMS_DP_SMSPKG$`) and
  classifies roles by **unauthenticated** status code, then identifies whether
  a **PKI client certificate** is required.

`ConfigManBearPig.ps1` authenticates to AdminService only as the current Windows
user (`Invoke-WebRequest -UseDefaultCredentials`,
[ConfigManBearPig.ps1:6898](../../../../ConfigManBearPig.ps1)) and does its HTTP
probing unauthenticated (`Invoke-HttpRequest`,
[ConfigManBearPig.ps1:1151](../../../../ConfigManBearPig.ps1)). This client
**deliberately exceeds** the PS1: it supports passwordless current-user auth,
Kerberos and NTLM with explicit credentials/NT-hash/ticket, and anonymous
requests, behind one ladder — bringing HTTP auth in line with what already
exists for LDAP ([clients/ad.py](../../../src/openhound_sccm/clients/ad.py)) and
SMB ([clients/smb_sso.py](../../../src/openhound_sccm/clients/smb_sso.py)).

## 2. Decisions (resolved during brainstorming)

| Decision | Choice |
|---|---|
| **Auth precedence** | Explicit creds win → current-user SSPI → anonymous. Matches `smb_sso.py` / `ad.py` / `mssql_epa.py` (the `http.py` stub's "SSPI first" is rejected). |
| **Auth engine** | **impacket** mints Kerberos AP-REQ (from password, NT-hash-as-RC4-key, or base64 ticket) and NTLM type-1/3 (password or hash); **pywin32 SSPI** drives the passwordless current-user path. Hand-driven over a `requests` session — mirrors `smb_sso.py`. (`pyspnego` and `requests-*` plugins rejected: neither cleanly does Kerberos-from-NT-hash + ticket injection.) |
| **Auth mode is caller-chosen** | The client takes an explicit `AuthMode`: `NEGOTIATE` (run the ladder) or `NONE` (never send `Authorization`). AdminService → `NEGOTIATE`; HTTP probe → `NONE`. Auth is **never** implicit-when-available. |
| **Credential plumbing** | Full end-to-end: new `--nt-hash` and `--ticket` CLI flags + env mappings; new `SourceContext.kerberos_ticket` field (`nt_hash` already exists); client reads all creds from `SourceContext`. |
| **PKI detection boundary** | Client returns a structured result (status code + error classification). The **collector** maps SCCM-specific 403s to `ClientCertificateRequired`. No client-cert *presentation* (only *identification* of the requirement). |
| **Module split** | `clients/http.py` (transport) + `clients/http_auth.py` (Negotiate token engine + ladder), per `source-collection.md`'s "dedicated auth.py when auth is complex". |

### Locked assumptions

- **Kerberos SPN:** `HTTP/<target-fqdn>`. If `target` is a bare IP with no
  reverse DNS, **Kerberos is skipped** (no SPN can be formed) and the ladder
  proceeds to NTLM/SSPI — same lockout-safe pattern as `ad.py`.
- **KDC:** the already-resolved `--dc` / `ctx.domain_controller`. **No new
  `--kdc` flag.**
- **Kerberos → NTLM fallback** fires only on *protocol* failures (no SPN, clock
  skew, KDC unreachable), **not** on a clean credential rejection — mirroring
  `ad.py`'s "don't keep poking after a credential-class failure" rule. A bare
  ticket has **no** NTLM fallback (a ticket cannot produce an NTLM token).
- **`--nt-hash`** takes a **bare** NT hash (matching the existing
  `SourceContext.nt_hash`); normalized internally to impacket's `LM:NT` form via
  the empty-LM-hash convention already used in
  [mssql_epa.py:`_format_hashes`](../../../src/openhound_sccm/clients/mssql_epa.py).
- **`--ticket`** takes a **base64-encoded KRB-CRED (`.kirbi`)** blob
  (Rubeus/offensive-tooling convention), loaded via impacket's ccache/kirbi
  reader.
- **TLS:** `verify=False` by default (matches PS1's `TrustAllCertsPolicy`,
  [ConfigManBearPig.ps1:10232](../../../../ConfigManBearPig.ps1)); urllib3
  `InsecureRequestWarning` suppressed.
- **No AES-key input** (not requested).
- **No client-certificate presentation** (not requested).

## 3. Architecture

### 3.1 New module: `src/openhound_sccm/clients/http_auth.py`

The Negotiate token engine + ladder selection, isolated from transport (mirrors
how `smb_sso.py` isolates the SSPI handshake). Surface:

1. **`sspi_negotiate_available() -> bool`** — capability gate; `True` only on
   Windows with `sspi` / `sspicon` importable. Evaluated once at import, like
   `smb_sso._SSPI_NEGOTIATE_AVAILABLE`.

2. **`AuthMode`** — enum: `NEGOTIATE`, `NONE`.

3. **`choose_auth(...) -> AuthPlan`** — the **pure** ladder-selection function
   (inputs: username, password, nt_hash, ticket, target-host, sspi_available;
   output: an ordered list of rungs to attempt, e.g.
   `["kerberos", "ntlm"]` / `["sspi"]` / `["anonymous"]`). Pure → unit-tested
   with no network, exactly like `mssql_epa._choose_auth` / `determine_epa`.

4. **`negotiate_token(...)`** — given a chosen rung and (optionally) the
   server's previous token, return the next `Authorization: Negotiate <b64>`
   value and a `done` flag:
   - **kerberos** — impacket builds a TGT then a service ticket for
     `HTTP/<fqdn>` from password / NT-hash (RC4) / AES, or uses the supplied
     base64 KRB-CRED, then wraps the AP-REQ in SPNEGO.
   - **ntlm** — impacket `getNTLMSSPType1` / `getNTLMSSPType3` from password or
     `LM:NT` hash (two-leg; the second leg consumes the server challenge).
   - **sspi** — a `_SSPINegotiateClient` over `sspi.ClientAuth("Negotiate",
     targetspn="HTTP/<fqdn>")`, stepped with the server token, mirroring
     `smb_sso._SSPINegotiateClient`.

### 3.2 New module: `src/openhound_sccm/clients/http.py`

Transport only. Owns one `requests.Session` per client and the request/response
result shape. Surface:

```python
class ErrorClass(enum.Enum):
    RESPONSE = "response"          # an HTTP response was received (ANY status —
                                   #   200/401/403/404/5xx are all signals, not errors)
    CONNECT_FAILURE = "connect"    # dead socket / DNS / refused / timeout
    TLS_FAILURE = "tls"            # secure-channel / handshake error

@dataclass
class HttpResult:
    status_code: int | None        # set whenever error_class is RESPONSE; else None
    content: bytes | None
    error_class: ErrorClass

class HttpClient:
    @classmethod
    def from_context(cls, ctx, target, *, auth: AuthMode,
                     scheme: str = "https", timeout: int = 5) -> "HttpClient": ...
    def get(self, path_or_url: str) -> HttpResult: ...
    def close(self) -> None: ...
```

- **`from_context`** reads `domain`, `username`, `password`, `nt_hash`,
  `kerberos_ticket`, and `domain_controller` (→ KDC) from `SourceContext`, so
  collectors do not re-plumb credentials.
- One **keep-alive** `requests.Session`: NTLM is connection-oriented, so the
  token exchange must ride the same TCP connection; AdminService's paginated
  `GET`s reuse the authenticated connection.
- **`get`** runs the Negotiate handshake lazily on the first authenticated
  request (§4), then reuses the connection. In `AuthMode.NONE` it never sends
  `Authorization` — a plain `GET` whose status the HTTP collector reads.

### 3.3 Consumers (this work wires the client; collectors land in their own tickets)

- **AdminService** ([ope-b287]) constructs `HttpClient.from_context(ctx, target,
  auth=NEGOTIATE)` (HTTPS).
- **HTTP** ([ope-9d62]) constructs `HttpClient.from_context(ctx, target,
  auth=NONE)`, tries `http` then `https` (PS1 order,
  [ConfigManBearPig.ps1:8637](../../../../ConfigManBearPig.ps1)), and maps a
  `403` on `?SMSTRC` / `SMS_DP_SMSPKG$` to `ClientCertificateRequired`
  ([ConfigManBearPig.ps1:8671](../../../../ConfigManBearPig.ps1)).

> These collectors are out of scope here; this spec covers only the shared
> client + its credential wiring. The collector tickets reuse the client.

## 4. Core mechanism: HTTP Negotiate handshake

`HttpClient.get`, in `NEGOTIATE` mode, performs the standard SPNEGO header dance
over the keep-alive session:

1. Send the request with no `Authorization`.
2. If the response is `401` with `WWW-Authenticate: Negotiate`, consult the
   `AuthPlan` from `choose_auth(...)` and take the first rung.
3. Build the token via `negotiate_token(rung, server_token=None)`; resend with
   `Authorization: Negotiate <b64>`.
4. While the server replies `401` with a continuation token (NTLM's second
   leg), feed it back through `negotiate_token(...)` and resend on the **same
   connection**.
5. On a non-401 response, return it as an `HttpResult`. On a rung failure that
   is a *protocol* failure (not a credential rejection), advance to the next
   rung in the plan (Kerberos → NTLM); on a credential rejection, stop.

Kerberos typically completes in one authenticated request; NTLM in two.

## 5. Credential & CLI wiring (full end-to-end)

- **`SourceContext`** ([context.py](../../../src/openhound_sccm/context.py))
  gains `kerberos_ticket: str | None = None` beside the existing `nt_hash`.
- **`main.py`** ([main.py](../../../src/openhound_sccm/main.py)):
  - `collect_sccm` gains `--nt-hash` and `--ticket` options.
  - `_FLAG_TO_ENV` gains `nt_hash → SOURCES__SCCM__NT_HASH` and
    `kerberos_ticket → SOURCES__SCCM__KERBEROS_TICKET`.
  - `--nt-hash` / `--ticket` added to `_LONG_OPTIONS_WITH_VALUES`, and to
    `_SENSITIVE_OPTIONS` so they are redacted in suspicious-arg warnings.
  - The DLT `source(...)` factory ([source.py](../../../src/openhound_sccm/source.py))
    resolves the two new secrets and passes them into the `SourceContext`.
- **README** ([README.md](../../../README.md)) — **Command Line Options** gains
  the two flags and a short auth-methods note, with a copy-pasteable
  `mayyhem.com` example.

## 6. Capability gating & cross-platform behavior

- `sspi_negotiate_available()` returns `False` off Windows or when `sspi` /
  `sspicon` are absent; the ladder then has no SSPI rung (explicit creds or
  anonymous only).
- `pywin32` and `impacket` are already dependencies
  ([pyproject.toml:28,32](../../../pyproject.toml)). **`requests` is added as a
  direct dependency** (today only transitive via dlt).

## 7. Error handling

- `requests` exceptions are caught in `get` and classified into `ErrorClass`:
  `ConnectionError` / `Timeout` → `CONNECT_FAILURE`; `SSLError` → `TLS_FAILURE`;
  any received HTTP response → `RESPONSE` (its `status_code` carried verbatim,
  whatever it is). This is the richer analogue of PS1's `IsConnectionFailure`
  ([ConfigManBearPig.ps1:1196](../../../../ConfigManBearPig.ps1)) — note `SSLError`
  is split out from `CONNECT_FAILURE` because a TLS failure on an HTTPS SCCM
  endpoint is itself a (secondary) PKI signal the collector may weigh.
- Auth-rung failures: a *protocol* failure advances the ladder; a *credential*
  rejection stops it and surfaces the `401`/`403` to the caller. No password or
  hash is logged. Kerberos lockout concerns do not apply (no password is sent in
  the SSPI/ticket paths).

## 8. Logging / observability

Per the project logging rule, every ladder rung and every `error_class` branch
logs at the right level: `verbose` for "trying rung X via Negotiate", `info` for
the chosen mechanism, `warning` on auth failure, `debug` for per-request traces
— mirroring `ad.py`'s clear per-attempt auth logging. Credentials/tokens are
never logged.

## 9. Testing & validation

- **Unit tests** (cross-platform, SSPI/impacket mocked): `choose_auth` selects
  the right rung order for every credential/capability/target-shape combination
  (incl. IP-target → no Kerberos); `HttpResult` classification maps each
  `requests` exception to the right `ErrorClass`; the 401→token→resend loop with
  a mocked session. These are pure-seam tests like `mssql_epa`'s.
- **Integration test** (Windows + live host, opt-in/skipped otherwise): real
  Negotiate against the lab AdminService on a SpecterOps/`mayyhem.com` SMS
  provider, asserting an authenticated `200` and a parseable body.
- **Validation commands** (isolated uv env, per `validate-extension.md`):
  `UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest`,
  `uv run ruff check src/`, `uv run mypy src/`.

## 10. Out of scope

- The AdminService ([ope-b287]) and HTTP ([ope-9d62]) collectors themselves —
  they reuse this client when they land.
- Wiring `--nt-hash` / `--ticket` into the LDAP / MSSQL / SMB auth paths (global
  pass-the-hash is tracked separately by [ope-272e]); this work only consumes
  them in the HTTP client.
- AES-key Kerberos input and client-certificate *presentation*.
- Changes to OpenHound, impacket, or requests source.

[ope-b287]: AdminService per-host collector
[ope-9d62]: HTTP per-host collector
[ope-272e]: LDAP pass-the-hash (--nt-hash) support — placeholder
