# SOCKS5 proxy spike — offline results + live lab runbook

This document has two parts:

1. **Offline validation spike (done, this session)** — proves the three
   production libraries the SCCM collector depends on (`ldap3`, `requests`,
   `impacket`) actually open their sockets through the stdlib functions our
   process-wide interception patches, using a local recording SOCKS5 stub. No
   lab, no real proxy, no network required — see [`tests/proxy_integration_test.py`](tests/proxy_integration_test.py).
2. **Live lab runbook (not yet run — for the user)** — the real-world
   confirmation against an actual SOCKS5 pivot and a genuine mayyhem.com
   target, including a packet capture to prove there's no bypass traffic.

---

## Part 1 — Offline spike results

**Question:** the interception (`sccm`/`openhound-collector-common`'s
`openhound_collector_common.proxy` module) replaces `socket.socket`,
`socket.create_connection`, and `socket.getaddrinfo` for the life of a proxied
run. Do `ldap3`, `requests`/`urllib3`, and `impacket` actually route their
connections through those three stdlib entry points, or does any of them use
its own connection primitive (which would silently skip the tunnel), or a
resolver we don't patch (`socket.gethostbyname`), which would fail (or worse,
leak a DNS query) on an internal-only hostname before a socket is ever opened?

**Method:** `RecordingSocks5`, a minimal local SOCKS5 server, completes the
no-auth handshake and the `CONNECT` request, records the requested
`(host, port)` **as sent on the wire** (not resolved locally), replies success,
then drops the connection (it doesn't speak LDAP/HTTP/SMB — we only need to
observe the CONNECT). Each library is driven at a made-up internal hostname
(`*.internal.invalid`, guaranteed to NOT resolve on this machine) while the
proxy interception is installed. If the recorded target is the **hostname**
(not an IP), that proves two things at once: the library funneled through our
patched socket path, and it did NOT resolve the name locally first (i.e.
true socks5h behavior — the proxy would have done the DNS).

**Result: all three libraries funnel through the trio. No bypass found.**

```
$ .venv/Scripts/python -m pytest tests/proxy_integration_test.py -v

============================= test session starts =============================
platform win32 -- Python 3.14.5, pytest-9.0.3, pluggy-1.6.0
collected 3 items

tests\proxy_integration_test.py::test_ldap3_funnels_through_proxy PASSED [ 33%]
tests\proxy_integration_test.py::test_requests_funnels_through_proxy PASSED [ 66%]
tests\proxy_integration_test.py::test_impacket_smb_funnels_through_proxy PASSED [100%]

============================== 3 passed in 1.44s ==============================
```

Re-run twice; stable both times (not flaky).

| Library | Drive | Target recorded by stub | Verdict |
|---|---|---|---|
| `ldap3` | `Server("dc.internal.invalid", port=389)` + `Connection(...).open()` | `("dc.internal.invalid", 389)` | Funnels — `ldap3` opens its socket via `socket.create_connection`, which we patch. |
| `requests` | `requests.get("http://mp.internal.invalid/", timeout=3)` | `("mp.internal.invalid", 80)` | Funnels — `urllib3`'s `HTTPConnectionPool` calls `socket.create_connection`, and our `getaddrinfo` pass-through hands the raw name through instead of failing pre-resolution. |
| `impacket` | `SMBConnection("smb.internal.invalid", "smb.internal.invalid", sess_port=445)` | `("smb.internal.invalid", 445)` | Funnels — the `SMBConnection.__init__` itself opens the transport socket (no separate `.login()` needed to observe a connect attempt), via stdlib `socket.socket`/`connect`. |

**No `@pytest.mark.xfail` was needed** — nothing to document as a gap in this
offline pass.

**Scope of what this offline spike does *not* exercise** (documented honestly,
not glossed over — these are different code paths within the same libraries
that the live run below should still cover):

- **HTTPS.** The offline `requests` drive uses plain `http://` to keep the
  recording stub simple (a TLS `ClientHello` would need real cert handling to
  complete, which isn't the point of this spike). Production's AdminService /
  HTTP phase talks **HTTPS** by default (`clients/http.py`, `scheme: str =
  "https"`). `urllib3`'s `HTTPSConnectionPool` opens its raw TCP socket via the
  exact same `socket.create_connection` before layering TLS on top, so this
  should carry over identically — but it is a distinct code path we have not
  literally driven, so the live run's `-m HTTP,AdminService` pass is the real
  confirmation.
- **impacket DCOM (WMI fallback) and TDS (a separate MSSQL client, not this
  collector's own probe).** Only `SMBConnection`'s constructor was driven.
  `clients/wmi.py`'s `DCOMConnection` path (used for the WMI fallback behind
  AdminService) is a different impacket entry point and wasn't driven here.
  SCCM's own `MSSQL` phase (`collectors/mssql.py`) does **not** use impacket at
  all — it opens a plain `socket.create_connection((hostname, port))` banner
  probe directly, so it's covered by definition (same primitive already
  unit-tested elsewhere in this plan) and isn't a "does the library funnel"
  question.
- **ldap3's StartTLS / LDAPS variants** — only a plain `Connection.open()` was
  driven. The collector's LDAP port auto-detection (LDAPS:636 → StartTLS:389 →
  LDAP:389) layers TLS on top of the same underlying socket, so this should
  also carry over, but wasn't separately driven.

None of this is a known bypass — it's a description of what's left for the
live run to confirm, per the "trust but verify with a real proxy" spirit of
this task.

---

## Part 2 — Live lab runbook (deferred to the user)

### Step 1: Stand up a SOCKS5 pivot

From a box with a route into the mayyhem.com lab (or the lab's jump host
itself), open a SOCKS5 listener over SSH — no separate proxy software needed:

```bash
ssh -N -D 127.0.0.1:1080 operator@<inside-pivot-host>
```

(Any real SOCKS5 server works; the point is a **real** proxy hop, not the
unit-test stub above.)

### Step 2: Run one method at a time through the proxy

`--collection-methods`/`-m` takes a **comma-separated** list (not repeated
flags — see `openhound collect sccm --help`), so a single command with a
comma-separated method list is equivalent to repeating the command per method,
but the run-per-method form below makes it easy to isolate which protocol's
proxy log entry corresponds to which run. `--proxy` (`-x`) requires `--dc` or
`--dns` (an internal-name pin — the collector cannot resolve mayyhem.com names
locally once the proxy is up), and credentials come from `debug_epa_matrix.py`
(don't hardcode them here).

```bash
# LDAP discovery + a single host, everything forced through the proxy:
uv run openhound collect sccm ./out \
  -d mayyhem.com --dc dc.mayyhem.com \
  -u <user> -p <password> \
  -c ps1-mp.mayyhem.com --threads 1 \
  --proxy socks5://127.0.0.1:1080 -m LDAP -v

# Repeat with -m SMB, -m HTTP, -m AdminService, -m MSSQL (or combine as
# -m LDAP,SMB,HTTP,AdminService,MSSQL for a single run once each is confirmed
# individually):
uv run openhound collect sccm ./out \
  -d mayyhem.com --dc dc.mayyhem.com \
  -u <user> -p <password> \
  -c ps1-mp.mayyhem.com --threads 1 \
  --proxy socks5://127.0.0.1:1080 -m SMB -v
```

Use `ps1-sms.mayyhem.com` as the `-c` target for the AdminService/HTTP
methods (per the lab notes: it's the live AdminService — 200 when the SMS
Provider is up; an empty 500 is a transient post-boot warm-up; it's often
powered off, so check port 443 first).

### Step 3: Confirm no DNS leak

```bash
uv run openhound collect sccm ./out \
  -d mayyhem.com --dns <internal-resolver-ip> \
  -c ps1-mp.mayyhem.com --threads 1 \
  --proxy socks5://127.0.0.1:1080 -m LDAP -v
```

### What to verify at each step

- **Rows collected** — the run produces the expected JSONL output for the
  method under test (not a silent empty/failed collection).
- **The proxy's own connection log shows the target `host:port`** — e.g. SSH's
  `-v` output, or a purpose-built SOCKS5 logger, showing a `CONNECT` to
  `ps1-mp.mayyhem.com:<port>` (or `ps1-sms.mayyhem.com:<port>`) for each method.
- **A packet capture on the outside box's real NIC** (the interface facing the
  lab network directly, not the loopback the proxy listens on) shows traffic
  **only** to `127.0.0.1:1080` — no direct connection from the outside box to
  any target IP, and **no UDP/53** (DNS) leaving that NIC at all. This is the
  proof that neither a bypassed library nor an un-patched resolver leaked
  traffic or a hostname outside the tunnel.

### Offline-spike summary to carry into the live run

All three libraries (`ldap3`, `requests`, `impacket`) were proven offline to
funnel through the process-wide `socket.socket` / `create_connection` /
`getaddrinfo` interception, using an internal-only hostname each — see Part 1
above and `tests/proxy_integration_test.py`. No bypass was found; nothing was
marked `xfail`. The live run's job is to confirm the same holds for the code
paths the offline spike didn't reach (HTTPS, DCOM, LDAPS/StartTLS — see the
"Scope" list in Part 1) and, per the original plan, to capture proof (proxy
log + packet capture) that a *real* proxy hop is being used end to end, not
just that the stdlib call sites are reached.
