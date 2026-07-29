# SOCKS5 Proxy for ALL SCCM Collection Traffic — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `--socks-proxy` route *every* piece of SCCM collection traffic — discovery (LDAP/DNS/DC) and all five per-host protocols — through a SOCKS5 pivot, using the shared `openhound-collector-common` library.

**Architecture:** The operator runs the tool on an *outside* box with no direct route into the target network; a SOCKS5 pivot on an *inside* box is the only egress. We install a **process-wide socket interception** (built around the shared lib's existing hand-rolled `connect_through_socks5` dialer) for the duration of a `collect` run. Every library that opens a normal Python TCP socket — `ldap3`, `impacket`, `requests`/`urllib3`, `dnspython`-over-TCP, the raw SMB probe — is transparently tunneled with no per-call changes. DNS is forced onto TCP so it, too, rides the tunnel; destination names are resolved *at the proxy* (`socks5h`). Auth that Windows/Linux performs natively (current-user SSPI, OS-Kerberos to the KDC) physically cannot be captured from our process and is documented as requiring OS-level transparent proxying; the in-process credential toolkit (explicit `-u/-p`, `--nt-hash` pass-the-hash, `--ticket` pass-the-ticket, impacket-minted Kerberos+NTLM) is tunneled in full, KDC traffic included.

**Tech Stack:** Python 3.14, stdlib `socket`/`struct`/`contextlib`/`contextvars`, `dnspython`, `ldap3`, `impacket`, `requests`, `typer`, `pytest`. No new third-party dependency (the shared dialer is deliberately stdlib-only; we do **not** adopt PySocks).

## Global Constraints

- Modify only `sccm/sccm/` and `openhound-collector-common/`. Never edit `openhound/` core. (Shared-lib edits are explicitly authorized for this work.)
- The shared SOCKS dialer stays **stdlib-only** — no PySocks, no new third-party dep. Reuse `connect_through_socks5` / the RFC-1928/1929 handshake already in `openhound_collector_common/proxy/socks.py`.
- The socket interception is **install-once-per-process** and must **restore the originals** in a `finally`. The existing collect pipeline already assumes "one collect run per process" (see [ARCHITECTURE.md §1 trade-offs]); this reuses that assumption. Mirror the existing `extract_workers_for(...)` context-manager pattern in `openhound_collector_common.dlt.source_bridge`.
- **socks5h semantics:** destination hostnames are sent to the proxy for resolution; we never resolve a *target* name on the outside box.
- **No traffic may leak outside the tunnel while a proxy is active** — that includes DNS. Forcing dnspython to TCP and removing stdlib `getaddrinfo`/`gethostbyname` for target names is a correctness/OPSEC requirement, not an optimization.
- Loopback (`127.0.0.0/8`, `::1`) and the proxy's own endpoint are **never** re-proxied (recursion/deadlock guard).
- Logging rule (CLAUDE.md): every `if/else` and `try/except` gets a log line of the right level (error/warning/info/verbose/debug) unless genuinely unnecessary, in which case leave a comment.
- Property/name casing rules are unaffected (no new nodes/edges here).
- Tests live under the package's `tests/` directory, organized; shared-lib tests under `openhound-collector-common/tests/`. Do **not** `git add`/`commit` — the user commits after testing.
- Docs must stay true to the code (README is code-truth for the CLI surface with status markers).

---

## File Structure

**Shared library (`openhound-collector-common/`):**
- `src/openhound_collector_common/proxy/socks.py` — **modify**: extract a public `socks5_handshake(sock, proxy, dest_host, dest_port)` from `connect_through_socks5` so the interception layer can run the handshake on an already-open socket without duplicating the RFC code.
- `src/openhound_collector_common/proxy/patch.py` — **create**: the process-wide interception (`_ProxiedSocket`, `create_connection`, `getaddrinfo` pass-through), module-level active-proxy state (`active_proxy`), `install`/`uninstall`, and the `socks_proxy_installed(...)` context manager.
- `src/openhound_collector_common/proxy/__init__.py` — **modify**: export the new symbols.
- `src/openhound_collector_common/discovery/dns.py` — **modify**: make `make_resolver(force_tcp=True)` actually force TCP (currently only logs); this is the fix noted in the CLAUDE.md context.
- `README.md` — **modify**: document the proxy module + DNS force-TCP knob.
- `tests/test_socks_patch.py` — **create**: install/teardown, recursion/loopback guard, end-to-end through a local SOCKS5 stub server.
- `tests/test_dns_force_tcp.py` — **create**: `make_resolver(force_tcp=True)` passes `tcp=True` to `resolve`.

**SCCM extension (`sccm/sccm/`):**
- `src/openhound_sccm/main.py` — **modify**: parse `ProxyConfig`, validate `--dc`/`--dns` requirement, fix `--socks-proxy` help text, install the proxy context manager around Stage 1 + Stage 2, force-TCP the DC-discovery lookup.
- `src/openhound_sccm/collectors/dns.py` — **modify**: force-TCP the MP `SRV` lookup and replace the stdlib `_resolve_v4` with a proxy-aware resolve.
- `src/openhound_sccm/context.py` — **modify**: make `resolve_ip` proxy-aware (force TCP, drop `gethostbyname`).
- `README.md` — **modify**: fix the wrong `--socks-proxy` row; add a "Proxying / pivoting" subsection.
- `ARCHITECTURE.md` — **modify**: new divergence section + changelog + quick-reference row.
- `tests/proxy_wiring_test.py` — **create**: parse + `--dc`/`--dns` validation + install-around-run wiring (offline).
- `tests/proxy_dns_test.py` — **create**: the four DNS sites force TCP / don't call stdlib resolvers when a proxy is active.

---

## Task 1: Shared lib — extract a reusable SOCKS5 handshake

**Files:**
- Modify: `openhound-collector-common/src/openhound_collector_common/proxy/socks.py`
- Test: `openhound-collector-common/tests/test_socks.py` (extend)

**Interfaces:**
- Produces: `socks5_handshake(sock: socket.socket, proxy: ProxyConfig, dest_host: str, dest_port: int) -> None` — runs the RFC-1928 greeting/auth + `CONNECT` on an **already-connected-to-the-proxy** socket, leaving it positioned at the tunneled stream. Raises `SocksError` on failure.
- `connect_through_socks5(...)` keeps its current signature/behavior (now delegates to `socks5_handshake`).

- [ ] **Step 1: Write the failing test** (extend `tests/test_socks.py`)

```python
def test_socks5_handshake_is_public_and_reuses_connect_path():
    # socks5_handshake must be importable and callable on a bare socket.
    from openhound_collector_common.proxy.socks import socks5_handshake
    assert callable(socks5_handshake)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_socks.py::test_socks5_handshake_is_public_and_reuses_connect_path -v`
Expected: FAIL with `ImportError: cannot import name 'socks5_handshake'`

- [ ] **Step 3: Refactor `socks.py` to expose the handshake**

In `connect_through_socks5`, replace the two private calls with one public call, and add the public function just above it:

```python
def socks5_handshake(
    sock: socket.socket,
    proxy: ProxyConfig,
    dest_host: str,
    dest_port: int,
) -> None:
    """Run the SOCKS5 greeting/auth + CONNECT on an already-open socket.

    *sock* must already be connected to the proxy endpoint. On return it is a
    live tunnel to ``(dest_host, dest_port)``. Raises :class:`SocksError` on any
    protocol failure (the caller owns closing the socket).
    """
    _socks5_negotiate_auth(sock, proxy)
    _socks5_connect(sock, dest_host, dest_port)
```

Then in `connect_through_socks5`, swap the body of the `try`:

```python
    sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    try:
        socks5_handshake(sock, proxy, dest_host, dest_port)
    except Exception:
        # Never leak the socket if the handshake fails part-way through.
        sock.close()
        raise
```

Add `"socks5_handshake"` to `__all__`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_socks.py -v`
Expected: PASS (all existing parse tests + the new import test)

- [ ] **Step 5: Commit**

```bash
git add openhound-collector-common/src/openhound_collector_common/proxy/socks.py openhound-collector-common/tests/test_socks.py
git commit -m "refactor(proxy): extract public socks5_handshake for socket reuse"
```

---

## Task 2: Shared lib — the process-wide socket interception

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/proxy/patch.py`
- Test: `openhound-collector-common/tests/test_socks_patch.py`

**Interfaces:**
- Consumes: `ProxyConfig`, `socks5_handshake` (Task 1).
- Produces:
  - `active_proxy() -> Optional[ProxyConfig]` — the currently-installed proxy, or `None`.
  - `install(proxy: ProxyConfig) -> None` / `uninstall() -> None`.
  - `socks_proxy_installed(proxy: Optional[ProxyConfig])` — context manager; a `None`/falsey proxy is a no-op pass-through (so callers can wrap unconditionally).

- [ ] **Step 1: Write the failing test** (`tests/test_socks_patch.py`)

Concrete tests, including a tiny in-process SOCKS5 CONNECT stub so the end-to-end path is exercised without a real proxy:

```python
"""Tests for the process-wide SOCKS5 socket interception."""
import socket
import threading

import pytest

from openhound_collector_common.proxy import (
    ProxyConfig,
    active_proxy,
    socks_proxy_installed,
)


class _Socks5EchoStub:
    """Minimal no-auth SOCKS5 CONNECT server that echoes bytes after CONNECT.

    Speaks just enough of RFC 1928 to complete the handshake, then loops
    reading and echoing so a test can prove data flows through the tunnel.
    """

    def __init__(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.host, self.port = self._srv.getsockname()
        self.saw_domain = None  # the CONNECT target name, for socks5h assertions
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        conn, _ = self._srv.accept()
        with conn:
            # greeting: VER, NMETHODS, METHODS...
            ver, nmethods = conn.recv(2)
            conn.recv(nmethods)
            conn.sendall(bytes([0x05, 0x00]))  # no-auth selected
            # request: VER, CMD, RSV, ATYP, ADDR, PORT
            head = conn.recv(4)
            atyp = head[3]
            if atyp == 0x03:  # DOMAINNAME
                length = conn.recv(1)[0]
                self.saw_domain = conn.recv(length).decode()
            elif atyp == 0x01:
                conn.recv(4)
            else:
                conn.recv(16)
            conn.recv(2)  # port
            # reply: success, bound 0.0.0.0:0
            conn.sendall(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)

    def close(self):
        self._srv.close()


@pytest.fixture
def stub():
    s = _Socks5EchoStub()
    yield s
    s.close()


def test_context_manager_installs_and_restores(stub):
    orig_socket = socket.socket
    orig_create = socket.create_connection
    orig_getaddr = socket.getaddrinfo
    proxy = ProxyConfig(host=stub.host, port=stub.port)
    with socks_proxy_installed(proxy):
        assert active_proxy() == proxy
        assert socket.socket is not orig_socket  # hook installed
    # everything restored on exit
    assert active_proxy() is None
    assert socket.socket is orig_socket
    assert socket.create_connection is orig_create
    assert socket.getaddrinfo is orig_getaddr


def test_none_proxy_is_passthrough():
    orig_socket = socket.socket
    with socks_proxy_installed(None):
        assert active_proxy() is None
        assert socket.socket is orig_socket  # nothing installed


def test_traffic_flows_through_proxy_by_name(stub):
    # Connecting to an unresolvable internal name must succeed via the proxy
    # (socks5h): the name is sent to the proxy, never resolved locally.
    proxy = ProxyConfig(host=stub.host, port=stub.port)
    with socks_proxy_installed(proxy):
        sock = socket.create_connection(("server01.internal.invalid", 445), timeout=5)
        try:
            sock.sendall(b"ping")
            assert sock.recv(4) == b"ping"
        finally:
            sock.close()
    assert stub.saw_domain == "server01.internal.invalid"


def test_loopback_is_not_proxied(stub):
    # A loopback target must bypass the proxy entirely (guard against
    # re-proxying local/dlt traffic and against proxy self-recursion).
    echo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo.bind(("127.0.0.1", 0))
    echo.listen(1)
    port = echo.getsockname()[1]
    accepted = {}

    def _accept():
        c, _ = echo.accept()
        accepted["peer"] = True
        c.close()

    threading.Thread(target=_accept, daemon=True).start()
    proxy = ProxyConfig(host=stub.host, port=stub.port)
    with socks_proxy_installed(proxy):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.close()
    echo.close()
    assert accepted.get("peer") is True
    assert stub.saw_domain is None  # proxy never saw the loopback connect
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_socks_patch.py -v`
Expected: FAIL with `ImportError` (no `patch`/`active_proxy`/`socks_proxy_installed`).

- [ ] **Step 3: Implement `proxy/patch.py`**

```python
# New module (no SCCM equivalent). Installs a process-wide SOCKS5 interception
# so every stdlib-socket-based client (ldap3, impacket, requests/urllib3,
# dnspython-over-TCP, raw probes) tunnels through the proxy with no per-call
# changes. Ports the INTENT of the Go MSSQLHound proxydialer, generalized from
# "one TDS dial" to "all in-process TCP", because the SCCM collector speaks five
# protocols across four libraries.
"""Process-wide SOCKS5 socket interception for OpenHound collectors.

`install(proxy)` swaps three things on the stdlib ``socket`` module:

- ``socket.socket``          -> :class:`_ProxiedSocket` (a subclass whose
  ``connect`` runs the SOCKS5 handshake to the destination).
- ``socket.create_connection`` -> :func:`create_connection` (passes the raw
  hostname to the proxy — never resolves a target name locally).
- ``socket.getaddrinfo``     -> :func:`getaddrinfo` (a pass-through that returns
  the hostname unresolved, so libraries that pre-resolve — e.g. urllib3 — hand
  the name to ``connect`` for socks5h resolution instead of failing on an
  internal-only name).

Loopback targets and the proxy endpoint itself are never proxied (recursion /
local-traffic guard). `uninstall()` restores the originals; prefer the
:func:`socks_proxy_installed` context manager so restore is guaranteed.

This is install-once-per-process: the collect pipeline already assumes a single
run per process. Not reentrant.
"""
from __future__ import annotations

import ipaddress
import logging
import socket as _socket
from contextlib import contextmanager
from typing import Iterator, Optional

from .socks import ProxyConfig, socks5_handshake

logger = logging.getLogger(__name__)

# The originals, captured at import so repeated install/uninstall can't stack.
_ORIG_SOCKET = _socket.socket
_ORIG_CREATE_CONNECTION = _socket.create_connection
_ORIG_GETADDRINFO = _socket.getaddrinfo

_ACTIVE: Optional[ProxyConfig] = None


def active_proxy() -> Optional[ProxyConfig]:
    """Return the currently-installed proxy, or None when direct."""
    return _ACTIVE


def _is_local(host: str) -> bool:
    """True if *host* is loopback (never proxied) — guards recursion/local dlt."""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # A name: treat only the literal localhost as local. Everything else is
        # a target that must go through the proxy (resolved at the proxy).
        return host == "localhost"


def _bypass(host: str) -> bool:
    """True if a connection to *host* must NOT be proxied."""
    if _ACTIVE is None:
        return True  # no proxy installed — never intercept
    if host == _ACTIVE.host:
        return True  # the proxy's own endpoint (recursion guard)
    if _is_local(host):
        logger.debug("_bypass: %s is local; connecting direct", host)
        return True
    return False


class _ProxiedSocket(_ORIG_SOCKET):  # type: ignore[misc,valid-type]
    """A socket whose ``connect`` tunnels through the active SOCKS5 proxy."""

    def connect(self, address):  # noqa: D401 - stdlib override
        host = address[0]
        port = address[1]
        if _bypass(host):
            return super().connect(address)
        proxy = _ACTIVE
        # Connect to the proxy with the *real* connect (super), then hand the
        # destination NAME to the proxy so it resolves (socks5h).
        logger.debug("_ProxiedSocket.connect: tunneling to %s:%s via %s:%s",
                     host, port, proxy.host, proxy.port)
        super().connect((proxy.host, proxy.port))
        socks5_handshake(self, proxy, host, port)


def create_connection(address, timeout=_socket._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None):
    """Proxy-aware replacement for ``socket.create_connection``.

    For proxied targets we build a :class:`_ProxiedSocket` and connect by name
    (no local getaddrinfo). For bypassed targets we defer to the original.
    """
    host = address[0]
    if _bypass(host):
        return _ORIG_CREATE_CONNECTION(address, timeout, source_address)
    sock = _ProxiedSocket(_socket.AF_INET, _socket.SOCK_STREAM)
    if timeout is not _socket._GLOBAL_DEFAULT_TIMEOUT:
        sock.settimeout(timeout)
    if source_address is not None:
        sock.bind(source_address)
    sock.connect(address)  # runs the SOCKS handshake
    return sock


def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Pass-through resolver used while a proxy is active.

    Returns the hostname UNresolved so callers that pre-resolve (urllib3) hand
    the name to ``connect`` for socks5h resolution. Loopback/bypassed hosts are
    resolved for real so local traffic is unaffected.
    """
    if _bypass(host):
        return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)
    logger.debug("getaddrinfo: deferring resolution of %s to the proxy", host)
    st = type or _socket.SOCK_STREAM
    return [(_socket.AF_INET, st, proto, "", (host, port or 0))]


def install(proxy: ProxyConfig) -> None:
    """Install the process-wide interception for *proxy*."""
    global _ACTIVE
    if _ACTIVE is not None:
        # Not reentrant — a second install would stack wrappers. Fail loud.
        logger.error("install: a proxy (%s:%s) is already active", _ACTIVE.host, _ACTIVE.port)
        raise RuntimeError("SOCKS proxy already installed; uninstall first")
    _ACTIVE = proxy
    _socket.socket = _ProxiedSocket
    _socket.create_connection = create_connection
    _socket.getaddrinfo = getaddrinfo
    logger.info("SOCKS5 proxy installed: all TCP now tunnels via %s:%s", proxy.host, proxy.port)


def uninstall() -> None:
    """Restore the original socket functions."""
    global _ACTIVE
    _socket.socket = _ORIG_SOCKET
    _socket.create_connection = _ORIG_CREATE_CONNECTION
    _socket.getaddrinfo = _ORIG_GETADDRINFO
    if _ACTIVE is not None:
        logger.info("SOCKS5 proxy uninstalled (was %s:%s)", _ACTIVE.host, _ACTIVE.port)
    _ACTIVE = None


@contextmanager
def socks_proxy_installed(proxy: Optional[ProxyConfig]) -> Iterator[None]:
    """Install *proxy* for the duration of the block, then restore.

    A falsey *proxy* is a pass-through no-op, so callers can wrap a run
    unconditionally: ``with socks_proxy_installed(maybe_proxy): ...``.
    """
    if not proxy:
        logger.debug("socks_proxy_installed: no proxy; running direct")
        yield
        return
    install(proxy)
    try:
        yield
    finally:
        uninstall()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_socks_patch.py -v`
Expected: PASS (install/restore, none-passthrough, by-name tunnel with `saw_domain` assertion, loopback bypass).

- [ ] **Step 5: Commit**

```bash
git add openhound-collector-common/src/openhound_collector_common/proxy/patch.py openhound-collector-common/tests/test_socks_patch.py
git commit -m "feat(proxy): process-wide SOCKS5 socket interception"
```

---

## Task 3: Shared lib — force-TCP DNS + exports

**Files:**
- Modify: `openhound-collector-common/src/openhound_collector_common/discovery/dns.py`
- Modify: `openhound-collector-common/src/openhound_collector_common/proxy/__init__.py`
- Test: `openhound-collector-common/tests/test_dns_force_tcp.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `make_resolver(..., force_tcp=True)` now makes **every** `resolver.resolve(...)` call default to `tcp=True`. `proxy` package exports `active_proxy`, `install`, `uninstall`, `socks_proxy_installed`.

- [ ] **Step 1: Write the failing test** (`tests/test_dns_force_tcp.py`)

```python
"""make_resolver(force_tcp=True) must actually force TCP on resolve()."""
from openhound_collector_common.discovery.dns import make_resolver


def test_force_tcp_defaults_resolve_to_tcp(monkeypatch):
    import dns.resolver
    seen = {}

    def _fake_resolve(self, qname, rdtype=None, *args, **kwargs):
        seen["tcp"] = kwargs.get("tcp")
        return []

    # Patch the CLASS method BEFORE make_resolver runs, so make_resolver's
    # wrapper captures this fake as its _orig_resolve bound method.
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve, raising=True)
    resolver = make_resolver("10.0.0.1", force_tcp=True)
    resolver.resolve("_ldap._tcp.example.com", "SRV")
    assert seen["tcp"] is True


def test_force_tcp_bare_resolve_forwards_without_rdtype(monkeypatch):
    import dns.resolver
    seen = {}

    def _fake_resolve(self, qname, *args, **kwargs):
        seen["args"] = args
        seen["tcp"] = kwargs.get("tcp")
        return []

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve, raising=True)
    resolver = make_resolver("10.0.0.1", force_tcp=True)
    resolver.resolve("example.com")  # no rdtype — wrapper must NOT inject rdtype=None
    assert seen["tcp"] is True
    assert seen["args"] == ()


def test_no_force_tcp_leaves_resolve_untouched():
    resolver = make_resolver("10.0.0.1", force_tcp=False)
    # No wrapper: resolve is the class method, not a per-instance closure.
    assert "resolve" not in resolver.__dict__
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_dns_force_tcp.py -v`
Expected: FAIL (`test_force_tcp_defaults_resolve_to_tcp` — `seen["tcp"]` is `None`, because the current `force_tcp` branch only logs).

- [ ] **Step 3: Make `force_tcp` real** (replace the `if force_tcp:` block in `make_resolver`)

```python
    if force_tcp:
        # SOCKS5 (our dialer) can't carry UDP, so proxied DNS must use TCP.
        # dnspython takes tcp per-call, so wrap resolve() to default it on.
        # Mirrors the Go SetProxyDialer rebuild that forces "tcp".
        _orig_resolve = resolver.resolve

        def _resolve_tcp(qname, *args, **kwargs):
            # Pure forward — do NOT give rdtype a default here. dnspython's real
            # default is A; injecting rdtype=None would raise TypeError on the
            # common bare `.resolve(name)` call shape.
            kwargs.setdefault("tcp", True)
            return _orig_resolve(qname, *args, **kwargs)

        resolver.resolve = _resolve_tcp  # per-instance override
        logger.debug("make_resolver: forcing DNS over TCP (proxy mode)")
```

Also guard the stdlib fallback in `_domain_resolves` so a proxied resolver never leaks a local `getaddrinfo` (add an early return when the caller passed a force-tcp resolver). Detect it via the per-instance override:

```python
def _domain_resolves(domain: str, resolver: dns.resolver.Resolver) -> bool:
    ...
    # (existing dnspython attempt unchanged)
    ...
    if "resolve" in resolver.__dict__:
        # force_tcp resolver (proxy mode): do NOT fall back to a local
        # getaddrinfo — that would resolve on the outside box and leak.
        logger.debug("_domain_resolves: proxy mode; skipping stdlib fallback for %s", domain)
        return False
    try:
        socket.getaddrinfo(domain, None)
        return True
    except (socket.gaierror, OSError) as exc:
        logger.debug("_domain_resolves: stdlib getaddrinfo for %s failed: %s", domain, exc)
        return False
```

- [ ] **Step 4: Export proxy symbols** (`proxy/__init__.py`)

```python
from .patch import (
    active_proxy,
    install,
    socks_proxy_installed,
    uninstall,
)
from .socks import (
    ProxyConfig,
    SocksError,
    connect_through_socks5,
    parse_proxy_address,
    socks5_handshake,
)

__all__ = [
    "ProxyConfig",
    "SocksError",
    "connect_through_socks5",
    "parse_proxy_address",
    "socks5_handshake",
    "active_proxy",
    "install",
    "uninstall",
    "socks_proxy_installed",
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_dns_force_tcp.py tests/test_socks.py tests/test_socks_patch.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add openhound-collector-common/src/openhound_collector_common/discovery/dns.py openhound-collector-common/src/openhound_collector_common/proxy/__init__.py openhound-collector-common/tests/test_dns_force_tcp.py
git commit -m "feat(dns): make force_tcp real; export proxy interception"
```

---

## Task 4: SCCM — parse the proxy, validate `--dc`/`--dns`, fix help text

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (help text at :950; add validation in the `try` body after `_require_domain_or_explain`, ~:1001)
- Modify: `sccm/sccm/src/openhound_sccm/source.py` (drop the dead `socks_proxy` param plumbing OR keep for env parity — see step 3)
- Test: `sccm/sccm/tests/proxy_wiring_test.py`

**Interfaces:**
- Consumes: `parse_proxy_address` (shared).
- Produces: `_parse_proxy_or_exit(socks_proxy: Optional[str]) -> Optional[ProxyConfig]` and `_require_dc_or_dns_for_proxy(flag_kwargs: dict, proxy: Optional[ProxyConfig]) -> None` in `main.py`. Both raise `typer.Exit(2)` on misconfiguration.

- [ ] **Step 1: Write the failing test** (`tests/proxy_wiring_test.py`)

```python
"""Offline tests for --socks-proxy parsing and --dc/--dns validation."""
import pytest
import typer

from openhound_sccm.main import _parse_proxy_or_exit, _require_dc_or_dns_for_proxy


def test_parse_bare_host_port():
    cfg = _parse_proxy_or_exit("10.2.10.254:1080")
    assert (cfg.host, cfg.port) == ("10.2.10.254", 1080)


def test_parse_none_returns_none():
    assert _parse_proxy_or_exit(None) is None


def test_bad_proxy_string_exits():
    with pytest.raises(typer.Exit):
        _parse_proxy_or_exit("http://nope:3128")  # non-socks scheme


def test_proxy_requires_dc_or_dns():
    cfg = _parse_proxy_or_exit("10.2.10.254:1080")
    with pytest.raises(typer.Exit):
        _require_dc_or_dns_for_proxy({"domain_controller": None, "dns_resolver": None}, cfg)


def test_proxy_ok_with_dc():
    cfg = _parse_proxy_or_exit("10.2.10.254:1080")
    # Should not raise when --dc is present.
    _require_dc_or_dns_for_proxy({"domain_controller": "dc.mayyhem.com", "dns_resolver": None}, cfg)


def test_no_proxy_skips_validation():
    _require_dc_or_dns_for_proxy({"domain_controller": None, "dns_resolver": None}, None)
```

- [ ] **Step 2: Run test to verify it fails**

Run (SCCM venv): `.venv/Scripts/python -m pytest tests/proxy_wiring_test.py -v`
Expected: FAIL with `ImportError` (functions don't exist).

- [ ] **Step 3: Implement in `main.py`**

Fix the help text (line ~950):

```python
    socks_proxy: Optional[str] = typer.Option(
        None, "--socks-proxy",
        help="Route ALL collection traffic through a SOCKS5 proxy. Forms: "
             "socks5://[user:pass@]host:port or bare host:port. Requires --dc "
             "or --dns (internal names can't be resolved locally under a pivot).",
    ),
```

Add the helpers (near the other `_*` CLI helpers):

```python
def _parse_proxy_or_exit(socks_proxy: Optional[str]) -> Optional["ProxyConfig"]:
    """Parse --socks-proxy into a ProxyConfig, or exit(2) with a clear error."""
    from openhound_collector_common.proxy import ProxyConfig, SocksError, parse_proxy_address
    if not socks_proxy:
        return None
    try:
        cfg = parse_proxy_address(socks_proxy)
        logger.info("SOCKS5 proxy configured: %s:%s", cfg.host, cfg.port)
        return cfg
    except SocksError as ex:
        logger.error("Invalid --socks-proxy value %r: %s", socks_proxy, ex)
        raise typer.Exit(2)


def _require_dc_or_dns_for_proxy(flag_kwargs: dict, proxy: Optional["ProxyConfig"]) -> None:
    """Under a proxy, we can't resolve internal names locally, so demand a pin."""
    if proxy is None:
        return  # direct mode: nothing to enforce
    if flag_kwargs.get("domain_controller") or flag_kwargs.get("dns_resolver"):
        logger.debug("_require_dc_or_dns_for_proxy: DC/DNS pin present; ok")
        return
    logger.error(
        "--socks-proxy requires --dc <ip/host> or --dns <internal-resolver-ip>: "
        "target names can't be resolved from the outside box under a pivot."
    )
    raise typer.Exit(2)
```

Wire them into the `try` body, right after `_require_domain_or_explain(flag_kwargs)` (~:1001):

```python
        proxy_cfg = _parse_proxy_or_exit(flag_kwargs.get("socks_proxy"))
        _require_dc_or_dns_for_proxy(flag_kwargs, proxy_cfg)
```

(Keep the top-of-file `from openhound_collector_common.proxy import ProxyConfig` under `TYPE_CHECKING` for the annotation; runtime imports stay inside the helpers to preserve current import-time behavior.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/proxy_wiring_test.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sccm/sccm/src/openhound_sccm/main.py sccm/sccm/tests/proxy_wiring_test.py
git commit -m "feat(sccm): parse --socks-proxy and require --dc/--dns under a pivot"
```

---

## Task 5: SCCM — install the proxy around the collect run

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (`collect_sccm`, wrap Stage 1 + Stage 2)
- Test: `sccm/sccm/tests/proxy_wiring_test.py` (extend)

**Interfaces:**
- Consumes: `socks_proxy_installed` (shared), `proxy_cfg` (Task 4).
- Produces: the socket interception is active for the entire discovery + per-host collection window and torn down afterward.

- [ ] **Step 1: Write the failing test** (extend `tests/proxy_wiring_test.py`)

```python
def test_active_proxy_scoped_to_run(monkeypatch):
    # Prove the collect body runs inside socks_proxy_installed by checking
    # active_proxy() is set during a stubbed run and cleared after.
    from openhound_collector_common.proxy import active_proxy, ProxyConfig
    from openhound_sccm import main as m

    seen = {}

    def fake_run_body(proxy):
        # Simulate the wrapped region.
        from openhound_collector_common.proxy import socks_proxy_installed
        with socks_proxy_installed(proxy):
            seen["during"] = active_proxy()

    fake_run_body(ProxyConfig(host="10.2.10.254", port=1080))
    assert seen["during"] == ProxyConfig(host="10.2.10.254", port=1080)
    assert active_proxy() is None
```

(This test guards the pattern; the wiring itself is verified live in Task 7.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/proxy_wiring_test.py::test_active_proxy_scoped_to_run -v`
Expected: PASS trivially only after import wiring exists; if `socks_proxy_installed` import path is wrong it FAILS with ImportError.

- [ ] **Step 3: Wrap the run** in `collect_sccm`

Import at top of `main.py`:

```python
from openhound_collector_common.proxy import socks_proxy_installed
```

Wrap Stage 1 + Stage 2. The cleanest single wrap point encloses from the source build through the per-host stage (lines ~1022–1052). Change:

```python
        src = sccm_source()
        ...
        per_host_counts = _run_per_host_stage(...)
```

to:

```python
        with socks_proxy_installed(proxy_cfg):
            src = sccm_source()
            if not src:
                set_shared_queue(None)
                set_shared_ad_cache(None)
                set_shared_discovered_domains(None)
                return None
            per_host_ctx = get_last_ctx()
            load_info = collector.run(src.with_resources(*DISCOVERY_RESOURCE_NAMES))
            discovery_counts = _normalize_row_counts(load_info.pipeline) if load_info else {}
            if per_host_ctx is not None:
                for host in _cli_seed_targets(computers, computer_file):
                    per_host_ctx.register_target(host, source="CLI")
            per_host_counts = {}
            per_host_expected = bool(per_host_ctx is not None and PER_HOST_PHASES)
            if per_host_expected:
                per_host_counts = _run_per_host_stage(collector.pipeline, work_queue, per_host_ctx, threads)
```

(The summary logging and cache-clearing stay after the `with` block — they touch no network.)

- [ ] **Step 4: Run the full offline suite**

Run: `.venv/Scripts/python -m pytest tests/proxy_wiring_test.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sccm/sccm/src/openhound_sccm/main.py sccm/sccm/tests/proxy_wiring_test.py
git commit -m "feat(sccm): install SOCKS5 interception around the collect run"
```

---

## Task 6: SCCM — make the four DNS/name-resolution sites proxy-aware

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (`_resolve_dc_via_dns`, ~:527-530)
- Modify: `sccm/sccm/src/openhound_sccm/collectors/dns.py` (`SRV` resolve ~:76; `_resolve_v4` ~:207-215)
- Modify: `sccm/sccm/src/openhound_sccm/context.py` (`resolve_ip` ~:138-154)
- Test: `sccm/sccm/tests/proxy_dns_test.py`

**Interfaces:**
- Consumes: `active_proxy` (shared), `make_resolver(force_tcp=...)` (shared).
- Produces: when a proxy is active, all four sites resolve via dnspython-over-TCP (through the tunnel) and never call stdlib `getaddrinfo`/`gethostbyname`.

- [ ] **Step 1: Write the failing test** (`tests/proxy_dns_test.py`)

```python
"""Under a proxy, name resolution must use dnspython/TCP, never stdlib."""
import socket

import pytest

from openhound_collector_common.proxy import ProxyConfig, socks_proxy_installed


def test_resolve_v4_does_not_use_stdlib_under_proxy(monkeypatch):
    from openhound_sccm.collectors import dns as dnsmod

    def _boom(*a, **k):
        raise AssertionError("stdlib getaddrinfo must not be called under a proxy")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    called = {}
    monkeypatch.setattr(dnsmod, "_resolve_v4_via_dns", lambda host: called.setdefault("host", host) or "10.0.0.9")
    with socks_proxy_installed(ProxyConfig(host="127.0.0.1", port=9)):
        assert dnsmod._resolve_v4("mp.internal.invalid") == "10.0.0.9"
    assert called["host"] == "mp.internal.invalid"


def test_resolve_ip_uses_force_tcp_resolver_under_proxy(monkeypatch):
    from openhound_sccm.context import SourceContext
    # Build a minimal context; resolve_ip only needs dns_resolver.
    ctx = SourceContext.__new__(SourceContext)
    ctx.dns_resolver = "10.0.0.1"
    seen = {}
    import openhound_collector_common.discovery.dns as sdns

    real_make = sdns.make_resolver

    def _spy(server_ip=None, **kw):
        seen["force_tcp"] = kw.get("force_tcp")
        return real_make(server_ip, **kw)

    monkeypatch.setattr("openhound_sccm.context.make_resolver", _spy, raising=False)
    with socks_proxy_installed(ProxyConfig(host="127.0.0.1", port=9)):
        try:
            ctx.resolve_ip("10.0.0.5")  # may fail to resolve; we only assert the knob
        except Exception:
            pass
    assert seen.get("force_tcp") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/proxy_dns_test.py -v`
Expected: FAIL (`_resolve_v4_via_dns` / proxy-aware `resolve_ip` don't exist yet).

- [ ] **Step 3: Edit the four sites**

**`main.py` `_resolve_dc_via_dns`** (~:527-530) — build the resolver force-tcp under a proxy:

```python
        from openhound_collector_common.discovery.dns import make_resolver
        from openhound_collector_common.proxy import active_proxy

        resolver = make_resolver(dns_resolver, lifetime=5, force_tcp=active_proxy() is not None)
        answers = resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
```

**`collectors/dns.py`** — the `SRV` resolver at ~:76 must also be force-tcp under a proxy. Wherever that `resolver` is built, pass `force_tcp=active_proxy() is not None` (import `active_proxy` and `make_resolver` at top). Then replace `_resolve_v4`:

```python
def _resolve_v4_via_dns(host: str) -> Optional[str]:
    """Resolve *host* to an IPv4 via dnspython (honors proxy force-TCP)."""
    from openhound_collector_common.discovery.dns import make_resolver
    from openhound_collector_common.proxy import active_proxy
    try:
        resolver = make_resolver(force_tcp=active_proxy() is not None)
        answer = resolver.resolve(host, "A")
        return answer[0].to_text()
    except Exception as ex:
        logger.debug("_resolve_v4_via_dns: %s did not resolve: %s", host, ex)
        return None


def _resolve_v4(host: str) -> Optional[str]:
    """Resolve a hostname to its first IPv4 address, or None.

    Under a proxy we must not touch the local stdlib resolver (leak + can't see
    internal names), so route through dnspython/TCP; otherwise keep the fast
    stdlib path.
    """
    from openhound_collector_common.proxy import active_proxy
    if active_proxy() is not None:
        return _resolve_v4_via_dns(host)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except (socket.gaierror, OSError) as ex:
        logger.debug("_resolve_v4: stdlib getaddrinfo for %s failed: %s", host, ex)
    return None
```

**`context.py` `resolve_ip`** (~:138-154) — route through `make_resolver`, force-tcp under a proxy, drop `gethostbyname`:

```python
    def resolve_ip(self, ip: str) -> Optional[str]:
        """Resolve a name/IP using the configured DNS resolver (proxy-aware)."""
        from openhound_collector_common.discovery.dns import make_resolver
        from openhound_collector_common.proxy import active_proxy
        proxied = active_proxy() is not None
        try:
            if self.dns_resolver or proxied:
                resolver = make_resolver(self.dns_resolver, force_tcp=proxied)
                answer = resolver.resolve(ip)
                return answer[0].to_text()
            # Direct mode, no explicit resolver: stdlib is fine.
            import socket
            return socket.gethostbyname(ip)
        except Exception as ex:
            logger.warning("DNS resolution failed for %s: %s", ip, ex)
            return None
```

Add `from openhound_collector_common.discovery.dns import make_resolver` near the top of `context.py` so the `_spy` monkeypatch in the test can target `openhound_sccm.context.make_resolver` (adjust the import in `resolve_ip` to use the module-level name).

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/proxy_dns_test.py -v`
Expected: PASS.

- [ ] **Step 5: Run the existing DNS collector tests to catch regressions**

Run: `.venv/Scripts/python -m pytest tests/ -k "dns" -v`
Expected: PASS (no regression in direct-mode resolution).

- [ ] **Step 6: Commit**

```bash
git add sccm/sccm/src/openhound_sccm/main.py sccm/sccm/src/openhound_sccm/collectors/dns.py sccm/sccm/src/openhound_sccm/context.py sccm/sccm/tests/proxy_dns_test.py
git commit -m "feat(sccm): proxy-aware DNS (force TCP, no local resolver leak)"
```

---

## Task 7: Live validation spike — verify per-protocol coverage against a real SOCKS5 proxy

**Files:**
- Create: `sccm/sccm/spike_socks_proxy.md` (a lab runbook; not shipped code)

**Why a task:** the interception is proven in unit tests against a stub, but the *real* question is whether each production library (`ldap3`, `impacket` SMB/DCOM/TDS, `requests`/`urllib3`) actually funnels through `socket.socket`/`create_connection`/`getaddrinfo` as assumed. This task discovers any library that bypasses the trio and, if found, adds the targeted fix (contingency below). Per the openhound `validate-extension` reference, behavior changes must be validated live.

- [ ] **Step 1: Stand up a local SOCKS5 proxy to the lab**

On a box with a route to the lab (or the lab jump host), open a SOCKS5 listener. Simplest:

```bash
ssh -N -D 127.0.0.1:1080 operator@<inside-pivot-host>
```

(Or any SOCKS5 server. The point is a real proxy, not the unit-test stub.)

- [ ] **Step 2: Run a single-host, single-method collect through the proxy per protocol**

For each method, confirm collection succeeds *and* capture proxy-side logs to prove traffic egressed there (never from the outside box). Use the lab creds from `debug_epa_matrix.py`.

```bash
# LDAP discovery + a single host, forcing everything through the proxy:
.venv/Scripts/python -m openhound_sccm.main collect ./out \
  -d mayyhem.com --dc dc.mayyhem.com \
  -u <user> -p <pass> \
  -c ps1-mp.mayyhem.com --threads 1 \
  --socks-proxy socks5://127.0.0.1:1080 -m LDAP

# Repeat -m for: SMB, HTTP, AdminService (impacket WMI fallback), MSSQL
```

Expected per run: rows collected; the proxy's connection log shows the target host:port; a packet capture on the outside box's real interface shows **no** direct traffic to target IPs (only to 127.0.0.1:1080).

- [ ] **Step 3: Confirm no DNS leak**

Run a collect with `--dns <internal-resolver>` and only an internal-only name as target; confirm it resolves (via the tunnel) and that a capture shows no UDP/53 leaving the outside box.

- [ ] **Step 4: If any protocol bypasses the trio — apply the contingency**

- **`requests`/`urllib3` HTTPS fails on internal names:** if urllib3's connection pool doesn't honor the `getaddrinfo` pass-through in this version, mount a proxy-aware `HTTPAdapter` on `HttpClient._session` (in `clients/http.py`) whose `init_poolmanager` uses a connection class that dials via `connect_through_socks5`. Gate it on `active_proxy()`.
- **`impacket` DCOM second connection or TDS opens its own socket by IP:** confirm the host arg passed to `SMBConnection`/`DCOMConnection`/`MSSQL` is a **name** (so socks5h applies); if impacket pre-resolves to an IP internally via `socket.gethostbyname`, that call is caught by the trio (it's stdlib) — verify. If a raw `socket.socket().connect((ip, port))` slips through with a pre-resolved IP, that still tunnels (connect-by-IP works through SOCKS `CONNECT`); only *name resolution* would have leaked, which the trio prevents.

Document findings and any code delta in the runbook; if a code fix was needed, fold it back as a new TDD sub-task before Task 8.

- [ ] **Step 5: Commit the runbook (and any contingency code)**

```bash
git add sccm/sccm/spike_socks_proxy.md
git commit -m "test(sccm): live SOCKS5 proxy validation runbook + findings"
```

---

## Task 8: Docs — README, ARCHITECTURE.md, and the corrected `--help`

**Files:**
- Modify: `sccm/sccm/README.md` (the `--socks-proxy` row ~:405; add a "Proxying / pivoting" subsection)
- Modify: `sccm/sccm/ARCHITECTURE.md` (new divergence section + quick-reference row + changelog)
- (help text already fixed in Task 4)

- [ ] **Step 1: Fix the README command-line row**

Replace the misleading row:

```markdown
| `--socks-proxy` | Route **all** collection traffic (discovery + every per-host protocol) through a SOCKS5 proxy. Forms: `socks5://[user:pass@]host:port` or bare `host:port`. Requires `--dc` or `--dns`. See [Proxying / pivoting](#proxying--pivoting). |
```

- [ ] **Step 2: Add a "Proxying / pivoting" subsection** (under Command Line Options)

Cover, with a copy-pasteable mayyhem.com example:
- What tunnels automatically (all in-process auth: `-u/-p`, `--nt-hash`, `--ticket`, impacket Kerberos+NTLM incl. KDC).
- The boundary: live current-user SSPI / OS-Kerberos can't be tunneled from the process; use OS-level transparent proxying (tun2socks/Proxifier) **or** the pass-the-ticket bridge (export the logged-in user's TGT, pass `--ticket`).
- Why `--dc`/`--dns` is required (no local resolution of internal names).
- DNS is forced to TCP through the tunnel.

Example block:

```markdown
### Proxying / pivoting

Run the collector on an outside box and tunnel **everything** through a SOCKS5
pivot inside the target network:

    openhound-sccm collect ./out \
      -d mayyhem.com --dc dc.mayyhem.com \
      -u lowpriv -p 'Password123!' \
      --socks-proxy socks5://127.0.0.1:1080

All discovery (LDAP/DNS/DC) and every per-host protocol (RemoteRegistry, MSSQL,
AdminService, WMI, HTTP, SMB) egress at the proxy. Destination names resolve at
the proxy (socks5h); DNS is forced onto TCP.

**Authentication through a pivot.** Explicit creds, pass-the-hash (`--nt-hash`)
and pass-the-ticket (`--ticket`) tunnel completely — including the Kerberos KDC
exchange, which impacket performs in-process. **Current-user single-sign-on
(SSPI) cannot be tunneled by the tool**: Windows itself contacts the KDC, and
that traffic never touches our sockets. To use a logged-in identity through the
pivot, export its Kerberos ticket and pass `--ticket`, or set up OS-level
transparent proxying (tun2socks/Proxifier) on the outside box.

`--dc` or `--dns` is **required** with `--socks-proxy`: internal names can't be
resolved from the outside box.
```

- [ ] **Step 3: Add the ARCHITECTURE.md divergence section**

New section (e.g. `## 13. Tunneling all collection traffic through a SOCKS5 pivot`) following the standard spine (framework baseline → why it breaks → the add-on → trade-offs), plus:
- a row in the "Quick reference: which framework extension point each add-on uses" table (extension point: *runtime mutation of stdlib `socket`*),
- a row in the shared-library "Where this code lives" table (`proxy/patch.py` + `proxy/socks.py` shared; SCCM keeps the CLI parse/validate + the install wrap + the four proxy-aware DNS sites),
- a changelog entry dated 2026-07-17.

Note explicitly: the interception mutates **stdlib** `socket` (not a framework object), and the native-auth / UDP boundaries are documented limits, not bugs.

- [ ] **Step 4: Verify docs match code**

Re-read the `--socks-proxy` help string, the README row, and the ARCHITECTURE section against the implemented flags. Grep for any remaining "DHCP/TFTP" references and remove them:

Run: `rg -n "DHCP/TFTP" sccm/sccm/`
Expected: no matches in README/help (only historical `.sdd/` snapshots may remain).

- [ ] **Step 5: Commit**

```bash
git add sccm/sccm/README.md sccm/sccm/ARCHITECTURE.md
git commit -m "docs(sccm): document SOCKS5 pivot; fix wrong --socks-proxy help/README"
```

---

## Task 9: Follow-up — MSSQL sibling ticket

**Files:** none (ticket only).

The proxy machinery now lives in the shared library, so the MSSQL collector can wire the same flag cheaply — but that's the MSSQL agent's job (extension separation: SCCM agents don't edit `mssql/mssql/`).

- [ ] **Step 1: Create a ticket** for the MSSQL agent

```bash
gtk create --status requested "Wire --socks-proxy in MSSQL collector via shared proxy interception"
```

Body: point at `openhound_collector_common.proxy.socks_proxy_installed`, this plan, and note that MSSQLHound's Go origin already had a proxydialer (TDS only) — the shared interception now covers TDS + LDAP + its EPA probe in one wrap. Same `--dc`/`--dns` and native-auth caveats apply.

- [ ] **Step 2: Commit** — n/a (tickets are tracked files; the user commits).

---

## Validation Summary (run before declaring done)

Per the openhound `validate-extension` reference, in an isolated venv:

```bash
# Shared library
cd openhound-collector-common && uv run pytest && uv run ruff check src/ && uv run mypy src/

# SCCM extension (offline suite)
cd sccm/sccm && .venv/Scripts/python -m pytest tests/proxy_wiring_test.py tests/proxy_dns_test.py -v
.venv/Scripts/python -m ruff check src/
.venv/Scripts/python -m mypy src/openhound_sccm/main.py src/openhound_sccm/context.py src/openhound_sccm/collectors/dns.py
```

Plus the **live** Task 7 spike against a real proxy (report skipped if the lab is unavailable, per the reference's guidance on unavailable external services).

## Self-Review notes (author)

- **Spec coverage:** scope=everything (Tasks 5/6), strategy=global interception in shared lib (Tasks 2/3), native-auth boundary kept + documented (Task 8), `--dc`/`--dns` requirement + force-TCP DNS (Tasks 4/6). All four locked decisions map to tasks.
- **Type consistency:** `active_proxy()`, `socks_proxy_installed()`, `ProxyConfig`, `make_resolver(force_tcp=)`, `socks5_handshake()`, `_parse_proxy_or_exit()`, `_require_dc_or_dns_for_proxy()` are used with identical names/signatures across tasks.
- **Known residual risk (Task 7):** whether every library funnels through the stdlib trio is verified empirically, not assumed; the requests/urllib3 HTTPAdapter contingency is spelled out so it's not a placeholder.
