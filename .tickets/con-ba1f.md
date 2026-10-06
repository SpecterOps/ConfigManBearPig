---
id: con-ba1f
status: closed
deps: []
links: []
created: 2026-09-08T00:00:00Z
type: bug
priority: 1
tags: [real-env, http, proxy]
---

# HTTP client trusted the ambient system/environment proxy

Found during a real-environment (non-lab) assessment: every AdminService/HTTP request,
including same-LAN, same-domain targets, got a `ProxyError` connect-timeout. All of them
tried to route through the operator's corporate web proxy (configured for general
internet access), which has no route to internal hosts.

Root cause: `HttpClient.__init__` (`clients/http.py`) creates `requests.Session()` with
no override, and `requests` trusts ambient proxy config by default — env vars, or on
Windows the registry-configured system proxy via `urllib.request.getproxies_registry()`.

This collector already has its own explicit, intentional pivoting mechanism, `-x`/`--proxy`
(a SOCKS5 tunnel installed at the socket layer, per `main.py`). Silently trusting a random
ambient corporate proxy was never intended, and broke a real engagement until worked
around with a manually-set `NO_PROXY` environment variable.

## Fix

`self._session.trust_env = False` right after session construction. Confirmed safe
against `--proxy`: the SOCKS5 mechanism patches `socket.socket`/`socket.create_connection`/
`socket.getaddrinfo` process-wide and never touches `requests`' own proxy resolution, so
the two don't interact.

## Notes

**2026-09-08T00:00:00Z**

Fixed and tested. New test `test_session_does_not_trust_ambient_proxy_env` in
`tests/http_client_test.py`. README's "Proxying / pivoting" section updated to state
ambient proxies are never used automatically.
