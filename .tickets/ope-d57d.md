---
id: ope-d57d
status: closed
deps: []
links: []
created: 2026-06-09T20:43:02Z
type: task
priority: 2
tags: [sccm, http, auth, negotiate, adminservice]
---

# Shared HTTP client (Negotiate auth) for AdminService + HTTP collectors

Build the shared HTTP client used by the AdminService (ope-b287) and HTTP (ope-9d62) collectors. Negotiate auth ladder (explicit creds win -> current-user SSPI -> anonymous) via impacket (Kerberos from password/NT-hash/base64-kirbi-ticket, NTLM type1/3) + pywin32 SSPI, hand-driven over a keep-alive requests session. Caller-chosen AuthMode (NEGOTIATE vs NONE) so the HTTP probe stays unauthenticated. Returns structured HttpResult (status + RESPONSE/CONNECT_FAILURE/TLS_FAILURE) so the collector decides ClientCertificateRequired. Full end-to-end cred wiring: --nt-hash + --ticket flags, env maps, SourceContext.kerberos_ticket. Adds requests as a direct dep. Design: docs/superpowers/specs/2026-06-09-sccm-http-client-design.md

## Notes

**2026-06-09T21:30:38Z**

Implementation complete and live-validated (not committed; owner commits after testing). New: clients/http_auth.py (AuthMode, choose_auth ladder, SSPI/NTLM/Kerberos negotiators) + clients/http.py (HttpClient, HttpResult, ErrorClass, Negotiate handshake loop). Wired: SourceContext.kerberos_ticket, --nt-hash/--ticket CLI flags + env maps, source.py secret, requests dep, README auth section. Tests: tests/test_http_auth.py (15), tests/test_http_client.py (12), tests/test_http_cli_flags.py (3) all green; tests/test_http_negotiate_integration.py opt-in, 3 passed live vs ps1-sms.mayyhem.com (SSPI + password-Kerberos + pass-the-hash). Key live finding: explicit-Kerberos AP-REQ must OMIT GSS_C_DCE_STYLE (http.sys/IIS rejects DCE-style with 401; WinRM accepts it). ruff clean; mypy only the shared impacket-untyped/logger.verbose baseline. NOTE: 10 pre-existing test failures on this branch (test_registry_current_user FakeProbe missing read_dword; test_extension_methods app.converter None) are unrelated to this work.

**2026-06-11T15:26:22Z**

Refinement: HttpClient now reuses the authenticated keep-alive connection when the server persists Negotiate auth, and adaptively stops probing (one-time) when it doesn't. Live finding: SCCM's http.sys AdminService does NOT persist Negotiate auth across requests (reused connection 401s), so it re-authenticates per request (SSPI path = 1 round-trip/request, LSA-cached token, cheap). Per-request choose_auth logs downgraded verbose->debug; one 'authenticated to <host> via <rung>' verbose line per auth. New tests: reuse-success, reauth-on-401, stop-probing-after-failure. DEFERRED/possible follow-up: cache the Kerberos TGS for the explicit-credential path so -u/-p / --nt-hash / --ticket don't hit the KDC (TGT+TGS) on every request against a non-persisting server (SSPI path unaffected).

**2026-06-11T15:34:29Z**

DONE: service-ticket (TGS) caching implemented + live-validated. KerberosNegotiator caches (tgs,cipher,sessionKey) after the first _service_ticket() and rebuilds only the AP-REQ per request; HttpClient caches the Kerberos negotiator across get() calls so the KDC exchange (TGT+TGS) happens once per provider, not per request. Live: explicit-password against ps1-sms = one 'requesting TGT+TGS' + KDC:88 contact on request 1, zero KDC contact on requests 2-3, all 200. Matches browser behavior (mint ticket once, cheap per-request AP-REQ). SSPI path already LSA-cached; NTLM stays a per-request handshake. 53 client/auth/adminservice unit tests green; ruff+mypy clean.
