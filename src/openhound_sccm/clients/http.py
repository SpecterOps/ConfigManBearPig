"""HTTP transport for the SCCM AdminService REST API and HTTP role probes.

Owns one keep-alive ``requests.Session`` per target and the Negotiate header
dance (auth tokens come from ``clients/http_auth.py``). Transport only: it
returns raw status codes and a connection-error classification. SCCM-specific
reading of those signals (e.g. a 403 on ``?SMSTRC`` meaning a client cert is
required) lives in the collectors, not here.

The caller picks the auth behaviour explicitly via ``AuthMode``: ``NEGOTIATE``
runs the auth ladder on the first request; ``NONE`` never sends an
``Authorization`` header (used by the HTTP role probe, whose role detection
relies on reading the *unauthenticated* 401/403/200 codes).
"""
from __future__ import annotations

import base64
import enum
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

import requests
import urllib3

from ..log_context import get_logger
from . import http_auth
from .http_auth import AuthMode

logger = get_logger(__name__)

# SCCM site systems routinely use self-signed certs; PS1 disables validation
# globally (TrustAllCertsPolicy). Match that and silence the per-request warning.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ErrorClass(enum.Enum):
    """How a request outcome is classified for the caller."""
    RESPONSE = "response"          # an HTTP response was received (ANY status)
    CONNECT_FAILURE = "connect"    # dead socket / DNS / refused / timeout
    TLS_FAILURE = "tls"            # secure-channel / handshake error


@dataclass
class HttpResult:
    """One request outcome. ``status_code`` is set iff ``error_class`` is RESPONSE."""
    status_code: Optional[int]
    content: Optional[bytes]
    error_class: ErrorClass


def classify_exception(exc: BaseException) -> ErrorClass:
    """Map a requests exception to an ErrorClass.

    SSLError is checked before ConnectionError because requests' SSLError is a
    subclass of ConnectionError, and a TLS failure on an HTTPS SCCM endpoint is
    a secondary PKI signal the collector may weigh separately from a dead socket.
    """
    if isinstance(exc, requests.exceptions.SSLError):
        return ErrorClass.TLS_FAILURE
    if isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
        return ErrorClass.CONNECT_FAILURE
    # Any other requests error without a response is treated as a connect failure.
    return ErrorClass.CONNECT_FAILURE


def _parse_negotiate_token(www_authenticate: str) -> Optional[bytes]:
    """Extract the base64 token from a ``WWW-Authenticate: Negotiate <b64>`` header.

    Returns None when the header carries the scheme with no token (the initial
    challenge), which is the signal to start a fresh handshake leg.
    """
    parts = www_authenticate.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "negotiate":
        return None
    try:
        return base64.b64decode(parts[1].strip())
    except Exception:  # noqa: BLE001 - a malformed token is treated as "no token"
        return None


class HttpClient:
    """Per-target HTTP client wrapping one keep-alive ``requests.Session``."""

    def __init__(
        self,
        *,
        base_url: str,
        auth: AuthMode,
        domain: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        nt_hash: Optional[str] = None,
        kerberos_ticket: Optional[str] = None,
        kdc_host: Optional[str] = None,
        verify_ssl: bool = False,
        # Applies to both connect and read. 10s rather than 5s because the SCCM
        # AdminService answers some WMI-backed classes slowly when the SMS Provider
        # is warming up or under load -- SMS_SCI_Reserved was observed exceeding 5s
        # on every site server in a healthy lab, and a read timeout there is
        # indistinguishable from "no rows" once the response is lost.
        timeout: int = 10,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = auth
        self._domain = domain
        self._username = username
        self._password = password
        self._nt_hash = nt_hash
        self._kerberos_ticket = kerberos_ticket
        self._kdc_host = kdc_host
        self._timeout = timeout
        self._host = urlparse(self._base_url).hostname or self._base_url
        # Some servers persist Negotiate auth on the keep-alive connection, so a
        # later request can skip the handshake; others (e.g. SCCM's http.sys
        # AdminService) require auth on every request. ``_authenticated`` records
        # that we have succeeded at least once; ``_reuse_works`` is tri-state
        # (None = untested, True = server persists, False = re-auth every time)
        # so we probe reuse at most once and never waste a round-trip again.
        self._authenticated = False
        self._reuse_works: Optional[bool] = None
        # Kerberos negotiator is cached across requests so its service ticket
        # (and the KDC exchange) is obtained once; SSPI/NTLM are rebuilt per
        # request (SSPI is LSA-cached and cheap; NTLM is a per-request handshake).
        self._kerberos_negotiator: Any = None

        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._session.headers.update({"Accept": "application/json"})

    @classmethod
    def from_context(cls, ctx, target: str, *, auth: AuthMode,
                     scheme: str = "https", timeout: int = 10) -> "HttpClient":
        """Build a client for *target*, reading credentials from a SourceContext.

        The KDC defaults to the already-resolved domain controller
        (``ctx.ad.creds.domain_controller``); no separate ``--kdc`` knob.
        """
        kdc = None
        creds = getattr(getattr(ctx, "ad", None), "creds", None)
        if creds is not None:
            kdc = getattr(creds, "domain_controller", None)
        return cls(
            base_url=f"{scheme}://{target}",
            auth=auth,
            domain=getattr(ctx, "domain", "") or "",
            username=getattr(ctx, "username", None),
            password=getattr(ctx, "password", None),
            nt_hash=getattr(ctx, "nt_hash", None),
            kerberos_ticket=getattr(ctx, "kerberos_ticket", None),
            kdc_host=kdc,
            timeout=timeout,
        )

    def _full_url(self, path_or_url: str) -> str:
        if path_or_url.lower().startswith(("http://", "https://")):
            return path_or_url
        return f"{self._base_url}/{path_or_url.lstrip('/')}"

    def get(self, path_or_url: str, headers: Optional[dict[str, str]] = None) -> HttpResult:
        """GET a path (or absolute URL). Runs the Negotiate dance in NEGOTIATE mode.

        ``headers`` overrides the session defaults for this request (anonymous GETs).
        The session default is ``Accept: application/json`` for the AdminService/XML
        endpoints; a binary fetch (e.g. ccmsetup.exe) must pass ``{"Accept": "*/*"}`` or
        IIS returns ``406 Not Acceptable`` for the octet-stream.
        """
        url = self._full_url(path_or_url)
        try:
            if self._auth is AuthMode.NEGOTIATE:
                return self._get_negotiate(url)
            resp = self._session.get(url, timeout=self._timeout, headers=headers)
            logger.debug("HTTP GET %s -> %s (anonymous)", url, resp.status_code)
            # Truncate the body preview: a binary fetch (e.g. ccmsetup.exe) is
            # multiple MB, and this line now always lands in the full on-disk log.
            # Slice the bytes first so we never repr() the whole body.
            _body = resp.content or b""
            _preview = repr(_body[:1024])[:1024]
            if len(_body) > 1024:
                _preview += f" ...({len(_body)} bytes total, truncated)"
            logger.debug("HTTP GET %s content: %s", url, _preview)
            return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
        except Exception as exc:  # noqa: BLE001 - classify any transport failure
            cls = classify_exception(exc)
            logger.verbose("HTTP GET %s failed (%s): %s", url, cls.value, exc)
            return HttpResult(None, None, cls)

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass

    # ----------------------------------------------------------- negotiate --

    def _build_negotiator(self, rung: str):
        """Instantiate the negotiator object for a chosen ladder rung."""
        if rung == "sspi":
            return http_auth.SspiNegotiator(target_host=self._host)
        if rung == "ntlm":
            ad_domain, sam = http_auth.split_user_domain(self._username or "", self._domain)
            return http_auth.NtlmNegotiator(
                domain=ad_domain, username=sam,
                password=self._password, nt_hash=self._nt_hash,
            )
        if rung == "kerberos":
            # Cached across requests so the service ticket (one KDC exchange) is
            # fetched once; later requests rebuild only the AP-REQ.
            if self._kerberos_negotiator is None:
                _, sam = http_auth.split_user_domain(self._username or "", self._domain)
                self._kerberos_negotiator = http_auth.KerberosNegotiator(
                    target_host=self._host, realm=self._domain, username=sam,
                    password=self._password, nt_hash=self._nt_hash,
                    ticket=self._kerberos_ticket, kdc_host=self._kdc_host,
                )
            return self._kerberos_negotiator
        return None  # "anonymous"

    def _negotiate_once(self, url: str, rung: str) -> Optional[HttpResult]:
        """Drive one rung's full token exchange.

        Returns a result, or None if the rung hit a *protocol* failure and the
        ladder should advance to the next rung. A credential rejection (final
        401) is returned as a RESPONSE — it does not advance the ladder.
        """
        negotiator = self._build_negotiator(rung)
        if negotiator is None:  # anonymous
            resp = self._session.get(url, timeout=self._timeout)
            logger.debug("HTTP GET %s -> %s (anonymous rung)", url, resp.status_code)
            return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
        try:
            server_token: Optional[bytes] = None
            while True:
                token, done = negotiator.step(server_token)
                header = {"Authorization": "Negotiate " + base64.b64encode(token).decode()}
                resp = self._session.get(url, headers=header, timeout=self._timeout)
                if resp.status_code != 401:
                    logger.debug("HTTP Negotiate(%s) %s -> %s", rung, url, resp.status_code)
                    return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
                server_token = _parse_negotiate_token(resp.headers.get("WWW-Authenticate", ""))
                if done or server_token is None:
                    # Server rejected our completed token (credential failure):
                    # surface the 401 and stop (per ad.py's "don't keep poking").
                    logger.warning("HTTP Negotiate(%s) rejected on %s (401)", rung, url)
                    return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
        except Exception as exc:  # noqa: BLE001 - protocol failure -> try next rung
            logger.verbose("HTTP Negotiate(%s) protocol failure on %s: %s", rung, url, exc)
            return None

    def _get_negotiate(self, url: str) -> HttpResult:
        # Fast path: if the server persisted auth on the keep-alive connection, a
        # plain request needs no fresh handshake. Probe this at most once: a 401
        # means the server re-auths every request (``_reuse_works = False``), so
        # we stop probing and never waste another round-trip.
        if self._authenticated and self._reuse_works is not False:
            try:
                resp = self._session.get(url, timeout=self._timeout)
                if resp.status_code != 401:
                    self._reuse_works = True
                    logger.debug("HTTP GET %s -> %s (reused Negotiate auth)", url, resp.status_code)
                    return HttpResult(resp.status_code, resp.content, ErrorClass.RESPONSE)
                if self._reuse_works is None:
                    logger.verbose("HTTP %s does not persist Negotiate auth; re-authenticating each request", self._host)
                self._reuse_works = False
            except Exception as exc:  # noqa: BLE001 - connection dropped; re-handshake on a fresh one
                logger.verbose("HTTP %s: reused connection failed (%s); re-authenticating", url, exc)

        plan = http_auth.choose_auth(
            username=self._username, password=self._password, nt_hash=self._nt_hash,
            ticket=self._kerberos_ticket, target_host=self._host,
            sspi_available=http_auth.sspi_negotiate_available(),
        )
        for rung in plan:
            result = self._negotiate_once(url, rung)
            if result is None:
                continue  # protocol failure on this rung; try the next
            if result.status_code != 401:
                # Authenticated: remember it so later requests reuse the connection.
                self._authenticated = True
                logger.verbose("HTTP authenticated to %s via %s", self._host, rung)
            return result
        # Every rung hit a protocol failure: report as a connect failure.
        logger.verbose("HTTP Negotiate exhausted all rungs (%s) on %s", plan, url)
        return HttpResult(None, None, ErrorClass.CONNECT_FAILURE)
