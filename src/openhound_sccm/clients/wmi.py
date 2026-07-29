"""Transport-only WMI client for SCCM: a per-target credential ladder over the
shared DCOM/pywin32 backends.

``WmiClient`` plays the role ``clients/http.HttpClient`` plays for HTTP: it owns a
per-target connection and a credential ladder, and streams normalized rows for a
WQL query built from a namespace + class + columns. It is service-agnostic — the
caller supplies the WMI *namespace* and class (e.g. ``root\\SMS\\site_<code>`` for
the SCCM SMS Provider, ``root\\cimv2`` for stock WMI); nothing here knows about SCCM.

The DCOM/pywin32 transport backends (``_ImpacketBackend`` / ``_PyWin32Backend`` +
row normalization) live in the shared library
(``openhound_collector_common.clients.wmi``). They were proven here first — the
per-namespace ``DCOMConnection`` workaround and the embedded-object unwrap — and
generalized so the MSSQL collector reuses them. This module keeps only SCCM's
*wrapper*: the ``choose_auth`` credential ladder (try each rung, cache the winner)
and the namespace/class/columns query convenience.

Auth reuses the shared ``choose_auth`` (via ``http_auth``) for credential
*precedence*, then realizes each rung over a WMI transport:

  * ``ticket`` / ``kerberos`` / ``ntlm`` -> impacket DCOM (incl. pass-the-hash,
    pass-the-ticket); cross-platform.
  * ``sspi``     -> pywin32 WMI as the current Windows user; Windows-only.
  * ``anonymous``-> skipped (DCOM always requires authentication).

The first rung whose ``execquery`` runs the caller's initial query without raising
wins and is cached; later queries reuse it. Rows stream: each is yielded as it is
pulled off the WMI enumerator.
"""
from __future__ import annotations

import base64
from typing import Any, Iterator, Optional

from openhound_collector_common.clients.wmi import _ImpacketBackend, _PyWin32Backend

from ..log_context import get_logger
from . import http_auth
from .http_auth import format_hashes, split_user_domain

logger = get_logger(__name__)


def _build_wql(class_name: str, columns: Optional[tuple] = None, where: Optional[str] = None) -> str:
    """Render a WQL query. ``columns=None`` selects all (``SELECT *``)."""
    select = ",".join(columns) if columns else "*"
    wql = f"SELECT {select} FROM {class_name}"
    if where:
        wql += f" WHERE {where}"
    return wql


class WmiClient:
    """Per-target WMI client mirroring ``HttpClient`` for the SMS Provider."""

    def __init__(self, *, target: str, domain: str, username: Optional[str] = None,
                 password: Optional[str] = None, nt_hash: Optional[str] = None,
                 kerberos_ticket: Optional[str] = None, kdc_host: Optional[str] = None) -> None:
        self._target = target
        self._domain = domain or ""
        self._username = username
        self._password = password
        self._nt_hash = nt_hash
        self._kerberos_ticket = kerberos_ticket
        self._kdc_host = kdc_host
        self._backend: Any = None       # the rung that connected, cached

    @classmethod
    def from_context(cls, ctx, target: str) -> "WmiClient":
        """Build a client for *target*, reading credentials from a SourceContext.

        The KDC defaults to the already-resolved domain controller, matching
        ``HttpClient.from_context``.
        """
        kdc = None
        creds = getattr(getattr(ctx, "ad", None), "creds", None)
        if creds is not None:
            kdc = getattr(creds, "domain_controller", None)
        return cls(
            target=target,
            domain=getattr(ctx, "domain", "") or "",
            username=getattr(ctx, "username", None),
            password=getattr(ctx, "password", None),
            nt_hash=getattr(ctx, "nt_hash", None),
            kerberos_ticket=getattr(ctx, "kerberos_ticket", None),
            kdc_host=kdc,
        )

    # ----- auth ladder ----------------------------------------------------

    def _build_backend(self, rung: str):
        """Construct the shared WMI backend for a chosen ladder rung (None for anonymous)."""
        _, sam = split_user_domain(self._username or "", self._domain)
        if rung == "sspi":
            return _PyWin32Backend(self._target)
        if rung == "ntlm":
            ad_domain, _ = split_user_domain(self._username or "", self._domain)
            lm, nt = (format_hashes(self._nt_hash) or ":").split(":")
            return _ImpacketBackend(
                self._target, domain=ad_domain, username=sam, password=self._password or "",
                lmhash=lm, nthash=nt, do_kerberos=False, kdc_host=self._kdc_host,
            )
        if rung == "kerberos":
            lm, nt = (format_hashes(self._nt_hash) or ":").split(":")
            tgt = tgs = None
            if self._kerberos_ticket:
                ticket_user, tgt, tgs = self._load_ticket()
                # Pass-the-ticket may supply no -u; impacket still needs a client
                # principal for the AP-REQ, so derive it from the ticket's cname.
                if not sam:
                    sam = ticket_user
            return _ImpacketBackend(
                # doKerberos treats `domain` as the realm, so pass the full DNS domain.
                self._target, domain=self._domain, username=sam, password=self._password or "",
                lmhash=lm, nthash=nt, do_kerberos=True, kdc_host=self._kdc_host, tgt=tgt, tgs=tgs,
            )
        return None  # anonymous

    def _load_ticket(self):
        """Load a base64 KRB-CRED (.kirbi) into ``(username, TGT, TGS)`` for impacket.

        The client principal is read from the ticket so pass-the-ticket works
        even when no ``-u`` was supplied.
        """
        from impacket.krb5.ccache import CCache
        ccache = CCache()
        ccache.fromKRBCRED(base64.b64decode(self._kerberos_ticket, validate=True))
        if not ccache.credentials:
            raise ValueError("--ticket contains no usable credentials")
        cred = ccache.credentials[0]
        username = cred["client"].prettyPrint().decode("utf-8", "replace").split("@")[0]
        # impacket's DCOMConnection requests the DCOM service ticket from the TGT.
        tgt = cred.toTGT()
        return username, tgt, None

    def query(self, namespace: str, class_name: str, *, columns: Optional[tuple] = None,
              where: Optional[str] = None) -> Iterator[dict]:
        """Run a WQL query against *namespace*, streaming normalized rows.

        The first query runs the auth ladder (this query is the probe) and caches
        the winning backend; later queries reuse it. Yields nothing (and logs) if
        the ladder is exhausted or the query fails.
        """
        wql = _build_wql(class_name, columns, where)
        try:
            logger.verbose("WMI query on %s (%s): %s", self._target, namespace, wql)
            raw = self._open(namespace, wql)
        except Exception as ex:  # noqa: BLE001 - one class failing must not abort the rest
            logger.warning("WMI query %s on %s failed: %s", class_name, self._target, ex)
            return
        if raw is None:
            return  # ladder exhausted (logged in _open)
        yield from self._backend.stream(raw)

    def _open(self, namespace: str, wql: str):
        """Return a WMI enumerator for (namespace, wql).

        On the first call the auth ladder runs, using this query as the rung
        probe; the first rung whose ``execquery`` returns without raising wins and
        is cached. Returns None if every rung is exhausted.
        """
        if self._backend is not None:
            return self._backend.execquery(namespace, wql)
        plan = http_auth.choose_auth(
            username=self._username, password=self._password, nt_hash=self._nt_hash,
            ticket=self._kerberos_ticket, target_host=self._target,
            sspi_available=http_auth.sspi_negotiate_available(),
        )
        for rung in plan:
            backend = self._build_backend(rung)
            if backend is None:
                logger.info("WMI on %s: skipping anonymous rung (DCOM requires authentication)", self._target)
                continue
            try:
                logger.verbose("WMI auth attempt on %s via %s", self._target, rung)
                backend.connect()
                raw = backend.execquery(namespace, wql)
            except Exception as ex:  # noqa: BLE001 - this rung failed; try the next
                logger.verbose("WMI %s rung failed on %s: %s", rung, self._target, ex)
                backend.close()
                continue
            logger.info("WMI authenticated on %s via %s", self._target, rung)
            self._backend = backend
            return raw
        logger.info("WMI auth ladder exhausted on %s (%s)", self._target, plan)
        return None

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()
