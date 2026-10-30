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
import json
from typing import Any, Iterator, Optional

from openhound_collector_common.clients.credential_guard import (
    CredentialGuard,
    is_rejected_sign_in,
)
from openhound_collector_common.clients.wmi import (
    _ImpacketBackend, _PyWin32Backend,
)
from openhound_collector_common.collection.errors import FatalCollectionError

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
                 kerberos_ticket: Optional[str] = None, kdc_host: Optional[str] = None,
                 credential_guard: Optional[CredentialGuard] = None) -> None:
        self._target = target
        self._domain = domain or ""
        self._username = username
        self._password = password
        self._nt_hash = nt_hash
        self._kerberos_ticket = kerberos_ticket
        self._kdc_host = kdc_host
        # The run's shared record of a rejected password. Checked before each
        # sign-in method; a definite rejection is reported there and ends the
        # ladder, because the next method would submit the same password.
        self._credential_guard = credential_guard
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
            credential_guard=getattr(ctx, "credential_guard", None),
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
            else:
                # Handing impacket no ticket makes it look for a credential cache
                # in KRB5CCNAME first, which is unset on Windows -- so it logs a
                # CRITICAL about the missing cache and then succeeds anyway with
                # the password/hash below. main.py's _ImpacketNoiseFilter demotes
                # that misleading CRITICAL; this line is what replaces it, so the
                # log still says what happened instead of just going quiet.
                logger.verbose(
                    "WMI Kerberos rung on %s: no --ticket supplied and no Kerberos credential "
                    "cache (KRB5CCNAME is unset), so a fresh TGT is requested with the supplied "
                    "credentials. impacket's 'CCache file is not found' notice is expected here.",
                    self._target,
                )
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
        # Guarded the same way as smb_sso._load_ticket: bad base64 would otherwise
        # surface as binascii's "Only base64 data is allowed" and a non-KRB-CRED
        # payload as a raw pyasn1 EndOfStreamError, neither naming the flag at fault.
        # No log here -- the raised message is the report.
        try:
            krb_cred = base64.b64decode(self._kerberos_ticket, validate=True)
        except ValueError as ex:  # binascii.Error subclasses ValueError
            raise ValueError(f"--ticket is not valid base64: {ex}") from ex
        ccache = CCache()
        try:
            ccache.fromKRBCRED(krb_cred)
        except Exception as ex:  # noqa: BLE001 - impacket/pyasn1 raise many types here
            raise ValueError(f"--ticket is not a valid KRB-CRED (.kirbi): {ex}") from ex
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
        except FatalCollectionError:
            logger.error("WMI setup/cleanup failed fatally on %s", self._target)
            raise
        except Exception as ex:  # noqa: BLE001 - one class failing must not abort the rest
            logger.warning("WMI query %s on %s failed: %s", class_name, self._target, ex)
            return
        if raw is None:
            return  # ladder exhausted (logged in _open)
        yield from self._backend.stream(raw)

    def read_instance(self, namespace: str, class_name: str, key_field: str,
                      key: int | str) -> dict[str, Any] | None:
        """Read one complete object, including fields omitted by WMI queries.

        SCCM marks administrator assignments and role actions as lazy: even a
        SELECT * leaves them empty. GetObject retrieves the complete instance.
        Call query first so the normal credential selection has already run.
        """
        if self._backend is None:
            logger.warning("WMI cannot read %s on %s before a successful query",
                           class_name, self._target)
            return None
        object_path = f"{class_name}.{key_field}={json.dumps(key)}"
        try:
            # The shared method owns the host lease, namespace and cleanup for
            # this entire object read, just as it does for streamed queries.
            logger.debug("WMI reading complete object %s through the selected provider", object_path)
            return self._backend.read_instance(namespace, object_path)
        except FatalCollectionError:
            logger.error("WMI complete-object cleanup failed on %s; the run must fail", self._target)
            raise
        except Exception as error:  # One refused instance must not abort collection.
            logger.warning("WMI complete read of %s on %s failed: %s; details are incomplete",
                           object_path, self._target, error)
            return None

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
            if self._credential_guard is not None and self._credential_guard.is_rejected:
                logger.warning("Not signing in to WMI on %s: the sign-in details were already rejected",
                               self._target)
                return None
            backend = self._build_backend(rung)
            if backend is None:
                logger.info("WMI on %s: skipping anonymous rung (DCOM requires authentication)", self._target)
                continue
            try:
                logger.verbose("WMI auth attempt on %s via %s", self._target, rung)
                backend.connect()
                raw = backend.execquery(namespace, wql)
            except FatalCollectionError:
                logger.error("WMI provider cleanup failed during authentication on %s", self._target)
                raise
            except Exception as ex:  # noqa: BLE001 - this rung failed; try the next
                backend.close()
                if rung != "sspi" and is_rejected_sign_in(ex):
                    # The next rung would submit the same password: stop here.
                    logger.warning("WMI %s rung on %s: the sign-in details were rejected", rung, self._target)
                    if self._credential_guard is not None:
                        self._credential_guard.record_rejection(f"WMI on {self._target}")
                    return None
                logger.verbose("WMI %s rung failed on %s: %s", rung, self._target, ex)
                continue
            logger.info("WMI authenticated on %s via %s", self._target, rung)
            self._backend = backend
            return raw
        logger.info("WMI auth ladder exhausted on %s (%s)", self._target, plan)
        return None

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()
