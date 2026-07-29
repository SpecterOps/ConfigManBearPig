"""EPA (Extended Protection for Authentication) detection for SQL Server hosts.

SCCM's :func:`test_epa` is a thin adapter over the shared
:func:`openhound_collector_common.clients.mssql.detect_epa`. The TDS probe matrix,
the TLS-1.2-capped EPA login, channel-binding classification, and the
Off/Allowed/Required decision tree were proven here first and generalized into the
shared library (which the MSSQL collector also uses). This module keeps only
SCCM's collector-facing glue:

  * :func:`test_epa` — the credential-ladder entry point the MSSQL collector calls;
    it selects explicit-creds vs current-user SSPI (vs a ticket-only WARNING+skip,
    since pass-the-ticket can't probe channel binding, vs skip), pins the
    registered ``MSSQLSvc`` SPN from the host's AD SPN list, runs the shared
    ``detect_epa``, and returns an :class:`EPAResult` (or ``None``);
  * :class:`EPAResult` — the small result record the collector reads;
  * :func:`_select_mssql_spn` — SPN selection from the AD SPN list.

The "Allowed/Required" verdict under SSPI (Windows always sends the AV pairs, so
Allowed and Required are indistinguishable) is surfaced verbatim, exactly as the
shared detector reports it (memory: feedback_epa_uncertainty_label).
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from typing import Optional

from openhound_collector_common.clients.auth import split_user_domain
from openhound_collector_common.clients.mssql import (
    Auth,
    EPAPrereqError,  # noqa: F401  (re-exported for debug_epa_matrix.py)
    detect_epa,
)

logger = logging.getLogger(__name__)


@dataclass
class EPAResult:
    """EPA determination outcome, as the MSSQL collector consumes it.

    ``extended_protection`` is "Off" / "Allowed" / "Required" / "Allowed/Required"
    (SSPI) / "Unknown", surfaced verbatim from the shared detector.
    """

    extended_protection: str
    force_encryption: bool = False
    strict_encryption: bool = False


def _sspi_available() -> bool:
    """True only on Windows with the pywin32 SSPI modules importable."""
    if sys.platform != "win32":
        return False
    try:
        import sspi  # noqa: F401
        import sspicon  # noqa: F401
        import win32security  # noqa: F401

        return True
    except ImportError:
        return False


def _select_mssql_spn(spns: Optional[list], host: str, port: int) -> str:
    """Pick the registered ``MSSQLSvc`` SPN, or derive ``MSSQLSvc/host:port``."""
    for spn in spns or []:
        if spn.lower().startswith("mssqlsvc/"):
            return spn
    return f"MSSQLSvc/{host}:{port}"


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
    """Determine EPA enforcement for one SQL Server via the shared detector.

    Credential ladder: explicit credentials (password or NT hash) -> current-user
    SSPI integrated auth -> (ticket-only: WARNING + skip, because pass-the-ticket
    cannot probe channel binding) -> skip (returns ``None``). *spns* is the host's
    AD SPN list, used to pin the registered ``MSSQLSvc`` SPN so the service-binding
    AV pair matches what the server expects. Raises :class:`EPAPrereqError` (from
    the shared detector) when the baseline login can't establish a trustworthy
    result.
    """
    remote_name = remote_name or target
    spn = _select_mssql_spn(spns, remote_name, port)

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
        # a ticket is the *sole* usable credential -- explicit creds and SSPI, both
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

    verdict = detect_epa(f"{target}:{port}", auth)
    return EPAResult(
        extended_protection=verdict["extendedProtection"],
        force_encryption=bool(verdict["forceEncryption"]),
        strict_encryption=bool(verdict["strictEncryption"]),
    )
