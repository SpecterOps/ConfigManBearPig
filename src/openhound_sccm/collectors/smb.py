"""SCCM SMB share + signing per-host collector.

Port of ``Invoke-SMBCollection`` (ConfigManBearPig.ps1:9000), including the SMB
signing scan (``Get-SMBSigningRequiredViaSMBNegotiate``, ps1:5113). For one
target it:

1. probes whether SMB signing is *required* via an unauthenticated SMB2 negotiate
   and emits that fact (``source = "SMB-Negotiate"``);
2. if the host was reachable, enumerates its shares (``NetShareEnum`` level 1 via
   impacket) and classifies SCCM-specific share names/descriptions into site
   system roles, a site code, and the PXE / content-library flags, emitting a
   role/flags row plus an ``smb_sites`` row.

Three deliberate departures from a byte-faithful port (improvements per project
guidance, in the spirit of ``http.py``'s):

* The role/flags row is emitted only when at least one SCCM-specific share
  matched. PS1 upserts a Computer with ``SCCMInfra=True`` for *any* host whose
  shares enumerate, over-tagging plain file servers; we require an SCCM signature.
* PS1's ``SMS_*`` and share-description site-code branches read
  ``$smsSite.Description`` -- a copy-paste bug, since ``$smsSite`` is ``$null`` in
  both branches, so those site-code paths never resolve. We read the matched
  share's own description.
* PS1's ``SMS_DP$`` guard ``-not $smsDP.Description -contains "ConfigMgr Site
  Server"`` misuses ``-contains`` (an array operator) on a string; we use a
  substring test, preserving the intent (suppress the "no site code" warning for
  a site server's own DP share).

Per the project design, per-host share classification stays in ``collect`` (it is
parsing, not cross-record comparison). Reconciling SMB facts against the other
collectors and the "site systems without SMB signing + NTLM unrestricted"
relay-coercion analysis (ps1:6734) are deferred to preproc; Computer /
``SCCM_Site`` node + edge construction to convert.

Runs last among the per-host phases and is skipped once AdminService or WMI has
already collected the host (``per_host_phases.should_run_phase`` mirrors PS1's
"already Collected -> skip SMB" check at ps1:9053).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from ..clients.smb import check_smb_signing, list_shares
from ..clients.smb_sso import connect_smb
from ..context import SourceContext
from ..log_context import get_logger

logger = get_logger(__name__)

# Site code lives in a share description as "SMS Site <CODE>" (the DP share spells
# it "SMS Site <CODE> DP"). The SMS_* share name is "SMS_<CODE>".
_SITE_CODE_RE = re.compile(r"SMS Site (\w+)")
_SMS_DP_SITE_RE = re.compile(r"SMS Site (\w+) DP")
_SMS_STAR_RE = re.compile(r"^SMS_(\w+)$")


def _role(base: str, site_code: Optional[str]) -> str:
    """A site-system role string, suffixed ``@<site_code>`` when the code is known.

    Matches PS1's ``SCCMSiteSystemRoles`` strings (e.g. ``"SMS Site Server@PS1"``).
    """
    return f"{base}@{site_code}" if site_code else base


@dataclass
class _ShareClassification:
    """The per-host facts derived from one share enumeration.

    Attributes:
        collection_source: Ordered ``SMB-*`` tags for each SCCM share that matched.
        site_code: The SCCM site code, if any share named or described it.
        is_site_server: Host carries the SMS Site Server role.
        is_dp: Host carries the SMS Distribution Point role.
        is_pxe_enabled: Host has the REMINST (PXE) share.
        hosts_content_library: Host has a content-library share (current or legacy).
    """

    collection_source: list[str]
    site_code: Optional[str]
    is_site_server: bool
    is_dp: bool
    is_pxe_enabled: bool
    hosts_content_library: bool

    @property
    def is_sccm(self) -> bool:
        """True once any SCCM-specific share confirmed this host is SCCM infra."""
        return bool(self.collection_source)

    def roles(self) -> list[str]:
        """The site-system role strings implied by the matched shares."""
        roles: list[str] = []
        if self.is_site_server:
            roles.append(_role("SMS Site Server", self.site_code))
        if self.is_dp:
            roles.append(_role("SMS Distribution Point", self.site_code))
        return roles


def _classify_shares(shares: list[tuple[str, str]]) -> _ShareClassification:
    """Classify enumerated ``(name, description)`` shares into SCCM roles + flags.

    Walks the share signatures in the exact order PS1 does so the ``site_code`` is
    resolved from the same precedence (SMS_SITE, then SMS_*, then any matching
    share description, then SMS_DP$) and the ``collection_source`` tags accumulate
    in the same sequence.
    """

    def _first(predicate) -> Optional[tuple[str, str]]:
        return next(((n, d) for n, d in shares if predicate(n, d)), None)

    sms_site = _first(lambda n, d: n == "SMS_SITE")
    sms_star = _first(lambda n, d: _SMS_STAR_RE.match(n))
    sms_dp = _first(lambda n, d: n == "SMS_DP$")
    has_reminst = any(n == "REMINST" for n, _ in shares)
    has_content_lib = any(n == "SCCMContentLib$" for n, _ in shares)
    has_sms_pkg = any("SMSPKG" in n for n, _ in shares)
    site_shares = [(n, d) for n, d in shares if _SITE_CODE_RE.search(d)]

    collection_source: list[str] = []
    site_code: Optional[str] = None
    is_site_server = False

    # SMS_SITE -> site server; site code from its description.
    if sms_site:
        collection_source.append("SMB-SMS_SITE")
        is_site_server = True
        match = _SITE_CODE_RE.search(sms_site[1])
        if match:
            site_code = match.group(1)
            logger.info("Found site server for site: %s", site_code)
        else:
            logger.warning("Could not determine site code from SMS_SITE share description")

    # SMS_<sitecode> -> site server, only if SMS_SITE didn't already settle it.
    # PS1 reads $smsSite.Description here (null in this branch); we read the
    # matched SMS_* share's own description.
    if not is_site_server and sms_star:
        collection_source.append("SMB-SMS_*")
        match = _SITE_CODE_RE.search(sms_star[1])
        if match:
            is_site_server = True
            site_code = match.group(1)
            logger.info("Found site server for site: %s", site_code)
        else:
            logger.warning("Could not determine site code from SMS_* share description")

    # REMINST -> PXE support enabled.
    is_pxe_enabled = False
    if has_reminst:
        collection_source.append("SMB-REMINST")
        is_pxe_enabled = True
        logger.verbose("Distribution point has PXE support enabled")

    # Content-library shares (current then legacy).
    hosts_content_library = False
    if has_content_lib:
        collection_source.append("SMB-SCCMContentLib$")
        hosts_content_library = True
        logger.verbose("Target hosts the content library (SCCMContentLib$)")
    if has_sms_pkg:
        collection_source.append("SMB-SMSPKG$")
        hosts_content_library = True
        logger.verbose("Target hosts the legacy content library (SMSPKG$)")

    # Fallback: site code from any share description. PS1 reads $smsSite.Description
    # in this loop (null here); we read each candidate share's own description.
    if not site_code and site_shares:
        collection_source.append("SMB-ShareDescription")
        for _, desc in site_shares:
            match = _SITE_CODE_RE.search(desc)
            if match:
                site_code = match.group(1)
                logger.info("Found site code in share description: %s", site_code)
                break

    # SMS_DP$ -> distribution point; its description can refine the site code.
    is_dp = False
    if sms_dp:
        collection_source.append("SMB-SMS_DP$")
        is_dp = True
        match = _SMS_DP_SITE_RE.search(sms_dp[1])
        if match:
            site_code = match.group(1)
        elif "ConfigMgr Site Server" not in (sms_dp[1] or ""):
            logger.warning("Could not determine site code from SMS_DP$ share description")
        logger.info("Found distribution point role for site: %s", site_code)

    return _ShareClassification(
        collection_source=collection_source,
        site_code=site_code,
        is_site_server=is_site_server,
        is_dp=is_dp,
        is_pxe_enabled=is_pxe_enabled,
        hosts_content_library=hosts_content_library,
    )


def collect_smb(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield SMB-derived rows for *target*: a signing fact, then SCCM share facts.

    PS1 order: the unauthenticated SMB2-negotiate signing check first (recorded
    even when share enumeration later fails), then -- only if the host was
    reachable -- authenticated share enumeration and SCCM classification.
    """
    if not ctx.method_enabled("SMB"):
        return

    logger.info("Starting SMB collection on %s", target)

    target_entry = ctx.target_hosts_by_hostname.get(target.lower())
    ad_object = target_entry.ad_object if target_entry else None
    name = (ad_object.get("name") if ad_object else None) or target

    # Step 1 (PS1 9059): unauthenticated SMB2-negotiate signing check.
    logger.info("Checking SMB signing requirement on %s", target)
    signing_required = check_smb_signing(target)
    if signing_required is None:
        # PS1 sets $result.Error and skips share enumeration when the host can't be
        # negotiated (unreachable / 445 closed).
        logger.info("Could not determine SMB signing requirement on %s; skipping share enumeration", target)
        logger.info("SMB collection completed for %s", target)
        return
    yield "smb_computers", {
        **(ad_object or {}),
        "source": "SMB-Negotiate",
        "smb_signing_required": signing_required,
        "name": name,
    }

    # Step 2 (PS1 9078): authenticated share enumeration + SCCM classification.
    # Pass the full credential set so share enum honors password, pass-the-hash
    # (--nt-hash), pass-the-ticket (--ticket), current-user SSPI, or null session.
    logger.info("Enumerating SMB shares on %s", target)
    creds = getattr(getattr(ctx, "ad", None), "creds", None)
    smb = connect_smb(
        target, ctx.domain, ctx.username, ctx.password,
        nt_hash=getattr(ctx, "nt_hash", None),
        kerberos_ticket=getattr(ctx, "kerberos_ticket", None),
        kdc_host=getattr(creds, "domain_controller", None),
    )
    if smb is None:
        # connect_smb already logged the transport/auth cause at verbose.
        logger.warning("Failed to enumerate SMB shares on %s (could not authenticate)", target)
        logger.info("SMB collection completed for %s", target)
        return

    shares: Optional[list[tuple[str, str]]] = None
    try:
        shares = list_shares(smb)
    except Exception as ex:  # noqa: BLE001 - access denied / RPC failure isn't fatal
        logger.error("SMB enumeration failed for %s: %s", target, ex)
    finally:
        try:
            smb.logoff()
        except Exception:  # noqa: BLE001 - best-effort logoff
            pass

    if shares is None:
        logger.info("SMB collection completed for %s", target)
        return

    logger.verbose("Enumerated %d SMB shares on %s:", len(shares), target)
    for share_name, share_desc in shares:
        logger.verbose("  %s (%s)", share_name, share_desc)

    classification = _classify_shares(shares)
    if not classification.is_sccm:
        # PS1 tags any share-enumerable host SCCMInfra=True; we only record a host
        # once an SCCM-specific share confirms it (mirrors http.py's improvement).
        logger.info("No SCCM-specific shares found on %s", target)
        logger.info("SMB collection completed for %s", target)
        return

    if classification.site_code:
        yield "smb_sites", {
            "source": "SMB-Shares",
            "site_code": classification.site_code,
        }

    roles = classification.roles()
    yield "smb_computers", {
        **(ad_object or {}),
        "source": "SMB-Shares",
        "collection_source": classification.collection_source,
        "sccm_infra": True,
        "sccm_hosts_content_library": classification.hosts_content_library,
        "sccm_is_pxe_support_enabled": classification.is_pxe_enabled,
        "sccm_site_system_roles": roles or None,
        "site_code": classification.site_code,
        "name": name,
    }
    logger.info("SMB collection completed for %s", target)
