"""Shared source-run context for SCCM collectors.

``SourceContext`` wraps the LDAP/AD client and all CMBP-equivalent CLI knobs
(``--collection-methods``, ``--computers``, ``--site-codes``, etc.) and
provides the lazy-loaded caches that every ``@app.resource`` in
``collectors/*`` shares:
"""
from dataclasses import dataclass, field
from typing import Any, Optional

from ldap3 import BASE

from openhound_collector_common.discovery.dns import make_resolver

from .clients.ad import ADClient
from .models.target_entry import TargetEntry
from .log_context import get_logger

logger = get_logger(__name__)


def _domain_from_dn(dn: str) -> str | None:
    """Derive a dotted domain name from a DN's DC= components, e.g.
    "CN=Bob,DC=corp,DC=local" -> "corp.local". Returns None if the DN has
    no DC= components (shouldn't happen for AD objects, but stay defensive)."""
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().lower().startswith("dc=")]
    return ".".join(parts) if parts else None


@dataclass
class SourceContext:
    ad: ADClient
    domain: str
    username: str | None = None
    password: str | None = None
    nt_hash: str | None = None
    kerberos_ticket: str | None = None  # base64-encoded KRB-CRED (.kirbi) for pass-the-ticket
    dns_resolver: str | None = None
    # Collection (-m / --collection-methods)
    collection_methods: str = "All"

    # Behaviour flags persisted at collect time so preproc/convert can gate
    # "possible" nodes/edges without re-reading the CLI (separate runs).
    disable_possible_edges: bool = False
    enable_bad_opsec: bool = False

    # Public, injectable — shared across the run via the module-level _shared_*
    # pattern in source.py. ``work_queue`` is the phased_pipeline.WorkQueue that
    # the per-host engine drains; register_target submits newly-discovered,
    # allow-listed targets onto it.
    allowed_targets: frozenset = field(default_factory=frozenset)
    work_queue: Any = field(default=None)
    ad_resolution_cache: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    discovered_domains: set = field(default_factory=set)

    # Every uniquely-resolved AD principal from this run, keyed by SID —
    # populated by resolve_principal() on each fresh (non-cache-hit) success,
    # regardless of whether the hit came during discovery or a per-host phase.
    # Unlike ad_resolution_cache (keyed by lookup string, holds hits AND
    # misses), this is a pure, deduped record of resolved objects, meant to be
    # dumped to the "ldap_resolved_principals" raw table (source.py) once the
    # whole run finishes — see main.py::_run_per_host_stage.
    resolved_principals: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Site codes emitted into the sited DLT table during the preproc stage
    # collected from LDAP, local WMI
    site_codes: Optional[set[str]] = None

    # Site codes classified as Primary sites (site_type == "Primary Site") from
    # management-point capabilities during ldap_management_points_raw. A CAS publishes an
    # mSSMSSite object like any other site (so it appears in ``site_codes``) but has no
    # management point and cannot own clients. This narrower set lets the CmRcService
    # discovery stamp inferred ("possible") client devices with a Primary site code rather
    # than the CAS. Populated lazily, like ``site_codes``.
    primary_site_codes: Optional[set[str]] = None

    # Per-run local-collection state, discovered by one local resource and reused
    # by its siblings (they run in order, ``parallelized=False``). Previously held
    # in module-level globals in collectors/local.py; living on the context makes
    # the data flow explicit and typed. ``current_site_code`` is this host's
    # single site code (``site_codes`` above is the full set across all sources).
    current_site_code: str | None = None
    current_mp_ad_object: dict[str, Any] | None = None
    this_computer_ad_object: dict[str, Any] | None = None

    # CmRcService SPN match cache. Populated by ``cmrc_spn_matches()`` when
    # the LDAP phase first asks for it; the network call is bracketed by
    # ``phase_context("LDAP")`` so the resulting log line is tagged as an
    # LDAP event regardless of which resource forces the lazy build. PS1
    # also runs this query exactly once during its LDAP once-phase
    # (``ConfigManBearPig.ps1:3221``).
    _cmrc_spn_matches: Optional[list[dict[str, Any]]] = None

    # Mutable per-host probe-target accumulator. PS1's ``Add-DeviceToTargets``
    # appends to a live list and each subsequent per-host phase iterates the
    # *updated* list — so an MP discovered mid-run via MPLIST XML parsing
    # still gets RemoteRegistry / MSSQL / WMI / HTTP / SMB probes. The OH
    # per-host resources call ``target_hosts_snapshot()`` to read this set
    # at iteration time so late additions are picked up.
    #
    # Two parallel indexes:
    #   target_hosts_by_hostname — always populated; key = lowercased canonical hostname
    #   _target_hosts_by_sid      — only when SID available; key = objectSid string
    # Both dicts hold references to the same entry dicts, so a mutation via
    # either index is immediately visible via the other.
    target_hosts_by_hostname: dict = field(default_factory=dict)  # str -> TargetEntry
    _target_hosts_by_sid: dict = field(default_factory=dict)       # str -> TargetEntry
    _target_hosts_lock: Any = field(default=None)

    @property
    def system_management_dn(self) -> str:
        return f"CN=System Management,CN=System,{self.ad.base_dn}"

    # ---- Collection method gating (-m / --collection-methods) --------
    def method_enabled(self, method: str) -> bool:
        """Return True when ``method`` (e.g. "AdminService", "WMI", "SMB") is
        enabled by the current ``collection_methods`` setting.

        The value is a comma-separated list of method names (case-insensitive),
        matching CMBP's ``-m`` flag. ``"All"`` (the default) enables every
        method. Unknown method names are ignored so callers can pass in
        arbitrary labels without crashing the pipeline.
        """
        if not self.collection_methods:
            return True
        wanted = {m.strip().lower() for m in self.collection_methods.split(",") if m.strip()}
        if "all" in wanted:
            return True
        return method.lower() in wanted


    def _ensure_target_lock(self) -> Any:
        if self._target_hosts_lock is None:
            import threading
            self._target_hosts_lock = threading.Lock()
        return self._target_hosts_lock

    def _build_domains_to_try(self, hint_domain: Optional[str] = None) -> list:
        """Return an ordered, deduplicated list of domains to search.

        Order: [hint_domain, self.domain, ...discovered_domains]
        hint_domain is the domain extracted from a DOMAIN\\name prefix or FQDN suffix.
        self.domain (the operator-configured domain) is always included as the reliable
        fallback. Previously discovered domains follow as extended coverage — fixing a
        PS1 bug where $script:DiscoveredDomains was tracked but never fed back into
        future lookups.
        """
        seen: set = set()
        domains: list[str] = []

        def _add(d: str) -> None:
            d = d.upper()
            if d and d not in seen:
                seen.add(d)
                domains.append(d)

        if hint_domain:
            _add(hint_domain)
        if self.domain:
            _add(self.domain)
        for d in self.discovered_domains:
            _add(d)
        return domains

    def resolve_ip(self, ip: str) -> Optional[str]:
        """Resolve a name/IP using the configured DNS resolver (proxy-aware).

        Under a proxy we must route through dnspython/TCP even when no explicit
        ``--dns-resolver`` was given — the stdlib resolver runs on the outside
        box and can't see internal-only names (and would leak the query).
        """
        from openhound_collector_common.proxy import active_proxy
        proxied = active_proxy() is not None
        try:
            if self.dns_resolver or proxied:
                # Custom resolver and/or proxy-forced TCP.
                resolver = make_resolver(self.dns_resolver, force_tcp=proxied)
                answer = resolver.resolve(ip)
                return answer[0].to_text()
            # Direct mode, no explicit resolver: stdlib is fine.
            import socket
            return socket.gethostbyname(ip)
        except Exception as ex:
            logger.warning(f"DNS resolution failed for {ip}: {ex}")
            return None
        
    def resolve_principal(self, identifier: str) -> dict[str, Any] | None:
        """Resolve an identifier to an AD object dict, with multi-domain support.

        Mirrors PS1's Resolve-PrincipalInDomain (ConfigManBearPig.ps1:459-905):
        - Strips DOMAIN\\username prefix; uses prefix as a domain hint
        - Extracts domain suffix from FQDNs and records it in discovered_domains
        - Tries domains in order: [hint, configured, previously-discovered]
        - Per-domain cache keys ("domain|name") + all-domains-tried sentinel ("all|name")
        - Both hits and misses cached; second call for the same name never fires LDAP
        - DNs (contain "=") are resolved directly via BASE scope, bypassing domain iteration
        """
        name = identifier.strip()

        # Distinguished names are fully qualified — no domain iteration needed
        if "=" in name:
            cache_key = f"dn|{name.lower()}"
            if cache_key in self.ad_resolution_cache:
                return self.ad_resolution_cache[cache_key]
            result = self._ldap_resolve_dn(name)
            self.ad_resolution_cache[cache_key] = result
            if result is not None:
                self._record_resolved_principal(result)
            return result

        # Strip DOMAIN\username prefix; use prefix as domain hint
        hint_domain: Optional[str] = None
        if "\\" in name:
            hint_domain, name = name.split("\\", 1)

        # Extract domain suffix from FQDN and register as a discovered domain so
        # future plain-name lookups also try it (fixes PS1 DiscoveredDomains bug)
        if not hint_domain and "." in name:
            parts = name.split(".")
            if len(parts) > 2:
                hint_domain = ".".join(parts[1:]).upper()
                self.discovered_domains.add(hint_domain)

        name = name.lower()

        # Short-circuit: all domains already tried for this name
        if f"all|{name}" in self.ad_resolution_cache:
            return None

        for domain in self._build_domains_to_try(hint_domain):
            domain_key = f"{domain.lower()}|{name}"
            if domain_key in self.ad_resolution_cache:
                cached = self.ad_resolution_cache[domain_key]
                if cached is None:
                    continue  # already failed this domain, try next
                return cached
            result = self._ldap_resolve(name, domain)
            self.ad_resolution_cache[domain_key] = result
            if result is not None:
                self._record_resolved_principal(result)
                return result

        # All domains exhausted — store sentinel so repeat calls short-circuit
        self.ad_resolution_cache[f"all|{name}"] = None
        return None

    def _ldap_resolve_dn(self, dn: str) -> Optional[dict]:
        """Fetch a single AD object by its distinguished name using BASE scope."""
        attrs = [
            "sAMAccountName", "objectSid", "dNSHostName", "cn",
            "distinguishedName", "objectClass", "userPrincipalName", "name",
            "userAccountControl", "servicePrincipalName",
        ]
        result = next(
            self.ad.paged_search("(objectClass=*)", attrs, base=dn, scope=BASE),
            None,
        )
        # A DN-scoped lookup has no separate "domain" parameter to draw from
        # (unlike _ldap_resolve), so derive it from the DN's own DC= components.
        if isinstance(result, dict):
            result["domain"] = _domain_from_dn(dn)
        return result

    def _ldap_resolve(self, name: str, domain: str) -> Optional[dict]:
        """Fire a single paged_search for name within the given domain's base DN."""
        from ldap3.utils.conv import escape_filter_chars
        # A NetBIOS / single-label domain (e.g. "MAYYHEM") can't form a valid LDAP
        # naming context: "DC=MAYYHEM" doesn't exist, so AD answers with a referral
        # that ldap3 chases into "invalid server address". Skip it and let the
        # caller fall through to the FQDN domain in the try-list. This is why only
        # NetBIOS-prefixed principals (NAA, sccm_push) ever hit the crash.
        if "." not in domain:
            logger.debug(
                "Skipping LDAP resolve of %r: single-label domain %r has no valid "
                "naming context; deferring to an FQDN domain",
                name,
                domain,
            )
            return None
        safe = escape_filter_chars(name.rstrip("$"))
        ldap_filter = (
            f"(|(cn={safe})(sAMAccountName={safe})(sAMAccountName={safe}$)"
            f"(dNSHostName={safe})(dNSHostName={safe}.*)(userPrincipalName={safe})(objectSid={safe}))"
        )
        attrs = [
            "sAMAccountName", "objectSid", "dNSHostName", "cn",
            "distinguishedName", "objectClass", "userPrincipalName", "name",
            "userAccountControl", "servicePrincipalName",
        ]
        base = "DC=" + domain.replace(".", ",DC=") if domain else None
        results = list(self.ad.paged_search(ldap_filter, attrs, base=base, size_limit=1))
        result = results[0] if results else None
        # Stamp the domain this hit was resolved in — the caller (resolve_principal)
        # already knows it, but this is the layer that actually gets the AD object
        # back, so it's the natural place to attach it before returning.
        if isinstance(result, dict):
            result["domain"] = domain
        return result

    def _record_resolved_principal(self, ad_object: dict[str, Any]) -> None:
        """Accumulate a freshly (non-cache-hit) resolved AD object for later
        persistence to the "ldap_resolved_principals" raw table.

        Called from both fresh-resolution return paths in resolve_principal
        (the DN branch and the per-domain loop) — never from a cache-hit
        return, since a cache hit's object was already recorded the first
        time it was resolved. Deduped by SID: the same underlying AD object
        can be reached via several different names/domains in one run, but
        must appear only once in the table.
        """
        sid = ad_object.get("object_sid")
        if not sid:
            # No SID (e.g. a malformed/partial LDAP entry) — nothing to key
            # the persisted row on, so there's nothing useful to record.
            logger.debug("Resolved AD object has no object_sid; not persisting: %r", ad_object.get("distinguished_name"))
            return
        if sid in self.resolved_principals:
            return  # already recorded via an earlier name/domain lookup
        self.resolved_principals[sid] = {
            "sid": sid,
            "object_class": ad_object.get("object_class"),
            "user_account_control": ad_object.get("user_account_control"),
            "service_principal_name": ad_object.get("service_principal_name"),
            "cn": ad_object.get("cn"),
            "dns_host_name": ad_object.get("dns_host_name"),
            "sam_account_name": ad_object.get("sam_account_name"),
            "user_principal_name": ad_object.get("user_principal_name"),
            "distinguished_name": ad_object.get("distinguished_name"),
            # Stamped by _ldap_resolve (the domain it searched) or _ldap_resolve_dn
            # (parsed from the DN's DC= components) before the object reaches here.
            "domain": ad_object.get("domain"),
        }
        logger.debug("Recorded resolved principal for persistence: sid=%s cn=%s", sid, ad_object.get("cn"))

    def _is_allowed_target(self, identifier: str, ad_object: Optional[dict]) -> bool:
        """Mirror PS1's Test-AllowedTarget: empty allowed_targets means allow all.

        Builds candidate name forms from the identifier and AD object, then
        checks intersection with the pre-lowercased allowed_targets set.
        """
        if not self.allowed_targets:
            return True
        candidates: set = set()
        candidates.add(identifier.lower())
        if "." in identifier:
            candidates.add(identifier.split(".")[0].lower())
        if ad_object:
            for field_name in ("dns_host_name", "name", "sam_account_name"):
                v = ad_object.get(field_name)
                if isinstance(v, str):
                    candidates.add(v.lower().rstrip("$"))
                    if "." in v:
                        candidates.add(v.split(".")[0].lower())
        return bool(candidates & self.allowed_targets)

    def register_target(
        self,
        identifier: Optional[str], # dNSHostName, name, SID, DOMAIN\name, or DN
        source: Optional[str],
        site_code: Optional[str] | None = None,
        ad_object: dict[str, Any] | None = None,
    ) -> Optional[TargetEntry]:
        """Register a device as a probe target, mirroring PS1's Add-DeviceToTargets.

        Returns the TargetEntry (new or updated) so callers can inspect is_new,
        hostname, ad_object, etc. Returns None when identifier is empty or the
        target is rejected by the allowed-targets filter. In both None cases this
        method logs the reason itself (empty -> debug, filtered -> warning), so a
        None return is an intentional skip, not a registration failure — callers
        should not log their own "failed to register" message on the None path.
        """
        if not identifier or not identifier.strip():
            logger.debug("register_target: empty identifier (source=%r)", source)
            return None

        # Step 1: Resolve to AD object (best-effort, non-fatal)
        if not ad_object:
            try:
                ad_object = self.resolve_principal(identifier)
            except Exception as ex:
                # Best-effort: a missing LDAP client (ad=None) or a transient LDAP
                # error leaves ad_object None. The single user-facing "adding target
                # by name" warning is emitted in Step 3; keep the cause at verbose.
                logger.verbose("AD resolution failed for %r: %s", identifier, ex)

        if ad_object:
            identifier = ad_object.get("dns_host_name") or ad_object.get("name") or identifier
        # else: unresolved — reported once by the Step 3 warning below, not here.

        # Step 2: Allowed-targets filter
        if not self._is_allowed_target(identifier, ad_object):
            logger.warning("Skipping %r — not in allowed targets filter", identifier)
            return None

        # Step 3: Canonical name and dedup key
        sid = ad_object.get("object_sid") if ad_object else None
        # `sid` can only be set when ad_object exists, but testing both makes that
        # dependency visible instead of implied one line up.
        if ad_object and sid:
            canonical = ad_object.get("dns_host_name") or ad_object.get("name") or identifier
        else:
            canonical = identifier
            logger.warning(
                "Could not resolve %r to a domain object; adding target by name", identifier
            )
        canonical_lower = canonical.lower()

        with self._ensure_target_lock():
            # Step 4: Find existing entry — SID index first, hostname fallback
            existing: Optional[TargetEntry] = (
                self._target_hosts_by_sid.get(sid) if sid else None
            ) or self.target_hosts_by_hostname.get(canonical_lower)

            if existing is not None:
                logger.verbose(f"Already registered target: {existing.ad_object.get('dns_host_name') if existing.ad_object else existing.hostname}")
                # FQDN upgrade: re-key target_hosts_by_hostname
                if "." in canonical_lower and "." not in existing.hostname.lower():
                    logger.verbose("Upgrading hostname %r -> %r", existing.hostname, canonical)
                    del self.target_hosts_by_hostname[existing.hostname.lower()]
                    existing.hostname = canonical
                    self.target_hosts_by_hostname[canonical_lower] = existing
                # Backfill ad_object + SID index if we now have one
                if ad_object and existing.ad_object is None:
                    existing.ad_object = ad_object
                    if sid:
                        self._target_hosts_by_sid[sid] = existing
                # Merge source
                if source and source not in existing.sources:
                    existing.sources.append(source)
                # Merge site_code (first writer wins; warn on conflict)
                if site_code:
                    if not existing.site_code:
                        existing.site_code = site_code
                    elif existing.site_code != site_code:
                        logger.warning(
                            "Target %r already has site_code %r; ignoring %r",
                            canonical, existing.site_code, site_code,
                        )
                existing.is_new = False
                return existing

            # Step 5: New entry
            entry = TargetEntry(
                hostname=canonical,
                ad_object=ad_object,
                sources=[source] if source else [],
                site_code=site_code if site_code else None,
                is_new=True,
            )
            self.target_hosts_by_hostname[canonical_lower] = entry
            if sid:
                self._target_hosts_by_sid[sid] = entry
            if self.work_queue is not None:
                self.work_queue.submit(canonical)
            logger.info("Added collection target: %r from %r", canonical, source)
            return entry


    def target_hosts_snapshot(self) -> list:
        """Return the current list of probe targets (TargetEntry objects) as a copy.

        Per-host resources iterate this so late-registered hosts are picked
        up by phases that haven't started yet. Thread-safe against concurrent
        ``register_target`` mutations.
        """
        with self._ensure_target_lock():
            return list(self.target_hosts_by_hostname.values())