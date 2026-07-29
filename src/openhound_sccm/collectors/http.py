"""Unauthenticated HTTP role-probe per-host collector.

Port of ``Invoke-HTTPCollection`` (ConfigManBearPig.ps1:8602-8916) plus the
``Get-ManagementPointCertIssuer`` helper it calls first (8918-8998). For one
target it probes the SCCM web endpoints over ``http`` then ``https`` and reads
the *unauthenticated* status codes (401/403/200) to identify four site-system
roles -- Management Point, Distribution Point, SMS Provider, and (via the site
signing certificate) Site Server. Sibling management points parsed out of the MP
XML, and the site server named in the certificate, are registered as live probe
targets so the per-host pipeline fans out to them (PS1's ``Add-DeviceToTargets``).

Two deliberate departures from a byte-faithful port:

* PS1 wraps the whole MP-endpoint body in ``if ($isMP -ne
  $true)``, so on a healthy MP the first endpoint (MPKEYINFORMATION) confirms the
  role and MPLIST / SMSTRC / MPLIST1 never run, defeating their documented
  "enumerate MPs" / "check client cert" purpose. We keep the exact endpoint order
  but probe them all within a protocol (the cross-protocol guard stays).
* A row is emitted only when a role is *confirmed* by a positive
  response on an SCCM-specific path, so a non-SCCM target (e.g. a computer added
  only because it holds rights on the System Management container) 404s on every
  probe and is tagged with nothing. When a role is confirmed but the payload names
  no host (e.g. a cert-required MP whose MPKEYINFORMATION is 403), the row is
  attributed to the system we connected to -- the MP's self-reported FQDN, or the
  probe target itself.

Row shaping is shallow on purpose (spread AD object + role + ``site_code`` +
``client_cert_required``), mirroring ``registry.py`` / ``privileged.py``. The
comparative work (reconciling/merging rows for one host) is deferred to preproc,
and Computer / SCCM_Site node construction to convert.

Runs only when neither AdminService nor WMI already collected the host
(``per_host_phases.should_run_phase`` mirrors PS1's "Collected" skip at 8617).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable, Iterator, Optional

from ..clients.http import ErrorClass, HttpClient, HttpResult
from ..clients.http_auth import AuthMode
from ..context import SourceContext
from ..log_context import get_logger

logger = get_logger(__name__)


# --- transport + XML parsing helpers ---------------------------------------

def _is_connection_failure(result: HttpResult) -> bool:
    """PS1's ``IsConnectionFailure``: no HTTP response came back at all. A
    TLS/secure-channel failure counts too (PS1 lists SecureChannelFailure /
    TrustFailure among the connection-level statuses)."""
    return result.error_class in (ErrorClass.CONNECT_FAILURE, ErrorClass.TLS_FAILURE)


def _localname(tag: str) -> str:
    """Strip the ``{namespace}`` prefix ElementTree prepends to a tag, if any."""
    return tag.rsplit("}", 1)[-1]


def _find_text(elem: ET.Element, name: str) -> Optional[str]:
    """First descendant element whose local-name is *name*, its text stripped.

    Namespace-tolerant so the SCCM .sms_aut XML is read by element name
    regardless of any default namespace (mirrors PS1's ``//X509Certificate``
    and ``$xml.MPKEYINFORMATION.FQDN`` access, which ignore namespaces)."""
    for child in elem.iter():
        if _localname(child.tag) == name and child.text and child.text.strip():
            return child.text.strip()
    return None


def _parse_mpkeyinformation(content: bytes) -> tuple[Optional[str], Optional[str]]:
    """Return ``(fqdn, site_code)`` from an MPKEYINFORMATION XML body."""
    root = ET.fromstring(content)
    return _find_text(root, "FQDN"), _find_text(root, "SITECODE")


def _attr(elem: ET.Element, name: str) -> Optional[str]:
    """Attribute of *elem* whose local-name is *name* (namespace-tolerant), or None."""
    for key, value in elem.attrib.items():
        if _localname(key) == name and value and value.strip():
            return value.strip()
    return None


def _parse_mplist(content: bytes) -> list[str]:
    """Return the FQDN of every ``<MP>`` entry in an MPList XML body.

    The live SCCM MPList carries the FQDN as an *attribute* of ``<MP>``
    (``<MP Name="..." FQDN="...">``) -- which is what PS1's ``$mp.FQDN`` reads, since
    PowerShell's XML adapter surfaces attributes and child elements alike. Fall back
    to a child ``<FQDN>`` element for robustness."""
    root = ET.fromstring(content)
    fqdns: list[str] = []
    for mp in root.iter():
        if _localname(mp.tag) != "MP":
            continue
        fqdn = _attr(mp, "FQDN") or _find_text(mp, "FQDN")
        if fqdn:
            fqdns.append(fqdn)
    return fqdns


def _parse_sitesigncert_hex(content: bytes) -> Optional[str]:
    """Return the hex-encoded DER in the ``<X509Certificate>`` element, or None.

    PS1 sanity-checks the payload before decoding it (even length, >= 20 chars);
    we do the same so a malformed or truncated body never reaches the parser."""
    root = ET.fromstring(content)
    hex_der = _find_text(root, "X509Certificate")
    if hex_der and len(hex_der) % 2 == 0 and len(hex_der) >= 20:
        return hex_der
    return None


def _cert_issuer_and_dns(hex_der: str) -> tuple[Optional[str], Optional[str]]:
    """Parse a hex-DER X.509 certificate; return ``(issuer CN, first SAN DNS)``.

    PS1 reads the issuer CN (to detect a "Site Server" issuer) and the cert's
    first DNS name (the site server's hostname)."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(bytes.fromhex(hex_der))
    issuer_cn: Optional[str] = None
    issuer_cns = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if issuer_cns:
        # A NameAttribute value is normally str, but the API types it as str|bytes.
        value = issuer_cns[0].value
        issuer_cn = value if isinstance(value, str) else value.decode("utf-8", "replace")
    dns_name: Optional[str] = None
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        if isinstance(san, x509.SubjectAlternativeName):
            dns_names = san.get_values_for_type(x509.DNSName)
            if dns_names:
                dns_name = dns_names[0]
    except x509.ExtensionNotFound:
        logger.verbose("sitesigncert certificate has no Subject Alternative Name")
    return issuer_cn, dns_name


# UTF-16LE-encoded SCCM version string (e.g. "5.00.9141.1015") embedded in ccmsetup.exe.
# Matches SCCMVersionGuesser's regex. Bytes: 5 . XX . XXXX . XXXX, each char UTF-16LE.
_CCMSETUP_VERSION_RE = re.compile(
    rb"5\x00\.\x00\d\x00\d\x00\.\x00\d\x00\d\x00\d\x00\d\x00\.\x00\d\x00\d\x00\d\x00\d\x00"
)


def _extract_ccmsetup_version(body: bytes) -> Optional[str]:
    """Return the SCCM version string embedded in a ccmsetup.exe body, or None.

    A real ccmsetup.exe embeds several version strings -- a ``5.00.0000.0000`` template,
    older baseline versions, and the actual installed build (observed on a live 2303 MP:
    ``5.00.0000.0000``, ``5.00.7550.0000``, ``5.00.8690.1000``, ``5.00.9106.1000``). Return
    the highest version (compared field-by-field, so a tie on build falls through to the
    revision field) -- the installed build is the newest -- rather than the first match,
    which is typically the ``0000`` placeholder.
    """
    matches = _CCMSETUP_VERSION_RE.findall(body or b"")
    if not matches:
        return None
    versions = [m.decode("utf-16-le") for m in matches]
    # The regex guarantees 4 numeric dotted fields, so the int() conversion can't raise.
    return max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))


def _role_row(table: str, ad_object: Optional[dict], name_fallback: str, source: str,
              role_base: str, site_code: Optional[str],
              client_cert_required: Optional[bool]) -> tuple[str, dict]:
    """Build one role-tagged computer row: spread AD object + role + site facts.

    ``role`` is suffixed with ``@<site_code>`` when the site code is known, matching
    PS1's ``SMSSiteSystemRoles`` strings. Only called with a resolved ``ad_object``
    (PS1 guards every node upsert on ``$x.ADObject``); ``name_fallback`` is the
    discovered hostname used when the AD object carries no ``name``."""
    role = f"{role_base}@{site_code}" if site_code else role_base
    row = {
        **(ad_object or {}),
        "source": source,
        "sccm_infra": True,
        "sccm_site_system_roles": role,
        "site_code": site_code,
        "client_cert_required": client_cert_required,
    }
    row.setdefault("name", (ad_object or {}).get("name") or name_fallback)
    return table, row


def _register_and_resolve(ctx: SourceContext, identifier: str, source: str,
                          site_code: Optional[str] = None) -> Optional[dict]:
    """Register *identifier* as a probe target and return its resolved AD object.

    The allowed-targets (``--computers``) filter gates *probing*, not *recording*:
    ``register_target`` returns None for a host the filter excludes, but a filtered
    host is still a genuine discovery whose role row must be recorded. So when the
    host is declined for probing we resolve its AD object directly instead
    (``resolve_principal`` is cached, so this adds no LDAP round-trip). Returns None
    only when the host cannot be resolved in AD at all."""
    entry = ctx.register_target(identifier, source=source, site_code=site_code)
    if entry is not None:
        if entry.is_new:
            logger.info("Discovered and queued %s for probing (%s)", identifier, source)
        return entry.ad_object
    ad_object = ctx.resolve_principal(identifier)
    if ad_object is not None:
        logger.verbose("Adding %s site system role to results table", identifier)
    return ad_object


# --- site-signing certificate probe (PS1 Get-ManagementPointCertIssuer) -----

def _sitesigncert_probe(client: HttpClient, target: str,
                        ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    """Read the MP site-signing certificate; if its issuer is a Site Server,
    register that host and emit its role row.

    Runs first (PS1 8611) and is best-effort: the caller swallows any failure."""
    logger.verbose("Probing MP site signing certificate issuer on: %s", target)
    issuer_cn: Optional[str] = None
    dns_name: Optional[str] = None
    for protocol in ("http", "https"):
        url = f"{protocol}://{target}/SMS_MP/.sms_aut?sitesigncert"
        result = client.get(url)
        if result.error_class is not ErrorClass.RESPONSE or result.status_code != 200 or not result.content:
            logger.verbose("sitesigncert not available via %s on %s", protocol, target)
            continue
        hex_der = _parse_sitesigncert_hex(result.content)
        if not hex_der:
            logger.verbose("sitesigncert response on %s did not contain a valid hex payload", target)
            continue
        issuer_cn, dns_name = _cert_issuer_and_dns(hex_der)
        logger.verbose("sitesigncert issuer CN on %s: %s (DNS %s)", target, issuer_cn, dns_name)
        if issuer_cn:
            break

    if not (issuer_cn and "site server" in issuer_cn.lower() and dns_name):
        logger.verbose("No Site Server issuer detected via sitesigncert on %s", target)
        return

    logger.info("Detected Site Server certificate issuer %s via sitesigncert", dns_name)
    # The site server is a different host than the one we probed, and may be
    # excluded from probing by --computers -- but it's still a real discovery, so
    # resolve and record it even when register_target declines to queue it.
    ad_object = _register_and_resolve(ctx, dns_name, "HTTP-sitesigncert")
    if ad_object is None:
        return  # unresolved in AD; PS1 guards the node upsert on $x.ADObject
    target_entry = ctx.target_hosts_by_hostname.get(target.lower())
    site_code = target_entry.site_code if target_entry else None
    table, row = _role_row("http_site_servers", ad_object, dns_name, "HTTP-sitesigncert",
                           "SMS Site Server", site_code, None)
    # D6: sitesigncert is an MP endpoint, so the issuer named in the cert is the
    # site server of *this MP's* site. The probe runs before MPKEYINFORMATION has
    # set self.site_code (ps1:8611 ordering, which we must not change), so record
    # the MP we dialed and let the transform join it for the code. Mirrors
    # http_site_versions.mp_host.
    row["mp_host"] = target
    yield table, row


# --- per-target role probe state -------------------------------------------

class _HttpProbe:
    """Per-target probe state. Each method probes one role family, mutates the
    shared discovery flags (``site_code`` / ``client_cert_required`` / ``is_*``),
    and yields role rows. ``connection_failed`` short-circuits the whole run
    (PS1's ``$connectionFailed``)."""

    def __init__(self, client: HttpClient, target: str, ctx: SourceContext) -> None:
        self.client = client
        self.target = target
        self.ctx = ctx
        self.site_code: Optional[str] = None
        self.mp_self_fqdn: Optional[str] = None  # the MP's own FQDN per MPKEYINFORMATION
        self.client_cert_required = False
        self.is_mp = False
        self.is_dp = False
        self.is_sms = False
        self.connection_failed = False

    def _request(self, url: str) -> Optional[HttpResult]:
        """GET *url*; return the result, or None on connection failure. Sets
        ``connection_failed`` so the orchestrator stops probing this target."""
        result = self.client.get(url)
        if _is_connection_failure(result):
            logger.warning("Unable to connect to %s (%s) - skipping remaining HTTP checks",
                           url, result.error_class.value)
            self.connection_failed = True
            return None
        return result

    def _emit_role(self, table: str, identifier: str, source: str,
                   role_base: str) -> Iterator[tuple[str, dict]]:
        """Register *identifier* as a probe target and yield its role row.

        The allowed-targets filter gates *probing*, not *recording*: a host it
        excludes is still emitted as a discovered site system (see
        ``_register_and_resolve``). Yields nothing only when the host can't be
        resolved in AD at all -- PS1 guards every node upsert on ``$x.ADObject``."""
        ad_object = _register_and_resolve(self.ctx, identifier, source, self.site_code)
        if ad_object is None:
            return
        yield _role_row(table, ad_object, identifier, source, role_base,
                        self.site_code, self.client_cert_required)

    # --- management points -------------------------------------------------
    def management_points(self, protocol: str) -> Iterator[tuple[str, dict]]:
        """Probe every MP .sms_aut endpoint in order (decision B), then emit the
        connected MP's row plus any enumerated sibling MPs (decision 6)."""
        if self.is_mp:
            return  # already confirmed on the other protocol; don't re-probe
        endpoints = [
            (f"{protocol}://{self.target}/SMS_MP/.sms_aut?MPKEYINFORMATION", "MPKEYINFORMATION"),
            (f"{protocol}://{self.target}/SMS_MP/.sms_aut?MPLIST", "MPLIST"),
            (f"{protocol}://{self.target}/SMS_MP/.sms_aut?SMSTRC", "SMSTRC"),
        ]
        # Enumerate MPs for the other sites in the hierarchy. PS1 builds these from
        # the known SCCM_Site nodes; here the known site codes live on ctx.site_codes.
        for site_code in sorted(self.ctx.site_codes or ()):
            endpoints.append(
                (f"{protocol}://{self.target}/SMS_MP/.sms_aut?MPLIST1&{site_code}", "MPLIST"))

        siblings: list[str] = []
        for url, kind in endpoints:
            logger.verbose("Testing management point endpoint: %s", url)
            result = self._request(url)
            if result is None:
                return  # connection failure; orchestrator breaks the protocol loop
            if not (result.status_code == 403 or (result.status_code == 200 and result.content)):
                logger.verbose("    Received %s", result.status_code)
                continue
            if not self.is_mp:
                logger.info("Found management point role on %s", self.target)
            self.is_mp = True
            if kind == "MPKEYINFORMATION":
                self._read_mpkeyinformation(result)
            elif kind == "SMSTRC" and result.status_code == 403:
                self.client_cert_required = True
                logger.info("Client certificate required (SMSTRC 403) on %s", self.target)
            elif kind == "MPLIST":
                siblings.extend(self._read_mplist(result))

        if not self.is_mp:
            return
        # Confirmed MP: fingerprint the SCCM version from ccmsetup.exe (best effort).
        yield from self._probe_ccmsetup_version(protocol)
        # The host we connected to is itself an MP. Attribute its row to the FQDN
        # the MP reported for itself (MPKEYINFORMATION), or -- when that gave
        # nothing (e.g. a cert-required MP that 403s) -- to the probe target we
        # dialed (decision 6). Emitted after the loop so site_code and the cert
        # flag are final for every MP row.
        if self.mp_self_fqdn:
            yield from self._emit_role("http_management_points", self.mp_self_fqdn,
                                       "HTTP-MPKEYINFORMATION", "SMS Management Point")
        else:
            yield from self._emit_role("http_management_points", self.target,
                                       "HTTP-SMS_MP", "SMS Management Point")
        # Sibling MPs enumerated from MPLIST / MPLIST1 are separate hosts. PS1
        # mislabels their node source as "HTTP-MPKEYINFORMATION" (copy-paste bug at
        # 8743); the registration source is correctly "HTTP-MPLIST", which we use.
        # An MP's MPList lists itself among its siblings; skip that self-entry so
        # the connected MP isn't emitted twice (the row above already covers it).
        self_names = {name.lower() for name in (self.mp_self_fqdn, self.target) if name}
        for fqdn in siblings:
            if fqdn.lower() in self_names:
                continue
            yield from self._emit_role("http_management_points", fqdn,
                                       "HTTP-MPLIST", "SMS Management Point")

    def _read_mpkeyinformation(self, result: HttpResult) -> None:
        """Record the site code and the MP's self-reported FQDN (best effort)."""
        try:
            fqdn, site_code = _parse_mpkeyinformation(result.content or b"")
        except ET.ParseError as ex:
            logger.warning("Failed to parse MPKEYINFORMATION XML on %s: %s", self.target, ex)
            return
        if site_code:
            self.site_code = site_code
        if fqdn:
            self.mp_self_fqdn = fqdn
            logger.info("Found site code for %s: %s", fqdn, site_code)

    def _read_mplist(self, result: HttpResult) -> list[str]:
        """Return the sibling MP FQDNs listed in an MPLIST / MPLIST1 response."""
        try:
            return _parse_mplist(result.content or b"")
        except ET.ParseError as ex:
            logger.warning("Failed to parse MPLIST XML on %s: %s", self.target, ex)
            return []

    def _probe_ccmsetup_version(self, protocol: str) -> Iterator[tuple[str, dict]]:
        """Fingerprint the SCCM version from the MP's ccmsetup.exe (SCCMVersionGuesser).

        Best effort: a failed/missing/version-less fetch is logged and skipped; it never
        affects the MP role row -- unlike ``_request``, this bypasses ``connection_failed``
        entirely, so a timeout downloading the multi-MB ccmsetup.exe never aborts DP/SMS
        Provider probing for this target. Emits one http_site_versions row when a version
        is found.
        NOTE: v1 downloads the full ccmsetup.exe (multiple MB) via the existing anonymous
        HttpClient; a bounded/Range fetch is a future optimization (see ARCHITECTURE.md).
        """
        url = f"{protocol}://{self.target}/CCM_Client/ccmsetup.exe"
        logger.verbose("Fingerprinting SCCM version via %s", url)
        # ccmsetup.exe is a binary; the client's default Accept: application/json makes IIS
        # return 406 Not Acceptable for it, so request */* to receive the octet-stream.
        # Wrapped best-effort: a raised exception here must never abort the host's other
        # role probes (DP / SMS Provider), matching the "never affects role detection" contract.
        try:
            result = self.client.get(url, headers={"Accept": "*/*"})
        except Exception as ex:  # noqa: BLE001 - best-effort version fetch, never fatal
            logger.debug("ccmsetup.exe version probe on %s errored: %s", self.target, ex)
            return
        if _is_connection_failure(result) or result.status_code != 200 or not result.content:
            logger.debug("No ccmsetup.exe version fingerprint from %s (status=%s)",
                         self.target, result.status_code)
            return
        version = _extract_ccmsetup_version(result.content)
        if not version:
            logger.debug("ccmsetup.exe on %s had no parseable version string", self.target)
            return
        logger.info("Fingerprinted SCCM version %s on %s (site %s)",
                    version, self.target, self.site_code)
        yield ("http_site_versions", {
            "site_code": self.site_code,
            "sccm_version": version,
            "source": "HTTP-ccmsetup",
            "mp_host": self.mp_self_fqdn or self.target,
        })

    # --- distribution points ----------------------------------------------
    def distribution_points(self, protocol: str) -> Iterator[tuple[str, dict]]:
        """Probe the DP package-share endpoint; 401/200/403 indicate a DP."""
        if self.is_dp:
            return
        url = f"{protocol}://{self.target}/SMS_DP_SMSPKG$"
        logger.verbose("Testing distribution point endpoint: %s", url)
        result = self._request(url)
        if result is None:
            return  # connection failure
        if result.status_code in (401, 200, 403):
            self.is_dp = True
            if result.status_code == 403:
                self.client_cert_required = True
        else:
            logger.verbose("    Received %s", result.status_code)
            return
        logger.info("Found distribution point role on %s", self.target)
        yield from self._emit_role("http_distribution_points", self.target,
                                   "HTTP-SMS_DP_SMSPKG$", "SMS Distribution Point")

    # --- SMS provider ------------------------------------------------------
    def sms_provider(self) -> Iterator[tuple[str, dict]]:
        """Probe the AdminService identification endpoint; 401/200/403 indicate
        an SMS Provider. HTTPS-only regardless of the loop protocol (PS1 8834)."""
        if self.is_sms:
            return
        url = f"https://{self.target}/AdminService/wmi/SMS_Identification"
        logger.verbose("Testing SMS Provider endpoint: %s", url)
        result = self._request(url)
        if result is None:
            return  # connection failure
        if result.status_code in (401, 200, 403):
            self.is_sms = True
            if result.status_code == 403:
                self.client_cert_required = True
        else:
            logger.verbose("    Received %s", result.status_code)
            return
        logger.info("Found SMS Provider role on %s", self.target)
        yield from self._emit_role("http_smsproviders", self.target,
                                   "HTTP-SMS_Identification", "SMS Provider")


# --- orchestrator + entry point --------------------------------------------

def collect_http(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield role-tagged rows discovered by unauthenticated HTTP probing of *target*.

    PS1 order: the site-signing-certificate issuer probe first, then for ``http``
    and ``https`` the Management Point, Distribution Point, and SMS Provider
    endpoints. Newly discovered MPs and the site server are registered as live
    probe targets. A connection failure on either protocol stops everything."""
    if not ctx.method_enabled("HTTP"):
        return
    logger.info("Attempting HTTP collection on: %s", target)
    client = HttpClient.from_context(ctx, target, auth=AuthMode.NONE)
    try:
        # Step 1 (PS1 8611): site-signing-certificate issuer probe -- best effort.
        try:
            yield from _sitesigncert_probe(client, target, ctx)
        except Exception as ex:  # noqa: BLE001 - PS1 swallows this probe's failures
            logger.verbose("sitesigncert issuer probe failed or not applicable on %s: %s", target, ex)

        # Step 2: role endpoints over http, then https. A connection failure on
        # either protocol stops everything (PS1's $connectionFailed break).
        probe = _HttpProbe(client, target, ctx)
        for protocol in ("http", "https"):
            logger.verbose("Trying connections via %s", protocol)
            try:
                yield from probe.management_points(protocol)
                if probe.connection_failed:
                    break
                yield from probe.distribution_points(protocol)
                if probe.connection_failed:
                    break
                yield from probe.sms_provider()
            except Exception as ex:  # noqa: BLE001 - one protocol's failure isn't fatal
                logger.warning("HTTP collection failed for protocol %s on %s: %s", protocol, target, ex)
            if probe.connection_failed:
                break
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("HTTP collection failed for %s: %s", target, ex)
    finally:
        client.close()
    logger.info("HTTP collection completed for %s", target)
