"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the ldap phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""
import re
import struct
import xml.etree.ElementTree as ET
from typing import Any, Iterable, Optional

import dlt
from ldap3 import BASE

from ..clients.ad import bytes_to_sid
from ..context import SourceContext
from ..log_context import get_logger, with_log_context
from ..main import app
from ..models.raw_table import raw_table_asset

logger = get_logger(__name__)


def _parse_mp_capabilities(capabilities_str: str, mp_site_code: str) -> dict:
    """Parse mSSMSCapabilities XML into structured fields.

    Returns a dict with keys: site_type, parent_site_code,
    command_line_site_code, root_site_code, fsp_hostname.
    Returns safe defaults on parse failure or empty input.
    """
    # Default assumption — overwritten below if XML parses successfully
    result: dict = {
        "site_type": "Secondary Site",
        "parent_site_code": "Undetermined",
        "command_line_site_code": None,
        "root_site_code": None,
        "fsp_hostname": None,
    }
    if not capabilities_str:
        return result
    try:
        # Clean unescaped ampersands before parsing
        clean = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", str(capabilities_str))
        root = ET.fromstring(clean)

        # Extract CommandLine site code
        # ClientOperationalSettings.CCM.CommandLine contains "SMSSITECODE=XYZ"
        ccm = root.find(".//CCM")
        if ccm is not None:
            cmd = ccm.get("CommandLine", "") or ""
            if not cmd:
                cl_elem = ccm.find("CommandLine")
                cmd = (cl_elem.text or "") if cl_elem is not None else (ccm.text or "")
            m = re.search(r"SMSSITECODE=([A-Z0-9]{3})", cmd, re.IGNORECASE)
            if m:
                result["command_line_site_code"] = m.group(1).upper()

        # Extract root site code — identifies the hierarchy root
        rs = root.find("RootSiteCode")
        if rs is None:
            rs = root.find(".//RootSiteCode")
        if rs is not None and rs.text:
            result["root_site_code"] = rs.text.strip().upper()

        # Extract the fallback status point hostname
        # An FSPServer node names a host serving as an FSP for this site. At
        # most one FSP is expected per MP; warn and keep the first if several.
        fsp_elem = root.find("FSP")
        if fsp_elem is None:
            fsp_elem = root.find(".//FSP")
        if fsp_elem is not None:
            fsp_hostnames = [
                s.text.strip()
                for s in fsp_elem.findall("FSPServer")
                if s.text and s.text.strip()
            ]
            if len(fsp_hostnames) > 1:
                logger.warning(
                    "Multiple FSPServer entries for site %s; using the first (%s)",
                    mp_site_code,
                    fsp_hostnames[0],
                )
            if fsp_hostnames:
                result["fsp_hostname"] = fsp_hostnames[0]

        # Determine site type from the relationship between this MP's site code,
        # the CommandLine site code, and the root site code
        mp_code = mp_site_code.upper() if mp_site_code else ""
        cmd_code = result["command_line_site_code"]
        root_code = result["root_site_code"]

        # Check if this MP's CommandLine site code matches the site we're analyzing
        if cmd_code and cmd_code == mp_code:
            # Primary Site: an MP exists whose CommandLine.SMSSITECODE equals
            # this site's code
            result["site_type"] = "Primary Site"
            # A different root site code indicates this Primary reports to a CAS
            result["parent_site_code"] = root_code if (root_code and root_code != mp_code) else "None"
        elif root_code and root_code == mp_code and cmd_code != mp_code:
            # Central Administration Site: an MP exists whose RootSiteCode equals
            # this site's code but CommandLine.SMSSITECODE points elsewhere
            result["site_type"] = "Central Administration Site"
            result["parent_site_code"] = "None"
        else:
            # Neither condition met — Secondary Site; parent is the root if known,
            # otherwise fall back to the CommandLine site code
            result["site_type"] = "Secondary Site"
            if root_code and root_code != mp_code:
                result["parent_site_code"] = root_code
            elif cmd_code and cmd_code != mp_code:
                result["parent_site_code"] = cmd_code

    except Exception as parse_err:
        logger.error("mSSMSCapabilities parse failed for %s: %s", mp_site_code, parse_err)
    return result


def _pick_client_device_site_code(
    primary_site_codes: set[str] | None, site_codes: set[str] | None
) -> str | None:
    """Choose the site code to stamp on a CmRcService-only ("possible") client device.

    A CAS publishes an mSSMSSite object like any other site, so ``site_codes`` alone can
    lead us to attach an inferred client to the CAS -- which cannot own clients. Prefer a
    Primary site (identified from management-point capabilities during
    ``ldap_management_points_raw``); fall back to any known site code, then None. Sorting
    keeps repeated runs deterministic. Mirrors CMBP's "first primary site published to
    AD" (ps1:3253-3254). The preproc transform is the authoritative corrector; this only
    sets the raw collected value.
    """
    if primary_site_codes:
        return sorted(primary_site_codes)[0]
    if site_codes:
        return sorted(site_codes)[0]
    return None


_SITE_ATTRS = [
    "mSSMSSiteCode",
    "mSSMSHealthState",
    "mSSMSSourceForest",
    "objectClass",
    "distinguishedName",
    "name",
]

@app.resource(name="ldap_sites", parallelized=False, columns=raw_table_asset("ldap_sites"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_sites(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    SCCM sites discovered via mSSMSSite objects in the System Management container.
    """
    if not ctx.method_enabled("LDAP"):
        return

    if ctx.site_codes is None:
        ctx.site_codes = set()
    seen_codes = ctx.site_codes
    site_count = 0

    logger.info("Searching for mSSMSSite objects in System Management container...")
    try:
        results = list(
            ctx.ad.paged_search(
                search_filter="(objectClass=mSSMSSite)",
                base=ctx.system_management_dn,
                attributes=_SITE_ATTRS,
            )
        )
    except Exception as ex:
        logger.error("Failed to search System Management container: %s", ex)
        logger.warning("The System Management container may not exist or access is denied")
        results = []

    for entry in results:
        try:
            site_code = entry.get("mSSMSSiteCode").strip()
            if not site_code:
                continue

            # Parse health state for SiteGUID
            site_guid = None
            health = entry.get("mSSMSHealthState")
            if health:
                m = re.search(rf"{re.escape(site_code)}\.(\{{[^}}]+\}})", str(health))
                if m:
                    site_guid = m.group(1)

            seen_codes.add(site_code.upper())
            site_count += 1
            logger.info("Found site: %s", site_code)

            yield {
                "collection_source": ["LDAP-mSSMSSite"],
                "distinguished_name": entry.get("distinguished_name"),
                "parent_site_code": "Undetermined", # Will be determined by mSSMSManagementPoint
                "sccm_infra": True,
                "site_code": site_code,
                "site_guid": site_guid,
                "source_forest": entry.get("mSSMSSourceForest"),
            }
        except Exception as ex:
            logger.error("Failed to process mSSMSSite entry %s: %s", entry.get("mSSMSSiteCode"), ex)
            logger.debug(f"Search result: {entry}")

    logger.info("Found %d mSSMSSite objects", site_count)


@app.resource(name="ldap_management_points_raw", parallelized=False, columns=raw_table_asset("ldap_management_points_raw"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_management_points_raw(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Management points, FSP hosts, and site classification from mSSMSManagementPoint.

    One row per mSSMSManagementPoint entry. Registers both the MP hostname and
    the FSP hostname parsed from mSSMSCapabilities as collection targets.
    Preproc transforms derive site_types, computer_mp_roles, computer_fsp_roles,
    and computer_site_system_roles from this table.
    """
    if not ctx.method_enabled("LDAP"):
        return
    
    logger.info("Searching for mSSMSManagementPoint objects in System Management container...")
    mp_count = 0
    fsp_count = 0

    try:
        results = list(
            ctx.ad.paged_search(
                search_filter="(objectClass=mSSMSManagementPoint)",
                base=ctx.system_management_dn,
                attributes=["mSSMSSiteCode", "mSSMSCapabilities", "mSSMSMPName"],
            )
        )
    except Exception as ex:
        logger.error("Failed to search System Management container: %s", ex)
        logger.warning("The System Management container may not exist or access is denied")
        results = []

    logger.info("Found %d mSSMSManagementPoint objects", len(results))

    for entry in results:

        try:
            mp_hostname = entry.get("mSSMSMPName")
            mp_site_code = (entry.get("mSSMSSiteCode") or "").strip()
            mp_code_upper = mp_site_code.upper() if mp_site_code else None

            # Register the management point as a collection target so its
            # per-host resources run in subsequent passes
            if mp_hostname:
                if not mp_site_code:
                    logger.warning("mSSMSManagementPoint missing site code: %s", mp_hostname)
                mp_target = ctx.register_target(
                    mp_hostname,
                    site_code=mp_code_upper,
                    source="LDAP-mSSMSManagementPoint",
                )
                if mp_target:
                    # register_target can return an entry with ad_object=None (host
                    # registered as a probe target but not resolved in AD yet) --
                    # ``.ad_object.get(...)`` unguarded would raise AttributeError,
                    # which the outer except would swallow by discarding this ENTIRE
                    # capabilities row, including site_type/parent_site_code/
                    # root_site_code that site_hierarchy (Task 1) depends on. Guard it.
                    mp_sid = mp_target.ad_object.get("object_sid") if mp_target.ad_object else None
                    sid_suffix = f" ({mp_sid})" if mp_sid else ""
                    logger.info("Found management point in site %s: %s%s", mp_site_code, mp_hostname, sid_suffix)
                    mp_count += 1
                # No else: register_target logs why it skipped (filtered host or
                # empty name), so a None return isn't a failure here.

            # Parse capabilities to determine site relationships and extract
            # FSP hostnames from the capabilities XML
            parsed = _parse_mp_capabilities(entry.get("mSSMSCapabilities") or "", mp_site_code)

            # A Primary site's MP advertises its own site code; record Primary sites so the
            # CmRcService discovery can attach inferred clients to a Primary rather than the
            # CAS (a CAS has no MP and cannot own clients). This resource runs before
            # ldap_cmrc_devices, so the set is populated by the time that resource reads it.
            if parsed["site_type"] == "Primary Site" and mp_code_upper:
                if ctx.primary_site_codes is None:
                    ctx.primary_site_codes = set()
                ctx.primary_site_codes.add(mp_code_upper)
                logger.verbose("Recorded Primary site %s from management-point capabilities", mp_code_upper)

            # Register the fallback status point as a collection target;
            # the FSP hostname comes from the FSPServer node inside the capabilities XML
            fsp_hostname = parsed["fsp_hostname"]
            # Hoisted out of the `if fsp_target:` block (was previously only used to
            # build the log-message suffix below and never reached the yielded row) so
            # the transform can key node_computer's FSP arm off a real sid instead of
            # having to invent one from the hostname.
            fsp_sid: Optional[str] = None
            if fsp_hostname:
                fsp_target = ctx.register_target(
                    fsp_hostname,
                    site_code=mp_code_upper,
                    source="LDAP-mSSMSManagementPoint",
                )
                if fsp_target:
                    # Same unresolved-in-AD guard as mp_target above -- an unguarded
                    # ``.ad_object.get(...)`` here would blow up the whole capabilities
                    # row (and this task's fsp_sid with it) the moment one FSP can't be
                    # resolved.
                    fsp_sid = fsp_target.ad_object.get("object_sid") if fsp_target.ad_object else None
                    sid_suffix = f" ({fsp_sid})" if fsp_sid else ""
                    logger.info("Found fallback status point in site %s: %s%s", mp_site_code, fsp_hostname, sid_suffix)
                    fsp_count += 1
                else:
                    # register_target returns None only when the --computers
                    # allowed-targets filter declines the host (an empty
                    # identifier is already ruled out by the `if fsp_hostname`
                    # guard above) -- it resolves the AD object internally
                    # BEFORE applying that filter (context.py Step 1 vs Step 2),
                    # so the object exists, it was just discarded. The filter
                    # gates *probing*, not *recording* (mirrors http.py's
                    # _register_and_resolve / D6): the sitesigncert probe
                    # resolves-without-probing for exactly this reason, so an
                    # FSP excluded from probing by --computers should still
                    # surface its role here rather than vanish silently.
                    # resolve_principal is cached, so this costs no extra LDAP
                    # round-trip.
                    fsp_ad_object = ctx.resolve_principal(fsp_hostname)
                    if fsp_ad_object:
                        fsp_sid = fsp_ad_object.get("object_sid")
                        sid_suffix = f" ({fsp_sid})" if fsp_sid else ""
                        logger.info(
                            "Found fallback status point in site %s: %s%s "
                            "(excluded from probing by --computers; recording its role only)",
                            mp_site_code, fsp_hostname, sid_suffix,
                        )
                        fsp_count += 1
                    else:
                        logger.debug(
                            "Fallback status point %s in site %s could not be resolved "
                            "in AD; no role will be recorded for it", fsp_hostname, mp_site_code,
                        )

            yield {
                "mp_hostname": mp_hostname,
                "site_code": mp_site_code,
                "site_type": parsed["site_type"],
                "parent_site_code": parsed["parent_site_code"],
                "command_line_site_code": parsed["command_line_site_code"],
                "root_site_code": parsed["root_site_code"],
                "fsp_hostname": parsed["fsp_hostname"],
                "fsp_sid": fsp_sid,
            }
        except Exception as ex:
            logger.error("Failed to process mSSMSManagementPoint entry %s: %s", entry.get("mSSMSMPName"), ex)
            logger.debug(f"Search result: {entry}")

    logger.info("Found %d management points and %d fallback status points", mp_count, fsp_count)


@app.resource(name="ldap_cmrc_devices", parallelized=False, columns=raw_table_asset("ldap_cmrc_devices"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_cmrc_devices(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    Computers with the CmRcService SPN registered, indicating they have the SCCM client remote control service installed.
    One row per computer with the CmRcService SPN. Registers each computer as a collection target for subsequent passes.
    """
    if not ctx.method_enabled("LDAP"):
        return

    logger.info("Searching for computers with Remote Control SPN (CmRcService/*)...")

    try:
        results = list(
            ctx.ad.paged_search(
                search_filter="(servicePrincipalName=CmRcService/*)",
                attributes = [
                    "dNSHostName", "distinguishedName", "objectClass", "servicePrincipalName", 
                    "objectSid", "cn", "name", "samAccountName"
                ]            
            )
        )
    except Exception as ex:
        logger.error("CmRcService search failed: %s", ex)
        results = []

    logger.info("Found %d computers with CmRcService SPN in %s", len(results), ctx.domain)
    
    # Give this client device a Primary site code -- a CAS is published to AD as an
    # mSSMSSite too but cannot own clients, so prefer a site the MP-capabilities parse
    # classified as Primary (ldap_management_points_raw ran first). This could still be
    # wrong in multi-Primary environments, but it stays in the same hierarchy, so it's
    # better than nothing for the offensive use case and is replaced by the authoritative
    # Primary from privileged site definitions during preprocess.
    site_code = _pick_client_device_site_code(ctx.primary_site_codes, ctx.site_codes)

    for entry in results:

        try:
            sid = entry.get("object_sid")
            dns_host_name = entry.get("dns_host_name")

            logger.verbose("Found computer with Remote Control SPN: %s (%s)", dns_host_name, sid)

            # Do NOT register the computer as a target. This could be any domain computer.

            yield {
                "object_sid": sid,
                "sam_account_name": entry.get("sam_account_name"),
                "name": entry.get("name"),
                "dns_host_name": dns_host_name,
                "domain": ctx.domain,
                "site_code": site_code,
            }
        except Exception as ex:
            logger.error("Failed to process computer with Remote Control SPN %s: %s", entry.get("dns_host_name"), ex)
            logger.debug(f"Search result: {entry}")


@app.resource(name="ldap_network_boot_servers", parallelized=False, columns=raw_table_asset("ldap_network_boot_servers"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_network_boot_servers(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    Searches for connectionPoint objects with netbootserver attribute and 
    intellimirrorSCP objects, which are likely WDS/PXE-enabled distribution points.
    """
    if not ctx.method_enabled("LDAP"):
        return

    logger.info("Searching for network boot servers (PXE-enabled DPs)...")

    # Search for connectionPoint objects with netbootserver
    try:
        netbootserver_rows = list(
            ctx.ad.paged_search(
                search_filter="(&(objectClass=connectionPoint)(netbootserver=*))",
                attributes = ["distinguishedName","objectClass"]            
            )
        )
        logger.info("Found %d connectionPoint objects with netbootserver in %s", len(netbootserver_rows), ctx.domain)   
    except Exception as ex:
        logger.error("netbootserver search failed: %s", ex)
        netbootserver_rows = []

    # Search for intellimirrorSCP objects
    try:
        intellimirror_rows = list(
            ctx.ad.paged_search(
                search_filter="(objectClass=intellimirrorSCP)",
                attributes = ["distinguishedName", "objectClass"]          
            )
        )
        logger.info("Found %d intellimirrorSCP objects in %s", len(intellimirror_rows), ctx.domain)
    except Exception as ex:
        logger.error("intellimirrorSCP search failed: %s", ex)
        intellimirror_rows = []

    # Uniquify and combine results from both searches because there may be some overlap
    # They are list[dict[str, Any]] with key distinguishedName
    all_results = {entry["distinguished_name"]: entry for entry in (netbootserver_rows + intellimirror_rows)}.values()

    if not all_results:
        logger.info("No network boot server objects found in %s", ctx.domain)
        return

    for entry in all_results:
        dn = entry.get("distinguished_name")
        obj_class = entry.get("object_class", [])
        if isinstance(obj_class, str):
            obj_class = [obj_class]

        if not dn:
            logger.warning(f"Network boot server entry missing distinguished_name: {entry}")
            logger.debug(f"Search result: {entry}")
            continue

        try:
            # Extract everything after the first comma to get parent DN (the computer object)
            computer_dn = dn.split(",", 1)[1] if "," in dn else None
            if not computer_dn:
                continue

            target = ctx.register_target(
                identifier=computer_dn,
                source=f"LDAP-{obj_class}",
            )

            if target and target.ad_object:
                logger.info(f"Found network boot server: {target.ad_object.get('dns_host_name')} ({target.ad_object.get('object_sid')})")
                yield target.ad_object
            elif target:
                # Registered, but with no AD object to emit. Previously this yielded None
                # into the dlt resource, which fails schema validation downstream with no
                # indication of which host caused it.
                logger.warning("Registered network boot server %s carries no AD object; nothing to emit", dn)
            # No else: register_target logs why it skipped (filtered host or
            # empty name), so a None return isn't a failure here.

        except Exception as ex:
            logger.error(f"Failed to process network boot server {dn}: {ex}")
            logger.debug(f"Search result: {entry}")


@app.resource(name="ldap_pattern_matches", parallelized=False, columns=raw_table_asset("ldap_pattern_matches"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_pattern_matches(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    Searches the domain for computers whose names match
    SCCM-related patterns (sccm, mecm, mcm, memcm, configm, cfgm, sms).
    """
    if not ctx.method_enabled("LDAP"):
        return

    logger.info("Searching for computers with SCCM naming patterns...")

    search_patterns = ["sccm", "mecm", "mcm", "memcm", "configm", "cfgm", "sms"]

    # Build dynamic LDAP filter to search for any of the patterns in multiple attributes
    filter_parts = []
    for pattern in search_patterns:
        filter_parts.append(f"(samaccountname=*{pattern}*)")
        filter_parts.append(f"(description=*{pattern}*)")
        filter_parts.append(f"(name=*{pattern}*)")
        filter_parts.append(f"(cn=*{pattern}*)")
        filter_parts.append(f"(displayname=*{pattern}*)")
        filter_parts.append(f"(serviceprincipalname=*{pattern}*)")
        filter_parts.append(f"(dnshostname=*{pattern}*)")
        filter_parts.append(f"(description=*{pattern}*)")

    ldap_filter = f"(&(objectCategory=computer)(|{''.join(filter_parts)}))"

    try:
        results = list(
            ctx.ad.paged_search(
                search_filter=ldap_filter,
                attributes=[
                    "sAMAccountName", "description", "name", "displayName",
                    "servicePrincipalName", "dNSHostName", "objectClass", "objectSid",
                ],
            )
        )
    except Exception as ex:
        logger.error("SCCM naming pattern search failed: %s", ex)
        results = []

    if not results:
        logger.info("No computers with SCCM naming patterns found")
        return

    logger.info("Found %d computers with SCCM naming patterns in %s", len(results), ctx.domain)

    for computer in results:

        try:
            # Add to collection targets for subsequent collection phases
            target = ctx.register_target(
                identifier=computer.get("object_sid"),
                source="LDAP-NamePattern",
                ad_object=computer,
            )

            if target and target.ad_object:
                logger.info(f"Found system with SCCM naming pattern: {target.ad_object.get('dns_host_name')} ({target.ad_object.get('object_sid')})")
                yield target.ad_object
            elif target:
                # See ldap_network_boot_servers: yielding a None ad_object breaks dlt
                # schema validation downstream rather than here.
                logger.warning("Registered pattern match %s carries no AD object; nothing to emit",
                               computer.get("name"))
            # No else: register_target logs why it skipped (filtered host or
            # empty name), so a None return isn't a failure here.

        except Exception as ex:
            logger.error(f"Failed to process search result {computer.get('name')}: {ex}")
            logger.debug(f"Search result: {computer}")


def _format_guid(raw_guid: Optional[str]) -> Optional[str]:
    """Render an AD objectGUID in SharpHound's canonical UPPERCASE 8-4-4-4-12 form.

    ADClient._entry_to_dict already decodes the binary objectGUID into that
    dashed form (bytes_to_guid), but lowercase. SharpHound's objectid for
    GUID-keyed AD objects (containers, OUs, GPOs) is always uppercase, so a
    Container node built here (Task 11) must match exactly or it will not merge
    with SharpHound's own node for the same object.
    """
    return raw_guid.upper() if raw_guid else None


@app.resource(name="ldap_system_management_dacl", parallelized=False, columns=raw_table_asset("ldap_system_management_dacl"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_system_management_dacl(ctx: SourceContext) -> Iterable[Any]:
    """
    Check ACLs on the System Management container.
    Looks for GenericAll (Full Control) permissions, which indicate site servers.

    Yields two shapes, hence the loose ``Iterable[Any]``: plain principal dicts for
    ``ldap_system_management_dacl`` itself, and ``dlt.mark.with_table_name``-wrapped rows
    routed to ``ldap_smc_group_members``. One resource feeding two tables is what lets the
    recursive group walk record every member -> group hop without a second LDAP pass.
    """
    if not ctx.method_enabled("LDAP"):
        return

    logger.info("Checking permissions on System Management container...")

    # Query the container's nTSecurityDescriptor
    # Need to use SD_FLAGS control to request DACL (0x04)
    # SD_FLAGS OID: 1.2.840.113556.1.4.801
    # BER value: SEQUENCE { INTEGER 4 } = 30 03 02 01 04
    system_mgmt_dn = f"CN=System Management,CN=System,{ctx.ad.base_dn}"

    try:
        sd_control = ("1.2.840.113556.1.4.801", True, bytes([0x30, 0x03, 0x02, 0x01, 0x04]))
        results = list(
            ctx.ad.paged_search(
            search_filter="(objectClass=container)",
            base=system_mgmt_dn,
            attributes=["nTSecurityDescriptor", "objectGUID", "name"],
            controls=[sd_control],
            )
        )
    except Exception as e:
        logger.error(f"Failed to read System Management container ACLs: {e}")
        return

    if not results:
        logger.warning("Could not read System Management container ACLs")
        return

    # Task 11 (Tier A+): capture the container's own identity once, so every
    # GenericAll principal row below can carry it through to the transform, which
    # builds a Container node (id = objectGUID, matching SharpHound's own node so
    # the two merge) and a GenericAll edge from each principal to it.
    container_guid = _format_guid(results[0].get("object_guid"))
    container_dn = results[0].get("distinguished_name") or system_mgmt_dn
    if container_guid:
        logger.debug("System Management container objectGUID resolved to %s", container_guid)
    else:
        # No usable GUID means Task 11's Container/GenericAll edges can't be built for
        # this run -- not fatal, the rest of this resource (GenericAll principal
        # discovery/registration) still proceeds unaffected.
        logger.warning(
            "System Management container has no resolvable objectGUID; "
            "Container/GenericAll edges will be skipped for this run"
        )

    sd_bytes = results[0].get("nTSecurityDescriptor")
    if not sd_bytes or not isinstance(sd_bytes, bytes):
        logger.warning("nTSecurityDescriptor not returned as bytes")
        logger.debug(f"nTSecurityDescriptor: {sd_bytes}")
        return

    # Parse security descriptor and extract GenericAll ACEs
    try:
        generic_all_sids = _parse_sd_generic_all(sd_bytes)
    except Exception as ex:
        logger.error(f"Failed to parse System Management container ACLs: {ex}")
        return
    
    if not generic_all_sids:
        logger.warning("No GenericAll permissions found on System Management container")
        return

    for sid_str in generic_all_sids:
        ad_obj = None

        try:
            # Resolve SID to AD object
            ad_obj = ctx.resolve_principal(sid_str)
            if not ad_obj:
                logger.warning(f"Could not resolve GenericAll principal '{sid_str}' to domain object")
                continue

            sam = ad_obj.get("sam_account_name")

            obj_class = ad_obj.get("object_class", [])
            if isinstance(obj_class, str):
                obj_class = [obj_class]

            # Determine object type
            obj_type = "unknown"
            if "computer" in [c.lower() for c in obj_class]:
                obj_type = "computer"

                # Add as collection target. register_target logs why it skipped
                # (filtered host or empty name), so we don't inspect the result.
                ctx.register_target(
                    identifier=ad_obj.get("dns_host_name"),
                    source="LDAP-GenericAllSystemManagement",
                    ad_object=ad_obj,
                )

            elif "user" in [c.lower() for c in obj_class]:
                obj_type = "user"
            elif "group" in [c.lower() for c in obj_class]:
                obj_type = "group"
                # Members effectively inherit Full Control on the container (ope-e191) —
                # recurse so member computers get registered as scan targets too, and
                # (Task 12) collect a MemberOf row for every member -> containing-group
                # hop the walk visits, at every nesting level. Routed to a distinct
                # table (ldap_smc_group_members) via dlt.mark so this one resource can
                # feed both the DACL-principal table and the membership table.
                for member_row in _expand_group_targets(ctx, ad_obj, set()):
                    yield dlt.mark.with_table_name(member_row, "ldap_smc_group_members")
            logger.info(f"Found {obj_type} with GenericAll on System Management container: {sam} ({sid_str})")

            # Task 11: stamp the container's identity on every principal row so the
            # transform can build the Container node + GenericAll edge from this
            # single table.
            ad_obj["smc_container_guid"] = container_guid
            ad_obj["smc_container_dn"] = container_dn

            yield ad_obj

        except Exception as ex:
            logger.error(f"Failed to process GenericAll principal {sid_str}: {ex}")


def _expand_group_targets(ctx: SourceContext, group_obj: dict[str, Any],
                           visited: set[str]) -> list[dict[str, Any]]:
    """Recursively register computer members of a group that holds GenericAll on the
    System Management container (ope-e191), and (Task 12) return a MemberOf row for
    every member -> containing-group hop the walk visits, at every nesting level.

    The recursion already descends nested groups (to register their computer
    members as scan targets), so accumulating one row per (member, its immediate
    parent group) at each level yields the full nested MemberOf chain for free —
    we already pay for the walk. Users are logged (modeled elsewhere via the
    caller's yield), nested groups recurse; visited guards circular nesting.
    """
    rows: list[dict[str, Any]] = []
    group_dn = group_obj.get("distinguished_name")
    group_sid = group_obj.get("object_sid")
    if not group_dn or group_dn in visited:
        logger.debug("System Management container ACL group expansion: skipping visited/empty group %s", group_dn)
        return rows
    visited.add(group_dn)
    grp = next(ctx.ad.paged_search("(objectClass=*)", ["member"], base=group_dn, scope=BASE), None) or {}
    members = grp.get("member") or []
    if isinstance(members, str):
        members = [members]
    # ldap3's auto_range (on by default in the shared client) transparently pages large
    # member lists and merges them under the plain "member" key. A residual "member;range="
    # key therefore means auto_range did NOT complete for this group — warn so the operator
    # knows membership may be incomplete rather than silently under-collecting.
    if any(str(k).lower().startswith("member;range=") for k in grp):
        logger.warning(
            "System Management container ACL group expansion: group %s returned a range-limited member attribute "
            "(ldap3 auto_range did not complete); membership may be incomplete — some "
            "controlling principals could be undiscovered. Review manually.",
            group_dn)
    if not members:
        logger.debug("System Management container ACL group expansion: group %s has no members", group_dn)
        return rows
    for member_dn in members:
        member = ctx.resolve_principal(member_dn)
        if not member:
            logger.warning("System Management container ACL group expansion: could not resolve member %s", member_dn)
            continue
        member_sid = member.get("object_sid")
        oc = member.get("object_class", [])
        oc = [oc] if isinstance(oc, str) else oc
        ocl = [c.lower() for c in oc]
        if group_sid and member_sid:
            rows.append({
                "group_sid": group_sid,
                "member_sid": member_sid,
                "member_type": oc[-1].lower() if oc else "unknown",
            })
        else:
            # No SID on one side means no MemberOf row can be keyed -- log and move
            # on rather than emit an unusable row (mirrors the existing "could not
            # resolve member" skip just above).
            logger.debug(
                "System Management container ACL group expansion: %s has no resolvable "
                "SID pair (group=%s member=%s); skipping MemberOf row",
                member_dn, group_sid, member_sid)
        if "computer" in ocl:
            ctx.register_target(identifier=member.get("dns_host_name"),
                                source="LDAP-GenericAllSystemManagement", ad_object=member)
        elif "group" in ocl:
            rows.extend(_expand_group_targets(ctx, member, visited))
        elif "user" in ocl:
            logger.info("System Management container ACL group expansion: user member %s controls the container (modeled, not a scan target)",
                        member.get("sam_account_name"))
        else:
            logger.warning("System Management container ACL group expansion: member %s has unhandled objectClass %s", member_dn, ocl)
    return rows


def _parse_sd_generic_all(sd_bytes: bytes) -> list[str]:
    """
    Parse a Windows SECURITY_DESCRIPTOR binary blob and return SIDs with GenericAll.

    In Active Directory, GenericAll maps to 0x000F01FF (Full Control) rather than
    the raw Windows GENERIC_ALL bit (0x10000000). The .NET ActiveDirectoryRights
    enum GenericAll = 0x000F01FF. We check for both, plus any mask that includes
    all the AD-specific rights.

    Structure reference:
    - SECURITY_DESCRIPTOR header (20 bytes for self-relative)
    - DACL at OffsetDacl
    - ACL header (8 bytes): revision, padding, size, ace_count, padding
    - Each ACE: AceType(1), AceFlags(1), AceSize(2), ACCESS_MASK(4), SID(variable)
    - ACCESS_ALLOWED_OBJECT_ACE (type 0x05) has extra: Flags(4), optional ObjectType(16),
      optional InheritedObjectType(16) before the SID
    """
    if len(sd_bytes) < 20:
        logger.warning("System Management container ACL: security descriptor too short (%d bytes); cannot parse ACEs", len(sd_bytes))
        return []

    # Parse SECURITY_DESCRIPTOR header
    offset_dacl = struct.unpack_from("<I", sd_bytes, 16)[0]

    if offset_dacl == 0 or offset_dacl >= len(sd_bytes):
        logger.warning(
            "System Management container ACL: DACL offset %d out of range (SD is %d bytes); cannot parse ACEs",
            offset_dacl, len(sd_bytes))
        return []

    # Parse ACL header at offset_dacl
    ace_count = struct.unpack_from("<H", sd_bytes, offset_dacl + 4)[0]

    results = []
    pos = offset_dacl + 8  # Skip ACL header

    # AD GenericAll = 0x000F01FF (DS Full Control)
    # Also check raw GENERIC_ALL = 0x10000000 in case it wasn't mapped
    AD_GENERIC_ALL = 0x000F01FF
    GENERIC_ALL = 0x10000000
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05

    for _ in range(ace_count):
        if pos + 4 > len(sd_bytes):
            logger.debug("System Management container ACL: truncated ACE header at offset %d; stopping ACE scan", pos)
            break

        ace_type = sd_bytes[pos]
        ace_size = struct.unpack_from("<H", sd_bytes, pos + 2)[0]

        if ace_size < 4 or pos + ace_size > len(sd_bytes):
            logger.debug(
                "System Management container ACL: invalid/overrunning ACE size %d at offset %d; stopping ACE scan",
                ace_size, pos)
            break

        if pos + 8 > len(sd_bytes):
            logger.debug("System Management container ACL: ACE at offset %d too short for an access mask; skipping", pos)
            pos += ace_size
            continue

        access_mask = struct.unpack_from("<I", sd_bytes, pos + 4)[0]
        is_generic_all = (access_mask & GENERIC_ALL) or (access_mask & AD_GENERIC_ALL) == AD_GENERIC_ALL

        if is_generic_all:
            sid_data = None

            if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                # ACCESS_ALLOWED_ACE: header(4) + mask(4) + SID
                sid_data = sd_bytes[pos + 8:pos + ace_size]

            elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                # ACCESS_ALLOWED_OBJECT_ACE: header(4) + mask(4) + flags(4) +
                #   [ObjectType(16)] + [InheritedObjectType(16)] + SID
                if pos + 12 <= len(sd_bytes):
                    obj_flags = struct.unpack_from("<I", sd_bytes, pos + 8)[0]
                    sid_start = pos + 12
                    if obj_flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                        sid_start += 16
                    if obj_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                        sid_start += 16
                    sid_data = sd_bytes[sid_start:pos + ace_size]

            if sid_data:
                sid_str = bytes_to_sid(sid_data)
                if sid_str:
                    results.append(sid_str)

        pos += ace_size

    return results
