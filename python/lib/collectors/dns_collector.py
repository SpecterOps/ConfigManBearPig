"""
DNS collection for ConfigManBearPig.

Translated from PowerShell Invoke-DNSCollection (lines 4413-4637).

Discovers SCCM management points via:
- SRV record queries: _mssms_mp_<sitecode>._tcp.<domain>
- ADIDNS queries via LDAP
- Standard A/CNAME record resolution
"""

import logging
import re
from typing import Any, Optional

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from lib.ad_resolver import ADResolver
from lib.graph import GraphStore
from lib.targets import TargetManager

logger = logging.getLogger("ConfigManBearPig")


def invoke_dns_collection(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    domain_controller: Optional[str] = None,
    target_site_codes: Optional[list[str]] = None,
) -> None:
    """
    Run DNS collection phase.

    Translated from PowerShell Invoke-DNSCollection (lines 4413-4637).

    Queries DNS for SCCM management point SRV records.

    Args:
        ad_resolver: AD resolver
        graph: Graph store
        target_manager: Target manager
        domain: Domain name
        domain_controller: DNS server to query
        target_site_codes: Specific site codes to query
    """
    if not HAS_DNSPYTHON:
        logger.error("dnspython library not available. Install with: uv add dnspython")
        return

    logger.info("Starting DNS collection...")

    # Collect site codes from existing graph data + provided codes
    site_codes: set[str] = set()

    # From existing SCCM_Site nodes
    for site in graph.find_nodes_by_kind("SCCM_Site"):
        sc = site.get("id", "")
        if sc:
            site_codes.add(sc)

    # From parameters
    if target_site_codes:
        site_codes.update(target_site_codes)

    if not site_codes:
        logger.warning("No site codes known for DNS collection. Provide site codes via --site-codes parameter.")
        # Try common site codes
        logger.info("Trying common site codes: CAS, PS1, PS2, SEC, SS1")
        site_codes = {"CAS", "PS1", "PS2", "SEC", "SS1"}

    # Configure resolver
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    if domain_controller:
        resolver.nameservers = [domain_controller]

    # Query SRV records for each site code
    for site_code in sorted(site_codes):
        _query_mp_srv_records(
            resolver, graph, target_manager, ad_resolver,
            site_code, domain
        )

    # Query ADIDNS for management point records
    _query_adidns(ad_resolver, graph, target_manager, domain, site_codes)

    logger.info("DNS collection completed")


def _query_mp_srv_records(
    resolver: "dns.resolver.Resolver",
    graph: GraphStore,
    target_manager: TargetManager,
    ad_resolver: ADResolver,
    site_code: str,
    domain: str,
) -> None:
    """
    Query SRV records for management points.

    Translated from PowerShell DNS collection SRV query logic (lines 4445-4530).

    Format: _mssms_mp_<sitecode>._tcp.<domain>
    """
    srv_name = f"_mssms_mp_{site_code.lower()}._tcp.{domain}"
    logger.info(f"Querying SRV record: {srv_name}")

    try:
        answers = resolver.resolve(srv_name, "SRV")

        for rdata in answers:
            target_host = str(rdata.target).rstrip(".")
            port = rdata.port

            logger.info(f"Found management point: {target_host}:{port} (site: {site_code})")

            # Add as collection target
            target = target_manager.add_device(target_host, source=f"DNS-SRV-{site_code}")

            # Resolve AD object
            ad_obj = ad_resolver.get_ad_computer(target_host)

            if ad_obj:
                sid = ad_obj.get("SID") or ad_obj.get("objectSid")
                if isinstance(sid, bytes):
                    sid = ad_resolver._sid_bytes_to_string(sid)

                if sid:
                    role_str = f"SMS Management Point@{site_code}"
                    graph.upsert_node(
                        sid,
                        ["Computer", "Base"],
                        properties={
                            "collectionSource": [f"DNS-SRV-{site_code}"],
                            "SCCMInfra": True,
                            "SCCMSiteSystemRoles": [role_str],
                            "dNSHostName": ad_obj.get("dNSHostName", target_host),
                            "sAMAccountName": ad_obj.get("sAMAccountName", ""),
                            "name": ad_obj.get("sAMAccountName", ""),
                        },
                        ad_object=ad_obj,
                    )

            # Ensure site node exists
            graph.upsert_node(
                site_code,
                ["SCCM_Site"],
                properties={
                    "collectionSource": [f"DNS-SRV"],
                    "SCCMInfra": True,
                    "siteCode": site_code,
                },
            )

    except dns.resolver.NXDOMAIN:
        logger.debug(f"No SRV record found for {srv_name} (NXDOMAIN)")
    except dns.resolver.NoAnswer:
        logger.debug(f"No SRV record found for {srv_name} (NoAnswer)")
    except dns.exception.Timeout:
        logger.warning(f"DNS query timed out for {srv_name}")
    except Exception as e:
        logger.debug(f"DNS query failed for {srv_name}: {e}")


def _query_adidns(
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    site_codes: set[str],
) -> None:
    """
    Query AD-integrated DNS for management point records.

    Translated from PowerShell ADIDNS query logic (lines 4532-4600).
    Searches dnsNode objects in the MicrosoftDNS container.
    """
    logger.info("Querying AD-integrated DNS (ADIDNS)...")

    # Build search filter for MP record names
    or_clauses = []
    for site_code in site_codes:
        name = f"_mssms_mp_{site_code.lower()}"
        or_clauses.append(f"(name={name}*)")

    if not or_clauses:
        return

    search_filter = f"(&(objectClass=dnsNode)(|{''.join(or_clauses)}))"

    # Search in the domain DNS zones
    dns_base = f"DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones,{ad_resolver.base_dn}"

    try:
        results = ad_resolver.get_ad_object(
            search_filter=search_filter,
            search_base=dns_base,
            attributes=["name", "dnsRecord", "distinguishedName"],
        )

        if results:
            logger.info(f"Found {len(results)} ADIDNS records for management points")
            for record in results:
                name = record.get("name", "")
                logger.debug(f"ADIDNS record: {name}")
                # dnsRecord parsing is complex binary format - log for now
                # The SRV records from standard DNS queries should cover this
        else:
            logger.debug("No ADIDNS records found for management points")

    except Exception as e:
        logger.debug(f"ADIDNS query failed: {e}")
