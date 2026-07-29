"""
This module hosts the ``@app.resource`` generators for the local phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""

from __future__ import annotations

import functools
import os
import platform
import re
from typing import Any, Iterable

from ..context import SourceContext
from ..main import app
from ..models.raw_table import raw_table_asset
from ..log_context import get_logger, with_log_context

logger = get_logger(__name__)


@functools.lru_cache(maxsize=1)
def _wmi_ccm():
    """Return the connected root\\CCM WMI service, or None if unavailable.

    A box that is local admin but not an SCCM client simply has no root\\CCM
    namespace, which is normal rather than an error. To tell that expected case
    apart from a genuine WMI problem (denied access, RPC down, corrupt
    repository), connect to the parent ``root`` namespace first and enumerate
    its child namespaces: connecting to ``root`` succeeds on any healthy Windows
    box, so a failure there is worth surfacing, while an absent ``CCM`` child
    just means "not a client" and is skipped quietly.
    """
    if platform.system() != "Windows":
        logger.info("Local collection only supported on Windows SCCM client devices")
        return None

    import win32com.client
    locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")

    # Reaching the parent root namespace should always work; failure here means
    # a real WMI problem, so surface it at ERROR (traceback follows under --debug).
    try:
        root = locator.ConnectServer(".", "root")
    except Exception as ex:
        logger.error("Failed to connect to WMI root namespace: %s", ex)
        return None

    # Look for the CCM child namespace via the __NAMESPACE system class. Its
    # absence is the ordinary non-client state; a failure to enumerate is not.
    try:
        ccm_present = any(
            getattr(ns, "Name", "").upper() == "CCM"
            for ns in root.InstancesOf("__NAMESPACE")
        )
    except Exception as ex:
        logger.error("Failed to enumerate WMI namespaces under root: %s", ex)
        return None

    if not ccm_present:
        logger.info("root\\CCM namespace not present; this host doesn't appear to be an SCCM client, skipping local collection")
        return None

    # CCM namespace exists, so this is an SCCM client -- connect and proceed.
    try:
        svc = locator.ConnectServer(".", "root\\CCM")
        logger.info("Connected to WMI root\\CCM namespace, proceeding with local collection")
        return svc
    except Exception as ex:
        logger.error("Failed to connect to WMI root\\CCM namespace: %s", ex)
        return None


# ---- Local collector ------------------------------------------------------
@app.resource(name="local_wmi_sms_authority", parallelized=False, columns=raw_table_asset("local_wmi_sms_authority"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_wmi_sms_authority(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """
    Yield row for the current management point and cache site code discovered in SMS_Authority WMI class.
    """
    if not ctx.method_enabled("Local"):
        return
    svc = _wmi_ccm()
    if svc is None:
        return

    logger.info("Starting local collection...")
    logger.info("Querying SMS_Authority for current management point and site code...")

    # site_codes is lazily created (same pattern as the LDAP phase) so a
    # local-first run doesn't crash adding to a None set.
    if ctx.site_codes is None:
        ctx.site_codes = set()
    site_codes = ctx.site_codes

    try:
        for item in svc.ExecQuery("SELECT * FROM SMS_Authority"):
            current_mp = getattr(item, "CurrentManagementPoint", None)
            # Extract site code from Name property (format: "SMS:PS1")
            ctx.current_site_code = getattr(item, "Name", "").split(":")[-1] if ":" in getattr(item, "Name", "") else None

            if ctx.current_site_code and ctx.current_site_code not in site_codes:
                logger.info(f"Found new site code '{ctx.current_site_code}' in local WMI repository")
                site_codes.add(ctx.current_site_code)

            if current_mp:
                target = ctx.register_target(
                    identifier=current_mp,
                    source="Local-SMS_Authority",
                    site_code=ctx.current_site_code if ctx.current_site_code else None
                )

                # Only emit a graph row when the MP resolved in AD; an
                # unresolved MP is still a probe target (register_target added
                # it) but has no AD identity to yield. register_target already
                # logged why it skipped a filtered/empty host.
                if target and target.ad_object:
                    logger.info(f"Found current management point: {target.ad_object.get('dns_host_name')} ({target.ad_object.get('object_sid')})")
                    ctx.current_mp_ad_object = target.ad_object
                    # Stamp the site code parsed from SMS_Authority.Name above -- on
                    # a Local-only run this is the sole site-code source, and without
                    # it site_hierarchy/_node_computer can never attribute this MP to
                    # a site (same defect class as dns_management_points).
                    yield {**target.ad_object, "site_code": ctx.current_site_code}

    except Exception as ex:
        logger.error("Error querying SMS_Authority: %s", ex)


@app.resource(name="local_wmi_sms_lookupmp", parallelized=False, columns=raw_table_asset("local_wmi_sms_lookupmp"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_wmi_sms_lookupmp(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """
    Yield row for other known management points discovered in SMS_LookupMP WMI class.
    """
    if not ctx.method_enabled("Local"):
        return
    svc = _wmi_ccm()
    if svc is None:
        return

    logger.info("Qeurying SMS_LookupMP for additional management points...")

    try:
        for item in svc.ExecQuery("SELECT * FROM SMS_LookupMP"):
            mp = getattr(item, "Name", None)

            if mp:
                target = ctx.register_target(
                    identifier=mp,
                    source="Local-SMS_LookupMP",
                    site_code=ctx.current_site_code if ctx.current_site_code else None
                )

                # Emit only resolved MPs; an unresolved one is still a probe
                # target but has no AD row to yield. register_target already
                # logged filtered/empty skips.
                if target and target.ad_object:
                    logger.info(f"Found management point: {target.ad_object.get('dns_host_name')} ({target.ad_object.get('object_sid')})")
                    # Same site-code stamp as local_wmi_sms_authority above --
                    # ctx.current_site_code is already cached from SMS_Authority.
                    yield {**target.ad_object, "site_code": ctx.current_site_code}

    except Exception as ex:
        logger.error("Error querying SMS_LookupMP: %s", ex)


@app.resource(name="local_wmi_ccm_client", parallelized=False, columns=raw_table_asset("local_wmi_ccm_client"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_wmi_ccm_client(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """
    Yield row for SCCM client device identifiers discovered in CCM_Client WMI class.
    """
    if not ctx.method_enabled("Local"):
        return
    svc = _wmi_ccm()
    if svc is None:
        return

    logger.info("Querying CCM_Client for client information...")

    try:
        for item in svc.ExecQuery("SELECT * FROM CCM_Client"):
            client_id = getattr(item, "ClientId", None)
            client_id_change_date = getattr(item, "ClientIdChangeDate", None)
            previous_client_id = getattr(item, "PreviousClientId", None)

            # Get COMPUTERNAME and USERDNSDOMAIN to resolve in AD
            computer_name = os.environ.get("COMPUTERNAME", None)
            user_dns_domain = os.environ.get("USERDNSDOMAIN", None)
            name_to_resolve = f"{computer_name}.{user_dns_domain}" if user_dns_domain else computer_name

            if name_to_resolve:
                try:
                    # Just resolve, don't add local host to targets
                    ctx.this_computer_ad_object = ctx.resolve_principal(name_to_resolve)
                except Exception as ex:
                    logger.error("Error resolving principal for %s: %s", name_to_resolve, ex)

            if client_id:
                log_suffix = ""
                if previous_client_id and previous_client_id != client_id:
                    log_suffix = f" (previous ID: {previous_client_id}"
                    if client_id_change_date:
                        log_suffix += f", changed on {client_id_change_date}"
                    log_suffix += ")"
                logger.info(f"Found client ID (SMSID) for {name_to_resolve}: {client_id} {log_suffix}")

                this_computer = ctx.this_computer_ad_object
                current_mp = ctx.current_mp_ad_object
                yield {
                    "ad_domain_sid": this_computer.get("object_sid") if this_computer else None,
                    "current_management_point": current_mp.get("dns_host_name") if current_mp else None,
                    "current_management_point_sid": current_mp.get("object_sid") if current_mp else None,
                    "distinguished_name": this_computer.get("distinguished_name") if this_computer else None,
                    "dns_host_name": this_computer.get("dns_host_name") if this_computer else None,
                    "name": this_computer.get("sam_account_name") if this_computer else None,
                    "previous_smsid_change_date": client_id_change_date,
                    "previous_smsid": previous_client_id,
                    "site_code": ctx.current_site_code if ctx.current_site_code else None,
                    "smsid": client_id,
                    "source": "Local-CCM_Client",
                }
    except Exception as ex:
        logger.error("Error querying CCM_Client: %s", ex)


def collection_settings_rows(ctx):
    """One row capturing the collect-time behaviour flags, so preproc/convert can
    gate possible nodes/edges without re-reading the CLI (the flags are collect-time)."""
    yield {
        "disable_possible_edges": bool(getattr(ctx, "disable_possible_edges", False)),
        "enable_bad_opsec": bool(getattr(ctx, "enable_bad_opsec", False)),
    }


@app.resource(name="collection_settings", parallelized=False, columns=raw_table_asset("collection_settings"))
def collection_settings(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Persist collect-time behaviour flags as a one-row table so the separate
    preproc/convert runs can gate possible nodes/edges without re-reading the CLI."""
    # ctx is injected the same way sibling local resources receive it; emit exactly one row.
    yield from collection_settings_rows(ctx)


@app.resource(name="local_client_logs_targets", parallelized=False, columns=raw_table_asset("local_client_logs_targets"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_client_logs_targets(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for management points and distribution points discovered via 
    local SCCM client log scrape.

    SCCM client logs (``CCM\\Logs\\*.log``, ``CCMSetup\\Logs\\*.log``) frequently
    reference MP and DP UNC and HTTP endpoints.
    """
    if not ctx.method_enabled("Local"):
        return
    if platform.system() != "Windows":
        return

    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    log_dirs = [
        os.path.join(system_root, "CCM", "Logs"),
        os.path.join(system_root, "ccmsetup", "Logs"),
    ]

    unc_pattern = re.compile(r"\\\\([a-zA-Z0-9\-_\s]{2,15}(?:\.[a-zA-Z0-9\-_\s]{1,64}){0,3})(\\[^\\\/:\*\?`\"<>\|;]{1,64})+(\\)?", re.IGNORECASE)
    # group(1) is the bare hostname used for target discovery (no port/path);
    # the trailing optional port and path/query keep group(0) spanning the whole
    # URL so the "Found URL" verbose log prints it in full, the way CMBP's
    # path-tail regex did. Without them group(0) stopped at "scheme://host".
    url_pattern = re.compile(
        r"\w+://(?:[\w@][\w.:@]+@)?([\w][\w.-]*)(?::\d+)?(?:/[\w.?=%&\-@/$,]*)?",
        re.IGNORECASE,
    )

    # Maps discovered hostname (lowercase) to its source type for targeted log messages.
    discovered: dict[str, str] = {}

    def _parse(path: str) -> None:
        file_name = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for m in unc_pattern.finditer(line):
                        unc_path = m.group(0).strip()
                        logger.verbose(f"Found UNC path in {file_name}: {unc_path}")
                        discovered.setdefault(m.group(1).lower(), "UNC path")
                    for m in url_pattern.finditer(line):
                        full_url = m.group(0).strip()
                        logger.verbose(f"Found URL in {file_name}: {full_url}")
                        discovered.setdefault(m.group(1).lower(), "URL")
        except Exception as ex:
            logger.error(f"Failed to search log file {path}: {ex}")

    for log_dir in log_dirs:
        if os.path.isdir(log_dir):
            try:
                for filename in os.listdir(log_dir):
                    if filename.endswith(".log"):
                        logger.verbose(f"Processing log file: {os.path.join(log_dir, filename)}")
                        _parse(os.path.join(log_dir, filename))
            except (Exception) as ex:
                logger.error(f"Failed to process log directory {log_dir}: {ex}")
                continue

    # Build the set of names that identify this machine once, so references to
    # ourselves in the logs are skipped. Guard each lookup: a resolved AD object
    # may lack dns_host_name / sam_account_name, and .lower() on a missing value
    # would crash.
    skip_hosts = {"localhost", "127.0.0.1"}
    this_computer = ctx.this_computer_ad_object
    if this_computer:
        for key in ("dns_host_name", "sam_account_name"):
            value = this_computer.get(key)
            if value:
                skip_hosts.add(value.lower())

    for host in sorted(discovered.keys()):
        # Skip localhost references and current machine
        if host in skip_hosts:
            logger.debug(f"Skipping localhost reference found in client logs: {host}")
            continue

        resolved_ip = ctx.resolve_ip(host)

        if resolved_ip:
            # Check RFC1918 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if (resolved_ip.startswith("10.") or
                (resolved_ip.startswith("172.") and 16 <= int(resolved_ip.split(".")[1]) <= 31) or
                resolved_ip.startswith("192.168.")):
                logger.info(f"Host resolved to RFC1918 IP address: {host} ({resolved_ip})")

                target = ctx.register_target(
                    identifier=host,
                    source="Local-ClientLogs",
                    site_code=ctx.current_site_code
                )

                # Emit only resolved hosts; an unresolved one is still a probe
                # target but has no AD row to yield. register_target already
                # logged filtered/empty skips.
                if target and target.ad_object:
                    logger.info(f"Found host in client logs: {target.ad_object.get('dns_host_name')} ({target.ad_object.get('object_sid')})")
                    yield target.ad_object
            else:
                logger.debug(f"Host found in client logs resolved to non-RFC1918 IP address, skipping: {host} ({resolved_ip})")
        else:
            logger.verbose(f"Failed to resolve hostname {host} from {discovered[host]}")