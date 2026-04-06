#!/usr/bin/env python3
"""
ConfigManBearPig: Python SCCM Data Collector for BloodHound OpenGraph

Translated from PowerShell ConfigManBearPig.ps1 by SpecterOps.

Collects SCCM/ConfigMgr data following these ordered steps:
    1.  LDAP (identify sites, site servers, management points)
    2.  Local (identify management points and DPs from logs)
    3.  DNS (identify management points published to DNS)
    4.  DHCP (identify PXE-enabled DPs) [stub]
    5.  Remote Registry (identify site servers, databases, current users)
    6.  MSSQL (check database servers for EPA)
    7.  AdminService (collect info from SMS Providers)
    8.  WMI (fallback if AdminService fails) [stub]
    9.  HTTP (identify MPs, DPs, SMS Providers via web services)
    10. SMB (identify site servers and DPs via file shares)

Usage:
    uv run python configmanbearpig.py -d mayyhem.com -dc 10.2.10.100 \\
        -u MAYYHEM\\domainadmin -p password

    uv run python configmanbearpig.py -d mayyhem.com -dc 10.2.10.100 \\
        -u MAYYHEM\\domainadmin -p password \\
        -m AdminService -sms cas-pss.mayyhem.com

Setup (requires uv - https://docs.astral.sh/uv/):
    cd collector_python
    uv sync
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.logging_utils import setup_logging, log_message
from lib.graph import GraphStore
from lib.ad_resolver import ADResolver
from lib.targets import TargetManager
from lib.pipeline import PipelineOrchestrator, get_selected_phases, PHASES_ONCE
from lib.post_processing import invoke_post_processing
from lib.output import export_bloodhound_data, generate_custom_nodes_json

# Collectors
from lib.collectors.ldap_collector import invoke_ldap_collection
from lib.collectors.local_collector import invoke_local_collection
from lib.collectors.dns_collector import invoke_dns_collection
from lib.collectors.dhcp_collector import invoke_dhcp_collection
from lib.collectors.registry_collector import invoke_remote_registry_collection
from lib.collectors.mssql_collector import invoke_mssql_collection
from lib.collectors.adminservice_collector import invoke_adminservice_collection
from lib.collectors.wmi_collector import invoke_wmi_collection
from lib.collectors.http_collector import invoke_http_collection
from lib.collectors.smb_collector import invoke_smb_collection


# Script version
SCRIPT_VERSION = "1.2-python"
SCRIPT_NAME = "ConfigManBearPig"


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments matching the PowerShell parameter block."""
    parser = argparse.ArgumentParser(
        description=(
            "ConfigManBearPig: Python SCCM Data Collector for BloodHound OpenGraph\n"
            "Translated from PowerShell by SpecterOps"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Full collection with explicit creds (works through proxychains):\n"
            "  uv run python configmanbearpig.py -d mayyhem.com -dc 10.2.10.100 \\\n"
            "      -u MAYYHEM\\\\domainadmin -p password\n"
            "\n"
            "  # AdminService only against specific SMS Provider:\n"
            "  uv run python configmanbearpig.py -d mayyhem.com -dc 10.2.10.100 \\\n"
            "      -u MAYYHEM\\\\domainadmin -p password \\\n"
            "      -m AdminService -sms cas-pss.mayyhem.com\n"
            "\n"
            "  # Generate custom node types JSON:\n"
            "  uv run python configmanbearpig.py --custom-nodes\n"
        ),
    )

    # Connection parameters
    conn = parser.add_argument_group("Connection")
    conn.add_argument(
        "-d", "--domain",
        help="Domain name (e.g., mayyhem.com)",
    )
    conn.add_argument(
        "-dc", "--domain-controller",
        help="Domain controller hostname or IP",
    )
    conn.add_argument(
        "-u", "--username",
        help="Username in DOMAIN\\\\user format for explicit auth",
    )
    conn.add_argument(
        "-p", "--password",
        help="Password for explicit auth",
    )
    conn.add_argument(
        "--ldap-port",
        type=int,
        default=389,
        help="LDAP port (default: 389, use 636 for LDAPS)",
    )
    conn.add_argument(
        "--ldaps",
        action="store_true",
        help="Use LDAPS (SSL)",
    )

    # Collection parameters
    coll = parser.add_argument_group("Collection")
    coll.add_argument(
        "-m", "--collection-methods",
        default="All",
        help=(
            "Collection methods (comma-separated): "
            "All, LDAP, Local, DNS, DHCP, RemoteRegistry, MSSQL, "
            "AdminService, WMI, HTTP, SMB"
        ),
    )
    coll.add_argument(
        "-c", "--computers",
        help="Comma-separated list of computer targets",
    )
    coll.add_argument(
        "-cf", "--computer-file",
        help="File containing computer targets (one per line)",
    )
    coll.add_argument(
        "-sms", "--sms-provider",
        help="Specific SMS Provider to collect from",
    )
    coll.add_argument(
        "-sc", "--site-codes",
        help="Site codes for DNS collection (comma-separated or file path)",
    )

    # Behavior flags
    flags = parser.add_argument_group("Flags")
    flags.add_argument(
        "--disable-possible-edges",
        action="store_true",
        help="Disable creation of possible (uncertain) edges",
    )
    flags.add_argument(
        "--enable-bad-opsec",
        action="store_true",
        help="Enable bad opsec operations (NAA decryption, etc.)",
    )
    flags.add_argument(
        "-t", "--threads",
        type=int,
        default=1,
        help="Number of parallel threads for per-host collection (default: 1, sequential)",
    )
    flags.add_argument(
        "--show-cleartext-passwords",
        action="store_true",
        help="Display cleartext passwords when discovered",
    )

    # Machine account / CRED-2 parameters
    cred = parser.add_argument_group("Machine Account (CRED-2)")
    cred.add_argument(
        "--machine-name",
        help="Machine account name (DOMAIN\\\\MACHINE$) for SCCM client registration",
    )
    cred.add_argument(
        "--machine-pass",
        help="Machine account password for SCCM client registration",
    )
    cred.add_argument(
        "--client-name",
        help="Client FQDN to register (default: auto-generated)",
    )
    cred.add_argument(
        "--create-machine-account",
        nargs="?",
        const="auto",
        default=None,
        metavar="NAME",
        help="Create a machine account for CRED-2. Use 'auto' or omit value for auto-generated name, "
             "or specify a name (e.g., MYPC). Requires domain creds and MachineAccountQuota > 0. "
             "Use --machine-pass to set the password (auto-generated if omitted).",
    )
    cred.add_argument(
        "--use-altauth",
        action="store_true",
        help="Use ccm_system_altauth endpoint (bypasses mTLS requirement)",
    )
    cred.add_argument(
        "--registration-sleep",
        type=int,
        default=10,
        help="Seconds to wait after SCCM registration before policy request (default: 10)",
    )

    # Network / proxy parameters
    net = parser.add_argument_group("Network")
    net.add_argument(
        "--socks-proxy",
        help=(
            "SOCKS5 proxy in HOST:PORT format for DHCP/TFTP collection. "
            "Proxychains cannot relay UDP; use this for CRED-1 PXE attacks through a tunnel."
        ),
    )

    # Output parameters
    out = parser.add_argument_group("Output")
    out.add_argument(
        "-o", "--output",
        help="Output directory for ZIP file (default: current directory)",
    )
    out.add_argument(
        "--temp-dir",
        help="Temporary directory for JSON files before zipping",
    )
    out.add_argument(
        "--custom-nodes",
        action="store_true",
        help="Output custom node types JSON and exit",
    )
    out.add_argument(
        "--file-size-limit",
        default="1GB",
        help="Max cumulative file size (e.g., 500MB, 1GB)",
    )
    out.add_argument(
        "--log-file",
        default="ConfigManBearPig_output.log",
        help="Log file path",
    )

    # General
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit",
    )

    return parser.parse_args()


def get_input_targets(
    computers: Optional[str],
    computer_file: Optional[str],
    sms_provider: Optional[str],
) -> set[str]:
    """
    Parse input targets from arguments.

    Translated from PowerShell Get-InputTargets (lines 9851-9871).
    """
    targets: set[str] = set()

    if computers:
        for c in computers.split(","):
            c = c.strip()
            if c:
                targets.add(c)

    if computer_file:
        if os.path.isfile(computer_file):
            with open(computer_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        targets.add(line)
        else:
            print(f"Warning: File not found: {computer_file}", file=sys.stderr)

    if sms_provider:
        targets.add(sms_provider.strip())

    return targets


def parse_site_codes(site_codes_arg: Optional[str]) -> list[str]:
    """Parse site codes from argument (file path or comma-separated string)."""
    if not site_codes_arg:
        return []

    if os.path.isfile(site_codes_arg):
        with open(site_codes_arg, "r") as f:
            return [line.strip() for line in f if line.strip()]

    return [sc.strip() for sc in site_codes_arg.split(",") if sc.strip()]


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Handle version
    if args.version:
        print(f"{SCRIPT_NAME} version {SCRIPT_VERSION}")
        return 0

    # Handle custom nodes
    if args.custom_nodes:
        custom = generate_custom_nodes_json()
        print(json.dumps(custom, indent=2))
        return 0

    # Set up logging
    logger = setup_logging(
        log_file=args.log_file,
        verbose=args.verbose,
    )

    start_time = time.time()

    # Banner
    log_message(logger, "Info", "=" * 80)
    log_message(logger, "Info", "ConfigManBearPig - SCCM Data Collector for BloodHound (Python)")
    log_message(logger, "Info", f"Version: {SCRIPT_VERSION}")
    log_message(logger, "Info", f"Collection Method: {args.collection_methods}")
    log_message(logger, "Info", "=" * 80)

    # Validate required parameters
    if not args.domain:
        log_message(logger, "Error", "Domain is required. Use -d/--domain to specify.")
        return 1

    domain = args.domain
    dc = args.domain_controller
    username = args.username
    password = args.password

    # If username provided without domain prefix, warn
    if username and "\\" not in username and "@" not in username:
        log_message(logger, "Warning", "Username should be in DOMAIN\\user format")

    log_message(logger, "Info", f"Domain: {domain}")
    if dc:
        log_message(logger, "Info", f"Domain Controller: {dc}")
    if username:
        log_message(logger, "Info", f"Username: {username}")

    # Initialize components
    graph = GraphStore()

    try:
        ad_resolver = ADResolver(
            domain=domain,
            domain_controller=dc,
            username=username,
            password=password,
            use_ssl=args.ldaps,
            port=args.ldap_port if not args.ldaps else 636,
        )
        log_message(logger, "Success", "LDAP connection established")
    except Exception as e:
        log_message(logger, "Error", f"Failed to connect to LDAP: {e}")
        return 1

    # Test DNS resolution
    try:
        import socket
        socket.getaddrinfo(domain, None)
        log_message(logger, "Success", "DNS resolution successful")
    except socket.gaierror:
        log_message(logger, "Error", f"DNS resolution failed for {domain}")
        return 1

    # Parse input targets
    input_targets = get_input_targets(
        args.computers, args.computer_file, args.sms_provider
    )

    # Set up allowed targets filter
    allowed_targets = input_targets if input_targets else None

    target_manager = TargetManager(
        ad_resolver=ad_resolver,
        allowed_targets=allowed_targets,
    )

    # Seed targets
    for host in input_targets:
        if args.sms_provider and host == args.sms_provider:
            source = "ScriptParameter-SMSProvider"
        elif args.computers and host in args.computers.split(","):
            source = "ScriptParameter-Computers"
        elif args.computer_file:
            source = "ScriptParameter-ComputerFile"
        else:
            source = "ScriptParameter"
        target_manager.add_device(host, source=source)

    # Get selected phases
    selected_phases = get_selected_phases(args.collection_methods)
    log_message(logger, "Info", f"Selected phases: {', '.join(selected_phases)}")

    # SMS Provider convenience mode
    if args.sms_provider:
        once_requested = [p for p in ["LDAP", "Local", "DNS", "DHCP"] if p in selected_phases]
        if not once_requested:
            selected_phases = [p for p in ["AdminService", "WMI"] if p in selected_phases]
            if not selected_phases:
                selected_phases = ["AdminService", "WMI"]
            log_message(logger, "Info", f"SMS Provider mode -> phases: {', '.join(selected_phases)}")

    # Parse site codes
    target_site_codes = parse_site_codes(args.site_codes)
    if target_site_codes:
        log_message(logger, "Info", f"Target site codes: {', '.join(target_site_codes)}")

    # Set up pipeline
    max_threads = max(1, args.threads)
    if max_threads > 1:
        log_message(logger, "Info", f"Parallel mode: {max_threads} threads")
    pipeline = PipelineOrchestrator(max_workers=max_threads)

    # Register once-phase handlers
    pipeline.register_once_handler(
        "LDAP",
        lambda: invoke_ldap_collection(
            ad_resolver, graph, target_manager, domain,
            args.disable_possible_edges, target_site_codes,
        ),
    )
    pipeline.register_once_handler(
        "Local",
        lambda: invoke_local_collection(
            graph, target_manager, domain,
            args.enable_bad_opsec, args.show_cleartext_passwords,
            args.disable_possible_edges,
            ad_resolver=ad_resolver,
        ),
    )
    pipeline.register_once_handler(
        "DNS",
        lambda: invoke_dns_collection(
            ad_resolver, graph, target_manager, domain, dc, target_site_codes,
        ),
    )
    pipeline.register_once_handler(
        "DHCP",
        lambda: invoke_dhcp_collection(
            graph, target_manager, domain,
            socks_proxy=args.socks_proxy,
        ),
    )

    # Register per-host phase handlers
    pipeline.register_per_host_handler(
        "RemoteRegistry",
        lambda target: invoke_remote_registry_collection(
            target, ad_resolver, graph, target_manager, domain, username, password,
            args.disable_possible_edges,
        ),
    )
    pipeline.register_per_host_handler(
        "MSSQL",
        lambda target: invoke_mssql_collection(
            target, ad_resolver, graph, target_manager, domain, username, password,
            args.disable_possible_edges,
        ),
    )
    pipeline.register_per_host_handler(
        "AdminService",
        lambda target: invoke_adminservice_collection(
            target, ad_resolver, graph, target_manager, domain, username, password,
            args.disable_possible_edges,
        ),
    )
    pipeline.register_per_host_handler(
        "WMI",
        lambda target: invoke_wmi_collection(
            target, ad_resolver, graph, target_manager, domain, username, password,
            args.disable_possible_edges,
        ),
    )
    pipeline.register_per_host_handler(
        "HTTP",
        lambda target: invoke_http_collection(
            target, ad_resolver, graph, target_manager, domain, username, password,
            enable_bad_opsec=args.enable_bad_opsec,
            show_cleartext_passwords=args.show_cleartext_passwords,
            machine_name=args.machine_name,
            machine_pass=args.machine_pass,
            client_name=args.client_name,
            use_altauth=args.use_altauth,
            registration_sleep=args.registration_sleep,
            create_machine_account=args.create_machine_account,
            domain_controller=dc,
        ),
    )
    pipeline.register_per_host_handler(
        "SMB",
        lambda target: invoke_smb_collection(
            target, ad_resolver, graph, target_manager, domain, username, password,
            enable_bad_opsec=args.enable_bad_opsec,
            show_cleartext_passwords=args.show_cleartext_passwords,
        ),
    )

    # Run collection
    try:
        log_message(logger, "Info", "Initializing SCCM collection...")
        pipeline.run(
            selected_phases=selected_phases,
            get_targets=lambda: list(target_manager.targets.values()),
        )
        log_message(logger, "Success", "SCCM collection completed.")
    except KeyboardInterrupt:
        log_message(logger, "Warning", "Collection interrupted by user")
    except Exception as e:
        log_message(logger, "Error", f"Critical error during collection: {e}")
        import traceback
        log_message(logger, "Error", f"Stack trace: {traceback.format_exc()}")

    # Post-processing — skip if nothing was collected
    if not graph.nodes and not graph.edges:
        log_message(logger, "Warning", "No nodes or edges collected — skipping post-processing")
    else:
        try:
            invoke_post_processing(graph, args.disable_possible_edges, domain=domain)
        except Exception as e:
            log_message(logger, "Error", f"Post-processing failed: {e}")
            import traceback
            log_message(logger, "Error", f"Stack trace: {traceback.format_exc()}")

    # Export
    try:
        zip_path = export_bloodhound_data(
            graph=graph,
            temp_dir=args.temp_dir,
            zip_dir=args.output,
            file_size_limit=args.file_size_limit,
        )
        if zip_path:
            log_message(logger, "Success", f"Final output: {zip_path}")
    except Exception as e:
        log_message(logger, "Error", f"Export failed: {e}")

    # Elapsed time
    elapsed = time.time() - start_time
    total_sec = int(elapsed)
    if total_sec < 60:
        elapsed_str = f"{total_sec}s"
    elif total_sec < 3600:
        elapsed_str = f"{total_sec // 60}m {total_sec % 60}s"
    else:
        h = total_sec // 3600
        m = (total_sec % 3600) // 60
        s = total_sec % 60
        elapsed_str = f"{h}h {m}m {s}s"

    log_message(logger, "Success", f"ConfigManBearPig completed in {elapsed_str}")
    log_message(logger, "Info", "=" * 80)
    log_message(logger, "Info", "ConfigManBearPig execution completed")
    log_message(logger, "Info", "=" * 80)

    # Clean up
    ad_resolver.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
