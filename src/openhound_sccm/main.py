import datetime
import importlib.metadata
import duckdb
import logging
import os
import pathlib
import platform
import shutil
import socket
import sys
import threading
import time
import types
from enum import Enum
import typer
from openhound.cli.collect import collect as _collect_typer  # noqa: E402
from openhound.cli.convert import convert as _convert_typer  # noqa: E402

from typing import TYPE_CHECKING, Any, Callable, List, Optional, Protocol, Sequence, cast

from openhound.core.app import (
    Contract,
    DEFAULT_LOOKUP_FILE,
    InputPath,
    OpenHound,
    OutputPath,
)
from openhound.core.collect import CollectContext, Collector
from openhound.core.convert import ConvertContext, Converter, Method
from openhound.core.preproc import PreProcContext
from openhound.core.progress import Progress
from openhound_collector_common.dlt.progress import ProgressOption, resolve_progress
from openhound_collector_common.logging.files import DiagnosticFileHandler as _DiagnosticFileHandler, GroupedFileHandler as _OrderedLogFileHandler  # noqa: F401 - handler re-exports used by the existing consumer checks
from openhound_collector_common.logging.files import RunFileLogs
from openhound_collector_common.logging.console import is_secret_field
from openhound_collector_common.orchestration.artifacts import (
    OutputCleanupError,
    clean_previous_collection as _shared_clean_previous_collection,
    prior_load_packages as _shared_prior_load_packages,
)
from openhound_collector_common.orchestration.commands import cli_path_arg as _cli_path_arg
from openhound_collector_common.orchestration.arguments import suspicious_argument_warnings
from dlt.common.pipeline import LoadInfo
import dlt
from .convert_pipeline import emit_graph_from_duckdb, emit_hybrid_edges_from_duckdb
from .lookup import SCCMLookup
from .log_context import get_logger
from .models.computer import ComputerNode
from .models.container import ContainerNode
from .models.group import GroupNode
from .models.graph_edge import GraphEdge
from .models.mssql_database import MSSQLDatabase
from .models.mssql_database_role import MSSQLDatabaseRole
from .models.mssql_database_user import MSSQLDatabaseUser
from .models.mssql_login import MSSQLLogin
from .models.mssql_server import MSSQLServer
from .models.mssql_server_role import MSSQLServerRole
from .models.sccm_admin_user import SCCMAdminUser
from .models.sccm_client_device import SCCMClientDevice
from .models.sccm_collection import SCCMCollection
from .models.sccm_security_role import SCCMSecurityRole
from .models.sccm_site import SCCMSite
from .models.stub_node import StubNode
from .models.user import UserNode
from .transforms import transforms

if TYPE_CHECKING:
    # Type-only import: StagePaths annotates the --run-all output-summary helpers.
    # The runtime import stays deferred inside the functions so importing this
    # module never pulls the shared library in at import time.
    from openhound_collector_common.orchestration import StagePaths
    # Type-only import: ProxyConfig annotates the --proxy helpers below.
    # The runtime import stays deferred inside _parse_proxy_or_exit for the same reason.
    from openhound_collector_common.proxy import ProxyConfig

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Progress backend selection (`--progress`)
# ---------------------------------------------------------------------------
# dlt draws a live counter for every resource it extracts (the
# `adminservice_r_system: 69it [...]` lines). Those redraws smear into the
# collector's own [target][phase] INFO/VERBOSE records, so the default here is
# "off": no dlt progress at all, leaving only our structured logs. tqdm / log /
# alive_progress stay available as opt-ins for anyone who wants a live bar.
#
# The framework's core Progress enum (off-limits to edit) has no "off" member,
# and core's Collector always forwards `progress.value` to
# `dlt.pipeline(progress=...)`. dlt maps a `None` progress arg to its no-op
# NULL_COLLECTOR, so we express "off" as a tiny stand-in whose `.value` is None
# rather than touching OpenHound core.
# ---------------------------------------------------------------------------
class IntegrationPrivilege(str, Enum):
    """Which fixture set --run-integration-tests asserts.

    Describes the COLLECTION, not the fixtures. `auto` derives it from how much the
    run actually collected; the two explicit values exist for the case auto cannot
    see -- a partially-privileged run, where AdminService reached one site and not
    another, looks privileged by row count but should often be asserted as low.
    """
    auto = "auto"
    high = "high"
    low = "low"


# AdminService and WMI are the two privileged per-host transports. The prefixes are
# matched with startswith, never a substring test: local_wmi_sms_authority,
# local_wmi_sms_lookupmp and local_wmi_ccm_client are DISCOVERY resources reading
# WMI on the collector host itself, which any domain user can do.
_PRIVILEGED_TABLE_PREFIXES = ("adminservice_", "wmi_")


def _resolve_progress(choice: ProgressOption):
    """Use the shared choices while retaining SCCM's existing diagnostic logger."""
    return resolve_progress(choice, logger=logger)


# ---------------------------------------------------------------------------
# OpenHound app instance. Still owns `source_kind` (flows into the OpenGraph
# metadata block) plus the asset registry that ``Converter.run`` reads. The
# `@app.collect/@app.preproc/@app.convert` convenience decorators are
# intentionally *not* used here — we register richer Typer commands on the
# framework's public Typer groups directly so we can add CLI options/flags.
# ---------------------------------------------------------------------------
app = OpenHound(
    "sccm",
    # source_kind tags every emitted node/edge as belonging to the SCCM data source in
    # BloodHound (used for source-scoped re-ingest/deletion). Was the Stage-0 spike
    # placeholder "Kind"; set to the real collector source name.
    source_kind="SCCM",
    help="OpenGraph collector for sccm"
)


def _show_version(ctx: typer.Context, value: bool) -> None:
    if value and not ctx.resilient_parsing:
        # No collection or logging session exists for this metadata-only command.
        typer.echo(f"ConfigManBearPig {importlib.metadata.version('configmanbearpig')}")
        raise typer.Exit()

# ---------------------------------------------------------------------------
# Flag → env-var translation
# ---------------------------------------------------------------------------
# Every CMBP-style flag on `collect` / `preprocess` / `convert` maps to a
# ``SOURCES__SCCM__*`` env var. The Typer command sets the env var BEFORE the
# DLT source factory resolves its `dlt.config.value` parameters, so the user
# can supply config equivalently via CLI flag, env var, or `.env` file. Flag
# values win because they're applied last (just before the framework's
# Collector/Converter/PreProcessor is constructed).
# ---------------------------------------------------------------------------
_FLAG_TO_ENV: dict[str, str] = {
    # Connection
    "domain": "SOURCES__SCCM__DOMAIN",
    "domain_controller": "SOURCES__SCCM__DOMAIN_CONTROLLER",
    "username": "SOURCES__SCCM__USERNAME",
    "password": "SOURCES__SCCM__PASSWORD",
    "nt_hash": "SOURCES__SCCM__NT_HASH",
    "kerberos_ticket": "SOURCES__SCCM__KERBEROS_TICKET",
    "ldap_port": "SOURCES__SCCM__LDAP_PORT",
    # Collection
    "collection_methods": "SOURCES__SCCM__COLLECTION_METHODS",
    "computers": "SOURCES__SCCM__COMPUTERS",
    "computer_file": "SOURCES__SCCM__COMPUTER_FILE",
    "site_codes": "SOURCES__SCCM__SITE_CODES",
    # Behavior
    "disable_possible_edges": "SOURCES__SCCM__DISABLE_POSSIBLE_EDGES",
    "enable_bad_opsec": "SOURCES__SCCM__ENABLE_BAD_OPSEC",
    "threads": "SOURCES__SCCM__THREADS",
    "show_cleartext_passwords": "SOURCES__SCCM__SHOW_CLEARTEXT_PASSWORDS",
    # Network
    "socks_proxy": "SOURCES__SCCM__SOCKS_PROXY",
    "http_proxy": "SOURCES__SCCM__HTTP_PROXY_CONFIG",
    # DNS
    "dns_resolver": "SOURCES__SCCM__DNS_RESOLVER",
}

_TYPED_DLT_ENV = {
    "SOURCES__SCCM__LDAP_PORT",
    "SOURCES__SCCM__THREADS",
    "SOURCES__SCCM__DISABLE_POSSIBLE_EDGES",
    "SOURCES__SCCM__ENABLE_BAD_OPSEC",
    "SOURCES__SCCM__SHOW_CLEARTEXT_PASSWORDS",
}


def _drop_empty_dlt_env_values() -> None:
    for env_name in _FLAG_TO_ENV.values():
        if os.environ.get(env_name) == "":
            os.environ.pop(env_name, None)

    for env_name in _TYPED_DLT_ENV:
        value = os.environ.get(env_name)
        if value is not None and value.strip() == "":
            os.environ.pop(env_name, None)


_SHORT_OPTIONS_WITH_VALUES: dict[str, str] = {
    "-d": "--domain",
    "-u": "--username",
    "-p": "--password",
    "-m": "--collection-methods",
    "-c": "--computers",
    "-t": "--threads",
    "-x": "--proxy",
}
_LONG_OPTIONS_WITH_VALUES: set[str] = {
    "--progress",
    "--tables",
    "--columns",
    "--data-type",
    "--domain",
    "--dc",
    "--domain-controller",
    "--username",
    "--password",
    "--nt-hash",
    "--ticket",
    "--ldap-port",
    "--collection-methods",
    "--computers",
    "--cf",
    "--computer-file",
    "--sc",
    "--site-codes",
    "--threads",
    "--proxy",
    "--http-proxy",
    "--dns",
    "--dns-resolver",
}
_SENSITIVE_OPTIONS: set[str] = {
    "-p",
    "--password",
    "--machine-pass",
    "--nt-hash",
    "--ticket",
    # A proxy address can embed credentials (socks5://user:pass@host:port),
    # so mask it in the split-value warnings just like a password.
    "-x",
    "--proxy",
    "--http-proxy",
}


def _suspicious_cli_argument_warnings(argv: Sequence[str]) -> list[str]:
    """Use shared typo detection with SCCM's existing option names and masking."""
    return suspicious_argument_warnings(
        argv, short_options=_SHORT_OPTIONS_WITH_VALUES,
        long_options=_LONG_OPTIONS_WITH_VALUES, sensitive_options=_SENSITIVE_OPTIONS,
    )


def _warn_for_suspicious_cli_arguments(argv: Sequence[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    for warning in _suspicious_cli_argument_warnings(args):
        logger.warning(warning)


def _apply_env_overrides(flag_kwargs: dict) -> None:
    """Map CLI option/flag values to ``SOURCES__SCCM__*`` env vars.

    Skips values that are ``None`` or default-``False`` so a flag that wasn't
    passed doesn't overwrite a higher-priority env-var or ``.env`` entry.
    Booleans serialise as ``"true"`` / ``"false"`` (lowercased); paths
    serialise via ``str()``.
    """
    for flag_name, env_name in _FLAG_TO_ENV.items():
        if flag_name not in flag_kwargs:
            continue
        value = flag_kwargs[flag_name]
        if value is None:
            continue
        if isinstance(value, bool):
            if not value:
                continue
            os.environ[env_name] = "true"
        elif isinstance(value, pathlib.Path):
            os.environ[env_name] = str(value)
        else:
            os.environ[env_name] = str(value)


def _resolve_dc_only_methods(dc_only: bool, collection_methods: Optional[str]) -> Optional[str]:
    """Resolve the effective --collection-methods for a run, honoring --dc-only.

    --dc-only is a recon mode: collect only LDAP + DNS from the domain controller
    and skip every per-host phase. It forces the method set to "LDAP,DNS". Because
    both flags decide *what* gets collected, passing them together is a
    contradiction we reject up front rather than silently pick a winner.
    """
    if not dc_only:
        # Normal run: leave the operator's -m (or None -> "All" later) untouched.
        return collection_methods
    if collection_methods is not None:
        # Explicit -m alongside --dc-only: the operator asked for two different scopes.
        raise typer.BadParameter(
            "--dc-only and -m/--collection-methods are mutually exclusive; "
            "--dc-only already restricts collection to LDAP + DNS."
        )
    return "LDAP,DNS"


def _should_run_per_host(ctx, phases, dc_only: bool) -> bool:
    """Whether Stage 2 (per-host probing) runs this collect.

    It runs only when discovery produced a usable context and there are phases to
    run — and never in --dc-only recon mode, which stops after LDAP + DNS discovery
    against the domain controller.
    """
    return bool(ctx is not None and phases) and not dc_only


# A level above CRITICAL (50) that no record can ever reach — used to mute a
# console handler without detaching it. Reversible and in keeping with this
# extension's "mutate live handler instances" approach (see ARCHITECTURE §7).
_CONSOLE_MUTE_LEVEL = logging.CRITICAL + 1


def _is_console_handler(handler: logging.Handler) -> bool:
    """True for handlers that write to the terminal — the framework's
    ``RichHandler`` (CLI mode) or its stdout ``StreamHandler`` (container mode) —
    and False for on-disk sinks (the rotating JSON file, plus this extension's
    ``_DiagnosticFileHandler`` / ``_OrderedLogFileHandler``).

    ``FileHandler`` is a ``StreamHandler`` subclass, so it must be excluded first.
    ``RichHandler`` is *not* a ``StreamHandler``, so it's matched by duck-typing
    on its ``.console`` attribute (avoids importing rich just to isinstance it).
    """
    if isinstance(handler, logging.FileHandler):
        return False
    return isinstance(handler, logging.StreamHandler) or hasattr(handler, "console")


def _silence_console_handlers() -> None:
    """Mute every console handler on the root / ``dlt`` / ``openhound`` loggers by
    raising it above CRITICAL. File handlers are left untouched, so ``--silent``
    gags the terminal while the on-disk logs keep recording."""
    for logger_name in ("", "dlt", "openhound"):
        for handler in logging.getLogger(logger_name).handlers:
            if _is_console_handler(handler):
                logger.debug("Silencing console handler %r (--silent)", handler)
                handler.setLevel(_CONSOLE_MUTE_LEVEL)


def _apply_log_level(verbose: bool, debug: bool, silent: bool) -> None:
    """Set the console log level from the verbosity flags — or mute the console
    entirely with ``--silent`` — and install the ``[target][phase]`` prefix filter.

    (no flags) → INFO     (collection-step summaries)
    ``-v``      → VERBOSE  (PS1 ``[Verbose]`` parity tier: per-AD-resolution,
                  per-node-add, per-edge dedupe traces)
    ``--debug`` → DEBUG    (everything, including dlt and ldap3 internals)

    ``--debug`` outranks ``-v``. ``--silent`` silences the *console only*: the
    console handlers are raised above CRITICAL so nothing prints, while the root
    logger stays at the requested detail level so the on-disk logs
    (``collect_full_*`` / ``collect_issues_*``) keep recording. ``--silent``
    therefore composes with ``-v`` / ``--debug`` — e.g. ``--silent --debug`` is a
    quiet terminal with DEBUG-level file logs. (The full log always captures the
    collector's own DEBUG regardless; ``--debug`` additionally adds dlt/ldap3.)

    The framework's default config uses a ``RichHandler`` (or stdout
    ``StreamHandler`` in container mode) wired up by
    ``openhound/core/logging.py``. We keep those handlers in place — the
    user prefers the framework's ``time=…, msg=…`` format — and only swap
    the formatter to drop the trailing ``(openhound_version=…)`` suffix
    that ``OpenHoundRichFormatter`` appends to every line.
    """
    from .log_context import VERBOSE, install_filter

    if debug:
        level_name, level = "DEBUG", logging.DEBUG
    elif verbose:
        level_name, level = "VERBOSE", VERBOSE
    else:
        level_name, level = "INFO", logging.INFO

    os.environ["RUNTIME__LOG_LEVEL"] = level_name
    os.environ["RUNTIME__LOG_CLI_LEVEL"] = level_name
    root = logging.getLogger()
    # Lower the root logger so records of the requested level can reach any
    # handler. This is also what keeps --silent's on-disk logs at full detail:
    # only the console handlers get muted below, never the root logger. Existing
    # file handlers keep their own level.
    if root.level == 0 or root.level > level:
        root.setLevel(level)

    if silent:
        # Console-only mute — see _silence_console_handlers. Skip the level-lowering
        # loop below entirely so the terminal handlers stay muted.
        _silence_console_handlers()
    else:
        for log in (root, logging.getLogger("dlt")):
            for handler in log.handlers:
                if handler.level == 0 or handler.level > level:
                    handler.setLevel(level)
    # The OpenHound framework's CLI handler uses ``OpenHoundRichFormatter``
    # (see ``openhound/core/logging.py:170``) which appends
    # `` (openhound_version=<v>)`` to every line. Swap the formatter
    # for one that produces the same ``time=…, msg=…`` shape minus
    # that suffix — keeps the framework's preferred format without
    # touching OpenHound code. The JSON file handler keeps its own
    # formatter so the structured log is untouched.
    _strip_version_suffix_from_handlers()

    install_filter()


# Hard-frozen to the framework's current timestamp format. We identify the
# formatter to swap by class name, so format divergence is a visible signal.
_LOG_TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"


class _NoVersionRichFormatter(logging.Formatter):
    """Mirror of ``openhound.core.logging.OpenHoundRichFormatter`` minus the
    trailing ``(openhound_version=…)`` suffix. Used by ``_apply_log_level``
    to swap the framework's CLI formatter in place."""

    def format(self, record: logging.LogRecord) -> str:
        return f"time={self.formatTime(record, _LOG_TIMESTAMP_FMT)}, msg={record.getMessage()}"


def _strip_version_suffix_from_handlers() -> None:
    """Replace any ``OpenHoundRichFormatter`` instance on console handlers
    with ``_NoVersionRichFormatter``. Identifies by class name to avoid
    importing the framework symbol (which would tie us to its module layout).
    Idempotent: re-running it on already-swapped handlers is a no-op.
    """
    seen_loggers = (
        logging.getLogger(),
        logging.getLogger("dlt"),
        logging.getLogger("openhound"),
    )
    replacement = _NoVersionRichFormatter()
    for log in seen_loggers:
        for handler in log.handlers:
            fmt = handler.formatter
            if fmt is None:
                continue
            if type(fmt).__name__ == "OpenHoundRichFormatter":
                handler.setFormatter(replacement)


# ---------------------------------------------------------------------------
# Windows-safe core log rotation
# ---------------------------------------------------------------------------
# OpenHound core attaches a TimedRotatingFileHandler (``when="midnight"``) to
# BOTH the root and ``dlt`` loggers, each pointed at the same ``openhound.log``
# (see ``openhound/core/logging.py``). The first record after midnight fires a
# rollover whose ``os.rename(openhound.log -> openhound.log.<date>)`` fails on
# Windows with ``WinError 32``, because the sibling handler still holds the
# file open — so core's daily rotation has never worked on Windows. We cannot
# edit core, so we mutate the live handler instances from our side:
#
#   1. Repoint each to a per-run timestamped file so every run owns a distinct
#      log and a stale rotated file never collides with a fresh rename target.
#   2. Replace ``doRollover`` with a copy+truncate that never renames, so a run
#      crossing midnight (or tripping the size cap) rotates without needing
#      exclusive access to the open file.


class _RotatingHandler(Protocol):
    """The subset of core's ``RotatingFileHandler`` that the Windows fix below reaches into.

    Written as a Protocol rather than an import of the class, because the handler belongs
    to openhound core, is attached to the root logger before this module runs, and is
    identified by class *name* — a duck-type check, since core's class is not a stdlib
    ``RotatingFileHandler`` and `isinstance` against the stdlib one would not match. So
    there is no concrete type available to annotate against.

    Spelling the contract out has a second benefit beyond satisfying the type checker: it
    is the only place a reader can see exactly which attributes — two of them private —
    this fix depends on, and therefore what a core upgrade could silently break.
    """

    stream: Any
    baseFilename: str
    rolloverAt: int
    # A settable attribute, not a method: the fix replaces it with a bound MethodType.
    doRollover: Callable[[], None]

    def computeRollover(self, current_time: int) -> int: ...
    def _open(self) -> Any: ...
    def acquire(self) -> None: ...
    def release(self) -> None: ...


def _copytruncate_rollover(self: _RotatingHandler) -> None:
    """Windows-safe ``doRollover`` for core's ``RotatingFileHandler``.

    Copies the live log to a dated sibling, then truncates it in place rather
    than renaming it — so the sibling handler's open handle stays valid and
    Windows never raises ``WinError 32``. Mirrors core's suffix scheme: a date
    for time-based rollovers, date + time for size-triggered ones.
    """
    self.acquire()
    try:
        if self.stream:
            self.stream.close()
            self.stream = None
        if getattr(self, "_size_triggered", False):
            stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        else:
            stamp = time.strftime("%Y-%m-%d")
        src = pathlib.Path(self.baseFilename)
        if src.exists():
            shutil.copy2(src, src.with_name(f"{src.name}.{stamp}"))
            open(src, "w").close()  # truncate in place; keeps path + handle valid
        self.rolloverAt = self.computeRollover(int(time.time()))
    finally:
        self.release()


def _make_core_rotation_windows_safe() -> None:
    """Neutralize the Windows-broken daily rotation in core's log handlers.

    See the section comment above. No-op off Windows, where core's
    rename-based rollover works correctly. Runs once at module import, after
    core has already attached its handlers, so it covers every CLI subcommand.
    """
    if platform.system() != "Windows":
        return
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    for log in (logging.getLogger(), logging.getLogger("dlt")):
        for raw_handler in log.handlers:
            if type(raw_handler).__name__ != "RotatingFileHandler":
                continue
            # The name check above IS the type narrowing; a cast is how it reaches mypy,
            # since core's class is not the stdlib RotatingFileHandler.
            handler = cast(_RotatingHandler, raw_handler)
            base = pathlib.Path(handler.baseFilename)
            handler.acquire()
            try:
                if handler.stream:
                    handler.stream.close()
                handler.baseFilename = str(base.with_name(f"{base.stem}_{ts}{base.suffix}"))
                handler.rolloverAt = handler.computeRollover(int(time.time()))
                handler.doRollover = types.MethodType(_copytruncate_rollover, handler)
                # Open the new file now (core constructs with delay=False). Core's
                # shouldRollover calls os.path.getsize(baseFilename) on every record,
                # so the file must exist before the first log line.
                handler.stream = handler._open()
            finally:
                handler.release()


_make_core_rotation_windows_safe()


def _detect_windows_domain() -> Optional[str]:
    """Derive the AD domain from the current Windows user context.

    Mirrors ``ConfigManBearPig.ps1``'s order:
      1. ``$env:USERDNSDOMAIN`` (set by the LSA at logon for a domain-joined
         session).
      2. DNS suffix of ``socket.getfqdn()`` (the computer's domain), used as
         a fallback when USERDNSDOMAIN is missing.

    Returns ``None`` on non-Windows or when discovery fails — callers should
    treat the field as still-unset and surface a clear required-flag error.
    """
    if platform.system() != "Windows":
        return None
    domain = os.environ.get("USERDNSDOMAIN")
    if not domain:
        fqdn = socket.getfqdn()
        if "." in fqdn:
            domain = fqdn.split(".", 1)[1]
    if not domain:
        return None
    return domain.strip().rstrip(".").lower()


def _resolve_dc_via_dns(domain: str, dns_resolver: Optional[str] = None) -> Optional[str]:
    """Resolve a domain controller FQDN from the domain via DNS SRV.

    Looks up ``_ldap._tcp.dc._msdcs.<domain>`` — the path .NET's
    ``Domain.FindDomainController()`` ultimately takes via DC Locator.
    Cross-platform: works wherever the host has DNS reachability to the AD
    DNS zone, not just Windows.

    The resolver is built via the shared ``discovery.dns.make_resolver`` (explicit
    nameserver when ``dns_resolver`` is set, else the host's configured resolvers).
    SCCM keeps its own SRV query here — ``_ldap._tcp.dc._msdcs.<domain>`` is the
    precise DC-Locator record (.NET ``Domain.FindDomainController``), narrower than
    the shared ``resolve_dc``'s general ``_ldap._tcp.<domain>``.
    """
    try:
        from openhound_collector_common.discovery.dns import make_resolver
        from openhound_collector_common.proxy import active_proxy

        resolver = make_resolver(dns_resolver, lifetime=5, force_tcp=active_proxy() is not None)
        answers = resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
        srvs = sorted(answers, key=lambda r: (r.priority, -r.weight))
        if srvs:
            return str(srvs[0].target).rstrip(".")
    except Exception as exc:  # dnspython errors, timeouts, no SRV records
        logger.warning("DNS SRV lookup for domain controller failed: %s", exc)
    return None


def _apply_connection_context(flag_kwargs: dict) -> None:
    """Backfill domain (Windows current-user context) and domain controller
    (DNS SRV from the resolved domain) when those values weren't supplied
    via flag or env.

    Domain auto-detection is Windows-only — Linux/macOS users must pass
    ``-d`` / ``--domain`` explicitly. DC resolution is cross-platform: as
    long as the domain is known (from flag, env, or Windows auto-detect),
    we try to resolve the DC via DNS SRV before failing.
    """
    has_domain = bool(flag_kwargs.get("domain")) or bool(os.environ.get("SOURCES__SCCM__DOMAIN"))
    has_dc = bool(flag_kwargs.get("domain_controller")) or bool(
        os.environ.get("SOURCES__SCCM__DOMAIN_CONTROLLER")
    )

    if not has_domain:
        domain = _detect_windows_domain()
        if domain:
            os.environ["SOURCES__SCCM__DOMAIN"] = domain
            logger.info("Auto-detected domain from current user context: %s", domain)
            has_domain = True

    if has_domain and not has_dc:
        # Prefer flag value, then env (already set above if auto-detected).
        domain = (
            flag_kwargs.get("domain")
            or os.environ.get("SOURCES__SCCM__DOMAIN")
            or ""
        ).strip().rstrip(".").lower()
        if domain:
            logger.verbose("No domain controller (--dc) provided, trying to find one via DNS")
            dc = _resolve_dc_via_dns(domain, dns_resolver=flag_kwargs.get("dns_resolver"))
            if dc:
                os.environ["SOURCES__SCCM__DOMAIN_CONTROLLER"] = dc
                logger.info("Resolved domain controller via DNS SRV: %s", dc)
            else:
                logger.error("Could not identify a domain controller via DNS. Try specifying a domain controller FQDN or IP with the --dc option.")
                sys.exit(1)
        

def _require_domain_or_explain(flag_kwargs: dict) -> None:
    """Fail fast with a clear message if ``domain`` is still unresolved.

    On Linux/macOS this is the dominant failure mode (no Windows current-user
    context to fall back on). Surfacing it before dlt's config-resolver fires
    avoids the noisy ``ConfigFieldMissingException`` traceback.
    """
    if flag_kwargs.get("domain") or os.environ.get("SOURCES__SCCM__DOMAIN"):
        return
    if platform.system() == "Windows":
        msg = (
            "Could not auto-detect the Active Directory domain from the current "
            "user context (USERDNSDOMAIN unset and FQDN has no DNS suffix). "
            "Pass -d / --domain explicitly."
        )
    else:
        msg = (
            "Running on a non-Windows host: -d / --domain is required "
            "(auto-detection of the current user's domain context is Windows-only). "
            "--dc / --domain-controller will be resolved from the domain via DNS SRV "
            "if omitted. -u / --username and -p / --password are also required for "
            "any phase that needs AD/SCCM auth."
        )
    raise typer.BadParameter(msg, param_hint="--domain")


def _parse_proxy_or_exit(socks_proxy: Optional[str]) -> Optional["ProxyConfig"]:
    """Parse --proxy into a ProxyConfig, or exit(2) with a clear error."""
    from openhound_collector_common.proxy import SocksError, parse_proxy_address
    if not socks_proxy:
        return None
    try:
        cfg = parse_proxy_address(socks_proxy)
        logger.info("SOCKS5 proxy configured: %s:%s", cfg.host, cfg.port)
        return cfg
    except SocksError as ex:
        logger.error("Invalid --proxy value %r: %s", socks_proxy, ex)
        raise typer.Exit(2)


def _parse_http_proxy_or_exit(value: Optional[str]) -> Optional[str]:
    """Validate the HTTP-only proxy option before making any network calls."""
    from .clients.http import parse_http_proxy

    try:
        proxy = parse_http_proxy(value)
    except ValueError as ex:
        logger.error("Invalid --http-proxy: %s", ex)
        raise typer.Exit(2) from ex
    if proxy == "auto":
        logger.info("HTTP proxy: auto (environment or Windows user settings)")
    elif proxy:
        logger.info("HTTP proxy configured: %s", proxy.rsplit("@", 1)[-1].removeprefix("http://"))
    return proxy


def _require_dc_or_dns_for_proxy(flag_kwargs: dict, proxy: Optional["ProxyConfig"]) -> None:
    """Under a proxy, we can't resolve internal names locally, so demand a pin."""
    if proxy is None:
        return  # direct mode: nothing to enforce
    if flag_kwargs.get("domain_controller") or flag_kwargs.get("dns_resolver"):
        logger.debug("_require_dc_or_dns_for_proxy: DC/DNS pin present; ok")
        return
    logger.error(
        "--proxy requires --dc <ip/host> or --dns <internal-resolver-ip>: "
        "target names can't be resolved from the outside box under a pivot."
    )
    raise typer.Exit(2)


class _ImpacketNoiseFilter(logging.Filter):
    """Demote impacket's benign "no Kerberos credential cache" CRITICAL to DEBUG.

    impacket's ``CCache.parseFile`` reads the ``KRB5CCNAME`` environment variable
    to find a Kerberos credential cache. That variable is a Unix convention and is
    essentially never set on Windows, so on every Windows run the WMI Kerberos rung
    takes without ``--ticket``, impacket finds no cache, logs
    ``CRITICAL: CCache file is not found. Skipping...`` -- and then goes on to
    request a fresh TGT with the supplied password or hash and succeed. Nothing is
    skipped that we wanted; the word "Skipping" refers only to the cache lookup.

    It fires once per host (nine CRITICALs in a nine-host lab run), it is the only
    CRITICAL the collector ever shows, and an operator reasonably reads a red
    CRITICAL as "collection is broken". So the record's level is rewritten in
    place: handlers compare ``record.levelno`` when deciding what to emit, and the
    ``impacket`` logger has no handlers of its own (it propagates to root), so
    lowering the level here is enough to keep it off the console and out of
    ``collect_issues_<ts>.log`` while ``--debug`` still shows it.

    Deliberately matched on the one message rather than by capping the whole
    ``impacket`` logger: any *other* impacket CRITICAL still reaches the operator
    at full volume. ``wmi.py``'s Kerberos rung logs its own verbose line saying
    what actually happened, so the log explains itself rather than going silent.
    """

    # Substring, not the whole line: impacket's wording around it has changed
    # across releases, and this much has been stable.
    BENIGN_MESSAGE = "CCache file is not found"

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno > logging.DEBUG and self.BENIGN_MESSAGE in record.getMessage():
            record.levelno = logging.DEBUG
            record.levelname = "DEBUG"
        return True  # always keep the record; only its level changes




def _cli_seed_targets(computers: Optional[str], computer_file) -> list[str]:
    """Hostnames given on the command line, to seed onto the work queue."""
    hosts: list[str] = []
    if computers:
        hosts.extend(token.strip() for token in computers.split(",") if token.strip())
    if computer_file:
        p = pathlib.Path(computer_file)
        if p.exists():
            hosts.extend(line.strip() for line in p.read_text().splitlines() if line.strip())
    return hosts


def _build_phase_scope():
    """Return a context manager factory that tags log lines [target][phase]."""
    import contextlib

    from .log_context import phase_context, target_context

    @contextlib.contextmanager
    def _phase_scope(target: str, phase_name: str):
        with target_context(target), phase_context(phase_name):
            yield

    return _phase_scope


def _run_per_host_stage(pipeline, work_queue, ctx, threads, maxsize: int = 1000, phases=None) -> dict[str, int]:
    """Stage 2: drain the work queue with a worker pool while streaming each
    per-host table to disk through its emit resource.

    Runs the engine on a background thread (it produces rows onto the bounded
    per-table streams and, at quiescence, closes them with DONE) while the emit
    resources drain those streams on this thread via ``pipeline.run``. Returns
    only after both halves finish. As each target finishes its phase sequence,
    ``fire_host_complete`` notifies the ordered-log handler to flush that host's
    block (a no-op when no handler is registered, e.g. in unit tests).

    Not reentrant: it plants a process-global stream bridge (``set_bridge``) and
    temporarily raises the process-wide ``EXTRACT__WORKERS`` env var (via
    ``extract_workers_for``), so a single collect run per process is assumed
    (true for the CLI).
    """
    from openhound_collector_common.dlt.source_bridge import StreamBridge, extract_workers_for

    from . import source as _source
    from .log_context import fire_host_complete
    from .per_host_phases import PER_HOST_PHASES, all_table_names, should_run_phase
    from .phased_pipeline import run_pipeline

    # `phases` is injectable so integration tests can drive the stage with stub
    # phases; production always uses the real PER_HOST_PHASES.
    default_phases = phases is None
    if phases is None:
        phases = PER_HOST_PHASES
    table_names = all_table_names(phases)
    # The shared StreamBridge owns this run's bounded per-table queues (the
    # backpressure bound) and the blocking drain. The engine pushes rows onto
    # bridge.streams; the emit resources (via source._drain_stream) drain them.
    bridge = StreamBridge(table_names, maxsize=maxsize)
    _source.set_bridge(bridge)
    phase_scope = _build_phase_scope()
    producer_errors: list[BaseException] = []

    def _pool() -> None:
        try:
            run_pipeline(
                work_queue,
                ctx,
                phases,
                bridge.streams,
                max_workers=threads,
                should_run=should_run_phase,
                phase_scope=phase_scope,
                on_target_complete=fire_host_complete,
                emit=bridge.put,
                finish=bridge.broadcast_done,
                on_failure=lambda error: bridge.cancel("A collection worker failed; see the run logs"),
            )
        except BaseException as error:
            # A successful DLT drain must not hide a failed producer thread.
            producer_errors.append(error)
            bridge.cancel("The per-host producer failed; see the run logs")

    per_host_counts: dict[str, int] = {}
    pool_thread = threading.Thread(target=_pool, name="per-host-pool", daemon=False)
    pool_thread.start()
    try:
        # Each emit resource blocks on its queue until DONE, so it holds a dlt
        # extract worker for the whole run. extract_workers_for raises dlt's
        # worker cap to one-per-table (plus a margin) for the duration and
        # restores it after — without it, more tables than workers would wedge an
        # undrained queue and deadlock. (parallelized=True on each emit resource
        # is the other half of that guard; see source._make_emit_resource.)
        with extract_workers_for(len(table_names)):
            pipeline.run(
                # Production reuses the cached emit resources; an injected phase
                # set gets emit resources matching its own tables.
                _source.build_emit_resources(None if default_phases else table_names),
                write_disposition="append",
                loader_file_format="jsonl",
            )
        # Capture this run's per-table row counts from dlt's normalize step while
        # the in-memory trace still reflects the per-host pass — a later run on the
        # same pipeline would replace it.
        per_host_counts = _normalize_row_counts(pipeline)
    except BaseException:
        work_queue.stop("The output consumer stopped; no further targets will start")
        bridge.cancel("The output consumer stopped")
        raise
    finally:
        # Always await the engine thread. If pipeline.run raised, the emit
        # consumers stopped draining, so a worker may be blocked on a full queue;
        # cancel/drain the queues so those writes can finish. Active provider
        # calls must still return and release their own resources; native calls
        # can overrun a requested stop. Never abandon those worker threads.
        while pool_thread.is_alive():
            bridge.drain_to_unblock()
            pool_thread.join(timeout=0.1)
        _source.clear_bridge()

    if producer_errors:
        logger.error("Per-host collection failed after its active workers finished cleanup")
        raise RuntimeError("Per-host collection failed; saved data is incomplete") from producer_errors[0]

    # ctx.resolved_principals now reflects every AD principal resolved during
    # the WHOLE run: Stage-1 discovery (which finished before this function
    # was even called) plus every per-host phase above — pool_thread is only
    # not alive once run_pipeline's ThreadPoolExecutor has joined all its
    # workers, so every resolve_principal() call any phase made has already
    # happened.
    _emit_resolved_principals(pipeline, ctx)
    return per_host_counts


def _emit_resolved_principals(pipeline, ctx) -> None:
    """Flush the in-memory resolved-principal buffer (ctx.resolved_principals) to
    the ldap_resolved_principals raw table in one final pipeline.run.

    Populated by resolve_principal() across BOTH discovery and the per-host stage,
    it isn't produced by a Phase, so it has no per-host stream of its own — it is
    emitted once, after all resolutions for the run are guaranteed in. Called at the
    tail of _run_per_host_stage for a normal collect, and directly after discovery
    for a --dc-only run (which skips the per-host stage). A failure here is logged,
    not fatal: the discovery/per-host tables are already on disk.

    Skipped (with a debug log) only when this is exercised without a real context,
    e.g. collect_summary_test's row-count test — never in a real collect run, where
    collect_sccm only calls this with a live context.
    """
    from . import source as _source

    if ctx is None:
        logger.debug("Skipping ldap_resolved_principals emission: no context supplied")
        return
    try:
        pipeline.run(
            [_source.ldap_resolved_principals(ctx)],
            write_disposition="append",
            loader_file_format="jsonl",
        )
    except Exception as exc:
        # Both stages above already succeeded and are on disk — losing this
        # last, separate pipeline.run shouldn't take collect_sccm down with it.
        logger.warning("Failed to persist ldap_resolved_principals: %s", exc)


# ---------------------------------------------------------------------------
# `openhound collect sccm ...` — full CMBP-style flag surface
# ---------------------------------------------------------------------------
@_collect_typer.command(
    name="sccm",
    help="Collect SCCM resources from LDAP, AdminService, MSSQL, WMI, etc. Accepts CMBP-style flags or SOURCES__SCCM__* env vars.",
)
def collect_sccm(
    # ---- standard framework arguments ----
    output_path: OutputPath,
    resources: Optional[List[str]] = typer.Argument(None, help="Optional subset of resource names; default = all."),
    # ---- Authentication ----
    # Panel order in --help follows the order each panel's first option appears
    # here, so keep the panels grouped and in the intended display sequence:
    # Authentication -> Collection -> Performance -> Output -> Logging.
    domain: Optional[str] = typer.Option(None, "-d", "--domain", rich_help_panel="Authentication", help="Domain (e.g. mayyhem.com). On Windows, auto-detected from $env:USERDNSDOMAIN; on Linux/macOS this flag is required."),
    domain_controller: Optional[str] = typer.Option(None, "--dc", "--domain-controller", rich_help_panel="Authentication", help="DC hostname or IP. If omitted, resolved from --domain via DNS SRV (_ldap._tcp.dc._msdcs.<domain>)."),
    username: Optional[str] = typer.Option(None, "-u", "--username", rich_help_panel="Authentication", help="DOMAIN\\\\user for explicit auth."),
    password: Optional[str] = typer.Option(None, "-p", "--password", rich_help_panel="Authentication", help="Password for explicit auth."),
    nt_hash: Optional[str] = typer.Option(None, "--nt-hash", rich_help_panel="Authentication", help="NT hash for pass-the-hash auth (bare 32-hex NT hash; LM half assumed empty). Used by LDAP, AdminService (Kerberos RC4 key and NTLM), the SMB-based phases (RemoteRegistry, SMB), and the MSSQL EPA probe."),
    ticket: Optional[str] = typer.Option(None, "--ticket", rich_help_panel="Authentication", help="Base64-encoded Kerberos ticket (.kirbi / KRB-CRED) for pass-the-ticket. Kerberos only, no NTLM fallback. Honored by LDAP, AdminService/WMI, and the SMB-based phases (RemoteRegistry, SMB). Not used for the MSSQL EPA probe (it cannot probe channel binding — use -p/--password or --nt-hash there)."),
    # Help text stays ASCII-only: rich renders it to the active console encoding,
    # and a redirected `--help` on Windows uses cp1252, which can't encode "->"
    # arrows (U+2192) and would crash. Use ASCII "->" instead. See the cp1252
    # guard in tests/test_cli_option_panels.py.
    ldap_port: Optional[int] = typer.Option(None, "--ldap-port", rich_help_panel="Authentication", help="Pin LDAP port. Omit to auto-detect (LDAPS:636 -> StartTLS:389 -> LDAP:389+sign/seal). 636/3269 -> LDAPS; any other port -> LDAP."),
    # ---- Collection ----
    collection_methods: Optional[str] = typer.Option(
        None, "-m", "--collection-methods", rich_help_panel="Collection",
        help="Comma-separated methods: All, LDAP, Local, DNS, DHCP, RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB.",
    ),
    computers: Optional[str] = typer.Option(None, "-c", "--computers", rich_help_panel="Collection", help="Comma-separated computer targets."),
    computer_file: Optional[pathlib.Path] = typer.Option(None, "--cf", "--computer-file", rich_help_panel="Collection", help="File with computer targets (one per line)."),
    site_codes: Optional[str] = typer.Option(None, "--sc", "--site-codes", rich_help_panel="Collection", help="Site codes for DNS collection (CSV or file path)."),
    dc_only: bool = typer.Option(
        False, "--dc-only", rich_help_panel="Collection",
        help="Recon mode: collect only LDAP + DNS from the domain controller and "
             "skip all per-host probing (RemoteRegistry/MSSQL/AdminService/WMI/HTTP/SMB). "
             "Maps the SCCM attack surface from AD without touching any site system or "
             "client. Mutually exclusive with -m/--collection-methods.",
    ),
    # --proxy and --dns steer how collection reaches its targets, so they live
    # with the other Collection controls rather than in a separate network group.
    socks_proxy: Optional[str] = typer.Option(
        None, "-x", "--proxy", rich_help_panel="Collection",
        help="SOCKS5 proxy address (host:port or "
             "socks5://[user:pass@]host:port). Requires --dc or --dns.",
    ),
    http_proxy: Optional[str] = typer.Option(
        None, "--http-proxy", rich_help_panel="Collection",
        help="HTTP-only proxy: auto, host[:port], or user:pass@host[:port]. "
             "A bare host uses port 80; other protocols stay direct.",
    ),
    dns_resolver: Optional[str] = typer.Option(None, "--dns", "--dns-resolver", rich_help_panel="Collection", help="DNS nameserver IP for all lookups (DC discovery, SRV probes). Omit to use system default."),
    enable_bad_opsec: bool = typer.Option(False, "--enable-bad-opsec", rich_help_panel="Collection", help="Enable bad-opsec operations (NAA decryption, etc.)."),
    # ---- Performance ----
    threads: int = typer.Option(10, "-t", "--threads", rich_help_panel="Performance", help="Number of machines collected concurrently (per-host worker pool size; default 10)."),
    # ---- Output ----
    clean: bool = typer.Option(
        False, "--clean", rich_help_panel="Output",
        help="Discard a previous collection in OUTPUT_PATH before collecting: removes the "
        "sccm/ dataset dir, graph/, and lookup.duckdb. Without it, dlt APPENDS beside the "
        "old load packages and preprocess merges both runs' rows into one graph (a table "
        "this run finds empty keeps the old rows entirely). Per-run logs and "
        "integration/compare reports are timestamped and are always kept.",
    ),
    run_all: bool = typer.Option(
        False, "--run-all", rich_help_panel="Output",
        help="After collecting, automatically run preprocess and convert in-process so a "
        "single command produces the OpenGraph files. All paths are derived from OUTPUT_PATH "
        "(lookup.duckdb, the sccm/ dataset dir, and graph/).",
    ),
    progress: ProgressOption = typer.Option(
        ProgressOption.off, rich_help_panel="Output",
        help="Progress backend. 'off' (default) silences dlt's progress counters so only the "
        "collector's own logs print; 'tqdm' / 'log' / 'alive_progress' re-enable a live tracker.",
    ),
    version: bool = typer.Option(
        False, "--version", callback=_show_version, is_eager=True, rich_help_panel="Output",
        help="Show the installed ConfigManBearPig version and exit.",
    ),
    # --disable-possible-edges and --show-cleartext-passwords change what the
    # graph/console shows, so they sit under Output alongside the dlt contracts.
    disable_possible_edges: bool = typer.Option(False, "--disable-possible-edges", rich_help_panel="Output", help="Disable uncertain/possible edges."),
    show_cleartext_passwords: bool = typer.Option(False, "--show-cleartext-passwords", rich_help_panel="Output", help="Display cleartext passwords when discovered."),
    tables: Contract = typer.Option(Contract.evolve, rich_help_panel="Output", help="Contract for newly-seen resources/tables."),
    columns: Contract = typer.Option(Contract.evolve, rich_help_panel="Output", help="Contract for unknown fields."),
    data_type: Contract = typer.Option(Contract.freeze, rich_help_panel="Output", help="Contract for type mismatches."),
    # ---- Testing ----
    # Both flags imply --run-all (there is no graph to test/compare without a
    # completed convert), so collect_sccm forces run_all on below.
    run_integration_tests: bool = typer.Option(
        False, "--run-integration-tests", rich_help_panel="Testing",
        help="Implies --run-all, then assert the resulting graph against the built-in mayyhem "
             "lab fixtures. Prints PASS/FAIL/SKIP + summary + coverage, writes "
             "integration_results-<ts>.json and .html, and exits non-zero if any case fails.",
    ),
    integration_privilege: IntegrationPrivilege = typer.Option(
        IntegrationPrivilege.auto, "--integration-privilege", rich_help_panel="Testing",
        help="Which fixture set --run-integration-tests asserts. Describes the COLLECTION, "
             "not the fixtures. 'auto' (default) decides from whether AdminService/WMI "
             "actually returned rows this run. 'low' skips the SCCM-admin-only RBAC cases "
             "(SCCM_FullAdministrator, SCCM_IsAssigned, SCCM_IsMappedTo, SCCM_AllPermissions "
             "and the SCCM_AdminUser / SCCM_SecurityRole / SCCM_Collection nodes) that need "
             "AdminService or WMI, so they cannot fail for behaving correctly. 'high' asserts "
             "every case -- use it when a partially-privileged run should be held to the full set.",
    ),
    compare_to_zip: Optional[pathlib.Path] = typer.Option(
        None, "--compare-to-zip", rich_help_panel="Testing",
        help="Implies --run-all, then deep-diff this run's graph (A) against an arbitrary node/edge "
             "payload B (a CMBP zip or another OpenHound run). Reports property-level differences and "
             "writes compare-<ts>.json. Informational: always exits 0.",
    ),
    # ---- Logging ----
    verbose: bool = typer.Option(False, "-v", "--verbose", rich_help_panel="Logging", help="Verbose console output (VERBOSE level: PS1 [Verbose] parity — per-resolution / per-node-add / per-edge dedupe traces). Default is INFO (step summaries)."),
    silent: bool = typer.Option(False, "--silent", rich_help_panel="Logging", help="Silence all console output. The on-disk logs are still written: collect_full_* (always the complete DEBUG trace of the collector) and collect_issues_* (warnings/errors with tracebacks)."),
    debug: bool = typer.Option(False, "--debug", rich_help_panel="Logging", help="Debug console output (DEBUG level; very chatty, includes dlt and ldap3 internals)."),
) -> Optional[LoadInfo]:
    # --dc-only forces LDAP+DNS and skips per-host probing. Resolve it first so a
    # conflict with -m fails fast, and so the forced method set is picked up by the
    # locals()->flag_kwargs->env bridge below (it maps to SOURCES__SCCM__COLLECTION_METHODS).
    collection_methods = _resolve_dc_only_methods(dc_only, collection_methods)
    _apply_log_level(verbose, debug, silent)

    # Testing against a graph (fixtures or a comparison zip) requires a completed
    # convert, so either flag implies --run-all rather than making the operator
    # pass both.
    if run_integration_tests or compare_to_zip is not None:
        run_all = True

    # This run's merged per-table row counts, read by --integration-privilege auto
    # after collection. Initialised here rather than inside the collection try block
    # so mypy's possibly-undefined check (enabled in pyproject) is satisfied on every
    # path, including the one where collection raises before any counts exist.
    collect_counts: dict[str, int] = {}

    _ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Reject stale-output cleanup failure before opening new run-owned logs.
    _clean_previous_collection(output_path, clean)
    _parameters = locals().copy()
    _log_secrets = tuple(value for name, value in _parameters.items() if is_secret_field(name) and isinstance(value, str) and value)
    _log_secrets += tuple(value for name, value in os.environ.items() if name.startswith("SOURCES__SCCM__") and is_secret_field(name) and value)
    with RunFileLogs(output_path, run_id=_ts, namespaces=("openhound_sccm", "openhound_collector_common"), secrets=_log_secrets) as _file_logs:
        log_path = _file_logs.issues_path
        _ordered_log_path = _file_logs.full_path
        _diag = _file_logs.issues

        # Quiet impacket's one benign CRITICAL (see _ImpacketNoiseFilter). Installed
        # here, with the other per-run logging setup, and removed in the finally below
        # so a long-lived process that calls collect_sccm twice does not stack filters.
        _impacket_logger = logging.getLogger("impacket")
        _impacket_noise_filter = _ImpacketNoiseFilter()
        _impacket_logger.addFilter(_impacket_noise_filter)

        try:
            _warn_for_suspicious_cli_arguments()
            flag_kwargs = locals()
            # The Typer param is `ticket`; the env map keys it as `kerberos_ticket`.
            flag_kwargs["kerberos_ticket"] = flag_kwargs.pop("ticket", None)
            _apply_env_overrides(flag_kwargs)
            _drop_empty_dlt_env_values()
            # Parse + validate the proxy BEFORE connection-context auto-detect, so
            # the --dc/--dns check sees the user's flags (not an auto-filled DC) and
            # so DC discovery itself runs inside the tunnel.
            proxy_cfg = _parse_proxy_or_exit(
                flag_kwargs.get("socks_proxy") or os.environ.get("SOURCES__SCCM__SOCKS_PROXY")
            )
            http_proxy_raw = flag_kwargs.get("http_proxy") or os.environ.get("SOURCES__SCCM__HTTP_PROXY_CONFIG")
            http_proxy_cfg = _parse_http_proxy_or_exit(http_proxy_raw)
            if http_proxy_cfg and proxy_cfg:
                logger.error("--http-proxy and --proxy cannot be used together")
                raise typer.Exit(2)
            _require_dc_or_dns_for_proxy(flag_kwargs, proxy_cfg)

            # Route ALL collection traffic through the SOCKS5 proxy for the whole
            # window — including DC discovery (SRV over TCP) — no-op when proxy_cfg is None.
            from openhound_collector_common.proxy import socks_proxy_installed
            with socks_proxy_installed(proxy_cfg):
                _apply_connection_context(flag_kwargs)
                _require_domain_or_explain(flag_kwargs)

                from .per_host_phases import PER_HOST_PHASES
                from .phased_pipeline import WorkQueue
                from .source import (
                    DISCOVERY_RESOURCE_NAMES,
                    get_last_ctx,
                    set_shared_ad_cache,
                    set_shared_discovered_domains,
                    set_shared_queue,
                )
                from .source import source as sccm_source

                work_queue = WorkQueue()
                set_shared_queue(work_queue)
                set_shared_ad_cache({})
                set_shared_discovered_domains(set())

                # --silent also mutes the progress tracker (it renders straight to the
                # console, bypassing logging), so force it off regardless of --progress.
                collector = Collector(name=app.name, output_path=output_path, resources=resources, progress=_resolve_progress(ProgressOption.off if silent else progress))
                ctx = CollectContext(pipeline=collector)

                src = sccm_source(http_proxy=http_proxy_raw)
                if not src:
                    set_shared_queue(None)
                    set_shared_ad_cache(None)
                    set_shared_discovered_domains(None)
                    return None

                # Reuse the exact context discovery built, so the per-host stage shares
                # its target accumulator, allow-list, caches, and work queue.
                per_host_ctx = get_last_ctx()

                if dc_only:
                    logger.info(
                        "DC-only mode: collecting LDAP + DNS from the domain controller; "
                        "per-host collection skipped."
                    )

                # Stage 1 — discovery (once-phases): run only the discovery resources.
                # They seed the work queue via register_target (allow-list applied).
                load_info = collector.run(src.with_resources(*DISCOVERY_RESOURCE_NAMES))
                # Capture discovery row counts from the pipeline that just ran (held via
                # LoadInfo.pipeline) before the per-host pass replaces the trace.
                discovery_counts = _normalize_row_counts(load_info.pipeline) if load_info else {}

                # Seed CLI-specified targets through the same register_target path, so
                # the allow-list / resolution / dedup is identical for them.
                if per_host_ctx is not None:
                    for host in _cli_seed_targets(computers, computer_file):
                        per_host_ctx.register_target(host, source="CLI")

                # Stage 2 — per-host collection: a worker pool runs each target's phases
                # in order while emit resources stream the tables to disk, looping
                # recursively until the work queue drains.
                per_host_counts: dict[str, int] = {}
                per_host_expected = _should_run_per_host(per_host_ctx, PER_HOST_PHASES, dc_only)
                if per_host_expected:
                    per_host_counts = _run_per_host_stage(collector.pipeline, work_queue, per_host_ctx, threads)
                elif per_host_ctx is not None:
                    # --dc-only: the per-host stage (which normally flushes resolved
                    # principals) is skipped, but discovery already resolved principals
                    # whose AD attributes enrich Computer/User/Group nodes. Flush them so a
                    # recon graph carries the same AD props a full run would (decision 4).
                    logger.info(
                        "DC-only mode: persisting %d discovery-resolved principals for AD node properties.",
                        len(per_host_ctx.resolved_principals),
                    )
                    _emit_resolved_principals(collector.pipeline, per_host_ctx)

            set_shared_queue(None)
            set_shared_ad_cache(None)
            set_shared_discovered_domains(None)

            # Clear the [target][phase] log context so the summary block reads as a
            # global section rather than inheriting whatever phase ran last.
            from .log_context import phase_context, target_context
            with target_context(None), phase_context(None):
                _log_collect_summary(
                    discovery_counts, per_host_counts, per_host_expected, output_path, run_all=run_all
                )
            # Keep the merged counts for --integration-privilege auto below; the summary
            # above merges the same two dicts for display, this keeps them for a decision.
            collect_counts = _merge_row_counts(discovery_counts, per_host_counts)
        except typer.Exit:
            raise  # Preserve intentional command statuses.
        except Exception as error:
            logger.exception("Collection failed: %s", error)
            raise typer.Exit(code=1) from error
        finally:
            _impacket_logger.removeFilter(_impacket_noise_filter)
            _file_logs.finish_collection()
            # NOTE: _diag is deliberately NOT removed here -- see the run_all block below.
            # It stays attached across preprocess/convert so their WARNING/ERROR records
            # reach collect_issues_*.log (con-2ca2). The grouped full log finishes: its job
            # is the collect phase's host/resource bucketing, which has no meaning here.
            if _ordered_log_path.exists():
                logger.info("Full log: %s", _ordered_log_path)
            if _diag.warning_count or _diag.error_count:
                w, e = _diag.warning_count, _diag.error_count
                parts = []
                if w:
                    parts.append(f"{w} WARNING{'s' if w != 1 else ''}")
                if e:
                    parts.append(f"{e} ERROR{'s' if e != 1 else ''}")
                detail = ", ".join(parts)
                if log_path.exists():
                    logger.warning(
                        "%s detected. Traceback details available in: %s",
                        detail, log_path,
                    )
                else:
                    logger.warning(
                        "%s detected. Run with --debug to display traceback details after WARNING/ERROR logs.",
                        detail,
                    )

        # Collection succeeded here — an exception in the try above would have
        # propagated past the finally and never reached this point. Chain the
        # remaining phases only when the operator asked for it.
        #
        # con-2ca2: the whole chain runs inside its own try/finally so `_diag` -- the
        # WARNING+ handler behind collect_issues_*.log -- survives into preprocess and
        # convert. It used to be detached with the collect-phase handlers above, which
        # meant every preproc failure went unrecorded: a transform that `_safe` skipped
        # (or that failed outright) produced no line in ANY on-disk log, so grepping for
        # the transform's own label returned nothing and there was no trail to follow.
        # The finally is required rather than a trailing call because the integration
        # suite below exits via `typer.Exit`.
        try:
            if run_all:
                # _ts is the same run timestamp the collect logs carry, so every artifact
                # from this invocation shares one suffix. The name only needs to go one
                # way now: the chain writes the archive and reports it back on
                # StagePaths.graph_zip, which the summary reads.
                _paths = _run_e2e_after_collect(
                    output_path, progress,
                    graph_zip_name=f"configmanbearpig_collection_{_ts}.zip",
                )
                # Re-surface every artifact's location in one block at the very end, so the
                # operator doesn't have to scroll back through the collect/preproc/convert
                # logs to find where each output landed.
                _log_all_output_locations(
                    output_path, _paths, _ordered_log_path, log_path,
                    _diag.warning_count + _diag.error_count,
                )
                # --compare-to-zip and --run-integration-tests both need the graph convert
                # just produced. _ts is the same run timestamp used for the collect logs
                # above, so every artifact from this invocation shares one suffix.
                graph_dir = _paths.graph_out
                # Both testing flags run to completion before either decides the exit
                # code, so an operator who passed both always gets both reports rather
                # than having the first failure hide the second's findings.
                if compare_to_zip is not None or run_integration_tests:
                    code = _run_graph_checks(
                        graph_dir, output_path, _ts,
                        compare_to_zip=compare_to_zip,
                        privileged=_resolve_integration_privileged(
                            integration_privilege, collect_counts
                        ) if run_integration_tests else None,
                    )
                    raise typer.Exit(code=code)
            else:
                logger.debug("--run-all not set; leaving preprocess/convert to the operator.")
        except typer.Exit:
            raise  # Preserve the combined comparison/integration status.
        except Exception as error:
            logger.exception("A stage after collection failed: %s", error)
            raise typer.Exit(code=1) from error
        finally:
            _file_logs.close()
        return load_info

def _merge_row_counts(discovery: dict[str, int], per_host: dict[str, int]) -> dict[str, int]:
    """Combine the two collection stages' per-table row counts.

    Their table sets are disjoint today (discovery emits ldap_*/dns_*/local_*/
    collection_settings; per-host emits the rest), but sum on overlap so a future
    shared table can never silently drop rows -- same rule _log_collect_summary uses.
    """
    counts = dict(discovery)
    for table, rows in per_host.items():
        counts[table] = counts.get(table, 0) + rows
    return counts


def _detect_privileged(counts: dict[str, int]) -> tuple[bool, int]:
    """Return (privileged, rows) from this run's per-table row counts.

    Privileged means AdminService or WMI actually returned data. This measures the
    collection INPUT deliberately: inferring from the emitted graph would be
    circular, because a broken privileged builder emits nothing, would read as
    low-privilege, and would skip exactly the cases that would have caught it.
    """
    rows = sum(n for table, n in counts.items()
               if table.startswith(_PRIVILEGED_TABLE_PREFIXES))
    return rows > 0, rows


def _resolve_integration_privileged(choice: IntegrationPrivilege,
                                    counts: dict[str, int]) -> bool:
    """Resolve --integration-privilege into the boolean the harness takes."""
    if choice is IntegrationPrivilege.high:
        logger.info("Integration suite: --integration-privilege high; asserting every "
                    "case including the SCCM-admin-only RBAC families")
        return True
    if choice is IntegrationPrivilege.low:
        logger.info("Integration suite: --integration-privilege low; skipping the cases "
                    "that require AdminService/WMI collection")
        return False
    privileged, rows = _detect_privileged(counts)
    if privileged:
        logger.info("Integration suite: privileged collection detected (%d row(s) across "
                    "AdminService/WMI tables); asserting every case", rows)
    else:
        logger.info("Integration suite: low-privilege collection detected (no rows in any "
                    "AdminService/WMI table); skipping the cases that require them. "
                    "Pass --integration-privilege high to assert them anyway.")
    return privileged


def _run_graph_checks(
    graph_dir: pathlib.Path, output_path: pathlib.Path, run_label: str, *,
    compare_to_zip: pathlib.Path | None, privileged: bool | None,
) -> int:
    """Keep SCCM's choices while common attempts each requested check/report.

    A None privilege means no fixture suite was requested. False still runs the
    existing low-privilege suite; it must not be mistaken for an omitted check.
    """
    from openhound_collector_common.integration_testing.validation import (
        RequestedCheck, run_requested_checks,
    )
    from openhound_sccm.integration import compare_to_zip as compare

    checks = []
    if compare_to_zip is not None:
        comparison_report = output_path / f"compare-{run_label}.json"
        checks.append(RequestedCheck(
            "baseline comparison",
            lambda: compare(graph_dir, compare_to_zip, out_path=comparison_report, log=logger.info),
            comparison_report,
        ))
    # Omitted checks have no operational work or result to report.
    if privileged is not None:
        suite_report = output_path / f"integration_results-{run_label}.json"
        checks.append(RequestedCheck(
            "SCCM fixture assertions",
            lambda: _run_integration_suite(graph_dir, suite_report, privileged=privileged),
            suite_report,
        ))
    return run_requested_checks(checks).exit_code


def _run_integration_suite(graph_dir: pathlib.Path, results_path: pathlib.Path,
                           privileged: bool) -> int:
    """Assert the graph in *graph_dir* against the built-in mayyhem lab fixtures.

    *privileged* describes the COLLECTION, not the fixtures. Pass False for a graph
    collected without AdminService/WMI: the harness then skips the cases marked
    ``requires_privilege`` -- the SCCM-admin-only RBAC families (``SCCM_FullAdministrator`` /
    ``SCCM_IsAssigned`` / ``SCCM_IsMappedTo`` / ``SCCM_AllPermissions`` and the
    ``SCCM_AdminUser`` / ``SCCM_SecurityRole`` / ``SCCM_Collection`` nodes). Those
    families have no AD or LDAP representation and RemoteRegistry does not expose
    them, so asserting them against a low-privilege graph reports a failure for
    behaving correctly. Everything else is still asserted, so a low-privilege run
    stays a real gate rather than a weakened one.

    The verdict itself is decided and logged by _resolve_integration_privileged, so
    nothing is logged here -- a second message would imply a second decision.

    Returns the harness's process-friendly exit code (1 if any case failed).
    """
    from openhound_sccm.integration import run_integration_tests as _run_integration_tests
    return _run_integration_tests(
        graph_dir,
        results_path=results_path,
        log=logger.info,
        privileged=privileged,
    )


def _normalize_row_counts(pipeline) -> dict[str, int]:
    """Return ``{table_name: rows}`` from *pipeline*'s most recent normalize step.

    dlt records per-run row counts on the pipeline trace. ``last_trace`` is
    replaced by each multi-step ``pipeline.run``, so callers must read this right
    after the run whose counts they want — not once at the end. dlt bookkeeping
    tables (``_dlt_*``) are dropped. Returns ``{}`` when no trace or normalize
    info is available (e.g. a run that failed before normalize); the summary
    treats an empty result from an expected stage as a "partial run" signal.
    """
    try:
        trace = pipeline.last_trace
        if trace is None:
            # No run has completed on this pipeline object yet.
            logger.debug("No dlt trace on pipeline; row counts unavailable")
            return {}
        info = trace.last_normalize_info
        if info is None:
            # Trace exists but the run never reached the normalize step.
            logger.debug("No dlt normalize info on trace; row counts unavailable")
            return {}
        return {
            table: int(rows)
            for table, rows in info.row_counts.items()
            if not table.startswith("_dlt")
        }
    except Exception as ex:
        # A metrics read must never break the collection summary.
        logger.warning("Could not read dlt row counts for the collection summary: %s", ex)
        return {}


def _log_collect_summary(
    discovery_counts: dict[str, int],
    per_host_counts: dict[str, int],
    per_host_expected: bool,
    output_path: pathlib.Path,
    run_all: bool = False,
) -> None:
    """Emit an end-of-collection summary at INFO level.

    Row counts are a TRUE per-run metric: they come from dlt's normalize step
    for this run's two passes (discovery + per-host), merged here. This replaces
    the old on-disk directory scan, which double-counted stale tables left by
    older code or prior runs. The final node/edge totals aren't known yet — those
    come from ``output.py::package`` after convert.
    """
    logger.info("Collection complete.")
    logger.info("Raw output directory: %s", output_path)

    # Merge the two stages. Their table sets are disjoint (discovery emits
    # ldap_*/dns_*/local_*/collection_settings; per-host emits the rest), but sum
    # on overlap so a future shared table can never silently drop rows.
    counts: dict[str, int] = dict(discovery_counts)
    for table, rows in per_host_counts.items():
        counts[table] = counts.get(table, 0) + rows

    # A stage we expected to run but got no counts from means the numbers below
    # are partial — e.g. the stage raised before dlt normalized, or its trace was
    # lost. Surface it rather than silently under-reporting.
    if not discovery_counts:
        logger.warning("Discovery stage reported no row counts; the collection summary may be incomplete.")
    if per_host_expected and not per_host_counts:
        logger.warning("Per-host stage reported no row counts; the collection summary may be incomplete.")

    if counts:
        total = sum(counts.values())
        logger.info("Extracted %d rows across %d resources:", total, len(counts))
        for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            logger.info("    %-40s %d", name, count)
    else:
        # Both stages empty — nothing was extracted at all.
        logger.warning("No rows were extracted during this collection run.")

    # Flag stale/orphan table folders so an operator notices data left by older
    # code or earlier runs (e.g. a renamed resource). Compared against the
    # authoritative table universe (the preproc map) rather than this run's
    # counts, so a current table that legitimately got 0 rows is never mis-flagged.
    try:
        dataset_dir = output_path / "sccm"
        if dataset_dir.is_dir():
            known = set(_preproc_table_map().keys())
            on_disk = {
                d.name
                for d in dataset_dir.iterdir()
                if d.is_dir() and not d.name.startswith("_dlt")
            }
            orphans = sorted(on_disk - known)
            if orphans:
                logger.warning(
                    "Found %d stale table folder(s) under %s not produced by any current "
                    "collector (likely from older code or prior runs): %s. Preprocess/convert "
                    "ignore them, but you may want to delete them.",
                    len(orphans), dataset_dir, ", ".join(orphans),
                )
            else:
                logger.debug("No orphan table folders under %s", dataset_dir)
        else:
            logger.debug("Dataset dir %s missing; skipping orphan-folder check", dataset_dir)
    except Exception as ex:
        # Orphan detection is best-effort — never fail collect because of it.
        logger.error("Orphan-folder check failed: %s", ex)

    # When --run-all is set, preprocess and convert run automatically right after
    # this summary, so the manual copy-paste hint would only mislead. Derive the
    # printed paths from the shared convention so this hint and --run-all can
    # never disagree about where files land.
    if run_all:
        logger.info("--run-all set: preprocess and convert will run automatically next.")
        return

    # Derive every next-stage path from the one path the operator gave collect
    # (OUTPUT_PATH), so both printed commands are ready to copy and run: the
    # lookup DB and graph land alongside the raw data, and convert reads the
    # "sccm" dataset dir dlt wrote beneath it. Commands are prefixed with
    # `uv run` (matching the README) so they resolve to the sccm project's venv
    # when run from the sccm/sccm dir — a bare `openhound` would resolve to
    # whatever venv happens to be active, which may lack the SCCM extension.
    from openhound_collector_common.orchestration import derive_stage_paths

    paths = derive_stage_paths(app, output_path)
    preprocess_cmd = (
        f"uv run openhound preprocess sccm {_cli_path_arg(output_path)} {_cli_path_arg(paths.lookup_db)}"
    )
    convert_cmd = (
        f"uv run openhound convert sccm {_cli_path_arg(paths.dataset_dir)} {_cli_path_arg(paths.graph_out)} "
        f"--lookup-file {_cli_path_arg(paths.lookup_db)}"
    )
    logger.info("Next steps: '%s' then '%s'", preprocess_cmd, convert_cmd)


# Artifacts a previous run leaves behind that FEED or FORM the graph. Everything else
# in the output dir (collect_full_<ts>.log, collect_issues_<ts>.log,
# integration_results-<ts>.json, compare-<ts>.json) is uniquely named per run, never read
# back, and is often what you want to diff against afterwards -- so it is deliberately kept.
_REUSABLE_ARTIFACTS = ("sccm", "graph", "lookup.duckdb")


def _prior_load_packages(output_path: pathlib.Path) -> tuple[int, Optional[str]]:
    """Count SCCM's load records through the shared output inspector."""
    return _shared_prior_load_packages(output_path, "sccm")


def _clean_previous_collection(output_path: pathlib.Path, clean: bool) -> None:
    """Keep SCCM's artifact list and argument-error policy around common cleanup."""
    try:
        _shared_clean_previous_collection(
            output_path, clean, dataset_name="sccm",
            artifact_names=_REUSABLE_ARTIFACTS, logger=logger,
        )
    except OutputCleanupError as error:
        # Preserve the collector's established clean-failure command behavior.
        logger.error("Could not prepare SCCM output for collection: %s", error)
        raise typer.BadParameter(str(error)) from error


def _run_e2e_after_collect(
    output_path: pathlib.Path, progress: ProgressOption, graph_zip_name: str | None = None,
) -> "StagePaths":
    """Chain preprocess + convert in-process after a successful --run-all collect.

    Maps the collector's --progress choice to what the shared orchestrator wants
    (a framework Progress member, or None for silent), then delegates to
    run_end_to_end and returns the StagePaths it produced (dataset dir, lookup DB,
    graph dir) so the caller can report every output location. If a stage fails,
    the raw collected data is left intact and the equivalent manual commands are
    logged so the operator can resume from preprocess without recollecting.
    """
    from openhound_collector_common.orchestration import (
        derive_stage_paths,
        run_end_to_end,
    )

    # 'off' -> None (dlt NULL_COLLECTOR in both stages); any real backend -> the
    # matching framework Progress member. (Note: unlike collect, we can't reuse
    # _resolve_progress here — its 'off' path returns a .value=None *object*,
    # which the preprocess stage would hand raw to dlt. run_end_to_end needs the
    # None/Progress form and applies the convert-side shim itself.)
    if progress is ProgressOption.off:
        e2e_progress = None
        logger.debug("--run-all: preprocess/convert progress disabled (matches --progress off).")
    else:
        e2e_progress = Progress(progress.value)
        logger.debug("--run-all: preprocess/convert progress backend: %s", progress.value)

    logger.info("--run-all: continuing with preprocess and convert (in-process).")
    try:
        return run_end_to_end(app, output_path, progress=e2e_progress, graph_zip_name=graph_zip_name)
    except Exception:
        # Collect already succeeded, so the raw data on disk is still good; tell
        # the operator exactly how to resume rather than lose that work. Commands
        # are prefixed with `uv run`, matching the manual "Next steps" hint above,
        # so they resolve to the sccm project's venv regardless of which venv
        # happens to be active.
        paths = derive_stage_paths(app, output_path)
        logger.error(
            "--run-all: preprocess/convert failed after a successful collect. Your raw data "
            "is intact at %s. Resume manually: 'uv run openhound preprocess sccm %s %s' then "
            "'uv run openhound convert sccm %s %s --lookup-file %s'.",
            output_path,
            _cli_path_arg(output_path), _cli_path_arg(paths.lookup_db),
            _cli_path_arg(paths.dataset_dir), _cli_path_arg(paths.graph_out),
            _cli_path_arg(paths.lookup_db),
        )
        raise


def _log_all_output_locations(
    output_path: pathlib.Path,
    paths: "StagePaths",
    collect_log_path: pathlib.Path,
    collect_diag_path: pathlib.Path,
    diag_issue_count: int,
) -> None:
    """Log a consolidated list of every artifact a ``--run-all`` run produced.

    Printed once at the very end (after convert) so the operator sees, in a single
    block, where the raw data, collect logs, lookup DB, and OpenGraph files all
    landed — the collect-phase paths plus the preprocess/convert outputs, gathered
    back together rather than scattered across three phases of log output.

    The bundled zip closes the block deliberately: of everything listed here it is
    the only artifact the operator does something *with* (upload to BloodHound File
    Ingest), so it is the line their eye lands on last. It is read straight off
    ``paths.graph_zip`` — the archive ``run_end_to_end`` reports having written
    (``None`` when convert emitted no ``*.json``), rather than a path rebuilt from
    the name we asked for. Those two can disagree; only the one that came back is
    evidence. Needs openhound-collector-common >= 0.1.3, which added the field.
    """
    # output_path, the raw dataset dir, and the lookup DB always exist on the
    # success path (a completed run_end_to_end guarantees them), so they are listed
    # unconditionally; the logs and graph files below are guarded on existence.
    logger.info("--run-all complete. Output files:")
    logger.info("    Output directory:    %s", output_path)
    logger.info("    Raw data (JSONL):    %s", paths.dataset_dir)

    # Collect-phase logs (written during collection; re-surfaced here for one-stop
    # reference). Both are created lazily and may be absent: the ordered log only
    # if collection produced records, and the diagnostics file (delay=True) only
    # if a WARNING+ was emitted — so a clean run has no diagnostics file to list.
    # Each line is therefore guarded on existence.
    if collect_log_path.exists():
        logger.info("    Full log:            %s", collect_log_path)
    else:
        logger.debug("Full log not found at %s; omitting from summary.", collect_log_path)
    if collect_diag_path.exists():
        note = (
            f"{diag_issue_count} warning(s)/error(s), with tracebacks"
            if diag_issue_count
            else "no warnings/errors"
        )
        logger.info("    Issues log:          %s  (%s)", collect_diag_path, note)
    else:
        logger.debug("Issues log not found at %s; omitting from summary.", collect_diag_path)

    logger.info("    Lookup DB:           %s", paths.lookup_db)

    # OpenGraph files emitted by convert (SCCM + untagged-AD split, one or more each).
    if paths.graph_out.exists():
        graph_files = sorted(paths.graph_out.glob("*.json"))
        if graph_files:
            logger.info("    OpenGraph files (%d):", len(graph_files))
            for graph_file in graph_files:
                logger.info("        %s", graph_file)
        else:
            logger.warning("    OpenGraph output has no .json files: %s", paths.graph_out)
    else:
        logger.warning("    OpenGraph output directory is missing: %s", paths.graph_out)

    # Last line, and the only one that is an instruction rather than a location.
    # zip_graph_output skips the archive when convert wrote no .json (it logs why),
    # which surfaces here as graph_zip being None.
    if paths.graph_zip is not None:
        logger.info("    Upload to BloodHound: %s", paths.graph_zip)
    else:
        logger.warning("    No graph archive was written: convert emitted no .json to bundle.")


# Set at module scope so `CollectorManager.validate_extension` (which runs at
# import time, before any command is invoked) sees a non-None hook. The
# `@app.collect()` convenience decorator would do this for us, but we register
# directly on the framework's Typer group to keep CMBP-style flag surface.
app.collector = collect_sccm


def _preproc_table_map() -> dict[str, str]:
    """Return the DuckDB-table → JSONL-path mapping consumed by ``preprocess``.

    Each entry maps the exact DuckDB table name to the JSONL directory path
    that DLT writes during collection. Only tables that an actual collector
    emits are listed here — stale names that no collector produces are omitted
    so preproc does not silently load wrong data.

    The canonical source of truth for each table name is:
    - LDAP/DNS/Local: the ``name=`` argument on ``@app.resource`` in
      ``collectors/ldap.py``, ``collectors/dns.py``, ``collectors/local.py``.
    - RemoteRegistry/MSSQL/HTTP/SMB: the ``"table_name"`` string passed to
      ``yield "table_name", row`` in those per-host collectors.
    - AdminService/WMI: ``run.table("suffix")`` in ``privileged.py``, which
      expands to ``adminservice_<suffix>`` or ``wmi_<suffix>`` from
      ``PER_HOST_PHASES`` in ``per_host_phases.py``.
    """
    base_tables = [
        # LDAP discovery phase (ldap.py @app.resource name=...)
        "ldap_sites",
        "ldap_management_points_raw",
        "ldap_cmrc_devices",
        "ldap_network_boot_servers",
        "ldap_pattern_matches",
        "ldap_system_management_dacl",
        # Task 12: routed out of ldap_system_management_dacl's own generator via
        # dlt.mark.with_table_name (same resource, a second destination table) --
        # not a separate @app.resource, so it has no name= of its own to point to.
        "ldap_smc_group_members",
        # DNS discovery phase (dns.py @app.resource name=...)
        "dns_management_points",
        # Local discovery phase (local.py @app.resource name=...)
        "local_wmi_sms_authority",
        "local_wmi_sms_lookupmp",
        "local_wmi_ccm_client",
        "local_client_logs_targets",
        "collection_settings",
        # RemoteRegistry per-host phase (registry.py yield "table", row)
        "remoteregistry_sites",
        "remoteregistry_computers",
        "remoteregistry_users",
        "remoteregistry_mssql_servers",
        # MSSQL per-host phase (mssql.py yield "table", row)
        "mssql_server_instances",
        # AdminService per-host phase (privileged.py run.table("suffix"))
        "adminservice_sites",
        "adminservice_site_definitions",
        "adminservice_site_definitions_computers",
        "adminservice_reserved_accounts",
        "adminservice_client_devices",
        "adminservice_r_system",
        "adminservice_r_user",
        "adminservice_user_group",
        "adminservice_collections",
        "adminservice_collection_members",
        "adminservice_security_roles",
        "adminservice_admins",
        "adminservice_site_systems",
        # WMI per-host phase (privileged.py run.table("suffix"); same suffixes as AdminService)
        "wmi_sites",
        "wmi_site_definitions",
        "wmi_site_definitions_computers",
        "wmi_reserved_accounts",
        "wmi_client_devices",
        "wmi_r_system",
        "wmi_r_user",
        "wmi_user_group",
        "wmi_collections",
        "wmi_collection_members",
        "wmi_security_roles",
        "wmi_admins",
        "wmi_site_systems",
        # HTTP per-host phase (http.py yield via _role_row / _sitesigncert_probe)
        "http_management_points",
        "http_distribution_points",
        "http_smsproviders",
        "http_site_servers",
        "http_site_versions",
        # SMB per-host phase (smb.py yield "table", row)
        "smb_computers",
        "smb_sites",
        # Finalization resource (source.py @app.resource name=...), dumping
        # SourceContext.resolved_principals after both stages finish —
        # see _run_per_host_stage's trailing pipeline.run call below.
        "ldap_resolved_principals",
    ]
    return {table: f"sccm/{table}" for table in base_tables}


@app.preproc(transformer=transforms)
def preproc(ctx: PreProcContext) -> dict[str, str]:
    """Build a DuckDB lookup database from collected SCCM JSONL."""
    return _preproc_table_map()


@dlt.source(name="sccm_convert_noop")
def _noop_convert_source():
    """Converter.run runs over whatever `_sccm_convert_hook` returns. All real
    emission happens in the Convert2-Read-DB pipeline (run in `_sccm_convert_hook` below), so
    this source carries no graph-resource models — Converter.run finds no models and its own
    pipeline is a no-op. opengraph_file appends uniquely-numbered files, so the two pipelines
    writing to the same output dir never collide."""

    @dlt.resource(name="_noop")
    def _empty():
        return
        yield  # unreachable; makes _empty a generator yielding nothing

    return _empty


# Registry of (table_name, ModelClass) pairs for the three existing file sets.
# SQL-to-SCCM connections use the separate hybrid writer (ARCHITECTURE.md §11f).
#   - SCCM payload  -> source_kind="SCCM"   (custom SCCM_* kinds only)
#   - MSSQL payload -> source_kind="MSSQL"  (MSSQL_* kinds; the separate MSSQL OpenGraph
#                                            schema, schema_MSSQL.json, owns these)
#   - AD payload    -> NO source_kind       (native Computer/User/Group/Container + backfill
#                                            stubs; BloodHound merges these into its AD graph)
#   - Hybrid file   -> NO source_kind       (SQL-to-SCCM connections only)

# MSSQL nodes/edges belong to the separately maintained MSSQL schema (schema_MSSQL.json,
# name/namespace "MSSQL"), even though this SCCM collector emits them. Their own source_kind
# means re-ingesting or deleting the SCCM source never touches SQL topology.
MSSQL_SOURCE_KIND = "MSSQL"

SCCM_NODE_SPECS: list[tuple[str, type]] = [
    ("node_site", SCCMSite),
    ("node_collection", SCCMCollection),
    ("node_security_role", SCCMSecurityRole),
    ("node_admin_user", SCCMAdminUser),
    ("node_client_device", SCCMClientDevice),
]

MSSQL_NODE_SPECS: list[tuple[str, type]] = [
    ("node_mssql_server", MSSQLServer),
    ("node_mssql_database", MSSQLDatabase),
    ("node_mssql_server_role", MSSQLServerRole),
    ("node_mssql_database_role", MSSQLDatabaseRole),
    ("node_mssql_login", MSSQLLogin),
    ("node_mssql_database_user", MSSQLDatabaseUser),
]

AD_NODE_SPECS: list[tuple[str, type]] = [
    ("node_computer", ComputerNode),
    ("node_user", UserNode),
    ("node_group", GroupNode),
    # Container (Task 11, Tier A+) is a standard BloodHound base kind, like the
    # three above -- its id (objectGUID) merges with SharpHound's own node.
    ("node_container", ContainerNode),
    # node_backfill is LAST so a real AD node wins any id overlap via append semantics.
    # Every backfill stub is an AD principal (User/Group/Computer or bare Base).
    ("node_backfill", StubNode),
]

# These tables and graph_edges_hybrid are built by transforms._graph_edges_split.
SCCM_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_sccm", GraphEdge)]
MSSQL_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_mssql", GraphEdge)]
AD_EDGE_SPECS: list[tuple[str, type]] = [("graph_edges_ad", GraphEdge)]


def _emit_split_graph(lookup: SCCMLookup, output_path) -> None:
    """Write the SCCM, SQL, AD, and hybrid files into the same directory.

    SCCM payload (sccm_* files, source_kind="SCCM"): SCCM_* nodes and SCCM-only edges.
    MSSQL payload (mssql_* files,
    source_kind="MSSQL"): MSSQL_* nodes + every edge whose endpoints are BOTH MSSQL nodes.
    AD payload (ad_* files, no source_kind): native Computer/User/Group/Container/stub nodes
    + every edge touching one (including AD<->MSSQL), so BloodHound merges them into the
    native AD graph. SQL-to-SCCM edges go to hybrid_edges.json with no source_kind.
    See ARCHITECTURE.md §11f.
    """
    emit_graph_from_duckdb(
        lookup, output_path, app.source_kind,
        SCCM_NODE_SPECS, SCCM_EDGE_SPECS, resource_prefix="sccm",
    )
    emit_graph_from_duckdb(
        lookup, output_path, MSSQL_SOURCE_KIND,
        MSSQL_NODE_SPECS, MSSQL_EDGE_SPECS, resource_prefix="mssql",
    )
    emit_graph_from_duckdb(
        lookup, output_path, None,
        AD_NODE_SPECS, AD_EDGE_SPECS, resource_prefix="ad",
    )
    emit_hybrid_edges_from_duckdb(lookup, output_path)


def _sccm_convert_hook(ctx: ConvertContext):
    """Write SCCM, SQL, AD, and hybrid files from DuckDB, then return a no-op source."""
    _emit_split_graph(ctx.lookup, ctx.output_path)
    return _noop_convert_source(), {}


def _run_convert(
    input_path: pathlib.Path,
    output_path: pathlib.Path,
    lookup_file: pathlib.Path = DEFAULT_LOOKUP_FILE,
    progress: Progress = Progress.tqdm,
    method: Method = Method.write,
):
    """In-process convert callable — replicates the ~10-line closure the framework's
    ``@app.convert`` decorator builds automatically (open a read-only lookup DB session,
    build a ``Converter``, call the hook, run it).

    Assigned to ``app.converter`` below so ``run_end_to_end`` (the --run-all chain) keeps
    calling it exactly like before, and called directly by the hand-registered CLI command,
    which exists because the decorator exposes no seam for the command's own options.
    """
    client = duckdb.connect(str(lookup_file), read_only=True)
    lookup_session = SCCMLookup(client)
    if isinstance(progress, str):
        progress = Progress(progress)
    converter = Converter(
        name=app.name, source_kind=app.source_kind, input_path=input_path,
        output_path=output_path, lookup=lookup_session, progress=progress, method=method,
    )
    source_method, extra_context = _sccm_convert_hook(
        ConvertContext(input_path=input_path, output_path=output_path,
                       lookup=lookup_session, pipeline=converter)
    )
    return converter.run(source_method, graph_resources=app.assets, extra_context=extra_context)


# Set at module scope, same reasoning as `app.collector = collect_sccm` above: the
# `@app.convert()` convenience decorator would normally wire this up, but we register
# directly on the framework's Typer group instead so the convert command can carry its own
# options (--lookup-file, --progress) -- the decorator exposes no flag-carrying seam.
# `run_end_to_end` (the --run-all chain) calls `app.converter` directly, so it must be set
# here regardless of which CLI command runs.
app.converter = _run_convert


@_convert_typer.command(
    name="sccm",
    help="Convert collected SCCM data to OpenGraph.",
)
def convert_sccm(
    input_path: InputPath,
    output_path: OutputPath,
    lookup_file: pathlib.Path = typer.Option(DEFAULT_LOOKUP_FILE, "--lookup-file", help="DuckDB lookup file path."),
    progress: ProgressOption = typer.Option(ProgressOption.off, help="Progress backend."),
) -> None:
    # No --disable-possible-edges here, deliberately. Possible edges are gated during
    # PREPROCESS (transforms._read_disable_possible, from the collect-time value persisted
    # in collection_settings, optionally tightened by SOURCES__SCCM__DISABLE_POSSIBLE_EDGES).
    # By convert time the decision is already baked into the lookup DB, so a flag here could
    # only ever have affected the schema that the removed upload path pushed -- which is
    # exactly what it did. To re-process an existing collection in high-confidence mode, set
    # the env var on the `preprocess` run instead.
    _apply_log_level(verbose=False, debug=False, silent=False)
    _run_convert(
        input_path=input_path, output_path=output_path, lookup_file=lookup_file,
        progress=_resolve_progress(progress), method=Method.write,
    )
