"""Privileged SCCM collect-only per-host collector (AdminService + WMI).

Both transports read the *same* SMS Provider classes — the AdminService REST API
is a veneer over the SMS Provider's ``root\\SMS\\site_<code>`` WMI namespace — so
they share one set of ten collection helpers and one orchestrator. The only
differences are injected via a :class:`_Run`:

  * a ``fetch`` closure that knows the transport (OData GET + pagination, or a
    streaming WMI ``query``),
  * a flavor ``name`` (``"AdminService"`` / ``"WMI"``) used as the phase token,
    the ``completed_phases`` key, the ``<name>-<class>`` source label, and the
    ``<name lower>_<suffix>`` table prefix, and
  * the query dialect's equality operator ``eq`` (``"eq"`` for OData, ``"="`` for
    WQL) for the one filtered collection.

Two thin entry points (``collect_adminservice`` / ``collect_wmi``) keep the two
registered per-host phases. They do transport-specific connect + identify, then
hand a ``_Run`` to the shared orchestrator. Row shaping (snake-casing, the column
whitelists, SMS ``Props`` extraction) lives in ``sms_rows.py``. No AD resolution
beyond the site-server/SQL-server/reserved-account principal lookups the PS1 does
inline; node/edge construction is a deferred convert stage.
"""
import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, Optional

from ..clients.http import ErrorClass, HttpClient
from ..clients.http_auth import AuthMode
from ..clients.wmi import WmiClient
from ..context import SourceContext
from ..log_context import get_logger
from .sms_rows import (
    _prop,
    _row,
    ADMIN_COLUMNS,
    COLLECTION_COLUMNS,
    COLLECTION_MEMBER_COLUMNS,
    DEVICE_COLUMNS,
    ROLE_COLUMNS,
    RSYSTEM_COLUMNS,
    RUSER_COLUMNS,
    SITE_COLUMNS,
    SITEDEF_COLUMNS,
    SYSRES_COLUMNS,
    USERGROUP_COLUMNS,
)

logger = get_logger(__name__)

_BATCH = 1000


@dataclass(frozen=True)
class _Run:
    """One collection run over one transport.

    Attributes:
        fetch: ``(class_name, columns=None, where=None) -> Iterator[dict]`` — the
            transport adapter that yields raw rows for an SMS class.
        name: Flavor name: ``"AdminService"`` or ``"WMI"``.
        eq: The query dialect's equality operator (``"eq"`` OData / ``"="`` WQL).
        site_code: The identified SMS Provider site code (every row's source site).
        ctx: The shared per-host SourceContext (principal resolution, gating).
    """
    fetch: Callable[..., Iterator[dict]]
    name: str
    eq: str
    site_code: str
    ctx: SourceContext

    def source(self, cls: str) -> str:
        """The ``source`` label for rows of *cls* (e.g. ``AdminService-SMS_Site``)."""
        return f"{self.name}-{cls}"

    def table(self, suffix: str) -> str:
        """The raw table name for *suffix* (e.g. ``adminservice_sites``)."""
        return f"{self.name.lower()}_{suffix}"


# --- collection helpers (PS1 order) ---------------------------------------

def _sites(run: _Run) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting all sites (SMS_Site) via %s", run.name)
    count = 0
    for site in run.fetch("SMS_Site", columns=SITE_COLUMNS):
        yield run.table("sites"), _row(run.source("SMS_Site"), run.site_code, site)
        target_site = site.get("SiteCode")
        if target_site:
            logger.verbose("  %s", target_site)
            logger.debug("    %s", site)
            yield from _site_definition(run, target_site)
        else:
            logger.warning("Site record missing SiteCode: %s", site)
        count += 1
    logger.info("Collected %d sites via %s", count, run.name)


def _site_definition(run: _Run, target_site: str) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting site definition for site %s via %s", target_site, run.name)
    for sdef in run.fetch("SMS_SCI_SiteDefinition", columns=SITEDEF_COLUMNS,
                          where=f"SiteCode {run.eq} '{target_site}'"):
        props = sdef.get("Props")
        logger.debug("Site definition for site %s: %s", target_site, sdef)
        site_server = sdef.get("SiteServerName")
        sql_fqdn = _prop(props, "SQLServerFQDN", "Value1")
        yield run.table("site_definitions"), _row(
            run.source("SMS_SCI_SiteDefinition"), target_site, sdef, drop={"Props"},
            extra={
                "site_guid": _prop(props, "siteGUID", "Value1"),
                "sql_server_fqdn": sql_fqdn,
                "sql_service_port": _prop(props, "SQLServicePort", "Value"),
            },
        )
        # A computer row for the site server and the site database server, each
        # tagged with its role. Skipped when the principal can't be resolved.
        for fqdn, role in ((site_server, "SMS Site Server"), (sql_fqdn, "SMS SQL Server")):
            if not fqdn:
                continue
            logger.verbose("Found %s for site %s: %s", role, target_site, fqdn)
            ad_object = run.ctx.resolve_principal(fqdn)
            if not ad_object:
                logger.warning("Failed to resolve %s (%s) to AD object", fqdn, role)
                continue
            row = {
                **ad_object,
                "source": f"{run.name}-SiteDefinition",
                "sccm_infra": True,
                "sccm_site_system_roles": f"{role}@{target_site}" if target_site else role,
            }
            row.setdefault("name", fqdn)
            yield run.table("site_definitions_computers"), row


def _reserved_accounts(run: _Run) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting stored accounts (SMS_SCI_Reserved) via %s", run.name)
    count = 0
    for account in run.fetch("SMS_SCI_Reserved"):
        user_name = account.get("UserName")
        logger.verbose("  %s (site: %s)", user_name, account.get("SiteCode"))
        logger.debug("    %s", account)
        if not user_name:
            # Nothing to resolve or name the row by; previously this reached
            # resolve_principal(None) and failed there without saying why.
            logger.warning("Stored account row carries no UserName; skipping: %s", account)
            continue
        ad_object = run.ctx.resolve_principal(user_name)
        if not ad_object:
            logger.warning("Failed to resolve stored account %s to AD object", user_name)
            continue
        row = {**ad_object, "source": run.source("SMS_SCI_Reserved"), "sccm_infra": True, **account}
        row.setdefault("name", user_name)
        yield run.table("reserved_accounts"), row
        count += 1
    logger.info("Collected %d stored accounts via %s", count, run.name)


def _client_devices(run: _Run) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting client devices (SMS_CombinedDeviceResources) via %s", run.name)
    count = 0
    for device in run.fetch("SMS_CombinedDeviceResources", columns=DEVICE_COLUMNS):
        # Skip non-clients and obsolete records (stale reinstalls).
        if device.get("IsClient") is False or device.get("IsObsolete") is True:
            logger.debug("Skipping device %s (IsClient=%s, IsObsolete=%s)",
                         device.get("DistinguishedName") or device.get("Name"),
                         device.get("IsClient"), device.get("IsObsolete"))
            continue
        logger.debug("Found client device: %s", device)
        count += 1
        yield run.table("client_devices"), _row(run.source("SMS_CombinedDeviceResources"), run.site_code, device)
    logger.info("Collected %d client devices via %s", count, run.name)


def _simple(run: _Run, cls: str, suffix: str, columns: Optional[tuple], label: str,
            *, keep: Optional[tuple] = None, extra_fn=None) -> Iterator[tuple[str, dict]]:
    """Shared body for the straight ``fetch -> _row`` collections.

    ``keep`` whitelists output columns for the lazy classes (SMS_Role / SMS_Admin
    / SMS_SCI_SysResUse) that return every field — and bounds the debug log to
    those fields so encrypted/lazy values are never logged. ``extra_fn(obj)``
    adds derived columns (e.g. the flattened SQL service account).
    """
    logger.verbose("Collecting %s (%s) via %s", label, cls, run.name)
    count = 0
    for obj in run.fetch(cls, columns=columns):
        # Column-projected classes are already minimal; keep-whitelisted classes
        # may carry encrypted cert blobs, so debug-log only the kept fields.
        logger.debug("Found %s: %s", label,
                     {k: v for k, v in obj.items() if k in keep} if keep else obj)
        extra = extra_fn(obj) if extra_fn else None
        yield run.table(suffix), _row(run.source(cls), run.site_code, obj, keep=keep, extra=extra)
        count += 1
    logger.info("Collected %d %s via %s", count, label, run.name)


def _r_system(run: _Run) -> Iterator[tuple[str, dict]]:
    return _simple(run, "SMS_R_System", "r_system", RSYSTEM_COLUMNS, "system and security group records")


def _r_user(run: _Run) -> Iterator[tuple[str, dict]]:
    return _simple(run, "SMS_R_User", "r_user", RUSER_COLUMNS, "user and security group records")


def _user_group(run: _Run) -> Iterator[tuple[str, dict]]:
    # SMS_R_User / SMS_R_System list groups by NAME only (SecurityGroupName); this
    # class is the one resource that carries each group's SID, so preproc can resolve
    # those names offline (principal_by_name) instead of a live AD lookup per name.
    return _simple(run, "SMS_R_UserGroup", "user_group", USERGROUP_COLUMNS, "security group records")


def _collections(run: _Run) -> Iterator[tuple[str, dict]]:
    return _simple(run, "SMS_Collection", "collections", COLLECTION_COLUMNS, "device and user collections")


def _collection_members(run: _Run) -> Iterator[tuple[str, dict]]:
    return _simple(run, "SMS_FullCollectionMembership", "collection_members",
                   COLLECTION_MEMBER_COLUMNS, "collection memberships")


def _security_roles(run: _Run) -> Iterator[tuple[str, dict]]:
    return _simple(run, "SMS_Role", "security_roles", None, "security roles", keep=ROLE_COLUMNS)


def _admins(run: _Run) -> Iterator[tuple[str, dict]]:
    return _simple(run, "SMS_Admin", "admins", None, "admin users and groups", keep=ADMIN_COLUMNS)


def _site_systems(run: _Run) -> Iterator[tuple[str, dict]]:
    return _simple(
        run, "SMS_SCI_SysResUse", "site_systems", None, "site system roles", keep=SYSRES_COLUMNS,
        extra_fn=lambda o: {"sql_server_service_logon_account":
                            _prop(o.get("Props"), "SQL Server Service Logon Account", "Value2")},
    )


_COLLECTIONS = (
    _sites,
    _reserved_accounts,
    _client_devices,
    _r_system,
    _r_user,
    _user_group,
    _collections,
    _collection_members,
    _security_roles,
    _admins,
    _site_systems,
)


# --- transport adapters + identification ----------------------------------

def _http_get_value(client, path: str, *, probing: bool = False) -> Optional[list]:
    """GET an AdminService path; return its JSON ``value`` list, or None on failure.

    ``probing`` marks a call that is testing *whether* this host is an AdminService
    provider. A connect failure there is an expected negative -- most candidate hosts
    are not providers -- so it stays at VERBOSE to avoid a warning per host.

    Once the host is known to be a provider, the same failure means a collection came
    back short, and that has to be a WARNING: the caller reports it as
    ``Collected 0 <things>``, which is otherwise indistinguishable from an accurate
    empty result. A read timeout silently becoming "no rows" is how an incomplete
    graph looks complete.
    """
    result = client.get(path)
    if result.error_class is ErrorClass.CONNECT_FAILURE:
        if probing:
            logger.verbose("AdminService GET %s failed to connect", path)
        else:
            logger.warning("AdminService GET %s failed to connect (timeout, refused, or DNS); "
                           "this collection will be incomplete", path)
        return None
    if result.error_class is not ErrorClass.RESPONSE:
        logger.warning("AdminService GET %s failed: %s", path, result.error_class.value)
        return None
    if result.status_code != 200:
        logger.warning("AdminService GET %s returned HTTP %s", path, result.status_code)
        return None
    try:
        value = json.loads(result.content or b"").get("value")
    except Exception as ex:  # noqa: BLE001 - malformed body
        logger.warning("AdminService GET %s returned invalid JSON: %s", path, ex)
        return None
    if value is None:
        logger.warning("AdminService GET %s response had no 'value' array", path)
    return value


def _http_fetch(client) -> Callable[..., Iterator[dict]]:
    """Build the AdminService fetch adapter: OData GET + ``$top``/``$skip`` paging."""
    def fetch(class_name: str, columns: Optional[tuple] = None,
              where: Optional[str] = None) -> Iterator[dict]:
        path = f"/AdminService/wmi/{class_name}"
        params = []
        if columns:
            params.append("$select=" + ",".join(columns))
        if where:
            params.append("$filter=" + where)
        base = path + ("?" + "&".join(params) if params else "")
        skip = 0
        yielded = 0
        while True:
            sep = "&" if "?" in base else "?"
            value = _http_get_value(client, f"{base}{sep}$top={_BATCH}&$skip={skip}")
            # None means the request failed; [] means it succeeded with no rows. Treating
            # them alike is what let a timeout be reported as an accurate empty result, so
            # the failure case says so and names how much it did get -- a partial page
            # matters more than a total failure, because the caller's count looks plausible.
            if value is None:
                logger.warning("AdminService %s: collection incomplete, stopped after %d row(s)",
                               class_name, yielded)
                return
            if not value:
                return  # genuinely no (more) rows
            yield from value
            yielded += len(value)
            if len(value) < _BATCH:
                return  # short (final) page
            skip += _BATCH
    return fetch


def _wmi_fetch(client, namespace: str) -> Callable[..., Iterator[dict]]:
    """Build the WMI fetch adapter: a streaming WQL query against *namespace*."""
    def fetch(class_name: str, columns: Optional[tuple] = None,
              where: Optional[str] = None) -> Iterator[dict]:
        yield from client.query(namespace, class_name, columns=columns, where=where)
    return fetch


def _http_identify(client) -> Optional[str]:
    """Gate: this AdminService provider's site code, or None if not reachable."""
    value = _http_get_value(client, "/AdminService/wmi/SMS_Identification?$select=ThisSiteCode,ThisSiteName",
                            probing=True)
    if not value:
        return None  # issues logged by _http_get_value
    site_code = value[0].get("ThisSiteCode")
    if not site_code:
        logger.warning("AdminService SMS_Identification returned no site code")
        return None
    logger.info("Identified AdminService site: %s (%s)", site_code, value[0].get("ThisSiteName"))
    return site_code


def _wmi_identify(client) -> Optional[str]:
    """Gate: this SMS Provider's site code via WMI, or None if not reachable.

    The ``root\\SMS`` ``SMS_ProviderLocation`` query doubles as the auth-ladder
    probe (the WmiClient runs the ladder on its first query)."""
    rows = list(client.query("root\\SMS", "SMS_ProviderLocation"))
    if not rows:
        logger.info("WMI SMS_ProviderLocation returned nothing (rung exhausted or not a provider)")
        return None
    local = next((r for r in rows if r.get("ProviderForLocalSite")), rows[0])
    site_code = local.get("SiteCode")
    if not site_code:
        logger.warning("WMI SMS_ProviderLocation returned no site code")
        return None
    logger.info("Identified WMI SMS Provider site: %s", site_code)
    return site_code


# --- orchestrator + entry points ------------------------------------------

def _collect(run: _Run, target: str) -> Iterator[tuple[str, dict]]:
    """Run the ten collections in PS1 order, then mark the host complete.

    The completion marker is set *after* the loop (PS1-faithful): a catastrophic
    escape is caught by the entry point's outer ``except``, leaving the host
    unmarked so the WMI fallback can retry it.
    """
    for collection in _COLLECTIONS:
        try:
            yield from collection(run)
        except Exception as ex:  # noqa: BLE001 - one collection failing must not abort the rest
            logger.warning("%s %s failed on %s: %s", run.name, collection.__name__, target, ex)
    entry = run.ctx.target_hosts_by_hostname.get(target.lower())
    if entry is not None:
        entry.completed_phases.add(run.name)
        logger.verbose("Marked %s complete on %s", run.name, target)
    else:
        logger.debug("No TargetEntry for %s; phase-completion gating unavailable", target)
    logger.info("%s collection completed for %s (site %s)", run.name, target, run.site_code)


def collect_adminservice(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield raw AdminService rows for one target, or nothing if it isn't a
    reachable SMS provider (the SMS_Identification gate fails)."""
    if not ctx.method_enabled("AdminService"):
        return
    logger.info("Starting AdminService collection on %s...", target)
    client = HttpClient.from_context(ctx, target, auth=AuthMode.NEGOTIATE)
    try:
        site_code = _http_identify(client)
        if site_code is None:
            logger.info("%s is not a reachable AdminService provider; skipping", target)
            return
        yield from _collect(_Run(_http_fetch(client), "AdminService", "eq", site_code, ctx), target)
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("AdminService collection failed for %s: %s", target, ex)
    finally:
        client.close()


def collect_wmi(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield raw WMI rows for one target, or nothing if it isn't a reachable SMS
    Provider over WMI. Runs only when AdminService did not already reach this host
    (enforced by ``per_host_phases.should_run_phase``)."""
    if not ctx.method_enabled("WMI"):
        return
    logger.info("Starting WMI collection on %s...", target)
    client = WmiClient.from_context(ctx, target)
    try:
        site_code = _wmi_identify(client)
        if site_code is None:
            logger.info("%s is not a reachable SMS Provider over WMI; skipping", target)
            return
        namespace = f"root\\SMS\\site_{site_code}"
        yield from _collect(_Run(_wmi_fetch(client, namespace), "WMI", "=", site_code, ctx), target)
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("WMI collection failed for %s: %s", target, ex)
    finally:
        client.close()
