# Design: --dns-resolver / --dns flag

**Ticket:** Ope-vpdw  
**Date:** 2026-05-29  
**Status:** Approved

## Problem

When OpenHound is run from a machine whose system DNS does not point at Active Directory (e.g. a Linux attack box or a pivot host), two DNS operations fail silently or use wrong servers:

1. DC auto-discovery (`_resolve_dc_via_dns`) queries `_ldap._tcp.dc._msdcs.<domain>` using the system resolver.
2. SRV probing in `dns_management_points` sets the domain controller's IP as its nameserver, but first falls back to the system resolver to resolve the DC hostname to an IP.

Operators need to specify an explicit nameserver IP so all DNS lookups are routed through an AD-aware server even from non-AD-joined machines.

## Acceptance Criteria (from ticket)

- `--dns` / `--dns-resolver <ip>` flag accepted by the CLI.
- `dns.resolver.Resolver(configure=False)` used with the provided nameserver when the flag is set.
- System default DNS used when the flag is omitted (no behaviour change).

## Approach

Full flag → env var → `dlt.config.value` → `SourceContext` pipeline, consistent with all other config knobs.

## Design

### 1. CLI & Config wiring — `main.py`

**New Typer option** added to `collect_sccm()`:

```python
dns_resolver: Optional[str] = typer.Option(
    None, "--dns", "--dns-resolver",
    help="DNS nameserver IP for all lookups (DC discovery, SRV probes). Omit to use system default."
),
```

**`_FLAG_TO_ENV` addition:**

```python
"dns_resolver": "SOURCES__SCCM__DNS_RESOLVER",
```

**`_LONG_OPTIONS_WITH_VALUES` additions:**

```python
"--dns",
"--dns-resolver",
```

**`_resolve_dc_via_dns(domain, dns_resolver=None)`** — new second parameter. When `dns_resolver` is provided:

```python
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = [dns_resolver]
resolver.lifetime = 5
answers = resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
```

When omitted, the existing `dns.resolver.resolve(...)` module-level call is used unchanged.

**`_apply_connection_context(flag_kwargs)`** passes `flag_kwargs.get("dns_resolver")` to `_resolve_dc_via_dns()`.

### 2. Data flow — `source.py` and `context.py`

**`source()` in `source.py`** gains a new dlt config parameter:

```python
dns_resolver: str | None = dlt.config.value,
```

Passed directly to `SourceContext`:

```python
ctx = SourceContext(
    ...
    dns_resolver=dns_resolver,
)
```

**`SourceContext` dataclass** (`context.py`) gets one new field:

```python
dns_resolver: Optional[str] = None
```

No logic in `SourceContext` — it is a data carrier only.

### 3. DNS collector — `collectors/dns.py`

`dns_management_points()` resolver construction is updated:

```python
if ctx.dns_resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ctx.dns_resolver]
else:
    resolver = dns.resolver.Resolver()
    if ctx.ad.creds.domain_controller:
        resolver.nameservers = [
            _resolve_v4(ctx.ad.creds.domain_controller) or ctx.ad.creds.domain_controller
        ]
resolver.timeout = 5
resolver.lifetime = 10
```

`_resolve_v4()` is kept for the existing DC-as-nameserver path; it is not called when `--dns-resolver` is set.

## Files Changed

| File | Change |
|------|--------|
| `sccm/sccm/src/openhound_sccm/main.py` | Add flag, env mapping, long-options entry, update `_resolve_dc_via_dns` + `_apply_connection_context` |
| `sccm/sccm/src/openhound_sccm/source.py` | Add `dns_resolver` dlt config param, pass to `SourceContext` |
| `sccm/sccm/src/openhound_sccm/context.py` | Add `dns_resolver: Optional[str] = None` field |
| `sccm/sccm/src/openhound_sccm/collectors/dns.py` | Update resolver construction in `dns_management_points` |

## Error Handling

- Invalid IP formats are not validated by the CLI (consistent with how `--dc` is handled). If the IP is unreachable or returns no records, existing exception handling in both DNS functions covers it gracefully (logs warning/debug, continues).

## No Behaviour Change When Flag Is Omitted

All code paths that were active before remain active when `dns_resolver is None`. The only change is an additional branch when the value is present.
