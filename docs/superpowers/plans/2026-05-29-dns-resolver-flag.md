# --dns-resolver Flag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--dns` / `--dns-resolver <ip>` CLI flag so all DNS lookups (DC discovery SRV + management-point SRV probes) route through a user-specified nameserver instead of the system default.

**Architecture:** The value flows through the existing flag→env var→`dlt.config.value`→`SourceContext` pipeline. `_resolve_dc_via_dns()` (called before the pipeline) receives it as an explicit argument. `dns_management_points()` reads it from `ctx.dns_resolver`. No global state; no behaviour change when the flag is omitted.

**Tech Stack:** Python 3.13, dnspython (`dns.resolver`), Typer, dlt (data load tool), pytest

---

## File Map

| File | Change |
|------|--------|
| `sccm/sccm/src/openhound_sccm/context.py` | Add `dns_resolver: Optional[str] = None` field to `SourceContext` |
| `sccm/sccm/src/openhound_sccm/source.py` | Add `dns_resolver: str \| None = dlt.config.value` param; pass to `SourceContext` |
| `sccm/sccm/src/openhound_sccm/main.py` | Add flag, env mapping, long-options entry, update `_resolve_dc_via_dns` + `_apply_connection_context` |
| `sccm/sccm/src/openhound_sccm/collectors/dns.py` | Update resolver construction in `dns_management_points` |
| `sccm/sccm/tests/test_dns_resolver_flag.py` | New test file covering all changed behaviour |

---

## Task 1: Add `dns_resolver` field to `SourceContext`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/context.py`

- [ ] **Step 1: Add the field**

  In `context.py`, add `dns_resolver` after the existing `password` field (around line 25). The full updated field block (lines 21–27) should read:

  ```python
  @dataclass
  class SourceContext:
      ad: ADClient
      domain: str
      username: Optional[str] = None
      password: Optional[str] = None
      dns_resolver: Optional[str] = None
      # Collection (-m / --collection-methods)
      collection_methods: str = "All"
  ```

- [ ] **Step 2: Verify import still works**

  Run from `sccm/sccm/`:
  ```
  uv run python -c "from openhound_sccm.context import SourceContext; print('ok')"
  ```
  Expected output: `ok`

- [ ] **Step 3: Commit**

  ```bash
  git add sccm/sccm/src/openhound_sccm/context.py
  git commit -m "feat(sccm): add dns_resolver field to SourceContext"
  ```

---

## Task 2: Thread `dns_resolver` through `source.py`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/source.py`

- [ ] **Step 1: Add the dlt config parameter to `source()`**

  In `source.py`, the `source()` function signature currently ends (around line 85) with:

  ```python
      # Network
      socks_proxy: str | None = dlt.config.value,
  ):
  ```

  Change it to:

  ```python
      # Network
      socks_proxy: str | None = dlt.config.value,
      # DNS
      dns_resolver: str | None = dlt.config.value,
  ):
  ```

- [ ] **Step 2: Pass the value to `SourceContext`**

  The `SourceContext(...)` constructor call (around line 120) currently ends with:

  ```python
      ctx = SourceContext(
          ad=ADClient(creds),
          domain=domain,
          username=username,
          password=password,
          collection_methods=collection_methods or "All",
          allowed_targets=frozenset(allowed),
          target_queue=_shared_queue,
          ad_resolution_cache=_shared_ad_cache if _shared_ad_cache is not None else {},
          discovered_domains=_shared_discovered_domains if _shared_discovered_domains is not None else set(),
          site_codes=_parse_csv_option(site_codes) or None,
      )
  ```

  Add `dns_resolver=dns_resolver,` as the last keyword argument:

  ```python
      ctx = SourceContext(
          ad=ADClient(creds),
          domain=domain,
          username=username,
          password=password,
          collection_methods=collection_methods or "All",
          allowed_targets=frozenset(allowed),
          target_queue=_shared_queue,
          ad_resolution_cache=_shared_ad_cache if _shared_ad_cache is not None else {},
          discovered_domains=_shared_discovered_domains if _shared_discovered_domains is not None else set(),
          site_codes=_parse_csv_option(site_codes) or None,
          dns_resolver=dns_resolver,
      )
  ```

- [ ] **Step 3: Verify import still works**

  Run from `sccm/sccm/`:
  ```
  uv run python -c "from openhound_sccm.source import source; print('ok')"
  ```
  Expected output: `ok`

- [ ] **Step 4: Commit**

  ```bash
  git add sccm/sccm/src/openhound_sccm/source.py
  git commit -m "feat(sccm): thread dns_resolver through source() into SourceContext"
  ```

---

## Task 3: Update `_resolve_dc_via_dns` + write tests

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py`
- Create: `sccm/sccm/tests/test_dns_resolver_flag.py`

- [ ] **Step 1: Write the failing tests**

  Create `sccm/sccm/tests/test_dns_resolver_flag.py`:

  ```python
  """Tests for --dns-resolver flag behaviour in main.py and collectors/dns.py."""
  from unittest.mock import MagicMock, patch, call
  
  
  # ---------------------------------------------------------------------------
  # _resolve_dc_via_dns
  # ---------------------------------------------------------------------------
  
  def test_resolve_dc_via_dns_uses_custom_resolver_when_provided():
      """When dns_resolver is set, Resolver(configure=False) is used with that IP."""
      from openhound_sccm.main import _resolve_dc_via_dns
  
      mock_resolver = MagicMock()
      mock_answer = MagicMock()
      mock_answer.target = MagicMock()
      mock_answer.target.__str__ = lambda self: "dc1.corp.local."
      mock_resolver.resolve.return_value = [mock_answer]
  
      with patch("openhound_sccm.main.dns") as mock_dns:
          mock_dns.resolver.Resolver.return_value = mock_resolver
  
          result = _resolve_dc_via_dns("corp.local", dns_resolver="192.168.1.53")
  
          mock_dns.resolver.Resolver.assert_called_once_with(configure=False)
          assert mock_resolver.nameservers == ["192.168.1.53"]
          assert result == "dc1.corp.local"
  
  
  def test_resolve_dc_via_dns_uses_module_resolver_when_not_provided():
      """When dns_resolver is None, the module-level dns.resolver.resolve() is used."""
      from openhound_sccm.main import _resolve_dc_via_dns
  
      mock_answer = MagicMock()
      mock_answer.target = MagicMock()
      mock_answer.target.__str__ = lambda self: "dc1.corp.local."
  
      with patch("openhound_sccm.main.dns") as mock_dns:
          mock_dns.resolver.resolve.return_value = [mock_answer]
  
          result = _resolve_dc_via_dns("corp.local", dns_resolver=None)
  
          mock_dns.resolver.resolve.assert_called_once()
          mock_dns.resolver.Resolver.assert_not_called()
          assert result == "dc1.corp.local"
  ```

- [ ] **Step 2: Run to confirm FAIL**

  Run from `sccm/sccm/`:
  ```
  uv run pytest tests/test_dns_resolver_flag.py -v
  ```
  Expected: FAIL — `_resolve_dc_via_dns` does not yet accept a second argument.

- [ ] **Step 3: Update `_resolve_dc_via_dns` in `main.py`**

  The current function (around line 348) reads:

  ```python
  def _resolve_dc_via_dns(domain: str) -> Optional[str]:
      """Resolve a domain controller FQDN from the domain via DNS SRV.
      ...
      """
      try:
          import dns.resolver  # type: ignore[import-not-found]

          answers = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV", lifetime=5)
          srvs = sorted(answers, key=lambda r: (r.priority, -r.weight))
          if srvs:
              return str(srvs[0].target).rstrip(".")
      except Exception as exc:  # dnspython errors, timeouts, no SRV records
          logger.warning("DNS SRV lookup for domain controller failed: %s", exc)
      return None
  ```

  Replace it with:

  ```python
  def _resolve_dc_via_dns(domain: str, dns_resolver: Optional[str] = None) -> Optional[str]:
      """Resolve a domain controller FQDN from the domain via DNS SRV.

      Looks up ``_ldap._tcp.dc._msdcs.<domain>`` — the path .NET's
      ``Domain.FindDomainController()`` ultimately takes via DC Locator.
      Cross-platform: works wherever the host has DNS reachability to the AD
      DNS zone, not just Windows.

      When ``dns_resolver`` is provided, a ``Resolver(configure=False)`` is
      created with that IP as the sole nameserver. When omitted the module-level
      ``dns.resolver.resolve()`` call is used (system default).
      """
      try:
          import dns.resolver  # type: ignore[import-not-found]

          if dns_resolver:
              resolver = dns.resolver.Resolver(configure=False)
              resolver.nameservers = [dns_resolver]
              resolver.lifetime = 5
              answers = resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
          else:
              answers = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV", lifetime=5)
          srvs = sorted(answers, key=lambda r: (r.priority, -r.weight))
          if srvs:
              return str(srvs[0].target).rstrip(".")
      except Exception as exc:  # dnspython errors, timeouts, no SRV records
          logger.warning("DNS SRV lookup for domain controller failed: %s", exc)
      return None
  ```

- [ ] **Step 4: Run tests to confirm PASS**

  Run from `sccm/sccm/`:
  ```
  uv run pytest tests/test_dns_resolver_flag.py::test_resolve_dc_via_dns_uses_custom_resolver_when_provided tests/test_dns_resolver_flag.py::test_resolve_dc_via_dns_uses_module_resolver_when_not_provided -v
  ```
  Expected: 2 PASSED

- [ ] **Step 5: Commit**

  ```bash
  git add sccm/sccm/src/openhound_sccm/main.py sccm/sccm/tests/test_dns_resolver_flag.py
  git commit -m "feat(sccm): update _resolve_dc_via_dns to accept custom nameserver"
  ```

---

## Task 4: Wire up CLI flag + env mapping in `main.py`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py`

- [ ] **Step 1: Add to `_FLAG_TO_ENV`**

  The `_FLAG_TO_ENV` dict ends (around line 81) with:

  ```python
      # Network
      "socks_proxy": "SOURCES__SCCM__SOCKS_PROXY",
  }
  ```

  Change to:

  ```python
      # Network
      "socks_proxy": "SOURCES__SCCM__SOCKS_PROXY",
      # DNS
      "dns_resolver": "SOURCES__SCCM__DNS_RESOLVER",
  }
  ```

- [ ] **Step 2: Add to `_LONG_OPTIONS_WITH_VALUES`**

  The `_LONG_OPTIONS_WITH_VALUES` set ends (around line 139) with:

  ```python
      "--socks-proxy",
  }
  ```

  Change to:

  ```python
      "--socks-proxy",
      "--dns",
      "--dns-resolver",
  }
  ```

- [ ] **Step 3: Add the Typer option to `collect_sccm()`**

  In the `collect_sccm` function signature, the `# ---- Network ----` block (around line 638) currently reads:

  ```python
      # ---- Network ----
      socks_proxy: Optional[str] = typer.Option(None, "--socks-proxy", help="SOCKS5 proxy HOST:PORT for DHCP/TFTP collection."),
  ```

  Change to:

  ```python
      # ---- Network ----
      socks_proxy: Optional[str] = typer.Option(None, "--socks-proxy", help="SOCKS5 proxy HOST:PORT for DHCP/TFTP collection."),
      dns_resolver: Optional[str] = typer.Option(None, "--dns", "--dns-resolver", help="DNS nameserver IP for all lookups (DC discovery, SRV probes). Omit to use system default."),
  ```

- [ ] **Step 4: Pass `dns_resolver` to `_resolve_dc_via_dns` in `_apply_connection_context()`**

  The call inside `_apply_connection_context()` (around line 399) currently reads:

  ```python
              dc = _resolve_dc_via_dns(domain)
  ```

  Change to:

  ```python
              dc = _resolve_dc_via_dns(domain, dns_resolver=flag_kwargs.get("dns_resolver"))
  ```

- [ ] **Step 5: Write and run a test for the CLI env-var wiring**

  Add to `sccm/sccm/tests/test_dns_resolver_flag.py`:

  ```python
  # ---------------------------------------------------------------------------
  # _apply_env_overrides — dns_resolver → SOURCES__SCCM__DNS_RESOLVER
  # ---------------------------------------------------------------------------
  
  def test_apply_env_overrides_sets_dns_resolver(monkeypatch):
      """dns_resolver flag value propagates to the expected env var."""
      import os
      from openhound_sccm.main import _apply_env_overrides
  
      monkeypatch.delenv("SOURCES__SCCM__DNS_RESOLVER", raising=False)
      _apply_env_overrides({"dns_resolver": "10.0.0.53"})
      assert os.environ["SOURCES__SCCM__DNS_RESOLVER"] == "10.0.0.53"
  
  
  def test_apply_env_overrides_does_not_set_dns_resolver_when_none(monkeypatch):
      """When dns_resolver is None, the env var is left untouched."""
      import os
      from openhound_sccm.main import _apply_env_overrides
  
      monkeypatch.delenv("SOURCES__SCCM__DNS_RESOLVER", raising=False)
      _apply_env_overrides({"dns_resolver": None})
      assert "SOURCES__SCCM__DNS_RESOLVER" not in os.environ
  ```

  Run from `sccm/sccm/`:
  ```
  uv run pytest tests/test_dns_resolver_flag.py -v
  ```
  Expected: 4 PASSED

- [ ] **Step 6: Commit**

  ```bash
  git add sccm/sccm/src/openhound_sccm/main.py sccm/sccm/tests/test_dns_resolver_flag.py
  git commit -m "feat(sccm): add --dns/--dns-resolver CLI flag and env-var wiring"
  ```

---

## Task 5: Update `dns_management_points` resolver construction

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/dns.py`
- Modify: `sccm/sccm/tests/test_dns_resolver_flag.py`

- [ ] **Step 1: Write the failing test**

  Add to `sccm/sccm/tests/test_dns_resolver_flag.py`:

  ```python
  # ---------------------------------------------------------------------------
  # dns_management_points — resolver construction
  # ---------------------------------------------------------------------------
  
  def _make_ctx(dns_resolver=None, domain_controller=None, domain="corp.local",
                site_codes=None, collection_methods="All"):
      """Build a minimal SourceContext-like mock for dns_management_points tests."""
      ctx = MagicMock()
      ctx.dns_resolver = dns_resolver
      ctx.ad.creds.domain_controller = domain_controller
      ctx.domain = domain
      ctx.site_codes = site_codes or set()
      ctx.method_enabled.return_value = True
      return ctx
  
  
  def test_dns_management_points_uses_configure_false_when_dns_resolver_set():
      """When ctx.dns_resolver is set, Resolver(configure=False) is used."""
      from openhound_sccm.collectors.dns import dns_management_points
  
      ctx = _make_ctx(dns_resolver="192.168.1.53", site_codes={"PS1"})
      mock_resolver = MagicMock()
      mock_resolver.resolve.return_value = []
  
      with patch("openhound_sccm.collectors.dns.dns") as mock_dns:
          mock_dns.resolver.Resolver.return_value = mock_resolver
          mock_dns.resolver.NXDOMAIN = Exception
          mock_dns.resolver.NoAnswer = Exception
          mock_dns.exception.Timeout = Exception
  
          list(dns_management_points(ctx))
  
          mock_dns.resolver.Resolver.assert_called_once_with(configure=False)
          assert mock_resolver.nameservers == ["192.168.1.53"]
  
  
  def test_dns_management_points_uses_default_resolver_when_dns_resolver_not_set():
      """When ctx.dns_resolver is None and no DC, Resolver() uses system defaults."""
      from openhound_sccm.collectors.dns import dns_management_points
  
      ctx = _make_ctx(dns_resolver=None, domain_controller=None, site_codes={"PS1"})
      mock_resolver = MagicMock()
      mock_resolver.resolve.return_value = []
  
      with patch("openhound_sccm.collectors.dns.dns") as mock_dns:
          mock_dns.resolver.Resolver.return_value = mock_resolver
          mock_dns.resolver.NXDOMAIN = Exception
          mock_dns.resolver.NoAnswer = Exception
          mock_dns.exception.Timeout = Exception
  
          list(dns_management_points(ctx))
  
          mock_dns.resolver.Resolver.assert_called_once_with()
          assert mock_resolver.nameservers != ["192.168.1.53"]
  ```

- [ ] **Step 2: Run to confirm FAIL**

  Run from `sccm/sccm/`:
  ```
  uv run pytest tests/test_dns_resolver_flag.py::test_dns_management_points_uses_configure_false_when_dns_resolver_set tests/test_dns_resolver_flag.py::test_dns_management_points_uses_default_resolver_when_dns_resolver_not_set -v
  ```
  Expected: FAIL — `dns_management_points` doesn't check `ctx.dns_resolver` yet.

- [ ] **Step 3: Update resolver construction in `dns_management_points`**

  In `collectors/dns.py`, the resolver block (around line 62) currently reads:

  ```python
      if has_dnspython:
          resolver = dns.resolver.Resolver()
          resolver.timeout = 5
          resolver.lifetime = 10
          if ctx.ad.creds.domain_controller:
              resolver.nameservers = [_resolve_v4(ctx.ad.creds.domain_controller) or ctx.ad.creds.domain_controller]
  ```

  Replace with:

  ```python
      if has_dnspython:
          if ctx.dns_resolver:
              resolver = dns.resolver.Resolver(configure=False)
              resolver.nameservers = [ctx.dns_resolver]
          else:
              resolver = dns.resolver.Resolver()
              if ctx.ad.creds.domain_controller:
                  resolver.nameservers = [_resolve_v4(ctx.ad.creds.domain_controller) or ctx.ad.creds.domain_controller]
          resolver.timeout = 5
          resolver.lifetime = 10
  ```

- [ ] **Step 4: Run all tests to confirm PASS**

  Run from `sccm/sccm/`:
  ```
  uv run pytest tests/test_dns_resolver_flag.py -v
  ```
  Expected: 6 PASSED

- [ ] **Step 5: Run the full test suite to confirm no regressions**

  Run from `sccm/sccm/`:
  ```
  uv run pytest tests/ -v
  ```
  Expected: all tests PASS (no regressions)

- [ ] **Step 6: Commit**

  ```bash
  git add sccm/sccm/src/openhound_sccm/collectors/dns.py sccm/sccm/tests/test_dns_resolver_flag.py
  git commit -m "feat(sccm): use custom dns_resolver in dns_management_points (Ope-vpdw)"
  ```

---

## Self-Review

**Spec coverage:**
- ✅ `--dns` / `--dns-resolver <ip>` flag accepted by CLI → Task 4, Step 3
- ✅ `Resolver(configure=False)` with provided nameserver when set → Task 3, Step 3 + Task 5, Step 3
- ✅ System default DNS when flag omitted → both resolver paths fall through to `Resolver()` unchanged
- ✅ `_resolve_dc_via_dns()` updated → Task 3
- ✅ `dns_management_points()` updated → Task 5

**Type/name consistency:** `dns_resolver` is used consistently across all four files and all test cases. `SOURCES__SCCM__DNS_RESOLVER` is the env var name throughout.

**No placeholders:** All steps include complete code.
