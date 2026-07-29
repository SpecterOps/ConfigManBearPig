# Design: SMB Collection collector (`collectors/smb.py` + `clients/smb.py`)

**Ticket:** ope-4483
**Date:** 2026-06-15
**Status:** Approved (not committed per CLAUDE.md)

## Problem

Port `Invoke-SMBCollection` (ConfigManBearPig.ps1:9000), including the SMB
signing scan (`Get-SMBSigningRequiredViaSMBNegotiate`, ps1:5113), to an
OpenHound per-host collector. This work covers the **collect** phase only.
Per-host reconciliation and the cross-host relay analysis go to **preproc**, and
Computer / `SCCM_Site` node + edge construction to **convert** — both coded in
follow-up tickets.

## What the PowerShell does (in order)

`Invoke-SMBCollection($CollectionTarget)`:

1. Skip the host entirely if it was already `Collected` (set only by AdminService
   at ps1:6875 and WMI at ps1:8195).
2. **SMB signing scan** — `Get-SMBSigningRequiredViaSMBNegotiate`: a raw,
   *unauthenticated* SMB2 NEGOTIATE to TCP/445, reading the `SecurityMode`
   signing-required bit (`0x0002`). Records `SMBSigningRequired` on the Computer,
   `CollectionSource = @("SMB-Negotiate")`. The result carries an `Error` field;
   share enumeration is gated on `-not $Error` (i.e. the host was reachable).
3. **Enumerate shares** via `NetShareEnum` level 1 (`SHARE_INFO_1`): name +
   description per share.
4. **Classify** share names/descriptions into roles, a site code, and flags, in
   this exact order: `SMS_SITE` → Site Server (+ site code from
   `"SMS Site (\w+)"`); `SMS_*` → Site Server if not already; `REMINST` → PXE;
   `SCCMContentLib$` / `SMSPKG` → content library; a share-description fallback
   for the site code; `SMS_DP$` → Distribution Point (+ site code from
   `"SMS Site (\w+) DP"`). Each match appends a `collectionSource` tag
   (`SMB-SMS_SITE`, `SMB-SMS_*`, `SMB-REMINST`, `SMB-SCCMContentLib$`,
   `SMB-SMSPKG$`, `SMB-ShareDescription`, `SMB-SMS_DP$`).
5. Upsert an `SCCM_Site` node (if a site code was found) and a `Computer` node
   with the roles list, `SCCMHostsContentLibrary`, `SCCMIsPXESupportEnabled`,
   `SCCMInfra`, and the `collectionSource` list.

## Design decisions (resolved with the user)

1. **Share → role/site-code derivation lives in `collect`** (inline), exactly as
   [http.py](../../../sccm/sccm/src/openhound_sccm/collectors/http.py) and
   [registry.py](../../../sccm/sccm/src/openhound_sccm/collectors/registry.py) do.
   "Complex comparison logic" deferred to preproc = genuine cross-record work:
   reconciling the SMB facts against registry/HTTP/AdminService for a host, and
   the "site systems without SMB signing + NTLM unrestricted" relay analysis
   (ps1:6734). Per-host share parsing is collection, not comparison.
2. **Signing scan = impacket negotiate.** Read the negotiated `RequireSigning`
   flag (the same `0x0002` bit) off an impacket `SMBConnection` rather than
   hand-rolling the SMB2 NEGOTIATE wire bytes. `smb_sso.py` already relies on
   `smb3._Connection["RequireSigning"]`, so this is established precedent and far
   less code.
3. **`registry.py` reuses the same capability.** When the registry
   `RequireSecuritySignature` DWORD is absent, fall back to the negotiated flag
   read off the SMB connection registry already holds open. Registry value wins
   (PS1's two-tier `Get-SMBSigningRequiredFromRegistry`: registry first, negotiate
   fallback). Adds a `smb_signing_source` indicator; no other schema change.

## Design

### 1. New `clients/smb.py`

SMB-specific operations on impacket's public API, reusing `connect_smb` from
`smb_sso.py` for the authenticated share-enumeration session.

```python
def negotiated_signing_required(smb: SMBConnection) -> Optional[bool]:
    """Read RequireSigning off an EXISTING connection (no extra round-trip)."""
    # smb.getSMBServer()._Connection["RequireSigning"]; None if pre-SMB2.

def check_smb_signing(hostname: str, timeout: int = 2) -> Optional[bool]:
    """Throwaway negotiate-only connection (no login); returns the flag.
    None = unreachable/undetermined (PS1's $Error path that gates share enum)."""

def list_shares(smb: SMBConnection) -> list[tuple[str, str]]:
    """impacket listShares() (= NetShareEnum level 1); (shi1_netname, shi1_remark)
    with NDR null terminators stripped."""
```

### 2. New `collectors/smb.py`

`@with_log_context(phase="SMB")` `collect_smb(target, ctx)`:

1. `if not ctx.method_enabled("SMB"): return`.
2. Resolve `ad_object` / `name` from `ctx.target_hosts_by_hostname.get(target.lower())`.
3. **Signing scan** — `check_smb_signing(target)`.
   - Determined → yield `smb_computers` `{**ad_object, "source": "SMB-Negotiate",
     "smb_signing_required": bool, "name": name}`.
   - `None` (unreachable) → log info + return (PS1 gates share enum on no-error).
4. **Share enum** — `connect_smb(...)`; if `None`, log warning + return. Else
   `list_shares(smb)` (in `try/finally` that logs off).
5. `_classify_shares(shares)` — pure helper walking shares in exact PS1 order,
   returning `collection_source`, `site_code`, `is_site_server`, `is_dp`,
   `is_pxe_enabled`, `hosts_content_library`.
6. **Emit only when an SCCM share matched** (`collection_source` non-empty):
   - if `site_code`: yield `smb_sites` `{"source": "SMB-Shares", "site_code": ...}`.
   - yield `smb_computers` `{**ad_object, "source": "SMB-Shares",
     "collection_source": [tags], "sccm_infra": True,
     "sccm_hosts_content_library": bool, "sccm_is_pxe_support_enabled": bool,
     "sccm_site_system_roles": [roles] | None, "site_code": site_code | None,
     "name": name}`.

Roles are `"SMS Site Server@<site>"` / `"SMS Distribution Point@<site>"`
(`@<site>` suffix only when the site code is known), matching PS1's
`SCCMSiteSystemRoles` strings. PXE and content-library are flags, not roles
(faithful to PS1).

### 3. Wiring — `per_host_phases.py`

- Import `smb`; append `Phase("SMB", ("smb_computers", "smb_sites"),
  smb.collect_smb)` after the HTTP phase (PS1 order:
  `RemoteRegistry, MSSQL, AdminService, HTTP, SMB`; OpenHound keeps WMI as the
  AdminService fallback before HTTP).
- Extend the HTTP branch of `should_run_phase` to `if phase.name in ("HTTP", "SMB")`:
  skip when AdminService or WMI already collected this host (PS1's `Collected`
  skip at 9053).
- Emit resources auto-generate from `all_table_names(PER_HOST_PHASES)`
  ([source.py:182](../../../sccm/sccm/src/openhound_sccm/source.py)); **no
  `source.py` edit, no Pydantic model needed for collect.**

### 4. Edit — `registry.py` (`get_ntlm_settings`)

When `RequireSecuritySignature` is `None`, fall back to
`negotiated_signing_required(probe.smb)`; registry value wins. Add
`smb_signing_source` (`"Registry"` / `"SMB-Negotiate"` / `None`) to the emitted
`remoteregistry_computers` row.

## Faithful PS1 bug-fixes / improvements (documented in the collector docstring)

- **Only emit the roles row on a real SCCM share match.** PS1 upserts a Computer
  with `SCCMInfra=True` for *any* host whose shares enumerate, over-tagging plain
  file servers. Mirrors http.py's "only emit a confirmed role" improvement.
- **`SMS_*` and share-description branches read the matched share's own
  description.** PS1 reads `$smsSite.Description` in both, which is `$null` in
  those branches (copy-paste bug) — so its `SMS_*`-only and description-fallback
  site-code paths never resolve. We read the correct share's description.
- **`SMS_DP$` description check.** PS1's `-not $smsDP.Description -contains
  "ConfigMgr Site Server"` misuses `-contains` (array operator on a string); we
  use a substring test, preserving the intent (suppress the warning for a site
  server's own DP share).

## Files Changed

| File | Change |
|------|--------|
| `sccm/sccm/src/openhound_sccm/clients/smb.py` | **New** — `negotiated_signing_required`, `check_smb_signing`, `list_shares` |
| `sccm/sccm/src/openhound_sccm/collectors/smb.py` | **New** — `collect_smb` + `_classify_shares` |
| `sccm/sccm/src/openhound_sccm/per_host_phases.py` | Register SMB phase after HTTP; extend skip gate to SMB |
| `sccm/sccm/src/openhound_sccm/collectors/registry.py` | Negotiate fallback for `smb_signing_required` + `smb_signing_source` |

## Out of scope (follow-up tickets)

- **preproc:** reconcile SMB signals vs registry/HTTP/AdminService per host; the
  "site systems without SMB signing + NTLM unrestricted" relay-coercion analysis
  (ps1:6734).
- **convert:** build the `Computer` and `SCCM_Site` nodes and their edges from the
  `smb_computers` / `smb_sites` tables.

## Addendum (2026-06-15): full auth-method coverage

Follow-up to "does this work with all authentication methods?": the original port
reused `connect_smb` *unchanged*, which only honored password / current-user SSPI
/ null session — silently ignoring `--nt-hash` (pass-the-hash) and `--ticket`
(pass-the-ticket). This is a pre-existing limitation of the shared client (it
affected RemoteRegistry too), not specific to SMB; the PowerShell original only
ever did current-user SMB.

`connect_smb` ([clients/smb_sso.py](../../../sccm/sccm/src/openhound_sccm/clients/smb_sso.py))
now accepts `nt_hash`, `kerberos_ticket`, and `kdc_host` and routes:
pass-the-ticket → `kerberosLogin(TGT=…)`, pass-the-hash → `login(nthash=…)`,
password → `login`, then SSPI, then null. Ticket decoding reuses the same
`CCache.fromKRBCRED` / `toTGT` path as `clients/wmi.py`; hash formatting reuses
`http_auth.format_hashes`. Both [collectors/smb.py](../../../sccm/sccm/src/openhound_sccm/collectors/smb.py)
and [collectors/registry.py](../../../sccm/sccm/src/openhound_sccm/collectors/registry.py)
pass `ctx.nt_hash` / `ctx.kerberos_ticket` and the resolved DC as the KDC. The
signing check stays unauthenticated, so it is auth-method-agnostic.

## Addendum (2026-06-16): signing detection must read the SERVER's SecurityMode

The first cut read impacket's `_Connection['RequireSigning']`. That is impacket's
*client-side* "should I sign?" decision, which smb3.py:658-663 forces `True` for
SMB 3.1.1 ("always sign") — the default dialect on modern Windows. Result: every
modern host reported signing-required, a false positive that hides relay targets
(the opposite of this tool's goal). Live lab confirmed it: ps1-sms / ps1-pss /
ps1-dp all read `True` when they in fact do **not** require signing.

Fix (hybrid, both read the server's advertised SecurityMode, not RequireSigning):
- `check_smb_signing` does a raw, unauthenticated SMB2 NEGOTIATE over a socket and
  tests `SecurityMode & 0x0002` at response offset 70 — PS1-faithful, dialect-
  independent, no impacket internals.
- `negotiated_signing_required` reads `_Connection['ServerSecurityMode']`
  (smb3.py:687, the uncontaminated server value) off an existing connection for
  registry.py's fallback; returns None for dialect < 3.0 (impacket leaves it 0).

Post-fix lab: dc / ps1-mp → `True`; ps1-sms / ps1-pss / ps1-dp → `False` (raw
negotiate and ServerSecurityMode agree on every host).

## Validation

Run the existing suite in an isolated uv venv
(`UV_PROJECT_ENVIRONMENT=/tmp/openhound-venv uv run pytest`). No existing test
pins the production phase list exactly or the registry NTLM row shape, so adding
the SMB phase and the `smb_signing_source` field is non-breaking. A focused unit
test for `_classify_shares` (pure, no I/O) covers the share-classification order
and the bug-fixed branches.
