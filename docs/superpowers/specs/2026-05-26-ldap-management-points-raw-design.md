# Design: `ldap_management_points_raw` — Multi-Type Collection from `mSSMSManagementPoint`

**Date:** 2026-05-26
**Status:** Approved

## Problem

A single `mSSMSManagementPoint` LDAP entry contains data that must feed three downstream concerns:

1. **Site classification** — `site_type` and `parent_site_code` for `SCCM_Site` nodes
2. **MP computer role** — `"SMS Management Point@<site_code>"` for the MP host's `Computer.SCCMSiteSystemRoles`
3. **FSP computer roles** — `"SMS Fallback Status Point@<site_code>"` for FSP hostnames parsed from the capabilities XML

The existing `ldap_mp_site_classifications` resource only addresses (1) partially, omits `mp_hostname` from its yield, never extracts FSP hostnames, and is not wired into `source.py`. `Computer.SCCMSiteSystemRoles` is populated via `self._lookup.computer_site_system_roles()` but that method is not implemented.

## Decision

**One resource, one raw table, three derived transforms.**

Parse the capabilities XML once at collection time (it must happen then anyway to call `ctx.register_target()` for FSPs). Yield all derived fields as a flat row. Let preproc fan the single table into three materialised lookup tables via plain SQL.

## Architecture

### Collection (`collectors/ldap.py`)

Rename `ldap_mp_site_classifications` → `ldap_management_points_raw`.

For each `mSSMSManagementPoint` entry, in a single XML parse pass:

1. Extract `mp_hostname` (`mSSMSMPName`), `mp_site_code` (`mSSMSSiteCode`)
2. Call `ctx.register_target(mp_hostname, site_code=mp_site_code, source="LDAP-mSSMSManagementPoint")`
3. Parse `mSSMSCapabilities` XML:
   - `command_line_site_code` — from `CCM.CommandLine` SMSSITECODE match
   - `root_site_code` — from `RootSiteCode` element
   - `site_type` — derived: Primary / CAS / Secondary (same logic as current code)
   - `parent_site_code` — derived from site_type + root/command_line codes
   - `fsp_hostnames` — list from `ClientOperationalSettings.FSP.FSPServer` nodes
4. Call `ctx.register_target(fsp_hostname, site_code=mp_site_code, source="LDAP-mSSMSManagementPoint")` for each FSP hostname
5. Yield one flat row:

```python
{
    "mp_hostname": str | None,
    "site_code": str,
    "site_type": str | None,          # "Primary Site" | "Central Administration Site" | "Secondary Site"
    "parent_site_code": str | None,
    "command_line_site_code": str | None,
    "root_site_code": str | None,
    "fsp_hostnames": list[str],        # empty list when none found
}
```

`raw_table_asset("ldap_management_points_raw")` replaces `raw_table_asset("ldap_mp_site_classifications")`.

### Source wiring (`source.py`)

Add `ldap_management_points_raw` to the import and the `source()` return tuple. (The old resource was never wired in — this is the first time it runs.)

### Base tables list (`main.py`)

Replace `"ldap_mp_site_classifications"` with `"ldap_management_points_raw"` in the preproc base tables list.

### Preproc transforms (`transforms.py`)

Three new transforms, all reading from `sccm.ldap_management_points_raw`:

**`sccm.site_types`** — already in `_EMPTY_SCHEMAS`, now actually built:
```sql
SELECT site_code, site_type, parent_site_code
FROM sccm.ldap_management_points_raw
WHERE site_code IS NOT NULL
```

**`sccm.computer_mp_roles`** — one row per MP:
```sql
SELECT mp_hostname AS hostname,
       'SMS Management Point@' || site_code AS role,
       site_code
FROM sccm.ldap_management_points_raw
WHERE mp_hostname IS NOT NULL AND site_code IS NOT NULL
```

**`sccm.computer_fsp_roles`** — fanned out, one row per FSP per site:
```sql
SELECT UNNEST(fsp_hostnames) AS hostname,
       'SMS Fallback Status Point@' || site_code AS role,
       site_code
FROM sccm.ldap_management_points_raw
WHERE fsp_hostnames IS NOT NULL AND LEN(fsp_hostnames) > 0
```

**`sccm.computer_site_system_roles`** — unified UNION across all sources:
```sql
SELECT hostname, role, site_code FROM sccm.computer_mp_roles
UNION ALL
SELECT hostname, role, site_code FROM sccm.computer_fsp_roles
-- Additional sources (e.g. connectionPoint PXE DPs) unioned here as they are added
```

All transforms are guarded with `_table_exists()` checks and wrapped in `_safe_exec()` to degrade gracefully if collection didn't run.

### Lookup (`lookup.py`)

Implement `computer_site_system_roles(object_sid, dns_host_name)` on `SCCMLookup`:

- Match by hostname (FQDN and short name) against `sccm.computer_site_system_roles`
- Return a tuple of `"RoleName@SiteCode"` strings, or empty tuple if none found
- `@lru_cache` on the method for convert-time efficiency. Cache key is `(object_sid, dns_host_name)` — both args passed so the cache correctly separates computers that share a short hostname across domains.

## Files Changed

| File | Change |
|------|--------|
| `collectors/ldap.py` | Rename resource; add `mp_hostname`, `fsp_hostnames` to yield; add FSP `register_target()` calls |
| `source.py` | Import + wire `ldap_management_points_raw` into `source()` return |
| `main.py` | Rename `"ldap_mp_site_classifications"` → `"ldap_management_points_raw"` in base tables list |
| `transforms.py` | Implement `site_types`, `computer_mp_roles`, `computer_fsp_roles`, `computer_site_system_roles` transforms |
| `lookup.py` | Implement `computer_site_system_roles()` method |

No test files require changes (no existing test references to `ldap_mp_site_classifications`).

## Design Boundaries

- XML parsing stays in the collector (Python `ElementTree`). Preproc owns derivation of structured-from-structured, not parsing of raw bytes.
- `ctx.register_target()` for FSP hosts must occur at collection time to seed the target queue for subsequent per-host collection passes.
- `sccm.computer_site_system_roles` is designed as a UNION table so future LDAP sources (e.g. `connectionPoint`/PXE DPs) can append rows without changing the lookup method.
- The `site_type` value strings match PS1/CMBP conventions: `"Primary Site"`, `"Central Administration Site"`, `"Secondary Site"`.
