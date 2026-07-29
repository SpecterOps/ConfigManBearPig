---
id: ope-b916
status: closed
deps: []
links: []
created: 2026-07-17T16:25:15Z
type: feature
priority: 2
tags: [sccm, http, preproc, convert, cve, version]
---

# Wire SCCM version->CVE fingerprinting into HTTP collection + site node

Wire cve_table.py (dead code) into the collector: (1) HTTP collection fingerprints SCCM version via GET /CCM_Client/ccmsetup.exe on confirmed MPs (SCCMVersionGuesser regex), yields http_site_versions(site_code,sccm_version); (2) preproc _node_site LEFT JOINs it, coalesce(privileged_version, http_version) [privileged preferred]; (3) convert sccm_site.py computes versionCVEs=lookup_cves(version), new SCCMSiteProperties.versionCVEs field; (4) cve_table conservative major-version base-build enumeration + robust _locate_build by build number + fix false docstring; (5) README + ARCHITECTURE (new HTTP divergence). Decisions: conservative base-build CVEs for major-version-only; privileged-preferred version. Spec: docs/superpowers/specs/2026-07-17-sccm-version-cve-fingerprint-design.md

## Notes

**2026-07-17T17:30:31Z**

Spec updated: (decision #4) suppress CoerceAndRelayToAdminService when site version confirmed >= build 9141 (SCCM 2509, AdminService rejects NTLM); fail OPEN on unknown/unparseable version. New transforms section: _edge_coerce_relay_adminservice LEFT JOINs node_site, gates on try_cast(split_part(version,'.',3)) >= ADMINSERVICE_NTLM_MIN_BUILD (new constant in cve_table.py, single source of truth); ordering dep: _node_site before the coerce edge. Added live lab validation (required): ps1-mp.mayyhem.com (HTTP ccmsetup.exe fingerprint) + ps1-sms.mayyhem.com (AdminService privileged version -> versionCVEs) + e2e gate check; skip-with-reason if hosts powered off (creds in debug_epa_matrix.py). Open decisions for user: Range-fetch now vs v2 (rec: v2, full streamed download v1); http_site_versions table vs MP-row column (rec: table).

**2026-07-20T14:32:51Z**

COMPLETE (mechanism + all 7 tasks + final review fixes), no commit per CLAUDE.md. Live-validated: ps1-mp (HTTP ccmsetup fingerprint) AND ps1-sms (AdminService) both yield SCCM 2303 build 9106 -> identical 5 versionCVEs; 2509 gate correct (9106<9141 -> edge kept; PS1 edge absent only due to lab topology: SMS Provider+Site Server co-located). HTTP validation caught+fixed a real bug (extractor first-match grabbed 5.00.0000.0000 placeholder -> now findall+max-by-version-tuple). Final review fixes: probe no longer aborts DP/SMS role detection on download timeout; coalesce _ensure_columns-guarded vs dlt-dropped site_code. 55/55 tests green, ruff+mypy clean.

**2026-07-20T17:04:20Z**

POST-COMPLETION BUGFIX (user caught http_site_versions missing from a live collect resource summary): root cause was HttpClient's default 'Accept: application/json' -> IIS 406 on the binary ccmsetup.exe (not the timeout the review predicted; download is 0.07s). Fixed: get() gains optional headers param, probe sends Accept: */* + is now exception-wrapped (best-effort truly can't abort DP/SMS role detection), _FakeHttp double updated. Live-confirmed vs ps1-mp: probe now yields http_site_versions{PS1, 5.00.9106.1000}. 48 CVE+HTTP tests green, ruff clean.

**2026-07-20T17:16:19Z**

BUGFIX #2 (user hit --run-all preprocess crash 'Adding columns with constraints not yet supported'). Root cause: _coalesce_http_site_version's CREATE TABLE IF NOT EXISTS created http_site_versions, which is a DLT-MANAGED resource; when the old 406 bug meant no MP was fingerprinted, it left a bare 2-col table (no _dlt_id); the next run's dlt load tried to ALTER ADD the constrained _dlt_id -> DuckDB rejects. Fix: helper now existence-checks http_site_versions and skips when absent (never creates the dlt-owned table); _ensure_columns retained for the dlt-dropped-column case (plain cols, safe). Regression test added. E2E: fresh preprocess of live raw succeeds, http_site_versions dlt-owned (PS1/SEC=5.00.9106.1000), node_site.version=9106 all sites. 24-test sweep green. USER ACTION: delete the already-poisoned output/lookup.duckdb before re-running --run-all.

**2026-07-20T17:30:15Z**

Committed by user 2026-07-20. Feature complete: version->CVE fingerprinting (HTTP ccmsetup + AdminService), versionCVEs on SCCM_Site, 2509 CoerceAndRelayToAdminService gate. All 7 tasks + final review + 2 live bugfixes (406 Accept header; dlt-owned-table CREATE crash). Live-validated vs ps1-mp + ps1-sms (SCCM 2303/9106). Closing.
