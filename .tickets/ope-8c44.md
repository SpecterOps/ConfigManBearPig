---
id: ope-8c44
status: closed
deps: []
links: [Ope-8wi2, ope-feb0]
created: 2026-07-24T13:45:49Z
type: task
priority: 2
tags: [sccm, bloodhound, upload, shared-lib, collector-common]
---

# Direct BloodHound CE upload (schema + results) from SCCM via shared openhound-collector-common uploader

Port the Go MSSQLHound BloodHound-CE direct-upload flow (PUT /api/v2/extensions for schema + /api/v2/file-upload job API for a results zip; HMAC or Bearer auth; retry on 429/5xx) into a reusable uploader in openhound-collector-common, then wire it into the SCCM collector's collect (--run-all) and convert commands. Uploads BOTH sccm/sccm/schema.json and schema_MSSQL.json, applies --disable-possible-edges mutation, bundles convert output into a zip, adds --upload-dir standalone mode and --skip-collection schema-only push. Plan: sccm/sccm/docs/superpowers/plans/2026-07-24-bloodhound-direct-upload.md

## Notes

**2026-07-24T19:45:09Z**

Implemented: shared bloodhound uploader in openhound-collector-common (auth/client/uploader/zip/schema); SCCM collect+convert wired (-B/--bloodhound, env vars, --upload-schema-only/--upload-results-only, --skip-collection, --upload-dir); uploads schema_SCCM.json + schema_MSSQL.json with --disable-possible-edges mutation; convert hand-registered. Offline tests green. Live lab validation vs bloodhound.mayyhem.com pending.

**2026-07-31T15:35:44Z**

Status audit 2026-07-31: IMPLEMENTED, THEN DELIBERATELY REMOVED -> closing as reverted. This work landed on 2026-07-24 (shared uploader in openhound-collector-common; SCCM collect+convert wired with -B/--bloodhound, --upload-schema-only/--upload-results-only, --skip-collection, --upload-dir), then ope-2419 removed the entire direct-upload feature from BOTH published packages on 2026-07-29 ahead of the PyPI publish, archiving 24 files in the fork at bloodhound-upload/ with a re-wiring checklist. Code-verified 2026-07-31: zero 'bloodhound' hits anywhere under src/ and no upload flag on collect sccm; the only surviving traces are two stale strings 'skip_collection' and 'upload_dir' in tests/cli_option_panels_test.py:41-42. Closing rather than leaving open because the removal was a considered product decision (every operator would otherwise ship an HTTP client, HMAC/Bearer signing, a zip bundler and a schema mutator for a workflow most do not use), not an accident. If direct upload is wanted again post-release, reopen this ticket and follow bloodhound-upload/docs/removal-record.md.
