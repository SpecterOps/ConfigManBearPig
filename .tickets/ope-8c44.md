---
id: ope-8c44
status: open
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
