---
id: Ope-8wi2
status: closed
deps: []
links: [ope-8c44]
created: 2026-05-28T13:31:15Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, bloodhound, output]
---

# Upload Directly to BloodHound

Wire up the SCCM extension output to the existing BloodHound upload destinations in OpenHound core. OpenHound core already implements BloodHound CE and BHE upload destinations but the SCCM extension only writes to local files. The app = OpenHound(sccm) instance supports registering additional destinations.

## Design

Add --bloodhound-url, --bloodhound-token (CE) and --bhe-url, --bhe-token (Enterprise) CLI flags to main.py. When provided, register the BloodHound upload destination with the DLT pipeline after conversion. Respect existing BloodHound client in /src/openhound/core/clients/bloodhound.py. Add --no-local-output flag to suppress local JSON write when uploading directly.

## Acceptance Criteria

--bloodhound-url and --bloodhound-token causes graph to be uploaded to BH CE after conversion. --bhe-url/--bhe-token targets BHE ingest API. Upload errors are reported without crashing (data still saved locally unless --no-local-output).

## Notes

**2026-07-22T16:24:34Z**

CLI panel reserved (2026-07-22): during the collect-sccm --help reorg, the operator asked for a 'BloodHound Upload' rich_help_panel. It was NOT added yet because there are no upload flags. When this ticket is implemented, add the upload flag(s) to collect_sccm() (or a dedicated 'openhound upload' path) with rich_help_panel='BloodHound Upload' so they render as their own titled section in --help. Sibling reorg note: options are grouped into Authentication/Collection/Performance/Output/Logging panels via rich_help_panel; follow that pattern.

**2026-07-24T13:54:55Z**

2026-07-24: Design PIVOTED during a grill with the owner. Original design (reuse OpenHound core's ingest DLT destination + --bhe-url/--bhe-token) was rejected. New locked design: port the Go MSSQLHound flow (PUT /api/v2/extensions for schema + POST /api/v2/file-upload/{start,{id},end} for a results zip; HMAC or Bearer auth; retry on 429/5xx) into a REUSABLE uploader in openhound-collector-common, then wire into SCCM collect (--run-all) and convert. Uploads BOTH schema.json + schema_MSSQL.json, honors --disable-possible-edges, adds --upload-dir + --skip-collection. Implementation tracked in linked ope-8c44. Full plan: sccm/sccm/docs/superpowers/plans/2026-07-24-bloodhound-direct-upload.md

**2026-07-31T15:36:02Z**

Status audit 2026-07-31: SUPERSEDED BY A PRODUCT DECISION -> closing. This feature was designed twice (the original core-ingest-destination design, then the 2026-07-24 pivot to a reusable uploader in openhound-collector-common) and implemented under the linked ope-8c44 on 2026-07-24. On 2026-07-29 ope-2419 removed direct BloodHound CE upload from BOTH published packages ahead of the PyPI publish and archived it in the fork at bloodhound-upload/ (24 files, incl. a re-wiring checklist and cli_integration.py extracted verbatim from the inline main.py code). Code-verified 2026-07-31: no upload flags on collect sccm or convert sccm, and zero 'bloodhound' hits under src/. The 'BloodHound Upload' rich_help_panel this ticket reserved was consequently never added, and should not be until the feature returns. Closing because the current answer to 'should the collector upload directly?' is a decided no for 2.0, not an open question. Reopen post-release if that changes.
