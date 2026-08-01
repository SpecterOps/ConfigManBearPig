---
id: ope-feb0
status: closed
deps: []
links: [ope-8c44]
created: 2026-07-28T17:42:09Z
type: bug
priority: 2
tags: [sccm, bloodhound, upload, cli, observability]
---

# BloodHound upload-only CLI path is silent (no operator feedback; failed upload still exits 0)

The upload-only CLI paths (collect sccm --skip-collection and --upload-dir) run the BloodHound upload BEFORE any Collector/Converter pipeline is constructed, so OpenHound's console log handler (cli_level default ERROR, finalized in Collector.run/Converter.run via set_handler) never surfaces the INFO-level upload logs. Result: 'collect sccm --skip-collection --upload-schema-only -B ... [-v/--debug]' exits 0 with ZERO console output — the operator gets no confirmation the upload happened, and a FAILED upload is equally silent (run_upload logs failures at WARNING but the summary is discarded and exit stays 0). Live-verified 2026-07-28 against BloodHound CE at 127.0.0.1:8080: the upload itself WORKS (schema PUT /api/v2/extensions x2 + results file-upload job both succeed, kinds registered), only the CLI feedback+exit-code is missing. Fix in openhound_sccm.main._dispatch_bloodhound_upload: echo a definitive start+result line to stdout via typer.echo and raise typer.Exit(1) on upload failure. Linked to ope-8c44. Plan: sccm/sccm/docs/superpowers/plans/2026-07-28-bloodhound-upload-cli-feedback.md

## Notes

**2026-07-28T19:58:25Z**

IMPLEMENTED + live-verified 2026-07-28 (no-commit; owner to commit). Fix: _dispatch_bloodhound_upload now reports via typer.echo (stdout) independent of OpenHound's logging, and raises typer.Exit(1) on upload failure or missing-token; url-None stays a silent no-op. Surgical anchor-based edit to main.py (did NOT touch the concurrent --clean flag / ContainerNode / low-priv regions). +4 tests in bloodhound_cli_test.py (9/9 pass). Live: schema-only push -> exit 0 + 'BloodHound upload complete: 2 schema(s), 0 results file(s).'; bad token -> exit 1 + 'BloodHound upload FAILED (2 error(s)): ... HTTP 401 signature digest mismatch ...' + 'output on disk is intact'. README one-line note deferred (avoided touching shared doc during low-priv work). NOTE: pre-existing unrelated failures in tests/test_cli_option_panels.py (KeyError 'clean') come from the concurrent --clean flag work missing a 'clean' entry in EXPECTED_PANEL -- NOT this change.

**2026-07-31T15:36:02Z**

Status audit 2026-07-31: THE BUG IS UNREACHABLE -- the code it patches no longer exists -> closing as obsolete. This bug lived in openhound_sccm.main._dispatch_bloodhound_upload; that function, _resolve_upload_mode, and all 16 upload CLI options were deleted by ope-2419 on 2026-07-29 when the direct BloodHound CE upload was removed from both published packages. Code-verified 2026-07-31: no _dispatch_bloodhound_upload / _resolve_upload_mode anywhere under src/, and zero 'bloodhound' hits in the whole package. The fix described here (typer.echo start+result lines to stdout, typer.Exit(1) on failure) was implemented and live-verified on 2026-07-28, so it is preserved inside the fork archive at bloodhound-upload/ along with the rest of the feature. If direct upload returns, this observability fix is part of the re-wiring checklist rather than a separate open bug. Note for whoever picks that up: bloodhound_cli_test.py's 4 tests went with it, but tests/cli_option_panels_test.py:41-42 still names 'skip_collection' and 'upload_dir' -- two stale strings left behind by the removal.
